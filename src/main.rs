

use ark_bls12_381::{Bls12_381, Config, Fr as F, Fq, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AffineRepr;
use kzg_commitment::KZGCommitment;

use ark_ff::PrimeField;
use num_bigint::BigUint;


struct VerkleTree {
    root: Option<VerkleNode>,
    width: usize
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: G1Affine,
    children: Option<Vec<VerkleNode>>,
}

impl VerkleTree {
    fn new(datas: &Vec<F>, width: usize) -> Self {
        let kzg = KZGCommitment::new(width);
        
        unimplemented!()
    }

    fn build_tree(kzg: &KZGCommitment, datas: &Vec<F>, width: usize) -> VerkleTree {
        
        if datas.len() <= width {
            let polynomial = KZGCommitment::vector_to_polynomial(datas);
            let commitment = kzg.commit_polynomial(&polynomial);
            return VerkleTree {
                root: Some(VerkleNode {
                    commitment,
                    children: None,
                }),
                width
            };
        }
    
        // Create leaf nodes
        let leaf_nodes = Self::create_leaf_nodes(kzg, datas, width);
    
        // Recursively build the tree
        let root = Self::build_tree_recursively(kzg, &leaf_nodes, width);
    
        VerkleTree { root: Some(root), width }

    }

    fn create_leaf_nodes(kzg: &KZGCommitment, datas: &Vec<F>, width: usize) -> Vec<VerkleNode> {
        datas.chunks(width).map(|chunk| {
            let polynomial = KZGCommitment::vector_to_polynomial(&chunk.to_vec());
            let commitment = kzg.commit_polynomial(&polynomial);
            VerkleNode {
                commitment,
                children: None
            }
        }).collect()

    }

    fn build_from_nodes(kzg: &KZGCommitment, nodes: &Vec<VerkleNode>, width: usize) -> Vec<VerkleNode> {
        
        nodes.chunks(width).map(|chunk| {
            let vector_commitment_mapping = chunk.into_iter().map(|node| Self::map_commitment_to_field(&node.commitment)).collect();
            let polynomial = KZGCommitment::vector_to_polynomial(&vector_commitment_mapping);
            let commitment = kzg.commit_polynomial(&polynomial);
            VerkleNode {
                commitment,
                children: Some(chunk.to_vec())
            }
        }).collect()

    }

    fn build_tree_recursively(kzg: &KZGCommitment, nodes: &Vec<VerkleNode>, width: usize) -> VerkleNode {
        if nodes.len() == 1 {
            return nodes[0].clone();
        }

        let next_level = Self::build_from_nodes(kzg, nodes, width);

        Self::build_tree_recursively(kzg, &next_level, width)

    }

    fn map_commitment_to_field(g1_point: &G1Affine) -> F {
        Self::map_fq_to_fr(&(g1_point.x().unwrap() + g1_point.y().unwrap()))
    }

    fn map_fq_to_fr(fq_value: &Fq) -> F {
        let fq_bigint = Self::field_to_biguint(fq_value);
        Self::biguint_to_field(&fq_bigint)
    }

    fn biguint_to_field<F: PrimeField>(big_uint: &BigUint) -> F {
        F::from_le_bytes_mod_order(&big_uint.to_bytes_le())
    }
    
    fn field_to_biguint<F: PrimeField>(field_elem: &F) -> BigUint {
        field_elem.into_bigint().into()
    }


}

fn main() {
    println!("Hello, world!");
}