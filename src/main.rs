

use ark_bls12_381::{Bls12_381, Config, Fr as F, Fq, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AffineRepr;
use ark_poly::univariate::DensePolynomial;
use kzg_commitment::KZGCommitment;

use ark_ff::PrimeField;
use num_bigint::BigUint;
use rand::{prelude::SliceRandom, Rng};


struct VerkleTree {
    root: Option<VerkleNode>,
    width: usize,
    kzg: KZGCommitment
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: G1Affine,
    polynomial: DensePolynomial<F>,
    children: Option<Vec<VerkleNode>>,
}

struct VerkleProof {
    proofs: Vec<ProofNode>
}

struct ProofNode {
    commitment: G1Affine,
    proof: G1Affine,
    point: Vec<(F, F)>,
}

impl VerkleTree {
    fn new(datas: &Vec<F>, width: usize) -> Self {
        let kzg = KZGCommitment::new(width);
        Self::build_tree(kzg, datas, width)
    }

    fn build_tree(kzg: KZGCommitment, datas: &Vec<F>, width: usize) -> VerkleTree {
        
        if datas.len() <= width {
            let polynomial = KZGCommitment::vector_to_polynomial(datas);
            let commitment = kzg.commit_polynomial(&polynomial);
            return VerkleTree {
                root: Some(VerkleNode {
                    commitment,
                    polynomial,
                    children: None,
                }),
                width,
                kzg
            };
        }
        let leaf_nodes = Self::create_leaf_nodes(&kzg, datas, width);
        let root = Self::build_tree_recursively(&kzg, &leaf_nodes, width);
    
        VerkleTree { root: Some(root), width, kzg }

    }

    fn create_leaf_nodes(kzg: &KZGCommitment, datas: &Vec<F>, width: usize) -> Vec<VerkleNode> {
        println!("Building Leaf Nodes");
        datas.chunks(width).map(|chunk| {
            let polynomial = KZGCommitment::vector_to_polynomial(&chunk.to_vec());
            let commitment = kzg.commit_polynomial(&polynomial);
            VerkleNode {
                commitment,
                polynomial,
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
                polynomial,
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


    pub fn generate_proof(&self, index: usize, data: F) -> VerkleProof {
        let mut node_positions = Vec::<usize>::new();
        let mut value_positions = Vec::<usize>::new();

        let mut current_node = index / self.width;
        let mut current_position = index % self.width;

        let depth = self.depth();

        for _ in 0..=depth {
            node_positions.push(current_node);
            value_positions.push(current_position);

            current_position = current_node % self.width;
            current_node = current_node / self.width;
            
        }
        node_positions.reverse();
        value_positions.reverse();

        let mut current_node = self.root.clone().unwrap();

        let mut proofs = Vec::<ProofNode>::new();
        for (i, &node_position) in node_positions.iter().enumerate() {
            let current_commitment = current_node.commitment.clone();
            // assert_eq!(current_commitment, self.root().unwrap());
            let current_polynomial = current_node.polynomial.clone();
            let node_to_prove_position = value_positions[i];
            let data_to_prove = if let Some(children) = current_node.children {
                let next_node = children[node_to_prove_position].clone();
                let next_node_commitment = next_node.commitment;
                current_node = next_node;
                Self::map_commitment_to_field(&next_node_commitment)
            } else {
                data
            };
            
            let points = vec![(F::from(node_to_prove_position as u32), data_to_prove)];
            let proof = self.kzg.generate_proof(&current_polynomial, &points);
            println!("Generated Proof");
            proofs.push(ProofNode { commitment: current_commitment, proof: proof.unwrap(), point: points });

        }

        VerkleProof { proofs }

    }


    pub fn verify_proof(&self, proof: Vec<G1Affine>) -> bool {
        unimplemented!()
    }

    fn map_commitment_to_field(g1_point: &G1Affine) -> F {
        let fq_value = g1_point.x().unwrap() + g1_point.y().unwrap();
        let fq_bigint: BigUint = fq_value.into_bigint().into();
        F::from_le_bytes_mod_order(&fq_bigint.to_bytes_le())
    }

    pub fn depth(&self) -> usize {
        let mut depth = 0;

        let mut current_node = self.root.clone().unwrap(); // TODO: error handling
        while current_node.children.is_some() {
            depth += 1;
            current_node = current_node.children.unwrap()[0].clone();
        }
        depth
    }


    pub fn root(&self) -> Option<G1Affine> {
        match &self.root {
            None => None,
            Some(verkle_node) => Some(verkle_node.commitment)
        }
    }


}

fn generate_random_vec(length: usize) -> Vec<F> {
    let mut rng = rand::thread_rng();
    println!("Generating vector with length: {}", length);
    (0..length).map(|_| F::from(rng.gen_range(-100..=100))).collect()
}
fn main() {
    let width = 4 as usize;
    let datas = generate_random_vec(16);
    let verkle_tree = VerkleTree::new(&datas, width);
    println!("root {:?}", verkle_tree.root().unwrap());
    println!("Depth: {}", verkle_tree.depth());
    let index = 6;
    let data = datas[index];
    verkle_tree.generate_proof(index, data);


}