use ark_bls12_381::{Bls12_381, Config, Fq, Fr as F, G1Affine};
use ark_ec::AffineRepr;
use ark_poly::univariate::DensePolynomial;
use kzg_commitment::KZGCommitment;

use ark_ff::PrimeField;
use num_bigint::BigUint;

pub struct VerkleTree {
    root: Option<VerkleNode>,
    width: usize,
    kzg: KZGCommitment,
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: G1Affine,
    polynomial: DensePolynomial<F>,
    children: Option<Vec<VerkleNode>>,
}

#[derive(Debug, Clone)]
pub struct VerkleProof {
    pub proofs: Vec<ProofNode>,
}

#[derive(Debug, Clone)]
pub struct ProofNode {
    pub commitment: G1Affine,
    pub proof: G1Affine,
    pub point: Vec<(F, F)>,
}

impl VerkleTree {
    pub fn new(datas: &Vec<F>, width: usize) -> Self {
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
                kzg,
            };
        }
        let leaf_nodes = Self::create_leaf_nodes(&kzg, datas, width);
        let root = Self::build_tree_recursively(&kzg, &leaf_nodes, width);

        VerkleTree {
            root: Some(root),
            width,
            kzg,
        }
    }

    fn create_leaf_nodes(kzg: &KZGCommitment, datas: &Vec<F>, width: usize) -> Vec<VerkleNode> {
        println!("Building Leaf Nodes");
        datas
            .chunks(width)
            .map(|chunk| {
                let polynomial = KZGCommitment::vector_to_polynomial(&chunk.to_vec());
                let commitment = kzg.commit_polynomial(&polynomial);
                VerkleNode {
                    commitment,
                    polynomial,
                    children: None,
                }
            })
            .collect()
    }

    fn build_from_nodes(
        kzg: &KZGCommitment,
        nodes: &Vec<VerkleNode>,
        width: usize,
    ) -> Vec<VerkleNode> {
        nodes
            .chunks(width)
            .map(|chunk| {
                let vector_commitment_mapping = chunk
                    .into_iter()
                    .map(|node| Self::map_commitment_to_field(&node.commitment))
                    .collect();
                let polynomial = KZGCommitment::vector_to_polynomial(&vector_commitment_mapping);
                let commitment = kzg.commit_polynomial(&polynomial);
                VerkleNode {
                    commitment,
                    polynomial,
                    children: Some(chunk.to_vec()),
                }
            })
            .collect()
    }

    fn build_tree_recursively(
        kzg: &KZGCommitment,
        nodes: &Vec<VerkleNode>,
        width: usize,
    ) -> VerkleNode {
        if nodes.len() == 1 {
            return nodes[0].clone();
        }
        let next_level = Self::build_from_nodes(kzg, nodes, width);
        Self::build_tree_recursively(kzg, &next_level, width)
    }

    pub fn generate_proof(&self, index: usize, data: &F) -> Result<VerkleProof, VerkleTreeError> {
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
                *data
            };

            let points = vec![(F::from(node_to_prove_position as u32), data_to_prove)];
            let proof = self.kzg.generate_proof(&current_polynomial, &points);

            match proof {
                Ok(proof) => {
                    proofs.push(ProofNode {
                        commitment: current_commitment,
                        proof: proof,
                        point: points,
                    });
                }
                Err(_) => return Err(VerkleTreeError::ProofGenerateError),
            }
        }

        Ok(VerkleProof { proofs })
    }

    pub fn verify_proof(&self, verkle_proof: &VerkleProof) -> bool {
        let proof_root = verkle_proof.proofs[0].commitment;
        if proof_root != self.root_commitment().unwrap() {
            return false;
        }
        let verkle_proofs = verkle_proof.proofs.clone();
        for proof in verkle_proofs {
            if !self
                .kzg
                .verify_proof(&proof.commitment, &proof.point, &proof.proof)
            {
                return false;
            }
        }
        true
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

    pub fn root_commitment(&self) -> Option<G1Affine> {
        match &self.root {
            None => None,
            Some(verkle_node) => Some(verkle_node.commitment),
        }
    }
}

#[derive(Debug)]
pub enum VerkleTreeError {
    BuildError,
    ProofGenerateError,
    EmptyTree,
}
