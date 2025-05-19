use std::{collections::HashSet, vec};

use pairing_plus::serdes::SerDes;

use pointproofs::pairings::{param::paramgen_from_seed, *};
use pointproofs::pairings::Commitment;
use rayon::prelude::*;

pub struct VerkleTree {
    root: Option<VerkleNode>,
    width: usize,
    pp: ProverParams,
}

#[derive(Debug, Clone)]
struct VerkleNode {
    commitment: Commitment,
    values: Vec<Vec<u8>>, //should maybe be a vector 
    children: Option<Vec<VerkleNode>>,
}

#[derive(Debug, Clone)]
pub struct VerkleProof {
    pub proofs: Vec<ProofNode>,
}

#[derive(Debug, Clone)]
pub struct ProofNode {
    pub commitment: Commitment, //mayb be commitment
    pub proof: Proof, //of type Proof
    pub indices : Vec<usize>,
    pub values: Vec<Vec<u8>> , // just a vector  (index:usize, value: vec<vec<u8>>)
}

impl VerkleTree {
    pub fn new(datas: &Vec<Vec<u8>>, width: usize) -> Result<Self, VerkleTreeError> {
        let (prover_params, _) =
            paramgen_from_seed("This is our Favourite very very long Seed", 0, width).unwrap();
        
        Self::build_tree(prover_params, datas, width)
    }

    fn build_tree(prover_params: ProverParams, datas: &Vec<Vec<u8>>, width: usize) -> Result<VerkleTree, VerkleTreeError> {
        if datas.is_empty() {
          return Err(VerkleTreeError::BuildError);
        }
        if datas.len() <= width {
            let commitment: Commitment = Commitment::new(&prover_params, &datas).unwrap();
            return Ok(VerkleTree {
                root: Some(VerkleNode {
                    commitment,
                    values: datas.to_vec(),
                    children: None,
                }),
                width,
                pp: prover_params,
            });
        }
        let leaf_nodes = Self::create_leaf_nodes(&prover_params, datas, width);
        let root = Self::build_tree_recursively(&prover_params, &leaf_nodes, width);

        Ok(VerkleTree {
            root: Some(root),
            width,
            pp: prover_params,
        })
    }
    
    fn create_leaf_nodes(prover_params: &ProverParams, datas: &Vec<Vec<u8>>, width: usize) -> Vec<VerkleNode> {
        datas
            .par_chunks(width)
            .map(|chunk| {
                let values = chunk.to_vec();
                let commitment: Commitment = Commitment::new(&prover_params, &values).unwrap();
                VerkleNode {
                    commitment,
                    values,
                    children: None,
                }
            })
            .collect()
    }

    fn build_from_nodes(prover_params: &ProverParams, nodes: &[VerkleNode], width: usize) -> Vec<VerkleNode> {
        nodes
        .par_chunks(width)
            .map(|chunk| {
                let values: Vec<Vec<u8>> = chunk
                    .par_iter()
                    .map(|node| Self::map_commitment_to_vec_u8(&node.commitment))
                    .collect();
                let commitment: Commitment = Commitment::new(&prover_params, &values).unwrap();
                VerkleNode {
                    commitment,
                    values,
                    children: Some(chunk.to_vec()),
                }
            })
            .collect()
    }

    fn build_tree_recursively(prover_params: &ProverParams, nodes: &[VerkleNode], width: usize) -> VerkleNode {
        if nodes.len() == 1 {
            return nodes[0].clone();
        }
        let next_level = Self::build_from_nodes(prover_params, nodes, width);
        Self::build_tree_recursively(prover_params, &next_level, width)
    }

    pub fn generate_proof(&self, index: usize, data: &Vec<u8>) -> Result<VerkleProof, VerkleTreeError> {
        let mut node_positions = Vec::<usize>::new();
        let mut value_positions = Vec::<usize>::new();

        let mut current_node = index / self.width;
        let mut current_position = index % self.width;

        let depth = self.depth();

        for _ in 0..=depth {
            node_positions.push(current_node);
            value_positions.push(current_position);

            current_position = current_node % self.width;
            current_node /= self.width;
        }
        node_positions.reverse();
        value_positions.reverse();

        let mut current_node = self.root.clone().unwrap();

        let mut proofs = Vec::<ProofNode>::new();
        for (i, &_node_position) in node_positions.iter().enumerate() {
            let current_commitment = current_node.commitment.clone();
            let current_values = current_node.values.clone();
            let node_to_prove_position = value_positions[i];
            let data_to_prove = if let Some(children) = current_node.children {
                let next_node = children[node_to_prove_position].clone();
                let next_node_commitment = next_node.commitment.clone();
                current_node = next_node.clone();
                Self::map_commitment_to_vec_u8(&next_node_commitment)
            } else {
                data.to_vec()
            };

            //let points: Vec<(usize, Vec<u8>)> = vec![(node_to_prove_position, data_to_prove)];
            let proof = Proof::new(&self.pp, &current_values, index);
            match proof {
                Ok(proof) => {
                    proofs.push(ProofNode {
                        commitment: current_commitment,
                        proof,
                        indices: vec![node_to_prove_position],
                        values: vec![data_to_prove],
                    });
                }
                Err(_) => return Err(VerkleTreeError::ProofGenerateError),
            }
        }

        Ok(VerkleProof { proofs })
    }

/* The next functions are to generate proofs for several indices simultaeusly  */

    /*  This function returns a long vector which reads the nodes from top to bottom left to right
        Each index contains either a proof of some children, or a None value
    */
    pub fn generate_batch_proof (&self, index: Vec<usize>, data: &Vec<Vec<u8>>) -> Vec<Option<ProofNode>> {
        assert!(data.len() % self.width == 0, "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");
        assert!(!index.is_empty(), "Please give a non empty index");
        let width = self.width;
        let depth = self.depth();
        // The following line creates a vector, on each index is a vector which incidates which children nodes need to be proven
        let index_for_proof = VerkleTree::create_index_for_proof(index, width, self.depth());
        
        let proofs: Vec<Option<ProofNode>> = (0.. index_for_proof.len())
        .into_par_iter()
        .map(|ind| {
            if index_for_proof[ind]!= vec![]  {
                let path = Self::path_to_child(ind, width);

                let node: VerkleNode = Self::find_commitment_node(self, path);
                let index_first_child: usize =
                    if node.children.is_none(){
                        let index_first_child_data: usize = 
                            if width == 2 {
                                usize::pow(width, (depth+1).try_into().unwrap())/(width-1) -1
                            }
                            else {
                                usize::pow(width, (depth+1).try_into().unwrap())/(width-1)
                            };
                        width*ind +1 - index_first_child_data
                    }
                    else {
                        width*ind +1
                    };
                let proof_of_node = self.find_proof_node(node,  index_for_proof[ind].clone(), data, index_first_child).expect("failed to generate proof for node");
                Some(proof_of_node)
            }
            else {
                None
            }
        }).collect();
        proofs
    }

    fn path_to_child (mut index: usize, width: usize) -> Vec<usize> {
        let mut path : Vec<usize> = Vec::new();
        if index == 0 {
            return path;
        }
        else {
            path.push((index-1) % width); //push current node index
            while index > width{
                index = (index-1)/width; //compute parent
                path.push((index-1) % width); //push parent
            }
        }
        path.reverse();
        path

    }

    fn create_index_for_proof(index: Vec<usize>, width: usize, depth: usize) -> Vec<Vec<usize>> {

        /* This creates a vector of the form:
            [[2, 0], [1, 2], [], [0]] 
            The root is on index 0 and children [2,0] need to be proven.
            etc.
            */
        let mut tree_path: Vec<Vec<usize>>  = Vec::new();
        let mut indexes = index.clone();
        for level in 1.. (depth+1){
            let data_level_above = width.pow((depth+1-level) as u32);
            // This creates for each parent node an empty vector
            let mut level_above: Vec<Vec<usize>> = vec![vec![]; data_level_above];
            // This is a hash set to only insert if the node is "new"
            let mut new_indices: HashSet<usize> = HashSet::new();
            /* The loop adds the index of the child that needs to be proven in the vector of the parent node
                This is done modulus the width of the tree. 
                Also the loop creates a vector for the indices of the parent node for the next layer*/
            for i in 0.. indexes.len(){
                level_above[indexes[i] / width].push(indexes[i]% width);
                new_indices.insert(indexes[i]/ width);
            }
            level_above.reverse();
            for parent in level_above{
                tree_path.push(parent);
            }
            indexes = new_indices.into_iter().collect();
                
        }
        // We need to add the root manually
        //println!("{:?}", tree_path);
        let mut node_root: Vec<usize> = Vec::new();
        for child in 0.. width{
            if !tree_path[tree_path.len()- child-1].is_empty(){
                node_root.push(child);
            }
        }
        tree_path.push( node_root);
        tree_path.reverse();
        //println!("tree proofs {:?}", tree_proofs);
        //println!("tree path{:?}", tree_path);
        tree_path
    }
    
    fn find_commitment_node(&self, path: Vec<usize>) -> VerkleNode{
        let mut current_node = self.root.clone().unwrap();
        for i in path {
            current_node = current_node.children.expect("failed to find children")[i].clone();
        }
        current_node
    }

    fn find_proof_node (&self, node: VerkleNode, indices_to_proof: Vec<usize>, data: &Vec<Vec<u8>>, index_first_child: usize) ->  Result<ProofNode, VerkleTreeError>  {
        //let mut indices: Vec<usize> = Vec::new();
        let mut values: Vec<Vec<u8>> = Vec::new();
        if  let Some(child) = node.children {
            for child_node in child {
                let com = child_node.commitment;
                let child_commitment = Self::map_commitment_to_vec_u8(&com);
                values.push(child_commitment);
            }
        }
        else {
            for ind in 0 .. self.width {
                values.push(data[index_first_child + ind].clone());
            }
        }
        let proof = Proof::batch_new_aggregated(&self.pp, &node.commitment, &values, &indices_to_proof);
        match proof {
            Ok(proof) => {
                let proof_node = ProofNode {
                    commitment: node.commitment,
                    proof,
                    indices: indices_to_proof,
                    values,
                };
                Ok(proof_node)
            }
            Err(_) => Err(VerkleTreeError::ProofGenerateError),
        }
    }

    // This function computes batch proofs, is also works if the NONE values are already deleted.
    pub fn batch_proof_verify (root: Commitment, mut tree_proofs: Vec<Option<ProofNode>>, width: usize, indices: Vec<usize>, depth: usize, data: Vec<Vec<u8>>) -> bool {
        assert!(tree_proofs[0].is_some());

        // Check if the root is correct
        if root != tree_proofs[0].as_ref().unwrap().commitment {
            println!("Root commitment is not correct");
            return false;
        }

        // Check if the proofs are of the correct size, also works if NONE values were already deleted
        tree_proofs.retain(|node| node.is_some());
        // The expected length
        let mut check_vector: Vec<Vec<usize>> = Self::create_index_for_proof(indices, width, depth);
        check_vector.retain(|vector| !vector.is_empty());
        if tree_proofs.len() != check_vector.len() {
            println!("The tree proofs vector is not of the correct length");
            return false;
        }
        // To find the commitment value easier, we dont save the ProofNodes but the commitments in the next vector
        let mut commitments_vector: Vec<Vec<u8>> = tree_proofs.iter().map(|proof_node|
            {
                let node = proof_node.as_ref().unwrap();
                Self::map_commitment_to_vec_u8(&node.commitment)
            }
        ).collect();
        data.iter().for_each(|d| commitments_vector.push(d.to_vec()));
        
        let (_, verifier_params) =
            paramgen_from_seed("This is our Favourite very very long Seed", 0, width).unwrap();
        tree_proofs.par_iter().all(|proof_node| {
            if let Some(node) = proof_node{
                let b1 = Proof::same_commit_batch_verify(&node.proof, &verifier_params, &node.commitment, &node.indices, &node.values);
                // For simplicity we check if there is a commitment that matches
                let b2 = node.values.par_iter().all(|point| {
                    commitments_vector.par_iter().any(|n| n == point)
                });
                b1 & b2
            }
            else {
                true
            }
        });
        true
    }


    pub fn verify_proof(root: Commitment, verkle_proof: &VerkleProof, width: usize) -> bool {
        if verkle_proof.proofs[0].commitment != root {
            return false;
        }
         let (_, verifier_params) =
            paramgen_from_seed("This is our Favourite very very long Seed", 0, width).unwrap();
        let verkle_proofs = verkle_proof.proofs.clone();
        for node in verkle_proofs {
            if !Proof::verify(&node.proof, &verifier_params, &node.commitment, &node.values[0], node.indices[0]){
                return  false;
            }
        }
        true
    }

    fn map_commitment_to_vec_u8(com: &Commitment) -> Vec<u8> {
        let mut old_commitment_bytes: Vec<u8> = vec![];
        com.serialize(&mut old_commitment_bytes, true).unwrap();
        old_commitment_bytes
        //Vec::new()
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

    pub fn root_commitment(&self) -> Option<Commitment> {
        // match &self.root {
        //     None => None,
        //     Some(verkle_node) => Some(verkle_node.commitment),
        // }
        self.root.as_ref().map(|verkle_node| verkle_node.commitment.clone())
    }
}

#[derive(Debug)]
pub enum VerkleTreeError {
    BuildError,
    ProofGenerateError,
    EmptyTree,
}
