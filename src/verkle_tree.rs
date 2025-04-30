use std::{collections::HashSet, time::Instant, vec};

use ark_bls12_381::{Fr as F, G1Affine};
//use ark_ec::bls12::G1Affine;
use ark_ec::AffineRepr;
use ark_poly::univariate::DensePolynomial;
use kzg_commitment::KZGCommitment;

use ark_ff::PrimeField;
use kzg_commitment::ProofError;
use num_bigint::BigUint;

use rand::seq::index;
use recursive::recursive;

use rayon::prelude::*;
use rayon::scope;
//use rayon::ThreadPoolBuilder;
use std::sync::{Arc, Mutex};

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
    pub fn new(datas: &Vec<F>, width: usize) -> Result<Self, VerkleTreeError> {
        let kzg = KZGCommitment::new(width);
        Self::build_tree(kzg, datas, width)
    }

    fn build_tree(kzg: KZGCommitment, datas: &Vec<F>, width: usize) -> Result<VerkleTree, VerkleTreeError> {
        if datas.len() == 0 {
          return Err(VerkleTreeError::BuildError);
        }
        if datas.len() <= width {
            let polynomial = KZGCommitment::vector_to_polynomial(datas);
            let commitment = kzg.commit_polynomial(&polynomial);
            return Ok(VerkleTree {
                root: Some(VerkleNode {
                    commitment,
                    polynomial,
                    children: None,
                }),
                width,
                kzg,
            });
        }
        let leaf_nodes = Self::create_leaf_nodes(&kzg, datas, width);
        // for i in 0.. leaf_nodes.len(){
        //     println!("leaf node {} of build_tree {:?}", i, leaf_nodes[i]);
        // }
        let root = Self::build_tree_recursively(&kzg, &leaf_nodes, width);

        Ok(VerkleTree {
            root: Some(root),
            width,
            kzg,
        })
    }

    fn create_leaf_nodes(kzg: &KZGCommitment, datas: &Vec<F>, width: usize) -> Vec<VerkleNode> {
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
        for (i, &_node_position) in node_positions.iter().enumerate() {
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


    pub fn generate_batch_proof (&self, index: Vec<usize>, data: &Vec<F>) -> Vec<Option<ProofNode>> {
        assert!(data.len() % self.width == 0, "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");
        assert!(index.len() !=0, "Please give a non empty index");
        let width = self.width;
        let depth = self.depth();
        let index_for_proof = VerkleTree::create_index_for_proof(index, width, self.depth());
        
        let proofs: Vec<Option<ProofNode>> = (0.. index_for_proof.len()).into_par_iter().map(|ind| {
            if index_for_proof[ind]!= vec![]  {
                let path = Self::path_to_child(ind, width);

                let node: VerkleNode = Self::find_commitment_node(&self, path);
                let index_first_child: usize; 
                if node.children.is_none(){
                    let index_first_child_data = usize::pow(width, (depth+1).try_into().unwrap())/(width-1);
                    let index_first_child_node = width*ind +1;
                    index_first_child = index_first_child_node-index_first_child_data;
                }
                else {
                    index_first_child = width*ind +1;
                }
        
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
        //println!("{}", index);
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
            It has lenght 2, this indicates that there are 2 layers in the tree
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
            for parent in 0.. level_above.len(){
                tree_path.push(level_above[parent].clone());
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
        //println!("current node of rind commitment node should be the root {:?}", current_node);
        for i in path {
            current_node = current_node.children.expect("failed to find children")[i].clone();
        }
        current_node
    }

    fn find_proof_node (&self, node: VerkleNode, indices_to_proof: Vec<usize>, data: &Vec<F>, index_first_child: usize) ->  Result<ProofNode, VerkleTreeError>  {
        let mut points = Vec::new();
        if  node.children.is_some() {
            //let mut points = Vec::new();
            for ind in indices_to_proof.iter() {
                let child_commitment = Self::map_commitment_to_field(&node.children.clone().unwrap()[*ind].commitment);
                points.push((F::from(*ind as u32),child_commitment));
            }
        }
        else {
            for ind in indices_to_proof.iter() {
                points.push((F::from(*ind as u32), data[index_first_child + ind]));
            }
        }

        let proof: Result<G1Affine, ProofError> = self.kzg.generate_proof(&node.polynomial, &points);
        
        match proof {
            Ok(proof) => {
                let proof_node = ProofNode {
                    commitment: node.commitment,
                    proof: proof,
                    point: points,
                };
                return Ok(proof_node);
            }
            Err(_) => return Err(VerkleTreeError::ProofGenerateError),
        }
    }

    pub fn batch_proof_verify (root: G1Affine, tree_proofs: Vec<Option<ProofNode>>, width: usize) -> bool {
        if tree_proofs[0].is_none(){
            println!("Tree element is None");
            return false;
        }
        else if root != tree_proofs[0].as_ref().unwrap().commitment {
            println!("Root commitment is not correct");
            return false;
        }
        // .all makes it such that if any verification fails, it stops immediately and returns false
        let kzg = KZGCommitment::new(width + 1);
        //let _ = Instant::now();
        tree_proofs.par_iter().all(|proof_node| {
            if let Some(node) = proof_node{
                kzg.verify_proof(&node.commitment, &node.point, &node.proof)
            }
            else {
                true
            }
        });
        //println!("end verify {:0.3?}", startverify.elapsed());
        true
    }


    pub fn create_index_for_proof_old(index: Vec<usize>, width: usize, depth: usize, tree_proofs: &mut Vec<Vec<Vec<ProofNode>>>) -> Vec<Vec<Vec<usize>>> {

        /* This creates a vector of the form:
            [[[2, 0]], [[1, 2], [], [0]]] 
            It has lenght 2, this indicates that there are 2 layers in the tree
            The root is implicit indicated, on place 0 there is [[2,0]] which indicates that 
            children 0 and 2 of the root need to be proven.
            The next layer, there is [[1, 2], [], [0]] which indicates that
            for the first child [1,2] need to be proven, for the next child nothing needs to be proven
            and for the last child only index [0] needs to be proven.
         */
        let mut tree_path: Vec<Vec<Vec<usize>>>  = Vec::new();
        let mut indexes = index.clone();
        for level in 1.. (depth+1){
            let data_level_above = width.pow((depth+1-level) as u32);
            // This creates for each parent node an empty vector
            let mut level_above: Vec<Vec<usize>> = vec![vec![]; data_level_above];
            let level_above_proofs: Vec<Vec<ProofNode >>= vec![vec![]; data_level_above];
            let mut new_indices: HashSet<usize> = HashSet::new();
            /* The loop adds the index of the child that needs to be proven in the vector of the parent node
                This is done modulus the width of the tree. 
                Also the loop creates a vector for the indices of the parent node for the next layer*/
            for i in 0.. indexes.len(){
                level_above[indexes[i] / width].push(indexes[i]% width);
                new_indices.insert(indexes[i]/ width);
            }
            tree_path.push(level_above);
            tree_proofs.push(level_above_proofs);
            indexes = new_indices.into_iter().collect();
             
        }
        // We need to add the root manually
        let mut node_root: Vec<usize> = Vec::new();
        for child in 0.. width{
            if !tree_path[tree_path.len()-1][child].is_empty(){
                node_root.push(child);
            }
        }
        tree_path.push(vec![node_root]);
        tree_proofs.push(vec![vec![]]);
        tree_path.reverse();
        tree_proofs.reverse();
        //println!("tree proofs {:?}", tree_proofs);
        //(tree_path, tree_proofs)
        tree_path
    }

    #[recursive]
    fn batch_proof_layer_vector(
        &self,
        current_node: VerkleNode,
        node_ind: usize,
        tree_path: Vec<Vec<Vec<usize>>>,
        data: &Vec<F>,
        tree_proofs: Arc<Vec<Vec<Mutex<Vec<ProofNode>>>>>)
        -> Result<ProofNode, VerkleTreeError> {
        
        /*  The three path contains information about what children to prove
            The first index contains info about the nodes to the right of the current node
            The next indices of the path contain information about the next layers
             */ 
        let index_to_prove: &Vec<usize> = &tree_path[0][node_ind];
        /*  The index of the current node in the layer can be found
            by the difference of the original length of the layer and the 
            current length of the layer. Together with the index of the node. 
        */
        let original_length_layer_0 = if tree_path.len() > 1 {
            tree_path[1].len() / self.width
        } else {
            data.len() / self.width
        };
        let new = tree_path[0].len();
        let index_node_in_layer = original_length_layer_0 - new + node_ind;
        let index_first_child = index_node_in_layer * self.width;

        // Use a thread-local vector to avoid lock contention
        let mut local_points = Vec::new();

        /* If the node has children we continue down the tree,
        if the node has no children we go to the leaf case */
        if let Some(children) = current_node.children {
            // Parallelize processing of child nodes
            scope(|s| {
                for &ind in index_to_prove {
                    let next_node = children[ind].clone();
                    let next_node_commitment = Self::map_commitment_to_field(&next_node.commitment);
                    
                    // We need to proof the children later, so add them to points
                    local_points.push((F::from(ind as u32), next_node_commitment));
                    /* We need to proof some children of the children nodes as well.
                    They are in the next layer, so we pop the first element. */
                    let mut tree_path_next_layer: Vec<Vec<Vec<usize>>> = tree_path[1..].to_vec();
                    /* The first vector of the next layer starts at the beginning of the tree.
                        We want it to start at the index we are interested in */
                    tree_path_next_layer[0] = tree_path_next_layer[0][index_first_child..].to_vec();
                    let tree_proofs_clone = Arc::clone(&tree_proofs);
                    s.spawn(move |_| {
                        self.batch_proof_layer_vector(
                            next_node, ind, tree_path_next_layer, data, tree_proofs_clone
                        ).expect("failed tree");
                    });
                }
            });
        } else {
            // Leaf case: process leaf proofs in parallel
            local_points.extend(
                index_to_prove
                    .par_iter()
                    .map(|ind| {
                        // The index of data
                        let index_data = index_first_child + ind;
                        // The point we need to prove
                        (F::from(*ind as u32), data[index_data])
                    })
                    .collect::<Vec<_>>(),
            );
        }

        let current_polynomial = current_node.polynomial.clone();
        let proof = self.kzg.generate_proof(&current_polynomial, &local_points);
        let current_commitment = current_node.commitment.clone();

        if let Ok(proof) = proof {
            let proof_node = ProofNode {
                commitment: current_commitment,
                proof,
                point: local_points,
            };

            // Update tree_proofs safely in parallel
            let mut locked_slot = tree_proofs[self.depth() - (tree_path.len() - 1)][index_node_in_layer].lock().unwrap();
            locked_slot.push(proof_node.clone());

            // let mut locked_tree_proofs = tree_proofs.lock().unwrap();
            // locked_tree_proofs[self.depth() - (tree_path.len() - 1)][index_node_in_layer].push(proof_node.clone());

            return Ok(proof_node);
        } else {
            return Err(VerkleTreeError::ProofGenerateError);
        }
    }

    pub fn generate_batch_proof_old (&self, index: Vec<usize>, data: &Vec<F>) -> Vec<Vec<Vec<ProofNode>>> {
        //println!("depth {}", depth);
        assert!(data.len() % self.width == 0, "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");

        let mut tree_proofs: Vec<Vec<Vec<ProofNode>>>  = Vec::new();
        let tree_path: Vec<Vec<Vec<usize>>> = Self::create_index_for_proof_old(index, self.width, self.depth(), &mut tree_proofs);

        // To make the recursive function work on multiple threads we need an Arc structure
        let tree_proofs_arc: Arc<Vec<Vec<Mutex<Vec<ProofNode>>>>> = Arc::new(
            tree_proofs
                .into_iter()
                .map(|layer| {
                    layer
                        .into_iter()
                        .map(|slot| Mutex::new(slot)) // Wrap each slot in a Mutex
                        .collect()
                })
                .collect()
        );
        
        let current_node = self.root.clone().unwrap();
        self.batch_proof_layer_vector(current_node, 0, tree_path, data, tree_proofs_arc.clone()).expect("failed to make batch proof");
        // We unwrap the proofs to a vector for further processing
        let tree_proofs_vector: Vec<Vec<Vec<ProofNode>>> = tree_proofs_arc
        .iter()
        .map(|layer| {
            layer
                .iter()
                .map(|slot| slot.lock().unwrap().clone()) // Lock each slot and clone the inner Vec<ProofNode>
                .collect()
        })
        .collect();
        tree_proofs_vector
    }
 


    // pub fn generate_batch_proof_april_layer(&self, index: Vec<usize>, data: &Vec<F>) -> Vec<Vec<Vec<ProofNode>>> {
    //     assert!(data.len() % self.width == 0, "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");

    //     let mut tree_proofs: Vec<Vec<Vec<ProofNode>>>  = Vec::new();
    //     let mut collect: Vec<Vec<usize>> = vec![vec![]; data.len() / self.width];
    //     for ind in index {
    //         collect[ind/ self.width].push(ind % self.width);
    //     }
    //     println!("{:?}", collect);

    //     for node in 0 .. collect.len() {
            
    //     }
    //     tree_proofs
    // }

    // fn proof_per_current_node (&self, current_node: &VerkleNode, node_to_prove_position: &Vec<usize>, data: &Vec<F>) -> 
    //     Result<ProofNode, VerkleTreeError>{
    //     let mut points: Vec<(F, F)> = Vec::new();
    //     let current_polynomial = current_node.polynomial.clone();
    //     if let Some(children) = &current_node.children {
    //         for ind in node_to_prove_position {
    //             points.push( (F::from(*ind as u32), Self::map_commitment_to_field(&children[*ind].commitment)) );
    //         }
    //     } else {
    //         let mut points = Vec::new();
    //         for ind in node_to_prove_position {
    //             points.push( (F::from(*ind as u32), data[*ind]) );
    //         }
    //     };

    //     let proof= self.kzg.generate_proof(&current_polynomial, &points);
    //     if let Ok(proof) = proof {
    //         let proof_node = ProofNode {
    //             commitment: current_node.commitment,
    //             proof,
    //             point: points,
    //         };
    //         return Ok(proof_node);
    //     } else {
    //         return Err(VerkleTreeError::ProofGenerateError);
    //     }
    //     // (current_node.clone(), points, proof)
    //     //commitment is current_node
    //     // points are points
    // }

    // #[recursive]
    // fn invoke_proof_per_current_node (&self, current_node: VerkleNode, ind1:usize, ind2:usize, tree_path:&Vec<Vec<Vec<usize>>>, tree_kzg_proofs: &mut Vec<Vec<Vec<ProofNode>>>, data: &Vec<F>) {
    //     let node_to_prove_position: &Vec<usize> = &tree_path[ind1][ind2];
    //     let index_first_child: usize = ind1*self.width;
    //     // if let Some(children) = current_node.children {
    //     //     for ind in node_to_prove_position {
    //     //         let index_child_1: usize = ind1+1;
    //     //         let index_child_2: usize = index_first_child + *ind;
    //     //         let proof:Result<ProofNode, VerkleTreeError> = self.proof_per_current_node(&children[*ind], &tree_path[index_child_1.clone()][index_child_2.clone()], data );
    //     //         //tree_kzg_proofs[index_child_1.clone()][index_child_2.clone()]= vec![proof.expect("proof of child went wrong")];
    //     //         tree_kzg_proofs[index_child_1.clone()][index_child_2.clone()].push(proof.expect("proof of child went wrong"));
    //     //         self.invoke_proof_per_current_node(children[*ind].clone(), index_child_1, index_child_2, tree_path, tree_kzg_proofs, data);
    //     //     }
    //     // }
    //     //let children = current_node.children;
    //     if let Some(children) = current_node.children {
    //         node_to_prove_position.par_iter().map( |ind| {
    //             let index_child_1: usize = ind1+1;
    //             let index_child_2: usize = index_first_child + *ind;
    //             let proof:Result<ProofNode, VerkleTreeError> = self.proof_per_current_node(&children[*ind], &tree_path[index_child_1.clone()][index_child_2.clone()], data );
    //             //tree_kzg_proofs[index_child_1.clone()][index_child_2.clone()]= vec![proof.expect("proof of child went wrong")];
    //             tree_kzg_proofs[index_child_1.clone()][index_child_2.clone()].push(proof.expect("proof of child went wrong"));
    //             self.invoke_proof_per_current_node(children[*ind].clone(), index_child_1, index_child_2, tree_path, tree_kzg_proofs, data);
    //         }
    //         ).collect()
    //     }
    // }

    // pub fn generate_batch_proof_april(&self, index: Vec<usize>, data: &Vec<F>) -> Vec<Vec<Vec<ProofNode>>> {
    //     assert!(data.len() % self.width == 0, "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");

    //     let mut tree_kzg_proofs: Vec<Vec<Vec<ProofNode >>>  = Vec::new();
    //     let tree_path: Vec<Vec<Vec<usize>>> = Self::create_index_for_proof(index, self.width, self.depth(), &mut tree_kzg_proofs);

    //     let proof:ProofNode  = self.proof_per_current_node(&self.root.as_ref().unwrap(), &tree_path[0][0], data).expect("failed to create proof");
    //     tree_kzg_proofs[0][0].push(proof);
    //     self.invoke_proof_per_current_node(self.root.clone().unwrap(), 0, 0, &tree_path, &mut tree_kzg_proofs, data);

    //     tree_kzg_proofs.to_vec()
    // }

    // pub fn verify_batch_proof_april(root: G1Affine, tree_proofs: Vec<Vec<Vec<ProofNode >>>, width: usize) -> bool {
    //     if root != tree_proofs[0][0][0].commitment {
    //         return false;
    //     }
    //     // .all makes it such that if any verification fails, it stops immediately and returns false
    //     let kzg = KZGCommitment::new(width + 1);
    //     let _ = Instant::now();
    //     tree_proofs.par_iter().all(|layer| {
    //         layer.par_iter().all(|node| {
    //             node.par_iter().all(|proof| {
    //                 kzg.verify_proof(&proof.commitment, &proof.point, &proof.proof)
    //             })
    //         })
    //     });
    //     //println!("end verify {:0.3?}", startverify.elapsed());
    //     true
    // }


    pub fn verify_proof(root: G1Affine, verkle_proof: &VerkleProof, width: usize) -> bool {
        let proof_root = verkle_proof.proofs[0].commitment;
        if proof_root != root {
            return false;
        }
        let kzg = KZGCommitment::new(width+1);
        let verkle_proofs = verkle_proof.proofs.clone();
        for proof in verkle_proofs {
            if !kzg.verify_proof(&proof.commitment, &proof.point, &proof.proof){
                return  false;
            }
        }
        true
    }

    pub fn verify_batch_proof_old(root: G1Affine, tree_proofs: Vec<Vec<Vec<ProofNode>>>, width: usize) -> bool {
        if root != tree_proofs[0][0][0].commitment {
            return false;
        }
        // .all makes it such that if any verification fails, it stops immediately and returns false
        let kzg = KZGCommitment::new(width + 1);
        let _ = Instant::now();
        tree_proofs.par_iter().all(|layer| {
            layer.par_iter().all(|node| {
                node.par_iter().all(|proof| {
                    kzg.verify_proof(&proof.commitment, &proof.point, &proof.proof)
                })
            })
        });
        //println!("end verify {:0.3?}", startverify.elapsed());
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
