
    // pub fn create_index_for_proof_old(index: Vec<usize>, width: usize, depth: usize, tree_proofs: &mut Vec<Vec<Vec<ProofNode>>>) -> Vec<Vec<Vec<usize>>> {

    //     /* This creates a vector of the form:
    //         [[[2, 0]], [[1, 2], [], [0]]] 
    //         It has lenght 2, this indicates that there are 2 layers in the tree
    //         The root is implicit indicated, on place 0 there is [[2,0]] which indicates that 
    //         children 0 and 2 of the root need to be proven.
    //         The next layer, there is [[1, 2], [], [0]] which indicates that
    //         for the first child [1,2] need to be proven, for the next child nothing needs to be proven
    //         and for the last child only index [0] needs to be proven.
    //      */
    //     let mut tree_path: Vec<Vec<Vec<usize>>>  = Vec::new();
    //     let mut indexes = index.clone();
    //     for level in 1.. (depth+1){
    //         let data_level_above = width.pow((depth+1-level) as u32);
    //         // This creates for each parent node an empty vector
    //         let mut level_above: Vec<Vec<usize>> = vec![vec![]; data_level_above];
    //         let level_above_proofs: Vec<Vec<ProofNode >>= vec![vec![]; data_level_above];
    //         let mut new_indices: HashSet<usize> = HashSet::new();
    //         /* The loop adds the index of the child that needs to be proven in the vector of the parent node
    //             This is done modulus the width of the tree. 
    //             Also the loop creates a vector for the indices of the parent node for the next layer*/
    //         for i in 0.. indexes.len(){
    //             level_above[indexes[i] / width].push(indexes[i]% width);
    //             new_indices.insert(indexes[i]/ width);
    //         }
    //         tree_path.push(level_above);
    //         tree_proofs.push(level_above_proofs);
    //         indexes = new_indices.into_iter().collect();
             
    //     }
    //     // We need to add the root manually
    //     let mut node_root: Vec<usize> = Vec::new();
    //     for child in 0.. width{
    //         if !tree_path[tree_path.len()-1][child].is_empty(){
    //             node_root.push(child);
    //         }
    //     }
    //     tree_path.push(vec![node_root]);
    //     tree_proofs.push(vec![vec![]]);
    //     tree_path.reverse();
    //     tree_proofs.reverse();
    //     //println!("tree proofs {:?}", tree_proofs);
    //     //(tree_path, tree_proofs)
    //     tree_path
    // }

    // #[recursive]
    // fn batch_proof_layer_vector(
    //     &self,
    //     current_node: VerkleNode,
    //     node_ind: usize,
    //     tree_path: Vec<Vec<Vec<usize>>>,
    //     data: &Vec<F>,
    //     tree_proofs: Arc<Vec<Vec<Mutex<Vec<ProofNode>>>>>)
    //     -> Result<ProofNode, VerkleTreeError> {
        
    //     /*  The three path contains information about what children to prove
    //         The first index contains info about the nodes to the right of the current node
    //         The next indices of the path contain information about the next layers
    //          */ 
    //     let index_to_prove: &Vec<usize> = &tree_path[0][node_ind];
    //     /*  The index of the current node in the layer can be found
    //         by the difference of the original length of the layer and the 
    //         current length of the layer. Together with the index of the node. 
    //     */
    //     let original_length_layer_0 = if tree_path.len() > 1 {
    //         tree_path[1].len() / self.width
    //     } else {
    //         data.len() / self.width
    //     };
    //     let new = tree_path[0].len();
    //     let index_node_in_layer = original_length_layer_0 - new + node_ind;
    //     let index_first_child = index_node_in_layer * self.width;

    //     // Use a thread-local vector to avoid lock contention
    //     let mut local_points = Vec::new();

    //     /* If the node has children we continue down the tree,
    //     if the node has no children we go to the leaf case */
    //     if let Some(children) = current_node.children {
    //         // Parallelize processing of child nodes
    //         scope(|s| {
    //             for &ind in index_to_prove {
    //                 let next_node = children[ind].clone();
    //                 //println!("In layer vector");
    //                 let next_node_commitment = Self::map_commitment_to_field(&next_node.commitment);
                    
    //                 // We need to proof the children later, so add them to points
    //                 local_points.push((F::from(ind as u32), next_node_commitment));
    //                 /* We need to proof some children of the children nodes as well.
    //                 They are in the next layer, so we pop the first element. */
    //                 let mut tree_path_next_layer: Vec<Vec<Vec<usize>>> = tree_path[1..].to_vec();
    //                 /* The first vector of the next layer starts at the beginning of the tree.
    //                     We want it to start at the index we are interested in */
    //                 tree_path_next_layer[0] = tree_path_next_layer[0][index_first_child..].to_vec();
    //                 let tree_proofs_clone = Arc::clone(&tree_proofs);
    //                 s.spawn(move |_| {
    //                     self.batch_proof_layer_vector(
    //                         next_node, ind, tree_path_next_layer, data, tree_proofs_clone
    //                     ).expect("failed tree");
    //                 });
    //             }
    //         });
    //     } else {
    //         // Leaf case: process leaf proofs in parallel
    //         local_points.extend(
    //             index_to_prove
    //                 .par_iter()
    //                 .map(|ind| {
    //                     // The index of data
    //                     let index_data = index_first_child + ind;
    //                     // The point we need to prove
    //                     (F::from(*ind as u32), data[index_data])
    //                 })
    //                 .collect::<Vec<_>>(),
    //         );
    //     }

    //     let current_polynomial = current_node.polynomial.clone();
    //     let proof = self.kzg.generate_proof(&current_polynomial, &local_points);
    //     let current_commitment = current_node.commitment.clone();

    //     if let Ok(proof) = proof {
    //         let proof_node = ProofNode {
    //             commitment: current_commitment,
    //             proof,
    //             point: local_points,
    //         };

    //         // Update tree_proofs safely in parallel
    //         let mut locked_slot = tree_proofs[self.depth() - (tree_path.len() - 1)][index_node_in_layer].lock().unwrap();
    //         locked_slot.push(proof_node.clone());

    //         // let mut locked_tree_proofs = tree_proofs.lock().unwrap();
    //         // locked_tree_proofs[self.depth() - (tree_path.len() - 1)][index_node_in_layer].push(proof_node.clone());

    //         return Ok(proof_node);
    //     } else {
    //         return Err(VerkleTreeError::ProofGenerateError);
    //     }
    // }

    // pub fn generate_batch_proof_old (&self, index: Vec<usize>, data: &Vec<F>) -> Vec<Vec<Vec<ProofNode>>> {
    //     //println!("depth {}", depth);
    //     assert!(data.len() % self.width == 0, "Please give a tree that is compeletly filled, i.e. log_{{width}}(data) is a natural number");

    //     let mut tree_proofs: Vec<Vec<Vec<ProofNode>>>  = Vec::new();
    //     let tree_path: Vec<Vec<Vec<usize>>> = Self::create_index_for_proof_old(index, self.width, self.depth(), &mut tree_proofs);

    //     // To make the recursive function work on multiple threads we need an Arc structure
    //     let tree_proofs_arc: Arc<Vec<Vec<Mutex<Vec<ProofNode>>>>> = Arc::new(
    //         tree_proofs
    //             .into_iter()
    //             .map(|layer| {
    //                 layer
    //                     .into_iter()
    //                     .map(|slot| Mutex::new(slot)) // Wrap each slot in a Mutex
    //                     .collect()
    //             })
    //             .collect()
    //     );
        
    //     let current_node = self.root.clone().unwrap();
    //     self.batch_proof_layer_vector(current_node, 0, tree_path, data, tree_proofs_arc.clone()).expect("failed to make batch proof");
    //     // We unwrap the proofs to a vector for further processing
    //     let tree_proofs_vector: Vec<Vec<Vec<ProofNode>>> = tree_proofs_arc
    //     .iter()
    //     .map(|layer| {
    //         layer
    //             .iter()
    //             .map(|slot| slot.lock().unwrap().clone()) // Lock each slot and clone the inner Vec<ProofNode>
    //             .collect()
    //     })
    //     .collect();
    //     tree_proofs_vector
    // }
 


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
/*
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

 */


THE FOLLOWING CODE IS NON ParallelizeD TREE CREATION

    // fn create_leaf_nodes(kzg: &KZGCommitment, datas: &Vec<F>, width: usize) -> Vec<VerkleNode> {
    //     datas
    //         .chunks(width)
    //         .map(|chunk| {
    //             let polynomial = KZGCommitment::vector_to_polynomial(&chunk.to_vec());
    //             let commitment = kzg.commit_polynomial(&polynomial);
    //             VerkleNode {
    //                 commitment,
    //                 polynomial,
    //                 children: None,
    //             }
    //         })
    //         .collect()
    // }

    // fn build_from_nodes(
    //     kzg: &KZGCommitment,
    //     nodes: &Vec<VerkleNode>,
    //     width: usize,
    // ) -> Vec<VerkleNode> {
    //     nodes
    //         .chunks(width)
    //         .map(|chunk| {
    //             let vector_commitment_mapping = chunk
    //                 .into_iter()
    //                 .map(|node| Self::map_commitment_to_field(&node.commitment))
    //                 .collect();
    //             let polynomial = KZGCommitment::vector_to_polynomial(&vector_commitment_mapping);
    //             let commitment = kzg.commit_polynomial(&polynomial);
    //             VerkleNode {
    //                 commitment,
    //                 polynomial,
    //                 children: Some(chunk.to_vec()),
    //             }
    //         })
    //         .collect()
    // }
