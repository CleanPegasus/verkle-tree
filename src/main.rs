use std::time::Instant;

use std::fs::OpenOptions;
use std::io::Write;

use ark_bls12_381::G1Affine;
use kzg_commitment::KZGCommitment;
use verkle_tree::ProofNode;
use verkle_tree::VerkleTree;
use ark_bls12_381::Fr as F;
use rand::Rng;
use rand::prelude::*;


fn test_batch_proof_verify(datas: Vec<F>, filename : String) {


    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true) // Clears previous content
        .open(filename)
        .expect("Failed to open file");
    writeln!(file, "{:<5} {:15} {:<15} {:<15} {:<15}", "width", "tree time", "batch proof", "batch verify", "total").expect("Failed to write header");

    for width in vec![2,4,8,16,64]{

        println!("start build tree");
    let starttree = Instant::now();
        let tree = VerkleTree::new(&datas, width).unwrap();
    let endtree = starttree.elapsed();

    // //println!("datas len {}", datas.len());
    let indices: Vec<usize> = (0..=(datas.len()-1) as usize)
        .choose_multiple(&mut thread_rng(),(datas.len() as f64 *(0.2))as usize);

        println!("start proof");
    let startproof = Instant::now();
    let proof = tree.generate_batch_proof(indices.clone(), &datas);
    let endproof= startproof.elapsed();

    let root = VerkleTree::root_commitment(&tree).unwrap();

        println!("start verify");
    let startverify = Instant::now();
    VerkleTree::batch_proof_verify(root, proof.clone(), width);
    let endverify= startverify.elapsed();

    writeln!(file, "{:<5} {:<15.1?} {:<15.1?} {:<15.1?} {:<15.1?}", width, endtree, endproof, endverify, endtree + endproof+endverify).expect("Failed to write values");
    }

}


fn main (){
    println!("Hello world");

    let mut file = OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true) // Clears previous content
    .open("data")
    .expect("Failed to open file");
   
    
    let mut datas: Vec<F> = Vec::new();

    //let width: usize = 2;
    //for _i in 0..i32::pow(width as i32, 12){
    // for _i in 0.. 4096{
    //     let value = F::from(rand::thread_rng().gen_range(0..=4096*4096) as u32); 
    //     datas.push(value);
    //     writeln!(file, "value = {:?}", value).expect("something went wrong");
    // }

    for _i in 0.. 4096{
        let value = F::from(rand::thread_rng().gen_range(0..=4096*4096) as u32); 
        datas.push(value);
        writeln!(file, "value = {:?}", value).expect("something went wrong");
    }
    println!("data length {}", datas.len());
    //let tree = VerkleTree::new(&datas, width).unwrap();
    //println!("{:?}",VerkleTree::create_index_for_proof(vec![12,15,16,25], 3, 2));
//     let batch_proof = VerkleTree::generate_batch_proof(&tree, vec![1,2,6, 12,15,16,25], &datas);
//     println!("Finished batch proof");
    test_batch_proof_verify(datas.clone(), "test_compare".to_string());
//     let verify = VerkleTree::batch_proof_verify(tree.root_commitment().unwrap(), batch_proof, width);
//     println!("Finised verify {:?}", verify);
    //println!("{:?}", VerkleTree::generate_batch_proof_old(&tree, vec![1,3,6,7,11,12], &datas));
    //let mut tree_proofs: Vec<Vec<Vec<ProofNode>>>  = Vec::new();
    //println!("index: {:?}", VerkleTree::create_index_for_proof(vec![1,3,6,7,12], width, tree.depth(), &mut tree_proofs));
    //let batch_proofs = VerkleTree::generate_batch_proof_old(&tree, vec![1,3,6,7,12], &datas);
    // println!("proofs: {:?}", batch_proofs);
    // println!("is correct {}",VerkleTree::verify_batch_proof_old(tree.root_commitment().unwrap(), batch_proofs, width));
}