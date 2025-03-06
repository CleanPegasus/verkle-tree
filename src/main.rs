use std::time::Instant;

use std::fs::OpenOptions;
use std::io::Write;

use verkle_tree::VerkleTree;
use ark_bls12_381::Fr as F;
use rand::Rng;
use rand::prelude::*;


fn test_batch_proof_verify(datas: Vec<F>, width: usize, filename : String) {


    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true) // Clears previous content
        .open(filename)
        .expect("Failed to open file");
   // writeln!(file, "All times in seconds, If I want miliseconds just do times 1000 and then truncate to 3").expect("Failed to write header");
    writeln!(file, "{:<15} {:<15} {:<15} {:<15} {:<15}", "batch proof", "batch verify", "batch ver slow",  "Proof single", "Verify single").expect("Failed to write header");

    let tree = VerkleTree::new(&datas, width).unwrap();

    //println!("datas len {}", datas.len());
    let indices: Vec<usize> = (0..=(datas.len()-1) as usize).choose_multiple(&mut thread_rng(),(datas.len() as f64 *(0.2))as usize); 
    //println!("indices length {}", indices.len());
    let startproof = Instant::now();
    let proof = tree.generate_batch_proof(indices.clone(), &datas);
    let endproof= startproof.elapsed();
    
    let root = VerkleTree::root_commitment(&tree).unwrap();
    
    let startverify = Instant::now();
    let verification = VerkleTree::verify_batch_proof(root, proof.clone(), width);
    let endverify= startverify.elapsed();

    let startverify_clas = Instant::now();
    let verification = VerkleTree::batch_verify_classic(root, proof, width);
    let endverify_clas= startverify_clas.elapsed();

    //println!("Then the single proof");
    let startproof_single = Instant::now();
    let mut all_proofs = Vec::new();
    for ind in indices{
        all_proofs.push(tree.generate_proof(ind, &datas[ind]).unwrap());
    }
    let endproof_single= startproof_single.elapsed();

    let root = VerkleTree::root_commitment(&tree).unwrap();

    let startverify_sing = Instant::now();
    for proof in all_proofs{
        let verification = VerkleTree::verify_proof(root, &proof, width);
    }
    let endverify_sing= startverify_sing.elapsed();

    writeln!(file, "{:<15.3?} {:<15.3?} {:<15.3?} {:<15.3?} {:<15.3?}", endproof, endverify, endverify_clas, endproof_single, endverify_sing).expect("Failed to write values");
}

fn main (){
    println!("Hello world");

    for i in 0..1 {
        let mut datas: Vec<F> = Vec::new();
        let width: usize = 5;
        for i in 0..i32::pow(width as i32, 5){
            datas.push(F::from(rand::thread_rng().gen_range(0..=datas.len()*datas.len()) as u32));
        }
        test_batch_proof_verify(datas, width, "test".to_string());
    }

    
}