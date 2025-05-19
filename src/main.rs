use std::time::Instant;

use std::fs::OpenOptions;
use std::io::Write;

use ark_bls12_381::Fr as F;
use rand::Rng;
use rand::prelude::*;
use verkle_tree::*;
mod verkle_tree_point;
use verkle_tree_point::{VerkleTree as VerkleTree_point};


fn test_batch_proof_verify(datas: Vec<F>, filename : String) {


    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true) // Clears previous content
        .open(filename)
        .expect("Failed to open file");
    writeln!(file, "{:<5} {:15} {:<15} {:<15} {:<15}", "width", "build tree", "batch proof", "batch verify", "total").expect("Failed to write header");

    //for width in [8]{
    let width = 8;

    let starttree = Instant::now();
        let tree = VerkleTree::new(&datas, width).unwrap();
    let endtree = starttree.elapsed();
    let depth = tree.depth();
    //println!("lets try {}", datas.len().ilog(width) -1 );
    //println!("depth = {}", depth);
    // //println!("datas len {}", datas.len());
    let indices: Vec<usize> = (0..=(datas.len()-1) )
        .choose_multiple(&mut thread_rng(),(datas.len() as f64 *(0.2))as usize);
        //.choose_multiple(&mut thread_rng(),2_usize);
    //println!("indices = {:?}", indices);

    let startproof = Instant::now();
    let proof = tree.generate_batch_proof(indices.clone(), &datas);
    let endproof= startproof.elapsed();
    println!("total proof time {:?}", endproof);

    let root = VerkleTree::root_commitment(&tree).unwrap();

    let mut datas_verify = Vec::new();
    for i in indices.clone() {
        datas_verify.push(datas[i]);
    }


    let startverify = Instant::now();
    let b = VerkleTree::batch_proof_verify(root, proof.clone(), width, indices, depth, datas_verify);
    let endverify= startverify.elapsed();

    writeln!(file, "{:<5} {:<15.1?} {:<15.1?} {:<15.1?} {:<15.1?}", width, endtree, endproof, endverify, endtree + endproof+endverify).expect("Failed to write values");
    println!("b {}", b);
    //}

}



fn test_batch_point_proof_verify(datas: Vec<Vec<u8>>, filename : String) {


    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true) // Clears previous content
        .open(filename)
        .expect("Failed to open file");
    writeln!(file, "{:<5} {:15} {:<15} {:<15} {:<15}", "width", "build tree", "batch proof", "batch verify", "total").expect("Failed to write header");

    //for width in [8]{
    let width = 8;

    let starttree = Instant::now();
        let tree = VerkleTree_point::new(&datas, width).unwrap();
    let endtree = starttree.elapsed();
    let depth = tree.depth();
    //println!("lets try {}", datas.len().ilog(width) -1 );
    //println!("depth = {}", depth);
    // //println!("datas len {}", datas.len());
    let indices: Vec<usize> = (0..=(datas.len()-1) )
        .choose_multiple(&mut thread_rng(),(datas.len() as f64 *(0.2))as usize);
        //.choose_multiple(&mut thread_rng(),1_usize);
    //println!("indices = {:?}", indices);

    let startproof = Instant::now();
    let proof = tree.generate_batch_proof(indices.clone(), &datas);
    let endproof= startproof.elapsed();
    println!("total proof time {:?}", endproof);

    let root = VerkleTree_point::root_commitment(&tree).unwrap();

    let mut datas_verify: Vec<Vec<u8>> = Vec::new();
    for i in indices.clone() {
        datas_verify.push(datas[i].clone());
    }


    let startverify = Instant::now();
    let b = VerkleTree_point::batch_proof_verify(root, proof.clone(), width, indices, depth, datas_verify);
    let endverify= startverify.elapsed();

    writeln!(file, "{:<5} {:<15.1?} {:<15.1?} {:<15.1?} {:<15.1?}", width, endtree, endproof, endverify, endtree + endproof+endverify).expect("Failed to write values");
    println!("b {}", b);
    //}

}


fn main (){
    println!("Hello world");
    let mut datas: Vec<F> = Vec::new();
    let mut datas_point: Vec<Vec<u8>> =Vec::new();

    for _i in 0.. 4096{
        let v = rand::thread_rng().gen_range(0..=4096*4096) as u8;
        datas.push(F::from(v));
        datas_point.push(vec![v]);
    }
    println!("data length {}", datas.len());
    test_batch_proof_verify(datas.clone(), "test_compare".to_string());

    println!("now point proofs");
    test_batch_point_proof_verify(datas_point, "test_compare_point".to_string());


}