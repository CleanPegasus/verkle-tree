use std::time::Instant;

use std::fs::OpenOptions;
use std::io::Write;

use ark_bls12_381::Fr as F;
use rand::Rng;
use rand::prelude::*;
use verkle_tree::*;


fn test_batch_proof_verify(datas: Vec<F>, filename : String) {


    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true) // Clears previous content
        .open(filename)
        .expect("Failed to open file");
    writeln!(file, "{:<5} {:15} {:<15} {:<15} {:<15}", "width", "build tree", "batch proof", "batch verify", "total").expect("Failed to write header");

    //for width in [8]{
    let width = 3;

    let starttree = Instant::now();
        let tree = VerkleTree::new(&datas, width).unwrap();
    let endtree = starttree.elapsed();
    let depth = tree.depth();
    println!("lets try {}", datas.len().ilog(width) -1 );
    println!("depth = {}", depth);
    // //println!("datas len {}", datas.len());
    let indices: Vec<usize> = (0..=(datas.len()-1) )
        //.choose_multiple(&mut thread_rng(),(datas.len() as f64 *(0.2))as usize);
        .choose_multiple(&mut thread_rng(),(2)as usize);
    println!("indices = {:?}", indices);

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
    let b = VerkleTree::batch_proof_verify(root, proof.clone(), width, indices, depth, &datas_verify);
    let endverify= startverify.elapsed();

    writeln!(file, "{:<5} {:<15.1?} {:<15.1?} {:<15.1?} {:<15.1?}", width, endtree, endproof, endverify, endtree + endproof+endverify).expect("Failed to write values");
    println!("b {}", b);
    //}

}


fn main (){
    println!("Hello world");
    let mut datas: Vec<F> = Vec::new();

    for _i in 0.. 27{
        let value = F::from(rand::thread_rng().gen_range(0..=4096*4096) as u32); 
        datas.push(value);
    }
    println!("data length {}", datas.len());
    test_batch_proof_verify(datas.clone(), "test_compare".to_string());


}