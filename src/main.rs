use verkle_tree::VerkleTree;
use ark_bls12_381::Fr as F;

fn main (){
    println!("Hello world");

    fn test_batch_proof (data: Vec<F>, indexes: Vec<usize>, width: usize){
        

        let tree = VerkleTree::new(&data, width).expect("make tree");

        let proof = VerkleTree::generate_batch_proof(&tree, indexes, &data);
        let bol: bool = VerkleTree::verify_batch_proof(tree.root_commitment().unwrap(), proof, width);
        println!("{}", bol);

    }
    let mut datas: Vec<F> = Vec::new();
        for i in 0..i32::pow(3, 3){
            datas.push(F::from(i));
        }
        for i in (1.. datas.len()).step_by(2){
            datas[i] = F::from(0);
        }

    let indexes: Vec<usize> = vec![1,2,6, 12,15,16, 25];
    let width: usize = 3;

    test_batch_proof(datas, indexes, width);

    let mut datas2: Vec<F> = Vec::new();
        for i in 0..i32::pow(5, 5){
            datas2.push(F::from(i));
        }
        for i in (1.. datas2.len()).step_by(2){
            datas2[i] = F::from(0);
        }

    let indexes2: Vec<usize> = vec![1,2,6, 12,15,16, 25, 33,34,35];
    let width2: usize = 5;

    test_batch_proof(datas2, indexes2, width2);
    
}