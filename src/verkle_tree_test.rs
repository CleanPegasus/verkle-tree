#[cfg(test)]
mod tests {

    use crate::VerkleTree;
    use ark_bls12_381::Fr as F;
    use rand::Rng;
    use random_number::random;
    use rand::prelude::*;

    #[test]
    fn test_build_tree() {
        let (tree, _, _, _) = build_verkle_tree();
        assert!(
            tree.root_commitment().is_some(),
            "Failed building verkle tree"
        );
    }

    #[test]
    fn test_generate_proof() {
        let (tree, datas, length, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=length * width);
        let random_point = datas[ranom_index];
        let proof = tree.generate_proof(ranom_index, &random_point);
        assert!(proof.is_ok(), "Proof Generation failed");
    }

    #[test]
    fn test_generate_invalid_proof() {
        let (tree, _datas, length, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=length * width);
        let fake_point = F::from(rng.gen_range(-100..=100));
        let proof = tree.generate_proof(ranom_index, &fake_point);
        assert!(
            proof.is_err(),
            "Should not be able to generate a valid proof"
        );
    }

    #[test]
    fn test_verify_proof() {
        let (tree, datas, length, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=length * width);
        let random_point = datas[ranom_index];
        let proof = tree.generate_proof(ranom_index, &random_point).unwrap();
        let root = VerkleTree::root_commitment(&tree).unwrap();
        let verification = VerkleTree::verify_proof(root, &proof, width);

        assert!(verification, "Given point should generate a valid proof");
    }

    #[test]
    fn test_invalid_proof_verification() {
        let (tree, _, _, _) = build_verkle_tree();
        let (invalid_tree, datas, length, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=length * width);
        let random_point = datas[ranom_index];
        let proof = invalid_tree.generate_proof(ranom_index, &random_point);
        let root = VerkleTree::root_commitment(&tree).unwrap();
        let verification = VerkleTree::verify_proof(root,&proof.unwrap(), width);

        assert_eq!(verification, false, "Should not accept invalid proof");
    }

    fn build_verkle_tree() -> (VerkleTree, Vec<F>, usize, usize) {
        let mut rng = rand::thread_rng();
        let width = rng.gen_range(2..=20);
        let length = rng.gen_range(2..=20);
        println!("Generating tree with length {} and width {}", length, width);
        let datas = generate_random_vec(length * width);
        (VerkleTree::new(&datas, width).unwrap(), datas, width, length)
    }

    fn generate_random_vec(length: usize) -> Vec<F> {
        let mut rng = rand::thread_rng();
        println!("Generating vector with length: {}", length);
        (0..length)
            .map(|_| F::from(rng.gen_range(-100..=100)))
            .collect()
    }

    fn test_batch_proof (data: Vec<F>, indexes: Vec<usize>, width: usize)-> bool{
        

        let tree = VerkleTree::new(&data, width).expect("make tree");

        let proof = VerkleTree::generate_batch_proof(&tree, indexes, &data);
        let bol: bool = VerkleTree::batch_verify(tree.root_commitment().unwrap(), proof, width);
        bol

    }

    #[test]
    fn test_batch_proof_1() {
        let mut datas: Vec<F> = Vec::new();
        for i in 0..i32::pow(3, 3){
            datas.push(F::from(i));
        }
        for i in (1.. datas.len()).step_by(2){
            datas[i] = F::from(0);
        }

        let indexes: Vec<usize> = vec![1,2,6, 12,15,16, 25];
        let width: usize = 3;

        assert!(test_batch_proof(datas, indexes, width));
    }

    #[test]
    fn test_batch_proof_2() {
        
    let mut datas2: Vec<F> = Vec::new();
    for i in 0..i32::pow(5, 5){
        datas2.push(F::from(i));
    }
    for i in (1.. datas2.len()).step_by(2){
        datas2[i] = F::from(0);
    }

    let indexes2: Vec<usize> = vec![1,2,6, 12,15,16, 25, 33,34,35];
    let width2: usize = 5;

    assert!(test_batch_proof(datas2, indexes2, width2));
    }

    #[test]
    fn test_batch_proof_rand() {
        let mut datas: Vec<F> = Vec::new();
        let width: usize = 5;
        let n: i32 = i32::pow(width as i32, 4);
        for i in 0..n{
            datas.push(F::from(random!(0..n)));
        }
        let indices: Vec<usize> = (0..=(n-1) as usize).choose_multiple(&mut thread_rng(),(n as f64*0.2) as usize);

        assert!(test_batch_proof(datas, indices, width));
    }

    #[test]
    fn test_batch_proof_rand_2() {
        let mut datas: Vec<F> = Vec::new();
        let width: usize = 3;
        let n: i32 = i32::pow(width as i32, 6);
        for i in 0..n{
            datas.push(F::from(random!(0..n)));
        }
        let indices: Vec<usize> = (0..=(n-1) as usize).choose_multiple(&mut thread_rng(),(n as f64*0.2) as usize);

        assert!(test_batch_proof(datas, indices, width));
    }

    

}
