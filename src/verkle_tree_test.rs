#[cfg(test)]
mod tests {

    use crate::VerkleTree;
    use ark_bls12_381::Fr as F;
    use rand::Rng;
   // use random_number::random;
    use rand::prelude::*;

    #[test]
    fn test_build_tree() {
        let (tree, _, _) = build_verkle_tree();
        assert!(
            tree.root_commitment().is_some(),
            "Failed building verkle tree"
        );
    }

    #[test]
    fn test_generate_proof() {
        let (tree, datas, _) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=datas.len()-1);
        let random_point = datas[ranom_index];
        let proof = tree.generate_proof(ranom_index, &random_point);
        assert!(proof.is_ok(), "Proof Generation failed");
    }

    #[test]
    fn test_generate_invalid_proof() {
        let (tree, datas, _) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=datas.len()-1);
        let fake_point = F::from(rng.gen_range(-100..=100));
        let proof = tree.generate_proof(ranom_index, &fake_point);
        assert!(
            proof.is_err(),
            "Should not be able to generate a valid proof"
        );
    }

    #[test]
    fn test_verify_proof() {
        let (tree, datas, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=datas.len()-1);
        let random_point = datas[ranom_index];
        let proof = tree.generate_proof(ranom_index, &random_point).unwrap();
        let root = VerkleTree::root_commitment(&tree).unwrap();
        let verification = VerkleTree::verify_proof(root, &proof, width);

        assert!(verification, "Given point should generate a valid proof");
    }

    #[test]
    fn test_invalid_proof_verification() {
        let (tree, _, _) = build_verkle_tree();
        let (invalid_tree, datas, width) = build_verkle_tree();
        let mut rng = rand::thread_rng();
        let ranom_index = rng.gen_range(0..=datas.len()-1);
        let random_point = datas[ranom_index];
        let proof = invalid_tree.generate_proof(ranom_index, &random_point);
        let root = VerkleTree::root_commitment(&tree).unwrap();
        let verification = VerkleTree::verify_proof(root,&proof.unwrap(), width);

        assert_eq!(verification, false, "Should not accept invalid proof");
    }

    fn build_verkle_tree() -> (VerkleTree, Vec<F>, usize) {
        let mut datas: Vec<F> = Vec::new();
        let width: usize = 6;
        for _i in 0..i32::pow(width as i32, 5){
            datas.push(F::from(rand::thread_rng().gen_range(0..=u32::pow(10, 8))));
        }
        let tree = VerkleTree::new(&datas, width).unwrap();
        (tree, datas, width)
    }

    /*
    #[test]
    fn test_batch_proof_verify() {
        let (tree, datas, width) = build_verkle_tree();
        let indices: Vec<usize> = (0..=(datas.len()-1) as usize).choose_multiple(
            &mut thread_rng(),((datas.len() as f64) *0.2 )as usize);
        let proof = tree.generate_batch_proof(indices, &datas);
        let root = VerkleTree::root_commitment(&tree).unwrap();
        let verification = VerkleTree::verify_batch_proof(root, proof, width);
        assert!(verification, "Given point should generate a valid proof");
    }
     */
}
