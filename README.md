
# VerkleTree
VerkleTree is a Rust library implementing Verkle Trees using the BLS12-381 elliptic curve and KZG commitments for efficient storage and verification of data. This library provides functionality to build a Verkle Tree, generate proofs, and verify them.

### Features
- Verkle Tree Construction: Build a Verkle Tree from a set of data.
- Proof Generation: Generate proofs for specific data points in the Verkle Tree.
- Proof Verification: Verify the generated proofs.

### Installation
To use this library, add the following to your `Cargo.toml`
```toml
verkle-tree = "0.1.0"
```

### Usage
Here is a basic example of how to use the library:

```rust
use verkle_tree::{VerkleTree, VerkleProof};
use ark_bls12_381::Fr as F;

fn main() {
    let datas = vec![F::from(10), F::from(20), F::from(30), F::from(40), F::from(50), F::from(60), F::from(70), F::from(80), F::from(90), F::from(100), F::from(110), F::from(120), F::from(130), F::from(140), F::from(150), F::from(160)];

    let width = 4;
    let verkle_tree = VerkleTree::new(&datas, width);
    let index = 0;
    let data_at_index = datas[index];
    let proof = verkle_tree.generate_proof(index, &data_at_index);
    let is_valid = verkle_tree.verify_proof(&proof, &data_at_index);
    assert!(is_valid);
}
```
### Testing
To run the tests, use the following command:
```bash
cargo test
```

### TODO
- [ ] Add support for multiproof using random evaluation
- [ ] Store VerkleTree
- [ ] Add benchmarks in comparison to Merkle Trees
- [ ] VerkleTree solidity verifier???


### Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
This project is licensed under the MIT License. See the LICENSE file for details.