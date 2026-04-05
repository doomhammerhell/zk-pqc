use crate::{MerkleError, MerkleProof, MerkleTree};
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::{HashFunction, PoseidonHash};

fn felt(v: u64) -> FELT {
    FELT::from(v)
}

#[test]
fn test_empty_leaves_returns_error() {
    let hasher = PoseidonHash;
    let result = MerkleTree::new(hasher, vec![]);
    match result {
        Err(MerkleError::EmptyLeaves) => {}
        _ => panic!("Expected MerkleError::EmptyLeaves"),
    }
}

#[test]
fn test_single_leaf_tree() {
    let hasher = PoseidonHash;
    let leaf = felt(42);
    let tree = MerkleTree::new(hasher, vec![leaf]).unwrap();

    // With one leaf padded to 2, root = H(leaf, 0).
    let expected_root = PoseidonHash.hash(&[leaf, felt(0)]);
    assert_eq!(tree.root(), expected_root);
}

#[test]
fn test_two_leaf_tree() {
    let hasher = PoseidonHash;
    let leaves = vec![felt(1), felt(2)];
    let tree = MerkleTree::new(hasher, leaves.clone()).unwrap();

    let expected_root = PoseidonHash.hash(&[felt(1), felt(2)]);
    assert_eq!(tree.root(), expected_root);
}

#[test]
fn test_four_leaf_tree_root() {
    let hasher = PoseidonHash;
    let leaves = vec![felt(10), felt(20), felt(30), felt(40)];
    let tree = MerkleTree::new(hasher, leaves).unwrap();

    let h01 = PoseidonHash.hash(&[felt(10), felt(20)]);
    let h23 = PoseidonHash.hash(&[felt(30), felt(40)]);
    let expected_root = PoseidonHash.hash(&[h01, h23]);
    assert_eq!(tree.root(), expected_root);
}

#[test]
fn test_three_leaf_tree_pads_to_four() {
    let hasher = PoseidonHash;
    let leaves = vec![felt(1), felt(2), felt(3)];
    let tree = MerkleTree::new(hasher, leaves).unwrap();

    // Padded to 4 leaves: [1, 2, 3, 0]
    let h01 = PoseidonHash.hash(&[felt(1), felt(2)]);
    let h23 = PoseidonHash.hash(&[felt(3), felt(0)]);
    let expected_root = PoseidonHash.hash(&[h01, h23]);
    assert_eq!(tree.root(), expected_root);
}

#[test]
fn test_prove_index_out_of_bounds() {
    let hasher = PoseidonHash;
    let tree = MerkleTree::new(hasher, vec![felt(1), felt(2)]).unwrap();

    match tree.prove(2) {
        Err(MerkleError::IndexOutOfBounds {
            index: 2,
            tree_size: 2,
        }) => {}
        _ => panic!("Expected MerkleError::IndexOutOfBounds {{ index: 2, tree_size: 2 }}"),
    }
}

#[test]
fn test_prove_and_verify_round_trip() {
    let hasher = PoseidonHash;
    let leaves = vec![felt(10), felt(20), felt(30), felt(40)];
    let tree = MerkleTree::new(hasher, leaves.clone()).unwrap();
    let root = tree.root();

    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.prove(i).unwrap();
        assert!(MerkleTree::verify(&PoseidonHash, &root, leaf, &proof, i));
    }
}

#[test]
fn test_verify_wrong_leaf_returns_false() {
    let hasher = PoseidonHash;
    let leaves = vec![felt(10), felt(20), felt(30), felt(40)];
    let tree = MerkleTree::new(hasher, leaves).unwrap();
    let root = tree.root();

    let proof = tree.prove(0).unwrap();
    let wrong_leaf = felt(999);
    assert!(!MerkleTree::verify(
        &PoseidonHash,
        &root,
        &wrong_leaf,
        &proof,
        0
    ));
}

#[test]
fn test_verify_wrong_root_returns_false() {
    let hasher = PoseidonHash;
    let leaves = vec![felt(10), felt(20)];
    let tree = MerkleTree::new(hasher, leaves.clone()).unwrap();

    let proof = tree.prove(0).unwrap();
    let wrong_root = felt(999);
    assert!(!MerkleTree::verify(
        &PoseidonHash,
        &wrong_root,
        &leaves[0],
        &proof,
        0
    ));
}

#[test]
fn test_verify_invalid_proof_length_returns_false() {
    let hasher = PoseidonHash;
    let leaves = vec![felt(1), felt(2)];
    let tree = MerkleTree::new(hasher, leaves.clone()).unwrap();
    let root = tree.root();

    // Mismatched siblings and path_bits lengths.
    let bad_proof = MerkleProof {
        siblings: vec![felt(0), felt(0)],
        path_bits: vec![false],
    };
    assert!(!MerkleTree::verify(
        &PoseidonHash,
        &root,
        &leaves[0],
        &bad_proof,
        0
    ));
}

#[test]
fn test_verify_tampered_sibling_returns_false() {
    let hasher = PoseidonHash;
    let leaves = vec![felt(10), felt(20), felt(30), felt(40)];
    let tree = MerkleTree::new(hasher, leaves.clone()).unwrap();
    let root = tree.root();

    let mut proof = tree.prove(0).unwrap();
    // Tamper with the first sibling.
    proof.siblings[0] = felt(999);
    assert!(!MerkleTree::verify(
        &PoseidonHash,
        &root,
        &leaves[0],
        &proof,
        0
    ));
}
