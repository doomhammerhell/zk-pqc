// Feature: zk-pqc-framework, Property 2: Merkle Inclusion Round-Trip (Binary)
//
// Validates: Requirements 3.1, 3.3, 3.6
//
// Verifies:
// - For any list of leaves and any leaf index i, constructing a binary Merkle tree,
//   generating an inclusion proof for leaf i, and verifying that proof returns true.
// - Reconstructing the root from the leaf and its proof produces the original root.

// Feature: zk-pqc-framework, Property 3: Merkle Proof Tamper Detection (Binary)
//
// Validates: Requirements 3.4
//
// Verifies:
// - Altering the leaf value causes verification to return false.
// - Altering a sibling in the proof causes verification to return false.
// - Altering the root causes verification to return false.

// Feature: zk-pqc-framework, Property 2 (HexTree): Merkle Inclusion Round-Trip (HexTree)
//
// Validates: Requirements 14.1, 14.4
//
// Verifies:
// - For any list of leaves and any leaf index, HexTree prove/verify round-trip.

// Feature: zk-pqc-framework, Property 3 (HexTree): Merkle Proof Tamper Detection (HexTree)
//
// Validates: Requirements 3.4 (extended to HexTree)
//
// Verifies tamper detection for HexTree proofs.

// Feature: zk-pqc-framework, Property 4 (HexTree): HexTree Proof Structure
//
// Validates: Requirements 14.2, 14.3
//
// Verifies:
// - Depth = ceil(log_16(N))
// - Proof size = depth × 15 siblings

#[cfg(test)]
mod binary_tests {
    use crate::{MerkleProof, MerkleTree};
    use proptest::prelude::*;
    use zk_pqc_hash_layer::constants::FELT;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    /// Strategy: generate a Vec of u64 values (length 1..=64) to use as leaves.
    fn leaves_strategy() -> impl Strategy<Value = Vec<u64>> {
        prop::collection::vec(any::<u64>(), 1..=16)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Validates: Requirements 3.1, 3.3, 3.6**
        #[test]
        fn prop_merkle_inclusion_round_trip(raw_leaves in leaves_strategy()) {
            let leaves: Vec<FELT> = raw_leaves.iter().map(|&v| FELT::from(v)).collect();
            let hasher = PoseidonHash;
            let tree = MerkleTree::new(hasher, leaves.clone()).unwrap();
            let root = tree.root();

            for (i, leaf) in leaves.iter().enumerate() {
                let proof = tree.prove(i).unwrap();

                // Verify returns true for valid proof
                prop_assert!(
                    MerkleTree::verify(&PoseidonHash, &root, leaf, &proof, i),
                    "Verification failed for leaf index {}", i
                );

                // Reconstruct root from proof and check it matches
                let reconstructed = reconstruct_root(leaf, &proof);
                prop_assert!(
                    reconstructed == root,
                    "Reconstructed root does not match original for leaf index {}", i
                );
            }
        }

        /// **Validates: Requirements 3.4**
        #[test]
        fn prop_merkle_proof_tamper_detection(raw_leaves in leaves_strategy()) {
            let leaves: Vec<FELT> = raw_leaves.iter().map(|&v| FELT::from(v)).collect();
            let hasher = PoseidonHash;
            let tree = MerkleTree::new(hasher, leaves.clone()).unwrap();
            let root = tree.root();

            // Pick the first leaf for tamper tests
            let idx = 0;
            let proof = tree.prove(idx).unwrap();

            // --- Tamper scenario 1: Alter the leaf value ---
            let tampered_leaf = FELT::from(u64::MAX) - leaves[idx] + FELT::from(1u64);
            prop_assert!(
                !MerkleTree::verify(&PoseidonHash, &root, &tampered_leaf, &proof, idx),
                "Verification should fail with tampered leaf"
            );

            // --- Tamper scenario 2: Alter a sibling in the proof ---
            if !proof.siblings.is_empty() {
                let mut tampered_proof = MerkleProof {
                    siblings: proof.siblings.clone(),
                    path_bits: proof.path_bits.clone(),
                };
                tampered_proof.siblings[0] += FELT::from(1u64);
                prop_assert!(
                    !MerkleTree::verify(&PoseidonHash, &root, &leaves[idx], &tampered_proof, idx),
                    "Verification should fail with tampered sibling"
                );
            }

            // --- Tamper scenario 3: Alter the root ---
            let tampered_root = root + FELT::from(1u64);
            prop_assert!(
                !MerkleTree::verify(&PoseidonHash, &tampered_root, &leaves[idx], &proof, idx),
                "Verification should fail with tampered root"
            );
        }
    }

    /// Reconstruct the Merkle root from a leaf and its inclusion proof.
    fn reconstruct_root(leaf: &FELT, proof: &MerkleProof<FELT>) -> FELT {
        let hasher = PoseidonHash;
        let mut current = *leaf;
        for (sibling, &is_right) in proof.siblings.iter().zip(proof.path_bits.iter()) {
            current = if is_right {
                zk_pqc_hash_layer::traits::HashFunction::hash(&hasher, &[*sibling, current])
            } else {
                zk_pqc_hash_layer::traits::HashFunction::hash(&hasher, &[current, *sibling])
            };
        }
        current
    }
}

#[cfg(test)]
mod hextree_tests {
    use crate::{HexProof, HexTree};
    use proptest::prelude::*;
    use zk_pqc_hash_layer::constants::FELT;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    /// Strategy: generate a Vec of u64 values (length 1..=256) to use as leaves.
    fn leaves_strategy() -> impl Strategy<Value = Vec<u64>> {
        prop::collection::vec(any::<u64>(), 1..=64)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Validates: Requirements 14.1, 14.4**
        ///
        /// Property 2 (HexTree): Merkle Inclusion Round-Trip (HexTree)
        #[test]
        fn prop_hextree_inclusion_round_trip(raw_leaves in leaves_strategy()) {
            let leaves: Vec<FELT> = raw_leaves.iter().map(|&v| FELT::from(v)).collect();
            let hasher = PoseidonHash;
            let tree = HexTree::new(hasher, leaves.clone()).unwrap();
            let root = tree.root();

            for (i, leaf) in leaves.iter().enumerate() {
                let proof = tree.prove(i).unwrap();

                // Verify returns true for valid proof
                prop_assert!(
                    HexTree::verify(&PoseidonHash, &root, leaf, &proof, i),
                    "HexTree verification failed for leaf index {}", i
                );
            }
        }

        /// **Validates: Requirements 3.4 (extended to HexTree)**
        ///
        /// Property 3 (HexTree): Merkle Proof Tamper Detection (HexTree)
        #[test]
        fn prop_hextree_proof_tamper_detection(raw_leaves in leaves_strategy()) {
            let leaves: Vec<FELT> = raw_leaves.iter().map(|&v| FELT::from(v)).collect();
            let hasher = PoseidonHash;
            let tree = HexTree::new(hasher, leaves.clone()).unwrap();
            let root = tree.root();

            // Skip empty trees
            prop_assume!(!leaves.is_empty());
            let idx = 0;
            let proof = tree.prove(idx).unwrap();

            // --- Tamper scenario 1: Alter the leaf value ---
            let tampered_leaf = FELT::from(u64::MAX) - leaves[idx] + FELT::from(1u64);
            prop_assert!(
                !HexTree::verify(&PoseidonHash, &root, &tampered_leaf, &proof, idx),
                "Verification should fail with tampered leaf"
            );

            // --- Tamper scenario 2: Alter a sibling in the proof ---
            if !proof.siblings.is_empty() {
                let mut tampered_proof = HexProof {
                    siblings: proof.siblings.clone(),
                    path_indices: proof.path_indices.clone(),
                };
                tampered_proof.siblings[0][0] += FELT::from(1u64);
                prop_assert!(
                    !HexTree::verify(&PoseidonHash, &root, &leaves[idx], &tampered_proof, idx),
                    "Verification should fail with tampered sibling"
                );
            }

            // --- Tamper scenario 3: Alter the root ---
            let tampered_root = root + FELT::from(1u64);
            prop_assert!(
                !HexTree::verify(&PoseidonHash, &tampered_root, &leaves[idx], &proof, idx),
                "Verification should fail with tampered root"
            );
        }

        /// **Validates: Requirements 14.2, 14.3**
        ///
        /// Property 4 (HexTree): HexTree Proof Structure
        #[test]
        fn prop_hextree_proof_structure(raw_leaves in leaves_strategy()) {
            let leaves: Vec<FELT> = raw_leaves.iter().map(|&v| FELT::from(v)).collect();
            let hasher = PoseidonHash;
            let tree = HexTree::new(hasher, leaves.clone()).unwrap();

            let n = leaves.len();
            let expected_depth = if n <= 1 { 1 } else { ((n - 1).ilog2() as usize) / 4 + 1 };

            prop_assert_eq!(tree.depth(), expected_depth, "Tree depth mismatch");

            // Verify proof structure for all leaves
            for i in 0..n {
                let proof = tree.prove(i).unwrap();

                // Verify depth
                prop_assert_eq!(
                    proof.depth(),
                    expected_depth,
                    "Proof depth mismatch for leaf {}"
                , i);

                // Verify proof size = depth × 15 siblings
                for (level, siblings) in proof.siblings.iter().enumerate() {
                    prop_assert_eq!(
                        siblings.len(),
                        15,
                        "Siblings count mismatch at level {} for leaf {}", level, i
                    );
                }

                // Verify path indices are in [0, 15]
                for (level, &path_idx) in proof.path_indices.iter().enumerate() {
                    prop_assert!(
                        path_idx < 16,
                        "Path index {} out of range at level {} for leaf {}",
                        path_idx, level, i
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod smt_tests {
    use crate::SparseMerkleTree;
    use proptest::prelude::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    /// Strategy: generate a Vec of distinct u64 indices to consume.
    fn indices_strategy() -> impl Strategy<Value = Vec<u64>> {
        prop::collection::vec(any::<u64>(), 0..=32)
            .prop_filter("indices too large", |v| v.iter().all(|&i| i < (1u64 << 32)))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Validates: Requirements 8.2, 8.3, 8.4, 16.4**
        ///
        /// Property 14: OTS Index Non-Reuse Enforcement
        #[test]
        fn prop_smt_index_non_reuse(raw_indices in indices_strategy()) {
            let hasher = PoseidonHash;
            let mut smt = SparseMerkleTree::new(hasher);
            let root_before = smt.root();

            // Mark all indices as consumed
            for (i, &idx) in raw_indices.iter().enumerate() {
                let result = smt.mark_consumed(idx);

                if i > 0 && raw_indices[..i].contains(&idx) {
                    // Duplicate should fail
                    prop_assert!(
                        matches!(result, Err(crate::SmtError::AlreadyConsumed { .. })),
                        "Duplicate index {} should fail", idx
                    );
                } else {
                    // First occurrence should succeed
                    prop_assert!(result.is_ok(), "First mark of index {} should succeed", idx);
                }
            }

            // Verify all consumed indices are marked
            for &idx in &raw_indices {
                prop_assert!(smt.is_consumed(idx), "Index {} should be consumed", idx);
            }

            // Root should have changed if any indices were consumed
            if !raw_indices.is_empty() {
                prop_assert_ne!(smt.root(), root_before, "Root should change after marking");
            }
        }
    }
}
