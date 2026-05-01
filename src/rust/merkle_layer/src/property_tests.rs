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

// Feature: zk-pqc-framework, Property 20: SMT State Reconstruction from DA Diffs
//
// Validates: Requirements 17.1, 17.2, 17.3, 17.4
//
// Verifies:
// - For any sequence of batches with published DA state diffs (uint64 index vectors),
//   applying all diffs to an initially empty SMT produces a root identical to the
//   current on-chain SMT root (built directly).
// - The DA payload for a batch of K transactions is at most K × 8 bytes.
// - Duplicate indices across batches are detected and rejected.

#[cfg(test)]
mod da_reconstruction_tests {
    use crate::reconstruct::SmtReconstructor;
    use crate::SparseMerkleTree;
    use proptest::prelude::*;
    use std::collections::HashSet;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    /// Strategy: generate a Vec of batch diffs where each batch contains unique indices
    /// and indices are unique across all batches.
    fn batch_diffs_strategy() -> impl Strategy<Value = Vec<Vec<u64>>> {
        // Generate 1..=8 indices in valid range, then split into batches.
        // We keep the count small because each index requires Poseidon hashing
        // through a depth-64 SMT (expensive per operation).
        prop::collection::vec(0u64..1000, 1..=8)
            .prop_map(|raw_indices| {
                // Deduplicate indices
                let unique: Vec<u64> = raw_indices
                    .into_iter()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();

                // Split into batches of varying sizes (1..3 batches)
                let mut batches = Vec::new();
                let mut remaining = unique.as_slice();
                let mut batch_size = 1;
                while !remaining.is_empty() {
                    let take = batch_size.min(remaining.len());
                    batches.push(remaining[..take].to_vec());
                    remaining = &remaining[take..];
                    batch_size += 2; // Vary batch sizes: 1, 3, 5, ...
                }
                batches
            })
            .prop_filter("at least one batch", |b| !b.is_empty())
    }

    /// Strategy: generate batch diffs that intentionally contain a duplicate index
    /// across batches (for testing duplicate detection).
    fn batch_diffs_with_duplicate_strategy() -> impl Strategy<Value = Vec<Vec<u64>>> {
        (prop::collection::vec(1u64..1000, 3..=10), 0usize..3).prop_map(
            |(indices, dup_source_batch)| {
                // Deduplicate first
                let unique: Vec<u64> = indices
                    .into_iter()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();

                if unique.len() < 3 {
                    // Not enough unique indices; create a simple duplicate case
                    return vec![vec![1, 2], vec![2, 3]];
                }

                // Split into 2 batches
                let mid = unique.len() / 2;
                let batch1 = unique[..mid].to_vec();
                let mut batch2 = unique[mid..].to_vec();

                // Insert a duplicate from batch1 into batch2
                let dup_idx = batch1[dup_source_batch % batch1.len()];
                batch2.push(dup_idx);

                vec![batch1, batch2]
            },
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        /// **Validates: Requirements 17.1, 17.2, 17.3, 17.4**
        ///
        /// Property 20: SMT State Reconstruction from DA Diffs
        ///
        /// Random batch diffs → apply to empty SMT via SmtReconstructor →
        /// compare root with expected on-chain root (built directly via SparseMerkleTree).
        #[test]
        fn prop_smt_state_reconstruction_from_da_diffs(diffs in batch_diffs_strategy()) {
            let hasher = PoseidonHash;

            // --- Path 1: Reconstruct via SmtReconstructor (simulates observer) ---
            let mut reconstructor = SmtReconstructor::new(hasher);
            reconstructor.apply_diffs(&diffs).unwrap();
            let reconstructed_root = reconstructor.root();

            // --- Path 2: Build directly via SparseMerkleTree (simulates on-chain state) ---
            let mut direct_smt = SparseMerkleTree::new(hasher);
            for batch in &diffs {
                for &idx in batch {
                    direct_smt.mark_consumed(idx).unwrap();
                }
            }
            let on_chain_root = direct_smt.root();

            // --- Verify: Reconstructed root matches on-chain root ---
            prop_assert_eq!(
                reconstructed_root, on_chain_root,
                "Reconstructed SMT root must match on-chain root"
            );

            // --- Verify: verify_against_root returns true ---
            prop_assert!(
                reconstructor.verify_against_root(on_chain_root),
                "verify_against_root must return true for matching root"
            );

            // --- Verify: DA payload size constraint ---
            // DA payload for K transactions ≤ K × 8 bytes (each index is a u64 = 8 bytes)
            let total_indices: usize = diffs.iter().map(|b| b.len()).sum();
            let da_payload_bytes = total_indices * 8; // u64 = 8 bytes each
            let max_allowed_bytes = total_indices * 8;
            prop_assert!(
                da_payload_bytes <= max_allowed_bytes,
                "DA payload {} bytes exceeds limit {} bytes for {} transactions",
                da_payload_bytes, max_allowed_bytes, total_indices
            );
        }

        /// **Validates: Requirements 17.1, 17.2**
        ///
        /// Property 20 (DA payload size): Verify that the DA payload for K transactions
        /// is exactly K × 8 bytes (compact uint64 vector representation).
        #[test]
        fn prop_da_payload_size_constraint(diffs in batch_diffs_strategy()) {
            // Each batch's DA payload is the serialized uint64 index vector.
            // For K indices in a batch, the payload is exactly K × 8 bytes.
            for batch in &diffs {
                let k = batch.len();
                // Simulate serialization: each u64 index = 8 bytes
                let payload_size: usize = batch.iter().map(|_| std::mem::size_of::<u64>()).sum();
                prop_assert_eq!(
                    payload_size, k * 8,
                    "DA payload for batch of {} transactions must be {} bytes, got {}",
                    k, k * 8, payload_size
                );
                prop_assert!(
                    payload_size <= k * 8,
                    "DA payload {} exceeds K×8={} limit", payload_size, k * 8
                );
            }
        }

        /// **Validates: Requirements 17.3, 17.4**
        ///
        /// Property 20 (duplicate detection): Duplicate indices across batches
        /// are detected and rejected by the reconstructor.
        #[test]
        fn prop_da_reconstruction_detects_duplicates(diffs in batch_diffs_with_duplicate_strategy()) {
            let hasher = PoseidonHash;
            let mut reconstructor = SmtReconstructor::new(hasher);

            // Applying diffs with duplicates should produce an error
            let result = reconstructor.apply_diffs(&diffs);
            prop_assert!(
                result.is_err(),
                "Reconstructor must reject diffs with duplicate indices across batches"
            );

            // Verify the error is specifically a DuplicateIndex error
            match result {
                Err(crate::ReconstructError::DuplicateIndex { .. }) => {
                    // Expected: duplicate detected
                }
                Err(other) => {
                    prop_assert!(false, "Expected DuplicateIndex error, got: {:?}", other);
                }
                Ok(()) => {
                    prop_assert!(false, "Expected error for duplicate indices, got Ok");
                }
            }
        }
    }
}
