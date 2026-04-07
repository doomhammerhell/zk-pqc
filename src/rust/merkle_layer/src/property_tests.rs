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

#[cfg(test)]
mod tests {
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
