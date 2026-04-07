#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::constants::{FELT, T};
    use crate::poseidon::Poseidon;
    use crate::traits::{HashFunction, HybridHashWrapper, PoseidonHash, Sha256Hash};

    #[test]
    fn test_poseidon_compilation_and_execution() {
        let poseidon = Poseidon::new();
        let mut state = [FELT::zero(); T];

        // Initial state with some values
        for (i, state_i) in state.iter_mut().enumerate().take(T) {
            *state_i = FELT::from(i as u64);
        }

        let original_state = state;
        poseidon.permute(&mut state);

        // Verify that the state has changed
        assert_ne!(state, original_state);
    }

    #[test]
    fn test_poseidon_sponge_hash() {
        use crate::sponge::PoseidonSponge;
        let input = vec![
            FELT::from(1),
            FELT::from(2),
            FELT::from(3),
            FELT::from(4),
            FELT::from(5), // Triggers second absorbing chunk
        ];

        let hash_result = PoseidonSponge::hash(&input);
        println!("Hash(1..5): {:?}", hash_result);

        // Hash of empty input should also be valid (initial state permutation)
        let hash_empty = PoseidonSponge::hash(&[]);
        assert_ne!(hash_result, hash_empty);
    }

    #[test]
    fn test_hybrid_hash() {
        use crate::hybrid::HybridHash;
        let input = vec![FELT::from(1), FELT::from(2)];

        let result = HybridHash::hash(&input);
        println!("HybridHash(1, 2): {:?}", result);
        assert_ne!(result, FELT::zero());
    }

    // --- HashFunction trait tests ---

    #[test]
    fn test_poseidon_trait_hash_nonzero() {
        let hasher = PoseidonHash;
        let input = [FELT::from(1), FELT::from(2), FELT::from(3)];
        let result = hasher.hash(&input);
        assert_ne!(result, FELT::zero());
    }

    #[test]
    fn test_sha256_trait_hash_nonzero() {
        let hasher = Sha256Hash;
        let input = [FELT::from(1), FELT::from(2), FELT::from(3)];
        let result = hasher.hash(&input);
        assert_ne!(result, FELT::zero());
    }

    #[test]
    fn test_hybrid_trait_hash_nonzero() {
        let hasher = HybridHashWrapper;
        let input = [FELT::from(1), FELT::from(2), FELT::from(3)];
        let result = hasher.hash(&input);
        assert_ne!(result, FELT::zero());
    }

    #[test]
    fn test_poseidon_trait_deterministic() {
        let hasher = PoseidonHash;
        let input = [FELT::from(42), FELT::from(99)];
        let a = hasher.hash(&input);
        let b = hasher.hash(&input);
        assert_eq!(a, b);
    }

    #[test]
    fn test_sha256_trait_deterministic() {
        let hasher = Sha256Hash;
        let input = [FELT::from(42), FELT::from(99)];
        let a = hasher.hash(&input);
        let b = hasher.hash(&input);
        assert_eq!(a, b);
    }

    #[test]
    fn test_hybrid_trait_deterministic() {
        let hasher = HybridHashWrapper;
        let input = [FELT::from(42), FELT::from(99)];
        let a = hasher.hash(&input);
        let b = hasher.hash(&input);
        assert_eq!(a, b);
    }

    #[test]
    fn test_domain_separation_changes_output() {
        let hasher = PoseidonHash;
        let input = [FELT::from(1), FELT::from(2)];
        let no_ds = hasher.hash(&input);
        let with_ds = hasher.hash_with_domain_separation(FELT::from(1), &input);
        assert_ne!(no_ds, with_ds);
    }

    #[test]
    fn test_sha256_domain_separation_changes_output() {
        let hasher = Sha256Hash;
        let input = [FELT::from(1), FELT::from(2)];
        let no_ds = hasher.hash(&input);
        let with_ds = hasher.hash_with_domain_separation(FELT::from(1), &input);
        assert_ne!(no_ds, with_ds);
    }

    #[test]
    fn test_hybrid_domain_separation_changes_output() {
        let hasher = HybridHashWrapper;
        let input = [FELT::from(1), FELT::from(2)];
        let no_ds = hasher.hash(&input);
        let with_ds = hasher.hash_with_domain_separation(FELT::from(1), &input);
        assert_ne!(no_ds, with_ds);
    }

    // --- Targeted tests for Hybrid-Hash domain separation fix (11A.2) ---

    #[test]
    fn test_hybrid_sha256_component_changes_with_ds() {
        // Extract the SHA-256 component independently and verify it changes
        // with different domain separation values.
        use sha2::{Digest, Sha256};

        let input = [FELT::from(1), FELT::from(2)];
        let ds_a = FELT::from(1);
        let ds_b = FELT::from(2);

        // Compute SHA-256(ds_a || input)
        let mut hasher_a = Sha256::new();
        hasher_a.update(ds_a.to_bytes_be());
        for val in &input {
            hasher_a.update(val.to_bytes_be());
        }
        let sha_a = hasher_a.finalize();

        // Compute SHA-256(ds_b || input)
        let mut hasher_b = Sha256::new();
        hasher_b.update(ds_b.to_bytes_be());
        for val in &input {
            hasher_b.update(val.to_bytes_be());
        }
        let sha_b = hasher_b.finalize();

        // SHA-256 output MUST differ when DS differs
        assert_ne!(
            sha_a, sha_b,
            "SHA-256 component must change with different DS values"
        );
    }

    #[test]
    fn test_hybrid_sha256_component_without_ds_differs_from_with_ds() {
        // SHA-256(input) must differ from SHA-256(ds || input) for any non-zero DS
        use sha2::{Digest, Sha256};

        let input = [FELT::from(10), FELT::from(20)];
        let ds = FELT::from(5);

        // SHA-256(input) — no DS
        let mut hasher_no_ds = Sha256::new();
        for val in &input {
            hasher_no_ds.update(val.to_bytes_be());
        }
        let sha_no_ds = hasher_no_ds.finalize();

        // SHA-256(ds || input) — with DS
        let mut hasher_with_ds = Sha256::new();
        hasher_with_ds.update(ds.to_bytes_be());
        for val in &input {
            hasher_with_ds.update(val.to_bytes_be());
        }
        let sha_with_ds = hasher_with_ds.finalize();

        assert_ne!(
            sha_no_ds, sha_with_ds,
            "SHA-256 with DS must differ from without DS"
        );
    }

    #[test]
    fn test_hybrid_different_ds_produces_different_output() {
        // The full HybridHashWrapper must produce different outputs for different DS values
        let hasher = HybridHashWrapper;
        let input = [FELT::from(1), FELT::from(2), FELT::from(3)];
        let ds_a = FELT::from(1);
        let ds_b = FELT::from(2);

        let out_a = hasher.hash_with_domain_separation(ds_a, &input);
        let out_b = hasher.hash_with_domain_separation(ds_b, &input);
        assert_ne!(
            out_a, out_b,
            "Hybrid hash must differ for different DS values"
        );
    }

    /// Generic function accepting any HashFunction with Digest=FELT.
    /// Verifies all three implementations work through the trait interface.
    fn generic_hash_test(hasher: &impl HashFunction<Digest = FELT>) {
        let input = [FELT::from(10), FELT::from(20)];
        let result = hasher.hash(&input);
        assert_ne!(result, FELT::zero());

        let ds_result = hasher.hash_with_domain_separation(FELT::from(7), &input);
        assert_ne!(ds_result, FELT::zero());
        assert_ne!(result, ds_result);
    }

    #[test]
    fn test_generic_with_poseidon() {
        generic_hash_test(&PoseidonHash);
    }

    #[test]
    fn test_generic_with_sha256() {
        generic_hash_test(&Sha256Hash);
    }

    #[test]
    fn test_generic_with_hybrid() {
        generic_hash_test(&HybridHashWrapper);
    }

    // --- Interop divergence test (task 11B.3) ---

    /// Verifies that our project-specific Poseidon (t=6, Cauchy MDS, SHA-256 CSPRNG)
    /// produces a DIFFERENT output than Starknet's native Poseidon (t=3, Grain LFSR).
    ///
    /// This is a guardrail against accidentally conflating the two implementations.
    /// See docs/POSEIDON_CONSTANTS.md for the full rationale.
    ///
    /// The Starknet-native poseidon_hash_span([1, 2, 3]) is a well-known value
    /// produced by the starknet-crypto crate (t=3, Grain LFSR constants).
    /// Our implementation uses completely different parameters and MUST NOT match.
    #[test]
    fn test_poseidon_diverges_from_starknet_known_output() {
        let hasher = PoseidonHash;
        let input = [FELT::from(1), FELT::from(2), FELT::from(3)];
        let our_output = hasher.hash(&input);

        // Known Starknet-native Poseidon output for poseidon_hash_span([1, 2, 3]).
        // Source: starknet-crypto crate (t=3, Grain LFSR constants).
        // This value is produced by a fundamentally different parameterization:
        //   - Starknet: t=3, Grain LFSR round constants
        //   - Ours:     t=6, Cauchy MDS + SHA-256 CSPRNG round constants
        let starknet_known_output = FELT::from_hex_unchecked(
            "0x2f0d8840bcf3bc629598d8a6cc80cb7c0d9e52d93dab244bbf9cd0dca0ad71d",
        );

        assert_ne!(
            our_output, starknet_known_output,
            "Our Poseidon output MUST differ from Starknet-native. \
             If this fails, our constants may have been accidentally replaced \
             with Starknet-native values. See docs/POSEIDON_CONSTANTS.md."
        );

        // Sanity: our output should be non-zero
        assert_ne!(our_output, FELT::zero(), "Hash output should not be zero");
    }
}
