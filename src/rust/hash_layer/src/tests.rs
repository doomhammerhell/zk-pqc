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
}
