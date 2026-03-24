#[cfg(test)]
mod tests {
    use crate::poseidon::Poseidon;
    use crate::constants::{FELT, T};

    #[test]
    fn test_poseidon_compilation_and_execution() {
        let poseidon = Poseidon::new();
        let mut state = [FELT::zero(); T];
        
        // Initial state with some values
        for i in 0..T {
            state[i] = FELT::from(i as u64);
        }

        let original_state = state.clone();
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
        let input = vec![
            FELT::from(1),
            FELT::from(2),
        ];
        
        let result = HybridHash::hash(&input);
        println!("HybridHash(1, 2): {:?}", result);
        assert_ne!(result, FELT::zero());
    }
}
