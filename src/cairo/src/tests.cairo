#[cfg(test)]
mod tests {
    use zk_pqc_cairo::poseidon::permute;
    use zk_pqc_cairo::sponge::hash;
    use zk_pqc_cairo::hybrid::hybrid_hash;
    use core::array::ArrayTrait;

    #[test]
    fn test_poseidon_execution() {
        let mut state = ArrayTrait::new();
        state.append(0);
        state.append(1);
        state.append(2);
        state.append(3);
        state.append(4);
        state.append(5);

        let mut current_state = state.clone();
        permute(ref current_state);

        // Basic check that state changed
        let mut same = true;
        let mut i: usize = 0;
        while i < 6 {
            if *state.at(i) != *current_state.at(i) {
                same = false;
            };
            i += 1;
        };
        assert(!same, 'State did not change');
    }

    #[test]
    fn test_sponge_hash() {
        let mut input = ArrayTrait::new();
        input.append(1);
        input.append(2);
        input.append(3);
        input.append(4);
        input.append(5);
        
        let result = hash(input.span());
        assert(result != 0, 'Hash resulted in zero');
    }

    #[test]
    fn test_hybrid_hash() {
        let mut input = ArrayTrait::new();
        input.append(1);
        input.append(2);
        
        let result = hybrid_hash(input.span());
        assert(result != 0, 'Hybrid hash resulted in zero');
    }
}
