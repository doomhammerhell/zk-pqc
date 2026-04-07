/// WOTS+ integration tests that exercise full keygen/sign/verify chains.
/// These are computationally intensive (66 chains × 15 hash iterations each)
/// and run in a dedicated CI step.
#[cfg(test)]
mod wots_slow_tests {
    use zk_pqc_cairo::hash_trait::{HashFunction, PoseidonHash};
    use zk_pqc_cairo::wots::{keygen as wots_keygen, sign as wots_sign, verify as wots_verify};

    #[test]
    #[available_gas(99999999999)]
    fn slow_wots_keygen_chain_integrity() {
        let w: u32 = 16;
        let seed = array![42];
        let kp = wots_keygen::<PoseidonHash>(w, seed.span());

        let mut i: u32 = 0;
        while i < 3 {
            let secret = *kp.secret_chains.at(i);
            let mut current = secret;
            let mut j: u32 = 0;
            while j < w - 1 {
                current = HashFunction::<PoseidonHash>::hash(array![current].span());
                j += 1;
            }
            assert(current == *kp.public_chains.at(i), 'chain integrity fail');
            i += 1;
        };
    }

    #[test]
    #[available_gas(99999999999)]
    fn slow_wots_sign_verify_roundtrip() {
        let w: u32 = 16;
        let seed = array![123];
        let kp = wots_keygen::<PoseidonHash>(w, seed.span());
        let message: felt252 = 999;
        let sig = wots_sign::<PoseidonHash>(w, @kp, message);
        let valid = wots_verify::<PoseidonHash>(w, kp.public_chains.span(), message, @sig);
        assert(valid, 'roundtrip verify failed');
    }

    #[test]
    #[available_gas(99999999999)]
    fn slow_wots_wrong_message_rejection() {
        let w: u32 = 16;
        let seed = array![7];
        let kp = wots_keygen::<PoseidonHash>(w, seed.span());
        let msg1: felt252 = 100;
        let msg2: felt252 = 200;
        let sig = wots_sign::<PoseidonHash>(w, @kp, msg1);
        let valid = wots_verify::<PoseidonHash>(w, kp.public_chains.span(), msg2, @sig);
        assert(!valid, 'wrong msg should fail');
    }

    #[test]
    #[available_gas(99999999999)]
    fn slow_wots_wrong_key_rejection() {
        let w: u32 = 16;
        let kp_a = wots_keygen::<PoseidonHash>(w, array![1].span());
        let kp_b = wots_keygen::<PoseidonHash>(w, array![2].span());
        let message: felt252 = 42;
        let sig = wots_sign::<PoseidonHash>(w, @kp_a, message);
        let valid = wots_verify::<PoseidonHash>(w, kp_b.public_chains.span(), message, @sig);
        assert(!valid, 'wrong key should fail');
    }
}
