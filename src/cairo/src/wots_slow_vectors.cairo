/// WOTS+ cross-language test vectors.
/// These are computationally intensive and run in a dedicated CI step.
#[cfg(test)]
mod wots_slow_vectors {
    use zk_pqc_cairo::hash_trait::PoseidonHash;
    use zk_pqc_cairo::wots::{keygen as wots_keygen, sign as wots_sign, verify as wots_verify};

    #[test]
    #[available_gas(99999999999)]
    fn slow_vec_wots_001() {
        // w=16, seed=[42], message=999
        let w: u32 = 16;
        let seed = array![42];
        let kp = wots_keygen::<PoseidonHash>(w, seed.span());

        let expected_pub_0: felt252 =
            0x03bfe088907c504df8bb073a52b504fe2bf7b580ddb9b42619a0321877b52e67;
        assert(*kp.public_chains.at(0) == expected_pub_0, 'wots_001 pub[0] mismatch');

        let message: felt252 = 999;
        let sig = wots_sign::<PoseidonHash>(w, @kp, message);
        let valid = wots_verify::<PoseidonHash>(w, kp.public_chains.span(), message, @sig);
        assert(valid, 'wots_001 verify failed');
    }

    #[test]
    #[available_gas(99999999999)]
    fn slow_vec_wots_002() {
        // w=16, seed=[7], message=12345
        let w: u32 = 16;
        let seed = array![7];
        let kp = wots_keygen::<PoseidonHash>(w, seed.span());

        let expected_pub_0: felt252 =
            0x079bf17ffa99182ad61f9611930db76e842731412fb1189afb06a414970a322c;
        assert(*kp.public_chains.at(0) == expected_pub_0, 'wots_002 pub[0] mismatch');

        let message: felt252 = 12345;
        let sig = wots_sign::<PoseidonHash>(w, @kp, message);
        let valid = wots_verify::<PoseidonHash>(w, kp.public_chains.span(), message, @sig);
        assert(valid, 'wots_002 verify failed');
    }
}
