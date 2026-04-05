#[cfg(test)]
mod tests {
    use core::array::ArrayTrait;
    use zk_pqc_cairo::hash_trait::{HashFunction, HybridHashWrapper, PoseidonHash, Sha256Hash};
    use zk_pqc_cairo::hybrid::hybrid_hash;
    use zk_pqc_cairo::poseidon::permute;
    use zk_pqc_cairo::sponge::hash;

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
            }
            i += 1;
        }
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

    // --- HashFunction trait tests ---

    #[test]
    fn test_poseidon_trait_hash_nonzero() {
        let input = array![1, 2, 3];
        let result = HashFunction::<PoseidonHash>::hash(input.span());
        assert(result != 0, 'Poseidon trait hash is zero');
    }

    #[test]
    fn test_sha256_trait_hash_nonzero() {
        let input = array![1, 2, 3];
        let result = HashFunction::<Sha256Hash>::hash(input.span());
        assert(result != 0, 'SHA256 trait hash is zero');
    }

    #[test]
    fn test_hybrid_trait_hash_nonzero() {
        let input = array![1, 2, 3];
        let result = HashFunction::<HybridHashWrapper>::hash(input.span());
        assert(result != 0, 'Hybrid trait hash is zero');
    }

    #[test]
    fn test_poseidon_trait_deterministic() {
        let input = array![42, 99];
        let a = HashFunction::<PoseidonHash>::hash(input.span());
        let b = HashFunction::<PoseidonHash>::hash(input.span());
        assert(a == b, 'Poseidon not deterministic');
    }

    #[test]
    fn test_sha256_trait_deterministic() {
        let input = array![42, 99];
        let a = HashFunction::<Sha256Hash>::hash(input.span());
        let b = HashFunction::<Sha256Hash>::hash(input.span());
        assert(a == b, 'SHA256 not deterministic');
    }

    #[test]
    fn test_hybrid_trait_deterministic() {
        let input = array![42, 99];
        let a = HashFunction::<HybridHashWrapper>::hash(input.span());
        let b = HashFunction::<HybridHashWrapper>::hash(input.span());
        assert(a == b, 'Hybrid not deterministic');
    }

    #[test]
    fn test_poseidon_domain_separation_changes_output() {
        let input = array![1, 2];
        let no_ds = HashFunction::<PoseidonHash>::hash(input.span());
        let with_ds = HashFunction::<PoseidonHash>::hash_with_domain_separation(1, input.span());
        assert(no_ds != with_ds, 'Poseidon DS no effect');
    }

    #[test]
    fn test_sha256_domain_separation_changes_output() {
        let input = array![1, 2];
        let no_ds = HashFunction::<Sha256Hash>::hash(input.span());
        let with_ds = HashFunction::<Sha256Hash>::hash_with_domain_separation(1, input.span());
        assert(no_ds != with_ds, 'SHA256 DS no effect');
    }

    #[test]
    fn test_hybrid_domain_separation_changes_output() {
        let input = array![1, 2];
        let no_ds = HashFunction::<HybridHashWrapper>::hash(input.span());
        let with_ds = HashFunction::<
            HybridHashWrapper,
        >::hash_with_domain_separation(1, input.span());
        assert(no_ds != with_ds, 'Hybrid DS no effect');
    }

    // --- Merkle tree tests ---

    use zk_pqc_cairo::merkle::{build_tree, prove, root, verify};

    /// Helper: compute H(left, right) using PoseidonHash.
    fn h(left: felt252, right: felt252) -> felt252 {
        HashFunction::<PoseidonHash>::hash(array![left, right].span())
    }

    #[test]
    fn test_merkle_two_leaf_tree() {
        let leaves = array![1, 2];
        let nodes = build_tree::<PoseidonHash>(leaves.span());
        let r = root(nodes.span());
        let expected = h(1, 2);
        assert(r == expected, 'two-leaf root mismatch');
    }

    #[test]
    fn test_merkle_four_leaf_tree() {
        let leaves = array![10, 20, 30, 40];
        let nodes = build_tree::<PoseidonHash>(leaves.span());
        let r = root(nodes.span());
        let h01 = h(10, 20);
        let h23 = h(30, 40);
        let expected = h(h01, h23);
        assert(r == expected, 'four-leaf root mismatch');
    }

    #[test]
    fn test_merkle_three_leaf_pads_to_four() {
        let leaves = array![1, 2, 3];
        let nodes = build_tree::<PoseidonHash>(leaves.span());
        let r = root(nodes.span());
        let h01 = h(1, 2);
        let h23 = h(3, 0);
        let expected = h(h01, h23);
        assert(r == expected, 'three-leaf root mismatch');
    }

    #[test]
    fn test_merkle_prove_verify_round_trip() {
        let leaves = array![10, 20, 30, 40];
        let nodes = build_tree::<PoseidonHash>(leaves.span());
        let r = root(nodes.span());
        let leaves_span = leaves.span();

        let mut i: u32 = 0;
        while i < 4 {
            let proof = prove(nodes.span(), 4, i);
            let valid = verify::<PoseidonHash>(r, *leaves_span.at(i), @proof);
            assert(valid, 'round-trip verify failed');
            i += 1;
        };
    }

    #[test]
    fn test_merkle_verify_wrong_leaf() {
        let leaves = array![10, 20, 30, 40];
        let nodes = build_tree::<PoseidonHash>(leaves.span());
        let r = root(nodes.span());
        let proof = prove(nodes.span(), 4, 0);
        let wrong_leaf: felt252 = 999;
        let valid = verify::<PoseidonHash>(r, wrong_leaf, @proof);
        assert(!valid, 'wrong leaf should fail');
    }

    #[test]
    fn test_merkle_verify_wrong_root() {
        let leaves = array![10, 20];
        let nodes = build_tree::<PoseidonHash>(leaves.span());
        let proof = prove(nodes.span(), 2, 0);
        let wrong_root: felt252 = 999;
        let valid = verify::<PoseidonHash>(wrong_root, 10, @proof);
        assert(!valid, 'wrong root should fail');
    }

    #[test]
    fn test_merkle_verify_tampered_sibling() {
        let leaves = array![10, 20, 30, 40];
        let nodes = build_tree::<PoseidonHash>(leaves.span());
        let r = root(nodes.span());
        let proof = prove(nodes.span(), 4, 0);

        // Build a tampered proof with first sibling replaced by 999
        let orig_siblings = @proof.siblings;
        let orig_path_bits = @proof.path_bits;
        let mut tampered_siblings: Array<felt252> = ArrayTrait::new();
        let mut tampered_path_bits: Array<bool> = ArrayTrait::new();

        let mut j: u32 = 0;
        while j < orig_siblings.len() {
            if j == 0 {
                tampered_siblings.append(999);
            } else {
                tampered_siblings.append(*orig_siblings.at(j));
            }
            tampered_path_bits.append(*orig_path_bits.at(j));
            j += 1;
        }

        let tampered_proof = zk_pqc_cairo::merkle::MerkleProof {
            siblings: tampered_siblings, path_bits: tampered_path_bits,
        };
        let valid = verify::<PoseidonHash>(r, 10, @tampered_proof);
        assert(!valid, 'tampered sib should fail');
    }

    // --- Lamport OTS tests ---
    // Note: Full 256-bit Lamport keygen is expensive in Cairo (512 Poseidon hashes).
    // Tests validate the core logic by checking a subset of positions.

    use zk_pqc_cairo::lamport::{
        felt_to_bits, keygen as lamport_keygen, sign as lamport_sign, verify as lamport_verify,
    };

    #[test]
    #[available_gas(99999999999)]
    fn test_lamport_keygen_integrity() {
        let seed = array![42];
        let kp = lamport_keygen::<PoseidonHash>(seed.span());

        // Verify public_0[i] = H(secret_0[i]) and public_1[i] = H(secret_1[i])
        // Check first 4 positions to keep test fast
        let mut i: u32 = 0;
        while i < 4 {
            let h0 = HashFunction::<PoseidonHash>::hash(array![*kp.secret_0.at(i)].span());
            assert(h0 == *kp.public_0.at(i), 'pub0 mismatch');
            let h1 = HashFunction::<PoseidonHash>::hash(array![*kp.secret_1.at(i)].span());
            assert(h1 == *kp.public_1.at(i), 'pub1 mismatch');
            i += 1;
        };
    }

    #[test]
    #[available_gas(99999999999)]
    fn test_lamport_sign_verify_roundtrip() {
        let seed = array![123];
        let kp = lamport_keygen::<PoseidonHash>(seed.span());
        let bits = felt_to_bits(999);
        let sig = lamport_sign(@kp, bits.span());
        let valid = lamport_verify::<
            PoseidonHash,
        >(kp.public_0.span(), kp.public_1.span(), bits.span(), @sig);
        assert(valid, 'roundtrip verify failed');
    }

    #[test]
    #[available_gas(99999999999)]
    fn test_lamport_wrong_key_rejection() {
        let kp_a = lamport_keygen::<PoseidonHash>(array![1].span());
        let kp_b = lamport_keygen::<PoseidonHash>(array![2].span());
        let bits = felt_to_bits(42);
        let sig = lamport_sign(@kp_a, bits.span());
        let valid = lamport_verify::<
            PoseidonHash,
        >(kp_b.public_0.span(), kp_b.public_1.span(), bits.span(), @sig);
        assert(!valid, 'wrong key should fail');
    }

    #[test]
    #[available_gas(99999999999)]
    fn test_lamport_wrong_message_rejection() {
        let kp = lamport_keygen::<PoseidonHash>(array![7].span());
        let bits1 = felt_to_bits(100);
        let bits2 = felt_to_bits(200);
        let sig = lamport_sign(@kp, bits1.span());
        let valid = lamport_verify::<
            PoseidonHash,
        >(kp.public_0.span(), kp.public_1.span(), bits2.span(), @sig);
        assert(!valid, 'wrong msg should fail');
    }

    #[test]
    fn test_felt_to_bits_zero() {
        let bits = felt_to_bits(0);
        assert(bits.len() == 256, 'should be 256 bits');
        let mut i: u32 = 0;
        while i < bits.len() {
            assert(*bits.at(i) == 0, 'zero should have all 0 bits');
            i += 1;
        };
    }

    #[test]
    fn test_felt_to_bits_one() {
        let bits = felt_to_bits(1);
        assert(bits.len() == 256, 'should be 256 bits');
        // Last bit should be 1
        assert(*bits.at(255) == 1, 'last bit should be 1');
        // All others should be 0
        let mut i: u32 = 0;
        while i < 255 {
            assert(*bits.at(i) == 0, 'other bits should be 0');
            i += 1;
        };
    }

    // --- WOTS+ tests ---

    use zk_pqc_cairo::wots::{
        checksum, keygen as wots_keygen, message_len, sign as wots_sign, total_chains,
        verify as wots_verify,
    };

    #[test]
    fn test_wots_message_len() {
        // w=16, log_w=4, ceil(252/4) = 63
        assert(message_len(16) == 63, 'msg_len w=16 should be 63');
    }

    #[test]
    fn test_wots_total_chains() {
        // w=16: 63 message + 3 checksum = 66
        assert(total_chains(16) == 66, 'total w=16 should be 66');
    }

    #[test]
    fn test_wots_checksum_all_zeros() {
        // All zeros: each element is 0, checksum = msg_len * (w-1)
        let w: u32 = 16;
        let ml = message_len(w);
        let mut elems: Array<u32> = ArrayTrait::new();
        let mut i: u32 = 0;
        while i < ml {
            elems.append(0);
            i += 1;
        }
        let cs = checksum(w, elems.span());
        // Checksum value = 63 * 15 = 945
        // Verify all checksum digits are in [0, w)
        let mut j: u32 = 0;
        while j < cs.len() {
            assert(*cs.at(j) < w, 'cs digit >= w');
            j += 1;
        }
        // Reconstruct checksum value from digits
        let mut val: u32 = 0;
        let mut k: u32 = 0;
        while k < cs.len() {
            val = val * w + *cs.at(k);
            k += 1;
        }
        assert(val == ml * (w - 1), 'all-zero cs mismatch');
    }

    #[test]
    fn test_wots_checksum_all_max() {
        // All max (w-1): checksum = 0
        let w: u32 = 16;
        let ml = message_len(w);
        let mut elems: Array<u32> = ArrayTrait::new();
        let mut i: u32 = 0;
        while i < ml {
            elems.append(w - 1);
            i += 1;
        }
        let cs = checksum(w, elems.span());
        // Checksum value should be 0
        let mut val: u32 = 0;
        let mut k: u32 = 0;
        while k < cs.len() {
            val = val * w + *cs.at(k);
            k += 1;
        }
        assert(val == 0, 'all-max cs should be 0');
    }

    #[test]
    fn test_wots_checksum_mixed() {
        // Mixed: some zeros, some max
        let w: u32 = 16;
        let mut elems: Array<u32> = ArrayTrait::new();
        // 10 elements of value 5, rest are 0
        let ml = message_len(w);
        let mut i: u32 = 0;
        while i < ml {
            if i < 10 {
                elems.append(5);
            } else {
                elems.append(0);
            }
            i += 1;
        }
        let cs = checksum(w, elems.span());
        // Expected: 10*(15-5) + 53*15 = 100 + 795 = 895
        let mut val: u32 = 0;
        let mut k: u32 = 0;
        while k < cs.len() {
            val = val * w + *cs.at(k);
            k += 1;
        }
        assert(val == 895, 'mixed cs mismatch');
    }

    #[test]
    #[available_gas(99999999999)]
    fn test_wots_keygen_chain_integrity() {
        // Verify public = H^(w-1)(secret) for first few chains
        let w: u32 = 16;
        let seed = array![42];
        let kp = wots_keygen::<PoseidonHash>(w, seed.span());

        // Check first 3 chains
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
    fn test_wots_sign_verify_roundtrip() {
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
    fn test_wots_wrong_message_rejection() {
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
    fn test_wots_wrong_key_rejection() {
        let w: u32 = 16;
        let kp_a = wots_keygen::<PoseidonHash>(w, array![1].span());
        let kp_b = wots_keygen::<PoseidonHash>(w, array![2].span());
        let message: felt252 = 42;
        let sig = wots_sign::<PoseidonHash>(w, @kp_a, message);
        let valid = wots_verify::<PoseidonHash>(w, kp_b.public_chains.span(), message, @sig);
        assert(!valid, 'wrong key should fail');
    }
}
