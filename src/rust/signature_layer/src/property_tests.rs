use proptest::prelude::*;
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::{HashFunction, PoseidonHash};

use crate::lamport::{felt_to_bits, LamportOTS, LAMPORT_BITS};
use crate::wots::{WotsParams, WotsPlus};

/// Generate an arbitrary FELT from a random u64 seed.
fn arb_felt() -> impl Strategy<Value = FELT> {
    any::<u64>().prop_map(FELT::from)
}

/// Generate an arbitrary 256-bit message as a bool array.
fn arb_message_bits() -> impl Strategy<Value = Vec<bool>> {
    proptest::collection::vec(any::<bool>(), LAMPORT_BITS..=LAMPORT_BITS)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    // Feature: zk-pqc-framework, Property 5: Lamport OTS Key Pair Integrity
    //
    // For any seed, Lamport keygen shall produce a key pair where for every
    // bit position i and bit value b, public[b][i] = H(secret[b][i]).
    // Validates: Requirements 4.1, 4.2
    #[test]
    fn prop_lamport_keypair_integrity(seed in arb_felt()) {
        let hasher = PoseidonHash;
        let kp = LamportOTS::keygen(&hasher, &[seed]);

        for b in 0..2usize {
            for i in 0..LAMPORT_BITS {
                let expected = hasher.hash(&[kp.secret[b][i]]);
                prop_assert_eq!(kp.public[b][i], expected,
                    "public[{}][{}] != H(secret[{}][{}])", b, i, b, i);
            }
        }
    }

    // Feature: zk-pqc-framework, Property 6: Lamport OTS Sign-Verify Round-Trip
    //
    // For any Lamport key pair and any 256-bit message, signing the message
    // and verifying the signature against the corresponding public key shall return true.
    // Validates: Requirements 4.3
    #[test]
    fn prop_lamport_sign_verify_roundtrip(
        seed in arb_felt(),
        message_bits in arb_message_bits()
    ) {
        let hasher = PoseidonHash;
        let kp = LamportOTS::keygen(&hasher, &[seed]);
        let sig = LamportOTS::sign(&kp, &message_bits).unwrap();
        prop_assert!(
            LamportOTS::verify(&hasher, &kp.public, &message_bits, &sig),
            "Sign-verify round-trip failed"
        );
    }

    // Feature: zk-pqc-framework, Property 7: Lamport OTS Wrong-Key Rejection
    //
    // For any two distinct Lamport key pairs A and B, and any message signed
    // with key A, verifying the signature against key B's public key shall return false.
    // Validates: Requirements 4.4
    #[test]
    fn prop_lamport_wrong_key_rejection(
        seed_a in arb_felt(),
        seed_b in arb_felt(),
        msg_felt in arb_felt()
    ) {
        // Ensure distinct seeds
        prop_assume!(seed_a != seed_b);

        let hasher = PoseidonHash;
        let kp_a = LamportOTS::keygen(&hasher, &[seed_a]);
        let kp_b = LamportOTS::keygen(&hasher, &[seed_b]);

        let bits = felt_to_bits(&msg_felt);
        let sig = LamportOTS::sign(&kp_a, &bits).unwrap();

        prop_assert!(
            !LamportOTS::verify(&hasher, &kp_b.public, &bits, &sig),
            "Verification should fail with wrong key"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    // Feature: zk-pqc-framework, Property 8: WOTS+ Decomposition and Checksum Invariant
    //
    // For any base-w message elements, the checksum C = Σ(w-1-m_i) decomposed into
    // base-w digits shall have all digits in [0, w), and the total sum of all message
    // elements plus all checksum elements equals n*(w-1) where n is the number of
    // message elements.
    // Validates: Requirements 5.1, 5.2
    #[test]
    fn prop_wots_checksum_invariant(
        elements in proptest::collection::vec(0..16usize, 63..=63)
    ) {
        let w = 16usize;
        let n = elements.len();

        // All message elements must be in [0, w)
        for &e in &elements {
            prop_assert!(e < w, "Message element {} not in [0, {})", e, w);
        }

        // Compute checksum
        let checksum_digits = WotsPlus::checksum(w, &elements);

        // All checksum digits must be in [0, w)
        for &d in &checksum_digits {
            prop_assert!(d < w, "Checksum digit {} not in [0, {})", d, w);
        }

        // Invariant: sum of message elements + sum of checksum digits
        // The checksum C = Σ(w-1-m_i) = n*(w-1) - Σ(m_i)
        // So Σ(m_i) + C = n*(w-1)
        // And C is decomposed into base-w digits, so sum of checksum digits
        // is not necessarily C itself, but the checksum value C = n*(w-1) - Σ(m_i).
        let msg_sum: usize = elements.iter().sum();
        let expected_checksum_value = n * (w - 1) - msg_sum;

        // Reconstruct checksum value from its base-w digits (big-endian)
        let mut reconstructed = 0usize;
        for &d in &checksum_digits {
            reconstructed = reconstructed * w + d;
        }
        prop_assert_eq!(reconstructed, expected_checksum_value,
            "Checksum reconstruction mismatch: got {}, expected {}", reconstructed, expected_checksum_value);
    }

    // Feature: zk-pqc-framework, Property 9: WOTS+ Sign-Verify Round-Trip
    //
    // For any WOTS+ key pair and any message, signing the message and verifying
    // the signature against the committed public key shall return true.
    // Validates: Requirements 5.3
    #[test]
    fn prop_wots_sign_verify_roundtrip(
        seed in any::<u64>().prop_map(FELT::from),
        msg in any::<u64>().prop_map(FELT::from)
    ) {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let kp = WotsPlus::keygen(&hasher, &params, &[seed]);
        let sig = WotsPlus::sign(&hasher, &params, &kp, &[msg]).unwrap();
        let valid = WotsPlus::verify(&hasher, &params, &kp.public_chains, &[msg], &sig);
        prop_assert!(valid, "WOTS+ sign-verify round-trip failed");
    }

    // Feature: zk-pqc-framework, Property 10: WOTS+ Forgery Resistance via Checksum
    //
    // For any valid WOTS+ signature, advancing any single chain value by one
    // additional hash iteration shall cause verification to fail, because the
    // checksum constraint prevents the total iteration sum from being maintained.
    // Validates: Requirements 5.4
    #[test]
    fn prop_wots_forgery_resistance(
        seed in any::<u64>().prop_map(FELT::from),
        msg in any::<u64>().prop_map(FELT::from),
        chain_idx in 0..66usize // total_chains for w=16 is 63 + 3 = 66
    ) {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let total = WotsPlus::total_chains(&params);
        let chain_idx = chain_idx % total;

        let kp = WotsPlus::keygen(&hasher, &params, &[seed]);
        let mut sig = WotsPlus::sign(&hasher, &params, &kp, &[msg]).unwrap();

        // Advance one chain value by one additional hash iteration
        sig.chain_values[chain_idx] = hasher.hash(&[sig.chain_values[chain_idx]]);

        let valid = WotsPlus::verify(&hasher, &params, &kp.public_chains, &[msg], &sig);
        prop_assert!(!valid,
            "WOTS+ verification should fail after advancing chain {} by one hash", chain_idx);
    }
}
