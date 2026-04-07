// NOTE: Lamport OTS property tests have been moved to examples/lamport_reference.rs
// Run them with: cargo test --example lamport_reference

use proptest::prelude::*;
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::{HashFunction, PoseidonHash};

use crate::wots::{WotsParams, WotsPlus};

// ── Fast property tests (10 cases, run in CI by default) ──

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

// ── Thorough property tests (100 cases, run with `cargo test -- --ignored`) ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    #[ignore]
    fn prop_wots_checksum_invariant_thorough(
        elements in proptest::collection::vec(0..16usize, 63..=63)
    ) {
        let w = 16usize;
        let n = elements.len();

        for &e in &elements {
            prop_assert!(e < w, "Message element {} not in [0, {})", e, w);
        }

        let checksum_digits = WotsPlus::checksum(w, &elements);

        for &d in &checksum_digits {
            prop_assert!(d < w, "Checksum digit {} not in [0, {})", d, w);
        }

        let msg_sum: usize = elements.iter().sum();
        let expected_checksum_value = n * (w - 1) - msg_sum;

        let mut reconstructed = 0usize;
        for &d in &checksum_digits {
            reconstructed = reconstructed * w + d;
        }
        prop_assert_eq!(reconstructed, expected_checksum_value,
            "Checksum reconstruction mismatch: got {}, expected {}", reconstructed, expected_checksum_value);
    }

    #[test]
    #[ignore]
    fn prop_wots_sign_verify_roundtrip_thorough(
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

    #[test]
    #[ignore]
    fn prop_wots_forgery_resistance_thorough(
        seed in any::<u64>().prop_map(FELT::from),
        msg in any::<u64>().prop_map(FELT::from),
        chain_idx in 0..66usize
    ) {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let total = WotsPlus::total_chains(&params);
        let chain_idx = chain_idx % total;

        let kp = WotsPlus::keygen(&hasher, &params, &[seed]);
        let mut sig = WotsPlus::sign(&hasher, &params, &kp, &[msg]).unwrap();

        sig.chain_values[chain_idx] = hasher.hash(&[sig.chain_values[chain_idx]]);

        let valid = WotsPlus::verify(&hasher, &params, &kp.public_chains, &[msg], &sig);
        prop_assert!(!valid,
            "WOTS+ verification should fail after advancing chain {} by one hash", chain_idx);
    }
}
