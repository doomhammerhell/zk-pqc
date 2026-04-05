use crate::lamport::{felt_to_bits, LamportOTS, LAMPORT_BITS};
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::{HashFunction, PoseidonHash};

#[test]
fn test_keygen_produces_valid_keypair() {
    let hasher = PoseidonHash;
    let seed = [FELT::from(42u64)];
    let kp = LamportOTS::keygen(&hasher, &seed);

    // Verify public[b][i] = H(secret[b][i])
    for b in 0..2usize {
        for i in 0..LAMPORT_BITS {
            assert_eq!(kp.public[b][i], hasher.hash(&[kp.secret[b][i]]));
        }
    }
}

#[test]
fn test_sign_verify_roundtrip() {
    let hasher = PoseidonHash;
    let seed = [FELT::from(123u64)];
    let kp = LamportOTS::keygen(&hasher, &seed);

    let msg = FELT::from(999u64);
    let bits = felt_to_bits(&msg);
    let sig = LamportOTS::sign(&kp, &bits).unwrap();
    assert!(LamportOTS::verify(&hasher, &kp.public, &bits, &sig));
}

#[test]
fn test_wrong_key_rejection() {
    let hasher = PoseidonHash;
    let kp_a = LamportOTS::keygen(&hasher, &[FELT::from(1u64)]);
    let kp_b = LamportOTS::keygen(&hasher, &[FELT::from(2u64)]);

    let msg = FELT::from(42u64);
    let bits = felt_to_bits(&msg);
    let sig = LamportOTS::sign(&kp_a, &bits).unwrap();

    // Verify with wrong key should fail
    assert!(!LamportOTS::verify(&hasher, &kp_b.public, &bits, &sig));
}

#[test]
fn test_wrong_message_rejection() {
    let hasher = PoseidonHash;
    let seed = [FELT::from(7u64)];
    let kp = LamportOTS::keygen(&hasher, &seed);

    let msg1 = FELT::from(100u64);
    let msg2 = FELT::from(200u64);
    let bits1 = felt_to_bits(&msg1);
    let bits2 = felt_to_bits(&msg2);

    let sig = LamportOTS::sign(&kp, &bits1).unwrap();
    assert!(!LamportOTS::verify(&hasher, &kp.public, &bits2, &sig));
}

#[test]
fn test_invalid_message_length() {
    let hasher = PoseidonHash;
    let kp = LamportOTS::keygen(&hasher, &[FELT::from(1u64)]);

    // Too short
    let short_bits = vec![false; 10];
    assert!(LamportOTS::sign(&kp, &short_bits).is_err());

    // Verify with wrong length returns false
    assert!(!LamportOTS::verify(
        &hasher,
        &kp.public,
        &short_bits,
        &crate::lamport::LamportSignature {
            revealed: [FELT::from(0); LAMPORT_BITS],
        }
    ));
}

#[test]
fn test_felt_to_bits_zero() {
    let bits = felt_to_bits(&FELT::from(0u64));
    assert!(bits.iter().all(|&b| !b));
}

#[test]
fn test_felt_to_bits_one() {
    let bits = felt_to_bits(&FELT::from(1u64));
    // Last bit should be 1, all others 0
    assert!(bits[LAMPORT_BITS - 1]);
    assert!(bits[..LAMPORT_BITS - 1].iter().all(|&b| !b));
}

// ============================================================
// WOTS+ Unit Tests
// ============================================================

use crate::wots::{HashMode, WotsError, WotsParams, WotsPlus};

#[test]
fn test_wots_checksum_all_zeros() {
    // All message elements are 0 → checksum = msg_len * (w-1)
    let w = 16;
    let msg_elements = vec![0usize; 63];
    let checksum = WotsPlus::checksum(w, &msg_elements);
    let c: usize = checksum.iter().fold(0usize, |acc, &d| acc * w + d);
    assert_eq!(c, 63 * 15); // 63 * (16-1) = 945
}

#[test]
fn test_wots_checksum_all_max() {
    // All message elements are w-1 → checksum = 0
    let w = 16;
    let msg_elements = vec![15usize; 63];
    let checksum = WotsPlus::checksum(w, &msg_elements);
    let c: usize = checksum.iter().fold(0usize, |acc, &d| acc * w + d);
    assert_eq!(c, 0);
}

#[test]
fn test_wots_checksum_invariant() {
    // For any message, sum of (message_elements[i] + checksum contribution) = constant
    let w = 16;
    let msg_elements = vec![3, 7, 0, 15, 1, 8, 12, 4, 9, 2];
    let checksum = WotsPlus::checksum(w, &msg_elements);

    // All checksum digits should be in [0, w)
    for &d in &checksum {
        assert!(d < w, "Checksum digit {} >= w={}", d, w);
    }

    // Reconstruct checksum value
    let c: usize = checksum.iter().fold(0usize, |acc, &d| acc * w + d);
    let expected_c: usize = msg_elements.iter().map(|&m| (w - 1) - m).sum();
    assert_eq!(c, expected_c);
}

#[test]
fn test_wots_total_chains_w16() {
    let params = WotsParams::default(); // w=16
    let total = WotsPlus::total_chains(&params);
    // msg_len = ceil(252/4) = 63, checksum_len for max_checksum = 63*15 = 945
    // 945 needs ceil(log2(945+1)/4) = ceil(9.88/4) = ceil(2.47) = 3 digits
    assert_eq!(total, 63 + 3); // 66
}

#[test]
fn test_wots_keygen_chain_integrity() {
    let hasher = PoseidonHash;
    let params = WotsParams::default();
    let seed = [FELT::from(42u64)];
    let kp = WotsPlus::keygen(&hasher, &params, &seed);

    let total = WotsPlus::total_chains(&params);
    assert_eq!(kp.secret_chains.len(), total);
    assert_eq!(kp.public_chains.len(), total);

    // Verify public_chains[i] = H^(w-1)(secret_chains[i]) for first few chains
    for i in 0..3 {
        let mut val = kp.secret_chains[i];
        for _ in 0..(params.w - 1) {
            val = hasher.hash(&[val]);
        }
        assert_eq!(val, kp.public_chains[i], "Chain {} integrity failed", i);
    }
}

#[test]
fn test_wots_sign_verify_roundtrip() {
    let hasher = PoseidonHash;
    let params = WotsParams::default();
    let seed = [FELT::from(123u64)];
    let kp = WotsPlus::keygen(&hasher, &params, &seed);

    let msg = FELT::from(999u64);
    let sig = WotsPlus::sign(&hasher, &params, &kp, &[msg]).unwrap();
    assert!(WotsPlus::verify(
        &hasher,
        &params,
        &kp.public_chains,
        &[msg],
        &sig
    ));
}

#[test]
fn test_wots_sign_verify_zero_message() {
    let hasher = PoseidonHash;
    let params = WotsParams::default();
    let seed = [FELT::from(7u64)];
    let kp = WotsPlus::keygen(&hasher, &params, &seed);

    let msg = FELT::from(0u64);
    let sig = WotsPlus::sign(&hasher, &params, &kp, &[msg]).unwrap();
    assert!(WotsPlus::verify(
        &hasher,
        &params,
        &kp.public_chains,
        &[msg],
        &sig
    ));
}

#[test]
fn test_wots_wrong_message_rejection() {
    let hasher = PoseidonHash;
    let params = WotsParams::default();
    let seed = [FELT::from(55u64)];
    let kp = WotsPlus::keygen(&hasher, &params, &seed);

    let msg1 = FELT::from(100u64);
    let msg2 = FELT::from(200u64);
    let sig = WotsPlus::sign(&hasher, &params, &kp, &[msg1]).unwrap();
    assert!(!WotsPlus::verify(
        &hasher,
        &params,
        &kp.public_chains,
        &[msg2],
        &sig
    ));
}

#[test]
fn test_wots_wrong_key_rejection() {
    let hasher = PoseidonHash;
    let params = WotsParams::default();
    let kp_a = WotsPlus::keygen(&hasher, &params, &[FELT::from(1u64)]);
    let kp_b = WotsPlus::keygen(&hasher, &params, &[FELT::from(2u64)]);

    let msg = FELT::from(42u64);
    let sig = WotsPlus::sign(&hasher, &params, &kp_a, &[msg]).unwrap();
    assert!(!WotsPlus::verify(
        &hasher,
        &params,
        &kp_b.public_chains,
        &[msg],
        &sig
    ));
}

#[test]
fn test_wots_invalid_message_length() {
    let hasher = PoseidonHash;
    let params = WotsParams::default();
    let seed = [FELT::from(1u64)];
    let kp = WotsPlus::keygen(&hasher, &params, &seed);

    // Empty message
    let result = WotsPlus::sign(&hasher, &params, &kp, &[]);
    assert!(matches!(
        result,
        Err(WotsError::InvalidMessageLength {
            expected: 1,
            got: 0
        })
    ));

    // Two elements
    let result = WotsPlus::sign(&hasher, &params, &kp, &[FELT::from(1u64), FELT::from(2u64)]);
    assert!(matches!(
        result,
        Err(WotsError::InvalidMessageLength {
            expected: 1,
            got: 2
        })
    ));
}

#[test]
fn test_wots_verify_bad_pubkey_length() {
    let hasher = PoseidonHash;
    let params = WotsParams::default();
    let kp = WotsPlus::keygen(&hasher, &params, &[FELT::from(1u64)]);

    let msg = FELT::from(42u64);
    let sig = WotsPlus::sign(&hasher, &params, &kp, &[msg]).unwrap();

    // Truncated pubkey
    assert!(!WotsPlus::verify(
        &hasher,
        &params,
        &kp.public_chains[..5],
        &[msg],
        &sig
    ));
}

#[test]
fn test_wots_default_params() {
    let params = WotsParams::default();
    assert_eq!(params.w, 16);
    assert_eq!(params.hash_mode, HashMode::Poseidon);
}
