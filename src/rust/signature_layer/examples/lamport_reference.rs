//! Lamport OTS — Reference Implementation (NOT production API)
//!
//! Lamport One-Time Signatures are included as a reference and educational
//! implementation only. For production use, prefer WOTS+ which provides
//! equivalent security with significantly smaller key and signature sizes
//! (66 field elements vs 2×256) and lower gas cost.
//!
//! **Rationale for demotion**: ~25B gas, 2×256 key size, strictly inferior to WOTS+.
//!
//! # Running the reference tests
//!
//! ```sh
//! cargo test --example lamport_reference
//! ```

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;

/// Number of bits in a Lamport signature (one secret per message bit).
pub const LAMPORT_BITS: usize = 256;

/// Error types for Lamport OTS operations.
#[derive(Debug, Clone, PartialEq)]
pub enum LamportError {
    /// Message does not have exactly LAMPORT_BITS bits.
    InvalidMessageLength { expected: usize, got: usize },
}

impl std::fmt::Display for LamportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LamportError::InvalidMessageLength { expected, got } => {
                write!(
                    f,
                    "Invalid message length: expected {} bits, got {}",
                    expected, got
                )
            }
        }
    }
}

impl std::error::Error for LamportError {}

/// Lamport OTS key pair: 2×256 secrets and their hash images as the public key.
///
/// `secret[b][i]` is the secret for bit value `b` at position `i`.
/// `public[b][i] = H(secret[b][i])`.
#[derive(Debug, Clone)]
pub struct LamportKeyPair {
    pub secret: [[FELT; LAMPORT_BITS]; 2],
    pub public: [[FELT; LAMPORT_BITS]; 2],
}

/// Lamport OTS signature: one revealed secret per message bit.
///
/// `revealed[i] = secret[msg_bit_i][i]`.
#[derive(Debug, Clone)]
pub struct LamportSignature {
    pub revealed: [FELT; LAMPORT_BITS],
}

/// Lamport One-Time Signature scheme, generic over `HashFunction`.
pub struct LamportOTS;

impl LamportOTS {
    /// Generate a Lamport key pair from a seed.
    ///
    /// Uses the hash function to derive 2×256 secrets deterministically from the seed,
    /// then computes public keys as `H(secret[b][i])`.
    pub fn keygen<H: HashFunction<Digest = FELT>>(hasher: &H, seed: &[FELT]) -> LamportKeyPair {
        let mut secret = [[FELT::from(0); LAMPORT_BITS]; 2];
        let mut public = [[FELT::from(0); LAMPORT_BITS]; 2];

        // Derive secrets: secret[b][i] = H(seed || b || i)
        for b in 0..2u64 {
            for (i, secret_i) in secret[b as usize].iter_mut().enumerate().take(LAMPORT_BITS) {
                let b_felt = FELT::from(b);
                let i_felt = FELT::from(i as u64);
                let mut input = seed.to_vec();
                input.push(b_felt);
                input.push(i_felt);
                *secret_i = hasher.hash(&input);
            }
        }

        // Compute public keys: public[b][i] = H(secret[b][i])
        for b in 0..2usize {
            for i in 0..LAMPORT_BITS {
                public[b][i] = hasher.hash(&[secret[b][i]]);
            }
        }

        LamportKeyPair { secret, public }
    }

    /// Sign a 256-bit message (represented as a slice of bools).
    ///
    /// For each bit position `i`, reveals `secret[msg_bit][i]`.
    pub fn sign(
        key: &LamportKeyPair,
        message_bits: &[bool],
    ) -> Result<LamportSignature, LamportError> {
        if message_bits.len() != LAMPORT_BITS {
            return Err(LamportError::InvalidMessageLength {
                expected: LAMPORT_BITS,
                got: message_bits.len(),
            });
        }

        let mut revealed = [FELT::from(0); LAMPORT_BITS];
        for (i, &msg_bit) in message_bits.iter().enumerate().take(LAMPORT_BITS) {
            let b = if msg_bit { 1 } else { 0 };
            revealed[i] = key.secret[b][i];
        }

        Ok(LamportSignature { revealed })
    }

    /// Verify a Lamport signature against a public key and message bits.
    ///
    /// For each bit position `i`, checks that `H(revealed[i]) == public[msg_bit][i]`.
    /// Returns `false` for any mismatch (does not panic).
    pub fn verify<H: HashFunction<Digest = FELT>>(
        hasher: &H,
        pubkey: &[[FELT; LAMPORT_BITS]; 2],
        message_bits: &[bool],
        sig: &LamportSignature,
    ) -> bool {
        if message_bits.len() != LAMPORT_BITS {
            return false;
        }

        for i in 0..LAMPORT_BITS {
            let b = if message_bits[i] { 1 } else { 0 };
            let hash_of_revealed = hasher.hash(&[sig.revealed[i]]);
            if hash_of_revealed != pubkey[b][i] {
                return false;
            }
        }

        true
    }
}

/// Convert a FELT to a 256-bit boolean array (big-endian).
///
/// Extracts the big-endian byte representation and converts each byte to 8 bits.
pub fn felt_to_bits(felt: &FELT) -> [bool; LAMPORT_BITS] {
    #[allow(unused_imports)]
    use lambdaworks_math::traits::ByteConversion;
    let bytes = felt.to_bytes_be();
    let mut bits = [false; LAMPORT_BITS];
    for (byte_idx, byte) in bytes.iter().enumerate() {
        for bit_idx in 0..8 {
            bits[byte_idx * 8 + bit_idx] = (byte >> (7 - bit_idx)) & 1 == 1;
        }
    }
    bits
}

// ── Reference unit tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    #[test]
    fn test_keygen_produces_valid_keypair() {
        let hasher = PoseidonHash;
        let seed = [FELT::from(42u64)];
        let kp = LamportOTS::keygen(&hasher, &seed);

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

        let short_bits = vec![false; 10];
        assert!(LamportOTS::sign(&kp, &short_bits).is_err());

        assert!(!LamportOTS::verify(
            &hasher,
            &kp.public,
            &short_bits,
            &LamportSignature {
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
        assert!(bits[LAMPORT_BITS - 1]);
        assert!(bits[..LAMPORT_BITS - 1].iter().all(|&b| !b));
    }
}

// ── Reference property tests ──

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    fn arb_felt() -> impl Strategy<Value = FELT> {
        any::<u64>().prop_map(FELT::from)
    }

    fn arb_message_bits() -> impl Strategy<Value = Vec<bool>> {
        proptest::collection::vec(any::<bool>(), LAMPORT_BITS..=LAMPORT_BITS)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        // Feature: zk-pqc-framework, Property 5: Lamport OTS Key Pair Integrity
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
        // Validates: Requirements 4.4
        #[test]
        fn prop_lamport_wrong_key_rejection(
            seed_a in arb_felt(),
            seed_b in arb_felt(),
            msg_felt in arb_felt()
        ) {
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
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        #[ignore]
        fn prop_lamport_keypair_integrity_thorough(seed in arb_felt()) {
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

        #[test]
        #[ignore]
        fn prop_lamport_sign_verify_roundtrip_thorough(
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

        #[test]
        #[ignore]
        fn prop_lamport_wrong_key_rejection_thorough(
            seed_a in arb_felt(),
            seed_b in arb_felt(),
            msg_felt in arb_felt()
        ) {
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
}

fn main() {
    println!("Lamport OTS — Reference Implementation");
    println!("This is NOT a production primitive. Use WOTS+ instead.");
    println!("Run tests with: cargo test --example lamport_reference");
}
