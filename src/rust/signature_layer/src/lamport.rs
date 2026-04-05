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
