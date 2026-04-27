use crate::constants::FELT;
use crate::hybrid::HybridHash as HybridHashImpl;
use crate::sponge::PoseidonSponge;
use lambdaworks_math::traits::ByteConversion;
use sha2::{Digest, Sha256};

/// Trait-based hash abstraction for the Hash Layer (L1).
/// Upper layers (Merkle, Signature) are generic over this trait,
/// enabling hash-agility without code changes.
pub trait HashFunction {
    type Digest;
    fn hash(&self, input: &[FELT]) -> Self::Digest;
    fn hash_with_domain_separation(&self, ds: FELT, input: &[FELT]) -> Self::Digest;
}

/// Poseidon sponge-based hash (t=6, RF=8, RP=83).
#[derive(Clone, Copy, Debug)]
pub struct PoseidonHash;

impl HashFunction for PoseidonHash {
    type Digest = FELT;

    fn hash(&self, input: &[FELT]) -> FELT {
        PoseidonSponge::hash(input)
    }

    fn hash_with_domain_separation(&self, ds: FELT, input: &[FELT]) -> FELT {
        PoseidonSponge::hash_with_ds(ds, input)
    }
}

/// SHA-256 wrapper with FELT serialization.
/// Serializes FELT elements to big-endian bytes, hashes with SHA-256,
/// then converts the result back to a FELT (truncated to fit in the field).
pub struct Sha256Hash;

impl Sha256Hash {
    fn sha256_felts(input: &[FELT]) -> FELT {
        let mut hasher = Sha256::new();
        for val in input {
            hasher.update(val.to_bytes_be());
        }
        let sha_result = hasher.finalize();

        // Truncate to fit in Stark252 field (zero the MSB, same approach as hybrid.rs)
        // MSB byte zeroed → 248 bits effective → 124-bit collision resistance
        let mut padded = [0u8; 32];
        padded[1..32].copy_from_slice(&sha_result[1..32]);
        FELT::from_bytes_be(&padded).unwrap()
    }
}

impl HashFunction for Sha256Hash {
    type Digest = FELT;

    fn hash(&self, input: &[FELT]) -> FELT {
        Self::sha256_felts(input)
    }

    fn hash_with_domain_separation(&self, ds: FELT, input: &[FELT]) -> FELT {
        // Prepend the domain separation felt to the input before hashing
        let mut combined = Vec::with_capacity(1 + input.len());
        combined.push(ds);
        combined.extend_from_slice(input);
        Self::sha256_felts(&combined)
    }
}

/// Hybrid-Hash: Poseidon ⊕ truncated SHA-256.
///
/// SHA-256 truncation security impact: MSB byte zeroed → 248 bits effective
/// → 124-bit collision resistance.
pub struct HybridHashWrapper;

impl HashFunction for HybridHashWrapper {
    type Digest = FELT;

    fn hash(&self, input: &[FELT]) -> FELT {
        HybridHashImpl::hash(input)
    }

    fn hash_with_domain_separation(&self, ds: FELT, input: &[FELT]) -> FELT {
        // Both components MUST respect domain separation to prevent
        // cross-context collisions. Previously the SHA-256 component
        // ignored the DS tag — a real cryptographic bug.
        let poseidon_hash = PoseidonSponge::hash_with_ds(ds, input);

        // SHA-256 component: hash(ds || input) so DS affects the digest
        let mut hasher = Sha256::new();
        hasher.update(ds.to_bytes_be());
        for val in input {
            hasher.update(val.to_bytes_be());
        }
        let sha_result = hasher.finalize();

        // MSB byte zeroed → 248 bits effective → 124-bit collision resistance
        let mut padded_sha = [0u8; 32];
        padded_sha[1..32].copy_from_slice(&sha_result[1..32]);
        let sha_felt = FELT::from_bytes_be(&padded_sha).unwrap();

        poseidon_hash + sha_felt
    }
}
