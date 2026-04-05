use core::sha256::compute_sha256_byte_array;
use zk_pqc_cairo::hybrid::{hybrid_hash as hybrid_hash_fn, sha256_words_to_felt};
use zk_pqc_cairo::sponge::{hash as poseidon_hash_fn, hash_with_ds as poseidon_hash_with_ds_fn};

/// Trait-based hash abstraction for the Hash Layer (L1).
/// Upper layers (Merkle, Signature) are generic over this trait.
///
/// The generic parameter T acts as a marker type to select the implementation.
/// All implementations produce felt252 digests.
pub trait HashFunction<T> {
    fn hash(input: Span<felt252>) -> felt252;
    fn hash_with_domain_separation(ds: felt252, input: Span<felt252>) -> felt252;
}

/// Marker type for Poseidon hash.
#[derive(Drop)]
pub struct PoseidonHash {}

/// Marker type for SHA-256 hash.
#[derive(Drop)]
pub struct Sha256Hash {}

/// Marker type for Hybrid hash.
#[derive(Drop)]
pub struct HybridHashWrapper {}

/// Poseidon sponge-based hash implementation.
pub impl PoseidonHashImpl of HashFunction<PoseidonHash> {
    fn hash(input: Span<felt252>) -> felt252 {
        poseidon_hash_fn(input)
    }

    fn hash_with_domain_separation(ds: felt252, input: Span<felt252>) -> felt252 {
        poseidon_hash_with_ds_fn(ds, input)
    }
}

/// SHA-256 wrapper with felt252 serialization.
pub impl Sha256HashImpl of HashFunction<Sha256Hash> {
    fn hash(input: Span<felt252>) -> felt252 {
        sha256_felts(input)
    }

    fn hash_with_domain_separation(ds: felt252, input: Span<felt252>) -> felt252 {
        // Prepend the domain separation felt to the input before hashing
        let mut combined = array![ds];
        let mut i: usize = 0;
        while i < input.len() {
            combined.append(*input.at(i));
            i += 1;
        }
        sha256_felts(combined.span())
    }
}

/// Hybrid-Hash implementation (Poseidon ⊕ truncated SHA-256).
pub impl HybridHashWrapperImpl of HashFunction<HybridHashWrapper> {
    fn hash(input: Span<felt252>) -> felt252 {
        hybrid_hash_fn(input)
    }

    fn hash_with_domain_separation(ds: felt252, input: Span<felt252>) -> felt252 {
        // Use Poseidon with DS for the Poseidon component,
        // keep SHA-256 the same (no DS for SHA component).
        let p_hash = poseidon_hash_with_ds_fn(ds, input);
        let sha_felt = sha256_felts(input);
        p_hash + sha_felt
    }
}

/// Helper: compute SHA-256 over felt252 elements and return truncated felt252.
/// Uses the same truncation as Rust: zero the MSB of the 32-byte BE output.
fn sha256_felts(input: Span<felt252>) -> felt252 {
    let mut ba: ByteArray = Default::default();
    let mut i: usize = 0;
    while i < input.len() {
        let val: u256 = (*input.at(i)).into();
        ba.append_word(val.high.into(), 16);
        ba.append_word(val.low.into(), 16);
        i += 1;
    }

    let sha_res = compute_sha256_byte_array(@ba);
    let sha_span = sha_res.span();

    sha256_words_to_felt(sha_span)
}
