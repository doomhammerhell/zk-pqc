mod constants;
pub mod hash_trait;
mod hybrid;
pub mod merkle;
mod poseidon;
mod sponge;

// NOTE: Lamport OTS has been demoted to a reference-only implementation.
// It is no longer part of the production API.
// See: reference/lamport.cairo
// Rationale: ~25B gas, 2×256 key size, strictly inferior to WOTS+.

#[cfg(test)]
mod test_vectors;

#[cfg(test)]
mod tests;
pub mod wots;
pub mod zk_pqc_cairo;
