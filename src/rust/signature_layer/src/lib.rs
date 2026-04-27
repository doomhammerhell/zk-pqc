pub mod domain;
pub mod wots;
pub mod xmss;

pub use domain::{canonical_message_hash, Domain, DomainConfig};
pub use wots::{HashMode, WotsError, WotsKeyPair, WotsParams, WotsPlus, WotsSignature};
pub use xmss::{XmssError, XmssSignature, XmssTree};

// NOTE: Lamport OTS has been demoted to a reference-only example.
// It is no longer part of the production API.
// See: examples/lamport_reference.rs
// Rationale: ~25B gas, 2×256 key size, strictly inferior to WOTS+.

#[cfg(test)]
mod tests;

#[cfg(test)]
mod property_tests;
