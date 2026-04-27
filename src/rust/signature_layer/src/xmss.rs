//! XMSS (eXtended Merkle Signature Scheme) — Many-Time Signatures from WOTS+.
//!
//! # Mathematical Foundation
//!
//! XMSS transforms a one-time signature scheme (WOTS+) into a many-time scheme
//! by placing N WOTS+ key pairs as leaves of a Merkle tree. Each signature
//! includes:
//! 1. The WOTS+ signature for the message
//! 2. A Merkle inclusion proof linking the WOTS+ public key to the root
//!
//! ## Security
//!
//! - Each index can only be used once (enforced by construction)
//! - Supports up to 2^h signatures where h is the tree height
//! - Uses HexTree (arity-16) for reduced proof size in STARK contexts
//!
//! ## Formal Properties
//!
//! 1. **Existential Unforgeability**: Infeasible to forge without breaking WOTS+ or Merkle hash
//! 2. **Index Binding**: Each signature is bound to a specific tree index
//! 3. **Stateless Verification**: Verifier only needs the Merkle root
//!
//! # Type Parameters
//!
//! - `H`: Hash function implementing `HashFunction<Digest = FELT>`
//! - `Depth`: Tree height (determines number of signatures: 16^Depth for HexTree)
//!
//! # Usage
//!
//! ```rust
//! use zk_pqc_signature_layer::xmss::{XmssTree, XmssSignature};
//! use zk_pqc_signature_layer::{WotsParams, HashMode};
//! use zk_pqc_hash_layer::traits::PoseidonHash;
//! use zk_pqc_hash_layer::constants::FELT;
//!
//! let hasher = PoseidonHash;
//! let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
//! let seed = [FELT::from(42u64)];
//!
//! // Create XMSS tree with height 2 (256 signatures)
//! let mut xmss = XmssTree::new(&hasher, &params, &seed, 2).unwrap();
//! let root = xmss.root();
//!
//! // Sign with index 0
//! let msg = FELT::from(123u64);
//! let sig = xmss.sign(0, &msg).unwrap();
//!
//! // Verify
//! assert!(XmssTree::verify(&hasher, &params, &root, 0, &msg, &sig));
//! ```

use crate::wots::{WotsError, WotsKeyPair, WotsParams, WotsPlus, WotsSignature};
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;
use zk_pqc_merkle_layer::{HexProof, HexTree};

/// XMSS signature combining WOTS+ with Merkle inclusion proof.
#[derive(Debug, Clone)]
pub struct XmssSignature {
    /// Tree index used for signing.
    pub index: u64,
    /// WOTS+ signature for the message.
    pub wots_sig: WotsSignature,
    /// HexTree inclusion proof for the WOTS+ public key.
    pub proof: HexProof,
    /// WOTS+ public key commitment (leaf value).
    pub wots_pubkey_commitment: FELT,
}

/// Error types for XMSS operations.
#[derive(Debug, Clone, PartialEq)]
pub enum XmssError {
    /// Index already used.
    IndexAlreadyUsed { index: u64 },
    /// Index out of bounds for tree height.
    IndexOutOfBounds { index: u64, max: u64 },
    /// WOTS+ signing error.
    WotsError(WotsError),
    /// HexTree error.
    HexTreeError(String),
}

impl std::fmt::Display for XmssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XmssError::IndexAlreadyUsed { index } => {
                write!(f, "XMSS index {} already used", index)
            }
            XmssError::IndexOutOfBounds { index, max } => {
                write!(f, "XMSS index {} out of bounds (max: {})", index, max)
            }
            XmssError::WotsError(e) => write!(f, "WOTS+ error: {}", e),
            XmssError::HexTreeError(e) => write!(f, "HexTree error: {}", e),
        }
    }
}

impl std::error::Error for XmssError {}

impl From<WotsError> for XmssError {
    fn from(e: WotsError) -> Self {
        XmssError::WotsError(e)
    }
}

/// XMSS tree state for many-time signatures.
///
/// Maintains the tree structure and tracks used indices.
pub struct XmssTree<'a, H: HashFunction<Digest = FELT> + Clone> {
    hasher: &'a H,
    params: &'a WotsParams,
    /// All WOTS+ key pairs (leaves of the tree).
    wots_keys: Vec<WotsKeyPair>,
    /// HexTree for commitment to public keys.
    tree: HexTree<H>,
    /// Set of used indices.
    used_indices: Vec<bool>,
    /// Tree height (depth).
    height: usize,
    /// Next available index (for sequential use).
    next_index: u64,
}

impl<'a, H: HashFunction<Digest = FELT> + Clone> XmssTree<'a, H> {
    /// Creates a new XMSS tree.
    ///
    /// # Arguments
    /// * `hasher` - Hash function for all operations
    /// * `params` - WOTS+ parameters
    /// * `seed` - Master seed for deterministic key generation
    /// * `height` - Tree height (number of signatures = 16^height)
    ///
    /// # Returns
    /// * `Ok(XmssTree)` - Successfully constructed tree
    /// * `Err(XmssError)` - If construction fails
    pub fn new(
        hasher: &'a H,
        params: &'a WotsParams,
        seed: &[FELT],
        height: usize,
    ) -> Result<Self, XmssError> {
        if height == 0 || height > 8 {
            // Practical limit: 16^8 = 2^32 signatures
            return Err(XmssError::HexTreeError(
                "Height must be in [1, 8]".to_string(),
            ));
        }

        // Generate all WOTS+ key pairs
        let num_keys = 16usize.pow(height as u32);
        let mut wots_keys = Vec::with_capacity(num_keys);

        for i in 0..num_keys {
            // Derive per-key seed: H(seed || i)
            let key_seed_input = [seed, &[FELT::from(i as u64)]].concat();
            let key_seed = hasher.hash(&key_seed_input);
            let kp = WotsPlus::keygen(hasher, params, &[key_seed]);
            wots_keys.push(kp);
        }

        // Compute leaf commitments (hash of WOTS+ public chains)
        let leaves: Vec<FELT> = wots_keys
            .iter()
            .map(|kp| {
                // Hash all public chains together as the leaf value
                hasher.hash(&kp.public_chains)
            })
            .collect();

        // Build HexTree over the commitments
        let tree = HexTree::new(hasher.clone(), leaves)
            .map_err(|e| XmssError::HexTreeError(format!("{:?}", e)))?;

        Ok(Self {
            hasher,
            params,
            wots_keys,
            tree,
            used_indices: vec![false; num_keys],
            height,
            next_index: 0,
        })
    }

    /// Returns the XMSS root (Merkle root of WOTS+ commitments).
    pub fn root(&self) -> FELT {
        self.tree.root()
    }

    /// Returns the tree height.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns the total number of signatures available.
    pub fn max_signatures(&self) -> u64 {
        16u64.pow(self.height as u32)
    }

    /// Returns the number of remaining (unused) signatures.
    pub fn remaining(&self) -> u64 {
        self.used_indices.iter().filter(|&&u| !u).count() as u64
    }

    /// Returns whether a specific index has been used.
    pub fn is_used(&self, index: u64) -> bool {
        if index >= self.max_signatures() {
            return false;
        }
        self.used_indices[index as usize]
    }

    /// Signs a message using a specific index.
    ///
    /// # Arguments
    /// * `index` - Tree index to use (must be unused)
    /// * `message` - Message to sign (single FELT)
    ///
    /// # Returns
    /// * `Ok(XmssSignature)` - Signature
    /// * `Err(XmssError::IndexAlreadyUsed)` - Index already consumed
    /// * `Err(XmssError::IndexOutOfBounds)` - Index exceeds tree capacity
    pub fn sign(&mut self, index: u64, message: &FELT) -> Result<XmssSignature, XmssError> {
        // Check bounds
        if index >= self.max_signatures() {
            return Err(XmssError::IndexOutOfBounds {
                index,
                max: self.max_signatures() - 1,
            });
        }

        // Check not already used
        if self.used_indices[index as usize] {
            return Err(XmssError::IndexAlreadyUsed { index });
        }

        // Get WOTS+ key for this index
        let kp = &self.wots_keys[index as usize];

        // Sign with WOTS+
        let wots_sig = WotsPlus::sign(self.hasher, self.params, kp, &[*message])?;

        // Get Merkle proof for this index
        let proof = self
            .tree
            .prove(index as usize)
            .map_err(|e| XmssError::HexTreeError(format!("{:?}", e)))?;

        // Compute commitment (leaf value)
        let wots_pubkey_commitment = self.hasher.hash(&kp.public_chains);

        // Mark index as used
        self.used_indices[index as usize] = true;
        if index == self.next_index {
            self.next_index += 1;
        }

        Ok(XmssSignature {
            index,
            wots_sig,
            proof,
            wots_pubkey_commitment,
        })
    }

    /// Signs with the next available index.
    ///
    /// Convenience method for sequential signing.
    pub fn sign_next(&mut self, message: &FELT) -> Result<XmssSignature, XmssError> {
        let idx = self.next_index;
        if idx >= self.max_signatures() {
            return Err(XmssError::IndexOutOfBounds {
                index: idx,
                max: self.max_signatures() - 1,
            });
        }
        self.sign(idx, message)
    }

    /// Verifies an XMSS signature.
    ///
    /// # Arguments
    /// * `hasher` - Hash function (must match signing hasher)
    /// * `params` - WOTS+ parameters (must match signing params)
    /// * `root` - XMSS root commitment
    /// * `index` - Index claimed in signature
    /// * `message` - Message being verified
    /// * `sig` - XMSS signature
    ///
    /// # Returns
    /// * `true` if signature is valid
    /// * `false` otherwise
    ///
    /// # Formal Verification
    /// This implements the XMSS verification predicate:
    /// verify(root, index, M, sig) ↔
    ///   WOTS.verify(sig.wots, M) ∧ HexTree.verify(root, sig.commitment, sig.proof, index)
    pub fn verify(
        hasher: &H,
        params: &WotsParams,
        root: &FELT,
        index: u64,
        message: &FELT,
        sig: &XmssSignature,
    ) -> bool {
        // Verify index matches
        if sig.index != index {
            return false;
        }

        // Verify WOTS+ signature
        // We need the public key chains, but we only have the commitment.
        // For verification, we verify that the WOTS+ signature reconstructs to
        // a public key whose commitment matches the proof's leaf.
        //
        // However, XMSS verification typically requires the verifier to know
        // that the WOTS+ signature is valid. We verify:
        // 1. The WOTS+ signature is internally consistent (checksum, etc.)
        // 2. The commitment matches the Merkle proof leaf

        // First, compute the public key from the signature
        // In WOTS+, verification reconstructs the public key from signature
        let reconstructed_pubkey =
            Self::reconstruct_pubkey_from_sig(hasher, params, message, &sig.wots_sig);

        // Verify commitment matches
        let computed_commitment = hasher.hash(&reconstructed_pubkey);
        if computed_commitment != sig.wots_pubkey_commitment {
            return false;
        }

        // Verify Merkle inclusion
        HexTree::verify(
            hasher,
            root,
            &sig.wots_pubkey_commitment,
            &sig.proof,
            index as usize,
        )
    }

    /// Reconstructs the WOTS+ public key from signature during verification.
    ///
    /// This implements the WOTS+ verification logic that iterates each
    /// signature chain value to reconstruct the public key endpoint.
    fn reconstruct_pubkey_from_sig(
        hasher: &H,
        params: &WotsParams,
        message: &FELT,
        sig: &WotsSignature,
    ) -> Vec<FELT> {
        let msg_elements = WotsPlus::decompose_message(params.w, message);
        let checksum_elements = WotsPlus::checksum(params.w, &msg_elements);

        let mut all_elements = msg_elements;
        all_elements.extend_from_slice(&checksum_elements);

        let total = WotsPlus::total_chains(params);
        if all_elements.len() != total {
            return Vec::new(); // Error case
        }

        let mut reconstructed = Vec::with_capacity(total);

        for (i, &m_i) in all_elements.iter().enumerate() {
            if i >= sig.chain_values.len() {
                return Vec::new(); // Error case
            }

            let remaining = (params.w - 1) - m_i;
            let mut current = sig.chain_values[i];

            // Apply remaining hash iterations
            for _ in 0..remaining {
                current = hasher.hash(&[current]);
            }

            reconstructed.push(current);
        }

        reconstructed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    #[test]
    fn test_xmss_new() {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let seed = [FELT::from(42u64)];

        let xmss = XmssTree::new(&hasher, &params, &seed, 2).unwrap();

        assert_eq!(xmss.height(), 2);
        assert_eq!(xmss.max_signatures(), 256); // 16^2
        assert_eq!(xmss.remaining(), 256);
        assert_ne!(xmss.root(), FELT::zero());
    }

    #[test]
    fn test_xmss_sign_verify() {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let seed = [FELT::from(123u64)];
        let mut xmss = XmssTree::new(&hasher, &params, &seed, 2).unwrap();

        let root = xmss.root();
        let msg = FELT::from(999u64);

        // Sign with index 0
        let sig = xmss.sign(0, &msg).unwrap();
        assert_eq!(sig.index, 0);

        // Verify
        assert!(XmssTree::verify(&hasher, &params, &root, 0, &msg, &sig));

        // Wrong message should fail
        let wrong_msg = FELT::from(888u64);
        assert!(!XmssTree::verify(
            &hasher, &params, &root, 0, &wrong_msg, &sig
        ));

        // Wrong index should fail
        assert!(!XmssTree::verify(&hasher, &params, &root, 1, &msg, &sig));
    }

    #[test]
    fn test_xmss_double_sign_error() {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let seed = [FELT::from(55u64)];
        let mut xmss = XmssTree::new(&hasher, &params, &seed, 2).unwrap();

        let msg = FELT::from(111u64);

        // First sign should succeed
        xmss.sign(0, &msg).unwrap();

        // Second sign with same index should fail
        let result = xmss.sign(0, &msg);
        assert!(matches!(
            result,
            Err(XmssError::IndexAlreadyUsed { index: 0 })
        ));
    }

    #[test]
    fn test_xmss_index_tracking() {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let seed = [FELT::from(77u64)];
        let mut xmss = XmssTree::new(&hasher, &params, &seed, 2).unwrap();

        assert!(!xmss.is_used(0));
        assert!(!xmss.is_used(1));

        xmss.sign(0, &FELT::from(1u64)).unwrap();
        assert!(xmss.is_used(0));
        assert!(!xmss.is_used(1));

        xmss.sign(1, &FELT::from(2u64)).unwrap();
        assert!(xmss.is_used(0));
        assert!(xmss.is_used(1));

        assert_eq!(xmss.remaining(), 254);
    }

    #[test]
    fn test_xmss_out_of_bounds() {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let seed = [FELT::from(88u64)];
        let mut xmss = XmssTree::new(&hasher, &params, &seed, 1).unwrap(); // 16 signatures

        // Index 15 is valid
        xmss.sign(15, &FELT::from(1u64)).unwrap();

        // Index 16 is out of bounds
        let result = xmss.sign(16, &FELT::from(1u64));
        assert!(matches!(
            result,
            Err(XmssError::IndexOutOfBounds { index: 16, max: 15 })
        ));
    }

    #[test]
    fn test_xmss_multiple_signatures() {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let seed = [FELT::from(99u64)];
        let mut xmss = XmssTree::new(&hasher, &params, &seed, 2).unwrap();

        let root = xmss.root();

        // Sign multiple messages with different indices
        for i in 0..10 {
            let msg = FELT::from(1000u64 + i);
            let sig = xmss.sign(i, &msg).unwrap();
            assert!(XmssTree::verify(&hasher, &params, &root, i, &msg, &sig));
        }
    }

    #[test]
    fn test_xmss_sign_next() {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let seed = [FELT::from(111u64)];
        let mut xmss = XmssTree::new(&hasher, &params, &seed, 2).unwrap();

        let root = xmss.root();

        // Sign sequentially
        let sig1 = xmss.sign_next(&FELT::from(1u64)).unwrap();
        assert_eq!(sig1.index, 0);

        let sig2 = xmss.sign_next(&FELT::from(2u64)).unwrap();
        assert_eq!(sig2.index, 1);

        // Verify both
        assert!(XmssTree::verify(
            &hasher,
            &params,
            &root,
            0,
            &FELT::from(1u64),
            &sig1
        ));
        assert!(XmssTree::verify(
            &hasher,
            &params,
            &root,
            1,
            &FELT::from(2u64),
            &sig2
        ));
    }

    #[test]
    fn test_xmss_wrong_root_rejection() {
        let hasher = PoseidonHash;
        let params = WotsParams::default();
        let seed1 = [FELT::from(1u64)];
        let seed2 = [FELT::from(2u64)];
        let mut xmss1 = XmssTree::new(&hasher, &params, &seed1, 2).unwrap();
        let xmss2 = XmssTree::new(&hasher, &params, &seed2, 2).unwrap();

        let msg = FELT::from(999u64);
        let sig = xmss1.sign(0, &msg).unwrap();

        // Verification with wrong root should fail
        assert!(!XmssTree::verify(
            &hasher,
            &params,
            &xmss2.root(),
            0,
            &msg,
            &sig
        ));
    }
}
