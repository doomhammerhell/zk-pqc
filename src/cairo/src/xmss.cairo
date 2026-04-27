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
//! - Supports up to 16^h signatures where h is the tree height
//! - Uses HexTree (arity-16) for reduced proof size in STARK contexts
//!
//! ## Formal Properties
//!
//! 1. **Existential Unforgeability**: Infeasible to forge without breaking WOTS+ or Merkle hash
//! 2. **Index Binding**: Each signature is bound to a specific tree index
//! 3. **Stateless Verification**: Verifier only needs the Merkle root
//!
//! # Usage
//!
//! ```cairo
//! use zk_pqc_cairo::xmss::{XmssSignature, verify_xmss};
//! use zk_pqc_cairo::wots::{WotsParams, verify_wots};
//! use zk_pqc_cairo::poseidon::PoseidonHash;
//!
//! // Verify XMSS signature (verification only, signing is off-chain)
//! let is_valid = verify_xmss::<PoseidonHash>(
//!     root,
//!     index,
//!     message,
//!     signature,
//!     params,
//! );
//! ```

use zk_pqc_cairo::hash_trait::HashFunction;
use zk_pqc_cairo::wots::{WotsParams, WotsSignature, checksum, decompose_message};

/// XMSS signature combining WOTS+ with Merkle inclusion proof.
#[derive(Drop, Clone)]
pub struct XmssSignature {
    /// Tree index used for signing.
    pub index: u64,
    /// WOTS+ signature for the message.
    pub wots_sig: WotsSignature,
    /// WOTS+ public key commitment (leaf value).
    pub wots_pubkey_commitment: felt252,
    /// Inclusion proof: sibling hashes at each level.
    pub proof_siblings: Array<Array<felt252>>,
    /// Path indices at each level.
    pub proof_path_indices: Array<u8>,
}

/// Error types for XMSS operations.
#[derive(Drop, Debug)]
pub enum XmssError {
    /// Index already used.
    IndexAlreadyUsed,
    /// Index out of bounds for tree height.
    IndexOutOfBounds,
    /// WOTS+ verification failed.
    WotsVerificationFailed,
    /// Merkle proof verification failed.
    MerkleVerificationFailed,
    /// Invalid signature structure.
    InvalidSignature,
}

/// Verifies an XMSS signature.
///
/// # Arguments
/// * `root` - XMSS root commitment
/// * `index` - Index claimed in signature
/// * `message` - Message being verified
/// * `sig` - XMSS signature
/// * `params` - WOTS+ parameters
///
/// # Returns
/// * `true` if signature is valid
/// * `false` otherwise
///
/// # Formal Verification
/// This implements the XMSS verification predicate:
/// verify(root, index, M, sig) ↔
///   WOTS.verify(sig.wots, M) ∧ HexTree.verify(root, sig.commitment, sig.proof, index)
pub fn verify_xmss<T, +HashFunction<T>, +Drop<T>>(
    root: felt252, index: u64, message: felt252, sig: @XmssSignature, params: @WotsParams,
) -> bool {
    // Verify index matches
    if *sig.index != index {
        return false;
    }

    // Verify WOTS+ signature and reconstruct public key
    let reconstructed_pubkey =
        match reconstruct_pubkey_from_sig::<T>(message, sig.wots_sig, params) {
        Option::Some(pk) => pk,
        Option::None => { return false; },
    };

    // Verify commitment matches
    let computed_commitment = HashFunction::<T>::hash(reconstructed_pubkey.span());
    if computed_commitment != *sig.wots_pubkey_commitment {
        return false;
    }

    // Verify Merkle inclusion proof
    verify_merkle_proof::<
        T,
    >(root, *sig.wots_pubkey_commitment, index, sig.proof_siblings, sig.proof_path_indices)
}

/// Reconstructs the WOTS+ public key from signature during verification.
///
/// This implements the WOTS+ verification logic that iterates each
/// signature chain value to reconstruct the public key endpoint.
fn reconstruct_pubkey_from_sig<T, +HashFunction<T>, +Drop<T>>(
    message: felt252, sig: @WotsSignature, params: @WotsParams,
) -> Option<Array<felt252>> {
    let w = *params.w;
    let msg_elements = decompose_message(w, message);
    let checksum_elements = checksum(w, msg_elements.span());

    // Combine message and checksum elements
    let mut all_elements: Array<u32> = msg_elements;
    let mut i: u32 = 0;
    while i < checksum_elements.len() {
        all_elements.append(*checksum_elements.at(i));
        i += 1;
    }

    let total = total_chains(params);
    if all_elements.len() != total {
        return Option::None;
    }

    let mut reconstructed: Array<felt252> = ArrayTrait::new();

    let mut idx: u32 = 0;
    while idx < total {
        if idx >= sig.chain_values.len() {
            return Option::None;
        }

        let m_i: u32 = *all_elements.at(idx);
        let remaining = (w - 1) - m_i;
        let mut current: felt252 = *sig.chain_values.at(idx);

        // Apply remaining hash iterations
        let mut j: u32 = 0;
        while j < remaining {
            current = HashFunction::<T>::hash(array![current].span());
            j += 1;
        }

        reconstructed.append(current);
        idx += 1;
    }

    Option::Some(reconstructed)
}

/// Verify Merkle inclusion proof (HexTree/Arity-16).
fn verify_merkle_proof<T, +HashFunction<T>, +Drop<T>>(
    root: felt252,
    leaf: felt252,
    leaf_index: u64,
    proof_siblings: @Array<Array<felt252>>,
    proof_path_indices: @Array<u8>,
) -> bool {
    if proof_siblings.len() != proof_path_indices.len() {
        return false;
    }

    let mut current = leaf;
    let mut idx = leaf_index;

    let mut i: u32 = 0;
    while i < proof_siblings.len() {
        let siblings = proof_siblings.at(i);
        let path_idx: u64 = (*proof_path_indices.at(i)).into();

        // Verify path index matches leaf_index at this level
        let expected_idx = idx % 16;
        if path_idx != expected_idx {
            return false;
        }
        idx = idx / 16;

        // Reconstruct parent hash
        let mut children: Array<felt252> = ArrayTrait::new();
        let mut sib_idx: u32 = 0;
        let mut child_pos: u32 = 0;
        while child_pos < 16 {
            if child_pos == path_idx.try_into().unwrap() {
                children.append(current);
            } else {
                if sib_idx >= siblings.len() {
                    return false;
                }
                children.append(*siblings.at(sib_idx));
                sib_idx += 1;
            }
            child_pos += 1;
        }

        current = HashFunction::<T>::hash(children.span());

        i += 1;
    }

    // Check remaining index bits are 0
    if idx != 0 {
        return false;
    }

    current == root
}

/// Calculate total number of chains for WOTS+.
fn total_chains(params: @WotsParams) -> u32 {
    let w = *params.w;
    let msg_len = message_len(w);
    let checksum_len = checksum_len(w, msg_len);
    msg_len + checksum_len
}

/// Calculate message length in base-w digits.
fn message_len(w: u32) -> u32 {
    if w <= 1 {
        return 1;
    }
    let log_w = log2_int(w);
    // ceil(252 / log_w)
    (252 + log_w - 1) / log_w
}

/// Calculate checksum length in base-w digits.
fn checksum_len(w: u32, msg_len: u32) -> u32 {
    let max_checksum = msg_len * (w - 1);
    if max_checksum == 0 {
        return 1;
    }
    let log_w = log2_int(w);
    let bits_needed = log2_int(max_checksum) + 1;
    (bits_needed + log_w - 1) / log_w
}

/// Integer log2.
fn log2_int(n: u32) -> u32 {
    if n <= 1 {
        return 0;
    }
    let mut result: u32 = 0;
    let mut x = n;
    while x > 1 {
        x = x / 2;
        result += 1;
    }
    result
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use zk_pqc_cairo::hash_trait::PoseidonHash;
    use zk_pqc_cairo::wots::{keygen, sign};
    use super::*;

    #[test]
    fn test_xmss_signature_structure() {
        // Create a dummy XMSS signature structure
        let sig = XmssSignature {
            index: 0,
            wots_sig: WotsSignature { chain_values: ArrayTrait::new() },
            wots_pubkey_commitment: 0,
            proof_siblings: ArrayTrait::new(),
            proof_path_indices: ArrayTrait::new(),
        };

        assert(sig.index == 0, 'index should be 0');
    }

    #[test]
    fn test_xmss_verify_invalid_index() {
        // Create signature with index 0
        let sig = XmssSignature {
            index: 0,
            wots_sig: WotsSignature { chain_values: ArrayTrait::new() },
            wots_pubkey_commitment: 0,
            proof_siblings: ArrayTrait::new(),
            proof_path_indices: ArrayTrait::new(),
        };

        // Verify with different index should fail
        let params = WotsParams { w: 16 };
        let is_valid = verify_xmss::<
            PoseidonHash,
        >(0, // root
        1, // different index
        123, // message
        @sig, @params);

        assert(!is_valid, 'different index should fail');
    }

    #[test]
    fn test_xmss_verify_empty_signature_fails() {
        let sig = XmssSignature {
            index: 0,
            wots_sig: WotsSignature { chain_values: ArrayTrait::new() },
            wots_pubkey_commitment: 0,
            proof_siblings: ArrayTrait::new(),
            proof_path_indices: ArrayTrait::new(),
        };

        let params = WotsParams { w: 16 };
        let is_valid = verify_xmss::<
            PoseidonHash,
        >(0, // root
        0, // index
        123, // message
        @sig, @params);

        assert(!is_valid, 'empty sig should fail');
    }

    #[test]
    fn test_total_chains_calculation() {
        let params = WotsParams { w: 16 };
        let total = total_chains(@params);
        // For w=16: msg_len = ceil(252/4) = 63
        // checksum_len for max_checksum = 63*15 = 945
        // log2(945) ≈ 9.88, bits_needed = 10
        // checksum_len = ceil(10/4) = 3
        // total = 63 + 3 = 66
        assert(total == 66, 'total chains should be 66');
    }

    #[test]
    fn test_message_len_calculation() {
        // w=16, log_w=4
        // ceil(252/4) = 63
        assert(message_len(16) == 63, 'msg_len for w=16 should be 63');

        // w=4, log_w=2
        // ceil(252/2) = 126
        assert(message_len(4) == 126, 'msg_len for w=4 should be 126');
    }

    #[test]
    fn test_checksum_len_calculation() {
        // w=16, msg_len=63
        // max_checksum = 63 * 15 = 945
        // log2(945) ≈ 9.88, bits_needed = 10
        // ceil(10/4) = 3
        assert(checksum_len(16, 63) == 3, 'checksum_len should be 3');
    }

    #[test]
    fn test_log2_int() {
        assert(log2_int(1) == 0, 'log2(1) = 0');
        assert(log2_int(2) == 1, 'log2(2) = 1');
        assert(log2_int(4) == 2, 'log2(4) = 2');
        assert(log2_int(8) == 3, 'log2(8) = 3');
        assert(log2_int(16) == 4, 'log2(16) = 4');
    }
}
