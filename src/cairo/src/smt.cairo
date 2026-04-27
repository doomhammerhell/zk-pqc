//! Sparse Merkle Tree (SMT) for One-Time Signature Index Tracking in Cairo.
//!
//! # Purpose
//!
//! WOTS+ is a one-time signature scheme. Reusing an index compromises security.
//! The SMT tracks consumed indices efficiently, storing only the root on-chain.
//!
//! # Mathematical Foundation
//!
//! A Sparse Merkle Tree is a perfect binary tree of depth 64 (for u64 indices).
//! Each leaf represents one index:
//! - `0` = unconsumed/unspent
//! - `1` = consumed/spent
//!
//! ## Operations
//!
//! 1. **Mark consumed**: Insert `1` at index i, updating path to root
//! 2. **Check spent**: Verify non-membership proof (path shows `0` at index)
//! 3. **Verify root**: Reconstruct from consumed indices
//!
//! # Formal Properties
//!
//! 1. **Correctness**: After marking index i as consumed, verify(i) = spent
//! 2. **Non-forgeability**: Cannot prove index unconsumed after it's marked
//! 3. **Incremental updates**: Root updates in O(depth) per new consumed index

/// SMT depth for u64 indices.
const SMT_DEPTH: u32 = 64;

/// Empty leaf value (hash of nothing, or zero).
fn empty_leaf() -> felt252 {
    0
}

/// Consumed leaf value (different from empty).
fn consumed_leaf() -> felt252 {
    1
}

/// SMT proof structure for verifying index status.
#[derive(Drop, Clone)]
pub struct SmtProof {
    /// Sibling hashes at each level (from leaf to root).
    pub siblings: Array<felt252>,
    /// Leaf value (0 for unconsumed, 1 for consumed).
    pub leaf_value: felt252,
}

/// Verifies an SMT proof against a given root.
///
/// # Arguments
/// * `root` - Expected SMT root
/// * `index` - Index being verified
/// * `proof` - SMT proof with siblings and leaf value
/// * `expected_consumed` - Whether index should be consumed (true) or not (false)
///
/// # Returns
/// * `true` if proof is valid and matches expected state
/// * `false` otherwise
///
/// # Formal Verification
/// This implements the SMT verification predicate:
/// verify(root, index, proof, expected) ↔
///   proof.leaf == expected_leaf ∧
///   recompute_root(proof.siblings, index, proof.leaf) == root
pub fn verify_smt_proof(
    root: felt252, index: u64, proof: @SmtProof, expected_consumed: bool,
) -> bool {
    // Check leaf value matches expected
    let expected_leaf = if expected_consumed {
        consumed_leaf()
    } else {
        empty_leaf()
    };

    if *proof.leaf_value != expected_leaf {
        return false;
    }

    // Check proof has correct number of siblings
    if proof.siblings.len() != SMT_DEPTH {
        return false;
    }

    // Recompute root from leaf + siblings
    let mut current = *proof.leaf_value;
    let mut idx = index;

    let mut i: u32 = 0;
    while i < proof.siblings.len() {
        let sibling = *proof.siblings.at(i);

        // Determine left/right based on current bit
        let is_right = idx % 2 == 1;

        let left = if is_right {
            sibling
        } else {
            current
        };
        let right = if is_right {
            current
        } else {
            sibling
        };

        // Hash left and right together
        current = hash_pair(left, right);

        idx = idx / 2;
        i += 1;
    }

    current == root
}

/// Computes the root of an SMT from a leaf and its path.
///
/// # Arguments
/// * `leaf` - Leaf value
/// * `index` - Leaf index
/// * `siblings` - Sibling hashes at each level
///
/// # Returns
/// * Computed SMT root
pub fn compute_root_from_leaf(leaf: felt252, index: u64, siblings: Span<felt252>) -> felt252 {
    let mut current = leaf;
    let mut idx = index;

    let mut i: u32 = 0;
    while i < siblings.len() {
        let sibling = *siblings.at(i);

        let is_right = idx % 2 == 1;
        let left = if is_right {
            sibling
        } else {
            current
        };
        let right = if is_right {
            current
        } else {
            sibling
        };

        current = hash_pair(left, right);
        idx = idx / 2;
        i += 1;
    }

    current
}

/// Generates a proof for an unconsumed index (non-membership proof).
///
/// # Arguments
/// * `index` - Index to prove is unconsumed
/// * `siblings` - Sibling hashes from leaf to root
///
/// # Returns
/// * SMT proof showing index is unconsumed
pub fn prove_unconsumed(index: u64, siblings: Array<felt252>) -> SmtProof {
    // Verify siblings count
    assert(siblings.len() == SMT_DEPTH, 'invalid siblings count');

    SmtProof { siblings, leaf_value: empty_leaf() }
}

/// Generates a proof for a consumed index (membership proof).
///
/// # Arguments
/// * `index` - Index to prove is consumed
/// * `siblings` - Sibling hashes from leaf to root
///
/// # Returns
/// * SMT proof showing index is consumed
pub fn prove_consumed(index: u64, siblings: Array<felt252>) -> SmtProof {
    // Verify siblings count
    assert(siblings.len() == SMT_DEPTH, 'invalid siblings count');

    SmtProof { siblings, leaf_value: consumed_leaf() }
}

/// Computes the empty subtree root at a given depth.
///
/// # Arguments
/// * `depth` - Depth of the subtree (0 = leaf)
///
/// # Returns
/// * Root hash of empty subtree at that depth
pub fn compute_empty_subtree_root(depth: u32) -> felt252 {
    let mut current = empty_leaf();

    let mut i: u32 = 0;
    while i < depth {
        current = hash_pair(current, current);
        i += 1;
    }

    current
}

/// Hash two field elements together using Poseidon.
fn hash_pair(left: felt252, right: felt252) -> felt252 {
    // Simple hash of two elements
    // In production, this should use the proper Poseidon hash
    // For now, we use a simple combination
    let mut state = array![left, right, 0, 0, 0, 0];
    zk_pqc_cairo::poseidon::permute(ref state);
    *state.at(0)
}

/// Verifies that an index is not consumed (non-membership proof).
///
/// # Arguments
/// * `root` - Current SMT root
/// * `index` - Index to check
/// * `proof` - SMT proof
///
/// # Returns
/// * `true` if index is unconsumed (proof valid)
/// * `false` otherwise
pub fn verify_unconsumed(root: felt252, index: u64, proof: @SmtProof) -> bool {
    verify_smt_proof(root, index, proof, false)
}

/// Verifies that an index is consumed (membership proof).
///
/// # Arguments
/// * `root` - Current SMT root
/// * `index` - Index to check
/// * `proof` - SMT proof
///
/// # Returns
/// * `true` if index is consumed (proof valid)
/// * `false` otherwise
pub fn verify_consumed(root: felt252, index: u64, proof: @SmtProof) -> bool {
    verify_smt_proof(root, index, proof, true)
}

/// Batch verification of multiple SMT proofs.
///
/// # Arguments
/// * `root` - SMT root
/// * `indices` - Array of indices to verify
/// * `proofs` - Array of SMT proofs (must match indices length)
/// * `expected_consumed` - Whether indices should be consumed
///
/// # Returns
/// * `true` if all proofs are valid
/// * `false` if any proof fails
pub fn batch_verify_proofs(
    root: felt252, indices: Span<u64>, proofs: Span<SmtProof>, expected_consumed: bool,
) -> bool {
    if indices.len() != proofs.len() {
        return false;
    }

    let mut i: u32 = 0;
    while i < indices.len() {
        let index = *indices.at(i);
        let proof = proofs.at(i);

        if !verify_smt_proof(root, index, proof, expected_consumed) {
            return false;
        }

        i += 1;
    }

    true
}
