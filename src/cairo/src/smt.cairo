//! Jellyfish Merkle Tree (JMT) Verification for One-Time Signature Index Tracking in Cairo.
//!
//! # Purpose
//!
//! WOTS+ is a one-time signature scheme. Reusing an index compromises security.
//! The JMT tracks consumed indices efficiently, storing only the root on-chain (32 bytes).
//!
//! # JMT vs Basic SMT
//!
//! The Jellyfish Merkle Tree is an optimized Sparse Merkle Tree variant:
//! - **Path compression**: Empty subtrees are never instantiated; only active
//!   branches exist in memory.
//! - **Lazy node instantiation**: Internal nodes are created only when a second
//!   leaf shares a common prefix, splitting the path at the divergence point.
//! - **Efficient updates**: Cost proportional to the number of active nodes,
//!   not the theoretical 2^64 address space.
//! - **On-chain storage**: Single 32-byte root (constant footprint).
//!
//! # Proof Format (matching Rust JMT)
//!
//! - Siblings: `depth - 1` elements, ordered from leaf level (level 0) to root.
//! - Leaf value: 0 = unconsumed, 1 = consumed.
//! - Routing bit at level i: `(index >> i) & 1` — 0 = left, 1 = right.
//!
//! # Verification Algorithm
//!
//! 1. Start with the leaf value as `current`.
//! 2. For each sibling at level i (0..depth-1):
//!    a. Compute routing bit = (index >> i) & 1
//!    b. If bit == 0: current is left, sibling is right
//!    c. If bit == 1: sibling is left, current is right
//!    d. current = H(left, right)
//! 3. Compare final `current` with the stored JMT root.
//!
//! # Formal Properties
//!
//! 1. **Correctness**: After marking index i as consumed, verify(i) = spent
//! 2. **Non-forgeability**: Cannot prove index unconsumed after it's marked
//! 3. **Incremental updates**: Root updates in O(active_depth) per new consumed index
//!
//! Requirements: 16.3, 16.4

/// JMT depth for u64 indices.
/// The tree has 64 levels (0..63), with depth-1 = 63 internal node levels.
const JMT_DEPTH: u32 = 64;

/// Number of siblings in a JMT proof (depth - 1).
const JMT_PROOF_SIBLINGS: u32 = 63;

/// Legacy SMT depth constant (kept for backward compatibility).
const SMT_DEPTH: u32 = 64;

/// Empty leaf value (zero — represents unconsumed/unspent).
fn empty_leaf() -> felt252 {
    0
}

/// Consumed leaf value (1 — represents consumed/spent).
fn consumed_leaf() -> felt252 {
    1
}

/// JMT proof structure for verifying index status.
///
/// Matches the Rust `SmtProof` format:
/// - `siblings`: depth - 1 hashes (63 for u64 indices), leaf-to-root order
/// - `leaf_value`: 0 for unconsumed, 1 for consumed
#[derive(Drop, Clone)]
pub struct SmtProof {
    /// Sibling hashes at each level (from leaf to root).
    /// Length must be JMT_PROOF_SIBLINGS (depth - 1 = 63).
    pub siblings: Array<felt252>,
    /// Leaf value (0 for unconsumed, 1 for consumed).
    pub leaf_value: felt252,
}

/// Verifies a JMT proof against a given root.
///
/// # Arguments
/// * `root` - Expected JMT root
/// * `index` - Index being verified
/// * `proof` - JMT proof with siblings and leaf value
/// * `expected_consumed` - Whether index should be consumed (true) or not (false)
///
/// # Returns
/// * `true` if proof is valid and matches expected state
/// * `false` otherwise
///
/// # Proof Verification
///
/// Recomputes the root from the leaf value and siblings using the JMT routing:
/// - At level i, routing bit = (index >> i) & 1
/// - 0 = current goes left, sibling goes right
/// - 1 = sibling goes left, current goes right
/// - Siblings are in leaf-to-root order (level 0 first)
///
/// Requirements: 16.3, 16.4
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

    // JMT proofs have depth - 1 siblings
    if proof.siblings.len() != JMT_PROOF_SIBLINGS {
        return false;
    }

    // Recompute root from leaf + siblings
    // Siblings are in leaf-to-root order.
    // At level i (0-indexed from leaf), the routing bit is (index >> i) & 1.
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

/// Computes the root of a JMT from a leaf and its path.
///
/// # Arguments
/// * `leaf` - Leaf value
/// * `index` - Leaf index
/// * `siblings` - Sibling hashes at each level (depth - 1 elements, leaf-to-root)
///
/// # Returns
/// * Computed JMT root
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
/// * `siblings` - Sibling hashes from leaf to root (depth - 1 elements)
///
/// # Returns
/// * JMT proof showing index is unconsumed
pub fn prove_unconsumed(index: u64, siblings: Array<felt252>) -> SmtProof {
    // Verify siblings count matches JMT format
    assert(siblings.len() == JMT_PROOF_SIBLINGS, 'invalid siblings count');

    SmtProof { siblings, leaf_value: empty_leaf() }
}

/// Generates a proof for a consumed index (membership proof).
///
/// # Arguments
/// * `index` - Index to prove is consumed
/// * `siblings` - Sibling hashes from leaf to root (depth - 1 elements)
///
/// # Returns
/// * JMT proof showing index is consumed
pub fn prove_consumed(index: u64, siblings: Array<felt252>) -> SmtProof {
    // Verify siblings count matches JMT format
    assert(siblings.len() == JMT_PROOF_SIBLINGS, 'invalid siblings count');

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
///
/// This is the core hash function for JMT internal nodes.
/// Uses the same Poseidon permutation as the Rust JMT implementation.
fn hash_pair(left: felt252, right: felt252) -> felt252 {
    let mut state = array![left, right, 0, 0, 0, 0];
    zk_pqc_cairo::poseidon::permute(ref state);
    *state.at(0)
}

/// Verifies that an index is not consumed (non-membership proof).
///
/// This is the primary function used by the PCA contract to verify
/// that an OTS index has not been previously used before allowing
/// a new authorization.
///
/// # Arguments
/// * `root` - Current JMT root (32 bytes constant storage)
/// * `index` - Index to check
/// * `proof` - JMT proof (depth-1 siblings + leaf value)
///
/// # Returns
/// * `true` if index is unconsumed (proof valid against root)
/// * `false` otherwise
///
/// Requirements: 16.3, 16.4
pub fn verify_unconsumed(root: felt252, index: u64, proof: @SmtProof) -> bool {
    verify_smt_proof(root, index, proof, false)
}

/// Verifies that an index is consumed (membership proof).
///
/// # Arguments
/// * `root` - Current JMT root
/// * `index` - Index to check
/// * `proof` - JMT proof
///
/// # Returns
/// * `true` if index is consumed (proof valid)
/// * `false` otherwise
pub fn verify_consumed(root: felt252, index: u64, proof: @SmtProof) -> bool {
    verify_smt_proof(root, index, proof, true)
}

/// Batch verification of multiple JMT proofs.
///
/// # Arguments
/// * `root` - JMT root
/// * `indices` - Array of indices to verify
/// * `proofs` - Array of JMT proofs (must match indices length)
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

/// Compute the new JMT root after marking an index as consumed.
///
/// Given the current unconsumed proof for an index, computes what the
/// new root would be if that index were marked as consumed (leaf value
/// changes from 0 to 1).
///
/// # Arguments
/// * `index` - Index being consumed
/// * `siblings` - Sibling hashes from the unconsumed proof (depth-1 elements)
///
/// # Returns
/// * New JMT root with the index marked as consumed
pub fn compute_new_root_after_consume(index: u64, siblings: Span<felt252>) -> felt252 {
    compute_root_from_leaf(consumed_leaf(), index, siblings)
}
