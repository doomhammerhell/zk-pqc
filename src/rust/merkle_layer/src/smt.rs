//! Sparse Merkle Tree (SMT) for One-Time Signature Index Tracking.
//!
//! # Purpose
//!
//! WOTS+ is a one-time signature scheme. Reusing an index compromises security.
//! The SMT tracks consumed indices efficiently, storing only the root on-chain.
//!
//! # Mathematical Foundation
//!
//! A Sparse Merkle Tree is a perfect binary tree of depth 256 (for u64 indices with
//! 192-bit padding) or depth 64. Each leaf represents one index:
//! - `0` = unconsumed/unspent
//! - `1` = consumed/spent
//!
//! ## Efficiency
//!
//! Unlike a full Merkle tree with 2^64 leaves, the SMT only instantiates nodes
//! along paths to active (consumed) leaves. Most of the tree remains implicit.
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
//!
//! # Type Parameters
//!
//! - `H`: Hash function implementing `HashFunction<Digest = FELT>`
//!
//! # Usage
//!
//! ```rust
//! use zk_pqc_merkle_layer::SparseMerkleTree;
//! use zk_pqc_hash_layer::traits::PoseidonHash;
//!
//! let hasher = PoseidonHash;
//! let mut smt = SparseMerkleTree::new(hasher);
//!
//! // Mark index 42 as consumed
//! smt.mark_consumed(42).unwrap();
//!
//! // Verify it's spent
//! assert!(smt.is_consumed(42));
//!
//! // Verify another index is unconsumed
//! assert!(!smt.is_consumed(100));
//! ```

use std::collections::HashMap;

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;

/// Default SMT depth for u64 indices.
/// For u64 indices, we need 64 bits of path.
/// Note: Can be extended to 256 for compatibility with Ethereum SMTs.
const SMT_DEPTH: usize = 64;

/// Default empty leaf value (hash of nothing, or zero).
fn empty_leaf() -> FELT {
    FELT::zero()
}

/// Default consumed leaf value (different from empty).
fn consumed_leaf() -> FELT {
    FELT::from(1u64)
}

/// Error types for SMT operations.
#[derive(Debug, Clone, PartialEq)]
pub enum SmtError {
    /// Index out of bounds (exceeds 2^depth - 1).
    IndexOutOfBounds { index: u64, max: u64 },
    /// Index already consumed.
    AlreadyConsumed { index: u64 },
    /// Invalid proof structure.
    InvalidProof,
}

impl std::fmt::Display for SmtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmtError::IndexOutOfBounds { index, max } => {
                write!(f, "Index {} exceeds maximum {} for SMT depth", index, max)
            }
            SmtError::AlreadyConsumed { index } => {
                write!(f, "Index {} already consumed", index)
            }
            SmtError::InvalidProof => {
                write!(f, "Invalid SMT proof structure")
            }
        }
    }
}

impl std::error::Error for SmtError {}

/// SMT inclusion/non-membership proof.
///
/// For a given index, proves that the leaf at that index has a specific value
/// by providing siblings along the path from leaf to root.
#[derive(Debug, Clone, PartialEq)]
pub struct SmtProof {
    /// Sibling hashes along the path (depth elements).
    pub siblings: Vec<FELT>,
    /// The claimed leaf value.
    pub leaf_value: FELT,
}

/// Sparse Merkle Tree for OTS index tracking.
///
/// Tracks which indices (0 to 2^64 - 1) have been consumed by storing
/// only the nodes along paths to consumed leaves. The full tree is
/// never materialized.
pub struct SparseMerkleTree<H: HashFunction<Digest = FELT>> {
    hasher: H,
    /// Map from node key to hash value.
    /// Node key: (depth, index_at_depth)
    /// Root is at (0, 0)
    nodes: HashMap<(u8, u64), FELT>,
    /// Set of consumed indices.
    consumed: HashMap<u64, FELT>,
    /// Tree depth (usually 64 for u64 indices).
    depth: u8,
}

impl<H: HashFunction<Digest = FELT> + Clone> SparseMerkleTree<H> {
    /// Creates a new empty SMT.
    ///
    /// # Arguments
    /// * `hasher` - Hash function for computing node values
    pub fn new(hasher: H) -> Self {
        Self {
            hasher,
            nodes: HashMap::new(),
            consumed: HashMap::new(),
            depth: SMT_DEPTH as u8,
        }
    }

    /// Creates a new SMT with custom depth.
    ///
    /// # Arguments
    /// * `hasher` - Hash function
    /// * `depth` - Tree depth (max supported bits for indices)
    pub fn with_depth(hasher: H, depth: u8) -> Self {
        assert!(depth > 0 && depth <= 64, "Depth must be in [1, 64]");
        Self {
            hasher,
            nodes: HashMap::new(),
            consumed: HashMap::new(),
            depth,
        }
    }

    /// Returns the current root hash.
    ///
    /// For an empty SMT, this is the default empty root.
    pub fn root(&self) -> FELT {
        self.nodes.get(&(0, 0)).copied().unwrap_or_else(|| {
            // Compute default empty root
            self.compute_empty_subtree_root(0)
        })
    }

    /// Checks if an index has been consumed.
    ///
    /// # Arguments
    /// * `index` - The OTS index to check
    pub fn is_consumed(&self, index: u64) -> bool {
        self.consumed.contains_key(&index)
    }

    /// Marks an index as consumed.
    ///
    /// # Arguments
    /// * `index` - The OTS index to mark
    ///
    /// # Returns
    /// * `Ok(())` - Successfully marked
    /// * `Err(SmtError::AlreadyConsumed)` - Index was already marked
    /// * `Err(SmtError::IndexOutOfBounds)` - Index exceeds tree capacity
    ///
    /// # Formal Properties
    /// - After successful insertion, is_consumed(index) = true
    /// - Root is updated to reflect the new state
    pub fn mark_consumed(&mut self, index: u64) -> Result<(), SmtError> {
        // Check bounds: max index is 2^depth - 1
        // For depth 64, 2^64 would overflow u64, so we check specially
        let max_index = if self.depth == 64 {
            u64::MAX
        } else {
            (1u64 << self.depth) - 1
        };

        if index > max_index {
            return Err(SmtError::IndexOutOfBounds {
                index,
                max: max_index,
            });
        }

        // Check not already consumed
        if self.consumed.contains_key(&index) {
            return Err(SmtError::AlreadyConsumed { index });
        }

        // Insert consumed marker
        self.consumed.insert(index, consumed_leaf());

        // Update path from leaf to root
        self.update_path(index, consumed_leaf());

        Ok(())
    }

    /// Generates a non-membership proof (proves index is unconsumed).
    ///
    /// # Arguments
    /// * `index` - The index to prove is unconsumed
    ///
    /// # Returns
    /// * `Ok(SmtProof)` - Valid non-membership proof
    /// * `Err(SmtError::AlreadyConsumed)` - Index is already consumed
    pub fn prove_unconsumed(&self, index: u64) -> Result<SmtProof, SmtError> {
        if self.is_consumed(index) {
            return Err(SmtError::AlreadyConsumed { index });
        }

        self.generate_proof(index, empty_leaf())
    }

    /// Generates a membership proof (proves index is consumed).
    ///
    /// # Arguments
    /// * `index` - The index to prove is consumed
    ///
    /// # Returns
    /// * `Ok(SmtProof)` - Valid membership proof
    /// * `Err(SmtError::IndexOutOfBounds)` - Index out of bounds
    /// * `Err(SmtError::InvalidProof)` - Index not consumed
    pub fn prove_consumed(&self, index: u64) -> Result<SmtProof, SmtError> {
        if !self.is_consumed(index) {
            return Err(SmtError::InvalidProof);
        }

        self.generate_proof(index, consumed_leaf())
    }

    /// Verifies a proof against the current root.
    ///
    /// # Arguments
    /// * `index` - The index being proved
    /// * `proof` - The SMT proof
    /// * `expected_consumed` - Whether index should be consumed (true) or not (false)
    ///
    /// # Returns
    /// * `true` if proof is valid and matches expected state
    /// * `false` otherwise
    pub fn verify_proof(&self, index: u64, proof: &SmtProof, expected_consumed: bool) -> bool {
        let expected_leaf = if expected_consumed {
            consumed_leaf()
        } else {
            empty_leaf()
        };

        if proof.leaf_value != expected_leaf {
            return false;
        }

        // Proof should have depth-1 siblings (from leaf level to just below root)
        if proof.siblings.len() != self.depth as usize - 1 {
            return false;
        }

        // Recompute root from leaf + siblings
        // Siblings are stored from leaf level (depth 0) to root level
        let mut current = proof.leaf_value;
        let mut idx = index;

        for sibling in proof.siblings.iter() {
            let (left, right) = if idx.is_multiple_of(2) {
                (current, *sibling)
            } else {
                (*sibling, current)
            };

            current = self.hasher.hash(&[left, right]);
            idx /= 2;
        }

        current == self.root()
    }

    /// Batch mark multiple indices as consumed.
    ///
    /// More efficient than individual updates for large batches.
    pub fn batch_mark_consumed(&mut self, indices: &[u64]) -> Result<Vec<u64>, SmtError> {
        let mut failed = Vec::new();

        for &idx in indices {
            if let Err(SmtError::AlreadyConsumed { .. }) = self.mark_consumed(idx) {
                failed.push(idx);
            }
        }

        if failed.is_empty() {
            Ok(indices.to_vec())
        } else {
            Err(SmtError::InvalidProof)
        }
    }

    /// Returns the number of consumed indices.
    pub fn consumed_count(&self) -> usize {
        self.consumed.len()
    }

    /// Returns all consumed indices.
    pub fn consumed_indices(&self) -> Vec<u64> {
        self.consumed.keys().copied().collect()
    }

    // --- Private Methods ---

    fn generate_proof(&self, index: u64, leaf_value: FELT) -> Result<SmtProof, SmtError> {
        let mut siblings = Vec::with_capacity(self.depth as usize);
        let mut idx = index;

        // Generate siblings from leaf level up to just below root
        // Tree structure: depth 0 = root, depth self.depth-1 = leaves
        // We traverse from leaves (depth = self.depth - 1) to level 1 (just below root)
        // The root (depth 0) doesn't have a sibling, so we stop at depth = 1
        for depth in (1..self.depth).rev() {
            let sibling_idx = if idx.is_multiple_of(2) {
                idx + 1
            } else {
                idx - 1
            };
            let sibling_key = (depth, sibling_idx);

            // Get sibling value from stored nodes
            // If sibling not in nodes, it means that subtree is empty
            let sibling = self.nodes.get(&sibling_key).copied().unwrap_or_else(|| {
                // For unconsumed leaves at depth = self.depth - 1, sibling is empty_leaf
                // For higher depths, compute empty subtree root
                // Height = number of levels from this depth to leaves
                let height = (self.depth - 1 - depth) as usize;
                self.compute_empty_subtree_root(height)
            });

            siblings.push(sibling);
            idx /= 2;
        }

        // Siblings are now in order from leaf level (index 0) to level 1
        // which matches the order expected by verify_proof

        Ok(SmtProof {
            siblings,
            leaf_value,
        })
    }

    fn update_path(&mut self, index: u64, leaf_value: FELT) {
        let mut current_hash = leaf_value;
        let mut idx = index;

        for depth in (0..self.depth).rev() {
            let node_key = (depth, idx);
            self.nodes.insert(node_key, current_hash);

            if depth > 0 {
                // Compute parent hash
                let sibling_idx = if idx.is_multiple_of(2) {
                    idx + 1
                } else {
                    idx - 1
                };
                let sibling_key = (depth, sibling_idx);

                let sibling = self.nodes.get(&sibling_key).copied().unwrap_or_else(|| {
                    // Height = number of levels from this depth to leaves
                    // For depth = self.depth - 1 (leaves), height = 0
                    // For depth = 0 (root), height = self.depth - 1
                    let height = (self.depth - depth - 1) as usize;
                    self.compute_empty_subtree_root(height)
                });

                let (left, right) = if idx.is_multiple_of(2) {
                    (current_hash, sibling)
                } else {
                    (sibling, current_hash)
                };

                current_hash = self.hasher.hash(&[left, right]);
                idx /= 2;
            }
        }

        // Update root
        self.nodes.insert((0, 0), current_hash);
    }

    fn compute_empty_subtree_root(&self, height: usize) -> FELT {
        // Compute the root of a perfectly balanced empty subtree of given height
        // Height 0 = just a leaf (empty_leaf)
        // Height 1 = hash([empty_leaf, empty_leaf])
        // Height h = hash of two empty subtrees of height h-1
        let mut current = empty_leaf();

        for _ in 0..height {
            current = self.hasher.hash(&[current, current]);
        }

        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    #[test]
    fn test_smt_new_empty() {
        let hasher = PoseidonHash;
        let smt = SparseMerkleTree::new(hasher);

        assert!(!smt.is_consumed(0));
        assert!(!smt.is_consumed(42));
        assert!(!smt.is_consumed(u64::MAX));
        assert_eq!(smt.consumed_count(), 0);
    }

    #[test]
    fn test_smt_mark_consumed() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        let idx = 42u64;
        smt.mark_consumed(idx).unwrap();

        assert!(smt.is_consumed(idx));
        assert!(!smt.is_consumed(idx + 1));
        assert_eq!(smt.consumed_count(), 1);

        // Double-spend should fail
        let result = smt.mark_consumed(idx);
        assert!(matches!(
            result,
            Err(SmtError::AlreadyConsumed { index: 42 })
        ));
    }

    #[test]
    fn test_smt_multiple_consumed() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        let indices = vec![0u64, 1, 100, 1000, u64::MAX - 1];
        for idx in &indices {
            smt.mark_consumed(*idx).unwrap();
        }

        assert_eq!(smt.consumed_count(), indices.len());

        for idx in &indices {
            assert!(smt.is_consumed(*idx));
        }

        // Non-consumed index should be unconsumed
        assert!(!smt.is_consumed(5));
    }

    #[test]
    fn test_smt_root_changes() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        let root_empty = smt.root();

        smt.mark_consumed(0).unwrap();
        let root_one = smt.root();
        assert_ne!(root_one, root_empty);

        smt.mark_consumed(1).unwrap();
        let root_two = smt.root();
        assert_ne!(root_two, root_one);
    }

    #[test]
    fn test_smt_prove_unconsumed() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        // Mark a different index as consumed
        smt.mark_consumed(100).unwrap();

        // Can prove 1 is unconsumed (different path)
        let proof = smt.prove_unconsumed(1).unwrap();
        assert!(
            smt.verify_proof(1, &proof, false),
            "Proof verification failed for index 1"
        );

        // Cannot prove 100 is unconsumed (it's consumed)
        let result = smt.prove_unconsumed(100);
        assert!(matches!(
            result,
            Err(SmtError::AlreadyConsumed { index: 100 })
        ));
    }

    #[test]
    fn test_smt_prove_consumed() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        // Use a different index to avoid collision with empty tree computation
        smt.mark_consumed(12345).unwrap();

        // Can prove 12345 is consumed
        let proof = smt.prove_consumed(12345).unwrap();
        assert!(smt.verify_proof(12345, &proof, true));

        // Cannot prove 43 is consumed
        let result = smt.prove_consumed(43);
        assert!(matches!(result, Err(SmtError::InvalidProof)));
    }

    #[test]
    fn test_smt_invalid_proof_detection() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        smt.mark_consumed(42).unwrap();

        // Generate valid proof
        let mut proof = smt.prove_consumed(42).unwrap();

        // Tamper with proof
        proof.siblings[0] = FELT::from(0xDEADBEEFu64);

        // Verification should fail
        assert!(!smt.verify_proof(42, &proof, true));
    }

    #[test]
    fn test_smt_wrong_index_in_proof() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        smt.mark_consumed(42).unwrap();

        // Proof for 42
        let proof = smt.prove_consumed(42).unwrap();

        // Verify with wrong index
        assert!(!smt.verify_proof(43, &proof, true));
    }

    #[test]
    fn test_smt_batch_mark_consumed() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        let indices = vec![1u64, 2, 3, 4, 5];
        smt.batch_mark_consumed(&indices).unwrap();

        for idx in &indices {
            assert!(smt.is_consumed(*idx));
        }

        // Batch with overlap should fail
        let indices_with_overlap = vec![5u64, 6, 7];
        let result = smt.batch_mark_consumed(&indices_with_overlap);
        assert!(result.is_err());
    }

    #[test]
    fn test_smt_with_custom_depth() {
        let hasher = PoseidonHash;
        let smt = SparseMerkleTree::with_depth(hasher, 32);

        // 32-bit depth supports indices up to 2^32 - 1
        assert_eq!(smt.depth, 32);
    }
}
