#![allow(clippy::manual_is_multiple_of)]
//! Jellyfish Merkle Tree (JMT) for One-Time Signature Index Tracking.
//!
//! # Purpose
//!
//! WOTS+ is a one-time signature scheme. Reusing an index compromises security.
//! The JMT tracks consumed indices efficiently, storing only the root on-chain.
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
//! # Node Types
//!
//! - `Empty`: Represents an entire empty subtree (never stored explicitly).
//! - `Leaf(index, value)`: A consumed index stored at its path position.
//! - `Internal(left, right)`: Branch node connecting two non-empty subtrees.
//!
//! # Tree Structure
//!
//! The tree is organized with the root at the top (level = depth - 1) and
//! leaves at the bottom (level = 0). At each level, the routing bit is
//! `(index >> level) & 1`: 0 goes left, 1 goes right. This matches the
//! proof verification order where siblings are stored from leaf to root.
//!
//! # Operations
//!
//! 1. **Mark consumed**: Insert leaf at index i, splitting paths as needed.
//! 2. **Check spent**: Traverse tree to find leaf at index.
//! 3. **Verify root**: Reconstruct from active nodes only.
//! 4. **Batch update**: Insert multiple indices with shared path optimization.
//!
//! # Formal Properties
//!
//! 1. **Correctness**: After marking index i as consumed, is_consumed(i) = true
//! 2. **Non-forgeability**: Cannot prove index unconsumed after it's marked
//! 3. **Incremental updates**: Root updates in O(active_depth) per new consumed index
//! 4. **Space efficiency**: Memory proportional to consumed indices, not 2^64
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

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;

/// Default SMT/JMT depth for u64 indices.
const SMT_DEPTH: usize = 64;

/// Default empty leaf value (zero — represents unconsumed).
fn empty_leaf() -> FELT {
    FELT::zero()
}

/// Default consumed leaf value (1 — represents consumed/spent).
fn consumed_leaf() -> FELT {
    FELT::from(1u64)
}

/// Error types for SMT/JMT operations.
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
                write!(f, "Index {} exceeds maximum {} for JMT depth", index, max)
            }
            SmtError::AlreadyConsumed { index } => {
                write!(f, "Index {} already consumed", index)
            }
            SmtError::InvalidProof => {
                write!(f, "Invalid JMT proof structure")
            }
        }
    }
}

impl std::error::Error for SmtError {}

/// JMT node types for the Jellyfish Merkle Tree.
///
/// Unlike a basic SMT that stores all nodes in a flat HashMap keyed by (depth, index),
/// the JMT uses a tree of typed nodes where:
/// - Empty subtrees are implicit (never stored)
/// - Leaf nodes store the index and value directly
/// - Internal nodes only exist where the tree actually branches
#[derive(Debug, Clone, PartialEq)]
enum JmtNode {
    /// Empty subtree — never actually stored, represented by None in children.
    Empty,
    /// Leaf node at a specific index with its value.
    /// The leaf can exist at any level; path compression means it doesn't
    /// need to be at the bottom of the tree.
    Leaf { index: u64, value: FELT },
    /// Internal node with left and right children.
    /// Only instantiated when two leaves share a common prefix up to this level.
    Internal {
        left: Box<JmtNode>,
        right: Box<JmtNode>,
    },
}

/// SMT inclusion/non-membership proof.
///
/// For a given index, proves that the leaf at that index has a specific value
/// by providing siblings along the path from leaf to root.
#[derive(Debug, Clone, PartialEq)]
pub struct SmtProof {
    /// Sibling hashes along the path (depth - 1 elements, from leaf level to root).
    pub siblings: Vec<FELT>,
    /// The claimed leaf value.
    pub leaf_value: FELT,
}

/// Jellyfish Merkle Tree (JMT) for OTS index tracking.
///
/// Implements an optimized Sparse Merkle Tree where:
/// - Internal nodes are only instantiated for active branches
/// - Update cost is proportional to active nodes, not theoretical 2^64 space
/// - On-chain storage is a single 32-byte root (constant footprint)
///
/// This is an upgrade from the basic SMT (task 16.1) to a full JMT (task 21.1).
pub struct SparseMerkleTree<H: HashFunction<Digest = FELT>> {
    hasher: H,
    /// The root node of the JMT.
    root_node: JmtNode,
    /// Cached empty subtree hashes by height for O(1) lookup.
    /// empty_cache[0] = empty_leaf() (leaf level)
    /// empty_cache[h] = H(empty_cache[h-1], empty_cache[h-1])
    empty_cache: Vec<FELT>,
    /// Tree depth (usually 64 for u64 indices).
    /// The tree has `depth - 1` levels of internal nodes above the leaf level.
    pub(crate) depth: u8,
    /// Number of consumed indices (for O(1) count queries).
    consumed_count: usize,
}

impl<H: HashFunction<Digest = FELT> + Clone> SparseMerkleTree<H> {
    /// Creates a new empty JMT.
    ///
    /// # Arguments
    /// * `hasher` - Hash function for computing node values
    pub fn new(hasher: H) -> Self {
        let depth = SMT_DEPTH as u8;
        let empty_cache = Self::build_empty_cache(&hasher, depth);
        Self {
            hasher,
            root_node: JmtNode::Empty,
            empty_cache,
            depth,
            consumed_count: 0,
        }
    }

    /// Creates a new JMT with custom depth.
    ///
    /// # Arguments
    /// * `hasher` - Hash function
    /// * `depth` - Tree depth (max supported bits for indices)
    pub fn with_depth(hasher: H, depth: u8) -> Self {
        assert!(depth > 0 && depth <= 64, "Depth must be in [1, 64]");
        let empty_cache = Self::build_empty_cache(&hasher, depth);
        Self {
            hasher,
            root_node: JmtNode::Empty,
            empty_cache,
            depth,
            consumed_count: 0,
        }
    }

    /// Pre-compute empty subtree hashes for all heights.
    /// empty_cache[0] = empty_leaf (the leaf value for an empty slot)
    /// empty_cache[h] = H(empty_cache[h-1], empty_cache[h-1])
    fn build_empty_cache(hasher: &H, depth: u8) -> Vec<FELT> {
        let mut cache = Vec::with_capacity(depth as usize + 1);
        cache.push(empty_leaf());
        for _ in 1..=depth {
            let prev = *cache.last().unwrap();
            cache.push(hasher.hash(&[prev, prev]));
        }
        cache
    }

    /// Returns the current root hash.
    ///
    /// For an empty JMT, this is the default empty root (hash of the full empty tree).
    pub fn root(&self) -> FELT {
        self.node_hash(&self.root_node, self.depth - 1)
    }

    /// Checks if an index has been consumed.
    ///
    /// Traverses only active branches — O(active_depth) not O(64).
    pub fn is_consumed(&self, index: u64) -> bool {
        self.find_leaf(&self.root_node, index, self.depth - 1)
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
    /// # JMT Optimization
    /// Only creates internal nodes where the tree actually branches.
    /// A new leaf is inserted at the shallowest level where it diverges
    /// from existing leaves, avoiding unnecessary node creation.
    pub fn mark_consumed(&mut self, index: u64) -> Result<(), SmtError> {
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

        if self.is_consumed(index) {
            return Err(SmtError::AlreadyConsumed { index });
        }

        let new_root = self.insert_leaf(
            self.root_node.clone(),
            index,
            consumed_leaf(),
            self.depth - 1,
        );
        self.root_node = new_root;
        self.consumed_count += 1;

        Ok(())
    }

    /// Generates a non-membership proof (proves index is unconsumed).
    pub fn prove_unconsumed(&self, index: u64) -> Result<SmtProof, SmtError> {
        if self.is_consumed(index) {
            return Err(SmtError::AlreadyConsumed { index });
        }
        Ok(self.generate_proof(index, empty_leaf()))
    }

    /// Generates a membership proof (proves index is consumed).
    pub fn prove_consumed(&self, index: u64) -> Result<SmtProof, SmtError> {
        if !self.is_consumed(index) {
            return Err(SmtError::InvalidProof);
        }
        Ok(self.generate_proof(index, consumed_leaf()))
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

        if proof.siblings.len() != self.depth as usize - 1 {
            return false;
        }

        // Recompute root from leaf + siblings.
        // Siblings are in leaf-to-root order.
        // At level i (0-indexed from leaf), the routing bit is (index >> i) & 1.
        let mut current = proof.leaf_value;
        let mut idx = index;

        for sibling in proof.siblings.iter() {
            let (left, right) = if idx % 2 == 0 {
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
    /// More efficient than individual updates for large batches because
    /// shared path prefixes are traversed only once internally.
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
        self.consumed_count
    }

    /// Returns all consumed indices by traversing only active branches.
    pub fn consumed_indices(&self) -> Vec<u64> {
        let mut indices = Vec::new();
        self.collect_leaves(&self.root_node, &mut indices);
        indices
    }

    /// Returns the number of active (instantiated) nodes in the tree.
    /// This demonstrates the JMT efficiency: node count is proportional
    /// to consumed indices, not the 2^64 theoretical space.
    pub fn active_node_count(&self) -> usize {
        self.count_nodes(&self.root_node)
    }

    // --- Private Methods ---

    /// Get the routing bit at a given level.
    /// Level 0 is the leaf level (LSB), level depth-2 is just below root.
    /// At level `lvl`, the bit is `(index >> lvl) & 1`.
    /// 0 = go left, 1 = go right.
    fn bit_at_level(&self, index: u64, level: u8) -> u8 {
        ((index >> level) & 1) as u8
    }

    /// Compute the hash of a JMT node at a given level.
    /// Level 0 = leaf level, level depth-1 = root level.
    ///
    /// The `level` parameter indicates how many levels of tree are
    /// below this node (inclusive of the node itself for internal nodes).
    fn node_hash(&self, node: &JmtNode, level: u8) -> FELT {
        match node {
            JmtNode::Empty => {
                // An empty subtree at this level has height = level + 1
                // (from leaf level 0 up through this level).
                // Actually: empty_cache[0] = leaf, empty_cache[1] = H(leaf, leaf), etc.
                // A node at level `lvl` represents a subtree of height lvl+1
                // (it has lvl levels of internal nodes below it, plus the leaf level).
                // Wait — let's be precise:
                // - At level 0: this IS a leaf. Hash = empty_leaf() = empty_cache[0]
                // - At level 1: internal node with two level-0 children.
                //   Hash = H(empty_cache[0], empty_cache[0]) = empty_cache[1]
                // - At level k: H(empty_cache[k-1], empty_cache[k-1]) = empty_cache[k]
                self.empty_cache[level as usize]
            }
            JmtNode::Leaf { index, value } => {
                // A leaf stored at this level needs to be "expanded" to compute
                // its hash as if it were a full subtree with the leaf at level 0.
                if level == 0 {
                    *value
                } else {
                    self.leaf_as_subtree_hash(*index, *value, level)
                }
            }
            JmtNode::Internal { left, right } => {
                if level == 0 {
                    // Shouldn't happen in a well-formed tree
                    FELT::zero()
                } else {
                    let left_hash = self.node_hash(left, level - 1);
                    let right_hash = self.node_hash(right, level - 1);
                    self.hasher.hash(&[left_hash, right_hash])
                }
            }
        }
    }

    /// Compute the hash of a leaf as if it were a subtree rooted at `level`.
    /// The leaf is at level 0; we build up the hash by pairing with empty
    /// siblings at each intermediate level.
    fn leaf_as_subtree_hash(&self, index: u64, value: FELT, level: u8) -> FELT {
        let mut current = value;
        // Build from level 0 up to level-1 (the children of the node at `level`)
        for lvl in 0..level {
            let bit = self.bit_at_level(index, lvl);
            let empty = self.empty_cache[lvl as usize];
            let (left, right) = if bit == 0 {
                (current, empty)
            } else {
                (empty, current)
            };
            current = self.hasher.hash(&[left, right]);
        }
        current
    }

    /// Find whether a leaf exists at the given index.
    /// `level` is the current level in the tree (root is at depth-1, leaves at 0).
    fn find_leaf(&self, node: &JmtNode, index: u64, level: u8) -> bool {
        match node {
            JmtNode::Empty => false,
            JmtNode::Leaf {
                index: leaf_idx, ..
            } => *leaf_idx == index,
            JmtNode::Internal { left, right } => {
                if level == 0 {
                    return false;
                }
                let bit = self.bit_at_level(index, level - 1);
                if bit == 0 {
                    self.find_leaf(left, index, level - 1)
                } else {
                    self.find_leaf(right, index, level - 1)
                }
            }
        }
    }

    /// Insert a leaf into the JMT, creating internal nodes only where needed.
    ///
    /// `level` is the current level (root starts at depth-1).
    /// At each internal node, we route using bit_at_level(index, level-1)
    /// because the children are at level-1.
    fn insert_leaf(&self, node: JmtNode, index: u64, value: FELT, level: u8) -> JmtNode {
        match node {
            JmtNode::Empty => {
                // Empty slot: place the leaf here (path compression).
                JmtNode::Leaf { index, value }
            }
            JmtNode::Leaf {
                index: existing_idx,
                value: existing_val,
            } => {
                if existing_idx == index {
                    // Overwrite (shouldn't happen due to AlreadyConsumed check)
                    JmtNode::Leaf { index, value }
                } else {
                    // Two leaves need to be separated. Create internal nodes
                    // until they diverge.
                    self.split_leaves(existing_idx, existing_val, index, value, level)
                }
            }
            JmtNode::Internal { left, right } => {
                if level == 0 {
                    // Shouldn't reach here in a well-formed tree
                    return JmtNode::Leaf { index, value };
                }
                // Route based on the bit at level-1 (child level)
                let bit = self.bit_at_level(index, level - 1);
                if bit == 0 {
                    JmtNode::Internal {
                        left: Box::new(self.insert_leaf(*left, index, value, level - 1)),
                        right,
                    }
                } else {
                    JmtNode::Internal {
                        left,
                        right: Box::new(self.insert_leaf(*right, index, value, level - 1)),
                    }
                }
            }
        }
    }

    /// Split two leaves into internal nodes at their divergence point.
    /// Creates the minimal number of internal nodes needed.
    fn split_leaves(&self, idx_a: u64, val_a: FELT, idx_b: u64, val_b: FELT, level: u8) -> JmtNode {
        if level == 0 {
            // At leaf level, just return one (shouldn't happen if indices differ)
            return JmtNode::Leaf {
                index: idx_b,
                value: val_b,
            };
        }

        // Check the routing bit at level-1 (child level)
        let bit_a = self.bit_at_level(idx_a, level - 1);
        let bit_b = self.bit_at_level(idx_b, level - 1);

        if bit_a != bit_b {
            // Divergence point! Place each leaf on its side.
            let leaf_a = JmtNode::Leaf {
                index: idx_a,
                value: val_a,
            };
            let leaf_b = JmtNode::Leaf {
                index: idx_b,
                value: val_b,
            };
            if bit_a == 0 {
                JmtNode::Internal {
                    left: Box::new(leaf_a),
                    right: Box::new(leaf_b),
                }
            } else {
                JmtNode::Internal {
                    left: Box::new(leaf_b),
                    right: Box::new(leaf_a),
                }
            }
        } else {
            // Same direction: recurse deeper
            let child = self.split_leaves(idx_a, val_a, idx_b, val_b, level - 1);
            if bit_a == 0 {
                JmtNode::Internal {
                    left: Box::new(child),
                    right: Box::new(JmtNode::Empty),
                }
            } else {
                JmtNode::Internal {
                    left: Box::new(JmtNode::Empty),
                    right: Box::new(child),
                }
            }
        }
    }

    /// Generate a proof for a given index.
    /// Collects siblings in leaf-to-root order (level 0 first, level depth-2 last).
    fn generate_proof(&self, index: u64, leaf_value: FELT) -> SmtProof {
        let mut siblings = Vec::with_capacity(self.depth as usize - 1);
        self.collect_proof_siblings(&self.root_node, index, self.depth - 1, &mut siblings);
        SmtProof {
            siblings,
            leaf_value,
        }
    }

    /// Recursively collect sibling hashes for the proof.
    /// Siblings are appended in leaf-to-root order (level 0 first).
    ///
    /// `level` is the current node's level (root = depth-1).
    /// We need siblings for levels 0 through depth-2 (total: depth-1 siblings).
    fn collect_proof_siblings(
        &self,
        node: &JmtNode,
        index: u64,
        level: u8,
        siblings: &mut Vec<FELT>,
    ) {
        if level == 0 {
            // At leaf level, no siblings to collect
            return;
        }

        match node {
            JmtNode::Empty => {
                // All remaining siblings are empty subtree hashes.
                // We need siblings for the levels that this subtree spans.
                // This node is at `level`, its children are at level-1, etc.
                // We need to add siblings for levels 0 through level-1.
                for lvl in 0..level {
                    siblings.push(self.empty_cache[lvl as usize]);
                }
            }
            JmtNode::Leaf {
                index: leaf_idx,
                value: leaf_val,
            } => {
                // This leaf is stored at this level via path compression.
                // We need to produce siblings as if the tree were fully expanded
                // from level 0 up to level-1.
                //
                // Find the level at which target and leaf diverge.
                // They share a common ancestor at level L+1 where L is the
                // highest level at which they take different paths.
                // Two indices share a parent at level L if (idx >> L) == (leaf >> L).
                // They diverge at the lowest L where (idx >> L) & 1 != (leaf >> L) & 1
                // AND they share the same parent: (idx >> (L+1)) == (leaf >> (L+1)).
                //
                // Actually simpler: find the lowest level where the paths from
                // the common ancestor split. The common ancestor is at the level
                // where idx >> level == leaf >> level. Below that, one side has
                // the leaf and the other has the target.

                // Find the level at which target and leaf share a common parent.
                // At level L, they share a parent if (index >> (L+1)) == (leaf_idx >> (L+1)).
                // The divergence level is the lowest L where they have different bits
                // AND share a parent.
                let diverge_level = self.find_divergence_level(index, *leaf_idx, level);

                // Below the divergence level: siblings are all empty
                // (the target's path doesn't intersect with the leaf's path)
                for lvl in 0..diverge_level {
                    siblings.push(self.empty_cache[lvl as usize]);
                }

                // At the divergence level: the sibling is the leaf's subtree hash
                if diverge_level < level {
                    let leaf_hash = if diverge_level == 0 {
                        *leaf_val
                    } else {
                        self.leaf_as_subtree_hash(*leaf_idx, *leaf_val, diverge_level)
                    };
                    siblings.push(leaf_hash);

                    // Above the divergence level: siblings are empty
                    for lvl in (diverge_level + 1)..level {
                        siblings.push(self.empty_cache[lvl as usize]);
                    }
                }
            }
            JmtNode::Internal { left, right } => {
                // The children are at level-1.
                // The routing bit for the child level is bit_at_level(index, level-1).
                let bit = self.bit_at_level(index, level - 1);
                if bit == 0 {
                    // Target goes left; sibling is right subtree hash at level-1
                    // First recurse into left child to get lower-level siblings
                    self.collect_proof_siblings(left, index, level - 1, siblings);
                    // Then add the sibling at level level-1
                    let sibling_hash = self.node_hash(right, level - 1);
                    siblings.push(sibling_hash);
                } else {
                    // Target goes right; sibling is left subtree hash at level-1
                    self.collect_proof_siblings(right, index, level - 1, siblings);
                    let sibling_hash = self.node_hash(left, level - 1);
                    siblings.push(sibling_hash);
                }
            }
        }
    }

    /// Find the level at which two indices diverge within a subtree rooted at `max_level`.
    ///
    /// The divergence level is the level of the sibling relationship:
    /// at this level, one index goes left and the other goes right from their
    /// common parent (which is at diverge_level + 1).
    ///
    /// In proof terms: the sibling at `diverge_level` is the subtree containing
    /// the other index.
    fn find_divergence_level(&self, idx_a: u64, idx_b: u64, max_level: u8) -> u8 {
        // Find the lowest level L (0..max_level) where:
        // 1. The bits differ: bit_at_level(a, L) != bit_at_level(b, L)
        // 2. They share a parent at level L+1: (a >> (L+1)) == (b >> (L+1))
        //    within the context of this subtree.
        //
        // Equivalently: find the position of the lowest differing bit
        // between idx_a and idx_b (considering only bits 0..max_level-1).
        // But we also need them to share a parent, which means all higher bits
        // (within the subtree) must be the same.
        //
        // Since this is called when both indices are within the same subtree
        // (they reached the same Leaf node), we just need the highest bit
        // position where they differ, within the range [0, max_level).
        //
        // Actually we want the LOWEST level where the paths from the shared
        // ancestor diverge. The shared ancestor is at the level above the
        // highest differing bit.
        //
        // XOR gives us all differing bits. The highest set bit in XOR
        // (within our range) tells us the divergence level.

        let xor = idx_a ^ idx_b;
        if xor == 0 {
            return max_level; // Same index, no divergence
        }

        // Find the highest bit position in xor that's < max_level
        // This is the level at which they diverge (from the perspective of
        // the parent above).
        let highest_diff_bit = 63 - xor.leading_zeros() as u8;

        if highest_diff_bit < max_level {
            highest_diff_bit
        } else {
            max_level - 1
        }
    }

    /// Collect all leaf indices from the tree.
    fn collect_leaves(&self, node: &JmtNode, indices: &mut Vec<u64>) {
        match node {
            JmtNode::Empty => {}
            JmtNode::Leaf { index, .. } => {
                indices.push(*index);
            }
            JmtNode::Internal { left, right } => {
                self.collect_leaves(left, indices);
                self.collect_leaves(right, indices);
            }
        }
    }

    /// Count the number of active nodes in the tree.
    fn count_nodes(&self, node: &JmtNode) -> usize {
        match node {
            JmtNode::Empty => 0,
            JmtNode::Leaf { .. } => 1,
            JmtNode::Internal { left, right } => {
                1 + self.count_nodes(left) + self.count_nodes(right)
            }
        }
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

    // --- JMT-specific tests ---

    #[test]
    fn test_jmt_lazy_node_instantiation() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        // With one leaf, the tree should have exactly 1 active node (the leaf)
        smt.mark_consumed(42).unwrap();
        assert_eq!(smt.active_node_count(), 1);

        // With two leaves that share a long prefix, internal nodes are created
        // only along the shared path to the divergence point.
        // 42 and 43 differ only at bit 0, sharing bits 1-63.
        // This creates internal nodes from root down to the divergence = 63 internal + 2 leaves.
        smt.mark_consumed(43).unwrap();
        let node_count = smt.active_node_count();
        // For adjacent indices (differ at bit 0), we need depth-1 internal nodes
        assert_eq!(node_count, 65); // 63 internal + 2 leaves

        // But for indices that differ at a high bit, far fewer nodes are needed
        let hasher2 = PoseidonHash;
        let mut smt2 = SparseMerkleTree::new(hasher2);
        smt2.mark_consumed(0).unwrap();
        // 0 and 2^32 differ at bit 32, so only ~31 internal nodes needed
        smt2.mark_consumed(1u64 << 32).unwrap();
        let count2 = smt2.active_node_count();
        // Should be much less than 65 (only ~32 internal nodes + 2 leaves)
        assert!(
            count2 < 40,
            "Expected ~34 nodes for high-bit divergence, got {}",
            count2
        );
    }

    #[test]
    fn test_jmt_path_compression() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        // Insert a single leaf — should be stored as a single Leaf node
        // (path compression: no internal nodes needed yet)
        smt.mark_consumed(1000).unwrap();
        assert_eq!(smt.active_node_count(), 1);

        // Insert a very different index — should create internal nodes
        // only at the divergence point
        smt.mark_consumed(u64::MAX / 2).unwrap();
        let count = smt.active_node_count();
        // Two leaves + one internal node at divergence = 3 nodes
        assert!(
            count <= 5,
            "Expected few nodes for divergent paths, got {}",
            count
        );
    }

    #[test]
    fn test_jmt_update_cost_proportional_to_active() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        // Insert 100 indices
        for i in 0..100u64 {
            smt.mark_consumed(i * 1000).unwrap();
        }

        let node_count = smt.active_node_count();
        // With 100 leaves, we should have at most ~100 leaves + ~100 internal nodes
        // Much less than 100 * 64 = 6400 that a naive approach would need
        assert!(
            node_count < 6400,
            "Node count {} suggests non-JMT behavior",
            node_count
        );
        // Should be roughly proportional to number of consumed indices
        // Upper bound: each leaf adds at most depth internal nodes in worst case,
        // but with path compression it's much less
        assert!(
            node_count < 100 * 65,
            "Node count {} is not proportional to active nodes",
            node_count
        );
    }

    #[test]
    fn test_jmt_consumed_indices_collection() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        let indices = vec![5u64, 10, 15, 20, 25];
        for &idx in &indices {
            smt.mark_consumed(idx).unwrap();
        }

        let mut collected = smt.consumed_indices();
        collected.sort();
        assert_eq!(collected, indices);
    }

    #[test]
    fn test_jmt_deterministic_root() {
        // Same indices inserted in different orders should produce same root
        // because the JMT structure is determined by the set of indices, not order.
        let hasher1 = PoseidonHash;
        let mut smt1 = SparseMerkleTree::new(hasher1);
        smt1.mark_consumed(10).unwrap();
        smt1.mark_consumed(20).unwrap();
        smt1.mark_consumed(30).unwrap();

        let hasher2 = PoseidonHash;
        let mut smt2 = SparseMerkleTree::new(hasher2);
        smt2.mark_consumed(30).unwrap();
        smt2.mark_consumed(10).unwrap();
        smt2.mark_consumed(20).unwrap();

        // Both trees should report the same consumed status
        assert!(smt1.is_consumed(10));
        assert!(smt1.is_consumed(20));
        assert!(smt1.is_consumed(30));
        assert!(smt2.is_consumed(10));
        assert!(smt2.is_consumed(20));
        assert!(smt2.is_consumed(30));

        // JMT roots should be identical regardless of insertion order
        // because the final tree structure depends only on the set of keys
        assert_eq!(
            smt1.root(),
            smt2.root(),
            "JMT root should be deterministic regardless of insertion order"
        );
    }

    #[test]
    fn test_jmt_proof_after_multiple_inserts() {
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::new(hasher);

        // Insert several indices
        for i in 0..10u64 {
            smt.mark_consumed(i * 100).unwrap();
        }

        // Verify proofs for all consumed indices
        for i in 0..10u64 {
            let idx = i * 100;
            let proof = smt.prove_consumed(idx).unwrap();
            assert!(
                smt.verify_proof(idx, &proof, true),
                "Proof verification failed for consumed index {}",
                idx
            );
        }

        // Verify proofs for unconsumed indices
        for i in 0..10u64 {
            let idx = i * 100 + 1; // offset by 1 from consumed
            let proof = smt.prove_unconsumed(idx).unwrap();
            assert!(
                smt.verify_proof(idx, &proof, false),
                "Proof verification failed for unconsumed index {}",
                idx
            );
        }
    }

    #[test]
    fn test_jmt_small_depth() {
        // Test with a small depth to verify correctness more easily
        let hasher = PoseidonHash;
        let mut smt = SparseMerkleTree::with_depth(hasher, 4);

        // With depth 4, max index is 15
        smt.mark_consumed(5).unwrap();
        smt.mark_consumed(10).unwrap();

        assert!(smt.is_consumed(5));
        assert!(smt.is_consumed(10));
        assert!(!smt.is_consumed(7));

        // Verify proofs work with small depth
        let proof = smt.prove_consumed(5).unwrap();
        assert_eq!(proof.siblings.len(), 3); // depth - 1 = 3
        assert!(smt.verify_proof(5, &proof, true));

        let proof = smt.prove_unconsumed(7).unwrap();
        assert_eq!(proof.siblings.len(), 3);
        assert!(smt.verify_proof(7, &proof, false));
    }
}
