//! HexTree (Arity-16 Merkle Tree) — High-Arity Merkle Trees for STARK Optimization.
//!
//! # Mathematical Foundation
//!
//! A HexTree is a Merkle tree where each internal node has exactly 16 children.
//! This reduces tree depth by a factor of log₂(16) = 4 compared to binary trees,
//! significantly reducing the number of hash operations in STARK traces.
//!
//! ## Node Layout
//!
//! For a tree with N leaves (padded to the next power of 16):
//! - Leaves are stored at indices [base_leaf .. base_leaf + N - 1]
//! - Base leaf index for depth D: base = Σ(16^i for i in 0..D-1) = (16^D - 1) / 15
//! - Parent of node at index i: parent = (i - 1) / 16
//! - Children of node at index i: [16*i + 1, 16*i + 2, ..., 16*i + 16]
//!
//! ## Depth Calculation
//!
//! For N leaves, depth D = ⌈log₁₆(N)⌉
//! Proof size = D × 15 siblings (one sibling per path level, excluding the path child)
//!
//! # Formal Properties
//!
//! 1. **Completeness**: ∀ leaf ∈ tree, verify(prove(leaf)) = true
//! 2. **Soundness**: verify(leaf', proof, root) = false for leaf' ≠ leaf (with overwhelming probability)
//! 3. **Binding**: computationally infeasible to find leaf₁ ≠ leaf₂ where prove(leaf₁) = prove(leaf₂)
//!
//! # Usage
//!
//! ```rust
//! use zk_pqc_merkle_layer::HexTree;
//! use zk_pqc_hash_layer::traits::PoseidonHash;
//! use zk_pqc_hash_layer::constants::FELT;
//!
//! let hasher = PoseidonHash;
//! let leaves: Vec<FELT> = (0..16u64).map(FELT::from).collect();
//! let tree = HexTree::new(hasher, leaves.clone()).unwrap();
//! let root = tree.root();
//! let proof = tree.prove(0).unwrap();
//! assert!(HexTree::verify(&hasher, &root, &leaves[0], &proof, 0));
//! ```

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;

use crate::MerkleError;

/// Maximum depth for HexTree (supports up to 16^16 leaves, more than enough for practical use).
#[allow(dead_code)]
const MAX_DEPTH: usize = 16;

/// A HexTree inclusion proof containing sibling hashes and path indices.
///
/// For a tree of depth D:
/// - siblings: D arrays of 15 FELT values each (the siblings at each level)
/// - path_indices: D values in [0, 15] indicating which child position was taken
///
/// Total proof size: D × 15 field elements + D bytes for path indices
#[derive(Debug, Clone, PartialEq)]
pub struct HexProof {
    /// Sibling hashes at each level. siblings[i] are the 15 siblings at depth i.
    pub siblings: Vec<[FELT; 15]>,
    /// Path indices: which child index [0-15] was taken at each level.
    pub path_indices: Vec<u8>,
}

impl HexProof {
    /// Returns the depth of this proof (number of levels).
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Verifies the proof structure is valid.
    pub fn is_valid(&self) -> bool {
        self.siblings.len() == self.path_indices.len()
            && self.path_indices.iter().all(|&i| i < 16)
            && self
                .siblings
                .iter()
                .all(|s| s.iter().all(|f| *f != FELT::zero()))
    }
}

/// HexTree (Arity-16 Merkle Tree) implementation.
///
/// Generic over any `HashFunction` implementation, enabling hash-agility.
pub struct HexTree<H: HashFunction<Digest = FELT>> {
    #[allow(dead_code)]
    hasher: H,
    /// Original (unpadded) leaves.
    leaves: Vec<FELT>,
    /// Flat array storing all nodes. Indexed with geometric series formula.
    /// For depth D, total nodes = (16^D - 1) / 15 + 16^D (leaves)
    nodes: Vec<FELT>,
    /// Number of leaves after padding to next power of 16.
    #[allow(dead_code)]
    padded_size: usize,
    /// Tree depth.
    depth: usize,
    /// Base index where leaves start.
    leaf_base: usize,
}

impl<H: HashFunction<Digest = FELT> + Clone> HexTree<H> {
    /// Creates a new HexTree from the given leaves.
    ///
    /// # Arguments
    /// * `hasher` - Hash function implementation
    /// * `leaves` - Leaf values (will be padded to next power of 16)
    ///
    /// # Returns
    /// * `Ok(HexTree)` - Successfully constructed tree
    /// * `Err(MerkleError::EmptyLeaves)` - If leaves vector is empty
    ///
    /// # Formal Guarantees
    /// - The resulting tree satisfies the Merkle tree invariant:
    ///   ∀ internal node i, node[i] = H(node[16i+1], ..., node[16i+16])
    /// - Root is stored at index 0 (or accessible via root())
    pub fn new(hasher: H, leaves: Vec<FELT>) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyLeaves);
        }

        // Calculate depth and padded size
        let depth = Self::calculate_depth(leaves.len());
        let padded_size = 16usize.pow(depth as u32);
        let leaf_base = Self::leaf_base_index(depth);
        let total_nodes = leaf_base + padded_size;

        // Allocate nodes array
        let mut nodes = vec![FELT::from(0); total_nodes];

        // Place leaves at their positions
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[leaf_base + i] = *leaf;
        }
        // Remaining leaf positions stay as zero (padding)

        // Build internal nodes bottom-up
        for d in (0..depth).rev() {
            let level_base = Self::level_base_index(d);
            let next_level_base = Self::level_base_index(d + 1);
            let num_nodes_at_level = 16usize.pow(d as u32);

            for i in 0..num_nodes_at_level {
                let parent_idx = level_base + i;
                let child_base = next_level_base + i * 16;

                // Collect all 16 children
                let children: Vec<FELT> = (0..16).map(|j| nodes[child_base + j]).collect();

                nodes[parent_idx] = hasher.hash(&children);
            }
        }

        Ok(Self {
            hasher,
            leaves,
            nodes,
            padded_size,
            depth,
            leaf_base,
        })
    }

    /// Returns the Merkle root (hash of the root node).
    pub fn root(&self) -> FELT {
        // Root is at index 0 (level 0, position 0)
        self.nodes[0]
    }

    /// Returns the number of original (unpadded) leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the tree depth.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Generates an inclusion proof for the leaf at `leaf_index`.
    ///
    /// # Arguments
    /// * `leaf_index` - 0-based index of the leaf to prove
    ///
    /// # Returns
    /// * `Ok(HexProof)` - Valid proof
    /// * `Err(MerkleError::IndexOutOfBounds)` - If index >= leaf count
    ///
    /// # Formal Properties
    /// - Proof is valid for the leaf at the given index
    /// - Proof binds leaf to root via collision-resistant hash chain
    pub fn prove(&self, leaf_index: usize) -> Result<HexProof, MerkleError> {
        if leaf_index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                tree_size: self.leaves.len(),
            });
        }

        let mut siblings: Vec<[FELT; 15]> = Vec::with_capacity(self.depth);
        let mut path_indices: Vec<u8> = Vec::with_capacity(self.depth);

        // Build proof from leaf level to root level
        // Start at leaf level
        let mut current_idx = self.leaf_base + leaf_index;

        for d in (0..self.depth).rev() {
            // Find the parent and which child we are
            let level_base = Self::level_base_index(d + 1);
            let position_in_level = current_idx - level_base;
            let parent_child_base = position_in_level / 16;
            let child_index = (position_in_level % 16) as u8;

            // Collect the 15 siblings
            let sibling_base = level_base + parent_child_base * 16;
            let mut level_siblings = [FELT::from(0); 15];
            let mut sib_idx = 0;

            for i in 0..16 {
                if i != child_index as usize {
                    level_siblings[sib_idx] = self.nodes[sibling_base + i];
                    sib_idx += 1;
                }
            }

            siblings.push(level_siblings);
            path_indices.push(child_index);

            // Move up to parent
            if d > 0 {
                current_idx = Self::level_base_index(d) + parent_child_base;
            }
        }

        Ok(HexProof {
            siblings,
            path_indices,
        })
    }

    /// Verifies a HexTree inclusion proof.
    ///
    /// # Arguments
    /// * `hasher` - Hash function (must match the tree's hasher)
    /// * `root` - Expected Merkle root
    /// * `leaf` - Leaf value being verified
    /// * `proof` - Inclusion proof
    /// * `leaf_index` - Index of the leaf (determines path)
    ///
    /// # Returns
    /// * `true` if proof is valid and reconstructs to `root`
    /// * `false` if proof is invalid or doesn't match
    ///
    /// # Formal Verification
    /// This function implements the Merkle verification predicate:
    /// verify(root, leaf, proof) ↔ reconstruct(leaf, proof) = root
    pub fn verify(
        hasher: &H,
        root: &FELT,
        leaf: &FELT,
        proof: &HexProof,
        leaf_index: usize,
    ) -> bool {
        // Check proof structure
        if proof.siblings.len() != proof.path_indices.len() {
            return false;
        }

        if proof.siblings.is_empty() {
            return false;
        }

        if proof.path_indices.iter().any(|&i| i >= 16) {
            return false;
        }

        // Verify proof depth matches expected depth for this leaf_index
        let expected_depth = proof.siblings.len();
        let max_leaves = 16usize.pow(expected_depth as u32);
        if leaf_index >= max_leaves {
            return false;
        }

        // Reconstruct path from leaf to root
        let mut current = *leaf;
        let mut idx = leaf_index;

        // Iterate through proof levels (leaf to root order in proof)
        for (siblings, path_idx) in proof.siblings.iter().zip(proof.path_indices.iter()) {
            // Verify path index matches leaf_index at this level
            let expected_idx = (idx % 16) as u8;
            if *path_idx != expected_idx {
                return false;
            }
            idx /= 16;

            // Reconstruct the parent hash from child + siblings
            let mut children = Vec::with_capacity(16);

            // Insert siblings and current value at correct position
            let mut sib_idx = 0;
            for i in 0..16 {
                if i == *path_idx as usize {
                    children.push(current);
                } else {
                    if sib_idx >= siblings.len() {
                        return false;
                    }
                    children.push(siblings[sib_idx]);
                    sib_idx += 1;
                }
            }

            current = hasher.hash(&children);
        }

        current == *root
    }

    // --- Helper Methods ---

    /// Calculate tree depth for N leaves.
    fn calculate_depth(n: usize) -> usize {
        if n <= 1 {
            return 1; // Minimum depth
        }
        ((n - 1).ilog2() as usize) / 4 + 1 // Divide by 4 since log₂(16) = 4
    }

    /// Calculate base index for leaves at the given depth.
    ///
    /// Formula: Σ(16^i for i in 0..depth-1) = (16^depth - 1) / 15
    fn leaf_base_index(depth: usize) -> usize {
        if depth == 0 {
            return 0;
        }
        (16usize.pow(depth as u32) - 1) / 15
    }

    /// Calculate base index for a level.
    ///
    /// Level 0 = root (index 0)
    /// Level 1 = children of root (indices 1..16)
    /// etc.
    fn level_base_index(level: usize) -> usize {
        if level == 0 {
            return 0;
        }
        (16usize.pow(level as u32) - 1) / 15
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    #[test]
    fn test_hextree_depth_calculation() {
        assert_eq!(HexTree::<PoseidonHash>::calculate_depth(1), 1);
        assert_eq!(HexTree::<PoseidonHash>::calculate_depth(16), 1);
        assert_eq!(HexTree::<PoseidonHash>::calculate_depth(17), 2);
        assert_eq!(HexTree::<PoseidonHash>::calculate_depth(256), 2);
        assert_eq!(HexTree::<PoseidonHash>::calculate_depth(257), 3);
    }

    #[test]
    fn test_hextree_leaf_base_index() {
        assert_eq!(HexTree::<PoseidonHash>::leaf_base_index(1), 1);
        assert_eq!(HexTree::<PoseidonHash>::leaf_base_index(2), 17); // 1 + 16
        assert_eq!(HexTree::<PoseidonHash>::leaf_base_index(3), 273); // 1 + 16 + 256
    }

    #[test]
    fn test_hextree_single_leaf() {
        let hasher = PoseidonHash;
        let leaf = FELT::from(42u64);
        let tree = HexTree::new(hasher, vec![leaf]).unwrap();

        // For single leaf, depth = 1, root = hash([leaf, 0, ..., 0])
        assert_eq!(tree.depth(), 1);
        assert_ne!(tree.root(), FELT::zero());

        let proof = tree.prove(0).unwrap();
        assert_eq!(proof.depth(), 1);
        assert!(HexTree::verify(&hasher, &tree.root(), &leaf, &proof, 0));
    }

    #[test]
    fn test_hextree_prove_verify_roundtrip() {
        let hasher = PoseidonHash;
        let leaves: Vec<FELT> = (0..100u64).map(FELT::from).collect();
        let tree = HexTree::new(hasher, leaves.clone()).unwrap();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i).unwrap();
            assert!(
                HexTree::verify(&hasher, &tree.root(), leaf, &proof, i),
                "Proof verification failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_hextree_wrong_leaf_rejected() {
        let hasher = PoseidonHash;
        let leaves: Vec<FELT> = (0..10u64).map(FELT::from).collect();
        let tree = HexTree::new(hasher, leaves.clone()).unwrap();

        let proof = tree.prove(0).unwrap();
        let wrong_leaf = FELT::from(999u64);

        assert!(!HexTree::verify(
            &hasher,
            &tree.root(),
            &wrong_leaf,
            &proof,
            0
        ));
    }

    #[test]
    fn test_hextree_wrong_index_rejected() {
        let hasher = PoseidonHash;
        let leaves: Vec<FELT> = (0..10u64).map(FELT::from).collect();
        let tree = HexTree::new(hasher, leaves.clone()).unwrap();

        let proof = tree.prove(0).unwrap();

        // Verification with wrong index should fail
        assert!(!HexTree::verify(
            &hasher,
            &tree.root(),
            &leaves[0],
            &proof,
            1
        ));
    }

    #[test]
    fn test_hextree_tampered_proof_rejected() {
        let hasher = PoseidonHash;
        let leaves: Vec<FELT> = (0..10u64).map(FELT::from).collect();
        let tree = HexTree::new(hasher, leaves.clone()).unwrap();

        let mut proof = tree.prove(0).unwrap();
        // Tamper with a sibling
        proof.siblings[0][0] = FELT::from(0xDEADBEEFu64);

        assert!(!HexTree::verify(
            &hasher,
            &tree.root(),
            &leaves[0],
            &proof,
            0
        ));
    }

    #[test]
    fn test_hextree_empty_leaves_error() {
        let hasher = PoseidonHash;
        let result = HexTree::new(hasher, vec![]);
        assert!(matches!(result, Err(MerkleError::EmptyLeaves)));
    }

    #[test]
    fn test_hextree_out_of_bounds_error() {
        let hasher = PoseidonHash;
        let leaves: Vec<FELT> = (0..5u64).map(FELT::from).collect();
        let tree = HexTree::new(hasher, leaves).unwrap();

        let result = tree.prove(10);
        assert!(matches!(result, Err(MerkleError::IndexOutOfBounds { .. })));
    }

    #[test]
    fn test_hextree_proof_structure_valid() {
        let hasher = PoseidonHash;
        let leaves: Vec<FELT> = (0..100u64).map(FELT::from).collect();
        let tree = HexTree::new(hasher, leaves).unwrap();

        let proof = tree.prove(0).unwrap();
        assert!(proof.is_valid());
    }

    #[test]
    fn test_hextree_depth_vs_binary() {
        // For 65536 leaves:
        // - Binary tree depth: 16
        // - HexTree depth: 4 (4x reduction!)
        let hasher = PoseidonHash;
        let leaves: Vec<FELT> = (0..65536u64).map(FELT::from).collect();
        let tree = HexTree::new(hasher, leaves).unwrap();

        assert_eq!(tree.depth(), 4); // log₁₆(65536) = 4

        let proof = tree.prove(12345).unwrap();
        assert_eq!(proof.depth(), 4);
        // Proof size: 4 levels × 15 siblings = 60 field elements
        // vs Binary: 16 levels × 1 sibling = 16 field elements
        // Trade-off: fewer hash operations in STARK, larger proof elements
    }
}
