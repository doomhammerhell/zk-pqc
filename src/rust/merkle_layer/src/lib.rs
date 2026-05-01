use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;

/// HexTree (Arity-16) module for high-arity Merkle trees optimized for STARKs.
pub mod hextree;

/// Sparse Merkle Tree module for OTS index tracking.
pub mod smt;

/// SMT state reconstruction from DA diffs.
pub mod reconstruct;

pub use hextree::{HexProof, HexTree};
pub use reconstruct::{ReconstructError, SmtReconstructor};
pub use smt::{SmtError, SmtProof, SparseMerkleTree};

/// Error types for Merkle tree operations.
#[derive(Debug, Clone, PartialEq)]
pub enum MerkleError {
    /// Tree construction with zero leaves.
    EmptyLeaves,
    /// Proof requested for leaf index >= tree size.
    IndexOutOfBounds { index: usize, tree_size: usize },
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MerkleError::EmptyLeaves => write!(f, "Cannot construct Merkle tree with zero leaves"),
            MerkleError::IndexOutOfBounds { index, tree_size } => {
                write!(
                    f,
                    "Leaf index {} out of bounds for tree with {} leaves",
                    index, tree_size
                )
            }
        }
    }
}

impl std::error::Error for MerkleError {}

/// A Merkle inclusion proof containing sibling hashes and path direction bits.
#[derive(Debug, Clone)]
pub struct MerkleProof<D> {
    /// Sibling hashes along the path from leaf to root (log2(N) elements).
    pub siblings: Vec<D>,
    /// Direction bits: false = node is left child, true = node is right child.
    pub path_bits: Vec<bool>,
}

/// Binary Merkle tree generic over a `HashFunction` implementation.
///
/// Nodes are stored in a 1-indexed flat array:
/// - Index 1 is the root
/// - Left child of node i is at 2*i
/// - Right child of node i is at 2*i + 1
/// - Leaves start at index N (where N is the padded leaf count, a power of 2)
pub struct MerkleTree<H: HashFunction<Digest = FELT>> {
    #[allow(dead_code)]
    hasher: H,
    /// Original (unpadded) leaves.
    leaves: Vec<FELT>,
    /// Flat 1-indexed node array. Index 0 is unused.
    /// Indices [1..N) are internal nodes, [N..2N) are leaves.
    nodes: Vec<FELT>,
    /// Number of leaves after padding to next power of 2.
    padded_size: usize,
}

impl<H: HashFunction<Digest = FELT>> MerkleTree<H> {
    /// Construct a new binary Merkle tree from the given leaves.
    ///
    /// Leaves are padded to the next power of 2 using `FELT::from(0)`.
    /// Returns `MerkleError::EmptyLeaves` if the leaves vector is empty.
    pub fn new(hasher: H, leaves: Vec<FELT>) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyLeaves);
        }

        let n = leaves.len().next_power_of_two().max(2);

        // Allocate 2*n nodes (1-indexed, so index 0 is a placeholder).
        let mut nodes = vec![FELT::from(0); 2 * n];

        // Place leaves at indices [n .. 2n).
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[n + i] = *leaf;
        }
        // Remaining leaf slots [n + leaves.len() .. 2n) stay as zero (padding).

        // Build internal nodes bottom-up.
        for i in (1..n).rev() {
            nodes[i] = hasher.hash(&[nodes[2 * i], nodes[2 * i + 1]]);
        }

        Ok(Self {
            hasher,
            leaves,
            nodes,
            padded_size: n,
        })
    }

    /// Return the Merkle root (node at index 1).
    pub fn root(&self) -> FELT {
        self.nodes[1]
    }

    /// Return the number of original (unpadded) leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Generate an inclusion proof for the leaf at `leaf_index`
    /// (0-based, relative to original leaves).
    pub fn prove(&self, leaf_index: usize) -> Result<MerkleProof<FELT>, MerkleError> {
        if leaf_index >= self.leaves.len() {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                tree_size: self.leaves.len(),
            });
        }

        let mut siblings = Vec::new();
        let mut path_bits = Vec::new();
        let mut idx = self.padded_size + leaf_index;

        while idx > 1 {
            let is_right = idx % 2 == 1;
            path_bits.push(is_right);

            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            siblings.push(self.nodes[sibling_idx]);

            idx /= 2;
        }

        Ok(MerkleProof {
            siblings,
            path_bits,
        })
    }

    /// Verify a Merkle inclusion proof.
    ///
    /// Returns `true` if reconstructing the root from `leaf` and `proof` matches `root`.
    /// Returns `false` for invalid proof length or root mismatch (does not panic).
    pub fn verify(
        hasher: &H,
        root: &FELT,
        leaf: &FELT,
        proof: &MerkleProof<FELT>,
        _index: usize,
    ) -> bool {
        // InvalidProofLength: mismatched siblings/path_bits → return false.
        if proof.siblings.len() != proof.path_bits.len() {
            return false;
        }

        let mut current = *leaf;

        for (sibling, &is_right) in proof.siblings.iter().zip(proof.path_bits.iter()) {
            current = if is_right {
                // Current node is the right child; sibling is left.
                hasher.hash(&[*sibling, current])
            } else {
                // Current node is the left child; sibling is right.
                hasher.hash(&[current, *sibling])
            };
        }

        // RootMismatch: reconstructed root ≠ expected root → return false.
        current == *root
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod property_tests;
