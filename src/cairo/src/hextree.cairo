//! HexTree (Arity-16 Merkle Tree) — High-Arity Merkle Trees for STARK Optimization.
//!
//! # Mathematical Foundation
//!
//! A HexTree is a Merkle tree where each internal node has exactly 16 children.
//! This reduces tree depth by a factor of log₂(16) = 4 compared to binary trees.

use zk_pqc_cairo::hash_trait::HashFunction;

/// Maximum depth for HexTree.
const MAX_DEPTH: u32 = 8;

/// A HexTree inclusion proof.
#[derive(Drop, Clone)]
pub struct HexProof {
    /// Sibling hashes at each level. Each level has 15 siblings.
    pub siblings: Array<Array<felt252>>,
    /// Path indices: which child index [0-15] was taken at each level.
    pub path_indices: Array<u8>,
}

/// HexTree (Arity-16 Merkle Tree) implementation.
pub struct HexTree {
    /// All nodes stored in a flat array. Root is at index 0.
    pub nodes: Array<felt252>,
    /// Number of leaves after padding to next power of 16.
    pub padded_size: u32,
    /// Tree depth.
    pub depth: u32,
    /// Base index where leaves start.
    pub leaf_base: u32,
}

/// Error types for HexTree operations.
#[derive(Drop, Debug)]
pub enum HexTreeError {
    /// Tree construction with zero leaves.
    EmptyLeaves,
    /// Proof requested for leaf index >= tree size.
    IndexOutOfBounds,
    /// Invalid depth.
    InvalidDepth,
}

/// Creates a new HexTree from the given leaves.
pub fn new_hextree<T, +HashFunction<T>, +Drop<T>>(
    leaves: Span<felt252>,
) -> Result<HexTree, HexTreeError> {
    if leaves.len() == 0 {
        return Result::Err(HexTreeError::EmptyLeaves);
    }

    // Calculate depth and padded size
    let depth = calculate_depth(leaves.len());
    let padded_size = pow16(depth);
    let leaf_base = leaf_base_index(depth);
    let total_nodes = leaf_base + padded_size;

    // Initialize nodes array
    let mut nodes: Array<felt252> = ArrayTrait::new();
    let mut i: u32 = 0;
    while i < total_nodes {
        nodes.append(0);
        i += 1;
    }

    // Place leaves at their positions
    // Note: In Cairo, arrays are immutable, so we need to rebuild
    let mut new_nodes: Array<felt252> = ArrayTrait::new();

    // Copy nodes up to leaf_base
    let mut node_idx: u32 = 0;
    while node_idx < leaf_base {
        new_nodes.append(*nodes.at(node_idx));
        node_idx += 1;
    }

    // Place leaves
    let mut leaf_idx: u32 = 0;
    while leaf_idx < leaves.len() {
        new_nodes.append(*leaves.at(leaf_idx));
        leaf_idx += 1;
    }

    // Pad remaining leaves with zeros
    while new_nodes.len() < total_nodes {
        new_nodes.append(0);
    }

    // Build internal nodes bottom-up
    let mut d: u32 = depth;
    while d > 0 {
        let level = d - 1;
        let level_base = level_base_index(level);
        let next_level_base = level_base_index(level + 1);
        let num_nodes_at_level = pow16(level);

        let mut node_i: u32 = 0;
        while node_i < num_nodes_at_level {
            let parent_idx = level_base + node_i;
            let child_base = next_level_base + node_i * 16;

            // Collect all 16 children
            let mut children: Array<felt252> = ArrayTrait::new();
            let mut child_i: u32 = 0;
            while child_i < 16 {
                children.append(*new_nodes.at((child_base + child_i)));
                child_i += 1;
            }

            let parent_hash = HashFunction::<T>::hash(children.span());

            // Rebuild array with updated parent
            let mut updated_nodes: Array<felt252> = ArrayTrait::new();
            let mut k: u32 = 0;
            while k < new_nodes.len() {
                if k == parent_idx {
                    updated_nodes.append(parent_hash);
                } else {
                    updated_nodes.append(*new_nodes.at(k));
                }
                k += 1;
            }
            new_nodes = updated_nodes;

            node_i += 1;
        }

        d -= 1;
    }

    Result::Ok(HexTree { nodes: new_nodes, padded_size, depth, leaf_base })
}

/// Returns the Merkle root.
pub fn root(tree: @HexTree) -> felt252 {
    *tree.nodes.at(0)
}

/// Generates an inclusion proof for the leaf at `leaf_index`.
pub fn prove(tree: @HexTree, leaf_index: u32) -> Result<HexProof, HexTreeError> {
    if leaf_index >= *tree.padded_size {
        return Result::Err(HexTreeError::IndexOutOfBounds);
    }

    let mut siblings: Array<Array<felt252>> = ArrayTrait::new();
    let mut path_indices: Array<u8> = ArrayTrait::new();

    let mut current_idx: u32 = *tree.leaf_base + leaf_index;

    let mut d: u32 = *tree.depth;
    while d > 0 {
        let level = d;
        let level_base = level_base_index(level);
        let position_in_level = current_idx - level_base;
        let parent_child_base = position_in_level / 16;
        let child_index: u8 = (position_in_level % 16).try_into().unwrap();

        // Collect the 15 siblings
        let sibling_base = level_base + parent_child_base * 16;
        let mut level_siblings: Array<felt252> = ArrayTrait::new();

        let mut i: u32 = 0;
        while i < 16 {
            if i != child_index.into() {
                level_siblings.append(*tree.nodes.at((sibling_base + i)));
            }
            i += 1;
        }

        siblings.append(level_siblings);
        path_indices.append(child_index);

        if d > 1 {
            current_idx = level_base_index(d - 1) + parent_child_base;
        }

        d -= 1;
    }

    Result::Ok(HexProof { siblings, path_indices })
}

/// Verifies a HexTree inclusion proof.
pub fn verify<T, +HashFunction<T>, +Drop<T>>(
    root_val: felt252, leaf: felt252, proof: @HexProof, leaf_index: u32,
) -> bool {
    if proof.siblings.len() != proof.path_indices.len() {
        return false;
    }

    let mut current = leaf;
    let mut idx = leaf_index;

    let mut i: u32 = 0;
    while i < proof.siblings.len() {
        let siblings = proof.siblings.at(i);
        let path_idx: u32 = (*proof.path_indices.at(i)).into();

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
            if child_pos == path_idx {
                children.append(current);
            } else {
                children.append(*siblings.at(sib_idx));
                sib_idx += 1;
            }
            child_pos += 1;
        }

        current = HashFunction::<T>::hash(children.span());

        i += 1;
    }

    if idx != 0 {
        return false;
    }

    current == root_val
}

// --- Helper Functions ---

fn calculate_depth(n: u32) -> u32 {
    if n <= 1 {
        return 1;
    }
    let log2_n = log2_int(n);
    (log2_n + 3) / 4
}

fn leaf_base_index(depth: u32) -> u32 {
    if depth == 0 {
        return 0;
    }
    (pow16(depth) - 1) / 15
}

fn level_base_index(level: u32) -> u32 {
    if level == 0 {
        return 0;
    }
    (pow16(level) - 1) / 15
}

fn pow16(n: u32) -> u32 {
    if n == 0 {
        return 1;
    }
    let mut result: u32 = 1;
    let mut i: u32 = 0;
    while i < n {
        result = result * 16;
        i += 1;
    }
    result
}

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
