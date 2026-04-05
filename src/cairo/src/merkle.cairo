use zk_pqc_cairo::hash_trait::HashFunction;

/// Merkle inclusion proof containing sibling hashes and path direction bits.
/// siblings: sibling hashes along the path from leaf to root (log2(N) elements).
/// path_bits: direction bits — false = node is left child, true = node is right child.
#[derive(Drop, Clone)]
pub struct MerkleProof {
    pub siblings: Array<felt252>,
    pub path_bits: Array<bool>,
}

/// Compute the next power of two >= n, with a minimum of 2.
fn next_power_of_two(n: u32) -> u32 {
    if n <= 2 {
        return 2;
    }
    let mut p: u32 = 1;
    while p < n {
        p = p * 2;
    };
    p
}

/// Build a binary Merkle tree from leaves, returning the flat 1-indexed node array.
///
/// Nodes are stored in a 1-indexed flat array:
/// - Index 0 is unused (placeholder zero)
/// - Index 1 is the root
/// - Left child of node i is at 2*i, right child at 2*i + 1
/// - Leaves occupy indices [n .. 2n), where n = next_power_of_two(leaves.len())
///
/// Leaves are padded to the next power of 2 with zero.
/// Panics if leaves is empty.
pub fn build_tree<T, +HashFunction<T>, +Drop<T>>(leaves: Span<felt252>) -> Array<felt252> {
    let leaf_count = leaves.len();
    assert(leaf_count > 0, 'Cannot build tree: empty leaves');

    let n: u32 = next_power_of_two(leaf_count);

    // Extract leaf layer: original leaves + zero padding to size n
    let mut leaf_layer: Array<felt252> = ArrayTrait::new();
    let mut i: u32 = 0;
    while i < n {
        if i < leaf_count {
            leaf_layer.append(*leaves.at(i));
        } else {
            leaf_layer.append(0);
        };
        i += 1;
    };

    // Compute levels bottom-up, storing each level
    // all_levels[0] = leaf layer, all_levels[1] = parents of leaves, ..., last = root
    let mut current_level: Array<felt252> = leaf_layer;
    let mut level_size: u32 = n;
    let mut all_levels: Array<Array<felt252>> = ArrayTrait::new();
    all_levels.append(current_level.clone());

    while level_size > 1 {
        let parent_size = level_size / 2;
        let mut parent_level: Array<felt252> = ArrayTrait::new();
        let current_span = current_level.span();
        let mut k: u32 = 0;
        while k < parent_size {
            let left = *current_span.at(2 * k);
            let right = *current_span.at(2 * k + 1);
            let hash_input = array![left, right];
            parent_level.append(HashFunction::<T>::hash(hash_input.span()));
            k += 1;
        };
        all_levels.append(parent_level.clone());
        current_level = parent_level;
        level_size = parent_size;
    };

    // Reconstruct flat 1-indexed array
    // all_levels: [leaves, parents_of_leaves, ..., root]
    // Flat array: index 0 = placeholder, index 1 = root, ..., indices [n..2n) = leaves
    let num_levels = all_levels.len();
    let all_levels_span = all_levels.span();

    let mut flat: Array<felt252> = ArrayTrait::new();
    flat.append(0); // index 0 placeholder

    // Traverse from root (last level) to leaves (first level)
    let mut lvl_idx: u32 = num_levels;
    while lvl_idx > 0 {
        lvl_idx -= 1;
        let level_span = all_levels_span.at(lvl_idx);
        let mut elem_idx: u32 = 0;
        while elem_idx < level_span.len() {
            flat.append(*level_span.at(elem_idx));
            elem_idx += 1;
        };
    };

    flat
}

/// Get the Merkle root from a flat 1-indexed node array (index 1).
pub fn root(nodes: Span<felt252>) -> felt252 {
    assert(nodes.len() >= 2, 'Node array too small');
    *nodes.at(1)
}

/// Generate an inclusion proof for the leaf at `leaf_index` (0-based).
/// `nodes` is the flat 1-indexed node array, `leaf_count` is the original
/// (unpadded) number of leaves.
pub fn prove(nodes: Span<felt252>, leaf_count: u32, leaf_index: u32) -> MerkleProof {
    assert(leaf_index < leaf_count, 'Leaf index out of bounds');

    let padded_size = next_power_of_two(leaf_count);
    let mut idx: u32 = padded_size + leaf_index;

    let mut siblings: Array<felt252> = ArrayTrait::new();
    let mut path_bits: Array<bool> = ArrayTrait::new();

    while idx > 1 {
        let is_right: bool = (idx % 2) == 1;
        path_bits.append(is_right);

        let sibling_idx = if is_right {
            idx - 1
        } else {
            idx + 1
        };
        siblings.append(*nodes.at(sibling_idx));

        idx = idx / 2;
    };

    MerkleProof { siblings, path_bits }
}

/// Verify a Merkle inclusion proof.
/// Returns true if reconstructing the root from `leaf` and `proof` matches `expected_root`.
pub fn verify<T, +HashFunction<T>, +Drop<T>>(
    expected_root: felt252,
    leaf: felt252,
    proof: @MerkleProof,
) -> bool {
    let siblings = proof.siblings;
    let path_bits = proof.path_bits;

    if siblings.len() != path_bits.len() {
        return false;
    }

    let mut current = leaf;
    let mut i: u32 = 0;
    let len = siblings.len();

    while i < len {
        let sibling = *siblings.at(i);
        let is_right = *path_bits.at(i);

        current =
            if is_right {
                // Current node is right child; sibling is left
                let hash_input = array![sibling, current];
                HashFunction::<T>::hash(hash_input.span())
            } else {
                // Current node is left child; sibling is right
                let hash_input = array![current, sibling];
                HashFunction::<T>::hash(hash_input.span())
            };

        i += 1;
    };

    current == expected_root
}
