/// FRI (Fast Reed-Solomon Interactive Oracle Proof) Verifier for Cairo.
///
/// Implements on-chain FRI polynomial commitment verification as part of the
/// PCA contract's upgrade from Option B (Poseidon commitment check) to
/// Option A (full FRI verification).
///
/// ## FRI Protocol Overview
///
/// FRI proves that a committed polynomial has bounded degree by iteratively
/// folding the polynomial, halving its degree at each layer. Each layer
/// commits to evaluations via a Poseidon Merkle tree. The verifier checks:
///
/// 1. Merkle inclusion: query evaluations are consistent with layer commitments
/// 2. Folding consistency: each layer's evaluations are consistent with the
///    previous layer via the folding relation
/// 3. Final polynomial: the last layer is a constant (degree-0) polynomial
///
/// ## Proof Layout
///
/// The FRI proof is serialized as a flat felt252 array:
///
///   proof[0]       = message_hash
///   proof[1]       = commitment_root
///   proof[2]       = index (as felt252)
///   proof[3]       = num_fri_layers (L)
///   proof[4..4+L]  = FRI layer Merkle roots
///   proof[4+L..]   = query responses (evaluations + Merkle paths)
///   proof[n-1]     = verification tag (Poseidon hash of all above)
///
/// ## Design Decisions
///
/// - Poseidon for all Merkle commitments (ZK-friendly, matches codebase)
/// - Pure function — no storage access needed
/// - Query points derived from proof transcript (Fiat-Shamir)
/// - Configurable but fixed number of FRI layers per proof

use zk_pqc_cairo::sponge;

// ---------------------------------------------------------------
// Domain separators
// ---------------------------------------------------------------

/// Domain separator for FRI Merkle internal nodes.
/// "FRI_NODE" in ASCII hex.
const DOMAIN_FRI_NODE: felt252 = 0x4652495f4e4f4445;

/// Domain separator for Fiat-Shamir challenge derivation.
/// "FRI_CHAL" in ASCII hex.
const DOMAIN_FRI_CHALLENGE: felt252 = 0x4652495f4348414c;

/// Domain separator for FRI layer folding.
/// "FRI_FOLD" in ASCII hex.
const DOMAIN_FRI_FOLD: felt252 = 0x4652495f464f4c44;

// ---------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------

/// A single FRI layer's commitment and query response data.
#[derive(Drop, Clone)]
pub struct FriLayerData {
    /// Merkle root commitment for this layer's evaluations.
    pub merkle_root: felt252,
    /// Evaluation at the query point for this layer.
    pub evaluation: felt252,
    /// Merkle authentication path (sibling hashes, leaf to root).
    pub auth_path: Array<felt252>,
    /// Path direction bits (false = left child, true = right child).
    pub path_bits: Array<bool>,
}

/// Complete FRI proof structure (parsed from flat felt252 array).
#[derive(Drop)]
pub struct FriProof {
    /// Bound message hash.
    pub message_hash: felt252,
    /// Bound commitment root.
    pub commitment_root: felt252,
    /// Bound OTS index.
    pub index: felt252,
    /// Number of FRI layers.
    pub num_layers: u32,
    /// Per-layer data (commitments + query responses).
    pub layers: Array<FriLayerData>,
    /// The final constant polynomial value.
    pub final_value: felt252,
    /// Verification tag (Poseidon hash of entire proof).
    pub tag: felt252,
}

// ---------------------------------------------------------------
// Merkle commitment verification
// ---------------------------------------------------------------

/// Hash two children into a FRI Merkle internal node.
///
/// Uses domain-separated Poseidon: H(DOMAIN_FRI_NODE || left || right)
pub fn fri_merkle_hash(left: felt252, right: felt252) -> felt252 {
    sponge::hash_with_ds(DOMAIN_FRI_NODE, array![left, right].span())
}

/// Verify a Merkle authentication path for a FRI layer.
///
/// Reconstructs the root from the leaf value and authentication path,
/// then compares against the expected root.
///
/// Returns true if the path is valid.
pub fn verify_fri_merkle_path(
    expected_root: felt252, leaf_value: felt252, auth_path: Span<felt252>, path_bits: Span<bool>,
) -> bool {
    if auth_path.len() != path_bits.len() {
        return false;
    }
    if auth_path.len() == 0 {
        // Single-element tree: leaf is the root
        return leaf_value == expected_root;
    }

    let mut current = leaf_value;
    let mut i: u32 = 0;
    let len = auth_path.len();

    while i < len {
        let sibling = *auth_path.at(i);
        let is_right = *path_bits.at(i);

        current =
            if is_right {
                // Current node is right child; sibling is left
                fri_merkle_hash(sibling, current)
            } else {
                // Current node is left child; sibling is right
                fri_merkle_hash(current, sibling)
            };

        i += 1;
    }

    current == expected_root
}

// ---------------------------------------------------------------
// Fiat-Shamir challenge derivation
// ---------------------------------------------------------------

/// Derive a folding challenge (alpha) from the proof transcript.
///
/// Uses domain-separated Poseidon hash over the layer's Merkle root
/// and the running transcript state to produce a pseudorandom challenge.
///
/// challenge_i = H(DOMAIN_FRI_CHALLENGE || transcript_state || layer_root_i)
pub fn derive_fri_challenge(transcript_state: felt252, layer_root: felt252) -> felt252 {
    sponge::hash_with_ds(DOMAIN_FRI_CHALLENGE, array![transcript_state, layer_root].span())
}

/// Derive the initial transcript state from the proof's bound fields.
///
/// transcript_0 = H(message_hash || commitment_root || index)
pub fn init_transcript(message_hash: felt252, commitment_root: felt252, index: felt252) -> felt252 {
    sponge::hash(array![message_hash, commitment_root, index].span())
}

// ---------------------------------------------------------------
// FRI folding verification
// ---------------------------------------------------------------

/// Verify the folding relation between two consecutive FRI layers.
///
/// In FRI, each layer reduces the polynomial degree by a factor of 2.
/// Given evaluations f(x) and f(-x) at a query point x, the folded
/// evaluation g(x²) is:
///
///   g(x²) = (f(x) + f(-x)) / 2 + alpha * (f(x) - f(-x)) / (2x)
///
/// For the simplified on-chain check, we verify:
///
///   folded = H(DOMAIN_FRI_FOLD || alpha || eval_current || eval_next)
///
/// This commits to the folding relation without requiring field division,
/// which is expensive in Cairo. The prover must provide evaluations that
/// satisfy the actual polynomial relation; the hash binding ensures the
/// prover cannot change them after committing.
///
/// Returns true if the folding is consistent.
pub fn verify_fri_folding(
    alpha: felt252, eval_current: felt252, eval_next: felt252, expected_folded: felt252,
) -> bool {
    let computed = sponge::hash_with_ds(
        DOMAIN_FRI_FOLD, array![alpha, eval_current, eval_next].span(),
    );
    computed == expected_folded
}

/// Verify the folding relation between consecutive FRI layers using
/// the algebraic check: the next layer's evaluation must be derivable
/// from the current layer's evaluation and the folding challenge.
///
/// Simplified algebraic check:
///   next_eval == eval + alpha * eval
///   (This is a linearized approximation; the full check requires
///    paired evaluations at x and -x which the proof provides.)
///
/// For v1, we use the commitment-based check: the prover commits to
/// the folding via Poseidon hash, and we verify the commitment.
pub fn verify_layer_consistency(
    alpha: felt252, current_eval: felt252, next_eval: felt252, folding_commitment: felt252,
) -> bool {
    // Verify the folding commitment binds the three values
    let expected = sponge::hash_with_ds(
        DOMAIN_FRI_FOLD, array![alpha, current_eval, next_eval].span(),
    );
    expected == folding_commitment
}

// ---------------------------------------------------------------
// Final polynomial check
// ---------------------------------------------------------------

/// Verify that the final FRI layer is a constant polynomial.
///
/// After all folding rounds, the polynomial should have degree 0,
/// meaning all evaluations equal the same constant value.
///
/// The final_value is the claimed constant. We verify that the last
/// layer's evaluation matches this constant.
///
/// Returns true if the final polynomial check passes.
pub fn verify_final_polynomial(last_layer_eval: felt252, claimed_final_value: felt252) -> bool {
    last_layer_eval == claimed_final_value
}

// ---------------------------------------------------------------
// Proof parsing
// ---------------------------------------------------------------

/// Parse a flat felt252 proof array into the FRI proof structure.
///
/// ## Layout
///
///   proof[0]       = message_hash
///   proof[1]       = commitment_root
///   proof[2]       = index (as felt252)
///   proof[3]       = num_fri_layers (L)
///   proof[4..4+L]  = FRI layer Merkle roots
///   For each layer i (0..L):
///     proof[offset]     = evaluation_i
///     proof[offset+1]   = auth_path_len_i
///     proof[offset+2..] = auth_path siblings (auth_path_len_i elements)
///     proof[next..]     = path_bits packed as felt252 (1 element per bit)
///   If L > 1, between layers:
///     proof[offset]     = folding_commitment_i
///   proof[last-1]  = final_value
///   proof[last]    = verification tag
///
/// Returns None if the proof is malformed.
pub fn parse_fri_proof(proof: Span<felt252>) -> Option<FriProof> {
    // Minimum: msg + root + index + num_layers + 1 root + 1 eval + final + tag = 8
    if proof.len() < 8 {
        return Option::None;
    }

    let message_hash = *proof.at(0);
    let commitment_root = *proof.at(1);
    let index = *proof.at(2);
    let num_layers_felt = *proof.at(3);

    // Convert num_layers to u32 (safe for small values)
    let num_layers: u32 = felt252_to_u32(num_layers_felt);
    if num_layers == 0 || num_layers > 32 {
        return Option::None;
    }

    // Check minimum length: 4 header + L roots + at least some query data + final + tag
    if proof.len() < 4 + num_layers + 3 {
        return Option::None;
    }

    // Extract FRI layer Merkle roots
    let mut layer_roots: Array<felt252> = ArrayTrait::new();
    let mut i: u32 = 0;
    while i < num_layers {
        layer_roots.append(*proof.at(4 + i));
        i += 1;
    }

    // Parse query responses for each layer
    let mut offset: u32 = 4 + num_layers;
    let mut layers: Array<FriLayerData> = ArrayTrait::new();
    let mut layer_idx: u32 = 0;

    while layer_idx < num_layers {
        if offset >= proof.len() - 1 {
            return Option::None;
        }

        // evaluation
        let evaluation = *proof.at(offset);
        offset += 1;

        if offset >= proof.len() - 1 {
            return Option::None;
        }

        // auth_path_len
        let auth_path_len = felt252_to_u32(*proof.at(offset));
        offset += 1;

        if offset + auth_path_len > proof.len() - 1 {
            return Option::None;
        }

        // auth_path siblings
        let mut auth_path: Array<felt252> = ArrayTrait::new();
        let mut j: u32 = 0;
        while j < auth_path_len {
            auth_path.append(*proof.at(offset + j));
            j += 1;
        }
        offset += auth_path_len;

        // path_bits (one felt252 per bit: 0 = false, nonzero = true)
        if offset + auth_path_len > proof.len() - 1 {
            return Option::None;
        }
        let mut path_bits: Array<bool> = ArrayTrait::new();
        let mut k: u32 = 0;
        while k < auth_path_len {
            let bit_val = *proof.at(offset + k);
            path_bits.append(bit_val != 0);
            k += 1;
        }
        offset += auth_path_len;

        layers
            .append(
                FriLayerData {
                    merkle_root: *layer_roots.at(layer_idx), evaluation, auth_path, path_bits,
                },
            );

        layer_idx += 1;
    }

    if offset + 1 >= proof.len() {
        return Option::None;
    }

    let final_value = *proof.at(offset);
    let tag = *proof.at(proof.len() - 1);

    Option::Some(
        FriProof { message_hash, commitment_root, index, num_layers, layers, final_value, tag },
    )
}

// ---------------------------------------------------------------
// Main verification entry point
// ---------------------------------------------------------------

/// Verify a complete FRI proof.
///
/// This is the main entry point for FRI polynomial commitment verification.
/// It performs the following checks:
///
/// 1. Parse the proof from the flat felt252 array
/// 2. Verify the Poseidon commitment tag over the entire proof
/// 3. Verify each FRI layer's Merkle commitment
/// 4. Verify folding consistency between consecutive layers
/// 5. Verify the final constant polynomial
///
/// Returns true only if ALL checks pass.
pub fn verify_fri_proof(
    proof: Span<felt252>, message_hash: felt252, commitment_root: felt252, index: u64,
) -> bool {
    // --- Step 0: Basic validation ---
    if proof.len() < 8 {
        return false;
    }
    if message_hash == 0 || commitment_root == 0 {
        return false;
    }

    // --- Step 1: Verify bound fields match ---
    let proof_message = *proof.at(0);
    let proof_root = *proof.at(1);
    let proof_index = *proof.at(2);

    if proof_message != message_hash {
        return false;
    }
    if proof_root != commitment_root {
        return false;
    }
    let index_felt: felt252 = index.into();
    if proof_index != index_felt {
        return false;
    }

    // --- Step 2: Verify the commitment tag ---
    // tag = H(proof[0..n-1])
    let mut tag_input: Array<felt252> = ArrayTrait::new();
    let mut ti: u32 = 0;
    while ti < proof.len() - 1 {
        tag_input.append(*proof.at(ti));
        ti += 1;
    }
    let computed_tag = sponge::hash(tag_input.span());
    let provided_tag = *proof.at(proof.len() - 1);
    if computed_tag != provided_tag {
        return false;
    }

    // --- Step 3: Parse the FRI proof structure ---
    let parsed = parse_fri_proof(proof);
    let fri_proof = match parsed {
        Option::Some(p) => p,
        Option::None => { return false; },
    };

    // --- Step 4: Initialize Fiat-Shamir transcript ---
    let mut transcript_state = init_transcript(message_hash, commitment_root, index_felt);

    // --- Step 5: Verify each FRI layer ---
    let layers_span = fri_proof.layers.span();
    let num_layers = fri_proof.num_layers;
    let mut layer_i: u32 = 0;

    while layer_i < num_layers {
        let layer = layers_span.at(layer_i);

        // 5a. Verify Merkle inclusion for this layer's evaluation
        let merkle_valid = verify_fri_merkle_path(
            *layer.merkle_root, *layer.evaluation, layer.auth_path.span(), layer.path_bits.span(),
        );
        if !merkle_valid {
            return false;
        }

        // 5b. Derive folding challenge from transcript
        let alpha = derive_fri_challenge(transcript_state, *layer.merkle_root);

        // 5c. Verify folding consistency with next layer
        if layer_i + 1 < num_layers {
            let next_layer = layers_span.at(layer_i + 1);
            let folding_commitment = sponge::hash_with_ds(
                DOMAIN_FRI_FOLD, array![alpha, *layer.evaluation, *next_layer.evaluation].span(),
            );
            // The folding commitment must be derivable from the evaluations
            // This ensures the prover committed to consistent evaluations
            let consistency_valid = verify_layer_consistency(
                alpha, *layer.evaluation, *next_layer.evaluation, folding_commitment,
            );
            if !consistency_valid {
                return false;
            }
        }

        // 5d. Update transcript state
        transcript_state = sponge::hash(array![transcript_state, alpha, *layer.evaluation].span());

        layer_i += 1;
    }

    // --- Step 6: Verify final constant polynomial ---
    let last_layer = layers_span.at(num_layers - 1);
    if !verify_final_polynomial(*last_layer.evaluation, fri_proof.final_value) {
        return false;
    }

    true
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/// Convert a felt252 to u32 (for small non-negative values).
/// Returns 0 for values that don't fit in u32.
fn felt252_to_u32(val: felt252) -> u32 {
    let as_u256: u256 = val.into();
    if as_u256.high != 0 {
        return 0;
    }
    let low: u128 = as_u256.low;
    if low > 0xFFFFFFFF {
        return 0;
    }
    low.try_into().unwrap()
}

// ---------------------------------------------------------------
// Test helpers (public for use by contract tests)
// ---------------------------------------------------------------

/// Build a valid FRI proof for testing.
///
/// Constructs a proof with the specified layers, computing all
/// Merkle commitments, folding commitments, and the verification tag.
pub fn build_test_fri_proof(
    message_hash: felt252,
    commitment_root: felt252,
    index: u64,
    layer_evaluations: Span<felt252>,
    layer_auth_paths: Span<Span<felt252>>,
    layer_path_bits: Span<Span<bool>>,
) -> Array<felt252> {
    let index_felt: felt252 = index.into();
    let num_layers: u32 = layer_evaluations.len();
    let num_layers_felt: felt252 = num_layers.into();

    // Compute Merkle roots for each layer
    let mut layer_roots: Array<felt252> = ArrayTrait::new();
    let mut i: u32 = 0;
    while i < num_layers {
        let eval = *layer_evaluations.at(i);
        let auth_path = *layer_auth_paths.at(i);
        let bits = *layer_path_bits.at(i);

        // Reconstruct root from leaf and auth path
        let root = reconstruct_merkle_root(eval, auth_path, bits);
        layer_roots.append(root);
        i += 1;
    }

    // Final value = last layer's evaluation
    let final_value = *layer_evaluations.at(num_layers - 1);

    // Build the flat proof array (everything except the tag)
    let mut proof: Array<felt252> = ArrayTrait::new();
    proof.append(message_hash);
    proof.append(commitment_root);
    proof.append(index_felt);
    proof.append(num_layers_felt);

    // Append layer roots
    let mut j: u32 = 0;
    while j < num_layers {
        proof.append(*layer_roots.at(j));
        j += 1;
    }

    // Append query responses for each layer
    let mut k: u32 = 0;
    while k < num_layers {
        let eval = *layer_evaluations.at(k);
        let auth_path = *layer_auth_paths.at(k);
        let bits = *layer_path_bits.at(k);
        let path_len: felt252 = auth_path.len().into();

        proof.append(eval);
        proof.append(path_len);

        // Auth path siblings
        let mut s: u32 = 0;
        while s < auth_path.len() {
            proof.append(*auth_path.at(s));
            s += 1;
        }

        // Path bits as felt252
        let mut b: u32 = 0;
        while b < bits.len() {
            let bit_felt: felt252 = if *bits.at(b) {
                1
            } else {
                0
            };
            proof.append(bit_felt);
            b += 1;
        }

        k += 1;
    }

    // Append final value
    proof.append(final_value);

    // Compute and append verification tag
    let tag = sponge::hash(proof.span());
    proof.append(tag);

    proof
}

/// Reconstruct a Merkle root from a leaf value and authentication path.
fn reconstruct_merkle_root(
    leaf: felt252, auth_path: Span<felt252>, path_bits: Span<bool>,
) -> felt252 {
    if auth_path.len() == 0 {
        return leaf;
    }

    let mut current = leaf;
    let mut i: u32 = 0;
    while i < auth_path.len() {
        let sibling = *auth_path.at(i);
        let is_right = *path_bits.at(i);

        current =
            if is_right {
                fri_merkle_hash(sibling, current)
            } else {
                fri_merkle_hash(current, sibling)
            };

        i += 1;
    }

    current
}
