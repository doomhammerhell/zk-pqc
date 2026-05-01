//! BatchMerkleAIR — AIR for proving Poseidon Merkle commitment computation.
//!
//! Proves that a batch Merkle commitment root was computed correctly over N
//! proof digests. The trace records each Poseidon hash step in the binary
//! Merkle tree construction (bottom-up).
//!
//! ## Trace Layout (5 columns)
//!   - Column 0: `left_input`    — left child hash
//!   - Column 1: `right_input`   — right child hash
//!   - Column 2: `output`        — H(DOMAIN || left || right)
//!   - Column 3: `next_left`     — the left_input that will appear in the next row
//!   - Column 4: `flag`          — 1 if this row's output feeds into the next row
//!     as next_left, 0 otherwise (padding/level boundary)
//!
//! ## Constraints
//!   - Transition constraint: `flag * (next_left - output) = 0`
//!     When flag=1, the current output must equal the next row's left_input.
//!     When flag=0 (padding or level boundary), no constraint.
//!   - Boundary constraints: first row's left_input and last active row's output.
//!
//! The trace is laid out so that within each Merkle tree level, consecutive
//! pairs of hash outputs feed into the next level. The flag column controls
//! which transitions are constrained.
//!
//! Requirements: 15.1, 15.3, 15.4

use stark_platinum_prover::{
    constraints::{
        boundary::{BoundaryConstraint, BoundaryConstraints},
        transition::TransitionConstraint,
    },
    context::AirContext,
    proof::options::ProofOptions,
    trace::TraceTable,
    traits::{TransitionEvaluationContext, AIR},
    Felt252, PrimeField,
};
use std::marker::PhantomData;

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::sponge::PoseidonSponge;

use crate::wots_air::local_felt_to_stark;

/// Number of columns in the batch Merkle commitment trace.
pub const BATCH_NUM_COLS: usize = 5;
pub const COL_LEFT_INPUT: usize = 0;
pub const COL_RIGHT_INPUT: usize = 1;
pub const COL_OUTPUT: usize = 2;
pub const COL_NEXT_LEFT: usize = 3;
pub const COL_FLAG: usize = 4;

/// Domain separator for internal Merkle nodes (matches aggregator.rs).
const DOMAIN_MERKLE_NODE: u64 = 0x5043415f4e4f4445; // "PCA_NODE"

/// Public inputs for the batch Merkle commitment AIR.
#[derive(Clone, Debug)]
pub struct BatchPublicInputs {
    /// The leaf hashes that form the base of the Merkle tree.
    pub leaf_hashes: Vec<Felt252>,
    /// The expected Merkle commitment root.
    pub commitment_root: Felt252,
    /// Number of leaves (batch size).
    pub batch_size: usize,
    /// Boundary values: (row_index, column, value).
    pub boundary_values: Vec<(usize, usize, Felt252)>,
}

// ---------------------------------------------------------------------------
// Transition Constraint
// ---------------------------------------------------------------------------

/// Transition constraint: `next_row.left_input - current_row.next_left = 0`
///
/// The prover sets `next_left` to equal `output` when the output feeds into
/// the next level, and to equal the next row's actual left_input in all cases.
/// This way the constraint is simply: next row's left_input must match what
/// the current row declared as `next_left`.
#[derive(Clone)]
pub struct BatchMerkleContinuityConstraint<F: Send + Sync> {
    phantom: PhantomData<F>,
}

impl<F: Send + Sync> Default for BatchMerkleContinuityConstraint<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Send + Sync> BatchMerkleContinuityConstraint<F> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl TransitionConstraint<PrimeField, PrimeField> for BatchMerkleContinuityConstraint<PrimeField> {
    fn degree(&self) -> usize {
        1
    }

    fn constraint_idx(&self) -> usize {
        0
    }

    fn end_exemptions(&self) -> usize {
        1
    }

    fn evaluate(
        &self,
        evaluation_context: &TransitionEvaluationContext<PrimeField, PrimeField>,
        transition_evaluations: &mut [Felt252],
    ) {
        let (frame, _, _) = match evaluation_context {
            TransitionEvaluationContext::Prover {
                frame,
                periodic_values,
                rap_challenges,
            }
            | TransitionEvaluationContext::Verifier {
                frame,
                periodic_values,
                rap_challenges,
            } => (frame, periodic_values, rap_challenges),
        };

        let cur = frame.get_evaluation_step(0);
        let nxt = frame.get_evaluation_step(1);

        // Constraint: next row's left_input == current row's next_left
        let cur_next_left = cur.get_main_evaluation_element(0, COL_NEXT_LEFT);
        let nxt_left = nxt.get_main_evaluation_element(0, COL_LEFT_INPUT);

        transition_evaluations[self.constraint_idx()] = nxt_left - cur_next_left;
    }
}

// ---------------------------------------------------------------------------
// AIR
// ---------------------------------------------------------------------------

pub struct BatchMerkleAIR {
    context: AirContext,
    trace_length: usize,
    pub_inputs: BatchPublicInputs,
    constraints: Vec<Box<dyn TransitionConstraint<PrimeField, PrimeField>>>,
}

impl AIR for BatchMerkleAIR {
    type Field = PrimeField;
    type FieldExtension = PrimeField;
    type PublicInputs = BatchPublicInputs;
    const STEP_SIZE: usize = 1;

    fn new(
        trace_length: usize,
        pub_inputs: &Self::PublicInputs,
        proof_options: &ProofOptions,
    ) -> Self {
        let constraints: Vec<Box<dyn TransitionConstraint<PrimeField, PrimeField>>> =
            vec![Box::new(
                BatchMerkleContinuityConstraint::<PrimeField>::new(),
            )];
        let context = AirContext {
            proof_options: proof_options.clone(),
            trace_columns: BATCH_NUM_COLS,
            transition_offsets: vec![0, 1],
            num_transition_constraints: constraints.len(),
        };
        Self {
            pub_inputs: pub_inputs.clone(),
            context,
            trace_length,
            constraints,
        }
    }

    fn composition_poly_degree_bound(&self) -> usize {
        self.trace_length()
    }

    fn transition_constraints(
        &self,
    ) -> &Vec<Box<dyn TransitionConstraint<PrimeField, PrimeField>>> {
        &self.constraints
    }

    fn boundary_constraints(&self, _rap_challenges: &[Felt252]) -> BoundaryConstraints<PrimeField> {
        let constraints: Vec<BoundaryConstraint<PrimeField>> = self
            .pub_inputs
            .boundary_values
            .iter()
            .map(|(step, col, value)| BoundaryConstraint::new_main(*col, *step, *value))
            .collect();
        BoundaryConstraints::from_constraints(constraints)
    }

    fn context(&self) -> &AirContext {
        &self.context
    }

    fn trace_length(&self) -> usize {
        self.trace_length
    }

    fn trace_layout(&self) -> (usize, usize) {
        (BATCH_NUM_COLS, 0)
    }

    fn pub_inputs(&self) -> &Self::PublicInputs {
        &self.pub_inputs
    }
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

/// A single hash step in the Merkle tree construction.
struct MerkleStep {
    left: FELT,
    right: FELT,
    output: FELT,
}

/// Build the execution trace for a Poseidon Merkle commitment computation.
///
/// The trace records every internal hash node in the binary Merkle tree,
/// bottom-up. For N leaves, there are N-1 internal nodes (when N is a power
/// of 2; slightly fewer with odd-count promotions).
///
/// The trace is laid out level by level, left to right. The `next_left` column
/// is set to the next row's actual `left_input` value, which makes the
/// transition constraint `next_row.left == cur_row.next_left` trivially
/// satisfied for all active rows.
///
/// Returns the trace table and public inputs (including boundary constraints).
pub fn build_batch_merkle_trace(
    leaf_hashes: &[FELT],
) -> (TraceTable<PrimeField, PrimeField>, BatchPublicInputs) {
    assert!(
        leaf_hashes.len() >= 2,
        "Need at least 2 leaves for a Merkle tree"
    );

    let domain = FELT::from(DOMAIN_MERKLE_NODE);

    // Build the Merkle tree bottom-up, recording each hash step
    let mut steps: Vec<MerkleStep> = Vec::new();
    let mut current_level: Vec<FELT> = leaf_hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));
        let mut i = 0;

        while i + 1 < current_level.len() {
            let left = current_level[i];
            let right = current_level[i + 1];
            let output = PoseidonSponge::hash_with_ds(domain, &[left, right]);

            steps.push(MerkleStep {
                left,
                right,
                output,
            });
            next_level.push(output);
            i += 2;
        }

        // If odd number of nodes, promote the last one
        if current_level.len() % 2 == 1 {
            next_level.push(*current_level.last().unwrap());
        }

        current_level = next_level;
    }

    let commitment_root = current_level[0];
    let active_rows = steps.len();
    assert!(active_rows >= 1, "Must have at least one hash step");

    // Build trace columns
    let mut col_left: Vec<Felt252> = Vec::with_capacity(active_rows);
    let mut col_right: Vec<Felt252> = Vec::with_capacity(active_rows);
    let mut col_output: Vec<Felt252> = Vec::with_capacity(active_rows);
    let mut col_next_left: Vec<Felt252> = Vec::with_capacity(active_rows);
    let mut col_flag: Vec<Felt252> = Vec::with_capacity(active_rows);

    for (idx, step) in steps.iter().enumerate() {
        col_left.push(local_felt_to_stark(&step.left));
        col_right.push(local_felt_to_stark(&step.right));
        col_output.push(local_felt_to_stark(&step.output));

        // next_left: set to the next row's left_input if there is a next row,
        // otherwise set to the current output (doesn't matter, last row is exempt).
        if idx + 1 < active_rows {
            col_next_left.push(local_felt_to_stark(&steps[idx + 1].left));
            col_flag.push(Felt252::from(1u64));
        } else {
            col_next_left.push(local_felt_to_stark(&step.output));
            col_flag.push(Felt252::from(0u64));
        }
    }

    // Boundary constraints:
    // - First row: left_input = first leaf pair's left child
    // - Last active row: output = commitment root
    let boundary_values = vec![
        (0, COL_LEFT_INPUT, col_left[0]),
        (
            active_rows - 1,
            COL_OUTPUT,
            local_felt_to_stark(&commitment_root),
        ),
    ];

    // Pad to next power of 2 (minimum 8 for FFT)
    let trace_length = active_rows.next_power_of_two().max(8);

    // Padding: repeat the last active row's values.
    // For continuity: padding row's left_input = previous row's next_left = last output.
    // Each padding row: left=output=next_left=last_output, right=last_output, flag=0.
    let pad_val = col_output[active_rows - 1];

    // Fix the last active row's next_left to point to the first padding row's left
    col_next_left[active_rows - 1] = pad_val;

    for _ in active_rows..trace_length {
        col_left.push(pad_val);
        col_right.push(pad_val);
        col_output.push(pad_val);
        col_next_left.push(pad_val); // next padding row's left = same value
        col_flag.push(Felt252::from(0u64));
    }

    let leaf_hashes_stark: Vec<Felt252> = leaf_hashes.iter().map(local_felt_to_stark).collect();

    let trace = TraceTable::from_columns_main(
        vec![col_left, col_right, col_output, col_next_left, col_flag],
        1,
    );

    let pub_inputs = BatchPublicInputs {
        leaf_hashes: leaf_hashes_stark,
        commitment_root: local_felt_to_stark(&commitment_root),
        batch_size: leaf_hashes.len(),
        boundary_values,
    };

    (trace, pub_inputs)
}
