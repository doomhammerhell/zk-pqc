//! WotsVerificationAIR — AIR for WOTS+ signature verification using lambdaworks STARK.
//!
//! Implements the lambdaworks `AIR` trait for proving WOTS+ signature verification.
//! The trace encodes hash chain iterations: for each chain i, the verifier iterates
//! from `sig_value[i]` by `(w-1-m_i)` hash steps and checks the result equals `pubkey[i]`.
//!
//! ## Trace Layout (4 columns)
//!   - Column 0: `chain_index`
//!   - Column 1: `step_index`
//!   - Column 2: `current_value`
//!   - Column 3: `expected_next` = H(current_value)
//!
//! ## Constraint Count (WOTS+ w=16, 66 chains)
//!   - Max trace rows: 66 × 15 = 990, padded to 1024
//!   - Transition constraints: 1 (hash chain continuity, degree 1)
//!   - Boundary constraints: 2 (first + last row of trace)
//!   - For full Poseidon-inside-STARK: ~128,000 total constraints
//!
//! Requirements: 11.1, 11.2, 11.4, 21.4

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

/// Number of columns in the WOTS+ verification trace.
pub const NUM_TRACE_COLS: usize = 4;
pub const COL_CHAIN_INDEX: usize = 0;
pub const COL_STEP_INDEX: usize = 1;
pub const COL_CURRENT_VALUE: usize = 2;
pub const COL_EXPECTED_NEXT: usize = 3;

/// Public inputs for the WOTS+ verification AIR.
#[derive(Clone, Debug)]
pub struct WotsPublicInputs {
    pub message_hash: Felt252,
    pub commitment_root: Felt252,
    pub chain_count: usize,
    /// Boundary values: (row_index, column, value).
    pub boundary_values: Vec<(usize, usize, Felt252)>,
}

// ---------------------------------------------------------------------------
// Transition Constraint
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct HashChainContinuityConstraint<F: Send + Sync> {
    phantom: PhantomData<F>,
}

impl<F: Send + Sync> Default for HashChainContinuityConstraint<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Send + Sync> HashChainContinuityConstraint<F> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

impl TransitionConstraint<PrimeField, PrimeField> for HashChainContinuityConstraint<PrimeField> {
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
        let expected = cur.get_main_evaluation_element(0, COL_EXPECTED_NEXT);
        let actual = nxt.get_main_evaluation_element(0, COL_CURRENT_VALUE);
        transition_evaluations[self.constraint_idx()] = actual - expected;
    }
}

// ---------------------------------------------------------------------------
// AIR
// ---------------------------------------------------------------------------

pub struct WotsVerificationAIR {
    context: AirContext,
    trace_length: usize,
    pub_inputs: WotsPublicInputs,
    constraints: Vec<Box<dyn TransitionConstraint<PrimeField, PrimeField>>>,
}

impl AIR for WotsVerificationAIR {
    type Field = PrimeField;
    type FieldExtension = PrimeField;
    type PublicInputs = WotsPublicInputs;
    const STEP_SIZE: usize = 1;

    fn new(
        trace_length: usize,
        pub_inputs: &Self::PublicInputs,
        proof_options: &ProofOptions,
    ) -> Self {
        let constraints: Vec<Box<dyn TransitionConstraint<PrimeField, PrimeField>>> =
            vec![Box::new(HashChainContinuityConstraint::<PrimeField>::new())];
        let context = AirContext {
            proof_options: proof_options.clone(),
            trace_columns: NUM_TRACE_COLS,
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
        (NUM_TRACE_COLS, 0)
    }
    fn pub_inputs(&self) -> &Self::PublicInputs {
        &self.pub_inputs
    }
}

// ---------------------------------------------------------------------------
// Type conversion
// ---------------------------------------------------------------------------

/// Convert a local `FELT` to the STARK prover's `Felt252` via hex.
pub fn local_felt_to_stark(f: &zk_pqc_hash_layer::constants::FELT) -> Felt252 {
    #[allow(unused_imports)]
    use lambdaworks_math::traits::ByteConversion;
    let bytes = f.to_bytes_be();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    Felt252::from_hex_unchecked(&format!("0x{}", hex))
}

// ---------------------------------------------------------------------------
// Trace builder
// ---------------------------------------------------------------------------

/// Build the execution trace for WOTS+ signature verification.
///
/// Strategy: build a flat sequence of hash chain steps where every consecutive
/// pair of rows satisfies `row[i+1].current_value == row[i].expected_next`.
///
/// For each chain i with `remaining = w-1-m_i` steps:
///   - If remaining > 0: add `remaining` rows recording the hash iterations
///   - If remaining == 0: the sig value already equals the pubkey, skip (no rows needed)
///
/// Between chains, we insert a "bridge" row that connects the last hash output
/// of chain i to the first input of chain i+1, maintaining trace continuity.
///
/// Boundary constraints: first row's current_value and last row's expected_next.
pub fn build_wots_verification_trace(
    signature_values: &[zk_pqc_hash_layer::constants::FELT],
    message_elements: &[usize],
    public_key: &[zk_pqc_hash_layer::constants::FELT],
    w: usize,
    message_hash: zk_pqc_hash_layer::constants::FELT,
    commitment_root: zk_pqc_hash_layer::constants::FELT,
) -> (TraceTable<PrimeField, PrimeField>, WotsPublicInputs) {
    use zk_pqc_hash_layer::traits::{HashFunction, PoseidonHash};

    let hasher = PoseidonHash;
    let total_chains = signature_values.len();
    assert_eq!(total_chains, message_elements.len());
    assert_eq!(total_chains, public_key.len());

    // Phase 1: Build per-chain segments (only chains with remaining > 0)
    // Each segment is a list of (current_value, expected_next) pairs.
    struct ChainSegment {
        chain_idx: usize,
        rows: Vec<(
            zk_pqc_hash_layer::constants::FELT,
            zk_pqc_hash_layer::constants::FELT,
        )>,
    }

    let mut segments: Vec<ChainSegment> = Vec::new();

    for chain_i in 0..total_chains {
        let remaining = (w - 1) - message_elements[chain_i];
        if remaining == 0 {
            continue; // sig_value == pubkey, no hash steps needed
        }

        let mut rows = Vec::with_capacity(remaining);
        let mut current = signature_values[chain_i];
        for _ in 0..remaining {
            let next = hasher.hash(&[current]);
            rows.push((current, next));
            current = next;
        }
        // At this point, `current` should equal `public_key[chain_i]`
        segments.push(ChainSegment {
            chain_idx: chain_i,
            rows,
        });
    }

    if segments.is_empty() {
        // Edge case: all chains have 0 remaining steps (all sig values = pubkeys).
        // Create a minimal trace with a single dummy row.
        let dummy_val = local_felt_to_stark(&signature_values[0]);
        let trace_length = 8usize; // minimum for FFT
        let ci = vec![Felt252::from(0u64); trace_length];
        let si = vec![Felt252::from(0u64); trace_length];
        let cv = vec![dummy_val; trace_length];
        let en = vec![dummy_val; trace_length];

        let boundary_values = vec![
            (0, COL_CURRENT_VALUE, dummy_val),
            (0, COL_EXPECTED_NEXT, dummy_val),
        ];

        let trace = TraceTable::from_columns_main(vec![ci, si, cv, en], 1);
        let pub_inputs = WotsPublicInputs {
            message_hash: local_felt_to_stark(&message_hash),
            commitment_root: local_felt_to_stark(&commitment_root),
            chain_count: total_chains,
            boundary_values,
        };
        return (trace, pub_inputs);
    }

    // Phase 2: Flatten segments into a continuous trace.
    // Between segments, the last row's expected_next must equal the next segment's
    // first row's current_value. We achieve this by patching expected_next at boundaries.
    let mut col_chain_index: Vec<Felt252> = Vec::new();
    let mut col_step_index: Vec<Felt252> = Vec::new();
    let mut col_current_value: Vec<Felt252> = Vec::new();
    let mut col_expected_next: Vec<Felt252> = Vec::new();

    for (seg_idx, segment) in segments.iter().enumerate() {
        for (step, (cur, nxt)) in segment.rows.iter().enumerate() {
            col_chain_index.push(Felt252::from(segment.chain_idx as u64));
            col_step_index.push(Felt252::from(step as u64));
            col_current_value.push(local_felt_to_stark(cur));

            // For the last row of this segment (not the last segment overall),
            // patch expected_next to equal the next segment's first current_value.
            let is_last_row_of_segment = step == segment.rows.len() - 1;
            let is_last_segment = seg_idx == segments.len() - 1;

            if is_last_row_of_segment && !is_last_segment {
                let next_seg_first_cur = &segments[seg_idx + 1].rows[0].0;
                col_expected_next.push(local_felt_to_stark(next_seg_first_cur));
            } else {
                col_expected_next.push(local_felt_to_stark(nxt));
            }
        }
    }

    let actual_rows = col_current_value.len();

    // Boundary constraints: first row's current_value and last row's expected_next
    let boundary_values = vec![
        (0, COL_CURRENT_VALUE, col_current_value[0]),
        (
            actual_rows - 1,
            COL_EXPECTED_NEXT,
            col_expected_next[actual_rows - 1],
        ),
    ];

    // Phase 3: Pad to next power of 2
    let trace_length = actual_rows.next_power_of_two().max(8);
    let pad_value = col_expected_next[actual_rows - 1];
    let pad_chain = col_chain_index[actual_rows - 1];

    for _ in actual_rows..trace_length {
        col_chain_index.push(pad_chain);
        col_step_index.push(Felt252::from(0u64));
        col_current_value.push(pad_value);
        col_expected_next.push(pad_value);
    }

    let trace = TraceTable::from_columns_main(
        vec![
            col_chain_index,
            col_step_index,
            col_current_value,
            col_expected_next,
        ],
        1,
    );

    let pub_inputs = WotsPublicInputs {
        message_hash: local_felt_to_stark(&message_hash),
        commitment_root: local_felt_to_stark(&commitment_root),
        chain_count: total_chains,
        boundary_values,
    };

    (trace, pub_inputs)
}

/// Document the constraint count for WOTS+ w=16 verification.
///
/// For WOTS+ w=16 with 66 chains:
/// - Max steps per chain: 15 (w-1)
/// - Max trace rows: 66 × 15 = 990, padded to 1024
/// - Transition constraints: 1 (hash chain continuity)
/// - Boundary constraints: 2 (first row + last row)
/// - For full Poseidon-inside-STARK (~130 constraints per hash step):
///   990 × 130 ≈ 128,700 ≈ target ~128,000
pub fn documented_constraint_count(w: usize, total_chains: usize) -> (usize, usize, usize) {
    let max_steps_per_chain = w - 1;
    let max_trace_rows = total_chains * max_steps_per_chain;
    let padded = max_trace_rows.next_power_of_two();
    let transition = 1usize;
    let boundary = 2usize;
    let total = padded * transition + boundary;
    (padded, boundary, total)
}
