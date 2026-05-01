use proptest::prelude::*;
use zk_pqc_hash_layer::constants::{FELT, T};

use crate::air::{booleanity_constraint, evaluate_constraints, generate_trace};

/// Generate an arbitrary FELT from a random u64 seed.
fn arb_felt() -> impl Strategy<Value = FELT> {
    any::<u64>().prop_map(FELT::from)
}

/// Generate an arbitrary Poseidon state [FELT; T].
fn arb_state() -> impl Strategy<Value = [FELT; T]> {
    proptest::array::uniform6(arb_felt())
}

// Feature: zk-pqc-framework, Property 18: AIR Constraint Satisfaction
//
// For any valid Poseidon permutation execution trace, all AIR polynomial
// transition constraints (S-box, MDS mixing, ARK addition) shall evaluate
// to zero, and all boolean flags in the trace shall satisfy b*(b-1) = 0.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    fn prop_air_constraint_satisfaction(state in arb_state()) {
        let trace = generate_trace(state);
        let eval = evaluate_constraints(&trace);

        // All S-box residuals must be zero
        for (i, r) in eval.sbox_residuals.iter().enumerate() {
            prop_assert_eq!(
                *r,
                FELT::zero(),
                "S-box constraint {} violated",
                i
            );
        }

        // All MDS residuals must be zero
        for (i, r) in eval.mds_residuals.iter().enumerate() {
            prop_assert_eq!(
                *r,
                FELT::zero(),
                "MDS constraint {} violated",
                i
            );
        }

        // All ARK residuals must be zero
        for (i, r) in eval.ark_residuals.iter().enumerate() {
            prop_assert_eq!(
                *r,
                FELT::zero(),
                "ARK constraint {} violated",
                i
            );
        }

        prop_assert!(eval.is_satisfied(), "Not all constraints satisfied");
    }

    #[test]
    fn prop_booleanity_constraint_valid(b_bit in prop::bool::ANY) {
        // Boolean values (0 and 1) must satisfy b*(b-1) = 0
        let b = if b_bit { FELT::one() } else { FELT::zero() };
        let residual = booleanity_constraint(&b);
        prop_assert_eq!(
            residual,
            FELT::zero(),
            "Booleanity constraint violated for boolean value"
        );
    }

    #[test]
    fn prop_booleanity_constraint_rejects_non_boolean(v in 2u64..1000u64) {
        // Non-boolean values must NOT satisfy b*(b-1) = 0
        let b = FELT::from(v);
        let residual = booleanity_constraint(&b);
        prop_assert_ne!(
            residual,
            FELT::zero(),
            "Booleanity constraint should reject non-boolean value {}",
            v
        );
    }
}

use crate::pca::{
    commitment_root, generate_keypair, generate_pca_proof, verify_pca_proof, verify_pca_proof_bound,
};
use crate::wots_prover::{default_proof_options, prove_wots_verification};
use crate::wots_verifier::verify_stark_proof_real;
use zk_pqc_signature_layer::{HashMode, WotsParams};

/// Generate an arbitrary non-zero FELT for messages.
fn arb_nonzero_felt() -> impl Strategy<Value = FELT> {
    (1u64..u64::MAX).prop_map(FELT::from)
}

/// Generate arbitrary WOTS+ seed (1–4 FELTs).
fn arb_seed() -> impl Strategy<Value = Vec<FELT>> {
    proptest::collection::vec(arb_felt(), 1..=4)
}

// ---------------------------------------------------------------------------
// Feature: zk-pqc-framework, Property 17 (UPDATED): PCA Proof Binding and
// Verification (Real STARK)
//
// For any valid STARK authorization proof π_auth generated for message M and
// commitment root R, on-chain verification shall accept it. For any proof
// generated for (M, R), verifying with a different message M' ≠ M or a
// different root R' ≠ R shall be rejected. For any invalid proof,
// verification shall be rejected.
//
// Validates: Requirements 10.2, 10.3, 10.4, 12.1, 12.2, 12.3
// ---------------------------------------------------------------------------

// ── Unit tests for real STARK PCA ──

/// Generate a WOTS+ keypair, sign, prove with real STARK, verify.
#[test]
fn test_real_stark_pca_prove_verify() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };
    let seed = vec![FELT::from(42u64), FELT::from(123u64)];
    let keypair = generate_keypair(&seed, &params);
    let message = FELT::from(999u64);

    let pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
        .expect("PCA proof generation must succeed");

    assert!(
        verify_pca_proof(&pca_proof),
        "Real STARK PCA proof must verify"
    );

    // Also verify with explicit binding
    let root = commitment_root(&keypair.public_chains);
    assert!(
        verify_pca_proof_bound(&pca_proof, &pca_proof.message_hash, &root),
        "Bound verification must pass"
    );
}

/// Tampered public inputs should be rejected by the real STARK verifier.
#[test]
fn test_real_stark_tampered_proof_rejected() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };
    let seed = vec![FELT::from(77u64)];
    let keypair = generate_keypair(&seed, &params);
    let message = FELT::from(555u64);

    let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
        .expect("PCA proof generation must succeed");

    // Tamper: alter a boundary constraint value in the public inputs
    if !pca_proof.pub_inputs.boundary_values.is_empty() {
        pca_proof.pub_inputs.boundary_values[0].2 =
            crate::wots_air::local_felt_to_stark(&FELT::from(12345u64));
    }

    assert!(
        !verify_pca_proof(&pca_proof),
        "Proof with tampered boundary constraints must be rejected"
    );
}

/// Proof for message A must be rejected when verified against message B.
#[test]
fn test_real_stark_wrong_message_rejected() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };
    let seed = vec![FELT::from(55u64)];
    let keypair = generate_keypair(&seed, &params);

    let message_a = FELT::from(0xAAAAu64);
    let message_b = FELT::from(0xBBBBu64);

    let pca_proof = generate_pca_proof(&params, &keypair, &message_a, 0)
        .expect("PCA proof generation must succeed");

    let message_b_hash = zk_pqc_hash_layer::sponge::PoseidonSponge::hash(&[message_b]);
    let root = commitment_root(&keypair.public_chains);

    assert!(
        !verify_pca_proof_bound(&pca_proof, &message_b_hash, &root),
        "Proof for message A must be rejected when verified against message B"
    );
}

/// Random garbage public inputs must be rejected.
#[test]
fn test_real_stark_random_garbage_rejected() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };
    let seed = vec![FELT::from(88u64)];
    let keypair = generate_keypair(&seed, &params);
    let message = FELT::from(0x1234u64);

    let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
        .expect("PCA proof generation must succeed");

    // Replace message_hash with garbage
    pca_proof.message_hash = FELT::from(0xDEADBEEFu64);

    assert!(
        !verify_pca_proof(&pca_proof),
        "Proof with garbage message_hash must be rejected"
    );
}

// ── Fast real STARK PCA property tests (10 cases, run in CI) ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_real_stark_pca_valid_proof_accepted(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        index in 0u64..1000u64,
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let pca_proof = generate_pca_proof(&params, &keypair, &message, index)
            .expect("proof generation must succeed");

        prop_assert!(
            verify_pca_proof(&pca_proof),
            "Valid real STARK PCA proof must be accepted"
        );
    }

    #[test]
    fn prop_real_stark_pca_message_tamper_rejected(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        tampered_message in arb_nonzero_felt(),
    ) {
        prop_assume!(message != tampered_message);

        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
            .expect("proof generation must succeed");

        // Tamper: change the message_hash binding
        pca_proof.message_hash = tampered_message;

        prop_assert!(
            !verify_pca_proof(&pca_proof),
            "Proof with tampered message must be rejected"
        );
    }

    #[test]
    fn prop_real_stark_pca_root_tamper_rejected(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        tampered_root in arb_nonzero_felt(),
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
            .expect("proof generation must succeed");

        prop_assume!(pca_proof.commitment_root != tampered_root);

        // Tamper: change the commitment_root binding
        pca_proof.commitment_root = tampered_root;

        prop_assert!(
            !verify_pca_proof(&pca_proof),
            "Proof with tampered root must be rejected"
        );
    }

    #[test]
    fn prop_real_stark_pca_random_garbage_rejected(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        garbage in arb_nonzero_felt(),
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
            .expect("proof generation must succeed");

        // Replace both message_hash and commitment_root with garbage
        pca_proof.message_hash = garbage;
        pca_proof.commitment_root = garbage;

        prop_assert!(
            !verify_pca_proof(&pca_proof),
            "Proof with random garbage bindings must be rejected"
        );
    }
}

// ── Thorough real STARK PCA property tests (100 cases, run with --ignored) ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    #[ignore]
    fn prop_real_stark_pca_valid_proof_accepted_thorough(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        index in 0u64..1000u64,
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let pca_proof = generate_pca_proof(&params, &keypair, &message, index)
            .expect("proof generation must succeed");

        prop_assert!(
            verify_pca_proof(&pca_proof),
            "Valid real STARK PCA proof must be accepted"
        );
    }

    #[test]
    #[ignore]
    fn prop_real_stark_pca_message_tamper_rejected_thorough(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        tampered_message in arb_nonzero_felt(),
    ) {
        prop_assume!(message != tampered_message);

        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
            .expect("proof generation must succeed");

        pca_proof.message_hash = tampered_message;

        prop_assert!(
            !verify_pca_proof(&pca_proof),
            "Proof with tampered message must be rejected"
        );
    }

    #[test]
    #[ignore]
    fn prop_real_stark_pca_root_tamper_rejected_thorough(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        tampered_root in arb_nonzero_felt(),
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
            .expect("proof generation must succeed");

        prop_assume!(pca_proof.commitment_root != tampered_root);

        pca_proof.commitment_root = tampered_root;

        prop_assert!(
            !verify_pca_proof(&pca_proof),
            "Proof with tampered root must be rejected"
        );
    }
}

// ---------------------------------------------------------------------------
// Low-level STARK proof tests (direct wots_prover/wots_verifier)
// ---------------------------------------------------------------------------

// ── Fast STARK property tests (10 cases) ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_real_stark_wots_prove_verify(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let hasher = zk_pqc_hash_layer::traits::PoseidonHash;
        let signature = zk_pqc_signature_layer::WotsPlus::sign(
            &hasher, &params, &keypair, &[message],
        )
        .expect("signing must succeed");

        let proof_options = default_proof_options();

        let result = prove_wots_verification(
            &params,
            &signature.chain_values,
            &message,
            &keypair.public_chains,
            &proof_options,
        )
        .expect("STARK proof generation must succeed");

        prop_assert!(
            verify_stark_proof_real(&result.proof, &result.pub_inputs, &result.proof_options),
            "Real STARK proof must verify for any valid keypair + message"
        );
    }
}

// ── Thorough STARK property tests (100 cases, run with --ignored) ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    #[test]
    #[ignore]
    fn prop_real_stark_wots_prove_verify_thorough(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let hasher = zk_pqc_hash_layer::traits::PoseidonHash;
        let signature = zk_pqc_signature_layer::WotsPlus::sign(
            &hasher, &params, &keypair, &[message],
        )
        .expect("signing must succeed");

        let proof_options = default_proof_options();

        let result = prove_wots_verification(
            &params,
            &signature.chain_values,
            &message,
            &keypair.public_chains,
            &proof_options,
        )
        .expect("STARK proof generation must succeed");

        prop_assert!(
            verify_stark_proof_real(&result.proof, &result.pub_inputs, &result.proof_options),
            "Real STARK proof must verify for any valid keypair + message"
        );
    }
}

// ---------------------------------------------------------------------------
// Feature: zk-pqc-framework, Property 19: Recursive Batch Aggregation Soundness
//
// For any set of N valid individual authorization proofs, the recursive
// aggregator shall produce a single Π_Batch that verifies on-chain. If any
// of the N individual proofs is invalid, the aggregator shall reject the
// batch and identify the invalid proof.
//
// Validates: Requirements 15.1, 15.2, 15.3
// ---------------------------------------------------------------------------

use crate::aggregator::{AggregatorConfig, Lane, ProofDigest, RecursiveAggregator};
use zk_pqc_hash_layer::sponge::PoseidonSponge;

/// Generate an arbitrary ProofDigest with random public_input_hash and index.
fn arb_proof_digest() -> impl Strategy<Value = ProofDigest> {
    (any::<u64>(), 0u64..10_000u64).prop_map(|(hash_seed, index)| ProofDigest {
        public_input_hash: PoseidonSponge::hash(&[FELT::from(hash_seed)]),
        index,
        lane: Lane::PoseidonOnly,
    })
}

/// Generate a vector of N arbitrary ProofDigests (2..=50 for fast tests).
fn arb_proof_digests(min: usize, max: usize) -> impl Strategy<Value = Vec<ProofDigest>> {
    proptest::collection::vec(arb_proof_digest(), min..=max)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 19a: N valid pre-verified proofs aggregate into a Π_Batch that verifies.
    ///
    /// **Validates: Requirements 15.1, 15.2**
    #[test]
    fn prop_recursive_batch_aggregation_valid_batch_verifies(
        digests in arb_proof_digests(1, 50),
    ) {
        let aggregator = RecursiveAggregator::with_defaults();

        // Aggregate pre-verified digests
        let batch = aggregator.aggregate_preverified(digests.clone())
            .expect("Aggregation of valid digests must succeed");

        // Batch size must match input count
        prop_assert_eq!(
            batch.batch_size, digests.len(),
            "Batch size must equal number of input proofs"
        );

        // Batch proof must verify
        prop_assert!(
            aggregator.verify_batch(&batch),
            "Batch proof from valid digests must verify"
        );

        // Commitment-based verification must also pass
        let root = batch.commitment_root;
        prop_assert!(
            aggregator.verify_batch_commitment(&root, &batch),
            "Batch commitment verification must pass for valid batch"
        );
    }

    /// Property 19b: Tampering with one digest in a verified batch causes rejection.
    ///
    /// After aggregation, if we tamper with one proof digest's public_input_hash,
    /// the batch verification must fail (detecting the invalid proof).
    ///
    /// **Validates: Requirements 15.1, 15.3**
    #[test]
    fn prop_recursive_batch_aggregation_tampered_digest_rejected(
        digests in arb_proof_digests(2, 50),
        tamper_index_seed in any::<usize>(),
        tamper_value in any::<u64>(),
    ) {
        let aggregator = RecursiveAggregator::with_defaults();

        // Aggregate valid digests
        let mut batch = aggregator.aggregate_preverified(digests.clone())
            .expect("Aggregation of valid digests must succeed");

        // Pick a random index to tamper with
        let tamper_idx = tamper_index_seed % batch.proof_digests.len();

        // Tamper with the digest's public_input_hash
        let tampered_hash = PoseidonSponge::hash(&[FELT::from(tamper_value), FELT::from(0xDEADu64)]);
        prop_assume!(batch.proof_digests[tamper_idx].public_input_hash != tampered_hash);
        batch.proof_digests[tamper_idx].public_input_hash = tampered_hash;

        // Batch verification must now fail (leaf hash won't match)
        prop_assert!(
            !aggregator.verify_batch(&batch),
            "Batch with tampered digest at index {} must be rejected",
            tamper_idx
        );
    }

    /// Property 19c: Tampering with the commitment root causes rejection.
    ///
    /// If the batch commitment root is altered, verification must fail.
    ///
    /// **Validates: Requirements 15.2**
    #[test]
    fn prop_recursive_batch_aggregation_tampered_root_rejected(
        digests in arb_proof_digests(1, 50),
        fake_root_seed in any::<u64>(),
    ) {
        let aggregator = RecursiveAggregator::with_defaults();

        let mut batch = aggregator.aggregate_preverified(digests)
            .expect("Aggregation must succeed");

        // Tamper with the commitment root
        let fake_root = FELT::from(fake_root_seed);
        prop_assume!(batch.commitment_root != fake_root);
        batch.commitment_root = fake_root;

        // Verification must fail
        prop_assert!(
            !aggregator.verify_batch(&batch),
            "Batch with tampered commitment root must be rejected"
        );
    }

    /// Property 19d: Aggregator rejects empty batches.
    ///
    /// **Validates: Requirements 15.1**
    #[test]
    fn prop_recursive_batch_aggregation_empty_rejected(_dummy in 0u8..1u8) {
        let aggregator = RecursiveAggregator::with_defaults();
        let result = aggregator.aggregate_preverified(vec![]);
        prop_assert!(
            result.is_err(),
            "Empty batch must be rejected"
        );
    }

    /// Property 19e: Aggregator rejects batches exceeding max size and identifies the issue.
    ///
    /// **Validates: Requirements 15.3**
    #[test]
    fn prop_recursive_batch_aggregation_exceeds_max_rejected(
        base_seed in any::<u64>(),
        excess in 1usize..=10usize,
    ) {
        let max_size = 10; // Small max for fast testing
        let config = AggregatorConfig {
            max_batch_size: max_size,
            verify_individual_proofs: false,
        };
        let aggregator = RecursiveAggregator::new(config);

        let digests: Vec<ProofDigest> = (0..(max_size + excess))
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[
                    FELT::from(base_seed),
                    FELT::from(i as u64),
                ]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let result = aggregator.aggregate_preverified(digests);
        prop_assert!(
            result.is_err(),
            "Batch exceeding max_batch_size must be rejected"
        );
        let err = result.unwrap_err();
        prop_assert!(
            err.message.contains("exceeds maximum"),
            "Error message must identify the size violation"
        );
    }
}

// ── Property 19 large batch test (10 cases — expensive Poseidon hashing over 1000+ items) ──

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    /// Property 19f: Large batches (1000+) aggregate and verify correctly.
    ///
    /// The aggregator must support batches of at least 1000 transactions.
    ///
    /// **Validates: Requirements 15.1, 15.2**
    #[test]
    fn prop_recursive_batch_aggregation_large_batch(
        base_seed in any::<u64>(),
        batch_size in 1000usize..=1100usize,
    ) {
        let aggregator = RecursiveAggregator::with_defaults();

        // Generate a large batch of digests deterministically from the seed
        let digests: Vec<ProofDigest> = (0..batch_size)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[
                    FELT::from(base_seed),
                    FELT::from(i as u64),
                ]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let batch = aggregator.aggregate_preverified(digests)
            .expect("Aggregation of 1000+ digests must succeed");

        prop_assert_eq!(batch.batch_size, batch_size);
        prop_assert!(
            aggregator.verify_batch(&batch),
            "Large batch (N={}) must verify",
            batch_size
        );
    }
}

// ---------------------------------------------------------------------------
// Feature: zk-pqc-framework, Property 21: Transaction Lane Classification
//
// For any transaction with a hash flag, the mempool classifier shall route it
// to the correct lane (Poseidon-Only or Hybrid-Hash), and the recursive
// aggregator shall produce separate batch proofs per lane.
//
// Validates: Requirements 18.1, 18.3
// ---------------------------------------------------------------------------

/// Generate an arbitrary Lane value.
fn arb_lane() -> impl Strategy<Value = Lane> {
    prop_oneof![Just(Lane::PoseidonOnly), Just(Lane::HybridHash)]
}

/// Generate an arbitrary ProofDigest with a random lane assignment.
fn arb_proof_digest_with_lane() -> impl Strategy<Value = ProofDigest> {
    (any::<u64>(), 0u64..10_000u64, arb_lane()).prop_map(|(hash_seed, index, lane)| ProofDigest {
        public_input_hash: PoseidonSponge::hash(&[FELT::from(hash_seed)]),
        index,
        lane,
    })
}

/// Generate a vector of N arbitrary ProofDigests with random lane assignments.
fn arb_lane_digests(min: usize, max: usize) -> impl Strategy<Value = Vec<ProofDigest>> {
    proptest::collection::vec(arb_proof_digest_with_lane(), min..=max)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 21a: Random transactions with hash flags are correctly routed
    /// to their respective lanes, and each lane's batch proof contains only
    /// digests from that lane.
    ///
    /// **Validates: Requirements 18.1, 18.3**
    #[test]
    fn prop_lane_classification_correct_routing(
        digests in arb_lane_digests(2, 50),
    ) {
        let aggregator = RecursiveAggregator::with_defaults();

        let result = aggregator.aggregate_preverified_by_lane(digests.clone())
            .expect("Lane aggregation must succeed");

        // Each lane's batch must contain only digests from that lane
        for (&lane, batch) in &result {
            for digest in &batch.proof_digests {
                prop_assert_eq!(
                    digest.lane, lane,
                    "Digest with lane {:?} found in batch for lane {:?}",
                    digest.lane, lane
                );
            }
        }
    }

    /// Property 21b: Each lane's batch proof verifies independently.
    ///
    /// **Validates: Requirements 18.1, 18.3**
    #[test]
    fn prop_lane_classification_independent_verification(
        digests in arb_lane_digests(2, 50),
    ) {
        let aggregator = RecursiveAggregator::with_defaults();

        let result = aggregator.aggregate_preverified_by_lane(digests)
            .expect("Lane aggregation must succeed");

        // Each lane's batch proof must verify independently
        for (&lane, batch) in &result {
            prop_assert!(
                aggregator.verify_batch(batch),
                "Batch proof for lane {:?} must verify independently",
                lane
            );
        }
    }

    /// Property 21c: Lane batch sizes sum to total input size.
    ///
    /// **Validates: Requirements 18.1, 18.3**
    #[test]
    fn prop_lane_classification_sizes_sum_to_total(
        digests in arb_lane_digests(2, 50),
    ) {
        let total = digests.len();
        let aggregator = RecursiveAggregator::with_defaults();

        let result = aggregator.aggregate_preverified_by_lane(digests)
            .expect("Lane aggregation must succeed");

        let sum: usize = result.values().map(|b| b.batch_size).sum();
        prop_assert_eq!(
            sum, total,
            "Sum of lane batch sizes ({}) must equal total input size ({})",
            sum, total
        );
    }

    /// Property 21d: Changing one lane's digests does not affect the other
    /// lane's commitment root.
    ///
    /// We construct two sets of digests that share the same PoseidonOnly
    /// digests but differ in their HybridHash digests. The PoseidonOnly
    /// commitment root must be identical in both aggregations.
    ///
    /// **Validates: Requirements 18.1, 18.3**
    #[test]
    fn prop_lane_classification_cross_lane_independence(
        poseidon_count in 2usize..=10usize,
        hybrid_seed_a in any::<u64>(),
        hybrid_seed_b in any::<u64>(),
        hybrid_count in 2usize..=10usize,
        base_seed in any::<u64>(),
    ) {
        prop_assume!(hybrid_seed_a != hybrid_seed_b);

        let aggregator = RecursiveAggregator::with_defaults();

        // Shared PoseidonOnly digests
        let poseidon_digests: Vec<ProofDigest> = (0..poseidon_count)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[
                    FELT::from(base_seed),
                    FELT::from(i as u64),
                ]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        // Set A: HybridHash digests derived from hybrid_seed_a
        let hybrid_a: Vec<ProofDigest> = (0..hybrid_count)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[
                    FELT::from(hybrid_seed_a),
                    FELT::from(i as u64),
                ]),
                index: (poseidon_count + i) as u64,
                lane: Lane::HybridHash,
            })
            .collect();

        // Set B: HybridHash digests derived from hybrid_seed_b
        let hybrid_b: Vec<ProofDigest> = (0..hybrid_count)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[
                    FELT::from(hybrid_seed_b),
                    FELT::from(i as u64),
                ]),
                index: (poseidon_count + i) as u64,
                lane: Lane::HybridHash,
            })
            .collect();

        let mut digests_a = poseidon_digests.clone();
        digests_a.extend(hybrid_a);

        let mut digests_b = poseidon_digests;
        digests_b.extend(hybrid_b);

        let result_a = aggregator.aggregate_preverified_by_lane(digests_a)
            .expect("Lane aggregation A must succeed");
        let result_b = aggregator.aggregate_preverified_by_lane(digests_b)
            .expect("Lane aggregation B must succeed");

        // PoseidonOnly commitment roots must be identical
        prop_assert_eq!(
            result_a[&Lane::PoseidonOnly].commitment_root,
            result_b[&Lane::PoseidonOnly].commitment_root,
            "PoseidonOnly commitment root must not change when HybridHash digests differ"
        );

        // HybridHash commitment roots must differ (different inputs)
        prop_assert_ne!(
            result_a[&Lane::HybridHash].commitment_root,
            result_b[&Lane::HybridHash].commitment_root,
            "HybridHash commitment roots should differ when inputs differ"
        );
    }
}

// ---------------------------------------------------------------------------
// Feature: zk-pqc-framework, Property 22: ZK-Fraud Proof Acceptance and Slashing
//
// For any valid Accountability Trace proving a sequencer violation (equivocation,
// replay, index reuse), the contract shall accept the proof from any submitter
// and apply 100% slashing on the violating sequencer's stake.
//
// The Rust-side property test validates the accountability trace generation and
// Poseidon commitment scheme that the Cairo contract uses for fraud proof
// verification. The trace format is:
//   [violation_type, violator_felt, evidence_data..., tag]
// where tag = PoseidonSponge::hash(violation_type || violator_felt || evidence_data)
//
// Validates: Requirements 19.1, 19.2
// ---------------------------------------------------------------------------

/// Accountability Trace — Rust-side representation matching the Cairo contract.
///
/// The trace encodes a sequencer violation proof:
///   trace[0]       = violation_type (equivocation=1, replay=2, index_reuse=3, ...)
///   trace[1]       = violator address (as FELT)
///   trace[2..n-1]  = evidence data (variable length)
///   trace[n-1]     = tag = PoseidonSponge::hash(violation_type || violator || evidence)
#[derive(Debug, Clone)]
struct AccountabilityTrace {
    violation_type: FELT,
    violator: FELT,
    evidence: Vec<FELT>,
    tag: FELT,
}

impl AccountabilityTrace {
    /// Build a valid accountability trace with a correct Poseidon commitment tag.
    fn new(violation_type: FELT, violator: FELT, evidence: Vec<FELT>) -> Self {
        let tag = Self::compute_tag(&violation_type, &violator, &evidence);
        Self {
            violation_type,
            violator,
            evidence,
            tag,
        }
    }

    /// Compute the Poseidon commitment tag over all trace fields (excluding the tag itself).
    /// Matches Cairo: tag = PoseidonSponge::hash(violation_type || violator || evidence)
    fn compute_tag(violation_type: &FELT, violator: &FELT, evidence: &[FELT]) -> FELT {
        let mut input = Vec::with_capacity(2 + evidence.len());
        input.push(*violation_type);
        input.push(*violator);
        input.extend_from_slice(evidence);
        PoseidonSponge::hash(&input)
    }

    /// Serialize the trace to a flat FELT array matching the Cairo layout.
    fn to_felts(&self) -> Vec<FELT> {
        let mut out = Vec::with_capacity(3 + self.evidence.len());
        out.push(self.violation_type);
        out.push(self.violator);
        out.extend_from_slice(&self.evidence);
        out.push(self.tag);
        out
    }

    /// Verify the trace's tag is valid by recomputing from the fields.
    fn verify(&self) -> bool {
        let expected = Self::compute_tag(&self.violation_type, &self.violator, &self.evidence);
        expected == self.tag
    }

    /// Verify a raw FELT array as an accountability trace against a given violator.
    /// Matches the Cairo `verify_accountability_trace` function exactly.
    fn verify_raw(trace: &[FELT], violator: &FELT) -> bool {
        if trace.len() < 3 {
            return false;
        }

        // The violator field in the trace must match the provided violator
        if trace[1] != *violator {
            return false;
        }

        // Recompute the tag from all fields except the last
        let hash_input = &trace[..trace.len() - 1];
        let computed_tag = PoseidonSponge::hash(hash_input);
        let provided_tag = trace[trace.len() - 1];
        computed_tag == provided_tag
    }
}

/// Generate an arbitrary violation type (1=equivocation, 2=replay, 3=index_reuse).
fn arb_violation_type() -> impl Strategy<Value = FELT> {
    (1u64..=3u64).prop_map(FELT::from)
}

/// Generate an arbitrary violator address as a non-zero FELT.
fn arb_violator() -> impl Strategy<Value = FELT> {
    (1u64..u64::MAX).prop_map(FELT::from)
}

/// Generate arbitrary evidence data (1..=10 FELTs).
fn arb_evidence() -> impl Strategy<Value = Vec<FELT>> {
    proptest::collection::vec(arb_felt(), 1..=10)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 22a: A valid accountability trace with correct Poseidon commitment
    /// tag verifies successfully. Any submitter can verify the trace.
    ///
    /// **Validates: Requirements 19.1, 19.2**
    #[test]
    fn prop_fraud_proof_valid_trace_accepted(
        violation_type in arb_violation_type(),
        violator in arb_violator(),
        evidence in arb_evidence(),
    ) {
        let trace = AccountabilityTrace::new(violation_type, violator, evidence);

        // The trace must verify via the structured API
        prop_assert!(
            trace.verify(),
            "Valid accountability trace must verify"
        );

        // The trace must also verify via the raw FELT array API (matching Cairo)
        let raw = trace.to_felts();
        prop_assert!(
            AccountabilityTrace::verify_raw(&raw, &violator),
            "Valid accountability trace must verify via raw FELT array"
        );

        // Minimum trace length: violation_type + violator + at least 1 evidence + tag = 4
        prop_assert!(
            raw.len() >= 4,
            "Trace must have at least 4 elements (type + violator + evidence + tag)"
        );
    }

    /// Property 22b: The Poseidon commitment tag is deterministic — same inputs
    /// always produce the same tag.
    ///
    /// **Validates: Requirements 19.1**
    #[test]
    fn prop_fraud_proof_tag_deterministic(
        violation_type in arb_violation_type(),
        violator in arb_violator(),
        evidence in arb_evidence(),
    ) {
        let tag1 = AccountabilityTrace::compute_tag(&violation_type, &violator, &evidence);
        let tag2 = AccountabilityTrace::compute_tag(&violation_type, &violator, &evidence);

        prop_assert_eq!(
            tag1, tag2,
            "Same inputs must produce the same Poseidon commitment tag"
        );
    }

    /// Property 22c: Tampering with the violation_type invalidates the tag.
    ///
    /// **Validates: Requirements 19.1**
    #[test]
    fn prop_fraud_proof_tampered_violation_type_rejected(
        violation_type in arb_violation_type(),
        violator in arb_violator(),
        evidence in arb_evidence(),
        tampered_type in arb_violation_type(),
    ) {
        prop_assume!(violation_type != tampered_type);

        let mut trace = AccountabilityTrace::new(violation_type, violator, evidence);
        trace.violation_type = tampered_type;

        prop_assert!(
            !trace.verify(),
            "Trace with tampered violation_type must be rejected"
        );
    }

    /// Property 22d: Tampering with the violator address invalidates the tag.
    ///
    /// **Validates: Requirements 19.1, 19.2**
    #[test]
    fn prop_fraud_proof_tampered_violator_rejected(
        violation_type in arb_violation_type(),
        violator in arb_violator(),
        evidence in arb_evidence(),
        tampered_violator in arb_violator(),
    ) {
        prop_assume!(violator != tampered_violator);

        let mut trace = AccountabilityTrace::new(violation_type, violator, evidence);
        trace.violator = tampered_violator;

        prop_assert!(
            !trace.verify(),
            "Trace with tampered violator must be rejected"
        );
    }

    /// Property 22e: Tampering with any evidence element invalidates the tag.
    ///
    /// **Validates: Requirements 19.1**
    #[test]
    fn prop_fraud_proof_tampered_evidence_rejected(
        violation_type in arb_violation_type(),
        violator in arb_violator(),
        evidence in arb_evidence(),
        tamper_value in any::<u64>(),
    ) {
        let mut trace = AccountabilityTrace::new(violation_type, violator, evidence);

        // Tamper with a random evidence element
        let tamper_idx = tamper_value as usize % trace.evidence.len();
        let tampered_felt = FELT::from(tamper_value.wrapping_add(0xDEAD));
        prop_assume!(trace.evidence[tamper_idx] != tampered_felt);
        trace.evidence[tamper_idx] = tampered_felt;

        prop_assert!(
            !trace.verify(),
            "Trace with tampered evidence at index {} must be rejected",
            tamper_idx
        );
    }

    /// Property 22f: Verifying a trace against a different violator address
    /// than the one embedded in the trace is rejected (matching Cairo's
    /// violator address check in verify_accountability_trace).
    ///
    /// **Validates: Requirements 19.1, 19.2**
    #[test]
    fn prop_fraud_proof_wrong_violator_address_rejected(
        violation_type in arb_violation_type(),
        violator in arb_violator(),
        evidence in arb_evidence(),
        wrong_violator in arb_violator(),
    ) {
        prop_assume!(violator != wrong_violator);

        let trace = AccountabilityTrace::new(violation_type, violator, evidence);
        let raw = trace.to_felts();

        // Verify against the wrong violator address — must be rejected
        prop_assert!(
            !AccountabilityTrace::verify_raw(&raw, &wrong_violator),
            "Trace verified against wrong violator address must be rejected"
        );

        // But verify against the correct violator — must pass
        prop_assert!(
            AccountabilityTrace::verify_raw(&raw, &violator),
            "Trace verified against correct violator address must pass"
        );
    }

    /// Property 22g: The serialized trace format matches the expected layout:
    /// [violation_type, violator, evidence..., tag] with correct length.
    ///
    /// **Validates: Requirements 19.1**
    #[test]
    fn prop_fraud_proof_trace_format_correct(
        violation_type in arb_violation_type(),
        violator in arb_violator(),
        evidence in arb_evidence(),
    ) {
        let trace = AccountabilityTrace::new(violation_type, violator, evidence.clone());
        let raw = trace.to_felts();

        // Length = 2 (type + violator) + evidence.len() + 1 (tag)
        let expected_len = 2 + evidence.len() + 1;
        prop_assert_eq!(
            raw.len(), expected_len,
            "Trace length must be 2 + evidence_len + 1"
        );

        // First element is violation_type
        prop_assert_eq!(raw[0], violation_type, "raw[0] must be violation_type");

        // Second element is violator
        prop_assert_eq!(raw[1], violator, "raw[1] must be violator");

        // Middle elements are evidence
        for (i, ev) in evidence.iter().enumerate() {
            prop_assert_eq!(raw[2 + i], *ev, "raw[{}] must be evidence[{}]", 2 + i, i);
        }

        // Last element is the tag
        prop_assert_eq!(raw[raw.len() - 1], trace.tag, "Last element must be the tag");
    }
}

// ---------------------------------------------------------------------------
// Feature: zk-pqc-framework, Property 23: Index Window Concurrency
//
// For any account with index window [base, base + k], submitting multiple
// transactions with distinct indices within the window shall all be accepted.
// When all k indices are consumed, the window base shall advance to base + k.
// Submitting two transactions with the same index within the window shall
// cause the second to be rejected.
//
// This Rust-side property test validates the index window model that the Cairo
// contract implements. The model mirrors the Cairo storage layout:
//   - window_base: u64
//   - window_size: u64 (k)
//   - consumed: HashSet<u64> (indices consumed in current window)
//
// Validates: Requirements 20.1, 20.2, 20.3, 20.4
// ---------------------------------------------------------------------------

use std::collections::HashSet;

/// Rust-side model of the Cairo account index window.
///
/// Mirrors the Cairo contract's per-account state:
///   account_window_base, account_window_size, account_window_consumed,
///   account_window_consumed_count
#[derive(Debug, Clone)]
struct IndexWindow {
    /// Current window start (inclusive).
    base: u64,
    /// Window size k — the number of indices available per window.
    size: u64,
    /// Set of consumed indices within the current window.
    consumed: HashSet<u64>,
}

/// Result of attempting to consume an index.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConsumeResult {
    /// Index accepted and consumed.
    Accepted,
    /// Index rejected — already consumed (duplicate).
    DuplicateRejected,
    /// Index rejected — outside the active window range.
    OutOfRange,
    /// Index accepted and window advanced (all k indices now consumed).
    AcceptedAndAdvanced { new_base: u64 },
}

impl IndexWindow {
    /// Create a new index window for an account.
    /// Matches Cairo: `register_account(account, window_size)` → base=0, consumed=∅.
    fn new(window_size: u64) -> Self {
        assert!(window_size > 0, "window size must be > 0");
        Self {
            base: 0,
            size: window_size,
            consumed: HashSet::new(),
        }
    }

    /// Attempt to consume an index within the active window.
    ///
    /// Matches Cairo `consume_index(account, index)`:
    /// 1. Reject if index < base (below window)
    /// 2. Reject if index >= base + size (above window)
    /// 3. Reject if index already consumed (duplicate)
    /// 4. Accept and mark consumed
    /// 5. If all k indices consumed, advance window base to base + k
    fn consume(&mut self, index: u64) -> ConsumeResult {
        // Range check: index must be in [base, base + size)
        if index < self.base || index >= self.base + self.size {
            return ConsumeResult::OutOfRange;
        }

        // Duplicate check
        if self.consumed.contains(&index) {
            return ConsumeResult::DuplicateRejected;
        }

        // Accept the index
        self.consumed.insert(index);

        // Check if window is fully consumed → auto-advance
        if self.consumed.len() as u64 == self.size {
            let new_base = self.base + self.size;
            // Clear consumed set and advance (mirrors Cairo's loop clearing consumed flags)
            self.consumed.clear();
            self.base = new_base;
            ConsumeResult::AcceptedAndAdvanced { new_base }
        } else {
            ConsumeResult::Accepted
        }
    }

    /// Check whether an index is within the active window range.
    fn in_range(&self, index: u64) -> bool {
        index >= self.base && index < self.base + self.size
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Property 23a: All distinct indices within [base, base + k) are accepted.
    ///
    /// For a random window size k, consuming each index in [0, k) exactly once
    /// must succeed (no rejections).
    ///
    /// **Validates: Requirements 20.1, 20.2**
    #[test]
    fn prop_index_window_distinct_indices_accepted(
        window_size in 1u64..=16u64,
    ) {
        let mut window = IndexWindow::new(window_size);

        // Consume all indices except the last (to avoid triggering advance)
        for idx in 0..window_size.saturating_sub(1) {
            let result = window.consume(idx);
            prop_assert!(
                result == ConsumeResult::Accepted,
                "Distinct index {} within window [0, {}) must be accepted, got {:?}",
                idx, window_size, result
            );
        }

        // The last index triggers advance (if window_size > 0)
        if window_size > 0 {
            let last_idx = window_size - 1;
            let result = window.consume(last_idx);
            match result {
                ConsumeResult::AcceptedAndAdvanced { new_base } => {
                    prop_assert_eq!(
                        new_base, window_size,
                        "Window must advance to base=k after all k indices consumed"
                    );
                }
                ConsumeResult::Accepted => {
                    // window_size == 1 case: single index accepted and advanced
                    // (this branch shouldn't happen since size=1 always advances)
                    prop_assert!(false, "Last index should trigger advance");
                }
                other => {
                    prop_assert!(false, "Last index must be accepted, got {:?}", other);
                }
            }
        }
    }

    /// Property 23b: Duplicate index within window is rejected.
    ///
    /// For a random window size k and a random index within [0, k), consuming
    /// the index twice must succeed the first time and be rejected the second.
    ///
    /// **Validates: Requirements 20.4**
    #[test]
    fn prop_index_window_duplicate_rejected(
        window_size in 2u64..=16u64,
        dup_index_offset in 0u64..15u64,
    ) {
        // Use window_size >= 2 so we can consume a duplicate without triggering advance
        let dup_index = dup_index_offset % window_size;
        let mut window = IndexWindow::new(window_size);

        // First consume: must succeed
        let first = window.consume(dup_index);
        prop_assert!(
            first == ConsumeResult::Accepted,
            "First consume of index {} must be accepted, got {:?}",
            dup_index, first
        );

        // Second consume of same index: must be rejected as duplicate
        let second = window.consume(dup_index);
        prop_assert_eq!(
            second,
            ConsumeResult::DuplicateRejected,
            "Second consume of index {} must be rejected as duplicate",
            dup_index
        );
    }

    /// Property 23c: Window advances when all k indices are consumed.
    ///
    /// After consuming all k indices in [base, base + k), the window base
    /// advances to base + k, and the new window [base+k, base+2k) becomes active.
    ///
    /// **Validates: Requirements 20.3**
    #[test]
    fn prop_index_window_advances_on_exhaustion(
        window_size in 1u64..=16u64,
    ) {
        let mut window = IndexWindow::new(window_size);

        // Consume all k indices in order
        for idx in 0..window_size {
            window.consume(idx);
        }

        // After exhaustion, base must have advanced to window_size
        prop_assert_eq!(
            window.base, window_size,
            "After consuming all {} indices, base must advance to {}",
            window_size, window_size
        );

        // The new window [k, 2k) must accept its indices
        for idx in window_size..(2 * window_size) {
            prop_assert!(
                window.in_range(idx),
                "Index {} must be in new window [{}, {})",
                idx, window_size, 2 * window_size
            );
        }

        // Old window indices [0, k) must now be out of range
        for idx in 0..window_size {
            prop_assert!(
                !window.in_range(idx),
                "Old index {} must be out of range after window advance",
                idx
            );
        }
    }

    /// Property 23d: Indices outside [base, base + k) are rejected.
    ///
    /// For a random window, indices below base and at or above base + k
    /// must be rejected as out-of-range.
    ///
    /// **Validates: Requirements 20.1**
    #[test]
    fn prop_index_window_out_of_range_rejected(
        window_size in 1u64..=16u64,
        advance_count in 0u64..=3u64,
    ) {
        let mut window = IndexWindow::new(window_size);

        // Optionally advance the window a few times to test non-zero base
        for round in 0..advance_count {
            let round_base = round * window_size;
            for idx in round_base..(round_base + window_size) {
                window.consume(idx);
            }
        }

        let current_base = window.base;
        let current_end = current_base + window_size;

        // Index below base must be rejected
        if current_base > 0 {
            let below = current_base - 1;
            let result = window.consume(below);
            prop_assert_eq!(
                result,
                ConsumeResult::OutOfRange,
                "Index {} below base {} must be out-of-range",
                below, current_base
            );
        }

        // Index at or above base + k must be rejected
        let above = current_end;
        let result = window.consume(above);
        prop_assert_eq!(
            result,
            ConsumeResult::OutOfRange,
            "Index {} at/above end {} must be out-of-range",
            above, current_end
        );
    }

    /// Property 23e: Random consumption order within window all succeeds.
    ///
    /// For a random permutation of indices [base, base + k), consuming them
    /// in any order must all succeed (the last one triggers advance).
    ///
    /// **Validates: Requirements 20.1, 20.2**
    #[test]
    fn prop_index_window_random_order_accepted(
        window_size in 1u64..=16u64,
        shuffle_seed in any::<u64>(),
    ) {
        let mut window = IndexWindow::new(window_size);

        // Create a permutation of [0, k) using a simple Fisher-Yates with the seed
        let mut indices: Vec<u64> = (0..window_size).collect();
        let mut rng_state = shuffle_seed;
        for i in (1..indices.len()).rev() {
            // Simple LCG-based shuffle
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (rng_state >> 33) as usize % (i + 1);
            indices.swap(i, j);
        }

        // Consume all indices in shuffled order
        let mut accepted_count = 0u64;
        for &idx in &indices {
            let result = window.consume(idx);
            match result {
                ConsumeResult::Accepted | ConsumeResult::AcceptedAndAdvanced { .. } => {
                    accepted_count += 1;
                }
                other => {
                    prop_assert!(
                        false,
                        "Index {} in shuffled order must be accepted, got {:?}",
                        idx, other
                    );
                }
            }
        }

        prop_assert_eq!(
            accepted_count, window_size,
            "All {} indices must be accepted regardless of consumption order",
            window_size
        );

        // Window must have advanced
        prop_assert_eq!(
            window.base, window_size,
            "Window must advance after all indices consumed in random order"
        );
    }

    /// Property 23f: Multiple window advances work correctly.
    ///
    /// Consuming indices across multiple window generations (advancing 2+ times)
    /// must work correctly — each generation's indices are independent.
    ///
    /// **Validates: Requirements 20.1, 20.2, 20.3**
    #[test]
    fn prop_index_window_multiple_advances(
        window_size in 1u64..=8u64,
        num_generations in 2u64..=5u64,
    ) {
        let mut window = IndexWindow::new(window_size);

        for gen in 0..num_generations {
            let gen_base = gen * window_size;

            // All indices in this generation must be in range
            for idx in gen_base..(gen_base + window_size) {
                prop_assert!(
                    window.in_range(idx),
                    "Index {} must be in range for generation {} (base={})",
                    idx, gen, window.base
                );
            }

            // Consume all indices in this generation
            for idx in gen_base..(gen_base + window_size) {
                let result = window.consume(idx);
                match result {
                    ConsumeResult::Accepted | ConsumeResult::AcceptedAndAdvanced { .. } => {}
                    other => {
                        prop_assert!(
                            false,
                            "Index {} in generation {} must be accepted, got {:?}",
                            idx, gen, other
                        );
                    }
                }
            }

            // After consuming all indices, base must advance
            let expected_base = (gen + 1) * window_size;
            prop_assert_eq!(
                window.base, expected_base,
                "After generation {}, base must be {}",
                gen, expected_base
            );
        }
    }
}
