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
