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

use crate::pca::{generate_keypair, generate_pca_proof, verify_pca_proof_offchain};
use zk_pqc_signature_layer::{HashMode, WotsParams};

/// Generate an arbitrary non-zero FELT for messages.
fn arb_nonzero_felt() -> impl Strategy<Value = FELT> {
    (1u64..u64::MAX).prop_map(FELT::from)
}

/// Generate arbitrary WOTS+ seed (1–4 FELTs).
fn arb_seed() -> impl Strategy<Value = Vec<FELT>> {
    proptest::collection::vec(arb_felt(), 1..=4)
}

// Feature: zk-pqc-framework, Property 17: PCA Proof Binding and Verification
//
// For any valid STARK authorization proof π_auth generated for message M and
// commitment root R, on-chain verification shall accept it. For any proof
// generated for (M, R), verifying with a different message M' ≠ M or a
// different root R' ≠ R shall be rejected. For any invalid proof,
// verification shall be rejected.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_pca_valid_proof_accepted(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        index in 0u64..1000u64,
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let pca_proof = generate_pca_proof(&params, &keypair, &message, index)
            .expect("proof generation must succeed");

        prop_assert!(
            verify_pca_proof_offchain(&pca_proof),
            "Valid PCA proof must be accepted"
        );
    }

    #[test]
    fn prop_pca_message_tamper_rejected(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        tampered_message in arb_nonzero_felt(),
    ) {
        // Only test when messages differ
        prop_assume!(message != tampered_message);

        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
            .expect("proof generation must succeed");

        // Tamper: change the message_hash binding
        pca_proof.message_hash = tampered_message;

        prop_assert!(
            !verify_pca_proof_offchain(&pca_proof),
            "Proof with tampered message must be rejected"
        );
    }

    #[test]
    fn prop_pca_root_tamper_rejected(
        seed in arb_seed(),
        message in arb_nonzero_felt(),
        tampered_root in arb_nonzero_felt(),
    ) {
        let params = WotsParams { w: 16, hash_mode: HashMode::Poseidon };
        let keypair = generate_keypair(&seed, &params);

        let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
            .expect("proof generation must succeed");

        // Only test when roots differ
        prop_assume!(pca_proof.commitment_root != tampered_root);

        // Tamper: change the commitment_root binding
        pca_proof.commitment_root = tampered_root;

        prop_assert!(
            !verify_pca_proof_offchain(&pca_proof),
            "Proof with tampered root must be rejected"
        );
    }
}
