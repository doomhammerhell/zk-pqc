//! End-to-end PCA Transaction integration tests with real STARK proofs.
//!
//! Exercises the complete PCA flow:
//! 1. Generate a WOTS+ key pair
//! 2. Sign a message
//! 3. Generate a real STARK proof off-chain (lambdaworks)
//! 4. Verify the STARK proof off-chain (mirrors on-chain verification)
//!
//! Documents proof size and generation time as required by Requirement 12.2.
//!
//! Requirements: 10.2, 10.3, 10.4, 12.1, 12.2, 12.3

use std::time::Instant;

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::sponge::PoseidonSponge;
use zk_pqc_proof_layer::pca::{
    commitment_root, generate_keypair, generate_pca_proof, verify_pca_proof, verify_pca_proof_bound,
};
use zk_pqc_signature_layer::{HashMode, WotsParams};

/// test_real_stark_pca_transaction: keygen → sign → prove (real) → verify → true
#[test]
fn test_real_stark_pca_transaction() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };

    // Step 1: Generate WOTS+ key pair
    let seed = [FELT::from(42u64), FELT::from(137u64)];
    let t0 = Instant::now();
    let keypair = generate_keypair(&seed, &params);
    let keygen_time = t0.elapsed();

    assert!(
        !keypair.public_chains.is_empty(),
        "keygen must produce public chains"
    );
    let root = commitment_root(&keypair.public_chains);
    assert_ne!(root, FELT::zero(), "commitment root must be non-zero");

    // Step 2 + 3: Sign message and generate real STARK PCA proof
    let message = FELT::from(0x48454C4C4Fu64); // "HELLO" in hex
    let message_hash = PoseidonSponge::hash(&[message]);
    let index = 0u64;

    let t1 = Instant::now();
    let pca_proof = generate_pca_proof(&params, &keypair, &message, index)
        .expect("PCA proof generation should succeed");
    let proof_gen_time = t1.elapsed();

    // Verify proof structure
    assert_eq!(pca_proof.message_hash, message_hash);
    assert_eq!(pca_proof.commitment_root, root);
    assert_eq!(pca_proof.index, index);

    // Step 4: Verify the real STARK proof
    let t2 = Instant::now();
    let valid = verify_pca_proof(&pca_proof);
    let verify_time = t2.elapsed();

    assert!(valid, "Real STARK PCA proof must verify successfully");

    // Also verify with explicit binding check
    assert!(
        verify_pca_proof_bound(&pca_proof, &message_hash, &root),
        "Bound verification must pass with correct message and root"
    );

    // Document timings and proof size (Requirement 12.2)
    println!("=== Real STARK PCA Transaction ===");
    println!("  Key generation:      {:?}", keygen_time);
    println!(
        "  Proof generation:    {:?} ({}ms)",
        proof_gen_time, pca_proof.generation_time_ms
    );
    println!("  Proof verification:  {:?}", verify_time);
    println!(
        "  Total:               {:?}",
        keygen_time + proof_gen_time + verify_time
    );
    println!(
        "  STARK trace length:  {}",
        pca_proof.stark_proof.trace_length
    );
    println!(
        "  Boundary constraints: {}",
        pca_proof.pub_inputs.boundary_values.len()
    );
}

/// test_real_stark_tampered_proof_rejected: flip boundary value → verify → false
#[test]
fn test_real_stark_tampered_proof_rejected() {
    let params = WotsParams::default();
    let seed = [FELT::from(99u64)];
    let keypair = generate_keypair(&seed, &params);
    let message = FELT::from(0x1234u64);

    let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
        .expect("proof generation should succeed");

    // Tamper: alter a boundary constraint value in the public inputs.
    // This changes what the STARK verifier expects at the trace boundary,
    // causing verification to fail.
    if !pca_proof.pub_inputs.boundary_values.is_empty() {
        pca_proof.pub_inputs.boundary_values[0].2 =
            zk_pqc_proof_layer::wots_air::local_felt_to_stark(&FELT::from(0xDEADu64));
    }

    assert!(
        !verify_pca_proof(&pca_proof),
        "Tampered STARK proof must be rejected"
    );
}

/// test_real_stark_wrong_message_rejected: prove msg A → verify msg B → false
#[test]
fn test_real_stark_wrong_message_rejected() {
    let params = WotsParams::default();
    let seed = [FELT::from(77u64)];
    let keypair = generate_keypair(&seed, &params);

    let message_a = FELT::from(0xAAAAu64);
    let message_b = FELT::from(0xBBBBu64);

    let pca_proof = generate_pca_proof(&params, &keypair, &message_a, 0)
        .expect("proof generation should succeed");

    // The proof was generated for message A. Verifying with message B's hash must fail.
    let message_b_hash = PoseidonSponge::hash(&[message_b]);
    let root = commitment_root(&keypair.public_chains);

    assert!(
        !verify_pca_proof_bound(&pca_proof, &message_b_hash, &root),
        "Proof for message A must be rejected when verified against message B"
    );
}

/// Verify that proofs for different messages are distinct.
#[test]
fn test_pca_different_messages_produce_different_proofs() {
    let params = WotsParams::default();
    let seed = [FELT::from(42u64)];
    let keypair = generate_keypair(&seed, &params);

    let proof_a = generate_pca_proof(&params, &keypair, &FELT::from(1u64), 0).expect("proof A");
    let proof_b = generate_pca_proof(&params, &keypair, &FELT::from(2u64), 1).expect("proof B");

    assert!(verify_pca_proof(&proof_a));
    assert!(verify_pca_proof(&proof_b));

    // Different messages must produce different message hashes
    assert_ne!(proof_a.message_hash, proof_b.message_hash);
}

/// Verify that a proof generated with one keypair cannot be verified
/// against a different keypair's commitment root.
#[test]
fn test_pca_wrong_root_rejected() {
    let params = WotsParams::default();

    let keypair_a = generate_keypair(&[FELT::from(10u64)], &params);
    let keypair_b = generate_keypair(&[FELT::from(20u64)], &params);

    let message = FELT::from(0xCAFEu64);
    let pca_proof = generate_pca_proof(&params, &keypair_a, &message, 0)
        .expect("proof generation should succeed");

    let root_b = commitment_root(&keypair_b.public_chains);
    let message_hash = PoseidonSponge::hash(&[message]);

    assert!(
        !verify_pca_proof_bound(&pca_proof, &message_hash, &root_b),
        "Proof for keypair A must be rejected when verified against keypair B's root"
    );
}
