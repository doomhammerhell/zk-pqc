//! End-to-end "Hello World" PCA Transaction integration test.
//!
//! Exercises the complete PCA flow:
//! 1. Generate a WOTS+ key pair
//! 2. Sign a message
//! 3. Generate a STARK proof off-chain
//! 4. Verify the proof off-chain (mirrors Cairo contract logic)
//!
//! Documents proof generation time as required by Requirement 12.2.
//!
//! Requirements: 12.1, 12.2, 12.3

use std::time::Instant;

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_proof_layer::pca::{
    commitment_root, generate_keypair, generate_pca_proof, verify_pca_proof_offchain,
};
use zk_pqc_signature_layer::{HashMode, WotsParams};

#[test]
fn test_hello_world_pca_transaction() {
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

    // Step 2 + 3: Sign message and generate PCA proof
    let message = FELT::from(0x48454C4C4Fu64); // "HELLO" in hex
    let index = 0u64;

    let t1 = Instant::now();
    let pca_proof = generate_pca_proof(&params, &keypair, &message, index)
        .expect("PCA proof generation should succeed");
    let proof_gen_time = t1.elapsed();

    // Verify proof structure
    assert!(
        pca_proof.proof.len() >= 3,
        "proof must have at least 3 elements"
    );
    assert_eq!(
        pca_proof.proof[0], pca_proof.message_hash,
        "proof[0] must be message_hash"
    );
    assert_eq!(
        pca_proof.proof[1], pca_proof.commitment_root,
        "proof[1] must be commitment_root"
    );
    assert_eq!(pca_proof.index, index);

    // Step 4: Verify off-chain (mirrors Cairo contract verification)
    let t2 = Instant::now();
    let valid = verify_pca_proof_offchain(&pca_proof);
    let verify_time = t2.elapsed();

    assert!(valid, "PCA proof must verify successfully");

    // Document timings (Requirement 12.2)
    println!("=== PCA Transaction Timing ===");
    println!("  Key generation:    {:?}", keygen_time);
    println!("  Proof generation:  {:?}", proof_gen_time);
    println!("  Proof verification: {:?}", verify_time);
    println!(
        "  Total:             {:?}",
        keygen_time + proof_gen_time + verify_time
    );
    println!(
        "  Proof size:        {} field elements",
        pca_proof.proof.len()
    );
}

#[test]
fn test_pca_invalid_proof_rejected_message_mismatch() {
    let params = WotsParams::default();
    let seed = [FELT::from(99u64)];
    let keypair = generate_keypair(&seed, &params);
    let message = FELT::from(0x1234u64);

    let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
        .expect("proof generation should succeed");

    // Tamper: change the message_hash binding
    pca_proof.message_hash = FELT::from(0xDEADu64);
    assert!(
        !verify_pca_proof_offchain(&pca_proof),
        "tampered message must be rejected"
    );
}

#[test]
fn test_pca_invalid_proof_rejected_root_mismatch() {
    let params = WotsParams::default();
    let seed = [FELT::from(77u64)];
    let keypair = generate_keypair(&seed, &params);
    let message = FELT::from(0xABCDu64);

    let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
        .expect("proof generation should succeed");

    // Tamper: change the commitment_root binding
    pca_proof.commitment_root = FELT::from(0xBEEFu64);
    assert!(
        !verify_pca_proof_offchain(&pca_proof),
        "tampered root must be rejected"
    );
}

#[test]
fn test_pca_invalid_proof_rejected_tag_tamper() {
    let params = WotsParams::default();
    let seed = [FELT::from(55u64)];
    let keypair = generate_keypair(&seed, &params);
    let message = FELT::from(0x9999u64);

    let mut pca_proof = generate_pca_proof(&params, &keypair, &message, 0)
        .expect("proof generation should succeed");

    // Tamper: alter the verification tag (last element)
    let last = pca_proof.proof.len() - 1;
    pca_proof.proof[last] = FELT::from(0xBADu64);
    assert!(
        !verify_pca_proof_offchain(&pca_proof),
        "tampered tag must be rejected"
    );
}

#[test]
fn test_pca_different_messages_produce_different_proofs() {
    let params = WotsParams::default();
    let seed = [FELT::from(42u64)];
    let keypair = generate_keypair(&seed, &params);

    let proof_a = generate_pca_proof(&params, &keypair, &FELT::from(1u64), 0).expect("proof A");
    let proof_b = generate_pca_proof(&params, &keypair, &FELT::from(2u64), 1).expect("proof B");

    assert!(verify_pca_proof_offchain(&proof_a));
    assert!(verify_pca_proof_offchain(&proof_b));

    // Different messages must produce different message hashes and tags
    assert_ne!(proof_a.message_hash, proof_b.message_hash);
    let tag_a = proof_a.proof.last().unwrap();
    let tag_b = proof_b.proof.last().unwrap();
    assert_ne!(tag_a, tag_b);
}
