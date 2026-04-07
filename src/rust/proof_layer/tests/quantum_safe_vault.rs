//! End-to-End Quantum-Safe Vault integration tests.
//!
//! **This test suite is the project's north star.**
//!
//! Exercises the complete quantum-safe vault lifecycle:
//! 1. WOTS+ keygen → commitment root R
//! 2. Sign message M
//! 3. Generate REAL STARK proof π_auth
//! 4. Verify off-chain with Rust STARK verifier
//! 5. Verify on-chain (simulated Cairo PCA contract)
//! 6. State mutation: submit_batch → index consumed
//! 7. Replay rejection: same index → rejected
//! 8. Tamper rejection: altered proof → rejected
//!
//! Plus adversarial tests for forgery, replay, and brute-force resistance.
//!
//! Requirements: 10.2, 10.3, 10.4, 12.1, 12.2, 12.3

use std::collections::HashSet;
use std::time::Instant;

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::sponge::PoseidonSponge;
use zk_pqc_hash_layer::traits::PoseidonHash;
use zk_pqc_proof_layer::pca::{
    commitment_root, generate_keypair, generate_pca_proof, verify_pca_proof,
    verify_pca_proof_bound, PcaProof,
};
use zk_pqc_proof_layer::wots_air::local_felt_to_stark;
use zk_pqc_signature_layer::{HashMode, WotsParams, WotsPlus};

// ---------------------------------------------------------------------------
// Simulated Cairo PCA Contract (on-chain behavior in Rust)
// ---------------------------------------------------------------------------

/// Simulates the Cairo PCA verifier contract's on-chain state and logic.
/// Tracks consumed indices and verifies STARK proofs with binding checks.
struct SimulatedPcaContract {
    /// Set of consumed OTS indices (simulates SMT/JMT).
    consumed_indices: HashSet<u64>,
    /// The commitment root this contract is bound to.
    commitment_root: FELT,
}

impl SimulatedPcaContract {
    fn new(commitment_root: FELT) -> Self {
        Self {
            consumed_indices: HashSet::new(),
            commitment_root,
        }
    }

    /// Simulates `verify_authorization` from the Cairo IPCAVerifier interface.
    ///
    /// Checks:
    /// 1. STARK proof is valid
    /// 2. Proof is bound to the expected message_hash and commitment_root
    /// 3. Index has not been consumed
    fn verify_authorization(&self, pca_proof: &PcaProof, message_hash: &FELT, index: u64) -> bool {
        // Check index not already consumed
        if self.consumed_indices.contains(&index) {
            return false;
        }

        // Verify proof binding to message and root
        verify_pca_proof_bound(pca_proof, message_hash, &self.commitment_root)
    }

    /// Simulates `submit_batch` from the Cairo IPCAVerifier interface.
    ///
    /// Marks the given indices as consumed. Returns false if any index
    /// was already consumed (replay rejection).
    fn submit_batch(&mut self, indices: &[u64]) -> bool {
        for &idx in indices {
            if self.consumed_indices.contains(&idx) {
                return false;
            }
        }
        for &idx in indices {
            self.consumed_indices.insert(idx);
        }
        true
    }

    /// Check if an index has been consumed.
    fn is_index_consumed(&self, index: u64) -> bool {
        self.consumed_indices.contains(&index)
    }
}

// ---------------------------------------------------------------------------
// 11I.1 — End-to-End Quantum-Safe Vault Flow (the north star test)
// ---------------------------------------------------------------------------

/// **The project's north star test.**
///
/// Complete quantum-safe vault cycle:
/// 1. Setup: WOTS+ keygen, compute commitment root R
/// 2. Sign: sign "transfer 100 tokens" message M
/// 3. Prove: generate REAL STARK proof π_auth for WOTS+ verification of (M, σ, R)
/// 4. Verify off-chain: verify π_auth with Rust STARK verifier → true
/// 5. Verify on-chain (simulated): submit to Cairo PCA contract → verify_authorization → true
/// 6. State mutation: submit_batch → index consumed
/// 7. Replay rejection: same index → rejected
/// 8. Tamper rejection: alter proof → verify_authorization → false
#[test]
fn test_quantum_safe_vault_e2e() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };

    // -----------------------------------------------------------------------
    // Step 1: Setup — WOTS+ keygen, compute commitment root R
    // -----------------------------------------------------------------------
    let seed = [FELT::from(0xDEADBEEFu64), FELT::from(0xCAFEBABEu64)];
    let t_keygen = Instant::now();
    let keypair = generate_keypair(&seed, &params);
    let keygen_ms = t_keygen.elapsed().as_millis();

    let root = commitment_root(&keypair.public_chains);
    assert_ne!(root, FELT::zero(), "commitment root must be non-zero");

    // Initialize the simulated on-chain contract
    let mut contract = SimulatedPcaContract::new(root);

    // -----------------------------------------------------------------------
    // Step 2: Sign — sign "transfer 100 tokens" message M
    // -----------------------------------------------------------------------
    // Encode "transfer 100 tokens" as a field element (hash of the calldata)
    let message = PoseidonSponge::hash(&[
        FELT::from(0x7472616E73666572u64), // "transfer" prefix
        FELT::from(100u64),                // amount
    ]);
    let message_hash = PoseidonSponge::hash(&[message]);
    let index: u64 = 0;

    // -----------------------------------------------------------------------
    // Step 3: Prove — generate REAL STARK proof π_auth
    // -----------------------------------------------------------------------
    let t_prove = Instant::now();
    let pca_proof = generate_pca_proof(&params, &keypair, &message, index)
        .expect("STARK proof generation must succeed for valid signature");
    let prove_ms = t_prove.elapsed().as_millis();

    // -----------------------------------------------------------------------
    // Step 4: Verify off-chain — verify π_auth with Rust STARK verifier → true
    // -----------------------------------------------------------------------
    let t_verify = Instant::now();
    let offchain_valid = verify_pca_proof(&pca_proof);
    let verify_ms = t_verify.elapsed().as_millis();

    assert!(offchain_valid, "Off-chain STARK verification must pass");

    // -----------------------------------------------------------------------
    // Step 5: Verify on-chain (simulated) — verify_authorization → true
    // -----------------------------------------------------------------------
    let onchain_valid = contract.verify_authorization(&pca_proof, &message_hash, index);
    assert!(
        onchain_valid,
        "Simulated on-chain verify_authorization must return true"
    );

    // -----------------------------------------------------------------------
    // Step 6: State mutation — submit_batch → index consumed
    // -----------------------------------------------------------------------
    let batch_ok = contract.submit_batch(&[index]);
    assert!(batch_ok, "submit_batch must succeed for fresh index");
    assert!(
        contract.is_index_consumed(index),
        "Index must be marked as consumed after submit_batch"
    );

    // -----------------------------------------------------------------------
    // Step 7: Replay rejection — same index → rejected
    // -----------------------------------------------------------------------
    let replay_ok = contract.submit_batch(&[index]);
    assert!(
        !replay_ok,
        "submit_batch must reject already-consumed index (replay)"
    );

    let replay_auth = contract.verify_authorization(&pca_proof, &message_hash, index);
    assert!(
        !replay_auth,
        "verify_authorization must reject consumed index"
    );

    // -----------------------------------------------------------------------
    // Step 8: Tamper rejection — alter proof → verify_authorization → false
    // -----------------------------------------------------------------------
    let mut tampered_proof = generate_pca_proof(&params, &keypair, &message, 1)
        .expect("proof generation for tamper test");

    // Tamper: alter a boundary constraint value in the public inputs
    if !tampered_proof.pub_inputs.boundary_values.is_empty() {
        tampered_proof.pub_inputs.boundary_values[0].2 =
            local_felt_to_stark(&FELT::from(0xBADBADBADu64));
    }

    let tampered_valid = verify_pca_proof(&tampered_proof);
    assert!(
        !tampered_valid,
        "Tampered STARK proof must be rejected by off-chain verifier"
    );

    // Also check that the simulated contract rejects the tampered proof
    // (use index 1 which hasn't been consumed, so rejection is purely from proof)
    let tampered_onchain =
        contract.verify_authorization(&tampered_proof, &PoseidonSponge::hash(&[message]), 1);
    assert!(
        !tampered_onchain,
        "Simulated on-chain must reject tampered proof"
    );

    // -----------------------------------------------------------------------
    // Document: proof size, generation time, verification time
    // -----------------------------------------------------------------------
    // Estimate proof size from trace length (actual serialized size varies)
    let proof_trace_len = pca_proof.stark_proof.trace_length;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       QUANTUM-SAFE VAULT — END-TO-END METRICS          ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!(
        "║  Key generation time:     {:>8} ms                   ║",
        keygen_ms
    );
    println!(
        "║  Proof generation time:   {:>8} ms                   ║",
        prove_ms
    );
    println!(
        "║  Proof verification time: {:>8} ms                   ║",
        verify_ms
    );
    println!(
        "║  STARK trace length:      {:>8}                      ║",
        proof_trace_len
    );
    println!(
        "║  Boundary constraints:    {:>8}                      ║",
        pca_proof.pub_inputs.boundary_values.len()
    );
    println!(
        "║  Chain count:             {:>8}                      ║",
        pca_proof.pub_inputs.chain_count
    );
    println!(
        "║  Prover-reported time:    {:>8} ms                   ║",
        pca_proof.generation_time_ms
    );
    println!("╚══════════════════════════════════════════════════════════╝");
}

// ---------------------------------------------------------------------------
// 11I.2 — Adversarial Tests
// ---------------------------------------------------------------------------

/// Adversarial: different keypair, same message → prove against original root → MUST fail.
///
/// An attacker who generates their own keypair and signs the same message
/// cannot produce a valid proof that verifies against the victim's commitment root.
#[test]
fn test_vault_forgery_attempt() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };

    // Victim's keypair and root
    let victim_seed = [FELT::from(0x1111u64), FELT::from(0x2222u64)];
    let victim_keypair = generate_keypair(&victim_seed, &params);
    let victim_root = commitment_root(&victim_keypair.public_chains);

    // Attacker's keypair (different seed → different keys)
    let attacker_seed = [FELT::from(0x6666u64), FELT::from(0x7777u64)];
    let attacker_keypair = generate_keypair(&attacker_seed, &params);
    let attacker_root = commitment_root(&attacker_keypair.public_chains);

    // Roots must differ
    assert_ne!(
        victim_root, attacker_root,
        "Different seeds must produce different commitment roots"
    );

    // Same message
    let message = FELT::from(0xCAFEu64);
    let message_hash = PoseidonSponge::hash(&[message]);

    // Attacker generates a valid proof with their own keypair
    let attacker_proof = generate_pca_proof(&params, &attacker_keypair, &message, 0)
        .expect("Attacker can generate a proof with their own key");

    // The proof verifies against the attacker's own root
    assert!(
        verify_pca_proof_bound(&attacker_proof, &message_hash, &attacker_root),
        "Attacker's proof must verify against attacker's own root"
    );

    // But it MUST fail against the victim's root
    assert!(
        !verify_pca_proof_bound(&attacker_proof, &message_hash, &victim_root),
        "Attacker's proof MUST NOT verify against victim's commitment root"
    );

    // Simulated contract bound to victim's root must reject
    let contract = SimulatedPcaContract::new(victim_root);
    assert!(
        !contract.verify_authorization(&attacker_proof, &message_hash, 0),
        "Contract bound to victim's root must reject attacker's proof"
    );
}

/// Adversarial: valid proof index 0 → submit → success → same index → MUST fail.
///
/// Ensures the one-time property of OTS indices is enforced.
#[test]
fn test_vault_proof_replay() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };

    let seed = [FELT::from(0xABCDu64)];
    let keypair = generate_keypair(&seed, &params);
    let root = commitment_root(&keypair.public_chains);
    let message = FELT::from(0x1234u64);
    let message_hash = PoseidonSponge::hash(&[message]);
    let index: u64 = 0;

    let pca_proof = generate_pca_proof(&params, &keypair, &message, index)
        .expect("proof generation must succeed");

    let mut contract = SimulatedPcaContract::new(root);

    // First submission: must succeed
    assert!(
        contract.verify_authorization(&pca_proof, &message_hash, index),
        "First verify_authorization must succeed"
    );
    assert!(
        contract.submit_batch(&[index]),
        "First submit_batch must succeed"
    );

    // Replay: same index → MUST fail
    assert!(
        !contract.verify_authorization(&pca_proof, &message_hash, index),
        "Replay verify_authorization must fail (index consumed)"
    );
    assert!(
        !contract.submit_batch(&[index]),
        "Replay submit_batch must fail (index consumed)"
    );

    // A different index with a new proof should still work
    let message2 = FELT::from(0x5678u64);
    let message2_hash = PoseidonSponge::hash(&[message2]);
    let pca_proof2 = generate_pca_proof(&params, &keypair, &message2, 1)
        .expect("proof for index 1 must succeed");

    assert!(
        contract.verify_authorization(&pca_proof2, &message2_hash, 1),
        "New index 1 must be accepted"
    );
    assert!(
        contract.submit_batch(&[1]),
        "submit_batch for index 1 must succeed"
    );
}

/// Adversarial: knows pubkey + message, NOT secret → cannot produce valid sig → cannot produce valid proof.
///
/// Without the secret key, an attacker cannot sign the message, and therefore
/// cannot generate a valid STARK proof of signature verification.
#[test]
fn test_vault_proof_without_secret() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };

    // Legitimate keypair
    let seed = [FELT::from(0x53454352u64)]; // "SECR" in hex
    let keypair = generate_keypair(&seed, &params);
    let _root = commitment_root(&keypair.public_chains);

    let message = FELT::from(0xAAAAu64);

    // Attacker knows the public key and message but NOT the secret chains.
    // They try to forge a signature by using random values as chain_values.
    let total_chains = WotsPlus::total_chains(&params);
    let forged_chain_values: Vec<FELT> = (0..total_chains)
        .map(|i| {
            // Deterministic but wrong values — attacker doesn't know the real secrets
            PoseidonSponge::hash(&[FELT::from(i as u64), FELT::from(0x464F524745u64)])
        })
        .collect();

    // The forged signature should not verify
    let forged_sig = zk_pqc_signature_layer::WotsSignature {
        chain_values: forged_chain_values.clone(),
    };
    let sig_valid = WotsPlus::verify(
        &PoseidonHash,
        &params,
        &keypair.public_chains,
        &[message],
        &forged_sig,
    );
    assert!(
        !sig_valid,
        "Forged signature (without secret) must not verify"
    );

    // Without a valid signature, the prover cannot generate a valid STARK proof.
    // prove_wots_verification checks signature validity before generating the proof.
    let proof_result = zk_pqc_proof_layer::wots_prover::prove_wots_verification(
        &params,
        &forged_chain_values,
        &message,
        &keypair.public_chains,
        &zk_pqc_proof_layer::wots_prover::default_proof_options(),
    );
    assert!(
        proof_result.is_none(),
        "STARK proof generation must fail for forged (invalid) signature"
    );

    // Even if an attacker somehow constructed a PcaProof struct with garbage,
    // the STARK verifier would reject it.

    // Generate a legitimate proof to get the structure, then corrupt it
    let legit_proof =
        generate_pca_proof(&params, &keypair, &message, 0).expect("legitimate proof must succeed");

    // Corrupt the STARK proof's public inputs to simulate a forged proof
    let mut fake_proof = legit_proof;
    // Alter the commitment root in the public inputs to break binding
    fake_proof.pub_inputs.commitment_root = local_felt_to_stark(&FELT::from(0xFA4E5007u64));

    assert!(
        !verify_pca_proof(&fake_proof),
        "Proof with corrupted public inputs must be rejected"
    );
}

/// Document the cost of brute-forcing a WOTS+ key (Grover resistance).
///
/// WOTS+ with Poseidon (248-bit effective output due to MSB byte zeroing):
/// - Classical brute-force: 2^248 hash evaluations to find a preimage
/// - Grover's algorithm: sqrt(2^248) = 2^124 hash evaluations
/// - At 10^12 hashes/sec (optimistic quantum computer): 2^124 / 10^12 ≈ 2^84 seconds ≈ 6 × 10^17 years
///
/// This test documents these security parameters rather than attempting to brute-force.
#[test]
fn test_vault_grover_resistance_doc() {
    let params = WotsParams {
        w: 16,
        hash_mode: HashMode::Poseidon,
    };

    let total_chains = WotsPlus::total_chains(&params);

    // Security parameters for WOTS+ with Poseidon over F_251
    let effective_output_bits: u32 = 248; // MSB byte zeroed → 248 bits effective
    let classical_security_bits: u32 = effective_output_bits; // preimage resistance
    let grover_security_bits: u32 = effective_output_bits / 2; // quantum (Grover) resistance

    // WOTS+ specific: attacker must find preimages for ALL chains simultaneously
    // The checksum prevents advancing individual chains, so the attacker must
    // brute-force the entire secret key, not just one chain.
    let chains_to_break = total_chains;

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║       GROVER RESISTANCE ANALYSIS — WOTS+ / Poseidon    ║");
    println!("╠══════════════════════════════════════════════════════════╣");
    println!(
        "║  Winternitz parameter w:    {:>6}                      ║",
        params.w
    );
    println!(
        "║  Total chains:              {:>6}                      ║",
        chains_to_break
    );
    println!(
        "║  Effective output bits:     {:>6}                      ║",
        effective_output_bits
    );
    println!(
        "║  Classical security:        2^{:<4} hash evals          ║",
        classical_security_bits
    );
    println!(
        "║  Grover (quantum) security: 2^{:<4} hash evals          ║",
        grover_security_bits
    );
    println!("║                                                          ║");
    println!("║  At 10^12 hashes/sec (optimistic quantum):               ║");
    println!("║    Time to brute-force: ~2^84 seconds ≈ 6×10^17 years   ║");
    println!("║                                                          ║");
    println!("║  NIST Post-Quantum Security Level: Category 1+           ║");
    println!("║  (≥ 124-bit quantum security exceeds AES-128 target)     ║");
    println!("╚══════════════════════════════════════════════════════════╝");

    // Assertions to document the security parameters in test output
    assert!(
        grover_security_bits >= 124,
        "Grover security must be at least 124 bits (got {})",
        grover_security_bits
    );
    assert!(
        classical_security_bits >= 248,
        "Classical security must be at least 248 bits (got {})",
        classical_security_bits
    );
    assert!(
        chains_to_break >= 63,
        "WOTS+ w=16 must have at least 63 message chains (got {})",
        chains_to_break
    );
}
