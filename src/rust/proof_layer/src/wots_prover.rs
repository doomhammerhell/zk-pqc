//! WotsVerificationProver — generates real STARK proofs for WOTS+ signature verification.
//!
//! Accepts a WOTS+ signature + message + public key, executes the verification,
//! records the execution trace, and calls the lambdaworks STARK prover to generate
//! a real `StarkProof`.
//!
//! Requirements: 10.5, 12.2, 21.1, 21.2

use std::time::Instant;

use log::info;
use stark_platinum_prover::{
    proof::{options::ProofOptions, stark::StarkProof},
    prover::{IsStarkProver, Prover},
    transcript::StoneProverTranscript,
    PrimeField,
};
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::sponge::PoseidonSponge;
use zk_pqc_hash_layer::traits::{HashFunction, PoseidonHash};
use zk_pqc_signature_layer::{WotsParams, WotsPlus};

use crate::wots_air::{build_wots_verification_trace, WotsPublicInputs, WotsVerificationAIR};

/// Result of STARK proof generation for WOTS+ verification.
pub struct WotsStarkProofResult {
    /// The STARK proof.
    pub proof: StarkProof<PrimeField, PrimeField>,
    /// Public inputs used (needed for verification).
    pub pub_inputs: WotsPublicInputs,
    /// Proof options used (needed for verification).
    pub proof_options: ProofOptions,
    /// Time taken to generate the proof in milliseconds.
    pub generation_time_ms: u128,
}

/// Default proof options for WOTS+ verification proofs.
/// Uses test-friendly parameters for development; production would use
/// `ProofOptions::new_secure(SecurityLevel::Conjecturable128Bits, 3)`.
pub fn default_proof_options() -> ProofOptions {
    ProofOptions::default_test_options()
}

/// Generate a real STARK proof for WOTS+ signature verification.
///
/// This function:
/// 1. Decomposes the message into base-w elements + checksum
/// 2. Executes the WOTS+ verification off-chain, recording the trace
/// 3. Calls the lambdaworks STARK prover to generate a proof
/// 4. Measures and logs proof generation time
///
/// Returns `None` if the WOTS+ signature is invalid or proof generation fails.
pub fn prove_wots_verification(
    params: &WotsParams,
    signature_values: &[FELT],
    message: &FELT,
    public_key: &[FELT],
    proof_options: &ProofOptions,
) -> Option<WotsStarkProofResult> {
    let hasher = PoseidonHash;
    let total_chains = WotsPlus::total_chains(params);

    if signature_values.len() != total_chains || public_key.len() != total_chains {
        return None;
    }

    // Decompose message into base-w elements + checksum
    let msg_elements = decompose_message_with_checksum(params, message);
    if msg_elements.len() != total_chains {
        return None;
    }

    // Verify the signature off-chain first (the computation we're proving)
    for (i, &m_i) in msg_elements.iter().enumerate() {
        let remaining = (params.w - 1) - m_i;
        let mut current = signature_values[i];
        for _ in 0..remaining {
            current = hasher.hash(&[current]);
        }
        if current != public_key[i] {
            return None; // Invalid signature
        }
    }

    // Compute public inputs
    let message_hash = PoseidonSponge::hash(&[*message]);
    let commitment_root = PoseidonSponge::hash(public_key);

    // Build the execution trace
    let (mut trace, pub_inputs) = build_wots_verification_trace(
        signature_values,
        &msg_elements,
        public_key,
        params.w,
        message_hash,
        commitment_root,
    );

    // Generate the STARK proof
    let start = Instant::now();

    let transcript = StoneProverTranscript::new(&[0x57, 0x4f, 0x54, 0x53]); // "WOTS"

    let proof_result =
        Prover::<WotsVerificationAIR>::prove(&mut trace, &pub_inputs, proof_options, transcript);

    let generation_time_ms = start.elapsed().as_millis();

    match proof_result {
        Ok(proof) => {
            info!(
                "WOTS+ STARK proof generated in {}ms (trace_length={}, chains={})",
                generation_time_ms, proof.trace_length, total_chains
            );
            Some(WotsStarkProofResult {
                proof,
                pub_inputs,
                proof_options: proof_options.clone(),
                generation_time_ms,
            })
        }
        Err(e) => {
            log::error!("STARK proof generation failed: {:?}", e);
            None
        }
    }
}

/// Decompose a message FELT into base-w elements + checksum elements.
/// This mirrors the logic in `WotsPlus` but returns the combined elements.
fn decompose_message_with_checksum(params: &WotsParams, message: &FELT) -> Vec<usize> {
    // Use the same decomposition as WotsPlus
    let log_w = (params.w as f64).log2() as usize;
    let msg_len = 252usize.div_ceil(log_w);

    #[allow(unused_imports)]
    use lambdaworks_math::traits::ByteConversion;
    let bytes = message.to_bytes_be();

    let mut bits = Vec::with_capacity(256);
    for byte in &bytes {
        for bit_idx in (0..8).rev() {
            bits.push((byte >> bit_idx) & 1);
        }
    }

    let start_bit = bits.len() - 252;
    let relevant_bits = &bits[start_bit..];

    let mut msg_elements = Vec::with_capacity(msg_len);
    for i in 0..msg_len {
        let mut val = 0usize;
        for j in 0..log_w {
            let bit_pos = i * log_w + j;
            if bit_pos < relevant_bits.len() {
                val = (val << 1) | (relevant_bits[bit_pos] as usize);
            } else {
                val <<= 1;
            }
        }
        msg_elements.push(val);
    }

    // Compute checksum
    let checksum_elements = WotsPlus::checksum(params.w, &msg_elements);

    let mut all_elements = msg_elements;
    all_elements.extend_from_slice(&checksum_elements);
    all_elements
}
