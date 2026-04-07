//! WotsVerifier — verifies real STARK proofs for WOTS+ signature verification.
//!
//! Uses `lambdaworks_stark::verify()` with the same AIR and public inputs
//! that were used during proof generation.
//!
//! Requirements: 10.2, 10.3, 10.4, 12.3

use stark_platinum_prover::{
    proof::{options::ProofOptions, stark::StarkProof},
    transcript::StoneProverTranscript,
    verifier::{IsStarkVerifier, Verifier},
    PrimeField,
};

use crate::wots_air::{WotsPublicInputs, WotsVerificationAIR};

/// Verify a real STARK proof for WOTS+ signature verification.
///
/// Returns `true` if the proof is valid for the given public inputs and options.
pub fn verify_stark_proof_real(
    proof: &StarkProof<PrimeField, PrimeField>,
    pub_inputs: &WotsPublicInputs,
    proof_options: &ProofOptions,
) -> bool {
    let transcript = StoneProverTranscript::new(&[0x57, 0x4f, 0x54, 0x53]); // "WOTS"

    Verifier::<WotsVerificationAIR>::verify(proof, pub_inputs, proof_options, transcript)
}
