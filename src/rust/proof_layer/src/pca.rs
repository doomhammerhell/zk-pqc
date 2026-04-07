//! PCA (Proof-Carrying Authorization) — end-to-end flow with real STARK proofs.
//!
//! Implements the off-chain side of the PCA model:
//! 1. Generate a WOTS+ key pair
//! 2. Sign a message
//! 3. Generate a real STARK proof via lambdaworks (WOTS+ verification trace)
//! 4. The proof can be verified off-chain or submitted to the Cairo contract
//!
//! **The proof is now unforgeable without the secret key.**
//!
//! Requirements: 10.2, 10.3, 10.4, 12.1, 12.2, 12.3

use stark_platinum_prover::proof::{options::ProofOptions, stark::StarkProof};
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::sponge::PoseidonSponge;
use zk_pqc_hash_layer::traits::PoseidonHash;
use zk_pqc_signature_layer::{WotsKeyPair, WotsParams, WotsPlus};

use crate::wots_air::WotsPublicInputs;
use crate::wots_prover::{default_proof_options, prove_wots_verification, WotsStarkProofResult};
use crate::wots_verifier::verify_stark_proof_real;
use stark_platinum_prover::PrimeField;

/// Result of the off-chain PCA proof generation backed by a real STARK proof.
pub struct PcaProof {
    /// The real STARK proof for WOTS+ signature verification.
    pub stark_proof: StarkProof<PrimeField, PrimeField>,
    /// Public inputs used during proof generation (needed for verification).
    pub pub_inputs: WotsPublicInputs,
    /// Proof options used during proof generation (needed for verification).
    pub proof_options: ProofOptions,
    /// The canonical message hash bound into the proof.
    pub message_hash: FELT,
    /// The WOTS+ public key commitment root bound into the proof.
    pub commitment_root: FELT,
    /// The OTS index used.
    pub index: u64,
    /// Time taken to generate the proof in milliseconds.
    pub generation_time_ms: u128,
}

/// Generate a WOTS+ key pair using Poseidon hashing.
pub fn generate_keypair(seed: &[FELT], params: &WotsParams) -> WotsKeyPair {
    let hasher = PoseidonHash;
    WotsPlus::keygen(&hasher, params, seed)
}

/// Compute the commitment root from a WOTS+ public key.
/// The root is H(public_chains[0] || public_chains[1] || ... || public_chains[n-1]).
pub fn commitment_root(pubkey: &[FELT]) -> FELT {
    PoseidonSponge::hash(pubkey)
}

/// Sign a message with WOTS+ and generate a real STARK PCA proof.
///
/// This performs the full off-chain flow:
/// 1. Sign the message with WOTS+
/// 2. Verify the signature off-chain (producing the execution trace)
/// 3. Generate a real STARK proof from the trace via lambdaworks
///
/// Returns `None` if signing, off-chain verification, or proof generation fails.
pub fn generate_pca_proof(
    params: &WotsParams,
    keypair: &WotsKeyPair,
    message: &FELT,
    index: u64,
) -> Option<PcaProof> {
    generate_pca_proof_with_options(params, keypair, message, index, &default_proof_options())
}

/// Sign a message with WOTS+ and generate a real STARK PCA proof with custom proof options.
pub fn generate_pca_proof_with_options(
    params: &WotsParams,
    keypair: &WotsKeyPair,
    message: &FELT,
    index: u64,
    proof_options: &ProofOptions,
) -> Option<PcaProof> {
    let hasher = PoseidonHash;

    // Step 1: Sign the message
    let signature = WotsPlus::sign(&hasher, params, keypair, &[*message]).ok()?;

    // Step 2: Verify off-chain (this is the computation whose trace is STARKed)
    let valid = WotsPlus::verify(
        &hasher,
        params,
        &keypair.public_chains,
        &[*message],
        &signature,
    );
    if !valid {
        return None;
    }

    // Step 3: Generate real STARK proof
    let WotsStarkProofResult {
        proof,
        pub_inputs,
        proof_options: used_options,
        generation_time_ms,
    } = prove_wots_verification(
        params,
        &signature.chain_values,
        message,
        &keypair.public_chains,
        proof_options,
    )?;

    let message_hash = PoseidonSponge::hash(&[*message]);
    let root = commitment_root(&keypair.public_chains);

    Some(PcaProof {
        stark_proof: proof,
        pub_inputs,
        proof_options: used_options,
        message_hash,
        commitment_root: root,
        index,
        generation_time_ms,
    })
}

/// Verify a PCA proof off-chain using the real STARK verifier.
///
/// Checks:
/// 1. The STARK proof is valid for the embedded public inputs
/// 2. The message_hash and commitment_root in the proof match the public inputs
pub fn verify_pca_proof(pca_proof: &PcaProof) -> bool {
    // Verify the message_hash and commitment_root are bound into the public inputs
    if pca_proof.pub_inputs.message_hash
        != crate::wots_air::local_felt_to_stark(&pca_proof.message_hash)
    {
        return false;
    }
    if pca_proof.pub_inputs.commitment_root
        != crate::wots_air::local_felt_to_stark(&pca_proof.commitment_root)
    {
        return false;
    }

    // Verify the real STARK proof
    verify_stark_proof_real(
        &pca_proof.stark_proof,
        &pca_proof.pub_inputs,
        &pca_proof.proof_options,
    )
}

/// Verify a PCA proof against specific expected message and root.
///
/// This is the function that mirrors on-chain verification: the caller
/// provides the expected message_hash and commitment_root, and the proof
/// must match both AND pass STARK verification.
pub fn verify_pca_proof_bound(
    pca_proof: &PcaProof,
    expected_message_hash: &FELT,
    expected_commitment_root: &FELT,
) -> bool {
    // Check that the proof is bound to the expected message and root
    if pca_proof.message_hash != *expected_message_hash {
        return false;
    }
    if pca_proof.commitment_root != *expected_commitment_root {
        return false;
    }

    verify_pca_proof(pca_proof)
}
