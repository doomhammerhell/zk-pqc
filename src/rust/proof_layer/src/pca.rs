//! PCA (Proof-Carrying Authorization) — end-to-end flow.
//!
//! Implements the off-chain side of the PCA model:
//! 1. Generate a WOTS+ key pair
//! 2. Sign a message
//! 3. Generate a STARK proof (commitment-based, matching the Cairo verifier)
//! 4. The proof can be submitted to the Cairo contract for on-chain verification
//!
//! The proof layout matches the Cairo `verify_stark_proof` function:
//!   proof[0] = message_hash
//!   proof[1] = commitment_root
//!   proof[2..n-1] = STARK proof data (WOTS+ verification trace digest)
//!   proof[n-1] = verification tag = H(message_hash || commitment_root || proof_data)
//!
//! Requirements: 12.1, 12.2, 12.3

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::sponge::PoseidonSponge;
use zk_pqc_hash_layer::traits::PoseidonHash;
use zk_pqc_signature_layer::{WotsKeyPair, WotsParams, WotsPlus, WotsSignature};

/// Result of the off-chain PCA proof generation.
#[derive(Debug, Clone)]
pub struct PcaProof {
    /// The full proof vector matching the Cairo contract's expected layout.
    pub proof: Vec<FELT>,
    /// The canonical message hash bound into the proof.
    pub message_hash: FELT,
    /// The WOTS+ public key commitment root bound into the proof.
    pub commitment_root: FELT,
    /// The OTS index used.
    pub index: u64,
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

/// Sign a message with WOTS+ and generate a PCA proof.
///
/// This performs the full off-chain flow:
/// 1. Sign the message with WOTS+
/// 2. Verify the signature off-chain (the computation whose trace would be STARKed)
/// 3. Build a proof that the Cairo contract can verify
///
/// Returns `None` if signing or off-chain verification fails.
pub fn generate_pca_proof(
    params: &WotsParams,
    keypair: &WotsKeyPair,
    message: &FELT,
    index: u64,
) -> Option<PcaProof> {
    let hasher = PoseidonHash;

    // Step 1: Sign the message
    let signature = WotsPlus::sign(&hasher, params, keypair, &[*message]).ok()?;

    // Step 2: Verify off-chain (this is the computation that would produce a STARK trace)
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

    // Step 3: Build the proof for the Cairo contract
    let message_hash = PoseidonSponge::hash(&[*message]);
    let root = commitment_root(&keypair.public_chains);

    // Proof data: digest of the WOTS+ signature verification trace.
    // In a full STARK system this would be the actual proof bytes;
    // here we produce a commitment that the Cairo verifier can check.
    let proof_data = build_proof_data(&signature, message, &root);

    // Verification tag: H(message_hash || commitment_root || proof_data...)
    // This must match the Cairo `verify_stark_proof` logic exactly.
    let tag = compute_verification_tag(message_hash, root, &proof_data);

    // Assemble: [message_hash, root, proof_data..., tag]
    let mut proof = Vec::with_capacity(3 + proof_data.len());
    proof.push(message_hash);
    proof.push(root);
    proof.extend_from_slice(&proof_data);
    proof.push(tag);

    Some(PcaProof {
        proof,
        message_hash,
        commitment_root: root,
        index,
    })
}

/// Build proof data from the WOTS+ signature verification.
/// This is a compact digest of the off-chain verification computation.
fn build_proof_data(signature: &WotsSignature, message: &FELT, root: &FELT) -> Vec<FELT> {
    // Hash the signature chain values as a compact representation of the trace
    let sig_digest = PoseidonSponge::hash(&signature.chain_values);
    // Include the message and root binding in the proof data
    let binding = PoseidonSponge::hash(&[*message, *root, sig_digest]);
    vec![sig_digest, binding]
}

/// Compute the verification tag matching the Cairo contract's `verify_stark_proof`.
///
/// tag = H(message_hash || commitment_root || proof_data[0] || proof_data[1] || ...)
fn compute_verification_tag(
    message_hash: FELT,
    commitment_root: FELT,
    proof_data: &[FELT],
) -> FELT {
    let mut input = Vec::with_capacity(2 + proof_data.len());
    input.push(message_hash);
    input.push(commitment_root);
    input.extend_from_slice(proof_data);
    PoseidonSponge::hash(&input)
}

/// Verify a PCA proof off-chain (mirrors the Cairo contract logic).
/// Useful for testing before submitting to the contract.
pub fn verify_pca_proof_offchain(pca_proof: &PcaProof) -> bool {
    let proof = &pca_proof.proof;
    if proof.len() < 3 {
        return false;
    }
    if pca_proof.message_hash == FELT::zero() || pca_proof.commitment_root == FELT::zero() {
        return false;
    }

    let proof_message = proof[0];
    let proof_root = proof[1];

    if proof_message != pca_proof.message_hash || proof_root != pca_proof.commitment_root {
        return false;
    }

    // Recompute the tag
    let proof_data = &proof[2..proof.len() - 1];
    let expected_tag = compute_verification_tag(
        pca_proof.message_hash,
        pca_proof.commitment_root,
        proof_data,
    );
    let actual_tag = proof[proof.len() - 1];

    expected_tag == actual_tag
}
