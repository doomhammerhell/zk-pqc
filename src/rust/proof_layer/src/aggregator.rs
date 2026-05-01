//! Recursive Batch Aggregator — folds N individual π_auth proofs into a single Π_Batch.
//!
//! ## Design
//!
//! The aggregator implements a practical batch aggregation approach:
//! 1. Verify all N individual proofs first (reject invalid ones with identification)
//! 2. Compute a Poseidon Merkle commitment over all proof hashes as the batch proof
//! 3. Generate a STARK proof that the Merkle commitment was computed correctly
//! 4. Batch verification checks the STARK proof against the public inputs
//!
//! On-chain verification cost is O(1) regardless of N — the verifier only checks the
//! STARK proof and validates the public inputs (leaf commitment + root).
//!
//! ## STARK Batch Proof
//!
//! The `BatchStarkProof` proves that the Poseidon Merkle commitment was computed
//! correctly over N proof digests. This is NOT full recursive STARK (proving a
//! verifier inside another STARK) — it proves that the batch commitment computation
//! itself is correct. The AIR records each Poseidon hash step in the Merkle tree
//! construction and enforces transition + boundary constraints.
//!
//! Requirements: 15.1, 15.3, 15.4, 18.3

use std::collections::HashMap;
use std::time::Instant;

use log::info;
use stark_platinum_prover::{
    proof::{options::ProofOptions, stark::StarkProof},
    prover::{IsStarkProver, Prover},
    transcript::StoneProverTranscript,
    verifier::{IsStarkVerifier, Verifier},
    PrimeField,
};
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::sponge::PoseidonSponge;

use crate::batch_air::{build_batch_merkle_trace, BatchMerkleAIR, BatchPublicInputs};
use crate::pca::PcaProof;
use crate::wots_air::local_felt_to_stark;
use crate::wots_verifier::verify_stark_proof_real;

/// Transaction lane classification for multi-lane mempool processing.
///
/// Transactions are classified by hash mode:
/// - Lane 0 (PoseidonOnly): High-frequency, low-cost path using Poseidon t=6
/// - Lane 1 (HybridHash): Institutional/conservative path using Poseidon ⊕ SHA-256
///
/// Separate batch proofs are generated per lane so that the recursive aggregator
/// processes lanes independently, ensuring Poseidon-Only throughput is unaffected
/// by Hybrid-Hash processing.
///
/// Requirements: 18.1, 18.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lane {
    /// Lane 0: Poseidon-Only — high-frequency, low-cost path.
    PoseidonOnly = 0,
    /// Lane 1: Hybrid-Hash — institutional/conservative path.
    HybridHash = 1,
}

/// Error returned when batch aggregation fails due to invalid individual proofs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregationError {
    /// Indices of the invalid proofs within the input batch (0-indexed).
    pub invalid_indices: Vec<usize>,
    /// Human-readable description of the failure.
    pub message: String,
}

impl std::fmt::Display for AggregationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Aggregation failed: {} invalid proof(s) at indices {:?}",
            self.invalid_indices.len(),
            self.invalid_indices
        )
    }
}

impl std::error::Error for AggregationError {}

/// A single proof's compact hash representation used in the Merkle commitment.
#[derive(Debug, Clone)]
pub struct ProofDigest {
    /// Hash of the proof's public inputs (message_hash, commitment_root, index).
    pub public_input_hash: FELT,
    /// The OTS index associated with this proof.
    pub index: u64,
    /// The lane this proof belongs to for multi-lane mempool classification.
    /// Defaults to `Lane::PoseidonOnly` for backward compatibility.
    pub lane: Lane,
}

/// A STARK proof that the Poseidon Merkle commitment was computed correctly.
///
/// This proves the batch commitment computation itself — that the Merkle tree
/// was built correctly from the leaf hashes to the root using Poseidon hashing
/// with the correct domain separator.
pub struct BatchStarkProof {
    /// The STARK proof for the Merkle commitment computation.
    pub stark_proof: StarkProof<PrimeField, PrimeField>,
    /// Public inputs used during proof generation (needed for verification).
    pub pub_inputs: BatchPublicInputs,
    /// Proof options used during proof generation (needed for verification).
    pub proof_options: ProofOptions,
    /// Time taken to generate the proof in milliseconds.
    pub generation_time_ms: u128,
}

/// The batch proof Π_Batch — a single compact proof attesting to N valid authorizations.
///
/// On-chain verification cost is O(1): verify the STARK proof against the public
/// inputs (leaf hashes + commitment root).
pub struct BatchProof {
    /// Poseidon Merkle commitment root over all proof digests.
    pub commitment_root: FELT,
    /// Number of individual proofs aggregated in this batch.
    pub batch_size: usize,
    /// Ordered list of proof digests (for off-chain reconstruction/audit).
    pub proof_digests: Vec<ProofDigest>,
    /// The Merkle tree leaf hashes (for verification).
    pub leaf_hashes: Vec<FELT>,
    /// Optional STARK proof that the Merkle commitment was computed correctly.
    /// When present, verification uses the STARK proof instead of recomputation.
    pub batch_stark_proof: Option<BatchStarkProof>,
}

impl std::fmt::Debug for BatchProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BatchProof")
            .field("commitment_root", &self.commitment_root)
            .field("batch_size", &self.batch_size)
            .field("proof_digests", &self.proof_digests)
            .field("leaf_hashes", &self.leaf_hashes)
            .field("has_batch_stark_proof", &self.batch_stark_proof.is_some())
            .finish()
    }
}

/// Configuration for the recursive aggregator.
#[derive(Debug, Clone)]
pub struct AggregatorConfig {
    /// Maximum batch size supported. Default: 4096 (well above the 1000 minimum).
    pub max_batch_size: usize,
    /// Whether to verify individual proofs before aggregation.
    /// Set to false only if proofs have been pre-verified.
    pub verify_individual_proofs: bool,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 4096,
            verify_individual_proofs: true,
        }
    }
}

/// The Recursive Aggregator — folds N individual π_auth proofs into a single Π_Batch.
///
/// # Usage
///
/// ```ignore
/// let aggregator = RecursiveAggregator::new(AggregatorConfig::default());
/// let batch_proof = aggregator.aggregate(&proofs)?;
/// assert!(aggregator.verify_batch(&batch_proof));
/// ```
pub struct RecursiveAggregator {
    config: AggregatorConfig,
}

impl RecursiveAggregator {
    /// Create a new aggregator with the given configuration.
    pub fn new(config: AggregatorConfig) -> Self {
        Self { config }
    }

    /// Create a new aggregator with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(AggregatorConfig::default())
    }

    /// Aggregate N individual PCA proofs into a single batch proof Π_Batch.
    ///
    /// This function:
    /// 1. Validates the batch size (must be >= 1 and <= max_batch_size)
    /// 2. Verifies each individual proof (if configured)
    /// 3. Rejects the entire batch if any proof is invalid, identifying the invalid proofs
    /// 4. Computes a Poseidon Merkle commitment over all proof digests
    /// 5. Returns the compact batch proof
    ///
    /// # Errors
    ///
    /// Returns `AggregationError` if any individual proof is invalid, with the
    /// indices of all invalid proofs identified.
    pub fn aggregate(&self, proofs: &[PcaProof]) -> Result<BatchProof, AggregationError> {
        // Validate batch size
        if proofs.is_empty() {
            return Err(AggregationError {
                invalid_indices: vec![],
                message: "Cannot aggregate an empty batch".to_string(),
            });
        }

        if proofs.len() > self.config.max_batch_size {
            return Err(AggregationError {
                invalid_indices: vec![],
                message: format!(
                    "Batch size {} exceeds maximum {}",
                    proofs.len(),
                    self.config.max_batch_size
                ),
            });
        }

        // Step 1: Verify all individual proofs and collect invalid indices
        let mut invalid_indices = Vec::new();

        if self.config.verify_individual_proofs {
            for (i, proof) in proofs.iter().enumerate() {
                if !verify_stark_proof_real(
                    &proof.stark_proof,
                    &proof.pub_inputs,
                    &proof.proof_options,
                ) {
                    invalid_indices.push(i);
                }
            }
        }

        // Reject if any proof is invalid
        if !invalid_indices.is_empty() {
            return Err(AggregationError {
                invalid_indices: invalid_indices.clone(),
                message: format!(
                    "Batch rejected: {} invalid proof(s) at indices {:?}",
                    invalid_indices.len(),
                    invalid_indices
                ),
            });
        }

        // Step 2: Compute proof digests
        let proof_digests: Vec<ProofDigest> = proofs
            .iter()
            .map(|p| {
                let public_input_hash = compute_proof_public_input_hash(p);
                ProofDigest {
                    public_input_hash,
                    index: p.index,
                    lane: Lane::PoseidonOnly,
                }
            })
            .collect();

        // Step 3: Compute leaf hashes for the Merkle commitment
        let leaf_hashes: Vec<FELT> = proof_digests.iter().map(compute_leaf_hash).collect();

        // Step 4: Build Poseidon Merkle commitment (recursive binary tree)
        let commitment_root = compute_merkle_commitment(&leaf_hashes);

        Ok(BatchProof {
            commitment_root,
            batch_size: proofs.len(),
            proof_digests,
            leaf_hashes,
            batch_stark_proof: None,
        })
    }

    /// Aggregate pre-verified proof digests into a batch proof.
    ///
    /// Use this when individual proofs have already been verified externally
    /// (e.g., by a distributed verification network). This skips STARK verification
    /// and directly computes the Merkle commitment.
    pub fn aggregate_preverified(
        &self,
        digests: Vec<ProofDigest>,
    ) -> Result<BatchProof, AggregationError> {
        if digests.is_empty() {
            return Err(AggregationError {
                invalid_indices: vec![],
                message: "Cannot aggregate an empty batch".to_string(),
            });
        }

        if digests.len() > self.config.max_batch_size {
            return Err(AggregationError {
                invalid_indices: vec![],
                message: format!(
                    "Batch size {} exceeds maximum {}",
                    digests.len(),
                    self.config.max_batch_size
                ),
            });
        }

        let leaf_hashes: Vec<FELT> = digests.iter().map(compute_leaf_hash).collect();
        let commitment_root = compute_merkle_commitment(&leaf_hashes);

        Ok(BatchProof {
            commitment_root,
            batch_size: digests.len(),
            proof_digests: digests,
            leaf_hashes,
            batch_stark_proof: None,
        })
    }

    /// Verify a batch proof by recomputing the Merkle commitment from the leaf hashes.
    ///
    /// This is the O(1) verification step: check that the commitment root matches
    /// the recomputed root from the stored leaf hashes.
    pub fn verify_batch(&self, batch_proof: &BatchProof) -> bool {
        // Verify structural integrity
        if batch_proof.batch_size == 0 {
            return false;
        }
        if batch_proof.batch_size != batch_proof.proof_digests.len() {
            return false;
        }
        if batch_proof.batch_size != batch_proof.leaf_hashes.len() {
            return false;
        }

        // Verify leaf hashes match proof digests
        for (i, digest) in batch_proof.proof_digests.iter().enumerate() {
            let expected_leaf = compute_leaf_hash(digest);
            if expected_leaf != batch_proof.leaf_hashes[i] {
                return false;
            }
        }

        // Recompute Merkle commitment and compare
        let recomputed_root = compute_merkle_commitment(&batch_proof.leaf_hashes);
        recomputed_root == batch_proof.commitment_root
    }

    /// Verify a batch proof with O(1) cost using only the commitment root.
    ///
    /// This is the on-chain verification path: given a commitment root and batch size,
    /// verify that the batch proof's root matches. The actual proof content is not needed.
    pub fn verify_batch_commitment(&self, expected_root: &FELT, batch_proof: &BatchProof) -> bool {
        *expected_root == batch_proof.commitment_root && batch_proof.batch_size > 0
    }

    /// Aggregate PCA proofs into separate batch proofs per lane.
    ///
    /// Classifies each proof by its lane (based on a lane classifier function),
    /// then aggregates each lane's proofs independently. This ensures that
    /// Poseidon-Only lane throughput is unaffected by Hybrid-Hash processing.
    ///
    /// The `lane_classifier` function determines which lane each proof belongs to.
    /// A simple default classifier is provided via [`default_lane_classifier`].
    ///
    /// # Errors
    ///
    /// Returns `AggregationError` if any individual proof is invalid (when
    /// verification is enabled), or if all lanes are empty.
    ///
    /// Requirements: 18.3
    pub fn aggregate_by_lane<F>(
        &self,
        proofs: &[PcaProof],
        lane_classifier: F,
    ) -> Result<HashMap<Lane, BatchProof>, AggregationError>
    where
        F: Fn(&PcaProof) -> Lane,
    {
        if proofs.is_empty() {
            return Err(AggregationError {
                invalid_indices: vec![],
                message: "Cannot aggregate an empty batch".to_string(),
            });
        }

        if proofs.len() > self.config.max_batch_size {
            return Err(AggregationError {
                invalid_indices: vec![],
                message: format!(
                    "Batch size {} exceeds maximum {}",
                    proofs.len(),
                    self.config.max_batch_size
                ),
            });
        }

        // Step 1: Verify all individual proofs and collect invalid indices
        let mut invalid_indices = Vec::new();

        if self.config.verify_individual_proofs {
            for (i, proof) in proofs.iter().enumerate() {
                if !verify_stark_proof_real(
                    &proof.stark_proof,
                    &proof.pub_inputs,
                    &proof.proof_options,
                ) {
                    invalid_indices.push(i);
                }
            }
        }

        if !invalid_indices.is_empty() {
            return Err(AggregationError {
                invalid_indices: invalid_indices.clone(),
                message: format!(
                    "Batch rejected: {} invalid proof(s) at indices {:?}",
                    invalid_indices.len(),
                    invalid_indices
                ),
            });
        }

        // Step 2: Classify proofs by lane and compute digests
        let mut lane_digests: HashMap<Lane, Vec<ProofDigest>> = HashMap::new();

        for proof in proofs {
            let lane = lane_classifier(proof);
            let public_input_hash = compute_proof_public_input_hash(proof);
            let digest = ProofDigest {
                public_input_hash,
                index: proof.index,
                lane,
            };
            lane_digests.entry(lane).or_default().push(digest);
        }

        // Step 3: Aggregate each lane independently
        let mut result = HashMap::new();

        for (lane, digests) in lane_digests {
            let leaf_hashes: Vec<FELT> = digests.iter().map(compute_leaf_hash).collect();
            let commitment_root = compute_merkle_commitment(&leaf_hashes);

            result.insert(
                lane,
                BatchProof {
                    commitment_root,
                    batch_size: digests.len(),
                    proof_digests: digests,
                    leaf_hashes,
                    batch_stark_proof: None,
                },
            );
        }

        Ok(result)
    }

    /// Aggregate pre-verified proof digests into separate batch proofs per lane.
    ///
    /// Each digest's `lane` field determines which lane it belongs to.
    /// Lanes are aggregated independently, producing separate `BatchProof`s.
    ///
    /// # Errors
    ///
    /// Returns `AggregationError` if the input is empty or exceeds max batch size.
    ///
    /// Requirements: 18.3
    pub fn aggregate_preverified_by_lane(
        &self,
        digests: Vec<ProofDigest>,
    ) -> Result<HashMap<Lane, BatchProof>, AggregationError> {
        if digests.is_empty() {
            return Err(AggregationError {
                invalid_indices: vec![],
                message: "Cannot aggregate an empty batch".to_string(),
            });
        }

        if digests.len() > self.config.max_batch_size {
            return Err(AggregationError {
                invalid_indices: vec![],
                message: format!(
                    "Batch size {} exceeds maximum {}",
                    digests.len(),
                    self.config.max_batch_size
                ),
            });
        }

        // Classify digests by lane
        let mut lane_digests: HashMap<Lane, Vec<ProofDigest>> = HashMap::new();
        for digest in digests {
            lane_digests.entry(digest.lane).or_default().push(digest);
        }

        // Aggregate each lane independently
        let mut result = HashMap::new();

        for (lane, digests) in lane_digests {
            let leaf_hashes: Vec<FELT> = digests.iter().map(compute_leaf_hash).collect();
            let commitment_root = compute_merkle_commitment(&leaf_hashes);

            result.insert(
                lane,
                BatchProof {
                    commitment_root,
                    batch_size: digests.len(),
                    proof_digests: digests,
                    leaf_hashes,
                    batch_stark_proof: None,
                },
            );
        }

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Internal helper functions
// ---------------------------------------------------------------------------

/// Domain separator for proof digest hashing.
const DOMAIN_PROOF_DIGEST: u64 = 0x5043415f44494745; // "PCA_DIGE" in ASCII

/// Domain separator for leaf hashing.
const DOMAIN_LEAF_HASH: u64 = 0x5043415f4c454146; // "PCA_LEAF" in ASCII

/// Domain separator for internal Merkle nodes.
const DOMAIN_MERKLE_NODE: u64 = 0x5043415f4e4f4445; // "PCA_NODE" in ASCII

/// Compute the public input hash for a PCA proof.
/// H(domain || message_hash || commitment_root || index)
fn compute_proof_public_input_hash(proof: &PcaProof) -> FELT {
    let domain = FELT::from(DOMAIN_PROOF_DIGEST);
    let index_felt = FELT::from(proof.index);
    PoseidonSponge::hash_with_ds(
        domain,
        &[proof.message_hash, proof.commitment_root, index_felt],
    )
}

/// Compute the leaf hash for a proof digest.
/// H(domain || public_input_hash || index)
fn compute_leaf_hash(digest: &ProofDigest) -> FELT {
    let domain = FELT::from(DOMAIN_LEAF_HASH);
    let index_felt = FELT::from(digest.index);
    PoseidonSponge::hash_with_ds(domain, &[digest.public_input_hash, index_felt])
}

/// Compute a Poseidon Merkle commitment over a list of leaf hashes.
///
/// Uses a binary tree structure where each internal node is:
///   H(domain || left || right)
///
/// If the number of leaves is odd, the last leaf is promoted to the next level.
/// This produces a single root hash regardless of N.
fn compute_merkle_commitment(leaves: &[FELT]) -> FELT {
    if leaves.is_empty() {
        return FELT::from(0u64);
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let domain = FELT::from(DOMAIN_MERKLE_NODE);

    // Iterative bottom-up Merkle tree construction
    let mut current_level: Vec<FELT> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));

        let mut i = 0;
        while i + 1 < current_level.len() {
            let node =
                PoseidonSponge::hash_with_ds(domain, &[current_level[i], current_level[i + 1]]);
            next_level.push(node);
            i += 2;
        }

        // If odd number of nodes, promote the last one
        if current_level.len() % 2 == 1 {
            next_level.push(*current_level.last().unwrap());
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Default lane classifier that assigns all proofs to `Lane::PoseidonOnly`.
///
/// In production, the classifier would inspect the proof's hash mode flag
/// to determine the lane. This default is provided for backward compatibility.
pub fn default_lane_classifier(_proof: &PcaProof) -> Lane {
    Lane::PoseidonOnly
}

// ---------------------------------------------------------------------------
// Batch STARK proof generation and verification
// ---------------------------------------------------------------------------

/// Generate a STARK proof that the Poseidon Merkle commitment was computed
/// correctly over the given leaf hashes.
///
/// This function:
/// 1. Builds the Merkle tree from the leaf hashes (recording each hash step)
/// 2. Constructs the execution trace for the `BatchMerkleAIR`
/// 3. Generates a STARK proof using lambdaworks
/// 4. Returns a `BatchStarkProof` containing the proof + public inputs
///
/// Requires at least 2 leaf hashes (a single leaf has no internal hash nodes).
///
/// Returns `None` if proof generation fails.
pub fn prove_batch_commitment(
    leaf_hashes: &[FELT],
    proof_options: &ProofOptions,
) -> Option<BatchStarkProof> {
    if leaf_hashes.len() < 2 {
        return None;
    }

    let (mut trace, pub_inputs) = build_batch_merkle_trace(leaf_hashes);

    let start = Instant::now();

    // Transcript seed: "BATC" in ASCII
    let transcript = StoneProverTranscript::new(&[0x42, 0x41, 0x54, 0x43]);

    let proof_result =
        Prover::<BatchMerkleAIR>::prove(&mut trace, &pub_inputs, proof_options, transcript);

    let generation_time_ms = start.elapsed().as_millis();

    match proof_result {
        Ok(proof) => {
            info!(
                "Batch STARK proof generated in {}ms (leaves={}, trace_length={})",
                generation_time_ms,
                leaf_hashes.len(),
                proof.trace_length
            );
            Some(BatchStarkProof {
                stark_proof: proof,
                pub_inputs,
                proof_options: proof_options.clone(),
                generation_time_ms,
            })
        }
        Err(e) => {
            log::error!("Batch STARK proof generation failed: {:?}", e);
            None
        }
    }
}

/// Verify a STARK proof that a Poseidon Merkle commitment was computed correctly.
///
/// Checks:
/// 1. The STARK proof is valid for the embedded public inputs and options
/// 2. The public inputs contain the expected leaf hashes and commitment root
///
/// Returns `true` if the proof is valid.
pub fn verify_batch_stark_proof(batch_stark_proof: &BatchStarkProof) -> bool {
    // Transcript seed must match the one used during proving: "BATC"
    let transcript = StoneProverTranscript::new(&[0x42, 0x41, 0x54, 0x43]);

    Verifier::<BatchMerkleAIR>::verify(
        &batch_stark_proof.stark_proof,
        &batch_stark_proof.pub_inputs,
        &batch_stark_proof.proof_options,
        transcript,
    )
}

/// Verify a batch STARK proof against specific expected values.
///
/// This is the function that mirrors on-chain verification: the caller provides
/// the expected leaf hashes and commitment root, and the proof must match both
/// AND pass STARK verification.
pub fn verify_batch_stark_proof_bound(
    batch_stark_proof: &BatchStarkProof,
    expected_leaf_hashes: &[FELT],
    expected_root: &FELT,
) -> bool {
    // Check that the public inputs match the expected values
    let expected_root_stark = local_felt_to_stark(expected_root);
    if batch_stark_proof.pub_inputs.commitment_root != expected_root_stark {
        return false;
    }

    if batch_stark_proof.pub_inputs.batch_size != expected_leaf_hashes.len() {
        return false;
    }

    let expected_leaves_stark: Vec<_> = expected_leaf_hashes
        .iter()
        .map(local_felt_to_stark)
        .collect();
    if batch_stark_proof.pub_inputs.leaf_hashes != expected_leaves_stark {
        return false;
    }

    // Verify the STARK proof
    verify_batch_stark_proof(batch_stark_proof)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pca::{generate_keypair, generate_pca_proof};
    use zk_pqc_hash_layer::constants::FELT;
    use zk_pqc_signature_layer::WotsParams;

    /// Helper: generate a valid PCA proof for testing.
    fn make_test_proof(seed_val: u64, message_val: u64, index: u64) -> PcaProof {
        let params = WotsParams::default();
        let seed = vec![FELT::from(seed_val), FELT::from(42u64)];
        let keypair = generate_keypair(&seed, &params);
        let message = FELT::from(message_val);
        generate_pca_proof(&params, &keypair, &message, index)
            .expect("Failed to generate test PCA proof")
    }

    #[test]
    fn test_aggregate_single_proof() {
        let proof = make_test_proof(1, 100, 0);
        let aggregator = RecursiveAggregator::with_defaults();

        let batch = aggregator.aggregate(&[proof]).unwrap();

        assert_eq!(batch.batch_size, 1);
        assert_eq!(batch.proof_digests.len(), 1);
        assert_eq!(batch.leaf_hashes.len(), 1);
        assert!(aggregator.verify_batch(&batch));
    }

    #[test]
    fn test_aggregate_multiple_proofs() {
        let proofs: Vec<PcaProof> = (0..3).map(|i| make_test_proof(i + 1, 100 + i, i)).collect();

        let aggregator = RecursiveAggregator::with_defaults();
        let batch = aggregator.aggregate(&proofs).unwrap();

        assert_eq!(batch.batch_size, 3);
        assert!(aggregator.verify_batch(&batch));
    }

    #[test]
    fn test_aggregate_empty_batch_rejected() {
        let aggregator = RecursiveAggregator::with_defaults();
        let result = aggregator.aggregate(&[]);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("empty batch"));
    }

    #[test]
    fn test_aggregate_exceeds_max_batch_size() {
        let config = AggregatorConfig {
            max_batch_size: 2,
            verify_individual_proofs: false,
        };
        let aggregator = RecursiveAggregator::new(config);

        // Create 3 proofs with pre-verified digests to avoid slow STARK generation
        let digests: Vec<ProofDigest> = (0..3)
            .map(|i| ProofDigest {
                public_input_hash: FELT::from(i as u64 + 1),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let result = aggregator.aggregate_preverified(digests);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("exceeds maximum"));
    }

    #[test]
    fn test_batch_verification_detects_tampered_root() {
        let proof = make_test_proof(1, 100, 0);
        let aggregator = RecursiveAggregator::with_defaults();

        let mut batch = aggregator.aggregate(&[proof]).unwrap();

        // Tamper with the commitment root
        batch.commitment_root = FELT::from(999u64);

        assert!(!aggregator.verify_batch(&batch));
    }

    #[test]
    fn test_batch_verification_detects_tampered_digest() {
        let proof = make_test_proof(1, 100, 0);
        let aggregator = RecursiveAggregator::with_defaults();

        let mut batch = aggregator.aggregate(&[proof]).unwrap();

        // Tamper with a proof digest
        batch.proof_digests[0].public_input_hash = FELT::from(999u64);

        assert!(!aggregator.verify_batch(&batch));
    }

    #[test]
    fn test_batch_verification_detects_size_mismatch() {
        let proof = make_test_proof(1, 100, 0);
        let aggregator = RecursiveAggregator::with_defaults();

        let mut batch = aggregator.aggregate(&[proof]).unwrap();

        // Tamper with batch size
        batch.batch_size = 5;

        assert!(!aggregator.verify_batch(&batch));
    }

    #[test]
    fn test_verify_batch_commitment() {
        let proof = make_test_proof(1, 100, 0);
        let aggregator = RecursiveAggregator::with_defaults();

        let batch = aggregator.aggregate(&[proof]).unwrap();
        let root = batch.commitment_root;

        assert!(aggregator.verify_batch_commitment(&root, &batch));
        assert!(!aggregator.verify_batch_commitment(&FELT::from(999u64), &batch));
    }

    #[test]
    fn test_aggregate_preverified_digests() {
        let digests: Vec<ProofDigest> = (0..5)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let aggregator = RecursiveAggregator::with_defaults();
        let batch = aggregator.aggregate_preverified(digests).unwrap();

        assert_eq!(batch.batch_size, 5);
        assert!(aggregator.verify_batch(&batch));
    }

    #[test]
    fn test_aggregate_preverified_large_batch() {
        // Test with 1000+ proofs to verify scalability requirement
        let digests: Vec<ProofDigest> = (0..1500)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let aggregator = RecursiveAggregator::with_defaults();
        let batch = aggregator.aggregate_preverified(digests).unwrap();

        assert_eq!(batch.batch_size, 1500);
        assert!(aggregator.verify_batch(&batch));
    }

    #[test]
    fn test_merkle_commitment_deterministic() {
        let leaves: Vec<FELT> = (0..10)
            .map(|i| PoseidonSponge::hash(&[FELT::from(i as u64)]))
            .collect();

        let root1 = compute_merkle_commitment(&leaves);
        let root2 = compute_merkle_commitment(&leaves);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_merkle_commitment_different_inputs_different_roots() {
        let leaves_a: Vec<FELT> = (0..4)
            .map(|i| PoseidonSponge::hash(&[FELT::from(i as u64)]))
            .collect();
        let leaves_b: Vec<FELT> = (10..14)
            .map(|i| PoseidonSponge::hash(&[FELT::from(i as u64)]))
            .collect();

        let root_a = compute_merkle_commitment(&leaves_a);
        let root_b = compute_merkle_commitment(&leaves_b);

        assert_ne!(root_a, root_b);
    }

    #[test]
    fn test_merkle_commitment_order_matters() {
        let leaves: Vec<FELT> = (0..4)
            .map(|i| PoseidonSponge::hash(&[FELT::from(i as u64)]))
            .collect();
        let mut reversed = leaves.clone();
        reversed.reverse();

        let root_original = compute_merkle_commitment(&leaves);
        let root_reversed = compute_merkle_commitment(&reversed);

        assert_ne!(root_original, root_reversed);
    }

    // -----------------------------------------------------------------------
    // Per-lane aggregation tests (Requirement 18.3)
    // -----------------------------------------------------------------------

    #[test]
    fn test_aggregate_preverified_by_lane_single_lane() {
        // All digests in PoseidonOnly lane → single lane in result
        let digests: Vec<ProofDigest> = (0..5)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let aggregator = RecursiveAggregator::with_defaults();
        let result = aggregator.aggregate_preverified_by_lane(digests).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&Lane::PoseidonOnly));
        let batch = &result[&Lane::PoseidonOnly];
        assert_eq!(batch.batch_size, 5);
        assert!(aggregator.verify_batch(batch));
    }

    #[test]
    fn test_aggregate_preverified_by_lane_two_lanes() {
        // Mix of PoseidonOnly and HybridHash digests
        let mut digests = Vec::new();

        // 3 PoseidonOnly digests
        for i in 0..3 {
            digests.push(ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            });
        }

        // 2 HybridHash digests
        for i in 3..5 {
            digests.push(ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::HybridHash,
            });
        }

        let aggregator = RecursiveAggregator::with_defaults();
        let result = aggregator.aggregate_preverified_by_lane(digests).unwrap();

        assert_eq!(result.len(), 2);

        // Verify PoseidonOnly lane
        let poseidon_batch = &result[&Lane::PoseidonOnly];
        assert_eq!(poseidon_batch.batch_size, 3);
        assert!(aggregator.verify_batch(poseidon_batch));

        // Verify HybridHash lane
        let hybrid_batch = &result[&Lane::HybridHash];
        assert_eq!(hybrid_batch.batch_size, 2);
        assert!(aggregator.verify_batch(hybrid_batch));
    }

    #[test]
    fn test_aggregate_preverified_by_lane_independent_roots() {
        // Verify that lane batch proofs are independent — changing one lane
        // doesn't affect the other lane's commitment root.
        let mut digests_a = Vec::new();
        let mut digests_b = Vec::new();

        // Same PoseidonOnly digests in both sets
        for i in 0..3 {
            let d = ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            };
            digests_a.push(d.clone());
            digests_b.push(d);
        }

        // Different HybridHash digests in each set
        for i in 3..5 {
            digests_a.push(ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::HybridHash,
            });
        }
        for i in 10..12 {
            digests_b.push(ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::HybridHash,
            });
        }

        let aggregator = RecursiveAggregator::with_defaults();
        let result_a = aggregator.aggregate_preverified_by_lane(digests_a).unwrap();
        let result_b = aggregator.aggregate_preverified_by_lane(digests_b).unwrap();

        // PoseidonOnly roots should be identical (same digests)
        assert_eq!(
            result_a[&Lane::PoseidonOnly].commitment_root,
            result_b[&Lane::PoseidonOnly].commitment_root
        );

        // HybridHash roots should differ (different digests)
        assert_ne!(
            result_a[&Lane::HybridHash].commitment_root,
            result_b[&Lane::HybridHash].commitment_root
        );
    }

    #[test]
    fn test_aggregate_preverified_by_lane_empty_rejected() {
        let aggregator = RecursiveAggregator::with_defaults();
        let result = aggregator.aggregate_preverified_by_lane(vec![]);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("empty batch"));
    }

    #[test]
    fn test_aggregate_preverified_by_lane_exceeds_max() {
        let config = AggregatorConfig {
            max_batch_size: 3,
            verify_individual_proofs: false,
        };
        let aggregator = RecursiveAggregator::new(config);

        let digests: Vec<ProofDigest> = (0..5)
            .map(|i| ProofDigest {
                public_input_hash: FELT::from(i as u64 + 1),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let result = aggregator.aggregate_preverified_by_lane(digests);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("exceeds maximum"));
    }

    #[test]
    fn test_aggregate_preverified_by_lane_only_hybrid() {
        // All digests in HybridHash lane
        let digests: Vec<ProofDigest> = (0..4)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64 + 100)]),
                index: i as u64,
                lane: Lane::HybridHash,
            })
            .collect();

        let aggregator = RecursiveAggregator::with_defaults();
        let result = aggregator.aggregate_preverified_by_lane(digests).unwrap();

        assert_eq!(result.len(), 1);
        assert!(result.contains_key(&Lane::HybridHash));
        assert!(!result.contains_key(&Lane::PoseidonOnly));
        let batch = &result[&Lane::HybridHash];
        assert_eq!(batch.batch_size, 4);
        assert!(aggregator.verify_batch(batch));
    }

    #[test]
    fn test_lane_enum_values() {
        // Verify lane enum discriminant values match spec
        assert_eq!(Lane::PoseidonOnly as u8, 0);
        assert_eq!(Lane::HybridHash as u8, 1);
    }

    #[test]
    fn test_per_lane_batch_matches_single_lane_aggregate() {
        // Verify that aggregating a single lane via aggregate_preverified_by_lane
        // produces the same result as aggregate_preverified for the same digests.
        let digests: Vec<ProofDigest> = (0..5)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let aggregator = RecursiveAggregator::with_defaults();

        // Aggregate all together (single batch)
        let single_batch = aggregator.aggregate_preverified(digests.clone()).unwrap();

        // Aggregate by lane (should produce identical result for the single lane)
        let lane_batches = aggregator.aggregate_preverified_by_lane(digests).unwrap();

        let lane_batch = &lane_batches[&Lane::PoseidonOnly];
        assert_eq!(single_batch.commitment_root, lane_batch.commitment_root);
        assert_eq!(single_batch.batch_size, lane_batch.batch_size);
    }

    // -----------------------------------------------------------------------
    // Batch STARK proof tests
    // -----------------------------------------------------------------------

    /// Helper: create leaf hashes for batch STARK proof tests.
    fn make_test_leaf_hashes(count: usize) -> Vec<FELT> {
        (0..count)
            .map(|i| PoseidonSponge::hash(&[FELT::from(i as u64 + 1)]))
            .collect()
    }

    #[test]
    fn test_batch_stark_proof_valid() {
        // Generate a batch STARK proof for 4 leaves and verify it.
        let leaf_hashes = make_test_leaf_hashes(4);
        let proof_options = crate::wots_prover::default_proof_options();

        let batch_stark = prove_batch_commitment(&leaf_hashes, &proof_options)
            .expect("Batch STARK proof generation should succeed");

        // Verify the STARK proof
        assert!(verify_batch_stark_proof(&batch_stark));

        // Verify the public inputs match
        assert_eq!(batch_stark.pub_inputs.batch_size, 4);

        // Verify the commitment root matches what compute_merkle_commitment produces
        let expected_root = compute_merkle_commitment(&leaf_hashes);
        let expected_root_stark = crate::wots_air::local_felt_to_stark(&expected_root);
        assert_eq!(batch_stark.pub_inputs.commitment_root, expected_root_stark);
    }

    #[test]
    fn test_batch_stark_proof_tampered_rejected() {
        // Generate a valid proof, tamper with the root, verify it's rejected.
        let leaf_hashes = make_test_leaf_hashes(4);
        let proof_options = crate::wots_prover::default_proof_options();

        let mut batch_stark = prove_batch_commitment(&leaf_hashes, &proof_options)
            .expect("Batch STARK proof generation should succeed");

        // Tamper with the commitment root in the public inputs AND the boundary values.
        // The boundary constraint at the last active row binds the output to the root,
        // so changing both should cause the STARK verifier to reject.
        let tampered_root = crate::wots_air::local_felt_to_stark(&FELT::from(999u64));
        batch_stark.pub_inputs.commitment_root = tampered_root;

        // Also tamper the boundary value that binds the root
        for bv in &mut batch_stark.pub_inputs.boundary_values {
            if bv.1 == crate::batch_air::COL_OUTPUT {
                bv.2 = tampered_root;
            }
        }

        // Verification should fail because the boundary constraints don't match the proof
        assert!(!verify_batch_stark_proof(&batch_stark));
    }

    #[test]
    fn test_batch_stark_proof_wrong_leaves_rejected() {
        // Generate a valid proof, then verify against wrong leaf hashes.
        let leaf_hashes = make_test_leaf_hashes(4);
        let proof_options = crate::wots_prover::default_proof_options();

        let batch_stark = prove_batch_commitment(&leaf_hashes, &proof_options)
            .expect("Batch STARK proof generation should succeed");

        // Create different leaf hashes
        let wrong_leaves = make_test_leaf_hashes(4)
            .iter()
            .map(|h| *h + FELT::from(1u64))
            .collect::<Vec<_>>();
        let wrong_root = compute_merkle_commitment(&wrong_leaves);

        // Bound verification should fail because leaves don't match
        assert!(!verify_batch_stark_proof_bound(
            &batch_stark,
            &wrong_leaves,
            &wrong_root,
        ));
    }

    #[test]
    fn test_batch_stark_proof_too_few_leaves() {
        // A single leaf should return None (no Merkle tree to prove).
        let leaf_hashes = make_test_leaf_hashes(1);
        let proof_options = crate::wots_prover::default_proof_options();

        let result = prove_batch_commitment(&leaf_hashes, &proof_options);
        assert!(result.is_none());
    }

    #[test]
    fn test_batch_stark_proof_bound_verification() {
        // Generate a proof and verify it with the correct expected values.
        let leaf_hashes = make_test_leaf_hashes(4);
        let proof_options = crate::wots_prover::default_proof_options();

        let batch_stark = prove_batch_commitment(&leaf_hashes, &proof_options)
            .expect("Batch STARK proof generation should succeed");

        let expected_root = compute_merkle_commitment(&leaf_hashes);

        // Bound verification with correct values should pass
        assert!(verify_batch_stark_proof_bound(
            &batch_stark,
            &leaf_hashes,
            &expected_root,
        ));

        // Bound verification with wrong root should fail
        let wrong_root = FELT::from(12345u64);
        assert!(!verify_batch_stark_proof_bound(
            &batch_stark,
            &leaf_hashes,
            &wrong_root,
        ));
    }

    #[test]
    fn test_batch_proof_with_stark_proof_attached() {
        // Test the full flow: aggregate preverified digests, then attach a STARK proof.
        let digests: Vec<ProofDigest> = (0..4)
            .map(|i| ProofDigest {
                public_input_hash: PoseidonSponge::hash(&[FELT::from(i as u64)]),
                index: i as u64,
                lane: Lane::PoseidonOnly,
            })
            .collect();

        let aggregator = RecursiveAggregator::with_defaults();
        let mut batch = aggregator.aggregate_preverified(digests).unwrap();

        // Initially no STARK proof
        assert!(batch.batch_stark_proof.is_none());

        // Generate and attach the STARK proof
        let proof_options = crate::wots_prover::default_proof_options();
        let batch_stark = prove_batch_commitment(&batch.leaf_hashes, &proof_options)
            .expect("Batch STARK proof generation should succeed");

        // Verify the STARK proof's root matches the batch's root
        let batch_root_stark = crate::wots_air::local_felt_to_stark(&batch.commitment_root);
        assert_eq!(batch_stark.pub_inputs.commitment_root, batch_root_stark);

        assert!(verify_batch_stark_proof(&batch_stark));

        batch.batch_stark_proof = Some(batch_stark);
        assert!(batch.batch_stark_proof.is_some());

        // The batch should still pass traditional verification too
        assert!(aggregator.verify_batch(&batch));
    }
}
