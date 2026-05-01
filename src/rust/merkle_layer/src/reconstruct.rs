//! SMT State Reconstruction from Data Availability (DA) Diffs.
//!
//! # Purpose
//!
//! Enables trustless state reconstruction by any network observer.
//! When a sequencer publishes batch diffs (compact uint64 index vectors) as calldata,
//! any observer can reconstruct the full SMT state from an empty tree by replaying
//! all accumulated diffs, then verify the resulting root matches the on-chain root.
//!
//! # Usage
//!
//! ```rust
//! use zk_pqc_merkle_layer::reconstruct::SmtReconstructor;
//! use zk_pqc_hash_layer::traits::PoseidonHash;
//! use zk_pqc_hash_layer::constants::FELT;
//!
//! let hasher = PoseidonHash;
//! let mut reconstructor = SmtReconstructor::new(hasher);
//!
//! // Apply batch diffs (each inner Vec is one batch's consumed indices)
//! let batch_diffs = vec![
//!     vec![0u64, 1, 2],       // batch 1
//!     vec![10u64, 11, 12],    // batch 2
//! ];
//!
//! reconstructor.apply_diffs(&batch_diffs).unwrap();
//!
//! // Verify against expected on-chain root
//! let on_chain_root = reconstructor.root();
//! assert!(reconstructor.verify_against_root(on_chain_root));
//! ```
//!
//! # Requirements
//!
//! - Validates: Requirements 17.3, 17.4
//! - Any observer can reconstruct the SMT state from published diffs
//! - Resulting root must match the on-chain root for consistency verification

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;

use crate::smt::{SmtError, SparseMerkleTree};

/// Error types for SMT reconstruction operations.
#[derive(Debug, Clone, PartialEq)]
pub enum ReconstructError {
    /// An index appeared in multiple batches (duplicate consumption).
    DuplicateIndex { index: u64, batch: usize },
    /// Root mismatch after reconstruction.
    RootMismatch { expected: FELT, reconstructed: FELT },
    /// Underlying SMT error during reconstruction.
    SmtError(SmtError),
}

impl std::fmt::Display for ReconstructError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReconstructError::DuplicateIndex { index, batch } => {
                write!(
                    f,
                    "Duplicate index {} found in batch {} (already consumed in a prior batch)",
                    index, batch
                )
            }
            ReconstructError::RootMismatch {
                expected,
                reconstructed,
            } => {
                write!(
                    f,
                    "Root mismatch: expected {:?}, reconstructed {:?}",
                    expected, reconstructed
                )
            }
            ReconstructError::SmtError(e) => write!(f, "SMT error during reconstruction: {}", e),
        }
    }
}

impl std::error::Error for ReconstructError {}

impl From<SmtError> for ReconstructError {
    fn from(e: SmtError) -> Self {
        ReconstructError::SmtError(e)
    }
}

/// SMT State Reconstructor from DA Diffs.
///
/// Applies accumulated DA diffs (sequences of uint64 index vectors from batches)
/// to an initially empty SMT and verifies the resulting root matches the expected
/// on-chain root. This enables trustless state reconstruction by any network observer.
///
/// # Invariants
///
/// 1. Each index may only appear once across all batches (no duplicate consumption).
/// 2. Batches are applied sequentially in order.
/// 3. The final root must match the on-chain root for the state to be valid.
pub struct SmtReconstructor<H: HashFunction<Digest = FELT> + Clone> {
    /// The underlying SMT being reconstructed.
    smt: SparseMerkleTree<H>,
    /// Number of batches applied so far.
    batches_applied: usize,
    /// Total number of indices consumed across all batches.
    total_indices_consumed: usize,
}

impl<H: HashFunction<Digest = FELT> + Clone> SmtReconstructor<H> {
    /// Creates a new reconstructor starting from an empty SMT.
    pub fn new(hasher: H) -> Self {
        Self {
            smt: SparseMerkleTree::new(hasher),
            batches_applied: 0,
            total_indices_consumed: 0,
        }
    }

    /// Returns the current reconstructed SMT root.
    pub fn root(&self) -> FELT {
        self.smt.root()
    }

    /// Returns the number of batches applied so far.
    pub fn batches_applied(&self) -> usize {
        self.batches_applied
    }

    /// Returns the total number of indices consumed across all batches.
    pub fn total_indices_consumed(&self) -> usize {
        self.total_indices_consumed
    }

    /// Applies a single batch diff to the SMT.
    ///
    /// Each batch diff is a vector of uint64 indices that were consumed in that batch.
    /// Returns an error if any index was already consumed in a prior batch.
    ///
    /// # Arguments
    /// * `batch` - Vector of indices consumed in this batch
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(ReconstructError::DuplicateIndex)` if an index was already consumed
    pub fn apply_batch(&mut self, batch: &[u64]) -> Result<(), ReconstructError> {
        let batch_number = self.batches_applied;

        for &index in batch {
            match self.smt.mark_consumed(index) {
                Ok(()) => {}
                Err(SmtError::AlreadyConsumed { index }) => {
                    return Err(ReconstructError::DuplicateIndex {
                        index,
                        batch: batch_number,
                    });
                }
                Err(e) => return Err(ReconstructError::SmtError(e)),
            }
        }

        self.batches_applied += 1;
        self.total_indices_consumed += batch.len();
        Ok(())
    }

    /// Applies multiple batch diffs sequentially to the SMT.
    ///
    /// Each inner Vec<u64> represents one batch's consumed indices.
    /// Batches are applied in order. Returns an error if any index appears
    /// in multiple batches (duplicate consumption).
    ///
    /// # Arguments
    /// * `diffs` - Sequence of batch diffs to apply
    ///
    /// # Returns
    /// * `Ok(())` on success
    /// * `Err(ReconstructError::DuplicateIndex)` if duplicate found
    pub fn apply_diffs(&mut self, diffs: &[Vec<u64>]) -> Result<(), ReconstructError> {
        for batch in diffs {
            self.apply_batch(batch)?;
        }
        Ok(())
    }

    /// Verifies the reconstructed root matches the expected on-chain root.
    ///
    /// # Arguments
    /// * `expected_root` - The on-chain SMT root to verify against
    ///
    /// # Returns
    /// * `true` if the reconstructed root matches the expected root
    /// * `false` otherwise
    pub fn verify_against_root(&self, expected_root: FELT) -> bool {
        self.root() == expected_root
    }

    /// Applies diffs and verifies against an expected root in one operation.
    ///
    /// Convenience method that combines `apply_diffs` and `verify_against_root`.
    ///
    /// # Arguments
    /// * `diffs` - Sequence of batch diffs to apply
    /// * `expected_root` - The on-chain SMT root to verify against
    ///
    /// # Returns
    /// * `Ok(true)` if reconstruction succeeds and root matches
    /// * `Ok(false)` if reconstruction succeeds but root doesn't match
    /// * `Err(ReconstructError)` if reconstruction fails (e.g., duplicate index)
    pub fn reconstruct_and_verify(
        &mut self,
        diffs: &[Vec<u64>],
        expected_root: FELT,
    ) -> Result<bool, ReconstructError> {
        self.apply_diffs(diffs)?;
        Ok(self.verify_against_root(expected_root))
    }

    /// Checks if a specific index has been consumed in the reconstructed state.
    pub fn is_consumed(&self, index: u64) -> bool {
        self.smt.is_consumed(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    #[test]
    fn test_empty_diffs_produce_empty_root() {
        let hasher = PoseidonHash;
        let reconstructor = SmtReconstructor::new(hasher);

        // Empty reconstructor should have the same root as an empty SMT
        let empty_smt = SparseMerkleTree::new(hasher);
        assert_eq!(reconstructor.root(), empty_smt.root());
        assert_eq!(reconstructor.batches_applied(), 0);
        assert_eq!(reconstructor.total_indices_consumed(), 0);
    }

    #[test]
    fn test_single_batch_matches_direct_construction() {
        let hasher = PoseidonHash;
        let mut reconstructor = SmtReconstructor::new(hasher);

        // Apply a single batch
        let batch = vec![5u64, 10, 15, 20];
        reconstructor.apply_batch(&batch).unwrap();

        // Build the same state directly
        let mut direct_smt = SparseMerkleTree::new(hasher);
        for &idx in &batch {
            direct_smt.mark_consumed(idx).unwrap();
        }

        // Roots must match
        assert_eq!(reconstructor.root(), direct_smt.root());
        assert!(reconstructor.verify_against_root(direct_smt.root()));
        assert_eq!(reconstructor.batches_applied(), 1);
        assert_eq!(reconstructor.total_indices_consumed(), 4);
    }

    #[test]
    fn test_multiple_batches_match_sequential_construction() {
        let hasher = PoseidonHash;
        let mut reconstructor = SmtReconstructor::new(hasher);

        // Apply multiple batches
        let diffs = vec![
            vec![0u64, 1, 2],
            vec![100u64, 101, 102],
            vec![1000u64, 1001],
        ];
        reconstructor.apply_diffs(&diffs).unwrap();

        // Build the same state directly (sequential insertion)
        let mut direct_smt = SparseMerkleTree::new(hasher);
        for batch in &diffs {
            for &idx in batch {
                direct_smt.mark_consumed(idx).unwrap();
            }
        }

        // Roots must match
        assert_eq!(reconstructor.root(), direct_smt.root());
        assert!(reconstructor.verify_against_root(direct_smt.root()));
        assert_eq!(reconstructor.batches_applied(), 3);
        assert_eq!(reconstructor.total_indices_consumed(), 8);
    }

    #[test]
    fn test_duplicate_index_in_different_batches_errors() {
        let hasher = PoseidonHash;
        let mut reconstructor = SmtReconstructor::new(hasher);

        // First batch succeeds
        reconstructor.apply_batch(&[1, 2, 3]).unwrap();

        // Second batch has index 2 which was already consumed
        let result = reconstructor.apply_batch(&[4, 2, 5]);
        assert!(result.is_err());
        match result {
            Err(ReconstructError::DuplicateIndex { index, batch }) => {
                assert_eq!(index, 2);
                assert_eq!(batch, 1); // second batch (0-indexed)
            }
            _ => panic!("Expected DuplicateIndex error"),
        }
    }

    #[test]
    fn test_duplicate_index_within_same_batch_errors() {
        let hasher = PoseidonHash;
        let mut reconstructor = SmtReconstructor::new(hasher);

        // Batch with duplicate index
        let result = reconstructor.apply_batch(&[1, 2, 3, 2]);
        assert!(result.is_err());
        match result {
            Err(ReconstructError::DuplicateIndex { index, batch }) => {
                assert_eq!(index, 2);
                assert_eq!(batch, 0);
            }
            _ => panic!("Expected DuplicateIndex error"),
        }
    }

    #[test]
    fn test_root_verification_against_expected() {
        let hasher = PoseidonHash;
        let mut reconstructor = SmtReconstructor::new(hasher);

        let diffs = vec![vec![42u64, 43, 44]];
        reconstructor.apply_diffs(&diffs).unwrap();

        // Correct root should verify
        let correct_root = reconstructor.root();
        assert!(reconstructor.verify_against_root(correct_root));

        // Wrong root should not verify
        let wrong_root = FELT::from(0xDEADBEEFu64);
        assert!(!reconstructor.verify_against_root(wrong_root));
    }

    #[test]
    fn test_reconstruct_and_verify_convenience() {
        let hasher = PoseidonHash;

        // Build expected root directly
        let mut direct_smt = SparseMerkleTree::new(hasher);
        direct_smt.mark_consumed(10).unwrap();
        direct_smt.mark_consumed(20).unwrap();
        direct_smt.mark_consumed(30).unwrap();
        let expected_root = direct_smt.root();

        // Use convenience method
        let mut reconstructor = SmtReconstructor::new(hasher);
        let diffs = vec![vec![10u64, 20], vec![30u64]];
        let result = reconstructor.reconstruct_and_verify(&diffs, expected_root);
        assert_eq!(result, Ok(true));
    }

    #[test]
    fn test_reconstruct_and_verify_mismatch() {
        let hasher = PoseidonHash;
        let mut reconstructor = SmtReconstructor::new(hasher);

        let diffs = vec![vec![1u64, 2, 3]];
        let wrong_root = FELT::from(12345u64);
        let result = reconstructor.reconstruct_and_verify(&diffs, wrong_root);
        assert_eq!(result, Ok(false));
    }

    #[test]
    fn test_is_consumed_after_reconstruction() {
        let hasher = PoseidonHash;
        let mut reconstructor = SmtReconstructor::new(hasher);

        let diffs = vec![vec![5u64, 10, 15], vec![20u64, 25]];
        reconstructor.apply_diffs(&diffs).unwrap();

        // Consumed indices should be reported
        assert!(reconstructor.is_consumed(5));
        assert!(reconstructor.is_consumed(10));
        assert!(reconstructor.is_consumed(15));
        assert!(reconstructor.is_consumed(20));
        assert!(reconstructor.is_consumed(25));

        // Non-consumed indices should not be reported
        assert!(!reconstructor.is_consumed(0));
        assert!(!reconstructor.is_consumed(6));
        assert!(!reconstructor.is_consumed(100));
    }

    #[test]
    fn test_empty_batches_are_valid() {
        let hasher = PoseidonHash;
        let mut reconstructor = SmtReconstructor::new(hasher);

        // Empty batches should be fine
        let diffs: Vec<Vec<u64>> = vec![vec![], vec![1, 2], vec![]];
        reconstructor.apply_diffs(&diffs).unwrap();

        assert_eq!(reconstructor.batches_applied(), 3);
        assert_eq!(reconstructor.total_indices_consumed(), 2);

        // Verify root matches direct construction
        let mut direct_smt = SparseMerkleTree::new(hasher);
        direct_smt.mark_consumed(1).unwrap();
        direct_smt.mark_consumed(2).unwrap();
        assert_eq!(reconstructor.root(), direct_smt.root());
    }
}
