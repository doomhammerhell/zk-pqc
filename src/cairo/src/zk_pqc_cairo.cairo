/// PCA (Proof-Carrying Authorization) Verifier Contract.
///
/// Replaces the original stub with a real verification interface that accepts
/// STARK proofs bound to a canonical message hash and commitment root.
/// On-chain cost is O(|π|) instead of O(|σ|).
///
/// Requirements: 10.1, 10.2, 10.3, 10.4

#[starknet::interface]
pub trait IPCAVerifier<TState> {
    /// Verify a single STARK authorization proof.
    ///
    /// The proof must be bound to the given `message_hash` and `commitment_root`.
    /// Returns true only when the proof is valid and bindings match.
    fn verify_authorization(
        self: @TState,
        proof: Span<felt252>,
        message_hash: felt252,
        commitment_root: felt252,
        index: u64,
    ) -> bool;

    /// Submit a batch of proofs with SMT state diff.
    ///
    /// Verifies the batch proof, updates the SMT root, and records consumed indices.
    fn submit_batch(
        ref self: TState,
        batch_proof: Span<felt252>,
        smt_diff: Span<u64>,
        new_smt_root: felt252,
    );

    /// Read the current SMT root.
    fn get_smt_root(self: @TState) -> felt252;

    /// Check whether a given index has been consumed.
    fn is_index_consumed(self: @TState, index: u64) -> bool;
}

#[starknet::contract]
mod PCAVerifier {
    use starknet::storage::{
        StoragePointerReadAccess, StoragePointerWriteAccess,
        Map, StorageMapReadAccess, StorageMapWriteAccess,
    };

    #[storage]
    struct Storage {
        smt_root: felt252,
        consumed_indices: Map<u64, bool>,
        batch_count: u64,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AuthorizationVerified: AuthorizationVerified,
        BatchSubmitted: BatchSubmitted,
    }

    #[derive(Drop, starknet::Event)]
    struct AuthorizationVerified {
        message_hash: felt252,
        commitment_root: felt252,
        index: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct BatchSubmitted {
        batch_id: u64,
        new_smt_root: felt252,
        num_indices: u32,
    }

    #[abi(embed_v0)]
    impl PCAVerifierImpl of super::IPCAVerifier<ContractState> {
        fn verify_authorization(
            self: @ContractState,
            proof: Span<felt252>,
            message_hash: felt252,
            commitment_root: felt252,
            index: u64,
        ) -> bool {
            if proof.len() == 0 {
                return false;
            }
            if message_hash == 0 || commitment_root == 0 {
                return false;
            }
            if self.consumed_indices.read(index) {
                return false;
            }
            if proof.len() < 3 {
                return false;
            }

            let proof_message = *proof.at(0);
            let proof_root = *proof.at(1);

            if proof_message != message_hash {
                return false;
            }
            if proof_root != commitment_root {
                return false;
            }

            verify_stark_proof(proof, message_hash, commitment_root)
        }

        fn submit_batch(
            ref self: ContractState,
            batch_proof: Span<felt252>,
            smt_diff: Span<u64>,
            new_smt_root: felt252,
        ) {
            assert(batch_proof.len() >= 3, 'batch proof too short');
            assert(smt_diff.len() > 0, 'empty smt diff');
            assert(new_smt_root != 0, 'invalid new smt root');

            let mut i: u32 = 0;
            while i < smt_diff.len() {
                let idx = *smt_diff.at(i);
                assert(!self.consumed_indices.read(idx), 'index already consumed');
                i += 1;
            };

            let proof_root = *batch_proof.at(1);
            assert(proof_root == new_smt_root, 'proof root mismatch');

            let proof_message = *batch_proof.at(0);
            let valid = verify_stark_proof(batch_proof, proof_message, new_smt_root);
            assert(valid, 'invalid batch proof');

            let mut j: u32 = 0;
            while j < smt_diff.len() {
                let idx = *smt_diff.at(j);
                self.consumed_indices.write(idx, true);
                j += 1;
            };

            self.smt_root.write(new_smt_root);

            let batch_id = self.batch_count.read() + 1;
            self.batch_count.write(batch_id);

            self.emit(
                BatchSubmitted {
                    batch_id,
                    new_smt_root,
                    num_indices: smt_diff.len(),
                },
            );
        }

        fn get_smt_root(self: @ContractState) -> felt252 {
            self.smt_root.read()
        }

        fn is_index_consumed(self: @ContractState, index: u64) -> bool {
            self.consumed_indices.read(index)
        }
    }

    /// Verify a STARK proof by checking the commitment hash.
    ///
    /// Proof layout:
    ///   proof[0] = bound message_hash
    ///   proof[1] = bound commitment_root
    ///   proof[2..n-1] = STARK proof data
    ///   proof[n-1] = verification tag
    ///
    /// In production this invokes a full STARK verifier; here we use a
    /// Poseidon-based commitment check that will be replaced in Phase 3.
    fn verify_stark_proof(
        proof: Span<felt252>,
        message_hash: felt252,
        commitment_root: felt252,
    ) -> bool {
        if proof.len() < 3 {
            return false;
        }

        let mut hash_input: Array<felt252> = ArrayTrait::new();
        hash_input.append(message_hash);
        hash_input.append(commitment_root);

        let mut i: u32 = 2;
        while i < proof.len() - 1 {
            hash_input.append(*proof.at(i));
            i += 1;
        };

        let verification_hash = zk_pqc_cairo::sponge::hash(hash_input.span());
        let tag = *proof.at(proof.len() - 1);
        verification_hash == tag
    }

    #[cfg(test)]
    mod tests {
        use super::PCAVerifierImpl;
        use zk_pqc_cairo::sponge::hash;

        fn build_valid_proof(
            message_hash: felt252, commitment_root: felt252, proof_data: Span<felt252>,
        ) -> Array<felt252> {
            let mut hash_input: Array<felt252> = ArrayTrait::new();
            hash_input.append(message_hash);
            hash_input.append(commitment_root);
            let mut i: u32 = 0;
            while i < proof_data.len() {
                hash_input.append(*proof_data.at(i));
                i += 1;
            };
            let tag = hash(hash_input.span());

            let mut proof: Array<felt252> = ArrayTrait::new();
            proof.append(message_hash);
            proof.append(commitment_root);
            let mut j: u32 = 0;
            while j < proof_data.len() {
                proof.append(*proof_data.at(j));
                j += 1;
            };
            proof.append(tag);
            proof
        }

        fn setup() -> super::ContractState {
            super::contract_state_for_testing()
        }

        // --- verify_authorization: valid proof acceptance (Req 10.2) ---

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_valid_proof_accepted() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = build_valid_proof(msg, root, array![42, 99, 7].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 0);
            assert(valid, 'valid proof should pass');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_minimal_valid_proof() {
            let state = setup();
            let msg: felt252 = 0x42;
            let root: felt252 = 0x99;
            let proof = build_valid_proof(msg, root, array![].span());
            assert(proof.len() == 3, 'minimal proof len wrong');
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 0);
            assert(valid, 'minimal proof should pass');
        }

        // --- verify_authorization: invalid proof rejection (Req 10.3) ---

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_invalid_proof_rejected() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = array![msg, root, 42, 99, 0xDEAD];
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 0);
            assert(!valid, 'invalid proof should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_empty_proof_rejected() {
            let state = setup();
            let proof: Array<felt252> = ArrayTrait::new();
            let valid = PCAVerifierImpl::verify_authorization(
                @state, proof.span(), 0x1234, 0xABCD, 0,
            );
            assert(!valid, 'empty proof should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_too_short_proof_rejected() {
            let state = setup();
            let proof = array![0x1234, 0xABCD];
            let valid = PCAVerifierImpl::verify_authorization(
                @state, proof.span(), 0x1234, 0xABCD, 0,
            );
            assert(!valid, 'short proof should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_zero_message_hash_rejected() {
            let state = setup();
            let root: felt252 = 0xABCD;
            let proof = build_valid_proof(0, root, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), 0, root, 0);
            assert(!valid, 'zero msg hash should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_zero_commitment_root_rejected() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let proof = build_valid_proof(msg, 0, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, 0, 0);
            assert(!valid, 'zero root should fail');
        }

        // --- verify_authorization: message/root mismatch (Req 10.3, 10.4) ---

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_message_mismatch_rejected() {
            let state = setup();
            let proof = build_valid_proof(0x1111, 0xABCD, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(
                @state, proof.span(), 0x2222, 0xABCD, 0,
            );
            assert(!valid, 'msg mismatch should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_root_mismatch_rejected() {
            let state = setup();
            let proof = build_valid_proof(0x1234, 0xAAAA, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(
                @state, proof.span(), 0x1234, 0xBBBB, 0,
            );
            assert(!valid, 'root mismatch should fail');
        }

        // --- verify_authorization: different data produces different tags ---

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_different_proof_data_different_tag() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof_a = build_valid_proof(msg, root, array![1, 2, 3].span());
            let proof_b = build_valid_proof(msg, root, array![4, 5, 6].span());

            let va = PCAVerifierImpl::verify_authorization(@state, proof_a.span(), msg, root, 0);
            let vb = PCAVerifierImpl::verify_authorization(@state, proof_b.span(), msg, root, 1);
            assert(va, 'proof A should pass');
            assert(vb, 'proof B should pass');

            let tag_a = *proof_a.at(proof_a.len() - 1);
            let tag_b = *proof_b.at(proof_b.len() - 1);
            assert(tag_a != tag_b, 'different data same tag');
        }

        // --- submit_batch tests ---

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_submit_batch_marks_indices_consumed() {
            let mut state = setup();
            let new_root: felt252 = 0xFEED;
            let smt_diff = array![10_u64, 20_u64, 30_u64];
            let proof = build_valid_proof(0x1234, new_root, array![77].span());

            PCAVerifierImpl::submit_batch(ref state, proof.span(), smt_diff.span(), new_root);

            assert(PCAVerifierImpl::is_index_consumed(@state, 10), 'idx 10 consumed');
            assert(PCAVerifierImpl::is_index_consumed(@state, 20), 'idx 20 consumed');
            assert(PCAVerifierImpl::is_index_consumed(@state, 30), 'idx 30 consumed');
            assert(!PCAVerifierImpl::is_index_consumed(@state, 99), 'idx 99 free');
            assert(PCAVerifierImpl::get_smt_root(@state) == new_root, 'smt root update');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('index already consumed',))]
        fn test_pca_submit_batch_rejects_consumed_index() {
            let mut state = setup();
            let r1: felt252 = 0xAAAA;
            let r2: felt252 = 0xBBBB;

            let p1 = build_valid_proof(0x11, r1, array![1].span());
            PCAVerifierImpl::submit_batch(ref state, p1.span(), array![5_u64].span(), r1);

            let p2 = build_valid_proof(0x22, r2, array![2].span());
            PCAVerifierImpl::submit_batch(ref state, p2.span(), array![5_u64].span(), r2);
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('invalid batch proof',))]
        fn test_pca_submit_batch_rejects_invalid_proof() {
            let mut state = setup();
            let new_root: felt252 = 0xFEED;
            let bad_proof = array![0x1234, new_root, 42, 0xDEAD];
            PCAVerifierImpl::submit_batch(
                ref state, bad_proof.span(), array![1_u64].span(), new_root,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('proof root mismatch',))]
        fn test_pca_submit_batch_rejects_root_mismatch() {
            let mut state = setup();
            let proof = build_valid_proof(0x11, 0xBBBB, array![1].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), 0xAAAA);
        }

        // --- Cross-concern: consumed index blocks verify_authorization ---

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_consumed_index_blocks_verify() {
            let mut state = setup();
            let batch_root: felt252 = 0xFEED;
            let bp = build_valid_proof(0x11, batch_root, array![1].span());
            PCAVerifierImpl::submit_batch(ref state, bp.span(), array![7_u64].span(), batch_root);

            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = build_valid_proof(msg, root, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 7);
            assert(!valid, 'consumed idx should fail');
        }
    }
}
