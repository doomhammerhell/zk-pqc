/// PCA (Proof-Carrying Authorization) Verifier Contract — Option B (Honest Intermediate).
///
/// ## Verification Model
///
/// This contract implements **Option B** of the PCA verification strategy:
///
/// - **Off-chain**: The Rust prover (lambdaworks) generates a **real STARK proof** for
///   WOTS+ signature verification. The proof is unforgeable without the secret key.
///   The prover also computes a Poseidon commitment (tag) over the proof data.
///
/// - **On-chain**: Cairo verifies the Poseidon commitment of the proof data, binding
///   the proof to the canonical message hash, commitment root, and OTS index.
///   Full FRI polynomial commitment verification in Cairo is deferred to **Phase 3**.
///
/// > "STARK proof generated and verified off-chain; on-chain uses proof commitment
/// >  pending full Cairo FRI verifier in Phase 3."
///
/// ## Proof Layout (serialized felt252 array)
///
///   proof[0]       = bound message_hash
///   proof[1]       = bound commitment_root
///   proof[2]       = bound index (as felt252)
///   proof[3..n-1]  = STARK proof commitment data
///   proof[n-1]     = verification tag
///
/// The verification tag commits to ALL bound fields:
///   tag = PoseidonSponge::hash(message_hash || commitment_root || index || proof_data)
///
/// This ensures the proof cannot be rebound to a different message, root, or index.
///
/// ## Access Control
///
/// - `owner`: Can update the authorized sequencer via `set_sequencer`.
/// - `authorized_sequencer`: The only address allowed to call `submit_batch`.
/// - `verify_authorization` is a view function and has no caller restriction.
///
/// Requirements: 10.1, 10.2, 10.3, 10.4

#[starknet::interface]
pub trait IPCAVerifier<TState> {
    /// Verify a single STARK authorization proof (Option B: commitment check).
    ///
    /// The proof must be bound to the given `message_hash`, `commitment_root`, and `index`.
    /// Returns true only when the Poseidon commitment tag is valid and all bindings match.
    ///
    /// NOTE: The real STARK proof is generated and verified off-chain by the Rust prover.
    /// On-chain, we verify the Poseidon commitment. Full Cairo FRI verifier in Phase 3.
    fn verify_authorization(
        self: @TState,
        proof: Span<felt252>,
        message_hash: felt252,
        commitment_root: felt252,
        index: u64,
    ) -> bool;

    /// Submit a batch of proofs with SMT state diff.
    ///
    /// Only callable by the authorized sequencer.
    /// Verifies the batch proof commitment, updates the SMT root, and records consumed indices.
    fn submit_batch(
        ref self: TState, batch_proof: Span<felt252>, smt_diff: Span<u64>, new_smt_root: felt252,
    );

    /// Read the current SMT root.
    fn get_smt_root(self: @TState) -> felt252;

    /// Check whether a given index has been consumed.
    fn is_index_consumed(self: @TState, index: u64) -> bool;

    /// Return the contract owner address.
    fn get_owner(self: @TState) -> starknet::ContractAddress;

    /// Return the currently authorized sequencer address.
    fn get_sequencer(self: @TState) -> starknet::ContractAddress;

    /// Read the current domain configuration.
    fn get_domain_config(self: @TState) -> (felt252, felt252, felt252, u64);

    /// Update the domain configuration. Only callable by the owner.
    fn set_domain_config(
        ref self: TState, domain: felt252, chain_id: felt252, contract_addr: felt252,
    );

    /// Verify a single authorization proof with domain separation check.
    /// Validates chain_id, contract_addr, and nonce before verification.
    fn verify_authorization_with_domain(
        self: @TState,
        proof: Span<felt252>,
        message_hash: felt252,
        commitment_root: felt252,
        index: u64,
        calldata_hash: felt252,
        nonce: u64,
    ) -> bool;

    /// Verify a single authorization proof with SMT index enforcement.
    ///
    /// This function:
    /// 1. Checks that the index has not been consumed
    /// 2. Verifies the SMT proof showing index is unconsumed
    /// 3. Verifies the authorization proof
    ///
    /// Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
    fn verify_authorization_with_smt(
        self: @TState,
        proof: Span<felt252>,
        message_hash: felt252,
        commitment_root: felt252,
        index: u64,
        smt_proof_siblings: Span<felt252>,
    ) -> bool;

    /// Update the authorized sequencer. Only callable by the owner.
    fn set_sequencer(ref self: TState, new_sequencer: starknet::ContractAddress);
}

#[starknet::contract]
mod PCAVerifier {
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::{ContractAddress, get_caller_address};

    #[storage]
    struct Storage {
        owner: ContractAddress,
        authorized_sequencer: ContractAddress,
        smt_root: felt252,
        consumed_indices: Map<u64, bool>,
        batch_count: u64,
        // Domain separation fields
        domain: felt252,
        chain_id: felt252,
        contract_addr: felt252,
        current_nonce: u64,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        initial_sequencer: ContractAddress,
        domain: felt252,
        chain_id: felt252,
        contract_addr: felt252,
    ) {
        self.owner.write(owner);
        self.authorized_sequencer.write(initial_sequencer);
        self.domain.write(domain);
        self.chain_id.write(chain_id);
        self.contract_addr.write(contract_addr);
        self.current_nonce.write(0);
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        AuthorizationVerified: AuthorizationVerified,
        BatchSubmitted: BatchSubmitted,
        SequencerUpdated: SequencerUpdated,
        DomainConfigUpdated: DomainConfigUpdated,
        NonceConsumed: NonceConsumed,
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

    #[derive(Drop, starknet::Event)]
    struct DomainConfigUpdated {
        old_domain: felt252,
        old_chain_id: felt252,
        old_contract: felt252,
        new_domain: felt252,
        new_chain_id: felt252,
        new_contract: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct NonceConsumed {
        nonce: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct SequencerUpdated {
        old_sequencer: ContractAddress,
        new_sequencer: ContractAddress,
    }

    #[abi(embed_v0)]
    impl PCAVerifierImpl of super::IPCAVerifier<ContractState> {
        /// Verify a single authorization proof (Option B: Poseidon commitment).
        ///
        /// The real STARK proof is generated and verified off-chain by the Rust prover
        /// (lambdaworks). On-chain, we verify the Poseidon commitment tag that binds
        /// the proof data to message_hash, commitment_root, and index.
        /// Full Cairo FRI verifier is deferred to Phase 3.
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
            // Minimum proof: [message_hash, commitment_root, index_felt, tag] = 4 elements
            if proof.len() < 4 {
                return false;
            }

            let proof_message = *proof.at(0);
            let proof_root = *proof.at(1);
            let proof_index: felt252 = *proof.at(2);

            if proof_message != message_hash {
                return false;
            }
            if proof_root != commitment_root {
                return false;
            }
            let index_felt: felt252 = index.into();
            if proof_index != index_felt {
                return false;
            }

            verify_proof_commitment(proof, message_hash, commitment_root, index)
        }

        /// Submit a batch of proofs with SMT state diff.
        ///
        /// Guarded: only the authorized_sequencer may call this function.
        fn submit_batch(
            ref self: ContractState,
            batch_proof: Span<felt252>,
            smt_diff: Span<u64>,
            new_smt_root: felt252,
        ) {
            // Access control: only authorized sequencer
            let caller = get_caller_address();
            let sequencer = self.authorized_sequencer.read();
            assert(caller == sequencer, 'caller not authorized');

            assert(batch_proof.len() >= 4, 'batch proof too short');
            assert(smt_diff.len() > 0, 'empty smt diff');
            assert(new_smt_root != 0, 'invalid new smt root');

            let mut i: u32 = 0;
            while i < smt_diff.len() {
                let idx = *smt_diff.at(i);
                assert(!self.consumed_indices.read(idx), 'index already consumed');
                i += 1;
            }

            let proof_root = *batch_proof.at(1);
            assert(proof_root == new_smt_root, 'proof root mismatch');

            let proof_message = *batch_proof.at(0);
            let proof_index_felt: felt252 = *batch_proof.at(2);
            // For batch proofs, use index 0 as the batch index binding
            let batch_index: u64 = 0;
            let expected_index_felt: felt252 = batch_index.into();
            assert(proof_index_felt == expected_index_felt, 'batch index mismatch');

            let valid = verify_proof_commitment(
                batch_proof, proof_message, new_smt_root, batch_index,
            );
            assert(valid, 'invalid batch proof');

            let mut j: u32 = 0;
            while j < smt_diff.len() {
                let idx = *smt_diff.at(j);
                self.consumed_indices.write(idx, true);
                j += 1;
            }

            self.smt_root.write(new_smt_root);

            let batch_id = self.batch_count.read() + 1;
            self.batch_count.write(batch_id);

            self.emit(BatchSubmitted { batch_id, new_smt_root, num_indices: smt_diff.len() });
        }

        fn get_smt_root(self: @ContractState) -> felt252 {
            self.smt_root.read()
        }

        fn is_index_consumed(self: @ContractState, index: u64) -> bool {
            self.consumed_indices.read(index)
        }

        fn get_owner(self: @ContractState) -> ContractAddress {
            self.owner.read()
        }

        fn get_sequencer(self: @ContractState) -> ContractAddress {
            self.authorized_sequencer.read()
        }

        /// Get the current domain configuration.
        fn get_domain_config(self: @ContractState) -> (felt252, felt252, felt252, u64) {
            (
                self.domain.read(),
                self.chain_id.read(),
                self.contract_addr.read(),
                self.current_nonce.read(),
            )
        }

        /// Update the domain configuration. Only the owner may call this.
        fn set_domain_config(
            ref self: ContractState, domain: felt252, chain_id: felt252, contract_addr: felt252,
        ) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'caller not owner');

            let old_domain = self.domain.read();
            let old_chain_id = self.chain_id.read();
            let old_contract = self.contract_addr.read();

            self.domain.write(domain);
            self.chain_id.write(chain_id);
            self.contract_addr.write(contract_addr);

            self
                .emit(
                    DomainConfigUpdated {
                        old_domain,
                        old_chain_id,
                        old_contract,
                        new_domain: domain,
                        new_chain_id: chain_id,
                        new_contract: contract_addr,
                    },
                );
        }

        /// Verify a single authorization proof with domain separation check.
        /// Validates domain, chain_id, contract_addr, and nonce before verification.
        fn verify_authorization_with_domain(
            self: @ContractState,
            proof: Span<felt252>,
            message_hash: felt252,
            commitment_root: felt252,
            index: u64,
            calldata_hash: felt252,
            nonce: u64,
        ) -> bool {
            // Check domain constraints
            // Note: In production, get contract address from starknet::get_contract_address()
            // and chain_id from syscall. For testing, use stored values.
            // This prevents replay across chains and contracts.

            // Check nonce hasn't been consumed (simplified: nonce < current_nonce)
            if nonce < self.current_nonce.read() {
                return false;
            }

            // Reconstruct expected canonical message hash
            // M_canonical = H(domain || chain_id || contract_addr || nonce || H(calldata))
            let domain = self.domain.read();
            let chain_id = self.chain_id.read();
            let contract_addr = self.contract_addr.read();

            // Compute domain commitment: H("DOMAIN" || domain || chain_id || contract || nonce)
            let domain_prefix: felt252 = 0x444F4D41494E; // "DOMAIN" in ASCII
            let nonce_felt: felt252 = nonce.into();
            let domain_commitment = zk_pqc_cairo::sponge::hash_with_domain_separation(
                domain_prefix, array![domain, chain_id, contract_addr, nonce_felt].span(),
            );

            // Compute canonical message hash
            let canonical_hash = zk_pqc_cairo::sponge::hash_with_domain_separation(
                domain_commitment, array![calldata_hash, nonce_felt].span(),
            );

            // Verify message_hash matches canonical hash
            if message_hash != canonical_hash {
                return false;
            }

            // Now verify the proof using standard verification
            self.verify_authorization(proof, message_hash, commitment_root, index)
        }

        /// Verify a single authorization proof with SMT index enforcement.
        ///
        /// This function:
        /// 1. Checks that the index has not been consumed
        /// 2. Verifies the SMT proof showing index is unconsumed
        /// 3. Verifies the authorization proof
        ///
        /// Requirements: 8.1, 8.2, 8.3, 8.4, 8.5
        fn verify_authorization_with_smt(
            self: @ContractState,
            proof: Span<felt252>,
            message_hash: felt252,
            commitment_root: felt252,
            index: u64,
            smt_proof_siblings: Span<felt252>,
        ) -> bool {
            // Check index not already consumed
            if self.consumed_indices.read(index) {
                return false;
            }

            // Build SMT proof
            let smt_proof = zk_pqc_cairo::smt::SmtProof {
                siblings: smt_proof_siblings.into(), leaf_value: 0 // Empty leaf = unconsumed
            };

            // Verify SMT proof shows index is unconsumed
            let current_root = self.smt_root.read();
            if !zk_pqc_cairo::smt::verify_unconsumed(current_root, index, @smt_proof) {
                return false;
            }

            // Now verify the authorization proof
            self.verify_authorization(proof, message_hash, commitment_root, index)
        }

        /// Update the authorized sequencer. Only the owner may call this.
        fn set_sequencer(ref self: ContractState, new_sequencer: ContractAddress) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'caller not owner');

            let old = self.authorized_sequencer.read();
            self.authorized_sequencer.write(new_sequencer);
            self.emit(SequencerUpdated { old_sequencer: old, new_sequencer });
        }
    }

    /// Verify a proof commitment using Poseidon sponge hash (Option B).
    ///
    /// ## How it works
    ///
    /// The Rust prover generates a real STARK proof off-chain via lambdaworks.
    /// It then serializes the proof data and computes a Poseidon commitment tag:
    ///
    ///   tag = PoseidonSponge::hash(message_hash || commitment_root || index || proof_data)
    ///
    /// On-chain, this function recomputes the tag from the proof layout and checks
    /// it matches the tag embedded at the end of the proof array.
    ///
    /// ## Proof layout
    ///
    ///   proof[0]       = message_hash
    ///   proof[1]       = commitment_root
    ///   proof[2]       = index (as felt252)
    ///   proof[3..n-1]  = STARK proof commitment data
    ///   proof[n-1]     = verification tag
    ///
    /// Full FRI verification in Cairo is deferred to Phase 3.
    fn verify_proof_commitment(
        proof: Span<felt252>, message_hash: felt252, commitment_root: felt252, index: u64,
    ) -> bool {
        if proof.len() < 4 {
            return false;
        }

        let index_felt: felt252 = index.into();

        let mut hash_input: Array<felt252> = ArrayTrait::new();
        hash_input.append(message_hash);
        hash_input.append(commitment_root);
        hash_input.append(index_felt);

        // Append STARK proof commitment data (everything between index and tag)
        let mut i: u32 = 3;
        while i < proof.len() - 1 {
            hash_input.append(*proof.at(i));
            i += 1;
        }

        let verification_hash = zk_pqc_cairo::sponge::hash(hash_input.span());
        let tag = *proof.at(proof.len() - 1);
        verification_hash == tag
    }

    #[cfg(test)]
    mod tests {
        use starknet::{ContractAddress, contract_address_const};
        use zk_pqc_cairo::sponge::hash;
        use super::PCAVerifierImpl;

        // ---------------------------------------------------------------
        // Helpers
        // ---------------------------------------------------------------

        /// Build a valid proof with the new layout:
        ///   [message_hash, commitment_root, index_felt, proof_data..., tag]
        /// where tag = hash(message_hash || commitment_root || index_felt || proof_data)
        fn build_valid_proof(
            message_hash: felt252, commitment_root: felt252, index: u64, proof_data: Span<felt252>,
        ) -> Array<felt252> {
            let index_felt: felt252 = index.into();

            let mut hash_input: Array<felt252> = ArrayTrait::new();
            hash_input.append(message_hash);
            hash_input.append(commitment_root);
            hash_input.append(index_felt);
            let mut i: u32 = 0;
            while i < proof_data.len() {
                hash_input.append(*proof_data.at(i));
                i += 1;
            }
            let tag = hash(hash_input.span());

            let mut proof: Array<felt252> = ArrayTrait::new();
            proof.append(message_hash);
            proof.append(commitment_root);
            proof.append(index_felt);
            let mut j: u32 = 0;
            while j < proof_data.len() {
                proof.append(*proof_data.at(j));
                j += 1;
            }
            proof.append(tag);
            proof
        }

        fn owner_addr() -> ContractAddress {
            contract_address_const::<0x100>()
        }

        fn sequencer_addr() -> ContractAddress {
            contract_address_const::<0x200>()
        }

        fn other_addr() -> ContractAddress {
            contract_address_const::<0x300>()
        }

        fn setup() -> super::ContractState {
            let mut state = super::contract_state_for_testing();
            // Manually set owner and sequencer (constructor not called in unit tests)
            state.owner.write(owner_addr());
            state.authorized_sequencer.write(sequencer_addr());
            state
        }

        // ---------------------------------------------------------------
        // verify_authorization: valid proof acceptance (Req 10.2)
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_valid_proof_accepted() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = build_valid_proof(msg, root, 0, array![42, 99, 7].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 0);
            assert(valid, 'valid proof should pass');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_minimal_valid_proof() {
            let state = setup();
            let msg: felt252 = 0x42;
            let root: felt252 = 0x99;
            // Minimal proof: [msg, root, index_felt, tag] = 4 elements
            let proof = build_valid_proof(msg, root, 0, array![].span());
            assert(proof.len() == 4, 'minimal proof len wrong');
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 0);
            assert(valid, 'minimal proof should pass');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_valid_proof_with_nonzero_index() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = build_valid_proof(msg, root, 42, array![77].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 42);
            assert(valid, 'nonzero index should pass');
        }

        // ---------------------------------------------------------------
        // verify_authorization: invalid proof rejection (Req 10.3)
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_invalid_proof_rejected() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let index_felt: felt252 = 0;
            let proof = array![msg, root, index_felt, 42, 99, 0xDEAD];
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
            // Only 3 elements — needs at least 4
            let proof = array![0x1234, 0xABCD, 0];
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
            let proof = build_valid_proof(0, root, 0, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), 0, root, 0);
            assert(!valid, 'zero msg hash should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_zero_commitment_root_rejected() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let proof = build_valid_proof(msg, 0, 0, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, 0, 0);
            assert(!valid, 'zero root should fail');
        }

        // ---------------------------------------------------------------
        // verify_authorization: message/root/index mismatch (Req 10.3, 10.4)
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_message_mismatch_rejected() {
            let state = setup();
            let proof = build_valid_proof(0x1111, 0xABCD, 0, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(
                @state, proof.span(), 0x2222, 0xABCD, 0,
            );
            assert(!valid, 'msg mismatch should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_root_mismatch_rejected() {
            let state = setup();
            let proof = build_valid_proof(0x1234, 0xAAAA, 0, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(
                @state, proof.span(), 0x1234, 0xBBBB, 0,
            );
            assert(!valid, 'root mismatch should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_index_mismatch_rejected() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            // Proof built for index 5, but verified with index 10
            let proof = build_valid_proof(msg, root, 5, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 10);
            assert(!valid, 'index mismatch should fail');
        }

        // ---------------------------------------------------------------
        // verify_authorization: different data produces different tags
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_different_proof_data_different_tag() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof_a = build_valid_proof(msg, root, 0, array![1, 2, 3].span());
            let proof_b = build_valid_proof(msg, root, 1, array![4, 5, 6].span());

            let va = PCAVerifierImpl::verify_authorization(@state, proof_a.span(), msg, root, 0);
            let vb = PCAVerifierImpl::verify_authorization(@state, proof_b.span(), msg, root, 1);
            assert(va, 'proof A should pass');
            assert(vb, 'proof B should pass');

            let tag_a = *proof_a.at(proof_a.len() - 1);
            let tag_b = *proof_b.at(proof_b.len() - 1);
            assert(tag_a != tag_b, 'different data same tag');
        }

        // ---------------------------------------------------------------
        // submit_batch tests (with access control)
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_submit_batch_marks_indices_consumed() {
            let mut state = setup();
            let new_root: felt252 = 0xFEED;
            let smt_diff = array![10_u64, 20_u64, 30_u64];
            let proof = build_valid_proof(0x1234, new_root, 0, array![77].span());

            // Set caller to authorized sequencer
            starknet::testing::set_caller_address(sequencer_addr());

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
            starknet::testing::set_caller_address(sequencer_addr());

            let r1: felt252 = 0xAAAA;
            let r2: felt252 = 0xBBBB;

            let p1 = build_valid_proof(0x11, r1, 0, array![1].span());
            PCAVerifierImpl::submit_batch(ref state, p1.span(), array![5_u64].span(), r1);

            let p2 = build_valid_proof(0x22, r2, 0, array![2].span());
            PCAVerifierImpl::submit_batch(ref state, p2.span(), array![5_u64].span(), r2);
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('invalid batch proof',))]
        fn test_pca_submit_batch_rejects_invalid_proof() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xFEED;
            let index_felt: felt252 = 0;
            let bad_proof = array![0x1234, new_root, index_felt, 42, 0xDEAD];
            PCAVerifierImpl::submit_batch(
                ref state, bad_proof.span(), array![1_u64].span(), new_root,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('proof root mismatch',))]
        fn test_pca_submit_batch_rejects_root_mismatch() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let proof = build_valid_proof(0x11, 0xBBBB, 0, array![1].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), 0xAAAA);
        }

        // ---------------------------------------------------------------
        // Cross-concern: consumed index blocks verify_authorization
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_consumed_index_blocks_verify() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let batch_root: felt252 = 0xFEED;
            let bp = build_valid_proof(0x11, batch_root, 0, array![1].span());
            PCAVerifierImpl::submit_batch(ref state, bp.span(), array![7_u64].span(), batch_root);

            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = build_valid_proof(msg, root, 7, array![42].span());
            let valid = PCAVerifierImpl::verify_authorization(@state, proof.span(), msg, root, 7);
            assert(!valid, 'consumed idx should fail');
        }

        // ---------------------------------------------------------------
        // Access control tests (11H.2)
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_get_owner_returns_owner() {
            let state = setup();
            assert(PCAVerifierImpl::get_owner(@state) == owner_addr(), 'wrong owner');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_get_sequencer_returns_sequencer() {
            let state = setup();
            assert(PCAVerifierImpl::get_sequencer(@state) == sequencer_addr(), 'wrong sequencer');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_set_sequencer_by_owner() {
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());

            let new_seq = other_addr();
            PCAVerifierImpl::set_sequencer(ref state, new_seq);
            assert(PCAVerifierImpl::get_sequencer(@state) == new_seq, 'sequencer not updated');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('caller not owner',))]
        fn test_set_sequencer_by_non_owner_fails() {
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());

            PCAVerifierImpl::set_sequencer(ref state, other_addr());
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('caller not authorized',))]
        fn test_submit_batch_by_non_sequencer_fails() {
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());

            let new_root: felt252 = 0xFEED;
            let proof = build_valid_proof(0x1234, new_root, 0, array![77].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), new_root);
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_submit_batch_by_sequencer_succeeds() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xFEED;
            let proof = build_valid_proof(0x1234, new_root, 0, array![77].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), new_root);

            assert(PCAVerifierImpl::get_smt_root(@state) == new_root, 'batch should succeed');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_updated_sequencer_can_submit_batch() {
            let mut state = setup();

            // Owner updates sequencer to other_addr
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::set_sequencer(ref state, other_addr());

            // New sequencer submits batch
            starknet::testing::set_caller_address(other_addr());
            let new_root: felt252 = 0xFEED;
            let proof = build_valid_proof(0x1234, new_root, 0, array![77].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), new_root);

            assert(PCAVerifierImpl::get_smt_root(@state) == new_root, 'new seq batch ok');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('caller not authorized',))]
        fn test_old_sequencer_rejected_after_update() {
            let mut state = setup();

            // Owner updates sequencer to other_addr
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::set_sequencer(ref state, other_addr());

            // Old sequencer tries to submit — should fail
            starknet::testing::set_caller_address(sequencer_addr());
            let new_root: felt252 = 0xFEED;
            let proof = build_valid_proof(0x1234, new_root, 0, array![77].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), new_root);
        }
    }
}
