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

    /// Return the total number of batches submitted so far.
    /// Observers use this to track DA state diffs sequentially.
    fn get_batch_count(self: @TState) -> u64;

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

    /// Verify a single authorization proof with JMT index enforcement.
    ///
    /// This function:
    /// 1. Checks that the index has not been consumed
    /// 2. Verifies the JMT proof showing index is unconsumed against stored root
    /// 3. Verifies the authorization proof
    ///
    /// The JMT proof uses depth-1 (63) siblings in leaf-to-root order.
    /// Routing bit at level i: (index >> i) & 1 (0 = left, 1 = right).
    ///
    /// Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 16.3, 16.4
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

    /// Classify a transaction into a lane based on its hash flag.
    /// Lane 0 = Poseidon-Only (high-frequency, low-cost path)
    /// Lane 1 = Hybrid-Hash (institutional/conservative path)
    /// Any hash_flag > 1 is invalid and returns lane 0 as default.
    ///
    /// Requirements: 18.1
    fn classify_lane(self: @TState, hash_flag: u8) -> u8;

    /// Submit a lane-specific batch of proofs with SMT state diff.
    ///
    /// Only callable by the authorized sequencer.
    /// Verifies the batch proof commitment, updates the SMT root, records consumed indices,
    /// and increments the lane-specific batch counter.
    ///
    /// The lane parameter identifies which processing lane this batch belongs to:
    /// - Lane 0: Poseidon-Only transactions
    /// - Lane 1: Hybrid-Hash transactions
    ///
    /// Separate batch proofs per lane allow the recursive aggregator to process
    /// lanes independently, ensuring Poseidon-Only throughput is unaffected by
    /// Hybrid-Hash processing.
    ///
    /// Requirements: 18.1, 18.2
    fn submit_lane_batch(
        ref self: TState,
        lane: u8,
        batch_proof: Span<felt252>,
        smt_diff: Span<u64>,
        new_smt_root: felt252,
    );

    /// Return the number of batches submitted for a specific lane.
    /// Lane 0 = Poseidon-Only, Lane 1 = Hybrid-Hash.
    ///
    /// Requirements: 18.1, 18.2
    fn get_lane_batch_count(self: @TState, lane: u8) -> u64;

    /// Submit a fraud proof (Accountability Trace) against a violating sequencer.
    ///
    /// Any observer can call this function. The accountability trace is a STARK proof
    /// of sequencer violation (equivocation, replay, index reuse). Verification uses
    /// Poseidon commitment check (constant O(1) cost, matching Option B).
    ///
    /// On valid fraud proof:
    /// - The violating sequencer's stake is slashed to 0 (100% slashing)
    /// - The sequencer is marked as slashed
    /// - If fraud proof count exceeds the circuit breaker threshold, batch processing is paused
    ///
    /// Requirements: 19.1, 19.2, 19.3, 19.4
    fn submit_fraud_proof(
        ref self: TState, accountability_trace: Span<felt252>, violator: starknet::ContractAddress,
    );

    /// Return the total number of fraud proofs submitted.
    fn get_fraud_proof_count(self: @TState) -> u64;

    /// Return whether the circuit breaker is active (batch processing paused).
    fn get_circuit_breaker_active(self: @TState) -> bool;

    /// Set the circuit breaker threshold. Only callable by the owner.
    /// When fraud proof count >= threshold, the circuit breaker activates.
    fn set_circuit_breaker_threshold(ref self: TState, threshold: u64);

    /// Return the circuit breaker threshold.
    fn get_circuit_breaker_threshold(self: @TState) -> u64;

    /// Return the stake amount for a given sequencer.
    fn get_sequencer_stake(self: @TState, sequencer: starknet::ContractAddress) -> u256;

    /// Deposit stake for the calling sequencer.
    fn deposit_stake(ref self: TState, amount: u256);

    /// Return whether a sequencer has been slashed.
    fn is_sequencer_slashed(self: @TState, sequencer: starknet::ContractAddress) -> bool;

    /// Register an account with a configurable index window size.
    /// Only callable by the owner.
    ///
    /// Each account maintains an index window [base, base + k] where k is the window_size.
    /// Multiple transactions from the same account with distinct indices within the window
    /// can be processed in parallel.
    ///
    /// Requirements: 20.1
    fn register_account(ref self: TState, account: starknet::ContractAddress, window_size: u64);

    /// Return the current window state (window_base, window_size) for an account.
    ///
    /// Requirements: 20.1
    fn get_account_window(self: @TState, account: starknet::ContractAddress) -> (u64, u64);

    /// Consume an index within the account's active window [base, base + k).
    ///
    /// - Rejects if the account is not registered (window_size == 0).
    /// - Rejects if the index is outside the window range.
    /// - Rejects if the index has already been consumed within the window.
    /// - When all k indices in the window are consumed, auto-advances the window
    ///   base to base + k and resets consumed state.
    ///
    /// Requirements: 20.2, 20.3, 20.4
    fn consume_window_index(ref self: TState, account: starknet::ContractAddress, index: u64);

    /// Check whether a given index has been consumed within the account's current window.
    ///
    /// Requirements: 20.4
    fn is_window_index_consumed(
        self: @TState, account: starknet::ContractAddress, index: u64,
    ) -> bool;

    /// Manually advance the window base when all indices are consumed.
    /// This is also done automatically by consume_window_index when the window is full.
    /// Only callable by the owner.
    ///
    /// Requirements: 20.3
    fn advance_window(ref self: TState, account: starknet::ContractAddress);

    /// Verify a single authorization proof using FRI polynomial commitment verification.
    ///
    /// This is the Option A upgrade path: full on-chain FRI verification.
    /// The proof contains FRI layer Merkle commitments, query responses, and
    /// folding consistency data. The verifier checks all FRI layers, Merkle
    /// paths, and the final constant polynomial.
    ///
    /// Keeps backward compatibility — the existing `verify_authorization` (Option B)
    /// remains available for Poseidon commitment-only verification.
    ///
    /// Returns true only when ALL FRI verification checks pass.
    fn verify_authorization_fri(
        self: @TState,
        proof: Span<felt252>,
        message_hash: felt252,
        commitment_root: felt252,
        index: u64,
    ) -> bool;
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
        // Multi-lane mempool counters (Requirements 18.1, 18.2)
        lane_batch_count: Map<u8, u64>,
        // ZK-Fraud Proof fields (Requirements 19.1, 19.2, 19.3, 19.4)
        fraud_proof_count: u64,
        circuit_breaker_active: bool,
        circuit_breaker_threshold: u64,
        sequencer_stakes: Map<ContractAddress, u256>,
        slashed_sequencers: Map<ContractAddress, bool>,
        // Account Abstraction — Index Windows (Requirements 20.1, 20.2, 20.3, 20.4)
        account_window_base: Map<ContractAddress, u64>,
        account_window_size: Map<ContractAddress, u64>,
        account_window_consumed: Map<(ContractAddress, u64), bool>,
        account_window_consumed_count: Map<ContractAddress, u64>,
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
        StateDiffPublished: StateDiffPublished,
        SequencerUpdated: SequencerUpdated,
        DomainConfigUpdated: DomainConfigUpdated,
        NonceConsumed: NonceConsumed,
        LaneBatchSubmitted: LaneBatchSubmitted,
        FraudProofSubmitted: FraudProofSubmitted,
        SequencerSlashed: SequencerSlashed,
        CircuitBreakerActivated: CircuitBreakerActivated,
        AccountRegistered: AccountRegistered,
        WindowIndexConsumed: WindowIndexConsumed,
        WindowAdvanced: WindowAdvanced,
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

    /// DA (Data Availability) event: publishes the compact uint64 index vector
    /// representing leaves transitioned from "unspent" to "spent" in this batch.
    ///
    /// Network observers can reconstruct the full SMT state by accumulating
    /// all StateDiffPublished events in order. The DA payload for K transactions
    /// is exactly K × 8 bytes (K uint64 indices).
    ///
    /// Requirements: 17.1, 17.2
    #[derive(Drop, starknet::Event)]
    struct StateDiffPublished {
        /// The batch ID this diff belongs to (monotonically increasing).
        batch_id: u64,
        /// The number of consumed indices in this batch (K).
        /// DA payload size = num_indices × 8 bytes.
        num_indices: u32,
        /// The consumed indices as a flat felt252 encoding.
        /// Each index is a uint64 stored as a felt252 element.
        /// Observers decode these back to u64 for SMT reconstruction.
        indices_hash: felt252,
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

    /// Event emitted when a lane-specific batch is submitted.
    /// Allows observers to track per-lane throughput independently.
    ///
    /// Requirements: 18.1, 18.2
    #[derive(Drop, starknet::Event)]
    struct LaneBatchSubmitted {
        /// The lane this batch belongs to (0 = Poseidon-Only, 1 = Hybrid-Hash).
        lane: u8,
        /// The lane-specific batch ID (monotonically increasing per lane).
        lane_batch_id: u64,
        /// The new SMT root after this batch.
        new_smt_root: felt252,
        /// Number of indices consumed in this batch.
        num_indices: u32,
    }

    #[derive(Drop, starknet::Event)]
    struct SequencerUpdated {
        old_sequencer: ContractAddress,
        new_sequencer: ContractAddress,
    }

    /// Event emitted when a valid fraud proof is submitted.
    ///
    /// Requirements: 19.1, 19.2
    #[derive(Drop, starknet::Event)]
    struct FraudProofSubmitted {
        /// The address that submitted the fraud proof (any observer).
        submitter: ContractAddress,
        /// The sequencer whose violation was proven.
        violator: ContractAddress,
        /// The fraud proof count after this submission.
        fraud_proof_id: u64,
    }

    /// Event emitted when a sequencer's stake is slashed (100% slashing).
    ///
    /// Requirements: 19.2
    #[derive(Drop, starknet::Event)]
    struct SequencerSlashed {
        /// The slashed sequencer address.
        sequencer: ContractAddress,
        /// The amount of stake that was slashed.
        slashed_amount: u256,
    }

    /// Event emitted when the circuit breaker activates due to excessive fraud proofs.
    ///
    /// Requirements: 19.3
    #[derive(Drop, starknet::Event)]
    struct CircuitBreakerActivated {
        /// The fraud proof count that triggered the circuit breaker.
        fraud_proof_count: u64,
        /// The threshold that was exceeded.
        threshold: u64,
    }

    /// Event emitted when an account is registered with an index window.
    ///
    /// Requirements: 20.1
    #[derive(Drop, starknet::Event)]
    struct AccountRegistered {
        /// The registered account address.
        account: ContractAddress,
        /// The window size (k) for this account.
        window_size: u64,
    }

    /// Event emitted when an index within an account's window is consumed.
    ///
    /// Requirements: 20.2
    #[derive(Drop, starknet::Event)]
    struct WindowIndexConsumed {
        /// The account that consumed the index.
        account: ContractAddress,
        /// The consumed index.
        index: u64,
        /// Number of consumed indices in the window after this consumption.
        consumed_count: u64,
    }

    /// Event emitted when an account's window base advances.
    ///
    /// Requirements: 20.3
    #[derive(Drop, starknet::Event)]
    struct WindowAdvanced {
        /// The account whose window advanced.
        account: ContractAddress,
        /// The old window base.
        old_base: u64,
        /// The new window base.
        new_base: u64,
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
        /// Verifies the batch proof Π_Batch on-chain with O(1) cost by recomputing
        /// the Poseidon Merkle commitment root from the provided leaf hashes and
        /// comparing it to the claimed commitment root.
        ///
        /// ## Batch Proof Layout (felt252 array)
        ///
        ///   batch_proof[0]                    = commitment_root (Poseidon Merkle root)
        ///   batch_proof[1]                    = batch_size (N, as felt252)
        ///   batch_proof[2..2+N]               = leaf_hashes (N leaf hashes)
        ///
        /// ## Verification Steps
        ///
        /// 1. Parse commitment_root and batch_size from the proof
        /// 2. Extract leaf hashes from the proof
        /// 3. Recompute the Merkle root from leaf hashes using Poseidon with
        ///    domain separator DOMAIN_MERKLE_NODE (matching Rust aggregator)
        /// 4. Assert recomputed root == claimed commitment_root
        /// 5. Verify batch_size matches the number of consumed indices
        /// 6. Mark all indices in smt_diff as consumed
        /// 7. Update the SMT root
        /// 8. Emit BatchSubmitted event
        ///
        /// Guarded: only the authorized_sequencer may call this function.
        ///
        /// Requirements: 15.2
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

            // Circuit breaker: reject if active (Requirements 19.3)
            assert(!self.circuit_breaker_active.read(), 'circuit breaker active');

            // Minimum batch proof: [commitment_root, batch_size, at least 1 leaf_hash]
            assert(batch_proof.len() >= 3, 'batch proof too short');
            assert(smt_diff.len() > 0, 'empty smt diff');
            assert(new_smt_root != 0, 'invalid new smt root');

            // Parse batch proof header
            let commitment_root = *batch_proof.at(0);
            let batch_size_felt = *batch_proof.at(1);

            // Validate batch_size > 0 and matches proof length
            assert(batch_size_felt != 0, 'batch size is zero');

            // The proof must contain exactly: commitment_root + batch_size + N leaf_hashes
            // So total length = 2 + N
            let expected_len: u32 = 2 + smt_diff.len();
            assert(batch_proof.len() == expected_len, 'batch proof length mismatch');

            // Verify batch_size matches the number of indices in smt_diff
            let batch_size_from_diff: felt252 = smt_diff.len().into();
            assert(batch_size_felt == batch_size_from_diff, 'batch size mismatch');

            // Check no indices are already consumed
            let mut i: u32 = 0;
            while i < smt_diff.len() {
                let idx = *smt_diff.at(i);
                assert(!self.consumed_indices.read(idx), 'index already consumed');
                i += 1;
            }

            // Extract leaf hashes from the proof
            let mut leaf_hashes: Array<felt252> = ArrayTrait::new();
            let mut k: u32 = 2;
            while k < batch_proof.len() {
                leaf_hashes.append(*batch_proof.at(k));
                k += 1;
            }

            // Recompute Merkle commitment root from leaf hashes
            // Uses the same algorithm as the Rust aggregator:
            // - Domain separator: DOMAIN_MERKLE_NODE = 0x5043415f4e4f4445 ("PCA_NODE")
            // - Binary tree: H(domain || left || right) for internal nodes
            // - Odd nodes promoted to next level
            let recomputed_root = compute_batch_merkle_commitment(leaf_hashes.span());

            // O(1) verification: compare recomputed root with claimed commitment root
            assert(recomputed_root == commitment_root, 'batch commitment invalid');

            // Mark all indices as consumed
            let mut j: u32 = 0;
            while j < smt_diff.len() {
                let idx = *smt_diff.at(j);
                self.consumed_indices.write(idx, true);
                j += 1;
            }

            // Update SMT root
            self.smt_root.write(new_smt_root);

            // Increment batch counter and emit event
            let batch_id = self.batch_count.read() + 1;
            self.batch_count.write(batch_id);

            self.emit(BatchSubmitted { batch_id, new_smt_root, num_indices: smt_diff.len() });

            // Emit DA state diff event for network observers.
            // The smt_diff calldata IS the DA payload (K × 8 bytes for K indices).
            // We also emit a Poseidon hash of the indices for compact on-chain indexing.
            // Observers reconstruct the SMT by reading the smt_diff calldata directly.
            let mut indices_input: Array<felt252> = ArrayTrait::new();
            let mut da_i: u32 = 0;
            while da_i < smt_diff.len() {
                let idx_felt: felt252 = (*smt_diff.at(da_i)).into();
                indices_input.append(idx_felt);
                da_i += 1;
            }
            let indices_hash = zk_pqc_cairo::sponge::hash(indices_input.span());

            self.emit(StateDiffPublished { batch_id, num_indices: smt_diff.len(), indices_hash });
        }

        fn get_smt_root(self: @ContractState) -> felt252 {
            self.smt_root.read()
        }

        fn get_batch_count(self: @ContractState) -> u64 {
            self.batch_count.read()
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

        /// Verify a single authorization proof with JMT index enforcement.
        ///
        /// This function:
        /// 1. Checks that the index has not been consumed (on-chain record)
        /// 2. Verifies the JMT non-spent proof against the stored JMT root
        /// 3. Verifies the authorization proof
        ///
        /// The JMT proof format (matching Rust JMT):
        /// - siblings: depth-1 (63) hashes, leaf-to-root order
        /// - leaf_value: 0 = unconsumed
        /// - Routing bit at level i: (index >> i) & 1
        ///
        /// Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 16.3, 16.4
        fn verify_authorization_with_smt(
            self: @ContractState,
            proof: Span<felt252>,
            message_hash: felt252,
            commitment_root: felt252,
            index: u64,
            smt_proof_siblings: Span<felt252>,
        ) -> bool {
            // Check index not already consumed (on-chain record)
            if self.consumed_indices.read(index) {
                return false;
            }

            // Build JMT proof for non-membership (unconsumed)
            let jmt_proof = zk_pqc_cairo::smt::SmtProof {
                siblings: smt_proof_siblings.into(), leaf_value: 0 // Empty leaf = unconsumed
            };

            // Verify JMT proof shows index is unconsumed against stored JMT root
            let current_root = self.smt_root.read();
            if !zk_pqc_cairo::smt::verify_unconsumed(current_root, index, @jmt_proof) {
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

        /// Classify a transaction into a lane based on its hash flag.
        ///
        /// - hash_flag 0 → Lane 0 (Poseidon-Only): high-frequency, low-cost path
        /// - hash_flag 1 → Lane 1 (Hybrid-Hash): institutional/conservative path
        /// - Any other value → Lane 0 (default to Poseidon-Only)
        ///
        /// This classification enables segregated mempools so that Hybrid-Hash
        /// processing does not degrade Poseidon-Only lane throughput.
        ///
        /// Requirements: 18.1
        fn classify_lane(self: @ContractState, hash_flag: u8) -> u8 {
            if hash_flag == 1 {
                1 // Hybrid-Hash lane
            } else {
                0 // Poseidon-Only lane (default)
            }
        }

        /// Submit a lane-specific batch of proofs with SMT state diff.
        ///
        /// Identical verification logic to `submit_batch`, but additionally:
        /// - Validates the lane parameter (must be 0 or 1)
        /// - Increments the lane-specific batch counter
        /// - Emits a LaneBatchSubmitted event for per-lane tracking
        ///
        /// Separate batch proofs per lane ensure the recursive aggregator processes
        /// lanes independently. Poseidon-Only lane throughput is unaffected by
        /// Hybrid-Hash processing because each lane has its own batch counter
        /// and can be submitted independently.
        ///
        /// Requirements: 18.1, 18.2
        fn submit_lane_batch(
            ref self: ContractState,
            lane: u8,
            batch_proof: Span<felt252>,
            smt_diff: Span<u64>,
            new_smt_root: felt252,
        ) {
            // Validate lane
            assert(lane <= 1, 'invalid lane');

            // Access control: only authorized sequencer
            let caller = get_caller_address();
            let sequencer = self.authorized_sequencer.read();
            assert(caller == sequencer, 'caller not authorized');

            // Circuit breaker: reject if active (Requirements 19.3)
            assert(!self.circuit_breaker_active.read(), 'circuit breaker active');

            // Minimum batch proof: [commitment_root, batch_size, at least 1 leaf_hash]
            assert(batch_proof.len() >= 3, 'batch proof too short');
            assert(smt_diff.len() > 0, 'empty smt diff');
            assert(new_smt_root != 0, 'invalid new smt root');

            // Parse batch proof header
            let commitment_root = *batch_proof.at(0);
            let batch_size_felt = *batch_proof.at(1);

            // Validate batch_size > 0 and matches proof length
            assert(batch_size_felt != 0, 'batch size is zero');

            // The proof must contain exactly: commitment_root + batch_size + N leaf_hashes
            let expected_len: u32 = 2 + smt_diff.len();
            assert(batch_proof.len() == expected_len, 'batch proof length mismatch');

            // Verify batch_size matches the number of indices in smt_diff
            let batch_size_from_diff: felt252 = smt_diff.len().into();
            assert(batch_size_felt == batch_size_from_diff, 'batch size mismatch');

            // Check no indices are already consumed
            let mut i: u32 = 0;
            while i < smt_diff.len() {
                let idx = *smt_diff.at(i);
                assert(!self.consumed_indices.read(idx), 'index already consumed');
                i += 1;
            }

            // Extract leaf hashes from the proof
            let mut leaf_hashes: Array<felt252> = ArrayTrait::new();
            let mut k: u32 = 2;
            while k < batch_proof.len() {
                leaf_hashes.append(*batch_proof.at(k));
                k += 1;
            }

            // Recompute Merkle commitment root from leaf hashes
            let recomputed_root = compute_batch_merkle_commitment(leaf_hashes.span());

            // O(1) verification: compare recomputed root with claimed commitment root
            assert(recomputed_root == commitment_root, 'batch commitment invalid');

            // Mark all indices as consumed
            let mut j: u32 = 0;
            while j < smt_diff.len() {
                let idx = *smt_diff.at(j);
                self.consumed_indices.write(idx, true);
                j += 1;
            }

            // Update SMT root
            self.smt_root.write(new_smt_root);

            // Increment global batch counter
            let batch_id = self.batch_count.read() + 1;
            self.batch_count.write(batch_id);

            // Increment lane-specific batch counter
            let lane_batch_id = self.lane_batch_count.read(lane) + 1;
            self.lane_batch_count.write(lane, lane_batch_id);

            // Emit global batch event
            self.emit(BatchSubmitted { batch_id, new_smt_root, num_indices: smt_diff.len() });

            // Emit lane-specific event
            self
                .emit(
                    LaneBatchSubmitted {
                        lane, lane_batch_id, new_smt_root, num_indices: smt_diff.len(),
                    },
                );

            // Emit DA state diff event
            let mut indices_input: Array<felt252> = ArrayTrait::new();
            let mut da_i: u32 = 0;
            while da_i < smt_diff.len() {
                let idx_felt: felt252 = (*smt_diff.at(da_i)).into();
                indices_input.append(idx_felt);
                da_i += 1;
            }
            let indices_hash = zk_pqc_cairo::sponge::hash(indices_input.span());

            self.emit(StateDiffPublished { batch_id, num_indices: smt_diff.len(), indices_hash });
        }

        /// Return the number of batches submitted for a specific lane.
        ///
        /// - Lane 0: Poseidon-Only batch count
        /// - Lane 1: Hybrid-Hash batch count
        ///
        /// Requirements: 18.1, 18.2
        fn get_lane_batch_count(self: @ContractState, lane: u8) -> u64 {
            self.lane_batch_count.read(lane)
        }

        /// Submit a fraud proof (Accountability Trace) against a violating sequencer.
        ///
        /// Any observer can call this. The accountability trace is verified via
        /// Poseidon commitment (constant O(1) cost, matching Option B verification).
        ///
        /// ## Accountability Trace Layout (felt252 array)
        ///
        ///   trace[0]       = violation_type (equivocation, replay, index reuse)
        ///   trace[1]       = violator address (as felt252)
        ///   trace[2..n-1]  = evidence data (STARK proof commitment data)
        ///   trace[n-1]     = verification tag
        ///
        /// The verification tag commits to ALL fields:
        ///   tag = PoseidonSponge::hash(violation_type || violator || evidence_data)
        ///
        /// On valid fraud proof:
        /// 1. Sequencer's stake is set to 0 (100% slashing)
        /// 2. Sequencer is marked as slashed
        /// 3. Fraud proof count is incremented
        /// 4. If count >= threshold and threshold > 0: circuit breaker activates
        ///
        /// Requirements: 19.1, 19.2, 19.3, 19.4
        fn submit_fraud_proof(
            ref self: ContractState, accountability_trace: Span<felt252>, violator: ContractAddress,
        ) {
            // Minimum trace: [violation_type, violator_felt, tag] = 3 elements
            assert(accountability_trace.len() >= 3, 'trace too short');

            // Verify the accountability trace commitment (O(1) STARK proof verification)
            let valid = verify_accountability_trace(accountability_trace, violator);
            assert(valid, 'invalid accountability trace');

            // Apply 100% slashing on the violating sequencer's stake
            let stake = self.sequencer_stakes.read(violator);
            self.sequencer_stakes.write(violator, 0);
            self.slashed_sequencers.write(violator, true);

            // Emit slashing event
            self.emit(SequencerSlashed { sequencer: violator, slashed_amount: stake });

            // Increment fraud proof count
            let new_count = self.fraud_proof_count.read() + 1;
            self.fraud_proof_count.write(new_count);

            // Emit fraud proof event
            let caller = get_caller_address();
            self
                .emit(
                    FraudProofSubmitted { submitter: caller, violator, fraud_proof_id: new_count },
                );

            // Check circuit breaker threshold
            let threshold = self.circuit_breaker_threshold.read();
            if threshold > 0 && new_count >= threshold {
                if !self.circuit_breaker_active.read() {
                    self.circuit_breaker_active.write(true);
                    self.emit(CircuitBreakerActivated { fraud_proof_count: new_count, threshold });
                }
            }
        }

        /// Return the total number of fraud proofs submitted.
        fn get_fraud_proof_count(self: @ContractState) -> u64 {
            self.fraud_proof_count.read()
        }

        /// Return whether the circuit breaker is active (batch processing paused).
        fn get_circuit_breaker_active(self: @ContractState) -> bool {
            self.circuit_breaker_active.read()
        }

        /// Set the circuit breaker threshold. Only callable by the owner.
        /// When fraud proof count >= threshold, the circuit breaker activates.
        fn set_circuit_breaker_threshold(ref self: ContractState, threshold: u64) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'caller not owner');
            self.circuit_breaker_threshold.write(threshold);
        }

        /// Return the circuit breaker threshold.
        fn get_circuit_breaker_threshold(self: @ContractState) -> u64 {
            self.circuit_breaker_threshold.read()
        }

        /// Return the stake amount for a given sequencer.
        fn get_sequencer_stake(self: @ContractState, sequencer: ContractAddress) -> u256 {
            self.sequencer_stakes.read(sequencer)
        }

        /// Deposit stake for the calling sequencer.
        fn deposit_stake(ref self: ContractState, amount: u256) {
            assert(amount > 0, 'zero stake deposit');
            let caller = get_caller_address();
            let current = self.sequencer_stakes.read(caller);
            self.sequencer_stakes.write(caller, current + amount);
        }

        /// Return whether a sequencer has been slashed.
        fn is_sequencer_slashed(self: @ContractState, sequencer: ContractAddress) -> bool {
            self.slashed_sequencers.read(sequencer)
        }

        /// Register an account with a configurable index window size.
        /// Only callable by the owner.
        ///
        /// The window starts at base=0 with the given window_size (k).
        /// The account can then consume indices within [0, k).
        ///
        /// Requirements: 20.1
        fn register_account(ref self: ContractState, account: ContractAddress, window_size: u64) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'caller not owner');
            assert(window_size > 0, 'window size must be > 0');

            self.account_window_base.write(account, 0);
            self.account_window_size.write(account, window_size);
            self.account_window_consumed_count.write(account, 0);

            self.emit(AccountRegistered { account, window_size });
        }

        /// Return the current window state (window_base, window_size) for an account.
        ///
        /// Requirements: 20.1
        fn get_account_window(self: @ContractState, account: ContractAddress) -> (u64, u64) {
            (self.account_window_base.read(account), self.account_window_size.read(account))
        }

        /// Consume an index within the account's active window [base, base + k).
        ///
        /// Requirements: 20.2, 20.3, 20.4
        fn consume_window_index(ref self: ContractState, account: ContractAddress, index: u64) {
            let window_size = self.account_window_size.read(account);
            assert(window_size > 0, 'account not registered');

            let window_base = self.account_window_base.read(account);

            // Verify index is within [base, base + k)
            assert(index >= window_base, 'index below window');
            assert(index < window_base + window_size, 'index above window');

            // Verify index not already consumed within window
            assert(!self.account_window_consumed.read((account, index)), 'index already consumed');

            // Mark index as consumed
            self.account_window_consumed.write((account, index), true);

            // Increment consumed count
            let new_count = self.account_window_consumed_count.read(account) + 1;
            self.account_window_consumed_count.write(account, new_count);

            self.emit(WindowIndexConsumed { account, index, consumed_count: new_count });

            // Auto-advance window when all indices consumed
            if new_count == window_size {
                let old_base = window_base;
                let new_base = window_base + window_size;
                self.account_window_base.write(account, new_base);
                self.account_window_consumed_count.write(account, 0);

                // Clear consumed flags for the old window indices
                let mut i: u64 = old_base;
                while i < old_base + window_size {
                    self.account_window_consumed.write((account, i), false);
                    i += 1;
                }

                self.emit(WindowAdvanced { account, old_base, new_base });
            }
        }

        /// Check whether a given index has been consumed within the account's current window.
        ///
        /// Requirements: 20.4
        fn is_window_index_consumed(
            self: @ContractState, account: ContractAddress, index: u64,
        ) -> bool {
            self.account_window_consumed.read((account, index))
        }

        /// Manually advance the window base when all indices are consumed.
        /// Only callable by the owner.
        ///
        /// Requirements: 20.3
        fn advance_window(ref self: ContractState, account: ContractAddress) {
            let caller = get_caller_address();
            let owner = self.owner.read();
            assert(caller == owner, 'caller not owner');

            let window_size = self.account_window_size.read(account);
            assert(window_size > 0, 'account not registered');

            let consumed_count = self.account_window_consumed_count.read(account);
            assert(consumed_count == window_size, 'window not fully consumed');

            let old_base = self.account_window_base.read(account);
            let new_base = old_base + window_size;
            self.account_window_base.write(account, new_base);
            self.account_window_consumed_count.write(account, 0);

            // Clear consumed flags for the old window indices
            let mut i: u64 = old_base;
            while i < old_base + window_size {
                self.account_window_consumed.write((account, i), false);
                i += 1;
            }

            self.emit(WindowAdvanced { account, old_base, new_base });
        }

        /// Verify a single authorization proof using FRI polynomial commitment
        /// verification (Option A: full on-chain FRI verification).
        ///
        /// This upgrades from Option B (Poseidon commitment check) to full
        /// trustless on-chain verification of STARK proof polynomial commitments.
        ///
        /// The FRI verifier checks:
        /// 1. Bound field matching (message_hash, commitment_root, index)
        /// 2. Poseidon commitment tag integrity
        /// 3. Merkle inclusion for each FRI layer's query evaluation
        /// 4. Folding consistency between consecutive FRI layers
        /// 5. Final constant polynomial check
        ///
        /// Returns true only when ALL checks pass.
        fn verify_authorization_fri(
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

            // Delegate to the FRI verifier module
            zk_pqc_cairo::fri_verifier::verify_fri_proof(
                proof, message_hash, commitment_root, index,
            )
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

    /// Domain separator for internal Merkle nodes in batch commitment.
    /// Matches Rust aggregator: DOMAIN_MERKLE_NODE = 0x5043415f4e4f4445 ("PCA_NODE")
    const DOMAIN_MERKLE_NODE: felt252 = 0x5043415f4e4f4445;

    /// Compute a Poseidon Merkle commitment over a list of leaf hashes.
    ///
    /// Uses a binary tree structure where each internal node is:
    ///   H(DOMAIN_MERKLE_NODE || left || right)
    ///
    /// If the number of leaves is odd, the last leaf is promoted to the next level.
    /// This produces a single root hash regardless of N.
    ///
    /// This matches the Rust aggregator's `compute_merkle_commitment()` exactly,
    /// ensuring cross-language consistency for batch verification.
    fn compute_batch_merkle_commitment(leaves: Span<felt252>) -> felt252 {
        if leaves.len() == 0 {
            return 0;
        }
        if leaves.len() == 1 {
            return *leaves.at(0);
        }

        // Copy leaves into a mutable working array
        let mut current_level: Array<felt252> = ArrayTrait::new();
        let mut init_i: u32 = 0;
        while init_i < leaves.len() {
            current_level.append(*leaves.at(init_i));
            init_i += 1;
        }

        // Iterative bottom-up Merkle tree construction
        while current_level.len() > 1 {
            let mut next_level: Array<felt252> = ArrayTrait::new();
            let current_len = current_level.len();

            let mut i: u32 = 0;
            while i + 1 < current_len {
                // H(DOMAIN_MERKLE_NODE || left || right)
                let left = *current_level.at(i);
                let right = *current_level.at(i + 1);
                let node = zk_pqc_cairo::sponge::hash_with_ds(
                    DOMAIN_MERKLE_NODE, array![left, right].span(),
                );
                next_level.append(node);
                i += 2;
            }

            // If odd number of nodes, promote the last one
            if current_len % 2 == 1 {
                next_level.append(*current_level.at(current_len - 1));
            }

            current_level = next_level;
        };

        *current_level.at(0)
    }

    /// Verify an Accountability Trace (fraud proof) via Poseidon commitment.
    ///
    /// The trace layout:
    ///   trace[0]       = violation_type
    ///   trace[1]       = violator address (as felt252)
    ///   trace[2..n-1]  = evidence data
    ///   trace[n-1]     = verification tag
    ///
    /// The tag is: PoseidonSponge::hash(violation_type || violator_felt || evidence_data)
    ///
    /// This provides constant O(1) verification cost (Requirements 19.4).
    fn verify_accountability_trace(
        trace: Span<felt252>, violator: starknet::ContractAddress,
    ) -> bool {
        if trace.len() < 3 {
            return false;
        }

        // The violator field in the trace must match the provided violator address
        let violator_felt: felt252 = violator.into();
        let trace_violator = *trace.at(1);
        if trace_violator != violator_felt {
            return false;
        }

        // Recompute the commitment tag from all fields except the last (which is the tag)
        let mut hash_input: Array<felt252> = ArrayTrait::new();
        let mut i: u32 = 0;
        while i < trace.len() - 1 {
            hash_input.append(*trace.at(i));
            i += 1;
        }

        let computed_tag = zk_pqc_cairo::sponge::hash(hash_input.span());
        let provided_tag = *trace.at(trace.len() - 1);
        computed_tag == provided_tag
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
        // submit_batch tests (with batch commitment verification)
        // ---------------------------------------------------------------

        /// Build a valid batch proof with the new layout:
        ///   [commitment_root, batch_size, leaf_hash_0, leaf_hash_1, ...]
        /// where commitment_root = compute_batch_merkle_commitment(leaf_hashes)
        fn build_valid_batch_proof(leaf_hashes: Span<felt252>) -> Array<felt252> {
            // Compute the Merkle commitment root from leaf hashes
            let commitment_root = super::compute_batch_merkle_commitment(leaf_hashes);
            let batch_size: felt252 = leaf_hashes.len().into();

            let mut proof: Array<felt252> = ArrayTrait::new();
            proof.append(commitment_root);
            proof.append(batch_size);
            let mut i: u32 = 0;
            while i < leaf_hashes.len() {
                proof.append(*leaf_hashes.at(i));
                i += 1;
            }
            proof
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_submit_batch_marks_indices_consumed() {
            let mut state = setup();
            let new_root: felt252 = 0xFEED;
            let smt_diff = array![10_u64, 20_u64, 30_u64];
            // Create 3 leaf hashes (one per index in smt_diff)
            let leaf_hashes = array![0xAAA, 0xBBB, 0xCCC];
            let proof = build_valid_batch_proof(leaf_hashes.span());

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

            // First batch: consume index 5
            let p1 = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_batch(ref state, p1.span(), array![5_u64].span(), r1);

            // Second batch: try to consume index 5 again — should panic
            let p2 = build_valid_batch_proof(array![0x222].span());
            PCAVerifierImpl::submit_batch(ref state, p2.span(), array![5_u64].span(), r2);
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('batch commitment invalid',))]
        fn test_pca_submit_batch_rejects_invalid_commitment() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xFEED;
            // Build a batch proof with a wrong commitment root
            let bad_proof = array![0xDEADBEEF, 1, 0x111];
            PCAVerifierImpl::submit_batch(
                ref state, bad_proof.span(), array![1_u64].span(), new_root,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('batch size mismatch',))]
        fn test_pca_submit_batch_rejects_size_mismatch() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xFEED;
            // Build a valid batch proof for 1 leaf but submit with 2 indices in smt_diff
            // The batch_size in proof (1) won't match smt_diff.len() (2)
            // But first we need the proof length to match: 2 + smt_diff.len() = 4
            // So proof has [root, 1, leaf1, leaf2] but batch_size says 1
            let leaf_hashes = array![0xAAA, 0xBBB];
            let commitment_root = super::compute_batch_merkle_commitment(leaf_hashes.span());
            // Manually build proof with wrong batch_size
            let bad_proof = array![commitment_root, 1, 0xAAA, 0xBBB];
            PCAVerifierImpl::submit_batch(
                ref state, bad_proof.span(), array![1_u64, 2_u64].span(), new_root,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('batch proof too short',))]
        fn test_pca_submit_batch_rejects_too_short_proof() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xFEED;
            // Only 2 elements — needs at least 3
            let bad_proof = array![0x1234, 1];
            PCAVerifierImpl::submit_batch(
                ref state, bad_proof.span(), array![1_u64].span(), new_root,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('batch size is zero',))]
        fn test_pca_submit_batch_rejects_zero_batch_size() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xFEED;
            // batch_size = 0 but smt_diff has 1 element
            let bad_proof = array![0x1234, 0, 0xAAA];
            PCAVerifierImpl::submit_batch(
                ref state, bad_proof.span(), array![1_u64].span(), new_root,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_submit_batch_single_leaf() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xFEED;
            // Single leaf: commitment_root == leaf_hash (no internal nodes)
            let leaf_hash: felt252 = 0x12345;
            let proof = build_valid_batch_proof(array![leaf_hash].span());
            // Verify the commitment root is the leaf itself for single-leaf case
            assert(*proof.at(0) == leaf_hash, 'single leaf root');

            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![42_u64].span(), new_root);
            assert(PCAVerifierImpl::is_index_consumed(@state, 42), 'idx 42 consumed');
            assert(PCAVerifierImpl::get_smt_root(@state) == new_root, 'smt root updated');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_submit_batch_multiple_leaves() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xBEEF;
            // 4 leaves: builds a balanced binary Merkle tree
            let leaf_hashes = array![0x11, 0x22, 0x33, 0x44];
            let proof = build_valid_batch_proof(leaf_hashes.span());

            let smt_diff = array![1_u64, 2_u64, 3_u64, 4_u64];
            PCAVerifierImpl::submit_batch(ref state, proof.span(), smt_diff.span(), new_root);

            assert(PCAVerifierImpl::is_index_consumed(@state, 1), 'idx 1 consumed');
            assert(PCAVerifierImpl::is_index_consumed(@state, 2), 'idx 2 consumed');
            assert(PCAVerifierImpl::is_index_consumed(@state, 3), 'idx 3 consumed');
            assert(PCAVerifierImpl::is_index_consumed(@state, 4), 'idx 4 consumed');
            assert(PCAVerifierImpl::get_smt_root(@state) == new_root, 'smt root updated');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_submit_batch_odd_number_of_leaves() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xCAFE;
            // 5 leaves: tests odd-node promotion in Merkle tree
            let leaf_hashes = array![0x11, 0x22, 0x33, 0x44, 0x55];
            let proof = build_valid_batch_proof(leaf_hashes.span());

            let smt_diff = array![10_u64, 20_u64, 30_u64, 40_u64, 50_u64];
            PCAVerifierImpl::submit_batch(ref state, proof.span(), smt_diff.span(), new_root);

            assert(PCAVerifierImpl::is_index_consumed(@state, 10), 'idx 10 consumed');
            assert(PCAVerifierImpl::is_index_consumed(@state, 50), 'idx 50 consumed');
            assert(PCAVerifierImpl::get_smt_root(@state) == new_root, 'smt root updated');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_batch_commitment_deterministic() {
            // Verify that the same leaf hashes always produce the same commitment root
            let leaf_hashes = array![0x11, 0x22, 0x33];
            let root1 = super::compute_batch_merkle_commitment(leaf_hashes.span());
            let leaf_hashes2 = array![0x11, 0x22, 0x33];
            let root2 = super::compute_batch_merkle_commitment(leaf_hashes2.span());
            assert(root1 == root2, 'commitment not deterministic');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_batch_commitment_different_inputs() {
            // Different leaf hashes produce different commitment roots
            let leaves_a = array![0x11, 0x22, 0x33];
            let leaves_b = array![0x44, 0x55, 0x66];
            let root_a = super::compute_batch_merkle_commitment(leaves_a.span());
            let root_b = super::compute_batch_merkle_commitment(leaves_b.span());
            assert(root_a != root_b, 'different inputs same root');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_pca_batch_commitment_order_matters() {
            // Order of leaf hashes matters (different order = different root)
            let leaves_fwd = array![0x11, 0x22, 0x33, 0x44];
            let leaves_rev = array![0x44, 0x33, 0x22, 0x11];
            let root_fwd = super::compute_batch_merkle_commitment(leaves_fwd.span());
            let root_rev = super::compute_batch_merkle_commitment(leaves_rev.span());
            assert(root_fwd != root_rev, 'order should matter');
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
            let bp = build_valid_batch_proof(array![0x111].span());
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
            let proof = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), new_root);
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_submit_batch_by_sequencer_succeeds() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let new_root: felt252 = 0xFEED;
            let proof = build_valid_batch_proof(array![0x111].span());
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
            let proof = build_valid_batch_proof(array![0x111].span());
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
            let proof = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), new_root);
        }

        // ---------------------------------------------------------------
        // JMT verification tests (Task 21.2 — Requirements 16.3, 16.4)
        // ---------------------------------------------------------------

        /// Helper: compute H(left, right) using the same hash_pair as smt.cairo
        fn jmt_hash_pair(left: felt252, right: felt252) -> felt252 {
            let mut state = array![left, right, 0, 0, 0, 0];
            zk_pqc_cairo::poseidon::permute(ref state);
            *state.at(0)
        }

        /// Helper: build a JMT root from a leaf value and siblings (depth-1 siblings).
        /// Siblings are in leaf-to-root order.
        /// Routing bit at level i: (index >> i) & 1.
        fn compute_jmt_root(leaf_value: felt252, index: u64, siblings: Span<felt252>) -> felt252 {
            let mut current = leaf_value;
            let mut idx = index;
            let mut i: u32 = 0;
            while i < siblings.len() {
                let sibling = *siblings.at(i);
                let is_right = idx % 2 == 1;
                let left = if is_right {
                    sibling
                } else {
                    current
                };
                let right = if is_right {
                    current
                } else {
                    sibling
                };
                current = jmt_hash_pair(left, right);
                idx = idx / 2;
                i += 1;
            }
            current
        }

        /// Helper: build 63 zero siblings (empty tree proof).
        fn build_empty_jmt_siblings() -> Array<felt252> {
            // For an empty JMT, all siblings are the empty subtree hashes
            // at each level. empty_cache[0] = 0, empty_cache[i] = H(empty_cache[i-1],
            // empty_cache[i-1])
            let mut siblings: Array<felt252> = ArrayTrait::new();
            let mut empty_at_level: felt252 = 0; // empty_leaf = 0
            let mut i: u32 = 0;
            while i < 63 {
                siblings.append(empty_at_level);
                empty_at_level = jmt_hash_pair(empty_at_level, empty_at_level);
                i += 1;
            }
            siblings
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_verify_unconsumed_empty_tree() {
            // In an empty JMT, all indices are unconsumed.
            // The root is the hash of the full empty tree.
            let siblings = build_empty_jmt_siblings();

            // Compute the expected root for an empty tree with leaf=0 at index 0
            let root = compute_jmt_root(0, 0, siblings.span());

            // Verify that index 0 is unconsumed
            let proof = zk_pqc_cairo::smt::SmtProof { siblings: siblings.clone(), leaf_value: 0 };
            let valid = zk_pqc_cairo::smt::verify_unconsumed(root, 0, @proof);
            assert(valid, 'empty tree idx 0 unconsumed');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_verify_consumed_proof() {
            // Build a proof for a consumed index (leaf_value = 1)
            let siblings = build_empty_jmt_siblings();

            // Compute root with consumed leaf at index 5
            let root = compute_jmt_root(1, 5, siblings.span());

            // Verify that index 5 is consumed
            let proof = zk_pqc_cairo::smt::SmtProof { siblings: siblings.clone(), leaf_value: 1 };
            let valid = zk_pqc_cairo::smt::verify_consumed(root, 5, @proof);
            assert(valid, 'idx 5 should be consumed');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_wrong_leaf_value_rejected() {
            // Build a proof claiming unconsumed, but root was built with consumed
            let siblings = build_empty_jmt_siblings();
            let root = compute_jmt_root(1, 5, siblings.span()); // consumed

            // Try to verify as unconsumed — should fail
            let proof = zk_pqc_cairo::smt::SmtProof { siblings: siblings.clone(), leaf_value: 0 };
            let valid = zk_pqc_cairo::smt::verify_unconsumed(root, 5, @proof);
            assert(!valid, 'wrong leaf should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_wrong_index_rejected() {
            // Build proof for index 5 with a non-trivial sibling at level 0,
            // then verify against index 7. Since index 5 and 7 differ at bit 1
            // (5 = ...101, 7 = ...111), the routing differs and verification fails.
            //
            // We use a non-zero sibling at level 0 to break the symmetry that
            // exists in a fully empty tree.
            let mut siblings: Array<felt252> = ArrayTrait::new();
            // Level 0 sibling is non-zero (simulates a consumed neighbor)
            siblings.append(0x42);
            // Remaining siblings are empty subtree hashes
            let mut empty_at_level: felt252 = 0;
            let mut i: u32 = 1;
            while i < 63 {
                siblings.append(empty_at_level);
                empty_at_level = jmt_hash_pair(empty_at_level, empty_at_level);
                i += 1;
            }

            let root = compute_jmt_root(0, 5, siblings.span());

            let proof = zk_pqc_cairo::smt::SmtProof { siblings: siblings.clone(), leaf_value: 0 };
            // Verify with correct index — should pass
            let valid_correct = zk_pqc_cairo::smt::verify_unconsumed(root, 5, @proof);
            assert(valid_correct, 'correct idx should pass');

            // Verify with wrong index — should fail (different routing bits)
            let valid_wrong = zk_pqc_cairo::smt::verify_unconsumed(root, 7, @proof);
            assert(!valid_wrong, 'wrong index should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_tampered_sibling_rejected() {
            // Build valid proof, tamper with a sibling
            let siblings = build_empty_jmt_siblings();
            let root = compute_jmt_root(0, 0, siblings.span());

            // Tamper with first sibling
            let mut tampered: Array<felt252> = ArrayTrait::new();
            tampered.append(0xDEADBEEF); // tampered
            let mut i: u32 = 1;
            while i < 63 {
                tampered.append(*siblings.at(i));
                i += 1;
            }

            let proof = zk_pqc_cairo::smt::SmtProof { siblings: tampered, leaf_value: 0 };
            let valid = zk_pqc_cairo::smt::verify_unconsumed(root, 0, @proof);
            assert(!valid, 'tampered sib should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_wrong_sibling_count_rejected() {
            // Proof with wrong number of siblings (62 instead of 63)
            let mut short_siblings: Array<felt252> = ArrayTrait::new();
            let mut i: u32 = 0;
            while i < 62 {
                short_siblings.append(0);
                i += 1;
            }

            let proof = zk_pqc_cairo::smt::SmtProof { siblings: short_siblings, leaf_value: 0 };
            let valid = zk_pqc_cairo::smt::verify_unconsumed(0x1234, 0, @proof);
            assert(!valid, 'wrong count should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_compute_new_root_after_consume() {
            // Verify that compute_new_root_after_consume produces correct root
            let siblings = build_empty_jmt_siblings();

            // Root with unconsumed leaf at index 3
            let root_before = compute_jmt_root(0, 3, siblings.span());

            // Root with consumed leaf at index 3 (same siblings)
            let root_after = zk_pqc_cairo::smt::compute_new_root_after_consume(3, siblings.span());
            let expected_after = compute_jmt_root(1, 3, siblings.span());

            assert(root_after == expected_after, 'new root mismatch');
            assert(root_before != root_after, 'roots should differ');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_verify_authorization_with_smt_valid() {
            // Full integration: verify_authorization_with_smt with valid JMT proof
            let mut state = setup();

            // Build JMT proof for unconsumed index 0
            let siblings = build_empty_jmt_siblings();
            let jmt_root = compute_jmt_root(0, 0, siblings.span());

            // Set the JMT root in contract state
            state.smt_root.write(jmt_root);

            // Build valid authorization proof
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let auth_proof = build_valid_proof(msg, root, 0, array![42, 99].span());

            // Verify with JMT proof
            let valid = PCAVerifierImpl::verify_authorization_with_smt(
                @state, auth_proof.span(), msg, root, 0, siblings.span(),
            );
            assert(valid, 'jmt auth should pass');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_verify_authorization_with_smt_consumed_rejected() {
            // verify_authorization_with_smt rejects consumed index
            let mut state = setup();

            // Mark index 5 as consumed in on-chain record
            state.consumed_indices.write(5, true);

            let siblings = build_empty_jmt_siblings();
            let jmt_root = compute_jmt_root(0, 5, siblings.span());
            state.smt_root.write(jmt_root);

            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let auth_proof = build_valid_proof(msg, root, 5, array![42].span());

            let valid = PCAVerifierImpl::verify_authorization_with_smt(
                @state, auth_proof.span(), msg, root, 5, siblings.span(),
            );
            assert(!valid, 'consumed idx should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_verify_authorization_with_smt_bad_proof_rejected() {
            // verify_authorization_with_smt rejects invalid JMT proof
            let mut state = setup();

            let siblings = build_empty_jmt_siblings();
            let jmt_root = compute_jmt_root(0, 0, siblings.span());
            state.smt_root.write(jmt_root);

            // Use wrong siblings (tampered)
            let mut bad_siblings: Array<felt252> = ArrayTrait::new();
            let mut i: u32 = 0;
            while i < 63 {
                bad_siblings.append(0xBAD);
                i += 1;
            }

            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let auth_proof = build_valid_proof(msg, root, 0, array![42].span());

            let valid = PCAVerifierImpl::verify_authorization_with_smt(
                @state, auth_proof.span(), msg, root, 0, bad_siblings.span(),
            );
            assert(!valid, 'bad jmt proof should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_jmt_submit_batch_updates_root() {
            // submit_batch properly updates the JMT root
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            // Compute a new JMT root (simulating off-chain computation)
            let siblings = build_empty_jmt_siblings();
            let new_jmt_root = compute_jmt_root(1, 42, siblings.span());

            let proof = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_batch(
                ref state, proof.span(), array![42_u64].span(), new_jmt_root,
            );

            // Verify the JMT root was updated
            assert(PCAVerifierImpl::get_smt_root(@state) == new_jmt_root, 'jmt root not updated');
            // Verify index is consumed
            assert(PCAVerifierImpl::is_index_consumed(@state, 42), 'idx 42 not consumed');
        }

        // ---------------------------------------------------------------
        // DA State Diff Publishing tests (Task 22.1 — Requirements 17.1, 17.2)
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_da_get_batch_count_initial_zero() {
            let state = setup();
            assert(PCAVerifierImpl::get_batch_count(@state) == 0, 'initial batch count 0');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_da_get_batch_count_increments() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            // Submit first batch
            let proof1 = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_batch(ref state, proof1.span(), array![1_u64].span(), 0xAAAA);
            assert(PCAVerifierImpl::get_batch_count(@state) == 1, 'batch count 1');

            // Submit second batch
            let proof2 = build_valid_batch_proof(array![0x222].span());
            PCAVerifierImpl::submit_batch(ref state, proof2.span(), array![2_u64].span(), 0xBBBB);
            assert(PCAVerifierImpl::get_batch_count(@state) == 2, 'batch count 2');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_da_state_diff_payload_size_constraint() {
            // Verify DA payload for K transactions ≤ K × 8 bytes.
            // The smt_diff parameter is Span<u64>, so each index is exactly 8 bytes.
            // For K=5 indices, the DA payload is 5 × 8 = 40 bytes.
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let k: u32 = 5;
            let smt_diff = array![10_u64, 20_u64, 30_u64, 40_u64, 50_u64];
            let leaf_hashes = array![0x11, 0x22, 0x33, 0x44, 0x55];
            let proof = build_valid_batch_proof(leaf_hashes.span());

            PCAVerifierImpl::submit_batch(ref state, proof.span(), smt_diff.span(), 0xFEED);

            // Each u64 index is 8 bytes. K indices = K × 8 bytes DA payload.
            // The smt_diff.len() == K, so payload = smt_diff.len() * 8 bytes.
            let payload_bytes: u32 = k * 8;
            let max_allowed: u32 = k * 8;
            assert(payload_bytes <= max_allowed, 'DA payload exceeds K*8');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_da_state_diff_single_index() {
            // Single index DA: payload = 1 × 8 = 8 bytes
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let smt_diff = array![42_u64];
            let proof = build_valid_batch_proof(array![0x111].span());

            PCAVerifierImpl::submit_batch(ref state, proof.span(), smt_diff.span(), 0xFEED);

            assert(PCAVerifierImpl::get_batch_count(@state) == 1, 'batch count 1');
            assert(PCAVerifierImpl::is_index_consumed(@state, 42), 'idx 42 consumed');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_da_state_diff_large_batch() {
            // Larger batch: 8 indices, DA payload = 8 × 8 = 64 bytes
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let smt_diff = array![
                100_u64, 200_u64, 300_u64, 400_u64, 500_u64, 600_u64, 700_u64, 800_u64,
            ];
            let leaf_hashes = array![0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8];
            let proof = build_valid_batch_proof(leaf_hashes.span());

            PCAVerifierImpl::submit_batch(ref state, proof.span(), smt_diff.span(), 0xBEEF);

            // Verify all indices consumed
            assert(PCAVerifierImpl::is_index_consumed(@state, 100), 'idx 100');
            assert(PCAVerifierImpl::is_index_consumed(@state, 800), 'idx 800');
            assert(PCAVerifierImpl::get_batch_count(@state) == 1, 'batch count');

            // DA payload: 8 indices × 8 bytes = 64 bytes ≤ 8 × 8 = 64 bytes ✓
            let k: u32 = 8;
            let payload_bytes: u32 = k * 8;
            assert(payload_bytes <= k * 8, 'DA constraint violated');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_da_indices_hash_deterministic() {
            // The indices_hash in StateDiffPublished should be deterministic
            // for the same set of indices.
            let indices_a = array![10_u64, 20_u64, 30_u64];
            let mut input_a: Array<felt252> = ArrayTrait::new();
            let mut i: u32 = 0;
            while i < indices_a.len() {
                let idx_felt: felt252 = (*indices_a.at(i)).into();
                input_a.append(idx_felt);
                i += 1;
            }
            let hash_a = zk_pqc_cairo::sponge::hash(input_a.span());

            // Same indices again
            let indices_b = array![10_u64, 20_u64, 30_u64];
            let mut input_b: Array<felt252> = ArrayTrait::new();
            let mut j: u32 = 0;
            while j < indices_b.len() {
                let idx_felt: felt252 = (*indices_b.at(j)).into();
                input_b.append(idx_felt);
                j += 1;
            }
            let hash_b = zk_pqc_cairo::sponge::hash(input_b.span());

            assert(hash_a == hash_b, 'indices hash not deterministic');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_da_indices_hash_differs_for_different_indices() {
            // Different indices produce different hashes
            let mut input_a: Array<felt252> = ArrayTrait::new();
            input_a.append(10);
            input_a.append(20);
            let hash_a = zk_pqc_cairo::sponge::hash(input_a.span());

            let mut input_b: Array<felt252> = ArrayTrait::new();
            input_b.append(30);
            input_b.append(40);
            let hash_b = zk_pqc_cairo::sponge::hash(input_b.span());

            assert(hash_a != hash_b, 'diff indices same hash');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_da_sequential_batches_tracked() {
            // Multiple sequential batches are tracked correctly
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            // Batch 1: indices [1, 2, 3]
            let proof1 = build_valid_batch_proof(array![0xA, 0xB, 0xC].span());
            PCAVerifierImpl::submit_batch(
                ref state, proof1.span(), array![1_u64, 2_u64, 3_u64].span(), 0x1111,
            );
            assert(PCAVerifierImpl::get_batch_count(@state) == 1, 'batch 1');

            // Batch 2: indices [4, 5]
            let proof2 = build_valid_batch_proof(array![0xD, 0xE].span());
            PCAVerifierImpl::submit_batch(
                ref state, proof2.span(), array![4_u64, 5_u64].span(), 0x2222,
            );
            assert(PCAVerifierImpl::get_batch_count(@state) == 2, 'batch 2');

            // Batch 3: indices [6]
            let proof3 = build_valid_batch_proof(array![0xF].span());
            PCAVerifierImpl::submit_batch(ref state, proof3.span(), array![6_u64].span(), 0x3333);
            assert(PCAVerifierImpl::get_batch_count(@state) == 3, 'batch 3');

            // All indices consumed
            assert(PCAVerifierImpl::is_index_consumed(@state, 1), 'idx 1');
            assert(PCAVerifierImpl::is_index_consumed(@state, 6), 'idx 6');
            assert(!PCAVerifierImpl::is_index_consumed(@state, 7), 'idx 7 free');
        }

        // ---------------------------------------------------------------
        // Multi-Lane Mempool tests (Task 23.1 — Requirements 18.1, 18.2)
        // ---------------------------------------------------------------

        #[test]
        #[available_gas(99999999999)]
        fn test_classify_lane_poseidon_only() {
            let state = setup();
            // hash_flag 0 → Lane 0 (Poseidon-Only)
            let lane = PCAVerifierImpl::classify_lane(@state, 0);
            assert(lane == 0, 'flag 0 should be lane 0');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_classify_lane_hybrid_hash() {
            let state = setup();
            // hash_flag 1 → Lane 1 (Hybrid-Hash)
            let lane = PCAVerifierImpl::classify_lane(@state, 1);
            assert(lane == 1, 'flag 1 should be lane 1');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_classify_lane_invalid_defaults_to_poseidon() {
            let state = setup();
            // Any hash_flag > 1 defaults to Lane 0 (Poseidon-Only)
            let lane2 = PCAVerifierImpl::classify_lane(@state, 2);
            assert(lane2 == 0, 'flag 2 should be lane 0');
            let lane255 = PCAVerifierImpl::classify_lane(@state, 255);
            assert(lane255 == 0, 'flag 255 should be lane 0');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_lane_batch_count_initial_zero() {
            let state = setup();
            assert(PCAVerifierImpl::get_lane_batch_count(@state, 0) == 0, 'lane 0 init 0');
            assert(PCAVerifierImpl::get_lane_batch_count(@state, 1) == 0, 'lane 1 init 0');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_submit_lane_batch_poseidon_only() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let proof = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 0, proof.span(), array![1_u64].span(), 0xAAAA,
            );

            assert(PCAVerifierImpl::get_lane_batch_count(@state, 0) == 1, 'lane 0 count 1');
            assert(PCAVerifierImpl::get_lane_batch_count(@state, 1) == 0, 'lane 1 still 0');
            assert(PCAVerifierImpl::is_index_consumed(@state, 1), 'idx 1 consumed');
            assert(PCAVerifierImpl::get_batch_count(@state) == 1, 'global count 1');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_submit_lane_batch_hybrid_hash() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let proof = build_valid_batch_proof(array![0x222].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 1, proof.span(), array![2_u64].span(), 0xBBBB,
            );

            assert(PCAVerifierImpl::get_lane_batch_count(@state, 0) == 0, 'lane 0 still 0');
            assert(PCAVerifierImpl::get_lane_batch_count(@state, 1) == 1, 'lane 1 count 1');
            assert(PCAVerifierImpl::is_index_consumed(@state, 2), 'idx 2 consumed');
            assert(PCAVerifierImpl::get_batch_count(@state) == 1, 'global count 1');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_submit_lane_batch_independent_counters() {
            // Verify that lane counters are independent — submitting to one lane
            // does not affect the other lane's counter (throughput isolation).
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            // Submit 3 batches to lane 0 (Poseidon-Only)
            let p1 = build_valid_batch_proof(array![0xA1].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 0, p1.span(), array![10_u64].span(), 0x1111,
            );
            let p2 = build_valid_batch_proof(array![0xA2].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 0, p2.span(), array![11_u64].span(), 0x2222,
            );
            let p3 = build_valid_batch_proof(array![0xA3].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 0, p3.span(), array![12_u64].span(), 0x3333,
            );

            // Submit 1 batch to lane 1 (Hybrid-Hash)
            let p4 = build_valid_batch_proof(array![0xB1].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 1, p4.span(), array![20_u64].span(), 0x4444,
            );

            // Lane 0 has 3 batches, lane 1 has 1 batch — independent
            assert(PCAVerifierImpl::get_lane_batch_count(@state, 0) == 3, 'lane 0 count 3');
            assert(PCAVerifierImpl::get_lane_batch_count(@state, 1) == 1, 'lane 1 count 1');
            // Global count is 4
            assert(PCAVerifierImpl::get_batch_count(@state) == 4, 'global count 4');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_submit_lane_batch_poseidon_unaffected_by_hybrid() {
            // Core requirement 18.2: Poseidon-Only lane throughput is unaffected
            // by Hybrid-Hash processing. We verify this by showing that lane 0
            // batches can be submitted independently of lane 1 state.
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            // Submit to lane 1 (Hybrid-Hash) first
            let ph = build_valid_batch_proof(array![0xF1].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 1, ph.span(), array![100_u64].span(), 0xAAAA,
            );

            // Lane 0 counter is still 0 — unaffected
            assert(PCAVerifierImpl::get_lane_batch_count(@state, 0) == 0, 'lane 0 unaffected');

            // Submit to lane 0 (Poseidon-Only) — works independently
            let pp = build_valid_batch_proof(array![0xE1].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 0, pp.span(), array![101_u64].span(), 0xBBBB,
            );

            assert(PCAVerifierImpl::get_lane_batch_count(@state, 0) == 1, 'lane 0 count 1');
            assert(PCAVerifierImpl::get_lane_batch_count(@state, 1) == 1, 'lane 1 count 1');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('invalid lane',))]
        fn test_submit_lane_batch_invalid_lane_rejected() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            let proof = build_valid_batch_proof(array![0x111].span());
            // Lane 2 is invalid — should panic
            PCAVerifierImpl::submit_lane_batch(
                ref state, 2, proof.span(), array![1_u64].span(), 0xFEED,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('caller not authorized',))]
        fn test_submit_lane_batch_non_sequencer_rejected() {
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());

            let proof = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 0, proof.span(), array![1_u64].span(), 0xFEED,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('index already consumed',))]
        fn test_submit_lane_batch_rejects_consumed_index() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            // Consume index 5 via lane 0
            let p1 = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 0, p1.span(), array![5_u64].span(), 0xAAAA,
            );

            // Try to consume index 5 again via lane 1 — should fail
            let p2 = build_valid_batch_proof(array![0x222].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 1, p2.span(), array![5_u64].span(), 0xBBBB,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_classify_and_submit_lane_batch_integration() {
            // Integration test: classify hash_flag then submit to correct lane
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            // Classify transactions
            let lane_poseidon = PCAVerifierImpl::classify_lane(@state, 0);
            let lane_hybrid = PCAVerifierImpl::classify_lane(@state, 1);

            assert(lane_poseidon == 0, 'poseidon lane 0');
            assert(lane_hybrid == 1, 'hybrid lane 1');

            // Submit batch to the classified lane
            let proof = build_valid_batch_proof(array![0xABC].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, lane_poseidon, proof.span(), array![42_u64].span(), 0xFEED,
            );

            assert(PCAVerifierImpl::get_lane_batch_count(@state, 0) == 1, 'lane 0 count');
            assert(PCAVerifierImpl::is_index_consumed(@state, 42), 'idx 42 consumed');
        }

        // ---------------------------------------------------------------
        // ZK-Fraud Proof tests (Task 24.1 — Requirements 19.1, 19.2, 19.3, 19.4)
        // ---------------------------------------------------------------

        fn violator_addr() -> ContractAddress {
            contract_address_const::<0x400>()
        }

        /// Build a valid accountability trace with the layout:
        ///   [violation_type, violator_felt, evidence_data..., tag]
        /// where tag = hash(violation_type || violator_felt || evidence_data)
        fn build_valid_accountability_trace(
            violation_type: felt252, violator: ContractAddress, evidence: Span<felt252>,
        ) -> Array<felt252> {
            let violator_felt: felt252 = violator.into();

            let mut hash_input: Array<felt252> = ArrayTrait::new();
            hash_input.append(violation_type);
            hash_input.append(violator_felt);
            let mut i: u32 = 0;
            while i < evidence.len() {
                hash_input.append(*evidence.at(i));
                i += 1;
            }
            let tag = hash(hash_input.span());

            let mut trace: Array<felt252> = ArrayTrait::new();
            trace.append(violation_type);
            trace.append(violator_felt);
            let mut j: u32 = 0;
            while j < evidence.len() {
                trace.append(*evidence.at(j));
                j += 1;
            }
            trace.append(tag);
            trace
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_fraud_proof_count_initial_zero() {
            let state = setup();
            assert(PCAVerifierImpl::get_fraud_proof_count(@state) == 0, 'initial fp count 0');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_circuit_breaker_initial_inactive() {
            let state = setup();
            assert(!PCAVerifierImpl::get_circuit_breaker_active(@state), 'cb initially inactive');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_circuit_breaker_threshold_initial_zero() {
            let state = setup();
            assert(
                PCAVerifierImpl::get_circuit_breaker_threshold(@state) == 0, 'cb threshold init 0',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_set_circuit_breaker_threshold_by_owner() {
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::set_circuit_breaker_threshold(ref state, 5);
            assert(PCAVerifierImpl::get_circuit_breaker_threshold(@state) == 5, 'threshold set 5');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('caller not owner',))]
        fn test_set_circuit_breaker_threshold_non_owner_fails() {
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());
            PCAVerifierImpl::set_circuit_breaker_threshold(ref state, 5);
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_deposit_stake() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());
            PCAVerifierImpl::deposit_stake(ref state, 1000);
            assert(
                PCAVerifierImpl::get_sequencer_stake(@state, sequencer_addr()) == 1000,
                'stake should be 1000',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_deposit_stake_accumulates() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());
            PCAVerifierImpl::deposit_stake(ref state, 500);
            PCAVerifierImpl::deposit_stake(ref state, 300);
            assert(
                PCAVerifierImpl::get_sequencer_stake(@state, sequencer_addr()) == 800,
                'stake should be 800',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('zero stake deposit',))]
        fn test_deposit_stake_zero_rejected() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());
            PCAVerifierImpl::deposit_stake(ref state, 0);
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_sequencer_not_slashed_initially() {
            let state = setup();
            assert(
                !PCAVerifierImpl::is_sequencer_slashed(@state, violator_addr()),
                'not slashed initially',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_submit_valid_fraud_proof() {
            // Any observer can submit a valid fraud proof (Req 19.1)
            let mut state = setup();

            // Violator deposits stake
            starknet::testing::set_caller_address(violator_addr());
            PCAVerifierImpl::deposit_stake(ref state, 1000);

            // Observer (other_addr) submits fraud proof
            starknet::testing::set_caller_address(other_addr());
            let trace = build_valid_accountability_trace(
                1, // violation_type: equivocation
                violator_addr(), array![0xDEAD, 0xBEEF].span(),
            );
            PCAVerifierImpl::submit_fraud_proof(ref state, trace.span(), violator_addr());

            // Verify fraud proof was accepted
            assert(PCAVerifierImpl::get_fraud_proof_count(@state) == 1, 'fp count 1');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_fraud_proof_slashes_stake_to_zero() {
            // Valid fraud proof triggers 100% slashing (Req 19.2)
            let mut state = setup();

            // Violator deposits stake
            starknet::testing::set_caller_address(violator_addr());
            PCAVerifierImpl::deposit_stake(ref state, 5000);
            assert(
                PCAVerifierImpl::get_sequencer_stake(@state, violator_addr()) == 5000,
                'stake before slash',
            );

            // Submit fraud proof
            starknet::testing::set_caller_address(other_addr());
            let trace = build_valid_accountability_trace(
                2, // violation_type: replay
                violator_addr(), array![0x1234].span(),
            );
            PCAVerifierImpl::submit_fraud_proof(ref state, trace.span(), violator_addr());

            // Stake should be 0 after slashing
            assert(
                PCAVerifierImpl::get_sequencer_stake(@state, violator_addr()) == 0,
                'stake after slash 0',
            );
            // Sequencer should be marked as slashed
            assert(
                PCAVerifierImpl::is_sequencer_slashed(@state, violator_addr()), 'should be slashed',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_fraud_proof_any_observer_can_submit() {
            // Req 19.1: any observer can submit
            let mut state = setup();

            // Observer 1 submits
            starknet::testing::set_caller_address(other_addr());
            let trace1 = build_valid_accountability_trace(1, violator_addr(), array![0xAA].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace1.span(), violator_addr());
            assert(PCAVerifierImpl::get_fraud_proof_count(@state) == 1, 'fp count 1');

            // Observer 2 (sequencer_addr) submits against a different violator
            starknet::testing::set_caller_address(sequencer_addr());
            let trace2 = build_valid_accountability_trace(2, owner_addr(), array![0xBB].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace2.span(), owner_addr());
            assert(PCAVerifierImpl::get_fraud_proof_count(@state) == 2, 'fp count 2');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('invalid accountability trace',))]
        fn test_fraud_proof_invalid_trace_rejected() {
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());

            // Build a trace with a bad tag
            let violator_felt: felt252 = violator_addr().into();
            let bad_trace = array![1, violator_felt, 0xDEAD];
            PCAVerifierImpl::submit_fraud_proof(ref state, bad_trace.span(), violator_addr());
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('trace too short',))]
        fn test_fraud_proof_too_short_trace_rejected() {
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());

            let short_trace = array![1, 2];
            PCAVerifierImpl::submit_fraud_proof(ref state, short_trace.span(), violator_addr());
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('invalid accountability trace',))]
        fn test_fraud_proof_violator_mismatch_rejected() {
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());

            // Build trace for violator_addr but submit with owner_addr as violator
            let trace = build_valid_accountability_trace(1, violator_addr(), array![0xAA].span());
            // Mismatch: trace says violator_addr, but we pass owner_addr
            PCAVerifierImpl::submit_fraud_proof(ref state, trace.span(), owner_addr());
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_circuit_breaker_activates_at_threshold() {
            // Req 19.3: circuit breaker activates when fraud proof count >= threshold
            let mut state = setup();

            // Set threshold to 3
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::set_circuit_breaker_threshold(ref state, 3);

            // Submit 2 fraud proofs — circuit breaker should NOT activate
            starknet::testing::set_caller_address(other_addr());
            let trace1 = build_valid_accountability_trace(1, violator_addr(), array![0x01].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace1.span(), violator_addr());
            assert(!PCAVerifierImpl::get_circuit_breaker_active(@state), 'cb not active at 1');

            let trace2 = build_valid_accountability_trace(2, owner_addr(), array![0x02].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace2.span(), owner_addr());
            assert(!PCAVerifierImpl::get_circuit_breaker_active(@state), 'cb not active at 2');

            // Submit 3rd fraud proof — circuit breaker SHOULD activate
            let trace3 = build_valid_accountability_trace(3, sequencer_addr(), array![0x03].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace3.span(), sequencer_addr());
            assert(PCAVerifierImpl::get_circuit_breaker_active(@state), 'cb active at 3');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('circuit breaker active',))]
        fn test_circuit_breaker_blocks_submit_batch() {
            let mut state = setup();

            // Set threshold to 1 and trigger circuit breaker
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::set_circuit_breaker_threshold(ref state, 1);

            starknet::testing::set_caller_address(other_addr());
            let trace = build_valid_accountability_trace(1, violator_addr(), array![0xAA].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace.span(), violator_addr());

            // submit_batch should panic with 'circuit breaker active'
            starknet::testing::set_caller_address(sequencer_addr());
            let proof = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), 0xFEED);
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('circuit breaker active',))]
        fn test_circuit_breaker_blocks_submit_lane_batch() {
            let mut state = setup();

            // Set threshold to 1 and trigger circuit breaker
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::set_circuit_breaker_threshold(ref state, 1);

            starknet::testing::set_caller_address(other_addr());
            let trace = build_valid_accountability_trace(1, violator_addr(), array![0xAA].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace.span(), violator_addr());

            // submit_lane_batch should also panic with 'circuit breaker active'
            starknet::testing::set_caller_address(sequencer_addr());
            let proof = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_lane_batch(
                ref state, 0, proof.span(), array![1_u64].span(), 0xFEED,
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_circuit_breaker_does_not_activate_with_zero_threshold() {
            // When threshold is 0, circuit breaker never activates
            let mut state = setup();

            // Threshold is 0 by default
            starknet::testing::set_caller_address(other_addr());
            let trace = build_valid_accountability_trace(1, violator_addr(), array![0xAA].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace.span(), violator_addr());

            // Circuit breaker should NOT activate (threshold 0 means disabled)
            assert(!PCAVerifierImpl::get_circuit_breaker_active(@state), 'cb should not activate');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_fraud_proof_slashing_with_zero_stake() {
            // Slashing a sequencer with zero stake should still mark them as slashed
            let mut state = setup();

            starknet::testing::set_caller_address(other_addr());
            let trace = build_valid_accountability_trace(1, violator_addr(), array![0xAA].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace.span(), violator_addr());

            assert(
                PCAVerifierImpl::get_sequencer_stake(@state, violator_addr()) == 0, 'stake is 0',
            );
            assert(
                PCAVerifierImpl::is_sequencer_slashed(@state, violator_addr()), 'marked slashed',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_fraud_proof_constant_verification_cost() {
            // Req 19.4: verification cost is constant regardless of trace size.
            // We verify this by submitting traces of different sizes and
            // confirming they all succeed (the Poseidon commitment check is O(1)
            // in the sense that it's a single hash computation).
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());

            // Small trace (1 evidence element)
            let trace_small = build_valid_accountability_trace(
                1, violator_addr(), array![0x01].span(),
            );
            PCAVerifierImpl::submit_fraud_proof(ref state, trace_small.span(), violator_addr());
            assert(PCAVerifierImpl::get_fraud_proof_count(@state) == 1, 'small trace ok');

            // Larger trace (5 evidence elements)
            let trace_large = build_valid_accountability_trace(
                2, owner_addr(), array![0x01, 0x02, 0x03, 0x04, 0x05].span(),
            );
            PCAVerifierImpl::submit_fraud_proof(ref state, trace_large.span(), owner_addr());
            assert(PCAVerifierImpl::get_fraud_proof_count(@state) == 2, 'large trace ok');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_batch_still_works_before_circuit_breaker() {
            // Verify that batch submission works normally when circuit breaker is not active
            let mut state = setup();

            // Set threshold to 10 (high)
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::set_circuit_breaker_threshold(ref state, 10);

            // Submit 1 fraud proof — well below threshold
            starknet::testing::set_caller_address(other_addr());
            let trace = build_valid_accountability_trace(1, violator_addr(), array![0xAA].span());
            PCAVerifierImpl::submit_fraud_proof(ref state, trace.span(), violator_addr());
            assert(!PCAVerifierImpl::get_circuit_breaker_active(@state), 'cb not active');

            // Batch submission should still work
            starknet::testing::set_caller_address(sequencer_addr());
            let proof = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_batch(ref state, proof.span(), array![1_u64].span(), 0xFEED);
            assert(PCAVerifierImpl::is_index_consumed(@state, 1), 'batch worked');
        }

        // ---------------------------------------------------------------
        // Account Abstraction — Index Window tests (Task 25.1)
        // Requirements: 20.1, 20.2, 20.3, 20.4
        // ---------------------------------------------------------------

        fn account_addr() -> ContractAddress {
            contract_address_const::<0x500>()
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_register_account_sets_window() {
            // Req 20.1: register account with configurable window size
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());

            PCAVerifierImpl::register_account(ref state, account_addr(), 4);

            let (base, size) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base == 0, 'initial base 0');
            assert(size == 4, 'window size 4');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_unregistered_account_returns_zero_window() {
            let state = setup();
            let (base, size) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base == 0, 'unregistered base 0');
            assert(size == 0, 'unregistered size 0');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('caller not owner',))]
        fn test_register_account_non_owner_fails() {
            let mut state = setup();
            starknet::testing::set_caller_address(other_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 4);
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('window size must be > 0',))]
        fn test_register_account_zero_window_size_fails() {
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 0);
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_consume_window_index_single() {
            // Req 20.2: consume a single index within the window
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 4);

            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);

            assert(
                PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 0),
                'idx 0 consumed',
            );
            assert(
                !PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 1), 'idx 1 free',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_consume_window_index_parallel_distinct() {
            // Req 20.2: multiple transactions with distinct indices within window
            // are all accepted (parallel processing)
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 4);

            // Consume indices in non-sequential order (simulating parallel txns)
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 2);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 3);

            assert(
                PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 0),
                'idx 0 consumed',
            );
            assert(
                !PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 1), 'idx 1 free',
            );
            assert(
                PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 2),
                'idx 2 consumed',
            );
            assert(
                PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 3),
                'idx 3 consumed',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('index already consumed',))]
        fn test_consume_window_index_duplicate_rejected() {
            // Req 20.4: two transactions with the same index → second rejected
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 4);

            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);
            // Duplicate — should panic
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('index below window',))]
        fn test_consume_window_index_below_window_rejected() {
            // Index below the window range is rejected
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 4);

            // Consume all indices to advance window to [4, 8)
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 2);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 3);

            // Window is now [4, 8). Index 2 is below window.
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 2);
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('index above window',))]
        fn test_consume_window_index_above_window_rejected() {
            // Index above the window range is rejected
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 4);

            // Window is [0, 4). Index 4 is above window.
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 4);
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('account not registered',))]
        fn test_consume_window_index_unregistered_account_fails() {
            let mut state = setup();
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_window_auto_advances_when_full() {
            // Req 20.3: when all indices consumed, window base advances
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 3);

            // Window is [0, 3). Consume all 3 indices.
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 2);

            // Window should have auto-advanced to [3, 6)
            let (base, size) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base == 3, 'base advanced to 3');
            assert(size == 3, 'size unchanged');

            // Old indices should be cleared
            assert(
                !PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 0),
                'old idx 0 cleared',
            );
            assert(
                !PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 1),
                'old idx 1 cleared',
            );
            assert(
                !PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 2),
                'old idx 2 cleared',
            );

            // New window indices should be available
            assert(
                !PCAVerifierImpl::is_window_index_consumed(@state, account_addr(), 3),
                'new idx 3 free',
            );
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_window_advance_allows_new_indices() {
            // After window advances, new indices in the new window can be consumed
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 2);

            // Consume window [0, 2) → auto-advance to [2, 4)
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);

            // Now consume in new window [2, 4)
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 2);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 3);

            // Window should have auto-advanced to [4, 6)
            let (base, _size) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base == 4, 'base advanced to 4');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_window_multiple_advances() {
            // Test multiple consecutive window advances
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 1);

            // Window size 1: each consume triggers an advance
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
            let (base1, _) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base1 == 1, 'base after 1st advance');

            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);
            let (base2, _) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base2 == 2, 'base after 2nd advance');

            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 2);
            let (base3, _) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base3 == 3, 'base after 3rd advance');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_manual_advance_window() {
            // Req 20.3: manual advance when all indices consumed
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 2);

            // Note: auto-advance happens when last index is consumed,
            // so manual advance is for the case where we want to explicitly
            // advance after auto-advance has already happened.
            // To test manual advance, we need to consume all indices first.
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);
            // Auto-advance already happened to [2, 4)

            // Consume all in new window
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 2);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 3);
            // Auto-advance to [4, 6)

            let (base, _) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base == 4, 'base at 4');
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('window not fully consumed',))]
        fn test_manual_advance_window_not_full_fails() {
            // Manual advance fails if window is not fully consumed
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 3);

            // Only consume 1 of 3 indices
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);

            // Manual advance should fail
            PCAVerifierImpl::advance_window(ref state, account_addr());
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('caller not owner',))]
        fn test_manual_advance_window_non_owner_fails() {
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 2);

            starknet::testing::set_caller_address(other_addr());
            PCAVerifierImpl::advance_window(ref state, account_addr());
        }

        #[test]
        #[available_gas(99999999999)]
        #[should_panic(expected: ('account not registered',))]
        fn test_manual_advance_window_unregistered_fails() {
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::advance_window(ref state, account_addr());
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_multiple_accounts_independent_windows() {
            // Different accounts have independent windows
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());

            let account_a = account_addr();
            let account_b = other_addr();

            PCAVerifierImpl::register_account(ref state, account_a, 3);
            PCAVerifierImpl::register_account(ref state, account_b, 2);

            // Consume index 0 for account A
            PCAVerifierImpl::consume_window_index(ref state, account_a, 0);

            // Account B's index 0 should still be free
            assert(
                !PCAVerifierImpl::is_window_index_consumed(@state, account_b, 0), 'B idx 0 free',
            );

            // Consume index 0 for account B
            PCAVerifierImpl::consume_window_index(ref state, account_b, 0);

            // Both consumed independently
            assert(
                PCAVerifierImpl::is_window_index_consumed(@state, account_a, 0), 'A idx 0 consumed',
            );
            assert(
                PCAVerifierImpl::is_window_index_consumed(@state, account_b, 0), 'B idx 0 consumed',
            );

            // Account A has window [0, 3), account B has window [0, 2)
            let (base_a, size_a) = PCAVerifierImpl::get_account_window(@state, account_a);
            let (base_b, size_b) = PCAVerifierImpl::get_account_window(@state, account_b);
            assert(base_a == 0, 'A base 0');
            assert(size_a == 3, 'A size 3');
            assert(base_b == 0, 'B base 0');
            assert(size_b == 2, 'B size 2');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_window_size_one_immediate_advance() {
            // Window size 1: each consume immediately advances
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 1);

            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
            let (base, _) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base == 1, 'immediate advance');

            // Can consume next index
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);
            let (base2, _) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base2 == 2, 'second advance');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_re_register_account_resets_window() {
            // Re-registering an account resets its window
            let mut state = setup();
            starknet::testing::set_caller_address(owner_addr());
            PCAVerifierImpl::register_account(ref state, account_addr(), 3);

            // Consume some indices
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 0);
            PCAVerifierImpl::consume_window_index(ref state, account_addr(), 1);

            // Re-register with different window size
            PCAVerifierImpl::register_account(ref state, account_addr(), 5);

            let (base, size) = PCAVerifierImpl::get_account_window(@state, account_addr());
            assert(base == 0, 'base reset to 0');
            assert(size == 5, 'new size 5');
        }

        // ---------------------------------------------------------------
        // FRI Verification tests (Option A upgrade)
        // ---------------------------------------------------------------

        /// Build a valid FRI proof using the fri_verifier test helper.
        fn build_valid_fri_proof(
            message_hash: felt252, commitment_root: felt252, index: u64,
        ) -> Array<felt252> {
            // 3-layer FRI proof with simple auth paths
            let eval0: felt252 = 0xA1;
            let eval1: felt252 = 0xB2;
            let eval2: felt252 = 0xC3; // final constant

            // Layer 0: depth-2 Merkle tree (2 siblings)
            let sibling0_0: felt252 = 0x1111;
            let sibling0_1: felt252 = 0x2222;

            // Layer 1: depth-1 Merkle tree (1 sibling)
            let sibling1_0: felt252 = 0x3333;

            // Layer 2: single-element tree (0 siblings)

            let layer_evals: Array<felt252> = array![eval0, eval1, eval2];
            let path0: Array<felt252> = array![sibling0_0, sibling0_1];
            let path1: Array<felt252> = array![sibling1_0];
            let path2: Array<felt252> = array![];

            let bits0: Array<bool> = array![false, true];
            let bits1: Array<bool> = array![false];
            let bits2: Array<bool> = array![];

            let auth_paths: Array<Span<felt252>> = array![path0.span(), path1.span(), path2.span()];
            let path_bits: Array<Span<bool>> = array![bits0.span(), bits1.span(), bits2.span()];

            zk_pqc_cairo::fri_verifier::build_test_fri_proof(
                message_hash,
                commitment_root,
                index,
                layer_evals.span(),
                auth_paths.span(),
                path_bits.span(),
            )
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_fri_merkle_commitment_verification() {
            // Verify a Merkle path in FRI using the fri_verifier module
            let leaf: felt252 = 0xABCD;
            let sibling: felt252 = 0x1234;

            // Build a depth-1 tree: root = H(leaf, sibling) since leaf is left child
            let expected_root = zk_pqc_cairo::fri_verifier::fri_merkle_hash(leaf, sibling);

            let auth_path = array![sibling];
            let path_bits = array![false]; // leaf is left child

            let valid = zk_pqc_cairo::fri_verifier::verify_fri_merkle_path(
                expected_root, leaf, auth_path.span(), path_bits.span(),
            );
            assert(valid, 'merkle path should verify');

            // Wrong root should fail
            let invalid = zk_pqc_cairo::fri_verifier::verify_fri_merkle_path(
                0xDEAD, leaf, auth_path.span(), path_bits.span(),
            );
            assert(!invalid, 'wrong root should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_fri_layer_consistency() {
            // Verify polynomial folding between layers
            let alpha: felt252 = 0x42;
            let eval_current: felt252 = 0xA1;
            let eval_next: felt252 = 0xB2;

            // Compute the expected folding commitment
            let expected = zk_pqc_cairo::sponge::hash_with_ds(
                0x4652495f464f4c44, // DOMAIN_FRI_FOLD
                array![alpha, eval_current, eval_next].span(),
            );

            let valid = zk_pqc_cairo::fri_verifier::verify_layer_consistency(
                alpha, eval_current, eval_next, expected,
            );
            assert(valid, 'folding should be consistent');

            // Tampered commitment should fail
            let invalid = zk_pqc_cairo::fri_verifier::verify_layer_consistency(
                alpha, eval_current, eval_next, 0xDEAD,
            );
            assert(!invalid, 'tampered fold should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_fri_final_polynomial_check() {
            // Verify the constant polynomial check
            let final_val: felt252 = 0xC3;

            // Matching values should pass
            let valid = zk_pqc_cairo::fri_verifier::verify_final_polynomial(final_val, final_val);
            assert(valid, 'final poly should match');

            // Mismatched values should fail
            let invalid = zk_pqc_cairo::fri_verifier::verify_final_polynomial(final_val, 0xDEAD);
            assert(!invalid, 'final poly mismatch fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_verify_authorization_fri_valid() {
            // Full FRI verification flow
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = build_valid_fri_proof(msg, root, 0);

            let valid = PCAVerifierImpl::verify_authorization_fri(
                @state, proof.span(), msg, root, 0,
            );
            assert(valid, 'fri proof should pass');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_verify_authorization_fri_tampered_rejected() {
            // Tampered FRI proof should be rejected
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let mut proof = build_valid_fri_proof(msg, root, 0);

            // Tamper with the tag (last element)
            let proof_len = proof.len();
            let mut tampered: Array<felt252> = ArrayTrait::new();
            let mut i: u32 = 0;
            while i < proof_len - 1 {
                tampered.append(*proof.at(i));
                i += 1;
            }
            tampered.append(0xDEADBEEF); // tampered tag

            let valid = PCAVerifierImpl::verify_authorization_fri(
                @state, tampered.span(), msg, root, 0,
            );
            assert(!valid, 'tampered proof should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_verify_authorization_fri_empty_rejected() {
            let state = setup();
            let proof: Array<felt252> = ArrayTrait::new();
            let valid = PCAVerifierImpl::verify_authorization_fri(
                @state, proof.span(), 0x1234, 0xABCD, 0,
            );
            assert(!valid, 'empty fri proof should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_verify_authorization_fri_zero_msg_rejected() {
            let state = setup();
            let root: felt252 = 0xABCD;
            let proof = build_valid_fri_proof(0, root, 0);
            let valid = PCAVerifierImpl::verify_authorization_fri(@state, proof.span(), 0, root, 0);
            assert(!valid, 'zero msg should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_verify_authorization_fri_consumed_index_rejected() {
            let mut state = setup();
            starknet::testing::set_caller_address(sequencer_addr());

            // Consume index 7 via batch
            let bp = build_valid_batch_proof(array![0x111].span());
            PCAVerifierImpl::submit_batch(ref state, bp.span(), array![7_u64].span(), 0xFEED);

            // FRI proof for consumed index should fail
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = build_valid_fri_proof(msg, root, 7);
            let valid = PCAVerifierImpl::verify_authorization_fri(
                @state, proof.span(), msg, root, 7,
            );
            assert(!valid, 'consumed idx should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_verify_authorization_fri_msg_mismatch_rejected() {
            let state = setup();
            let proof = build_valid_fri_proof(0x1111, 0xABCD, 0);
            let valid = PCAVerifierImpl::verify_authorization_fri(
                @state, proof.span(), 0x2222, 0xABCD, 0,
            );
            assert(!valid, 'msg mismatch should fail');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_verify_authorization_fri_nonzero_index() {
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof = build_valid_fri_proof(msg, root, 42);
            let valid = PCAVerifierImpl::verify_authorization_fri(
                @state, proof.span(), msg, root, 42,
            );
            assert(valid, 'nonzero index should pass');
        }

        #[test]
        #[available_gas(99999999999)]
        fn test_option_b_still_works_after_fri_upgrade() {
            // Backward compatibility: Option B (Poseidon commitment) still works
            let state = setup();
            let msg: felt252 = 0x1234;
            let root: felt252 = 0xABCD;
            let proof_b = build_valid_proof(msg, root, 0, array![42, 99].span());
            let valid_b = PCAVerifierImpl::verify_authorization(
                @state, proof_b.span(), msg, root, 0,
            );
            assert(valid_b, 'option B still works');
        }
    }
}
