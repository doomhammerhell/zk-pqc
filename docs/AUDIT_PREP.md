# Audit Preparation Package — zk-pqc-framework

**Version**: v1.0 (All phases complete)
**Date**: 2025
**Framework**: Post-Quantum Signature Verification for STARK-Based Smart Contracts

---

## 1. Audit Scope

### Cryptographic Components

| Component          | Description                                           | Implementation |
| ------------------ | ----------------------------------------------------- | -------------- |
| Poseidon t=6       | ZK-friendly hash (RF=8, RP=83, Stark252)              | Rust + Cairo   |
| PoseidonSponge     | Sponge construction over Poseidon                     | Rust + Cairo   |
| Hybrid-Hash        | Poseidon ⊕ truncated SHA-256                          | Rust + Cairo   |
| WOTS+              | Winternitz One-Time Signature (w=16, checksum)        | Rust + Cairo   |
| XMSS               | Extended Merkle Signature Scheme (many-time from OTS) | Rust + Cairo   |
| Binary Merkle Tree | Standard binary inclusion proofs                      | Rust + Cairo   |
| HexTree            | Arity-16 Merkle tree (4× proof compression)           | Rust + Cairo   |
| SMT/JMT            | Jellyfish Merkle Tree for index tracking              | Rust + Cairo   |
| STARK Prover       | WOTS+ verification AIR + lambdaworks prover           | Rust           |
| STARK Verifier     | Off-chain STARK proof verification                    | Rust           |
| FRI Verifier       | On-chain FRI polynomial commitment verification       | Cairo          |
| Batch Aggregator   | Recursive N-proof → Π_Batch folding                   | Rust           |
| Batch STARK Proof  | STARK proof for batch Merkle commitment               | Rust           |
| PCA Contract       | On-chain verifier, sequencer control, fraud proofs    | Cairo          |

### Languages

| Language | Role                                                              | Location                        |
| -------- | ----------------------------------------------------------------- | ------------------------------- |
| Rust     | Reference implementation, off-chain prover, test vector generator | `src/rust/`                     |
| Cairo    | On-chain verifier, smart contract                                 | `src/cairo/src/`                |
| Python   | Constants generation script                                       | `scripts/generate_constants.py` |

### Lines of Code

| Component                     | LOC (approx) |
| ----------------------------- | ------------ |
| Rust source (excluding tests) | ~6,500       |
| Rust tests + property tests   | ~6,100       |
| Cairo source + tests          | ~7,800       |
| **Total**                     | **~20,400**  |

### Key Files (Prioritized by Security Criticality)

**Critical — Core Cryptographic Logic**:

| Priority | File                                        | Description                                                                     |
| -------- | ------------------------------------------- | ------------------------------------------------------------------------------- |
| P0       | `src/cairo/src/zk_pqc_cairo.cairo`          | PCA verifier contract — all on-chain verification, access control, fraud proofs |
| P0       | `src/cairo/src/fri_verifier.cairo`          | FRI polynomial commitment verification                                          |
| P0       | `src/rust/proof_layer/src/wots_air.rs`      | AIR constraints for WOTS+ verification                                          |
| P0       | `src/rust/proof_layer/src/wots_prover.rs`   | STARK proof generation                                                          |
| P0       | `src/rust/proof_layer/src/wots_verifier.rs` | STARK proof verification                                                        |
| P0       | `src/rust/signature_layer/src/wots.rs`      | WOTS+ signature scheme (keygen, sign, verify, checksum)                         |
| P0       | `src/rust/hash_layer/src/poseidon.rs`       | Poseidon permutation                                                            |
| P0       | `src/rust/hash_layer/src/constants.rs`      | MDS matrix + round constants                                                    |
| P0       | `src/cairo/src/poseidon.cairo`              | Cairo Poseidon permutation                                                      |
| P0       | `src/cairo/src/constants.cairo`             | Cairo MDS matrix + round constants                                              |

**High — Proof Layer and Aggregation**:

| Priority | File                                     | Description                                |
| -------- | ---------------------------------------- | ------------------------------------------ |
| P1       | `src/rust/proof_layer/src/pca.rs`        | End-to-end PCA flow                        |
| P1       | `src/rust/proof_layer/src/aggregator.rs` | Recursive batch aggregator                 |
| P1       | `src/rust/proof_layer/src/batch_air.rs`  | Batch Merkle commitment AIR                |
| P1       | `src/rust/merkle_layer/src/smt.rs`       | Jellyfish Merkle Tree                      |
| P1       | `src/cairo/src/smt.cairo`                | Cairo SMT verification                     |
| P1       | `src/rust/signature_layer/src/domain.rs` | Domain separation + canonical message hash |
| P1       | `src/cairo/src/domain.cairo`             | Cairo domain separation                    |

**Medium — Supporting Infrastructure**:

| Priority | File                                   | Description                       |
| -------- | -------------------------------------- | --------------------------------- |
| P2       | `src/rust/signature_layer/src/xmss.rs` | XMSS tree (many-time signatures)  |
| P2       | `src/cairo/src/xmss.cairo`             | Cairo XMSS verification           |
| P2       | `src/rust/merkle_layer/src/hextree.rs` | HexTree (arity-16)                |
| P2       | `src/cairo/src/hextree.cairo`          | Cairo HexTree                     |
| P2       | `src/rust/hash_layer/src/sponge.rs`    | PoseidonSponge                    |
| P2       | `src/cairo/src/sponge.cairo`           | Cairo PoseidonSponge              |
| P2       | `src/rust/hash_layer/src/hybrid.rs`    | Hybrid-Hash                       |
| P2       | `src/cairo/src/hybrid.cairo`           | Cairo Hybrid-Hash                 |
| P2       | `scripts/generate_constants.py`        | Deterministic constants generator |

---

## 2. Invariants Checklist

All 23 correctness properties from the design document, with test status.

| #   | Property                                                                                                                                                         | Test File                                                | Test Function(s)                                                                                                                                                                                                                                                                     | Status |
| --- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------ |
| 1   | **Deterministic Constants Generation** — Repeated execution with same seed produces identical MDS + ARK; MDS property (all square submatrices invertible) holds. | `src/rust/hash_layer/src/property_tests.rs`              | `prop_deterministic_constants_generation`                                                                                                                                                                                                                                            | PASS ✓ |
| 2   | **Merkle Inclusion Round-Trip (Binary + HexTree)** — Build tree → prove leaf i → verify returns true; reconstructed root matches.                                | `src/rust/merkle_layer/src/property_tests.rs`            | `prop_merkle_inclusion_round_trip`, `prop_hextree_inclusion_round_trip`                                                                                                                                                                                                              | PASS ✓ |
| 3   | **Merkle Proof Tamper Detection** — Altering leaf, sibling, or root causes verification to return false.                                                         | `src/rust/merkle_layer/src/property_tests.rs`            | `prop_merkle_proof_tamper_detection`, `prop_hextree_proof_tamper_detection`                                                                                                                                                                                                          | PASS ✓ |
| 4   | **HexTree Proof Structure** — Depth = ceil(log_16(N)); proof size = depth × 15 siblings.                                                                         | `src/rust/merkle_layer/src/property_tests.rs`            | `prop_hextree_proof_structure`                                                                                                                                                                                                                                                       | PASS ✓ |
| 5   | **Lamport OTS Key Pair Integrity** — public[b][i] = H(secret[b][i]) for all positions.                                                                           | `src/rust/signature_layer/examples/lamport_reference.rs` | `prop_lamport_keypair_integrity`                                                                                                                                                                                                                                                     | PASS ✓ |
| 6   | **Lamport OTS Sign-Verify Round-Trip** — Sign → verify returns true.                                                                                             | `src/rust/signature_layer/examples/lamport_reference.rs` | `prop_lamport_sign_verify_roundtrip`                                                                                                                                                                                                                                                 | PASS ✓ |
| 7   | **Lamport OTS Wrong-Key Rejection** — Sign with A → verify with B returns false.                                                                                 | `src/rust/signature_layer/examples/lamport_reference.rs` | `prop_lamport_wrong_key_rejection`                                                                                                                                                                                                                                                   | PASS ✓ |
| 8   | **WOTS+ Decomposition and Checksum Invariant** — Elements in [0,w); checksum C = Σ(w-1-m_i) reconstructs correctly.                                              | `src/rust/signature_layer/src/property_tests.rs`         | `prop_wots_checksum_invariant`                                                                                                                                                                                                                                                       | PASS ✓ |
| 9   | **WOTS+ Sign-Verify Round-Trip** — Sign → verify returns true.                                                                                                   | `src/rust/signature_layer/src/property_tests.rs`         | `prop_wots_sign_verify_roundtrip`                                                                                                                                                                                                                                                    | PASS ✓ |
| 10  | **WOTS+ Forgery Resistance via Checksum** — Advance one chain by one hash → verify returns false.                                                                | `src/rust/signature_layer/src/property_tests.rs`         | `prop_wots_forgery_resistance`                                                                                                                                                                                                                                                       | PASS ✓ |
| 11  | **Cross-Language Cryptographic Consistency** — Rust and Cairo produce identical outputs for same inputs.                                                         | `src/rust/test_vectors/src/cross_language_props.rs`      | `prop_cross_language_poseidon_consistency`, `prop_cross_language_sponge_consistency`, `prop_cross_language_hybrid_consistency`, `prop_cross_language_merkle_consistency`, `prop_cross_language_json_serialization_format`                                                            | PASS ✓ |
| 12  | **Domain Separation Prevents Cross-Context Signatures** — Altered chain_id or contract_addr → different hash.                                                    | `src/rust/signature_layer/src/domain.rs`                 | `prop_domain_separation_prevents_cross_context`                                                                                                                                                                                                                                      | PASS ✓ |
| 13  | **Nonce Replay Rejection** — Consumed nonce → replay rejected.                                                                                                   | `src/rust/signature_layer/src/domain.rs`                 | `prop_nonce_replay_rejection`                                                                                                                                                                                                                                                        | PASS ✓ |
| 14  | **OTS Index Non-Reuse Enforcement** — Consumed index → non-spent proof fails; unconsumed → succeeds.                                                             | `src/rust/merkle_layer/src/property_tests.rs`            | `prop_smt_index_non_reuse`                                                                                                                                                                                                                                                           | PASS ✓ |
| 15  | **XMSS Sign-Verify Round-Trip** — Sign at index → verify (WOTS+ sig + Merkle proof) returns true.                                                                | `src/rust/signature_layer/src/xmss.rs`                   | `test_xmss_sign_verify`, `test_xmss_multiple_signatures`                                                                                                                                                                                                                             | PASS ✓ |
| 16  | **XMSS Wrong-Index Rejection** — Signature at index i → verify with index j ≠ i returns false.                                                                   | `src/rust/signature_layer/src/xmss.rs`                   | `test_xmss_wrong_root_rejection`                                                                                                                                                                                                                                                     | PASS ✓ |
| 17  | **PCA Proof Binding and Verification (Real STARK)** — Valid proof accepted; altered message/root rejected.                                                       | `src/rust/proof_layer/src/property_tests.rs`             | `prop_real_stark_pca_valid_proof_accepted`, `prop_real_stark_pca_message_tamper_rejected`, `prop_real_stark_pca_root_tamper_rejected`, `prop_real_stark_pca_random_garbage_rejected`                                                                                                 | PASS ✓ |
| 18  | **AIR Constraint Satisfaction** — Valid Poseidon trace → all constraints evaluate to zero; booleanity b(b-1)=0.                                                  | `src/rust/proof_layer/src/property_tests.rs`             | `prop_air_constraint_satisfaction`, `prop_booleanity_constraint_valid`, `prop_booleanity_constraint_rejects_non_boolean`                                                                                                                                                             | PASS ✓ |
| 19  | **Recursive Batch Aggregation Soundness** — N valid proofs → Π_Batch verifies; tampered digest/root → rejected.                                                  | `src/rust/proof_layer/src/property_tests.rs`             | `prop_recursive_batch_aggregation_valid_batch_verifies`, `prop_recursive_batch_aggregation_tampered_digest_rejected`, `prop_recursive_batch_aggregation_tampered_root_rejected`, `prop_recursive_batch_aggregation_large_batch`                                                      | PASS ✓ |
| 20  | **SMT State Reconstruction from DA Diffs** — Apply diffs to empty SMT → root matches on-chain root; DA payload ≤ K×8 bytes.                                      | `src/rust/merkle_layer/src/property_tests.rs`            | `prop_smt_state_reconstruction_from_da_diffs`, `prop_da_payload_size_constraint`, `prop_da_reconstruction_detects_duplicates`                                                                                                                                                        | PASS ✓ |
| 21  | **Transaction Lane Classification** — Hash flag → correct lane routing; separate batch proofs per lane.                                                          | `src/rust/proof_layer/src/property_tests.rs`             | `prop_lane_classification_correct_routing`, `prop_lane_classification_independent_verification`, `prop_lane_classification_sizes_sum_to_total`, `prop_lane_classification_cross_lane_independence`                                                                                   | PASS ✓ |
| 22  | **ZK-Fraud Proof Acceptance and Slashing** — Valid Accountability Trace → accepted from any submitter → slashing applied.                                        | `src/rust/proof_layer/src/property_tests.rs`             | `prop_fraud_proof_valid_trace_accepted`, `prop_fraud_proof_tag_deterministic`, `prop_fraud_proof_tampered_violation_type_rejected`, `prop_fraud_proof_tampered_violator_rejected`, `prop_fraud_proof_tampered_evidence_rejected`, `prop_fraud_proof_wrong_violator_address_rejected` | PASS ✓ |
| 23  | **Index Window Concurrency** — Distinct indices within [base, base+k] accepted; duplicate rejected; window advances on exhaustion.                               | `src/rust/proof_layer/src/property_tests.rs`             | `prop_index_window_distinct_indices_accepted`, `prop_index_window_duplicate_rejected`, `prop_index_window_advances_on_exhaustion`, `prop_index_window_out_of_range_rejected`, `prop_index_window_random_order_accepted`, `prop_index_window_multiple_advances`                       | PASS ✓ |

---

## 3. Attack Surface Map

### L1 — Hash Layer

| Aspect                | Detail                                                                                                                                             |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Entry points**      | `PoseidonSponge::hash()`, `PoseidonSponge::hash_with_ds()`, `HybridHash::hash()`, `HybridHash::hash_with_domain_separation()`                      |
| **Trust boundaries**  | Constants must be generated from canonical seed; MDS property must hold                                                                            |
| **Data flow**         | Raw field elements → Poseidon permutation → sponge squeeze → digest                                                                                |
| **Known mitigations** | Cauchy MDS with verified invertibility; SHA-256 CSPRNG for round constants; domain separation on both Poseidon and SHA-256 components              |
| **Residual risks**    | SHA-256 truncation to 248 bits (124-bit collision resistance for SHA-256 component alone); project-specific constants diverge from Starknet native |

### L2 — Merkle Layer

| Aspect                | Detail                                                                                                                                              |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Entry points**      | `MerkleTree::new()`, `prove()`, `verify()`; `HexTree::new()`, `prove()`, `verify()`; `SparseMerkleTree::mark_consumed()`, `is_consumed()`, `root()` |
| **Trust boundaries**  | Leaf data integrity; proof path correctness                                                                                                         |
| **Data flow**         | Leaves → tree construction → root commitment; index → SMT path → root update                                                                        |
| **Known mitigations** | Round-trip property verified; tamper detection verified; JMT lazy instantiation for O(active) cost                                                  |
| **Residual risks**    | HexTree padding for non-power-of-16 leaf counts (handled but worth auditing)                                                                        |

### L3 — Signature Layer

| Aspect                | Detail                                                                                                          |
| --------------------- | --------------------------------------------------------------------------------------------------------------- |
| **Entry points**      | `WotsPlus::keygen()`, `sign()`, `verify()`, `checksum()`; `XmssTree::new()`, `sign()`, `verify()`               |
| **Trust boundaries**  | Secret key material; checksum computation correctness; index monotonicity                                       |
| **Data flow**         | Seed → keygen → secret chains → hash iterations → public chains; message → decompose → chain values → signature |
| **Known mitigations** | Checksum C = Σ(w-1-m_i) prevents existential forgery; XMSS enforces monotonic index consumption                 |
| **Residual risks**    | WOTS+ is one-time — security depends entirely on index non-reuse enforcement at L4                              |

### L4 — Contract Layer (Cairo)

| Aspect                | Detail                                                                                                                                                                                                                                                                                  |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Entry points**      | `verify_authorization()`, `verify_authorization_fri()`, `verify_authorization_with_domain()`, `verify_authorization_with_smt()`, `submit_batch()`, `submit_lane_batch()`, `submit_fraud_proof()`, `consume_window_index()`, `set_sequencer()`, `set_domain_config()`, `deposit_stake()` |
| **Trust boundaries**  | Caller identity (access control); proof data integrity; SMT root consistency; domain configuration                                                                                                                                                                                      |
| **Data flow**         | Proof array → parse → verify tag/FRI → check index → update state → emit events                                                                                                                                                                                                         |
| **Known mitigations** | Access control on `submit_batch` (authorized sequencer only); owner-only for `set_sequencer`, `set_domain_config`; circuit breaker on excessive fraud proofs; 100% slashing on valid fraud proofs                                                                                       |
| **Residual risks**    | Owner key compromise allows sequencer rotation; circuit breaker requires manual resolution                                                                                                                                                                                              |

### L5 — Proof Layer (Rust)

| Aspect                | Detail                                                                                                                                                                 |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Entry points**      | `prove_wots_verification()`, `verify_stark_proof_real()`, `generate_pca_proof()`, `verify_pca_proof()`, `RecursiveAggregator::aggregate()`, `prove_batch_commitment()` |
| **Trust boundaries**  | AIR constraint completeness; lambdaworks STARK soundness; trace generation correctness                                                                                 |
| **Data flow**         | WOTS+ verification trace → AIR constraints → STARK proof → serialized proof array                                                                                      |
| **Known mitigations** | Real STARK proofs via lambdaworks; soundness error ≤ 2^(-80); batch aggregation with invalid proof identification                                                      |
| **Residual risks**    | Depends on lambdaworks correctness; AIR constraint count should be audited for completeness                                                                            |

---

## 4. Known Limitations

1. **Poseidon constants are project-specific** — The MDS matrix and round constants are generated via Cauchy construction + SHA-256 CSPRNG, intentionally diverging from Starknet's native Grain LFSR parameters. Our Poseidon output is NOT compatible with Starknet's `poseidon()` syscall. See `docs/POSEIDON_CONSTANTS.md`.

2. **FRI verification is commitment-based** — The on-chain FRI verifier uses Poseidon hash commitments for folding consistency checks rather than full polynomial evaluation in Cairo. This is sufficient for binding proofs to their claimed evaluations but does not perform raw field arithmetic polynomial division. Full polynomial evaluation verification is deferred to the Inner Verifier AIR (post-v1).

3. **Recursive STARK (Inner Verifier AIR) is post-v1** — True recursive proof composition (proving a STARK verifier inside another STARK) is architecturally planned but not yet implemented. The current batch aggregation uses Poseidon Merkle commitments with optional STARK proofs for the commitment computation itself.

4. **SHA-256 truncation to 248 bits** — SHA-256 output is truncated to fit `felt252` (MSB byte zeroed), yielding 248 effective bits and 124-bit collision resistance for the SHA-256 component alone. The Hybrid-Hash XOR with Poseidon provides defense-in-depth.

5. **Lamport OTS is reference-only** — Lamport has been demoted to `examples/` and is not part of the production API. WOTS+ is the sole production signature primitive.

6. **XMSS property tests use unit tests** — Properties 15 and 16 (XMSS round-trip and wrong-index rejection) are validated via deterministic unit tests rather than `proptest`-based property tests, due to the computational cost of XMSS tree construction.

---

## 5. Recommended Audit Focus Areas

### Critical Priority

1. **WOTS+ checksum computation (forgery resistance)**

   - Verify that `checksum()` correctly computes C = Σ(w-1-m_i) and decomposes into base-w digits
   - Verify that advancing any chain by one hash iteration causes verification failure
   - Files: `src/rust/signature_layer/src/wots.rs`, `src/cairo/src/wots.cairo`

2. **JMT proof generation and verification (index non-reuse)**

   - Verify that consumed indices cannot pass non-spent proof verification
   - Verify that the JMT root update is correct after marking an index consumed
   - Verify constant storage footprint (single root on-chain)
   - Files: `src/rust/merkle_layer/src/smt.rs`, `src/cairo/src/smt.cairo`, `src/cairo/src/zk_pqc_cairo.cairo` (`verify_authorization_with_smt`)

3. **STARK AIR constraint completeness (soundness)**

   - Verify that `WotsVerificationAIR` transition constraints fully encode hash chain continuity
   - Verify boundary constraints bind the trace to the correct public inputs
   - Verify no missing constraints that could allow a valid proof from an invalid trace
   - Files: `src/rust/proof_layer/src/wots_air.rs`, `src/rust/proof_layer/src/air.rs`

4. **FRI verifier correctness (on-chain verification)**
   - Verify Merkle path reconstruction is correct
   - Verify Fiat-Shamir challenge derivation is binding
   - Verify folding consistency checks are sound
   - Verify final polynomial check is correct
   - File: `src/cairo/src/fri_verifier.cairo`

### High Priority

5. **Domain separation implementation (replay prevention)**

   - Verify canonical message hash construction: `H(domain ‖ chain_id ‖ contract_addr ‖ nonce ‖ H(calldata))`
   - Verify nonce consumption and replay rejection
   - Verify cross-chain and cross-contract isolation
   - Files: `src/rust/signature_layer/src/domain.rs`, `src/cairo/src/domain.cairo`, `src/cairo/src/zk_pqc_cairo.cairo` (`verify_authorization_with_domain`)

6. **Access control in Cairo contract**
   - Verify `submit_batch` is restricted to authorized sequencer
   - Verify `set_sequencer` and `set_domain_config` are restricted to owner
   - Verify fraud proof submission is permissionless (any observer)
   - Verify circuit breaker activation and its effect on batch processing
   - File: `src/cairo/src/zk_pqc_cairo.cairo`

### Medium Priority

7. **Batch aggregation correctness**

   - Verify Poseidon Merkle commitment computation matches between Rust and Cairo
   - Verify domain separators (`PCA_DIGE`, `PCA_LEAF`, `PCA_NODE`) are consistent
   - Verify invalid proof identification in batch rejection
   - Files: `src/rust/proof_layer/src/aggregator.rs`, `src/cairo/src/zk_pqc_cairo.cairo` (`submit_batch`)

8. **Cross-language consistency**

   - Verify Poseidon, Sponge, Hybrid-Hash, Merkle, and WOTS+ produce identical outputs in Rust and Cairo for the same inputs
   - Review test vectors in `spec/test_vectors/`
   - Files: `src/rust/test_vectors/`, `src/cairo/src/test_vectors.cairo`, `src/cairo/src/test_vectors_phase2.cairo`

9. **Poseidon constants generation**
   - Verify MDS property (all square submatrices invertible)
   - Verify round constants are deterministically derived from canonical seed
   - Verify constants match between Rust and Cairo
   - Files: `scripts/generate_constants.py`, `src/rust/hash_layer/src/constants.rs`, `src/cairo/src/constants.cairo`

---

## 6. Test Coverage Summary

### Rust Tests

| Category                                      | Count   | Notes                                                  |
| --------------------------------------------- | ------- | ------------------------------------------------------ |
| Total test functions                          | ~217    | Across all crates                                      |
| Property-based tests (fast, 10 cases)         | ~15     | STARK-heavy tests; run in CI                           |
| Property-based tests (100 cases)              | ~30     | Hash, Merkle, aggregation, fraud proofs, index windows |
| Property-based tests (100 cases, `#[ignore]`) | ~8      | Thorough STARK tests; run with `--ignored`             |
| Unit tests                                    | ~164    | Known-answer tests, edge cases, integration            |
| Integration tests                             | 2 files | `quantum_safe_vault.rs`, `pca_e2e.rs`                  |

### Cairo Tests

| Category                    | Count | Notes                                                    |
| --------------------------- | ----- | -------------------------------------------------------- |
| Total test functions        | ~171  | Across all modules                                       |
| Cross-language vector tests | ~40   | Phase 1 + Phase 2 vectors                                |
| Contract tests              | ~60   | PCA verifier, batch, fraud proofs, windows               |
| Module tests                | ~71   | Poseidon, Sponge, Merkle, WOTS+, HexTree, XMSS, SMT, FRI |

### Property-Based Test Configuration

- **Library**: `proptest` (Rust)
- **Minimum iterations**: 100 per property (fast tests use 10 for STARK-heavy properties)
- **Total properties**: 23 (all passing)
- **Tag format**: `Feature: zk-pqc-framework, Property {N}: {name}`
- **Cairo PBT**: Deterministic vectors generated by Rust `proptest` and replayed in Cairo tests

### Key Integration Tests

| Test               | File                                               | Description                                                                                                  |
| ------------------ | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Quantum-Safe Vault | `src/rust/proof_layer/tests/quantum_safe_vault.rs` | Full cycle: keygen → sign → prove (real STARK) → verify → submit batch → replay rejection → tamper rejection |
| PCA End-to-End     | `src/rust/proof_layer/tests/pca_e2e.rs`            | Real STARK PCA transaction, tampered proof rejection, wrong message rejection                                |

### Running Tests

```bash
# Rust — all tests (fast)
cd src/rust && cargo test --all-features

# Rust — including thorough property tests
cd src/rust && cargo test --all-features -- --ignored

# Cairo — all tests
cd src/cairo && scarb test

# Rust — specific crate
cd src/rust && cargo test -p zk-pqc-proof-layer
cd src/rust && cargo test -p zk-pqc-merkle-layer
cd src/rust && cargo test -p zk-pqc-signature-layer
cd src/rust && cargo test -p zk-pqc-hash-layer
```
