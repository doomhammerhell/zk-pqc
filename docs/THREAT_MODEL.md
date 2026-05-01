# Threat Model — Post-Quantum Signature Verification Framework

## Scope

This document covers the attack surface of the zk-pqc-framework: a WOTS+-based
post-quantum signature scheme verified via STARK proofs on Cairo smart contracts.
Each vector lists the current mitigation status.

---

## Attack Vectors

### 1. OTS Key Reuse

| Attribute         | Detail                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Description       | WOTS+ is a one-time signature scheme. Signing two distinct messages with the same key index leaks enough hash chain preimages for an attacker to forge signatures.                                                                                                                                                                                                                                                                                     |
| Impact            | Complete key compromise for the reused index. Attacker can authorize arbitrary transactions under that key.                                                                                                                                                                                                                                                                                                                                            |
| Mitigation status | **MITIGATED** — Lamport demoted to reference-only (11E); WOTS+ is the sole production primitive. The Cairo contract tracks consumed indices via a JMT root (task 21) with path compression and lazy node instantiation. The SMT root provides constant-storage index tracking, enforcing non-reuse up to 2^64 indices. The `Map<u64, bool>` per-index guard remains as a fast-path check; the JMT root provides the scalable cryptographic commitment. |

### 2. Transaction Replay

| Attribute         | Detail                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Description       | A valid proof submitted once could be re-submitted to authorize the same state transition again.                                                                                                                                                                                                                                                                                                |
| Impact            | Double-spend or duplicate state mutation.                                                                                                                                                                                                                                                                                                                                                       |
| Mitigation status | **MITIGATED** — Domain separation with nonce binding (task 15) is implemented. The canonical message hash `H(domain ‖ chain_id ‖ contract_addr ‖ nonce ‖ H(calldata))` is enforced by the Cairo contract via `verify_authorization_with_domain`. Replayed nonces are rejected at the contract level. `submit_batch` marks indices as consumed; `verify_authorization` rejects consumed indices. |

### 3. Cross-Chain / Cross-Contract Signature Reuse

| Attribute         | Detail                                                                                                                                                                                                                                                                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Description       | A signature (and its STARK proof) generated for chain A or contract X is submitted on chain B or contract Y.                                                                                                                                                                                                                                                                   |
| Impact            | Unauthorized state transition on the target chain/contract.                                                                                                                                                                                                                                                                                                                    |
| Mitigation status | **MITIGATED** — Domain separation (task 15) binds every signature to `(domain, chain_id, contract_addr, nonce)`. The Cairo contract stores domain configuration and verifies it during `verify_authorization_with_domain`. Verification rejects mismatched context fields. Signatures for chain A are invalid on chain B; signatures for contract X are invalid on contract Y. |

### 4. STARK Proof Forgery

| Attribute         | Detail                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Description       | An attacker fabricates a STARK proof that passes verification without possessing the WOTS+ secret key.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Impact            | Unauthorized transaction authorization.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Mitigation status | **MITIGATED** — Real STARK proofs are generated via lambdaworks (task 11F–11G). The `WotsVerificationAIR` encodes the full WOTS+ hash chain verification as polynomial constraints. Off-chain verification uses `lambdaworks_stark::verify()`. On-chain, the Cairo contract supports two verification paths: (1) Poseidon commitment tag via `verify_authorization` (Option B), and (2) full FRI polynomial commitment verification via `verify_authorization_fri` (Option A). The FRI verifier (`src/cairo/src/fri_verifier.cairo`) performs a 6-step verification: parse proof, verify commitment tag, verify per-layer Merkle inclusion, verify folding consistency via Fiat-Shamir challenges, verify final constant polynomial, and confirm bound fields match. |
| Security level    | Soundness error ≤ 2^(-80) per the STARK protocol parameters.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

### 5. Sequencer Equivocation

| Attribute         | Detail                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Description       | A malicious sequencer submits conflicting batches, replays indices, or withholds transactions.                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Impact            | State inconsistency, censorship, or double-spend at the sequencer level.                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Mitigation status | **MITIGATED** — ZK-Fraud Proofs with 100% slashing (task 24) are implemented. Any observer can submit an Accountability Trace (STARK proof of sequencer violation) via `submit_fraud_proof`. Valid fraud proofs trigger 100% stake slashing on the violating sequencer. A circuit breaker pauses batch processing when fraud proof volume exceeds a configurable threshold. Additionally, `submit_batch` is guarded by `authorized_sequencer` access control (task 11H.2), and the owner can rotate the sequencer via `set_sequencer`. |

### 6. Quantum Attack (Grover's Algorithm)

| Attribute         | Detail                                                                                                                                                                                                                                          |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Description       | A quantum adversary uses Grover's algorithm to find hash preimages in O(2^(n/2)) evaluations instead of O(2^n).                                                                                                                                 |
| Impact            | Key recovery if security margin is insufficient.                                                                                                                                                                                                |
| Mitigation status | **MITIGATED** — Poseidon output over Stark252 provides 248 effective bits (MSB byte zeroed). Grover reduces preimage resistance to 2^124 hash evaluations. WOTS+ checksum forces the attacker to break all chains simultaneously, not just one. |
| Security level    | **124-bit quantum security** — exceeds NIST Post-Quantum Category 1 target (equivalent to AES-128 against quantum).                                                                                                                             |
| Reference         | `test_vault_grover_resistance_doc` in `src/rust/proof_layer/tests/quantum_safe_vault.rs` documents and asserts these parameters.                                                                                                                |

### 7. Poseidon Algebraic Attacks

| Attribute         | Detail                                                                                                                                                                                                                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Description       | Algebraic cryptanalysis targeting the Poseidon permutation structure (e.g., Gröbner basis, interpolation, or differential attacks on the S-box x^5).                                                                                                                           |
| Impact            | Hash collision or preimage, breaking signature and Merkle tree security.                                                                                                                                                                                                       |
| Mitigation status | **MITIGATED** — Parameters follow conservative recommendations: t=6, RF=8 full rounds, RP=83 partial rounds. MDS matrix is Cauchy-constructed with machine-verified invertibility of all square submatrices. Round constants are derived from SHA-256 CSPRNG for auditability. |
| Note              | This project uses project-specific Poseidon constants (not Starknet-native). See `docs/POSEIDON_CONSTANTS.md` for the rationale and divergence details.                                                                                                                        |

### 8. Hybrid-Hash Domain Separation Bypass

| Attribute         | Detail                                                                                                                                                                                                                 |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Description       | Prior to task 11A, the SHA-256 component of Hybrid-Hash ignored the domain separator, meaning `HybridHash(ds=A, x)` and `HybridHash(ds=B, x)` produced SHA-256 components that were identical.                         |
| Impact            | Weakened domain separation when using Hybrid-Hash mode.                                                                                                                                                                |
| Mitigation status | **MITIGATED** — Fixed in task 11A. Both Poseidon and SHA-256 components now incorporate the domain separator: `poseidon_hash_with_ds(ds, input) + sha256(ds ‖ input)`. Fix applied in both Rust and Cairo.             |
| Residual note     | SHA-256 output is truncated to fit felt252 (MSB byte zeroed), yielding 248 effective bits → 124-bit collision resistance for the SHA-256 component alone. The Hybrid-Hash XOR with Poseidon provides defense-in-depth. |

---

## Economic Attack Cost Analysis

| Attack                        | Classical Cost                                                   | Quantum Cost (Grover)                                                          | Status                                                                                     |
| ----------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| Forge STARK proof             | Computationally infeasible (soundness error ≤ 2^(-80))           | Not applicable — STARKs are post-quantum secure (no hidden subgroup structure) | Mitigated                                                                                  |
| Brute-force WOTS+ secret key  | 2^248 hash evaluations                                           | 2^124 hash evaluations                                                         | Mitigated                                                                                  |
| Brute-force single hash chain | 2^248 per chain, but checksum prevents single-chain exploitation | 2^124 per chain, same checksum constraint                                      | Mitigated                                                                                  |
| Replay attack (same nonce)    | O(1) — resubmit captured proof                                   | O(1)                                                                           | Mitigated — nonce binding enforced via domain separation; replayed nonces rejected         |
| Cross-chain replay            | O(1) — resubmit on different chain                               | O(1)                                                                           | Mitigated — domain separation binds signatures to (domain, chain_id, contract_addr, nonce) |
| Sequencer equivocation        | O(1) — submit conflicting batches                                | O(1)                                                                           | Mitigated — ZK-Fraud Proofs with 100% slashing; circuit breaker on excessive fraud proofs  |

### Cost Context

At an optimistic 10^12 quantum hash evaluations per second, brute-forcing a WOTS+ key
requires approximately 2^124 / 10^12 ≈ 2^84 seconds ≈ 6 × 10^17 years. This exceeds
the age of the universe by a factor of ~4 × 10^7.

---

## Mitigation Roadmap

| Phase     | Mitigations Delivered                                                                                                                                                                      | Status   |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------- |
| Phase 1.5 | Real STARK proofs (lambdaworks), Hybrid-Hash DS fix, Poseidon constants audit, access control on `submit_batch`, index consumption tracking, Lamport demotion                              | Complete |
| Phase 2   | Domain separation (`H(domain ‖ chain_id ‖ ...)`), nonce replay rejection, SMT/JMT for scalable index enforcement, XMSS many-time signatures                                                | Complete |
| Phase 3   | Full on-chain FRI verification, recursive batch aggregation, ZK-fraud proofs with slashing, data availability via state diffs, multi-lane mempools, account abstraction with index windows | Complete |

---

## Assumptions

1. The Poseidon permutation with t=6, RF=8, RP=83 is preimage and collision resistant at the stated security levels.
2. The STARK proof system (lambdaworks) is correctly implemented with soundness error ≤ 2^(-80).
3. The Cairo VM execution environment is deterministic and faithfully executes contract logic.
4. Sequencer honesty is no longer a trust assumption — ZK-Fraud Proofs with 100% slashing provide trustless enforcement. Any observer can submit an Accountability Trace proving sequencer violation, and valid fraud proofs trigger automatic slashing. The circuit breaker provides an additional safety mechanism.
5. No practical quantum computer capable of 2^124 hash evaluations exists or is expected within the framework's operational lifetime.
