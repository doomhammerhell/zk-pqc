# Threat Model — Post-Quantum Signature Verification Framework

## Scope

This document covers the attack surface of the zk-pqc-framework: a WOTS+-based
post-quantum signature scheme verified via STARK proofs on Cairo smart contracts.
Each vector lists the current mitigation status and the phase in which full
mitigation is delivered.

---

## Attack Vectors

### 1. OTS Key Reuse

| Attribute | Detail |
|-----------|--------|
| Description | WOTS+ is a one-time signature scheme. Signing two distinct messages with the same key index leaks enough hash chain preimages for an attacker to forge signatures. |
| Impact | Complete key compromise for the reused index. Attacker can authorize arbitrary transactions under that key. |
| Mitigation status | **PARTIAL** — Lamport demoted to reference-only (11E); WOTS+ is the sole production primitive. The Cairo contract tracks consumed indices in a `Map<u64, bool>` and rejects duplicates. |
| Full mitigation | **Phase 2** — SMT/JMT root (task 16) replaces the per-index map with a constant-storage Sparse Merkle Tree, enabling scalable non-reuse enforcement up to 2^64 indices. |

### 2. Transaction Replay

| Attribute | Detail |
|-----------|--------|
| Description | A valid proof submitted once could be re-submitted to authorize the same state transition again. |
| Impact | Double-spend or duplicate state mutation. |
| Mitigation status | **PARTIAL** — `submit_batch` marks indices as consumed; `verify_authorization` rejects consumed indices. However, there is no nonce or domain binding yet, so a proof valid on one deployment could theoretically be submitted to another. |
| Full mitigation | **Phase 2** — Canonical message hash with nonce binding (task 15): `H(domain ‖ chain_id ‖ contract_addr ‖ nonce ‖ H(calldata))`. Replayed nonces are rejected at the contract level. |

### 3. Cross-Chain / Cross-Contract Signature Reuse

| Attribute | Detail |
|-----------|--------|
| Description | A signature (and its STARK proof) generated for chain A or contract X is submitted on chain B or contract Y. |
| Impact | Unauthorized state transition on the target chain/contract. |
| Mitigation status | **NOT YET MITIGATED** — Proofs are currently bound to message hash and commitment root, but not to chain_id or contract address. |
| Full mitigation | **Phase 2** — Domain separation (task 15) binds every signature to `(domain, chain_id, contract_addr, nonce)`. Verification rejects mismatched context fields. |

### 4. STARK Proof Forgery

| Attribute | Detail |
|-----------|--------|
| Description | An attacker fabricates a STARK proof that passes verification without possessing the WOTS+ secret key. |
| Impact | Unauthorized transaction authorization. |
| Mitigation status | **MITIGATED (off-chain)** — Real STARK proofs are generated via lambdaworks (task 11F–11G). The `WotsVerificationAIR` encodes the full WOTS+ hash chain verification as polynomial constraints. Off-chain verification uses `lambdaworks_stark::verify()`. On-chain verification currently uses a Poseidon commitment tag (Option B) that binds the proof to message, root, and index. |
| Full mitigation | **Phase 3** — Full FRI polynomial commitment verification in Cairo. Until then, the real STARK proof is generated and verified off-chain; on-chain uses the proof commitment. The proof itself is cryptographically unforgeable. |
| Security level | Soundness error ≤ 2^(-80) per the STARK protocol parameters. |

### 5. Sequencer Equivocation

| Attribute | Detail |
|-----------|--------|
| Description | A malicious sequencer submits conflicting batches, replays indices, or withholds transactions. |
| Impact | State inconsistency, censorship, or double-spend at the sequencer level. |
| Mitigation status | **PARTIAL** — `submit_batch` is guarded by `authorized_sequencer` access control (task 11H.2). Owner can rotate the sequencer via `set_sequencer`. Index consumption is enforced per-batch. |
| Full mitigation | **Phase 3** — ZK-Fraud Proofs with slashing (task 24). Any observer can submit an Accountability Trace proving sequencer violation. Valid fraud proofs trigger 100% stake slashing. A circuit breaker pauses batch processing if fraud proof volume exceeds a threshold. |

### 6. Quantum Attack (Grover's Algorithm)

| Attribute | Detail |
|-----------|--------|
| Description | A quantum adversary uses Grover's algorithm to find hash preimages in O(2^(n/2)) evaluations instead of O(2^n). |
| Impact | Key recovery if security margin is insufficient. |
| Mitigation status | **MITIGATED** — Poseidon output over Stark252 provides 248 effective bits (MSB byte zeroed). Grover reduces preimage resistance to 2^124 hash evaluations. WOTS+ checksum forces the attacker to break all chains simultaneously, not just one. |
| Security level | **124-bit quantum security** — exceeds NIST Post-Quantum Category 1 target (equivalent to AES-128 against quantum). |
| Reference | `test_vault_grover_resistance_doc` in `src/rust/proof_layer/tests/quantum_safe_vault.rs` documents and asserts these parameters. |

### 7. Poseidon Algebraic Attacks

| Attribute | Detail |
|-----------|--------|
| Description | Algebraic cryptanalysis targeting the Poseidon permutation structure (e.g., Gröbner basis, interpolation, or differential attacks on the S-box x^5). |
| Impact | Hash collision or preimage, breaking signature and Merkle tree security. |
| Mitigation status | **MITIGATED** — Parameters follow conservative recommendations: t=6, RF=8 full rounds, RP=83 partial rounds. MDS matrix is Cauchy-constructed with machine-verified invertibility of all square submatrices. Round constants are derived from SHA-256 CSPRNG for auditability. |
| Note | This project uses project-specific Poseidon constants (not Starknet-native). See `docs/POSEIDON_CONSTANTS.md` for the rationale and divergence details. |

### 8. Hybrid-Hash Domain Separation Bypass

| Attribute | Detail |
|-----------|--------|
| Description | Prior to task 11A, the SHA-256 component of Hybrid-Hash ignored the domain separator, meaning `HybridHash(ds=A, x)` and `HybridHash(ds=B, x)` produced SHA-256 components that were identical. |
| Impact | Weakened domain separation when using Hybrid-Hash mode. |
| Mitigation status | **MITIGATED** — Fixed in task 11A. Both Poseidon and SHA-256 components now incorporate the domain separator: `poseidon_hash_with_ds(ds, input) + sha256(ds ‖ input)`. Fix applied in both Rust and Cairo. |
| Residual note | SHA-256 output is truncated to fit felt252 (MSB byte zeroed), yielding 248 effective bits → 124-bit collision resistance for the SHA-256 component alone. The Hybrid-Hash XOR with Poseidon provides defense-in-depth. |

---

## Economic Attack Cost Analysis

| Attack | Classical Cost | Quantum Cost (Grover) | Status |
|--------|---------------|----------------------|--------|
| Forge STARK proof | Computationally infeasible (soundness error ≤ 2^(-80)) | Not applicable — STARKs are post-quantum secure (no hidden subgroup structure) | Mitigated |
| Brute-force WOTS+ secret key | 2^248 hash evaluations | 2^124 hash evaluations | Mitigated |
| Brute-force single hash chain | 2^248 per chain, but checksum prevents single-chain exploitation | 2^124 per chain, same checksum constraint | Mitigated |
| Replay attack (same index) | O(1) — resubmit captured proof | O(1) | Partial — index tracking blocks same-index replay; nonce binding in Phase 2 |
| Cross-chain replay | O(1) — resubmit on different chain | O(1) | Not yet mitigated — domain separation in Phase 2 |
| Sequencer equivocation | O(1) — submit conflicting batches | O(1) | Partial — access control in place; fraud proofs in Phase 3 |

### Cost Context

At an optimistic 10^12 quantum hash evaluations per second, brute-forcing a WOTS+ key
requires approximately 2^124 / 10^12 ≈ 2^84 seconds ≈ 6 × 10^17 years. This exceeds
the age of the universe by a factor of ~4 × 10^7.

---

## Mitigation Roadmap

| Phase | Mitigations Delivered |
|-------|----------------------|
| Phase 1.5 (current) | Real STARK proofs (lambdaworks), Hybrid-Hash DS fix, Poseidon constants audit, access control on `submit_batch`, index consumption tracking, Lamport demotion |
| Phase 2 | Domain separation (`H(domain ‖ chain_id ‖ ...)`), nonce replay rejection, SMT/JMT for scalable index enforcement, XMSS many-time signatures |
| Phase 3 | Full on-chain FRI verification, recursive batch aggregation, ZK-fraud proofs with slashing, data availability via state diffs, multi-lane mempools |

---

## Assumptions

1. The Poseidon permutation with t=6, RF=8, RP=83 is preimage and collision resistant at the stated security levels.
2. The STARK proof system (lambdaworks) is correctly implemented with soundness error ≤ 2^(-80).
3. The Cairo VM execution environment is deterministic and faithfully executes contract logic.
4. The authorized sequencer key is not compromised (until fraud proofs provide trustless enforcement in Phase 3).
5. No practical quantum computer capable of 2^124 hash evaluations exists or is expected within the framework's operational lifetime.
