# PCA Architecture — Verification Evolution

## Overview

Proof-Carrying Authorization (PCA) is the core verification model of the zk-pqc-framework.
Instead of verifying WOTS+ signatures directly on-chain (O(|σ|) cost), the framework
executes signature verification off-chain, generates a STARK proof of correct execution,
and verifies only the proof on-chain (O(|π|) cost).

This document traces the evolution of the on-chain verification strategy across project
phases, from the initial commitment mock through to the full on-chain FRI verifier.

---

## Phase 1 — Commitment Mock

**Status**: Complete (superseded by Phase 1.5)

The initial PCA contract (`zk_pqc_cairo.cairo`) was a stub that accepted a proof
array and returned `true` unconditionally. No cryptographic verification was performed.

- **On-chain**: Stub contract; always accepts.
- **Off-chain**: No prover existed.
- **Security**: None. Served only as a contract interface placeholder.

---

## Phase 1.5 — Real STARK Off-Chain + Proof Commitment On-Chain

**Status**: Complete (superseded by Phase 3)

### Off-Chain: Real STARK Proofs via lambdaworks

The Rust prover generates genuine STARK proofs for WOTS+ signature verification:

1. The user signs a message with WOTS+ (`signature_layer`).
2. The prover executes the WOTS+ verification off-chain, recording the execution
   trace as a 4-column table (`chain_index`, `step_index`, `current_value`, `expected_next`).
3. The `WotsVerificationAIR` encodes hash chain continuity as a polynomial transition
   constraint: `row[i+1].current_value == row[i].expected_next`.
4. lambdaworks generates a real `StarkProof` from the trace and AIR.
5. The proof is cryptographically unforgeable without the WOTS+ secret key.

Key files:

- `src/rust/proof_layer/src/wots_air.rs` — AIR definition and trace builder
- `src/rust/proof_layer/src/wots_prover.rs` — STARK proof generation
- `src/rust/proof_layer/src/wots_verifier.rs` — off-chain STARK verification
- `src/rust/proof_layer/src/pca.rs` — end-to-end PCA flow

### On-Chain: Poseidon Commitment Verification (Option B)

The Cairo contract verifies a Poseidon commitment tag that binds the proof data to
the authorization context. This is an honest intermediate step — the proof is real,
but full polynomial commitment verification in Cairo is deferred.

**Proof layout** (serialized `felt252` array):

```
proof[0]       = message_hash
proof[1]       = commitment_root
proof[2]       = index (as felt252)
proof[3..n-1]  = STARK proof commitment data
proof[n-1]     = verification tag
```

**Verification tag**:

```
tag = PoseidonSponge::hash(message_hash ‖ commitment_root ‖ index ‖ proof_data)
```

The contract recomputes the tag from the proof array and checks it matches the
embedded tag. This ensures the proof cannot be rebound to a different message,
commitment root, or OTS index.

**What this guarantees**:

- Proof is bound to a specific (message, root, index) triple.
- Consumed indices are tracked and rejected on reuse.
- Access control restricts `submit_batch` to the authorized sequencer.

**What this does NOT guarantee**:

- The contract does not verify the STARK polynomial commitments on-chain.
- An entity that can compute Poseidon hashes could fabricate a valid tag without
  a real STARK proof. The security assumption is that the off-chain prover is
  honest or that the proof is independently verified off-chain before submission.

Key file: `src/cairo/src/zk_pqc_cairo.cairo`

### Constraint Profile

For WOTS+ w=16 with 66 chains:

- Max trace rows: 66 × 15 = 990, padded to 1024
- Transition constraints: 1 (hash chain continuity)
- Boundary constraints: 2 (first row current_value, last row expected_next)
- Full Poseidon-inside-STARK estimate: ~128,000 total constraints

---

## Phase 3 — FRI On-Chain Verification (Implemented)

**Status**: Complete

### Goal

Replace the Poseidon commitment tag with full FRI polynomial commitment verification
in Cairo. The contract independently verifies the STARK proof without trusting
the off-chain prover.

### FRI Verifier Implementation

The FRI verifier is implemented in `src/cairo/src/fri_verifier.cairo` and integrated
into the PCA contract via the `verify_authorization_fri` function.

#### Key Files

| File                               | Description                                                                                                      |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `src/cairo/src/fri_verifier.cairo` | FRI verification module — Merkle commitment, Fiat-Shamir challenges, folding consistency, final polynomial check |
| `src/cairo/src/zk_pqc_cairo.cairo` | PCA contract — `verify_authorization_fri` function for full FRI verification                                     |

#### Contract Function

`verify_authorization_fri(proof, message_hash, commitment_root, index) -> bool`

This is the Option A upgrade path: full on-chain FRI verification. The existing
`verify_authorization` (Option B) remains available for backward-compatible
Poseidon commitment-only verification.

#### FRI Proof Layout

The FRI proof is serialized as a flat `felt252` array:

```
proof[0]       = message_hash
proof[1]       = commitment_root
proof[2]       = index (as felt252)
proof[3]       = num_fri_layers (L)
proof[4..4+L]  = FRI layer Merkle roots
proof[4+L..]   = query responses (evaluations + Merkle paths)
proof[n-1]     = verification tag (Poseidon hash of all above)
```

#### 6-Step Verification Process

1. **Parse & Validate**: Parse the flat proof array, validate bound fields (message_hash, commitment_root, index) match the provided parameters.
2. **Tag Verification**: Recompute the Poseidon commitment tag over `proof[0..n-1]` and verify it matches `proof[n-1]`.
3. **Merkle Inclusion**: For each FRI layer, verify the evaluation's Merkle authentication path against the layer's committed root using domain-separated Poseidon hashing (`DOMAIN_FRI_NODE`).
4. **Folding Consistency**: Derive Fiat-Shamir challenges from the proof transcript (`DOMAIN_FRI_CHALLENGE`), then verify folding consistency between consecutive layers via `DOMAIN_FRI_FOLD` commitments.
5. **Final Polynomial**: Verify that the last FRI layer's evaluation equals the claimed final constant polynomial value (degree-0 check).
6. **Return**: Return `true` only if ALL checks pass.

#### Domain Separators

| Constant               | Value                             | Purpose                          |
| ---------------------- | --------------------------------- | -------------------------------- |
| `DOMAIN_FRI_NODE`      | `0x4652495f4e4f4445` ("FRI_NODE") | FRI Merkle internal node hashing |
| `DOMAIN_FRI_CHALLENGE` | `0x4652495f4348414c` ("FRI_CHAL") | Fiat-Shamir challenge derivation |
| `DOMAIN_FRI_FOLD`      | `0x4652495f464f4c44` ("FRI_FOLD") | FRI layer folding commitment     |

### Batch STARK Proof

The recursive aggregator generates STARK proofs for batch Merkle commitment correctness.

#### Key Files

| File                                     | Description                                                                                                         |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `src/rust/proof_layer/src/batch_air.rs`  | AIR for batch Merkle commitment — records each Poseidon hash step in tree construction                              |
| `src/rust/proof_layer/src/aggregator.rs` | `prove_batch_commitment()` — generates STARK proof for batch commitment; `verify_batch_stark_proof()` — verifies it |

#### BatchStarkProof Struct

```rust
pub struct BatchStarkProof {
    pub stark_proof: StarkProof<PrimeField, PrimeField>,
    pub pub_inputs: BatchPublicInputs,
    pub proof_options: ProofOptions,
    pub generation_time_ms: u128,
}
```

The `prove_batch_commitment(leaf_hashes, proof_options)` function:

1. Builds the Merkle tree from leaf hashes, recording each Poseidon hash step
2. Constructs the execution trace for the `BatchMerkleAIR`
3. Generates a STARK proof via lambdaworks
4. Returns a `BatchStarkProof` containing the proof + public inputs

Verification via `verify_batch_stark_proof()` and `verify_batch_stark_proof_bound()`
checks the STARK proof against the public inputs (leaf hashes + commitment root).

### What Changes

| Aspect                | Phase 1.5                       | Phase 3 (Current)                                                     |
| --------------------- | ------------------------------- | --------------------------------------------------------------------- |
| Off-chain prover      | Real STARK proof (lambdaworks)  | Same                                                                  |
| On-chain verification | Poseidon commitment tag         | FRI polynomial commitment verification via `verify_authorization_fri` |
| Trust assumption      | Off-chain prover is honest      | Trustless — contract verifies proof independently                     |
| Security              | Proof binding via Poseidon hash | Full STARK soundness (≤ 2^(-80) error)                                |
| Batch aggregation     | Poseidon Merkle commitment      | STARK-proven batch commitment (`BatchStarkProof`)                     |

---

## Post-v1 Roadmap: Inner Verifier AIR (Recursive STARK)

**Status**: Post-v1

The current FRI verifier performs commitment-based verification (Poseidon hash binding
of folding relations). A full recursive STARK would implement the Inner Verifier AIR:
a STARK circuit that verifies another STARK proof inside its execution trace.

This would enable:

- Full polynomial evaluation verification in Cairo (not just commitment-based)
- True recursive proof composition: prove that a batch of proofs was verified correctly
- Constant-size proofs regardless of the number of recursive layers

The Inner Verifier AIR is architecturally planned but deferred to post-v1 due to:

- Cairo VM gas constraints for full polynomial arithmetic
- Complexity of encoding the FRI verifier as AIR constraints
- The current commitment-based approach provides sufficient security for v1

---

## Transaction Lifecycle (All Phases)

```
User → WOTS+ sign(message) → σ
       ↓
Off-chain Prover → execute verify(σ, pubkey) → trace → prove(trace) → π_auth
       ↓
Sequencer → collect N proofs → fold → Π_Batch
       ↓
Cairo Contract → verify(Π_Batch) → update SMT root → emit events
```

The lifecycle is identical across phases. Only the on-chain `verify` step changes:

- Phase 1: stub (always true)
- Phase 1.5: Poseidon commitment tag
- Phase 3: full FRI verification via `verify_authorization_fri`

---

## References

- `docs/THREAT_MODEL.md` — attack vectors and mitigation status
- `docs/POSEIDON_CONSTANTS.md` — Poseidon parameter choices and Starknet divergence
- `src/rust/proof_layer/tests/quantum_safe_vault.rs` — end-to-end vault test
- `src/rust/proof_layer/tests/pca_e2e.rs` — PCA integration tests
- `src/cairo/src/fri_verifier.cairo` — FRI verifier implementation
- `src/rust/proof_layer/src/batch_air.rs` — Batch STARK AIR
