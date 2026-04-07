# PCA Architecture — Verification Evolution

## Overview

Proof-Carrying Authorization (PCA) is the core verification model of the zk-pqc-framework.
Instead of verifying WOTS+ signatures directly on-chain (O(|σ|) cost), the framework
executes signature verification off-chain, generates a STARK proof of correct execution,
and verifies only the proof on-chain (O(|π|) cost).

This document traces the evolution of the on-chain verification strategy across project
phases, from the initial commitment mock through to the target full on-chain FRI verifier.

---

## Phase 1 — Commitment Mock

**Status**: Complete (superseded by Phase 1.5)

The initial PCA contract (`zk_pqc_cairo.cairo`) was a stub that accepted a proof
array and returned `true` unconditionally. No cryptographic verification was performed.

- **On-chain**: Stub contract; always accepts.
- **Off-chain**: No prover existed.
- **Security**: None. Served only as a contract interface placeholder.

---

## Phase 1.5 — Real STARK Off-Chain + Proof Commitment On-Chain (Current)

**Status**: Active

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

## Phase 3 — Full On-Chain FRI Verification (Target)

**Status**: Planned

### Goal

Replace the Poseidon commitment tag with full FRI polynomial commitment verification
in Cairo. The contract will independently verify the STARK proof without trusting
the off-chain prover.

### What Changes

| Aspect | Phase 1.5 (Current) | Phase 3 (Target) |
|--------|---------------------|-------------------|
| Off-chain prover | Real STARK proof (lambdaworks) | Same |
| On-chain verification | Poseidon commitment tag | FRI polynomial commitment verification |
| Trust assumption | Off-chain prover is honest | Trustless — contract verifies proof independently |
| Security | Proof binding via Poseidon hash | Full STARK soundness (≤ 2^(-80) error) |

### Implementation Path

1. Implement FRI layer verification in Cairo: deserialize proof, verify polynomial
   commitments, check query responses against Merkle paths.
2. Implement AIR constraint evaluation in Cairo for the `WotsVerificationAIR`.
3. Integrate with the existing `IPCAVerifier` interface — the contract signature
   remains unchanged; only the internal `verify_proof_commitment` function is replaced.
4. Recursive batch aggregation (`Π_Batch`) folds N individual proofs into one,
   keeping on-chain verification cost at O(1) regardless of batch size.

### Prerequisites

- Recursive STARK aggregator (task 20) for batch proof folding.
- Cairo-native FRI verifier implementation.
- Gas profiling to ensure verification fits within Layer 0 block limits.

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
- Phase 3: full FRI verification

---

## References

- `docs/THREAT_MODEL.md` — attack vectors and mitigation status
- `docs/POSEIDON_CONSTANTS.md` — Poseidon parameter choices and Starknet divergence
- `src/rust/proof_layer/tests/quantum_safe_vault.rs` — end-to-end vault test
- `src/rust/proof_layer/tests/pca_e2e.rs` — PCA integration tests
