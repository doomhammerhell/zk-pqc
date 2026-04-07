# Poseidon Constants — Architectural Decision Record

## Summary

This project uses **project-specific Poseidon constants** that are intentionally different
from the Starknet-native Poseidon parameters. This is a deliberate architectural decision
made for auditability and research independence.

## Our Constants

| Parameter | Value |
|-----------|-------|
| State width (t) | 6 |
| Full rounds (RF) | 8 |
| Partial rounds (RP) | 83 |
| Field | Stark252 (P = 2^251 + 17·2^192 + 1) |
| MDS construction | **Cauchy matrix** over F_P |
| Round constant generation | **SHA-256 based CSPRNG** |
| Canonical seed | `zk-pqc-poseidon-t6-rf8-rp83-stark252` |
| Generator script | `scripts/generate_constants.py` |

## Starknet-Native Constants

Starknet's built-in `poseidon()` syscall uses parameters derived via the **Grain LFSR**
method described in the original Poseidon paper. The MDS matrix and round constants are
generated through a different procedure and are baked into the Cairo VM and Starknet OS.

## Why We Diverge

1. **Auditability**: Our Cauchy MDS + SHA-256 CSPRNG pipeline is fully deterministic and
   reproducible from a single seed string. Anyone can re-run `scripts/generate_constants.py`
   and verify the output byte-for-byte.

2. **Research independence**: This project is a research framework for post-quantum
   signature verification in ZK environments. Using our own constant generation allows us
   to study and modify the Poseidon parameterization without depending on Starknet's
   specific choices.

3. **MDS property verification**: The generator explicitly checks that all square
   submatrices of the MDS matrix are invertible over F_P, providing a machine-verifiable
   proof of the MDS property.

## Compatibility Warning

**Our Poseidon output is NOT compatible with Starknet's native `poseidon()` syscall.**

Hashing the same input with our implementation and with Starknet's built-in will produce
different results. This means:

- Do not mix our hash outputs with Starknet-native Poseidon outputs.
- Do not use Starknet's `poseidon()` syscall as a drop-in replacement for our hash layer.
- Cross-contract calls that depend on hash consistency must use the same implementation.

An interop divergence test (`test_poseidon_diverges_from_starknet_known_output` in
`src/rust/hash_layer/src/tests.rs`) asserts that our output for `[1, 2, 3]` differs from
the known Starknet result, serving as a guardrail against accidental conflation.

## Reproducing the Constants

```bash
python scripts/generate_constants.py \
  --seed "zk-pqc-poseidon-t6-rf8-rp83-stark252" \
  --t 6 --rf 8 --rp 83
```

The script outputs:
- `scripts/generated_constants_rust.txt` — Rust array literals
- `scripts/generated_constants_cairo.txt` — Cairo array literals
- SHA-256 audit hash of all generated values (printed to stdout)
