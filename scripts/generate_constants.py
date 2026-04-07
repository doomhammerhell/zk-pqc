#!/usr/bin/env python3
"""
Deterministic Constants Generator for Poseidon t=6, RF=8, RP=83 over Stark252.

WARNING: Project-specific Poseidon constants.
These constants are generated via Cauchy MDS + SHA-256 CSPRNG and are NOT compatible
with Starknet's native poseidon() syscall which uses Grain LFSR.
See docs/POSEIDON_CONSTANTS.md for the full rationale.

Generates:
  - 6x6 MDS matrix via Cauchy matrix construction
  - 546 round constants via SHA-256 based CSPRNG
  - Verifies MDS property (all square submatrices invertible over F_p)
  - Outputs constants for Rust and Cairo

Usage:
    python scripts/generate_constants.py [--seed SEED] [--t T] [--rf RF] [--rp RP]
"""

import hashlib
import itertools
import sys
import argparse

# Stark252 prime: P = 2^251 + 17 * 2^192 + 1
P = 2**251 + 17 * 2**192 + 1

# Default parameters
DEFAULT_SEED = "zk-pqc-poseidon-t6-rf8-rp83-stark252"
DEFAULT_T = 6
DEFAULT_RF = 8
DEFAULT_RP = 83


# ---------------------------------------------------------------------------
# Finite field arithmetic helpers (mod P)
# ---------------------------------------------------------------------------

def mod_inv(a, p):
    """Modular inverse via extended Euclidean algorithm."""
    if a % p == 0:
        raise ValueError("Zero has no inverse")
    g, x, _ = _extended_gcd(a % p, p)
    if g != 1:
        raise ValueError(f"No inverse for {a} mod {p}")
    return x % p


def _extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def mod_det(matrix, p):
    """Compute determinant of a square matrix over F_p using Gaussian elimination."""
    n = len(matrix)
    # Work on a copy
    m = [row[:] for row in matrix]
    det = 1
    for col in range(n):
        # Find pivot
        pivot = -1
        for row in range(col, n):
            if m[row][col] % p != 0:
                pivot = row
                break
        if pivot == -1:
            return 0
        if pivot != col:
            m[col], m[pivot] = m[pivot], m[col]
            det = (-det) % p
        inv_pivot = mod_inv(m[col][col], p)
        det = (det * m[col][col]) % p
        for row in range(col + 1, n):
            factor = (m[row][col] * inv_pivot) % p
            for k in range(col, n):
                m[row][k] = (m[row][k] - factor * m[col][k]) % p
    return det % p


# ---------------------------------------------------------------------------
# MDS Matrix Generation (Cauchy construction)
# ---------------------------------------------------------------------------

def generate_mds_matrix(t, p):
    """
    Generate a t×t Cauchy MDS matrix over F_p.

    Uses x = {0, 1, ..., t-1} and y = {t, t+1, ..., 2t-1}.
    M[i][j] = 1 / (x_i + y_j) mod p
    """
    x = list(range(t))
    y = list(range(t, 2 * t))
    matrix = []
    for i in range(t):
        row = []
        for j in range(t):
            val = mod_inv(x[i] + y[j], p)
            row.append(val)
        matrix.append(row)
    return matrix


# ---------------------------------------------------------------------------
# MDS Property Verification
# ---------------------------------------------------------------------------

def verify_mds_property(matrix, p):
    """
    Verify that ALL square submatrices of the given matrix have non-zero
    determinant over F_p. This confirms the MDS property.
    """
    t = len(matrix)
    for size in range(1, t + 1):
        for row_indices in itertools.combinations(range(t), size):
            for col_indices in itertools.combinations(range(t), size):
                submatrix = [
                    [matrix[r][c] for c in col_indices]
                    for r in row_indices
                ]
                det = mod_det(submatrix, p)
                if det == 0:
                    return False, size, row_indices, col_indices
    return True, None, None, None


# ---------------------------------------------------------------------------
# Round Constants Generation (SHA-256 CSPRNG)
# ---------------------------------------------------------------------------

def generate_round_constants(seed, t, rf, rp, p):
    """
    Generate (RF + RP) * t round constants via SHA-256 based CSPRNG.

    1. state = SHA-256(seed || "round_constants" || parameters_string)
    2. For each constant i: state = SHA-256(state || counter_bytes), reduce mod P
    """
    num_constants = (rf + rp) * t
    params_string = f"t={t},rf={rf},rp={rp},p={p}"
    initial_input = (seed + "round_constants" + params_string).encode("utf-8")
    state = hashlib.sha256(initial_input).digest()

    constants = []
    for counter in range(num_constants):
        counter_bytes = counter.to_bytes(8, byteorder="big")
        state = hashlib.sha256(state + counter_bytes).digest()
        # Interpret state as big-endian integer, reduce mod P
        value = int.from_bytes(state, byteorder="big") % p
        constants.append(value)

    return constants


# ---------------------------------------------------------------------------
# Audit hash
# ---------------------------------------------------------------------------

def compute_audit_hash(mds_matrix, round_constants):
    """Compute SHA-256 hash of all generated constants for auditing."""
    h = hashlib.sha256()
    for row in mds_matrix:
        for val in row:
            h.update(str(val).encode("utf-8"))
    for val in round_constants:
        h.update(str(val).encode("utf-8"))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def format_rust_output(mds_matrix, round_constants, t):
    """Format constants as Rust array literals."""
    lines = []
    lines.append("// Auto-generated by scripts/generate_constants.py")
    lines.append("// DO NOT EDIT MANUALLY")
    lines.append("")
    lines.append(f"// MDS Matrix ({t}x{t}) - Cauchy construction over Stark252")
    lines.append(f"pub const MDS_MATRIX: [[&str; {t}]; {t}] = [")
    for row in mds_matrix:
        entries = ", ".join(f'"{val}"' for val in row)
        lines.append(f"    [{entries}],")
    lines.append("];")
    lines.append("")
    num_rc = len(round_constants)
    lines.append(f"// Round Constants (ARK) - {num_rc} elements")
    lines.append(f"pub const ROUND_CONSTANTS: [&str; {num_rc}] = [")
    for i in range(0, num_rc, t):
        chunk = round_constants[i:i + t]
        entries = ", ".join(f'"{val}"' for val in chunk)
        lines.append(f"    {entries},")
    lines.append("];")
    return "\n".join(lines)


def format_cairo_output(mds_matrix, round_constants, t):
    """Format constants as Cairo array literals."""
    lines = []
    lines.append("// Auto-generated by scripts/generate_constants.py")
    lines.append("// DO NOT EDIT MANUALLY")
    lines.append("")
    lines.append(f"// MDS Matrix ({t}x{t}) - Cauchy construction over Stark252")
    lines.append(f"// Stored as flat array of {t*t} elements (row-major)")
    lines.append("pub const MDS_MATRIX: [felt252; " + str(t * t) + "] = [")
    for row in mds_matrix:
        entries = ", ".join(str(val) for val in row)
        lines.append(f"    {entries},")
    lines.append("];")
    lines.append("")
    num_rc = len(round_constants)
    lines.append(f"// Round Constants (ARK) - {num_rc} elements")
    lines.append(f"pub const ROUND_CONSTANTS: [felt252; {num_rc}] = [")
    for i in range(0, num_rc, t):
        chunk = round_constants[i:i + t]
        entries = ", ".join(str(val) for val in chunk)
        lines.append(f"    {entries},")
    lines.append("];")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate Poseidon constants (MDS matrix + round constants)"
    )
    parser.add_argument("--seed", default=DEFAULT_SEED, help="Canonical seed string")
    parser.add_argument("--t", type=int, default=DEFAULT_T, help="State width t")
    parser.add_argument("--rf", type=int, default=DEFAULT_RF, help="Full rounds RF")
    parser.add_argument("--rp", type=int, default=DEFAULT_RP, help="Partial rounds RP")
    args = parser.parse_args()

    seed = args.seed
    t = args.t
    rf = args.rf
    rp = args.rp
    num_constants = (rf + rp) * t

    # --- Audit log: parameters ---
    print("=" * 70)
    print("Poseidon Constants Generator")
    print("=" * 70)
    print(f"Seed:            {seed}")
    print(f"Parameters:      t={t}, RF={rf}, RP={rp}")
    print(f"Field modulus P: {P}")
    print(f"MDS size:        {t}x{t}")
    print(f"Round constants: {num_constants}")
    print()

    # --- Generate MDS matrix ---
    print("Generating MDS matrix (Cauchy construction)...")
    mds = generate_mds_matrix(t, P)
    print("  Done.")

    # --- Verify MDS property ---
    print("Verifying MDS property (all square submatrices invertible)...")
    ok, fail_size, fail_rows, fail_cols = verify_mds_property(mds, P)
    if not ok:
        print(f"  FAILED: {fail_size}x{fail_size} submatrix "
              f"rows={fail_rows} cols={fail_cols} has zero determinant")
        sys.exit(1)
    print("  MDS property verified: all square submatrices are invertible.")

    # --- Generate round constants ---
    print(f"Generating {num_constants} round constants via SHA-256 CSPRNG...")
    ark = generate_round_constants(seed, t, rf, rp, P)
    print("  Done.")

    # --- Audit hash ---
    audit_hash = compute_audit_hash(mds, ark)
    print()
    print(f"SHA-256 audit hash: {audit_hash}")
    print()

    # --- Write Rust output ---
    rust_path = "scripts/generated_constants_rust.txt"
    rust_content = format_rust_output(mds, ark, t)
    with open(rust_path, "w") as f:
        f.write(rust_content + "\n")
    print(f"Rust constants written to:  {rust_path}")

    # --- Write Cairo output ---
    cairo_path = "scripts/generated_constants_cairo.txt"
    cairo_content = format_cairo_output(mds, ark, t)
    with open(cairo_path, "w") as f:
        f.write(cairo_content + "\n")
    print(f"Cairo constants written to: {cairo_path}")

    print()
    print("Constants generation complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
