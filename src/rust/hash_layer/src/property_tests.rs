// Feature: zk-pqc-framework, Property 1: Deterministic Constants Generation
//
// Validates: Requirements 1.1, 1.2, 1.4
//
// Verifies:
// - Repeated calls to get_mds_matrix() and get_round_constants() produce identical output
// - The MDS matrix satisfies the MDS property (all square submatrices invertible over Stark252)
// - Dimensions are correct (6×6 MDS, 546 round constants)
// - Constants are non-trivial (not identity, not all zeros)

#[cfg(test)]
mod tests {
    use crate::constants::{get_mds_matrix, get_round_constants, FELT, RF, RP, T};
    use itertools::Itertools;
    use proptest::prelude::*;

    /// Compute the determinant of a square matrix over the Stark252 field
    /// using Gaussian elimination with partial pivoting.
    fn field_determinant(matrix: &[Vec<FELT>]) -> FELT {
        let n = matrix.len();
        if n == 0 {
            return FELT::one();
        }
        let mut m: Vec<Vec<FELT>> = matrix.to_vec();
        let mut det = FELT::one();

        for col in 0..n {
            let mut pivot = None;
            for row in col..n {
                if m[row][col] != FELT::zero() {
                    pivot = Some(row);
                    break;
                }
            }
            let pivot = match pivot {
                Some(p) => p,
                None => return FELT::zero(),
            };
            if pivot != col {
                m.swap(col, pivot);
                det = FELT::zero() - det;
            }
            let pivot_val = m[col][col].clone();
            det = det * &pivot_val;
            let inv_pivot = pivot_val.inv().unwrap();
            for row in (col + 1)..n {
                let factor = &m[row][col] * &inv_pivot;
                for k in col..n {
                    let val = &m[col][k] * &factor;
                    m[row][k] = &m[row][k] - val;
                }
            }
        }
        det
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn prop_deterministic_constants_generation(_dummy in 0u32..1000u32) {
            // --- Determinism: repeated calls produce identical output ---
            let mds_a = get_mds_matrix();
            let mds_b = get_mds_matrix();
            for i in 0..T {
                for j in 0..T {
                    prop_assert!(
                        mds_a[i][j] == mds_b[i][j],
                        "MDS matrix differs at [{}][{}] across calls", i, j
                    );
                }
            }

            let ark_a = get_round_constants();
            let ark_b = get_round_constants();
            prop_assert!(
                ark_a.len() == ark_b.len(),
                "Round constants length differs across calls"
            );
            for (idx, (a, b)) in ark_a.iter().zip(ark_b.iter()).enumerate() {
                prop_assert!(
                    a == b,
                    "Round constant differs at index {} across calls", idx
                );
            }

            // --- Dimension checks ---
            let mds = get_mds_matrix();
            prop_assert!(mds.len() == T, "MDS row count must be {}", T);
            for (i, row) in mds.iter().enumerate() {
                prop_assert!(
                    row.len() == T,
                    "MDS row {} column count must be {}", i, T
                );
            }

            let ark = get_round_constants();
            let expected_ark_len = (RF + RP) * T;
            prop_assert!(
                ark.len() == expected_ark_len,
                "Round constants count must be {}", expected_ark_len
            );

            // --- Non-triviality: MDS is not the identity matrix ---
            let mut is_identity = true;
            for i in 0..T {
                for j in 0..T {
                    let expected = if i == j { FELT::one() } else { FELT::zero() };
                    if mds[i][j] != expected {
                        is_identity = false;
                    }
                }
            }
            prop_assert!(!is_identity, "MDS matrix must not be the identity matrix");

            // --- Non-triviality: round constants are not all zeros ---
            let all_zero = ark.iter().all(|c| *c == FELT::zero());
            prop_assert!(!all_zero, "Round constants must not be all zeros");

            // --- Non-triviality: sample round constants are non-zero ---
            let sample_indices = [0usize, ark.len() / 2, ark.len() - 1];
            for &idx in &sample_indices {
                prop_assert!(
                    ark[idx] != FELT::zero(),
                    "Round constant at index {} should be non-zero", idx
                );
            }

            // --- MDS property: all square submatrices have non-zero determinant ---
            let mds = get_mds_matrix();
            for size in 1..=T {
                for row_combo in (0..T).combinations(size) {
                    for col_combo in (0..T).combinations(size) {
                        let submatrix: Vec<Vec<FELT>> = row_combo.iter()
                            .map(|&r| col_combo.iter().map(|&c| mds[r][c].clone()).collect())
                            .collect();
                        let det = field_determinant(&submatrix);
                        prop_assert!(
                            det != FELT::zero(),
                            "MDS property violated: {}x{} submatrix rows={:?} cols={:?}",
                            size, size, row_combo, col_combo
                        );
                    }
                }
            }
        }
    }
}
