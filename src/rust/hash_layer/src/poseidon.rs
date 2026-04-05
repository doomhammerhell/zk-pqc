use crate::constants::{get_mds_matrix, get_round_constants, FELT, RF, RP, T};

pub struct Poseidon {
    mds: [[FELT; T]; T],
    ark: Vec<FELT>,
}

impl Default for Poseidon {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon {
    pub fn new() -> Self {
        Self {
            mds: get_mds_matrix(),
            ark: get_round_constants(),
        }
    }

    pub fn sbox(x: &FELT) -> FELT {
        let x2 = *x * *x;
        let x4 = x2 * x2;
        x4 * *x
    }

    pub fn mix(&self, state: &mut [FELT; T]) {
        let mut next_state = [FELT::zero(); T];
        for (i, next) in next_state.iter_mut().enumerate().take(T) {
            let mut sum = FELT::zero();
            for (j, s) in state.iter().enumerate().take(T) {
                sum += self.mds[i][j] * *s;
            }
            *next = sum;
        }
        *state = next_state;
    }

    pub fn permute(&self, state: &mut [FELT; T]) {
        let mut ark_idx = 0;

        // Full rounds (first half)
        for _ in 0..(RF / 2) {
            for elem in state.iter_mut().take(T) {
                *elem += self.ark[ark_idx];
                *elem = Self::sbox(elem);
                ark_idx += 1;
            }
            self.mix(state);
        }

        // Partial rounds
        for _ in 0..RP {
            for elem in state.iter_mut().take(T) {
                *elem += self.ark[ark_idx];
                ark_idx += 1;
            }
            // S-box only on first element
            state[0] = Self::sbox(&state[0]);
            self.mix(state);
        }

        // Full rounds (second half)
        for _ in 0..(RF / 2) {
            for elem in state.iter_mut().take(T) {
                *elem += self.ark[ark_idx];
                *elem = Self::sbox(elem);
                ark_idx += 1;
            }
            self.mix(state);
        }
    }
}
