use crate::constants::{FELT, T};
use crate::poseidon::Poseidon;

pub struct PoseidonSponge {
    poseidon: Poseidon,
    state: [FELT; T],
    rate: usize,
}

impl PoseidonSponge {
    pub fn new_with_ds(ds: FELT) -> Self {
        let mut state = [FELT::zero(); T];
        state[T - 1] = ds; // DS in the capacity part
        Self {
            poseidon: Poseidon::new(),
            state,
            rate: 4,
        }
    }

    pub fn absorb(&mut self, input: &[FELT]) {
        for chunk in input.chunks(self.rate) {
            for (i, val) in chunk.iter().enumerate() {
                self.state[i] = self.state[i] + val;
            }
            self.poseidon.permute(&mut self.state);
        }
    }

    pub fn squeeze(&mut self) -> FELT {
        let result = self.state[0];
        self.poseidon.permute(&mut self.state);
        result
    }

    pub fn hash_with_ds(ds: FELT, input: &[FELT]) -> FELT {
        let mut sponge = Self::new_with_ds(ds);
        sponge.absorb(input);
        sponge.squeeze()
    }

    pub fn hash(input: &[FELT]) -> FELT {
        Self::hash_with_ds(FELT::zero(), input)
    }
}
