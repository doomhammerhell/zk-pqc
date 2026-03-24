use core::array::ArrayTrait;
use zk_pqc_cairo::poseidon::permute;

fn absorb(ref state: Array<felt252>, input: Span<felt252>) {
    let rate: usize = 4;
    let mut i: usize = 0;
    while i < input.len() {
        let mut next_state = ArrayTrait::new();
        // Add current chunk to rate part of the state
        let mut j: usize = 0;
        while j < T {
            let mut val = *state.at(j);
            if j < rate && (i + j) < input.len() {
                val = val + *input.at(i + j);
            }
            next_state.append(val);
            j += 1;
        };
        state = next_state;
        permute(ref state);
        i += rate;
    };
}

const T: usize = 6;

fn squeeze(ref state: Array<felt252>) -> felt252 {
    let result = *state.at(0);
    permute(ref state);
    result
}

pub fn hash_with_ds(ds: felt252, input: Span<felt252>) -> felt252 {
    let mut state = ArrayTrait::new();
    let mut i: usize = 0;
    while i < T - 1 {
        state.append(0);
        i += 1;
    };
    state.append(ds); // DS in the capacity part

    absorb(ref state, input);
    squeeze(ref state)
}

pub fn hash(input: Span<felt252>) -> felt252 {
    hash_with_ds(0, input)
}
