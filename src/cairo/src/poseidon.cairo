use zk_pqc_cairo::constants::{get_mds_matrix, get_round_constants};

const T: usize = 6;
const RF: usize = 8;
const RP: usize = 83;

fn sbox(x: felt252) -> felt252 {
    let x2 = x * x;
    let x4 = x2 * x2;
    x * x4
}

fn mix(ref state: Array<felt252>, mds: Span<felt252>) {
    let s0 = *state.at(0);
    let s1 = *state.at(1);
    let s2 = *state.at(2);
    let s3 = *state.at(3);
    let s4 = *state.at(4);
    let s5 = *state.at(5);

    let mut next_state = ArrayTrait::new();

    // Row 0
    next_state
        .append(
            *mds.at(0) * s0
                + *mds.at(1) * s1
                + *mds.at(2) * s2
                + *mds.at(3) * s3
                + *mds.at(4) * s4
                + *mds.at(5) * s5,
        );
    // Row 1
    next_state
        .append(
            *mds.at(6) * s0
                + *mds.at(7) * s1
                + *mds.at(8) * s2
                + *mds.at(9) * s3
                + *mds.at(10) * s4
                + *mds.at(11) * s5,
        );
    // Row 2
    next_state
        .append(
            *mds.at(12) * s0
                + *mds.at(13) * s1
                + *mds.at(14) * s2
                + *mds.at(15) * s3
                + *mds.at(16) * s4
                + *mds.at(17) * s5,
        );
    // Row 3
    next_state
        .append(
            *mds.at(18) * s0
                + *mds.at(19) * s1
                + *mds.at(20) * s2
                + *mds.at(21) * s3
                + *mds.at(22) * s4
                + *mds.at(23) * s5,
        );
    // Row 4
    next_state
        .append(
            *mds.at(24) * s0
                + *mds.at(25) * s1
                + *mds.at(26) * s2
                + *mds.at(27) * s3
                + *mds.at(28) * s4
                + *mds.at(29) * s5,
        );
    // Row 5
    next_state
        .append(
            *mds.at(30) * s0
                + *mds.at(31) * s1
                + *mds.at(32) * s2
                + *mds.at(33) * s3
                + *mds.at(34) * s4
                + *mds.at(35) * s5,
        );

    state = next_state;
}

pub fn permute(ref state: Array<felt252>) {
    let mds = get_mds_matrix();
    let ark = get_round_constants();
    let mut ark_idx: usize = 0;

    // Full rounds (first half)
    let mut r: usize = 0;
    while r < (RF / 2) {
        let mut i: usize = 0;
        let mut next_state = ArrayTrait::new();
        while i < T {
            let val = *state.at(i) + *ark.at(ark_idx);
            next_state.append(sbox(val));
            ark_idx += 1;
            i += 1;
        }
        state = next_state;
        mix(ref state, mds);
        r += 1;
    }

    // Partial rounds
    r = 0;
    while r < RP {
        let mut next_state = ArrayTrait::new();
        let mut i: usize = 0;
        while i < T {
            let val = *state.at(i) + *ark.at(ark_idx);
            if i == 0 {
                next_state.append(sbox(val));
            } else {
                next_state.append(val);
            }
            ark_idx += 1;
            i += 1;
        }
        state = next_state;
        mix(ref state, mds);
        r += 1;
    }

    // Full rounds (second half)
    r = 0;
    while r < (RF / 2) {
        let mut i: usize = 0;
        let mut next_state = ArrayTrait::new();
        while i < T {
            let val = *state.at(i) + *ark.at(ark_idx);
            next_state.append(sbox(val));
            ark_idx += 1;
            i += 1;
        }
        state = next_state;
        mix(ref state, mds);
        r += 1;
    };
}
