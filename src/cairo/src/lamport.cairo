use zk_pqc_cairo::hash_trait::HashFunction;

/// Number of bits in a Lamport signature.
pub const LAMPORT_BITS: u32 = 256;

/// Lamport OTS key pair.
/// secret_0, secret_1: secrets for bit values 0 and 1 (each 256 elements).
/// public_0, public_1: H(secret_b[i]) for each position.
#[derive(Drop, Clone)]
pub struct LamportKeyPair {
    pub secret_0: Array<felt252>,
    pub secret_1: Array<felt252>,
    pub public_0: Array<felt252>,
    pub public_1: Array<felt252>,
}

/// Lamport OTS signature: one revealed secret per message bit.
#[derive(Drop, Clone)]
pub struct LamportSignature {
    pub revealed: Array<felt252>,
}

/// Generate a Lamport key pair from a seed.
///
/// Derives 2×256 secrets as H(seed_elem, b, i) for b in {0,1}, i in 0..256.
/// Public keys are H(secret[b][i]).
pub fn keygen<T, +HashFunction<T>, +Drop<T>>(seed: Span<felt252>) -> LamportKeyPair {
    let mut secret_0: Array<felt252> = ArrayTrait::new();
    let mut secret_1: Array<felt252> = ArrayTrait::new();
    let mut public_0: Array<felt252> = ArrayTrait::new();
    let mut public_1: Array<felt252> = ArrayTrait::new();

    let mut i: u32 = 0;
    while i < LAMPORT_BITS {
        // secret_0[i] = H(seed || 0 || i)
        let mut input_0: Array<felt252> = ArrayTrait::new();
        let mut j: u32 = 0;
        while j < seed.len() {
            input_0.append(*seed.at(j));
            j += 1;
        }
        input_0.append(0);
        input_0.append(i.into());
        let s0 = HashFunction::<T>::hash(input_0.span());
        secret_0.append(s0);
        public_0.append(HashFunction::<T>::hash(array![s0].span()));

        // secret_1[i] = H(seed || 1 || i)
        let mut input_1: Array<felt252> = ArrayTrait::new();
        let mut k: u32 = 0;
        while k < seed.len() {
            input_1.append(*seed.at(k));
            k += 1;
        }
        input_1.append(1);
        input_1.append(i.into());
        let s1 = HashFunction::<T>::hash(input_1.span());
        secret_1.append(s1);
        public_1.append(HashFunction::<T>::hash(array![s1].span()));

        i += 1;
    }

    LamportKeyPair { secret_0, secret_1, public_0, public_1 }
}

/// Sign a message represented as a span of bools (0 or 1 felt values).
///
/// For each bit position i, reveals secret_b[i] where b = message_bits[i].
/// Panics if message_bits length != LAMPORT_BITS.
pub fn sign(key: @LamportKeyPair, message_bits: Span<felt252>) -> LamportSignature {
    assert(message_bits.len() == LAMPORT_BITS, 'Invalid message length');

    let mut revealed: Array<felt252> = ArrayTrait::new();
    let mut i: u32 = 0;
    while i < LAMPORT_BITS {
        let bit = *message_bits.at(i);
        if bit == 0 {
            revealed.append(*key.secret_0.at(i));
        } else {
            revealed.append(*key.secret_1.at(i));
        }
        i += 1;
    }

    LamportSignature { revealed }
}

/// Verify a Lamport signature against a public key and message bits.
///
/// For each bit position i, checks H(revealed[i]) == public_b[i] where b = message_bits[i].
/// Returns false for any mismatch.
pub fn verify<T, +HashFunction<T>, +Drop<T>>(
    public_0: Span<felt252>,
    public_1: Span<felt252>,
    message_bits: Span<felt252>,
    sig: @LamportSignature,
) -> bool {
    if message_bits.len() != LAMPORT_BITS {
        return false;
    }
    if public_0.len() != LAMPORT_BITS || public_1.len() != LAMPORT_BITS {
        return false;
    }

    let revealed = sig.revealed;
    if revealed.len() != LAMPORT_BITS {
        return false;
    }

    let mut i: u32 = 0;
    let mut valid = true;
    while i < LAMPORT_BITS {
        let bit = *message_bits.at(i);
        let hash_of_revealed = HashFunction::<T>::hash(array![*revealed.at(i)].span());
        let expected = if bit == 0 {
            *public_0.at(i)
        } else {
            *public_1.at(i)
        };
        if hash_of_revealed != expected {
            valid = false;
        }
        i += 1;
    }

    valid
}

/// Convert a felt252 to a 256-element array of 0/1 felt values (big-endian bits).
///
/// Uses repeated division by 2 to extract bits, then reverses for big-endian order.
pub fn felt_to_bits(value: felt252) -> Array<felt252> {
    let mut bits: Array<felt252> = ArrayTrait::new();
    let val_u256: u256 = value.into();

    let mut i: u32 = 0;
    while i < LAMPORT_BITS {
        // Extract bit at position (255 - i) for big-endian
        let bit_pos: u32 = LAMPORT_BITS - 1 - i;
        let bit = get_bit_u256(val_u256, bit_pos);
        bits.append(bit);
        i += 1;
    }

    bits
}

/// Extract bit at position `pos` from a u256 value.
fn get_bit_u256(val: u256, pos: u32) -> felt252 {
    // Split into high (128 bits) and low (128 bits)
    if pos < 128 {
        // Bit is in the low part
        let shifted = val.low / pow2_u128(pos);
        if shifted % 2 == 1 {
            1
        } else {
            0
        }
    } else {
        // Bit is in the high part
        let high_pos = pos - 128;
        let shifted = val.high / pow2_u128(high_pos);
        if shifted % 2 == 1 {
            1
        } else {
            0
        }
    }
}

/// Compute 2^n for u128 (n < 128).
fn pow2_u128(n: u32) -> u128 {
    if n == 0 {
        return 1;
    }
    let mut result: u128 = 1;
    let mut i: u32 = 0;
    while i < n {
        result = result * 2;
        i += 1;
    }
    result
}
