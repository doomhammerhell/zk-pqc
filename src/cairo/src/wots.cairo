use zk_pqc_cairo::hash_trait::HashFunction;

/// WOTS+ key pair.
/// secret_chains: base chain seeds (one per chain, including checksum chains).
/// public_chains: fully iterated chain endpoints: public_chains[i] = H^(w-1)(secret_chains[i]).
#[derive(Drop, Clone)]
pub struct WotsKeyPair {
    pub secret_chains: Array<felt252>,
    pub public_chains: Array<felt252>,
}

/// WOTS+ signature: intermediate chain values.
/// chain_values[i] = H^(m_i)(secret_chains[i]) where m_i is the i-th element
/// of the message+checksum decomposition.
#[derive(Drop, Clone)]
pub struct WotsSignature {
    pub chain_values: Array<felt252>,
}

/// Number of base-w digits needed to represent a 252-bit field element.
/// For w=16 (log_w=4): ceil(252/4) = 63.
/// For w=4 (log_w=2): ceil(252/2) = 126.
/// For w=256 (log_w=8): ceil(252/8) = 32.
pub fn message_len(w: u32) -> u32 {
    let log_w = log2_int(w);
    (252 + log_w - 1) / log_w
}

/// Number of base-w digits needed to represent the checksum.
/// Max checksum = msg_len * (w-1). We need ceil(log_w(max_checksum + 1)) digits.
pub fn checksum_len(w: u32, msg_len: u32) -> u32 {
    let max_checksum = msg_len * (w - 1);
    if max_checksum == 0 {
        return 1;
    }
    let log_w = log2_int(w);
    let bits_needed = int_log2_floor(max_checksum) + 1;
    (bits_needed + log_w - 1) / log_w
}

/// Total number of chains (message + checksum).
pub fn total_chains(w: u32) -> u32 {
    let ml = message_len(w);
    ml + checksum_len(w, ml)
}

/// Decompose a felt252 into base-w elements (big-endian nibble extraction).
/// Returns msg_len elements, each in [0, w).
pub fn decompose_message(w: u32, message: felt252) -> Array<u32> {
    let log_w = log2_int(w);
    let ml = message_len(w);
    let val_u256: u256 = message.into();

    // Extract log_w-bit chunks from the 252-bit value, big-endian.
    // Bit 251 is the MSB. Chunk i covers bits [252 - (i+1)*log_w, 252 - i*log_w).
    let mut elements: Array<u32> = ArrayTrait::new();
    let mut i: u32 = 0;
    while i < ml {
        // For chunk i (big-endian), we want bits starting at position 252 - (i+1)*log_w
        // from the LSB perspective. We shift right by that amount and mask log_w bits.
        let total_bits: u32 = 252;
        let chunk_start = if (i + 1) * log_w <= total_bits {
            total_bits - (i + 1) * log_w
        } else {
            0
        };
        let shifted = shr_u256(val_u256, chunk_start);
        let mask: u256 = pow2_u256(log_w) - 1;
        let nibble_u256 = shifted & mask;
        // Convert to u32 (safe since nibble < w which fits in u32)
        let nibble: u32 = nibble_u256.low.try_into().unwrap();
        elements.append(nibble);
        i += 1;
    };

    elements
}

/// Compute the WOTS+ checksum: C = Σ(w-1-m_i), decomposed into base-w elements.
/// This prevents existential forgery by ensuring the total iteration sum is constant.
pub fn checksum(w: u32, message_elements: Span<u32>) -> Array<u32> {
    let mut c: u32 = 0;
    let mut i: u32 = 0;
    while i < message_elements.len() {
        c += (w - 1) - *message_elements.at(i);
        i += 1;
    };

    let cs_len = checksum_len(w, message_elements.len());

    // Decompose c into base-w digits (least significant first, then reverse for big-endian).
    let mut digits: Array<u32> = ArrayTrait::new();
    let mut remaining = c;
    let mut j: u32 = 0;
    while j < cs_len {
        digits.append(remaining % w);
        remaining /= w;
        j += 1;
    };

    // Reverse to get big-endian order
    let mut reversed: Array<u32> = ArrayTrait::new();
    let len = digits.len();
    let mut k: u32 = 0;
    while k < len {
        reversed.append(*digits.at(len - 1 - k));
        k += 1;
    };

    reversed
}

/// Iterate a hash chain: H^n(value) — apply the hash function n times.
pub fn chain_hash<T, +HashFunction<T>, +Drop<T>>(value: felt252, iterations: u32) -> felt252 {
    let mut current = value;
    let mut i: u32 = 0;
    while i < iterations {
        current = HashFunction::<T>::hash(array![current].span());
        i += 1;
    };
    current
}

/// Generate a WOTS+ key pair from a seed.
/// secret_chains[i] = H(seed || i) for each chain
/// public_chains[i] = H^(w-1)(secret_chains[i])
pub fn keygen<T, +HashFunction<T>, +Drop<T>>(w: u32, seed: Span<felt252>) -> WotsKeyPair {
    let total = total_chains(w);
    let mut secret_chains: Array<felt252> = ArrayTrait::new();
    let mut public_chains: Array<felt252> = ArrayTrait::new();

    let mut i: u32 = 0;
    while i < total {
        // Derive secret: H(seed || i)
        let mut input: Array<felt252> = ArrayTrait::new();
        let mut j: u32 = 0;
        while j < seed.len() {
            input.append(*seed.at(j));
            j += 1;
        };
        input.append(i.into());
        let secret = HashFunction::<T>::hash(input.span());
        secret_chains.append(secret);

        // Public key: iterate w-1 times
        let public = chain_hash::<T>(secret, w - 1);
        public_chains.append(public);

        i += 1;
    };

    WotsKeyPair { secret_chains, public_chains }
}

/// Sign a message (single felt252) with WOTS+.
/// 1. Decompose message into base-w elements
/// 2. Compute checksum and append checksum elements
/// 3. For each element m_i: chain_values[i] = H^(m_i)(secret_chains[i])
pub fn sign<T, +HashFunction<T>, +Drop<T>>(
    w: u32, key: @WotsKeyPair, message: felt252,
) -> WotsSignature {
    let msg_elements = decompose_message(w, message);
    let checksum_elements = checksum(w, msg_elements.span());

    let total = total_chains(w);
    let mut chain_values: Array<felt252> = ArrayTrait::new();

    // Process message elements
    let mut i: u32 = 0;
    while i < msg_elements.len() {
        let m_i = *msg_elements.at(i);
        let val = chain_hash::<T>(*key.secret_chains.at(i), m_i);
        chain_values.append(val);
        i += 1;
    };

    // Process checksum elements
    let msg_len_val = msg_elements.len();
    let mut j: u32 = 0;
    while j < checksum_elements.len() {
        let c_j = *checksum_elements.at(j);
        let val = chain_hash::<T>(*key.secret_chains.at(msg_len_val + j), c_j);
        chain_values.append(val);
        j += 1;
    };

    assert(chain_values.len() == total, 'chain count mismatch');

    WotsSignature { chain_values }
}

/// Verify a WOTS+ signature.
/// For each element m_i, iterate chain_values[i] by (w-1-m_i) more hashes
/// and compare with public_chains[i]. All must match.
pub fn verify<T, +HashFunction<T>, +Drop<T>>(
    w: u32, pubkey: Span<felt252>, message: felt252, sig: @WotsSignature,
) -> bool {
    let total = total_chains(w);
    if pubkey.len() != total {
        return false;
    }
    if sig.chain_values.len() != total {
        return false;
    }

    let msg_elements = decompose_message(w, message);
    let checksum_elements = checksum(w, msg_elements.span());

    // Verify message chains
    let mut valid = true;
    let mut i: u32 = 0;
    while i < msg_elements.len() {
        let m_i = *msg_elements.at(i);
        let remaining = (w - 1) - m_i;
        let reconstructed = chain_hash::<T>(*sig.chain_values.at(i), remaining);
        if reconstructed != *pubkey.at(i) {
            valid = false;
        };
        i += 1;
    };

    // Verify checksum chains
    let msg_len_val = msg_elements.len();
    let mut j: u32 = 0;
    while j < checksum_elements.len() {
        let c_j = *checksum_elements.at(j);
        let remaining = (w - 1) - c_j;
        let reconstructed = chain_hash::<T>(*sig.chain_values.at(msg_len_val + j), remaining);
        if reconstructed != *pubkey.at(msg_len_val + j) {
            valid = false;
        };
        j += 1;
    };

    valid
}

// --- Helper functions ---

/// Integer log2 for powers of 2 (used for Winternitz parameter).
/// Returns the exponent: log2_int(16) = 4, log2_int(4) = 2, etc.
fn log2_int(n: u32) -> u32 {
    if n <= 1 {
        return 0;
    }
    let mut result: u32 = 0;
    let mut val = n;
    while val > 1 {
        val /= 2;
        result += 1;
    };
    result
}

/// Floor of log2 for arbitrary positive integers.
/// int_log2_floor(1) = 0, int_log2_floor(15) = 3, int_log2_floor(16) = 4.
fn int_log2_floor(n: u32) -> u32 {
    if n <= 1 {
        return 0;
    }
    let mut result: u32 = 0;
    let mut val = n;
    while val > 1 {
        val /= 2;
        result += 1;
    };
    result
}

/// Compute 2^n as u256.
fn pow2_u256(n: u32) -> u256 {
    if n == 0 {
        return 1;
    }
    if n < 128 {
        let low: u128 = pow2_u128(n);
        u256 { low: low, high: 0 }
    } else {
        let high: u128 = pow2_u128(n - 128);
        u256 { low: 0, high: high }
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
    };
    result
}

/// Shift right a u256 by n bits.
fn shr_u256(val: u256, n: u32) -> u256 {
    if n == 0 {
        return val;
    }
    if n >= 256 {
        return 0;
    }
    // Use division by 2^n
    let divisor = pow2_u256(n);
    val / divisor
}
