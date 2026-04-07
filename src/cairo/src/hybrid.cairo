use core::sha256::compute_sha256_byte_array;
use zk_pqc_cairo::sponge::hash as poseidon_hash;

pub fn hybrid_hash(input: Span<felt252>) -> felt252 {
    // 1. Poseidon Hash
    let p_hash = poseidon_hash(input);

    // 2. SHA-256 Hash
    // Convert felt252 span to ByteArray for sha256
    let mut ba = Default::default();
    let mut i: usize = 0;
    while i < input.len() {
        let val: u256 = (*input.at(i)).into();
        // Pack into byte array (big endian felt)
        // This is a simplified serialization for the hybrid anchor
        ba.append_word(val.high.into(), 16);
        ba.append_word(val.low.into(), 16);
        i += 1;
    }

    let sha_res = compute_sha256_byte_array(@ba);
    let sha_span = sha_res.span();

    // 3. Truncate/Convert SHA-256 to felt252
    // sha_res is [u32; 8] in big-endian order. We reconstruct the full 256-bit value
    // then zero the MSB (top byte of word 0) to fit in the Stark252 field.
    // This matches the Rust truncation: padded[0] = 0, padded[1..32] = sha[1..32].
    let sha_felt: felt252 = sha256_words_to_felt(sha_span);

    // 4. Combine
    p_hash + sha_felt
}

/// Convert SHA-256 output ([u32; 8] big-endian) to felt252, zeroing the MSB
/// to fit in the Stark252 field. Matches Rust truncation: bytes[0]=0, bytes[1..32] kept.
pub fn sha256_words_to_felt(sha_span: Span<u32>) -> felt252 {
    // Word 0 is the most significant 32 bits. Zero its top byte (bits 31..24)
    // to match Rust's approach of zeroing byte 0 of the 32-byte BE output.
    // Mask: 0x00FFFFFF keeps the lower 3 bytes of word 0.
    let w0_masked: felt252 = (*sha_span.at(0) & 0x00FFFFFF).into();
    let w1: felt252 = (*sha_span.at(1)).into();
    let w2: felt252 = (*sha_span.at(2)).into();
    let w3: felt252 = (*sha_span.at(3)).into();
    let w4: felt252 = (*sha_span.at(4)).into();
    let w5: felt252 = (*sha_span.at(5)).into();
    let w6: felt252 = (*sha_span.at(6)).into();
    let w7: felt252 = (*sha_span.at(7)).into();

    // Reconstruct: each word is 32 bits, so shift by multiples of 32
    // w0 is at position [224..255] (but MSB zeroed), w7 is at position [0..31]
    w0_masked * 0x100000000000000000000000000000000000000000000000000000000 // 2^224
        + w1 * 0x1000000000000000000000000000000000000000000000000 // 2^192
        + w2 * 0x10000000000000000000000000000000000000000 // 2^160
        + w3 * 0x100000000000000000000000000000000 // 2^128
        + w4 * 0x1000000000000000000000000 // 2^96
        + w5 * 0x10000000000000000 // 2^64
        + w6 * 0x100000000 // 2^32
        + w7
}
