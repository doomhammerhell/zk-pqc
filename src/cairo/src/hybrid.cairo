use zk_pqc_cairo::sponge::hash as poseidon_hash;
use core::sha256::compute_sha256_byte_array;

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
    };
    
    let sha_res = compute_sha256_byte_array(@ba);
    let sha_span = sha_res.span();
    
    // 3. Truncate/Convert SHA-256 to felt252
    // sha_res is [u32; 8]. We take the last 4 words (128 bits) to fit easily in felt252.
    // Or combine them into a larger value.
    let sha_felt: felt252 = (*sha_span.at(7)).into() + 
                           (*sha_span.at(6)).into() * 0x100000000 + 
                           (*sha_span.at(5)).into() * 0x10000000000000000 + 
                           (*sha_span.at(4)).into() * 0x1000000000000000000000000;
    
    // 4. Combine
    p_hash + sha_felt
}
