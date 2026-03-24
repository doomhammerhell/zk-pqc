use sha2::{Sha256, Digest};
use lambdaworks_math::traits::ByteConversion;
use crate::constants::FELT;
use crate::sponge::PoseidonSponge;

pub struct HybridHash;

impl HybridHash {
    pub fn hash(input: &[FELT]) -> FELT {
        // 1. Poseidon Sponge Hash
        let poseidon_hash = PoseidonSponge::hash(input);
        
        // 2. SHA-256 Hash of the same input
        // Since input is Vec<FELT>, we serialize it to bytes
        let mut hasher = Sha256::new();
        for val in input {
            hasher.update(val.to_bytes_be());
        }
        let sha_result = hasher.finalize();
        
        // 3. Convert SHA-256 (32 bytes) to FELT (truncated to ~251 bits)
        // To ensure it fits in the field, we zero the first byte (MSB)
        let mut padded_sha = [0u8; 32];
        padded_sha[1..32].copy_from_slice(&sha_result[1..32]);
        
        let sha_felt = FELT::from_bytes_be(&padded_sha).unwrap();
        
        // 4. Combine via XOR (or Addition in the field)
        // Paper specified \oplus, which we implement as Field Addition for ZK-friendliness
        // or bitwise if needed. For Cairo, addition is most efficient.
        poseidon_hash + sha_felt
    }
}
