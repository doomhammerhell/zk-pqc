//! Test Vector Generator for Cross-Language Cryptographic Consistency.
//!
//! Generates JSON test vectors for all cryptographic primitives in the ZK-PQC framework.
//! Vectors are output to `spec/test_vectors/` and consumed by Cairo tests.

use lambdaworks_math::traits::ByteConversion;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::sponge::PoseidonSponge;
use zk_pqc_hash_layer::traits::{HashFunction, HybridHashWrapper, PoseidonHash};
use zk_pqc_merkle_layer::MerkleTree;
use zk_pqc_signature_layer::wots::{WotsParams, WotsPlus};

// Lamport OTS is reference-only (not part of production signature_layer API).
// We inline the minimal types needed for test vector generation.
mod lamport_ref {
    use zk_pqc_hash_layer::constants::FELT;
    use zk_pqc_hash_layer::traits::HashFunction;

    pub const LAMPORT_BITS: usize = 256;

    #[derive(Debug, Clone)]
    pub struct LamportKeyPair {
        pub secret: [[FELT; LAMPORT_BITS]; 2],
        pub public: [[FELT; LAMPORT_BITS]; 2],
    }

    #[derive(Debug, Clone)]
    pub struct LamportSignature {
        pub revealed: [FELT; LAMPORT_BITS],
    }

    pub struct LamportOTS;

    impl LamportOTS {
        pub fn keygen<H: HashFunction<Digest = FELT>>(hasher: &H, seed: &[FELT]) -> LamportKeyPair {
            let mut secret = [[FELT::from(0); LAMPORT_BITS]; 2];
            let mut public = [[FELT::from(0); LAMPORT_BITS]; 2];
            for b in 0..2u64 {
                for (i, secret_i) in secret[b as usize].iter_mut().enumerate().take(LAMPORT_BITS) {
                    let mut input = seed.to_vec();
                    input.push(FELT::from(b));
                    input.push(FELT::from(i as u64));
                    *secret_i = hasher.hash(&input);
                }
            }
            for b in 0..2usize {
                for i in 0..LAMPORT_BITS {
                    public[b][i] = hasher.hash(&[secret[b][i]]);
                }
            }
            LamportKeyPair { secret, public }
        }

        pub fn sign(key: &LamportKeyPair, message_bits: &[bool]) -> LamportSignature {
            assert_eq!(message_bits.len(), LAMPORT_BITS);
            let mut revealed = [FELT::from(0); LAMPORT_BITS];
            for (i, &msg_bit) in message_bits.iter().enumerate() {
                let b = if msg_bit { 1 } else { 0 };
                revealed[i] = key.secret[b][i];
            }
            LamportSignature { revealed }
        }

        pub fn verify<H: HashFunction<Digest = FELT>>(
            hasher: &H,
            pubkey: &[[FELT; LAMPORT_BITS]; 2],
            message_bits: &[bool],
            sig: &LamportSignature,
        ) -> bool {
            if message_bits.len() != LAMPORT_BITS {
                return false;
            }
            for i in 0..LAMPORT_BITS {
                let b = if message_bits[i] { 1 } else { 0 };
                if hasher.hash(&[sig.revealed[i]]) != pubkey[b][i] {
                    return false;
                }
            }
            true
        }
    }

    pub fn felt_to_bits(felt: &FELT) -> [bool; LAMPORT_BITS] {
        #[allow(unused_imports)]
        use lambdaworks_math::traits::ByteConversion;
        let bytes = felt.to_bytes_be();
        let mut bits = [false; LAMPORT_BITS];
        for (byte_idx, byte) in bytes.iter().enumerate() {
            for bit_idx in 0..8 {
                bits[byte_idx * 8 + bit_idx] = (byte >> (7 - bit_idx)) & 1 == 1;
            }
        }
        bits
    }
}

use lamport_ref::{felt_to_bits, LamportOTS};

/// Hex-encode a FELT value with 0x prefix.
fn felt_to_hex(f: &FELT) -> String {
    let bytes = f.to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

/// Parse a hex string (with 0x prefix) back to FELT.
#[allow(dead_code)]
fn hex_to_felt(s: &str) -> FELT {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).expect("invalid hex");
    let mut padded = [0u8; 32];
    let start = 32 - bytes.len();
    padded[start..].copy_from_slice(&bytes);
    FELT::from_bytes_be(&padded).unwrap()
}

// ── JSON data models ──

#[derive(Serialize, Deserialize)]
struct TestVectorSuite {
    suite: String,
    vectors: Vec<TestVector>,
}

#[derive(Serialize, Deserialize)]
struct TestVector {
    id: String,
    input: Vec<String>,
    expected_output: String,
    domain_separation: String,
}

#[derive(Serialize, Deserialize)]
struct MerkleTestVectorSuite {
    suite: String,
    vectors: Vec<MerkleTestVector>,
}

#[derive(Serialize, Deserialize)]
struct MerkleTestVector {
    id: String,
    leaves: Vec<String>,
    expected_root: String,
    /// Proof for leaf at `proof_index`.
    proof_index: usize,
    proof_siblings: Vec<String>,
    proof_path_bits: Vec<bool>,
}

#[derive(Serialize, Deserialize)]
struct LamportTestVectorSuite {
    suite: String,
    vectors: Vec<LamportTestVector>,
}

#[derive(Serialize, Deserialize)]
struct LamportTestVector {
    id: String,
    seed: Vec<String>,
    message_felt: String,
    message_bits: Vec<u8>,
    /// First 8 public key entries for each bit value (for compact verification).
    public_0_prefix: Vec<String>,
    public_1_prefix: Vec<String>,
    signature_prefix: Vec<String>,
    verify_result: bool,
}

#[derive(Serialize, Deserialize)]
struct WotsTestVectorSuite {
    suite: String,
    vectors: Vec<WotsTestVector>,
}

#[derive(Serialize, Deserialize)]
struct WotsTestVector {
    id: String,
    w: usize,
    seed: Vec<String>,
    message: String,
    /// First 4 public chain entries (for compact verification).
    public_chains_prefix: Vec<String>,
    /// First 4 signature chain values.
    sig_chains_prefix: Vec<String>,
    verify_result: bool,
}

// ── Generator functions ──

fn generate_poseidon_vectors() -> TestVectorSuite {
    let hasher = PoseidonHash;
    let mut vectors = Vec::new();

    // Vector 1: Simple inputs [1, 2, 3]
    let input1: Vec<FELT> = vec![FELT::from(1u64), FELT::from(2u64), FELT::from(3u64)];
    let out1 = hasher.hash(&input1);
    vectors.push(TestVector {
        id: "poseidon_001".into(),
        input: input1.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out1),
        domain_separation: felt_to_hex(&FELT::from(0u64)),
    });

    // Vector 2: Single element [42]
    let input2: Vec<FELT> = vec![FELT::from(42u64)];
    let out2 = hasher.hash(&input2);
    vectors.push(TestVector {
        id: "poseidon_002".into(),
        input: input2.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out2),
        domain_separation: felt_to_hex(&FELT::from(0u64)),
    });

    // Vector 3: With domain separation ds=1, input=[1, 2]
    let input3: Vec<FELT> = vec![FELT::from(1u64), FELT::from(2u64)];
    let ds3 = FELT::from(1u64);
    let out3 = hasher.hash_with_domain_separation(ds3, &input3);
    vectors.push(TestVector {
        id: "poseidon_003".into(),
        input: input3.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out3),
        domain_separation: felt_to_hex(&ds3),
    });

    // Vector 4: Five elements [10, 20, 30, 40, 50]
    let input4: Vec<FELT> = (1..=5).map(|i| FELT::from(i * 10u64)).collect();
    let out4 = hasher.hash(&input4);
    vectors.push(TestVector {
        id: "poseidon_004".into(),
        input: input4.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out4),
        domain_separation: felt_to_hex(&FELT::from(0u64)),
    });

    TestVectorSuite {
        suite: "poseidon_hash".into(),
        vectors,
    }
}

fn generate_sponge_vectors() -> TestVectorSuite {
    let mut vectors = Vec::new();

    // Vector 1: Sponge hash of [1, 2, 3, 4, 5]
    let input1: Vec<FELT> = (1..=5).map(|i| FELT::from(i as u64)).collect();
    let out1 = PoseidonSponge::hash(&input1);
    vectors.push(TestVector {
        id: "sponge_001".into(),
        input: input1.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out1),
        domain_separation: felt_to_hex(&FELT::from(0u64)),
    });

    // Vector 2: Sponge hash with DS=7, input=[100, 200]
    let input2: Vec<FELT> = vec![FELT::from(100u64), FELT::from(200u64)];
    let ds2 = FELT::from(7u64);
    let out2 = PoseidonSponge::hash_with_ds(ds2, &input2);
    vectors.push(TestVector {
        id: "sponge_002".into(),
        input: input2.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out2),
        domain_separation: felt_to_hex(&ds2),
    });

    // Vector 3: Single element [999]
    let input3: Vec<FELT> = vec![FELT::from(999u64)];
    let out3 = PoseidonSponge::hash(&input3);
    vectors.push(TestVector {
        id: "sponge_003".into(),
        input: input3.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out3),
        domain_separation: felt_to_hex(&FELT::from(0u64)),
    });

    TestVectorSuite {
        suite: "sponge_hash".into(),
        vectors,
    }
}

fn generate_hybrid_vectors() -> TestVectorSuite {
    let hasher = HybridHashWrapper;
    let mut vectors = Vec::new();

    // Vector 1: [1, 2]
    let input1: Vec<FELT> = vec![FELT::from(1u64), FELT::from(2u64)];
    let out1 = hasher.hash(&input1);
    vectors.push(TestVector {
        id: "hybrid_001".into(),
        input: input1.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out1),
        domain_separation: felt_to_hex(&FELT::from(0u64)),
    });

    // Vector 2: [10, 20, 30]
    let input2: Vec<FELT> = vec![FELT::from(10u64), FELT::from(20u64), FELT::from(30u64)];
    let out2 = hasher.hash(&input2);
    vectors.push(TestVector {
        id: "hybrid_002".into(),
        input: input2.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out2),
        domain_separation: felt_to_hex(&FELT::from(0u64)),
    });

    // Vector 3: With domain separation ds=5, input=[42]
    let input3: Vec<FELT> = vec![FELT::from(42u64)];
    let ds3 = FELT::from(5u64);
    let out3 = hasher.hash_with_domain_separation(ds3, &input3);
    vectors.push(TestVector {
        id: "hybrid_003".into(),
        input: input3.iter().map(felt_to_hex).collect(),
        expected_output: felt_to_hex(&out3),
        domain_separation: felt_to_hex(&ds3),
    });

    TestVectorSuite {
        suite: "hybrid_hash".into(),
        vectors,
    }
}

fn generate_merkle_vectors() -> MerkleTestVectorSuite {
    let mut vectors = Vec::new();

    // Vector 1: Two leaves [1, 2]
    {
        let leaves: Vec<FELT> = vec![FELT::from(1u64), FELT::from(2u64)];
        let tree = MerkleTree::new(PoseidonHash, leaves.clone()).unwrap();
        let root = tree.root();
        let proof = tree.prove(0).unwrap();
        vectors.push(MerkleTestVector {
            id: "merkle_001".into(),
            leaves: leaves.iter().map(felt_to_hex).collect(),
            expected_root: felt_to_hex(&root),
            proof_index: 0,
            proof_siblings: proof.siblings.iter().map(felt_to_hex).collect(),
            proof_path_bits: proof.path_bits.clone(),
        });
    }

    // Vector 2: Four leaves [10, 20, 30, 40], proof for index 2
    {
        let leaves: Vec<FELT> = vec![
            FELT::from(10u64),
            FELT::from(20u64),
            FELT::from(30u64),
            FELT::from(40u64),
        ];
        let tree = MerkleTree::new(PoseidonHash, leaves.clone()).unwrap();
        let root = tree.root();
        let proof = tree.prove(2).unwrap();
        vectors.push(MerkleTestVector {
            id: "merkle_002".into(),
            leaves: leaves.iter().map(felt_to_hex).collect(),
            expected_root: felt_to_hex(&root),
            proof_index: 2,
            proof_siblings: proof.siblings.iter().map(felt_to_hex).collect(),
            proof_path_bits: proof.path_bits.clone(),
        });
    }

    // Vector 3: Three leaves [1, 2, 3] (padded to 4)
    {
        let leaves: Vec<FELT> = vec![FELT::from(1u64), FELT::from(2u64), FELT::from(3u64)];
        let tree = MerkleTree::new(PoseidonHash, leaves.clone()).unwrap();
        let root = tree.root();
        let proof = tree.prove(1).unwrap();
        vectors.push(MerkleTestVector {
            id: "merkle_003".into(),
            leaves: leaves.iter().map(felt_to_hex).collect(),
            expected_root: felt_to_hex(&root),
            proof_index: 1,
            proof_siblings: proof.siblings.iter().map(felt_to_hex).collect(),
            proof_path_bits: proof.path_bits.clone(),
        });
    }

    MerkleTestVectorSuite {
        suite: "binary_merkle".into(),
        vectors,
    }
}

fn generate_lamport_vectors() -> LamportTestVectorSuite {
    let hasher = PoseidonHash;
    let mut vectors = Vec::new();

    // Vector 1: seed=[42], message=999
    {
        let seed = vec![FELT::from(42u64)];
        let kp = LamportOTS::keygen(&hasher, &seed);
        let msg_felt = FELT::from(999u64);
        let msg_bits = felt_to_bits(&msg_felt);
        let sig = LamportOTS::sign(&kp, &msg_bits);
        let valid = LamportOTS::verify(&hasher, &kp.public, &msg_bits, &sig);

        // Convert bool bits to u8 for JSON
        let bits_u8: Vec<u8> = msg_bits.iter().map(|&b| if b { 1 } else { 0 }).collect();

        vectors.push(LamportTestVector {
            id: "lamport_001".into(),
            seed: seed.iter().map(felt_to_hex).collect(),
            message_felt: felt_to_hex(&msg_felt),
            message_bits: bits_u8,
            public_0_prefix: kp.public[0][..8].iter().map(felt_to_hex).collect(),
            public_1_prefix: kp.public[1][..8].iter().map(felt_to_hex).collect(),
            signature_prefix: sig.revealed[..8].iter().map(felt_to_hex).collect(),
            verify_result: valid,
        });
    }

    // Vector 2: seed=[123], message=1
    {
        let seed = vec![FELT::from(123u64)];
        let kp = LamportOTS::keygen(&hasher, &seed);
        let msg_felt = FELT::from(1u64);
        let msg_bits = felt_to_bits(&msg_felt);
        let sig = LamportOTS::sign(&kp, &msg_bits);
        let valid = LamportOTS::verify(&hasher, &kp.public, &msg_bits, &sig);

        let bits_u8: Vec<u8> = msg_bits.iter().map(|&b| if b { 1 } else { 0 }).collect();

        vectors.push(LamportTestVector {
            id: "lamport_002".into(),
            seed: seed.iter().map(felt_to_hex).collect(),
            message_felt: felt_to_hex(&msg_felt),
            message_bits: bits_u8,
            public_0_prefix: kp.public[0][..8].iter().map(felt_to_hex).collect(),
            public_1_prefix: kp.public[1][..8].iter().map(felt_to_hex).collect(),
            signature_prefix: sig.revealed[..8].iter().map(felt_to_hex).collect(),
            verify_result: valid,
        });
    }

    LamportTestVectorSuite {
        suite: "lamport_ots".into(),
        vectors,
    }
}

fn generate_wots_vectors() -> WotsTestVectorSuite {
    let hasher = PoseidonHash;
    let params = WotsParams::default(); // w=16, Poseidon
    let mut vectors = Vec::new();

    // Vector 1: seed=[42], message=999
    {
        let seed = vec![FELT::from(42u64)];
        let kp = WotsPlus::keygen(&hasher, &params, &seed);
        let message = vec![FELT::from(999u64)];
        let sig = WotsPlus::sign(&hasher, &params, &kp, &message).unwrap();
        let valid = WotsPlus::verify(&hasher, &params, &kp.public_chains, &message, &sig);

        vectors.push(WotsTestVector {
            id: "wots_001".into(),
            w: params.w,
            seed: seed.iter().map(felt_to_hex).collect(),
            message: felt_to_hex(&message[0]),
            public_chains_prefix: kp.public_chains[..4].iter().map(felt_to_hex).collect(),
            sig_chains_prefix: sig.chain_values[..4].iter().map(felt_to_hex).collect(),
            verify_result: valid,
        });
    }

    // Vector 2: seed=[7], message=12345
    {
        let seed = vec![FELT::from(7u64)];
        let kp = WotsPlus::keygen(&hasher, &params, &seed);
        let message = vec![FELT::from(12345u64)];
        let sig = WotsPlus::sign(&hasher, &params, &kp, &message).unwrap();
        let valid = WotsPlus::verify(&hasher, &params, &kp.public_chains, &message, &sig);

        vectors.push(WotsTestVector {
            id: "wots_002".into(),
            w: params.w,
            seed: seed.iter().map(felt_to_hex).collect(),
            message: felt_to_hex(&message[0]),
            public_chains_prefix: kp.public_chains[..4].iter().map(felt_to_hex).collect(),
            sig_chains_prefix: sig.chain_values[..4].iter().map(felt_to_hex).collect(),
            verify_result: valid,
        });
    }

    WotsTestVectorSuite {
        suite: "wots_plus".into(),
        vectors,
    }
}

fn main() {
    // Determine output directory (project root / spec / test_vectors)
    // Navigate up from src/rust/ to project root
    let out_dir = Path::new("../../spec/test_vectors");
    fs::create_dir_all(out_dir).expect("Failed to create spec/test_vectors directory");

    // Generate and write all test vector suites
    let poseidon = generate_poseidon_vectors();
    let poseidon_json = serde_json::to_string_pretty(&poseidon).unwrap();
    fs::write(out_dir.join("poseidon_hash.json"), &poseidon_json).unwrap();
    println!(
        "✓ Generated {} Poseidon hash vectors",
        poseidon.vectors.len()
    );

    let sponge = generate_sponge_vectors();
    let sponge_json = serde_json::to_string_pretty(&sponge).unwrap();
    fs::write(out_dir.join("sponge_hash.json"), &sponge_json).unwrap();
    println!("✓ Generated {} Sponge hash vectors", sponge.vectors.len());

    let hybrid = generate_hybrid_vectors();
    let hybrid_json = serde_json::to_string_pretty(&hybrid).unwrap();
    fs::write(out_dir.join("hybrid_hash.json"), &hybrid_json).unwrap();
    println!("✓ Generated {} Hybrid hash vectors", hybrid.vectors.len());

    let merkle = generate_merkle_vectors();
    let merkle_json = serde_json::to_string_pretty(&merkle).unwrap();
    fs::write(out_dir.join("binary_merkle.json"), &merkle_json).unwrap();
    println!("✓ Generated {} Binary Merkle vectors", merkle.vectors.len());

    let lamport = generate_lamport_vectors();
    let lamport_json = serde_json::to_string_pretty(&lamport).unwrap();
    fs::write(out_dir.join("lamport_ots.json"), &lamport_json).unwrap();
    println!("✓ Generated {} Lamport OTS vectors", lamport.vectors.len());

    let wots = generate_wots_vectors();
    let wots_json = serde_json::to_string_pretty(&wots).unwrap();
    fs::write(out_dir.join("wots_plus.json"), &wots_json).unwrap();
    println!("✓ Generated {} WOTS+ vectors", wots.vectors.len());

    println!("\nAll test vectors written to {}", out_dir.display());
}
