//! Test Vector Generator for Phase 2 Components.
//!
//! Generates JSON test vectors for:
//! - HexTree construction/proof
//! - XMSS sign/verify
//! - WOTS+ with Hybrid-Hash
//! - Domain separation
//!
//! Output: spec/test_vectors/

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::{HashFunction, HybridHashWrapper, PoseidonHash};
use zk_pqc_merkle_layer::hextree::HexTree;
use zk_pqc_signature_layer::domain::canonical_message_hash;
use zk_pqc_signature_layer::wots::{HashMode, WotsParams, WotsPlus};
use zk_pqc_signature_layer::xmss::XmssTree;

/// Test vector for HexTree.
#[derive(Serialize, Deserialize, Debug)]
struct HexTreeVector {
    id: String,
    leaves: Vec<String>,
    expected_root: String,
    proofs: Vec<HexProofVector>,
}

/// Proof vector for HexTree.
#[derive(Serialize, Deserialize, Debug)]
struct HexProofVector {
    leaf_index: usize,
    leaf_value: String,
    siblings: Vec<Vec<String>>,
    path_indices: Vec<u8>,
}

/// Test vector for XMSS.
#[derive(Serialize, Deserialize, Debug)]
struct XmssVector {
    id: String,
    tree_height: usize,
    seed: Vec<String>,
    message: String,
    signature_index: u64,
    expected_root: String,
    signature: XmssSignatureVector,
}

/// XMSS signature vector.
#[derive(Serialize, Deserialize, Debug)]
struct XmssSignatureVector {
    index: u64,
    wots_sig: WotsSignatureVector,
    wots_pubkey_commitment: String,
    proof_siblings: Vec<Vec<String>>,
    proof_path_indices: Vec<u8>,
}

/// WOTS+ signature vector.
#[derive(Serialize, Deserialize, Debug)]
struct WotsSignatureVector {
    chain_values: Vec<String>,
}

/// Test vector for WOTS+ with Hybrid-Hash.
#[derive(Serialize, Deserialize, Debug)]
struct WotsHybridVector {
    id: String,
    hash_mode: String,
    message: String,
    seed: Vec<String>,
    public_chains: Vec<String>,
    signature: WotsSignatureVector,
}

/// Test vector for domain separation.
#[derive(Serialize, Deserialize, Debug)]
struct DomainSeparationVector {
    id: String,
    domain: String,
    chain_id: String,
    contract_addr: String,
    nonce: u64,
    calldata_hash: String,
    expected_canonical_hash: String,
}

fn felt_to_hex(f: &FELT) -> String {
    let bytes = f.to_bytes_be();
    format!("0x{}", hex::encode(bytes))
}

fn generate_hextree_vectors() -> Vec<HexTreeVector> {
    let hasher = PoseidonHash;
    let mut vectors = Vec::new();

    // Vector 1: Simple tree with 4 leaves
    let leaves: Vec<FELT> = (1u64..=4).map(FELT::from).collect();
    let tree = HexTree::new(hasher, leaves.clone()).unwrap();
    let root = tree.root();

    let mut proofs = Vec::new();
    for i in 0..leaves.len() {
        let proof = tree.prove(i).unwrap();
        proofs.push(HexProofVector {
            leaf_index: i,
            leaf_value: felt_to_hex(&leaves[i]),
            siblings: proof
                .siblings
                .iter()
                .map(|s| s.iter().map(felt_to_hex).collect())
                .collect(),
            path_indices: proof.path_indices.clone(),
        });
    }

    vectors.push(HexTreeVector {
        id: "hextree_4_leaves".to_string(),
        leaves: leaves.iter().map(felt_to_hex).collect(),
        expected_root: felt_to_hex(&root),
        proofs,
    });

    // Vector 2: Tree with 16 leaves (single level)
    let leaves16: Vec<FELT> = (1u64..=16).map(FELT::from).collect();
    let tree16 = HexTree::new(hasher, leaves16.clone()).unwrap();
    let root16 = tree16.root();

    let mut proofs16 = Vec::new();
    for i in [0, 5, 10, 15] {
        let proof = tree16.prove(i).unwrap();
        proofs16.push(HexProofVector {
            leaf_index: i,
            leaf_value: felt_to_hex(&leaves16[i]),
            siblings: proof
                .siblings
                .iter()
                .map(|s| s.iter().map(felt_to_hex).collect())
                .collect(),
            path_indices: proof.path_indices.clone(),
        });
    }

    vectors.push(HexTreeVector {
        id: "hextree_16_leaves".to_string(),
        leaves: leaves16.iter().map(felt_to_hex).collect(),
        expected_root: felt_to_hex(&root16),
        proofs: proofs16,
    });

    vectors
}

fn generate_xmss_vectors() -> Vec<XmssVector> {
    let hasher = PoseidonHash;
    let params = WotsParams::new(16, HashMode::PoseidonOnly);
    let mut vectors = Vec::new();

    // Vector 1: Height 1 tree (16 signatures)
    let seed: Vec<FELT> = vec![FELT::from(12345u64)];
    let mut xmss_tree = XmssTree::new(&hasher, &params, &seed, 1).unwrap();

    let message = FELT::from(98765u64);
    let sig_index = 5u64;

    let signature = xmss_tree.sign(sig_index, &message).unwrap();
    let root = xmss_tree.root();

    vectors.push(XmssVector {
        id: "xmss_height_1_index_5".to_string(),
        tree_height: 1,
        seed: seed.iter().map(felt_to_hex).collect(),
        message: felt_to_hex(&message),
        signature_index: sig_index,
        expected_root: felt_to_hex(&root),
        signature: XmssSignatureVector {
            index: signature.index,
            wots_sig: WotsSignatureVector {
                chain_values: signature.wots_sig.chain_values.iter().map(felt_to_hex).collect(),
            },
            wots_pubkey_commitment: felt_to_hex(&signature.wots_pubkey_commitment),
            proof_siblings: signature
                .proof
                .siblings
                .iter()
                .map(|s| s.iter().map(felt_to_hex).collect())
                .collect(),
            proof_path_indices: signature.proof.path_indices.clone(),
        },
    });

    vectors
}

fn generate_wots_hybrid_vectors() -> Vec<WotsHybridVector> {
    let mut vectors = Vec::new();

    // Vector 1: Poseidon-only mode
    let hasher = PoseidonHash;
    let params = WotsParams::new(16, HashMode::PoseidonOnly);
    let seed = vec![FELT::from(12345u64)];
    let message = FELT::from(98765u64);

    let kp = WotsPlus::keygen(&hasher, &params, &seed);
    let sig = WotsPlus::sign(&hasher, &params, &kp, &message);

    vectors.push(WotsHybridVector {
        id: "wots_poseidon_only".to_string(),
        hash_mode: "PoseidonOnly".to_string(),
        message: felt_to_hex(&message),
        seed: seed.iter().map(felt_to_hex).collect(),
        public_chains: kp.public_chains.iter().map(felt_to_hex).collect(),
        signature: WotsSignatureVector {
            chain_values: sig.chain_values.iter().map(felt_to_hex).collect(),
        },
    });

    // Vector 2: Hybrid-Hash mode
    let hybrid_hasher = HybridHashWrapper::new(hasher);
    let hybrid_params = WotsParams::new(16, HashMode::Hybrid);
    let hybrid_seed = vec![FELT::from(54321u64)];
    let hybrid_message = FELT::from(56789u64);

    let hybrid_kp = WotsPlus::keygen(&hybrid_hasher, &hybrid_params, &hybrid_seed);
    let hybrid_sig = WotsPlus::sign(&hybrid_hasher, &hybrid_params, &hybrid_kp, &hybrid_message);

    vectors.push(WotsHybridVector {
        id: "wots_hybrid".to_string(),
        hash_mode: "Hybrid".to_string(),
        message: felt_to_hex(&hybrid_message),
        seed: hybrid_seed.iter().map(felt_to_hex).collect(),
        public_chains: hybrid_kp.public_chains.iter().map(felt_to_hex).collect(),
        signature: WotsSignatureVector {
            chain_values: hybrid_sig.chain_values.iter().map(felt_to_hex).collect(),
        },
    });

    vectors
}

fn generate_domain_separation_vectors() -> Vec<DomainSeparationVector> {
    let hasher = PoseidonHash;
    let mut vectors = Vec::new();

    // Vector 1: Basic domain separation
    let calldata_hash = FELT::from(12345u64);
    let canonical_hash = canonical_message_hash(
        &hasher,
        "zk-pqc-vault",
        "SN_MAIN",
        "0x1234567890abcdef",
        0,
        &calldata_hash,
    );

    vectors.push(DomainSeparationVector {
        id: "domain_basic".to_string(),
        domain: "zk-pqc-vault".to_string(),
        chain_id: "SN_MAIN".to_string(),
        contract_addr: "0x1234567890abcdef".to_string(),
        nonce: 0,
        calldata_hash: felt_to_hex(&calldata_hash),
        expected_canonical_hash: felt_to_hex(&canonical_hash),
    });

    // Vector 2: Different chain
    let calldata_hash2 = FELT::from(12345u64);
    let canonical_hash2 = canonical_message_hash(
        &hasher,
        "zk-pqc-vault",
        "SN_GOERLI",
        "0x1234567890abcdef",
        0,
        &calldata_hash2,
    );

    vectors.push(DomainSeparationVector {
        id: "domain_different_chain".to_string(),
        domain: "zk-pqc-vault".to_string(),
        chain_id: "SN_GOERLI".to_string(),
        contract_addr: "0x1234567890abcdef".to_string(),
        nonce: 0,
        calldata_hash: felt_to_hex(&calldata_hash2),
        expected_canonical_hash: felt_to_hex(&canonical_hash2),
    });

    // Vector 3: Different nonce
    let calldata_hash3 = FELT::from(12345u64);
    let canonical_hash3 = canonical_message_hash(
        &hasher,
        "zk-pqc-vault",
        "SN_MAIN",
        "0x1234567890abcdef",
        1,
        &calldata_hash3,
    );

    vectors.push(DomainSeparationVector {
        id: "domain_different_nonce".to_string(),
        domain: "zk-pqc-vault".to_string(),
        chain_id: "SN_MAIN".to_string(),
        contract_addr: "0x1234567890abcdef".to_string(),
        nonce: 1,
        calldata_hash: felt_to_hex(&calldata_hash3),
        expected_canonical_hash: felt_to_hex(&canonical_hash3),
    });

    vectors
}

fn main() {
    println!("Generating Phase 2 test vectors...");

    let output_dir = Path::new("../../spec/test_vectors");
    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    // Generate HexTree vectors
    let hextree_vectors = generate_hextree_vectors();
    let hextree_json = serde_json::to_string_pretty(&hextree_vectors).expect("Failed to serialize HexTree vectors");
    fs::write(output_dir.join("hextree.json"), hextree_json).expect("Failed to write HexTree vectors");
    println!("Generated {} HexTree vectors", hextree_vectors.len());

    // Generate XMSS vectors
    let xmss_vectors = generate_xmss_vectors();
    let xmss_json = serde_json::to_string_pretty(&xmss_vectors).expect("Failed to serialize XMSS vectors");
    fs::write(output_dir.join("xmss.json"), xmss_json).expect("Failed to write XMSS vectors");
    println!("Generated {} XMSS vectors", xmss_vectors.len());

    // Generate WOTS+ Hybrid vectors
    let wots_hybrid_vectors = generate_wots_hybrid_vectors();
    let wots_hybrid_json = serde_json::to_string_pretty(&wots_hybrid_vectors)
        .expect("Failed to serialize WOTS Hybrid vectors");
    fs::write(output_dir.join("wots_hybrid.json"), wots_hybrid_json)
        .expect("Failed to write WOTS Hybrid vectors");
    println!("Generated {} WOTS+ Hybrid vectors", wots_hybrid_vectors.len());

    // Generate Domain Separation vectors
    let domain_vectors = generate_domain_separation_vectors();
    let domain_json = serde_json::to_string_pretty(&domain_vectors).expect("Failed to serialize Domain vectors");
    fs::write(output_dir.join("domain_separation.json"), domain_json).expect("Failed to write Domain vectors");
    println!("Generated {} Domain Separation vectors", domain_vectors.len());

    println!("\nPhase 2 test vectors generated successfully!");
    println!("Output directory: {}", output_dir.canonicalize().unwrap().display());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hextree_vector_generation() {
        let vectors = generate_hextree_vectors();
        assert!(!vectors.is_empty());

        for v in &vectors {
            assert!(!v.leaves.is_empty());
            assert!(!v.proofs.is_empty());
        }
    }

    #[test]
    fn test_xmss_vector_generation() {
        let vectors = generate_xmss_vectors();
        assert!(!vectors.is_empty());

        for v in &vectors {
            assert!(!v.signature.wots_sig.chain_values.is_empty());
        }
    }

    #[test]
    fn test_domain_vector_generation() {
        let vectors = generate_domain_separation_vectors();
        assert_eq!(vectors.len(), 3);

        // Verify different chains produce different hashes
        assert_ne!(
            vectors[0].expected_canonical_hash,
            vectors[1].expected_canonical_hash
        );

        // Verify different nonces produce different hashes
        assert_ne!(
            vectors[0].expected_canonical_hash,
            vectors[2].expected_canonical_hash
        );
    }
}
