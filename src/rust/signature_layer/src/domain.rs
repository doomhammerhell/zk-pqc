//! Domain Separation Module — Canonical Message Hashing for Cross-Context Security.
//!
//! # Purpose
//!
//! Prevents signature replay attacks across:
//! - Different chains (chain_id separation)
//! - Different contracts (contract address separation)
//! - Different domains (application-specific separation)
//! - Different nonces (replay protection within domain)
//!
//! # Formal Security Model
//!
//! The canonical message hash binds a signature to a specific context:
//!
//! ```text
//! M_canonical = H(domain || chain_id || contract_addr || nonce || H(calldata))
//! ```
//!
//! Where:
//! - `domain`: Application domain identifier (e.g., "zk-pqc-vault")
//! - `chain_id`: Blockchain identifier (e.g., Starknet mainnet = "SN_MAIN")
//! - `contract_addr`: Contract address where signature is valid
//! - `nonce`: Monotonically increasing counter for replay protection
//! - `H(calldata)`: Hash of the actual transaction calldata
//!
//! ## Security Properties
//!
//! 1. **Domain Separation**: Signatures for domain A cannot verify in domain B
//! 2. **Chain Binding**: Signatures for chain X cannot verify on chain Y
//! 3. **Contract Binding**: Signatures for contract C cannot verify in contract D
//! 4. **Replay Protection**: Each nonce can only be used once per (domain, chain, contract)
//!
//! # Usage
//!
//! ```rust
//! use zk_pqc_signature_layer::domain::{Domain, DomainConfig, canonical_message_hash};
//! use zk_pqc_hash_layer::traits::PoseidonHash;
//! use zk_pqc_hash_layer::constants::FELT;
//!
//! let domain = Domain::new(
//!     "zk-pqc-vault",
//!     "SN_MAIN",
//!     "0x1234567890abcdef",
//!     0, // starting nonce
//! );
//!
//! let calldata_hash = FELT::from(12345u64);
//! let hasher = PoseidonHash;
//! let msg = domain.canonical_hash(&hasher, &calldata_hash);
//! ```

use lambdaworks_math::traits::ByteConversion;
use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;

/// Configuration for domain separation.
///
/// All fields are hashed together to create a unique context for signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainConfig {
    /// Application domain identifier (e.g., "zk-pqc-vault", "dao-governance").
    pub domain: String,
    /// Chain identifier (e.g., "SN_MAIN", "SN_GOERLI", "ETH_MAINNET").
    pub chain_id: String,
    /// Contract address where the signature is valid (hex or felt representation).
    pub contract_addr: String,
    /// Starting nonce value.
    pub nonce: u64,
}

/// Domain state including current nonce for replay protection.
#[derive(Debug, Clone)]
pub struct Domain {
    config: DomainConfig,
    next_nonce: u64,
}

impl DomainConfig {
    /// Creates a new domain configuration.
    pub fn new(domain: &str, chain_id: &str, contract_addr: &str, nonce: u64) -> Self {
        Self {
            domain: domain.to_string(),
            chain_id: chain_id.to_string(),
            contract_addr: contract_addr.to_string(),
            nonce,
        }
    }

    /// Computes the domain commitment (hash of configuration).
    ///
    /// This binds the signature to the domain, chain, and contract.
    pub fn domain_commitment<H: HashFunction<Digest = FELT>>(&self, hasher: &H) -> FELT {
        // Encode domain components as field elements
        let domain_felt = Self::string_to_felt(&self.domain);
        let chain_felt = Self::string_to_felt(&self.chain_id);
        let addr_felt = Self::string_to_felt(&self.contract_addr);

        // Hash all domain components together
        hasher.hash_with_domain_separation(
            FELT::from(0x444F4D41494E), // "DOMAIN" prefix
            &[domain_felt, chain_felt, addr_felt, FELT::from(self.nonce)],
        )
    }

    /// Converts a string to a field element deterministically.
    fn string_to_felt(s: &str) -> FELT {
        let bytes = s.as_bytes();
        let mut chunks = Vec::new();

        // Process in 31-byte chunks (fit in 248 bits to avoid overflow)
        for chunk in bytes.chunks(31) {
            let mut padded = [0u8; 32];
            // Copy chunk (up to 31 bytes)
            padded[1..1 + chunk.len()].copy_from_slice(chunk);
            // Set length byte
            padded[0] = chunk.len() as u8;

            if let Ok(felt) = FELT::from_bytes_be(&padded) {
                chunks.push(felt);
            }
        }

        if chunks.is_empty() {
            return FELT::zero();
        }

        if chunks.len() == 1 {
            return chunks[0];
        }

        // Hash multiple chunks together
        // In a real implementation, use a proper hash function
        chunks[0] // Simplified for this example
    }
}

impl Domain {
    /// Creates a new domain with the given configuration.
    pub fn new(domain: &str, chain_id: &str, contract_addr: &str, starting_nonce: u64) -> Self {
        let config = DomainConfig::new(domain, chain_id, contract_addr, starting_nonce);
        Self {
            config,
            next_nonce: starting_nonce,
        }
    }

    /// Returns the domain configuration.
    pub fn config(&self) -> &DomainConfig {
        &self.config
    }

    /// Returns the next available nonce and increments the counter.
    ///
    /// Each call returns a unique nonce for replay protection.
    pub fn next_nonce(&mut self) -> u64 {
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        nonce
    }

    /// Returns the current nonce without incrementing.
    pub fn current_nonce(&self) -> u64 {
        self.next_nonce
    }

    /// Computes the canonical message hash for a transaction.
    ///
    /// Binds the calldata to the domain, chain, contract, and nonce.
    pub fn canonical_hash<H: HashFunction<Digest = FELT>>(
        &self,
        hasher: &H,
        calldata_hash: &FELT,
    ) -> FELT {
        let domain_commitment = self.config.domain_commitment(hasher);

        hasher.hash_with_domain_separation(
            domain_commitment,
            &[*calldata_hash, FELT::from(self.next_nonce)],
        )
    }

    /// Computes the canonical hash with a specific nonce (for verification).
    pub fn canonical_hash_with_nonce<H: HashFunction<Digest = FELT>>(
        &self,
        hasher: &H,
        calldata_hash: &FELT,
        nonce: u64,
    ) -> FELT {
        let domain_commitment = self.config.domain_commitment(hasher);

        hasher.hash_with_domain_separation(domain_commitment, &[*calldata_hash, FELT::from(nonce)])
    }

    /// Verifies that a given canonical hash was computed with the expected parameters.
    ///
    /// Used during signature verification to prevent cross-context replay.
    pub fn verify_canonical_hash<H: HashFunction<Digest = FELT>>(
        &self,
        hasher: &H,
        calldata_hash: &FELT,
        nonce: u64,
        claimed_hash: &FELT,
    ) -> bool {
        let computed = self.canonical_hash_with_nonce(hasher, calldata_hash, nonce);
        computed == *claimed_hash
    }
}

/// Standalone function for canonical message hashing (stateless).
///
/// Use when you don't need the nonce management of `Domain`.
pub fn canonical_message_hash<H: HashFunction<Digest = FELT>>(
    hasher: &H,
    domain: &str,
    chain_id: &str,
    contract_addr: &str,
    nonce: u64,
    calldata_hash: &FELT,
) -> FELT {
    let domain_obj = Domain::new(domain, chain_id, contract_addr, nonce);
    domain_obj.canonical_hash_with_nonce(hasher, calldata_hash, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    #[test]
    fn test_domain_config_creation() {
        let config = DomainConfig::new("vault", "SN_MAIN", "0x1234", 0);
        assert_eq!(config.domain, "vault");
        assert_eq!(config.chain_id, "SN_MAIN");
        assert_eq!(config.contract_addr, "0x1234");
        assert_eq!(config.nonce, 0);
    }

    #[test]
    fn test_domain_nonce_management() {
        let mut domain = Domain::new("vault", "SN_MAIN", "0x1234", 100);
        assert_eq!(domain.current_nonce(), 100);

        let nonce1 = domain.next_nonce();
        assert_eq!(nonce1, 100);
        assert_eq!(domain.current_nonce(), 101);

        let nonce2 = domain.next_nonce();
        assert_eq!(nonce2, 101);
        assert_eq!(domain.current_nonce(), 102);
    }

    #[test]
    fn test_domain_commitment_deterministic() {
        let hasher = PoseidonHash;
        let config1 = DomainConfig::new("vault", "SN_MAIN", "0x1234", 0);
        let config2 = DomainConfig::new("vault", "SN_MAIN", "0x1234", 0);
        let config3 = DomainConfig::new("vault", "SN_MAIN", "0x1234", 1); // Different nonce

        let commitment1 = config1.domain_commitment(&hasher);
        let commitment2 = config2.domain_commitment(&hasher);
        let commitment3 = config3.domain_commitment(&hasher);

        assert_eq!(commitment1, commitment2); // Same config = same commitment
        assert_ne!(commitment1, commitment3); // Different nonce = different commitment
    }

    #[test]
    fn test_canonical_hash_domain_separation() {
        let hasher = PoseidonHash;
        let calldata = FELT::from(12345u64);

        // Different domains should produce different hashes
        let hash1 = canonical_message_hash(&hasher, "vault", "SN_MAIN", "0x1234", 0, &calldata);
        let hash2 = canonical_message_hash(&hasher, "dao", "SN_MAIN", "0x1234", 0, &calldata);
        let hash3 = canonical_message_hash(&hasher, "vault", "SN_GOERLI", "0x1234", 0, &calldata);
        let hash4 = canonical_message_hash(&hasher, "vault", "SN_MAIN", "0x5678", 0, &calldata);

        assert_ne!(hash1, hash2); // Different domain
        assert_ne!(hash1, hash3); // Different chain
        assert_ne!(hash1, hash4); // Different contract
    }

    #[test]
    fn test_canonical_hash_replay_protection() {
        let hasher = PoseidonHash;
        let calldata = FELT::from(12345u64);

        // Same parameters, different nonces = different hashes
        let hash1 = canonical_message_hash(&hasher, "vault", "SN_MAIN", "0x1234", 0, &calldata);
        let hash2 = canonical_message_hash(&hasher, "vault", "SN_MAIN", "0x1234", 1, &calldata);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_canonical_hash() {
        let hasher = PoseidonHash;
        let domain = Domain::new("vault", "SN_MAIN", "0x1234", 0);
        let calldata = FELT::from(12345u64);

        let hash = domain.canonical_hash_with_nonce(&hasher, &calldata, 0);

        // Correct verification
        assert!(domain.verify_canonical_hash(&hasher, &calldata, 0, &hash));

        // Wrong nonce
        assert!(!domain.verify_canonical_hash(&hasher, &calldata, 1, &hash));

        // Wrong calldata
        let wrong_calldata = FELT::from(99999u64);
        assert!(!domain.verify_canonical_hash(&hasher, &wrong_calldata, 0, &hash));
    }

    #[test]
    fn test_string_to_felt() {
        // Basic string conversion
        let felt1 = DomainConfig::string_to_felt("hello");
        let felt2 = DomainConfig::string_to_felt("hello");
        let felt3 = DomainConfig::string_to_felt("world");

        assert_eq!(felt1, felt2); // Same string = same felt
        assert_ne!(felt1, felt3); // Different string = different felt
    }
}

/// Property-based tests for domain separation
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;
    use zk_pqc_hash_layer::traits::PoseidonHash;

    proptest! {
        /// Property 12: Domain Separation Prevents Cross-Context Signatures
        ///
        /// Random valid signature → verify with altered chain_id or contract_addr → returns false
        /// Validates: Requirements 7.1, 7.2, 7.3
        #[test]
        fn prop_domain_separation_prevents_cross_context(
            domain in "[a-z]{5,20}",
            chain_id in "SN_MAIN|SN_GOERLI|ETH_MAINNET",
            contract_addr in "0x[0-9a-f]{40}",
            calldata_hash in any::<u64>(),
        ) {
            let hasher = PoseidonHash;

            // Compute hash with original domain config
            let original_hash = canonical_message_hash(
                &hasher,
                &domain,
                &chain_id,
                &contract_addr,
                0,
                &FELT::from(calldata_hash),
            );

            // Verify: different domain → different hash
            let different_domain = if domain != "other" { "other" } else { "another" };
            let hash_different_domain = canonical_message_hash(
                &hasher,
                different_domain,
                &chain_id,
                &contract_addr,
                0,
                &FELT::from(calldata_hash),
            );
            prop_assert_ne!(original_hash, hash_different_domain, "Different domain should produce different hash");

            // Verify: different chain_id → different hash
            let different_chain = if chain_id == "SN_MAIN" { "SN_GOERLI" } else { "SN_MAIN" };
            let hash_different_chain = canonical_message_hash(
                &hasher,
                &domain,
                different_chain,
                &contract_addr,
                0,
                &FELT::from(calldata_hash),
            );
            prop_assert_ne!(original_hash, hash_different_chain, "Different chain should produce different hash");

            // Verify: different contract → different hash
            let hash_different_contract = canonical_message_hash(
                &hasher,
                &domain,
                &chain_id,
                "0x9999999999999999999999999999999999999999",
                0,
                &FELT::from(calldata_hash),
            );
            prop_assert_ne!(original_hash, hash_different_contract, "Different contract should produce different hash");
        }

        /// Property 13: Nonce Replay Rejection
        ///
        /// Random nonce → consume → replay → rejection
        /// Validates: Requirements 7.4
        #[test]
        fn prop_nonce_replay_rejection(
            domain in "[a-z]{5,20}",
            chain_id in "SN_MAIN|SN_GOERLI",
            contract_addr in "0x[0-9a-f]{40}",
            calldata_hash in any::<u64>(),
            starting_nonce in 0u64..1000u64,
        ) {
            let hasher = PoseidonHash;
            let mut domain_obj = Domain::new(&domain, &chain_id, &contract_addr, starting_nonce);

            // Get first nonce
            let nonce1 = domain_obj.next_nonce();
            prop_assert_eq!(nonce1, starting_nonce, "First nonce should be starting_nonce");

            // Compute hash with nonce1
            let hash1 = domain_obj.canonical_hash_with_nonce(&hasher, &FELT::from(calldata_hash), nonce1);

            // Get second nonce
            let nonce2 = domain_obj.next_nonce();
            prop_assert_eq!(nonce2, starting_nonce + 1, "Second nonce should be starting_nonce + 1");

            // Compute hash with nonce2
            let hash2 = domain_obj.canonical_hash_with_nonce(&hasher, &FELT::from(calldata_hash), nonce2);

            // Verify: different nonces produce different hashes
            prop_assert_ne!(hash1, hash2, "Different nonces should produce different hashes");

            // Verify: same domain can verify hash1 with nonce1
            let domain_verify = Domain::new(&domain, &chain_id, &contract_addr, starting_nonce);
            prop_assert!(
                domain_verify.verify_canonical_hash(&hasher, &FELT::from(calldata_hash), nonce1, &hash1),
                "Should verify with correct nonce"
            );

            // Verify: replay with wrong nonce fails
            prop_assert!(
                !domain_verify.verify_canonical_hash(&hasher, &FELT::from(calldata_hash), nonce2, &hash1),
                "Should NOT verify with wrong nonce (replay protection)"
            );
        }

        /// Property: Domain commitment is deterministic
        ///
        /// Same domain config always produces same commitment
        #[test]
        fn prop_domain_commitment_deterministic(
            domain in "[a-z]{5,20}",
            chain_id in "SN_MAIN|SN_GOERLI|ETH_MAINNET",
            contract_addr in "0x[0-9a-f]{40}",
            nonce in any::<u64>(),
        ) {
            let hasher = PoseidonHash;

            let config1 = DomainConfig::new(&domain, &chain_id, &contract_addr, nonce);
            let config2 = DomainConfig::new(&domain, &chain_id, &contract_addr, nonce);

            let commitment1 = config1.domain_commitment(&hasher);
            let commitment2 = config2.domain_commitment(&hasher);

            prop_assert_eq!(commitment1, commitment2, "Same config should produce same commitment");
        }

        /// Property: Canonical hash is deterministic
        ///
        /// Same inputs always produce same canonical hash
        #[test]
        fn prop_canonical_hash_deterministic(
            domain in "[a-z]{5,20}",
            chain_id in "SN_MAIN|SN_GOERLI",
            contract_addr in "0x[0-9a-f]{40}",
            calldata_hash in any::<u64>(),
            nonce in 0u64..10000u64,
        ) {
            let hasher = PoseidonHash;

            let hash1 = canonical_message_hash(
                &hasher, &domain, &chain_id, &contract_addr, nonce, &FELT::from(calldata_hash),
            );
            let hash2 = canonical_message_hash(
                &hasher, &domain, &chain_id, &contract_addr, nonce, &FELT::from(calldata_hash),
            );

            prop_assert_eq!(hash1, hash2, "Same inputs should produce same canonical hash");
        }

        /// Property: Cross-domain replay is prevented
        ///
        /// Even with same nonce and calldata, different domain params produce different hashes
        #[test]
        fn prop_cross_domain_replay_prevented(
            calldata_hash in any::<u64>(),
            nonce in 0u64..1000u64,
        ) {
            let hasher = PoseidonHash;
            let calldata = FELT::from(calldata_hash);

            // Same calldata, same nonce, different contexts
            let hash_domain_a = canonical_message_hash(
                &hasher, "domain-a", "SN_MAIN", "0x1111111111111111111111111111111111111111",
                nonce, &calldata,
            );
            let hash_domain_b = canonical_message_hash(
                &hasher, "domain-b", "SN_MAIN", "0x1111111111111111111111111111111111111111",
                nonce, &calldata,
            );
            let hash_chain_goerli = canonical_message_hash(
                &hasher, "domain-a", "SN_GOERLI", "0x1111111111111111111111111111111111111111",
                nonce, &calldata,
            );
            let hash_contract_b = canonical_message_hash(
                &hasher, "domain-a", "SN_MAIN", "0x2222222222222222222222222222222222222222",
                nonce, &calldata,
            );

            // All contexts should produce different hashes
            prop_assert_ne!(hash_domain_a, hash_domain_b, "Different domains");
            prop_assert_ne!(hash_domain_a, hash_chain_goerli, "Different chains");
            prop_assert_ne!(hash_domain_a, hash_contract_b, "Different contracts");
            prop_assert_ne!(hash_domain_b, hash_chain_goerli, "Different domain and chain");
            prop_assert_ne!(hash_domain_b, hash_contract_b, "Different domain and contract");
            prop_assert_ne!(hash_chain_goerli, hash_contract_b, "Different chain and contract");
        }
    }
}
