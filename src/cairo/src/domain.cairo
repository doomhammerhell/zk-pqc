//! Domain Separation Module — Canonical Message Hashing for Cross-Context Security.
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
//! ## Security Properties
//!
//! 1. **Domain Separation**: Signatures for domain A cannot verify in domain B
//! 2. **Chain Binding**: Signatures for chain X cannot verify on chain Y
//! 3. **Contract Binding**: Signatures for contract C cannot verify in contract D
//! 4. **Replay Protection**: Each nonce can only be used once per (domain, chain, contract)

use zk_pqc_cairo::hash_trait::HashFunction;

/// Domain configuration for separation.
/// All fields are hashed together to create a unique context for signatures.
#[derive(Drop, Copy, Clone)]
pub struct DomainConfig {
    /// Application domain identifier (e.g., "zk-pqc-vault").
    pub domain: felt252,
    /// Chain identifier (e.g., "SN_MAIN", "SN_GOERLI").
    pub chain_id: felt252,
    /// Contract address where the signature is valid.
    pub contract_addr: felt252,
    /// Current nonce for replay protection.
    pub nonce: u64,
}

/// Domain state including consumed nonces tracking.
#[derive(Drop)]
pub struct Domain {
    pub config: DomainConfig,
    /// Set of consumed nonces (simplified: just track next expected nonce).
    pub next_nonce: u64,
}

/// Error types for domain operations.
#[derive(Drop, Debug)]
pub enum DomainError {
    /// Nonce already consumed (replay attempt).
    NonceAlreadyConsumed,
    /// Invalid nonce sequence.
    InvalidNonce,
    /// Domain mismatch.
    DomainMismatch,
    /// Chain ID mismatch.
    ChainIdMismatch,
    /// Contract address mismatch.
    ContractMismatch,
}

#[generate_trait]
pub impl DomainConfigImpl of DomainConfigTrait {
    /// Creates a new domain configuration.
    fn new(domain: felt252, chain_id: felt252, contract_addr: felt252, nonce: u64) -> DomainConfig {
        DomainConfig { domain, chain_id, contract_addr, nonce }
    }

    /// Computes the domain commitment (hash of configuration).
    /// This binds the signature to the domain, chain, and contract.
    fn domain_commitment<T, +HashFunction<T>, +Drop<T>>(self: @DomainConfig) -> felt252 {
        // Hash all domain components together with "DOMAIN" prefix
        let domain_prefix: felt252 = 0x444F4D41494E; // "DOMAIN" in ASCII

        let nonce_felt: felt252 = (*self.nonce).into();
        HashFunction::<
            T,
        >::hash_with_domain_separation(
            domain_prefix,
            array![*self.domain, *self.chain_id, *self.contract_addr, nonce_felt].span(),
        )
    }

    /// Checks if this domain config matches another (for verification).
    fn matches(self: @DomainConfig, other: @DomainConfig) -> bool {
        *self.domain == *other.domain
            && *self.chain_id == *other.chain_id
            && *self.contract_addr == *other.contract_addr
    }
}

#[generate_trait]
pub impl DomainImpl of DomainTrait {
    /// Creates a new domain with the given configuration.
    fn new(
        domain: felt252, chain_id: felt252, contract_addr: felt252, starting_nonce: u64,
    ) -> Domain {
        Domain {
            config: DomainConfig { domain, chain_id, contract_addr, nonce: starting_nonce },
            next_nonce: starting_nonce,
        }
    }

    /// Returns the next available nonce and increments the counter.
    fn consume_next_nonce(ref self: Domain) -> u64 {
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        nonce
    }

    /// Returns the current nonce without incrementing.
    fn current_nonce(self: @Domain) -> u64 {
        *self.next_nonce
    }

    /// Checks if a nonce has been consumed (nonce < next_nonce).
    fn is_nonce_consumed(self: @Domain, nonce: u64) -> bool {
        nonce < *self.next_nonce
    }

    /// Computes the canonical message hash for a transaction.
    /// Binds the calldata to the domain, chain, contract, and nonce.
    fn canonical_hash<T, +HashFunction<T>, +Drop<T>>(
        self: @Domain, calldata_hash: felt252,
    ) -> felt252 {
        let domain_commitment = self.config.domain_commitment::<T>();
        let nonce_felt: felt252 = (*self.next_nonce).into();

        HashFunction::<
            T,
        >::hash_with_domain_separation(domain_commitment, array![calldata_hash, nonce_felt].span())
    }

    /// Computes the canonical hash with a specific nonce (for verification).
    fn canonical_hash_with_nonce<T, +HashFunction<T>, +Drop<T>>(
        self: @Domain, calldata_hash: felt252, nonce: u64,
    ) -> felt252 {
        let domain_commitment = self.config.domain_commitment::<T>();
        let nonce_felt: felt252 = nonce.into();

        HashFunction::<
            T,
        >::hash_with_domain_separation(domain_commitment, array![calldata_hash, nonce_felt].span())
    }

    /// Verifies that a given canonical hash was computed with the expected parameters.
    /// Used during signature verification to prevent cross-context replay.
    fn verify_canonical_hash<T, +HashFunction<T>, +Drop<T>>(
        self: @Domain, claimed_hash: felt252, calldata_hash: felt252, expected_nonce: u64,
    ) -> bool {
        // Check nonce hasn't been consumed (replay protection)
        if self.is_nonce_consumed(expected_nonce) {
            return false;
        }

        // Recompute the expected hash
        let expected = self.canonical_hash_with_nonce::<T>(calldata_hash, expected_nonce);

        claimed_hash == expected
    }
}

/// Standalone function to compute canonical message hash.
/// Useful for off-chain message preparation.
pub fn canonical_message_hash<T, +HashFunction<T>, +Drop<T>>(
    domain: felt252, chain_id: felt252, contract_addr: felt252, nonce: u64, calldata_hash: felt252,
) -> felt252 {
    let config = DomainConfig { domain, chain_id, contract_addr, nonce };
    let domain_commitment = config.domain_commitment::<T>();
    let nonce_felt: felt252 = nonce.into();

    HashFunction::<
        T,
    >::hash_with_domain_separation(domain_commitment, array![calldata_hash, nonce_felt].span())
}

/// Verifies domain separation constraints.
/// Returns true only if all separation constraints are satisfied.
pub fn verify_domain_constraints(
    expected_domain: felt252,
    expected_chain_id: felt252,
    expected_contract: felt252,
    actual_domain: felt252,
    actual_chain_id: felt252,
    actual_contract: felt252,
) -> bool {
    expected_domain == actual_domain
        && expected_chain_id == actual_chain_id
        && expected_contract == actual_contract
}
