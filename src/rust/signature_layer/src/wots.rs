use zk_pqc_hash_layer::constants::FELT;
use zk_pqc_hash_layer::traits::HashFunction;

/// Hash mode selector for WOTS+ chains.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashMode {
    /// Poseidon t=6 (RP=83) — default, ZK-friendly.
    Poseidon,
    /// Hybrid-Hash (Poseidon ⊕ truncated SHA-256) — conservative fallback.
    Hybrid,
}

/// WOTS+ parameters.
#[derive(Debug, Clone)]
pub struct WotsParams {
    /// Winternitz parameter (default: 16). Must be a power of 2.
    pub w: usize,
    /// Hash mode for chain iterations.
    pub hash_mode: HashMode,
}

impl Default for WotsParams {
    fn default() -> Self {
        Self {
            w: 16,
            hash_mode: HashMode::Poseidon,
        }
    }
}

/// WOTS+ key pair.
#[derive(Debug, Clone)]
pub struct WotsKeyPair {
    /// Base chain seeds (one per chain, including checksum chains).
    pub secret_chains: Vec<FELT>,
    /// Fully iterated chain endpoints: public_chains[i] = H^(w-1)(secret_chains[i]).
    pub public_chains: Vec<FELT>,
}

/// WOTS+ signature: intermediate chain values.
#[derive(Debug, Clone)]
pub struct WotsSignature {
    /// chain_values[i] = H^(m_i)(secret_chains[i]) where m_i is the i-th element
    /// of the message+checksum decomposition.
    pub chain_values: Vec<FELT>,
}

/// Error types for WOTS+ operations.
#[derive(Debug, Clone, PartialEq)]
pub enum WotsError {
    /// Message doesn't match expected element count.
    InvalidMessageLength { expected: usize, got: usize },
    /// Checksum exceeds representable range in base-w.
    ChecksumOverflow { checksum: usize, max: usize },
}

impl std::fmt::Display for WotsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WotsError::InvalidMessageLength { expected, got } => {
                write!(
                    f,
                    "Invalid message length: expected {} elements, got {}",
                    expected, got
                )
            }
            WotsError::ChecksumOverflow { checksum, max } => {
                write!(
                    f,
                    "Checksum overflow: {} exceeds max representable value {}",
                    checksum, max
                )
            }
        }
    }
}

impl std::error::Error for WotsError {}

/// WOTS+ One-Time Signature scheme with checksum, generic over `HashFunction`.
pub struct WotsPlus;

impl WotsPlus {
    /// Number of base-w digits needed to represent a 252-bit field element.
    ///
    /// For w=16 (4-bit nibbles): ceil(252 / 4) = 63 message elements.
    fn message_len(w: usize) -> usize {
        let log_w = (w as f64).log2() as usize;
        // 252 bits in Stark252 field element
        252_usize.div_ceil(log_w)
    }

    /// Number of base-w digits needed to represent the checksum.
    ///
    /// Max checksum = msg_len * (w-1). We need ceil(log_w(max_checksum + 1)) digits.
    fn checksum_len(w: usize, msg_len: usize) -> usize {
        let max_checksum = msg_len * (w - 1);
        if max_checksum == 0 {
            return 1;
        }
        let log_w = (w as f64).log2() as usize;
        let bits_needed = ((max_checksum as f64).log2().floor() as usize) + 1;
        bits_needed.div_ceil(log_w)
    }

    /// Total number of chains (message + checksum).
    pub fn total_chains(params: &WotsParams) -> usize {
        let msg_len = Self::message_len(params.w);
        msg_len + Self::checksum_len(params.w, msg_len)
    }

    /// Decompose a FELT into base-w elements (big-endian bit extraction).
    ///
    /// Returns `msg_len` elements, each in [0, w).
    fn decompose_message(w: usize, message: &FELT) -> Vec<usize> {
        #[allow(unused_imports)]
        use lambdaworks_math::traits::ByteConversion;

        let log_w = (w as f64).log2() as usize;
        let msg_len = Self::message_len(w);
        let bytes = message.to_bytes_be();

        // Extract bits from the big-endian byte representation
        let mut bits = Vec::with_capacity(256);
        for byte in &bytes {
            for bit_idx in (0..8).rev() {
                bits.push((byte >> bit_idx) & 1);
            }
        }

        // Group bits into log_w-bit chunks, big-endian within each chunk.
        // We take the LAST 252 bits (skip the first 4 padding bits for 256-bit representation).
        let start_bit = bits.len() - 252;
        let relevant_bits = &bits[start_bit..];

        let mut elements = Vec::with_capacity(msg_len);
        for i in 0..msg_len {
            let mut val = 0usize;
            for j in 0..log_w {
                let bit_pos = i * log_w + j;
                if bit_pos < relevant_bits.len() {
                    val = (val << 1) | (relevant_bits[bit_pos] as usize);
                } else {
                    val <<= 1;
                }
            }
            elements.push(val);
        }

        elements
    }

    /// Compute the WOTS+ checksum: C = Σ(w-1-m_i), decomposed into base-w elements.
    ///
    /// This prevents existential forgery by ensuring the total iteration sum is constant.
    pub fn checksum(w: usize, message_elements: &[usize]) -> Vec<usize> {
        let c: usize = message_elements.iter().map(|&m_i| (w - 1) - m_i).sum();

        let checksum_len = Self::checksum_len(w, message_elements.len());

        // Decompose c into base-w digits (least significant first, then reverse for big-endian).
        let mut digits = Vec::with_capacity(checksum_len);
        let mut remaining = c;
        for _ in 0..checksum_len {
            digits.push(remaining % w);
            remaining /= w;
        }
        // Reverse to get big-endian order
        digits.reverse();

        debug_assert!(
            digits.iter().all(|&d| d < w),
            "Checksum digit exceeds base-w"
        );

        digits
    }

    /// Iterate a hash chain: H^n(value) — apply the hash function n times.
    fn chain_hash<H: HashFunction<Digest = FELT>>(
        hasher: &H,
        value: &FELT,
        iterations: usize,
    ) -> FELT {
        let mut current = *value;
        for _ in 0..iterations {
            current = hasher.hash(&[current]);
        }
        current
    }

    /// Generate a WOTS+ key pair from a seed.
    ///
    /// - `secret_chains[i] = H(seed || i)` for each chain
    /// - `public_chains[i] = H^(w-1)(secret_chains[i])`
    pub fn keygen<H: HashFunction<Digest = FELT>>(
        hasher: &H,
        params: &WotsParams,
        seed: &[FELT],
    ) -> WotsKeyPair {
        let total = Self::total_chains(params);
        let mut secret_chains = Vec::with_capacity(total);
        let mut public_chains = Vec::with_capacity(total);

        for i in 0..total {
            // Derive secret: H(seed || i)
            let mut input = seed.to_vec();
            input.push(FELT::from(i as u64));
            let secret = hasher.hash(&input);
            secret_chains.push(secret);

            // Public key: iterate w-1 times
            let public = Self::chain_hash(hasher, &secret, params.w - 1);
            public_chains.push(public);
        }

        WotsKeyPair {
            secret_chains,
            public_chains,
        }
    }

    /// Sign a message (single FELT) with WOTS+.
    ///
    /// 1. Decompose message into base-w elements
    /// 2. Compute checksum and append checksum elements
    /// 3. For each element m_i: chain_values[i] = H^(m_i)(secret_chains[i])
    pub fn sign<H: HashFunction<Digest = FELT>>(
        hasher: &H,
        params: &WotsParams,
        key: &WotsKeyPair,
        message: &[FELT],
    ) -> Result<WotsSignature, WotsError> {
        if message.len() != 1 {
            return Err(WotsError::InvalidMessageLength {
                expected: 1,
                got: message.len(),
            });
        }

        let msg_elements = Self::decompose_message(params.w, &message[0]);
        let checksum_elements = Self::checksum(params.w, &msg_elements);

        let mut all_elements = msg_elements;
        all_elements.extend_from_slice(&checksum_elements);

        let total = Self::total_chains(params);
        if all_elements.len() != total {
            return Err(WotsError::InvalidMessageLength {
                expected: total,
                got: all_elements.len(),
            });
        }

        let mut chain_values = Vec::with_capacity(total);
        for (i, &m_i) in all_elements.iter().enumerate() {
            let val = Self::chain_hash(hasher, &key.secret_chains[i], m_i);
            chain_values.push(val);
        }

        Ok(WotsSignature { chain_values })
    }

    /// Verify a WOTS+ signature.
    ///
    /// For each element m_i, iterate chain_values[i] by (w-1-m_i) more hashes
    /// and compare with public_chains[i]. All must match.
    pub fn verify<H: HashFunction<Digest = FELT>>(
        hasher: &H,
        params: &WotsParams,
        pubkey: &[FELT],
        message: &[FELT],
        sig: &WotsSignature,
    ) -> bool {
        if message.len() != 1 {
            return false;
        }

        let total = Self::total_chains(params);
        if pubkey.len() != total || sig.chain_values.len() != total {
            return false;
        }

        let msg_elements = Self::decompose_message(params.w, &message[0]);
        let checksum_elements = Self::checksum(params.w, &msg_elements);

        let mut all_elements = msg_elements;
        all_elements.extend_from_slice(&checksum_elements);

        if all_elements.len() != total {
            return false;
        }

        for (i, &m_i) in all_elements.iter().enumerate() {
            let remaining = (params.w - 1) - m_i;
            let reconstructed = Self::chain_hash(hasher, &sig.chain_values[i], remaining);
            if reconstructed != pubkey[i] {
                return false;
            }
        }

        true
    }
}
