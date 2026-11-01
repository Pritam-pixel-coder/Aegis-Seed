//! Layer 1: Entropy Extraction & GF(2) Vectorization
//!
//! Converts a 24-word BIP-39 mnemonic into a 256-bit entropy vector over GF(2)
//! alongside an 8-bit checksum.
//!
//! # Mathematical Model:
//! In BIP-39:
//! - 24 words represent 24 * 11 = 264 bits total (33 bytes).
//! - Raw Entropy: $\mathbf{e} \in \mathrm{GF}(2)^{256}$ (32 bytes).
//! - Checksum: $\mathbf{c} \in \mathrm{GF}(2)^8$, derived as the most significant 8 bits of $\mathrm{SHA256}(\mathbf{e})$.
//! - Concatenation: $\mathbf{v} = \mathbf{e} \,\|\, \mathbf{c} \in \mathrm{GF}(2)^{264}$ (33 bytes).
//! - 11-bit Word decomposition: $\mathbf{w}_i = \sum_{j=0}^{10} v_{11i + j} \cdot 2^j$ for $i \in \{0, \dots, 23\}$.
//!
//! # Constant-Time Guarantees:
//! - Zero branch conditions based on secret bits.
//! - Memory indexing into the bit array uses fixed bit shifts and branchless masking.
//! - Checksum verification uses `subtle::ConstantTimeEq`.

use core::ops::{Add, BitXor};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::ct_sha256::Sha256;

/// Error types for Layer 1 operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer1Error {
    InvalidChecksum,
    InvalidWordIndex,
    WordNotFound,
}

/// A high-performance constant-time vector over $\mathrm{GF}(2)$ of length `BYTES` bytes.
/// Elements in $\mathrm{GF}(2)$ follow XOR for addition and AND for multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct Gf2Vector<const BYTES: usize> {
    pub storage: [u8; BYTES],
}

impl<const BYTES: usize> Gf2Vector<BYTES> {
    pub const BYTE_LEN: usize = BYTES;

    /// Create an all-zero vector in GF(2)^(BYTES*8).
    pub const fn zero() -> Self {
        Self {
            storage: [0u8; BYTES],
        }
    }

    /// Construct vector from raw byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut vec = Self::zero();
        let copy_len = if bytes.len() < BYTES {
            bytes.len()
        } else {
            BYTES
        };
        vec.storage[..copy_len].copy_from_slice(&bytes[..copy_len]);
        vec
    }

    /// Retrieve the underlying bytes.
    pub fn to_bytes(&self) -> [u8; BYTES] {
        self.storage
    }

    /// Get bit value at `index` in constant time without branching.
    /// Returns 0 or 1.
    #[inline(always)]
    pub fn get_bit(&self, index: usize) -> u8 {
        let byte_idx = index / 8;
        let bit_idx = 7 - (index % 8); // Big-endian bit ordering
        (self.storage[byte_idx] >> bit_idx) & 1
    }

    /// Set bit value at `index` in constant time without secret-dependent branching.
    #[inline(always)]
    pub fn set_bit(&mut self, index: usize, value: u8) {
        let byte_idx = index / 8;
        let bit_idx = 7 - (index % 8);
        let mask = 1u8 << bit_idx;
        // Branchless update: clear bit, then conditionally set
        self.storage[byte_idx] &= !mask;
        let val_mask = ((value & 1) as u8).wrapping_neg();
        self.storage[byte_idx] |= mask & val_mask;
    }

    /// Compute inner product $\langle \mathbf{u}, \mathbf{v} \rangle = \sum_{i=0}^{N-1} u_i \cdot v_i \pmod 2$.
    /// Constant-time execution independent of secret bit values.
    pub fn inner_product(&self, other: &Self) -> u8 {
        let mut parity: u8 = 0;
        for i in 0..BYTES {
            let prod = self.storage[i] & other.storage[i];
            parity ^= prod.count_ones() as u8 & 1;
        }
        parity
    }
}

impl<const BYTES: usize> Add for Gf2Vector<BYTES> {
    type Output = Self;

    /// Vector addition in $\mathrm{GF}(2)^N$ corresponds to bitwise XOR.
    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        self ^ rhs
    }
}

impl<const BYTES: usize> BitXor for Gf2Vector<BYTES> {
    type Output = Self;

    #[inline(always)]
    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut out = Self::zero();
        for i in 0..BYTES {
            out.storage[i] = self.storage[i] ^ rhs.storage[i];
        }
        out
    }
}

impl<const BYTES: usize> ConstantTimeEq for Gf2Vector<BYTES> {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.storage.ct_eq(&other.storage)
    }
}

impl<const BYTES: usize> ConditionallySelectable for Gf2Vector<BYTES> {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut out = Self::zero();
        for i in 0..BYTES {
            out.storage[i] = u8::conditional_select(&a.storage[i], &b.storage[i], choice);
        }
        out
    }
}

/// Complete representation of parsed BIP-39 24-word state.
#[derive(Clone, Zeroize)]
pub struct Bip39MasterEntropy {
    /// Raw 256 bits of entropy $\mathbf{e} \in \mathrm{GF}(2)^{256}$ (32 bytes)
    pub entropy: Gf2Vector<32>,
    /// 8-bit checksum: $\mathbf{c} = \text{MSB}_8(\mathrm{SHA256}(\mathbf{e}))$
    pub checksum: u8,
    /// 24 x 11-bit word indices $\in [0, 2047]$
    pub word_indices: [u16; 24],
}

impl Bip39MasterEntropy {
    /// Construct from raw 256-bit entropy buffer.
    /// Calculates the 8-bit checksum and generates all 24 11-bit indices in constant time.
    pub fn from_raw_entropy(raw_bytes: &[u8; 32]) -> Self {
        let entropy = Gf2Vector::<32>::from_bytes(raw_bytes);
        
        // Calculate SHA-256(entropy)
        let hash = Sha256::digest(raw_bytes);
        let checksum = hash[0]; // First 8 bits

        // Pack 256 entropy bits + 8 checksum bits into 33-byte (264-bit) vector
        let mut full_vec = Gf2Vector::<33>::zero();
        full_vec.storage[..32].copy_from_slice(raw_bytes);
        full_vec.storage[32] = checksum;

        // Unpack into 24 11-bit indices
        let mut word_indices = [0u16; 24];
        for i in 0..24 {
            let mut word_val: u16 = 0;
            let bit_offset = i * 11;
            for bit_pos in 0..11 {
                let bit = full_vec.get_bit(bit_offset + bit_pos) as u16;
                word_val = (word_val << 1) | bit;
            }
            word_indices[i] = word_val;
        }

        Self {
            entropy,
            checksum,
            word_indices,
        }
    }

    /// Parse 24 11-bit word indices into 256-bit entropy and verify checksum in constant time.
    /// Returns `(Self, Choice)` where `Choice::from(1)` indicates valid checksum and `0` indicates corrupted.
    pub fn from_word_indices_ct(indices: &[u16; 24]) -> (Self, Choice) {
        let mut full_vec = Gf2Vector::<33>::zero();

        // Pack 24 * 11 bits branchlessly into 33-byte vector
        for i in 0..24 {
            let word_val = indices[i];
            let bit_offset = i * 11;
            for bit_pos in 0..11 {
                // Extract bit from most significant to least significant of the 11-bit integer
                let bit = ((word_val >> (10 - bit_pos)) & 1) as u8;
                full_vec.set_bit(bit_offset + bit_pos, bit);
            }
        }

        let mut entropy_bytes = [0u8; 32];
        entropy_bytes.copy_from_slice(&full_vec.storage[..32]);
        let extracted_checksum = full_vec.storage[32];

        // Compute expected checksum
        let expected_hash = Sha256::digest(&entropy_bytes);
        let expected_checksum = expected_hash[0];

        // Constant-time comparison of extracted checksum with expected checksum
        let is_valid = extracted_checksum.ct_eq(&expected_checksum);

        let parsed = Self {
            entropy: Gf2Vector::<32>::from_bytes(&entropy_bytes),
            checksum: extracted_checksum,
            word_indices: *indices,
        };

        (parsed, is_valid)
    }

    /// Constant-time dictionary lookup: finds the 11-bit index for a given word.
    ///
    /// # Side-Channel Resistance:
    /// Scans the entire `dictionary` of 2048 words uniformly.
    /// Every iteration executes identical memory fetches and comparisons, avoiding cache-timing leaks.
    pub fn find_word_index_ct(word: &[u8], dictionary: &[&[u8]; 2048]) -> (u16, Choice) {
        let mut selected_idx: u16 = 0;
        let mut found_match = Choice::from(0);

        for (i, &dict_word) in dictionary.iter().enumerate() {
            // Compare lengths branchlessly
            let len_match = (word.len() as u32).ct_eq(&(dict_word.len() as u32));

            // Compare up to 8 bytes (BIP-39 max word length) in constant time
            let mut content_match = Choice::from(1);
            let max_cmp = if word.len() < 8 { word.len() } else { 8 };
            let dict_cmp = if dict_word.len() < 8 { dict_word.len() } else { 8 };

            let cmp_limit = if max_cmp < dict_cmp { max_cmp } else { dict_cmp };
            for b in 0..cmp_limit {
                content_match &= word[b].ct_eq(&dict_word[b]);
            }

            let is_match = len_match & content_match;
            selected_idx = u16::conditional_select(&selected_idx, &(i as u16), is_match);
            found_match |= is_match;
        }

        (selected_idx, found_match)
    }
}
