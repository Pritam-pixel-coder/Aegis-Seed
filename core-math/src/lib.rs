//! # Core-Math: Strict `#![no_std]` Side-Channel Immune Cryptographic Mathematics
//!
//! Provides the mathematical core for Aegis-Seed:
//! 1. **BIP-39 Vectorization**: Constant-time conversion between 24 x 11-bit word indices and a 32-byte (256-bit) entropy array.
//! 2. **GF(2^8) Linear-Algebraic Secret Sharing**: Carryless field arithmetic, branchless Gaussian elimination,
//!    and full 32-byte `(t, n)` threshold secret sharing.
//! 3. **GF(2^11) Reed-Solomon Codec**: Systematic fault-tolerant error correction over 11-bit symbols.
//! 4. **Conic Curve KEM (CC-DLP)**: Constant-time Pell curve arithmetic ($x^2 - 2y^2 \equiv 1 \pmod p$) with Montgomery ladder.
//!
//! # Strict Security Invariants:
//! - `#![no_std]` bare-metal compatible.
//! - ZERO secret-dependent branches (`if`/`match`).
//! - ZERO secret-dependent memory indexing (no cache-timing S-box or log tables).
//! - True constant-time operations enforced via `subtle::ConditionallySelectable` and `subtle::ConstantTimeEq`.

#![no_std]
#![allow(
    clippy::suspicious_arithmetic_impl,
    clippy::suspicious_op_assign_impl,
    clippy::needless_range_loop,
    clippy::new_without_default,
    clippy::unnecessary_cast
)]

use core::ops::{Add, AddAssign, BitXor, Mul, MulAssign, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

// =============================================================================
// SECTION 1: Clean-Room Constant-Time SHA-256 (FIPS 180-4)
// =============================================================================

const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn sha256_ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn sha256_maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn sha256_big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn sha256_big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn sha256_small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn sha256_small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Constant-time SHA-256 Digest accumulator with memory zeroization on drop.
#[derive(Clone, Zeroize)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len_bits: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: SHA256_H0,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len_bits: 0,
        }
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for t in 0..16 {
            let offset = t * 4;
            w[t] = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for t in 16..64 {
            let s1 = sha256_small_sigma1(w[t - 2]);
            let s0 = sha256_small_sigma0(w[t - 15]);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for t in 0..64 {
            let t1 = h
                .wrapping_add(sha256_big_sigma1(e))
                .wrapping_add(sha256_ch(e, f, g))
                .wrapping_add(SHA256_K[t])
                .wrapping_add(w[t]);
            let t2 = sha256_big_sigma0(a).wrapping_add(sha256_maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);

        w.zeroize();
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len_bits = self
            .total_len_bits
            .wrapping_add((data.len() as u64).wrapping_mul(8));

        let mut data_idx = 0;
        while data_idx < data.len() {
            let space = 64 - self.buffer_len;
            let available = data.len() - data_idx;
            let take = if available < space { available } else { space };

            self.buffer[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&data[data_idx..data_idx + take]);
            self.buffer_len += take;
            data_idx += take;

            if self.buffer_len == 64 {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            for b in &mut self.buffer[self.buffer_len..64] {
                *b = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
        }

        for b in &mut self.buffer[self.buffer_len..56] {
            *b = 0;
        }

        let len_bytes = self.total_len_bits.to_be_bytes();
        self.buffer[56..64].copy_from_slice(&len_bytes);

        let final_block = self.buffer;
        self.process_block(&final_block);

        let mut digest = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        self.state.zeroize();
        self.buffer.zeroize();

        digest
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

// =============================================================================
// SECTION 2: Layer 1 - BIP-39 Entropy Extraction & GF(2) Vectorization
// =============================================================================

/// A constant-time bitvector over GF(2) with fixed byte length `BYTES`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct Gf2Vector<const BYTES: usize> {
    pub storage: [u8; BYTES],
}

impl<const BYTES: usize> Gf2Vector<BYTES> {
    pub const fn zero() -> Self {
        Self {
            storage: [0u8; BYTES],
        }
    }

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

    #[inline(always)]
    pub fn get_bit(&self, index: usize) -> u8 {
        let byte_idx = index / 8;
        let bit_idx = 7 - (index % 8);
        (self.storage[byte_idx] >> bit_idx) & 1
    }

    #[inline(always)]
    pub fn set_bit(&mut self, index: usize, value: u8) {
        let byte_idx = index / 8;
        let bit_idx = 7 - (index % 8);
        let mask = 1u8 << bit_idx;
        self.storage[byte_idx] &= !mask;
        let val_mask = ((value & 1) as u8).wrapping_neg();
        self.storage[byte_idx] |= mask & val_mask;
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

/// Representation of a 24-word BIP-39 seed phrase holding an exact 32-byte (256-bit) entropy array.
#[derive(Clone, Zeroize)]
pub struct Bip39MasterEntropy {
    /// Exactly 32 bytes (256 bits) of raw master entropy
    pub entropy: [u8; 32],
    /// 8-bit checksum: MSB_8(SHA256(entropy))
    pub checksum: u8,
    /// 24 x 11-bit BIP-39 word indices in [0, 2047]
    pub word_indices: [u16; 24],
}

impl Bip39MasterEntropy {
    /// Ingest exactly 32 bytes of raw entropy. Calculates the 8-bit checksum
    /// and generates all 24 11-bit indices in constant time.
    pub fn from_raw_entropy(raw_bytes: &[u8; 32]) -> Self {
        let hash = Sha256::digest(raw_bytes);
        let checksum = hash[0];

        // 33 bytes = 264 bits = 256 bits entropy + 8 bits checksum
        let mut full_vec = Gf2Vector::<33>::zero();
        full_vec.storage[..32].copy_from_slice(raw_bytes);
        full_vec.storage[32] = checksum;

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
            entropy: *raw_bytes,
            checksum,
            word_indices,
        }
    }

    /// Parse 24 11-bit word indices into a 32-byte entropy array and verify checksum in constant time.
    pub fn from_word_indices_ct(indices: &[u16; 24]) -> (Self, Choice) {
        let mut full_vec = Gf2Vector::<33>::zero();

        for i in 0..24 {
            let word_val = indices[i];
            let bit_offset = i * 11;
            for bit_pos in 0..11 {
                let bit = ((word_val >> (10 - bit_pos)) & 1) as u8;
                full_vec.set_bit(bit_offset + bit_pos, bit);
            }
        }

        let mut entropy_bytes = [0u8; 32];
        entropy_bytes.copy_from_slice(&full_vec.storage[..32]);
        let extracted_checksum = full_vec.storage[32];

        let expected_hash = Sha256::digest(&entropy_bytes);
        let expected_checksum = expected_hash[0];

        let is_valid = extracted_checksum.ct_eq(&expected_checksum);

        let parsed = Self {
            entropy: entropy_bytes,
            checksum: extracted_checksum,
            word_indices: *indices,
        };

        (parsed, is_valid)
    }
}

// =============================================================================
// SECTION 3: Layer 2 - Linear-Algebraic Secret Sharing over GF(2^8)
// =============================================================================

/// Finite field element in GF(2^8) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Zeroize)]
pub struct Gf256(pub u8);

impl Gf256 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const POLY: u8 = 0x1B; // x^8 + x^4 + x^3 + x + 1 (low byte)

    #[inline(always)]
    pub fn new(val: u8) -> Self {
        Self(val)
    }

    /// Constant-Time Carryless Russian Peasant Multiplication in GF(2^8).
    /// Executes exactly 8 uniform bit-serial iterations with ZERO table lookups.
    #[inline(always)]
    pub fn ct_mul(self, rhs: Self) -> Self {
        let mut res = 0u8;
        let mut temp_a = self.0;
        let b = rhs.0;

        for i in 0..8 {
            let bit = (b >> i) & 1;
            let mask = (bit as u8).wrapping_neg();
            res ^= temp_a & mask;

            let hi_bit = (temp_a >> 7) & 1;
            let hi_mask = (hi_bit as u8).wrapping_neg();
            temp_a = (temp_a << 1) ^ (Self::POLY & hi_mask);
        }

        Self(res)
    }

    #[inline(always)]
    pub fn square(self) -> Self {
        self.ct_mul(self)
    }

    /// Constant-time field inversion via Fermat's Little Theorem: a^{-1} = a^{254}.
    pub fn invert(self) -> Self {
        let a = self;
        let a2 = a.square();
        let a3 = a2.ct_mul(a);
        let a6 = a3.square();
        let a7 = a6.ct_mul(a);
        let a14 = a7.square();
        let a15 = a14.ct_mul(a);
        let a30 = a15.square();
        let a31 = a30.ct_mul(a);
        let a62 = a31.square();
        let a63 = a62.ct_mul(a);
        let a126 = a63.square();
        let a127 = a126.ct_mul(a);
        a127.square()
    }
}

impl Add for Gf256 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl AddAssign for Gf256 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Sub for Gf256 {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl SubAssign for Gf256 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl Mul for Gf256 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        self.ct_mul(rhs)
    }
}

impl MulAssign for Gf256 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.ct_mul(rhs);
    }
}

impl ConstantTimeEq for Gf256 {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Gf256 {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u8::conditional_select(&a.0, &b.0, choice))
    }
}

pub const MAX_SHARES: usize = 16;
pub const MAX_MATRIX_DIM: usize = 8;
pub const MAX_AUGMENTED_COLS: usize = 16;

/// Square Matrix over GF(2^8) of dimension K x K.
#[derive(Clone, Copy)]
pub struct Matrix<const K: usize> {
    pub data: [[Gf256; K]; K],
}

impl<const K: usize> Matrix<K> {
    pub fn identity() -> Self {
        let mut mat = Self {
            data: [[Gf256::ZERO; K]; K],
        };
        for i in 0..K {
            mat.data[i][i] = Gf256::ONE;
        }
        mat
    }

    /// Branchless Gaussian Elimination Matrix Inversion over GF(2^8).
    /// All candidate rows are uniformly scanned and conditionally swapped without branching.
    pub fn invert_ct(&self) -> (Self, Choice) {
        assert!(K <= MAX_MATRIX_DIM);
        let double_k = 2 * K;

        let mut aug = [[Gf256::ZERO; MAX_AUGMENTED_COLS]; MAX_MATRIX_DIM];
        for r in 0..K {
            for c in 0..K {
                aug[r][c] = self.data[r][c];
            }
            aug[r][K + r] = Gf256::ONE;
        }

        let mut is_invertible = Choice::from(1);

        for r in 0..K {
            let mut pivot_val = aug[r][r];
            let mut pivot_is_zero = pivot_val.ct_eq(&Gf256::ZERO);

            for cand_r in (r + 1)..K {
                let cand_non_zero = !aug[cand_r][r].ct_eq(&Gf256::ZERO);
                let should_swap = pivot_is_zero & cand_non_zero;

                for c in 0..double_k {
                    let a_elem = aug[r][c];
                    let b_elem = aug[cand_r][c];
                    let (s_a, s_b) = (
                        Gf256::conditional_select(&a_elem, &b_elem, should_swap),
                        Gf256::conditional_select(&b_elem, &a_elem, should_swap),
                    );
                    aug[r][c] = s_a;
                    aug[cand_r][c] = s_b;
                }

                pivot_val = aug[r][r];
                pivot_is_zero = pivot_val.ct_eq(&Gf256::ZERO);
            }

            is_invertible &= !pivot_is_zero;

            let inv_pivot = pivot_val.invert();
            for c in 0..double_k {
                aug[r][c] *= inv_pivot;
            }

            for other_r in 0..K {
                let factor = aug[other_r][r];
                let is_different = Choice::from(((other_r != r) as u8) & 1);
                let effective_factor =
                    Gf256::conditional_select(&Gf256::ZERO, &factor, is_different);

                for c in 0..double_k {
                    let subtrahend = effective_factor * aug[r][c];
                    aug[other_r][c] += subtrahend;
                }
            }
        }

        let mut inv_mat = Self {
            data: [[Gf256::ZERO; K]; K],
        };
        for r in 0..K {
            for c in 0..K {
                inv_mat.data[r][c] = aug[r][K + c];
            }
        }

        (inv_mat, is_invertible)
    }
}

/// A complete 32-byte secret share in GF(2^8) corresponding to evaluation point `x`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct SecretShare {
    pub x: Gf256,
    pub values: [Gf256; 32],
}

impl SecretShare {
    pub fn empty() -> Self {
        Self {
            x: Gf256::ZERO,
            values: [Gf256::ZERO; 32],
        }
    }

    /// Export the 32 share bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = self.values[i].0;
        }
        out
    }

    /// Construct share from raw evaluation coordinate and 32-byte array
    pub fn from_bytes(x: u8, bytes: &[u8; 32]) -> Self {
        let mut values = [Gf256::ZERO; 32];
        for i in 0..32 {
            values[i] = Gf256::new(bytes[i]);
        }
        Self {
            x: Gf256::new(x),
            values,
        }
    }
}

/// Linear-Algebraic (t, n) Threshold Secret Sharing Engine for 32-byte secrets.
pub struct ThresholdScheme;

impl ThresholdScheme {
    /// Split a 32-byte (256-bit) secret into `n` shares of exactly 32 bytes each with threshold `t`.
    pub fn split(
        secret: &[u8; 32],
        threshold: usize,
        total_shares: usize,
        coefficients: &[[u8; 32]],
    ) -> [SecretShare; MAX_SHARES] {
        assert!(threshold >= 2 && threshold <= total_shares && total_shares <= MAX_SHARES);
        let mut shares = [SecretShare::empty(); MAX_SHARES];

        for i in 0..total_shares {
            let x_coord = Gf256::new((i + 1) as u8);
            shares[i].x = x_coord;

            for byte_idx in 0..32 {
                let s_byte = Gf256::new(secret[byte_idx]);
                let mut accum = Gf256::ZERO;
                for deg in (1..threshold).rev() {
                    let coef = Gf256::new(coefficients[deg - 1][byte_idx]);
                    accum = (accum + coef) * x_coord;
                }
                accum += s_byte;
                shares[i].values[byte_idx] = accum;
            }
        }

        shares
    }

    /// Reconstruct the exact 32-byte master secret from any `T` shares using constant-time Lagrange interpolation.
    pub fn reconstruct<const T: usize>(shares: &[SecretShare; T]) -> [u8; 32] {
        let mut secret = [0u8; 32];

        let mut basis = [Gf256::ONE; T];
        for i in 0..T {
            let xi = shares[i].x;
            let mut num = Gf256::ONE;
            let mut den = Gf256::ONE;

            for j in 0..T {
                let is_diff = Choice::from(((i != j) as u8) & 1);
                let xj = shares[j].x;
                let diff = xj + xi;

                let factor_num = Gf256::conditional_select(&Gf256::ONE, &xj, is_diff);
                let factor_den = Gf256::conditional_select(&Gf256::ONE, &diff, is_diff);

                num *= factor_num;
                den *= factor_den;
            }

            basis[i] = num * den.invert();
        }

        for byte_idx in 0..32 {
            let mut accum = Gf256::ZERO;
            for i in 0..T {
                accum += shares[i].values[byte_idx] * basis[i];
            }
            secret[byte_idx] = accum.0;
        }

        secret
    }
}

// =============================================================================
// SECTION 4: Layer 3 - Number-Theoretic Fault Tolerance over GF(2^11)
// =============================================================================

/// Finite Field element in GF(2^11) = GF(2)[x] / (x^11 + x^2 + 1). Order = 2048.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Zeroize)]
pub struct Gf2048(pub u16);

impl Gf2048 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const ALPHA: Self = Self(2); // Primitive element alpha = x
    pub const POLY_LOW: u16 = 5; // x^2 + 1

    #[inline(always)]
    pub fn new(val: u16) -> Self {
        Self(val & 0x7FF)
    }

    /// Constant-Time Carryless Multiplication in GF(2^11).
    #[inline(always)]
    pub fn ct_mul(self, rhs: Self) -> Self {
        let mut res: u16 = 0;
        let mut temp_a = self.0;
        let b = rhs.0;

        for i in 0..11 {
            let bit = (b >> i) & 1;
            let mask = (bit as u16).wrapping_neg();
            res ^= temp_a & mask;

            let hi = (temp_a >> 10) & 1;
            let hi_mask = (hi as u16).wrapping_neg();
            temp_a = ((temp_a << 1) & 0x7FF) ^ (Self::POLY_LOW & hi_mask);
        }

        Self(res)
    }

    #[inline(always)]
    pub fn square(self) -> Self {
        self.ct_mul(self)
    }

    /// Constant-time Field Inversion using Fermat's Little Theorem: a^{-1} = a^{2^{11}-2} = a^{2046}.
    pub fn invert(self) -> Self {
        let mut res = Self::ONE;
        let mut base = self;
        let exp: u16 = 2046;

        for i in 0..11 {
            let bit = (exp >> i) & 1;
            let choice = Choice::from(bit as u8);
            let prod = res.ct_mul(base);
            res = Self::conditional_select(&res, &prod, choice);
            base = base.square();
        }

        res
    }
}

impl Add for Gf2048 {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2048 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        self.ct_mul(rhs)
    }
}

impl ConstantTimeEq for Gf2048 {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Gf2048 {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u16::conditional_select(&a.0, &b.0, choice))
    }
}

pub const RS_K: usize = 24;
pub const RS_PARITY: usize = 2;
pub const RS_N: usize = RS_K + RS_PARITY; // 26 total symbols

/// Systematic Reed-Solomon Codec for 24-word BIP-39 phrases over GF(2^11).
#[derive(Clone, Zeroize)]
pub struct ReedSolomonGf2048 {
    g0: Gf2048,
    g1: Gf2048,
}

impl ReedSolomonGf2048 {
    pub fn new() -> Self {
        let a1 = Gf2048::ALPHA;
        let a2 = a1.square();
        let a3 = a1.ct_mul(a2);

        Self {
            g0: a3,
            g1: a1 + a2,
        }
    }

    /// Systematically encode 24 word indices into a 26-symbol codeword with 2 parity symbols.
    pub fn encode(&self, words: &[u16; RS_K]) -> [u16; RS_N] {
        let mut rem = [Gf2048::ZERO; 2];

        for &w in words.iter() {
            let symbol = Gf2048::new(w);
            let feedback = symbol + rem[1];
            rem[1] = rem[0] + feedback * self.g1;
            rem[0] = feedback * self.g0;
        }

        let mut codeword = [0u16; RS_N];
        codeword[..RS_K].copy_from_slice(words);
        codeword[RS_K] = rem[1].0; // p_1
        codeword[RS_K + 1] = rem[0].0; // p_0
        codeword
    }

    /// Constant-Time Syndrome Evaluation & Single-Word Error Correction without error oracles.
    pub fn decode_and_correct_ct(&self, received: &[u16; RS_N]) -> ([u16; RS_K], Choice) {
        let mut symbols = [Gf2048::ZERO; RS_N];
        for i in 0..RS_N {
            symbols[i] = Gf2048::new(received[i]);
        }

        let a1 = Gf2048::ALPHA;
        let a2 = a1.square();

        let mut s1 = Gf2048::ZERO;
        let mut s2 = Gf2048::ZERO;
        for i in 0..RS_N {
            s1 = s1 * a1 + symbols[i];
            s2 = s2 * a2 + symbols[i];
        }

        let no_errors = s1.ct_eq(&Gf2048::ZERO) & s2.ct_eq(&Gf2048::ZERO);
        let s1_inv = s1.invert();
        let target_locator = s2 * s1_inv;

        let mut current_locator = Gf2048::ONE;
        let mut error_found = Choice::from(0);

        for i in (0..RS_N).rev() {
            let is_error_pos = current_locator.ct_eq(&target_locator) & (!s1.ct_eq(&Gf2048::ZERO));
            error_found |= is_error_pos;

            let loc_inv = current_locator.invert();
            let error_magnitude = s1 * loc_inv;

            let corrected_sym = symbols[i] + error_magnitude;
            symbols[i] = Gf2048::conditional_select(&symbols[i], &corrected_sym, is_error_pos);

            current_locator = current_locator * a1;
        }

        let mut v1 = Gf2048::ZERO;
        let mut v2 = Gf2048::ZERO;
        for i in 0..RS_N {
            v1 = v1 * a1 + symbols[i];
            v2 = v2 * a2 + symbols[i];
        }
        let verify_ok = v1.ct_eq(&Gf2048::ZERO) & v2.ct_eq(&Gf2048::ZERO);
        let success = no_errors | (error_found & verify_ok);

        let mut output_words = [0u16; RS_K];
        for i in 0..RS_K {
            output_words[i] = symbols[i].0;
        }

        (output_words, success)
    }
}

// =============================================================================
// SECTION 5: Layer 4 - Conic Curve KEM (CC-DLP) over Prime Field
// =============================================================================

/// 256-bit unsigned integer stored as four 64-bit limbs.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Zeroize)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            let offset = 32 - (i + 1) * 8;
            limbs[i] = u64::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
        }
        Self(limbs)
    }

    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = 32 - (i + 1) * 8;
            bytes[offset..offset + 8].copy_from_slice(&self.0[i].to_be_bytes());
        }
        bytes
    }

    #[inline(always)]
    pub fn adc(&self, rhs: &Self, carry: u64) -> (Self, u64) {
        let mut sum = [0u64; 4];
        let mut c = carry;
        for i in 0..4 {
            let (w1, c1) = self.0[i].overflowing_add(rhs.0[i]);
            let (w2, c2) = w1.overflowing_add(c);
            sum[i] = w2;
            c = (c1 as u64) + (c2 as u64);
        }
        (Self(sum), c)
    }

    #[inline(always)]
    pub fn sbb(&self, rhs: &Self, borrow: u64) -> (Self, u64) {
        let mut diff = [0u64; 4];
        let mut b = borrow;
        for i in 0..4 {
            let (w1, b1) = self.0[i].overflowing_sub(rhs.0[i]);
            let (w2, b2) = w1.overflowing_sub(b);
            diff[i] = w2;
            b = (b1 as u64) + (b2 as u64);
        }
        (Self(diff), b)
    }

    pub fn add_mod(&self, rhs: &Self, modulus: &Self) -> Self {
        let (sum, carry) = self.adc(rhs, 0);
        let (sub, borrow) = sum.sbb(modulus, 0);
        let should_sub = Choice::from((carry as u8) | (((borrow ^ 1) & 1) as u8));
        Self::conditional_select(&sum, &sub, should_sub)
    }

    pub fn sub_mod(&self, rhs: &Self, modulus: &Self) -> Self {
        let (diff, borrow) = self.sbb(rhs, 0);
        let (added, _) = diff.adc(modulus, 0);
        let should_add = Choice::from((borrow & 1) as u8);
        Self::conditional_select(&diff, &added, should_add)
    }

    pub fn mul_wide(&self, rhs: &Self) -> [u64; 8] {
        let mut res = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (rhs.0[j] as u128) + (res[i + j] as u128) + carry;
                res[i + j] = prod as u64;
                carry = prod >> 64;
            }
            res[i + 4] = carry as u64;
        }
        res
    }
}

impl ConstantTimeEq for U256 {
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl ConditionallySelectable for U256 {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

/// Constant-Time Montgomery Arithmetic Engine
#[derive(Clone, Copy)]
pub struct MontgomeryContext {
    pub n: U256,
    pub n_prime: u64,
    pub r2: U256,
}

impl MontgomeryContext {
    pub const fn compute_n_prime(n0: u64) -> u64 {
        let mut inv = 1u64;
        let mut i = 0;
        while i < 6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
            i += 1;
        }
        inv.wrapping_neg()
    }

    pub fn montgomery_reduce(&self, t: &[u64; 8]) -> U256 {
        let mut a = *t;

        for i in 0..4 {
            let m = a[i].wrapping_mul(self.n_prime);
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (m as u128) * (self.n.0[j] as u128) + (a[i + j] as u128) + carry;
                a[i + j] = prod as u64;
                carry = prod >> 64;
            }
            let mut k = i + 4;
            while carry > 0 && k < 8 {
                let sum = (a[k] as u128) + carry;
                a[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
        }

        let res = U256([a[4], a[5], a[6], a[7]]);
        let (sub, borrow) = res.sbb(&self.n, 0);
        let should_sub = Choice::from(((borrow ^ 1) & 1) as u8);
        U256::conditional_select(&res, &sub, should_sub)
    }

    pub fn mul(&self, a: &U256, b: &U256) -> U256 {
        let wide = a.mul_wide(b);
        self.montgomery_reduce(&wide)
    }

    pub fn to_montgomery(&self, a: &U256) -> U256 {
        self.mul(a, &self.r2)
    }

    pub fn from_montgomery(&self, a: &U256) -> U256 {
        let mut wide = [0u64; 8];
        wide[..4].copy_from_slice(&a.0);
        self.montgomery_reduce(&wide)
    }
}

/// Point on Pell Conic Curve C_d: x^2 - d y^2 = 1 (mod n)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct ConicPoint {
    pub x: U256,
    pub y: U256,
}

impl ConicPoint {
    pub fn identity(ctx: &MontgomeryContext) -> Self {
        Self {
            x: ctx.to_montgomery(&U256::ONE),
            y: ctx.to_montgomery(&U256::ZERO),
        }
    }

    pub fn is_valid_ct(&self, ctx: &MontgomeryContext, d_mont: &U256) -> Choice {
        let x2 = ctx.mul(&self.x, &self.x);
        let y2 = ctx.mul(&self.y, &self.y);
        let dy2 = ctx.mul(d_mont, &y2);
        let diff = x2.sub_mod(&dy2, &ctx.n);
        let one_mont = ctx.to_montgomery(&U256::ONE);
        diff.ct_eq(&one_mont)
    }

    pub fn add(&self, rhs: &Self, ctx: &MontgomeryContext, d_mont: &U256) -> Self {
        let x1x2 = ctx.mul(&self.x, &rhs.x);
        let y1y2 = ctx.mul(&self.y, &rhs.y);
        let dy1y2 = ctx.mul(d_mont, &y1y2);
        let x3 = x1x2.add_mod(&dy1y2, &ctx.n);

        let x1y2 = ctx.mul(&self.x, &rhs.y);
        let x2y1 = ctx.mul(&rhs.x, &self.y);
        let y3 = x1y2.add_mod(&x2y1, &ctx.n);

        Self { x: x3, y: y3 }
    }

    pub fn double(&self, ctx: &MontgomeryContext, d_mont: &U256) -> Self {
        let x2 = ctx.mul(&self.x, &self.x);
        let y2 = ctx.mul(&self.y, &self.y);
        let dy2 = ctx.mul(d_mont, &y2);
        let x3 = x2.add_mod(&dy2, &ctx.n);

        let xy = ctx.mul(&self.x, &self.y);
        let y3 = xy.add_mod(&xy, &ctx.n);

        Self { x: x3, y: y3 }
    }

    /// Constant-Time Montgomery Ladder Scalar Multiplication: [k] P
    pub fn scalar_mul(&self, scalar: &U256, ctx: &MontgomeryContext, d_mont: &U256) -> Self {
        let mut r0 = Self::identity(ctx);
        let mut r1 = *self;

        for limb_idx in (0..4).rev() {
            let limb = scalar.0[limb_idx];
            for bit_pos in (0..64).rev() {
                let bit = Choice::from(((limb >> bit_pos) & 1) as u8);

                Self::conditional_swap(&mut r0, &mut r1, bit);
                r1 = r0.add(&r1, ctx, d_mont);
                r0 = r0.double(ctx, d_mont);
                Self::conditional_swap(&mut r0, &mut r1, bit);
            }
        }

        r0
    }

    #[inline(always)]
    pub fn conditional_swap(a: &mut Self, b: &mut Self, choice: Choice) {
        let x_a = a.x;
        let x_b = b.x;
        a.x = U256::conditional_select(&x_a, &x_b, choice);
        b.x = U256::conditional_select(&x_b, &x_a, choice);

        let y_a = a.y;
        let y_b = b.y;
        a.y = U256::conditional_select(&y_a, &y_b, choice);
        b.y = U256::conditional_select(&y_b, &y_a, choice);
    }
}

#[derive(Clone, Copy)]
pub struct ConicParameters {
    pub ctx: MontgomeryContext,
    pub d_mont: U256,
    pub generator: ConicPoint,
}

#[derive(Clone, Copy)]
pub struct ConicPublicKey {
    pub q: ConicPoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct ConicPrivateKey {
    pub scalar: U256,
}

#[derive(Clone, Copy)]
pub struct ConicCiphertext {
    pub ephemeral_point: ConicPoint,
    pub encrypted_payload: [u8; 32],
    pub mac_tag: [u8; 16],
}

pub struct ConicKem;

impl ConicKem {
    fn derive_key(point: &ConicPoint, ctx: &MontgomeryContext) -> [u8; 64] {
        let x_std = ctx.from_montgomery(&point.x).to_be_bytes();
        let y_std = ctx.from_montgomery(&point.y).to_be_bytes();

        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&x_std);
        preimage[32..].copy_from_slice(&y_std);

        let mut hash1 = Sha256::new();
        hash1.update(&preimage);
        hash1.update(b"AEGIS_CONIC_KEM_KDF_ENC_v1");
        let enc_key = hash1.finalize();

        let mut hash2 = Sha256::new();
        hash2.update(&preimage);
        hash2.update(b"AEGIS_CONIC_KEM_KDF_MAC_v1");
        let mac_key = hash2.finalize();

        let mut key_material = [0u8; 64];
        key_material[..32].copy_from_slice(&enc_key);
        key_material[32..].copy_from_slice(&mac_key);
        key_material
    }

    fn compute_mac(
        mac_key: &[u8; 32],
        ciphertext: &[u8; 32],
        ephem: &ConicPoint,
        ctx: &MontgomeryContext,
    ) -> [u8; 16] {
        let ephem_bytes = ctx.from_montgomery(&ephem.x).to_be_bytes();
        let mut h = Sha256::new();
        h.update(mac_key);
        h.update(ciphertext);
        h.update(&ephem_bytes);
        let digest = h.finalize();
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&digest[..16]);
        tag
    }

    pub fn encapsulate(
        recipient_pk: &ConicPublicKey,
        secret_payload: &[u8; 32],
        ephemeral_scalar: &U256,
        params: &ConicParameters,
    ) -> ConicCiphertext {
        let ephem_point =
            params
                .generator
                .scalar_mul(ephemeral_scalar, &params.ctx, &params.d_mont);
        let shared_point = recipient_pk
            .q
            .scalar_mul(ephemeral_scalar, &params.ctx, &params.d_mont);

        let keys = Self::derive_key(&shared_point, &params.ctx);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&keys[..32]);
        mac_key.copy_from_slice(&keys[32..]);

        let mut encrypted_payload = [0u8; 32];
        for i in 0..32 {
            encrypted_payload[i] = secret_payload[i] ^ enc_key[i];
        }

        let mac_tag = Self::compute_mac(&mac_key, &encrypted_payload, &ephem_point, &params.ctx);

        ConicCiphertext {
            ephemeral_point: ephem_point,
            encrypted_payload,
            mac_tag,
        }
    }

    pub fn decapsulate_ct(
        sk: &ConicPrivateKey,
        ciphertext: &ConicCiphertext,
        params: &ConicParameters,
    ) -> ([u8; 32], Choice) {
        let is_point_valid = ciphertext
            .ephemeral_point
            .is_valid_ct(&params.ctx, &params.d_mont);
        let shared_point =
            ciphertext
                .ephemeral_point
                .scalar_mul(&sk.scalar, &params.ctx, &params.d_mont);

        let keys = Self::derive_key(&shared_point, &params.ctx);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&keys[..32]);
        mac_key.copy_from_slice(&keys[32..]);

        let mut real_plaintext = [0u8; 32];
        for i in 0..32 {
            real_plaintext[i] = ciphertext.encrypted_payload[i] ^ enc_key[i];
        }

        let expected_mac = Self::compute_mac(
            &mac_key,
            &ciphertext.encrypted_payload,
            &ciphertext.ephemeral_point,
            &params.ctx,
        );
        let is_mac_valid = expected_mac.ct_eq(&ciphertext.mac_tag);
        let is_valid = is_point_valid & is_mac_valid;

        // Implicit Rejection: branchless fallback to deterministic surrogate key
        let mut dummy_hasher = Sha256::new();
        dummy_hasher.update(&sk.scalar.to_be_bytes());
        dummy_hasher.update(&ciphertext.ephemeral_point.x.to_be_bytes());
        let surrogate_key = dummy_hasher.finalize();

        let mut result_plaintext = [0u8; 32];
        for i in 0..32 {
            result_plaintext[i] =
                u8::conditional_select(&surrogate_key[i], &real_plaintext[i], is_valid);
        }

        (result_plaintext, is_valid)
    }
}

/// Standard Default Conic Parameters for P = 2^{255} - 19, d = 2, G = (3, 2).
pub fn default_conic_parameters() -> ConicParameters {
    let p_bytes: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xed,
    ];
    let p = U256::from_be_bytes(&p_bytes);
    let n_prime = MontgomeryContext::compute_n_prime(p.0[0]);
    let r2 = U256([1444, 0, 0, 0]); // 2^512 mod (2^255 - 19)

    let ctx = MontgomeryContext { n: p, n_prime, r2 };
    let d = U256([2, 0, 0, 0]);
    let d_mont = ctx.to_montgomery(&d);

    let g_x = ctx.to_montgomery(&U256([3, 0, 0, 0]));
    let g_y = ctx.to_montgomery(&U256([2, 0, 0, 0]));

    ConicParameters {
        ctx,
        d_mont,
        generator: ConicPoint { x: g_x, y: g_y },
    }
}
