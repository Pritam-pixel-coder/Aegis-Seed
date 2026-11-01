//! Aegis-Seed: Constant-Time SHA-256 Implementation (FIPS 180-4)
//!
//! Provides a clean-room, `#![no_std]`, constant-time implementation of SHA-256.
//! Used for BIP-39 checksum calculation and Conic Curve KEM Key Derivation Function (KDF).
//!
//! # Constant-Time Security Guarantees:
//! 1. All word operations use native 32-bit arithmetic with fixed rotation counts.
//! 2. No data-dependent branching or conditional jumps.
//! 3. All intermediate states are zeroized on drop using the `zeroize` crate.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Initial hash values specified by FIPS 180-4 Section 5.3.3 (fractional parts of square roots of first 8 primes)
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 64 constant round keys (fractional parts of cube roots of first 64 primes)
const K: [u32; 64] = [
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
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Constant-time SHA-256 Digest accumulator with automatic memory zeroization on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len_bits: u64,
}

impl Sha256 {
    /// Initialize a new SHA-256 context with standard IV.
    pub fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len_bits: 0,
        }
    }

    /// Process a single 512-bit (64-byte) block.
    fn process_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];

        // 1. Prepare message schedule W_0 .. W_15
        for t in 0..16 {
            let offset = t * 4;
            w[t] = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }

        // 2. Extend message schedule W_16 .. W_63
        for t in 16..64 {
            let s1 = small_sigma1(w[t - 2]);
            let s0 = small_sigma0(w[t - 15]);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
        }

        // 3. Initialize working variables
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        // 4. Compression round function
        for t in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // 5. Compute intermediate hash values
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);

        // Zeroize working registers to prevent stack remanence
        w.zeroize();
    }

    /// Absorb byte slice into the hash state.
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

    /// Finalize the hash state and produce the 256-bit (32-byte) digest.
    pub fn finalize(mut self) -> [u8; 32] {
        // Pad with 0x80 followed by zeros, then 64-bit big-endian length
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            // Fill remaining with zeros and process block
            for b in &mut self.buffer[self.buffer_len..64] {
                *b = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
        }

        // Fill up to 56 bytes with zeros
        for b in &mut self.buffer[self.buffer_len..56] {
            *b = 0;
        }

        // Append 64-bit total length in big-endian
        let len_bytes = self.total_len_bits.to_be_bytes();
        self.buffer[56..64].copy_from_slice(&len_bytes);

        let final_block = self.buffer;
        self.process_block(&final_block);

        let mut digest = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }

        digest
    }

    /// One-shot hash computation for arbitrary byte slices.
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

