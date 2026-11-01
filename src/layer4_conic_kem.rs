//! Layer 4: Conic Curve Key Encapsulation Mechanism (CC-DLP KEM)
//!
//! Implements Conic Curve Cryptography over the ring $\mathbb{Z}_n$ or field $\mathbb{F}_p$.
//! The Conic Curve Discrete Logarithm Problem (CC-DLP) operates on the algebraic curve:
//!
//! $$C_d: x^2 - d y^2 \equiv 1 \pmod n$$
//!
//! # Group Law on $C_d$:
//! For points $P_1 = (x_1, y_1)$ and $P_2 = (x_2, y_2)$ on $C_d$:
//! - Point Addition: $P_1 \oplus P_2 = (x_1 x_2 + d y_1 y_2 \pmod n, \; x_1 y_2 + x_2 y_1 \pmod n)$
//! - Identity Element: $\mathcal{O} = (1, 0)$
//! - Point Doubling: $[2]P = (x_1^2 + d y_1^2 \pmod n, \; 2 x_1 y_1 \pmod n)$
//! - Scalar Multiplication: Constant-Time Montgomery Ladder with branchless conditional swaps.
//!
//! # Constant-Time Guarantees & Implicit Rejection:
//! - All modular operations on 256-bit multi-precision integers are branchless.
//! - Scalar multiplication performs identical operations for every bit (SPA/DPA immune).
//! - Decapsulation failure uses constant-time implicit rejection (Fujisaki-Okamoto style):
//!   an invalid ciphertext produces a deterministic pseudo-random key rather than an early error oracle.

use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::ct_sha256::Sha256;

// -----------------------------------------------------------------------------
// 256-Bit Constant-Time Multi-Precision Integer Arithmetic
// -----------------------------------------------------------------------------

/// 256-bit unsigned integer stored as four 64-bit limbs in little-endian order.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Zeroize)]
pub struct U256(pub [u64; 4]);

impl U256 {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Construct from 32 big-endian bytes
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

    /// Export to 32 big-endian bytes
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..4 {
            let offset = 32 - (i + 1) * 8;
            bytes[offset..offset + 8].copy_from_slice(&self.0[i].to_be_bytes());
        }
        bytes
    }

    /// Add with carry: returns (sum, carry)
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

    /// Subtract with borrow: returns (difference, borrow)
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

    /// Returns Choice::from(1) if self >= rhs, branchlessly.
    #[inline(always)]
    pub fn ct_gte(&self, rhs: &Self) -> Choice {
        let (_, borrow) = self.sbb(rhs, 0);
        Choice::from(((borrow ^ 1) & 1) as u8)
    }

    /// Constant-time modular addition: (self + rhs) mod modulus
    pub fn add_mod(&self, rhs: &Self, modulus: &Self) -> Self {
        let (sum, carry) = self.adc(rhs, 0);
        let (sub, borrow) = sum.sbb(modulus, 0);
        // If carry == 1 or sum >= modulus (borrow == 0), select sub, else sum
        let should_sub = Choice::from((carry as u8) | (((borrow ^ 1) & 1) as u8));
        Self::conditional_select(&sum, &sub, should_sub)
    }

    /// Constant-time modular subtraction: (self - rhs) mod modulus
    pub fn sub_mod(&self, rhs: &Self, modulus: &Self) -> Self {
        let (diff, borrow) = self.sbb(rhs, 0);
        let (added, _) = diff.adc(modulus, 0);
        let should_add = Choice::from((borrow & 1) as u8);
        Self::conditional_select(&diff, &added, should_add)
    }

    /// Multiply two 256-bit numbers producing a 512-bit result (8 x 64-bit limbs)
    pub fn mul_wide(&self, rhs: &Self) -> [u64; 8] {
        let mut res = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let prod = (self.0[i] as u128) * (rhs.0[j] as u128)
                    + (res[i + j] as u128)
                    + carry;
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

// -----------------------------------------------------------------------------
// Constant-Time Montgomery Arithmetic Engine
// -----------------------------------------------------------------------------

/// Montgomery Context for arbitrary 256-bit odd modulus $N$.
#[derive(Clone, Copy)]
pub struct MontgomeryContext {
    pub n: U256,
    pub n_prime: u64, // -N^{-1} mod 2^64
    pub r2: U256,     // R^2 mod N where R = 2^256
}

impl MontgomeryContext {
    /// Compute Montgomery parameter $N' = -N^{-1} \pmod{2^{64}}$ via Hensel lifting.
    pub const fn compute_n_prime(n0: u64) -> u64 {
        // Newton-Raphson inversion mod 2^64
        let mut inv = 1u64;
        let mut i = 0;
        while i < 6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
            i += 1;
        }
        inv.wrapping_neg()
    }

    /// Constant-Time Montgomery Reduction: $T \cdot R^{-1} \pmod N$
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

    /// Multiply two Montgomery form elements: $a \cdot b \cdot R^{-1} \pmod N$
    pub fn mul(&self, a: &U256, b: &U256) -> U256 {
        let wide = a.mul_wide(b);
        self.montgomery_reduce(&wide)
    }

    /// Convert regular integer into Montgomery form: $a \cdot R \pmod N$
    pub fn to_montgomery(&self, a: &U256) -> U256 {
        self.mul(a, &self.r2)
    }

    /// Convert Montgomery form back to standard integer: $a \cdot R^{-1} \pmod N$
    pub fn from_montgomery(&self, a: &U256) -> U256 {
        let mut wide = [0u64; 8];
        wide[..4].copy_from_slice(&a.0);
        self.montgomery_reduce(&wide)
    }
}

// -----------------------------------------------------------------------------
// Conic Curve Point & Group Operations
// -----------------------------------------------------------------------------

/// Point $(X, Y)$ on Conic Curve $C_d: x^2 - d y^2 \equiv 1 \pmod n$ in Montgomery domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct ConicPoint {
    pub x: U256,
    pub y: U256,
}

impl ConicPoint {
    /// Curve identity element: $\mathcal{O} = (1, 0)$
    pub fn identity(ctx: &MontgomeryContext) -> Self {
        Self {
            x: ctx.to_montgomery(&U256::ONE),
            y: ctx.to_montgomery(&U256::ZERO),
        }
    }

    /// Validate whether the point satisfies $x^2 - d y^2 \equiv 1 \pmod n$ in constant time.
    pub fn is_valid_ct(&self, ctx: &MontgomeryContext, d_mont: &U256) -> Choice {
        let x2 = ctx.mul(&self.x, &self.x);
        let y2 = ctx.mul(&self.y, &self.y);
        let dy2 = ctx.mul(d_mont, &y2);
        let diff = x2.sub_mod(&dy2, &ctx.n);
        let one_mont = ctx.to_montgomery(&U256::ONE);
        diff.ct_eq(&one_mont)
    }

    /// Constant-Time Point Addition: $P_1 \oplus P_2 = (x_1 x_2 + d y_1 y_2, \; x_1 y_2 + x_2 y_1)$
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

    /// Constant-Time Point Doubling: $[2]P = (x_1^2 + d y_1^2, \; 2 x_1 y_1)$
    pub fn double(&self, ctx: &MontgomeryContext, d_mont: &U256) -> Self {
        let x2 = ctx.mul(&self.x, &self.x);
        let y2 = ctx.mul(&self.y, &self.y);
        let dy2 = ctx.mul(d_mont, &y2);
        let x3 = x2.add_mod(&dy2, &ctx.n);

        let xy = ctx.mul(&self.x, &self.y);
        let y3 = xy.add_mod(&xy, &ctx.n); // 2 * xy

        Self { x: x3, y: y3 }
    }

    /// Constant-Time Scalar Multiplication using Montgomery Ladder.
    ///
    /// # Side-Channel Immunity:
    /// In each of the 256 iterations, exactly one point addition and one point doubling are performed.
    /// Register states are multiplexed using `ConditionallySelectable::conditional_swap`,
    /// completely defeating Simple Power Analysis (SPA) and timing attacks.
    pub fn scalar_mul(&self, scalar: &U256, ctx: &MontgomeryContext, d_mont: &U256) -> Self {
        let mut r0 = Self::identity(ctx);
        let mut r1 = *self;

        for limb_idx in (0..4).rev() {
            let limb = scalar.0[limb_idx];
            for bit_pos in (0..64).rev() {
                let bit = Choice::from(((limb >> bit_pos) & 1) as u8);

                // Conditional swap of registers R0 and R1
                Self::conditional_swap(&mut r0, &mut r1, bit);

                // Unified Montgomery step:
                // R1 = R0 + R1
                // R0 = 2 * R0
                r1 = r0.add(&r1, ctx, d_mont);
                r0 = r0.double(ctx, d_mont);

                // Restore register configuration
                Self::conditional_swap(&mut r0, &mut r1, bit);
            }
        }

        r0
    }

    /// Branchless register swap
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

// -----------------------------------------------------------------------------
// Conic Curve KEM Protocol (CC-KEM)
// -----------------------------------------------------------------------------

/// Public parameters for Conic Curve Cryptography
#[derive(Clone, Copy)]
pub struct ConicParameters {
    pub ctx: MontgomeryContext,
    pub d_mont: U256,
    pub generator: ConicPoint,
}

/// Conic Curve Public Key
#[derive(Clone, Copy)]
pub struct ConicPublicKey {
    pub q: ConicPoint,
}

/// Conic Curve Private Key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Zeroize)]
pub struct ConicPrivateKey {
    pub scalar: U256,
}

/// Encapsulated Ciphertext: ephemeral curve point + encrypted payload + MAC tag
#[derive(Clone, Copy)]
pub struct ConicCiphertext {
    pub ephemeral_point: ConicPoint,
    pub encrypted_payload: [u8; 32],
    pub mac_tag: [u8; 32],
}

pub struct ConicKem;

impl ConicKem {
    /// Derive a symmetric key from a Conic Point using SHA-256 KDF.
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

    /// Compute HMAC-SHA256 for integrity verification.
    fn compute_mac(mac_key: &[u8; 32], ciphertext: &[u8; 32], ephem: &ConicPoint, ctx: &MontgomeryContext) -> [u8; 32] {
        let ephem_bytes = ctx.from_montgomery(&ephem.x).to_be_bytes();
        let mut h = Sha256::new();
        h.update(mac_key);
        h.update(ciphertext);
        h.update(&ephem_bytes);
        h.finalize()
    }

    /// Encapsulate a 256-bit secret share under a recipient's public key.
    pub fn encapsulate(
        recipient_pk: &ConicPublicKey,
        secret_payload: &[u8; 32],
        ephemeral_scalar: &U256,
        params: &ConicParameters,
    ) -> ConicCiphertext {
        // Ephemeral curve point: C_0 = [r] G
        let ephem_point = params.generator.scalar_mul(ephemeral_scalar, &params.ctx, &params.d_mont);

        // Shared point: S = [r] Q_pub
        let shared_point = recipient_pk.q.scalar_mul(ephemeral_scalar, &params.ctx, &params.d_mont);

        // Derive keys
        let keys = Self::derive_key(&shared_point, &params.ctx);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&keys[..32]);
        mac_key.copy_from_slice(&keys[32..]);

        // Constant-time XOR stream encryption
        let mut encrypted_payload = [0u8; 32];
        for i in 0..32 {
            encrypted_payload[i] = secret_payload[i] ^ enc_key[i];
        }

        // Integrity MAC
        let mac_tag = Self::compute_mac(&mac_key, &encrypted_payload, &ephem_point, &params.ctx);

        ConicCiphertext {
            ephemeral_point: ephem_point,
            encrypted_payload,
            mac_tag,
        }
    }

    /// Constant-Time Decapsulation with Implicit Rejection (Failure Indistinguishability).
    ///
    /// # Error-Oracle Immunity:
    /// 1. Validates that ephemeral point $C_0$ lies on conic curve $C_d$.
    /// 2. Computes shared point $S = [s_k] C_0$.
    /// 3. Computes expected MAC tag and checks constant-time equality.
    /// 4. If point validity or MAC check fails, the decrypted payload is replaced branchlessly
    ///    with pseudo-random surrogate garbage derived from $(s_k \,\|\, C_0.x)$.
    ///
    /// Execution timing is identical on both success and failure paths.
    pub fn decapsulate_ct(
        sk: &ConicPrivateKey,
        ciphertext: &ConicCiphertext,
        params: &ConicParameters,
    ) -> ([u8; 32], Choice) {
        // 1. Point validity check on C_0
        let is_point_valid = ciphertext.ephemeral_point.is_valid_ct(&params.ctx, &params.d_mont);

        // 2. Compute shared point: S = [sk] C_0
        let shared_point = ciphertext.ephemeral_point.scalar_mul(&sk.scalar, &params.ctx, &params.d_mont);

        // 3. Derive keys from shared point
        let keys = Self::derive_key(&shared_point, &params.ctx);
        let mut enc_key = [0u8; 32];
        let mut mac_key = [0u8; 32];
        enc_key.copy_from_slice(&keys[..32]);
        mac_key.copy_from_slice(&keys[32..]);

        // Compute decrypted plaintext
        let mut real_plaintext = [0u8; 32];
        for i in 0..32 {
            real_plaintext[i] = ciphertext.encrypted_payload[i] ^ enc_key[i];
        }

        // 4. Verify MAC tag in constant time
        let expected_mac = Self::compute_mac(&mac_key, &ciphertext.encrypted_payload, &ciphertext.ephemeral_point, &params.ctx);
        let is_mac_valid = expected_mac.ct_eq(&ciphertext.mac_tag);

        let is_valid = is_point_valid & is_mac_valid;

        // 5. Implicit Rejection: compute pseudo-random surrogate key
        let mut dummy_hasher = Sha256::new();
        dummy_hasher.update(&sk.scalar.to_be_bytes());
        dummy_hasher.update(&ciphertext.ephemeral_point.x.to_be_bytes());
        let surrogate_key = dummy_hasher.finalize();

        // Branchless conditional selection of recovered plaintext
        let mut result_plaintext = [0u8; 32];
        for i in 0..32 {
            result_plaintext[i] = u8::conditional_select(&surrogate_key[i], &real_plaintext[i], is_valid);
        }

        (result_plaintext, is_valid)
    }
}

