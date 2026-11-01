//! Layer 3: Number-Theoretic Fault Tolerance over $\mathrm{GF}(2^{11})$
//!
//! Provides systematic Reed-Solomon encoding and constant-time single-word error correction
//! for BIP-39 11-bit word indices over $\mathrm{GF}(2^{11}) = \mathbb{F}_2[x] / (x^{11} + x^2 + 1)$.
//!
//! # Mathematical Foundations:
//! - Field Order: $q = 2^{11} = 2048$, exactly matching the 2048 BIP-39 word indices $[0, 2047]$.
//! - Primitive Polynomial: $P_{11}(x) = x^{11} + x^2 + 1$ ($0\mathrm{x}805$).
//! - Primitive Element: $\alpha = x$ (represented as integer 2).
//! - Code Parameters: $(N=26, K=24, d_{\min}=3)$.
//!   Allows deterministic detection and correction of $t=1$ corrupted or mistyped word index
//!   without leaking error locations or validity through timing side-channels.

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Finite Field Element in $\mathrm{GF}(2^{11}) = \mathbb{F}_2[x] / (x^{11} + x^2 + 1)$.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Zeroize)]
pub struct Gf2048(pub u16);

impl Gf2048 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    /// Primitive element $\alpha = x$
    pub const ALPHA: Self = Self(2);
    /// Irreducible reduction polynomial constant: $x^2 + 1 = 5$
    pub const POLY_LOW: u16 = 5;

    #[inline(always)]
    pub fn new(val: u16) -> Self {
        Self(val & 0x7FF) // 11-bit mask
    }

    /// Constant-Time Carryless Multiplication in $\mathrm{GF}(2^{11})$.
    ///
    /// # Algorithm:
    /// Executes 11 uniform bit-serial iterations.
    /// In each step, if bit $b_i$ is 1, $a(x) \cdot x^i$ is XORed into result.
    /// Modulo reduction by $x^{11} \equiv x^2 + 1 = 5$ is applied when bit 10 overflows.
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

    /// Constant-time squaring in $\mathrm{GF}(2^{11})$.
    #[inline(always)]
    pub fn square(self) -> Self {
        self.ct_mul(self)
    }

    /// Constant-time Field Inversion using Fermat's Little Theorem.
    ///
    /// In $\mathrm{GF}(2^{11})$, $a^{2^{11}-1} = a^{2047} = 1 \implies a^{-1} = a^{2046}$.
    /// Exponent $2046 = (11111111110)_2$.
    /// Executed with a uniform 11-step square-and-multiply ladder.
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

    /// Constant-time exponentiation: $a^e$
    pub fn pow(self, exp: u16) -> Self {
        let mut res = Self::ONE;
        let mut base = self;
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

impl AddAssign for Gf2048 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl Sub for Gf2048 {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs
    }
}

impl SubAssign for Gf2048 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self += rhs;
    }
}

impl Mul for Gf2048 {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        self.ct_mul(rhs)
    }
}

impl MulAssign for Gf2048 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.ct_mul(rhs);
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

// -----------------------------------------------------------------------------
// Systematic Reed-Solomon Code (N=26, K=24) over GF(2^11)
// -----------------------------------------------------------------------------

pub const RS_K: usize = 24; // 24 BIP-39 word indices
pub const RS_PARITY: usize = 2; // 2 parity symbols for single-word error correction
pub const RS_N: usize = RS_K + RS_PARITY; // 26 total symbols

/// Fault-tolerant Systematic Reed-Solomon Codec for 24-word BIP-39 phrases.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ReedSolomonGf2048 {
    /// Generator polynomial coefficients: $g(x) = (x - \alpha)(x - \alpha^2) = x^2 + g_1 x + g_0$
    g0: Gf2048,
    g1: Gf2048,
}

impl ReedSolomonGf2048 {
    /// Initialize Reed-Solomon generator polynomial.
    /// $g(x) = (x - \alpha)(x - \alpha^2) = x^2 + (\alpha + \alpha^2) x + \alpha^3$
    pub fn new() -> Self {
        let a1 = Gf2048::ALPHA;
        let a2 = a1.square();
        let a3 = a1.ct_mul(a2);

        Self {
            g0: a3,
            g1: a1 + a2,
        }
    }

    /// Systematically encode 24 word indices into a 26-symbol codeword:
    /// Codeword: $[c_0, c_1, \dots, c_{23}, p_0, p_1]$ where $p_0, p_1$ are the parity symbols.
    ///
    /// # Mathematical Formulation:
    /// $M(x) = \sum_{i=0}^{23} m_i x^{i+2}$
    /// $P(x) = M(x) \pmod{g(x)} = p_1 x + p_0$
    /// $C(x) = M(x) + P(x)$
    pub fn encode(&self, words: &[u16; RS_K]) -> [u16; RS_N] {
        let mut rem = [Gf2048::ZERO; 2];

        // Synthetic division / LFSR
        for &w in words.iter() {
            let symbol = Gf2048::new(w);
            let feedback = symbol + rem[1];
            rem[1] = rem[0] + feedback * self.g1;
            rem[0] = feedback * self.g0;
        }

        let mut codeword = [0u16; RS_N];
        // Systematic placement: original 24 words followed by 2 parity symbols
        codeword[..RS_K].copy_from_slice(words);
        codeword[RS_K] = rem[1].0; // p_1
        codeword[RS_K + 1] = rem[0].0; // p_0

        codeword
    }

    /// Constant-Time Syndrome Evaluation & Single-Word Error Correction.
    ///
    /// # Error-Oracle Immune Correction:
    /// 1. Evaluates syndromes $S_1 = C(\alpha)$ and $S_2 = C(\alpha^2)$.
    /// 2. If $S_1 = 0 \land S_2 = 0$, no errors exist.
    /// 3. If single error $e$ at location $j$, $S_1 = e \alpha^j$ and $S_2 = e \alpha^{2j} \implies S_2 / S_1 = \alpha^j$.
    /// 4. Iterates over ALL $N=26$ symbol positions uniformly. For each position $k$, checks branchlessly
    ///    if $\alpha^k == S_2 / S_1$, and conditionally subtracts $e$ from codeword.
    ///
    /// Returns `(corrected_words, is_valid_choice)`.
    pub fn decode_and_correct_ct(&self, received: &[u16; RS_N]) -> ([u16; RS_K], Choice) {
        let mut symbols = [Gf2048::ZERO; RS_N];
        for i in 0..RS_N {
            symbols[i] = Gf2048::new(received[i]);
        }

        // 1. Evaluate Syndromes using Horner's rule
        // S1 = \sum symbols[i] * \alpha^(N - 1 - i)
        let a1 = Gf2048::ALPHA;
        let a2 = a1.square();

        let mut s1 = Gf2048::ZERO;
        let mut s2 = Gf2048::ZERO;
        for i in 0..RS_N {
            s1 = s1 * a1 + symbols[i];
            s2 = s2 * a2 + symbols[i];
        }

        let no_errors = s1.ct_eq(&Gf2048::ZERO) & s2.ct_eq(&Gf2048::ZERO);

        // 2. Compute error locator ratio: target_locator = S2 / S1
        let s1_inv = s1.invert();
        let target_locator = s2 * s1_inv;

        // 3. Constant-Time Locator Scan over all 26 positions
        // Power of alpha for position (from highest degree N-1 down to 0)
        let mut current_locator = Gf2048::ONE;
        let mut error_found = Choice::from(0);

        // Scan in reverse order corresponding to polynomial evaluation
        for i in (0..RS_N).rev() {
            let is_error_pos = current_locator.ct_eq(&target_locator) & (!s1.ct_eq(&Gf2048::ZERO));
            error_found |= is_error_pos;

            // Error magnitude at this position: e = S1 / alpha^(exponent)
            let loc_inv = current_locator.invert();
            let error_magnitude = s1 * loc_inv;

            let corrected_sym = symbols[i] + error_magnitude;
            symbols[i] = Gf2048::conditional_select(&symbols[i], &corrected_sym, is_error_pos);

            current_locator = current_locator * a1;
        }

        // 4. Verify syndrome on corrected symbols in constant time
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

