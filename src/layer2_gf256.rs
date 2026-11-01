//! Layer 2: Linear-Algebraic Secret Sharing over $\mathrm{GF}(2^8)$
//!
//! Implements constant-time finite field arithmetic in $\mathrm{GF}(2^8)$ using the Rijndael
//! irreducible polynomial $P(x) = x^8 + x^4 + x^3 + x + 1$ ($0\mathrm{x}11\mathrm{B}$).
//!
//! # Side-Channel Defenses:
//! 1. ZERO secret-dependent table lookups: Replaces vulnerable $\mathrm{EXP}/\mathrm{LOG}$ S-box tables
//!    with bit-serial carryless multiplication.
//! 2. Inversion computed via Fermat's Little Theorem ($a^{-1} = a^{254}$) using a fixed
//!    addition chain.
//! 3. Branchless Gaussian elimination with constant-time row pivoting via `ConditionallySelectable`.
//! 4. $(t, n)$ Threshold Secret Sharing for 256-bit secrets.

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// Finite Field element in $\mathrm{GF}(2^8) = \mathbb{F}_2[x] / (x^8 + x^4 + x^3 + x + 1)$.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Zeroize)]
pub struct Gf256(pub u8);

impl Gf256 {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    /// Irreducible reduction polynomial modulo: $x^8 + x^4 + x^3 + x + 1$
    pub const POLY: u8 = 0x1B;

    #[inline(always)]
    pub fn new(val: u8) -> Self {
        Self(val)
    }

    /// Constant-time carryless multiplication in $\mathrm{GF}(2^8)$.
    ///
    /// # Mathematical Formulation:
    /// $a(x) \cdot b(x) = \sum_{i=0}^7 b_i \cdot (a(x) \cdot x^i \pmod{P(x)})$
    ///
    /// Runs in exactly 8 uniform iterations. Zero cache lookups. Zero secret branching.
    #[inline(always)]
    pub fn ct_mul(self, rhs: Self) -> Self {
        let mut res = 0u8;
        let mut temp_a = self.0;
        let b = rhs.0;

        for i in 0..8 {
            let bit = (b >> i) & 1;
            // Branchless conditional accumulation: if bit == 1 then res ^= temp_a
            let mask = (bit as u8).wrapping_neg();
            res ^= temp_a & mask;

            // Compute temp_a * x mod P(x)
            let hi_bit = (temp_a >> 7) & 1;
            let hi_mask = (hi_bit as u8).wrapping_neg();
            temp_a = (temp_a << 1) ^ (Self::POLY & hi_mask);
        }

        Self(res)
    }

    /// Constant-time squaring in $\mathrm{GF}(2^8)$.
    #[inline(always)]
    pub fn square(self) -> Self {
        self.ct_mul(self)
    }

    /// Constant-time field inversion using Fermat's Little Theorem.
    ///
    /// In any finite field $\mathbb{F}_q$, $a^{q-1} = 1 \implies a^{-1} = a^{q-2}$.
    /// Here $q = 2^8 = 256$, so $a^{-1} = a^{254}$.
    ///
    /// Addition chain for $254 = (11111110)_2$:
    /// Requires exactly 7 squarings and 6 multiplications.
    pub fn invert(self) -> Self {
        let a = self;
        let a2 = a.square();               // a^2
        let a3 = a2.ct_mul(a);             // a^3
        let a6 = a3.square();              // a^6
        let a7 = a6.ct_mul(a);             // a^7
        let a14 = a7.square();             // a^14
        let a15 = a14.ct_mul(a);           // a^15
        let a30 = a15.square();            // a^30
        let a31 = a30.ct_mul(a);           // a^31
        let a62 = a31.square();            // a^62
        let a63 = a62.ct_mul(a);           // a^63
        let a126 = a63.square();           // a^126
        let a127 = a126.ct_mul(a);         // a^127
        let a254 = a127.square();          // a^254

        // If self == 0, 0^254 evaluates to 0 (well-defined algebraic behavior)
        a254
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
        self + rhs // In characteristic 2, addition is subtraction
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

// -----------------------------------------------------------------------------
// Constant-Time Linear Algebra & Gaussian Elimination over GF(2^8)
// -----------------------------------------------------------------------------

/// Maximum matrix dimension for threshold secret sharing operations
pub const MAX_SHARES: usize = 16;
pub const MAX_MATRIX_DIM: usize = 8;
pub const MAX_AUGMENTED_COLS: usize = 16;

/// Square matrix over $\mathrm{GF}(2^8)$ of dimension $K \times K$.
#[derive(Clone, Copy)]
pub struct Matrix<const K: usize> {
    pub data: [[Gf256; K]; K],
}

impl<const K: usize> Matrix<K> {
    /// Identity matrix of size $K \times K$.
    pub fn identity() -> Self {
        let mut mat = Self {
            data: [[Gf256::ZERO; K]; K],
        };
        for i in 0..K {
            mat.data[i][i] = Gf256::ONE;
        }
        mat
    }

    /// Invert the matrix using Branchless Gaussian Elimination over $\mathrm{GF}(2^8)$.
    ///
    /// # Constant-Time Properties:
    /// - Performs full augmented elimination $[M \mid I_K] \to [I_K \mid M^{-1}]$.
    /// - Pivot selection scans ALL candidate rows branchlessly, swapping using `conditional_swap`.
    /// - Normalization and row eliminations execute identical operations across all elements.
    /// - Returns `(Matrix, Choice)` where Choice indicates whether the matrix is non-singular.
    pub fn invert_ct(&self) -> (Self, Choice) {
        assert!(K <= MAX_MATRIX_DIM, "K exceeds MAX_MATRIX_DIM");
        let double_k = 2 * K;

        // Augmented matrix: size K x 2K using fixed stack buffer for no_std compatibility
        let mut aug = [[Gf256::ZERO; MAX_AUGMENTED_COLS]; MAX_MATRIX_DIM];
        for r in 0..K {
            for c in 0..K {
                aug[r][c] = self.data[r][c];
            }
            aug[r][K + r] = Gf256::ONE;
        }

        let mut is_invertible = Choice::from(1);

        for r in 0..K {
            // 1. Branchless Pivot Selection:
            // Find a non-zero entry in column r at or below row r.
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

            // If pivot is still zero, the matrix is singular
            is_invertible &= !pivot_is_zero;

            // 2. Scale Pivot Row to make aug[r][r] == 1
            let inv_pivot = pivot_val.invert();
            for c in 0..double_k {
                aug[r][c] = aug[r][c] * inv_pivot;
            }

            // 3. Branchlessly Eliminate all other rows in column r
            for other_r in 0..K {
                let factor = aug[other_r][r];
                // Do not eliminate pivot row with itself
                let is_different = Choice::from(((other_r != r) as u8) & 1);
                let effective_factor = Gf256::conditional_select(&Gf256::ZERO, &factor, is_different);

                for c in 0..double_k {
                    let subtrahend = effective_factor * aug[r][c];
                    aug[other_r][c] += subtrahend;
                }
            }
        }

        // Extract inverted matrix from the right-hand half
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

// -----------------------------------------------------------------------------
// Constant-Time (t, n) Threshold Secret Sharing over GF(2^8)
// -----------------------------------------------------------------------------

/// Single share containing an evaluation point $x \neq 0$ and 32 bytes of shared evaluations.
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
}

/// Constant-time (t, n) Threshold Secret Sharing Engine
pub struct ThresholdScheme;

impl ThresholdScheme {
    /// Split a 256-bit secret into `n` shares with threshold `t`.
    ///
    /// # Mathematical Formulation:
    /// For each secret byte $s_k \in \mathrm{GF}(2^8)$ where $k \in \{0, \dots, 31\}$:
    /// Construct random polynomial $P_k(x) = s_k + \sum_{j=1}^{t-1} a_{k, j} x^j$.
    /// Evaluate $P_k(x_i)$ for distinct evaluation points $x_i \in \{1, \dots, n\}$.
    ///
    /// # Constant-Time Guarantee:
    /// Uses Horner's polynomial evaluation with uniform arithmetic operations.
    pub fn split(
        secret: &[u8; 32],
        threshold: usize,
        total_shares: usize,
        coefficients: &[[u8; 32]], // Array of (t-1) coefficient blocks
    ) -> [SecretShare; MAX_SHARES] {
        assert!(threshold >= 2 && threshold <= total_shares && total_shares <= MAX_SHARES);
        let mut shares = [SecretShare::empty(); MAX_SHARES];

        for i in 0..total_shares {
            let x_coord = Gf256::new((i + 1) as u8);
            shares[i].x = x_coord;

            for byte_idx in 0..32 {
                let s_byte = Gf256::new(secret[byte_idx]);
                // Horner's method: evaluate P(x) = s + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}
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

    /// Reconstruct 256-bit secret from any $T$ shares using constant-time Lagrange interpolation.
    ///
    /// # Lagrange Reconstruction Formula:
    /// $S = \sum_{i=0}^{T-1} y_i \cdot \ell_i(0)$, where:
    /// $\ell_i(0) = \prod_{j \neq i} \frac{x_j}{x_j \oplus x_i} = \prod_{j \neq i} x_j \cdot (x_j \oplus x_i)^{-1}$
    ///
    /// Completely branchless. Executes identical arithmetic independent of share contents.
    pub fn reconstruct<const T: usize>(shares: &[SecretShare; T]) -> [u8; 32] {
        let mut secret = [0u8; 32];

        // 1. Precalculate Lagrange basis coefficients $\ell_i(0)$ in constant time
        let mut basis = [Gf256::ONE; T];
        for i in 0..T {
            let xi = shares[i].x;
            let mut num = Gf256::ONE;
            let mut den = Gf256::ONE;

            for j in 0..T {
                let is_diff = Choice::from(((i != j) as u8) & 1);
                let xj = shares[j].x;
                let diff = xj + xi;

                // If j != i, multiply numerator by xj and denominator by (xj + xi)
                let factor_num = Gf256::conditional_select(&Gf256::ONE, &xj, is_diff);
                let factor_den = Gf256::conditional_select(&Gf256::ONE, &diff, is_diff);

                num *= factor_num;
                den *= factor_den;
            }

            basis[i] = num * den.invert();
        }

        // 2. Compute Secret = \sum y_i * \ell_i(0) for all 32 bytes
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
