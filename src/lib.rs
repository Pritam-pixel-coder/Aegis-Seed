//! # Aegis-Seed: Side-Channel Resistant Cryptographic System
//!
//! A high-assurance, `#![no_std]`, constant-time cryptographic library designed
//! to securely vectorize, fault-tolerantly encode, threshold-share, and conic-curve encapsulate
//! BIP-39 cryptocurrency master seed phrases.
//!
//! # Architecture:
//! - **Layer 1**: Entropy Extraction, Checksum Verification & $\mathrm{GF}(2)$ Vectorization.
//! - **Layer 2**: Linear-Algebraic Secret Sharing over $\mathrm{GF}(2^8)$ with branchless Gaussian Elimination.
//! - **Layer 3**: Number-Theoretic Fault Tolerance over $\mathrm{GF}(2^{11})$ via Systematic Reed-Solomon coding.
//! - **Layer 4**: Conic Curve Key Encapsulation Mechanism (CC-DLP KEM) with constant-time implicit rejection.
//! - **Layer 5**: Hardware-enforced memory isolation (`memfd_secret`, `VirtualLock`, `mlock`, `ZeroizeOnDrop`).

#![no_std]

#[cfg(feature = "std")]
extern crate std;

pub mod ct_sha256;
pub mod layer1_bip39;
pub mod layer2_gf256;
pub mod layer3_gf2048;
pub mod layer4_conic_kem;
pub mod layer5_mem_guard;

// Re-exports for convenient top-level access
pub use ct_sha256::Sha256;
pub use layer1_bip39::{Bip39MasterEntropy, Gf2Vector, Layer1Error};
pub use layer2_gf256::{Gf256, Matrix, SecretShare, ThresholdScheme};
pub use layer3_gf2048::{Gf2048, ReedSolomonGf2048};
pub use layer4_conic_kem::{
    ConicCiphertext, ConicKem, ConicParameters, ConicPoint, ConicPrivateKey, ConicPublicKey,
    MontgomeryContext, U256,
};
pub use layer5_mem_guard::ProtectedMemory;

/// Complete Pipeline Execution Context
pub struct AegisPipeline;

impl AegisPipeline {
    /// Standard curve parameters for 256-bit Conic Curve over prime $P = 2^{255} - 19$.
    ///
    /// Modulus $P = 2^{255} - 19$ is an odd prime.
    /// Quadratic non-residue $d = 2$.
    pub fn default_conic_parameters() -> ConicParameters {
        // P = 2^255 - 19:
        // 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        let p_bytes: [u8; 32] = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
        ];
        let p = U256::from_be_bytes(&p_bytes);

        // Precomputed Montgomery constants:
        // N' = -P^{-1} mod 2^64
        let n_prime = MontgomeryContext::compute_n_prime(p.0[0]);

        // R^2 mod P where R = 2^256: (2^512 mod P)
        // Since 2^255 = 19 mod P: 2^256 = 38 mod P.
        // 2^512 = 38^2 = 1444 mod P.
        let r2 = U256([1444, 0, 0, 0]);

        let ctx = MontgomeryContext { n: p, n_prime, r2 };

        // d = 2
        let d = U256([2, 0, 0, 0]);
        let d_mont = ctx.to_montgomery(&d);

        // Standard Generator point G = (3, 2) on C_d:
        // Check: 3^2 - 2 * 2^2 = 9 - 8 = 1 mod P. Exactly satisfies x^2 - d y^2 = 1!
        let g_x = ctx.to_montgomery(&U256([3, 0, 0, 0]));
        let g_y = ctx.to_montgomery(&U256([2, 0, 0, 0]));

        ConicParameters {
            ctx,
            d_mont,
            generator: ConicPoint { x: g_x, y: g_y },
        }
    }
}

