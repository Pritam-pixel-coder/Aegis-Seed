//! Aegis-Seed: Exhaustive Mathematical & Constant-Time Unit Tests

use aegis_seed::{
    layer1_bip39::{Bip39MasterEntropy, Gf2Vector},
    layer2_gf256::{Gf256, Matrix, SecretShare, ThresholdScheme},
    layer3_gf2048::{Gf2048, ReedSolomonGf2048},
    layer4_conic_kem::{
        ConicKem, ConicPrivateKey, ConicPublicKey, U256,
    },
    layer5_mem_guard::ProtectedMemory,
    AegisPipeline,
};
use subtle::ConstantTimeEq;

#[test]
fn test_layer1_vector_and_bip39() {
    let mut v = Gf2Vector::<32>::zero();
    assert_eq!(v.get_bit(0), 0);
    v.set_bit(0, 1);
    assert_eq!(v.get_bit(0), 1);
    v.set_bit(15, 1);
    assert_eq!(v.get_bit(15), 1);

    let raw = [0x5A; 32];
    let parsed = Bip39MasterEntropy::from_raw_entropy(&raw);
    let (reparsed, is_valid) = Bip39MasterEntropy::from_word_indices_ct(&parsed.word_indices);
    assert_eq!(is_valid.unwrap_u8(), 1);
    assert_eq!(parsed.entropy.to_bytes(), reparsed.entropy.to_bytes());
    assert_eq!(parsed.checksum, reparsed.checksum);
}

#[test]
fn test_layer2_gf256_arithmetic_and_inversion() {
    // 0 is additive identity
    let a = Gf256::new(0x57);
    assert_eq!(a + Gf256::ZERO, a);

    // Multiplication by 1
    assert_eq!(a * Gf256::ONE, a);

    // Inversion: a * a^{-1} == 1 for non-zero a
    for v in 1..=255 {
        let elem = Gf256::new(v);
        let inv = elem.invert();
        assert_eq!((elem * inv).0, 1, "Failed inverse for 0x{:02x}", v);
    }
}

#[test]
fn test_layer2_gaussian_elimination() {
    let mat = Matrix::<3> {
        data: [
            [Gf256::new(2), Gf256::new(1), Gf256::new(0)],
            [Gf256::new(1), Gf256::new(3), Gf256::new(2)],
            [Gf256::new(0), Gf256::new(1), Gf256::new(1)],
        ]
    };
    let (inv, is_invertible) = mat.invert_ct();
    assert_eq!(is_invertible.unwrap_u8(), 1);

    // Multiply mat * inv: should equal Identity
    for r in 0..3 {
        for c in 0..3 {
            let mut sum = Gf256::ZERO;
            for k in 0..3 {
                sum += mat.data[r][k] * inv.data[k][c];
            }
            let expected = if r == c { Gf256::ONE } else { Gf256::ZERO };
            assert_eq!(sum, expected, "Mismatch at ({}, {})", r, c);
        }
    }
}

#[test]
fn test_layer2_threshold_scheme() {
    let secret = [0x99; 32];
    let coeffs = [[0x11; 32], [0x22; 32]]; // t=3 (2 coefficient blocks)
    let shares = ThresholdScheme::split(&secret, 3, 5, &coeffs);

    // Reconstruct with any 3 shares: Share 1, Share 2, Share 4
    let chosen = [shares[0], shares[1], shares[3]];
    let recovered = ThresholdScheme::reconstruct::<3>(&chosen);
    assert_eq!(recovered, secret);

    // Reconstruct with another combination: Share 2, Share 3, Share 5
    let chosen2 = [shares[1], shares[2], shares[4]];
    let recovered2 = ThresholdScheme::reconstruct::<3>(&chosen2);
    assert_eq!(recovered2, secret);
}

#[test]
fn test_layer3_gf2048_arithmetic() {
    let a = Gf2048::new(1337);
    let a_inv = a.invert();
    assert_eq!((a * a_inv).0, 1);
}

#[test]
fn test_layer3_reed_solomon_error_correction() {
    let rs = ReedSolomonGf2048::new();
    let words = [
        12, 45, 999, 2041, 100, 3, 50, 77,
        88, 99, 101, 202, 303, 404, 505, 606,
        707, 808, 909, 1010, 1111, 1212, 1313, 1414,
    ];

    let codeword = rs.encode(&words);

    // Clean decode
    let (decoded_clean, ok_clean) = rs.decode_and_correct_ct(&codeword);
    assert_eq!(ok_clean.unwrap_u8(), 1);
    assert_eq!(decoded_clean, words);

    // Corrupt one symbol at position 13
    let mut corrupted = codeword;
    corrupted[13] ^= 0x4B3; // Invert multiple bits
    let (decoded_corrupted, ok_corrupted) = rs.decode_and_correct_ct(&corrupted);
    assert_eq!(ok_corrupted.unwrap_u8(), 1);
    assert_eq!(decoded_corrupted, words, "Failed to correct corrupted symbol at index 13");
}

#[test]
fn test_layer4_conic_kem_cycle() {
    let params = AegisPipeline::default_conic_parameters();

    let sk = ConicPrivateKey {
        scalar: U256([0xdead_beef_0001, 0, 0, 0]),
    };
    let pk = ConicPublicKey {
        q: params.generator.scalar_mul(&sk.scalar, &params.ctx, &params.d_mont),
    };

    let payload = [0xFE; 32];
    let ephem = U256([0xcafe_babe_0002, 0, 0, 0]);

    let ct = ConicKem::encapsulate(&pk, &payload, &ephem, &params);
    let (decrypted, is_valid) = ConicKem::decapsulate_ct(&sk, &ct, &params);

    assert_eq!(is_valid.unwrap_u8(), 1);
    assert_eq!(decrypted, payload);

    // Test rejection on tampered tag
    let mut corrupted_ct = ct;
    corrupted_ct.mac_tag[0] ^= 1;
    let (garbage, is_corrupt_valid) = ConicKem::decapsulate_ct(&sk, &corrupted_ct, &params);
    assert_eq!(is_corrupt_valid.unwrap_u8(), 0);
    assert_ne!(garbage, payload);
}

#[test]
fn test_layer5_protected_memory() {
    let secret = [0x77u8; 32];
    {
        let prot = ProtectedMemory::new(secret);
        assert_eq!(&prot[..], &secret[..]);
    }
}

