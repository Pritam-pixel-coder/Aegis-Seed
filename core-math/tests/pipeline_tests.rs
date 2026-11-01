//! Exhaustive Unit Tests for core-math crate

use core_math::{
    default_conic_parameters, Bip39MasterEntropy, ConicKem, ConicPrivateKey, ConicPublicKey,
    Gf2048, Gf256, Gf2Vector, Matrix, ReedSolomonGf2048, ThresholdScheme, U256,
};

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
    assert_eq!(parsed.entropy, reparsed.entropy);
    assert_eq!(parsed.checksum, reparsed.checksum);
}

#[test]
fn test_layer2_gf256_arithmetic_and_inversion() {
    let a = Gf256::new(0x57);
    assert_eq!(a + Gf256::ZERO, a);
    assert_eq!(a * Gf256::ONE, a);

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
        ],
    };
    let (inv, is_invertible) = mat.invert_ct();
    assert_eq!(is_invertible.unwrap_u8(), 1);

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
    let coeffs = [[0x11; 32], [0x22; 32]];
    let shares = ThresholdScheme::split(&secret, 3, 5, &coeffs);

    let chosen = [shares[0], shares[1], shares[3]];
    let recovered = ThresholdScheme::reconstruct::<3>(&chosen);
    assert_eq!(recovered, secret);

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
        12, 45, 999, 2041, 100, 3, 50, 77, 88, 99, 101, 202, 303, 404, 505, 606, 707, 808, 909,
        1010, 1111, 1212, 1313, 1414,
    ];

    let codeword = rs.encode(&words);

    let (decoded_clean, ok_clean) = rs.decode_and_correct_ct(&codeword);
    assert_eq!(ok_clean.unwrap_u8(), 1);
    assert_eq!(decoded_clean, words);

    let mut corrupted = codeword;
    corrupted[13] ^= 0x4B3;
    let (decoded_corrupted, ok_corrupted) = rs.decode_and_correct_ct(&corrupted);
    assert_eq!(ok_corrupted.unwrap_u8(), 1);
    assert_eq!(
        decoded_corrupted, words,
        "Failed to correct corrupted symbol at index 13"
    );
}

#[test]
fn test_layer4_conic_kem_cycle() {
    let params = default_conic_parameters();

    let sk = ConicPrivateKey {
        scalar: U256([0xdead_beef_0001, 0, 0, 0]),
    };
    let pk = ConicPublicKey {
        q: params
            .generator
            .scalar_mul(&sk.scalar, &params.ctx, &params.d_mont),
    };

    let payload = [0xFE; 32];
    let ephem = U256([0xcafe_babe_0002, 0, 0, 0]);

    let ct = ConicKem::encapsulate(&pk, &payload, &ephem, &params);
    let (decrypted, is_valid) = ConicKem::decapsulate_ct(&sk, &ct, &params);

    assert_eq!(is_valid.unwrap_u8(), 1);
    assert_eq!(decrypted, payload);

    let mut corrupted_ct = ct;
    corrupted_ct.mac_tag[0] ^= 1;
    let (garbage, is_corrupt_valid) = ConicKem::decapsulate_ct(&sk, &corrupted_ct, &params);
    assert_eq!(is_corrupt_valid.unwrap_u8(), 0);
    assert_ne!(garbage, payload);
}
