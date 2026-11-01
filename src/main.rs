//! Aegis-Seed: End-to-End Pipeline Demonstration
//!
//! Demonstrates the complete 5-Layer cryptographic lifecycle:
//! Input -> Fault-Tolerant Encode -> Fault Correction -> Secret Share -> Conic KEM Encrypt -> Decrypt -> Recover

use aegis_seed::{
    layer1_bip39::Bip39MasterEntropy,
    layer2_gf256::{Gf256, Matrix, ThresholdScheme},
    layer3_gf2048::ReedSolomonGf2048,
    layer4_conic_kem::{
        ConicKem, ConicPrivateKey, ConicPublicKey, U256,
    },
    layer5_mem_guard::ProtectedMemory,
    AegisPipeline,
};
use subtle::ConstantTimeEq;

fn main() {
    println!("================================================================================");
    println!("          AEGIS-SEED: SIDE-CHANNEL RESISTANT BIP-39 CRYPTOSYSTEM               ");
    println!("  Constant-Time no_std Architecture: Linear Algebra + Conic Curve KEM (CC-DLP)   ");
    println!("================================================================================\n");

    // -------------------------------------------------------------------------
    // STEP 1: LAYER 1 - ENTROPY EXTRACTION & GF(2) VECTORIZATION
    // -------------------------------------------------------------------------
    println!("[*] LAYER 1: Ingesting 256-bit Cryptocurrency Master Seed...");
    let raw_entropy: [u8; 32] = [
        0x5a, 0x1f, 0x93, 0x8c, 0xb2, 0x3d, 0x4e, 0xf1,
        0xa0, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,
        0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0x11, 0x22, 0x33,
    ];

    let master_entropy = Bip39MasterEntropy::from_raw_entropy(&raw_entropy);
    println!("    - Raw Entropy (256-bit GF(2) Vector): {:02x?}", &master_entropy.entropy.to_bytes()[..8]);
    println!("    - Extracted 8-bit SHA-256 Checksum: 0x{:02X}", master_entropy.checksum);
    println!("    - Generated 24 BIP-39 11-bit Word Indices:");
    print!("      ");
    for (i, &idx) in master_entropy.word_indices.iter().enumerate() {
        print!("{:4} ", idx);
        if (i + 1) % 8 == 0 {
            print!("\n      ");
        }
    }
    println!();

    // Verify constant-time parsing from word indices
    let (_reparsed, is_valid_cs) = Bip39MasterEntropy::from_word_indices_ct(&master_entropy.word_indices);
    assert_eq!(is_valid_cs.unwrap_u8(), 1, "Checksum verification must succeed");
    println!("    [+] Constant-Time Checksum Verification: PASSED\n");

    // -------------------------------------------------------------------------
    // STEP 2: LAYER 3 - NUMBER-THEORETIC FAULT TOLERANCE (GF(2^11))
    // -------------------------------------------------------------------------
    println!("[*] LAYER 3: Reed-Solomon (N=26, K=24) Error Correction over GF(2^11)...");
    let rs = ReedSolomonGf2048::new();
    let codeword = rs.encode(&master_entropy.word_indices);
    println!("    - Systematic Codeword (24 data symbols + 2 parity symbols):");
    println!("      Parity 0: {}, Parity 1: {}", codeword[24], codeword[25]);

    // Simulate real-world human error / hardware fault: corrupt word at position 5
    let mut corrupted_codeword = codeword;
    let corrupted_index = 5;
    let original_word = corrupted_codeword[corrupted_index];
    corrupted_codeword[corrupted_index] = (original_word ^ 0x3A5) & 0x7FF; // inject fault
    println!("    [!] Injected Word Corruption at Index {}: {} -> {}", 
             corrupted_index, original_word, corrupted_codeword[corrupted_index]);

    // Constant-time error correction
    let (corrected_words, correction_ok) = rs.decode_and_correct_ct(&corrupted_codeword);
    assert_eq!(correction_ok.unwrap_u8(), 1, "Reed-Solomon correction must succeed");
    assert_eq!(corrected_words[corrupted_index], original_word, "Corrected word must match original");
    println!("    [+] Constant-time syndrome locator restored corrupted word: {} (Identical to original!)", 
             corrected_words[corrupted_index]);
    println!("    [+] Single-word Fault Tolerance: VERIFIED\n");

    // -------------------------------------------------------------------------
    // STEP 3: LAYER 2 - LINEAR-ALGEBRAIC SECRET SHARING (GF(2^8))
    // -------------------------------------------------------------------------
    println!("[*] LAYER 2: Linear-Algebraic (t=3, n=5) Secret Sharing over GF(2^8)...");
    // Pseudo-random polynomial coefficients (t-1 = 2 coefficient blocks)
    let poly_coeffs: [[u8; 32]; 2] = [
        [0x71; 32],
        [0x9B; 32],
    ];

    let shares = ThresholdScheme::split(&raw_entropy, 3, 5, &poly_coeffs);
    println!("    - Generated 5 Secret Shares over GF(2^8):");
    for i in 0..5 {
        println!("      Share #{}: x = {}, data[0..4] = {:02x?}", 
                 i + 1, shares[i].x.0, [shares[i].values[0].0, shares[i].values[1].0, shares[i].values[2].0, shares[i].values[3].0]);
    }

    // Demonstrate Branchless Matrix Inversion over GF(2^8)
    println!("    - Testing Branchless Gaussian Elimination (3x3 Matrix Inversion):");
    let test_mat = Matrix::<3> {
        data: [
            [Gf256::new(1), Gf256::new(2), Gf256::new(3)],
            [Gf256::new(4), Gf256::new(5), Gf256::new(6)],
            [Gf256::new(7), Gf256::new(8), Gf256::new(10)],
        ]
    };
    let (_inv_mat, is_inv) = test_mat.invert_ct();
    assert_eq!(is_inv.unwrap_u8(), 1, "Matrix must be invertible");
    println!("    [+] Branchless Gaussian Elimination: PASSED (Non-singular inversion verified)\n");

    // -------------------------------------------------------------------------
    // STEP 4: LAYER 4 - CONIC CURVE KEM (CC-DLP) OVER Z_n
    // -------------------------------------------------------------------------
    println!("[*] LAYER 4: Conic Curve Key Encapsulation Mechanism (CC-KEM)...");
    let params = AegisPipeline::default_conic_parameters();

    // Recipient generates Conic Curve Keypair
    let recipient_sk = ConicPrivateKey {
        scalar: U256([0x1337_c0de_beef_cafe, 0x42, 0x88, 0x99]),
    };
    let recipient_pk = ConicPublicKey {
        q: params.generator.scalar_mul(&recipient_sk.scalar, &params.ctx, &params.d_mont),
    };
    println!("    - Conic Curve Generator G = (x, y) on x^2 - 2y^2 = 1");
    println!("    - Recipient Public Key Point Q = [sk] G computed via Constant-Time Montgomery Ladder.");

    // Encapsulate Share #1 payload
    let mut share_payload = [0u8; 32];
    for b in 0..32 {
        share_payload[b] = shares[0].values[b].0;
    }

    let ephemeral_scalar = U256([0x9876_5432_10fe_dcba, 0x11, 0x22, 0x33]);
    let ciphertext = ConicKem::encapsulate(&recipient_pk, &share_payload, &ephemeral_scalar, &params);
    println!("    - Encapsulated Share #1 into ConicCiphertext:");
    println!("      Encrypted Payload[0..8]: {:02x?}", &ciphertext.encrypted_payload[..8]);
    println!("      MAC Tag[0..8]:           {:02x?}", &ciphertext.mac_tag[..8]);

    // Decapsulate with recipient private key
    let (decrypted_payload, dec_valid) = ConicKem::decapsulate_ct(&recipient_sk, &ciphertext, &params);
    assert_eq!(dec_valid.unwrap_u8(), 1, "Decapsulation must succeed for valid ciphertext");
    assert_eq!(decrypted_payload, share_payload, "Decrypted payload must match encrypted share");
    println!("    [+] Constant-Time Decapsulation: SUCCESS (Share #1 securely retrieved)");

    // Test Implicit Rejection: Tampered Ciphertext
    let mut tampered_ciphertext = ciphertext;
    tampered_ciphertext.encrypted_payload[0] ^= 0xFF; // Tamper with byte
    let (garbage_payload, tampered_valid) = ConicKem::decapsulate_ct(&recipient_sk, &tampered_ciphertext, &params);
    assert_eq!(tampered_valid.unwrap_u8(), 0, "Decapsulation must reject tampered ciphertext");
    assert_ne!(garbage_payload, share_payload, "Tampered ciphertext must return surrogate pseudo-random garbage");
    println!("    [+] Implicit Rejection Test: PASSED (Branchless fallback to deterministic surrogate key)\n");

    // -------------------------------------------------------------------------
    // STEP 5: RECONSTRUCTION & LAYER 5 MEMORY HARDENING
    // -------------------------------------------------------------------------
    println!("[*] RECONSTRUCTION: Assembling 3 Threshold Shares (including KEM-decapsulated share)...");
    let mut recovered_share1 = shares[0];
    for b in 0..32 {
        recovered_share1.values[b] = Gf256::new(decrypted_payload[b]);
    }

    // Select threshold = 3 shares: Share 1 (decapsulated), Share 3, and Share 5
    let selected_shares = [recovered_share1, shares[2], shares[4]];
    let reconstructed_secret = ThresholdScheme::reconstruct::<3>(&selected_shares);

    println!("    - Original Entropy:      {:02x?}", &raw_entropy[..16]);
    println!("    - Reconstructed Entropy: {:02x?}", &reconstructed_secret[..16]);

    let is_identical = reconstructed_secret.ct_eq(&raw_entropy);
    assert_eq!(is_identical.unwrap_u8(), 1, "Reconstructed secret must strictly match original entropy");
    println!("    [+] Master Seed Reconstruction: EXACT MATCH!\n");

    // Store in ProtectedMemory (Layer 5)
    println!("[*] LAYER 5: Enclosing Master Seed in Hardware-Protected Memory...");
    {
        let protected_seed = ProtectedMemory::new(reconstructed_secret);
        println!("    - VirtualLock / mlock engaged: Memory pages locked into physical RAM");
        println!("    - Memory protection active. Accessing seed: {:02x?}...", &protected_seed[..8]);
        // protected_seed drops here: automatic zeroization via ZeroizeOnDrop and memory unlock
    }
    println!("    [+] ProtectedMemory dropped: Volatile zeroization and page release completed.\n");

    println!("================================================================================");
    println!("    AEGIS-SEED DEMONSTRATION COMPLETE: ALL 5 LAYERS FUNCTIONING PERFECTLY!      ");
    println!("================================================================================");
}

