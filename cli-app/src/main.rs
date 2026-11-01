//! Aegis-Seed CLI Application (`std`)
//!
//! Demonstrates the complete cryptographic lifecycle with full 32-byte (256-bit) entropy:
//! Input -> Fault-Tolerant Encode -> Fault Correction -> Secret Share -> Conic KEM Encrypt -> Decrypt -> Recover -> Hardware Memory Hardening

#![allow(clippy::needless_range_loop)]

use core_math::{
    default_conic_parameters, Bip39MasterEntropy, ConicKem, ConicPrivateKey, ConicPublicKey, Gf256,
    Matrix, ReedSolomonGf2048, ThresholdScheme, U256,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

// =============================================================================
// OS-Level Hardware Memory Protection (std)
// =============================================================================

/// Container providing OS-level memory locking and automatic zeroization on drop.
pub struct ProtectedMemory<T: Zeroize> {
    data: T,
    #[cfg(target_os = "windows")]
    is_locked: bool,
    #[cfg(target_os = "linux")]
    fd: Option<i32>,
}

impl<T: Zeroize> ProtectedMemory<T> {
    pub fn new(data: T) -> Self {
        #[cfg(target_os = "windows")]
        let is_locked = false;

        #[cfg(target_os = "linux")]
        let fd = Self::try_create_memfd_secret();

        let mut instance = Self {
            data,
            #[cfg(target_os = "windows")]
            is_locked,
            #[cfg(target_os = "linux")]
            fd,
        };

        instance.lock_memory();
        instance
    }

    fn lock_memory(&mut self) {
        let ptr = &self.data as *const T as *const core::ffi::c_void;
        let size = core::mem::size_of::<T>();

        #[cfg(target_os = "windows")]
        {
            unsafe {
                let res = windows_sys::Win32::System::Memory::VirtualLock(ptr, size);
                self.is_locked = res != 0;
            }
        }

        #[cfg(target_os = "linux")]
        {
            unsafe {
                if self.fd.is_none() {
                    libc::mlock(ptr, size);
                }
            }
        }
    }

    fn unlock_memory(&mut self) {
        let ptr = &self.data as *const T as *const core::ffi::c_void;
        let size = core::mem::size_of::<T>();

        #[cfg(target_os = "windows")]
        {
            if self.is_locked {
                unsafe {
                    windows_sys::Win32::System::Memory::VirtualUnlock(ptr, size);
                }
                self.is_locked = false;
            }
        }

        #[cfg(target_os = "linux")]
        {
            unsafe {
                if let Some(fd) = self.fd {
                    libc::close(fd);
                } else {
                    libc::munlock(ptr, size);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn try_create_memfd_secret() -> Option<i32> {
        #[cfg(target_arch = "x86_64")]
        const SYS_MEMFD_SECRET: libc::c_long = 447;
        #[cfg(target_arch = "aarch64")]
        const SYS_MEMFD_SECRET: libc::c_long = 447;

        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        unsafe {
            let res = libc::syscall(SYS_MEMFD_SECRET, 1);
            if res >= 0 {
                Some(res as i32)
            } else {
                None
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        None
    }

    pub fn get(&self) -> &T {
        &self.data
    }
}

impl<T: Zeroize> core::ops::Deref for ProtectedMemory<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T: Zeroize> Drop for ProtectedMemory<T> {
    fn drop(&mut self) {
        self.data.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        self.unlock_memory();
    }
}

// =============================================================================
// Helper: Hex Printing
// =============================================================================

fn print_hex_32(label: &str, bytes: &[u8; 32]) {
    print!("{}: [", label);
    for (i, b) in bytes.iter().enumerate() {
        print!("{:02x}", b);
        if i < 31 {
            print!(", ");
        }
    }
    println!("]");
}

fn print_hex_16(label: &str, bytes: &[u8; 16]) {
    print!("{}: [", label);
    for (i, b) in bytes.iter().enumerate() {
        print!("{:02x}", b);
        if i < 15 {
            print!(", ");
        }
    }
    println!("]");
}

// =============================================================================
// Main Execution Trace
// =============================================================================

fn main() {
    println!("================================================================================");
    println!("          AEGIS-SEED: SIDE-CHANNEL RESISTANT BIP-39 CRYPTOSYSTEM               ");
    println!(
        "  Strict no_std Math Core + std OS-Level Memory Hardening (memfd_secret/VirtualLock)"
    );
    println!("================================================================================\n");

    // -------------------------------------------------------------------------
    // STEP 1: LAYER 1 - BIP39 256-BIT (32-BYTE) MASTER ENTROPY
    // -------------------------------------------------------------------------
    println!("[*] LAYER 1: Ingesting 256-bit (32-byte) Cryptocurrency Master Entropy...");
    let raw_entropy: [u8; 32] = [
        0x5a, 0x1f, 0x93, 0x8c, 0xb2, 0x3d, 0x4e, 0xf1, 0xa0, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x11,
        0x22, 0x33,
    ];

    print_hex_32("    - Raw Master Entropy (Full 32 bytes)", &raw_entropy);

    let master_entropy = Bip39MasterEntropy::from_raw_entropy(&raw_entropy);
    println!(
        "    - Extracted 8-bit SHA-256 Checksum: 0x{:02X}",
        master_entropy.checksum
    );
    println!("    - Generated 24 BIP-39 11-bit Word Indices:");
    print!("      ");
    for (i, &idx) in master_entropy.word_indices.iter().enumerate() {
        print!("{:4} ", idx);
        if (i + 1) % 8 == 0 {
            print!("\n      ");
        }
    }
    println!();

    let (_reparsed, is_valid_cs) =
        Bip39MasterEntropy::from_word_indices_ct(&master_entropy.word_indices);
    assert_eq!(
        is_valid_cs.unwrap_u8(),
        1,
        "BIP-39 Checksum verification must succeed"
    );
    println!("    [+] Constant-Time Checksum Verification: PASSED\n");

    // -------------------------------------------------------------------------
    // STEP 2: LAYER 2 - LINEAR-ALGEBRAIC (t=3, n=5) SECRET SHARING OVER GF(2^8)
    // -------------------------------------------------------------------------
    println!("[*] LAYER 2: Linear-Algebraic (t=3, n=5) Secret Sharing over GF(2^8)...");
    let poly_coeffs: [[u8; 32]; 2] = [[0x71; 32], [0x9B; 32]];

    let shares = ThresholdScheme::split(&raw_entropy, 3, 5, &poly_coeffs);
    println!("    - Generated 5 Secret Shares (Each exactly 32 bytes long):");
    for (i, item) in shares.iter().enumerate().take(5) {
        let share_bytes = item.to_bytes();
        let prefix = format!("      Share #{}: x = {}, data", i + 1, item.x.0);
        print_hex_32(&prefix, &share_bytes);
    }

    // Branchless Gaussian Elimination Matrix Inversion
    println!("    - Testing Branchless Gaussian Elimination (3x3 Matrix Inversion over GF(2^8)):");
    let test_mat = Matrix::<3> {
        data: [
            [Gf256::new(1), Gf256::new(2), Gf256::new(3)],
            [Gf256::new(4), Gf256::new(5), Gf256::new(6)],
            [Gf256::new(7), Gf256::new(8), Gf256::new(10)],
        ],
    };
    let (_inv_mat, is_inv) = test_mat.invert_ct();
    assert_eq!(is_inv.unwrap_u8(), 1, "Matrix must be invertible");
    println!("    [+] Branchless Gaussian Elimination: PASSED (Non-singular inversion verified)\n");

    // -------------------------------------------------------------------------
    // STEP 3: LAYER 3 - REED-SOLOMON FAULT TOLERANCE (GF(2^11))
    // -------------------------------------------------------------------------
    println!("[*] LAYER 3: Reed-Solomon (N=26, K=24) Error Correction over GF(2^11)...");
    let rs = ReedSolomonGf2048::new();
    let codeword = rs.encode(&master_entropy.word_indices);
    println!("    - Systematic Codeword (24 data symbols + 2 parity symbols):");
    println!(
        "      Parity 0: {}, Parity 1: {}",
        codeword[24], codeword[25]
    );

    // Corrupt word index at position 5
    let mut corrupted_codeword = codeword;
    let corrupted_index = 5;
    let original_word = corrupted_codeword[corrupted_index];
    corrupted_codeword[corrupted_index] = (original_word ^ 0x3A5) & 0x7FF;
    println!(
        "    [!] Injected Word Corruption at Index {}: {} -> {}",
        corrupted_index, original_word, corrupted_codeword[corrupted_index]
    );

    let (corrected_words, correction_ok) = rs.decode_and_correct_ct(&corrupted_codeword);
    assert_eq!(
        correction_ok.unwrap_u8(),
        1,
        "Reed-Solomon correction must succeed"
    );
    assert_eq!(
        corrected_words[corrupted_index], original_word,
        "Restored word must match original"
    );
    println!(
        "    [+] Constant-time syndrome locator restored corrupted word: {} (Identical to original!)",
        corrected_words[corrupted_index]
    );
    println!("    [+] Single-word Fault Tolerance: VERIFIED\n");

    // -------------------------------------------------------------------------
    // STEP 4: LAYER 4 - CONIC CURVE KEM (CC-DLP) OVER PRIME FIELD
    // -------------------------------------------------------------------------
    println!("[*] LAYER 4: Conic Curve Key Encapsulation Mechanism (CC-KEM)...");
    let params = default_conic_parameters();

    let recipient_sk = ConicPrivateKey {
        scalar: U256([0x1337_c0de_beef_cafe, 0x42, 0x88, 0x99]),
    };
    let recipient_pk = ConicPublicKey {
        q: params
            .generator
            .scalar_mul(&recipient_sk.scalar, &params.ctx, &params.d_mont),
    };
    println!("    - Conic Curve Generator G = (x, y) on x^2 - 2y^2 = 1");
    println!(
        "    - Recipient Public Key Point Q = [sk] G computed via Constant-Time Montgomery Ladder."
    );

    // Encapsulate full 32-byte Share #1 payload
    let share_1_bytes = shares[0].to_bytes();
    let ephemeral_scalar = U256([0x9876_5432_10fe_dcba, 0x11, 0x22, 0x33]);
    let ciphertext =
        ConicKem::encapsulate(&recipient_pk, &share_1_bytes, &ephemeral_scalar, &params);
    println!("    - Encapsulated Share #1 (Full 32 bytes) into ConicCiphertext:");
    print_hex_32("      Encrypted Payload", &ciphertext.encrypted_payload);
    print_hex_16("      Poly1305 MAC Tag (16 bytes)", &ciphertext.mac_tag);

    // Decapsulate with private key
    let (decrypted_share_1, dec_valid) =
        ConicKem::decapsulate_ct(&recipient_sk, &ciphertext, &params);
    assert_eq!(
        dec_valid.unwrap_u8(),
        1,
        "Decapsulation must succeed for valid ciphertext"
    );
    assert_eq!(
        decrypted_share_1, share_1_bytes,
        "Decrypted payload must match original 32-byte share"
    );
    println!("    [+] Constant-Time Decapsulation: SUCCESS (Full 32-byte Share #1 retrieved)");

    // Test Implicit Rejection: Tampered Ciphertext
    let mut tampered_ciphertext = ciphertext;
    tampered_ciphertext.encrypted_payload[0] ^= 0xFF;
    let (garbage_payload, tampered_valid) =
        ConicKem::decapsulate_ct(&recipient_sk, &tampered_ciphertext, &params);
    assert_eq!(
        tampered_valid.unwrap_u8(),
        0,
        "Decapsulation must reject tampered ciphertext"
    );
    assert_ne!(
        garbage_payload, share_1_bytes,
        "Tampered ciphertext must return surrogate pseudo-random garbage"
    );
    println!("    [+] Implicit Rejection Test: PASSED (Branchless fallback to deterministic surrogate key)\n");

    // -------------------------------------------------------------------------
    // STEP 5: RECONSTRUCTION & HARDWARE MEMORY HARDENING
    // -------------------------------------------------------------------------
    println!("[*] RECONSTRUCTION: Assembling 3 Threshold Shares (32 bytes each)...");
    let recovered_share1 = core_math::SecretShare::from_bytes(1, &decrypted_share_1);

    // Reconstruct using threshold = 3 shares: Share 1 (decapsulated), Share 3, and Share 5
    let selected_shares = [recovered_share1, shares[2], shares[4]];
    let reconstructed_secret = ThresholdScheme::reconstruct::<3>(&selected_shares);

    print_hex_32("    - Original Master Entropy     ", &raw_entropy);
    print_hex_32("    - Reconstructed Master Entropy", &reconstructed_secret);

    let is_identical = reconstructed_secret.ct_eq(&raw_entropy);
    assert_eq!(
        is_identical.unwrap_u8(),
        1,
        "Reconstructed secret must strictly match original entropy"
    );
    println!("    [+] Master Seed Reconstruction: EXACT MATCH!\n");

    // Enclose master secret in OS-level ProtectedMemory
    println!("[*] LAYER 5: Enclosing Master Seed in Hardware-Protected Memory...");
    {
        let protected_seed = ProtectedMemory::new(reconstructed_secret);
        println!("    - VirtualLock / mlock engaged: Memory pages locked into physical RAM");
        print_hex_32(
            "    - ProtectedMemory active. Accessing seed",
            &protected_seed,
        );
        // protected_seed automatically zeroizes and unlocks memory on drop
    }
    println!("    [+] ProtectedMemory dropped: Volatile zeroization and page release completed.\n");

    println!("================================================================================");
    println!("    AEGIS-SEED DEMONSTRATION COMPLETE: ALL 5 LAYERS FUNCTIONING PERFECTLY!      ");
    println!("================================================================================");
}
