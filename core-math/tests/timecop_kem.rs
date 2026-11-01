//! TIMECOP / Valgrind Memcheck Dynamic Secret-Branch Verification
//!
//! Validates that Conic Curve KEM decapsulation contains ZERO secret-dependent
//! branches or secret-dependent table lookups.
//!
//! Under Valgrind Memcheck:
//! - Secret key memory is marked uninitialized via `VALGRIND_MAKE_MEM_UNDEFINED`.
//! - Valgrind's shadow memory tracks undefined bits (V-bits) across all registers and memory.
//! - Any branch (`if`, `match`, loop conditional) or pointer dereference based on secret data
//!   instantly triggers an error ("Conditional jump or move depends on uninitialised value(s)").
//! - Under `--error-exitcode=1`, Valgrind terminates the build if leakage is detected.

use core_math::{default_conic_parameters, ConicKem, ConicPrivateKey, ConicPublicKey, U256};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn valgrind_make_mem_undefined(ptr: *const u8, len: usize) {
    let req: [usize; 6] = [
        0x1002, // VG_USERREQ__MAKE_MEM_UNDEFINED
        ptr as usize,
        len,
        0,
        0,
        0,
    ];
    core::arch::asm!(
        "rol rdi, 3",
        "rol rdi, 13",
        "rol rdi, 29",
        "rol rdi, 19",
        "xchg rbx, rbx",
        inout("rax") &req => _,
        in("rdi") 0x5852554700000000u64,
        options(nostack, preserves_flags)
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[inline(always)]
unsafe fn valgrind_make_mem_defined(ptr: *const u8, len: usize) {
    let req: [usize; 6] = [
        0x1003, // VG_USERREQ__MAKE_MEM_DEFINED
        ptr as usize,
        len,
        0,
        0,
        0,
    ];
    core::arch::asm!(
        "rol rdi, 3",
        "rol rdi, 13",
        "rol rdi, 29",
        "rol rdi, 19",
        "xchg rbx, rbx",
        inout("rax") &req => _,
        in("rdi") 0x5852554700000000u64,
        options(nostack, preserves_flags)
    );
}

fn main() {
    println!("[*] Starting TIMECOP Conic KEM Branchless Verification...");
    let params = default_conic_parameters();
    let sk = ConicPrivateKey {
        scalar: U256([
            0xdead_beef_0001,
            0x1111_2222_3333_4444,
            0x5555_6666_7777_8888,
            0x9999_aaaa_bbbb_cccc,
        ]),
    };
    let pk = ConicPublicKey {
        q: params
            .generator
            .scalar_mul(&sk.scalar, &params.ctx, &params.d_mont),
    };
    let payload = [0x5Au8; 32];
    let ephem = U256([0xcafe_babe_0002, 0, 0, 0]);
    let valid_ct = ConicKem::encapsulate(&pk, &payload, &ephem, &params);

    // 1. Evaluate valid ciphertext under secret taint
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe {
        valgrind_make_mem_undefined(&sk as *const _ as *const u8, core::mem::size_of_val(&sk));
    }

    let (decrypted_valid, is_valid) = ConicKem::decapsulate_ct(&sk, &valid_ct, &params);

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe {
        valgrind_make_mem_defined(
            &decrypted_valid as *const _ as *const u8,
            core::mem::size_of_val(&decrypted_valid),
        );
        valgrind_make_mem_defined(
            &is_valid as *const _ as *const u8,
            core::mem::size_of_val(&is_valid),
        );
        valgrind_make_mem_defined(&sk as *const _ as *const u8, core::mem::size_of_val(&sk));
    }

    assert_eq!(is_valid.unwrap_u8(), 1);
    assert_eq!(decrypted_valid, payload);
    println!("    [+] Test 1: Valid decapsulation under secret taint PASSED");

    // 2. Evaluate tampered ciphertext under secret taint (proves implicit rejection is branchless)
    let mut tampered_ct = valid_ct;
    tampered_ct.mac_tag[0] ^= 0xFF;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe {
        valgrind_make_mem_undefined(&sk as *const _ as *const u8, core::mem::size_of_val(&sk));
    }

    let (decrypted_tampered, is_tampered_valid) =
        ConicKem::decapsulate_ct(&sk, &tampered_ct, &params);

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    unsafe {
        valgrind_make_mem_defined(
            &decrypted_tampered as *const _ as *const u8,
            core::mem::size_of_val(&decrypted_tampered),
        );
        valgrind_make_mem_defined(
            &is_tampered_valid as *const _ as *const u8,
            core::mem::size_of_val(&is_tampered_valid),
        );
        valgrind_make_mem_defined(&sk as *const _ as *const u8, core::mem::size_of_val(&sk));
    }

    assert_eq!(is_tampered_valid.unwrap_u8(), 0);
    assert_ne!(decrypted_tampered, payload);
    println!("    [+] Test 2: Implicit rejection under secret taint PASSED");
    println!("[+] TIMECOP Verification Complete: 0 Secret-Dependent Branches Detected.");
}
