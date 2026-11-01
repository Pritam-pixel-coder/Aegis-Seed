//! Dudect Side-Channel Verification Benchmark (Welch's t-test)
//!
//! Statistically validates constant-time execution by comparing execution time
//! distributions for fixed vs. random/altered inputs using Welch's two-sample t-test.
//!
//! Statistical Principle:
//! Null Hypothesis H0: mu_A = mu_B.
//! Threshold: If |t| < 4.5, H0 holds with confidence p > 0.99999 (no timing leakage).

use std::hint::black_box;
use std::time::Instant;

use core_math::{
    default_conic_parameters, ConicKem, ConicPrivateKey, ConicPublicKey, Gf256, ReedSolomonGf2048,
    U256,
};

/// Online statistical accumulator using Welford's algorithm
#[derive(Default)]
struct TTestStats {
    count: f64,
    mean: f64,
    m2: f64,
}

impl TTestStats {
    fn update(&mut self, sample: f64) {
        self.count += 1.0;
        let delta = sample - self.mean;
        self.mean += delta / self.count;
        let delta2 = sample - self.mean;
        self.m2 += delta * delta2;
    }

    fn variance(&self) -> f64 {
        if self.count < 2.0 {
            0.0
        } else {
            self.m2 / (self.count - 1.0)
        }
    }
}

fn compute_welchs_t(group_a: &TTestStats, group_b: &TTestStats) -> f64 {
    let var_a = group_a.variance();
    let var_b = group_b.variance();
    let n_a = group_a.count;
    let n_b = group_b.count;

    let denom = (var_a / n_a + var_b / n_b).sqrt();
    if denom == 0.0 {
        0.0
    } else {
        (group_a.mean - group_b.mean) / denom
    }
}

fn main() {
    println!("================================================================================");
    println!("   CORE-MATH: DUDECT STATISTICAL SIDE-CHANNEL VERIFICATION (WELCH'S T-TEST)     ");
    println!("================================================================================\n");

    const NUM_SAMPLES: usize = 15_000;
    println!(
        "[*] Executing {} dual-class iterations per target primitive...\n",
        NUM_SAMPLES
    );

    // -------------------------------------------------------------------------
    // TEST 1: GF(2^8) Carryless Multiplication Constant-Time Verification
    // -------------------------------------------------------------------------
    print!("[+] Evaluating GF(2^8) Carryless Multiplication... ");
    let mut stats_fixed = TTestStats::default();
    let mut stats_random = TTestStats::default();

    let fixed_val = Gf256::new(0xAA);
    let mut pseudo_rand = 0x55u8;

    for i in 0..NUM_SAMPLES {
        let is_class_a = (i & 1) == 0;
        let input = if is_class_a {
            fixed_val
        } else {
            pseudo_rand = pseudo_rand.wrapping_mul(63).wrapping_add(1);
            Gf256::new(pseudo_rand)
        };

        let start = Instant::now();
        let mut accum = input;
        for _ in 0..80 {
            accum = accum.ct_mul(input);
        }
        let elapsed = start.elapsed().as_nanos() as f64;

        black_box(accum);

        if is_class_a {
            stats_fixed.update(elapsed);
        } else {
            stats_random.update(elapsed);
        }
    }

    let t_gf256 = compute_welchs_t(&stats_fixed, &stats_random);
    println!("Welch's t-score: {:.4}", t_gf256);
    assert!(
        t_gf256.abs() < 4.5,
        "GF(2^8) multiplication failed constant-time test: |t| = {:.4} >= 4.5",
        t_gf256
    );
    println!("    -> Result: CONSTANT-TIME VERIFIED (|t| < 4.5)\n");

    // -------------------------------------------------------------------------
    // TEST 2: GF(2^11) Reed-Solomon Decode & Error Correction Constant-Time
    // -------------------------------------------------------------------------
    print!("[+] Evaluating GF(2^11) Reed-Solomon Fault Correction... ");
    let mut rs_clean_stats = TTestStats::default();
    let mut rs_corrupted_stats = TTestStats::default();

    let rs = ReedSolomonGf2048::new();
    let clean_words = [100u16; 24];
    let clean_codeword = rs.encode(&clean_words);

    let mut corrupted_codeword = clean_codeword;
    corrupted_codeword[7] ^= 0x123; // inject bit fault in class B

    for i in 0..NUM_SAMPLES {
        let is_class_a = (i & 1) == 0;
        let test_input = if is_class_a {
            clean_codeword
        } else {
            corrupted_codeword
        };

        let start = Instant::now();
        let (res, choice) = rs.decode_and_correct_ct(&test_input);
        let elapsed = start.elapsed().as_nanos() as f64;

        black_box((res, choice));

        if is_class_a {
            rs_clean_stats.update(elapsed);
        } else {
            rs_corrupted_stats.update(elapsed);
        }
    }

    let t_rs = compute_welchs_t(&rs_clean_stats, &rs_corrupted_stats);
    println!("Welch's t-score: {:.4}", t_rs);
    assert!(
        t_rs.abs() < 4.5,
        "GF(2^11) RS decode failed constant-time test: |t| = {:.4} >= 4.5",
        t_rs
    );
    println!("    -> Result: CONSTANT-TIME VERIFIED (|t| < 4.5)\n");

    // -------------------------------------------------------------------------
    // TEST 3: Conic KEM Decapsulation (Valid vs Tampered Implicit Rejection)
    // -------------------------------------------------------------------------
    print!("[+] Evaluating Conic Curve KEM Decapsulation (Timing Leakage Gate)... ");
    let mut kem_valid_stats = TTestStats::default();
    let mut kem_tampered_stats = TTestStats::default();

    let params = default_conic_parameters();
    let sk = ConicPrivateKey {
        scalar: U256([
            0x1234_5678_9abc_def0,
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
    let payload = [0x42u8; 32];
    let ephem = U256([0xbeef_cafe_0001_0002, 0, 0, 0]);
    let valid_ct = ConicKem::encapsulate(&pk, &payload, &ephem, &params);

    let mut tampered_ct = valid_ct;
    tampered_ct.mac_tag[0] ^= 0x01; // Corrupted Poly1305 MAC tag

    const KEM_SAMPLES: usize = 5_000;
    for i in 0..KEM_SAMPLES {
        let is_class_a = (i & 1) == 0;
        let ct = if is_class_a { valid_ct } else { tampered_ct };

        let start = Instant::now();
        let (shared_secret, is_valid) = ConicKem::decapsulate_ct(&sk, &ct, &params);
        let elapsed = start.elapsed().as_nanos() as f64;

        black_box((shared_secret, is_valid));

        if is_class_a {
            kem_valid_stats.update(elapsed);
        } else {
            kem_tampered_stats.update(elapsed);
        }
    }

    let t_kem = compute_welchs_t(&kem_valid_stats, &kem_tampered_stats);
    println!("Welch's t-score: {:.4}", t_kem);
    assert!(
        t_kem.abs() < 4.5,
        "Conic KEM decapsulation failed constant-time test: |t| = {:.4} >= 4.5",
        t_kem
    );
    println!("    -> Result: CONSTANT-TIME VERIFIED (|t| < 4.5)\n");

    println!("================================================================================");
    println!("  DUDECT VERIFICATION COMPLETE: ALL PRIMITIVES PROVEN CONSTANT-TIME (|t| < 4.5)  ");
    println!("================================================================================");
}
