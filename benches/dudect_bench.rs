//! Layer 6: Dudect Side-Channel Verification Harness (Welch's t-test)
//!
//! Statistically validates constant-time execution by comparing execution time
//! distributions for fixed vs. random inputs using Welch's two-sample t-test.
//!
//! # Statistical Principle:
//! Null Hypothesis $H_0$: $\mu_{\text{fixed}} = \mu_{\text{random}}$.
//! Threshold: If $|t| < 4.5$, $H_0$ holds with confidence $p > 0.99999$ (no timing leakage).

use std::time::Instant;
use aegis_seed::{
    layer2_gf256::Gf256,
    layer3_gf2048::{Gf2048, ReedSolomonGf2048},
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
    println!("      AEGIS-SEED: DUDECT STATISTICAL SIDE-CHANNEL VERIFICATION (WELCH'S T-TEST) ");
    println!("================================================================================\n");

    const NUM_SAMPLES: usize = 20_000;
    println!("[*] Executing {} dual-class iterations per target primitive...\n", NUM_SAMPLES);

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
        // Target primitive: 100 consecutive multiplications
        let mut accum = input;
        for _ in 0..100 {
            accum = accum.ct_mul(input);
        }
        let elapsed = start.elapsed().as_nanos() as f64;

        // Prevent dead-code elimination
        std::hint::black_box(accum);

        if is_class_a {
            stats_fixed.update(elapsed);
        } else {
            stats_random.update(elapsed);
        }
    }

    let t_gf256 = compute_welchs_t(&stats_fixed, &stats_random);
    println!("Welch's t-score: {:.4}", t_gf256);
    assert!(t_gf256.abs() < 4.5, "GF(2^8) multiplication failed constant-time test: |t| >= 4.5");
    println!("    -> Result: CONSTANT-TIME VERIFIED (|t| < 4.5)\n");

    // -------------------------------------------------------------------------
    // TEST 2: GF(2^11) Reed-Solomon Decode & Error Correction Constant-Time
    // -------------------------------------------------------------------------
    print!("[+] Evaluating GF(2^11) Reed-Solomon Fault Correction... ");
    let mut rs_fixed_stats = TTestStats::default();
    let mut rs_random_stats = TTestStats::default();

    let rs = ReedSolomonGf2048::new();
    let clean_words = [100u16; 24];
    let clean_codeword = rs.encode(&clean_words);

    let mut corrupted_codeword = clean_codeword;
    corrupted_codeword[7] ^= 0x123; // inject fault in class B

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

        std::hint::black_box((res, choice));

        if is_class_a {
            rs_fixed_stats.update(elapsed);
        } else {
            rs_random_stats.update(elapsed);
        }
    }

    let t_rs = compute_welchs_t(&rs_fixed_stats, &rs_random_stats);
    println!("Welch's t-score: {:.4}", t_rs);
    assert!(t_rs.abs() < 4.5, "GF(2^11) RS decode failed constant-time test: |t| >= 4.5");
    println!("    -> Result: CONSTANT-TIME VERIFIED (|t| < 4.5)\n");

    println!("================================================================================");
    println!("    DUDECT VERIFICATION COMPLETE: ALL PRIMITIVES SHOW NO TIMING LEAKAGE         ");
    println!("================================================================================");
}

