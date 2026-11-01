# Aegis-Seed: Side-Channel Resistant BIP-39 Cryptosystem

[![Aegis-Seed CI](https://github.com/aegis-seed/aegis-seed/actions/workflows/ci.yml/badge.svg)](https://github.com/aegis-seed/aegis-seed/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![no_std](https://img.shields.io/badge/no__std-compatible-success.svg)](src/lib.rs)
[![Constant-Time](https://img.shields.io/badge/dudect-|t|<4.5-brightgreen.svg)](benches/dudect_bench.rs)

**Aegis-Seed** is an enterprise-grade, side-channel immune cryptocurrency master seed management framework written in Rust. It combines low-level `#![no_std]` systems programming with finite field linear algebra, number-theoretic coding theory, and Conic Curve Cryptography (CC-DLP) to protect high-value 24-word BIP-39 seed phrases.

---

## 🛡️ Core Security Invariants

1. **ZERO Secret-Dependent Branches**: No `if`, `match`, or conditional branches depend on secret entropy, polynomial shares, or private keys.
2. **ZERO Secret-Dependent Memory Indexing**: No S-boxes, lookup tables, or array accesses depend on secret data, neutralizing cache-timing vulnerabilities (Bernstein 2005 / Meltdown / Spectre).
3. **No Standard Cryptographic Dependencies**: All mathematical primitives—SHA-256, $\mathrm{GF}(2^8)$ carryless arithmetic, $\mathrm{GF}(2^{11})$ field inversion, Montgomery multi-precision arithmetic, and Conic Curve group laws—are designed from clean-room mathematical specifications.
4. **Hardware-Enforced Memory Isolation**: Hardens master secrets in RAM using Linux `memfd_secret(2)` (unmapped from the kernel direct-map) and Windows `VirtualLock`, combined with volatile zeroization on deallocation (`ZeroizeOnDrop`).

---

## 🏛️ System Architecture

```text
+---------------------------------------------------------------------------------+
|                                 USER INPUT                                      |
|                       24-Word BIP-39 Seed Mnemonic                              |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
| LAYER 1: Entropy Extraction & Vectorization (GF(2))                             |
| - Constant-time word parsing & dictionary matching                              |
| - 256-bit Entropy Vector e in GF(2)^256 + 8-bit Checksum c                      |
| - FIPS 180-4 SHA-256 Checksum Verification via subtle::ConstantTimeEq           |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
| LAYER 3: Number-Theoretic Fault Tolerance (GF(2^11))                            |
| - Systematic Reed-Solomon Code (N=26, K=24, d_min=3) over GF(2^11)             |
| - Irreducible Polynomial: P(x) = x^11 + x^2 + 1 (0x805)                         |
| - Branchless syndrome calculation & single-word error correction                |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
| LAYER 2: Linear-Algebraic Secret Sharing (GF(2^8))                              |
| - Rijndael Field GF(2^8) with Carryless Russian Peasant Multiplication          |
| - Inversion via Fermat's Little Theorem (a^254) with fixed addition chain       |
| - Branchless Gaussian Elimination Matrix Inversion                              |
| - Constant-Time (t, n) Threshold Secret Sharing Engine                          |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
| LAYER 4: Conic Curve KEM (CC-DLP) over Ring Z_n                                 |
| - Curve: C_d : x^2 - d*y^2 = 1 (mod n) over prime P = 2^255 - 19, d = 2         |
| - Group Operations: P1 + P2 = (x1*x2 + d*y1*y2, x1*y2 + x2*y1)                  |
| - Constant-Time Montgomery Ladder Scalar Multiplication                         |
| - Implicit Rejection Decapsulation (Fujisaki-Okamoto style error-oracle defeat) |
+---------------------------------------------------------------------------------+
                                       |
                                       v
+---------------------------------------------------------------------------------+
| LAYER 5: System-Level Memory Hardening                                          |
| - Linux memfd_secret(2) (syscall 447) unmapped secret pages                     |
| - Windows VirtualLock page locking                                              |
| - ZeroizeOnDrop with volatile memory fences                                     |
+---------------------------------------------------------------------------------+
```

---

## 🧮 Mathematical Formulations

### Layer 2: $\mathrm{GF}(2^8)$ Carryless Arithmetic
Let $a(x), b(x) \in \mathbb{F}_2[x] / (x^8 + x^4 + x^3 + x + 1)$. Carryless multiplication computes:
$$c(x) = \sum_{i=0}^7 b_i \cdot \big(a(x) \cdot x^i \pmod{P(x)}\big)$$
Field inversion is computed without lookup tables via Fermat's Little Theorem:
$$a^{-1} = a^{2^8 - 2} = a^{254}$$

### Layer 3: Systematic Reed-Solomon over $\mathrm{GF}(2^{11})$
Each BIP-39 word index is an 11-bit integer in $\{0, \dots, 2047\}$, corresponding to an element of $\mathrm{GF}(2^{11}) = \mathbb{F}_2[x] / (x^{11} + x^2 + 1)$.
The generator polynomial with roots $\alpha, \alpha^2$ is:
$$g(x) = (x - \alpha)(x - \alpha^2) = x^2 + (\alpha + \alpha^2)x + \alpha^3$$
Syndromes $S_1 = C(\alpha)$ and $S_2 = C(\alpha^2)$ yield the error location ratio:
$$\frac{S_2}{S_1} = \alpha^j$$
The decoder tests all 26 locations uniformly in constant time using `subtle::ConstantTimeEq`.

### Layer 4: Conic Curve Discrete Logarithm Problem (CC-DLP)
For points on the conic section $x^2 - d y^2 \equiv 1 \pmod n$, addition corresponds to multiplication in the quadratic extension $\mathbb{Z}_n[\sqrt{d}]$:
$$(x_1 + y_1 \sqrt{d})(x_2 + y_2 \sqrt{d}) = (x_1 x_2 + d y_1 y_2) + (x_1 y_2 + x_2 y_1)\sqrt{d}$$
Scalar multiplication $[k]P$ is evaluated using a 256-step Montgomery ladder where every bit executes 1 addition and 1 doubling branchlessly.

---

## 🔬 Side-Channel Verification & Testing

### 1. Dudect Statistical Analysis (Welch's t-test)
Run the automated Dudect benchmark:
```bash
cargo bench --bench dudect_bench -- --nocapture
```
Criterion: If $|t| < 4.5$, the null hypothesis $H_0$ (execution times are independent of secret inputs) holds with $p > 0.99999$.

### 2. Valgrind Memcheck & TIMECOP
Run the dynamic branch analysis script:
```bash
chmod +x scripts/run_valgrind_timecop.sh
./scripts/run_valgrind_timecop.sh
```

---

## 🚀 Building & Running

```bash
# Verify no_std compatibility
cargo check --no-default-features

# Run the complete end-to-end demonstration
cargo run --release

# Run unit tests
cargo test
```

