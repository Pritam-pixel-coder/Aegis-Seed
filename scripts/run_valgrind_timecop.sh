#!/usr/bin/env bash
# ==============================================================================
# Aegis-Seed: Valgrind / Memcheck-TIMECOP Side-Channel Verification Script
#
# TIMECOP methodology leverages Valgrind's V-bits (definedness tracking):
# - Marks secret memory as uninitialized (VALGRIND_MAKE_MEM_UNDEFINED).
# - Any secret-dependent branch (`if`, `match`) or secret-dependent memory lookup
#   triggers an immediate Valgrind error: "Conditional jump or move depends on
#   uninitialised value(s)" or "Use of uninitialised value of size...".
# ==============================================================================

set -euo pipefail

echo "================================================================================"
echo "          AEGIS-SEED: VALGRIND / MEMCHECK-TIMECOP VERIFICATION RUNNER           "
echo "================================================================================"

# Check if Valgrind is installed
if ! command -v valgrind &> /dev/null; then
    echo "[-] Error: valgrind not found. Install via 'sudo apt-get install valgrind'."
    exit 1
fi

echo "[*] Step 1: Compiling TIMECOP KEM test binary with DWARF symbols..."
cargo test -p core-math --test timecop_kem --no-run

TIMECOP_BIN=$(ls -t target/debug/deps/timecop_kem-* | grep -v '\.d$' | head -n 1)
chmod +x "$TIMECOP_BIN"

echo "[*] Step 2: Executing TIMECOP Conic KEM Decapsulation under Valgrind Memcheck..."
valgrind \
    --tool=memcheck \
    --track-origins=yes \
    --error-exitcode=1 \
    "$TIMECOP_BIN"

echo ""
echo "[+] SUCCESS: Valgrind Memcheck passed with ZERO errors."
echo "[+] Constant-time guarantee upheld: No undefined/secret-dependent branches detected."
