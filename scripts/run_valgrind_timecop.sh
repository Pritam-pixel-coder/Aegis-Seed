#!/usr/bin/env bash
# ==============================================================================
# Aegis-Seed: Valgrind / Memcheck-TIMECOP Side-Channel Verification Script
#
# TIMECOP methodology leverages Valgrind's V-bits (definedness tracking):
# - Marks secret memory as uninitialized (VALGRIND_MAKE_MEM_UNDEFINED).
# - Any secret-dependent branch (`if`, `match`) or secret-dependent memory lookup
#   triggers an immediate Valgrind warning: "Conditional jump or move depends on
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

echo "[*] Step 1: Compiling TIMECOP test and CLI binaries with DWARF symbols..."
cargo test -p core-math --test timecop_kem --no-run
cargo build -p cli-app

TIMECOP_BIN=$(ls -t target/debug/deps/timecop_kem-* | grep -v '\.d$' | head -n 1)
CLI_BIN="./target/debug/cli-app"

echo "[*] Step 2: Executing TIMECOP KEM Decapsulation under Valgrind Memcheck..."
valgrind \
    --tool=memcheck \
    --leak-check=full \
    --track-origins=yes \
    --error-exitcode=1 \
    "$TIMECOP_BIN"

echo "[*] Step 3: Executing full CLI application under Valgrind Memcheck..."
valgrind \
    --tool=memcheck \
    --leak-check=full \
    --track-origins=yes \
    --error-exitcode=1 \
    "$CLI_BIN"

echo ""
echo "[+] SUCCESS: Valgrind Memcheck passed with ZERO errors."
echo "[+] Constant-time guarantee upheld: No undefined/secret-dependent branches detected."

