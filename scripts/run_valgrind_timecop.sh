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

echo "[*] Step 1: Compiling debug binary with full DWARF symbols..."
cargo build --bin aegis-seed

BINARY="./target/debug/aegis-seed"

if [ ! -f "$BINARY" ]; then
    echo "[-] Error: binary not found at $BINARY"
    exit 1
fi

echo "[*] Step 2: Executing under Valgrind Memcheck..."
valgrind \
    --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    --track-origins=yes \
    --error-exitcode=42 \
    "$BINARY"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "[+] SUCCESS: Valgrind Memcheck passed with ZERO errors."
    echo "[+] Constant-time guarantee upheld: No undefined/secret-dependent branches detected."
elif [ $EXIT_CODE -eq 42 ]; then
    echo ""
    echo "[-] FAILURE: Valgrind detected memory safety or timing branch violations!"
    exit 42
else
    echo "[-] Execution terminated with code $EXIT_CODE"
    exit $EXIT_CODE
fi

