#!/bin/bash
# ghidra_headless.sh - Run Ghidra headless analysis on a binary
# CarvedRock Security Training Lab
#
# Usage:
#   ghidra_headless.sh <binary> <script>
#   ghidra_headless.sh samples/sample_packed.bin DecompileFunctions
#   ghidra_headless.sh samples/sample_obfuscated.bin FindXORStrings

BINARY="$1"
SCRIPT="$2"

if [ -z "$BINARY" ] || [ -z "$SCRIPT" ]; then
    echo "Usage: $0 <binary_path> <script_name>"
    echo ""
    echo "Available scripts:"
    echo "  DecompileFunctions    - Decompile all functions to C pseudocode"
    echo "  ListFunctions         - List all user-defined functions"
    echo "  ListDefinedStrings    - List all defined strings in the binary"
    echo "  FindXORStrings        - Find XOR encryption patterns"
    echo "  IdentifyReflectiveLoader - Detect reflective loading indicators"
    exit 1
fi

if [ ! -f "$BINARY" ]; then
    echo "[-] Error: Binary not found: $BINARY"
    exit 1
fi

HEADLESS=/opt/ghidra/support/analyzeHeadless
SCRIPTS_DIR=/home/ubuntu/ghidra_scripts
PROJECT_DIR=/tmp/ghidra_headless_$$

mkdir -p "$PROJECT_DIR"

# Run headless analysis with the specified script
"$HEADLESS" "$PROJECT_DIR" "TempProject" \
    -import "$BINARY" \
    -overwrite \
    -scriptPath "$SCRIPTS_DIR" \
    -postScript "${SCRIPT}.java" \
    2>/dev/null | grep -E "^(===|---|    |\[\*\]|\[\!\]|\[+\]|\[-\]|Binary:|[A-Za-z])"

# Cleanup temp project
rm -rf "$PROJECT_DIR"
