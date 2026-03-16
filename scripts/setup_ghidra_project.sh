#!/bin/bash
# setup_ghidra_project.sh - Create Ghidra project with imported samples
# Runs during lab instantiation after samples are built

set -e

GHIDRA_HOME="/opt/ghidra"
PROJECT_DIR="/home/ubuntu/ghidra_lab/projects"
SAMPLES_DIR="/home/ubuntu/ghidra_lab/samples"
SCRIPTS_DIR="/home/ubuntu/ghidra_lab/ghidra_scripts"

mkdir -p "$PROJECT_DIR"

echo "[*] Creating Ghidra project with sample binaries..."

# Import each sample using Ghidra headless analyzer
# This pre-creates the .gpr project so learners don't have to wait for import

# Import sample_packed.bin
echo "[*] Importing sample_packed.bin..."
"$GHIDRA_HOME/support/analyzeHeadless" \
    "$PROJECT_DIR" "CarvedRock_Malware_Analysis" \
    -import "$SAMPLES_DIR/sample_packed.bin" \
    -overwrite \
    -scriptPath "$SCRIPTS_DIR" \
    2>/dev/null || true

# Import sample_obfuscated.bin
echo "[*] Importing sample_obfuscated.bin..."
"$GHIDRA_HOME/support/analyzeHeadless" \
    "$PROJECT_DIR" "CarvedRock_Malware_Analysis" \
    -import "$SAMPLES_DIR/sample_obfuscated.bin" \
    -overwrite \
    -scriptPath "$SCRIPTS_DIR" \
    2>/dev/null || true

# Import sample_reflective.bin
echo "[*] Importing sample_reflective.bin..."
"$GHIDRA_HOME/support/analyzeHeadless" \
    "$PROJECT_DIR" "CarvedRock_Malware_Analysis" \
    -import "$SAMPLES_DIR/sample_reflective.bin" \
    -overwrite \
    -scriptPath "$SCRIPTS_DIR" \
    2>/dev/null || true

# Import the unpacked reference (for comparison in Obj 1)
echo "[*] Importing sample_unpacked_reference.bin..."
"$GHIDRA_HOME/support/analyzeHeadless" \
    "$PROJECT_DIR" "CarvedRock_Malware_Analysis" \
    -import "$SAMPLES_DIR/sample_unpacked_reference.bin" \
    -overwrite \
    -scriptPath "$SCRIPTS_DIR" \
    2>/dev/null || true

echo "[+] Ghidra project created at $PROJECT_DIR/CarvedRock_Malware_Analysis.gpr"
