#!/bin/bash
# build_samples.sh - Compile and prepare malware training samples
# CarvedRock Security Training Lab
# Runs during lab instantiation to create analysis targets

set -e

SAMPLES_DIR="/home/ubuntu/ghidra_lab/samples"
SRC_DIR="/home/ubuntu/ghidra_lab/samples/src"
OUTPUT_DIR="/home/ubuntu/ghidra_lab/samples"

echo "[*] Building CarvedRock training samples..."

# Sample 1: Packed binary (compile then UPX-pack)
echo "[*] Building sample_packed..."
gcc -o "$OUTPUT_DIR/sample_unpacked_reference.bin" "$SRC_DIR/sample_packed.c" \
    -static -no-pie -O0 -g0
gcc -o "$OUTPUT_DIR/sample_packed.bin" "$SRC_DIR/sample_packed.c" \
    -static -no-pie -O0 -g0
upx --best "$OUTPUT_DIR/sample_packed.bin" 2>/dev/null || true
echo "[+] sample_packed.bin created (UPX-packed)"

# Sample 2: Obfuscated binary (compile with stripped symbols)
echo "[*] Building sample_obfuscated..."
gcc -o "$OUTPUT_DIR/sample_obfuscated.bin" "$SRC_DIR/sample_obfuscated.c" \
    -no-pie -O0 -s
strip --strip-debug "$OUTPUT_DIR/sample_obfuscated.bin"
echo "[+] sample_obfuscated.bin created (stripped)"

# Sample 3: Reflective loader (compile normally for analysis)
echo "[*] Building sample_reflective..."
gcc -o "$OUTPUT_DIR/sample_reflective.bin" "$SRC_DIR/sample_reflective.c" \
    -no-pie -O0 -s
echo "[+] sample_reflective.bin created"

# Sample 4: Custom-packed binary (compile with stripped symbols)
echo "[*] Building sample_custom_packed..."
gcc -o "$OUTPUT_DIR/sample_custom_packed.bin" "$SRC_DIR/sample_custom_packed.c" \
    -no-pie -O0 -s
strip --strip-debug "$OUTPUT_DIR/sample_custom_packed.bin"
echo "[+] sample_custom_packed.bin created (custom packer)"

# Set permissions
chmod 644 "$OUTPUT_DIR"/*.bin
chmod 755 "$OUTPUT_DIR/sample_reflective.bin"

echo "[*] All samples built successfully"
ls -la "$OUTPUT_DIR"/*.bin
