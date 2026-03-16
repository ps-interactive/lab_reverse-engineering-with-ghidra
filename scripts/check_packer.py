#!/usr/bin/env python3
"""
check_packer.py - Packer Identification Tool
CarvedRock Security Training Lab

Identifies common packing signatures in ELF binaries.
Used in Objective 1 to detect UPX and other packers.
"""

import sys
import struct
import os

PACKER_SIGNATURES = {
    b"UPX!": "UPX (Ultimate Packer for Executables)",
    b"UPX0": "UPX - Section 0 (compressed data)",
    b"UPX1": "UPX - Section 1 (decompression stub)",
    b"UPX2": "UPX - Section 2 (additional data)",
    b"\x7fELF": "ELF Header (standard)",
    b"MPRESS": "MPRESS Packer",
    b"ASPack": "ASPack Packer",
}

def check_entropy(data, block_size=256):
    """Calculate Shannon entropy of data blocks."""
    from math import log2
    results = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) < block_size:
            break
        freq = {}
        for byte in block:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / len(block)
            if p > 0:
                entropy -= p * log2(p)
        results.append(entropy)
    return results

def analyze_binary(filepath):
    """Analyze a binary file for packer signatures."""
    print(f"\n{'='*60}")
    print(f" Packer Analysis Report")
    print(f" CarvedRock Security - Threat Analysis Team")
    print(f"{'='*60}\n")

    if not os.path.exists(filepath):
        print(f"[-] Error: File not found: {filepath}")
        return

    with open(filepath, "rb") as f:
        data = f.read()

    file_size = len(data)
    print(f"[*] File: {filepath}")
    print(f"[*] Size: {file_size} bytes ({file_size/1024:.1f} KB)")

    # Check ELF header
    if data[:4] == b"\x7fELF":
        print(f"[*] Format: ELF (Executable and Linkable Format)")
        elf_class = data[4]
        if elf_class == 1:
            print(f"[*] Architecture: 32-bit")
        elif elf_class == 2:
            print(f"[*] Architecture: 64-bit")
    else:
        print(f"[!] Warning: Not a standard ELF binary")

    # Search for packer signatures
    print(f"\n[*] Scanning for packer signatures...")
    print(f"{'-'*50}")
    found_packers = []

    for sig, name in PACKER_SIGNATURES.items():
        offset = data.find(sig)
        if offset != -1 and sig != b"\x7fELF":
            print(f"    [!] FOUND: {name}")
            print(f"        Signature: {sig}")
            print(f"        Offset:    0x{offset:08X} ({offset})")
            found_packers.append(name)

    if not found_packers:
        print(f"    [*] No known packer signatures detected")

    # Entropy analysis
    print(f"\n[*] Entropy analysis...")
    print(f"{'-'*50}")
    entropies = check_entropy(data)
    if entropies:
        avg_entropy = sum(entropies) / len(entropies)
        max_entropy = max(entropies)
        high_entropy_blocks = sum(1 for e in entropies if e > 7.0)
        total_blocks = len(entropies)

        print(f"    Average entropy: {avg_entropy:.2f} / 8.00")
        print(f"    Maximum entropy: {max_entropy:.2f} / 8.00")
        print(f"    High-entropy blocks (>7.0): {high_entropy_blocks}/{total_blocks}")

        if avg_entropy > 6.5:
            print(f"\n    [!] HIGH ENTROPY - Binary is likely packed or encrypted")
            print(f"    [*] Packed binaries typically show entropy > 6.5")
        elif avg_entropy > 5.0:
            print(f"\n    [*] MODERATE ENTROPY - May contain encrypted sections")
        else:
            print(f"\n    [*] LOW ENTROPY - Binary appears unpacked")

    # Section analysis for ELF
    if data[:4] == b"\x7fELF":
        print(f"\n[*] Section name scan...")
        print(f"{'-'*50}")
        section_names = []
        # Look for common section name strings
        for name in [b".text", b".data", b".bss", b".rodata",
                     b"UPX0", b"UPX1", b"UPX2", b".upx"]:
            if name in data:
                decoded = name.decode("ascii", errors="replace")
                section_names.append(decoded)
                if b"UPX" in name or b"upx" in name:
                    print(f"    [!] Packer section: {decoded}")
                else:
                    print(f"    [*] Standard section: {decoded}")

    # Summary
    print(f"\n{'='*60}")
    print(f" Summary")
    print(f"{'='*60}")
    if found_packers:
        print(f"    Packer detected: {', '.join(found_packers)}")
        print(f"    Recommendation: Unpack before analysis")
        if any("UPX" in p for p in found_packers):
            print(f"    UPX unpack command: upx -d <binary>")
    else:
        print(f"    No packer signatures found")
        print(f"    Binary may be unpacked or use custom packing")
    print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <binary_file>")
        print(f"Example: {sys.argv[0]} sample_packed.bin")
        sys.exit(1)

    analyze_binary(sys.argv[1])
