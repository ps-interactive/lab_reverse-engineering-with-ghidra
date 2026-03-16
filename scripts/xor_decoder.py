#!/usr/bin/env python3
"""
xor_decoder.py - XOR String Decoder
CarvedRock Security Training Lab

Decodes XOR-encrypted strings found in malware binaries.
Used in Objective 2 to verify decryption findings from Ghidra.
"""

import sys
import os

def xor_decode(data, key):
    """Decode XOR-encrypted bytes with a single-byte key."""
    return bytes([b ^ key for b in data])

def extract_encrypted_strings(filepath, key, min_length=4):
    """Extract and decode potential XOR-encrypted strings from a binary."""
    print(f"\n{'='*60}")
    print(f" XOR String Decoder")
    print(f" CarvedRock Security - Threat Analysis Team")
    print(f"{'='*60}\n")

    if not os.path.exists(filepath):
        print(f"[-] Error: File not found: {filepath}")
        return

    with open(filepath, "rb") as f:
        data = f.read()

    print(f"[*] File: {filepath}")
    print(f"[*] XOR key: 0x{key:02X} ({key})")
    print(f"[*] Minimum string length: {min_length}")
    print(f"\n[*] Scanning for XOR-encrypted strings...")
    print(f"{'-'*50}")

    # Decode entire binary
    decoded = xor_decode(data, key)

    # Find printable string sequences in decoded data
    found_strings = []
    current_string = b""
    start_offset = 0

    for i, byte in enumerate(decoded):
        if 0x20 <= byte <= 0x7E:  # Printable ASCII
            if not current_string:
                start_offset = i
            current_string += bytes([byte])
        else:
            if len(current_string) >= min_length:
                found_strings.append((start_offset, current_string.decode("ascii")))
            current_string = b""

    if len(current_string) >= min_length:
        found_strings.append((start_offset, current_string.decode("ascii")))

    # Filter for interesting strings (URLs, paths, IPs, etc.)
    interesting_patterns = [
        "http", "https", "/etc/", "/tmp/", "/proc/",
        ".com", ".io", ".net", "c2", "exfil",
        "config", "beacon", "upload", "APT",
        "shadow", "passwd", "cron", "carvedrock"
    ]

    print(f"\n[*] Interesting decoded strings:")
    print(f"{'-'*50}")
    count = 0
    for offset, string in found_strings:
        if any(pattern.lower() in string.lower() for pattern in interesting_patterns):
            print(f"    Offset 0x{offset:08X}: {string}")
            count += 1

    if count == 0:
        print(f"    No interesting strings found with key 0x{key:02X}")
        print(f"    Try a different XOR key")

    # Also show all decoded strings of reasonable length
    print(f"\n[*] All decoded strings (length >= {min_length}):")
    print(f"{'-'*50}")
    for offset, string in found_strings[:30]:
        # Skip very common/boring strings
        if len(string) >= min_length:
            print(f"    0x{offset:08X}: {string}")

    print(f"\n[*] Total strings found: {len(found_strings)}")
    print(f"[*] Interesting strings: {count}")
    print()

def decode_hex_string(hex_input, key):
    """Decode a hex string with XOR key."""
    print(f"\n[*] Decoding hex input with key 0x{key:02X}:")
    try:
        raw = bytes.fromhex(hex_input.replace(" ", "").replace("0x", ""))
        decoded = xor_decode(raw, key)
        result = decoded.decode("ascii", errors="replace")
        print(f"    Encrypted: {hex_input}")
        print(f"    Decoded:   {result}")
        return result
    except Exception as e:
        print(f"    Error: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary_file> <xor_key_hex>")
        print(f"  Scan binary:  {sys.argv[0]} sample.bin 5A")
        print(f"  Decode hex:   {sys.argv[0]} --hex '32 3e 3e 30 39' 5A")
        sys.exit(1)

    if sys.argv[1] == "--hex":
        hex_str = sys.argv[2]
        key = int(sys.argv[3], 16)
        decode_hex_string(hex_str, key)
    else:
        filepath = sys.argv[1]
        key = int(sys.argv[2], 16)
        extract_encrypted_strings(filepath, key)
