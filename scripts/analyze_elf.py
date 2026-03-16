#!/usr/bin/env python3
"""
analyze_elf.py - ELF Binary Structure Analyzer
CarvedRock Security Training Lab

Analyzes ELF headers, sections, and identifies suspicious
characteristics related to reflective loading and in-memory execution.
"""

import sys
import struct
import os

def read_elf_header(data):
    """Parse ELF64 header."""
    if data[:4] != b"\x7fELF":
        return None

    header = {
        "class": "64-bit" if data[4] == 2 else "32-bit",
        "endian": "Little" if data[5] == 1 else "Big",
        "type": struct.unpack_from("<H", data, 16)[0],
        "machine": struct.unpack_from("<H", data, 18)[0],
        "entry": struct.unpack_from("<Q", data, 24)[0],
        "phoff": struct.unpack_from("<Q", data, 32)[0],
        "shoff": struct.unpack_from("<Q", data, 40)[0],
        "phnum": struct.unpack_from("<H", data, 56)[0],
        "shnum": struct.unpack_from("<H", data, 60)[0],
    }

    type_names = {1: "Relocatable", 2: "Executable", 3: "Shared Object", 4: "Core"}
    header["type_name"] = type_names.get(header["type"], "Unknown")

    return header

def find_suspicious_imports(data):
    """Search for function names commonly used in reflective loading."""
    suspicious_funcs = {
        b"mmap": "Memory mapping (RWX allocation)",
        b"mprotect": "Memory permission change",
        b"munmap": "Memory deallocation",
        b"dlopen": "Dynamic library loading",
        b"dlsym": "Dynamic symbol resolution",
        b"memcpy": "Memory copy (payload injection)",
        b"memset": "Memory initialization",
        b"ptrace": "Process tracing / anti-debug",
        b"fork": "Process creation",
        b"execve": "Process execution",
        b"/proc/self/maps": "Process memory map reading",
        b"/proc/self/status": "Process status checking (anti-debug)",
        b"TracerPid": "Debugger detection",
        b"PROT_EXEC": "Executable memory flag",
        b"MAP_ANONYMOUS": "Anonymous memory mapping",
    }

    found = []
    for sig, desc in suspicious_funcs.items():
        offset = data.find(sig)
        if offset != -1:
            found.append((sig.decode("ascii", errors="replace"), desc, offset))

    return found

def analyze_binary(filepath):
    """Perform full ELF analysis."""
    print(f"\n{'='*60}")
    print(f" ELF Binary Analysis Report")
    print(f" CarvedRock Security - Threat Analysis Team")
    print(f"{'='*60}\n")

    if not os.path.exists(filepath):
        print(f"[-] Error: File not found: {filepath}")
        return

    with open(filepath, "rb") as f:
        data = f.read()

    print(f"[*] File: {filepath}")
    print(f"[*] Size: {len(data)} bytes ({len(data)/1024:.1f} KB)")

    # ELF Header
    header = read_elf_header(data)
    if header is None:
        print(f"[-] Not a valid ELF binary")
        return

    print(f"\n[*] ELF Header Analysis:")
    print(f"{'-'*50}")
    print(f"    Class:         {header['class']}")
    print(f"    Endianness:    {header['endian']}")
    print(f"    Type:          {header['type_name']}")
    print(f"    Entry point:   0x{header['entry']:016X}")
    print(f"    Program hdrs:  {header['phnum']}")
    print(f"    Section hdrs:  {header['shnum']}")

    # Suspicious imports/strings
    print(f"\n[*] Suspicious Function/String Analysis:")
    print(f"{'-'*50}")
    suspicious = find_suspicious_imports(data)

    if suspicious:
        for func, desc, offset in suspicious:
            indicator = "[!]" if func in ["mmap", "mprotect", "dlopen",
                                           "/proc/self/maps", "TracerPid"] else "[*]"
            print(f"    {indicator} {func}")
            print(f"        Description: {desc}")
            print(f"        Offset:      0x{offset:08X}")
    else:
        print(f"    No suspicious functions detected")

    # Reflective loading indicators
    print(f"\n[*] Reflective Loading Assessment:")
    print(f"{'-'*50}")
    indicators = {
        "mmap_present": any(f[0] == "mmap" for f in suspicious),
        "memcpy_present": any(f[0] == "memcpy" for f in suspicious),
        "proc_maps": any("/proc/self" in f[0] for f in suspicious),
        "anti_debug": any(f[0] in ["ptrace", "TracerPid"] for f in suspicious),
        "mprotect_present": any(f[0] == "mprotect" for f in suspicious),
    }

    score = sum(indicators.values())

    for check, present in indicators.items():
        status = "DETECTED" if present else "not found"
        symbol = "[!]" if present else "[ ]"
        print(f"    {symbol} {check.replace('_', ' ').title()}: {status}")

    print(f"\n    Risk Score: {score}/5")
    if score >= 4:
        print(f"    Assessment: HIGH - Strong indicators of reflective loading")
        print(f"    Technique:  Likely T1620 (Reflective Code Loading)")
    elif score >= 2:
        print(f"    Assessment: MEDIUM - Some reflective loading indicators")
    else:
        print(f"    Assessment: LOW - Few reflective loading indicators")

    print()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <elf_binary>")
        sys.exit(1)

    analyze_binary(sys.argv[1])
