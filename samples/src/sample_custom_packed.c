/*
 * sample_custom_packed.c - Simulated custom-packed malware
 * CarvedRock Security Training - Custom Packing Analysis Sample
 *
 * This binary simulates a custom packer. Unlike UPX which has well-known
 * signatures, custom packers use proprietary formats that evade signature
 * detection. This sample has:
 *   - A custom packer header ("CRPK" magic bytes)
 *   - XOR-encrypted data section (decoded at runtime)
 *   - An unpacking stub that runs before main logic
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Custom packer magic bytes - NOT a known packer signature */
const char PACKER_MAGIC[] = "CRPK";
const char PACKER_VERSION[] = "CarvedRock-Packer-v1.3";
const int  PACKER_KEY = 0x37;

/* Encrypted payload data (XOR 0x37) representing packed malware config.
 * Plaintext: "C2=stager.carvedrock-apt.net:8443"
 */
unsigned char packed_payload[] = {
    0x74, 0x05, 0x0A, 0x44, 0x43, 0x56, 0x50, 0x52,
    0x45, 0x19, 0x54, 0x56, 0x45, 0x41, 0x52, 0x53,
    0x45, 0x58, 0x54, 0x5C, 0x1A, 0x56, 0x47, 0x43,
    0x19, 0x59, 0x52, 0x43, 0x0D, 0x0F, 0x03, 0x03,
    0x04, 0x00
};

/* Simulated unpacking stub - decrypts packed_payload at runtime */
void unpack_stub(unsigned char *data, int len, int key) {
    printf("[CRPK] Custom unpacker v1.3 executing...\n");
    printf("[CRPK] Decrypting %d bytes with key 0x%02X\n", len, key);
    for (int i = 0; i < len; i++) {
        data[i] = data[i] ^ key;
    }
    printf("[CRPK] Unpacking complete.\n");
}

/* Simulated packed malware functionality */
void execute_payload(const char *config) {
    printf("[*] Payload active\n");
    printf("[*] Configuration: %s\n", config);
    printf("[*] Establishing connection...\n");
    printf("[*] Beacon interval: 45 seconds\n");
}

/* Integrity check - verifies packer header before unpacking */
int verify_packer_header(void) {
    if (memcmp(PACKER_MAGIC, "CRPK", 4) == 0) {
        printf("[CRPK] Packer header verified: %s\n", PACKER_VERSION);
        return 1;
    }
    printf("[CRPK] ERROR: Invalid packer header\n");
    return 0;
}

int main(int argc, char *argv[]) {
    char config[128] = {0};

    printf("=== CarvedRock Threat Sample - Custom Packed Binary ===\n\n");

    /* Phase 1: Verify packer integrity */
    printf("[*] Phase 1: Verifying packer header...\n");
    if (!verify_packer_header()) {
        return 1;
    }

    /* Phase 2: Unpack payload */
    printf("\n[*] Phase 2: Unpacking payload...\n");
    memcpy(config, packed_payload, sizeof(packed_payload));
    unpack_stub((unsigned char *)config, strlen(config), PACKER_KEY);

    /* Phase 3: Execute unpacked payload */
    printf("\n[*] Phase 3: Executing payload...\n");
    execute_payload(config);

    printf("\n[!] This is a training sample. No malicious actions performed.\n");
    return 0;
}
