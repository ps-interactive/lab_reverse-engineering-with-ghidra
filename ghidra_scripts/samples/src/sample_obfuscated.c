/*
 * sample_obfuscated.c - Simulated malware with XOR-encrypted strings
 * CarvedRock Security Training - Deobfuscation Analysis Sample
 *
 * Contains XOR-encrypted C2 URLs, config data, and obfuscated function names.
 * Learners must locate the decryption routine and decode the payloads.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* XOR key used for string encryption */
#define XOR_KEY 0x5A

/*
 * Encrypted strings (XOR 0x5A):
 * "https://c2.carvedrock-malware.com/beacon"
 * "https://exfil.carvedrock-malware.com/upload"
 * "/etc/shadow"
 * "/tmp/.cr_config"
 * "CarvedRock-APT-Config-v2"
 */

/* Encrypted C2 beacon URL: https://c2.carvedrock-malware.com/beacon */
unsigned char enc_c2_beacon[] = {
    0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75,
    0x39, 0x68, 0x74, 0x39, 0x3B, 0x28, 0x2C, 0x3F,
    0x3E, 0x28, 0x35, 0x39, 0x31, 0x77, 0x37, 0x3B,
    0x36, 0x2D, 0x3B, 0x28, 0x3F, 0x74, 0x39, 0x35,
    0x37, 0x75, 0x38, 0x3F, 0x3B, 0x39, 0x35, 0x34,
    0x00
};

/* Encrypted exfil URL: https://exfil.carvedrock-malware.com/upload */
unsigned char enc_exfil_url[] = {
    0x32, 0x2E, 0x2E, 0x2A, 0x29, 0x60, 0x75, 0x75,
    0x3F, 0x22, 0x3C, 0x33, 0x36, 0x74, 0x39, 0x3B,
    0x28, 0x2C, 0x3F, 0x3E, 0x28, 0x35, 0x39, 0x31,
    0x77, 0x37, 0x3B, 0x36, 0x2D, 0x3B, 0x28, 0x3F,
    0x74, 0x39, 0x35, 0x37, 0x75, 0x2F, 0x2A, 0x36,
    0x35, 0x3B, 0x3E, 0x00
};

/* Encrypted target path: /etc/shadow */
unsigned char enc_target_path[] = {
    0x75, 0x3F, 0x2E, 0x39, 0x75, 0x29, 0x32, 0x3B,
    0x3E, 0x35, 0x2D, 0x00
};

/* Encrypted config path: /tmp/.cr_config */
unsigned char enc_config_path[] = {
    0x75, 0x2E, 0x37, 0x2A, 0x75, 0x74, 0x39, 0x28,
    0x05, 0x39, 0x35, 0x34, 0x3C, 0x33, 0x3D, 0x00
};

/* Encrypted campaign identifier: CarvedRock-APT-Config-v2 */
unsigned char enc_campaign_id[] = {
    0x19, 0x3B, 0x28, 0x2C, 0x3F, 0x3E, 0x08, 0x35,
    0x39, 0x31, 0x77, 0x1B, 0x0A, 0x0E, 0x77, 0x19,
    0x35, 0x34, 0x3C, 0x33, 0x3D, 0x77, 0x2C, 0x68,
    0x00
};

/*
 * decrypt_string - Core decryption routine
 * XOR decrypts a byte array using a single-byte key.
 * This is the function learners must locate in Ghidra.
 */
void decrypt_string(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] = data[i] ^ key;
    }
}

/*
 * Obfuscated function name: init_config
 * Decrypts and loads the malware configuration
 */
int _0x4f3a_init(void) {
    char c2_beacon[128] = {0};
    char exfil_url[128] = {0};
    char config_path[64] = {0};
    char campaign[64] = {0};

    /* Decrypt C2 beacon URL */
    memcpy(c2_beacon, enc_c2_beacon, sizeof(enc_c2_beacon));
    decrypt_string((unsigned char *)c2_beacon, strlen(c2_beacon), XOR_KEY);

    /* Decrypt exfil URL */
    memcpy(exfil_url, enc_exfil_url, sizeof(enc_exfil_url));
    decrypt_string((unsigned char *)exfil_url, strlen(exfil_url), XOR_KEY);

    /* Decrypt config path */
    memcpy(config_path, enc_config_path, sizeof(enc_config_path));
    decrypt_string((unsigned char *)config_path, strlen(config_path), XOR_KEY);

    /* Decrypt campaign ID */
    memcpy(campaign, enc_campaign_id, sizeof(enc_campaign_id));
    decrypt_string((unsigned char *)campaign, strlen(campaign), XOR_KEY);

    printf("[*] C2 Beacon:  %s\n", c2_beacon);
    printf("[*] Exfil URL:  %s\n", exfil_url);
    printf("[*] Config:     %s\n", config_path);
    printf("[*] Campaign:   %s\n", campaign);

    return 0;
}

/*
 * Obfuscated function name: steal_credentials
 * Simulates reading sensitive files
 */
int _0x7b2e_exfil(void) {
    char target[64] = {0};

    memcpy(target, enc_target_path, sizeof(enc_target_path));
    decrypt_string((unsigned char *)target, strlen(target), XOR_KEY);

    printf("[*] Target file: %s\n", target);
    printf("[*] Simulating credential exfiltration...\n");

    return 0;
}

/*
 * Obfuscated function name: main_loop
 * Orchestrates the malware lifecycle
 */
int _0x9c1d_loop(void) {
    printf("[*] Entering main loop...\n");
    printf("[*] Beacon interval: 60 seconds\n");
    printf("[*] Max retries: 5\n");
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== CarvedRock Threat Sample - Obfuscated Binary ===\n\n");

    printf("[*] Phase 1: Decrypting configuration...\n");
    _0x4f3a_init();

    printf("\n[*] Phase 2: Credential access...\n");
    _0x7b2e_exfil();

    printf("\n[*] Phase 3: C2 loop...\n");
    _0x9c1d_loop();

    printf("\n[!] This is a training sample. No malicious actions performed.\n");
    return 0;
}
