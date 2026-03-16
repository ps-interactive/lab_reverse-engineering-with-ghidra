/*
 * sample_packed.c - Simulated malware for Ghidra reverse engineering lab
 * CarvedRock Security Training - Packing Analysis Sample
 *
 * This binary will be UPX-packed before the lab begins.
 * Learners must unpack it to reveal the hidden strings and logic.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

/* Simulated C2 configuration - visible after unpacking */
const char *C2_SERVER = "malware-c2.carvedrock-threat.io";
const char *C2_BACKUP = "backup-c2.carvedrock-threat.io";
const char *CAMPAIGN_ID = "CARVED-2025-APT42";
const char *EXFIL_PATH = "/api/v2/exfil/upload";

/* Simulated beacon interval */
#define BEACON_INTERVAL 30

void initialize_persistence(void) {
    /* Simulated persistence mechanism */
    const char *cron_entry = "*/5 * * * * /tmp/.cache_update";
    const char *autostart = "/home/%s/.config/autostart/cache_update.desktop";
    printf("[*] Persistence method: cron + autostart\n");
    printf("[*] Cron: %s\n", cron_entry);
    printf("[*] Autostart template: %s\n", autostart);
}

void collect_system_info(void) {
    /* Simulated recon function */
    printf("[*] Collecting hostname...\n");
    printf("[*] Collecting username...\n");
    printf("[*] Collecting OS version...\n");
    printf("[*] Collecting network interfaces...\n");
}

void beacon_c2(const char *server, const char *path) {
    /* Simulated C2 beacon */
    printf("[*] Beaconing to %s%s\n", server, path);
    printf("[*] Campaign: %s\n", CAMPAIGN_ID);
    printf("[*] Beacon interval: %d seconds\n", BEACON_INTERVAL);
}

int main(int argc, char *argv[]) {
    printf("=== CarvedRock Threat Sample - Packed Binary ===\n\n");

    printf("[*] Stage 1: System reconnaissance\n");
    collect_system_info();

    printf("\n[*] Stage 2: Establishing persistence\n");
    initialize_persistence();

    printf("\n[*] Stage 3: C2 communication\n");
    beacon_c2(C2_SERVER, EXFIL_PATH);

    printf("\n[*] Primary C2: %s\n", C2_SERVER);
    printf("[*] Backup C2:  %s\n", C2_BACKUP);

    printf("\n[!] This is a training sample. No malicious actions performed.\n");
    return 0;
}
