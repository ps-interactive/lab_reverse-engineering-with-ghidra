/*
 * sample_reflective.c - Simulated malware with reflective loading
 * CarvedRock Security Training - In-Memory Execution Analysis Sample
 *
 * Demonstrates reflective loading techniques:
 * - mmap() to allocate executable memory
 * - Shellcode-style payload injection
 * - Self-modifying code patterns
 * - Process memory manipulation via /proc/self/maps
 *
 * Learners trace the injection mechanism and execution flow in Ghidra.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Simulated shellcode payload (just returns 42 - harmless) */
/* This is x86_64: mov eax, 42; ret */
unsigned char shellcode_payload[] = {
    0xB8, 0x2A, 0x00, 0x00, 0x00,  /* mov eax, 42 */
    0xC3                             /* ret */
};

#define PAYLOAD_SIZE sizeof(shellcode_payload)

/* Target process name for injection simulation */
const char *TARGET_PROCESS = "carvedrock-webapp";
const char *INJECTED_MODULE = "libcr_helper.so";

/*
 * reflective_alloc - Allocates RWX memory region
 * Uses mmap with PROT_READ|PROT_WRITE|PROT_EXEC
 * This is a key indicator of reflective loading.
 */
void *reflective_alloc(size_t size) {
    void *mem = mmap(NULL, size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS,
                     -1, 0);

    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return NULL;
    }

    printf("[*] Allocated RWX memory at: %p (size: %zu)\n", mem, size);
    return mem;
}

/*
 * reflective_inject - Copies payload into executable memory
 * Simulates the injection of code into the allocated region.
 */
int reflective_inject(void *target_mem, unsigned char *payload, size_t payload_len) {
    printf("[*] Injecting payload (%zu bytes) into memory at %p\n",
           payload_len, target_mem);

    /* Copy shellcode into executable memory */
    memcpy(target_mem, payload, payload_len);

    printf("[+] Payload injected successfully\n");
    return 0;
}

/*
 * reflective_execute - Executes code from injected memory
 * Casts memory region to function pointer and calls it.
 * This pattern is the hallmark of reflective code execution.
 */
int reflective_execute(void *code_addr) {
    printf("[*] Executing payload from memory at %p\n", code_addr);

    /* Cast memory to function pointer and execute */
    int (*payload_func)(void) = (int (*)(void))code_addr;
    int result = payload_func();

    printf("[+] Payload returned: %d\n", result);
    return result;
}

/*
 * enumerate_memory_regions - Reads /proc/self/maps
 * Adversaries use this to understand the process memory layout
 * before injection. Learners will see this in the decompiled code.
 */
void enumerate_memory_regions(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[256];
    int count = 0;

    printf("[*] Enumerating process memory regions:\n");

    if (maps == NULL) {
        perror("Cannot read /proc/self/maps");
        return;
    }

    while (fgets(line, sizeof(line), maps) && count < 10) {
        printf("    %s", line);
        count++;
    }

    if (count >= 10) {
        printf("    ... (truncated)\n");
    }

    fclose(maps);
}

/*
 * check_debugger - Anti-analysis technique
 * Checks /proc/self/status for TracerPid to detect debuggers.
 */
int check_debugger(void) {
    FILE *status = fopen("/proc/self/status", "r");
    char line[256];

    if (status == NULL) return 0;

    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(status);
            if (tracer_pid != 0) {
                printf("[!] Debugger detected (TracerPid: %d)\n", tracer_pid);
                return 1;
            }
            printf("[*] No debugger detected\n");
            return 0;
        }
    }

    fclose(status);
    return 0;
}

/*
 * cleanup_traces - Removes evidence of injection
 * Uses munmap to deallocate the injected memory region.
 */
void cleanup_traces(void *mem, size_t size) {
    printf("[*] Cleaning up: deallocating memory at %p\n", mem);
    munmap(mem, size);
    printf("[+] Memory region released\n");
}

int main(int argc, char *argv[]) {
    void *exec_mem = NULL;
    int result = 0;

    printf("=== CarvedRock Threat Sample - Reflective Loader ===\n\n");

    /* Phase 1: Anti-analysis check */
    printf("[*] Phase 1: Anti-analysis checks\n");
    if (check_debugger()) {
        printf("[!] Exiting due to debugger presence\n");
        /* In real malware this would exit - we continue for training */
    }

    /* Phase 2: Memory enumeration */
    printf("\n[*] Phase 2: Memory enumeration\n");
    enumerate_memory_regions();

    /* Phase 3: Reflective loading */
    printf("\n[*] Phase 3: Reflective loading sequence\n");
    printf("[*] Target process: %s\n", TARGET_PROCESS);
    printf("[*] Module to inject: %s\n", INJECTED_MODULE);

    /* Allocate executable memory */
    exec_mem = reflective_alloc(4096);
    if (exec_mem == NULL) {
        printf("[-] Failed to allocate executable memory\n");
        return 1;
    }

    /* Inject payload */
    if (reflective_inject(exec_mem, shellcode_payload, PAYLOAD_SIZE) != 0) {
        printf("[-] Injection failed\n");
        cleanup_traces(exec_mem, 4096);
        return 1;
    }

    /* Execute injected code */
    result = reflective_execute(exec_mem);
    printf("[*] Execution result: %d (expected: 42)\n", result);

    /* Phase 4: Cleanup */
    printf("\n[*] Phase 4: Cleanup\n");
    cleanup_traces(exec_mem, 4096);

    printf("\n[!] This is a training sample. No malicious actions performed.\n");
    return 0;
}
