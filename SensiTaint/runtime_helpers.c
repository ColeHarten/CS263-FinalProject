#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>

#define SHADOW_SIZE (1 << 20)

struct SensitiveVarInfo {
    void* ptr;
    size_t sz;
};

struct SensitiveVarInfo shadow_buffer[SHADOW_SIZE / sizeof(struct SensitiveVarInfo)];
static size_t shadow_index = 0;

void record_sensitive_var(const char* name, void* ptr, size_t sz) {
    if (shadow_index < (SHADOW_SIZE / sizeof(struct SensitiveVarInfo))) {
        fprintf(stdout, "[RUNTIME] Tracking '%s' at %p, size: %zu bytes\n", name, ptr, sz);
        shadow_buffer[shadow_index].ptr = ptr;
        shadow_buffer[shadow_index].sz = sz;
        shadow_index++;
    } else {
        fprintf(stderr, "[WARN] Shadow buffer overflow!\n");
    }
}

static void crash_handler(int sig, siginfo_t *si, void *unused) {
    printf("[CRASH]: Signal %d received, sanitizing sensitive data...\n", sig);
    
    // Memset all of the memory to 0
    for(size_t i = 0; i < shadow_index; i++ ) {
        struct SensitiveVarInfo *iter = &shadow_buffer[i];

        printf("[CRASH]: Sanitizing %zu bytes at address %p\n", iter->sz, iter->ptr);
        memset(iter->ptr, 0, iter->sz); 
    }
    
    printf("[CRASH]: Sanitization complete. Triggering core dump...\n");
    fflush(stdout);
    
    // Reset signal handler to default and re-raise to trigger core dump
    signal(sig, SIG_DFL);
    raise(sig);
}


__attribute__((constructor)) 
void install_handler() {
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = crash_handler;
    
    // Install handlers
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("sigaction SIGSEGV");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGABRT, &sa, NULL) == -1) {
        perror("sigaction SIGABRT");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGFPE, &sa, NULL) == -1) {
        perror("sigaction SIGFPE");
        exit(EXIT_FAILURE);
    }
    if (sigaction(SIGILL, &sa, NULL) == -1) {
        perror("sigaction SIGILL");
        exit(EXIT_FAILURE);
    }
} 