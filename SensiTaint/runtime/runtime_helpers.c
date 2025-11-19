#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <signal.h>
#include <string.h>

#include "hashmap.h"

/*
*   This code gets compiled and linked into the executable and used at runtime.
*/

static char shadow_buffer[SHADOW_BUFFER_SIZE + sizeof(uint32_t)];
static SensitiveMap *sensimap;

// Calls to this function are injected in the LLVM code and are used to record the declaration
// of variables that are marked sensitive.
void record_sensitive_var(const char* name, void* ptr, uint64_t sz) {
    if (sensimap->count < (SHADOW_BUFFER_SIZE / sizeof(SensitiveVarInfo))) {
        fprintf(stdout, "[RUNTIME] Tracking '%s' at %p, size: %zu bytes\n", name, ptr, sz);
        hm_insert(sensimap, (uint64_t)ptr, sz);
    } else {
        fprintf(stderr, "[WARN] Shadow buffer overflow!\n");
    }
}

// This is teh handler that we run at a crash. It just iterates through elements in teh
// shadow buffer and memsets them to 0.
static void crash_handler(int sig, siginfo_t *si, void *unused) {
    printf("[CRASH]: Signal %d received, sanitizing sensitive data...\n", sig);
    
    // Memset all of the memory to 0
    for(size_t i = 0; i < (SHADOW_BUFFER_SIZE/sizeof(SensitiveVarInfo)); i++ ) {
        SensitiveVarInfo *iter = &(sensimap->entries)[i];
        if(iter->ptr != 0) {
            printf("[CRASH]: Sanitizing %zu bytes at address %p\n", iter->sz, (void*)iter->ptr);
            memset((void*)iter->ptr, 0, iter->sz); 
        }
    }
    
    printf("[CRASH]: Sanitization complete. Triggering core dump...\n");
    fflush(stdout);
    
    // Reset signal handler to default and re-raise to trigger core dump
    signal(sig, SIG_DFL);
    raise(sig);
}


// This function (marked with the `constructor` attribute) is run right before `main`. 
// All it does is install the appropriate signal handlers. 
// NB: One issue is that a malicious client could potentially undo these signal handlers?
__attribute__((constructor)) 
void initialize_sensitaint() {

    // initialize our hashmap
    sensimap = hm_init(shadow_buffer);

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