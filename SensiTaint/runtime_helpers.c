#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SHADOW_SIZE (1 << 20)

struct SensitiveVarInfo {
    void* ptr;
    size_t size;
};

struct SensitiveVarInfo shadow_buffer[SHADOW_SIZE / sizeof(struct SensitiveVarInfo)];
static size_t shadow_index = 0;

void record_sensitive_var(const char* name, void* ptr, size_t sz) {
    if (shadow_index < (SHADOW_SIZE / sizeof(struct SensitiveVarInfo))) {
        fprintf(stdout, "[RUNTIME] Tracking '%s' at %p, size: %zu bytes\n", name, ptr, sz);
        shadow_buffer[shadow_index].ptr = ptr;
        shadow_buffer[shadow_index].size = sz;
        shadow_index++;
    } else {
        fprintf(stderr, "[WARN] Shadow buffer overflow!\n");
    }
}
