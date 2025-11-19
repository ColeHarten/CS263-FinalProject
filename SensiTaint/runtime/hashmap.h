#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdint.h>
#include <stddef.h>

#define SHADOW_BUFFER_SIZE (1 << 20)

typedef struct {
    uint64_t ptr;
    uint64_t sz;
} SensitiveVarInfo;

typedef struct {
    uint32_t count;
    SensitiveVarInfo entries[];   
} SensitiveMap;

SensitiveMap *hm_init(void *buffer);

int hm_insert(SensitiveMap *mp, uint64_t ptr, uint64_t sz);

uint64_t hm_remove(SensitiveMap *mp, uint64_t ptr);

#endif
