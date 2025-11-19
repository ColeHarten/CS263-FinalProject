#include "hashmap.h"
#include <string.h>

/*
*   This is just a pretty standard implementation of an open-addressed hashmap.
*   To handle the issues that arise with deletion, I chose to use the backward shift
*   deletion algorithm to avoid having to use tombstones. It is cause a somewhat large
*   overhead, however; so perhaps this should only be used for heap variables, with a
*   more efficient implementation using a shadow stack for the stack variables.
*/

#define CAP ((SHADOW_BUFFER_SIZE - sizeof(uint32_t))/ sizeof(SensitiveVarInfo))

static inline uint32_t hash_ptr(uint64_t ptr) {
    uint64_t z = ptr + 0x9e3779b97f4a7c15ULL;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    z = z ^ (z >> 31);
    return (uint32_t)(z ^ (z >> 32));
}

SensitiveMap *hm_init(void *buffer) {
    SensitiveMap *mp = (SensitiveMap *)buffer;
    memset(buffer, 0, SHADOW_BUFFER_SIZE);
    mp->count = 0;

    return mp;
}

// linear probing! (maybe quad-hashing is better?)
static SensitiveVarInfo *probe(SensitiveMap *mp, uint64_t ptr, int find_empty) {
    uint32_t hsh = hash_ptr(ptr) % CAP;
    uint32_t start = hsh;

    do {
        SensitiveVarInfo *e = &mp->entries[hsh];
        
        if (e->ptr == 0) {
            if (find_empty)
                return e;    // return this slot to be filled
            else 
                return NULL; // not found, hit empty slot
        }
        if (e->ptr == ptr)   // if we found the value, return it
            return e;
        hsh = (hsh + 1) % CAP;
    } while (hsh != start); 

    return NULL;
}

int hm_insert(SensitiveMap *mp, uint64_t ptr, uint64_t sz) {
    if (mp->count == CAP)
        return -1;
    
    SensitiveVarInfo *e = probe(mp, ptr, 1);
    if (!e)
        return -1;

    // If overwriting existing key
    if (e->ptr != 0 && e->ptr == ptr) {
        e->sz = sz;
        return 0;
    }

    // If inserting new into empty slot
    e->ptr = ptr;
    e->sz = sz;
    mp->count++;

    return 0;
}

// remove the element and return the size (so we know how much to memset)
uint64_t hm_remove(SensitiveMap *mp, uint64_t ptr) {
    SensitiveVarInfo *e = probe(mp, ptr, 0);
    if (!e)
        return 0;

    uint64_t sz = e->sz;
    uint32_t hole = e - mp->entries;

    // Walk until we reach an empty slot
    uint32_t i = (hole + 1) % CAP;

    while (mp->entries[i].ptr != 0) {
        uint32_t ideal = hash_ptr(mp->entries[i].ptr) % CAP;

        // Check if this key's natural interval covers the hole
        // Condition: ideal <= hole < i in circular sense
        uint32_t dist_i = (i - ideal + CAP) % CAP;
        uint32_t dist_h = (hole - ideal + CAP) % CAP;

        if (dist_h < dist_i) {
            // Move entry at i back into the hole
            mp->entries[hole] = mp->entries[i];
            hole = i;
        }

        i = (i + 1) % CAP;
    }

    // Clear final hole
    mp->entries[hole].ptr = 0;
    mp->entries[hole].sz = 0;

    mp->count--;
    return sz;
}
