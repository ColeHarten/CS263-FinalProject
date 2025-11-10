#ifndef SENSITAINT_HH
#define SENSITAINT_HH
#include <stdio.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "FATAL: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

struct sensitive_node {
    void            *ptr_;
    size_t           sz_;
    sensitive_node  *next_;
};

void register_sensitive(void *ptr, size_t sz);
void erase_sensitive();

#endif

