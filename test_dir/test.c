#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include "sensitive.h"

// sensitive int glob = 10;

int main() {

    volatile sensitive int x = 0xfeedbeef;
    volatile int y = 0xbeeffeed;

    volatile int *z = malloc(4);
    *z = 0xdeadbeef;

    printf("Address of `z`: %p\n",z);

    // trigger a core dump
    raise(SIGSEGV);

    return 0;
}