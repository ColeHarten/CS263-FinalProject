#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include "sensitive.h"

// sensitive int glob = 10;

// int mult(int a, int b) {
//     sensitive int ret = a * b;
//     return ret;
// }

struct test {
    int x_;
    int y_;
};

int main() {
    volatile sensitive int x = 0xfeedbeef;
    printf("Address of `x`: %p\n", &x);

    volatile int y = 0xbeeffeed;

    volatile sensitive int *z = malloc(4);
    *z = 0xdeadbeef;
    
    // struct test t;
    // t.x_ = x;
    // t.y_ = y;

    // int w = x;

    // int q = x + 1;

    // int k = mult(x, 10);

    // trigger a core dump
    raise(SIGSEGV);

    return 0;
}