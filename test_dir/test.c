#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include "sensitive.h"


void func(int data) {
    return data + 100;
}

// struct test {
//     int x_;
//     int y_;
// };

int main() {
    // volatile sensitive int x = 0xfeedbeef;
    // printf("Address of `x`: %p\n", &x);

    // volatile int y = 0xbeeffeed;

    // volatile sensitive int *z = malloc(4);
    // *z = 0xdeadbeef;
    
    // struct test t;
    // t.x_ = x;
    // t.y_ = y;

    // int w = x;

    // int q = x + 1;

    // func();

    // trigger a core dump
    // raise(SIGSEGV);

    sensitive int password = 0xDEADBEEF;

    // phasar should mark copy as tainted and both should get sanitized
    int copy = password;
    
    printf("Password: %x\n", password);
    printf("Copy: %x\n", copy);

    // // phasar should mark this as tainted as it's a func call with sensitive var
    // int result = func(secret);
    
    // printf("Secret: %x\n", secret);
    // printf("Result: %x\n", result);
    
    raise(SIGSEGV);

    return 0;
}