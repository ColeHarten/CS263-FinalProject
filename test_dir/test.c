#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include "sensitive.h"

int inc(int val) {
    return val + 1;
}

int main() {    
    // Enable a sensitive variable to ensure runtime is initialized
    int x = 0xfeedbeef - 1;
    
    int y = x + 1;

    int z = inc(y);

    return 0;
}