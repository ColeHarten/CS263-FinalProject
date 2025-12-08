#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include "sensitive.h"


int main() {    
    // Enable a sensitive variable to ensure runtime is initialized
    sensitive volatile int x = 0xfeedbeef;
    
    int y = x + 1;
    
    int *ptr = NULL;
    *ptr = 43;

    return 0;
}