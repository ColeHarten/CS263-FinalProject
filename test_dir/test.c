#include <signal.h>
#include "sensitive.h"

sensitive int glob = 10;

int main() {

    sensitive int x = 5;
    sensitive int y = 5;

    int z = 10;


    // trigger a core dump
    raise(SIGSEGV);

    return 0;
}