#include <signal.h>
#include "sensitive.h"

sensitive int glob = 10;

int main() {

    volatile sensitive int x = 0xfeedbeef;
    volatile int y = 0xbeeffeed;

    int z = 10;

    // trigger a core dump
    raise(SIGSEGV);

    return 0;
}