#include <signal.h>
#include "../SensiTaint/sensitive.h"


int main() {

    sensitive int x = 5;
    int y = 10;


    // trigger a core dump
    // raise(SIGSEGV);

    return 0;
}