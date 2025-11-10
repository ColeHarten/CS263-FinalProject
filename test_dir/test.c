#define sensitive __attribute__((annotate("sensitive")))

int main() {

    sensitive int x = 5;
    int y = 10;


    return 0;
}