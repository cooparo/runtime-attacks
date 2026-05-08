#include <stdio.h>
#include <string.h>

void safe() {
    printf("Safe function\n");
}

void dangerous() {
    printf("Dangerous function reached\n");
}

struct Data {
    char buffer[32];
    void (*func)();
};

void vulnerable(char *input) {
    struct Data d;

    d.func = safe;

    strcpy(d.buffer, input);

    d.func();
}

int main(int argc, char *argv[]) {
    if (argc < 2)
        return 1;

    vulnerable(argv[1]);
    return 0;
}
