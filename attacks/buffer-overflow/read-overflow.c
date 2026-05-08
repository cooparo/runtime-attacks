#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buffer[32];

    read(0, buffer, 128);

    printf("Done\n");
}

int main() {
    vulnerable();
    return 0;
}
