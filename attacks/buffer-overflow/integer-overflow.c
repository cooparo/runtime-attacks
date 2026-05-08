#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable(int len, char *input) {
    char *buffer = malloc(len);

    memcpy(buffer, input, strlen(input));

    printf("Done\n");

    free(buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 3)
        return 1;

    vulnerable(atoi(argv[1]), argv[2]);
    return 0;
}
