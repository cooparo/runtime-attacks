#include <stdio.h>

void vulnerable() {
    char buffer[16];

    scanf("%s", buffer);

    printf("%s\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}
