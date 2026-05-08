#include <stdio.h>

/* manual declaration */
char *gets(char *s);   //this is because "gets" was removed from a new GCC . That is why we do it manually (imitating it)

void vulnerable() {
    char buffer[32];

    printf("Input: ");
    gets(buffer);

    printf("You entered: %s\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}
