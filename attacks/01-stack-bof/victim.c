/*
 * victim.c — vulnerable program for iteration 1.
 *
 * vuln() is non-leaf (calls write/read), so the AArch64 prologue
 * spills X30 (LR) to the stack. read() into a 64-byte buffer with
 * a 256-byte read length lets the input overflow past the buffer
 * and overwrite the saved-X30 slot. When vuln() returns, the
 * loaded X30 is the attacker's value and ret jumps there.
 *
 * win() is the redirect target used to confirm successful exploitation.
 */

#include <unistd.h>

void win(void) {
  write(1, "[!] PWNED -- control flow hijacked\n", 35);
  _exit(42);
}

void vuln(void) {
  char buffer[64];
  write(1, "[victim] enter input: ", 22);
  read(0, buffer, 256);
  write(1, "[victim] you entered: ", 22);
  write(1, buffer, 64);
  write(1, "\n", 1);
}

int main(void) {
  write(1, "[victim] start\n", 15);
  vuln();
  write(1, "[victim] normal exit\n", 21);
  return 0;
}
