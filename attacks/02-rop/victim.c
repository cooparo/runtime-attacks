/*
 * victim.c — vulnerable program for iteration 2 (ROP).
 *
 * Same overflow primitive as 01-stack-bof: read(0, buffer, 256) into a
 * 64-byte stack buffer in vuln(). Past vuln's frame the overflow reaches
 * main's saved-X30 slot.
 *
 * Iter 1 used a single 8-byte payload (just win()'s address) to land at
 * win() in one ret. This iter chains through TWO gadgets first:
 *
 *     main.epilogue.ret  → stage1.epilogue (ldp x29,x30,[sp],#N; ret)
 *                        → stage2.epilogue (ldp x29,x30,[sp],#N; ret)
 *                        → win()
 *
 * stage1/stage2 are never called by the program; their bodies exist only
 * to give us function epilogues to use as ROP gadgets. We jump mid-function
 * to the `ldp x29, x30, [sp], #N; ret` pair, which pops a fresh x29/x30
 * pair from the controlled stack and rets to the next gadget.
 */

#include <unistd.h>

void win(void) {
  write(1, "[!] PWNED via ROP chain\n", 24);
  _exit(43);
}

void stage2(void) { write(1, "[stage2] reached\n", 17); }

void stage1(void) { write(1, "[stage1] reached\n", 17); }

void vuln(void) {
  char buffer[64];
  write(1, "[victim] enter input: ", 22);
  read(0, buffer, 256);
  write(1, "[victim] you entered: ", 22);
  write(1, buffer, 64);
  write(1, "\n", 1);
}

int main(void) {
  write(1, "[victim] ROP target start\n", 26);
  vuln();
  write(1, "[victim] normal exit\n", 21);
  return 0;
}
