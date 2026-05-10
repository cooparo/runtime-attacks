/*
 * victim.c — vulnerable program for iteration 3a (JOP).
 *
 * Same overflow primitive family as iter 1/2 but the redirect path is no
 * longer a hijacked `ret`. Vuln allocates a struct { char buffer[64];
 * void (*cb)(void); } on the stack so cb sits exactly 64 bytes after
 * buffer's start. read(0, c.buffer, 256) deterministically overflows cb,
 * and `c.cb()` compiles to `blr Xn` — the JOP entry pivot.
 *
 *     blr cb     →  jop_gadget   (ldr x16, [sp, #96]; br x16)
 *                →  win()        (_exit(44))
 *
 * AArch64 GCC ignores __attribute__((naked)) (warns "attribute directive
 * ignored"), so jop_gadget actually compiles WITH a prologue/epilogue.
 * That doesn't matter — the exploit jumps to the address of the
 * `ldr x16, [sp, #N]` instruction MID-function (skipping the prologue),
 * the same trick iter-2 ROP uses to land on `ldp x29, x30, [sp], #16`
 * inside stage1/stage2. exploit.py auto-detects both the gadget address
 * and the immediate N from disasm, so the hardcoded `#96` here can change
 * without breaking the chain.
 *
 * Why this slips the iter-1 shadow stack:
 *   - blr cb     pushes the post-blr return site (legitimate behavior).
 *   - br  x16    is decoded but treated as no-op by tracer.c.
 *   - win()      calls _exit(44) — no ret ever fires, so no shadow
 *                stack pop, so no mismatch ever observed.
 *   The tracee terminates "cleanly" from the detector's POV.
 */

#include <unistd.h>

void win(void) {
  write(1, "[!] PWNED via JOP chain\n", 24);
  _exit(44);
}

void default_handler(void) { write(1, "[default_handler]\n", 18); }

__attribute__((naked, used))
void jop_gadget(void) {
  __asm__(
      "ldr x16, [sp, #96]\n\t"
      "br x16\n"
  );
}

struct ctx {
  char buffer[64];
  void (*cb)(void);
};

void vuln(void) {
  struct ctx c;
  c.cb = default_handler;
  write(1, "[victim] enter input: ", 22);
  read(0, c.buffer, 256);
  write(1, "[victim] you entered: ", 22);
  write(1, c.buffer, 64);
  write(1, "\n", 1);
  c.cb();
}

int main(void) {
  write(1, "[victim] JOP target start\n", 26);
  vuln();
  write(1, "[victim] normal exit\n", 21);
  return 0;
}
