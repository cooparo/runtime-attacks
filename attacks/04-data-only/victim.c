/*
 * victim.c - iteration 4 (data-only / non-control-data attack).
 *
 * Demonstrates the L1 (control-flow) detection gap. A stack buffer
 * overflow that does NOT hijack any control-flow transfer - it stomps
 * an adjacent NON-control variable instead. Every branch, call, and
 * return the program takes in the exploited run is also one that a
 * benign run could legitimately take, so the CFG-edge / shadow-stack /
 * call-target detector reports clean even though admin_panel() leaks.
 *
 * Layout:
 *
 *     struct user { char name[32]; int is_admin; };   // 36 bytes, no padding
 *
 * read(0, u.name, 256) lets attacker bytes 32..35 spill into is_admin.
 * The exploit deliberately stops the write at byte 36 so saved x29/x30
 * above the struct stay intact - any further overflow would corrupt
 * main's saved x30 and the detector would catch it at `ret`.
 *
 *     if (u.is_admin) admin_panel();   // legal CFG edge; flipped by data
 *
 * The same `bl admin_panel` that benign control *could* legitimately
 * reach (if is_admin were ever truly set) is now reached under attacker
 * data. This is the canonical "non-control-data attack" (Chen, Xu,
 * Sezer, Gauriar, Iyer, USENIX Sec 2005). L1 cannot catch it; detection
 * needs
 *   - L2 data provenance  - flag that is_admin's value came from
 *                           attacker-controlled stdin bytes, or
 *   - L3 object-bounds    - prevent the write past name[32] in the
 *                           first place.
 */

#include <string.h>
#include <unistd.h>

struct user {
  char name[32];
  int  is_admin;
};

static void greet(const struct user *u) {
  /* u.name may not be NUL-terminated after the read - print up to the
   * first NUL or the fixed field width. */
  size_t len = 0;
  while (len < sizeof u->name && u->name[len] != '\0') len++;
  write(1, "[victim] hello, ", 16);
  write(1, u->name, len);
  write(1, "\n", 1);
}

static void admin_panel(void) {
  write(1, "[ADMIN] secret = s3cr3t\n", 24);
}

int main(void) {
  struct user u;
  memset(&u, 0, sizeof u);

  write(1, "[victim] name? ", 15);
  /* Deliberate bug: 256-byte read into a 32-byte field. The attack
   * limits its input to 36 bytes so only is_admin is overwritten. */
  ssize_t n = read(0, u.name, 256);
  if (n < 0) return 1;

  /* Strip a trailing newline (benign input arrives via `echo`). */
  for (size_t i = 0; i < sizeof u.name; i++)
    if (u.name[i] == '\n') { u.name[i] = 0; break; }

  greet(&u);

  if (u.is_admin) admin_panel();
  else            write(1, "[victim] (regular user)\n", 24);
  return 0;
}
