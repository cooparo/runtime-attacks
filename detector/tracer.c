/*
 * tracer.c — iteration 1 detector.
 *
 * Forks the victim, attaches via PTRACE_TRACEME, then:
 *   1. plants a one-shot BRK at the victim ELF's e_entry (skips ld.so
 *      and libc startup, both of which would otherwise dominate runtime
 *      under single-step);
 *   2. PTRACE_CONTs until that BRK fires;
 *   3. restores the original instruction at e_entry and enters the
 *      single-step loop.
 *
 * In the loop, decode happens BEFORE the step: we peek the instruction
 * at the current PC and act on it after the step lands. After a taken
 * branch the post-step PC points at the branch target, not at PC-4 of
 * the original branch, so a post-step decode at PC-4 would read garbage
 * for exactly the instructions we care about.
 *
 *   - bl  imm    : after step, push (pre_pc + 4) to shadow stack
 *   - blr Xn     : after step, push (pre_pc + 4) to shadow stack
 *   - ret        : after step, compare actual PC against shadow-stack top
 *                   → mismatch = ATTACK
 *
 * Direct b/b.cond and indirect br are unhandled in this iteration
 * (no CFG validation yet — deferred to iter 2).
 */

#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include "shadow_stack.h"

typedef enum {
  INSN_OTHER = 0,
  INSN_BL,
  INSN_BLR,
  INSN_BR,
  INSN_RET,
} insn_kind_t;

/*
 * AArch64 branch encodings (32-bit, little-endian):
 *   bl  imm26 : top 6 bits = 0b100101            → (insn >> 26) == 0x25
 *   blr Xn    : 11010110 0011 1111 0000 00 Rn 00000  → (insn & 0xFFFFFC1F) ==
 * 0xD63F0000 br  Xn    : 11010110 0001 1111 0000 00 Rn 00000  → (insn &
 * 0xFFFFFC1F) == 0xD61F0000 ret Xn    : 11010110 0101 1111 0000 00 Rn 00000  →
 * (insn & 0xFFFFFC1F) == 0xD65F0000
 */
static insn_kind_t decode_branch(uint32_t insn) {
  if ((insn >> 26) == 0x25)
    return INSN_BL;
  if ((insn & 0xFFFFFC1FU) == 0xD63F0000U)
    return INSN_BLR;
  if ((insn & 0xFFFFFC1FU) == 0xD61F0000U)
    return INSN_BR;
  if ((insn & 0xFFFFFC1FU) == 0xD65F0000U)
    return INSN_RET;
  return INSN_OTHER;
}

static int read_regs(pid_t pid, struct user_regs_struct *regs) {
  struct iovec iov = {.iov_base = regs, .iov_len = sizeof(*regs)};
  return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov);
}

static int peek_insn(pid_t pid, uint64_t addr, uint32_t *out) {
  errno = 0;
  long word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(uintptr_t)addr, NULL);
  if (word == -1 && errno != 0)
    return -1;
  *out = (uint32_t)((uint64_t)word & 0xFFFFFFFFULL);
  return 0;
}

/* AArch64 BRK #0 — synchronous breakpoint, raises SIGTRAP. */
#define BRK_INSN 0xD4200000U

/*
 * Plant a 4-byte BRK at addr while preserving the adjacent 4 bytes.
 * PTRACE_PEEKTEXT/POKETEXT operate on 8-byte words on aarch64, so we
 * read 8 bytes, replace only the low 4 (little-endian => bytes at addr).
 */
static int plant_breakpoint(pid_t pid, uint64_t addr, uint32_t *orig_out) {
  errno = 0;
  long word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(uintptr_t)addr, NULL);
  if (word == -1 && errno != 0)
    return -1;
  *orig_out = (uint32_t)((uint64_t)word & 0xFFFFFFFFULL);
  uint64_t patched =
      ((uint64_t)word & 0xFFFFFFFF00000000ULL) | (uint64_t)BRK_INSN;
  if (ptrace(PTRACE_POKETEXT, pid, (void *)(uintptr_t)addr,
             (void *)(uintptr_t)patched) < 0)
    return -1;
  return 0;
}

static int restore_breakpoint(pid_t pid, uint64_t addr, uint32_t orig_insn) {
  errno = 0;
  long word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(uintptr_t)addr, NULL);
  if (word == -1 && errno != 0)
    return -1;
  uint64_t restored =
      ((uint64_t)word & 0xFFFFFFFF00000000ULL) | (uint64_t)orig_insn;
  if (ptrace(PTRACE_POKETEXT, pid, (void *)(uintptr_t)addr,
             (void *)(uintptr_t)restored) < 0)
    return -1;
  return 0;
}

static int read_elf_entry(const char *path, uint64_t *entry_out) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  Elf64_Ehdr ehdr;
  if (fread(&ehdr, sizeof(ehdr), 1, f) != 1) {
    fclose(f);
    return -1;
  }
  fclose(f);
  if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
    return -1;
  if (ehdr.e_ident[EI_CLASS] != ELFCLASS64)
    return -1;
  *entry_out = (uint64_t)ehdr.e_entry;
  return 0;
}

/*
 * Look up a STT_FUNC symbol by name in the ELF's .symtab.
 * Returns 0 on success and writes st_value to *out, -1 otherwise.
 * Used to find `main` so we can skip glibc startup with a BRK there.
 */
static int find_symbol(const char *path, const char *symname, uint64_t *out) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;

  int rc = -1;
  Elf64_Shdr *shdrs = NULL;
  char *strtab = NULL;
  Elf64_Sym *syms = NULL;

  Elf64_Ehdr eh;
  if (fread(&eh, sizeof(eh), 1, f) != 1)
    goto out;
  if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0)
    goto out;
  if (eh.e_ident[EI_CLASS] != ELFCLASS64)
    goto out;

  shdrs = calloc(eh.e_shnum, sizeof(*shdrs));
  if (!shdrs)
    goto out;
  if (fseek(f, (long)eh.e_shoff, SEEK_SET) < 0)
    goto out;
  if (fread(shdrs, sizeof(*shdrs), eh.e_shnum, f) != eh.e_shnum)
    goto out;

  int symtab_idx = -1;
  for (size_t i = 0; i < eh.e_shnum; i++) {
    if (shdrs[i].sh_type == SHT_SYMTAB) {
      symtab_idx = (int)i;
      break;
    }
  }
  if (symtab_idx < 0)
    goto out;

  int strtab_idx = (int)shdrs[symtab_idx].sh_link;
  if (strtab_idx < 0 || strtab_idx >= (int)eh.e_shnum)
    goto out;

  size_t strsz = (size_t)shdrs[strtab_idx].sh_size;
  strtab = malloc(strsz);
  if (!strtab)
    goto out;
  if (fseek(f, (long)shdrs[strtab_idx].sh_offset, SEEK_SET) < 0)
    goto out;
  if (fread(strtab, 1, strsz, f) != strsz)
    goto out;

  size_t symsz = (size_t)shdrs[symtab_idx].sh_size;
  size_t nsyms = symsz / sizeof(Elf64_Sym);
  syms = malloc(symsz);
  if (!syms)
    goto out;
  if (fseek(f, (long)shdrs[symtab_idx].sh_offset, SEEK_SET) < 0)
    goto out;
  if (fread(syms, sizeof(*syms), nsyms, f) != nsyms)
    goto out;

  for (size_t i = 0; i < nsyms; i++) {
    if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC)
      continue;
    if (syms[i].st_name >= strsz)
      continue;
    if (strcmp(strtab + syms[i].st_name, symname) == 0) {
      *out = (uint64_t)syms[i].st_value;
      rc = 0;
      break;
    }
  }

out:
  free(shdrs);
  free(strtab);
  free(syms);
  fclose(f);
  return rc;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <victim_binary> [args...]\n", argv[0]);
    return 1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    /* Child: opt into being traced, then exec the victim. */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
      perror("ptrace(TRACEME)");
      _exit(127);
    }
    execv(argv[1], &argv[1]);
    perror("execv");
    _exit(127);
  }

  /* Parent: tracer. */
  shadow_stack_init();
  fprintf(stderr, "[tracer] pid=%d binary=%s\n", pid, argv[1]);

  int status;
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid");
    return 1;
  }
  if (!WIFSTOPPED(status)) {
    fprintf(stderr, "[tracer] tracee did not stop after exec\n");
    return 1;
  }

  /*
   * Plant a one-shot BRK at `main` (or fall back to e_entry if the
   * symbol isn't in the table) and PTRACE_CONT through ld.so + glibc
   * startup. Single-stepping the dynamic linker and __libc_start_main
   * is prohibitively slow under PTRACE_SINGLESTEP, and they aren't
   * what we're trying to validate.
   */
  uint64_t bp_addr;
  const char *bp_name;
  if (find_symbol(argv[1], "main", &bp_addr) == 0) {
    bp_name = "main";
  } else if (read_elf_entry(argv[1], &bp_addr) == 0) {
    bp_name = "e_entry";
    fprintf(stderr,
            "[tracer] symbol `main` not found, falling back to e_entry\n");
  } else {
    fprintf(stderr, "[tracer] cannot parse ELF of %s\n", argv[1]);
    return 1;
  }
  fprintf(stderr,
          "[tracer] %s=0x%lx — running pre-main code under PTRACE_CONT\n",
          bp_name, bp_addr);

  uint32_t orig_at_bp;
  if (plant_breakpoint(pid, bp_addr, &orig_at_bp) < 0) {
    perror("plant_breakpoint");
    return 1;
  }

  if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
    perror("PTRACE_CONT (to bp)");
    return 1;
  }
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid(bp)");
    return 1;
  }
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
    fprintf(stderr, "[tracer] expected SIGTRAP at %s; got status=0x%x\n",
            bp_name, status);
    return 1;
  }
  uint64_t initial_x30;
  {
    struct user_regs_struct r;
    if (read_regs(pid, &r) < 0) {
      perror("read_regs(bp)");
      return 1;
    }
    if (r.pc != bp_addr) {
      fprintf(stderr, "[tracer] BRK fired at PC=0x%llx, expected %s=0x%lx\n",
              (unsigned long long)r.pc, bp_name, bp_addr);
      return 1;
    }
    initial_x30 = (uint64_t)r.regs[30];
  }
  if (restore_breakpoint(pid, bp_addr, orig_at_bp) < 0) {
    perror("restore_breakpoint");
    return 1;
  }

  /*
   * Pre-push X30 (= the address that called us, e.g. __libc_start_main's
   * continuation when bp_name == "main"). This makes main's epilogue ret
   * verifiable: we never saw the bl that called main (PTRACE_CONT skipped
   * it), but we know the legitimate return address right now and want to
   * detect any corruption of main's saved x30.
   */
  shadow_stack_push(initial_x30);
  fprintf(stderr,
          "[tracer] reached %s — pre-pushed initial X30=0x%lx; switching to "
          "single-step\n",
          bp_name, initial_x30);

  size_t step_count = 0;
  size_t bl_count = 0;
  size_t ret_count = 0;
  size_t alert_count = 0;

  for (;;) {
    /* PRE-STEP: read PC, peek instruction about to execute, decode. */
    struct user_regs_struct pre;
    if (read_regs(pid, &pre) < 0) {
      perror("PTRACE_GETREGSET (pre)");
      return 1;
    }
    uint64_t pre_pc = pre.pc;

    uint32_t insn;
    insn_kind_t kind = INSN_OTHER;
    if (peek_insn(pid, pre_pc, &insn) == 0) {
      kind = decode_branch(insn);
    }

    /* STEP. */
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
      perror("PTRACE_SINGLESTEP");
      return 1;
    }
    if (waitpid(pid, &status, 0) < 0) {
      perror("waitpid");
      return 1;
    }

    if (WIFEXITED(status)) {
      fprintf(stderr,
              "[tracer] tracee exited status=%d  steps=%zu  bl=%zu  ret=%zu  "
              "alerts=%zu\n",
              WEXITSTATUS(status), step_count, bl_count, ret_count,
              alert_count);
      return alert_count > 0 ? 2 : 0;
    }
    if (WIFSIGNALED(status)) {
      fprintf(stderr, "[tracer] tracee killed by signal %d  alerts=%zu\n",
              WTERMSIG(status), alert_count);
      return alert_count > 0 ? 2 : 1;
    }
    if (!WIFSTOPPED(status))
      continue;

    int sig = WSTOPSIG(status);
    if (sig != SIGTRAP) {
      /* Forward the signal back to the tracee. */
      if (ptrace(PTRACE_SINGLESTEP, pid, NULL, (void *)(long)sig) < 0) {
        perror("PTRACE_SINGLESTEP forward");
        return 1;
      }
      continue;
    }

    step_count++;

    switch (kind) {
    case INSN_BL:
    case INSN_BLR: {
      /* Return address pushed by the call = pre_pc + 4. */
      shadow_stack_push(pre_pc + 4);
      bl_count++;
      break;
    }
    case INSN_RET: {
      struct user_regs_struct post;
      if (read_regs(pid, &post) < 0) {
        perror("PTRACE_GETREGSET (post)");
        return 1;
      }
      uint64_t actual = post.pc;
      uint64_t expected;
      if (shadow_stack_pop(&expected) < 0) {
        /* Pre-push at startup makes this unreachable in normal runs. */
        fprintf(stderr, "[tracer] BUG: ret at 0x%lx with empty shadow stack\n",
                pre_pc);
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        return 1;
      }
      ret_count++;
      if (actual != expected) {
        fprintf(stderr,
                "\n[!!! ATTACK DETECTED] ret at 0x%lx: expected 0x%lx, got "
                "0x%lx (depth=%zu, step=%zu)\n",
                pre_pc, expected, actual, shadow_stack_depth(), step_count);
        alert_count++;
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        waitpid(pid, &status, 0);
        fprintf(stderr,
                "[tracer] tracee killed after detection  steps=%zu  bl=%zu  "
                "ret=%zu\n",
                step_count, bl_count, ret_count);
        return 2;
      }
      if (shadow_stack_depth() == 0) {
        /*
         * The pre-pushed return has just been consumed → main has
         * returned cleanly. User-code instrumentation is done;
         * detach and let glibc cleanup + _exit run unobserved.
         */
        fprintf(stderr,
                "[tracer] depth=0 after ret at 0x%lx — main returned cleanly, "
                "detaching\n",
                pre_pc);
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
          perror("PTRACE_DETACH");
          return 1;
        }
        if (waitpid(pid, &status, 0) < 0) {
          perror("waitpid (detach)");
          return 1;
        }
        if (WIFEXITED(status)) {
          fprintf(stderr,
                  "[tracer] tracee exited status=%d  steps=%zu  bl=%zu  "
                  "ret=%zu  alerts=%zu\n",
                  WEXITSTATUS(status), step_count, bl_count, ret_count,
                  alert_count);
          return alert_count > 0 ? 2 : 0;
        }
        if (WIFSIGNALED(status)) {
          fprintf(
              stderr,
              "[tracer] tracee killed by signal %d after detach  alerts=%zu\n",
              WTERMSIG(status), alert_count);
          return alert_count > 0 ? 2 : 1;
        }
        fprintf(stderr, "[tracer] unexpected post-detach status=0x%x\n",
                status);
        return alert_count > 0 ? 2 : 1;
      }
      break;
    }
    case INSN_BR:
    case INSN_OTHER:
    default:
      break;
    }
  }
}
