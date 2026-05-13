/*
 * tracer.c — C-FLAT-style control-flow integrity monitor (L1).
 *
 * Runs the victim under ptrace single-step and validates *every taken
 * control-flow transfer* inside the victim's .text against a statically
 * recovered CFG (see tools/build_cfg.py and detector/cfg.c):
 *
 *   - bl / blr into .text  -> destination must be a legal call target
 *                             (cfg_is_call_target: a function that is called
 *                             directly somewhere, or whose address is taken);
 *                             push return site onto the shadow call stack.
 *   - bl / blr / br whose target leaves .text  -> a library (PLT->libc)
 *                             call: plant a one-shot BRK at the return
 *                             site and PTRACE_CONT over libc instead of
 *                             single-stepping it (C-FLAT attests the app,
 *                             not libc).
 *   - ret                  -> destination must equal the shadow-stack top.
 *   - direct / conditional branch (b, b.<cc>, cbz/cbnz, tbz/tbnz) taken
 *                          -> (branch_site -> destination) must be a known
 *                             CFG edge (cfg_has_edge).
 *   - br Xn into .text     -> destination must be a known basic-block
 *                             start or call target (conservative — catches
 *                             JOP gadget chains and wild jumps).
 *
 * Any violation -> "[!!! ATTACK DETECTED] ..." on stderr, PTRACE_KILL,
 * exit 2. On every exit the cumulative hash chain (hashchain.c) over the
 * executed transfers is printed as "[attestation] cfg-hash = 0x...".
 *
 * Decode happens BEFORE the step: we peek the instruction at the current
 * PC, single-step, then look at the post-step PC. After a taken branch
 * the post-step PC is the branch target, not PC-4 of the branch, so a
 * post-step decode would read the wrong instruction.
 *
 * Startup: fork + PTRACE_TRACEME + exec; plant a one-shot BRK at `main`
 * (fallback: ELF e_entry) and PTRACE_CONT through ld.so + glibc startup
 * (single-stepping those is prohibitively slow and isn't what we attest);
 * restore the instruction, pre-push the initial X30 so main's epilogue
 * ret is checkable, then single-step. Pre-main code (.init_array) and
 * post-detach glibc cleanup run unobserved — out of scope, as before.
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

#include "cfg.h"
#include "hashchain.h"
#include "shadow_stack.h"

/* ------------------------------------------------------------------ */
/* AArch64 instruction decode                                          */
/* ------------------------------------------------------------------ */

typedef enum {
  INSN_OTHER = 0, /* not a branch, OR a direct/conditional branch (b, b.cc,
                     cbz/cbnz, tbz/tbnz) — these we recognize implicitly via
                     "post.pc is not sequential", no separate encoding needed */
  INSN_BL,
  INSN_BLR,
  INSN_BR,
  INSN_RET,
} insn_kind_t;

/*
 * Encodings (32-bit, little-endian):
 *   bl  imm26 : (insn >> 26) == 0b100101
 *   blr Xn    : (insn & 0xFFFFFC1F) == 0xD63F0000
 *   br  Xn    : (insn & 0xFFFFFC1F) == 0xD61F0000
 *   ret {Xn}  : (insn & 0xFFFFFC1F) == 0xD65F0000
 */
static insn_kind_t decode_branch(uint32_t insn) {
  if ((insn >> 26) == 0x25U)
    return INSN_BL;
  if ((insn & 0xFFFFFC1FU) == 0xD63F0000U)
    return INSN_BLR;
  if ((insn & 0xFFFFFC1FU) == 0xD61F0000U)
    return INSN_BR;
  if ((insn & 0xFFFFFC1FU) == 0xD65F0000U)
    return INSN_RET;
  return INSN_OTHER;
}

/* ------------------------------------------------------------------ */
/* ptrace helpers                                                      */
/* ------------------------------------------------------------------ */

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

/* AArch64 BRK #0 — synchronous breakpoint, raises SIGTRAP (PC stays put). */
#define BRK_INSN 0xD4200000U

/* Replace the 4 bytes at addr with BRK, preserving the adjacent 4 bytes
 * (PEEK/POKETEXT operate on 8-byte words on aarch64). */
static int plant_breakpoint(pid_t pid, uint64_t addr, uint32_t *orig_out) {
  errno = 0;
  long word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(uintptr_t)addr, NULL);
  if (word == -1 && errno != 0)
    return -1;
  *orig_out = (uint32_t)((uint64_t)word & 0xFFFFFFFFULL);
  uint64_t patched =
      ((uint64_t)word & 0xFFFFFFFF00000000ULL) | (uint64_t)BRK_INSN;
  return ptrace(PTRACE_POKETEXT, pid, (void *)(uintptr_t)addr,
                (void *)(uintptr_t)patched);
}

static int restore_breakpoint(pid_t pid, uint64_t addr, uint32_t orig_insn) {
  errno = 0;
  long word = ptrace(PTRACE_PEEKTEXT, pid, (void *)(uintptr_t)addr, NULL);
  if (word == -1 && errno != 0)
    return -1;
  uint64_t restored =
      ((uint64_t)word & 0xFFFFFFFF00000000ULL) | (uint64_t)orig_insn;
  return ptrace(PTRACE_POKETEXT, pid, (void *)(uintptr_t)addr,
                (void *)(uintptr_t)restored);
}

/* ------------------------------------------------------------------ */
/* ELF symbol lookup (to find `main`)                                  */
/* ------------------------------------------------------------------ */

static int read_elf_entry(const char *path, uint64_t *entry_out) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  Elf64_Ehdr ehdr;
  int ok = (fread(&ehdr, sizeof(ehdr), 1, f) == 1);
  fclose(f);
  if (!ok || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 ||
      ehdr.e_ident[EI_CLASS] != ELFCLASS64)
    return -1;
  *entry_out = (uint64_t)ehdr.e_entry;
  return 0;
}

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
  if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
      eh.e_ident[EI_CLASS] != ELFCLASS64)
    goto out;

  shdrs = calloc(eh.e_shnum, sizeof(*shdrs));
  if (!shdrs)
    goto out;
  if (fseek(f, (long)eh.e_shoff, SEEK_SET) < 0)
    goto out;
  if (fread(shdrs, sizeof(*shdrs), eh.e_shnum, f) != eh.e_shnum)
    goto out;

  int symtab_idx = -1;
  for (size_t i = 0; i < eh.e_shnum; i++)
    if (shdrs[i].sh_type == SHT_SYMTAB) {
      symtab_idx = (int)i;
      break;
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

/* ------------------------------------------------------------------ */
/* monitor state + reporting                                           */
/* ------------------------------------------------------------------ */

typedef struct {
  size_t steps;
  size_t calls;     /* bl + blr into .text */
  size_t libcalls;  /* calls/jumps that left .text (run-to-return) */
  size_t rets;
  size_t branches;  /* taken direct/conditional/indirect-jump transfers */
  size_t alerts;
} stats_t;

static void print_summary(const stats_t *st, hashchain_t *hc, const char *why) {
  fprintf(stderr,
          "[tracer] %s — steps=%zu calls=%zu libcalls=%zu rets=%zu "
          "branches=%zu alerts=%zu\n",
          why, st->steps, st->calls, st->libcalls, st->rets, st->branches,
          st->alerts);
  fprintf(stderr, "[attestation] cfg-hash = 0x%016lx%s\n", hc_value(hc),
          st->alerts ? " (partial — run aborted on detection)" : "");
}

#define ALERT(st, kind, site, fmt, ...)                                        \
  do {                                                                         \
    fprintf(stderr,                                                            \
            "\n[!!! ATTACK DETECTED] %s at 0x%lx : " fmt "\n", (kind),         \
            (unsigned long)(site), ##__VA_ARGS__);                             \
    (st).alerts++;                                                             \
  } while (0)

/* Reap the tracee after a kill/detach and translate to an exit code. */
static int finish(pid_t pid, const stats_t *st, hashchain_t *hc,
                  const char *why) {
  int status;
  waitpid(pid, &status, 0);
  print_summary(st, hc, why);
  return st->alerts ? 2 : 0;
}

/* ------------------------------------------------------------------ */
/* library-call handling: run-to-return-breakpoint                     */
/* ------------------------------------------------------------------ */

/*
 * The just-executed call/jump landed outside .text (PLT -> libc). PC is
 * at the first PLT/libc instruction. Plant a one-shot BRK at `ret_site`
 * (which is in .text), PTRACE_CONT until it fires, restore. Returns 0 on
 * success, -1 on a fatal ptrace/wait error; *exited is set if the tracee
 * terminated during the excursion.
 */
static int run_to(pid_t pid, uint64_t ret_site, int *exited, int *exit_status) {
  *exited = 0;
  uint32_t orig;
  if (plant_breakpoint(pid, ret_site, &orig) < 0) {
    perror("plant_breakpoint(ret_site)");
    return -1;
  }
  long cont_sig = 0; /* signal to deliver on the next PTRACE_CONT, if any */
  for (;;) {
    if (ptrace(PTRACE_CONT, pid, NULL, (void *)cont_sig) < 0) {
      perror("PTRACE_CONT(libcall)");
      return -1;
    }
    cont_sig = 0;
    int status;
    if (waitpid(pid, &status, 0) < 0) {
      perror("waitpid(libcall)");
      return -1;
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      *exited = 1;
      *exit_status = status;
      return 0; /* tracee gone; nothing to restore */
    }
    if (!WIFSTOPPED(status))
      continue;
    int sig = WSTOPSIG(status);
    if (sig == SIGTRAP)
      break; /* hit our breakpoint at ret_site */
    cont_sig = sig; /* forward other signals into the tracee */
  }
  if (restore_breakpoint(pid, ret_site, orig) < 0) {
    perror("restore_breakpoint(ret_site)");
    return -1;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
  const char *cfg_path = NULL;
  int ai = 1;
  if (ai < argc && strcmp(argv[ai], "--cfg") == 0) {
    if (ai + 1 >= argc) {
      fprintf(stderr, "Usage: %s [--cfg PATH] <victim> [args...]\n", argv[0]);
      return 1;
    }
    cfg_path = argv[ai + 1];
    ai += 2;
  }
  if (ai >= argc) {
    fprintf(stderr, "Usage: %s [--cfg PATH] <victim> [args...]\n", argv[0]);
    return 1;
  }
  const char *victim = argv[ai];

  /* Default CFG path: "<victim>.cfg". */
  char cfg_buf[4096];
  if (!cfg_path) {
    int n = snprintf(cfg_buf, sizeof(cfg_buf), "%s.cfg", victim);
    if (n < 0 || n >= (int)sizeof(cfg_buf)) {
      fprintf(stderr, "[tracer] victim path too long\n");
      return 1;
    }
    cfg_path = cfg_buf;
  }
  cfg_t *cfg = cfg_load(cfg_path);
  if (!cfg) {
    fprintf(stderr,
            "[tracer] no CFG — run `python3 tools/build_cfg.py %s` first\n",
            victim);
    return 1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return 1;
  }
  if (pid == 0) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
      perror("ptrace(TRACEME)");
      _exit(127);
    }
    execv(victim, &argv[ai]);
    perror("execv");
    _exit(127);
  }

  /* --- parent: the tracer --- */
  shadow_stack_init();
  hashchain_t hc;
  hc_init(&hc);
  stats_t st = {0};
  fprintf(stderr, "[tracer] pid=%d victim=%s\n", pid, victim);

  int status;
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid");
    return 1;
  }
  if (!WIFSTOPPED(status)) {
    fprintf(stderr, "[tracer] tracee did not stop after exec\n");
    return 1;
  }

  /* Skip ld.so + __libc_start_main: one-shot BRK at `main`, PTRACE_CONT. */
  uint64_t bp_addr;
  const char *bp_name;
  if (find_symbol(victim, "main", &bp_addr) == 0) {
    bp_name = "main";
  } else if (read_elf_entry(victim, &bp_addr) == 0) {
    bp_name = "e_entry";
    fprintf(stderr, "[tracer] symbol `main` not found — falling back to e_entry\n");
  } else {
    fprintf(stderr, "[tracer] cannot parse ELF of %s\n", victim);
    return 1;
  }
  fprintf(stderr, "[tracer] %s=0x%lx — running pre-main code under PTRACE_CONT\n",
          bp_name, bp_addr);

  uint32_t orig_at_bp;
  if (plant_breakpoint(pid, bp_addr, &orig_at_bp) < 0) {
    perror("plant_breakpoint(main)");
    return 1;
  }
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
    perror("PTRACE_CONT(to main)");
    return 1;
  }
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid(main bp)");
    return 1;
  }
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
    fprintf(stderr, "[tracer] expected SIGTRAP at %s; status=0x%x\n", bp_name,
            status);
    return 1;
  }
  uint64_t initial_x30;
  {
    struct user_regs_struct r;
    if (read_regs(pid, &r) < 0) {
      perror("read_regs(main bp)");
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
    perror("restore_breakpoint(main)");
    return 1;
  }
  /* Pre-push the return-into-libc address so main's epilogue ret is
   * checkable even though we never saw the bl that called main. */
  shadow_stack_push(initial_x30);
  hc_fold(&hc, bp_addr); /* path starts at main */
  fprintf(stderr,
          "[tracer] reached %s — pre-pushed initial X30=0x%lx; single-stepping\n",
          bp_name, initial_x30);

  /* --- single-step loop --- */
  for (;;) {
    struct user_regs_struct pre;
    if (read_regs(pid, &pre) < 0) {
      perror("read_regs(pre)");
      return 1;
    }
    uint64_t pre_pc = pre.pc;

    uint32_t insn = 0;
    insn_kind_t kind = INSN_OTHER;
    if (peek_insn(pid, pre_pc, &insn) == 0)
      kind = decode_branch(insn);

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) {
      perror("PTRACE_SINGLESTEP");
      return 1;
    }
    if (waitpid(pid, &status, 0) < 0) {
      perror("waitpid(step)");
      return 1;
    }
    if (WIFEXITED(status)) {
      print_summary(&st, &hc, "tracee exited");
      return st.alerts ? 2 : 0;
    }
    if (WIFSIGNALED(status)) {
      print_summary(&st, &hc, "tracee killed by signal");
      return st.alerts ? 2 : 1;
    }
    if (!WIFSTOPPED(status))
      continue;
    int sig = WSTOPSIG(status);
    if (sig != SIGTRAP) {
      if (ptrace(PTRACE_SINGLESTEP, pid, NULL, (void *)(long)sig) < 0) {
        perror("PTRACE_SINGLESTEP(fwd)");
        return 1;
      }
      continue;
    }

    st.steps++;

    struct user_regs_struct post;
    if (read_regs(pid, &post) < 0) {
      perror("read_regs(post)");
      return 1;
    }
    uint64_t dst = post.pc;

    /* Sequential fall-through: nothing to validate (can't fall through to
     * an arbitrary address). */
    if (dst == pre_pc + 4)
      continue;

    switch (kind) {
    /* --------------------------------------------------------------- */
    case INSN_BL:
    case INSN_BLR: {
      uint64_t ret_site = pre_pc + 4;
      if (!cfg_in_text(cfg, dst)) {
        /* Library call (PLT -> libc): attest the app, not libc. */
        shadow_stack_push(ret_site);
        int exited = 0, ex_status = 0;
        if (run_to(pid, ret_site, &exited, &ex_status) < 0)
          return 1;
        if (exited) {
          if (WIFEXITED(ex_status)) {
            print_summary(&st, &hc, "tracee exited (in library)");
            return st.alerts ? 2 : 0;
          }
          print_summary(&st, &hc, "tracee killed by signal (in library)");
          return st.alerts ? 2 : 1;
        }
        uint64_t exp;
        shadow_stack_pop(&exp); /* the ret_site we just pushed */
        hc_fold(&hc, ret_site);
        st.libcalls++;
        continue;
      }
      /* Call into .text: target must be a legal call target (a function the
       * program calls directly or takes the address of — not an arbitrary
       * function-entry-shaped gadget). */
      if (!cfg_is_call_target(cfg, dst)) {
        ALERT(st, kind == INSN_BL ? "bl" : "blr", pre_pc,
              "destination 0x%lx is not a legal call target", (unsigned long)dst);
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        return finish(pid, &st, &hc, "tracee killed after detection");
      }
      shadow_stack_push(ret_site);
      hc_fold(&hc, dst);
      st.calls++;
      break;
    }
    /* --------------------------------------------------------------- */
    case INSN_RET: {
      uint64_t exp;
      if (shadow_stack_pop(&exp) < 0) {
        ALERT(st, "ret", pre_pc, "return with empty shadow stack (got 0x%lx)",
              (unsigned long)dst);
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        return finish(pid, &st, &hc, "tracee killed after detection");
      }
      st.rets++;
      if (dst != exp) {
        ALERT(st, "ret", pre_pc, "expected 0x%lx, got 0x%lx (depth=%zu)",
              (unsigned long)exp, (unsigned long)dst, shadow_stack_depth());
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        return finish(pid, &st, &hc, "tracee killed after detection");
      }
      if (shadow_stack_depth() == 0) {
        /* The pre-pushed return was just consumed: main returned cleanly.
         * Don't fold the return-into-libc address (out of the attested
         * region, and ASLR'd). Detach and let glibc cleanup run. */
        fprintf(stderr, "[tracer] main returned cleanly — detaching\n");
        if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
          perror("PTRACE_DETACH");
          return 1;
        }
        return finish(pid, &st, &hc, "tracee detached after clean return");
      }
      hc_fold(&hc, dst);
      break;
    }
    /* --------------------------------------------------------------- */
    case INSN_BR: {
      if (!cfg_in_text(cfg, dst)) {
        /* Indirect jump out of .text — e.g. a PLT thunk reached via br.
         * It returns (eventually) to wherever the *current* return
         * address points; the closest in-.text resume point we can pin
         * is the shadow-stack top. */
        uint64_t ret_site;
        if (shadow_stack_pop(&ret_site) < 0) {
          ALERT(st, "br", pre_pc, "indirect jump out of .text to 0x%lx with "
                "empty shadow stack", (unsigned long)dst);
          ptrace(PTRACE_KILL, pid, NULL, NULL);
          return finish(pid, &st, &hc, "tracee killed after detection");
        }
        shadow_stack_push(ret_site);
        int exited = 0, ex_status = 0;
        if (run_to(pid, ret_site, &exited, &ex_status) < 0)
          return 1;
        if (exited) {
          if (WIFEXITED(ex_status)) {
            print_summary(&st, &hc, "tracee exited (in library)");
            return st.alerts ? 2 : 0;
          }
          print_summary(&st, &hc, "tracee killed by signal (in library)");
          return st.alerts ? 2 : 1;
        }
        uint64_t exp;
        shadow_stack_pop(&exp);
        hc_fold(&hc, ret_site);
        st.libcalls++;
        continue;
      }
      /* Indirect jump within .text: conservative — must land on a known
       * basic-block start or function entry (catches JOP gadget chains
       * and wild jumps; over-accepts vs. a precise per-site target set). */
      if (!cfg_is_bb_start(cfg, dst) && !cfg_is_call_target(cfg, dst)) {
        ALERT(st, "br", pre_pc, "destination 0x%lx is not a CFG node",
              (unsigned long)dst);
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        return finish(pid, &st, &hc, "tracee killed after detection");
      }
      hc_fold(&hc, dst);
      st.branches++;
      break;
    }
    /* --------------------------------------------------------------- */
    case INSN_OTHER:
    default: {
      /* Non-sequential PC after a non-{bl,blr,br,ret} instruction => the
       * instruction was a direct/conditional branch (b, b.<cc>, cbz/cbnz,
       * tbz/tbnz) that was taken. Validate the CFG edge. */
      if (!cfg_in_text(cfg, dst)) {
        ALERT(st, "branch", pre_pc, "direct branch leaves .text to 0x%lx",
              (unsigned long)dst);
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        return finish(pid, &st, &hc, "tracee killed after detection");
      }
      if (!cfg_has_edge(cfg, pre_pc, dst)) {
        ALERT(st, "branch", pre_pc, "unknown CFG edge -> 0x%lx",
              (unsigned long)dst);
        ptrace(PTRACE_KILL, pid, NULL, NULL);
        return finish(pid, &st, &hc, "tracee killed after detection");
      }
      hc_fold(&hc, dst);
      st.branches++;
      break;
    }
    }
  }
}
