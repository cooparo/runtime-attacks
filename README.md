# Runtime Attack Research

> **Note:** This repo uses a **whitelist-based `.gitignore`** — everything is ignored by default, and only explicitly allowed files are tracked. If you add new source files or directories you want to commit, you must explicitly allowlist them in `.gitignore` with a `!` rule.

AAU project on runtime software attacks — research, PoC, detection, and evaluation.

## What the detector does

The detector is a **C-FLAT-style control-flow integrity monitor** that runs entirely in userspace. It has two halves:

**Offline — `tools/build_cfg.py`.** Disassembles the victim ELF's `.text` (pyelftools + capstone), recovers basic blocks, direct/conditional-branch edges, and the set of legal indirect-call targets (functions the program calls directly or takes the address of — coarse-grained forward-edge CFI, *not* "any function entry"), and writes a flat text `<victim>.cfg` (plus a `<victim>.dot` call graph for eyeballing).

**Online — `detector/tracer`.** Runs the victim under `ptrace` single-step and validates **every taken control-flow transfer** inside `.text` against that CFG, plus a shadow call stack for returns, while folding each transfer's destination into a cumulative non-cryptographic hash (FNV-1a 64-bit) — a path "attestation token" printed at exit.

Flow per traced process:

1. **Fork + `PTRACE_TRACEME`** — child execs the victim, parent becomes the tracer; load `<victim>.cfg`.
2. **One-shot `BRK` at `main`** — `PTRACE_CONT` past `ld.so` and `__libc_start_main` (single-stepping them is prohibitively slow on a Pi, and isn't what we attest). When the BRK fires, the original instruction is restored and the legitimate return-into-libc address is pre-pushed to the shadow stack.
3. **Single-step loop from `main`** — peek and decode the AArch64 instruction at the current PC *before* stepping (after a taken branch, post-step PC is the target, not PC+4); then on a non-sequential post-step PC, validate the transfer:
    - `bl` / `blr` whose target leaves `.text` → a library call (PLT → libc): plant a one-shot `BRK` at the return site and `PTRACE_CONT` over libc (C-FLAT attests the app, not libc), then resume stepping.
    - `bl` / `blr` into `.text` → destination must be a legal call target (`cfg_is_call_target`); push the return site onto the shadow stack.
    - `ret` → destination must equal the shadow-stack top.
    - direct / conditional branch (`b`, `b.<cc>`, `cbz`/`cbnz`, `tbz`/`tbnz`) taken → `(branch_site → destination)` must be a known CFG edge.
    - `br Xn` into `.text` → destination must be a known basic-block start or call target (conservative — catches JOP gadget chains and wild jumps).
    - any violation → `[!!! ATTACK DETECTED] <kind> at 0x… : <reason>` to stderr, `PTRACE_KILL` the tracee, exit `2`.
4. **Clean detach** — when `main` returns and the shadow stack drains, detach and let glibc cleanup run unobserved.

On every exit (clean or aborted) the tracer prints `[attestation] cfg-hash = 0x…` over the executed transfers, plus a one-line counter summary (steps / calls / libcalls / rets / branches / alerts).

This is the **L1 (control-flow) axis** only. Because direct ret-overwrites and ROP both forge a `ret`, the shadow stack catches them; because the CFG model rejects an indirect call/branch to a target the program never legitimately uses, JOP-style chains that never touch a `ret` are caught too. Provenance of data and bounds of objects are not checked yet — see the roadmap.

## Roadmap

What attacks are we able to detect:
- [x] Buffer overflows / code injection — `attacks/01-stack-bof/` (caught at the hijacked `ret`)
- [x] Return-Oriented Programming — `attacks/02-rop/` (3-gadget chain, caught at the first hijacked `ret`)
- [x] Jump-Oriented Programming — `attacks/03-jop/` (`blr`-pivot chain, caught at the pivot: not a legal call target)
- [ ] Function reuse — whole-function gadgets reached via *legal* CFG edges (the L1 model accepts these)
- [ ] Data-only attacks — `attacks/04-data-only/` is a PoC of the gap: a surgical 36-byte stack overflow flips an adjacent `is_admin` flag, so the legitimate `if (u.is_admin) admin_panel()` branch fires under attacker data. Every transfer is in the CFG and the shadow stack — L1 reports clean. Needs **L2** (data provenance) to flag that `is_admin`'s value came from untrusted bytes.
- [ ] Non-control-data overflows — same `attacks/04-data-only/` PoC viewed from the other side. Alternative defence is **L3** (object bounds) — prevent the write past `name[32]` in the first place.

The attestation hash printed by the detector *does* differ between the benign and 04-data-only runs (the sequence of legal edges taken is different); a C-FLAT-style verifier with a known-good baseline would catch the divergence. The current detector emits the hash but doesn't compare against a baseline, which is why 04-data-only is listed as an open gap rather than a caught attack.

Next axes (not yet implemented): **L2** data-provenance tracking and **L3** object-bounds checking.

## Development Environment (optional but recommended)

This repo uses a Nix flake to provide a reproducible dev shell.

**Prerequisites:** Nix with flakes enabled. If you don't have Nix, install it via [nixos.org](https://nixos.org/download/):
```sh
sh <(curl --proto '=https' --tlsv1.2 -L https://nixos.org/nix/install) --daemon
```

### Speed up the building time (needed only once)
Go into `/etc/nix/nix.conf` and add the following lines:
```
experimental-features = nix-command flakes
trusted-users = root <your-username>
```

After you edited the files, restart the nix daemon:
```
sudo systemctl restart nix-daemon
```

### Enter the shell

```sh
nix develop --command $SHELL
```

Press `y` when prompted with questions about whether would you like to add the cachix pwngdb to trusted, otherwise your nix development environment it is going to build from source code the `pwngdb` tool (dead slow). Instead, we are going to take advantage of the cache of pwngdb itself, to directly download the binary.

This drops you into a shell with all tools and packages listed in the `flake.nix` available. Exit with `Ctrl+D` or `exit`.

To know if you are correctly entered in the nix shell, run:
```sh
echo $IN_NIX_SHELL
```
you should get: `impure` (not sure, every not empty result is fine).

### Hardening disabled by default

The dev shell **automatically disables all GCC/linker security features** so that binaries compiled inside it are vulnerable by design. No extra flags are needed — just compile normally:

```sh
gcc vuln.c -o vuln
checksec vuln   # everything should show as disabled
```

Disabled features: stack canary, PIE, NX (executable stack), RELRO, FORTIFY_SOURCE, and control-flow enforcement (CET).

### With `direnv` (optional but recommended)

If you have [`direnv`](https://direnv.net/) installed, the **shell activates automatically when you `cd` into the repo**:

Give direnv permissions:
```sh
direnv allow
```

If you want to remove these permissions:
```sh
direnv disallow
```

## Get started

Inside the dev shell, build everything, recover a victim's CFG, and run
the tracer manually against an attack:

```sh
make build

# recover the static CFG once per victim (writes attacks/01-stack-bof/victim.cfg)
python3 tools/build_cfg.py attacks/01-stack-bof/victim

# benign run: payload is a clean line of text
echo "hello" | ./detector/tracer attacks/01-stack-bof/victim

# attack run: payload is the exploit's stdout
python3 attacks/01-stack-bof/exploit.py | ./detector/tracer attacks/01-stack-bof/victim
```

The tracer takes the victim path as argv and reads the victim's stdin
from the pipe. It expects `<victim>.cfg` next to the binary (override
with `--cfg PATH`); `make test` regenerates these automatically, but a
manual run needs `build_cfg.py` first. Exit codes: `0` clean, `1`
tracer error, `2` attack detected. On detection it prints
`[!!! ATTACK DETECTED] <kind> at 0x… : <reason>` to stderr (e.g.
`ret at 0x… : expected 0x…, got 0x…`, or `blr at 0x… : destination 0x…
is not a legal call target`); on every exit it prints
`[attestation] cfg-hash = 0x…`.

If you are not already in the dev shell, prefix each command with
`nix develop -c` (e.g. `nix develop -c make build`).

## Building and running the tests

The repo has a top-level `Makefile` that delegates to each component
(`detector/`, every `attacks/*/`). The test harness exercises every
attack against the current detector and reports pass/fail per case.

```sh
# enter the nix shell, if you are not already into
# to check if you are in a nix shell run 
# echo $IN_NIX_SHELL
# if retrieves non-empty string, then you are in a nix shell
# otherwise run
# nix develop -c $SHELL

make          # build detector + every attack
make test     # build (if needed) and run the matrix
make clean    # clean every component
```

The harness regenerates each `<victim>.cfg` first (via `build_cfg.py`,
echoing its function / BB / edge / indirect-call-target counts), then runs
the matrix. Expected `make test` output:
```
[harness] [build_cfg] 6 functions, 34 basic blocks, 16 edges, 2 indirect-call targets -> victim.cfg, victim.dot
[harness] [build_cfg] 8 functions, 38 basic blocks, 16 edges, 2 indirect-call targets -> victim.cfg, victim.dot
[harness] [build_cfg] 8 functions, 39 basic blocks, 16 edges, 3 indirect-call targets -> victim.cfg, victim.dot
[harness] [build_cfg] 6 functions, 49 basic blocks, 34 edges, 3 indirect-call targets -> victim.cfg, victim.dot
[ ok ] 01-stack-bof :: benign            (    12ms)  exit=0
[ ok ] 01-stack-bof :: attack            (  1089ms)  exit=2
[ ok ] 02-rop :: benign                  (    36ms)  exit=0
[ ok ] 02-rop :: attack                  (  1084ms)  exit=2
[ ok ] 03-jop :: benign                  (    12ms)  exit=0
[ ok ] 03-jop :: attack                  (  1063ms)  exit=2
[ ok ] 04-data-only :: benign            (    17ms)  exit=0
[ ok ] 04-data-only :: attack            (   101ms)  exit=0

8 passed, 0 failed
```
Benign cases must exit `0` with an `[attestation] cfg-hash` line and no
alert; attack cases that the L1 detector *catches* (01/02/03) must exit
`2` with `[!!! ATTACK DETECTED]`. **04-data-only is the documented
exception**: it is a non-control-data attack the L1 detector cannot
catch, so its attack run is asserted to exit `0` with no alert and the
`[ADMIN] secret` line in stdout (proving the exploit succeeded). The
case is in the matrix so a future detector that closes the gap will
surface the change as a test diff.

(Attack runs that the detector catches are ~100× slower — single-stepping
the victim to the hijack point. 04-data-only :: attack is fast because
nothing is ever caught and the program runs straight through.) Shell
exit code is 0 on success, 1 if any case fails.

### Adding a new attack to the test matrix

1. Create `attacks/NN-name/` with `victim.c`, `exploit.py`, `Makefile`
   (mirror the layout of `attacks/01-stack-bof/`).
2. Append two entries (one `benign`, one `attack`) to the `TESTS` list
   in `tools/run_tests.py`.
3. `make test` will build the new attack, recover its CFG, and run it
   against the detector automatically.

### Useful flags

```sh
python3 tools/run_tests.py -v               # dump tracer stderr on every case
python3 tools/run_tests.py -k 01-stack-bof  # only run cases matching substring
```

