# Runtime Attack Research

> **Note:** This repo uses a **whitelist-based `.gitignore`** — everything is ignored by default, and only explicitly allowed files are tracked. If you add new source files or directories you want to commit, you must explicitly allowlist them in `.gitignore` with a `!` rule.

AAU project on runtime software attacks — research, PoC, detection, and evaluation.

## What the detector does

The detector (`detector/tracer`) is a **user-space shadow call stack** built on the Linux `ptrace` API. It enforces call/return discipline at runtime: every `ret` must return to the address recorded by its matching `bl`/`blr`. Any deviation is flagged as an attack.

Flow per traced process:

1. **Fork + `PTRACE_TRACEME`** — child execs the victim, parent becomes the tracer.
2. **One-shot `BRK` at `main`** — `PTRACE_CONT` past `ld.so` and `__libc_start_main` (single-stepping them is prohibitively slow on a Pi). When the BRK fires, the original instruction is restored and the legitimate return-into-libc address is pre-pushed to the shadow stack.
3. **Single-step loop from `main`** — peek the next AArch64 instruction at the current PC and decode:
    - `bl imm` / `blr Xn` → push `pre_pc + 4` (the return site) to the shadow stack
    - `ret` → pop the expected target and compare against the actual post-step PC
    - mismatch → `[!!! ATTACK DETECTED]` to stderr, `PTRACE_KILL` the tracee, exit with code `2`
4. **Clean detach** — when main returns and the shadow stack drains, detach and let glibc cleanup run unobserved.

Because the check is structural (every ret matches a recorded call), the detector catches any control-flow hijack that subverts the call/return contract — including direct ret overwrite (stack buffer overflow) and full ROP chains — without per-attack signatures or a CFG model. It does **not** yet validate indirect-call (`blr`) targets or direct branches (`b`/`b.cond`); those are out of scope for the call/return shadow stack and require a CFG-edge model (planned for a later iteration).

## Roadmap

What attacks are we able to detect:
- [x] Buffer overflows/Code injection — `attacks/01-stack-bof/`
- [x] Return Oriented Programming — `attacks/02-rop/` (3-gadget chain, detected at first hijacked `ret`)
    - [~] Jump Oriented Programming — `attacks/03-jop/` (PoC works; **NOT yet detected** — see below)
    - [ ] Function reuse
- [ ] Data-only attacks
- [ ] Non-control Data overflows

> **Known gap.** The shadow stack catches every control-flow hijack that subverts the call/return contract (any `ret` to a non-call-site fails immediately). It does **not** catch indirect-branch hijacks that never execute a `ret` — e.g. a `blr Xn` that jumps to a `br x16` gadget which terminates in `_exit()`. `attacks/03-jop/` is exactly this PoC; the test harness's `03-jop :: attack (gap demo)` case is intentionally green when the attack succeeds. Closing this gap requires per-call-site CFG-edge validation (planned).

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

Inside the dev shell, build everything and run the tracer manually
against an attack:

```sh
make build

# benign run: payload is a clean line of text
echo "hello" | ./detector/tracer attacks/01-stack-bof/victim

# attack run: payload is the exploit's stdout
python3 attacks/01-stack-bof/exploit.py | ./detector/tracer attacks/01-stack-bof/victim
```

The tracer takes the victim path as argv and reads the victim's stdin
from the pipe. Exit codes: `0` clean, `1` tracer error, `2` attack
detected. On detection it prints
`[!!! ATTACK DETECTED] ret at 0x... expected 0x... got 0x...` to stderr.

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

Expected `make test` output:
```
[ ok ] 01-stack-bof :: benign            (    89ms)  exit=0
[ ok ] 01-stack-bof :: attack            (  1271ms)  exit=2
[ ok ] 02-rop :: benign                  (    47ms)  exit=0
[ ok ] 02-rop :: attack                  (  1331ms)  exit=2
[ ok ] 03-jop :: benign                  (    50ms)  exit=0
[ ok ] 03-jop :: attack (gap demo)       (  1450ms)  exit=0

6 passed, 0 failed
```
The `03-jop :: attack (gap demo)` case is GREEN when the attack succeeds (tracer exit 0, "PWNED via JOP chain" on stdout, no detector alert). It documents the indirect-branch gap.
Shell exit code is 0 on success, 1 if any case fails.

### Adding a new attack to the test matrix

1. Create `attacks/NN-name/` with `victim.c`, `exploit.py`, `Makefile`
   (mirror the layout of `attacks/01-stack-bof/`).
2. Append two entries (one `benign`, one `attack`) to the `TESTS` list
   in `tools/run_tests.py`.
3. `make test` will build the new attack and run it against the
   detector automatically.

### Useful flags

```sh
python3 tools/run_tests.py -v               # dump tracer stderr on every case
python3 tools/run_tests.py -k 01-stack-bof  # only run cases matching substring
```

