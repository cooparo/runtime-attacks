# Runtime Attack Research

> **Note:** This repo uses a **whitelist-based `.gitignore`** — everything is ignored by default, and only explicitly allowed files are tracked. If you add new source files or directories you want to commit, you must explicitly allowlist them in `.gitignore` with a `!` rule.

AAU project on runtime software attacks — research, PoC, detection, and evaluation.

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

### Enter the shell

```sh
nix develop --command $SHELL
```

Press `y` when prompted with questions about whether would you like to add the cachix pwngdb to trusted, otherwise your nix development environment it is going to build from source code the `pwngdb` tool (dead slow). Instead, we are going to take advantage of the cache of pwngdb itself, to directly download the binary.

This drops you into a shell with all tools and packages listed in the `flake.nix` available. Exit with `Ctrl+D` or `exit`.

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
[ ok ] 01-stack-bof :: benign           (   80ms)  exit=0
[ ok ] 01-stack-bof :: attack           (  950ms)  exit=2

2 passed, 0 failed
```
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

