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
