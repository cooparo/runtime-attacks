# Runtime Attack Research

> **Note:** This repo uses a **whitelist-based `.gitignore`** — everything is ignored by default, and only explicitly allowed files are tracked. If you add new source files or directories you want to commit, you must explicitly allowlist them in `.gitignore` with a `!` rule.

AAU project on runtime software attacks — research, PoC, detection, and evaluation.

## Development Environment (optional but recommended)

This repo uses a Nix flake to provide a reproducible dev shell.

**Prerequisites:** Nix with flakes enabled. If you don't have Nix, install it via [the Determinate installer](https://determinate.systems/posts/determinate-nix-installer/):

```sh
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

### Enter the shell

```sh
nix develop --command zsh
```

This drops you into a shell with all tools and packages listed in the `flake.nix` available. Exit with `Ctrl+D` or `exit`.

### With `direnv` (optional but recommended)

If you have [`direnv`](https://direnv.net/) installed, the shell activates automatically when you `cd` into the repo:

Give direnv permissions:
```sh
direnv allow
```
