# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AAU research project on runtime software attacks — PoC exploits, detection, and evaluation. The repo contains a Nix-managed dev environment and a LaTeX research report as a git submodule.

## Development Environment

The dev shell is managed via Nix flake. Enter it with:

```sh
nix develop --command $SHELL
```

With `direnv` installed, the shell activates automatically on `cd` into the repo (`direnv allow` required once).

**Available tools in the shell:** `gdb`, `pwntools`, `pwndbg`

### Hardening

All GCC/linker security features are **disabled by default** inside the dev shell. Compiling normally produces vulnerable binaries:

```sh
gcc vuln.c -o vuln
checksec vuln   # should show all disabled
```

Disabled: stack canary, PIE, NX (executable stack), RELRO, FORTIFY_SOURCE, CET.

## Repository Structure

- `flake.nix` — Nix devShell definition with hardening flags and tool packages
- `report/` — LaTeX research report (git submodule). Structure: `body/` (chapter `.tex` files numbered 00–99), `setup/` (preamble, macros, style), `main.tex` (root document), `appendix/`, `images/`
- `project_instructions.pdf` — original project assignment

## Gitignore

This repo uses a **whitelist-based `.gitignore`** — everything is ignored by default. To track new files or directories, add an explicit `!` allowlist rule to `.gitignore`.

## Report (LaTeX)

The report is compiled from `report/main.tex`. Chapter files follow the naming convention `NN-name.tex` (e.g., `10-introduction.tex`, `50-implementation.tex`). Bibliography is at `report/body/99-bibliography.bib`.
