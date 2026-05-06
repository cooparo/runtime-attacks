#!/usr/bin/env python3
"""
build_cfg.py — static control-flow analyzer for AArch64 ELF binaries.

Iteration 1: collects function symbols and the address of every branch
instruction (bl/blr/br/ret) in .text. Writes:
    <binary>.cfg   — JSON consumed by the C tracer (iter 2 onward)
    <binary>.dot   — graphviz CFG, one node per function, edges from direct calls

Iteration 2 will extend this with: valid (ret_site -> return_target) pairs
and (blr_site -> valid_indirect_target_set) pairs for CFG-edge validation.

Usage:
    python3 build_cfg.py <binary>
"""

import json
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import Cs, CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN

BRANCH_MNEMONICS = {"bl", "blr", "br", "ret", "b"}


def collect_functions(elf):
    funcs = {}
    for sect in elf.iter_sections():
        if not isinstance(sect, SymbolTableSection):
            continue
        for sym in sect.iter_symbols():
            if sym["st_info"]["type"] == "STT_FUNC" and sym["st_size"] > 0:
                funcs[sym.name] = {
                    "addr": int(sym["st_value"]),
                    "size": int(sym["st_size"]),
                }
    return funcs


def disassemble_text(elf):
    text = elf.get_section_by_name(".text")
    if text is None:
        raise RuntimeError(".text section not found")
    base = int(text["sh_addr"])
    code = text.data()
    md = Cs(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    return list(md.disasm(code, base))


def parse_imm_target(op_str):
    """Extract a hex immediate target from an op_str like '#0x4007a4'."""
    op_str = op_str.strip()
    if op_str.startswith("#"):
        op_str = op_str[1:]
    try:
        return int(op_str.split()[0], 0)
    except (ValueError, IndexError):
        return None


def function_containing(addr, funcs):
    for name, info in funcs.items():
        if info["addr"] <= addr < info["addr"] + info["size"]:
            return name
    return None


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("Usage: build_cfg.py <binary>\n")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        sys.stderr.write(f"build_cfg: {path} not found\n")
        sys.exit(1)

    with path.open("rb") as f:
        elf = ELFFile(f)
        funcs = collect_functions(elf)
        insns = disassemble_text(elf)

    branches = []
    for insn in insns:
        if insn.mnemonic not in BRANCH_MNEMONICS:
            continue
        entry = {
            "addr": int(insn.address),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
        }
        if insn.mnemonic in ("bl", "b"):
            tgt = parse_imm_target(insn.op_str)
            if tgt is not None:
                entry["target"] = tgt
        branches.append(entry)

    cfg = {
        "binary": str(path),
        "arch": "aarch64",
        "functions": funcs,
        "branches": branches,
    }

    out_json = path.with_suffix(".cfg")
    out_json.write_text(json.dumps(cfg, indent=2))

    out_dot = path.with_suffix(".dot")
    with out_dot.open("w") as f:
        f.write("digraph CFG {\n  rankdir=LR;\n  node [shape=box, fontname=monospace];\n")
        for name in sorted(funcs):
            f.write(f'  "{name}";\n')
        edges = set()
        for b in branches:
            if b["mnemonic"] != "bl" or "target" not in b:
                continue
            src = function_containing(b["addr"], funcs)
            tgt = function_containing(b["target"], funcs)
            if src and tgt:
                edges.add((src, tgt))
        for src, tgt in sorted(edges):
            f.write(f'  "{src}" -> "{tgt}";\n')
        f.write("}\n")

    print(
        f"[build_cfg] {len(funcs)} functions, {len(branches)} branches -> "
        f"{out_json.name}, {out_dot.name}"
    )


if __name__ == "__main__":
    main()
