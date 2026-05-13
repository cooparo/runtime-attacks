#!/usr/bin/env python3
"""
build_cfg.py — offline control-flow-graph recovery for AArch64 ELF binaries.

Disassembles .text, recovers basic blocks and intra-.text edges, and writes:

    <binary>.cfg   — flat line-based text consumed by the C tracer (detector/cfg.c)
    <binary>.dot   — graphviz of the function-level call graph (eyeballing only)

.cfg format (one record per line; '#' starts a comment; blank lines ignored):

    TEXT 0x<start> 0x<end>     .text section span [start, end)
    BB   0x<addr>              a basic-block start address
    CALLTGT 0x<addr>           a legal indirect-call (blr) target — see below
    EDGE 0x<src> 0x<dst>       a static control-flow edge; <src> is the
                               address of the branch instruction
    FUNC <name> 0x<addr>       function symbol (informational; the tracer
                               uses the ELF symtab itself, not this line)

Basic-block starts = function entries + branch targets + the instruction
after any branch.

Edges:
    - direct/conditional branch (b, b.<cc>, cbz/cbnz, tbz/tbnz, bl):
      EDGE branch_addr -> resolved_immediate_target
    - conditional branch also: EDGE branch_addr -> branch_addr+4 (fallthrough)
    - indirect branches (br Xn, blr Xn): not resolved here — the tracer's
      runtime policy is "blr dst must be a CALLTGT; br dst must be a known BB
      start or CALLTGT", conservative but enough to catch JOP / wild jumps.

CALLTGT — the legal indirect-call target set. *Not* "every STT_FUNC entry":
a function only counts if there is static evidence it can legitimately be
entered indirectly, i.e. it is

    - the target of a direct `bl` somewhere in .text  (it is called), OR
    - a function whose entry address the binary materialises as a value:
        * computed by `adrp Xn, #page` + `add Xd, Xn, #lo12` (or a plain
          `adr`)  — the -O0 idiom for `&func`; or
        * stored as an 8-byte word in any allocatable section (.data /
          .data.rel.ro / .rodata / a .text literal pool / a relocated slot)
          — `&func` written into a function-pointer table or initialiser.

This is coarse-grained forward-edge CFI (cf. Microsoft CFG, LLVM
-fsanitize=cfi-icall in its coarse mode): an indirect call may only land on a
function that something either calls or takes the address of. A `blr` to a
"gadget" function whose address the program never materialises — e.g. a JOP
pivot bolted into the binary purely as an exploitation primitive — is rejected.
(Over-approximating the set is safe: it only widens CALLTGT, never causes a
false alert.)

Usage:
    python3 build_cfg.py <binary>
"""

import struct
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

try:  # capstone >= 6 renamed the AArch64 arch/operand constants
    from capstone import Cs, CS_ARCH_AARCH64 as CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone.aarch64 import AARCH64_OP_IMM as OP_IMM, AARCH64_OP_REG as OP_REG
except ImportError:  # capstone 4/5
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    from capstone.arm64 import ARM64_OP_IMM as OP_IMM, ARM64_OP_REG as OP_REG

COND_BRANCHES = {"cbz", "cbnz", "tbz", "tbnz"}  # plus b.<cc>, handled below
DIRECT_BRANCHES = {"b", "bl"}  # unconditional direct
INDIRECT_BRANCHES = {"br", "blr"}
RETURNS = {"ret", "retaa", "retab"}

SHF_ALLOC = 0x2


def is_cond_branch(mnem):
    return mnem in COND_BRANCHES or mnem.startswith("b.")


def is_block_terminator(mnem):
    return (
        is_cond_branch(mnem)
        or mnem in DIRECT_BRANCHES
        or mnem in INDIRECT_BRANCHES
        or mnem in RETURNS
    )


def collect_functions(elf):
    """Return {name: addr} for STT_FUNC symbols (size > 0) that land in .text."""
    text = elf.get_section_by_name(".text")
    lo, hi = int(text["sh_addr"]), int(text["sh_addr"]) + int(text["sh_size"])
    funcs = {}
    for sect in elf.iter_sections():
        if not isinstance(sect, SymbolTableSection):
            continue
        for sym in sect.iter_symbols():
            if sym["st_info"]["type"] != "STT_FUNC" or sym["st_size"] == 0:
                continue
            addr = int(sym["st_value"])
            if lo <= addr < hi:
                funcs[sym.name] = addr
    return funcs


def disassemble_text(elf):
    text = elf.get_section_by_name(".text")
    if text is None:
        raise RuntimeError(".text section not found")
    base = int(text["sh_addr"])
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True  # we read resolved operand values, not just op_str
    return base, base + int(text["sh_size"]), list(md.disasm(text.data(), base))


def imm_target(insn):
    """The last operand of a branch is its (resolved) PC-relative target."""
    ops = insn.operands
    if ops and ops[-1].type == OP_IMM:
        return ops[-1].imm & 0xFFFFFFFFFFFFFFFF
    return None


def addr_taken_via_code(insns, func_addrs):
    """Functions whose entry address is materialised in code.

    -O0 emits `&func` as `adrp Xn, #page; add Xd, Xn, #lo12` (the add may
    write a different destination register); plain `adr` is also possible.
    Whenever such a computation yields a known function entry, that function
    is address-taken — a legal indirect target.
    """
    taken = set()
    page = {}  # reg-name -> page address of the most recent adrp into it
    for insn in insns:
        m = insn.mnemonic
        ops = insn.operands
        if m == "adrp" and len(ops) == 2 and ops[0].type == OP_REG and ops[1].type == OP_IMM:
            page[insn.reg_name(ops[0].reg)] = ops[1].imm & 0xFFFFFFFFFFFFFFFF
        elif m == "add" and len(ops) == 3 and ops[1].type == OP_REG and ops[2].type == OP_IMM:
            src = insn.reg_name(ops[1].reg)
            if src in page:
                cand = (page[src] + ops[2].imm) & 0xFFFFFFFFFFFFFFFF
                if cand in func_addrs:
                    taken.add(cand)
        elif m == "adr" and len(ops) == 2 and ops[1].type == OP_IMM:
            cand = ops[1].imm & 0xFFFFFFFFFFFFFFFF
            if cand in func_addrs:
                taken.add(cand)
    return taken


def addr_taken_via_data(elf, func_addrs):
    """Functions whose entry address appears as an 8-byte little-endian word
    in some allocatable section — a function pointer in .data / .rodata / a
    .text literal pool / a relocated slot."""
    if not func_addrs:
        return set()
    taken = set()
    for sect in elf.iter_sections():
        if not (int(sect["sh_flags"]) & SHF_ALLOC) or sect["sh_type"] == "SHT_NOBITS":
            continue
        data = sect.data()
        for off in range(0, len(data) - 7, 4):  # AArch64 keeps pointers 8-aligned, but 4-step is cheap and safe
            (word,) = struct.unpack_from("<Q", data, off)
            if word in func_addrs:
                taken.add(word)
    # also chase explicit relocations (RELA addends / symbol values)
    for sect in elf.iter_sections():
        if sect["sh_type"] not in ("SHT_RELA", "SHT_REL"):
            continue
        symtab = elf.get_section(sect["sh_link"]) if sect["sh_link"] else None
        for r in sect.iter_relocations():
            cand = int(r["r_addend"]) if r.entry.get("r_addend") else 0
            if cand in func_addrs:
                taken.add(cand)
            if symtab is not None:
                si = r["r_info_sym"]
                if 0 <= si < symtab.num_symbols():
                    sv = int(symtab.get_symbol(si)["st_value"])
                    if sv in func_addrs:
                        taken.add(sv)
    return taken


def func_of(addr, funcs):
    """Name of the nearest function symbol starting at-or-before addr."""
    best, best_addr = None, -1
    for name, a in funcs.items():
        if best_addr <= a <= addr:
            best, best_addr = name, a
    return best


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
        text_lo, text_hi, insns = disassemble_text(elf)
        func_addrs = set(funcs.values())
        addr_taken = addr_taken_via_code(insns, func_addrs) | addr_taken_via_data(elf, func_addrs)

    def in_text(a):
        return text_lo <= a < text_hi

    bb_starts = set(func_addrs)
    edges = set()        # (src_addr, dst_addr)
    bl_targets = set()   # in-.text functions reached by a direct `bl`
    call_edges = set()   # (src_func_name, dst_func_name) — for the .dot only

    for insn in insns:
        mnem = insn.mnemonic
        if not is_block_terminator(mnem):
            continue
        nxt = insn.address + insn.size
        if in_text(nxt):
            bb_starts.add(nxt)  # instruction after a branch starts a block
        if mnem in INDIRECT_BRANCHES or mnem in RETURNS:
            continue
        tgt = imm_target(insn)
        if tgt is None:
            continue
        if in_text(tgt):
            bb_starts.add(tgt)
            edges.add((insn.address, tgt))
        if is_cond_branch(mnem) and in_text(nxt):
            edges.add((insn.address, nxt))  # fallthrough
        if mnem == "bl":
            if in_text(tgt):
                bl_targets.add(tgt)  # this function is called -> legal target
            src_f, dst_f = func_of(insn.address, funcs), func_of(tgt, funcs)
            if src_f and dst_f:
                call_edges.add((src_f, dst_f))

    call_targets = bl_targets | {a for a in addr_taken if in_text(a)}

    cfg_path = path.with_suffix(".cfg")
    with cfg_path.open("w") as f:
        f.write(f"# CFG for {path.name} - generated by build_cfg.py\n")
        f.write(f"TEXT 0x{text_lo:x} 0x{text_hi:x}\n")
        for a in sorted(bb_starts):
            f.write(f"BB 0x{a:x}\n")
        for a in sorted(call_targets):
            f.write(f"CALLTGT 0x{a:x}\n")
        for src, dst in sorted(edges):
            f.write(f"EDGE 0x{src:x} 0x{dst:x}\n")
        for name, addr in sorted(funcs.items()):
            f.write(f"FUNC {name} 0x{addr:x}\n")

    dot_path = path.with_suffix(".dot")
    with dot_path.open("w") as f:
        f.write("digraph CFG {\n  rankdir=LR;\n"
                "  node [shape=box, fontname=monospace];\n")
        for name in sorted(funcs):
            f.write(f'  "{name}";\n')
        for src, dst in sorted(call_edges):
            f.write(f'  "{src}" -> "{dst}";\n')
        f.write("}\n")

    print(f"[build_cfg] {len(funcs)} functions, {len(bb_starts)} basic blocks, "
          f"{len(edges)} edges, {len(call_targets)} indirect-call targets "
          f"-> {cfg_path.name}, {dot_path.name}")


if __name__ == "__main__":
    main()
