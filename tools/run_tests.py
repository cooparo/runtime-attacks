#!/usr/bin/env python3
"""
run_tests.py - local matrix harness for runtime-attacks.

Drives the matrix {benign, attack} x each attack dir against the current
detector. Before the matrix it (re)generates each victim's static CFG with
tools/build_cfg.py (the tracer needs `<victim>.cfg`). Each case then runs an
input_cmd to produce payload bytes, pipes them as stdin to the tracer, and
asserts on (exit_code, stdout/stderr).

Usage:
    python3 tools/run_tests.py            # run all tests
    python3 tools/run_tests.py -v         # also dump stderr on each case
    python3 tools/run_tests.py -k benign  # filter by substring of test name

Adding a new attack:
    1. Create attacks/NN-foo/ with victim.c, exploit.py, Makefile.
    2. Append two entries (benign + attack) to TESTS below.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TRACER    = REPO_ROOT / "detector" / "tracer"
BUILD_CFG = REPO_ROOT / "tools" / "build_cfg.py"

# Each case:
#   name                  human-readable identifier
#   victim                path to victim binary, relative to REPO_ROOT
#   input_cmd             argv list run to produce payload bytes on stdout
#   expected_exit         required tracer exit code
#   must_contain          substrings that MUST appear in tracer stderr
#   must_not_contain      substrings that MUST NOT appear in tracer stderr
#   must_contain_stdout   (optional) substrings that MUST appear in tracer stdout
TESTS: list[dict] = [
    {
        "name": "01-stack-bof :: benign",
        "victim": "attacks/01-stack-bof/victim",
        "input_cmd": ["echo", "hello"],
        "expected_exit": 0,
        "must_contain": ["[attestation] cfg-hash = 0x"],
        "must_not_contain": ["[!!! ATTACK DETECTED]"],
    },
    {
        "name": "01-stack-bof :: attack",
        "victim": "attacks/01-stack-bof/victim",
        "input_cmd": ["python3", "attacks/01-stack-bof/exploit.py"],
        "expected_exit": 2,
        "must_contain": ["[!!! ATTACK DETECTED]"],
        "must_not_contain": [],
    },
    {
        "name": "02-rop :: benign",
        "victim": "attacks/02-rop/victim",
        "input_cmd": ["echo", "hello"],
        "expected_exit": 0,
        "must_contain": ["[attestation] cfg-hash = 0x"],
        "must_not_contain": ["[!!! ATTACK DETECTED]"],
    },
    {
        "name": "02-rop :: attack",
        "victim": "attacks/02-rop/victim",
        "input_cmd": ["python3", "attacks/02-rop/exploit.py"],
        "expected_exit": 2,
        "must_contain": ["[!!! ATTACK DETECTED]"],
        "must_not_contain": [],
    },
    {
        "name": "03-jop :: benign",
        "victim": "attacks/03-jop/victim",
        "input_cmd": ["echo", "hello"],
        "expected_exit": 0,
        "must_contain": ["[attestation] cfg-hash = 0x"],
        "must_not_contain": ["[!!! ATTACK DETECTED]"],
    },
    # The JOP chain hijacks `c.cb()` (a `blr Xn`) to a "gadget" function the
    # program never calls or takes the address of, then `br x16` onward to
    # win(). The CFG model's indirect-call check rejects the first hop: the
    # pivot is not a legal call target. (Earlier iterations, shadow-stack
    # only, could not see this — no `ret` is ever forged.)
    {
        "name": "03-jop :: attack",
        "victim": "attacks/03-jop/victim",
        "input_cmd": ["python3", "attacks/03-jop/exploit.py"],
        "expected_exit": 2,
        "must_contain": ["[!!! ATTACK DETECTED]"],
        "must_not_contain": ["[!] PWNED via JOP chain"],
    },
    {
        "name": "04-data-only :: benign",
        "victim": "attacks/04-data-only/victim",
        "input_cmd": ["echo", "hello"],
        "expected_exit": 0,
        "must_contain": ["[attestation] cfg-hash = 0x"],
        "must_not_contain": ["[!!! ATTACK DETECTED]", "[ADMIN]"],
        "must_contain_stdout": ["(regular user)"],
    },
    # KNOWN L1 GAP. A non-control-data overflow flips `is_admin` via the
    # adjacent-stack-variable overflow primitive. No control-flow transfer
    # is hijacked: the `bl admin_panel` it ends up taking is one of the two
    # static edges out of the `if (u.is_admin)` cbz — the L1 detector
    # cannot distinguish it from a legitimate admin login. expected_exit=0
    # / no alert asserts that gap; the attestation hash differs from the
    # benign run (a future detector with a baseline check would catch it).
    # When L2 (data provenance) or L3 (object bounds) lands and closes the
    # gap, this case will flip and the diff will surface the change.
    {
        "name": "04-data-only :: attack",
        "victim": "attacks/04-data-only/victim",
        "input_cmd": ["python3", "attacks/04-data-only/exploit.py"],
        "expected_exit": 0,
        "must_contain": ["[attestation] cfg-hash = 0x"],
        "must_not_contain": ["[!!! ATTACK DETECTED]"],
        "must_contain_stdout": ["[ADMIN] secret"],
    },
]


def build_cfgs() -> bool:
    """(Re)generate <victim>.cfg for every distinct victim in TESTS.

    Echoes build_cfg.py's one-line summary per victim (function / BB / edge /
    indirect-call-target counts) so a wrong CFG is obvious in the log.
    """
    ok = True
    for v in sorted({c["victim"] for c in TESTS}):
        if not (REPO_ROOT / v).exists():
            print(f"[harness] CFG FAIL: victim {v} missing - run `make build` first")
            return False
        r = subprocess.run(
            [sys.executable, str(BUILD_CFG), v],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        for line in (r.stdout + r.stderr).splitlines():
            print(f"[harness] {line}")
        if r.returncode != 0:
            print(f"[harness] CFG FAIL: build_cfg.py {v} exited {r.returncode}")
            ok = False
    return ok


def run_case(case: dict) -> tuple[bool, str, float, str]:
    """Run one case. Returns (passed, message, duration_s, tracer_stderr)."""
    t0 = time.monotonic()
    try:
        payload = subprocess.run(
            case["input_cmd"],
            capture_output=True,
            check=True,
            cwd=REPO_ROOT,
            timeout=30,
        ).stdout
    except subprocess.CalledProcessError as e:
        dt = time.monotonic() - t0
        err = e.stderr.decode(errors="replace") if e.stderr else ""
        return False, f"input_cmd failed (exit={e.returncode})", dt, err
    except subprocess.TimeoutExpired:
        dt = time.monotonic() - t0
        return False, "input_cmd timed out", dt, ""

    try:
        proc = subprocess.run(
            [str(TRACER), case["victim"]],
            input=payload,
            capture_output=True,
            cwd=REPO_ROOT,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        dt = time.monotonic() - t0
        return False, "tracer timed out", dt, ""

    dt = time.monotonic() - t0
    stderr = proc.stderr.decode(errors="replace")
    stdout = proc.stdout.decode(errors="replace")

    if proc.returncode != case["expected_exit"]:
        return False, f"exit={proc.returncode}, want {case['expected_exit']}", dt, stderr
    for s in case.get("must_contain", []):
        if s not in stderr:
            return False, f"stderr missing {s!r}", dt, stderr
    for s in case.get("must_not_contain", []):
        if s in stderr:
            return False, f"stderr unexpectedly contains {s!r}", dt, stderr
    for s in case.get("must_contain_stdout", []):
        if s not in stdout:
            return False, f"stdout missing {s!r}", dt, stderr
    return True, f"exit={proc.returncode}", dt, stderr


def main() -> int:
    ap = argparse.ArgumentParser(description="Runtime-attacks local test harness.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="dump stderr of every case (not just failures)")
    ap.add_argument("-k", "--filter", default="",
                    help="only run cases whose name contains this substring")
    args = ap.parse_args()

    # We echo back tracer stderr verbatim (e.g. on -v); it contains non-ASCII
    # (em-dashes), so don't let a C-locale stdout turn that into a crash.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")

    if not TRACER.exists():
        print(f"[harness] tracer not built at {TRACER} - run `make build` first",
              file=sys.stderr)
        return 2

    if not build_cfgs():
        return 2

    cases = [c for c in TESTS if args.filter in c["name"]]
    if not cases:
        print(f"[harness] no cases match filter {args.filter!r}", file=sys.stderr)
        return 2

    passed = failed = 0
    for c in cases:
        ok, msg, dt, stderr = run_case(c)
        tag = "[ ok ]" if ok else "[FAIL]"
        print(f"{tag} {c['name']:<32}  ({dt*1000:>6.0f}ms)  {msg}")
        if (not ok) or args.verbose:
            for line in stderr.rstrip().splitlines()[-12:]:
                print(f"       {line}")
        if ok:
            passed += 1
        else:
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
