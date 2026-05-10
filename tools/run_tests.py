#!/usr/bin/env python3
"""
run_tests.py - local matrix harness for runtime-attacks.

Drives the matrix {benign, attack} x each attack dir against the current
detector. Each case runs an input_cmd to produce payload bytes, pipes
them as stdin to the tracer, and asserts on (exit_code, stderr).

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

# Each case:
#   name              human-readable identifier
#   victim            path to victim binary, relative to REPO_ROOT
#   input_cmd         argv list run to produce payload bytes on stdout
#   expected_exit     required tracer exit code
#   must_contain      substrings that MUST appear in tracer stderr
#   must_not_contain  substrings that MUST NOT appear in tracer stderr
TESTS: list[dict] = [
    {
        "name": "01-stack-bof :: benign",
        "victim": "attacks/01-stack-bof/victim",
        "input_cmd": ["echo", "hello"],
        "expected_exit": 0,
        "must_contain": [],
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
        "must_contain": [],
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
]


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

    if proc.returncode != case["expected_exit"]:
        return False, f"exit={proc.returncode}, want {case['expected_exit']}", dt, stderr
    for s in case.get("must_contain", []):
        if s not in stderr:
            return False, f"stderr missing {s!r}", dt, stderr
    for s in case.get("must_not_contain", []):
        if s in stderr:
            return False, f"stderr unexpectedly contains {s!r}", dt, stderr
    return True, f"exit={proc.returncode}", dt, stderr


def main() -> int:
    ap = argparse.ArgumentParser(description="Runtime-attacks local test harness.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="dump stderr of every case (not just failures)")
    ap.add_argument("-k", "--filter", default="",
                    help="only run cases whose name contains this substring")
    args = ap.parse_args()

    if not TRACER.exists():
        print(f"[harness] tracer not built at {TRACER} - run `make build` first",
              file=sys.stderr)
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
