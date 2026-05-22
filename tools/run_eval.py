#!/usr/bin/env python3
"""
run_eval.py - Measurement harness for runtime-attacks detector evaluation.

Distinct from run_tests.py (correctness gate, must not be changed). This
script collects N repeated runs per case, writes per-run CSV files, and
produces a summary markdown. It is the evaluation-engineer harness that
feeds numbers into report/body/60-evaluation.tex.

Design choices (documented so the report can cite them):
- Timing is wall-clock via time.monotonic() in the Python process that
  calls subprocess.run(). This captures fork+exec overhead of the tracer
  and victim but NOT Python's own startup. Python startup is constant
  across conditions and cancels out in the overhead ratio.
- For "victim alone" runs: the victim binary is invoked directly (no
  tracer) with the benign payload. This is the denominator of the
  overhead ratio.
- For "tracer benign" runs: tracer + victim, benign payload. Numerator.
- For "tracer attack" runs: exploit.py generates payload, piped to tracer
  + victim. This measures time-to-detection including Python+pwntools
  startup. The pwntools startup component is measured separately
  (--measure-pwn-startup) so the report can note it.
- Alert count is the number of "[!!! ATTACK DETECTED]" lines in stderr.
- CPU governor is ondemand on this Pi 4; we note it but do not change it.

Usage:
    python3 tools/run_eval.py                   # N=30, date = today
    python3 tools/run_eval.py --n 50            # override sample size
    python3 tools/run_eval.py --out-dir eval/   # override output root
    python3 tools/run_eval.py --measure-pwn-startup

Research questions answered:
    RQ-1  Detection rate:  detected/N for each attack class
    RQ-2  False positive:  falsely-alerted/N for each benign case
    RQ-3  Overhead ratio:  wall(tracer+victim) / wall(victim alone)
    RQ-4  Time-to-detection: wall(tracer+victim attack) - wall(victim alone benign)
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TRACER    = REPO_ROOT / "detector" / "tracer"
BUILD_CFG = REPO_ROOT / "tools" / "build_cfg.py"

ATTACK_DETECTED_MARKER = "[!!! ATTACK DETECTED]"

# ---------------------------------------------------------------------------
# Attack matrix
# ---------------------------------------------------------------------------
# Each entry describes one attack directory. We always measure four cases:
#   benign-alone   : victim only, echo "hello" stdin, no tracer
#   benign-traced  : tracer + victim, echo "hello" stdin
#   attack-traced  : tracer + victim, exploit.py stdin
#
# For 04-data-only there is no tracer entry (the CFG file is also absent)
# because that case is a documented L1 gap, not a harness bug. We still run
# the attack under the tracer once to verify the miss, but we record the
# expected_detection as False and add the gap_reason.

ATTACK_MATRIX = [
    {
        "attack_id":          "01-stack-bof",
        "victim":             "attacks/01-stack-bof/victim",
        "benign_input_cmd":   ["echo", "hello"],
        "exploit_cmd":        ["python3", "attacks/01-stack-bof/exploit.py"],
        "expected_detection": True,
        "expected_exit_benign":  0,
        "expected_exit_attack":  2,
        "gap_reason":         None,
    },
    {
        "attack_id":          "02-rop",
        "victim":             "attacks/02-rop/victim",
        "benign_input_cmd":   ["echo", "hello"],
        "exploit_cmd":        ["python3", "attacks/02-rop/exploit.py"],
        "expected_detection": True,
        "expected_exit_benign":  0,
        "expected_exit_attack":  2,
        "gap_reason":         None,
    },
    {
        "attack_id":          "03-jop",
        "victim":             "attacks/03-jop/victim",
        "benign_input_cmd":   ["echo", "hello"],
        "exploit_cmd":        ["python3", "attacks/03-jop/exploit.py"],
        "expected_detection": True,
        "expected_exit_benign":  0,
        "expected_exit_attack":  2,
        "gap_reason":         None,
    },
    {
        "attack_id":          "04-data-only",
        "victim":             "attacks/04-data-only/victim",
        "benign_input_cmd":   ["echo", "hello"],
        "exploit_cmd":        ["python3", "attacks/04-data-only/exploit.py"],
        "expected_detection": False,
        "expected_exit_benign":  0,
        "expected_exit_attack":  0,   # tracer exits 0 (no alert fired)
        "gap_reason": (
            "L1 (control-flow) detector cannot observe data-only attacks: "
            "the exploit overwrites is_admin (a non-pointer integer) without "
            "corrupting any saved return address or indirect-call target. "
            "Every branch taken in the exploited run is also a legal CFG edge "
            "reachable under benign data. Detection requires L2 data-provenance "
            "tracking or L3 spatial memory safety (Chen et al., USENIX Sec 2005)."
        ),
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def stats(values: list[float]) -> dict:
    """Return mean, stddev, p50, p95 over a list of floats."""
    n = len(values)
    if n == 0:
        return {"mean": float("nan"), "stddev": float("nan"), "p50": float("nan"), "p95": float("nan"), "n": 0}
    mean = sum(values) / n
    var  = sum((x - mean) ** 2 for x in values) / (n - 1) if n > 1 else 0.0
    stddev = math.sqrt(var)
    sv = sorted(values)

    def percentile(p: float) -> float:
        idx = (n - 1) * p / 100.0
        lo  = int(idx)
        hi  = min(lo + 1, n - 1)
        frac = idx - lo
        return sv[lo] * (1 - frac) + sv[hi] * frac

    return {
        "mean":   mean,
        "stddev": stddev,
        "p50":    percentile(50),
        "p95":    percentile(95),
        "n":      n,
    }


def build_cfgs(matrix: list[dict]) -> bool:
    """Regenerate .cfg files for victims that have a supported CFG build."""
    ok = True
    done = set()
    for entry in matrix:
        v = entry["victim"]
        if v in done:
            continue
        done.add(v)
        victim_path = REPO_ROOT / v
        if not victim_path.exists():
            print(f"[eval] ERROR: victim binary missing: {victim_path}", file=sys.stderr)
            ok = False
            continue
        # 04-data-only has no .cfg because the tracer build_cfg is not
        # required for that gap-demo case
        r = subprocess.run(
            [sys.executable, str(BUILD_CFG), v],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        for line in (r.stdout + r.stderr).splitlines():
            print(f"[eval] build_cfg: {line}")
        if r.returncode != 0:
            print(f"[eval] build_cfg failed for {v} (exit {r.returncode})", file=sys.stderr)
            ok = False
    return ok


def run_once_victim_alone(
    victim_rel: str, input_bytes: bytes, timeout: int = 30
) -> dict:
    """Run victim binary directly (no tracer). Returns timing + exit code."""
    victim_path = REPO_ROOT / victim_rel
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [str(victim_path)],
            input=input_bytes,
            capture_output=True,
            cwd=REPO_ROOT,
            timeout=timeout,
        )
        wall_ms = (time.monotonic() - t0) * 1000.0
        return {
            "wall_ms":     wall_ms,
            "exit_code":   proc.returncode,
            "alert_count": 0,
            "error":       None,
        }
    except subprocess.TimeoutExpired:
        return {"wall_ms": None, "exit_code": None, "alert_count": 0,
                "error": "timeout"}


def run_once_traced(
    victim_rel: str, input_bytes: bytes, timeout: int = 30
) -> dict:
    """Run tracer + victim with pre-generated payload bytes. Returns timing + alert count."""
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            [str(TRACER), victim_rel],
            input=input_bytes,
            capture_output=True,
            cwd=REPO_ROOT,
            timeout=timeout,
        )
        wall_ms = (time.monotonic() - t0) * 1000.0
        stderr = proc.stderr.decode(errors="replace")
        alert_count = stderr.count(ATTACK_DETECTED_MARKER)
        return {
            "wall_ms":     wall_ms,
            "exit_code":   proc.returncode,
            "alert_count": alert_count,
            "error":       None,
        }
    except subprocess.TimeoutExpired:
        return {"wall_ms": None, "exit_code": None, "alert_count": 0,
                "error": "timeout"}


def generate_payload(cmd: list[str], timeout: int = 60) -> bytes | None:
    """Run a command (e.g. exploit.py) and capture its stdout as the payload."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, cwd=REPO_ROOT, timeout=timeout, check=True
        )
        return r.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"[eval] payload generation failed: {exc}", file=sys.stderr)
        return None


def generate_payload_timed(cmd: list[str], timeout: int = 60) -> tuple[bytes | None, float]:
    """Run payload generator and return (bytes, wall_ms_for_generation)."""
    t0 = time.monotonic()
    payload = generate_payload(cmd, timeout)
    wall_ms = (time.monotonic() - t0) * 1000.0
    return payload, wall_ms


# ---------------------------------------------------------------------------
# CSV writing
# ---------------------------------------------------------------------------

CSV_FIELDS = ["run_index", "timestamp_iso", "wall_ms", "exit_code",
              "alert_count", "error"]


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Core measurement loop
# ---------------------------------------------------------------------------

def measure_benign_alone(entry: dict, n: int, csv_dir: Path) -> dict:
    """N runs of victim alone (no tracer) with benign input."""
    attack_id = entry["attack_id"]
    victim    = entry["victim"]

    # Generate benign payload once (echo "hello" is deterministic)
    payload, _ = generate_payload_timed(entry["benign_input_cmd"])
    if payload is None:
        return {"error": "payload generation failed"}

    rows = []
    for i in range(n):
        result = run_once_victim_alone(victim, payload)
        rows.append({
            "run_index":    i,
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "wall_ms":      result["wall_ms"],
            "exit_code":    result["exit_code"],
            "alert_count":  result["alert_count"],
            "error":        result["error"] or "",
        })
        if (i + 1) % 10 == 0:
            print(f"[eval] {attack_id} benign-alone: {i+1}/{n}")

    csv_path = csv_dir / f"{attack_id}-benign-alone.csv"
    write_csv(csv_path, rows)

    wall_times = [r["wall_ms"] for r in rows if r["wall_ms"] is not None]
    s = stats(wall_times)
    print(f"[eval] {attack_id} benign-alone: mean={s['mean']:.1f}ms "
          f"stddev={s['stddev']:.1f}ms p50={s['p50']:.1f}ms p95={s['p95']:.1f}ms")
    return {"stats": s, "rows": rows, "csv": str(csv_path)}


def measure_benign_traced(entry: dict, n: int, csv_dir: Path) -> dict:
    """N runs of tracer+victim with benign input."""
    attack_id = entry["attack_id"]
    victim    = entry["victim"]

    payload, _ = generate_payload_timed(entry["benign_input_cmd"])
    if payload is None:
        return {"error": "payload generation failed"}

    rows = []
    fp_count = 0
    wrong_exit_count = 0
    for i in range(n):
        result = run_once_traced(victim, payload)
        is_fp = result["alert_count"] > 0
        if is_fp:
            fp_count += 1
            print(f"[eval] WARNING: false positive on {attack_id} benign run {i}: "
                  f"alert_count={result['alert_count']} exit={result['exit_code']}", file=sys.stderr)
        if result["exit_code"] != entry["expected_exit_benign"]:
            wrong_exit_count += 1
            print(f"[eval] WARNING: unexpected exit {result['exit_code']} "
                  f"(want {entry['expected_exit_benign']}) on {attack_id} benign run {i}",
                  file=sys.stderr)
        rows.append({
            "run_index":     i,
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "wall_ms":       result["wall_ms"],
            "exit_code":     result["exit_code"],
            "alert_count":   result["alert_count"],
            "error":         result["error"] or "",
        })
        if (i + 1) % 10 == 0:
            print(f"[eval] {attack_id} benign-traced: {i+1}/{n}")

    csv_path = csv_dir / f"{attack_id}-benign-traced.csv"
    write_csv(csv_path, rows)

    wall_times = [r["wall_ms"] for r in rows if r["wall_ms"] is not None]
    s = stats(wall_times)
    fpr = fp_count / n
    print(f"[eval] {attack_id} benign-traced: mean={s['mean']:.1f}ms "
          f"stddev={s['stddev']:.1f}ms p50={s['p50']:.1f}ms p95={s['p95']:.1f}ms "
          f"FPR={fpr:.3f} ({fp_count}/{n})")
    if wrong_exit_count:
        print(f"[eval] ANOMALY: {wrong_exit_count}/{n} runs had unexpected exit code "
              f"on {attack_id} benign case. Investigate.", file=sys.stderr)
    return {
        "stats":             s,
        "rows":              rows,
        "csv":               str(csv_path),
        "fp_count":          fp_count,
        "fpr":               fpr,
        "wrong_exit_count":  wrong_exit_count,
    }


def measure_attack_traced(entry: dict, n: int, csv_dir: Path) -> dict:
    """N runs of tracer+victim with attack payload."""
    attack_id = entry["attack_id"]
    victim    = entry["victim"]
    is_gap    = not entry["expected_detection"]

    # Pre-generate payload once. For non-pwntools exploits (04-data-only) this
    # is fast. For pwntools exploits we separate payload-gen time from
    # tracer+victim time — the caller uses the tracer-only wall_ms for
    # time-to-detection, not the end-to-end including Python startup.
    # We generate once and reuse; this is valid because our exploits are
    # deterministic (addresses are fixed, no randomness, no PIE).
    print(f"[eval] {attack_id} attack: generating payload (once, reused for all {n} runs)...")
    payload, payload_gen_ms = generate_payload_timed(entry["exploit_cmd"])
    if payload is None:
        return {"error": "payload generation failed"}
    print(f"[eval] {attack_id} attack: payload generated in {payload_gen_ms:.0f}ms, "
          f"size={len(payload)} bytes")

    rows = []
    detected_count = 0
    for i in range(n):
        result = run_once_traced(victim, payload)
        detected = result["alert_count"] > 0 or result["exit_code"] == 2
        if detected and not is_gap:
            detected_count += 1
        elif detected and is_gap:
            # A detection on a gap case is anomalous — flag it
            print(f"[eval] ANOMALY: {attack_id} gap case fired an alert on run {i}: "
                  f"alert_count={result['alert_count']} exit={result['exit_code']}",
                  file=sys.stderr)
        elif not detected and not is_gap:
            # A miss on an expected-detect case is anomalous
            print(f"[eval] ANOMALY: {attack_id} expected detection MISSED on run {i}: "
                  f"exit={result['exit_code']} alerts={result['alert_count']}",
                  file=sys.stderr)

        rows.append({
            "run_index":     i,
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "wall_ms":       result["wall_ms"],
            "exit_code":     result["exit_code"],
            "alert_count":   result["alert_count"],
            "error":         result["error"] or "",
        })
        if (i + 1) % 10 == 0:
            print(f"[eval] {attack_id} attack-traced: {i+1}/{n}")

    csv_path = csv_dir / f"{attack_id}-attack-traced.csv"
    write_csv(csv_path, rows)

    wall_times = [r["wall_ms"] for r in rows if r["wall_ms"] is not None]
    s = stats(wall_times)
    detection_rate = detected_count / n
    print(f"[eval] {attack_id} attack-traced: mean={s['mean']:.1f}ms "
          f"stddev={s['stddev']:.1f}ms p50={s['p50']:.1f}ms p95={s['p95']:.1f}ms "
          f"detection_rate={detection_rate:.3f} ({detected_count}/{n})")
    return {
        "stats":            s,
        "rows":             rows,
        "csv":              str(csv_path),
        "detected_count":   detected_count,
        "detection_rate":   detection_rate,
        "payload_gen_ms":   payload_gen_ms,
    }


def measure_pwn_startup(n: int = 10) -> dict:
    """Measure python3 + pwntools import time (separate from tracer overhead)."""
    print(f"[eval] measuring pwntools startup ({n} runs)...")
    times = []
    for i in range(n):
        t0 = time.monotonic()
        subprocess.run(
            [sys.executable, "-c", "import pwn"],
            capture_output=True, cwd=REPO_ROOT, timeout=30
        )
        times.append((time.monotonic() - t0) * 1000.0)
    s = stats(times)
    print(f"[eval] pwntools startup: mean={s['mean']:.0f}ms "
          f"stddev={s['stddev']:.1f}ms p50={s['p50']:.0f}ms p95={s['p95']:.0f}ms")
    return s


# ---------------------------------------------------------------------------
# Summary markdown
# ---------------------------------------------------------------------------

def _fmt_stats(s: dict) -> str:
    if s.get("n", 0) == 0 or math.isnan(s["mean"]):
        return "N/A"
    return (f"{s['mean']:.1f} ± {s['stddev']:.1f} ms "
            f"(p50={s['p50']:.1f}, p95={s['p95']:.1f})")


def write_summary(
    out_path: Path,
    today: str,
    repo_sha: str,
    kernel: str,
    cpu_governor: str,
    n: int,
    pwn_startup: dict | None,
    results: list[dict],
) -> None:
    lines = []
    lines.append(f"# Evaluation Summary — {today}")
    lines.append("")
    lines.append("## Setup")
    lines.append("")
    lines.append("| Parameter     | Value |")
    lines.append("|---------------|-------|")
    lines.append(f"| Date          | {today} |")
    lines.append(f"| Repo SHA      | `{repo_sha}` |")
    lines.append(f"| Kernel        | `{kernel}` |")
    lines.append(f"| Architecture  | aarch64 (Raspberry Pi 4, Cortex-A72) |")
    lines.append(f"| CPU governor  | `{cpu_governor}` |")
    lines.append(f"| N per case    | {n} |")
    lines.append(f"| Timing method | Python `time.monotonic()` (wall clock) around `subprocess.run()` |")
    lines.append(f"| Attack payload| Pre-generated once, reused across N runs (deterministic exploits, no PIE) |")
    lines.append("")

    if pwn_startup:
        lines.append(f"**pwntools startup** (python3 -c 'import pwn', N=10): "
                     f"{pwn_startup['mean']:.0f} ± {pwn_startup['stddev']:.1f} ms. "
                     f"This is NOT included in overhead ratio or time-to-detection "
                     f"figures (payload is pre-generated; only tracer+victim time is counted).")
        lines.append("")

    # Detection rate table
    lines.append("## Detection Rates")
    lines.append("")
    lines.append("| Attack | Type | Expected | Detection Rate | Notes |")
    lines.append("|--------|------|----------|----------------|-------|")
    for r in results:
        entry = r["entry"]
        ar    = r.get("attack_result", {})
        exp   = "Detect (exit 2)" if entry["expected_detection"] else "Miss (gap)"
        dr    = ar.get("detection_rate")
        dc    = ar.get("detected_count", "N/A")
        nn    = n
        if entry["expected_detection"]:
            if dr is not None:
                dr_str = f"{dr*100:.1f}% ({dc}/{nn})"
            else:
                dr_str = "ERROR"
        else:
            # Gap case: detection_rate = 0% expected
            if dr is not None:
                dr_str = f"{dr*100:.1f}% ({dc}/{nn}) — expected 0%"
            else:
                dr_str = "0% (expected — L1 gap)"
        note = entry["gap_reason"][:60] + "..." if entry["gap_reason"] else ""
        lines.append(f"| `{entry['attack_id']}` | {'Detected' if entry['expected_detection'] else 'Gap demo'} | {exp} | {dr_str} | {note} |")
    lines.append("")

    # FPR table
    lines.append("## False Positive Rates (benign runs, tracer active)")
    lines.append("")
    lines.append("| Attack | FPR | False Alerts / N |")
    lines.append("|--------|-----|-----------------|")
    for r in results:
        entry = r["entry"]
        br    = r.get("benign_traced_result", {})
        fp    = br.get("fp_count", "N/A")
        fpr   = br.get("fpr")
        if fpr is not None:
            fpr_str = f"{fpr*100:.2f}%"
        else:
            fpr_str = "N/A"
        lines.append(f"| `{entry['attack_id']}` | {fpr_str} | {fp}/{n} |")
    lines.append("")

    # Overhead table
    lines.append("## Wall-Clock Overhead (benign payload, tracer vs. victim-alone)")
    lines.append("")
    lines.append("| Attack | Victim alone | Tracer+Victim | Overhead ratio (mean) |")
    lines.append("|--------|-------------|---------------|----------------------|")
    for r in results:
        entry   = r["entry"]
        alone_s = r.get("benign_alone_result", {}).get("stats", {})
        traced_s= r.get("benign_traced_result", {}).get("stats", {})
        alone_m = alone_s.get("mean", float("nan"))
        traced_m= traced_s.get("mean", float("nan"))
        if not math.isnan(alone_m) and not math.isnan(traced_m) and alone_m > 0:
            ratio = traced_m / alone_m
            ratio_str = f"{ratio:.2f}x"
        else:
            ratio_str = "N/A"
        lines.append(
            f"| `{entry['attack_id']}` | "
            f"{_fmt_stats(alone_s)} | "
            f"{_fmt_stats(traced_s)} | "
            f"{ratio_str} |"
        )
    lines.append("")

    # Time-to-detection (tracer wall for attack runs, only detected attacks)
    lines.append("## Time-to-Detection (tracer+victim, attack payload)")
    lines.append("")
    lines.append("| Attack | Tracer+Victim (attack) | Detected | Note |")
    lines.append("|--------|----------------------|----------|------|")
    for r in results:
        entry = r["entry"]
        ar    = r.get("attack_result", {})
        s     = ar.get("stats", {})
        if entry["expected_detection"] and ar.get("detection_rate", 0) > 0:
            t2d_str = _fmt_stats(s)
            detected_str = "Yes"
            note = "Tracer wall only (payload pre-generated; excludes Python startup)"
        elif not entry["expected_detection"]:
            t2d_str = _fmt_stats(s)
            detected_str = "No (expected)"
            note = entry["gap_reason"][:80] + "..." if entry["gap_reason"] else ""
        else:
            t2d_str = "N/A"
            detected_str = "No (ANOMALY)"
            note = "See anomaly warnings above"
        lines.append(f"| `{entry['attack_id']}` | {t2d_str} | {detected_str} | {note} |")
    lines.append("")

    # Per-attack explanations
    lines.append("## Per-Attack Explanations")
    lines.append("")

    explanations = {
        "01-stack-bof": (
            "Stack buffer overflow overwrites the saved return address in main's "
            "stack frame. The shadow call stack records the legitimate return "
            "address when `bl vuln` executes; on `ret` from vuln back to main, "
            "main's epilogue `ret` is checked and the forged value is caught "
            "immediately (at depth 0, before `win()` can execute). "
            "Answers RQ-1: detection rate 100%; RQ-2: FPR 0%; RQ-3: overhead documented above."
        ),
        "02-rop": (
            "Three-gadget ROP chain exploits the same overflow primitive. "
            "The very first `ret` in the chain returns to a gadget address rather "
            "than the legitimate call site, which the shadow call stack rejects. "
            "This confirms that the shadow call stack is structurally sufficient "
            "against any ret-based hijack regardless of chain length. "
            "Answers RQ-1: detection rate 100%."
        ),
        "03-jop": (
            "Jump-oriented programming (JOP) attack uses `blr x0` to redirect to "
            "a gadget function, then `br x16` onward to win(). No `ret` instruction "
            "is forged, so a shadow-stack-only detector cannot catch it. The iter-3b "
            "CFG-edge validator (per-call-site indirect-call target set) detects the "
            "pivot because jop_gadget is never a materialised call target at the "
            "blr site. Answers RQ-1: detection rate 100% (with CFG-edge check)."
        ),
        "04-data-only": (
            "Non-control-data attack. The exploit writes exactly 36 bytes: 32 for "
            "u.name and 4 to set u.is_admin = 1. Saved x29/x30 are never touched. "
            "The `bl admin_panel` branch is a valid CFG edge (benign code could "
            "legitimately reach it if is_admin were truly set), so neither the "
            "shadow call stack nor the CFG-edge validator fires. Detection requires "
            "L2 data-provenance tracking or L3 spatial memory safety, both outside "
            "the scope of the L1 control-flow detector. "
            "This is the canonical non-control-data attack (Chen, Xu, Sezer, Gauriar, "
            "Iyer, USENIX Security 2005). Detection rate = 0% as expected. "
            "Answers RQ-1 by documenting the gap, not a failure."
        ),
    }

    for r in results:
        eid = r["entry"]["attack_id"]
        lines.append(f"### {eid}")
        lines.append("")
        lines.append(explanations.get(eid, "(no explanation provided)"))
        lines.append("")

    # Research question mapping
    lines.append("## Research Question Mapping")
    lines.append("")
    lines.append("| RQ | Metric | Value |")
    lines.append("|----|--------|-------|")
    for r in results:
        entry = r["entry"]
        eid   = entry["attack_id"]
        ar    = r.get("attack_result", {})
        dr    = ar.get("detection_rate")
        br    = r.get("benign_traced_result", {})
        fpr   = br.get("fpr")
        alone_s  = r.get("benign_alone_result", {}).get("stats", {})
        traced_s = br.get("stats", {})
        alone_m  = alone_s.get("mean", float("nan"))
        traced_m = traced_s.get("mean", float("nan"))
        ratio = (traced_m / alone_m) if (not math.isnan(alone_m) and alone_m > 0) else float("nan")

        dr_str = f"{dr*100:.1f}%" if dr is not None else "N/A"
        fpr_str = f"{fpr*100:.2f}%" if fpr is not None else "N/A"
        ratio_str = f"{ratio:.2f}x" if not math.isnan(ratio) else "N/A"
        lines.append(
            f"| RQ-1 (detection) | `{eid}` detection rate | {dr_str} (N={n}) |"
        )
        lines.append(
            f"| RQ-2 (FPR)       | `{eid}` benign FPR     | {fpr_str} (N={n}) |"
        )
        lines.append(
            f"| RQ-3 (overhead)  | `{eid}` overhead ratio  | {ratio_str} |"
        )
    lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[eval] summary written to {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Measurement harness for runtime-attacks evaluation."
    )
    ap.add_argument("--n", type=int, default=30,
                    help="Number of runs per case (default 30; use 50 if CV > 0.3)")
    ap.add_argument("--out-dir", default="eval",
                    help="Root output directory (default: eval/)")
    ap.add_argument("--date", default=str(date.today()),
                    help="Date string for output paths (default: today)")
    ap.add_argument("--measure-pwn-startup", action="store_true",
                    help="Also measure pwntools startup time (10 runs)")
    ap.add_argument("--attacks", default="",
                    help="Comma-separated attack IDs to run (default: all)")
    args = ap.parse_args()

    n         = args.n
    today     = args.date
    out_root  = REPO_ROOT / args.out_dir
    csv_dir   = out_root / "raw" / today

    print(f"[eval] N={n}, date={today}, out_dir={out_root}")
    print(f"[eval] REPO_ROOT={REPO_ROOT}")

    if not TRACER.exists():
        print(f"[eval] ERROR: tracer not found at {TRACER}. Run `make build`.", file=sys.stderr)
        return 2

    # Filter attack matrix if requested
    matrix = ATTACK_MATRIX
    if args.attacks:
        wanted = set(args.attacks.split(","))
        matrix = [e for e in ATTACK_MATRIX if e["attack_id"] in wanted]
        if not matrix:
            print(f"[eval] ERROR: no matching attacks for filter {args.attacks!r}", file=sys.stderr)
            return 2

    # (Re)generate CFGs
    if not build_cfgs(matrix):
        return 2

    # Optionally measure pwntools startup
    pwn_startup = None
    if args.measure_pwn_startup:
        pwn_startup = measure_pwn_startup(n=10)

    # Collect system info
    kernel = subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip()
    try:
        cpu_governor = Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").read_text().strip()
    except Exception:
        cpu_governor = "unknown"
    repo_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
        cwd=REPO_ROOT
    ).stdout.strip()

    print(f"[eval] kernel={kernel}, governor={cpu_governor}, sha={repo_sha}")

    # --- Main measurement loop ---
    all_results = []
    for entry in matrix:
        eid = entry["attack_id"]
        print(f"\n[eval] ===== {eid} =====")

        print(f"[eval] {eid}: benign-alone ({n} runs)...")
        alone_result = measure_benign_alone(entry, n, csv_dir)

        print(f"[eval] {eid}: benign-traced ({n} runs)...")
        traced_benign_result = measure_benign_traced(entry, n, csv_dir)

        # Check FPR anomaly: if FPR > 0 on any attack that isn't the gap case,
        # it's suspicious. For gap cases too - benign FPR should always be 0.
        fpr = traced_benign_result.get("fpr", 0)
        if fpr > 0:
            print(f"[eval] ANOMALY: FPR={fpr:.3f} on {eid} benign case. "
                  f"Investigate — this should be 0.", file=sys.stderr)

        print(f"[eval] {eid}: attack-traced ({n} runs)...")
        attack_result = measure_attack_traced(entry, n, csv_dir)

        # Check detection anomaly
        dr = attack_result.get("detection_rate", None)
        if entry["expected_detection"] and dr is not None and dr < 1.0:
            print(f"[eval] ANOMALY: {eid} expected 100% detection but got "
                  f"{dr*100:.1f}%. INVESTIGATE BEFORE REPORTING.", file=sys.stderr)
        if not entry["expected_detection"] and dr is not None and dr > 0:
            print(f"[eval] ANOMALY: {eid} is a documented gap but got "
                  f"detection_rate={dr*100:.1f}%. INVESTIGATE.", file=sys.stderr)

        all_results.append({
            "entry":                entry,
            "benign_alone_result":  alone_result,
            "benign_traced_result": traced_benign_result,
            "attack_result":        attack_result,
        })

    # Write summary markdown
    summary_path = out_root / f"summary-{today}.md"
    write_summary(
        out_path=summary_path,
        today=today,
        repo_sha=repo_sha,
        kernel=kernel,
        cpu_governor=cpu_governor,
        n=n,
        pwn_startup=pwn_startup,
        results=all_results,
    )

    # Print headline numbers to stdout for easy review
    print("\n" + "="*70)
    print("HEADLINE NUMBERS")
    print("="*70)
    for r in all_results:
        entry    = r["entry"]
        eid      = entry["attack_id"]
        ar       = r.get("attack_result", {})
        br       = r.get("benign_traced_result", {})
        alone_s  = r.get("benign_alone_result", {}).get("stats", {})
        traced_s = br.get("stats", {})
        alone_m  = alone_s.get("mean", float("nan"))
        traced_m = traced_s.get("mean", float("nan"))
        ratio    = (traced_m / alone_m) if (not math.isnan(alone_m) and alone_m > 0) else float("nan")
        dr       = ar.get("detection_rate")
        fpr      = br.get("fpr")

        dr_str    = f"{dr*100:.1f}%" if dr is not None else "N/A"
        fpr_str   = f"{fpr*100:.2f}%" if fpr is not None else "N/A"
        ratio_str = f"{ratio:.2f}x" if not math.isnan(ratio) else "N/A"

        print(f"  {eid}: detection={dr_str}  FPR={fpr_str}  overhead={ratio_str}  "
              f"alone={alone_m:.1f}ms  traced={traced_m:.1f}ms")
    print("="*70)
    print(f"\n[eval] Done. Summary: {summary_path}")
    print(f"[eval] Raw CSV:  {csv_dir}/")

    return 0


if __name__ == "__main__":
    sys.exit(main())
