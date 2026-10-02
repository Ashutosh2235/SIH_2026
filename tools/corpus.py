#!/usr/bin/env python3
"""Run SecureMailScope over a directory of captures and report how it coped.

    python tools/corpus.py ~/captures
    python tools/corpus.py ~/captures --timeout 120 --csv results.csv

This is a robustness harness, not a detection test. Third-party captures have no
ground truth, so the question it answers is "does the pipeline survive traffic
nobody built it for, and how fast" — parsed / crashed / timed out, throughput,
and what was actually found. Every crash it prints is a bug worth a test case.

Each capture runs in its own process so a hang or a segfault in one file cannot
take the sweep down with it.
"""
from __future__ import annotations

import argparse
import csv
import multiprocessing as mp
import sys
import time
from pathlib import Path

SUFFIXES = {".pcap", ".pcapng", ".cap", ".dmp"}
WRAPPERS = {".gz", ".bz2", ".xz", ".zst"}


def is_capture(path: Path) -> bool:
    suffixes = path.suffixes
    if not suffixes:
        return False
    if suffixes[-1] in WRAPPERS:
        return len(suffixes) > 1 and suffixes[-2] in SUFFIXES
    return suffixes[-1] in SUFFIXES


def _run(path: str, use_ml: bool, out) -> None:
    from securemailscope.pipeline import Options, analyze
    started = time.perf_counter()
    a = analyze(path, Options(use_ml=use_ml))
    out.put({
        "status": "ok",
        "seconds": round(time.perf_counter() - started, 3),
        "frames": a.meta["read"]["frames"],
        "compression": a.meta["read"]["compression"] or "-",
        "format": a.meta["read"]["format"],
        "flows": a.meta["flows"],
        "sessions": a.meta["mail_sessions"],
        "grade": a.posture["grade"],
        "score": a.posture["score"],
        "critical": a.posture["counts"]["critical"],
        "high": a.posture["counts"]["high"],
        "notes": "; ".join(a.meta["read"].get("notes", [])),
    })


def analyse_one(path: Path, timeout: float, use_ml: bool) -> dict:
    ctx = mp.get_context("spawn")
    queue = ctx.Queue()
    proc = ctx.Process(target=_run, args=(str(path), use_ml, queue))
    started = time.perf_counter()
    proc.start()
    proc.join(timeout)
    if proc.is_alive():
        proc.terminate(); proc.join()
        return {"status": "TIMEOUT", "seconds": round(time.perf_counter() - started, 1)}
    if not queue.empty():
        return queue.get()
    return {"status": f"CRASH (exit {proc.exitcode})",
            "seconds": round(time.perf_counter() - started, 3)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Robustness sweep over a capture corpus.")
    ap.add_argument("directory", type=Path)
    ap.add_argument("--timeout", type=float, default=90.0, help="seconds per capture")
    ap.add_argument("--no-ml", action="store_true", help="rules and baseline only (faster)")
    ap.add_argument("--csv", type=Path, help="also write the table here")
    args = ap.parse_args(argv)

    files = sorted(p for p in args.directory.rglob("*") if p.is_file() and is_capture(p))
    if not files:
        print(f"no captures under {args.directory}", file=sys.stderr)
        return 2

    print(f"{len(files)} captures under {args.directory}\n")
    header = f"{'capture':<52} {'status':<9} {'sec':>6} {'frames':>8} {'sess':>5} {'grade':>5}  findings"
    print(header); print("-" * len(header))

    rows, failures = [], 0
    for path in files:
        result = analyse_one(path, args.timeout, not args.no_ml)
        name = str(path.relative_to(args.directory))[:52]
        rows.append({"capture": name, **result})
        if result["status"] == "ok":
            sev = f"C{result['critical']} H{result['high']}"
            score = "—" if result["score"] is None else f"{result['grade']}"
            print(f"{name:<52} {'ok':<9} {result['seconds']:>6.2f} {result['frames']:>8,} "
                  f"{result['sessions']:>5} {score:>5}  {sev}"
                  + (f"   [{result['notes']}]" if result["notes"] else ""))
        else:
            failures += 1
            print(f"{name:<52} {result['status']:<9} {result['seconds']:>6.1f}")

    ok = [r for r in rows if r["status"] == "ok"]
    total_frames = sum(r["frames"] for r in ok)
    total_time = sum(r["seconds"] for r in ok)
    with_mail = sum(1 for r in ok if r["sessions"])

    print(f"\n  {len(ok)}/{len(files)} analysed, {failures} failed")
    print(f"  {with_mail} contained mail traffic, {len(ok) - with_mail} did not")
    print(f"  {total_frames:,} frames in {total_time:.1f}s"
          + (f"  ({total_frames / total_time:,.0f} frames/s)" if total_time else ""))
    if failures:
        print("\n  Every failure above is a capture shape the parser has not met. "
              "Add the smallest one that reproduces it to tests/ before fixing it.")

    if args.csv and rows:
        fields = sorted({k for r in rows for k in r})
        with args.csv.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["capture"] + [f for f in fields if f != "capture"])
            writer.writeheader(); writer.writerows(rows)
        print(f"\n  csv -> {args.csv}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
