"""
run.py - runs an experiment's configs in parallel. One output file per run.

    python sim/run.py --list                          # experiments and run counts
    python sim/run.py smoke --events --watchtower     # one run, full event log + watchtower log
    python sim/run.py capacity --limit 4              # first 4 runs only (to time it)
    python sim/run.py capacity --workers 8            # the whole sweep

Output: sim/out/<experiment>/<run_id>.jsonl = config line, [event lines], summary line.
Runs whose output already exists are skipped (so a stopped sweep resumes); --force reruns them.
"""
import argparse
import os
import subprocess
import sys
import time
from multiprocessing import Pool

import bindings
from config import ROOT, SEEDS, experiments
from engine import run_config

_lib = None


def _init_worker():
    # each process loads its own copy of librouting.so once (routing.c has no globals)
    global _lib
    _lib = bindings.load()


def _run_one(args):
    cfg, events, watchtower, commit = args
    try:
        s = run_config(cfg, lib=_lib, events=events, watchtower=watchtower, commit=commit)
        return cfg.run_id, None, s["wall_s"]
    except Exception as e:                       # report it and keep the sweep going
        return cfg.run_id, f"{type(e).__name__}: {e}", 0.0


def _commit() -> str:
    # which code produced the results; "+dirty" if there were uncommitted changes
    try:
        h = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "firmware/src/routing", "sim"], cwd=ROOT,
                               capture_output=True, text=True).stdout.strip()
        return h + ("+dirty" if dirty else "")
    except OSError:
        return None


def main():
    ap = argparse.ArgumentParser(description="Run a GhostMesh sim experiment.")
    ap.add_argument("experiment", nargs="?")
    ap.add_argument("--list", action="store_true", help="list experiments and exit")
    ap.add_argument("--seeds", type=int, default=SEEDS, help=f"seeds per configuration (default {SEEDS})")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--limit", type=int, help="only the first N runs")
    ap.add_argument("--force", action="store_true", help="rerun runs that already have output")
    ap.add_argument("--events", action="store_true", help="write every routing event (large files)")
    ap.add_argument("--watchtower", action="store_true", help="also write a watchtower-format log")
    a = ap.parse_args()

    exps = experiments(a.seeds)
    if a.list or not a.experiment:
        for name, runs in exps.items():
            print(f"{name:13s} {len(runs):5d} runs")
        return
    if a.experiment not in exps:
        sys.exit(f"unknown experiment '{a.experiment}'. try --list")

    bindings.build()                             # compile once here, not in every worker
    runs = exps[a.experiment][: a.limit] if a.limit else exps[a.experiment]
    todo = [r for r in runs if a.force or not r.out_path.exists()]
    commit = _commit()
    print(f"{a.experiment}: {len(todo)} to run, {len(runs) - len(todo)} already done, "
          f"{a.workers} workers, commit {commit}")
    if not todo:
        return

    start, done, failed = time.time(), 0, []
    with Pool(a.workers, initializer=_init_worker) as pool:
        for run_id, err, _ in pool.imap_unordered(_run_one, [(r, a.events, a.watchtower, commit) for r in todo]):
            done += 1
            if err:
                failed.append((run_id, err))
            print(f"\r  {done}/{len(todo)}  ({time.time() - start:.0f} s)", end="", flush=True)
    print()
    for run_id, err in failed:
        print(f"  FAILED {run_id}: {err}")
    print(f"output: {runs[0].out_path.parent.relative_to(ROOT)}/")


if __name__ == "__main__":
    main()
