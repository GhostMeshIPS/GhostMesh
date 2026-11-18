"""
analyze.py - turns an experiment's run files into a table, a CSV and plots.

    python3 sim/analyze.py capacity
    python3 sim/analyze.py capacity --x traffic.avg_rate_mps     # choose the x axis

Finds which settings were swept, averages every metric across seeds for each setting,
prints a table, and writes:
    sim/out/<experiment>.csv
    sim/out/figures/<experiment>_<metric>.png   (mean line, shaded band = ±1 std across seeds)
"""
import argparse
import csv
import json
import statistics
import sys
from pathlib import Path

from config import OUT_DIR

# summary fields to report (PROTOCOL.md §13), with axis labels
METRICS = {
    "delivery_ratio":    "Delivery ratio",
    "tx_per_delivered":  "Transmissions per delivered message",
    "latency_ms_median": "Latency, median (ms)",
    "latency_ms_p95":    "Latency, 95th percentile (ms)",
    "collisions":        "Collisions per run",
}
SKIP_KEYS = {"type", "run_id", "commit", "experiment", "seed"}


# ---- loading --------------------------------------------------------------------

def _flatten(d: dict, prefix: str = "") -> dict:
    # {"channel": {"bitrate_kbps": 300}} -> {"channel.bitrate_kbps": 300}
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        elif isinstance(v, list):
            out[key] = tuple(v)
        else:
            out[key] = v
    return out


def load_runs(folder: Path) -> list:
    # one (config, summary) pair per finished run; unfinished files are skipped
    runs = []
    for p in sorted(folder.glob("*.jsonl")):
        if p.name.endswith(".watchtower.jsonl"):
            continue
        lines = p.read_text().splitlines()
        if len(lines) < 2:
            continue
        cfg, summ = json.loads(lines[0]), json.loads(lines[-1])
        if cfg.get("type") == "config" and summ.get("type") == "summary":
            runs.append((cfg, summ))
    return runs


def swept_keys(runs: list) -> list:
    # config fields that differ between runs (seed doesn't count)
    flat = [_flatten(c) for c, _ in runs]
    keys = [k for k in flat[0] if k not in SKIP_KEYS]
    return [k for k in keys if len({f.get(k) for f in flat}) > 1]


# ---- aggregating ----------------------------------------------------------------

def aggregate(runs: list, keys: list) -> list:
    """One row per setting: the swept values, how many seeds, and mean/std of each metric."""
    groups = {}
    for cfg, summ in runs:
        flat = _flatten(cfg)
        groups.setdefault(tuple(flat.get(k) for k in keys), []).append(summ)

    rows = []
    # numbers sort as numbers (300 before 1000), anything else as text
    order = lambda vals: [(0, v, "") if isinstance(v, (int, float)) else (1, 0, str(v)) for v in vals]
    for values, summs in sorted(groups.items(), key=lambda kv: order(kv[0])):
        row = dict(zip(keys, values))
        row["runs"] = len(summs)
        for m in METRICS:
            xs = [s[m] for s in summs if s.get(m) is not None]
            row[m] = statistics.mean(xs) if xs else None
            row[m + "_std"] = statistics.stdev(xs) if len(xs) > 1 else 0.0
        rows.append(row)
    return rows


def _fmt(v, std=None) -> str:
    if v is None:
        return "-"
    s = f"{v:.3f}" if isinstance(v, float) and abs(v) < 10 else f"{v:.1f}" if isinstance(v, float) else str(v)
    return s if not std else f"{s} ±{std:.2g}"


def print_table(rows: list, keys: list) -> None:
    cols = keys + ["runs"] + list(METRICS)
    table = [[_fmt(r[c], r.get(c + "_std")) if c in METRICS else _fmt(r[c]) for c in cols] for r in rows]
    short = [c.split(".")[-1] for c in cols]
    widths = [max(len(h), *(len(t[i]) for t in table)) for i, h in enumerate(short)]
    print("  ".join(h.ljust(w) for h, w in zip(short, widths)))
    for t in table:
        print("  ".join(v.ljust(w) for v, w in zip(t, widths)))


def write_csv(rows: list, path: Path) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


# ---- plotting ---------------------------------------------------------------------

def plot(rows: list, keys: list, x: str, experiment: str, out: Path) -> list:
    """One figure per metric: x on the horizontal axis, one line per combination of the other swept keys."""
    import matplotlib
    matplotlib.use("Agg")                                   # files only, no window
    import matplotlib.pyplot as plt

    others = [k for k in keys if k != x]
    lines = {}
    for r in rows:
        label = ", ".join(f"{k.split('.')[-1]}={r[k]}" for k in others) or experiment
        lines.setdefault(label, []).append(r)

    out.mkdir(parents=True, exist_ok=True)
    saved = []
    for m, ylabel in METRICS.items():
        fig, ax = plt.subplots(figsize=(7, 4.5))
        for label, pts in lines.items():
            pts = sorted((p for p in pts if p[m] is not None), key=lambda p: p[x])
            if not pts:
                continue
            xs = [p[x] for p in pts]
            ys = [p[m] for p in pts]
            sd = [p[m + "_std"] for p in pts]
            ax.plot(xs, ys, marker="o", label=label)
            # band = ±1 std, clamped to values the metric can actually take
            top = 1.0 if m == "delivery_ratio" else float("inf")
            lo = [max(0.0, y - s) for y, s in zip(ys, sd)]
            hi = [min(top, y + s) for y, s in zip(ys, sd)]
            ax.fill_between(xs, lo, hi, alpha=0.2)
        ax.set_xlabel(x.split(".")[-1])
        ax.set_ylabel(ylabel)
        ax.set_title(f"{experiment}: {ylabel}")
        ax.grid(alpha=0.3)
        if len(lines) > 1:
            ax.legend(fontsize=8)
        fig.tight_layout()
        path = out / f"{experiment}_{m}.png"
        fig.savefig(path, dpi=150)
        plt.close(fig)
        saved.append(path)
    return saved


# ---- main --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Summarize and plot a sim experiment.")
    ap.add_argument("experiment")
    ap.add_argument("--x", help="swept setting for the x axis (default: the one with the most values)")
    ap.add_argument("--dir", type=Path, help="read runs from here instead of sim/out/<experiment>")
    ap.add_argument("--no-plots", action="store_true")
    a = ap.parse_args()

    folder = a.dir or OUT_DIR / a.experiment
    runs = load_runs(folder)
    if not runs:
        sys.exit(f"no finished runs in {folder}")

    # results from different code shouldn't be mixed silently
    commits = {c.get("commit") for c, _ in runs}
    if len(commits) > 1 or any(c and c.endswith("+dirty") for c in commits):
        print(f"warning: runs come from more than one code version or uncommitted code: {sorted(map(str, commits))}")

    keys = swept_keys(runs)
    rows = aggregate(runs, keys)
    print(f"{a.experiment}: {len(runs)} runs, {len(rows)} settings" + (f", swept: {', '.join(keys)}" if keys else ""))
    print_table(rows, keys)

    out = folder.parent if a.dir is None else a.dir
    csv_path = out / f"{a.experiment}.csv"
    write_csv(rows, csv_path)
    print(f"csv: {csv_path}")

    if a.no_plots or not keys:
        return
    x = a.x or max(keys, key=lambda k: len({r[k] for r in rows}))
    if x not in keys:
        sys.exit(f"--x must be one of: {', '.join(keys)}")
    saved = plot(rows, keys, x, a.experiment, out / "figures")
    print(f"plots: {saved[0].parent}/ ({len(saved)} files)")


if __name__ == "__main__":
    main()
