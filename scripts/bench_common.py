"""Shared statistics and raw-sample export for the research-track benchmarks.

Used by scripts/bench_crypto.py and scripts/bench_safety_response.py so both
report the same set of numbers the same way, and so neither benchmark's raw
samples are lost -- every reported figure must trace back to a row in
results/raw/*.csv, per docs/RESEARCH_AUDIT.md's reproducibility findings.
"""

import csv
import json
import pathlib
import statistics

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS_RAW = ROOT / "results" / "raw"
RESULTS_PROCESSED = ROOT / "results" / "processed"


def percentile(sorted_samples, p):
    """Nearest-rank percentile. sorted_samples must already be sorted."""
    if not sorted_samples:
        return None
    index = max(0, min(len(sorted_samples) - 1, int(round(p / 100 * len(sorted_samples))) - 1))
    return sorted_samples[index]


def stats(samples):
    """Full statistical summary for one series of millisecond timings.

    p99.9 is reported as None -- and must be printed as NOT MEASURED, never
    omitted silently -- when there are fewer than 1000 samples, because a
    999th-percentile estimate from under 1000 points is not a measurement.
    """
    ordered = sorted(samples)
    n = len(ordered)
    return {
        "n": n,
        "mean_ms": statistics.mean(ordered),
        "median_ms": statistics.median(ordered),
        "stdev_ms": statistics.stdev(ordered) if n > 1 else 0.0,
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
        "p50_ms": percentile(ordered, 50),
        "p90_ms": percentile(ordered, 90),
        "p95_ms": percentile(ordered, 95),
        "p99_ms": percentile(ordered, 99),
        "p999_ms": percentile(ordered, 99.9) if n >= 1000 else None,
    }


def write_raw_csv(name, rows, fieldnames):
    """rows: list of dicts. Appends a run to results/raw/<name>.csv (created
    with a header on first write) so repeated runs accumulate raw evidence
    rather than overwriting it."""
    RESULTS_RAW.mkdir(parents=True, exist_ok=True)
    path = RESULTS_RAW / f"{name}.csv"
    is_new = not path.exists()
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if is_new:
            writer.writeheader()
        writer.writerows(rows)
    return path


def write_summary_json(name, payload):
    RESULTS_PROCESSED.mkdir(parents=True, exist_ok=True)
    path = RESULTS_PROCESSED / f"{name}.json"
    path.write_text(json.dumps(payload, indent=2))
    return path


def print_stats_table(rows):
    """rows: list of (label, stats_dict). NOT MEASURED prints literally, per
    the parent research brief -- never a fabricated or estimated number."""
    header = f"{'operation':<34}{'n':>6}{'median':>10}{'p95':>10}{'p99':>10}{'p99.9':>10}"
    print(header)
    print("-" * len(header))
    for label, s in rows:
        p999 = f"{s['p999_ms']:.3f}ms" if s["p999_ms"] is not None else "NOT MEASURED"
        print(f"{label:<34}{s['n']:>6}{s['median_ms']:>9.3f}ms{s['p95_ms']:>9.3f}ms"
              f"{s['p99_ms']:>9.3f}ms{p999:>13}")
