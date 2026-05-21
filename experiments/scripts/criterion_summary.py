#!/usr/bin/env python3
"""Summarize criterion microbenchmark results into a single JSON file.

Reads each `target/criterion/<bench>/new/sample.json` produced by the
`slotguard-core` benches (`cargo bench -p slotguard-core`) and emits
median, p99, and per-iteration time so the SlotGuard paper can cite
real numbers for Experiment 3.
"""

import json
import os
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CRITERION = REPO / "target" / "criterion"
OUT = REPO / "experiments" / "results" / "exp3.json"


def per_iteration_ns(sample_path: Path):
    """Each criterion sample reports iters[i] iterations totaling times[i] ns.

    The per-iteration time we want is times[i] / iters[i].
    """
    raw = json.loads(sample_path.read_text())
    iters = raw["iters"]
    times = raw["times"]
    if len(iters) != len(times):
        raise ValueError(f"iters/times mismatch in {sample_path}")
    return [t / max(i, 1) for t, i in zip(times, iters)]


def percentile(sorted_values, p):
    if not sorted_values:
        return 0.0
    if p <= 0:
        return sorted_values[0]
    if p >= 100:
        return sorted_values[-1]
    k = (len(sorted_values) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = k - lo
    return sorted_values[lo] * (1 - frac) + sorted_values[hi] * frac


def summarize(bench_dir: Path) -> dict:
    sample = bench_dir / "new" / "sample.json"
    if not sample.exists():
        return {}
    per_iter = per_iteration_ns(sample)
    per_iter.sort()
    return {
        "name": str(bench_dir.relative_to(CRITERION)),
        "samples": len(per_iter),
        "median_ns": statistics.median(per_iter),
        "p95_ns": percentile(per_iter, 95),
        "p99_ns": percentile(per_iter, 99),
        "min_ns": per_iter[0],
        "max_ns": per_iter[-1],
        "mean_ns": statistics.fmean(per_iter),
    }


def main():
    if not CRITERION.exists():
        print(f"no criterion data at {CRITERION}", file=sys.stderr)
        sys.exit(2)

    summaries = []
    for entry in sorted(CRITERION.rglob("new/sample.json")):
        bench_dir = entry.parent.parent
        summary = summarize(bench_dir)
        if summary:
            summaries.append(summary)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"benches": summaries}, indent=2))
    print(f"wrote {OUT}")
    for s in summaries:
        print(
            f"  {s['name']:<40s}  median={s['median_ns']/1000:8.3f}us  p99={s['p99_ns']/1000:8.3f}us  n={s['samples']}"
        )


if __name__ == "__main__":
    main()
