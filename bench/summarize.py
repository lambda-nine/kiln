"""Prints a Markdown table (mean, p50, p95, p99 in ms) from hyperfine JSON.

Each row is named after its file, or after the command when a file holds
several (hyperfine run with more than one command).

usage: python3 -I summarize.py results/<label>/*.json
"""
import json
import os
import sys


def percentile(sorted_times, p):
    # Linear interpolation between closest ranks, like numpy's default.
    k = (len(sorted_times) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(sorted_times) - 1)
    return sorted_times[lo] + (sorted_times[hi] - sorted_times[lo]) * (k - lo)


print("| case | runs | mean | p50 | p95 | p99 |")
print("|---|---:|---:|---:|---:|---:|")
for path in sys.argv[1:]:
    with open(path) as f:
        results = json.load(f)["results"]
    for result in results:
        ms = sorted(t * 1000 for t in result["times"])
        name = os.path.basename(path).removesuffix(".json")
        if len(results) > 1:
            name = result["command"]
        stats = [sum(ms) / len(ms)] + [percentile(ms, p) for p in (50, 95, 99)]
        print(f"| {name} | {len(ms)} | " + " | ".join(f"{s:.1f}" for s in stats) + " |")
