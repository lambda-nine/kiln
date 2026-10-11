"""Turns bench/results into data/ for the white paper: values.tex (one macro
per number the text quotes, read with \\V{name}) and .dat tables for charts.
Every number in kiln-whitepaper.tex comes from here, so a rerun of the
benchmarks updates the paper.

usage (from docs/whitepaper): python3 -I gen-data.py ../../bench/results data
"""
import json
import os
import re
import statistics
import sys

results, out = sys.argv[1:3]
os.makedirs(out, exist_ok=True)
values = {}


def percentile(sorted_ms, p):
    # Same as bench/summarize.py: linear interpolation between closest ranks.
    k = (len(sorted_ms) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(sorted_ms) - 1)
    return sorted_ms[lo] + (sorted_ms[hi] - sorted_ms[lo]) * (k - lo)


def runs(path):
    with open(path) as f:
        raw = json.load(f)["results"]
    return [sorted(t * 1000 for t in r["times"]) for r in raw], raw


def record(prefix, ms):
    values[prefix + "/n"] = str(len(ms))
    values[prefix + "/mean"] = f"{sum(ms) / len(ms):.1f}"
    for p in (50, 95, 99):
        values[f"{prefix}/p{p}"] = f"{percentile(ms, p):.1f}"
    values[prefix + "/min"] = f"{ms[0]:.1f}"
    values[prefix + "/max"] = f"{ms[-1]:.1f}"


def one_file_sets(label):
    d = os.path.join(results, label)
    for name in sorted(os.listdir(d)):
        if name.endswith(".json"):
            (ms,), _ = runs(os.path.join(d, name))
            record(f"{label}/{name[:-5]}", ms)
            yield name[:-5], ms


cold = dict(one_file_sets("final"))
list(one_file_sets("final-session-baseline"))
list(one_file_sets("final-b2b"))
list(one_file_sets("baseline-b2b"))
list(one_file_sets("baseline"))
warm = dict(one_file_sets("warm"))

# Bar charts: p50 with p95 as the whisker, bottom row first.
def bars(name, rows):
    with open(os.path.join(out, name), "w") as f:
        f.write("y p50 p95 err\n")
        for i, (label, key) in enumerate(rows):
            p50, p95 = float(values[key + "/p50"]), float(values[key + "/p95"])
            f.write(f"{i} {p50:.1f} {p95:.1f} {p95 - p50:.1f}\n")


bars("cold-none.dat", [("Docker", "final/docker-none"), ("runc", "final/runc-none"),
                       ("crun", "final/crun-none"), ("kiln", "final/kiln-none")])
bars("cold-net.dat", [("Docker", "final/docker-net"), ("kiln", "final/kiln-net")])
bars("warm.dat", [("Docker", "warm/exec-docker"), ("runc", "warm/exec-runc"),
                  ("crun", "warm/exec-crun"), ("kiln", "warm/exec-kiln")])

# Distribution of each cold case: (ms, fraction of runs at or below).
for case, ms in cold.items():
    with open(os.path.join(out, f"cdf-{case}.dat"), "w") as f:
        f.write("ms frac\n")
        for i, t in enumerate(ms, 1):
            f.write(f"{t:.3f} {i / len(ms):.3f}\n")
    values[f"final/{case}/under6"] = str(sum(1 for t in ms if t < 6))

# Each build of the cold-start work, p50 per network mode.
for mode in ("net-none", "net-full"):
    all_ms, raw = runs(os.path.join(results, "steps", mode + ".json"))
    with open(os.path.join(out, f"steps-{mode}.dat"), "w") as f:
        f.write("step p50 p95\n")
        for i, (ms, r) in enumerate(zip(all_ms, raw)):
            build = re.search(r"kiln-(\d+)-", r["command"]).group(1)
            f.write(f"{i} {percentile(ms, 50):.2f} {percentile(ms, 95):.2f}\n")
            values[f"steps/{mode}/{build}/p50"] = f"{percentile(ms, 50):.1f}"

# rcu_expedited experiment: label each command.
for setting in ("0", "1"):
    all_ms, raw = runs(os.path.join(results, "rcu-expedited", f"expedited-{setting}.json"))
    for ms, r in zip(all_ms, raw):
        cmd = r["command"]
        prog = os.path.basename(cmd.split()[0])
        who = ("kiln-before" if "baseline" in cmd else "kiln-now" if prog == "kiln"
               else prog)
        net = "net" if "--net full" in cmd else "none"
        assert f"rcu/{setting}/{who}-{net}/p50" not in values, cmd
        values[f"rcu/{setting}/{who}-{net}/p50"] = f"{percentile(ms, 50):.1f}"

# Idle overhead: the tables in idle-run1 and idle-run2 summary.md.
for run in ("idle-run1", "idle-run2"):
    section = None
    for line in open(os.path.join(results, run, "summary.md")):
        if line.startswith("###"):
            section = "one" if "One idle" in line else "fifty" if "50 idle" in line else "daemons"
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or not cells[-1].replace(".", "").isdigit():
            continue
        if section == "one":
            rt, _, rss, pss, uss, cg = cells
            for k, v in (("rss", rss), ("pss", pss), ("uss", uss), ("cg", cg)):
                values[f"{run}/one/{rt}/{k}"] = v
        elif section == "fifty":
            rt, total, per = cells
            values[f"{run}/fifty/{rt}/per"] = per
        elif section == "daemons":
            name, _, rss, pss = cells
            values[f"{run}/daemon/{name}/rss"] = rss
            values[f"{run}/daemon/{name}/pss"] = pss
for run in ("idle-run1", "idle-run2"):
    pss = int(values[f"{run}/daemon/dockerd/pss"]) + int(values[f"{run}/daemon/containerd/pss"])
    values[f"{run}/docker-daemons-pss-mib"] = f"{pss / 1024:.1f}"
with open(os.path.join(out, "idle.dat"), "w") as f:
    f.write("rt run1 run2\n")
    for rt in ("kiln", "crun", "runc", "docker"):
        f.write(f"{rt} {values['idle-run1/fifty/' + rt + '/per']} {values['idle-run2/fifty/' + rt + '/per']}\n")

# Steady state: seconds per run, timed inside the sandbox.
steady = {}
for line in open(os.path.join(results, "steady", "times.txt")):
    workload, rt, secs = line.split()
    steady.setdefault((workload, rt), []).append(float(secs))
for (workload, rt), secs in steady.items():
    values[f"steady/{workload}/{rt}/n"] = str(len(secs))
    values[f"steady/{workload}/{rt}/median"] = f"{statistics.median(secs):.2f}"
    values[f"steady/{workload}/{rt}/min"] = f"{min(secs):.2f}"
    values[f"steady/{workload}/{rt}/max"] = f"{max(secs):.2f}"

# Ratios the text quotes.
def ratio(a, b):
    return f"{float(values[a]) / float(values[b]):.1f}"


values["ratio/docker-none-over-kiln"] = ratio("final/docker-none/p50", "final/kiln-none/p50")
values["ratio/docker-net-over-kiln"] = ratio("final/docker-net/p50", "final/kiln-net/p50")
values["ratio/runc-none-over-kiln"] = ratio("final/runc-none/p50", "final/kiln-none/p50")
values["ratio/warm-docker-over-kiln"] = ratio("warm/exec-docker/p50", "warm/exec-kiln/p50")
values["ratio/warm-crun-over-kiln"] = ratio("warm/exec-crun/p50", "warm/exec-kiln/p50")
values["ratio/warm-runc-over-kiln"] = ratio("warm/exec-runc/p50", "warm/exec-kiln/p50")
values["ratio/idle-docker-over-kiln"] = ratio("idle-run1/fifty/docker/per", "idle-run1/fifty/kiln/per")

with open(os.path.join(out, "values.tex"), "w") as f:
    f.write("% Generated by gen-data.py from bench/results. Do not edit.\n")
    for k in sorted(values):
        f.write(f"\\expandafter\\def\\csname v@{k}\\endcsname{{{values[k]}}}\n")
print(f"{len(values)} values, data in {out}/")
