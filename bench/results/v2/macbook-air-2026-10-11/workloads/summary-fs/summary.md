# Benchmark summary

Baseline: `kiln-fs`. Inputs: `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-01-fs/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-02-fs/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-03-fs/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| docker-fs | workload-boot-01 | 100.0 | 40 | 0 | 128.425 | 120.511 | 172.540 | 178.322 | 108.059 | 178.384 |
| docker-fs | workload-boot-02 | 100.0 | 40 | 0 | 136.701 | 124.095 | 217.945 | 251.788 | 107.753 | 271.070 |
| docker-fs | workload-boot-03 | 100.0 | 40 | 0 | 136.874 | 122.632 | 204.934 | 208.655 | 105.918 | 210.479 |
| kiln-fs | workload-boot-01 | 100.0 | 40 | 0 | 36.896 | 37.234 | 39.146 | 39.685 | 28.979 | 39.742 |
| kiln-fs | workload-boot-02 | 100.0 | 40 | 0 | 35.204 | 35.504 | 41.439 | 42.669 | 29.219 | 42.970 |
| kiln-fs | workload-boot-03 | 100.0 | 40 | 0 | 38.533 | 39.080 | 43.741 | 44.916 | 29.053 | 45.292 |
| nerdctl-fs | workload-boot-01 | 100.0 | 40 | 0 | 144.192 | 140.707 | 152.842 | 216.671 | 132.741 | 234.213 |
| nerdctl-fs | workload-boot-02 | 100.0 | 40 | 0 | 157.530 | 145.369 | 195.778 | 315.117 | 135.081 | 335.773 |
| nerdctl-fs | workload-boot-03 | 100.0 | 40 | 0 | 144.004 | 140.386 | 179.334 | 198.783 | 129.310 | 200.251 |
| podman-crun-fs | workload-boot-01 | 100.0 | 40 | 0 | 99.871 | 100.838 | 114.100 | 116.958 | 85.248 | 117.463 |
| podman-crun-fs | workload-boot-02 | 100.0 | 40 | 0 | 101.137 | 98.201 | 120.125 | 149.854 | 88.139 | 168.445 |
| podman-crun-fs | workload-boot-03 | 100.0 | 40 | 0 | 97.808 | 96.147 | 123.468 | 128.047 | 86.174 | 128.316 |

## Ratio to `kiln-fs` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| docker-fs | 100.0 | 3 | 3.138 | 3.237 | 3.495 | 3.286 | 3.138–3.495 (only 3 sessions; the interval is coarse) |
| nerdctl-fs | 100.0 | 3 | 3.592 | 3.779 | 4.094 | 3.816 | 3.592–4.094 (only 3 sessions; the interval is coarse) |
| podman-crun-fs | 100.0 | 3 | 2.460 | 2.708 | 2.766 | 2.641 | 2.460–2.766 (only 3 sessions; the interval is coarse) |
