# Benchmark summary

Baseline: `kiln-shell`. Inputs: `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-01-shell/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-02-shell/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-03-shell/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| docker-shell | workload-boot-01 | 100.0 | 40 | 0 | 117.135 | 100.280 | 211.002 | 233.104 | 79.002 | 239.030 |
| docker-shell | workload-boot-02 | 100.0 | 40 | 0 | 114.200 | 101.775 | 201.803 | 232.579 | 72.998 | 251.724 |
| docker-shell | workload-boot-03 | 100.0 | 40 | 0 | 112.058 | 100.561 | 198.130 | 251.705 | 77.966 | 255.361 |
| kiln-shell | workload-boot-01 | 100.0 | 40 | 0 | 4.676 | 4.547 | 5.867 | 8.528 | 3.270 | 10.015 |
| kiln-shell | workload-boot-02 | 100.0 | 40 | 0 | 5.406 | 4.880 | 10.045 | 11.289 | 3.233 | 11.584 |
| kiln-shell | workload-boot-03 | 100.0 | 40 | 0 | 4.990 | 4.745 | 8.948 | 10.660 | 3.071 | 10.711 |
| nerdctl-shell | workload-boot-01 | 100.0 | 40 | 0 | 132.328 | 115.012 | 148.356 | 411.158 | 101.244 | 514.052 |
| nerdctl-shell | workload-boot-02 | 100.0 | 40 | 0 | 120.675 | 114.481 | 158.429 | 180.427 | 102.779 | 180.811 |
| nerdctl-shell | workload-boot-03 | 100.0 | 40 | 0 | 121.228 | 112.778 | 162.575 | 201.395 | 99.898 | 207.738 |
| podman-crun-shell | workload-boot-01 | 100.0 | 40 | 0 | 81.728 | 78.959 | 109.173 | 112.126 | 62.715 | 113.825 |
| podman-crun-shell | workload-boot-02 | 100.0 | 40 | 0 | 77.585 | 73.573 | 104.161 | 111.165 | 62.887 | 114.276 |
| podman-crun-shell | workload-boot-03 | 100.0 | 40 | 0 | 79.073 | 72.267 | 106.802 | 109.671 | 63.157 | 111.297 |

## Ratio to `kiln-shell` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| docker-shell | 100.0 | 3 | 20.853 | 21.194 | 22.053 | 21.361 | 20.853–22.053 (only 3 sessions; the interval is coarse) |
| nerdctl-shell | 100.0 | 3 | 23.457 | 23.769 | 25.292 | 24.160 | 23.457–25.292 (only 3 sessions; the interval is coarse) |
| podman-crun-shell | 100.0 | 3 | 15.075 | 15.231 | 17.364 | 15.857 | 15.075–17.364 (only 3 sessions; the interval is coarse) |
