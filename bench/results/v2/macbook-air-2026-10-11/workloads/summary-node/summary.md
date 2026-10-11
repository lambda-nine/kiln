# Benchmark summary

Baseline: `kiln-node`. Inputs: `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-01-node/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-02-node/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-03-node/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| docker-node | workload-boot-01 | 100.0 | 40 | 0 | 127.543 | 120.314 | 175.010 | 230.880 | 99.832 | 260.523 |
| docker-node | workload-boot-02 | 100.0 | 40 | 0 | 140.522 | 120.892 | 219.450 | 297.285 | 97.735 | 316.645 |
| docker-node | workload-boot-03 | 100.0 | 40 | 0 | 125.473 | 116.473 | 183.345 | 253.192 | 96.297 | 284.710 |
| kiln-node | workload-boot-01 | 100.0 | 40 | 0 | 32.327 | 32.775 | 36.498 | 38.956 | 23.112 | 39.486 |
| kiln-node | workload-boot-02 | 100.0 | 40 | 0 | 29.412 | 28.133 | 35.872 | 39.545 | 24.016 | 40.554 |
| kiln-node | workload-boot-03 | 100.0 | 40 | 0 | 32.842 | 33.231 | 36.754 | 45.280 | 25.285 | 50.577 |
| nerdctl-node | workload-boot-01 | 100.0 | 40 | 0 | 137.458 | 134.008 | 167.389 | 198.348 | 121.858 | 198.433 |
| nerdctl-node | workload-boot-02 | 100.0 | 40 | 0 | 142.535 | 134.953 | 179.320 | 233.876 | 122.839 | 236.235 |
| nerdctl-node | workload-boot-03 | 100.0 | 40 | 0 | 139.212 | 133.101 | 151.703 | 245.277 | 124.361 | 273.630 |
| podman-crun-node | workload-boot-01 | 100.0 | 40 | 0 | 98.619 | 95.108 | 122.087 | 143.057 | 81.550 | 154.429 |
| podman-crun-node | workload-boot-02 | 100.0 | 40 | 0 | 94.342 | 91.851 | 114.073 | 121.536 | 79.468 | 123.611 |
| podman-crun-node | workload-boot-03 | 100.0 | 40 | 0 | 97.984 | 96.503 | 110.134 | 140.960 | 83.815 | 157.892 |

## Ratio to `kiln-node` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| docker-node | 100.0 | 3 | 3.505 | 3.671 | 4.297 | 3.810 | 3.505–4.297 (only 3 sessions; the interval is coarse) |
| nerdctl-node | 100.0 | 3 | 4.005 | 4.089 | 4.797 | 4.283 | 4.005–4.797 (only 3 sessions; the interval is coarse) |
| podman-crun-node | 100.0 | 3 | 2.902 | 2.904 | 3.265 | 3.019 | 2.902–3.265 (only 3 sessions; the interval is coarse) |
