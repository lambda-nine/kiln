# Benchmark summary

Baseline: `kiln-python`. Inputs: `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-01-python/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-02-python/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-03-python/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| docker-python | workload-boot-01 | 100.0 | 40 | 0 | 128.512 | 113.467 | 208.822 | 233.508 | 96.100 | 243.741 |
| docker-python | workload-boot-02 | 100.0 | 40 | 0 | 112.325 | 109.126 | 143.149 | 152.845 | 95.115 | 155.901 |
| docker-python | workload-boot-03 | 100.0 | 40 | 0 | 116.724 | 109.071 | 166.869 | 186.395 | 89.215 | 188.397 |
| kiln-python | workload-boot-01 | 100.0 | 40 | 0 | 23.115 | 23.471 | 29.143 | 32.270 | 16.911 | 32.772 |
| kiln-python | workload-boot-02 | 100.0 | 40 | 0 | 23.273 | 23.463 | 25.366 | 30.436 | 17.805 | 33.585 |
| kiln-python | workload-boot-03 | 100.0 | 40 | 0 | 23.630 | 24.144 | 26.657 | 32.123 | 17.397 | 32.712 |
| nerdctl-python | workload-boot-01 | 100.0 | 40 | 0 | 137.138 | 127.228 | 215.426 | 253.648 | 114.215 | 256.401 |
| nerdctl-python | workload-boot-02 | 100.0 | 40 | 0 | 136.577 | 128.911 | 166.260 | 253.603 | 120.229 | 307.927 |
| nerdctl-python | workload-boot-03 | 100.0 | 40 | 0 | 130.225 | 126.520 | 151.777 | 174.199 | 118.064 | 187.404 |
| podman-crun-python | workload-boot-01 | 100.0 | 40 | 0 | 89.454 | 86.058 | 108.743 | 111.396 | 69.719 | 111.928 |
| podman-crun-python | workload-boot-02 | 100.0 | 40 | 0 | 90.515 | 87.211 | 114.848 | 124.122 | 70.541 | 126.049 |
| podman-crun-python | workload-boot-03 | 100.0 | 40 | 0 | 90.336 | 86.697 | 109.503 | 112.471 | 74.856 | 114.316 |

## Ratio to `kiln-python` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| docker-python | 100.0 | 3 | 4.518 | 4.651 | 4.834 | 4.666 | 4.518–4.834 (only 3 sessions; the interval is coarse) |
| nerdctl-python | 100.0 | 3 | 5.240 | 5.421 | 5.494 | 5.384 | 5.240–5.494 (only 3 sessions; the interval is coarse) |
| podman-crun-python | 100.0 | 3 | 3.591 | 3.667 | 3.717 | 3.658 | 3.591–3.717 (only 3 sessions; the interval is coarse) |
