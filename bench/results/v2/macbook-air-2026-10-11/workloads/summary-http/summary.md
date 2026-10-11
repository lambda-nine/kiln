# Benchmark summary

Baseline: `kiln-http`. Inputs: `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-01-http/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-02-http/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-03-http/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| docker-http | workload-boot-01 | 1000.0 | 15 | 0 | 249.388 | 245.936 | 300.824 | 357.642 | 196.668 | 371.847 |
| docker-http | workload-boot-02 | 1000.0 | 15 | 0 | 239.557 | 243.486 | 260.773 | 263.462 | 200.141 | 264.135 |
| docker-http | workload-boot-03 | 1000.0 | 15 | 0 | 245.382 | 237.497 | 291.452 | 313.999 | 212.558 | 319.636 |
| kiln-http | workload-boot-01 | 1000.0 | 15 | 0 | 105.330 | 112.694 | 133.309 | 154.742 | 70.237 | 160.100 |
| kiln-http | workload-boot-02 | 1000.0 | 15 | 0 | 99.760 | 108.501 | 120.101 | 121.419 | 71.649 | 121.749 |
| kiln-http | workload-boot-03 | 1000.0 | 15 | 0 | 114.662 | 116.376 | 122.570 | 122.832 | 95.980 | 122.897 |
| nerdctl-http | workload-boot-01 | 1000.0 | 15 | 0 | 356.057 | 292.680 | 635.083 | 1156.049 | 243.561 | 1286.291 |
| nerdctl-http | workload-boot-02 | 1000.0 | 15 | 0 | 288.954 | 292.790 | 307.257 | 307.274 | 258.254 | 307.279 |
| nerdctl-http | workload-boot-03 | 1000.0 | 15 | 0 | 282.407 | 290.754 | 305.702 | 316.801 | 246.955 | 319.576 |
| podman-crun-http | workload-boot-01 | 1000.0 | 15 | 0 | 283.460 | 284.221 | 308.274 | 323.718 | 252.926 | 327.579 |
| podman-crun-http | workload-boot-02 | 1000.0 | 15 | 0 | 281.484 | 283.191 | 306.688 | 314.137 | 250.969 | 315.999 |
| podman-crun-http | workload-boot-03 | 1000.0 | 15 | 0 | 276.667 | 277.310 | 302.939 | 305.556 | 236.451 | 306.210 |

## Ratio to `kiln-http` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| docker-http | 1000.0 | 3 | 2.041 | 2.182 | 2.244 | 2.154 | 2.041–2.244 (only 3 sessions; the interval is coarse) |
| nerdctl-http | 1000.0 | 3 | 2.498 | 2.597 | 2.698 | 2.597 | 2.498–2.698 (only 3 sessions; the interval is coarse) |
| podman-crun-http | 1000.0 | 3 | 2.383 | 2.522 | 2.610 | 2.503 | 2.383–2.610 (only 3 sessions; the interval is coarse) |
