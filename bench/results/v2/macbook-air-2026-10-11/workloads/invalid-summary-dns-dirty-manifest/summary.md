# Benchmark summary

Baseline: `kiln-dns`. Inputs: `bench/results/v2/macbook-air-2026-10-11/workloads/invalid-workload-boot-01-dns-dirty-manifest/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-02-dns/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-03-dns/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| docker-dns | workload-boot-01 | 1000.0 | 15 | 0 | 189.574 | 186.738 | 223.630 | 226.787 | 163.236 | 227.576 |
| docker-dns | workload-boot-02 | 1000.0 | 15 | 0 | 177.146 | 172.958 | 196.204 | 203.472 | 164.234 | 205.288 |
| docker-dns | workload-boot-03 | 1000.0 | 15 | 0 | 195.077 | 191.984 | 218.519 | 226.127 | 158.324 | 228.029 |
| kiln-dns | workload-boot-01 | 1000.0 | 15 | 0 | 46.413 | 47.376 | 60.256 | 61.550 | 26.169 | 61.874 |
| kiln-dns | workload-boot-02 | 1000.0 | 15 | 0 | 26.254 | 25.197 | 32.298 | 34.318 | 22.720 | 34.823 |
| kiln-dns | workload-boot-03 | 1000.0 | 15 | 0 | 56.761 | 59.748 | 62.380 | 62.395 | 24.999 | 62.399 |
| nerdctl-dns | workload-boot-01 | 1000.0 | 15 | 0 | 246.634 | 247.580 | 260.915 | 262.194 | 224.769 | 262.514 |
| nerdctl-dns | workload-boot-02 | 1000.0 | 15 | 0 | 230.517 | 225.847 | 260.103 | 265.164 | 215.842 | 266.430 |
| nerdctl-dns | workload-boot-03 | 1000.0 | 15 | 0 | 243.177 | 245.686 | 280.486 | 280.801 | 195.754 | 280.880 |
| podman-crun-dns | workload-boot-01 | 1000.0 | 15 | 0 | 238.436 | 241.099 | 252.436 | 255.418 | 196.099 | 256.163 |
| podman-crun-dns | workload-boot-02 | 1000.0 | 15 | 0 | 211.473 | 212.956 | 232.968 | 251.270 | 193.040 | 255.845 |
| podman-crun-dns | workload-boot-03 | 1000.0 | 15 | 0 | 218.599 | 216.689 | 234.765 | 237.093 | 196.254 | 237.675 |

## Ratio to `kiln-dns` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| docker-dns | 1000.0 | 3 | 3.213 | 3.942 | 6.864 | 4.430 | 3.213–6.864 (only 3 sessions; the interval is coarse) |
| nerdctl-dns | 1000.0 | 3 | 4.112 | 5.226 | 8.963 | 5.775 | 4.112–8.963 (only 3 sessions; the interval is coarse) |
| podman-crun-dns | 1000.0 | 3 | 3.627 | 5.089 | 8.452 | 5.383 | 3.627–8.452 (only 3 sessions; the interval is coarse) |
