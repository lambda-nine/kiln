# Benchmark summary

Baseline: `kiln-dns`. Inputs: `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-01-dns/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-02-dns/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/workloads/workload-boot-03-dns/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| docker-dns | workload-boot-01 | 1000.0 | 15 | 0 | 182.505 | 188.522 | 207.805 | 208.732 | 149.861 | 208.964 |
| docker-dns | workload-boot-02 | 1000.0 | 15 | 0 | 177.146 | 172.958 | 196.204 | 203.472 | 164.234 | 205.288 |
| docker-dns | workload-boot-03 | 1000.0 | 15 | 0 | 195.077 | 191.984 | 218.519 | 226.127 | 158.324 | 228.029 |
| kiln-dns | workload-boot-01 | 1000.0 | 15 | 0 | 53.809 | 57.684 | 60.748 | 61.503 | 38.144 | 61.692 |
| kiln-dns | workload-boot-02 | 1000.0 | 15 | 0 | 26.254 | 25.197 | 32.298 | 34.318 | 22.720 | 34.823 |
| kiln-dns | workload-boot-03 | 1000.0 | 15 | 0 | 56.761 | 59.748 | 62.380 | 62.395 | 24.999 | 62.399 |
| nerdctl-dns | workload-boot-01 | 1000.0 | 15 | 0 | 247.281 | 246.616 | 257.335 | 260.067 | 230.686 | 260.749 |
| nerdctl-dns | workload-boot-02 | 1000.0 | 15 | 0 | 230.517 | 225.847 | 260.103 | 265.164 | 215.842 | 266.430 |
| nerdctl-dns | workload-boot-03 | 1000.0 | 15 | 0 | 243.177 | 245.686 | 280.486 | 280.801 | 195.754 | 280.880 |
| podman-crun-dns | workload-boot-01 | 1000.0 | 15 | 0 | 235.927 | 237.059 | 256.013 | 257.153 | 210.138 | 257.439 |
| podman-crun-dns | workload-boot-02 | 1000.0 | 15 | 0 | 211.473 | 212.956 | 232.968 | 251.270 | 193.040 | 255.845 |
| podman-crun-dns | workload-boot-03 | 1000.0 | 15 | 0 | 218.599 | 216.689 | 234.765 | 237.093 | 196.254 | 237.675 |

## Ratio to `kiln-dns` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| docker-dns | 1000.0 | 3 | 3.213 | 3.268 | 6.864 | 4.162 | 3.213–6.864 (only 3 sessions; the interval is coarse) |
| nerdctl-dns | 1000.0 | 3 | 4.112 | 4.275 | 8.963 | 5.401 | 4.112–8.963 (only 3 sessions; the interval is coarse) |
| podman-crun-dns | 1000.0 | 3 | 3.627 | 4.110 | 8.452 | 5.013 | 3.627–8.452 (only 3 sessions; the interval is coarse) |
