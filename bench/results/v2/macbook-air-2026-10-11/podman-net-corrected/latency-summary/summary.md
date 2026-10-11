# Benchmark summary

Baseline: `kiln-net`. Inputs: `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/podman-net-boot-01-latency/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/podman-net-boot-02-latency/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/podman-net-boot-03-latency/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/podman-net-boot-04-latency/records.jsonl`, `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/podman-net-boot-05-latency/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| kiln-net | podman-net-boot-01 | 100.0 | 100 | 0 | 10.217 | 9.486 | 15.543 | 20.384 | 5.403 | 23.117 |
| kiln-net | podman-net-boot-02 | 100.0 | 100 | 0 | 9.712 | 8.948 | 14.483 | 16.517 | 5.696 | 25.848 |
| kiln-net | podman-net-boot-03 | 100.0 | 100 | 0 | 11.247 | 9.500 | 16.411 | 43.825 | 5.868 | 100.055 |
| kiln-net | podman-net-boot-04 | 100.0 | 100 | 0 | 10.312 | 9.238 | 16.181 | 18.583 | 5.902 | 21.529 |
| kiln-net | podman-net-boot-05 | 100.0 | 100 | 0 | 9.943 | 9.173 | 14.224 | 16.804 | 5.290 | 16.887 |
| podman-crun-net | podman-net-boot-01 | 100.0 | 100 | 0 | 190.145 | 187.865 | 219.184 | 226.734 | 156.996 | 234.569 |
| podman-crun-net | podman-net-boot-02 | 100.0 | 100 | 0 | 189.080 | 186.804 | 218.603 | 224.656 | 141.222 | 227.329 |
| podman-crun-net | podman-net-boot-03 | 100.0 | 100 | 0 | 210.214 | 192.140 | 243.195 | 751.346 | 140.071 | 798.433 |
| podman-crun-net | podman-net-boot-04 | 100.0 | 100 | 0 | 193.923 | 191.633 | 230.288 | 250.704 | 166.715 | 253.569 |
| podman-crun-net | podman-net-boot-05 | 100.0 | 100 | 0 | 190.173 | 188.888 | 219.705 | 227.920 | 143.801 | 229.246 |

## Ratio to `kiln-net` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| podman-crun-net | 100.0 | 5 | 19.805 | 20.593 | 20.876 | 20.445 | 20.073–20.766 |
