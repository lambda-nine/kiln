# Benchmark summary

Baseline: `kiln-net`. Inputs: `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/gap-sweep/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| kiln-net | podman-net-gap | 0.0 | 10 | 0 | 10.165 | 5.650 | 25.287 | 31.331 | 4.901 | 32.841 |
| kiln-net | podman-net-gap | 10.0 | 10 | 0 | 8.149 | 6.871 | 13.478 | 14.388 | 5.344 | 14.616 |
| kiln-net | podman-net-gap | 100.0 | 10 | 0 | 9.362 | 8.952 | 10.963 | 11.278 | 8.091 | 11.356 |
| kiln-net | podman-net-gap | 1000.0 | 10 | 0 | 24.765 | 25.243 | 32.732 | 34.883 | 10.595 | 35.421 |
| kiln-net | podman-net-gap | 5000.0 | 10 | 0 | 21.649 | 23.380 | 33.545 | 35.324 | 8.288 | 35.769 |
| podman-crun-net | podman-net-gap | 0.0 | 10 | 0 | 179.177 | 176.690 | 197.916 | 200.006 | 162.223 | 200.529 |
| podman-crun-net | podman-net-gap | 10.0 | 10 | 0 | 180.031 | 176.024 | 205.705 | 208.583 | 162.460 | 209.302 |
| podman-crun-net | podman-net-gap | 100.0 | 10 | 0 | 197.200 | 198.185 | 210.609 | 210.906 | 165.111 | 210.980 |
| podman-crun-net | podman-net-gap | 1000.0 | 10 | 0 | 206.869 | 207.942 | 227.538 | 228.602 | 183.518 | 228.868 |
| podman-crun-net | podman-net-gap | 5000.0 | 10 | 0 | 205.566 | 205.931 | 228.592 | 230.832 | 170.874 | 231.392 |

## Ratio to `kiln-net` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| podman-crun-net | 0.0 | 1 | 31.273 | 31.273 | 31.273 | 31.273 | none (fewer than 2 sessions) |
| podman-crun-net | 10.0 | 1 | 25.618 | 25.618 | 25.618 | 25.618 | none (fewer than 2 sessions) |
| podman-crun-net | 100.0 | 1 | 22.139 | 22.139 | 22.139 | 22.139 | none (fewer than 2 sessions) |
| podman-crun-net | 1000.0 | 1 | 8.238 | 8.238 | 8.238 | 8.238 | none (fewer than 2 sessions) |
| podman-crun-net | 5000.0 | 1 | 8.808 | 8.808 | 8.808 | 8.808 | none (fewer than 2 sessions) |
