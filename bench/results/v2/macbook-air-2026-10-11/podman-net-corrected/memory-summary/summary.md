# Benchmark summary

Baseline: `kiln-net`. Inputs: `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/memory/records.jsonl`.

## Memory: OLS slope of used KiB growth vs running sandboxes

Used = MemTotal − MemAvailable; one fit per case and repeat, summarized across repeats.

| case | fits | sessions | mean KiB/sandbox | median | stdev | min | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| kiln-net | 3 | 1 | 1032 | 1101 | 451 | 550 | 1444 |
| podman-crun-net | 3 | 1 | 1410 | 1471 | 468 | 914 | 1844 |
