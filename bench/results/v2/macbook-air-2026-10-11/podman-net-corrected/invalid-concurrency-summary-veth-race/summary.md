# Benchmark summary

Baseline: `kiln-net`. Inputs: `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/concurrency/records.jsonl`.

## Concurrency

Throughput is successful completions per second of batch wall time; latency is per invocation (ms).

| case | level | batches | invocations | failures | completions/s p50 | completions/s mean | inv p50 | inv p95 | inv p99 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| kiln-net | 1 | 3 | 3 | 0 | 113.8 | 105.8 | 8.787 | 27.124 | 28.753 |
| kiln-net | 4 | 3 | 12 | 0 | 120.8 | 113.9 | 21.397 | 47.958 | 50.064 |
| kiln-net | 16 | 3 | 48 | 1 | 125.4 | 118.2 | 107.415 | 141.488 | 144.842 |
| kiln-net | 32 | 3 | 96 | 0 | 114.9 | 123.7 | 134.575 | 300.453 | 314.269 |
| kiln-net | 64 | 3 | 192 | 0 | 117.2 | 112.1 | 293.479 | 509.178 | 550.777 |
| podman-crun-net | 1 | 3 | 3 | 0 | 5.5 | 5.3 | 180.842 | 203.372 | 205.375 |
| podman-crun-net | 4 | 3 | 12 | 0 | 13.3 | 13.7 | 227.521 | 300.479 | 300.534 |
| podman-crun-net | 16 | 3 | 48 | 0 | 12.6 | 11.8 | 904.265 | 1359.550 | 1489.918 |
| podman-crun-net | 32 | 3 | 96 | 0 | 12.7 | 12.5 | 1866.599 | 2507.411 | 2712.017 |
| podman-crun-net | 64 | 3 | 192 | 0 | 9.7 | 10.0 | 4979.165 | 6342.763 | 6571.442 |
