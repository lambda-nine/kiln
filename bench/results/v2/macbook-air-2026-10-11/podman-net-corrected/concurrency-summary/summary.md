# Benchmark summary

Baseline: `kiln-net`. Inputs: `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/concurrency/records.jsonl`.

## Concurrency

Throughput is successful completions per second of batch wall time; latency is per invocation (ms).

| case | level | batches | invocations | failures | completions/s p50 | completions/s mean | start spread p50 ms | start spread max ms | inv p50 | inv p95 | inv p99 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| kiln-net | 1 | 3 | 3 | 0 | 46.6 | 52.0 | 0.000 | 0.000 | 21.462 | 24.001 | 24.227 |
| kiln-net | 4 | 3 | 12 | 0 | 75.7 | 86.7 | 0.597 | 0.662 | 32.897 | 53.328 | 53.907 |
| kiln-net | 16 | 3 | 48 | 0 | 93.1 | 109.8 | 3.319 | 4.493 | 78.598 | 167.464 | 173.488 |
| kiln-net | 32 | 3 | 96 | 0 | 106.4 | 108.9 | 8.477 | 10.223 | 128.646 | 303.423 | 336.543 |
| kiln-net | 64 | 3 | 192 | 0 | 97.5 | 114.4 | 13.665 | 19.924 | 228.844 | 497.432 | 650.313 |
| podman-crun-net | 1 | 3 | 3 | 0 | 5.7 | 5.4 | 0.000 | 0.000 | 176.012 | 209.945 | 212.961 |
| podman-crun-net | 4 | 3 | 12 | 0 | 13.0 | 13.6 | 0.360 | 0.886 | 230.174 | 311.735 | 316.252 |
| podman-crun-net | 16 | 3 | 48 | 0 | 10.4 | 10.9 | 5.408 | 8.166 | 1036.505 | 1563.013 | 1612.531 |
| podman-crun-net | 32 | 3 | 96 | 0 | 11.4 | 11.3 | 26.970 | 29.096 | 2117.228 | 2863.815 | 3100.671 |
| podman-crun-net | 64 | 3 | 192 | 0 | 10.7 | 10.6 | 36.822 | 95.787 | 4775.589 | 5811.869 | 6054.851 |
