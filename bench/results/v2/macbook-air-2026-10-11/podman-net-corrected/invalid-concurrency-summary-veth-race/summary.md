# Benchmark summary

Baseline: `kiln-net`. Inputs: `bench/results/v2/macbook-air-2026-10-11/podman-net-corrected/invalid-concurrency-veth-race/records.jsonl`.

## Concurrency

Throughput is successful completions per second of batch wall time; latency is per invocation (ms).

| case | level | batches | invocations | failures | completions/s p50 | completions/s mean | start spread p50 ms | start spread max ms | inv p50 | inv p95 | inv p99 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| kiln-net | 1 | 3 | 3 | 0 | 113.8 | 105.8 | 0.000 | 0.000 | 8.787 | 27.124 | 28.753 |
| kiln-net | 4 | 3 | 12 | 0 | 120.8 | 113.9 | 0.229 | 0.414 | 21.397 | 47.958 | 50.064 |
| kiln-net | 16 | 3 | 48 | 1 | 125.4 | 118.2 | 2.150 | 4.131 | 107.415 | 141.488 | 144.842 |
| kiln-net | 32 | 3 | 96 | 0 | 114.9 | 123.7 | 8.252 | 12.132 | 134.575 | 300.453 | 314.269 |
| kiln-net | 64 | 3 | 192 | 0 | 117.2 | 112.1 | 9.244 | 13.271 | 293.479 | 509.178 | 550.777 |
| podman-crun-net | 1 | 3 | 3 | 0 | 5.5 | 5.3 | 0.000 | 0.000 | 180.842 | 203.372 | 205.375 |
| podman-crun-net | 4 | 3 | 12 | 0 | 13.3 | 13.7 | 0.396 | 1.244 | 227.521 | 300.479 | 300.534 |
| podman-crun-net | 16 | 3 | 48 | 0 | 12.6 | 11.8 | 8.158 | 10.263 | 904.265 | 1359.550 | 1489.918 |
| podman-crun-net | 32 | 3 | 96 | 0 | 12.7 | 12.5 | 18.463 | 24.442 | 1866.599 | 2507.411 | 2712.017 |
| podman-crun-net | 64 | 3 | 192 | 0 | 9.7 | 10.0 | 32.013 | 107.943 | 4979.165 | 6342.763 | 6571.442 |
