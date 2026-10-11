# Benchmark summary

Baseline: `kiln-none`. Inputs: `bench/results/v2/macbook-air-2026-10-11/memory/records.jsonl`.

## Memory: OLS slope of used KiB growth vs running sandboxes

Used = MemTotal − MemAvailable; one fit per case and repeat, summarized across repeats.

| case | fits | sessions | mean KiB/sandbox | median | stdev | min | max |
|---|---:|---:|---:|---:|---:|---:|---:|
| crun-none | 3 | 1 | 455 | 472 | 42 | 407 | 486 |
| docker-net | 3 | 1 | 5205 | 5424 | 685 | 4438 | 5753 |
| docker-none | 3 | 1 | 4986 | 5007 | 342 | 4634 | 5316 |
| kiln-net | 3 | 1 | 712 | 669 | 222 | 516 | 952 |
| kiln-none | 3 | 1 | 755 | 749 | 79 | 680 | 837 |
| nerdctl-net | 3 | 1 | 12859 | 12712 | 411 | 12542 | 13323 |
| nerdctl-none | 3 | 1 | 13194 | 13172 | 121 | 13086 | 13325 |
| podman-crun-net | 3 | 1 | 1299 | 1104 | 535 | 890 | 1904 |
| podman-crun-none | 3 | 1 | 1216 | 1203 | 160 | 1063 | 1383 |
| podman-runc-none | 3 | 1 | 1323 | 1327 | 17 | 1304 | 1337 |
| runc-none | 3 | 1 | 466 | 434 | 73 | 414 | 549 |
| runsc-none | 3 | 1 | 14020 | 13986 | 207 | 13833 | 14242 |
| youki-none | 3 | 1 | 830 | 663 | 466 | 470 | 1357 |
