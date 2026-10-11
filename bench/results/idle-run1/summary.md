### One idle sandbox (KiB)

| runtime | processes | RSS | PSS | USS | cgroup memory.current |
|---|---|---:|---:|---:|---:|
| kiln | shim pid1 | 3504 | 758 | 136 | 280 |
| kiln-net | shim pid1 | 3700 | 769 | 144 | 96 |
| docker | shim pid1 | 11236 | 11228 | 11228 | 1644 |
| docker-net | shim pid1 | 11512 | 11504 | 11504 | 328 |
| runc | pid1 | 772 | 768 | 768 | 464 |
| crun | pid1 | 788 | 784 | 784 | 176 |

### 50 idle sandboxes: growth of MemTotal - MemAvailable (KiB)

| runtime | total | per sandbox |
|---|---:|---:|
| kiln | 18520 | 370 |
| docker | 266444 | 5328 |
| runc | 29924 | 598 |
| crun | 20596 | 411 |

### Daemons (KiB)

| process | needed for | RSS | PSS |
|---|---|---:|---:|
| dockerd | every Docker container | 106460 | 104077 |
| containerd | every Docker container | 61096 | 59823 |
| kiln-dns | DNS for networked sandboxes | 3036 | 1109 |
| kiln-metrics | Prometheus metrics (optional) | 3952 | 2025 |
