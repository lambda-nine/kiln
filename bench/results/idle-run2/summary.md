### One idle sandbox (KiB)

| runtime | processes | RSS | PSS | USS | cgroup memory.current |
|---|---|---:|---:|---:|---:|
| kiln | shim pid1 | 3496 | 754 | 136 | 284 |
| kiln-net | shim pid1 | 3700 | 769 | 144 | 100 |
| docker | shim pid1 | 11340 | 11332 | 11332 | 1640 |
| docker-net | shim pid1 | 11488 | 11480 | 11480 | 320 |
| runc | pid1 | 788 | 784 | 784 | 468 |
| crun | pid1 | 796 | 792 | 792 | 172 |

### 50 idle sandboxes: growth of MemTotal - MemAvailable (KiB)

| runtime | total | per sandbox |
|---|---:|---:|
| kiln | 18984 | 379 |
| docker | 280004 | 5600 |
| runc | 38008 | 760 |
| crun | 11968 | 239 |

### Daemons (KiB)

| process | needed for | RSS | PSS |
|---|---|---:|---:|
| dockerd | every Docker container | 106512 | 104129 |
| containerd | every Docker container | 62620 | 61347 |
| kiln-dns | DNS for networked sandboxes | 3036 | 1109 |
| kiln-metrics | Prometheus metrics (optional) | 3996 | 2069 |
