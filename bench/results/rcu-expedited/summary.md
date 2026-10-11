| case | runs | mean | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| expedited-0: /home/stephenestrada.guest/kiln-bins/kiln-0-baseline run -- true | 50 | 29.4 | 29.0 | 37.9 | 39.2 |
| expedited-0: /usr/local/bin/kiln run -- true | 50 | 12.2 | 13.2 | 15.6 | 18.5 |
| expedited-0: /home/stephenestrada.guest/kiln-bins/kiln-0-baseline run --net full -- true | 50 | 89.1 | 89.0 | 105.0 | 115.5 |
| expedited-0: /usr/local/bin/kiln run --net full -- true | 50 | 20.2 | 22.4 | 27.0 | 28.9 |
| expedited-0: crun run --bundle /var/lib/kiln-bench/bundle kiln-bench | 50 | 13.0 | 13.2 | 15.9 | 17.3 |
| expedited-0: runc run --bundle /var/lib/kiln-bench/bundle kiln-bench | 50 | 32.4 | 33.6 | 39.8 | 43.1 |
| expedited-1: /home/stephenestrada.guest/kiln-bins/kiln-0-baseline run -- true | 50 | 16.4 | 17.0 | 19.9 | 21.8 |
| expedited-1: /usr/local/bin/kiln run -- true | 50 | 11.7 | 13.3 | 15.9 | 17.6 |
| expedited-1: /home/stephenestrada.guest/kiln-bins/kiln-0-baseline run --net full -- true | 50 | 41.6 | 43.1 | 47.3 | 48.3 |
| expedited-1: /usr/local/bin/kiln run --net full -- true | 50 | 21.7 | 23.5 | 28.2 | 29.3 |
| expedited-1: crun run --bundle /var/lib/kiln-bench/bundle kiln-bench | 50 | 13.0 | 13.4 | 15.6 | 16.5 |
| expedited-1: runc run --bundle /var/lib/kiln-bench/bundle kiln-bench | 50 | 24.6 | 27.3 | 30.0 | 36.8 |
