# Benchmark summary

Baseline: `kiln-none`. Inputs: `bench/results/v2/macbook-air-2026-10-11/gap-sweep/records.jsonl`.

## Latency (ms, successful invocations)

p95/p99 are percentiles of individual invocations, not confidence intervals.

| case | session | gap ms | n | failures | mean | p50 | p95 | p99 | min | max |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| crun-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 2.856 | 2.582 | 4.263 | 4.491 | 2.218 | 4.548 |
| crun-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 2.646 | 2.567 | 3.186 | 3.193 | 2.290 | 3.195 |
| crun-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 5.472 | 4.604 | 10.788 | 13.655 | 3.052 | 14.372 |
| crun-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 11.431 | 12.500 | 15.649 | 15.737 | 3.412 | 15.759 |
| crun-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 14.136 | 14.801 | 18.117 | 18.694 | 3.147 | 18.838 |
| docker-net | boot-06-gap-sweep | 0.0 | 10 | 0 | 182.415 | 168.971 | 265.915 | 286.515 | 115.282 | 291.664 |
| docker-net | boot-06-gap-sweep | 10.0 | 10 | 0 | 215.420 | 173.826 | 382.692 | 419.545 | 140.540 | 428.758 |
| docker-net | boot-06-gap-sweep | 100.0 | 10 | 0 | 209.799 | 199.994 | 303.996 | 332.918 | 137.071 | 340.148 |
| docker-net | boot-06-gap-sweep | 1000.0 | 10 | 0 | 179.684 | 181.050 | 201.561 | 207.733 | 149.405 | 209.276 |
| docker-net | boot-06-gap-sweep | 5000.0 | 10 | 0 | 204.423 | 191.296 | 274.774 | 324.716 | 177.431 | 337.201 |
| docker-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 187.545 | 141.537 | 423.916 | 522.259 | 78.078 | 546.845 |
| docker-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 122.245 | 89.867 | 197.012 | 207.357 | 72.381 | 209.943 |
| docker-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 116.660 | 106.212 | 184.581 | 210.822 | 76.314 | 217.383 |
| docker-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 123.957 | 119.153 | 142.614 | 147.158 | 111.412 | 148.294 |
| docker-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 160.355 | 140.897 | 258.539 | 279.732 | 122.681 | 285.030 |
| kiln-net | boot-06-gap-sweep | 0.0 | 10 | 0 | 10.093 | 6.475 | 26.067 | 33.141 | 4.841 | 34.910 |
| kiln-net | boot-06-gap-sweep | 10.0 | 10 | 0 | 6.601 | 5.339 | 11.647 | 14.054 | 4.889 | 14.656 |
| kiln-net | boot-06-gap-sweep | 100.0 | 10 | 0 | 12.850 | 11.015 | 21.851 | 22.850 | 6.517 | 23.100 |
| kiln-net | boot-06-gap-sweep | 1000.0 | 10 | 0 | 25.167 | 25.278 | 28.791 | 29.254 | 21.246 | 29.369 |
| kiln-net | boot-06-gap-sweep | 5000.0 | 10 | 0 | 25.073 | 25.532 | 28.535 | 28.711 | 20.014 | 28.755 |
| kiln-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 3.155 | 2.785 | 5.301 | 6.713 | 2.345 | 7.066 |
| kiln-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 3.063 | 2.700 | 4.953 | 5.889 | 2.293 | 6.123 |
| kiln-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 7.485 | 5.343 | 14.989 | 15.047 | 2.942 | 15.062 |
| kiln-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 14.232 | 14.929 | 16.415 | 16.482 | 8.716 | 16.499 |
| kiln-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 14.567 | 14.883 | 16.214 | 16.574 | 12.261 | 16.664 |
| nerdctl-net | boot-06-gap-sweep | 0.0 | 10 | 0 | 232.921 | 207.852 | 315.040 | 328.530 | 184.776 | 331.903 |
| nerdctl-net | boot-06-gap-sweep | 10.0 | 10 | 0 | 244.631 | 209.719 | 417.784 | 469.194 | 176.593 | 482.047 |
| nerdctl-net | boot-06-gap-sweep | 100.0 | 10 | 0 | 220.794 | 212.322 | 284.564 | 304.711 | 187.240 | 309.747 |
| nerdctl-net | boot-06-gap-sweep | 1000.0 | 10 | 0 | 234.171 | 230.034 | 266.899 | 285.851 | 215.771 | 290.589 |
| nerdctl-net | boot-06-gap-sweep | 5000.0 | 10 | 0 | 230.622 | 230.749 | 239.255 | 241.744 | 220.204 | 242.366 |
| nerdctl-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 125.763 | 109.399 | 194.147 | 202.404 | 95.690 | 204.469 |
| nerdctl-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 143.037 | 110.479 | 237.786 | 244.565 | 97.159 | 246.259 |
| nerdctl-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 128.002 | 129.327 | 146.054 | 148.443 | 105.397 | 149.040 |
| nerdctl-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 144.643 | 141.592 | 162.361 | 172.415 | 134.458 | 174.928 |
| nerdctl-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 146.137 | 147.488 | 152.517 | 153.325 | 137.985 | 153.527 |
| podman-crun-net | boot-06-gap-sweep | 0.0 | 10 | 0 | 162.687 | 162.133 | 176.421 | 177.708 | 145.557 | 178.030 |
| podman-crun-net | boot-06-gap-sweep | 10.0 | 10 | 0 | 152.155 | 153.497 | 167.523 | 171.899 | 136.524 | 172.993 |
| podman-crun-net | boot-06-gap-sweep | 100.0 | 10 | 0 | 175.316 | 173.515 | 195.742 | 197.260 | 153.452 | 197.639 |
| podman-crun-net | boot-06-gap-sweep | 1000.0 | 10 | 0 | 193.242 | 199.272 | 211.174 | 212.272 | 141.140 | 212.546 |
| podman-crun-net | boot-06-gap-sweep | 5000.0 | 10 | 0 | 204.178 | 205.834 | 224.576 | 226.219 | 179.362 | 226.630 |
| podman-crun-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 67.240 | 62.342 | 90.054 | 91.756 | 55.249 | 92.181 |
| podman-crun-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 63.593 | 62.369 | 73.033 | 78.299 | 58.933 | 79.616 |
| podman-crun-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 83.404 | 84.981 | 100.026 | 103.256 | 64.132 | 104.064 |
| podman-crun-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 109.814 | 107.110 | 121.019 | 121.996 | 97.432 | 122.240 |
| podman-crun-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 107.056 | 109.269 | 118.191 | 120.472 | 86.404 | 121.042 |
| podman-runc-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 180.989 | 180.274 | 187.402 | 187.742 | 168.397 | 187.827 |
| podman-runc-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 185.511 | 182.319 | 206.270 | 213.279 | 176.714 | 215.031 |
| podman-runc-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 193.555 | 187.583 | 215.734 | 225.136 | 183.037 | 227.487 |
| podman-runc-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 233.285 | 233.778 | 237.718 | 238.019 | 224.724 | 238.095 |
| podman-runc-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 229.715 | 233.558 | 245.556 | 246.016 | 178.500 | 246.131 |
| runc-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 15.606 | 13.654 | 24.415 | 25.881 | 9.804 | 26.247 |
| runc-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 15.658 | 14.922 | 22.080 | 24.307 | 10.649 | 24.864 |
| runc-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 25.566 | 22.027 | 43.155 | 45.360 | 15.288 | 45.911 |
| runc-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 33.294 | 36.644 | 42.312 | 42.905 | 15.236 | 43.053 |
| runc-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 32.753 | 34.811 | 42.063 | 44.020 | 18.762 | 44.509 |
| runsc-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 31.446 | 29.530 | 41.170 | 47.159 | 27.734 | 48.656 |
| runsc-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 34.519 | 30.422 | 50.188 | 51.535 | 27.065 | 51.872 |
| runsc-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 40.537 | 35.706 | 64.769 | 75.325 | 30.313 | 77.964 |
| runsc-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 67.086 | 64.108 | 82.795 | 85.910 | 56.857 | 86.689 |
| runsc-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 64.279 | 67.449 | 74.211 | 74.395 | 37.926 | 74.441 |
| youki-none | boot-06-gap-sweep | 0.0 | 10 | 0 | 12.283 | 10.411 | 20.616 | 25.009 | 8.412 | 26.107 |
| youki-none | boot-06-gap-sweep | 10.0 | 10 | 0 | 12.582 | 12.353 | 14.469 | 14.572 | 10.635 | 14.598 |
| youki-none | boot-06-gap-sweep | 100.0 | 10 | 0 | 18.412 | 15.659 | 27.983 | 28.491 | 10.921 | 28.618 |
| youki-none | boot-06-gap-sweep | 1000.0 | 10 | 0 | 30.333 | 31.113 | 33.668 | 34.174 | 21.312 | 34.301 |
| youki-none | boot-06-gap-sweep | 5000.0 | 10 | 0 | 29.632 | 30.957 | 33.389 | 34.031 | 22.728 | 34.191 |

## Ratio to `kiln-none` (per-session median ratios)

Each session (one boot) contributes one ratio of medians. The 95% CI is a bootstrap over sessions and appears only with at least 2 paired sessions.

| case | gap ms | sessions | min | median | max | geomean | 95% CI (sessions) |
|---|---:|---:|---:|---:|---:|---:|---|
| crun-none | 0.0 | 1 | 0.927 | 0.927 | 0.927 | 0.927 | none (fewer than 2 sessions) |
| crun-none | 10.0 | 1 | 0.951 | 0.951 | 0.951 | 0.951 | none (fewer than 2 sessions) |
| crun-none | 100.0 | 1 | 0.862 | 0.862 | 0.862 | 0.862 | none (fewer than 2 sessions) |
| crun-none | 1000.0 | 1 | 0.837 | 0.837 | 0.837 | 0.837 | none (fewer than 2 sessions) |
| crun-none | 5000.0 | 1 | 0.995 | 0.995 | 0.995 | 0.995 | none (fewer than 2 sessions) |
| docker-net | 0.0 | 1 | 60.682 | 60.682 | 60.682 | 60.682 | none (fewer than 2 sessions) |
| docker-net | 10.0 | 1 | 64.377 | 64.377 | 64.377 | 64.377 | none (fewer than 2 sessions) |
| docker-net | 100.0 | 1 | 37.433 | 37.433 | 37.433 | 37.433 | none (fewer than 2 sessions) |
| docker-net | 1000.0 | 1 | 12.128 | 12.128 | 12.128 | 12.128 | none (fewer than 2 sessions) |
| docker-net | 5000.0 | 1 | 12.853 | 12.853 | 12.853 | 12.853 | none (fewer than 2 sessions) |
| docker-none | 0.0 | 1 | 50.830 | 50.830 | 50.830 | 50.830 | none (fewer than 2 sessions) |
| docker-none | 10.0 | 1 | 33.283 | 33.283 | 33.283 | 33.283 | none (fewer than 2 sessions) |
| docker-none | 100.0 | 1 | 19.880 | 19.880 | 19.880 | 19.880 | none (fewer than 2 sessions) |
| docker-none | 1000.0 | 1 | 7.982 | 7.982 | 7.982 | 7.982 | none (fewer than 2 sessions) |
| docker-none | 5000.0 | 1 | 9.467 | 9.467 | 9.467 | 9.467 | none (fewer than 2 sessions) |
| kiln-net | 0.0 | 1 | 2.325 | 2.325 | 2.325 | 2.325 | none (fewer than 2 sessions) |
| kiln-net | 10.0 | 1 | 1.977 | 1.977 | 1.977 | 1.977 | none (fewer than 2 sessions) |
| kiln-net | 100.0 | 1 | 2.062 | 2.062 | 2.062 | 2.062 | none (fewer than 2 sessions) |
| kiln-net | 1000.0 | 1 | 1.693 | 1.693 | 1.693 | 1.693 | none (fewer than 2 sessions) |
| kiln-net | 5000.0 | 1 | 1.716 | 1.716 | 1.716 | 1.716 | none (fewer than 2 sessions) |
| nerdctl-net | 0.0 | 1 | 74.646 | 74.646 | 74.646 | 74.646 | none (fewer than 2 sessions) |
| nerdctl-net | 10.0 | 1 | 77.670 | 77.670 | 77.670 | 77.670 | none (fewer than 2 sessions) |
| nerdctl-net | 100.0 | 1 | 39.740 | 39.740 | 39.740 | 39.740 | none (fewer than 2 sessions) |
| nerdctl-net | 1000.0 | 1 | 15.409 | 15.409 | 15.409 | 15.409 | none (fewer than 2 sessions) |
| nerdctl-net | 5000.0 | 1 | 15.504 | 15.504 | 15.504 | 15.504 | none (fewer than 2 sessions) |
| nerdctl-none | 0.0 | 1 | 39.288 | 39.288 | 39.288 | 39.288 | none (fewer than 2 sessions) |
| nerdctl-none | 10.0 | 1 | 40.916 | 40.916 | 40.916 | 40.916 | none (fewer than 2 sessions) |
| nerdctl-none | 100.0 | 1 | 24.206 | 24.206 | 24.206 | 24.206 | none (fewer than 2 sessions) |
| nerdctl-none | 1000.0 | 1 | 9.485 | 9.485 | 9.485 | 9.485 | none (fewer than 2 sessions) |
| nerdctl-none | 5000.0 | 1 | 9.910 | 9.910 | 9.910 | 9.910 | none (fewer than 2 sessions) |
| podman-crun-net | 0.0 | 1 | 58.227 | 58.227 | 58.227 | 58.227 | none (fewer than 2 sessions) |
| podman-crun-net | 10.0 | 1 | 56.848 | 56.848 | 56.848 | 56.848 | none (fewer than 2 sessions) |
| podman-crun-net | 100.0 | 1 | 32.477 | 32.477 | 32.477 | 32.477 | none (fewer than 2 sessions) |
| podman-crun-net | 1000.0 | 1 | 13.348 | 13.348 | 13.348 | 13.348 | none (fewer than 2 sessions) |
| podman-crun-net | 5000.0 | 1 | 13.830 | 13.830 | 13.830 | 13.830 | none (fewer than 2 sessions) |
| podman-crun-none | 0.0 | 1 | 22.389 | 22.389 | 22.389 | 22.389 | none (fewer than 2 sessions) |
| podman-crun-none | 10.0 | 1 | 23.099 | 23.099 | 23.099 | 23.099 | none (fewer than 2 sessions) |
| podman-crun-none | 100.0 | 1 | 15.906 | 15.906 | 15.906 | 15.906 | none (fewer than 2 sessions) |
| podman-crun-none | 1000.0 | 1 | 7.175 | 7.175 | 7.175 | 7.175 | none (fewer than 2 sessions) |
| podman-crun-none | 5000.0 | 1 | 7.342 | 7.342 | 7.342 | 7.342 | none (fewer than 2 sessions) |
| podman-runc-none | 0.0 | 1 | 64.742 | 64.742 | 64.742 | 64.742 | none (fewer than 2 sessions) |
| podman-runc-none | 10.0 | 1 | 67.522 | 67.522 | 67.522 | 67.522 | none (fewer than 2 sessions) |
| podman-runc-none | 100.0 | 1 | 35.110 | 35.110 | 35.110 | 35.110 | none (fewer than 2 sessions) |
| podman-runc-none | 1000.0 | 1 | 15.660 | 15.660 | 15.660 | 15.660 | none (fewer than 2 sessions) |
| podman-runc-none | 5000.0 | 1 | 15.693 | 15.693 | 15.693 | 15.693 | none (fewer than 2 sessions) |
| runc-none | 0.0 | 1 | 4.903 | 4.903 | 4.903 | 4.903 | none (fewer than 2 sessions) |
| runc-none | 10.0 | 1 | 5.527 | 5.527 | 5.527 | 5.527 | none (fewer than 2 sessions) |
| runc-none | 100.0 | 1 | 4.123 | 4.123 | 4.123 | 4.123 | none (fewer than 2 sessions) |
| runc-none | 1000.0 | 1 | 2.455 | 2.455 | 2.455 | 2.455 | none (fewer than 2 sessions) |
| runc-none | 5000.0 | 1 | 2.339 | 2.339 | 2.339 | 2.339 | none (fewer than 2 sessions) |
| runsc-none | 0.0 | 1 | 10.605 | 10.605 | 10.605 | 10.605 | none (fewer than 2 sessions) |
| runsc-none | 10.0 | 1 | 11.267 | 11.267 | 11.267 | 11.267 | none (fewer than 2 sessions) |
| runsc-none | 100.0 | 1 | 6.683 | 6.683 | 6.683 | 6.683 | none (fewer than 2 sessions) |
| runsc-none | 1000.0 | 1 | 4.294 | 4.294 | 4.294 | 4.294 | none (fewer than 2 sessions) |
| runsc-none | 5000.0 | 1 | 4.532 | 4.532 | 4.532 | 4.532 | none (fewer than 2 sessions) |
| youki-none | 0.0 | 1 | 3.739 | 3.739 | 3.739 | 3.739 | none (fewer than 2 sessions) |
| youki-none | 10.0 | 1 | 4.575 | 4.575 | 4.575 | 4.575 | none (fewer than 2 sessions) |
| youki-none | 100.0 | 1 | 2.931 | 2.931 | 2.931 | 2.931 | none (fewer than 2 sessions) |
| youki-none | 1000.0 | 1 | 2.084 | 2.084 | 2.084 | 2.084 | none (fewer than 2 sessions) |
| youki-none | 5000.0 | 1 | 2.080 | 2.080 | 2.080 | 2.080 | none (fewer than 2 sessions) |
