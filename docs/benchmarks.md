# Benchmarks

kiln is built for short-lived, untrusted agent workloads: many sandboxes,
each started on demand and often used for a single command. That makes four
things matter, and this file measures each against Docker, runc and crun on
the same VM and the same root filesystem:

| | kiln | crun | runc | Docker |
|---|---:|---:|---:|---:|
| **Cold start**, no network (p50) | **13.2 ms** | 13.4 ms | 34.2 ms | 84.0 ms |
| **Cold start**, with network (p50) | **22.2 ms** | | | 141.8 ms |
| **Warm start**: run `true` in an existing sandbox (p50) | **3.5 ms** | 9.7 ms | 24.1 ms | 53.7 ms |
| **Memory per extra idle sandbox** | **~0.4 MiB** | 0.2-0.4 MiB | 0.6-0.8 MiB | 5.3-5.6 MiB |
| **Daemons that must run** | none | none | none | dockerd + containerd, ~160 MiB |
| **Steady state** (CPU-bound / I/O-bound) | same | same | same | same |

Steady-state speed is the same everywhere, as it should be: once a sandbox is
running, its code runs on the same kernel whichever runtime set it up. What a
runtime controls is the cost around the code: starting, idling, tearing
down. kiln also isolates more by default than the others did here: a user
namespace and a per-sandbox disk quota, which none of them used, and a
seccomp filter, which the bare runc and crun configs didn't have (see
[what each one sets up](#method)).

Most of this file is about cold start: where kiln's time went and what was
changed to make it fast (28.9 → 13.2 ms without a network, 87.9 → 22.2 ms
with one).

![Cold-start p50 per runtime](coldstart.svg)

## Method

Every number is the wall time of one command, measured with
[hyperfine](https://github.com/sharkdp/hyperfine) without a shell (`-N`): 10
warmup runs, then 100 timed runs, reported as mean, p50, p95 and p99 in
milliseconds.

**Cold vs. back to back.** By default every run is preceded by 100 ms of idle
(`--prepare "sleep 0.1"`). Without the pause, runs follow each other within
microseconds and some kernel paths are still warm from the previous run (see
[RCU grace periods](#1-rcu-grace-periods) below). Before this work, kiln took
2.7 ms back to back but 28.9 ms after a pause, so a back-to-back benchmark
would have said kiln was already fast. Both are reported; the cold number is
the one an agent sees when it starts a sandbox after thinking for a while.

**Same root filesystem.** Every runtime starts the Alpine 3.24.2 minirootfs
that kiln uses (`/var/lib/kiln/images/alpine`). `bench/setup.sh` packs it with
its owners shifted back from kiln's sandbox ID range and imports it into Docker
(`docker import`) and into an OCI bundle for runc and crun.

**Same limits.** kiln's defaults: 512 MiB of memory with no swap, 1 CPU and
128 PIDs. Docker gets `--memory 512m --cpus 1 --pids-limit 128`, and the OCI
bundle the same values in `linux.resources`.

| case | command |
|---|---|
| kiln-none | `kiln run -- true` |
| kiln-net | `kiln run --net full -- true` |
| docker-none | `docker run --rm --network none --memory 512m --cpus 1 --pids-limit 128 kiln-alpine true` |
| docker-net | `docker run --rm --memory 512m --cpus 1 --pids-limit 128 kiln-alpine true` |
| runc-none | `runc run --bundle /var/lib/kiln-bench/bundle kiln-bench` |
| crun-none | `crun run --bundle /var/lib/kiln-bench/bundle kiln-bench` |

**What each one sets up.** They don't do the same amount of work, so the
comparison isn't perfectly like for like:

| | kiln | docker run --rm | runc / crun (bare `spec`) |
|---|---|---|---|
| Path to the kernel | one process, no daemon | CLI → dockerd → containerd → shim → runc | one process |
| Root filesystem | overlayfs on XFS with a per-run project quota (`--disk 1G`) | overlayfs snapshot (containerd) | the unpacked tree, read-only, no overlay |
| Namespaces | PID, mount, UTS, IPC, network, cgroup, **user** | PID, mount, UTS, IPC, network, cgroup | PID, mount, UTS, IPC, network, cgroup |
| cgroup limits | memory, swap, CPU, PIDs, OOM group kill | memory, swap, CPU, PIDs (systemd driver) | memory, swap, CPU, PIDs |
| Syscall filter | seccomp denylist + `no_new_privs` | default seccomp profile | none |
| PID 1 | kiln-init (forwards signals, reaps) | the command | the command |
| Network (`*-net` cases) | veth on a bridge, nftables chain per sandbox, DNS policy file | veth on docker0, iptables NAT | loopback only |

**Environment.** MacBook Air (Apple M2), macOS 27, Lima VM `kiln` (vz, 4 vCPU,
4 GiB), Ubuntu 24.04, kernel 6.8.0-146-generic aarch64. Docker 29.1.3
(containerd image store, runc 1.3.4), runc 1.3.4, crun 1.14.1, nftables 1.0.9,
hyperfine 1.18.0, rustc 1.99.0, kiln release build. The VM's vCPUs sleep when
idle, so every cold run also pays for waking them; that's part of what the
cold numbers measure. The Mac was otherwise in normal use, so results from
different sessions differ by a few milliseconds. Tables that compare builds
were measured in one session.

**Docker and kiln networking.** Docker sets the iptables FORWARD policy to DROP
by default, which would drop kiln's forwarded sandbox traffic.
`/etc/docker/daemon.json` contains `{"ip-forward-no-drop": true}` so the policy
stays ACCEPT. kiln's own nftables chains still decide what sandboxes may reach.

**Rerun.** Inside the VM:

```sh
sudo apt-get install docker.io runc crun hyperfine
sudo bench/setup.sh                         # Docker image + OCI bundle
sudo bench/coldstart.sh mylabel             # all runtimes, cold
sudo GAP=0 bench/coldstart.sh mylabel-b2b   # back to back
sudo bench/compare.sh mylabel kiln-a kiln-b # kiln builds against each other
sudo bench/warm.sh warm                     # exec into running sandboxes
sudo bench/idle.sh idle                     # memory of idle sandboxes, daemons
sudo bench/steady.sh steady                 # CPU- and I/O-bound workloads
python3 -I bench/chart.py results/final results/final-session-baseline ../docs/coldstart.svg  # from bench/
```

Results are in `bench/results/<label>/` (raw hyperfine JSON plus
`summary.md`).

## Results

### Cold (100 ms idle before each run)

| case | mean | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| **kiln-none** | 12.0 | **13.2** | 15.8 | 16.2 |
| kiln-none, before this work | 28.4 | 28.9 | 38.3 | 41.3 |
| crun-none | 12.7 | 13.4 | 15.8 | 16.7 |
| runc-none | 32.9 | 34.2 | 40.4 | 42.0 |
| docker-none | 84.6 | 84.0 | 91.2 | 102.3 |
| **kiln-net** | 20.8 | **22.2** | 28.4 | 29.9 |
| kiln-net, before this work | 85.0 | 87.9 | 102.4 | 104.0 |
| docker-net | 141.3 | 141.8 | 156.1 | 160.6 |

`bench/results/final` and `final-session-baseline`, measured back to back in
one session. The baseline run from the start of this work
(`bench/results/baseline`) agrees within 1 ms.

### Back to back (no pause)

| case | before: p50 | p95 | now: p50 | p95 |
|---|---:|---:|---:|---:|
| kiln-none | 2.7 | 7.0 | **1.8** | 2.0 |
| crun-none | 2.1 | 2.3 | 2.0 | 2.2 |
| runc-none | 12.0 | 16.6 | 11.2 | 16.7 |
| docker-none | 91.1 | 398.4 | 76.9 | 87.2 |
| kiln-net | 46.8 | 58.8 | **28.5** | 43.3 |
| docker-net | 134.5 | 162.5 | 132.3 | 142.5 |

`bench/results/baseline-b2b` and `final-b2b`. Docker's long tail (p99 250-600
ms) comes and goes between sessions. kiln-net is slower back to back than cold
(28.5 vs 22.2 ms): the next run gets the same IP while the kernel is still
removing the previous sandbox's veth, so it deletes it itself (see change 8).

### Warm start: running a command in an existing sandbox

For an agent session, a sandbox is created once and each tool call runs in
it. Latency to run `true` in an idle sandbox that's already running (a
`kiln create` sandbox; for the others a container running `sleep infinity`),
100 runs with 100 ms idle before each (`bench/warm.sh`,
`bench/results/warm`):

| command | mean | p50 | p95 | p99 |
|---|---:|---:|---:|---:|
| `kiln exec <id> -- true` | 3.5 | **3.5** | 5.6 | 5.9 |
| same, sandbox with `--net full` | 4.0 | 3.8 | 5.8 | 6.1 |
| `crun exec <id> true` | 9.4 | 9.7 | 11.4 | 12.0 |
| `runc exec <id> true` | 24.1 | 24.1 | 29.1 | 33.6 |
| `docker exec <id> true` | 50.6 | 53.7 | 61.9 | 63.3 |
| same, container on the bridge | 51.0 | 54.1 | 59.9 | 62.2 |

The difference is how the new process gets into the sandbox. runc and crun
start a fresh process on the host that joins the container from outside:
`setns` into each namespace, into its cgroup, then capabilities, seccomp and
exec. runc (a Go program) joins the cgroup by writing to `cgroup.procs`, the
same RCU wait as in [section 1](#1-rcu-grace-periods); crun (C) creates the
process inside it with `clone3(CLONE_INTO_CGROUP)`, as seen with `strace`.
Docker adds its API path (CLI → dockerd → containerd → shim) on top of runc. `kiln exec` doesn't enter from outside at all: it connects to a
root-only Unix socket held by the sandbox's PID 1, passes its stdin, stdout
and stderr over it (`SCM_RIGHTS`), and PID 1 forks the command. The child is
born with every namespace, the cgroup, the seccomp filter and the Landlock
policy already in place, because it inherits them.

### Idle overhead

What an idle sandbox costs the host (`bench/idle.sh`, `bench/results/idle-run1`
and `idle-run2`). For one idle sandbox, the host processes it adds and the
memory charged to its cgroup, in KiB:

| runtime | host processes | RSS | PSS | USS | cgroup `memory.current` |
|---|---|---:|---:|---:|---:|
| kiln | shim, PID 1 (kiln-init) | 3504 | 758 | 136 | 280 |
| kiln `--net full` | shim, PID 1 | 3700 | 769 | 144 | 96 |
| Docker | containerd-shim-runc-v2, PID 1 (`sleep`) | 11236 | 11228 | 11228 | 1644 |
| Docker, bridge | containerd-shim-runc-v2, PID 1 | 11512 | 11504 | 11504 | 328 |
| runc | PID 1 only | 772 | 768 | 768 | 464 |
| crun | PID 1 only | 788 | 784 | 784 | 176 |

RSS counts every page a process maps; PSS splits shared pages between the
processes sharing them; USS counts only pages nothing else maps, so it's what
stopping the sandbox frees. kiln's PID 1 is a clone of its shim and both run
the same binary as the other kiln processes, so almost all of their 3.5 MiB
is shared: 136 KiB is theirs alone. Docker's shim is a separate Go program per
container, about 11 MiB, nearly all private. runc and crun leave no
supervisor behind at all (the container is reparented to the host's init), so
nothing would clean up after it; kiln and Docker keep one per sandbox for
that, and for `exec`. `memory.current` varies between runs by a few hundred
KiB with no pattern.

The whole cost, kernel objects included (namespaces, mounts, page tables, the
cgroup itself), shows in how much `MemTotal - MemAvailable` grows when 50
idle sandboxes are started, with the page cache dropped before each reading:

| runtime | per sandbox, run 1 | run 2 |
|---|---:|---:|
| kiln | 370 KiB | 379 KiB |
| crun | 411 KiB | 239 KiB |
| runc | 598 KiB | 760 KiB |
| Docker | 5328 KiB | 5600 KiB |

This is a coarse, host-wide measurement, good to about ±200 KiB; the point is
the order of magnitude: kiln, runc and crun cost a few hundred KiB per idle
sandbox, Docker about 5.5 MiB.

Fixed costs, whatever the number of sandboxes (KiB, run 1):

| process | needed for | RSS | PSS |
|---|---|---:|---:|
| dockerd | every Docker container | 106460 | 104077 |
| containerd | every Docker container | 61096 | 59823 |
| kiln-dns | DNS for kiln sandboxes with a network | 3036 | 1109 |
| kiln-metrics | Prometheus metrics (optional) | 3952 | 2025 |

kiln needs no daemon to start a sandbox. `kiln-dns` is only needed for name
lookups from networked sandboxes, and `kiln-metrics` only for monitoring.

### Steady state

Once running, a sandbox's code should take the same time in every runtime.
Two single-threaded workloads, each under the same 1-CPU limit, timed inside
the sandbox with busybox `time -p` so startup isn't counted, 7 runs each,
interleaved (`bench/steady.sh`, `bench/results/steady`):

- CPU-bound: hash 512 MiB of zeros (`dd if=/dev/zero ... | sha256sum`)
- I/O-bound: write 1 GiB to the sandbox's writable layer and `fsync` it

| workload | runtime | median s | min | max |
|---|---|---:|---:|---:|
| CPU | kiln | 2.93 | 2.92 | 2.94 |
| CPU | Docker | 2.94 | 2.92 | 3.00 |
| CPU | runc | 2.93 | 2.92 | 2.94 |
| CPU | crun | 2.93 | 2.90 | 3.01 |
| I/O | kiln | 1.87 | 1.60 | 2.20 |
| I/O | Docker | 1.71 | 1.34 | 2.04 |
| I/O | runc | 1.66 | 1.38 | 1.77 |
| I/O | crun | 2.01 | 1.74 | 2.90 |

CPU time is identical. I/O overlaps across all four: the ranges are wide
because the VM's disk is a file on the Mac's SSD, and no runtime is
consistently faster. Where the writes land differs: kiln's overlay upper
layer is on XFS in a loop device (direct I/O, for the per-sandbox disk
quota), Docker's on an overlayfs snapshot on the ext4 root disk, runc's and
crun's straight into the unpacked directory on ext4, with no overlay. That's
a choice of storage, not of runtime.

### Each change

p50 in ms, cold, every build measured in the same session
(`bench/results/steps`):

| # | change | --net none | --net full |
|---:|---|---:|---:|
| 0 | baseline (db1947b) | 27.6 | 88.6 |
| 1 | `KILN_TRACE` phase timer | 28.7 | 86.6 |
| 2 | clone3 with `CLONE_INTO_CGROUP` | **17.0** | **71.2** |
| 3 | netlink instead of `ip` and `nsenter` | **13.5** | 75.6 |
| 4 | base ruleset: one listing, commit only on drift | 13.7 | **55.1** |
| 5 | sandbox nft teardown in one transaction | 13.6 | **41.2** |
| 6 | cheap lease checks before `nft get` | 13.0 | 41.9 |
| 7 | policy and base check in one nft run | 13.5 | **37.3** |
| 8a | teardown over nfnetlink, socket closed in the background | 13.4 | 37.5 |
| 8b | leave the veth to the dying namespace | 13.5 | **22.5** |

Changes 6 and 8a don't show up alone: 6 matters only with several sandboxes
running at once, and 8a's saving was hidden behind the veth deletion that 8b
removed (in a separate session, 8b alone averaged 31.9 ms and 8a + 8b 19.7 ms).
Change 3's --net full number is noise between sessions; its saving is the
`nsenter` process, about 3 ms.

## Where the time goes

`KILN_TRACE=1 kiln run ...` prints each phase on one timeline: the host-side
kiln as `host:` and the sandbox's init (a clone of it) as `init:`. Medians of
15 cold runs, ms:

| phase | none before | none now | full before | full now |
|---|---:|---:|---:|---:|
| image check, storage, quota, overlay dirs | 1.2 | 1.5 | 1.5 | 1.3 |
| cgroup create | 0.6 | 0.9 | 0.8 | 0.9 |
| clone (five namespaces) | 1.3 | 1.6 | 1.6 | 1.6 |
| **move child into its cgroup** | **8.6** | gone | **9.9** | gone |
| network setup (host) | 4.5 | — | **42.3** | 7.5 |
| child setup (mounts, pivot_root, /proc, userns) | ~2 | ~2.5 | ~2 | ~2.4 |
| command runs and exits | 1.4 | 1.6 | 0.9 | 1.0 |
| sandbox exit seen by host | 5.0 | 5.3 | 5.1 | 5.3 |
| **network cleanup** | 0.1 | 0.1 | **21.4** | 0.3 |
| cgroup and run dir cleanup | 0.3 | 0.3 | 0.2 | 0.3 |

Two things explain almost all of the old time: waiting for RCU grace periods,
and starting helper processes.

### 1. RCU grace periods

RCU (read-copy-update) lets the kernel's readers run without locks; a writer
that removes something must wait until every CPU has passed a quiescent state
before freeing it. That wait, a *grace period*, took 5-20 ms on this VM,
longer when the vCPUs were idle. Three places in kiln's old path waited for
one:

- **Writing a PID to `cgroup.procs`.** Migrating a running process takes
  `cgroup_threadgroup_rwsem` for writing. It's a per-CPU rwsem: readers
  (every fork) are cheap, and a writer has to switch them to the slow path
  first, which costs a grace period, unless another writer did so moments
  before. That's why the back-to-back benchmark hid it. **Fix:** `clone3`
  with `CLONE_INTO_CGROUP` creates the child already inside its cgroup, so
  nothing is migrated (crun does the same).
- **Closing an nftables socket after a deleting commit.** When a commit
  deletes rules, chains or set elements, nf_tables frees them later from a
  work queue, after a grace period. Closing a `NETLINK_NETFILTER` socket
  waits for that work (`netlink_release` → `nft_rcv_nl_event` →
  `flush_work`), so every `nft` process that deleted something spent 10-20 ms
  in `close()` after its commit was already done. Found with `perf record -e
  sched:sched_switch -g`. kiln paid it up to four times per networked run: the
  base-ruleset repair rewrote the private set on every run, and teardown used
  three separate `nft` processes. **Fixes:** commit nothing when the base
  ruleset is already right; send the teardown's three deletions as one batch
  over kiln's own netlink socket, and hand that socket's last reference to a
  short-lived child process, which sits through the wait while kiln exits.
  Everything the sandbox owned is gone before kiln returns; only the kernel's
  deferred freeing happens afterwards.
- **Deleting the host end of the veth.** `RTM_DELLINK` unregisters the device
  synchronously, with its own RCU waits. But the sandbox's network namespace
  is already being destroyed when kiln gets there, and that removes both ends
  of the pair from a work queue. **Fix:** leave it to the kernel; if the next
  sandbox on the same IP starts before it's gone, it deletes the stale one
  itself.

`/sys/kernel/rcu_expedited` makes every grace period an expedited one (IPIs
to all CPUs instead of waiting for them to pass a quiescent state), which
shows how much of each build's time was grace periods (p50, ms;
`bench/results/rcu-expedited`):

| | normal RCU | expedited RCU |
|---|---:|---:|
| kiln before, --net none | 29.0 | 17.0 |
| kiln now, --net none | 13.2 | 13.3 |
| kiln before, --net full | 89.0 | 43.1 |
| kiln now, --net full | 22.4 | 23.5 |
| runc | 33.6 | 27.3 |
| crun | 13.2 | 13.4 |

The current kiln, like crun, no longer waits for a normal grace period
anywhere on its critical path, so the setting makes no difference to it.
It was left off (it's a host-wide trade-off: more IPIs for everyone).

### 2. Helper processes

A cold `nft --version` takes 3.9 ms on this VM before doing anything: exec,
then loading a dozen shared libraries (libnftables, libnftnl, libmnl,
libxtables, libjansson, libgmp, ...). `ip` and `nsenter` are cheaper but not
free. The old networked path started 8 `nft`, 2 `ip` and 1 `nsenter` per run;
even `--net none` started `nsenter` + `ip` just to bring loopback up.

- `netlink.rs` speaks rtnetlink directly, the protocol `ip` uses: the bridge,
  the veth pair (peer created straight in the sandbox's namespace with
  `IFLA_NET_NS_PID`), bridge-port isolation, addresses, routes. The sandbox's
  side (lo, eth0, default route) is configured by kiln-init itself while it's
  still real root, before it creates its user namespace.
- One `nft` process per networked start: the sandbox's policy batch ends with
  `list table`, and that listing is checked against the canonical base
  ruleset. A second `nft` runs only to repair drift.
- Teardown deletions go over netlink without `nft` (no rule bytecode needed).

### What's left

- **--net none, 13 ms**, the same as crun. About 5 ms passes between the
  command exiting and the host seeing the sandbox gone: tearing down the
  mount namespace (an expedited RCU wait in `namespace_unlock`), the PID
  namespace, and waking the host-side kiln on an idle vCPU. Creating the five
  namespaces in clone3 takes 1.6 ms, the child's mounts about 2.5 ms, and
  starting the kiln binary itself 1-2 ms.
- **--net full, 22 ms**: the same plus one `nft` process (about 6 ms cold,
  including the network lock and the bridge check) and the veth (1 ms).

## Options not built

These would change kiln more than a local optimization, so they're listed
for a decision rather than done:

1. **libnftables in-process.** `dlopen("libnftables.so.1")` and
   `nft_run_cmd_from_buffer` run the same nft scripts without a process.
   Measured with ctypes: 0.55 ms to load and 1.2 ms to run the policy batch,
   against 4-6 ms for the `nft` process. Saves 3-4 ms per networked start, at
   the cost of ~80 lines of `unsafe` FFI and a C library in kiln's address
   space. Loaded only for networked runs, so `--net none` wouldn't pay for
   the libraries.
2. **Report the exit code before teardown.** kiln-init could pass the
   command's exit code to the host as soon as the command exits, and kiln
   could return it while the namespaces are torn down. Saves most of the
   5 ms "sandbox exit" phase, but cleanup would finish after `kiln run`
   returns, which changes what callers can rely on.
3. **A pool of pre-created sandboxes** in the planned `kilnd`: `kiln create`
   ahead of time, hand out a ready sandbox on request, so the latency an agent
   sees is an exec (3 ms) instead of a cold start (13-22 ms). This is the
   architecture-level change with the biggest effect; it needs the daemon and
   a policy for how many idle sandboxes to keep.
4. **Pre-created network plumbing.** With a pool, veth pairs and nftables
   chains could be set up per pooled sandbox ahead of time, so even a
   networked start would be just an exec.
