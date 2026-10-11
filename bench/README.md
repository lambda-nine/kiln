# Benchmark harness v2

`bench/v2.py` measures kiln against Docker, runc and crun with a randomized,
reproducible schedule and keeps every raw measurement. It replaces the
hyperfine-based scripts (`coldstart.sh`, `compare.sh`, `idle.sh`) for new
measurements; those stay as they are for the results already in
`docs/benchmarks.md`.

Python 3.12 or newer, standard library only. Cases live in
[`v2-config.json`](v2-config.json); tests in [`tests/`](tests/).

## Quick start

Inside the VM, after `sudo bench/setup.sh` (the Docker image and OCI bundles):

```sh
# Latency: 100 measured rounds, 10 warmup rounds, at 0 ms and 100 ms gaps
sudo python3 -I bench/v2.py latency --config bench/v2-config.json \
    --out bench/results/v2/boot1-latency --session boot1 \
    --runs 100 --warmups 10 --gap-ms 0,100 --seed 1

# Only kiln and runc; a different kiln binary
sudo python3 -I bench/v2.py latency --config bench/v2-config.json \
    --out bench/results/v2/boot1-kiln-runc --session boot1 \
    --runs 50 --warmups 5 --gap-ms 100 --seed 2 \
    --case '^(kiln|runc)-' --var kiln=/home/me/kiln/target/release/kiln

# Concurrency: 1, 4, 16 and 32 commands at once, 10 batches each, 500 ms apart
sudo python3 -I bench/v2.py concurrency --config bench/v2-config.json \
    --out bench/results/v2/boot1-conc --session boot1 \
    --levels 1,4,16,32 --batches 10 --gap-ms 500 --seed 3

# Memory: host memory with 0..100 idle sandboxes, 3 repeats
sudo python3 -I bench/v2.py memory --config bench/v2-config.json \
    --out bench/results/v2/boot1-mem --session boot1 \
    --counts 0,10,25,50,100 --repeats 3 --seed 4

# Summary across boots, every case against kiln-none
python3 -I bench/v2.py summarize bench/results/v2/boot*-latency \
    --out bench/results/v2/summary --baseline kiln-none
```

`--case REGEX` selects cases by `re.search` on their names. `--var NAME=VALUE`
overrides a config variable (`kiln`, `bundle`, `idle_bundle`, `image`).
Failed invocations never stop a run: each one is recorded with its exit code,
signal, timeout or spawn error, and the run goes on.

## What gets measured

Each invocation runs its argv directly (no shell). The clock is
`time.monotonic_ns`, started right before `subprocess.Popen` and stopped when
`waitpid` returns. So every number includes Python's fork/exec of the runtime's
CLI, a small cost that's the same for every case, and output goes to
temporary files rather than pipes, so a CLI that leaves a process holding its
stdout (`docker run -d`, `runc run -d`) can't stall the harness. A watchdog
thread armed before the clock starts kills a command after `timeout_s`.

**`true` is an overhead microbenchmark.** `kiln run -- true`,
`docker run --rm … true` and `runc run` on the `true` bundle measure the full
lifecycle of a sandbox whose workload does nothing: CLI start, create, start,
run `true`, wait, and tear down. That's the fixed cost an agent tool call pays
per fresh sandbox. It is not pure startup (time to the first instruction of the
workload), and it says nothing about how fast a real workload runs once inside.

### latency

For every measured round, every gap in `--gap-ms` comes up once (in shuffled
order), and for each gap every selected case runs exactly once, in shuffled
order. Cases are interleaved, never run in blocks, so drift on the host (thermal
state, page cache, a background job) spreads over all cases alike. Case orders
come from randomized Latin squares: within each block of *k* rounds (*k* cases),
each case takes each position once, so no case is always first after a pause.
Warmup rounds come first, are scheduled the same way, and are recorded with
`"warmup": true`; summaries leave them out.

The gap is an untimed `sleep` before each invocation. It exists because some
kernel paths stay warm when runs follow each other within microseconds (see the
RCU notes in `docs/benchmarks.md`); `--gap-ms 0` measures that back-to-back
case on purpose.

### concurrency

Each block runs every (case, level) pair once in seeded shuffled order, after a
quiet `--gap-ms` pause. A batch starts exactly *level* commands: one thread per
command waits on a barrier, then times its own Popen-to-waitpid. Python's GIL
serializes part of the spawning, so starts spread over a little time; each
batch records that spread (`start_spread_ns`). Each batch records wall time
(first start to last exit), successes, failures, timeouts and
`completions_per_s` (successes per second of wall time), plus `/proc/stat` CPU
lines, `/proc/meminfo` and load averages before and after, and
`cpu_busy_fraction` from the two CPU snapshots.

### memory

Each repeat measures every (case, count) pair in shuffled order. For one point
the harness settles, reads `/proc/meminfo`, starts *count* idle sandboxes with
the case's `memory.start_argv`, settles again, reads `/proc/meminfo`, then stops
every sandbox it tried to start, in reverse, from a `finally` block (so also
after a failure or Ctrl-C). If a start fails, the point stops starting more,
is marked `aborted`, and is left out of the fits; the stop attempts are still
recorded.

Settling means: as root, `sync`, write `3` to `/proc/sys/vm/drop_caches`, then
wait `settle_s` (config `memory.settle_s`, or `--settle-s`). Without root the
cache drop is skipped and every point records
`"cache_drop_before": "skipped: not root"`; page cache then adds noise to the
readings.

"Used" is `MemTotal - MemAvailable`: everything, kernel objects included. The
summary fits an ordinary least-squares line of the growth in used KiB
(after − before) against the number of sandboxes running, per case and repeat,
and summarizes the slopes across repeats. The slope is the marginal cost of one
more sandbox; fixed costs such as dockerd or kiln-dns land in the intercept and
in `count 0`, not in the slope.

## Configuration

```json
{
  "vars": {"kiln": "/usr/local/bin/kiln"},
  "workload": ["true"],
  "defaults": {"timeout_s": 120, "output_limit_bytes": 4096, "env": {}},
  "memory": {"settle_s": 2},
  "cases": {
    "kiln-none": {
      "tier": "end-user-stack",
      "capabilities": {"network": "none"},
      "argv": ["{kiln}", "run", "--", "{workload}"],
      "cwd": null,
      "env": {},
      "version_argv": null,
      "timeout_s": 120,
      "memory": {
        "start_argv": ["{kiln}", "create"],
        "sandbox_id_from": "stdout",
        "stop_argv": ["{kiln}", "rm", "{sandbox}"]
      }
    }
  }
}
```

Placeholders in any argv:

- `{id}`: a unique, safe invocation ID (`kb-<run id>-<slot>`, lowercase letters,
  digits and dashes). OCI container IDs and Docker `--name`s use it, so
  invocations never collide and leftovers are easy to find
  (`docker ps -a --filter name=kb-`, `runc list`).
- `{workload}`: as a whole argument, the workload's arguments spliced in; inside
  a longer argument, the shell-quoted workload. A case may set its own
  `workload`.
- `{sandbox}` (memory `stop_argv` only): the sandbox to remove. With
  `"sandbox_id_from": "id"` it is `{id}`; with `"stdout"` it is the last
  non-empty line the start command printed. `kiln create` names its own
  sandboxes and prints the ID, so kiln uses `stdout`, and no shell adapter is
  needed for any runtime.
- `{name}` for any key in `vars`.

Other braces (Docker's `{{.Client.Version}}` templates) pass through untouched;
an unknown `{name}` is an error when the config loads.

`tier` and `capabilities` are free-form metadata copied into the manifest:
`end-user-stack` for kiln and Docker (a complete CLI with images or rootfs
management, networking and cleanup), `low-level` for runc and crun (an OCI
runtime handed a prepared bundle).

## Fairness boundaries

Every case starts the same Alpine tree with the same limits: 512 MiB memory
with no swap (Docker: `--memory 512m --memory-swap 512m`), 1 CPU, 128 PIDs. They
still don't do the same work, and comparisons should stay within what each case
does:

- **Tiers.** runc and crun get a ready bundle: no image lookup, no overlay, no
  seccomp profile, no user namespace, no network setup beyond an empty network
  namespace, and their command is fixed by the bundle's `config.json`
  (`bench/setup.sh` writes `true`; `{workload}` doesn't apply). They're a floor
  for what a container runtime costs, not a like-for-like competitor to an
  end-user stack. Compare kiln with Docker as stacks, and with runc/crun as the
  low-level floor.
- **Daemons.** Docker's latency includes the client-to-dockerd round trips and
  containerd; its memory includes a containerd shim per container, but dockerd
  and containerd themselves are a fixed cost outside the slope. kiln-net relies
  on the kiln-dns service the same way.
- **Isolation differs.** kiln runs in a user namespace with seccomp and an
  overlay; Docker has seccomp and an overlay but no user namespace by default.
  The `capabilities` metadata lists what each case does.
- **Networking.** `-none` cases have no network; `kiln-net` and `docker-net`
  set up a veth pair and NAT. Compare `-net` with `-net`.
- **Harness overhead.** Python's spawn cost is in every number. It's small
  next to a container lifecycle and the same for every case, but it's there.
- **Concurrency start spread.** Commands in a batch start within
  `start_spread_ns` of each other, not at one instant.

## Sessions and separate boots

A session is the replication unit: one boot of the VM, with its own page
cache, kernel state and host load. Runs on the same boot share all of that, so
many runs in one boot are one sample of "a boot", not many. To replicate:

```sh
limactl stop kiln && limactl start kiln && limactl shell --workdir "$PWD" kiln
sudo python3 -I bench/v2.py latency ... --session boot2 --out bench/results/v2/boot2-latency
```

Use a new `--session` label and `--out` for each boot (and the same `--seed` if
you want the identical schedule). Every record and manifest carries the kernel
boot ID (`/proc/sys/kernel/random/boot_id`); `summarize` warns when one session
label spans several boot IDs or two labels share one.

Ratios against `--baseline` are computed per session (median of the case ÷
median of the baseline, same gap) and reported as a distribution over
sessions: min, median, max and geometric mean. With at least two paired
sessions the summary adds a 95% percentile-bootstrap interval of the geometric
mean, resampling sessions (10,000 resamples, `--bootstrap-seed`, default 0);
with fewer it says so and gives no interval. With two to four sessions that
interval is coarse and labeled as such. p95 and p99 are percentiles of single
invocations, never confidence intervals.

## Root

kiln, runc and crun need root to create sandboxes, and Docker needs root or
the `docker` group, so measuring runs go under `sudo`. The harness itself never
escalates. Dropping the page cache in `memory` needs root; without it the
run continues and records that the drop was skipped. `summarize` and the tests
need no privileges.

## Output

Each measuring run writes to a new directory; an existing `--out` is refused.

```
<out>/
  manifest.json   written before the first measured command
  config.json     byte-for-byte copy of the config used
  records.jsonl   one JSON object per line, appended and flushed as it goes
```

**Resuming.** `--resume` reuses an existing directory only if mode, session,
seed, config SHA-256, selected cases, plan parameters and boot ID all match the
manifest, and `config.json` matches the config. The schedule is a function of
the seed, so the harness skips the slots already recorded and runs the rest
with a new run ID (and therefore new `{id}`s). The manifest gains an entry in
`segments`.

**manifest.json**: `schema`, `created_utc`, `argv`, `mode`, `session`,
`seed`, `params`, `cases`, `case_specs` (tier, capabilities, argv), `vars`,
`config_path`, `config_sha256`, `git` (commit, dirty, dirty paths), `hostname`,
`uname`, `boot_id`, `os_release`, `python`, `cpu` (count, model, scaling
governors where available), `memory` (MemTotal, MemAvailable, SwapTotal,
SwapFree in kB), `cgroup_mode`, `euid`, `root`, `executables` (for every
command: resolved realpath and SHA-256), `versions` (each case's version
command: argv, exit code, stdout, stderr; `null` for kiln, which has no
`--version` and is identified by its binary's SHA-256 and the git commit), and
`segments`.

**records.jsonl**: every record has `schema`, `kind`, `mode`, `session`,
`boot_id` and `run_id`. Records of one command invocation also have
`invocation_id`, `argv`, `exit_code`, `signal`, `timed_out`, `error` (spawn
failure), `ok` (exit 0, no timeout, no error), `elapsed_ns`, `start_mono_ns`,
`end_mono_ns`, `start_utc`, `end_utc`, `stdout`, `stderr` (first
`output_limit_bytes`), `stdout_bytes`, `stderr_bytes`, `stdout_truncated`,
`stderr_truncated`. By kind:

| kind | extra fields |
|---|---|
| `latency` | `ordinal` (schedule slot), `warmup`, `round`, `gap_ms`, `position`, `case` |
| `concurrency_invocation` | `batch`, `block`, `position`, `case`, `level`, `slot` |
| `concurrency_batch` | `batch`, `block`, `position`, `case`, `level`, `gap_ms`, `invocation_ids`, `attempted`, `successes`, `failures`, `timeouts`, `spawn_errors`, `wall_ns`, `start_spread_ns`, `completions_per_s`, `cpu_stat_before/after`, `cpu_busy_fraction`, `meminfo_before/after`, `loadavg_before/after` |
| `memory_start` | `point`, `repeat`, `position`, `case`, `count`, `slot`, `sandbox_id` |
| `memory_stop` | as `memory_start`, plus `skipped` |
| `memory_point` | `point`, `repeat`, `position`, `case`, `count`, `count_running`, `sandbox_ids`, `invocation_ids`, `complete`, `aborted`, `error`, `root`, `settle_s`, `cache_drop_before/after`, `meminfo_before/after` (every field, as the kernel prints it), `used_kib_before/after`, `used_delta_kib` |

`summarize PATH…` takes run directories or `.jsonl` files and writes
`summary.json` and `summary.md` to `--out`: latency per case, session and gap
(n, failures, mean, p50, p95, p99, min, max of successful invocations, in ms),
ratios against the baseline as above, concurrency per case and level
(batches, invocations, failures, timeouts, completions/s, per-invocation
p50/p95/p99), and memory slopes per case. The summary has no timestamp, so the
same inputs give the same files.

## Tests

```sh
python3 -I -m unittest discover -s bench/tests -v
```

They run fake Python child commands against a fake `/proc` in temporary
directories; no root, no runtimes, a few seconds.
