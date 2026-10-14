# Changelog

Notable changes to kiln. Versions follow [Semantic Versioning](https://semver.org/);
before 1.0, any minor release may change the CLI or on-disk layout.

## Unreleased

### Runtime

- A persistent sandbox now survives a per-request setup failure, including
  `fork()` being refused at `pids.max`; only that `kiln exec` fails with 125.
- `kiln exec`: if the client disconnects before its command finishes, PID 1
  kills the command's process group and keeps serving. Before, the command
  ran on, blocked later execs, and PID 1 then exited on the failed status
  write, removing the whole sandbox.
- `kiln exec` exits 125 when kiln itself fails (invalid ID, missing sandbox,
  terminal stdio), as `docker exec` does, instead of 1, which a command can
  return too.

### Project

- Moved the project home to the Lambda IX GitHub organization and changed the
  default macOS checkout path to `~/Projects/lambda-nine/kiln`.
- `lima.yaml` also mounts the sibling `~/Projects/lambda-nine/kilnd` checkout
  so the control daemon builds and tests in the same VM.

## 0.1.0 - 2026-10-11

Initial public release. kiln is an experimental, shared-kernel sandbox runtime
for AI agent tool calls. It is not production software and not a security
boundary for hostile multi-tenant workloads; see [SECURITY.md](SECURITY.md).

### Runtime

- `kiln run`: one-shot sandboxes with UTS, PID, mount, IPC, network, cgroup and
  user namespaces; an overlayfs root over a verified Alpine image with
  `pivot_root`; and kiln-init as PID 1 for signal forwarding and reaping.
- Resource limits with cgroups v2 (`--memory`, `--cpus`, `--pids`, with
  `--stats`), started directly in the cgroup with `clone3(CLONE_INTO_CGROUP)`,
  and per-run XFS project quotas for blocks and inodes (`--disk`).
- Sandbox root mapped to an unprivileged host UID range, `no_new_privs`, a
  seccomp-bpf denylist that also blocks namespace creation, and an optional
  Landlock read-only mode (`--read-only`, `--writable`).
- Terminal-injection ioctls are denied. Persistent `kiln exec` refuses raw
  terminal descriptors until kiln has a controlled PTY mode.
- Per-run directories and persistent control sockets have explicit root-only
  permissions, independent of the invoking shell's umask.
- Networking: no network by default; `--net full` or `--allow` allowlists over
  a bridge, veth pair and nftables egress policy that blocks the host, private
  ranges and other sandboxes, with per-IP conntrack limits and a filtering DNS
  forwarder (`kiln dns`).
- Persistent sandboxes: `kiln create`, `exec`, `ls`, `rm` and `gc`.
- Observability: `kiln metrics` (Prometheus exporter), `kiln stats`,
  `KILN_TRACE=1` startup phase timing, and an optional Prometheus and Grafana
  setup.
- Setup scripts for a Lima Ubuntu 24.04 VM, the Alpine image (pinned release
  key, checksum and signature), XFS storage, services and monitoring.
- `kiln --version` reports the package version and source commit provenance.

### Reviews and tests

- Fixes from two adversarial reviews by AI models (not a professional audit),
  with a manual privileged regression script, `scripts/review-regressions.sh`.

### Benchmarks and papers

- A randomized benchmark harness (`bench/v2.py`) with tests, a published raw
  corpus for one ARM Lima VM, and its analysis in
  [docs/benchmarks.md](docs/benchmarks.md). Results are from a single machine
  and are bounded as described there.
- A design paper and a performance white paper (LaTeX sources and PDFs under
  `docs/`).

### Project

- Apache License 2.0, security policy, contributing guide, release checklist
  and CI on Ubuntu 24.04 x86_64, plus generated third-party dependency notices.
- `lima.yaml` mounts `{{.Home}}/Projects/kiln` instead of one user's absolute
  path. The VM it creates is unchanged for a clone at that location, but the
  file's SHA-256 no longer matches the `lima_config` hash recorded in the
  committed benchmark manifests.
