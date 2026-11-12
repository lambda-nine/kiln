# Security policy

## Supported versions

Security fixes go to the `main` branch and the latest release. Older releases
are not patched.

| Version        | Supported |
|----------------|-----------|
| latest release | yes       |
| `main`         | yes       |
| anything older | no        |

## Reporting a vulnerability

Report vulnerabilities privately through GitHub:
<https://github.com/lambda-nine/kiln/security/advisories/new>

Please don't open a public issue, pull request or discussion for a
vulnerability. Include what you can of:

- the kiln commit or release, host distribution and kernel version (`uname -r`)
- the command line and flags used
- what a sandbox could do that it shouldn't, and the steps to reproduce it

kiln is maintained by one person. Responses are best effort, with no
guaranteed response or fix time. When a fix is ready, it is released and
disclosed through the same advisory, with credit if you want it.

## Security boundary today

kiln is an experimental, shared-kernel sandbox runtime. Read this before
relying on it:

- **Shared kernel.** Sandboxes are Linux namespaces, cgroups, seccomp and
  Landlock on the host's kernel. A kernel bug reachable from inside a sandbox
  can compromise the host. There is no VM isolation tier yet.
- **Reviewed, not audited.** The design and code have had adversarial reviews
  by AI models, summarized in the README. No professional security audit has
  been done.
- **Not a boundary for hostile multi-tenant workloads.** Don't use kiln to
  separate mutually untrusted tenants.
- **One shared host UID range.** Every sandbox maps its IDs 0-65535 to the same
  host range, 2000000000-2000065535. The user ID does not separate one sandbox
  from another.
- **Public unicast IPv4 egress.** Full and allowlist modes reject the same
  canonical non-public set before any accept: 0/8, RFC 1918, CGNAT, loopback,
  link-local/metadata, 192.0.0/24, documentation ranges, deprecated
  192.88.99/24 relay space, 198.18/15 benchmarking, multicast and
  reserved/future-use space including limited broadcast. Explicit IPs and
  overlapping prefixes are refused. Hostname answers use the same filter and
  require a remaining public unicast IPv4 address; nft checks every packet,
  including after DNS changes in full mode. Only bridge DNS is reachable on
  the host. IPv6 destinations are unsupported.
- **seccomp denylist.** The filter blocks a list of risky syscalls and
  namespace creation. Everything else is allowed; an allowlist would be
  stricter.
- **Persistent exec descendants.** One serial exec at a time runs in a child
  cgroup, with PID 1 outside it. A trusted bootstrap joins through a
  host-opened `cgroup.procs` and waits for PID 1's release before any image or
  workload instruction runs. Descendants inherit membership and cannot
  migrate: cgroupfs is read-only, control descriptors are close-on-exec and
  closed before the workload runs, and PID 1 is nondumpable. The
  nondumpable protection also relies on PID 1 never exec'ing, so its memory
  stays tied to the host's user namespace rather than the sandbox's; revalidate
  it if PID 1 is ever changed to re-exec. On leader exit,
  client disconnect (including `kilnd` timeout/shutdown), startup failure or
  active `kiln rm`, PID 1 kills and drains the exec cgroup before status,
  reuse or removal. Separate sessions/process groups, `nohup` and double
  forks cannot keep background work alive past that exec; output pipes reach
  EOF after drainage. This is a lifecycle guarantee, not stronger kernel
  isolation: an uninterruptible kernel wait can delay drainage indefinitely.
  One-shot `kiln run` is unchanged.
- **Persistent PID 1 lifecycle.** PID 1 polls one lifetime-scoped signalfd
  beside the control listener and reaps adopted children even while idle.
  `SIGTERM`, `SIGHUP`, `SIGUSR1` and `SIGUSR2` received without an active exec
  stop the sandbox and trigger shim cleanup instead of remaining pending for
  the next command. During an exec they are sent to the command's process
  group; cgroup drainage, not the process group, remains the descendant
  containment boundary. Commands restore the default `SIGPIPE` disposition
  before `exec`. An accepted control request remains idle until admission, so
  a final signal drain prevents pending shutdown from crossing into its
  command. Request framing is nonblocking and polls the same signalfd, with one
  absolute two-second deadline across the header and payload. Invalid
  operations, lengths, reserved bytes, descriptor counts, truncated ancillary
  messages and descriptors attached to a body are rejected; received
  descriptors are owned immediately and close on every error path. A complete
  request may use `shutdown(SHUT_WR)` while reading its response. A full socket
  close remains cancellation for an active exec. Ready busy headers are
  advanced before handling disconnect; before exec cgroup drainage, queued
  listener connections retain busy classification through at most seventeen
  batches of eight before returning idle. Cgroup-wide killing starts before
  finalization, so continuous connectors cannot postpone descendant cleanup.
  Shutdown signals remain queued for idle and cannot relabel completed side
  effects as never started. Partial frames cannot take an idle receive deadline
  ahead of queued removal or become new execs at that transition. Connections
  arriving during cleanup remain eligible for immediate idle reuse.
- **Machine exec status.** Persistent-exec protocol v1 uses bounded typed
  replies and an anonymous private Unix status socket owned only by the host
  CLI. Only three explicit workload descriptors cross into PID 1; bootstrap
  closes control/cgroup/signal descriptors before exec. Workload stdout/stderr
  cannot spoof status, and bootstrap errors cannot pollute workload stderr.
  CLI diagnostics use a separate stream. Malformed, missing or truncated
  status is a protocol failure with unknown command result, never a legacy
  exit-code fallback. Capability checks must cover both the installed CLI and
  an existing sandbox PID 1; package version/provenance alone is insufficient.
  Reply writes are bounded and tolerate peer failure without stopping PID 1.
  Protocol v1 is first supplied by the resulting kiln commit based on
  `3b42552`; see [exact bytes and compatibility](docs/exec-protocol-v1.md).
  Exec options (cwd and environment, capability `0x20`) arrive in an
  exactly sealed memfd, never on a host command line, and are validated by
  the CLI and again by PID 1. The command's `chdir` runs after descriptor
  closure, so it cannot reach an inherited directory through
  `/proc/self/fd/N`; it is resolved with the workload's own credentials,
  Landlock and seccomp inside the sandbox's root. Values are not secret in
  this design: they are visible to the command and to anything that can read
  its environment.
- **Checkpoint leases and image identity.** Operation 6 (bit `0x40`) is a
  root-only control request, like exec. A lease stops command admission, but
  it is not an isolation mechanism. The lease holder is trusted to read the
  source only between Granted and its acknowledgment. Image identity is an
  integrity fingerprint of operator-provisioned content, not a signature.
  The registry, the run references and the layout records are root-only
  files; a damaged or missing record fails closed (unknown image, or not a
  checkpoint source). See [checkpoint-lease-v1.md](docs/checkpoint-lease-v1.md).
- **One-shot terminal passthrough.** `kiln run` preserves the caller's
  standard streams and controlling terminal for interactive use. It blocks
  the terminal-injection ioctls `TIOCSTI` and `TIOCLINUX`, but code in the
  sandbox can still read terminal input while it runs, change terminal
  settings and print escape sequences. Redirecting the three standard streams
  alone does not remove `/dev/tty`; invoke kiln from a noninteractive service
  that allocates no controlling terminal for fully untrusted one-shot
  workloads. Persistent `kiln exec` refuses terminal descriptors until kiln
  has a controlled PTY mode.
- **Host service privilege separation.** Sandbox lifecycle commands still need
  root. Installed `kiln dns` and `kiln metrics` listeners run as distinct system
  users: DNS retains only `CAP_NET_BIND_SERVICE`; the metrics HTTP service has
  no capabilities. Their units use `NoNewPrivileges`, a read-only host
  filesystem, protected home/kernel/cgroups, private temporary files, address
  family restrictions and system-call filters. Root owns their read-only
  policy and snapshot inputs, and sandbox control directories remain 0700.
  Bridge/firewall initialization is a separate root job with `CAP_NET_ADMIN`.
  Metrics collection is a short-lived root job with `CAP_SYS_ADMIN` for XFS
  project-quota reads and `CAP_NET_ADMIN` for nft reads; root ownership opens
  run directories without making them public. These jobs have no listeners,
  fixed operations and restricted writable paths; the collector's syscall
  filter excludes mounting. Their capabilities are still broad host privileges,
  so compromising a collector or setup job remains a host risk. Installed
  metrics can lag by a collection interval; missing or older-than-ten-second
  snapshots omit sandbox samples and expose `kiln_metrics_snapshot_fresh 0`.
  The optional Prometheus and Grafana stack also remains on the host.
- **Shared DNS capacity.** TCP has a 256-stream global bound, a two-stream
  per-source bound and an absolute three-second framing deadline. The final
  sixteen slots admit only a source with no outstanding permit. This prevents
  128 sources each holding two partial frames from exhausting admission, but
  enough distinct first streams can fill the finite reserve. UDP workers are
  separate. Global overload and upstream failure can still deny service.
- **One supported environment.** kiln is developed and dogfooded on Ubuntu
  24.04 with Linux 6.8 or newer, in the Lima VM described in the README. CI
  builds and runs unprivileged tests on Ubuntu 24.04 x86_64. Other
  distributions, kernels and architectures are untested.

[ARCHITECTURE.md](ARCHITECTURE.md) lists known failure modes and which of them
are open.
