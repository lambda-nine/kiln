# kiln architecture

kiln runs AI agent tool calls inside Linux sandboxes. This file records where
it is today, where it's going, and the decisions that shape the path.

## Today: one-shot and persistent CLI

The one-shot path is unchanged:

```
sudo kiln run [--memory --cpus --pids --disk --net --allow --read-only] -- <cmd>

 kiln (parent: supervisor)                  child (sandbox PID 1: kiln-init)
 ─────────────────────────                  ────────────────────────────────
 1. check image /var/lib/kiln/images/<name>
 2. run dir /var/lib/kiln/runs/<id>, XFS
    project quota, then upper/ work/ merged/
 3. cgroup /sys/fs/cgroup/kiln/<id> + limits;
    unless --net none: lease an IP, one nft
    batch adds its chain and lists the base
 4. clone3(NEWUTS|NEWPID|NEWNS|NEWNET|NEWIPC ►  close inherited fds, wait
 5.   | INTO_CGROUP): born in its cgroup
 6. netlink: veth with one end in the
    child's netns
 7. byte on the pipe ──────────────────────►  netlink: lo up, eth0 address and
                                              route → cgroup ns → hostname → private
                                              mounts → overlay → /dev + shm →
                                              pivot_root → /proc, net sysctls,
                                              read-only cgroupfs, resolv.conf
                                              unshare(NEWUSER), byte back
 8. write uid_map/gid_map ◄────────────────►  become root in the userns,
                                              pdeathsig, clean env,
                                              no_new_privs, Landlock, seccomp
                                              fork + exec cmd; forward
                                              signals, reap zombies
 9. wait, forwarding SIGTERM/HUP/USR1/USR2
10. cleanup: nft chain, lease, cgroup.kill,
    rmdir cgroup, rm run dir
```

No central sandbox-manager daemon and no database: core state is in the kernel
and a few directories. Non-networked starts need no shared service; networked
starts use the fixed `kiln dns` service, and the optional, read-only
`kiln metrics` service reads state for Prometheus. Each IP lease file holds its
run ID so traffic and rejected packets can be tied to a sandbox.
The parent is the supervisor: if it's killed, `PR_SET_PDEATHSIG` kills the
sandbox too, but its cgroup, run dir and lease are left for a future
reconcile.

`kiln create` uses the same sandbox setup, but detaches a host shim and leaves
PID 1 serving requests over a root-only control socket. The host also creates
`/sys/fs/cgroup/kiln/<id>/exec` and opens its `cgroup.procs`, `cgroup.kill` and
`cgroup.events` before sandbox lockdown. PID 1 stays in the parent sandbox
cgroup; one serial exec at a time uses the reusable child. The parent's
resource limits cover both, without enabling controllers in its subtree.

For each `kiln exec`, a trusted forked bootstrap writes itself to the
host-opened `cgroup.procs`, acknowledges admission, and waits for PID 1's
release before executing any image or workload instruction. Its descendants
inherit membership. Read-only cgroupfs prevents migration, the control
descriptors are close-on-exec and explicitly closed in the bootstrap before
the workload runs, and nondumpable PID 1 prevents workloads from reopening
its descriptors through `/proc/1/fd`.

On leader exit, client disconnect (including a `kilnd` timeout or shutdown),
startup failure, or an active `kiln rm`, PID 1 writes `cgroup.kill` and waits
for `cgroup.events` to report `populated 0`, then reaps exited children. Only
then does it report status, reuse the exec cgroup, or acknowledge removal.
`setsid`, `setpgid`, `nohup` and double forks do not escape this cleanup;
background work never outlives its launching exec, and inherited output pipes
reach EOF after drainage. Process groups only aid signal forwarding. A task
stuck in an uninterruptible kernel wait can delay drainage indefinitely.
Sandbox cleanup and `kiln gc [ID...]` remove nested cgroup directories
children-first. With IDs, GC inspects and removes only that explicit scope;
without them it retains the operator-facing global scan. Both modes recheck
recorded shim identity and liveness immediately before cleanup. Cgroup teardown
checks drainage and directory removal; network teardown verifies nft object,
veth, DNS policy and lease absence. A partial cleanup exits nonzero and retains
the run directory and any unconfirmed lease so a retry can finish it.

PID 1 keeps one signalfd for its whole lifetime and polls it beside the control
listener. It therefore reaps any unexpectedly adopted child even when no exec
is active. `SIGTERM`, `SIGHUP`, `SIGUSR1` or `SIGUSR2` received while idle stop
the sandbox and let the shim clean its resources; none can remain pending for
the next unrelated command. During an exec those signals go to the command's
process group, while the exec cgroup remains the non-escapable cleanup unit.
Commands restore the default `SIGPIPE` disposition before `exec`.
Request reception remains in the idle state: PID 1 drains the signalfd again
at the command-admission boundary, so a signal arriving after `accept()` still
stops the sandbox instead of crossing into the command. Accepted sockets are
nonblocking and PID 1 polls each beside the signalfd. The complete eight-byte
header and payload have one absolute two-second receive deadline, so byte-wise
progress cannot prolong it; a stalled or crashed peer is dropped and the next
`exec` or `rm` is accepted. Framing accepts exactly one SCM_RIGHTS message with
three stdio descriptors for exec, none for removal, rejects ancillary
truncation and descriptors attached to the payload, and closes every received
descriptor on errors. After a complete request, `shutdown(SHUT_WR)` explicitly
means "request finished; response still wanted"; a full close cancels an active
exec. Competing legacy and typed execs are refused from the fixed header
while busy: received descriptors close before the busy reply, and no body
bytes are consumed. A partial competing body cannot delay queued removal.

The shim atomically publishes `shim.start` followed by `shim.pid`, using a
same-directory rename for each file; the PID file is the completed identity
record. `kiln ls` and `kiln gc` call a shim live only when that PID's current
`/proc/<pid>/stat` start time still matches the record and the process is not a
zombie. A different process reusing the PID during the same boot is stale.
Once the PID marker exists, missing, malformed or unreadable identity metadata
is indeterminate and fails the operation rather than authorizing cleanup. The
Linux start time is boot-relative, however: without a recorded boot identity,
a coincidental PID/start-time match after reboot can still be retained as live.

[Persistent-exec protocol v1](docs/exec-protocol-v1.md) adds capability probe
operation 3 and typed exec operation 4 alongside unchanged legacy operations.
PID 1 retains exit versus signal/core status and uses a CLOEXEC bootstrap pipe
for admission/release/stdio/exec errors, keeping runtime diagnostics out of
workload stderr. All post-fork paths drain and reap before a command result;
cleanup failure reports unconfirmed cleanup and ends PID 1. Replies are bounded
to 2088 bytes and writes are nonblocking, signal-aware and request-local on
peer failure. Busy requests receive typed rejection; probes work during exec.
The machine CLI relays one frame on a private status socket, sends only three
explicit workload descriptors into PID 1 and preserves human exit projections.
Capabilities describe the responding binary/PID 1, never a minimum package
version. Protocol v1 is first supplied by the resulting kiln commit based on
`3b42552`; old live PID 1 processes must be recreated explicitly.

## Target

```
                    LLM API
                       ▲
 ┌─────────────────────┴───────────────────────┐
 │ Harness: agent loop + long-term memory      │
 │ tools: exec, read_file, write_file, diff    │
 └──────────────┬──────────────────────────────┘
                │ gRPC over a Unix socket
 ┌──────────────▼──────────────────────────────┐   per node
 │ kilnd (daemon)                              │
 │  sandbox manager: create/exec/stop/delete   │
 │    state machine + reconcile on startup     │
 │  image store + overlay snapshots            │
 │  cgroup manager · network manager           │
 │  run records (SQLite) · /metrics            │
 └──────────────┬──────────────────────────────┘
                │ one shim process per sandbox
 ┌──────────────▼──────────────────────────────┐
 │ kiln-shim → kiln-init (sandbox PID 1)       │
 └──────────────┬──────────────────────────────┘
                ▼
 kernel: namespaces · cgroups v2 · overlayfs · seccomp · Landlock · nftables

 Multi-node: k3s across several VMs; a Go operator with a Sandbox CRD places
 sandboxes on nodes; kilnd runs on each node as a DaemonSet.
```

## Decisions

1. **Sandboxes live for an agent session, not one command.** Agents need state
   between tool calls (installed packages, files), so a sandbox is created once
   and many commands run in it, like `docker exec`. `kiln exec` doesn't enter
   from the host with `setns`: it hands the command and its stdio to the
   sandbox's PID 1 over a control socket, so every command inherits the same
   restrictions. Files survive between commands; background processes do not.
   The per-exec cgroup must drain before another exec starts.
2. **A daemon (`kilnd`) will own sandbox state.** Until the API daemon is added,
   the CLI provides the same lifecycle and `kiln gc` reconciliation: it scans
   persistent run directories and removes cgroups and network state whose shim
   has died. `kiln gc ID...` gives the daemon a scoped form that cannot remove
   an unlisted operator-owned sandbox.
3. **One shim process per sandbox.** `kiln create` detaches a small host shim
   that owns cgroup and network cleanup while PID 1 serves `kiln exec` requests
   through a root-only Unix socket. This also lets sandboxes survive the CLI
   process that created them and later a `kilnd` crash or upgrade.
4. **Pluggable isolation backend.** Containers share the host kernel. The
   backend sits behind a trait so a Firecracker microVM backend can be added
   with the same API.
5. **Network egress denied by default**, with a per-sandbox allowlist and an
   egress proxy that logs requests.
6. **The overlay upper layer is the audit log.** It is an exact diff of what a
   sandbox changed, and the basis for snapshots later.

## Failure modes

| Failure                          | Status                                  |
|----------------------------------|-----------------------------------------|
| Memory hog                       | Handled: group OOM kill, reported       |
| Fork bomb                        | Handled: `pids.max`; a refused persistent exec leaves PID 1 and its overlay alive |
| CPU hog                          | Handled: `cpu.max` throttling           |
| Signals to PID 1 ignored         | Handled: kiln-init forwards them to an active command group; forwarded signals received while idle stop the sandbox instead of leaking into the next exec |
| Incomplete or malformed control request wedges PID 1 | Handled: nonblocking signal-aware framing has one absolute two-second header-plus-payload deadline; malformed frames and ancillary data are dropped without leaking descriptors |
| Zombie processes                 | Handled: lifetime signalfd loop reaps while busy or idle; exec cleanup also drains and reaps before reuse |
| Persistent exec descendants survive completion or disconnect | Handled: gated admission to the exec cgroup; PID 1 uses `cgroup.kill` and waits for `populated 0` before status or reuse, including normal leader exit, startup failure and `kilnd` timeout/shutdown |
| Active `kiln rm` leaves exec descendants | Handled: PID 1 interrupts the active exec and drains its cgroup before acknowledging removal; cleanup/GC removes child cgroup directories first |
| Descendants hold exec output pipes open | Handled: all descendants are killed and drained before completion, including separate sessions/process groups, `nohup` and double forks |
| Task stuck in uninterruptible kernel sleep | Limit: SIGKILL cannot finish until the kernel wait ends; cgroup drainage and removal have no fixed time bound |
| Disk or inode exhaustion        | Handled: XFS project block and inode quotas per run |
| I/O bandwidth hog                | Partial: iocost + io.weight wired and accounted; not enforced on this VM's fast disk without a tuned cost model |
| O_DIRECT writes beyond memory.max | Handled: loop device in direct I/O mode (was an OOM kill) |
| Supervisor crash leaves orphans  | Persistent sandboxes: handled (pdeathsig kills PID 1; `kiln gc` removes cgroup, network state and run dir). One-shot `kiln run`: pdeathsig kills the sandbox, but its cgroup, run dir and lease stay until cleaned by hand |
| Shared System V IPC              | Handled: IPC namespace per sandbox      |
| Descriptors inherited from caller| Handled: closed before setup            |
| Host reboot leaves run dirs      | Partial: `kiln gc` rejects same-boot PID reuse, but a coincidental PID/start-time match across boots is retained for manual review; boot identity and automatic daemon startup reconciliation remain open |
| Compromised image download       | Reduced: pinned Alpine signature, strict basename and atomic staged install |
| Sandbox escape                   | Reduced: userns, seccomp, Landlock, network namespace |
| Data exfiltration over network   | Reduced: no network by default; with `--allow`, only allowed names and their subdomains resolve and egress is restricted to their resolved IPs; `--net full` permits public hosts |
| Reaching the host or LAN         | Handled: only kiln's DNS forwarder on 10.88.0.1:53 is reachable |
| Reused IP inheriting old flows   | Handled: policy checked on every outbound packet, not just new flows |
| Conntrack table exhaustion       | Handled: nft dynamic count limits each sandbox IP to 256 tracked flows |
| Partial or modified base firewall| Handled: shared nft objects and hook chains reconcile under the network lock |
| Sandbox-to-sandbox traffic       | Handled: bridge port isolation |
| Allowlist drift (CDN IPs change) | Open: hostnames resolve once at start. Next step: the DNS forwarder adds the IPs it resolves to the sandbox's nft set |
| DNS tunneling                    | Handled with `--allow` (only allowed names and their subdomains resolve); logged but allowed with `--net full` |
| Kernel attack surface            | Reduced: seccomp denylist; an allowlist would be stricter |
| Sandboxes attacking each other   | Partial: all share one host ID range; per-sandbox ranges need idmapped mounts |

## Build order

~~kiln-init~~ → ~~disk quota~~ → ~~user namespaces~~ → ~~seccomp/Landlock~~ → ~~networking~~ →
~~metrics~~ → kilnd with long-lived sandboxes and exec → harness (with memory;
first user is the idea-marathon app) → ~~cold-start work~~ ([docs/benchmarks.md](docs/benchmarks.md);
a pool of pre-created sandboxes in kilnd is the next step) → k3s operator.

### Public unicast IPv4 egress invariant

The canonical `NON_PUBLIC_IPV4_RANGES` set in `validation.rs` drives literal
and prefix overlap checks, hostname-answer filtering, and the nft `@private`
set (the name is retained for upgrades). It covers 0/8, RFC 1918, CGNAT,
loopback, link-local/metadata, all of 192.0.0/24, documentation ranges,
deprecated 192.88.99/24 relay space, 198.18/15 benchmarking, 224/4 multicast,
and 240/4 reserved/future-use including limited broadcast. Every networked
mode rejects that set before any allowlist or full-mode accept. Hostnames must
have a public unicast IPv4 answer; non-public answers are discarded. The
packet-time guard also prevents a public-first hostname from rebinding into
the deny set in full mode. The bridge DNS service is the only permitted
host-side exception. IPv6 destinations are unsupported.

### Shared DNS admission

The DNS forwarder reserves twelve UDP workers and four TCP workers in separate
pools. Both queues schedule by source IP in round-robin order, with at most one
running query per source. UDP permits two queued/running queries per source
and 256 queued globally. TCP has at most 256 streams globally and two per
source across partial framing, queued queries and running work. A single
nonblocking reactor reads every partial stream; a slow prefix or body consumes
no worker. Expired streams and queued jobs release their permits. A TCP
frame's prefix and body share one absolute three-second deadline from accept,
including queue time, and query/upstream response frames are capped at 4096
bytes before allocation. Upstream calls can still occupy workers for three
seconds, and global capacity limits can drop queries; scheduling fairness is
not a service guarantee when all capacity or the upstream is unavailable.

### Busy control admission

While an exec runs, PID 1 polls its active client, signalfd, bootstrap pipe,
listener and at most sixteen incomplete busy headers together. It accepts at
most eight new connections per wake and evicts the oldest incomplete header
when the table is full. Headers advance only on nonblocking reads; each keeps
one absolute two-second deadline. A complete remove is selected before other
completed headers are answered, regardless of older partial clients. Competing
exec bodies are never read or allocated. Pending streams and received
descriptors close when the active exec ends; they cannot turn into later execs.

### Persistent-create certainty

Global CLI capabilities add bit 4 (`0x10`) for persistent-create preflight
certainty. `kiln create` exits 124 with empty stdout only for CLI/config
validation, image validation or other errors before `container::new_id`.
No sandbox ID, shim, cgroup, run directory, network lease or quota allocation
has been attempted. The explicit error marker is applied only on that side
of the boundary; errors after `new_id`, signals and missing/malformed results
remain ambiguous even if cleanup appears to have succeeded. A caller must
negotiate the capability before trusting the direct child's exit 124. Other
commands do not acquire this exit contract.

### Host service privileges

Installed listeners use separate system users: `kiln-dns` has only
`CAP_NET_BIND_SERVICE`, and `kiln-metrics` has no capabilities. Both have a
read-only host filesystem, protected home/kernel/cgroups, private temporary
files, an address-family allowlist and a system-call filter. Neither may write
DNS policies, metrics snapshots or sandbox control state.

The short-lived root `kiln-network-setup` job prepares the bridge, forwarding
sysctl and nft rules with `CAP_NET_ADMIN` before DNS starts. It has no listener.
`kiln-metrics-collect` also has no listener: once a second it publishes a
root-owned atomic snapshot under `/run/kiln-metrics`. It needs `CAP_NET_ADMIN`
for nft reads and `CAP_SYS_ADMIN` for XFS project-quota reads, and root ownership
to open 0700 run directories. Its filesystem writes are restricted to the
snapshot directory and its syscall filter excludes mounting. The HTTP service
only reads the snapshot; `kiln_metrics_snapshot_fresh` becomes zero and sandbox
samples are omitted if collection is missing or more than ten seconds old.
Direct `kiln metrics` without `--snapshot`, and `kiln stats`, still read the
kernel synchronously with the caller's privileges.
