# kiln architecture

kiln runs AI agent tool calls inside Linux sandboxes. This file records where
it is today, where it's going, and the decisions that shape the path.

## Today: one-shot CLI

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
   restrictions.
2. **A daemon (`kilnd`) will own sandbox state.** Until the API daemon is added,
   the CLI provides the same lifecycle and `kiln gc` reconciliation: it scans
   persistent run directories and removes cgroups and network state whose shim
   has died.
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
| Signals to PID 1 ignored         | Handled: kiln-init                      |
| Zombie processes                 | Handled: kiln-init reaps                |
| Disk or inode exhaustion        | Handled: XFS project block and inode quotas per run |
| I/O bandwidth hog                | Partial: iocost + io.weight wired and accounted; not enforced on this VM's fast disk without a tuned cost model |
| O_DIRECT writes beyond memory.max | Handled: loop device in direct I/O mode (was an OOM kill) |
| Supervisor crash leaves orphans  | Persistent sandboxes: handled (pdeathsig kills PID 1; `kiln gc` removes cgroup, network state and run dir). One-shot `kiln run`: pdeathsig kills the sandbox, but its cgroup, run dir and lease stay until cleaned by hand |
| Shared System V IPC              | Handled: IPC namespace per sandbox      |
| Descriptors inherited from caller| Handled: closed before setup            |
| Host reboot leaves run dirs      | Handled manually by `kiln gc`; automatic daemon startup reconciliation remains open |
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
