//! Sandbox networking: one network namespace per sandbox, joined to a host
//! bridge by a veth pair, with nftables deciding what each sandbox may reach.
//!
//! ```text
//!  sandbox netns           host (VM)                         internet
//!  eth0 10.88.0.N ──veth── kvNNNN ─┐
//!                                  ├─ kiln0 10.88.0.1 ── NAT ── eth0 ──►
//!  eth0 10.88.0.M ──veth── kvMMMM ─┘  (ports isolated from each other)
//! ```
//!
//! The namespace is created before the sandbox's user namespace, so sandbox
//! root can't change its own address, routes or firewall. All configuration is
//! done from the host side with `ip` and `nft`, the same tools you'd type.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::Pid;

const BRIDGE: &str = "kiln0";
const NETWORK: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 0);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
const PREFIX: u8 = 16;
/// On /run (a tmpfs), so leases vanish on reboot along with the bridge and
/// the nftables rules they refer to.
const STATE_DIR: &str = "/run/kiln/net";

/// Created once per boot. `egress` maps each sandbox's IP to its own chain.
const BASE_RULESET: &str = r#"
table inet kiln {
    # Destinations blocked in --net full mode: private networks (including the
    # VM's LAN and the Mac behind it), link-local and cloud metadata.
    set private {
        type ipv4_addr; flags interval
        elements = { 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
                     172.16.0.0/12, 192.168.0.0/16 }
    }
    map egress { type ipv4_addr : verdict; }

    chain forward {
        type filter hook forward priority filter; policy accept;
        # Every packet from a sandbox goes through its current policy, even on
        # an established connection. Leases reuse IPs, and conntrack entries
        # outlive sandboxes, so accepting "established" first would let a new
        # sandbox continue flows only the previous one was allowed.
        iifname "kiln0" ip saddr vmap @egress
        iifname "kiln0" counter reject with icmpx admin-prohibited
        oifname "kiln0" ct state established,related accept
        oifname "kiln0" counter drop
    }
    # Sandboxes may not talk to the host itself (sshd, later kilnd's API).
    chain input {
        type filter hook input priority filter; policy accept;
        iifname "kiln0" ct state established,related accept
        iifname "kiln0" counter reject with icmpx admin-prohibited
    }
    # NAT works in inet tables too (Linux 5.2+), so one table holds it all
    # and the existence check in ensure_bridge covers everything.
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.88.0.0/16 oifname != "kiln0" masquerade
    }
}
"#;

/// What a sandbox may reach.
pub enum Mode {
    /// Loopback only.
    None,
    /// Anything except private and link-local ranges.
    Full,
    /// Only these destinations (plus DNS).
    Allow(Vec<Allowed>),
}

pub struct Allowed {
    /// As written by the user, kept as a rule comment.
    label: String,
    addrs: Vec<String>,
    port: Option<u16>,
}

pub struct Plan {
    mode: Mode,
    resolvers: Vec<Ipv4Addr>,
}

impl Plan {
    /// Builds the plan from `--net` and `--allow`. Hostnames are resolved now,
    /// on the host; see ARCHITECTURE.md for why an egress proxy would be better.
    pub fn new(net: &str, allow: &[String]) -> Result<Self> {
        let mode = match (net, allow.is_empty()) {
            ("none", true) => Mode::None,
            ("none", false) => Mode::Allow(allow.iter().map(|a| parse_allowed(a)).collect::<Result<_>>()?),
            ("full", true) => Mode::Full,
            ("full", false) => bail!("--allow can't be combined with --net full"),
            (other, _) => bail!("invalid --net {other:?}: expected none or full"),
        };
        Ok(Plan { mode, resolvers: host_resolvers() })
    }

    /// Contents for the sandbox's /etc/resolv.conf, if it has a network.
    pub fn resolv_conf(&self) -> Option<String> {
        if matches!(self.mode, Mode::None) || self.resolvers.is_empty() {
            return None;
        }
        Some(self.resolvers.iter().map(|r| format!("nameserver {r}\n")).collect())
    }
}

/// `host`, `host:port`, `1.2.3.4`, `1.2.3.0/24` or any of those with `:port`.
fn parse_allowed(s: &str) -> Result<Allowed> {
    let (dest, port) = match s.rsplit_once(':') {
        Some((d, p)) => (d, Some(p.parse::<u16>().with_context(|| format!("invalid port in --allow {s:?}"))?)),
        None => (s, None),
    };
    let literal = match dest.split_once('/') {
        Some((ip, len)) => ip.parse::<Ipv4Addr>().is_ok() && len.parse::<u8>().is_ok_and(|l| l <= 32),
        None => dest.parse::<Ipv4Addr>().is_ok(),
    };
    let addrs = if literal {
        vec![dest.to_string()]
    } else {
        let mut ips: Vec<String> = (dest, 0)
            .to_socket_addrs()
            .with_context(|| format!("resolve {dest}"))?
            .filter_map(|a| match a.ip() {
                IpAddr::V4(v4) => Some(v4.to_string()),
                IpAddr::V6(_) => None,
            })
            .collect();
        ips.sort();
        ips.dedup();
        if ips.is_empty() {
            bail!("{dest} has no IPv4 address");
        }
        ips
    };
    Ok(Allowed { label: s.to_string(), addrs, port })
}

/// The host's real upstream resolvers. systemd-resolved's 127.0.0.53 only
/// listens in the host's namespace, so read the file it forwards to.
fn host_resolvers() -> Vec<Ipv4Addr> {
    ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"]
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .map(|text| {
            text.lines()
                .filter_map(|l| l.strip_prefix("nameserver")?.trim().parse::<Ipv4Addr>().ok())
                .filter(|ip| !ip.is_loopback())
                .collect::<Vec<_>>()
        })
        .find(|v| !v.is_empty())
        .unwrap_or_default()
}

/// A sandbox's network. Dropping it removes its firewall chain, host veth and
/// IP lease. The namespace itself dies with the sandbox's last process.
pub struct Network {
    ip: Ipv4Addr,
    lease: PathBuf,
}

impl Network {
    fn chain(&self) -> String {
        format!("sb_{}", self.ip.to_string().replace('.', "_"))
    }

    /// The host end of the veth pair. Interface names are capped at 15 bytes;
    /// the IP's host part is unique.
    fn host_if(&self) -> String {
        format!("kv{:04x}", u32::from(self.ip) & 0xffff)
    }

    /// Packets the sandbox tried to send that its policy rejected.
    pub fn blocked_packets(&self) -> u64 {
        let out = Command::new("nft").args(["list", "chain", "inet", "kiln", &self.chain()]).output();
        let Ok(out) = out else { return 0 };
        let text = String::from_utf8_lossy(&out.stdout);
        let words: Vec<&str> = text.split_whitespace().collect();
        words
            .windows(2)
            .filter(|w| w[0] == "packets")
            .filter_map(|w| w[1].parse::<u64>().ok())
            .sum()
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let chain = self.chain();
        let host_if = self.host_if();
        // Each step on its own so one failure doesn't skip the rest.
        let _ = run("nft", &["delete", "element", "inet", "kiln", "egress", &format!("{{ {} }}", self.ip)], None);
        let _ = run("nft", &["delete", "chain", "inet", "kiln", &chain], None);
        // Usually already gone: deleting the sandbox's namespace destroys its
        // end of the pair, which takes this end with it.
        if Path::new("/sys/class/net").join(&host_if).exists() {
            let _ = run("ip", &["link", "del", &host_if], None);
        }
        let _ = fs::remove_file(&self.lease);
    }
}

/// Configures the network namespace of `pid` (a freshly cloned sandbox that
/// is still waiting on its parent). Returns `None` for `--net none`.
pub fn setup(pid: Pid, plan: &Plan) -> Result<Option<Network>> {
    // Inside the namespace: loopback up (it starts down).
    let mut inside = String::from("link set lo up\n");

    let network = if matches!(plan.mode, Mode::None) {
        None
    } else {
        ensure_bridge()?;
        let network = lease()?;
        let host_if = network.host_if();
        let ip = network.ip;

        run(
            "ip",
            &["-batch", "-"],
            Some(&format!(
                "link add {host_if} type veth peer name eth0 netns {pid}\n\
                 link set {host_if} master {BRIDGE}\n\
                 link set dev {host_if} type bridge_slave isolated on\n\
                 link set {host_if} up\n"
            )),
        )
        .context("create veth pair")?;

        inside.push_str(&format!(
            "addr add {ip}/{PREFIX} dev eth0\n\
             link set eth0 up\n\
             route add default via {GATEWAY}\n"
        ));

        run("nft", &["-f", "-"], Some(&policy(&network, plan))).context("apply egress policy")?;
        Some(network)
    };

    let pid_s = pid.to_string();
    run(
        "nsenter",
        &["--target", &pid_s, "--net", "--", "ip", "-batch", "-"],
        Some(&inside),
    )
    .context("configure sandbox network namespace")?;
    Ok(network)
}

/// The sandbox's own nftables chain, reached through the `egress` map.
fn policy(network: &Network, plan: &Plan) -> String {
    let chain = network.chain();
    let rule = |body: &str| format!("add rule inet kiln {chain} {body}\n");
    // Flush in case a crashed run left this IP's chain behind: `add chain` is
    // a no-op on an existing chain, and its old rules would come first.
    let mut nft = format!("add chain inet kiln {chain}\nflush chain inet kiln {chain}\n");

    if !plan.resolvers.is_empty() {
        let dns = set(plan.resolvers.iter().map(|r| r.to_string()));
        nft += &rule(&format!("ip daddr {dns} meta l4proto {{ tcp, udp }} th dport 53 accept comment \"dns\""));
    }
    match &plan.mode {
        Mode::None => {}
        Mode::Full => {
            nft += &rule("ip daddr @private counter reject with icmpx admin-prohibited comment \"private ranges\"");
            nft += &rule("accept");
        }
        Mode::Allow(allowed) => {
            for a in allowed {
                let port = a.port.map(|p| format!(" meta l4proto {{ tcp, udp }} th dport {p}")).unwrap_or_default();
                let label = a.label.replace('"', "");
                nft += &rule(&format!("ip daddr {}{port} accept comment \"{label}\"", set(a.addrs.iter().cloned())));
            }
            nft += &rule("counter reject with icmpx admin-prohibited comment \"not allowed\"");
        }
    }
    nft += &format!("add element inet kiln egress {{ {} : jump {chain} }}\n", network.ip);
    nft
}

fn set(items: impl Iterator<Item = String>) -> String {
    format!("{{ {} }}", items.collect::<Vec<_>>().join(", "))
}

/// Creates the bridge and base ruleset if this boot doesn't have them yet.
/// Held under a lock so two sandboxes starting at once don't both create them.
fn ensure_bridge() -> Result<()> {
    fs::create_dir_all(STATE_DIR).with_context(|| format!("create {STATE_DIR}"))?;
    let lock_file = File::create(Path::new(STATE_DIR).join("lock")).context("create lock")?;
    let _lock = Flock::lock(lock_file, FlockArg::LockExclusive).map_err(|(_, e)| e).context("lock")?;

    if !Path::new("/sys/class/net").join(BRIDGE).exists() {
        run(
            "ip",
            &["-batch", "-"],
            Some(&format!(
                "link add {BRIDGE} type bridge\n\
                 addr add {GATEWAY}/{PREFIX} dev {BRIDGE}\n\
                 link set {BRIDGE} up\n"
            )),
        )
        .context("create bridge")?;
    }
    // Without this the kernel drops packets instead of routing them out.
    fs::write("/proc/sys/net/ipv4/ip_forward", "1").context("enable ip_forward")?;
    if run("nft", &["list", "table", "inet", "kiln"], None).is_err() {
        run("nft", &["-f", "-"], Some(BASE_RULESET)).context("create base ruleset")?;
    }
    Ok(())
}

/// Leases the lowest free address. Creating the lease file with O_EXCL is
/// atomic, so concurrent sandboxes can't get the same IP without a lock.
fn lease() -> Result<Network> {
    let dir = Path::new(STATE_DIR).join("leases");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let first = u32::from(GATEWAY) + 1;
    let last = u32::from(NETWORK) + (1 << (32 - PREFIX)) - 2; // skip broadcast
    for n in first..=last {
        let ip = Ipv4Addr::from(n);
        let path = dir.join(ip.to_string());
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(_) => return Ok(Network { ip, lease: path }),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("create {}", path.display())),
        }
    }
    bail!("no free addresses in {NETWORK}/{PREFIX}")
}

fn run(cmd: &str, args: &[&str], stdin: Option<&str>) -> Result<()> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("run {cmd}"))?;
    if let Some(input) = stdin {
        child.stdin.take().expect("piped").write_all(input.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{cmd} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
