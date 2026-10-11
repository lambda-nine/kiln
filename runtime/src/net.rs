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

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::Pid;

const BRIDGE: &str = "kiln0";
const NETWORK: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 0);
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 1);
const PREFIX: u8 = 16;
/// On /run (a tmpfs), so leases vanish on reboot along with the bridge and
/// the nftables rules they refer to.
const STATE_DIR: &str = "/run/kiln/net";

const PRIVATE_RANGES: &str = "10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16";

const FORWARD_RULES: &[&str] = &[
    "type filter hook forward priority filter; policy accept;",
    // The conntrack table is host-wide. Keep one sandbox from filling it with
    // distinct UDP or TCP tuples; the dynamic count follows its source IP.
    "iifname \"kiln0\" ct state new add @connlimit { ip saddr ct count over 256 } counter name \"conntrack_rejected\" counter reject with icmpx admin-prohibited",
    // Every outbound packet goes through the current policy. Conntrack entries
    // outlive leases, so an established-first rule would cross IP reuse.
    "iifname \"kiln0\" ip saddr vmap @egress",
    "iifname \"kiln0\" counter reject with icmpx admin-prohibited",
    "oifname \"kiln0\" ct state established,related accept",
    "oifname \"kiln0\" counter drop",
];

const INPUT_RULES: &[&str] = &[
    "type filter hook input priority filter; policy accept;",
    "iifname \"kiln0\" ct state established,related accept",
    "iifname \"kiln0\" ip daddr 10.88.0.1 meta l4proto { tcp, udp } th dport 53 accept",
    "iifname \"kiln0\" counter reject with icmpx admin-prohibited",
];

const POSTROUTING_RULES: &[&str] = &[
    "type nat hook postrouting priority srcnat; policy accept;",
    "ip saddr 10.88.0.0/16 oifname != \"kiln0\" masquerade",
];

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
    /// The hostname, if it was one; the DNS forwarder will resolve only these.
    host: Option<String>,
    addrs: Vec<String>,
    port: Option<u16>,
}

pub struct Plan {
    mode: Mode,
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
        Ok(Plan { mode })
    }

    /// Contents for the sandbox's /etc/resolv.conf, if it has a network: the
    /// `kiln dns` forwarder on the bridge.
    pub fn resolv_conf(&self) -> Option<String> {
        match self.mode {
            Mode::None => None,
            _ => Some(format!("nameserver {GATEWAY}\n")),
        }
    }

    /// The names this sandbox may resolve, as the forwarder's policy file.
    fn dns_policy(&self) -> String {
        match &self.mode {
            Mode::None => String::new(),
            Mode::Full => "*\n".into(),
            Mode::Allow(allowed) => allowed.iter().filter_map(|a| a.host.as_ref()).map(|h| format!("{h}\n")).collect(),
        }
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
    let host = (!literal).then(|| dest.to_ascii_lowercase());
    Ok(Allowed { label: s.to_string(), host, addrs, port })
}

/// The host's real upstream resolvers. systemd-resolved's 127.0.0.53 only
/// listens in the host's namespace, so read the file it forwards to.
pub fn host_resolvers() -> Vec<Ipv4Addr> {
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

    fn host_if(&self) -> String {
        host_if(self.ip)
    }

    /// Packets the sandbox tried to send that its policy rejected.
    pub fn blocked_packets(&self) -> u64 {
        let out = Command::new("nft").args(["list", "chain", "inet", "kiln", &self.chain()]).output();
        out.map(|o| sum_packets(&String::from_utf8_lossy(&o.stdout))).unwrap_or(0)
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }
}

/// The host end of the veth pair for the sandbox at `ip`. Interface names are
/// capped at 15 bytes; the IP's host part is unique.
pub fn host_if(ip: Ipv4Addr) -> String {
    format!("kv{:04x}", u32::from(ip) & 0xffff)
}

/// The IP of every networked sandbox, by run ID, read from the lease files.
pub fn leases() -> HashMap<String, Ipv4Addr> {
    let Ok(entries) = fs::read_dir(Path::new(STATE_DIR).join("leases")) else { return HashMap::new() };
    entries
        .flatten()
        .filter_map(|e| {
            let ip = e.file_name().to_str()?.parse().ok()?;
            let run = fs::read_to_string(e.path()).ok()?;
            Some((run.trim().to_string(), ip))
        })
        .collect()
}

/// Packet counters from kiln's nftables table, read in one `nft list table`.
#[derive(Default)]
pub struct Rejected {
    /// Per running sandbox: packets its egress policy rejected.
    pub by_sandbox: HashMap<Ipv4Addr, u64>,
    /// The same, summed over every sandbox since boot, including exited ones
    /// (whose chains are gone). From the named counter `egress_rejected`.
    pub egress_total: u64,
    /// Packets from sandboxes to the host itself (the input chain).
    pub host_total: u64,
    /// New flows refused because their source IP already has 256 conntrack
    /// entries. This protects the host-wide table from one sandbox.
    pub conntrack_total: u64,
}

pub fn rejected() -> Rejected {
    let mut found = Rejected::default();
    let Ok(out) = Command::new("nft").args(["list", "table", "inet", "kiln"]).output() else { return found };
    // The listing is nested blocks. Track which top-level block (a chain, a
    // set or a named counter) each line is in by counting braces, and add up
    // the "packets N" of the counters inside it.
    let mut depth = 0;
    let mut block = String::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let words: Vec<&str> = line.split_whitespace().collect();
        if depth == 1 && words.len() >= 2 {
            block = format!("{} {}", words[0], words[1]);
        }
        let packets = sum_packets(line);
        match block.split_once(' ') {
            Some(("counter", "egress_rejected")) => found.egress_total += packets,
            Some(("counter", "conntrack_rejected")) => found.conntrack_total += packets,
            Some(("chain", "input")) => found.host_total += packets,
            Some(("chain", name)) => {
                if let Some(ip) = name.strip_prefix("sb_").and_then(|n| n.replace('_', ".").parse().ok()) {
                    *found.by_sandbox.entry(ip).or_default() += packets;
                }
            }
            _ => {}
        }
        depth += line.matches('{').count();
        depth = depth.saturating_sub(line.matches('}').count());
    }
    found
}

/// Adds up every "packets N" in some `nft list` output.
fn sum_packets(text: &str) -> u64 {
    let words: Vec<&str> = text.split_whitespace().collect();
    words
        .windows(2)
        .filter(|w| w[0] == "packets")
        .filter_map(|w| w[1].parse::<u64>().ok())
        .sum()
}

/// The DNS forwarder's policy file for the sandbox at `ip`.
pub fn dns_policy_path(ip: Ipv4Addr) -> PathBuf {
    Path::new(STATE_DIR).join("dns").join(ip.to_string())
}

impl Drop for Network {
    fn drop(&mut self) {
        let _ = fs::remove_file(dns_policy_path(self.ip));
        let chain = self.chain();
        let host_if = self.host_if();
        // Each step on its own so one failure doesn't skip the rest.
        let _ = run("nft", &["delete", "element", "inet", "kiln", "egress", &format!("{{ {} }}", self.ip)], None);
        let _ = run("nft", &["destroy", "element", "inet", "kiln", "connlimit", &format!("{{ {} }}", self.ip)], None);
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
pub fn setup(pid: Pid, run_id: &str, plan: &Plan) -> Result<Option<Network>> {
    // Inside the namespace: loopback up (it starts down).
    let mut inside = String::from("link set lo up\n");

    let network = if matches!(plan.mode, Mode::None) {
        None
    } else {
        ensure_bridge()?;
        let forwarder = SocketAddr::from((GATEWAY, 53));
        if TcpStream::connect_timeout(&forwarder, Duration::from_millis(200)).is_err() {
            eprintln!("kiln: no DNS forwarder on {forwarder}, so name lookups will fail (sudo systemctl start kiln-dns)");
        }
        let network = lease(run_id)?;
        let policy_file = dns_policy_path(network.ip);
        fs::create_dir_all(policy_file.parent().expect("has parent")).context("create dns policy dir")?;
        fs::write(&policy_file, plan.dns_policy()).context("write dns policy")?;
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
    // Each reject bumps two counters: this chain's own (gone when the sandbox
    // is), and the named counter shared by all sandboxes, which lives as long
    // as the table, so `kiln metrics` can count rejects from exited sandboxes.
    // Adding an existing counter is a no-op, like `add chain`.
    nft += "add counter inet kiln egress_rejected\n";
    let reject = "counter name \"egress_rejected\" counter reject with icmpx admin-prohibited";

    match &plan.mode {
        Mode::None => {}
        Mode::Full => {
            nft += &rule(&format!("ip daddr @private {reject} comment \"private ranges\""));
            nft += &rule("accept");
        }
        Mode::Allow(allowed) => {
            for a in allowed {
                let port = a.port.map(|p| format!(" meta l4proto {{ tcp, udp }} th dport {p}")).unwrap_or_default();
                let label = a.label.replace('"', "");
                nft += &rule(&format!("ip daddr {}{port} accept comment \"{label}\"", set(a.addrs.iter().cloned())));
            }
            nft += &rule(&format!("{reject} comment \"not allowed\""));
        }
    }
    // The connlimit element for this IP counts live conntrack entries, and
    // those outlive a sandbox. Start from a fresh element so a previous
    // sandbox on the same IP can't leave this one over its limit.
    nft += &format!("destroy element inet kiln connlimit {{ {} }}\n", network.ip);
    nft += &format!("add element inet kiln egress {{ {} : jump {chain} }}\n", network.ip);
    nft
}

fn set(items: impl Iterator<Item = String>) -> String {
    format!("{{ {} }}", items.collect::<Vec<_>>().join(", "))
}

fn network_lock() -> Result<Flock<File>> {
    fs::create_dir_all(STATE_DIR).with_context(|| format!("create {STATE_DIR}"))?;
    let lock_file = File::create(Path::new(STATE_DIR).join("lock")).context("create lock")?;
    Flock::lock(lock_file, FlockArg::LockExclusive).map_err(|(_, e)| e).context("lock")
}

/// Creates the bridge and reconciles the complete shared ruleset. Held under a
/// lock so two sandboxes starting at once cannot repair the same objects.
pub fn ensure_bridge() -> Result<()> {
    let _lock = network_lock()?;

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
    reconcile_ruleset().context("reconcile base ruleset")?;
    Ok(())
}

/// Repairs base objects in one nft transaction while preserving active
/// per-sandbox chains and `egress` map elements. Hook chains are replaced only
/// when their stateless listing differs, so their counters survive normal runs.
fn reconcile_ruleset() -> Result<()> {
    let mut nft = String::from(
        "add table inet kiln\n\
         add set inet kiln private { type ipv4_addr; flags interval; }\n\
         flush set inet kiln private\n",
    );
    nft += &format!("add element inet kiln private {{ {PRIVATE_RANGES} }}\n");
    nft += "add map inet kiln egress { type ipv4_addr : verdict; }\n";
    nft += "add counter inet kiln egress_rejected\n";
    nft += "add set inet kiln connlimit { type ipv4_addr; flags dynamic; }\n";
    nft += "add counter inet kiln conntrack_rejected\n";
    for (name, rules) in [
        ("forward", FORWARD_RULES),
        ("input", INPUT_RULES),
        ("postrouting", POSTROUTING_RULES),
    ] {
        if chain_matches(name, rules) {
            continue;
        }
        if nft_object_exists("chain", name) {
            nft += &format!("delete chain inet kiln {name}\n");
        }
        nft += &format!("add chain inet kiln {name} {{ {} }}\n", rules[0]);
        for rule in &rules[1..] {
            nft += &format!("add rule inet kiln {name} {rule}\n");
        }
    }
    run("nft", &["-f", "-"], Some(&nft))
}

fn nft_object_exists(kind: &str, name: &str) -> bool {
    Command::new("nft")
        .args(["list", kind, "inet", "kiln", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn chain_matches(name: &str, expected: &[&str]) -> bool {
    let Ok(out) = Command::new("nft").args(["-s", "list", "chain", "inet", "kiln", name]).output() else {
        return false;
    };
    if !out.status.success() {
        return false;
    }
    let listing = String::from_utf8_lossy(&out.stdout);
    let actual: Vec<&str> = listing
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && *line != "{" && *line != "}" && !line.starts_with("table ") && !line.starts_with("chain "))
        .collect();
    actual == expected
}

/// Leases the lowest free address. Creating the lease file with O_EXCL is
/// atomic, so concurrent sandboxes can't get the same IP without a lock. The
/// file holds the run ID, so `kiln metrics` can tell whose IP it is.
fn lease(run_id: &str) -> Result<Network> {
    let _lock = network_lock()?;
    let dir = Path::new(STATE_DIR).join("leases");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    reconcile_leases(&dir);
    let first = u32::from(GATEWAY) + 1;
    let last = u32::from(NETWORK) + (1 << (32 - PREFIX)) - 2; // skip broadcast
    for n in first..=last {
        let ip = Ipv4Addr::from(n);
        let path = dir.join(ip.to_string());
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let network = Network { ip, lease: path };
                file.write_all(run_id.as_bytes()).context("write lease")?;
                return Ok(network);
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("create {}", path.display())),
        }
    }
    bail!("no free addresses in {NETWORK}/{PREFIX}")
}

/// Removes leases left by a supervisor that died before `Network::drop` ran.
/// A run is stale only when every independent sign of life is gone. Requiring
/// all four avoids reclaiming a lease during setup, while its supervisor is
/// alive but the veth and nft map element do not exist yet.
fn reconcile_leases(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Some(ip) = entry.file_name().to_str().and_then(|s| s.parse::<Ipv4Addr>().ok()) else { continue };
        let Ok(run_id) = fs::read_to_string(entry.path()) else { continue };
        let run_id = run_id.trim();
        let cgroup = Path::new("/sys/fs/cgroup/kiln").join(run_id).exists();
        let veth = Path::new("/sys/class/net").join(host_if(ip)).exists();
        let mapped = nft_has_map_entry(ip);
        if cgroup || veth || mapped || supervisor_alive(run_id) {
            continue;
        }

        let _ = fs::remove_file(dns_policy_path(ip));
        let chain = format!("sb_{}", ip.to_string().replace('.', "_"));
        let _ = run("nft", &["delete", "chain", "inet", "kiln", &chain], None);
        if fs::remove_file(entry.path()).is_ok() {
            eprintln!("kiln: reclaimed stale network lease {ip} from {run_id}");
        }
    }
}

fn nft_has_map_entry(ip: Ipv4Addr) -> bool {
    Command::new("nft")
        .args(["get", "element", "inet", "kiln", "egress", &format!("{{ {ip} }}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn supervisor_alive(run_id: &str) -> bool {
    let Some((_, pid)) = run_id.rsplit_once('-') else { return false };
    let Ok(pid) = pid.parse::<u32>() else { return false };
    let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else { return false };
    cmdline
        .split(|&b| b == 0)
        .next()
        .and_then(|arg0| Path::new(std::str::from_utf8(arg0).ok()?).file_name())
        .is_some_and(|name| name == "kiln")
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
