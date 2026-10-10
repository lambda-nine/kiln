//! `kiln metrics` and `kiln stats`: what running sandboxes are using, read
//! straight from the kernel.
//!
//! Nothing here keeps state. Every scrape reads the same files you'd `cat`:
//!
//! - **cgroup v2 files** in /sys/fs/cgroup/kiln/<run-id>/: `memory.current`,
//!   `cpu.stat`, `pids.current`, `io.stat`, the `*.pressure` files and so on.
//!   The parent, /sys/fs/cgroup/kiln, is hierarchical: its `memory.events`
//!   and `cpu.stat` include sandboxes that already exited. Most runs are
//!   short, so those parent counters are the only reliable way to count
//!   things like OOM kills that happen just before a cgroup disappears.
//!   Not everything is hierarchical, though: the parent's `nr_throttled`
//!   only counts the parent's own limit, so throttling is per sandbox only.
//! - **XFS project quotas** for disk use (`quotactl_fd`, see quota.rs).
//! - **The host end of each veth pair** for network traffic
//!   (/sys/class/net/kvNNNN/statistics).
//! - **nftables counters** for packets the egress policy rejected.
//!
//! The output is the Prometheus text format, written by hand: one `# HELP`
//! and `# TYPE` line per metric, then one line per labelled sample.
//!
//! ```text
//! # HELP kiln_sandbox_memory_bytes Memory in use, page cache included (memory.current).
//! # TYPE kiln_sandbox_memory_bytes gauge
//! kiln_sandbox_memory_bytes{run="186d4c2a1b3e0f00-4242"} 2265088
//! ```
//!
//! Metrics named `_total` are counters: they only go up, and Prometheus's
//! `rate()` turns them into per-second values. The rest are gauges.

use std::collections::HashMap;
use std::fmt::{Display, Write as _};
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, sleep};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use crate::cgroup::{self, read_flat, read_value};
use crate::container;
use crate::net;
use crate::quota;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:9840";
const HTTP_WORKERS: usize = 4;
const HTTP_QUEUE_CAPACITY: usize = 32;

/// Everything known about one running sandbox.
struct Sandbox {
    run: String,
    started: Option<f64>,
    memory: Option<u64>,
    memory_peak: Option<u64>,
    memory_max: Option<u64>,
    memory_stat: HashMap<String, u64>,
    memory_events: HashMap<String, u64>,
    cpu_stat: HashMap<String, u64>,
    /// Cores, from `cpu.max` ("<quota> <period>"). `None` = no limit.
    cpu_limit: Option<f64>,
    pids: Option<u64>,
    pids_peak: Option<u64>,
    pids_max: Option<u64>,
    pids_events: HashMap<String, u64>,
    io: Vec<IoStat>,
    /// (resource, "some" or "full", microseconds stalled).
    pressure: Vec<(&'static str, String, u64)>,
    disk: Option<quota::Usage>,
    net: Option<Net>,
}

/// One line of `io.stat`: bytes and operations on one block device.
struct IoStat {
    device: String,
    counts: HashMap<String, u64>,
}

struct Net {
    ip: Ipv4Addr,
    /// Counters of the host end of the veth pair.
    host_side: HashMap<&'static str, u64>,
    rejected: u64,
}

/// Totals over all sandboxes, read from the parent cgroup.
struct All {
    memory: Option<u64>,
    memory_events: HashMap<String, u64>,
    cpu_stat: HashMap<String, u64>,
    io: Vec<IoStat>,
    rejected: net::Rejected,
}

fn collect() -> (Vec<Sandbox>, All) {
    let leases = net::leases();
    let rejected = net::rejected();
    let sandboxes = cgroup::sandboxes()
        .into_iter()
        .map(|(run, dir)| {
            let net = leases.get(&run).map(|&ip| Net {
                ip,
                host_side: veth_counters(&net::host_if(ip)),
                rejected: rejected.by_sandbox.get(&ip).copied().unwrap_or(0),
            });
            Sandbox {
                started: container::run_started(&run),
                memory: read_value(&dir, "memory.current"),
                memory_peak: read_value(&dir, "memory.peak"),
                memory_max: read_value(&dir, "memory.max"),
                memory_stat: read_flat(&dir, "memory.stat"),
                memory_events: read_flat(&dir, "memory.events"),
                cpu_stat: read_flat(&dir, "cpu.stat"),
                cpu_limit: cpu_limit(&dir),
                pids: read_value(&dir, "pids.current"),
                pids_peak: read_value(&dir, "pids.peak"),
                pids_max: read_value(&dir, "pids.max"),
                pids_events: read_flat(&dir, "pids.events"),
                io: io_stat(&dir),
                pressure: pressure(&dir),
                disk: quota::usage(&container::run_dir(&run)),
                net,
                run,
            }
        })
        .collect();
    let parent = cgroup::parent_dir();
    let all = All {
        memory: read_value(&parent, "memory.current"),
        memory_events: read_flat(&parent, "memory.events"),
        cpu_stat: read_flat(&parent, "cpu.stat"),
        io: io_stat(&parent),
        rejected,
    };
    (sandboxes, all)
}

/// `cpu.max` is "<quota> <period>" in microseconds, or "max <period>".
fn cpu_limit(dir: &Path) -> Option<f64> {
    let text = fs::read_to_string(dir.join("cpu.max")).ok()?;
    let (quota, period) = text.trim().split_once(' ')?;
    Some(quota.parse::<f64>().ok()? / period.parse::<f64>().ok()?)
}

/// `io.stat` has one line per device: "253:0 rbytes=1 wbytes=2 rios=3 ...".
/// Devices are named by major:minor; sysfs knows their names (vda, loop0).
fn io_stat(dir: &Path) -> Vec<IoStat> {
    let text = fs::read_to_string(dir.join("io.stat")).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let dev = fields.next()?;
            let counts = fields
                .filter_map(|f| {
                    let (k, v) = f.split_once('=')?;
                    Some((k.to_string(), v.parse().ok()?))
                })
                .collect();
            Some(IoStat { device: device_name(dev), counts })
        })
        .collect()
}

fn device_name(dev: &str) -> String {
    let uevent = fs::read_to_string(format!("/sys/dev/block/{dev}/uevent")).unwrap_or_default();
    uevent
        .lines()
        .find_map(|l| l.strip_prefix("DEVNAME="))
        .map_or_else(|| dev.to_string(), str::to_string)
}

/// Pressure stall information (PSI). Each `<resource>.pressure` file says how
/// long tasks in the cgroup were stalled waiting for that resource:
///   some avg10=0.00 avg60=0.00 avg300=0.00 total=12345
///   full avg10=0.00 avg60=0.00 avg300=0.00 total=0
/// "some" = at least one task was stalled, "full" = all of them were. `total`
/// is in microseconds and only goes up.
fn pressure(dir: &Path) -> Vec<(&'static str, String, u64)> {
    let mut found = Vec::new();
    for resource in ["cpu", "memory", "io"] {
        let text = fs::read_to_string(dir.join(format!("{resource}.pressure"))).unwrap_or_default();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let Some(kind) = fields.next() else { continue };
            if let Some(total) = fields.find_map(|f| f.strip_prefix("total=")?.parse().ok()) {
                found.push((resource, kind.to_string(), total));
            }
        }
    }
    found
}

fn veth_counters(host_if: &str) -> HashMap<&'static str, u64> {
    let dir = Path::new("/sys/class/net").join(host_if).join("statistics");
    ["rx_bytes", "tx_bytes", "rx_packets", "tx_packets"]
        .into_iter()
        .filter_map(|name| Some((name, read_value(&dir, name)?)))
        .collect()
}

/// Builds the Prometheus text format, one metric family at a time.
#[derive(Default)]
pub struct Exposition {
    out: String,
}

impl Exposition {
    pub fn family(&mut self, name: &str, kind: &str, help: &str) {
        let _ = writeln!(self.out, "# HELP {name} {help}\n# TYPE {name} {kind}");
    }

    pub fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl Display) {
        self.out.push_str(name);
        if !labels.is_empty() {
            let pairs: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape(v))).collect();
            let _ = write!(self.out, "{{{}}}", pairs.join(","));
        }
        let _ = writeln!(self.out, " {value}");
    }

    pub fn finish(self) -> String {
        self.out
    }
}

/// Label values escape backslash, double quote and newline.
fn escape(v: &str) -> String {
    v.replace('\\', r"\\").replace('"', "\\\"").replace('\n', r"\n")
}

/// Renders the current state of all sandboxes as Prometheus metrics.
fn render() -> String {
    let (sandboxes, all) = collect();
    let mut m = Exposition::default();

    // One family per metric, with one sample per sandbox that has a value.
    // `get` picks the value out of a sandbox; `None` skips it (no limit set,
    // file missing, sandbox not networked).
    let mut per_sandbox = |name: &str, kind: &str, help: &str, get: &dyn Fn(&Sandbox) -> Option<f64>| {
        m.family(name, kind, help);
        for s in &sandboxes {
            if let Some(v) = get(s) {
                m.sample(name, &[("run", &s.run)], v);
            }
        }
    };
    let micros = |v: u64| v as f64 / 1e6;
    let flat = |map: &HashMap<String, u64>, key: &str| map.get(key).map(|&v| v as f64);

    per_sandbox("kiln_sandbox_start_time_seconds", "gauge", "When the sandbox started, in seconds since the Unix epoch (from the run ID).", &|s| s.started);
    per_sandbox("kiln_sandbox_memory_bytes", "gauge", "Memory in use, page cache included (memory.current).", &|s| s.memory.map(|v| v as f64));
    per_sandbox("kiln_sandbox_memory_peak_bytes", "gauge", "Highest memory use so far (memory.peak).", &|s| s.memory_peak.map(|v| v as f64));
    per_sandbox("kiln_sandbox_memory_limit_bytes", "gauge", "Memory limit (memory.max). Absent when unlimited.", &|s| s.memory_max.map(|v| v as f64));
    per_sandbox("kiln_sandbox_memory_max_events_total", "counter", "Times memory use hit memory.max and the kernel had to reclaim (memory.events max).", &|s| flat(&s.memory_events, "max"));
    per_sandbox("kiln_sandbox_oom_kills_total", "counter", "Processes killed by the OOM killer (memory.events oom_kill).", &|s| flat(&s.memory_events, "oom_kill"));
    per_sandbox("kiln_sandbox_cpu_limit_cores", "gauge", "CPU limit in cores (cpu.max quota / period). Absent when unlimited.", &|s| s.cpu_limit);
    per_sandbox("kiln_sandbox_cpu_periods_total", "counter", "100 ms enforcement periods in which the sandbox ran (cpu.stat nr_periods).", &|s| flat(&s.cpu_stat, "nr_periods"));
    per_sandbox("kiln_sandbox_cpu_throttled_periods_total", "counter", "Periods in which the sandbox used up its quota and was paused (cpu.stat nr_throttled).", &|s| flat(&s.cpu_stat, "nr_throttled"));
    per_sandbox("kiln_sandbox_cpu_throttled_seconds_total", "counter", "Time the sandbox spent paused by its CPU limit (cpu.stat throttled_usec).", &|s| s.cpu_stat.get("throttled_usec").map(|&v| micros(v)));
    per_sandbox("kiln_sandbox_pids", "gauge", "Processes and threads (pids.current).", &|s| s.pids.map(|v| v as f64));
    per_sandbox("kiln_sandbox_pids_peak", "gauge", "Most processes and threads at once (pids.peak).", &|s| s.pids_peak.map(|v| v as f64));
    per_sandbox("kiln_sandbox_pids_limit", "gauge", "Process and thread limit (pids.max). Absent when unlimited.", &|s| s.pids_max.map(|v| v as f64));
    per_sandbox("kiln_sandbox_pids_limit_hits_total", "counter", "fork() or clone() calls refused by pids.max: a fork bomb shows up here (pids.events max).", &|s| flat(&s.pids_events, "max"));
    per_sandbox("kiln_sandbox_disk_used_bytes", "gauge", "Bytes the sandbox has written to its upper layer (XFS project quota).", &|s| s.disk.as_ref().map(|d| d.used as f64));
    per_sandbox("kiln_sandbox_disk_limit_bytes", "gauge", "Disk limit (XFS project quota hard limit). Absent when unlimited.", &|s| s.disk.as_ref().and_then(|d| d.limit).map(|v| v as f64));
    per_sandbox("kiln_sandbox_egress_rejected_packets_total", "counter", "Packets the sandbox sent that its egress policy rejected (its nftables chain).", &|s| s.net.as_ref().map(|n| n.rejected as f64));

    // These have a second label, so they're written out by hand.
    m.family("kiln_sandbox_cpu_seconds_total", "counter", "CPU time used, by mode (cpu.stat user_usec, system_usec).");
    for s in &sandboxes {
        for mode in ["user", "system"] {
            if let Some(&v) = s.cpu_stat.get(&format!("{mode}_usec")) {
                m.sample("kiln_sandbox_cpu_seconds_total", &[("run", &s.run), ("mode", mode)], micros(v));
            }
        }
    }

    m.family("kiln_sandbox_memory_stat_bytes", "gauge", "Memory by kind (memory.stat): anon is process memory, file is page cache, shmem includes /dev/shm and tmpfs.");
    for s in &sandboxes {
        for kind in ["anon", "file", "shmem", "kernel", "sock"] {
            if let Some(&v) = s.memory_stat.get(kind) {
                m.sample("kiln_sandbox_memory_stat_bytes", &[("run", &s.run), ("kind", kind)], v);
            }
        }
    }

    io_families(&mut m, "kiln_sandbox", sandboxes.iter().flat_map(|s| s.io.iter().map(|io| (Some(s.run.as_str()), io))));

    m.family("kiln_sandbox_pressure_stalled_seconds_total", "counter", "Time tasks were stalled waiting for a resource (PSI, <resource>.pressure). some = at least one task, full = all of them.");
    for s in &sandboxes {
        for (resource, kind, usec) in &s.pressure {
            m.sample("kiln_sandbox_pressure_stalled_seconds_total", &[("run", &s.run), ("resource", resource), ("kind", kind)], micros(*usec));
        }
    }

    // The host's view of the veth pair is mirrored: what the host end
    // receives (rx) is what the sandbox sent.
    for (name, host_side, help) in [
        ("kiln_sandbox_network_transmit_bytes_total", "rx_bytes", "Bytes the sandbox sent (rx on the host end of its veth)."),
        ("kiln_sandbox_network_receive_bytes_total", "tx_bytes", "Bytes the sandbox received (tx on the host end of its veth)."),
        ("kiln_sandbox_network_transmit_packets_total", "rx_packets", "Packets the sandbox sent, rejected ones included."),
        ("kiln_sandbox_network_receive_packets_total", "tx_packets", "Packets the sandbox received."),
    ] {
        m.family(name, "counter", help);
        for s in &sandboxes {
            if let Some(n) = &s.net
                && let Some(v) = n.host_side.get(host_side)
            {
                m.sample(name, &[("run", &s.run), ("ip", &n.ip.to_string())], v);
            }
        }
    }

    // Totals over all sandboxes, exited ones included.
    m.family("kiln_sandboxes_running", "gauge", "Sandboxes with a cgroup under /sys/fs/cgroup/kiln.");
    m.sample("kiln_sandboxes_running", &[], sandboxes.len());
    let mut total = |name: &str, kind: &str, help: &str, value: Option<f64>| {
        if let Some(v) = value {
            m.family(name, kind, help);
            m.sample(name, &[], v);
        }
    };
    total("kiln_all_memory_bytes", "gauge", "Memory in use by all sandboxes (memory.current of /sys/fs/cgroup/kiln).", all.memory.map(|v| v as f64));
    total("kiln_all_oom_kills_total", "counter", "OOM kills in all sandboxes since boot, exited ones included (hierarchical memory.events of the parent cgroup).", flat(&all.memory_events, "oom_kill"));
    total("kiln_all_memory_max_events_total", "counter", "Times any sandbox hit its memory.max since boot (hierarchical memory.events max).", flat(&all.memory_events, "max"));
    total("kiln_all_cpu_seconds_total", "counter", "CPU time used by all sandboxes since boot, exited ones included (cpu.stat usage_usec of the parent cgroup).", all.cpu_stat.get("usage_usec").map(|&v| micros(v)));
    total("kiln_all_egress_rejected_packets_total", "counter", "Packets rejected by any sandbox's egress policy since boot (nftables named counter egress_rejected).", Some(all.rejected.egress_total as f64));
    total("kiln_all_host_rejected_packets_total", "counter", "Packets from sandboxes to the host itself that were rejected (nftables input chain).", Some(all.rejected.host_total as f64));
    io_families(&mut m, "kiln_all", all.io.iter().map(|io| (None, io)));

    m.finish()
}

/// `<prefix>_io_bytes_total` and `<prefix>_io_operations_total`, labelled
/// with the device and read/write (and the run, for per-sandbox ones).
fn io_families<'a>(m: &mut Exposition, prefix: &str, rows: impl Iterator<Item = (Option<&'a str>, &'a IoStat)> + Clone) {
    for (unit, read, write) in [("bytes", "rbytes", "wbytes"), ("operations", "rios", "wios")] {
        let name = format!("{prefix}_io_{unit}_total");
        m.family(&name, "counter", &format!("Block I/O {unit} by device and direction (io.stat {read}, {write})."));
        for (run, io) in rows.clone() {
            for (op, key) in [("read", read), ("write", write)] {
                let Some(v) = io.counts.get(key) else { continue };
                let mut labels = vec![("device", io.device.as_str()), ("op", op)];
                if let Some(run) = run {
                    labels.insert(0, ("run", run));
                }
                m.sample(&name, &labels, v);
            }
        }
    }
}

/// `kiln metrics`: serve `render()` at /metrics for Prometheus to scrape.
pub fn serve_metrics(listen: &str) -> Result<()> {
    serve(listen, render)
}

/// A minimal HTTP/1.1 server: enough for Prometheus, which sends one GET per
/// scrape. A bounded worker pool prevents slow clients from serializing all
/// scrapes without allowing connections to create unbounded host threads.
pub fn serve(listen: &str, render: fn() -> String) -> Result<()> {
    let listener = TcpListener::bind(listen).with_context(|| format!("listen on {listen}"))?;
    println!("kiln: serving metrics on http://{listen}/metrics");
    let (streams_tx, streams_rx) = mpsc::sync_channel(HTTP_QUEUE_CAPACITY);
    let streams_rx = Arc::new(Mutex::new(streams_rx));
    for _ in 0..HTTP_WORKERS {
        let streams_rx = Arc::clone(&streams_rx);
        thread::spawn(move || loop {
            let stream = {
                let receiver = streams_rx.lock().unwrap_or_else(|e| e.into_inner());
                receiver.recv()
            };
            match stream {
                Ok(stream) => {
                    let _ = handle(stream, render);
                }
                Err(_) => return,
            }
        });
    }
    for stream in listener.incoming().flatten() {
        // A scrape client will retry if all workers and queue slots are busy.
        let _ = streams_tx.try_send(stream);
    }
    Ok(())
}

fn handle(mut stream: TcpStream, render: fn() -> String) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    // Read until the blank line that ends the request headers. A GET has no
    // body, so that's the whole request.
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") && request.len() < 8192 {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
    }
    // The request line: "GET /metrics HTTP/1.1".
    let request = String::from_utf8_lossy(&request);
    let mut parts = request.split_whitespace();
    let (status, content_type, body) = match (parts.next(), parts.next()) {
        // Version 0.0.4 is the Prometheus text format.
        (Some("GET"), Some("/metrics")) => ("200 OK", "text/plain; version=0.0.4; charset=utf-8", render()),
        (Some("GET"), Some("/")) => ("200 OK", "text/plain; charset=utf-8", "kiln metrics: see /metrics\n".to_string()),
        _ => ("404 Not Found", "text/plain; charset=utf-8", "not found\n".to_string()),
    };
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )?;
    Ok(())
}

/// `kiln stats`: a table of running sandboxes, like `docker stats --no-stream`.
/// CPU % needs two readings of a counter, so this samples twice, a second apart.
pub fn print_stats() {
    let (before, _) = collect();
    let start = SystemTime::now();
    sleep(Duration::from_secs(1));
    let (after, _) = collect();
    let elapsed = start.elapsed().unwrap_or(Duration::from_secs(1)).as_secs_f64();

    if after.is_empty() {
        println!("no running sandboxes");
        return;
    }
    let mib = |b: u64| format!("{:.1}M", b as f64 / (1 << 20) as f64);
    let opt_mib = |b: Option<u64>| b.map_or("-".into(), mib);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
    println!(
        "{:<22} {:>7} {:>7} {:>17} {:>9} {:>9} {:>6} {:>17} {:<12} {:>8}",
        "RUN", "AGE", "CPU %", "MEM / LIMIT", "OOM", "THROTTLED", "PIDS", "DISK / LIMIT", "IP", "REJECTED"
    );
    for s in &after {
        // usage_usec is CPU time summed over all cores, so 2 busy cores = 200%.
        let usage = |s: &Sandbox| s.cpu_stat.get("usage_usec").copied().unwrap_or(0);
        let cpu = before
            .iter()
            .find(|b| b.run == s.run)
            .map(|b| format!("{:.1}", usage(s).saturating_sub(usage(b)) as f64 / 1e6 / elapsed * 100.0))
            .unwrap_or_else(|| "-".into());
        let age = s.started.map_or("-".into(), |t| format!("{:.0}s", now - t));
        let mem = format!("{} / {}", opt_mib(s.memory), opt_mib(s.memory_max));
        let disk = s.disk.as_ref().map_or("-".into(), |d| format!("{} / {}", mib(d.used), opt_mib(d.limit)));
        let pids = s.pids.map_or("-".into(), |p| p.to_string());
        println!(
            "{:<22} {:>7} {:>7} {:>17} {:>9} {:>9} {:>6} {:>17} {:<12} {:>8}",
            s.run,
            age,
            cpu,
            mem,
            s.memory_events.get("oom_kill").copied().unwrap_or(0),
            s.cpu_stat.get("nr_throttled").copied().unwrap_or(0),
            pids,
            disk,
            s.net.as_ref().map_or("-".into(), |n| n.ip.to_string()),
            s.net.as_ref().map_or("-".into(), |n| n.rejected.to_string()),
        );
    }
}
