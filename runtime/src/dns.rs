//! `kiln dns`: a tiny DNS forwarder for sandboxes, listening on the bridge
//! (10.88.0.1:53, UDP and TCP). Sandboxes can't reach any other resolver.
//!
//! Each query is checked against the asking sandbox's policy, a file named
//! after its IP in /run/kiln/net/dns: `*` allows any name (`--net full`),
//! otherwise one allowed name per line (`--allow` hostnames, subdomains
//! included). Allowed queries go to the host's upstream resolver; the rest
//! get REFUSED. With an allowlist, that also closes DNS as a way to smuggle
//! data out, since an attacker's domain never gets resolved. Every query is
//! logged to stdout, which systemd sends to the journal, and counted for
//! Prometheus on http://127.0.0.1:9841/metrics.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::metrics;
use crate::net;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const HEADER_LEN: usize = 12;
const UDP_WORKERS: usize = 12;
const TCP_WORKERS: usize = 4;
const TCP_PER_SOURCE: usize = 2;
const TCP_QUEUE_CAPACITY: usize = 32;
const MAX_TCP_MESSAGE: usize = 4096;
const QUEUE_CAPACITY: usize = 256;
/// Localhost only: the sandboxes' side of the host is the bridge, and the
/// input chain rejects them anyway.
const METRICS_LISTEN: &str = "127.0.0.1:9841";

/// Queries answered since the forwarder started, by (outcome, query type).
static QUERIES: Mutex<BTreeMap<(&str, String), u64>> = Mutex::new(BTreeMap::new());

pub fn serve() -> Result<()> {
    net::ensure_bridge()?;
    let Some(&upstream) = net::host_resolvers().first() else {
        bail!("no upstream resolver found in /run/systemd/resolve/resolv.conf or /etc/resolv.conf");
    };
    let udp = UdpSocket::bind((net::GATEWAY, 53)).context("bind udp 53")?;
    let tcp = TcpListener::bind((net::GATEWAY, 53)).context("bind tcp 53")?;
    println!("kiln dns: listening on {}:53, forwarding to {upstream}", net::GATEWAY);

    thread::spawn(|| {
        if let Err(e) = metrics::serve(METRICS_LISTEN, render_metrics) {
            eprintln!("kiln dns: metrics: {e:#}");
        }
    });

    let udp = Arc::new(udp);
    // Separate bounded pools reserve UDP capacity even when TCP is saturated.
    let jobs_tx = start_workers(UDP_WORKERS, QUEUE_CAPACITY, &udp, upstream);
    let tcp_jobs = start_workers(TCP_WORKERS, TCP_QUEUE_CAPACITY, &udp, upstream);
    let sources = Arc::new(Mutex::new(BTreeMap::new()));
    thread::spawn(move || {
        for stream in tcp.incoming().flatten() {
            let deadline = Instant::now() + UPSTREAM_TIMEOUT;
            let Ok(from) = stream.peer_addr() else { continue };
            let Some(permit) = admit_tcp(&sources, from.ip()) else { continue };
            // The permit covers queued and running work and is released even
            // when a full queue drops this stream. Queuing consumes its deadline.
            let _ = tcp_jobs.try_send(Job::Tcp(stream, deadline, permit));
        }
    });

    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = udp.recv_from(&mut buf).context("recv")?;
        // Keep both host threads and queued memory bounded. UDP clients retry
        // naturally when an overloaded forwarder drops a datagram.
        let _ = jobs_tx.try_send(Job::Udp(buf[..n].to_vec(), from));
    }
}

enum Job {
    Tcp(TcpStream, Instant, TcpPermit),
    Udp(Vec<u8>, SocketAddr),
}

type Sources = Arc<Mutex<BTreeMap<IpAddr, usize>>>;

struct TcpPermit { sources: Sources, source: IpAddr }

fn admit_tcp(sources: &Sources, source: IpAddr) -> Option<TcpPermit> {
    let mut counts = sources.lock().unwrap_or_else(|e| e.into_inner());
    let count = counts.entry(source).or_default();
    if *count >= TCP_PER_SOURCE { return None; }
    *count += 1;
    Some(TcpPermit { sources: Arc::clone(sources), source })
}

impl Drop for TcpPermit {
    fn drop(&mut self) {
        let mut counts = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.source) {
            *count -= 1;
            if *count == 0 { counts.remove(&self.source); }
        }
    }
}

fn start_workers(count: usize, capacity: usize, udp: &Arc<UdpSocket>, upstream: Ipv4Addr) -> mpsc::SyncSender<Job> {
    let (tx, rx) = mpsc::sync_channel(capacity);
    let rx = Arc::new(Mutex::new(rx));
    for _ in 0..count {
        let jobs = Arc::clone(&rx);
        let udp = Arc::clone(udp);
        thread::spawn(move || worker(jobs, udp, upstream));
    }
    tx
}

fn worker(jobs: Arc<Mutex<mpsc::Receiver<Job>>>, udp: Arc<UdpSocket>, upstream: Ipv4Addr) {
    loop {
        let job = {
            let receiver = jobs.lock().unwrap_or_else(|e| e.into_inner());
            receiver.recv()
        };
        match job {
            Ok(Job::Tcp(stream, deadline, _permit)) => {
                let _ = serve_tcp(stream, upstream, deadline);
            }
            Ok(Job::Udp(query, from)) => {
                if let Some(reply) = answer(&query, from, upstream, Transport::Udp) {
                    let _ = udp.send_to(&reply, from);
                }
            }
            Err(_) => return,
        }
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

/// DNS over TCP: each message is prefixed with its length as a u16.
fn serve_tcp(mut stream: TcpStream, upstream: Ipv4Addr, deadline: Instant) -> Result<()> {
    let from = stream.peer_addr()?;
    let query = read_tcp_message(&mut stream, deadline)?;
    if let Some(reply) = answer(&query, from, upstream, Transport::Tcp) {
        write_tcp_message(&mut stream, &reply, Instant::now() + UPSTREAM_TIMEOUT)?;
    }
    Ok(())
}

/// Checks the policy and returns the reply to send, or `None` to drop a
/// malformed query.
fn answer(query: &[u8], from: SocketAddr, upstream: Ipv4Addr, transport: Transport) -> Option<Vec<u8>> {
    let IpAddr::V4(sandbox) = from.ip() else { return None };
    let question = parse_question(query)?;
    let allowed = allowed(sandbox, &question.name);
    let qtype = qtype_name(question.qtype);
    println!(
        "{sandbox} {qtype} {} {}",
        question.name.escape_default(),
        if allowed { "allowed" } else { "refused" }
    );
    if !allowed {
        count("refused", qtype);
        return Some(refused(query, question.end));
    }
    let reply = match transport {
        Transport::Udp => forward_udp(query, upstream),
        Transport::Tcp => forward_tcp(query, upstream),
    };
    // On upstream failure, say so (SERVFAIL) rather than leave the client
    // waiting for its own timeout.
    match reply {
        Ok(reply) => {
            count("forwarded", qtype);
            Some(reply)
        }
        Err(_) => {
            count("servfail", qtype);
            Some(error_reply(query, question.end, 2))
        }
    }
}

fn count(outcome: &'static str, qtype: String) {
    let mut queries = QUERIES.lock().unwrap_or_else(|e| e.into_inner());
    *queries.entry((outcome, qtype)).or_default() += 1;
}

fn render_metrics() -> String {
    let mut m = metrics::Exposition::default();
    let name = "kiln_dns_queries_total";
    m.family(name, "counter", "DNS queries from sandboxes by outcome: forwarded upstream, refused by the sandbox's policy, or servfail (upstream failed).");
    for ((outcome, qtype), n) in QUERIES.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        m.sample(name, &[("outcome", outcome), ("qtype", qtype)], n);
    }
    m.finish()
}

/// Reads the sandbox's policy file. No file means an unknown sender: refuse.
fn allowed(sandbox: Ipv4Addr, name: &str) -> bool {
    let Ok(policy) = fs::read_to_string(net::dns_policy_path(sandbox)) else { return false };
    policy.lines().map(str::trim).filter(|l| !l.is_empty()).any(|entry| {
        entry == "*" || name == entry || name.ends_with(&format!(".{entry}"))
    })
}

struct Question {
    name: String,
    qtype: u16,
    /// Offset just past the question section.
    end: usize,
}

/// Parses the single question of a standard query: a series of
/// length-prefixed labels ending in a zero byte, then QTYPE and QCLASS.
fn parse_question(msg: &[u8]) -> Option<Question> {
    if msg.len() < HEADER_LEN || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return None;
    }
    let mut labels = Vec::new();
    let mut pos = HEADER_LEN;
    loop {
        let len = *msg.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        // 0xC0 and up are compression pointers, which a query has no use for.
        if len > 63 {
            return None;
        }
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    let qtype = u16::from_be_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]);
    msg.get(pos + 3)?; // QCLASS must be there too
    Some(Question { name: labels.join("."), qtype, end: pos + 4 })
}

fn refused(query: &[u8], question_end: usize) -> Vec<u8> {
    error_reply(query, question_end, 5)
}

/// Header plus the original question, marked as a response with `rcode`
/// (2 = SERVFAIL, 5 = REFUSED) and no answers.
fn error_reply(query: &[u8], question_end: usize, rcode: u8) -> Vec<u8> {
    let mut reply = query[..question_end].to_vec();
    reply[2] = 0x80 | (query[2] & 0x79); // QR=1, keep opcode and RD
    reply[3] = 0x80 | rcode; // RA=1
    reply[6..12].fill(0); // ANCOUNT, NSCOUNT, ARCOUNT
    reply
}

fn forward_udp(query: &[u8], upstream: Ipv4Addr) -> Result<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    socket.connect((upstream, 53))?;
    socket.send(query)?;
    let mut buf = [0u8; 4096];
    loop {
        let n = socket.recv(&mut buf)?;
        // Only accept the reply to our query (matching transaction ID).
        if n >= HEADER_LEN && buf[..2] == query[..2] {
            return Ok(buf[..n].to_vec());
        }
    }
}

fn forward_tcp(query: &[u8], upstream: Ipv4Addr) -> Result<Vec<u8>> {
    let deadline = Instant::now() + UPSTREAM_TIMEOUT;
    let mut stream = TcpStream::connect_timeout(&SocketAddr::from((upstream, 53)), remaining(deadline)?)?;
    write_tcp_message(&mut stream, query, deadline)?;
    read_tcp_message(&mut stream, deadline)
}

fn remaining(deadline: Instant) -> Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() { bail!("DNS TCP frame deadline exceeded"); }
    Ok(left)
}

fn read_exact_until(stream: &mut TcpStream, mut bytes: &mut [u8], deadline: Instant) -> Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => bail!("truncated DNS TCP frame"),
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("read DNS TCP frame"),
        }
    }
    remaining(deadline)?;
    Ok(())
}

fn read_tcp_message(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    read_exact_until(stream, &mut len, deadline)?;
    let size = u16::from_be_bytes(len) as usize;
    if !(HEADER_LEN..=MAX_TCP_MESSAGE).contains(&size) {
        bail!("DNS TCP message size must be {HEADER_LEN}..={MAX_TCP_MESSAGE} bytes");
    }
    let mut msg = vec![0u8; size];
    read_exact_until(stream, &mut msg, deadline)?;
    Ok(msg)
}

fn write_tcp_message(stream: &mut TcpStream, msg: &[u8], deadline: Instant) -> Result<()> {
    if msg.len() > MAX_TCP_MESSAGE { bail!("DNS TCP message too large"); }
    let mut frame = (msg.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(msg);
    let mut bytes = frame.as_slice();
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => bail!("short DNS TCP write"),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("write DNS TCP frame"),
        }
    }
    Ok(())
}

fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        5 => "CNAME".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        65 => "HTTPS".into(),
        n => format!("TYPE{n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn tcp_frame_has_one_deadline_despite_header_and_body_progress() {
        let (mut client, mut server) = pair();
        let writer = thread::spawn(move || {
            for byte in [0, 12].into_iter().chain(std::iter::repeat_n(0, 12)) {
                if client.write_all(&[byte]).is_err() { break; }
                thread::sleep(Duration::from_millis(40));
            }
        });
        let start = Instant::now();
        assert!(read_tcp_message(&mut server, start + Duration::from_millis(180)).is_err());
        assert!(start.elapsed() < Duration::from_millis(450));
        drop(server);
        writer.join().unwrap();
    }

    #[test]
    fn tcp_size_cap_rejects_before_waiting_for_body() {
        let (mut client, mut server) = pair();
        client.write_all(&((MAX_TCP_MESSAGE + 1) as u16).to_be_bytes()).unwrap();
        let start = Instant::now();
        assert!(read_tcp_message(&mut server, start + Duration::from_secs(3)).unwrap_err()
            .to_string().contains("message size"));
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn tcp_source_permits_cover_queued_work_and_release_on_drop() {
        let sources = Arc::new(Mutex::new(BTreeMap::new()));
        let first = "10.88.0.2".parse().unwrap();
        let second = "10.88.0.3".parse().unwrap();
        let a = admit_tcp(&sources, first).unwrap();
        let b = admit_tcp(&sources, first).unwrap();
        assert!(admit_tcp(&sources, first).is_none());
        let other = admit_tcp(&sources, second).unwrap();
        drop(a);
        let replacement = admit_tcp(&sources, first).unwrap();
        drop((b, other, replacement));
        assert!(sources.lock().unwrap().is_empty());
    }
}
