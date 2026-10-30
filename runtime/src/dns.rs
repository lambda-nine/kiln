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
//!
//! Sandboxes don't trust each other, so work is scheduled by source IP. UDP and
//! TCP keep separate fixed worker pools, and in each one sources take turns and
//! run one query at a time (`FairQueue`). TCP frames are read by a single
//! nonblocking thread (`TcpReactor`), so a slow frame holds a small buffer and a
//! per-source permit, never a worker.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::metrics;
use crate::net;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const HEADER_LEN: usize = 12;
const UDP_WORKERS: usize = 12;
const TCP_WORKERS: usize = 4;
/// UDP queries one source may have queued and running together.
const UDP_PER_SOURCE: usize = 2;
/// TCP streams one source may hold, from accept until a worker finishes.
const TCP_PER_SOURCE: usize = 2;
/// TCP streams held across all sources: partial, queued and running. Reading
/// them costs at most one buffer of `MAX_TCP_MESSAGE` each.
const TCP_MAX_STREAMS: usize = 256;
/// Connections accepted per reactor turn, so partial frames still get read.
const ACCEPT_BURST: usize = 32;
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
    let udp_jobs = start_workers(UDP_WORKERS, QUEUE_CAPACITY, UDP_PER_SOURCE, &udp, upstream);
    let tcp_jobs = start_workers(TCP_WORKERS, TCP_MAX_STREAMS, TCP_PER_SOURCE, &udp, upstream);
    tcp.set_nonblocking(true).context("set tcp 53 nonblocking")?;
    let reactor = TcpReactor::new(tcp, tcp_jobs);
    thread::spawn(move || reactor.run());

    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = udp.recv_from(&mut buf).context("recv")?;
        // Keep both host threads and queued memory bounded. UDP clients retry
        // naturally when an overloaded forwarder drops a datagram.
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        let _ = udp_jobs.try_push(from.ip(), deadline, Job::Udp(buf[..n].to_vec(), from));
    }
}

enum Job {
    // The stream closes before its permit is released.
    Tcp(TcpStream, Vec<u8>, SocketAddr, TcpPermit),
    Udp(Vec<u8>, SocketAddr),
}

/// A bounded work queue for a fixed worker pool, scheduled by source: sources
/// take turns, each runs one job at a time, and each may hold `per_source` jobs,
/// queued and running together. A busy source therefore costs one worker and a
/// small share of the queue, however fast it sends.
struct FairQueue<T> {
    state: Mutex<FairState<T>>,
    runnable: Condvar,
    capacity: usize,
    per_source: usize,
}

struct FairState<T> {
    /// Only sources with queued or running work, so idle ones cost nothing.
    sources: BTreeMap<IpAddr, SourceJobs<T>>,
    /// Sources with queued work and nothing running, next turn first.
    turns: VecDeque<IpAddr>,
    /// Queued jobs across all sources, bounded by `capacity`.
    queued: usize,
}

struct SourceJobs<T> {
    queued: VecDeque<(Instant, T)>,
    running: bool,
}

/// Holds a source's turn until its job ends, however it ends.
struct Running<T> {
    queue: Arc<FairQueue<T>>,
    source: IpAddr,
}

impl<T> FairQueue<T> {
    fn new(capacity: usize, per_source: usize) -> Arc<Self> {
        Arc::new(FairQueue {
            state: Mutex::new(FairState { sources: BTreeMap::new(), turns: VecDeque::new(), queued: 0 }),
            runnable: Condvar::new(),
            capacity,
            per_source,
        })
    }

    fn lock(&self) -> MutexGuard<'_, FairState<T>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queues a job that is worthless after `deadline`. Hands it back when the
    /// source's share or the whole queue is full.
    fn try_push(&self, source: IpAddr, deadline: Instant, job: T) -> Result<(), T> {
        let mut guard = self.lock();
        let state = &mut *guard;
        if state.queued >= self.capacity { return Err(job); }
        let jobs = state.sources.entry(source)
            .or_insert_with(|| SourceJobs { queued: VecDeque::new(), running: false });
        if jobs.queued.len() + usize::from(jobs.running) >= self.per_source { return Err(job); }
        jobs.queued.push_back((deadline, job));
        state.queued += 1;
        // A source with a job already queued has a turn, and a running one gets
        // its next turn when that job ends.
        if !jobs.running && jobs.queued.len() == 1 {
            state.turns.push_back(source);
            self.runnable.notify_one();
        }
        Ok(())
    }

    /// Waits for the next source's turn and returns its oldest live job.
    fn pop(self: &Arc<Self>) -> (Running<T>, T) {
        let mut state = self.lock();
        loop {
            let Some(source) = state.turns.pop_front() else {
                state = self.runnable.wait(state).unwrap_or_else(|e| e.into_inner());
                continue;
            };
            let jobs = state.sources.get_mut(&source).expect("a source with a turn has jobs");
            let (deadline, job) = jobs.queued.pop_front().expect("a source with a turn has jobs");
            state.queued -= 1;
            if deadline > Instant::now() {
                state.sources.get_mut(&source).expect("still queued").running = true;
                return (Running { queue: Arc::clone(self), source }, job);
            }
            state.settle(source);
            // Closing the expired job's stream doesn't need the lock.
            drop(state);
            drop(job);
            state = self.lock();
        }
    }

    /// Drops queued jobs past their deadline, so they stop holding permits while
    /// every worker is busy. Returns the next deadline among those left.
    fn expire(&self, now: Instant) -> Option<Instant> {
        let mut expired = Vec::new();
        let mut next = None;
        let mut guard = self.lock();
        let state = &mut *guard;
        if state.queued == 0 { return None; }
        for jobs in state.sources.values_mut() {
            for (deadline, job) in mem::take(&mut jobs.queued) {
                if deadline <= now {
                    expired.push(job);
                } else {
                    next = Some(next.map_or(deadline, |n: Instant| n.min(deadline)));
                    jobs.queued.push_back((deadline, job));
                }
            }
        }
        state.queued -= expired.len();
        let sources = &state.sources;
        state.turns.retain(|source| sources.get(source).is_some_and(|jobs| !jobs.queued.is_empty()));
        state.sources.retain(|_, jobs| jobs.running || !jobs.queued.is_empty());
        drop(guard);
        drop(expired);
        next
    }
}

impl<T> FairState<T> {
    /// A source with nothing running goes to the back of the turns, or is
    /// forgotten if it has nothing left. Returns whether it has a turn.
    fn settle(&mut self, source: IpAddr) -> bool {
        if self.sources.get(&source).is_some_and(|jobs| !jobs.queued.is_empty()) {
            self.turns.push_back(source);
            true
        } else {
            self.sources.remove(&source);
            false
        }
    }
}

impl<T> Drop for Running<T> {
    fn drop(&mut self) {
        let mut state = self.queue.lock();
        if let Some(jobs) = state.sources.get_mut(&self.source) { jobs.running = false; }
        if state.settle(self.source) { self.queue.runnable.notify_one(); }
    }
}

#[derive(Default)]
struct TcpCounts {
    total: usize,
    by_source: BTreeMap<IpAddr, usize>,
}

type Sources = Arc<Mutex<TcpCounts>>;

struct TcpPermit { sources: Sources, source: IpAddr }

fn admit_tcp(sources: &Sources, source: IpAddr) -> Option<TcpPermit> {
    let mut guard = sources.lock().unwrap_or_else(|e| e.into_inner());
    let counts = &mut *guard;
    if counts.total >= TCP_MAX_STREAMS { return None; }
    let count = counts.by_source.entry(source).or_default();
    if *count >= TCP_PER_SOURCE { return None; }
    *count += 1;
    counts.total += 1;
    Some(TcpPermit { sources: Arc::clone(sources), source })
}

impl Drop for TcpPermit {
    fn drop(&mut self) {
        let mut guard = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        let counts = &mut *guard;
        if let Some(count) = counts.by_source.get_mut(&self.source) {
            *count -= 1;
            counts.total -= 1;
            if *count == 0 { counts.by_source.remove(&self.source); }
        }
    }
}

/// One TCP message arriving in pieces: its length prefix, then its body, which
/// is allocated only once the prefix passes the size check.
#[derive(Default)]
struct FrameReader {
    prefix: [u8; 2],
    prefix_read: usize,
    body: Vec<u8>,
    body_read: usize,
}

impl FrameReader {
    /// Reads what has arrived, and nothing past this frame. `Ok(None)` means
    /// the stream has no more for now.
    fn advance(&mut self, stream: &mut impl Read) -> Result<Option<Vec<u8>>> {
        loop {
            let unread = if self.prefix_read < self.prefix.len() {
                &mut self.prefix[self.prefix_read..]
            } else {
                &mut self.body[self.body_read..]
            };
            match stream.read(unread) {
                Ok(0) => bail!("truncated DNS TCP frame"),
                Ok(n) if self.prefix_read < self.prefix.len() => {
                    self.prefix_read += n;
                    if self.prefix_read == self.prefix.len() {
                        self.body = vec![0; message_size(self.prefix)?];
                    }
                }
                Ok(n) => {
                    self.body_read += n;
                    if self.body_read == self.body.len() { return Ok(Some(mem::take(&mut self.body))); }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("read DNS TCP frame"),
            }
        }
    }
}

/// An accepted stream whose query hasn't fully arrived. Its deadline and permit
/// follow the query into the queue. The stream closes before the permit goes.
struct PartialFrame {
    stream: TcpStream,
    from: SocketAddr,
    deadline: Instant,
    frame: FrameReader,
    permit: TcpPermit,
}

/// Polls the listener and every partial frame on one thread, and hands complete
/// queries to the TCP workers.
struct TcpReactor {
    listener: TcpListener,
    partial: Vec<PartialFrame>,
    sources: Sources,
    jobs: Arc<FairQueue<Job>>,
}

impl TcpReactor {
    /// `listener` must already be nonblocking.
    fn new(listener: TcpListener, jobs: Arc<FairQueue<Job>>) -> Self {
        TcpReactor { listener, partial: Vec::new(), sources: Sources::default(), jobs }
    }

    fn run(mut self) {
        loop { self.turn(None); }
    }

    /// Expires what's overdue, waits for a socket (at most `max_wait`, and only
    /// until the next deadline), then does the nonblocking work that's ready.
    fn turn(&mut self, max_wait: Option<Duration>) {
        let now = Instant::now();
        self.partial.retain(|partial| partial.deadline > now);
        let queued = self.jobs.expire(now);
        let next = self.partial.iter().map(|partial| partial.deadline).chain(queued).min();
        let wait = next.map(|deadline| deadline.saturating_duration_since(now)).into_iter().chain(max_wait).min();
        // Round up so the turn after a timeout finds the deadline has passed.
        let timeout = wait.map_or(-1, |wait| wait.as_millis().saturating_add(1).min(i32::MAX as u128) as i32);

        let mut fds = Vec::with_capacity(self.partial.len() + 1);
        fds.push(libc::pollfd { fd: self.listener.as_raw_fd(), events: libc::POLLIN, revents: 0 });
        fds.extend(self.partial.iter().map(|partial| {
            libc::pollfd { fd: partial.stream.as_raw_fd(), events: libc::POLLIN, revents: 0 }
        }));
        // SAFETY: `fds` points to initialized pollfds for the supplied length.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                eprintln!("kiln dns: poll: {error}");
                thread::sleep(Duration::from_millis(10));
            }
            return;
        }
        // Backwards, because `swap_remove` only moves frames already handled.
        for i in (0..self.partial.len()).rev() {
            if fds[i + 1].revents != 0 { self.read_partial(i); }
        }
        if fds[0].revents != 0 { self.accept_ready(); }
    }

    fn accept_ready(&mut self) {
        for _ in 0..ACCEPT_BURST {
            match self.listener.accept() {
                Ok((stream, from)) => self.admit(stream, from),
                Err(e) if e.kind() == ErrorKind::WouldBlock => return,
                Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::ConnectionAborted) => {}
                // Out of descriptors: the listener stays readable, so don't spin.
                Err(e) => {
                    eprintln!("kiln dns: accept: {e}");
                    thread::sleep(Duration::from_millis(10));
                    return;
                }
            }
        }
    }

    /// Without a permit, the stream closes here. Accepting first is the only way
    /// to learn its source, and it keeps other sources' connections moving.
    fn admit(&mut self, stream: TcpStream, from: SocketAddr) {
        let Some(permit) = admit_tcp(&self.sources, from.ip()) else { return };
        if stream.set_nonblocking(true).is_err() { return; }
        // The deadline covers the whole frame and the time queued behind it.
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        self.partial.push(PartialFrame { stream, from, deadline, frame: FrameReader::default(), permit });
    }

    fn read_partial(&mut self, i: usize) {
        let partial = &mut self.partial[i];
        match partial.frame.advance(&mut partial.stream) {
            Ok(None) => {}
            Err(_) => { self.partial.swap_remove(i); }
            Ok(Some(query)) => {
                let PartialFrame { stream, from, deadline, permit, .. } = self.partial.swap_remove(i);
                // Workers write with blocking timeouts.
                if stream.set_nonblocking(false).is_ok() {
                    let _ = self.jobs.try_push(from.ip(), deadline, Job::Tcp(stream, query, from, permit));
                }
            }
        }
    }
}

fn start_workers(count: usize, capacity: usize, per_source: usize, udp: &Arc<UdpSocket>, upstream: Ipv4Addr) -> Arc<FairQueue<Job>> {
    let jobs = FairQueue::new(capacity, per_source);
    for _ in 0..count {
        let jobs = Arc::clone(&jobs);
        let udp = Arc::clone(udp);
        thread::spawn(move || worker(jobs, udp, upstream));
    }
    jobs
}

fn worker(jobs: Arc<FairQueue<Job>>, udp: Arc<UdpSocket>, upstream: Ipv4Addr) {
    loop {
        let (turn, job) = jobs.pop();
        match job {
            Job::Tcp(stream, query, from, permit) => {
                let _ = serve_tcp(stream, &query, from, upstream);
                // In this order, so a stream admitted on this permit always
                // finds its source's share of the queue free.
                drop(turn);
                drop(permit);
            }
            Job::Udp(query, from) => {
                if let Some(reply) = answer(&query, from, upstream, Transport::Udp) {
                    let _ = udp.send_to(&reply, from);
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

/// DNS over TCP: each message is prefixed with its length as a u16.
fn serve_tcp(mut stream: TcpStream, query: &[u8], from: SocketAddr, upstream: Ipv4Addr) -> Result<()> {
    if let Some(reply) = answer(query, from, upstream, Transport::Tcp) {
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
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("read DNS TCP frame"),
        }
    }
    remaining(deadline)?;
    Ok(())
}

/// The size from a length prefix, checked before the body is read or allocated.
fn message_size(prefix: [u8; 2]) -> Result<usize> {
    let size = u16::from_be_bytes(prefix) as usize;
    if !(HEADER_LEN..=MAX_TCP_MESSAGE).contains(&size) {
        bail!("DNS TCP message size must be {HEADER_LEN}..={MAX_TCP_MESSAGE} bytes");
    }
    Ok(size)
}

fn read_tcp_message(stream: &mut TcpStream, deadline: Instant) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    read_exact_until(stream, &mut len, deadline)?;
    let mut msg = vec![0u8; message_size(len)?];
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
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
        let sources = Sources::default();
        let first = "10.88.0.2".parse().unwrap();
        let second = "10.88.0.3".parse().unwrap();
        let a = admit_tcp(&sources, first).unwrap();
        let b = admit_tcp(&sources, first).unwrap();
        assert!(admit_tcp(&sources, first).is_none());
        let other = admit_tcp(&sources, second).unwrap();
        drop(a);
        let replacement = admit_tcp(&sources, first).unwrap();
        drop((b, other, replacement));
        let counts = sources.lock().unwrap();
        assert!(counts.by_source.is_empty());
        assert_eq!(counts.total, 0);
    }

    #[test]
    fn tcp_permits_have_a_global_bound() {
        let sources = Sources::default();
        let permits: Vec<_> = (0..TCP_MAX_STREAMS)
            .map(|i| admit_tcp(&sources, source(i / TCP_PER_SOURCE)).unwrap())
            .collect();
        let latecomer = source(TCP_MAX_STREAMS);
        assert!(admit_tcp(&sources, latecomer).is_none());
        assert!(!sources.lock().unwrap().by_source.contains_key(&latecomer));
        drop(permits);
        assert!(admit_tcp(&sources, latecomer).is_some());
    }

    fn source(i: usize) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 88, (i >> 8) as u8, i as u8))
    }

    fn live() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// `pop`, but only when it wouldn't wait.
    fn try_pop<T>(queue: &Arc<FairQueue<T>>) -> Option<(Running<T>, T)> {
        if queue.lock().turns.is_empty() { None } else { Some(queue.pop()) }
    }

    fn assert_idle<T>(queue: &FairQueue<T>) {
        let state = queue.lock();
        assert!(state.sources.is_empty());
        assert!(state.turns.is_empty());
        assert_eq!(state.queued, 0);
    }

    #[test]
    fn fair_queue_holds_a_flood_to_one_worker_and_its_share_of_the_queue() {
        let queue = FairQueue::new(QUEUE_CAPACITY, UDP_PER_SOURCE);
        let (flood, victim) = (source(1), source(2));
        for n in 0..1000 {
            let pushed = queue.try_push(flood, live(), n);
            assert_eq!(pushed.is_ok(), n < UDP_PER_SOURCE);
        }
        assert_eq!(queue.lock().queued, UDP_PER_SOURCE);

        // Twelve workers ask for work: the flood gets one of them.
        let (first, job) = try_pop(&queue).unwrap();
        assert_eq!(job, 0);
        assert!(try_pop(&queue).is_none());

        // Still at its limit while one runs and one waits.
        assert!(queue.try_push(flood, live(), 2).is_err());
        queue.try_push(victim, live(), 100).unwrap();
        let (second, job) = try_pop(&queue).unwrap();
        assert_eq!((second.source, job), (victim, 100));
        assert!(try_pop(&queue).is_none());

        drop(first);
        let (third, job) = try_pop(&queue).unwrap();
        assert_eq!((third.source, job), (flood, 1));
        drop((second, third));
        assert_idle(&queue);
    }

    #[test]
    fn fair_queue_takes_turns_while_a_source_stays_busy() {
        let queue = FairQueue::new(QUEUE_CAPACITY, 3);
        let (busy, b, c) = (source(1), source(2), source(3));
        queue.try_push(busy, live(), 1).unwrap();
        queue.try_push(busy, live(), 2).unwrap();
        queue.try_push(b, live(), 10).unwrap();
        queue.try_push(c, live(), 20).unwrap();

        let mut order = Vec::new();
        for n in 3..9 {
            let Some((turn, job)) = try_pop(&queue) else { break };
            order.push(job);
            // The busy source refills as fast as it's served.
            let _ = queue.try_push(busy, live(), n);
            drop(turn);
            if order.len() == 6 { break; }
        }
        // Everyone waiting gets served before the busy source's next turn.
        assert_eq!(&order[..4], &[1, 10, 20, 2]);
        assert!(order[4..].iter().all(|&job| job < 10));
    }

    #[test]
    fn fair_queue_full_rejects_without_keeping_the_source() {
        let queue = FairQueue::new(2, 2);
        queue.try_push(source(1), live(), 1).unwrap();
        queue.try_push(source(2), live(), 2).unwrap();
        assert_eq!(queue.try_push(source(3), live(), 3), Err(3));
        assert!(!queue.lock().sources.contains_key(&source(3)));
        drop(try_pop(&queue));
        drop(try_pop(&queue));
        assert_idle(&queue);
    }

    #[test]
    fn fair_queue_skips_expired_jobs_at_their_turn() {
        let queue = FairQueue::new(8, 2);
        let past = Instant::now();
        queue.try_push(source(1), past, 1).unwrap();
        queue.try_push(source(1), live(), 2).unwrap();
        queue.try_push(source(2), past, 3).unwrap();
        queue.try_push(source(3), live(), 4).unwrap();
        let (turn, job) = try_pop(&queue).unwrap();
        assert_eq!(job, 4);
        drop(turn);
        let (turn, job) = try_pop(&queue).unwrap();
        assert_eq!(job, 2);
        drop(turn);
        assert_idle(&queue);
    }

    #[test]
    fn fair_queue_expires_jobs_and_releases_their_permits_while_workers_are_busy() {
        let sources = Sources::default();
        let queue = FairQueue::new(8, 2);
        let now = Instant::now();
        let later = now + Duration::from_secs(60);
        let (running, queued_too, gone, stays) = (source(1), source(1), source(2), source(3));
        assert!(queue.try_push(running, later, admit_tcp(&sources, running).unwrap()).is_ok());
        let (turn, _job) = try_pop(&queue).unwrap();
        assert!(queue.try_push(queued_too, now, admit_tcp(&sources, queued_too).unwrap()).is_ok());
        assert!(queue.try_push(gone, now, admit_tcp(&sources, gone).unwrap()).is_ok());
        assert!(queue.try_push(stays, later, admit_tcp(&sources, stays).unwrap()).is_ok());
        assert_eq!(sources.lock().unwrap().total, 4);

        assert_eq!(queue.expire(now), Some(later));
        assert_eq!(sources.lock().unwrap().total, 2);
        assert_eq!(queue.lock().queued, 1);
        assert!(!queue.lock().sources.contains_key(&gone));
        assert!(queue.lock().sources.contains_key(&running));
        assert_eq!(queue.lock().turns, [stays]);

        let (other, _job) = try_pop(&queue).unwrap();
        assert!(try_pop(&queue).is_none());
        drop((turn, other));
        assert_idle(&queue);
        assert_eq!(queue.expire(now), None);
    }

    #[test]
    fn fair_queue_workers_finish_everything_without_overlapping_a_source() {
        const SOURCES: usize = 8;
        const JOBS_PER_SOURCE: usize = 50;
        let queue = FairQueue::new(QUEUE_CAPACITY, UDP_PER_SOURCE);
        let busy: Arc<[AtomicBool; SOURCES]> = Arc::new(std::array::from_fn(|_| AtomicBool::new(false)));
        let done = Arc::new(AtomicUsize::new(0));
        for _ in 0..UDP_WORKERS {
            let (queue, busy, done) = (Arc::clone(&queue), Arc::clone(&busy), Arc::clone(&done));
            thread::spawn(move || loop {
                let (_turn, job): (_, usize) = queue.pop();
                assert!(!busy[job].swap(true, Ordering::SeqCst), "two workers on one source");
                thread::sleep(Duration::from_micros(200));
                busy[job].store(false, Ordering::SeqCst);
                done.fetch_add(1, Ordering::SeqCst);
            });
        }
        let senders: Vec<_> = (0..SOURCES).map(|i| {
            let queue = Arc::clone(&queue);
            thread::spawn(move || {
                let mut sent = 0;
                while sent < JOBS_PER_SOURCE {
                    if queue.try_push(source(i), live(), i).is_ok() { sent += 1; } else { thread::yield_now(); }
                }
            })
        }).collect();
        for sender in senders { sender.join().unwrap(); }
        let start = Instant::now();
        while done.load(Ordering::SeqCst) < SOURCES * JOBS_PER_SOURCE {
            assert!(start.elapsed() < Duration::from_secs(10));
            thread::sleep(Duration::from_millis(1));
        }
        // A worker counts its job just before giving back the turn.
        while !queue.lock().sources.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10));
            thread::sleep(Duration::from_millis(1));
        }
        assert_idle(&queue);
    }

    fn reactor() -> (TcpReactor, SocketAddr) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        (TcpReactor::new(listener, FairQueue::new(TCP_MAX_STREAMS, TCP_PER_SOURCE)), addr)
    }

    fn turns(reactor: &mut TcpReactor, count: usize) {
        for _ in 0..count { reactor.turn(Some(Duration::from_millis(5))); }
    }

    fn query(id: u16) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(b"\x06denied\x07invalid\0\0\x01\0\x01");
        q
    }

    fn framed(msg: &[u8]) -> Vec<u8> {
        let mut frame = (msg.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(msg);
        frame
    }

    fn stream_count(reactor: &TcpReactor) -> usize {
        reactor.sources.lock().unwrap().total
    }

    #[test]
    fn slow_sources_hold_no_worker_capacity() {
        let (mut reactor, _) = reactor();
        // The attack from the review: 18 sources, each using both its permits.
        let mut clients = Vec::new();
        for i in 0..18 {
            for _ in 0..TCP_PER_SOURCE {
                let (mut client, server) = pair();
                client.write_all(&[0x10, 0x00, b'x']).unwrap();
                reactor.admit(server, SocketAddr::new(source(i), 40000));
                clients.push(client);
            }
        }
        turns(&mut reactor, 2);
        assert_eq!(reactor.partial.len(), 36);
        assert_eq!(reactor.jobs.lock().queued, 0);

        let (mut victim, server) = pair();
        victim.write_all(&framed(&query(7))).unwrap();
        reactor.admit(server, SocketAddr::new(source(18), 40000));
        turns(&mut reactor, 2);
        assert_eq!(reactor.partial.len(), 36);
        let (turn, job) = try_pop(&reactor.jobs).unwrap();
        assert_eq!(turn.source, source(18));
        let Job::Tcp(_, received, from, _) = job else { panic!("expected a TCP job") };
        assert_eq!((received, from.ip()), (query(7), source(18)));
    }

    #[test]
    fn reactor_reads_a_frame_in_pieces() {
        let (mut reactor, _) = reactor();
        let (mut client, server) = pair();
        reactor.admit(server, SocketAddr::new(source(1), 40000));
        let msg = vec![0xab; MAX_TCP_MESSAGE];
        let frame = framed(&msg);
        client.write_all(&frame[..1]).unwrap();
        turns(&mut reactor, 2);
        assert!(reactor.partial[0].frame.body.is_empty());
        client.write_all(&frame[1..2]).unwrap();
        turns(&mut reactor, 2);
        assert_eq!(reactor.partial[0].frame.body.len(), MAX_TCP_MESSAGE);
        client.write_all(&frame[2..frame.len() - 1]).unwrap();
        turns(&mut reactor, 2);
        assert_eq!(reactor.jobs.lock().queued, 0);
        client.write_all(&frame[frame.len() - 1..]).unwrap();
        turns(&mut reactor, 2);
        assert!(reactor.partial.is_empty());
        let (_turn, job) = try_pop(&reactor.jobs).unwrap();
        let Job::Tcp(_, received, _, _) = job else { panic!("expected a TCP job") };
        assert_eq!(received, msg);
    }

    #[test]
    fn reactor_rejects_bad_sizes_at_the_prefix_and_releases_the_stream() {
        for size in [MAX_TCP_MESSAGE + 1, u16::MAX as usize, HEADER_LEN - 1, 0] {
            let (mut reactor, _) = reactor();
            let (mut client, server) = pair();
            reactor.admit(server, SocketAddr::new(source(1), 40000));
            client.write_all(&(size as u16).to_be_bytes()).unwrap();
            turns(&mut reactor, 2);
            assert!(reactor.partial.is_empty());
            assert_eq!(stream_count(&reactor), 0);
            assert_eq!(reactor.jobs.lock().queued, 0);
            client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let closed = client.read(&mut [0u8; 1]);
            assert!(matches!(closed, Ok(0)) || closed.is_err_and(|e| e.kind() != ErrorKind::WouldBlock));
        }
    }

    #[test]
    fn reactor_releases_dropped_streams() {
        let (mut reactor, _) = reactor();
        let (mut client, server) = pair();
        reactor.admit(server, SocketAddr::new(source(1), 40000));
        client.write_all(&[0x10]).unwrap();
        turns(&mut reactor, 1);
        assert_eq!(stream_count(&reactor), 1);
        drop(client);
        turns(&mut reactor, 2);
        assert!(reactor.partial.is_empty());
        assert_eq!(stream_count(&reactor), 0);
    }

    #[test]
    fn reactor_deadline_is_absolute_despite_progress() {
        let (mut reactor, _) = reactor();
        let (mut client, server) = pair();
        reactor.admit(server, SocketAddr::new(source(1), 40000));
        let start = Instant::now();
        reactor.partial[0].deadline = start + Duration::from_millis(100);
        let mut bytes = [0u8, 12].into_iter().chain(std::iter::repeat_n(0, 12));
        while !reactor.partial.is_empty() {
            assert!(start.elapsed() < Duration::from_secs(1));
            // The peer may see the close first.
            if let Some(byte) = bytes.next() { let _ = client.write_all(&[byte]); }
            reactor.turn(Some(Duration::from_millis(20)));
            thread::sleep(Duration::from_millis(15));
        }
        assert!(start.elapsed() >= Duration::from_millis(100));
        assert_eq!(stream_count(&reactor), 0);
        assert_eq!(reactor.jobs.lock().queued, 0);
    }

    #[test]
    fn reactor_deadline_includes_time_queued() {
        let (mut reactor, _) = reactor();
        let (mut client, server) = pair();
        reactor.admit(server, SocketAddr::new(source(1), 40000));
        reactor.partial[0].deadline = Instant::now() + Duration::from_millis(300);
        client.write_all(&framed(&query(1))).unwrap();
        turns(&mut reactor, 2);
        assert!(reactor.partial.is_empty());
        assert_eq!(reactor.jobs.lock().queued, 1);
        assert_eq!(stream_count(&reactor), 1);
        // No worker ever came, and the reactor releases it anyway.
        let start = Instant::now();
        while stream_count(&reactor) > 0 {
            assert!(start.elapsed() < Duration::from_secs(2));
            reactor.turn(Some(Duration::from_millis(20)));
        }
        assert_idle(&reactor.jobs);
    }

    #[test]
    fn reactor_accepts_past_the_source_limit_only_to_close() {
        let (mut reactor, addr) = reactor();
        let clients: Vec<_> = (0..TCP_PER_SOURCE + 1).map(|_| TcpStream::connect(addr).unwrap()).collect();
        turns(&mut reactor, 2);
        assert_eq!(reactor.partial.len(), TCP_PER_SOURCE);
        assert_eq!(stream_count(&reactor), TCP_PER_SOURCE);
        drop(clients);
        turns(&mut reactor, 2);
        assert_eq!(stream_count(&reactor), 0);
    }

    #[test]
    fn workers_answer_past_slow_sources() {
        let (mut reactor, addr) = reactor();
        let udp = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap());
        let jobs = start_workers(TCP_WORKERS, TCP_MAX_STREAMS, TCP_PER_SOURCE, &udp, Ipv4Addr::LOCALHOST);
        reactor.jobs = jobs;
        let mut blockers = Vec::new();
        for i in 0..18 {
            for _ in 0..TCP_PER_SOURCE {
                let (mut client, server) = pair();
                client.write_all(&[0x10, 0x00, b'x']).unwrap();
                reactor.admit(server, SocketAddr::new(source(i), 40000));
                blockers.push(client);
            }
        }
        thread::spawn(move || reactor.run());

        // No policy file for this source, so no upstream is involved.
        let mut victim = TcpStream::connect(addr).unwrap();
        victim.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let start = Instant::now();
        victim.write_all(&framed(&query(0x4b49))).unwrap();
        let reply = read_tcp_message(&mut victim, start + Duration::from_secs(2)).unwrap();
        assert_eq!(reply[..2], [0x4b, 0x49]);
        assert_eq!(reply[3] & 15, 5);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
