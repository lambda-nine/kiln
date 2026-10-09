//! `kiln dns`: a tiny DNS forwarder for sandboxes, listening on the bridge
//! (10.88.0.1:53, UDP and TCP). Sandboxes can't reach any other resolver.
//!
//! Each query is checked against the asking sandbox's policy, a file named
//! after its IP in /run/kiln/net/dns: `*` allows any name (`--net full`),
//! otherwise one allowed name per line (`--allow` hostnames, subdomains
//! included). Allowed queries go to the host's upstream resolver; the rest
//! get REFUSED. With an allowlist, that also closes DNS as a way to smuggle
//! data out, since an attacker's domain never gets resolved. Every query is
//! logged to stdout, which systemd sends to the journal.

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::net;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const HEADER_LEN: usize = 12;

pub fn serve() -> Result<()> {
    net::ensure_bridge()?;
    let Some(&upstream) = net::host_resolvers().first() else {
        bail!("no upstream resolver found in /run/systemd/resolve/resolv.conf or /etc/resolv.conf");
    };
    let udp = UdpSocket::bind((net::GATEWAY, 53)).context("bind udp 53")?;
    let tcp = TcpListener::bind((net::GATEWAY, 53)).context("bind tcp 53")?;
    println!("kiln dns: listening on {}:53, forwarding to {upstream}", net::GATEWAY);

    thread::spawn(move || {
        for stream in tcp.incoming().flatten() {
            thread::spawn(move || {
                let _ = serve_tcp(stream, upstream);
            });
        }
    });

    let mut buf = [0u8; 4096];
    loop {
        let (n, from) = udp.recv_from(&mut buf).context("recv")?;
        let query = buf[..n].to_vec();
        let udp = udp.try_clone().context("clone socket")?;
        thread::spawn(move || {
            if let Some(reply) = answer(&query, from, upstream, Transport::Udp) {
                let _ = udp.send_to(&reply, from);
            }
        });
    }
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

/// DNS over TCP: each message is prefixed with its length as a u16.
fn serve_tcp(mut stream: TcpStream, upstream: Ipv4Addr) -> Result<()> {
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    let from = stream.peer_addr()?;
    let query = read_tcp_message(&mut stream)?;
    if let Some(reply) = answer(&query, from, upstream, Transport::Tcp) {
        write_tcp_message(&mut stream, &reply)?;
    }
    Ok(())
}

/// Checks the policy and returns the reply to send, or `None` to drop a
/// malformed query.
fn answer(query: &[u8], from: SocketAddr, upstream: Ipv4Addr, transport: Transport) -> Option<Vec<u8>> {
    let IpAddr::V4(sandbox) = from.ip() else { return None };
    let question = parse_question(query)?;
    let allowed = allowed(sandbox, &question.name);
    println!(
        "{sandbox} {} {} {}",
        qtype_name(question.qtype),
        question.name,
        if allowed { "allowed" } else { "refused" }
    );
    if !allowed {
        return Some(refused(query, question.end));
    }
    let reply = match transport {
        Transport::Udp => forward_udp(query, upstream),
        Transport::Tcp => forward_tcp(query, upstream),
    };
    // On upstream failure, say so (SERVFAIL) rather than leave the client
    // waiting for its own timeout.
    Some(reply.unwrap_or_else(|_| error_reply(query, question.end, 2)))
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
    let mut stream = TcpStream::connect_timeout(&SocketAddr::from((upstream, 53)), UPSTREAM_TIMEOUT)?;
    stream.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    write_tcp_message(&mut stream, query)?;
    read_tcp_message(&mut stream)
}

fn read_tcp_message(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len)?;
    let mut msg = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut msg)?;
    Ok(msg)
}

fn write_tcp_message(stream: &mut TcpStream, msg: &[u8]) -> Result<()> {
    stream.write_all(&(msg.len() as u16).to_be_bytes())?;
    stream.write_all(msg)?;
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
