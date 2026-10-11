//! A small rtnetlink client: just enough to create bridges and veth pairs,
//! set links up, and add addresses and routes, without spawning `ip`.
//!
//! `ip` is itself a thin wrapper around this protocol. Netlink is a socket
//! family for talking to the kernel; NETLINK_ROUTE is the part that manages
//! interfaces, addresses and routes. Every request is laid out as
//!
//! ```text
//!   struct nlmsghdr   16 bytes: total length, type (RTM_NEWLINK, ...),
//!                     flags, sequence number, port ID
//!   family header     ifinfomsg (links), ifaddrmsg (addresses) or
//!                     rtmsg (routes)
//!   attributes        each a 4-byte header (length, type) and a payload,
//!                     padded to 4 bytes. An attribute can contain more
//!                     attributes (IFLA_LINKINFO holds the link's kind, ...)
//! ```
//!
//! With NLM_F_ACK the kernel answers every request with an NLMSG_ERROR
//! message whose error field is 0 on success or a negative errno. Spawning
//! `ip` costs about a millisecond (fork, exec, dynamic linking, parsing); a
//! netlink round trip costs a few microseconds.

use std::ffi::CString;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;

// <linux/netlink.h>
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLA_F_NESTED: u16 = 1 << 15;
const NLMSG_HDRLEN: usize = 16;

// <linux/rtnetlink.h>
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;
const RTA_GATEWAY: u16 = 5;

// <linux/if_link.h>, <linux/if_addr.h>, <linux/veth.h>
const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_PID: u16 = 19;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const IFLA_INFO_SLAVE_KIND: u16 = 4;
const IFLA_INFO_SLAVE_DATA: u16 = 5;
const IFLA_BRPORT_ISOLATED: u16 = 33;
const VETH_INFO_PEER: u16 = 1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const IFF_UP: u32 = libc::IFF_UP as u32;

/// An open NETLINK_ROUTE socket. It talks to the network namespace it was
/// created in, for as long as it lives.
pub struct Netlink {
    socket: OwnedFd,
    seq: u32,
}

impl Netlink {
    pub fn open() -> Result<Self> {
        // SAFETY: plain socket(2); the fd is owned right away.
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        Errno::result(fd).context("open netlink socket")?;
        // SAFETY: fd is a fresh descriptor nothing else owns.
        Ok(Netlink { socket: unsafe { OwnedFd::from_raw_fd(fd) }, seq: 0 })
    }

    /// `ip link add <name> type bridge`
    pub fn add_bridge(&mut self, name: &str) -> Result<()> {
        let mut req = Request::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &ifinfomsg(0, 0));
        req.attr(IFLA_IFNAME, &c_str(name)?);
        req.nested(IFLA_LINKINFO, |r| {
            r.attr(IFLA_INFO_KIND, b"bridge");
        });
        self.call(req).with_context(|| format!("create bridge {name}"))
    }

    /// `ip link add <host> master <bridge> type veth peer name <peer> netns <pid>`:
    /// one end stays here on the bridge, the other is created directly in
    /// the network namespace of process `pid`.
    pub fn add_veth(&mut self, host: &str, bridge: u32, peer: &str, pid: i32) -> Result<()> {
        let mut req = Request::new(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, &ifinfomsg(0, 0));
        req.attr(IFLA_IFNAME, &c_str(host)?);
        req.attr(IFLA_MASTER, &bridge.to_ne_bytes());
        let peer = c_str(peer)?;
        req.nested(IFLA_LINKINFO, |r| {
            r.attr(IFLA_INFO_KIND, b"veth");
            r.nested(IFLA_INFO_DATA, |r| {
                // The peer is described like a link of its own: an ifinfomsg
                // followed by its attributes.
                r.nested(VETH_INFO_PEER, |r| {
                    r.raw(&ifinfomsg(0, 0));
                    r.attr(IFLA_IFNAME, &peer);
                    r.attr(IFLA_NET_NS_PID, &pid.to_ne_bytes());
                });
            });
        });
        self.call(req).with_context(|| format!("create veth pair {host}"))
    }

    /// `ip link set dev <name> type bridge_slave isolated on`: an isolated
    /// bridge port can't exchange frames with other isolated ports.
    pub fn isolate_bridge_port(&mut self, name: &str) -> Result<()> {
        let mut req = Request::new(RTM_NEWLINK, 0, &ifinfomsg(0, 0));
        req.attr(IFLA_IFNAME, &c_str(name)?);
        req.nested(IFLA_LINKINFO, |r| {
            r.attr(IFLA_INFO_SLAVE_KIND, b"bridge");
            r.nested(IFLA_INFO_SLAVE_DATA, |r| {
                r.attr(IFLA_BRPORT_ISOLATED, &[1]);
            });
        });
        self.call(req).with_context(|| format!("isolate bridge port {name}"))
    }

    /// `ip link set <name> up`
    pub fn set_up(&mut self, name: &str) -> Result<()> {
        // ifi_change says which flags to change, ifi_flags their new values.
        let mut req = Request::new(RTM_NEWLINK, 0, &ifinfomsg(IFF_UP, IFF_UP));
        req.attr(IFLA_IFNAME, &c_str(name)?);
        self.call(req).with_context(|| format!("set {name} up"))
    }

    /// `ip link del <name>`
    pub fn delete_link(&mut self, name: &str) -> Result<()> {
        let mut req = Request::new(RTM_DELLINK, 0, &ifinfomsg(0, 0));
        req.attr(IFLA_IFNAME, &c_str(name)?);
        self.call(req).with_context(|| format!("delete {name}"))
    }

    /// `ip addr add <addr>/<prefix> dev <name>`
    pub fn add_address(&mut self, name: &str, addr: Ipv4Addr, prefix: u8) -> Result<()> {
        // struct ifaddrmsg: family, prefix length, flags, scope, interface index.
        let mut header = vec![libc::AF_INET as u8, prefix, 0, RT_SCOPE_UNIVERSE];
        header.extend(index(name)?.to_ne_bytes());
        let mut req = Request::new(RTM_NEWADDR, NLM_F_CREATE | NLM_F_EXCL, &header);
        // For IPv4, LOCAL is the interface's address and ADDRESS the peer's,
        // which on a broadcast link is the same.
        req.attr(IFA_LOCAL, &addr.octets());
        req.attr(IFA_ADDRESS, &addr.octets());
        self.call(req).with_context(|| format!("add {addr}/{prefix} to {name}"))
    }

    /// `ip route add default via <gateway>`
    pub fn add_default_route(&mut self, gateway: Ipv4Addr) -> Result<()> {
        // struct rtmsg: family, dst_len (0 = default route), src_len, tos,
        // table, protocol, scope, type, then 32 bits of flags.
        let header = [
            libc::AF_INET as u8, 0, 0, 0, RT_TABLE_MAIN, RTPROT_BOOT, RT_SCOPE_UNIVERSE, RTN_UNICAST, 0, 0, 0, 0,
        ];
        let mut req = Request::new(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_EXCL, &header);
        req.attr(RTA_GATEWAY, &gateway.octets());
        self.call(req).with_context(|| format!("add default route via {gateway}"))
    }

    /// Sends one request and waits for the kernel's acknowledgement.
    fn call(&mut self, mut req: Request) -> Result<()> {
        self.seq += 1;
        let len = req.buf.len() as u32;
        req.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        req.buf[8..12].copy_from_slice(&self.seq.to_ne_bytes());
        let fd = self.socket.as_raw_fd();
        // No address: an unconnected netlink socket sends to the kernel.
        // SAFETY: sends from a live buffer of the given length.
        let sent = unsafe { libc::send(fd, req.buf.as_ptr().cast(), req.buf.len(), 0) };
        Errno::result(sent).context("netlink send")?;

        let mut reply = [0u8; 4096];
        loop {
            // SAFETY: receives into a live buffer of the given length.
            let n = unsafe { libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0) };
            let n = Errno::result(n).context("netlink recv")? as usize;
            let mut msg = &reply[..n];
            while msg.len() >= NLMSG_HDRLEN {
                let msg_len = u32::from_ne_bytes(msg[0..4].try_into()?) as usize;
                let kind = u16::from_ne_bytes(msg[4..6].try_into()?);
                let seq = u32::from_ne_bytes(msg[8..12].try_into()?);
                if msg_len < NLMSG_HDRLEN || msg_len > msg.len() {
                    bail!("malformed netlink reply");
                }
                if kind == NLMSG_ERROR && seq == self.seq {
                    // struct nlmsgerr: int error, then a copy of our header.
                    let error = i32::from_ne_bytes(msg.get(16..20).context("short netlink error")?.try_into()?);
                    return match error {
                        0 => Ok(()),
                        e => Err(Errno::from_raw(-e).into()),
                    };
                }
                msg = &msg[align(msg_len).min(msg.len())..];
            }
        }
    }
}

/// The interface index of `name` in this network namespace.
pub fn index(name: &str) -> Result<u32> {
    let c = CString::new(name)?;
    // SAFETY: c is a valid C string.
    match unsafe { libc::if_nametoindex(c.as_ptr()) } {
        0 => Err(std::io::Error::last_os_error()).with_context(|| format!("find interface {name}")),
        i => Ok(i),
    }
}

/// One request being built: a header with the length and sequence number
/// left blank (filled in by `call`), then the family header and attributes.
struct Request {
    buf: Vec<u8>,
}

impl Request {
    fn new(kind: u16, flags: u16, family_header: &[u8]) -> Self {
        let mut req = Request { buf: vec![0; NLMSG_HDRLEN] };
        req.buf[4..6].copy_from_slice(&kind.to_ne_bytes());
        req.buf[6..8].copy_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        req.raw(family_header);
        req
    }

    /// Appends bytes as they are, padded to 4 bytes.
    fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        self.buf.resize(align(self.buf.len()), 0);
    }

    fn attr(&mut self, kind: u16, payload: &[u8]) {
        self.buf.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.raw(payload);
    }

    /// An attribute whose payload is whatever `fill` appends; its length is
    /// patched in afterwards.
    fn nested(&mut self, kind: u16, fill: impl FnOnce(&mut Self)) {
        let start = self.buf.len();
        self.attr(kind | NLA_F_NESTED, &[]);
        fill(self);
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }
}

/// struct ifinfomsg: family, padding, device type, index (0 = look the link
/// up by IFLA_IFNAME), flags, and which flags to change.
fn ifinfomsg(flags: u32, change: u32) -> [u8; 16] {
    let mut m = [0u8; 16];
    m[0] = libc::AF_UNSPEC as u8;
    m[8..12].copy_from_slice(&flags.to_ne_bytes());
    m[12..16].copy_from_slice(&change.to_ne_bytes());
    m
}

fn c_str(s: &str) -> Result<Vec<u8>> {
    Ok(CString::new(s)?.into_bytes_with_nul())
}

fn align(len: usize) -> usize {
    (len + 3) & !3
}
