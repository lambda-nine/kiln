//! Persistent exec protocol v1. Workload bytes never enter this codec.
use std::io::{ErrorKind, Read};
use std::os::fd::RawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};

pub const VERSION: u16 = 1;
pub const MAGIC: &[u8; 8] = b"KILNEXO\0";
pub const MAX_PAYLOAD: usize = 2072;
pub const MAX_FRAME: usize = 16 + MAX_PAYLOAD;
pub const MAX_DIAGNOSTIC: usize = 2048;
pub const FRAME_TIMEOUT: Duration = Duration::from_secs(2);
// Assigned in the order specified by the protocol, not package versions.
pub const REQUIRED_FEATURES: u32 = 0x0f;
/// Persistent-create failures before allocation have the documented exit 124.
pub const CREATE_PREFLIGHT_FEATURE: u32 = 0x10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    Exited(i32),
    Signaled { signal: i32, core_dumped: bool },
}

impl CommandStatus {
    pub fn projection(self) -> i32 {
        match self { Self::Exited(code) => code, Self::Signaled { signal, .. } => 128 + signal }
    }
}

macro_rules! wire_enum {
    ($name:ident { $($variant:ident = $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u16)]
        pub enum $name { $($variant = $value),+ }
        impl TryFrom<u16> for $name {
            type Error = anyhow::Error;
            fn try_from(value: u16) -> Result<Self> {
                match value { $($value => Ok(Self::$variant),)+ _ => bail!(concat!("unknown ", stringify!($name), " {}"), value) }
            }
        }
    };
}

wire_enum!(FailureKind {
    None = 0, InvalidRequest = 1, Unavailable = 2, NotFound = 3,
    Incompatible = 4, Busy = 5, LaunchFailed = 6, Io = 7, Protocol = 8,
    CleanupFailed = 9, Internal = 10, Stopped = 11,
});
wire_enum!(Stage {
    None = 0, Validate = 1, Connect = 2, Request = 3, Prepare = 4, Fork = 5,
    Admission = 6, Stdio = 7, Exec = 8, Wait = 9, Cleanup = 10,
    Report = 11, Capture = 12, Handshake = 13,
});
wire_enum!(Cleanup { Unconfirmed = 0, NoChildStarted = 1, Drained = 2 });

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub status: Option<CommandStatus>,
    pub cleanup: Cleanup,
    pub kind: FailureKind,
    pub stage: Stage,
    pub errno: i32,
    pub diagnostic: String,
    pub diagnostic_truncated: bool,
}

impl Outcome {
    pub fn command(status: CommandStatus) -> Self {
        Self { status: Some(status), cleanup: Cleanup::Drained, kind: FailureKind::None,
            stage: Stage::None, errno: 0, diagnostic: String::new(), diagnostic_truncated: false }
    }

    pub fn failure(kind: FailureKind, stage: Stage, cleanup: Cleanup, errno: i32, message: &str) -> Self {
        let mut end = message.len().min(MAX_DIAGNOSTIC);
        while !message.is_char_boundary(end) { end -= 1; }
        Self { status: None, cleanup, kind, stage, errno: errno.max(0),
            diagnostic: message[..end].to_owned(), diagnostic_truncated: end < message.len() }
    }

    pub fn projection(&self) -> i32 {
        if self.kind == FailureKind::None {
            return self.status.unwrap().projection();
        }
        if self.kind == FailureKind::LaunchFailed {
            return match self.stage {
                Stage::Exec => 127,
                Stage::Admission | Stage::Stdio => 126,
                _ => 125,
            };
        }
        125
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.errno >= 0, "negative errno");
        ensure!(self.diagnostic.len() <= MAX_DIAGNOSTIC, "diagnostic too large");
        if let Some(status) = self.status {
            match status {
                CommandStatus::Exited(code) => ensure!((0..=255).contains(&code), "invalid exit code"),
                CommandStatus::Signaled { signal, .. } => ensure!((1..=64).contains(&signal), "invalid signal"),
            }
            ensure!(self.cleanup != Cleanup::NoChildStarted, "termination without a child");
        }
        if self.kind == FailureKind::None {
            ensure!(self.status.is_some() && self.cleanup == Cleanup::Drained, "command must terminate and drain");
            ensure!(self.stage == Stage::None && self.errno == 0 && self.diagnostic.is_empty()
                && !self.diagnostic_truncated, "command has diagnostic fields");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub features: u32,
    pub control_version: u16,
    pub status_fd_version: u16,
    pub package: String,
    pub provenance: String,
}

impl Capabilities {
    pub fn current() -> Self {
        Self { features: REQUIRED_FEATURES | CREATE_PREFLIGHT_FEATURE, control_version: VERSION, status_fd_version: VERSION,
            package: env!("CARGO_PKG_VERSION").into(), provenance: env!("KILN_GIT").into() }
    }

    pub fn require_v1(&self) -> Result<()> {
        ensure!(self.features & REQUIRED_FEATURES == REQUIRED_FEATURES
            && self.control_version == VERSION && self.status_fd_version == VERSION,
            "incompatible persistent-exec capabilities: {self:?}; require protocol 1");
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame { Outcome(Outcome), Capabilities(Capabilities) }

impl Frame {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let (ty, payload) = match self {
            Self::Outcome(o) => {
                o.validate()?;
                let mut p = vec![0u8; 24];
                p[0] = if o.kind == FailureKind::None { 1 } else { 2 };
                let (termination, value, core) = match o.status {
                    None => (0, 0i32, false),
                    Some(CommandStatus::Exited(c)) => (1, c, false),
                    Some(CommandStatus::Signaled { signal, core_dumped }) => (2, signal, core_dumped),
                };
                p[1] = termination;
                p[2] = o.cleanup as u8;
                p[3] = u8::from(core) | (u8::from(o.diagnostic_truncated) << 1);
                p[4..8].copy_from_slice(&value.to_le_bytes());
                p[8..10].copy_from_slice(&(o.kind as u16).to_le_bytes());
                p[10..12].copy_from_slice(&(o.stage as u16).to_le_bytes());
                p[12..16].copy_from_slice(&o.errno.to_le_bytes());
                p[16..20].copy_from_slice(&(o.diagnostic.len() as u32).to_le_bytes());
                p.extend_from_slice(o.diagnostic.as_bytes());
                (1u16, p)
            }
            Self::Capabilities(c) => {
                ensure!(c.package.len() <= 64 && c.provenance.len() <= 128, "capability strings too large");
                let mut p = Vec::new();
                p.extend_from_slice(&c.features.to_le_bytes());
                p.extend_from_slice(&c.control_version.to_le_bytes());
                p.extend_from_slice(&c.status_fd_version.to_le_bytes());
                p.extend_from_slice(&(c.package.len() as u16).to_le_bytes());
                p.extend_from_slice(&(c.provenance.len() as u16).to_le_bytes());
                p.extend_from_slice(&[0; 4]);
                p.extend_from_slice(c.package.as_bytes());
                p.extend_from_slice(c.provenance.as_bytes());
                (2, p)
            }
        };
        let mut frame = Vec::with_capacity(16 + payload.len());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&VERSION.to_le_bytes());
        frame.extend_from_slice(&ty.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        Ok(frame)
    }

    /// A single complete frame including EOF; trailing/duplicate bytes are invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= 16, "truncated reply header");
        let (ty, len) = header(&bytes[..16])?;
        ensure!(bytes.len() == 16 + len, "truncated or trailing reply data");
        let p = &bytes[16..];
        match ty {
            1 => {
                ensure!(p.len() >= 24, "truncated outcome");
                ensure!(p[3] & !3 == 0 && p[20..24] == [0; 4], "unknown flags or reserved bytes");
                let value = i32::from_le_bytes(p[4..8].try_into().unwrap());
                let status = match p[1] {
                    0 => { ensure!(value == 0, "unobserved termination value"); None }
                    1 => Some(CommandStatus::Exited(value)),
                    2 => Some(CommandStatus::Signaled { signal: value, core_dumped: p[3] & 1 != 0 }),
                    _ => bail!("unknown termination"),
                };
                ensure!(p[1] == 2 || p[3] & 1 == 0, "core flag without signal");
                let kind = FailureKind::try_from(u16::from_le_bytes(p[8..10].try_into().unwrap()))?;
                ensure!(matches!(p[0], 1 | 2) && (p[0] == 1) == (kind == FailureKind::None), "invalid outcome kind");
                let n = u32::from_le_bytes(p[16..20].try_into().unwrap()) as usize;
                ensure!(n <= MAX_DIAGNOSTIC && p.len() == 24 + n, "invalid diagnostic length");
                let o = Outcome { status, cleanup: Cleanup::try_from(p[2] as u16)?, kind,
                    stage: Stage::try_from(u16::from_le_bytes(p[10..12].try_into().unwrap()))?,
                    errno: i32::from_le_bytes(p[12..16].try_into().unwrap()),
                    diagnostic: std::str::from_utf8(&p[24..]).context("invalid diagnostic UTF-8")?.into(),
                    diagnostic_truncated: p[3] & 2 != 0 };
                o.validate()?;
                Ok(Self::Outcome(o))
            }
            2 => {
                ensure!(p.len() >= 16, "truncated capabilities");
                let a = u16::from_le_bytes(p[8..10].try_into().unwrap()) as usize;
                let b = u16::from_le_bytes(p[10..12].try_into().unwrap()) as usize;
                ensure!(a <= 64 && b <= 128 && p.len() == 16 + a + b, "invalid capability lengths");
                ensure!(p[12..16] == [0; 4], "capability reserved bytes");
                Ok(Self::Capabilities(Capabilities {
                    features: u32::from_le_bytes(p[..4].try_into().unwrap()),
                    control_version: u16::from_le_bytes(p[4..6].try_into().unwrap()),
                    status_fd_version: u16::from_le_bytes(p[6..8].try_into().unwrap()),
                    package: std::str::from_utf8(&p[16..16+a])?.into(),
                    provenance: std::str::from_utf8(&p[16+a..])?.into(),
                }))
            }
            _ => unreachable!(),
        }
    }
}

fn header(bytes: &[u8]) -> Result<(u16, usize)> {
    ensure!(&bytes[..8] == MAGIC, "malformed reply magic");
    ensure!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()) == VERSION, "unsupported reply version");
    let ty = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
    ensure!(matches!(ty, 1 | 2), "unknown reply type");
    let len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    ensure!(len <= MAX_PAYLOAD, "reply payload too large");
    Ok((ty, len))
}

/// First exec byte may wait for the workload; after it arrives framing and EOF
/// have an absolute deadline. Probes instead supply an overall deadline.
pub fn read_reply(stream: &mut UnixStream, overall: Option<Instant>) -> Result<Frame> {
    let mut bytes = Vec::with_capacity(MAX_FRAME);
    let mut deadline = overall;
    loop {
        stream.set_read_timeout(match deadline {
            Some(d) => Some(d.checked_duration_since(Instant::now()).context("incomplete reply framing deadline")?),
            None => None,
        })?;
        let mut chunk = [0u8; MAX_FRAME + 1];
        let read = stream.read(&mut chunk[..(MAX_FRAME + 1 - bytes.len())]);
        if let Some(d) = deadline { ensure!(Instant::now() < d, "incomplete reply framing deadline"); }
        match read {
            Ok(0) => {
                ensure!(!bytes.is_empty(), "missing control response");
                return Frame::decode(&bytes);
            }
            Ok(n) => {
                if deadline.is_none() { deadline = Some(Instant::now() + FRAME_TIMEOUT); }
                bytes.extend_from_slice(&chunk[..n]);
                ensure!(bytes.len() <= MAX_FRAME, "trailing or oversized reply");
                if bytes.len() >= 16 {
                    let (_, len) = header(&bytes[..16])?;
                    ensure!(bytes.len() <= 16 + len, "trailing or duplicate reply");
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::ConnectionReset => {
                // Header-only busy refusal intentionally leaves request bytes
                // unread. Linux may terminate that Unix stream with ECONNRESET
                // after delivering the complete reply instead of a clean EOF.
                let frame = Frame::decode(&bytes).context("reset before complete busy reply")?;
                ensure!(matches!(&frame, Frame::Outcome(o) if o.kind == FailureKind::Busy
                    && o.cleanup == Cleanup::NoChildStarted && o.status.is_none()),
                    "reset without complete busy reply");
                return Ok(frame);
            }
            Err(e) => return Err(e).context("incomplete control response"),
        }
    }
}

/// MSG_DONTWAIT avoids changing the peer-shared open-file flags. Service the
/// supplied signal callback between partial writes and while waiting for space.
pub fn write_bounded(fd: RawFd, bytes: &[u8], mut signals: impl FnMut() -> Result<()>) -> Result<()> {
    write_loop(bytes, |remaining| {
        let n = unsafe { libc::send(fd, remaining.as_ptr().cast(), remaining.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }, || {
        let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        // A short polling slice also services the lifetime signalfd callback.
        let n = unsafe { libc::poll(&mut p, 1, 20) };
        if n < 0 && std::io::Error::last_os_error().kind() != ErrorKind::Interrupted {
            return Err(std::io::Error::last_os_error()).context("poll control response");
        }
        Ok(())
    }, &mut signals)
}

fn write_loop(bytes: &[u8], mut send: impl FnMut(&[u8]) -> std::io::Result<usize>,
    mut wait: impl FnMut() -> Result<()>, mut signals: impl FnMut() -> Result<()>) -> Result<()> {
    let deadline = Instant::now() + FRAME_TIMEOUT;
    let mut at = 0;
    while at < bytes.len() {
        if at != 0 { signals()?; }
        ensure!(Instant::now() < deadline, "response write deadline");
        let e = match send(&bytes[at..]) {
            Ok(0) => bail!("response write made no progress"),
            Ok(n) => { at += n; continue; }
            Err(e) => e,
        };
        if e.kind() == ErrorKind::Interrupted { continue; }
        if e.kind() != ErrorKind::WouldBlock { return Err(e).context("write control response"); }
        signals()?;
        wait()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;

    #[test]
    fn current_build_advertises_create_preflight_certainty_additively() {
        let caps = Capabilities::current();
        caps.require_v1().unwrap();
        assert_eq!(caps.features & CREATE_PREFLIGHT_FEATURE, CREATE_PREFLIGHT_FEATURE);
        let mut execution_only = caps;
        execution_only.features = REQUIRED_FEATURES;
        execution_only.require_v1().unwrap();
    }

    #[test]
    fn golden_exit_125() {
        let bytes = Frame::Outcome(Outcome::command(CommandStatus::Exited(125))).encode().unwrap();
        assert_eq!(bytes, b"KILNEXO\0\x01\0\x01\0\x18\0\0\0\x01\x01\x02\0\x7d\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(Frame::decode(&bytes).unwrap().encode().unwrap(), bytes);
    }

    #[test]
    fn golden_capabilities() {
        let frame = Frame::Capabilities(Capabilities { features: 15, control_version: 1,
            status_fd_version: 1, package: "0.1.0".into(), provenance: "git test".into() });
        let bytes = b"KILNEXO\0\x01\0\x02\0\x1d\0\0\0\x0f\0\0\0\x01\0\x01\0\x05\0\x08\0\0\0\0\x000.1.0git test";
        assert_eq!(frame.encode().unwrap(), bytes);
        assert_eq!(Frame::decode(bytes).unwrap(), frame);
        let mut bad = bytes.to_vec(); bad[28] = 1;
        assert!(Frame::decode(&bad).is_err());
        let mut bad = bytes.to_vec(); bad[24] = 65;
        assert!(Frame::decode(&bad).is_err());
        let mut bad = bytes.to_vec(); bad[32] = 255;
        assert!(Frame::decode(&bad).is_err());
        let Frame::Capabilities(mut capabilities) = frame else { unreachable!() };
        capabilities.features = 0x8000000f;
        capabilities.require_v1().unwrap();
        capabilities.features &= !1;
        assert!(capabilities.require_v1().is_err());
    }

    #[test]
    fn maximum_diagnostic_truncates_on_a_utf8_boundary() {
        let message = "a".repeat(2047) + "é";
        let o = Outcome::failure(FailureKind::Io, Stage::Wait, Cleanup::Drained, 5, &message);
        assert_eq!(o.diagnostic.len(), 2047);
        assert!(o.diagnostic_truncated);
        let max = Frame::Outcome(Outcome::failure(FailureKind::Io, Stage::Wait, Cleanup::Drained, 5, &"x".repeat(2048)));
        assert_eq!(max.encode().unwrap().len(), MAX_FRAME);
        assert_eq!(Frame::decode(&max.encode().unwrap()).unwrap(), max);
        let mut invalid = Outcome::command(CommandStatus::Exited(256));
        assert!(Frame::Outcome(invalid.clone()).encode().is_err());
        invalid.status = Some(CommandStatus::Signaled { signal: 65, core_dumped: false });
        assert!(Frame::Outcome(invalid).encode().is_err());
    }

    #[test]
    fn writer_retries_short_writes_eintr_and_eagain_without_duplication() {
        let mut attempts = 0;
        let mut output = Vec::new();
        let mut waits = 0;
        let mut callbacks = 0;
        write_loop(b"exactly once", |bytes| {
            attempts += 1;
            match attempts {
                1 | 5 => Err(std::io::Error::from_raw_os_error(libc::EINTR)),
                2 | 4 => Err(std::io::Error::from_raw_os_error(libc::EAGAIN)),
                _ => { let n = bytes.len().min(3); output.extend_from_slice(&bytes[..n]); Ok(n) }
            }
        }, || { waits += 1; Ok(()) }, || { callbacks += 1; Ok(()) }).unwrap();
        assert_eq!(output, b"exactly once");
        assert_eq!(waits, 2);
        assert!(callbacks >= 2);
    }

    #[test]
    fn strict_frames_and_every_split() {
        let frames = [Frame::Outcome(Outcome::command(CommandStatus::Signaled { signal: 15, core_dumped: true })),
            Frame::Outcome(Outcome::failure(FailureKind::LaunchFailed, Stage::Exec, Cleanup::Drained, 2, "exec")),
            Frame::Capabilities(Capabilities { features: 15, control_version: 1, status_fd_version: 1,
                package: "0.1.0".into(), provenance: "git test".into() })];
        for frame in frames {
            let bytes = frame.encode().unwrap();
            for split in 0..=bytes.len() {
                let (mut tx, mut rx) = UnixStream::pair().unwrap();
                let b = bytes.clone();
                let t = std::thread::spawn(move || { tx.write_all(&b[..split]).unwrap();
                    std::thread::yield_now(); tx.write_all(&b[split..]).unwrap(); });
                assert_eq!(read_reply(&mut rx, Some(Instant::now() + FRAME_TIMEOUT)).unwrap(), frame);
                t.join().unwrap();
            }
            for end in 0..bytes.len() { assert!(Frame::decode(&bytes[..end]).is_err()); }
            let mut duplicate = bytes.clone(); duplicate.extend_from_slice(&bytes);
            assert!(Frame::decode(&duplicate).is_err());
            let mut trailing = bytes.clone(); trailing.push(0);
            assert!(Frame::decode(&trailing).is_err());
        }
    }

    #[test]
    fn transport_rejects_legacy_truncated_duplicate_and_trailing_replies() {
        let bytes = Frame::Outcome(Outcome::command(CommandStatus::Exited(0))).encode().unwrap();
        let mut duplicate = bytes.clone(); duplicate.extend_from_slice(&bytes);
        let mut trailing = bytes.clone(); trailing.push(0);
        for bad in [vec![], vec![125, 0, 0, 0], bytes[..39].to_vec(), duplicate, trailing] {
            let (mut tx, mut rx) = UnixStream::pair().unwrap();
            tx.write_all(&bad).unwrap(); drop(tx);
            assert!(read_reply(&mut rx, Some(Instant::now() + FRAME_TIMEOUT)).is_err());
        }
        let (mut tx, mut rx) = UnixStream::pair().unwrap();
        tx.write_all(&bytes).unwrap(); // A valid frame without EOF is incomplete.
        assert!(read_reply(&mut rx, Some(Instant::now() + Duration::from_millis(20))).is_err());
    }

    #[test]
    fn reset_after_unread_request_accepts_only_one_complete_busy_frame() {
        let busy = Frame::Outcome(Outcome::failure(FailureKind::Busy, Stage::Validate,
            Cleanup::NoChildStarted, 0, "active")).encode().unwrap();
        let command = Frame::Outcome(Outcome::command(CommandStatus::Exited(0))).encode().unwrap();
        let mut trailing = busy.clone(); trailing.push(0);
        for (bytes, accepted) in [(busy.clone(), true), (busy[..20].to_vec(), false),
            (command, false), (trailing, false)] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client.write_all(b"unread request body").unwrap();
            server.write_all(&bytes).unwrap();
            drop(server);
            assert_eq!(read_reply(&mut client, Some(Instant::now() + FRAME_TIMEOUT)).is_ok(), accepted);
        }
    }

    #[test]
    fn rejects_mutations_before_allocation() {
        let bytes = Frame::Outcome(Outcome::command(CommandStatus::Exited(0))).encode().unwrap();
        for (at, value) in [(0, 0), (8, 2), (10, 3), (12, 255), (16, 3), (17, 3),
            (18, 3), (19, 4), (19, 1), (24, 1), (26, 1), (28, 255), (32, 1), (36, 1)] {
            let mut bad = bytes.clone(); bad[at] = value;
            assert!(Frame::decode(&bad).is_err(), "offset {at}");
        }
        let mut bad = Frame::Outcome(Outcome::failure(FailureKind::Io, Stage::Report,
            Cleanup::Unconfirmed, 1, "x")).encode().unwrap();
        bad[40] = 255;
        assert!(Frame::decode(&bad).is_err());
    }

    #[test]
    fn bounded_writer_disconnect_and_nonreader() {
        let (tx, rx) = UnixStream::pair().unwrap(); drop(rx);
        assert!(write_bounded(tx.as_raw_fd(), b"x", || Ok(())).is_err());
        let (tx, _rx) = UnixStream::pair().unwrap();
        let size = 1024i32;
        unsafe { libc::setsockopt(tx.as_raw_fd(), libc::SOL_SOCKET, libc::SO_SNDBUF,
            (&size as *const i32).cast(), 4); }
        let start = Instant::now();
        let mut callbacks = 0;
        assert!(write_bounded(tx.as_raw_fd(), &vec![0; 1024 * 1024], || { callbacks += 1; Ok(()) }).is_err());
        assert!(start.elapsed() < Duration::from_secs(4));
        assert!(callbacks > 2);
    }
}
