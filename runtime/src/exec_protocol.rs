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
/// PID 1 accepts typed operation 5 (exec options: cwd and environment), and
/// the CLI accepts `--exec-options-fd`. Additive: older PID 1 instances
/// without it still serve operation 4.
pub const EXEC_OPTIONS_FEATURE: u32 = 0x20;
/// PID 1 grants operation 6 (checkpoint lease) and the CLI accepts
/// `kiln checkpoint-lease`. Additive like bits 4 and 5: PID 1 instances
/// without it are refused by the CLI before any lease byte is sent.
pub const CHECKPOINT_LEASE_FEATURE: u32 = 0x40;
/// Reply type 3: a checkpoint lease state frame.
pub const LEASE_PAYLOAD: usize = 16;
/// The holder's lease acknowledgment, sent only after its last source read.
pub const ACK_MAGIC: &[u8; 8] = b"KILNACK\0";
pub const ACK_LEN: usize = 16;

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
    Report = 11, Capture = 12, Handshake = 13, Chdir = 14, Lease = 15,
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
                Stage::Admission | Stage::Stdio | Stage::Chdir => 126,
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
        Self { features: REQUIRED_FEATURES | CREATE_PREFLIGHT_FEATURE | EXEC_OPTIONS_FEATURE
                | CHECKPOINT_LEASE_FEATURE,
            control_version: VERSION, status_fd_version: VERSION,
            package: env!("CARGO_PKG_VERSION").into(), provenance: env!("KILN_GIT").into() }
    }

    pub fn require_v1(&self) -> Result<()> {
        ensure!(self.features & REQUIRED_FEATURES == REQUIRED_FEATURES
            && self.control_version == VERSION && self.status_fd_version == VERSION,
            "incompatible persistent-exec capabilities: {self:?}; require protocol 1");
        Ok(())
    }
}

/// The state a lease frame reports. Granted starts the lease on this
/// connection; Released confirms a valid acknowledgment of that same lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseState { Granted = 1, Released = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub state: LeaseState,
    /// Nonzero, increasing for each lease one PID 1 grants. It names the lease
    /// an acknowledgment refers to; it is not a secret or a boot identity.
    pub generation: u64,
}

/// The holder's 16-byte acknowledgment: `KILNACK\0`, then the generation it
/// was granted, LE u64. It is the only byte sequence a lease holder sends.
pub fn encode_ack(generation: u64) -> [u8; ACK_LEN] {
    let mut ack = [0u8; ACK_LEN];
    ack[..8].copy_from_slice(ACK_MAGIC);
    ack[8..].copy_from_slice(&generation.to_le_bytes());
    ack
}

/// Returns the acknowledged generation of exactly one valid record.
pub fn decode_ack(bytes: &[u8]) -> Result<u64> {
    ensure!(bytes.len() == ACK_LEN, "lease acknowledgment must be exactly {ACK_LEN} bytes");
    ensure!(&bytes[..8] == ACK_MAGIC, "malformed lease acknowledgment magic");
    let generation = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    ensure!(generation != 0, "lease acknowledgment for generation 0");
    Ok(generation)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame { Outcome(Outcome), Capabilities(Capabilities), Lease(Lease) }

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
            Self::Lease(l) => {
                ensure!(l.generation != 0, "lease generation 0");
                let mut p = vec![0u8; LEASE_PAYLOAD];
                p[0] = l.state as u8;
                p[8..].copy_from_slice(&l.generation.to_le_bytes());
                (3, p)
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
            3 => {
                ensure!(p.len() == LEASE_PAYLOAD, "invalid lease payload length");
                ensure!(p[1..8] == [0; 7], "lease reserved bytes");
                let state = match p[0] { 1 => LeaseState::Granted, 2 => LeaseState::Released,
                    _ => bail!("unknown lease state") };
                let generation = u64::from_le_bytes(p[8..].try_into().unwrap());
                ensure!(generation != 0, "lease generation 0");
                Ok(Self::Lease(Lease { state, generation }))
            }
            _ => unreachable!(),
        }
    }
}

fn header(bytes: &[u8]) -> Result<(u16, usize)> {
    ensure!(&bytes[..8] == MAGIC, "malformed reply magic");
    ensure!(u16::from_le_bytes(bytes[8..10].try_into().unwrap()) == VERSION, "unsupported reply version");
    let ty = u16::from_le_bytes(bytes[10..12].try_into().unwrap());
    ensure!(matches!(ty, 1..=3), "unknown reply type");
    let len = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    ensure!(len <= MAX_PAYLOAD, "reply payload too large");
    Ok((ty, len))
}

/// The total length of the frame this validated reply header starts.
pub fn frame_len(bytes: &[u8; 16]) -> Result<usize> {
    Ok(16 + header(bytes)?.1)
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

/// Reads exactly one frame and nothing after it, for a connection that carries
/// more than one (the lease connection and the lease status stream). Like
/// `read_reply`, `overall` bounds the whole read; without it the first byte may
/// wait indefinitely and the rest of the frame then has `FRAME_TIMEOUT`. A
/// reset or EOF before the frame is complete is an error. The lease CLI reads
/// a grant with `persistent.rs`'s cancellable reader, which keeps these
/// semantics; the capture worker, which has no driver socket, uses this one.
pub fn read_frame(stream: &mut UnixStream, overall: Option<Instant>) -> Result<Frame> {
    let mut bytes = vec![0u8; 16];
    let mut at = 0;
    let mut deadline = overall;
    let mut want = 16;
    while at < want {
        stream.set_read_timeout(match deadline {
            Some(d) => Some(d.checked_duration_since(Instant::now()).context("incomplete frame deadline")?),
            None => None,
        })?;
        let read = stream.read(&mut bytes[at..want]);
        if let Some(d) = deadline { ensure!(Instant::now() < d, "incomplete frame deadline"); }
        match read {
            Ok(0) => bail!(if at == 0 { "missing control frame" } else { "truncated control frame" }),
            Ok(n) => {
                if deadline.is_none() { deadline = Some(Instant::now() + FRAME_TIMEOUT); }
                at += n;
                if at == 16 && want == 16 {
                    let (_, len) = header(&bytes[..16])?;
                    want = 16 + len;
                    bytes.resize(want, 0);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e).context("incomplete control frame"),
        }
    }
    Frame::decode(&bytes)
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
        assert_eq!(caps.features, 0x7f);
        assert_eq!(caps.features & CHECKPOINT_LEASE_FEATURE, 0x40);
        let mut execution_only = caps;
        execution_only.features = REQUIRED_FEATURES;
        execution_only.require_v1().unwrap();
    }

    #[test]
    fn golden_lease_frames_and_acknowledgment() {
        let granted = Frame::Lease(Lease { state: LeaseState::Granted, generation: 1 });
        let bytes = granted.encode().unwrap();
        assert_eq!(bytes, b"KILNEXO\0\x01\0\x03\0\x10\0\0\0\x01\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0");
        assert_eq!(Frame::decode(&bytes).unwrap(), granted);
        let released = Frame::Lease(Lease { state: LeaseState::Released, generation: 0x0102030405060708 });
        assert_eq!(&released.encode().unwrap()[16..],
            b"\x02\0\0\0\0\0\0\0\x08\x07\x06\x05\x04\x03\x02\x01");
        // Unknown state, reserved bytes, generation 0, short/long payloads.
        for (at, value) in [(16, 0), (16, 3), (17, 1), (23, 1)] {
            let mut bad = bytes.clone(); bad[at] = value;
            assert!(Frame::decode(&bad).is_err(), "offset {at}");
        }
        let mut zero = bytes.clone(); zero[24] = 0;
        assert!(Frame::decode(&zero).is_err());
        let mut long = bytes.clone(); long[12] = 17; long.push(0);
        assert!(Frame::decode(&long).is_err());
        let mut short = bytes[..31].to_vec(); short[12] = 15;
        assert!(Frame::decode(&short).is_err());
        assert!(Frame::Lease(Lease { state: LeaseState::Granted, generation: 0 }).encode().is_err());

        assert_eq!(&encode_ack(1), b"KILNACK\0\x01\0\0\0\0\0\0\0");
        assert_eq!(decode_ack(&encode_ack(u64::MAX)).unwrap(), u64::MAX);
        assert!(decode_ack(&encode_ack(0)).is_err());
        assert!(decode_ack(&encode_ack(1)[..15]).is_err());
        let mut trailing = encode_ack(1).to_vec(); trailing.push(0);
        assert!(decode_ack(&trailing).is_err());
        let mut magic = encode_ack(1); magic[0] = b'X';
        assert!(decode_ack(&magic).is_err());
    }

    #[test]
    fn read_frame_takes_exactly_one_frame_at_every_split() {
        let first = Frame::Lease(Lease { state: LeaseState::Granted, generation: 7 }).encode().unwrap();
        let second = Frame::Lease(Lease { state: LeaseState::Released, generation: 7 }).encode().unwrap();
        let mut both = first.clone(); both.extend_from_slice(&second);
        for split in 0..=both.len() {
            let (mut tx, mut rx) = UnixStream::pair().unwrap();
            let b = both.clone();
            let t = std::thread::spawn(move || { tx.write_all(&b[..split]).unwrap();
                std::thread::yield_now(); tx.write_all(&b[split..]).unwrap(); });
            assert_eq!(read_frame(&mut rx, Some(Instant::now() + FRAME_TIMEOUT)).unwrap(),
                Frame::decode(&first).unwrap());
            assert_eq!(read_frame(&mut rx, Some(Instant::now() + FRAME_TIMEOUT)).unwrap(),
                Frame::decode(&second).unwrap());
            t.join().unwrap();
            assert!(read_frame(&mut rx, Some(Instant::now() + FRAME_TIMEOUT)).is_err(), "EOF is not a frame");
        }
        for end in 1..first.len() {
            let (mut tx, mut rx) = UnixStream::pair().unwrap();
            tx.write_all(&first[..end]).unwrap(); drop(tx);
            assert!(read_frame(&mut rx, None).is_err(), "truncated at {end}");
        }
        // A valid Outcome type 1 frame still decodes; exec replies are unchanged.
        let exit = Frame::Outcome(Outcome::command(CommandStatus::Exited(125))).encode().unwrap();
        let (mut tx, mut rx) = UnixStream::pair().unwrap();
        tx.write_all(&exit).unwrap();
        assert!(matches!(read_frame(&mut rx, None).unwrap(), Frame::Outcome(_)));
    }

    #[test]
    fn lease_stage_is_15_and_projects_125() {
        let o = Outcome::failure(FailureKind::Stopped, Stage::Lease, Cleanup::NoChildStarted, 0, "lost");
        let bytes = Frame::Outcome(o.clone()).encode().unwrap();
        assert_eq!(&bytes[26..28], b"\x0f\0");
        assert_eq!(Frame::decode(&bytes).unwrap(), Frame::Outcome(o.clone()));
        assert_eq!(o.projection(), 125);
        let mut unknown = bytes.clone(); unknown[26] = 16;
        assert!(Frame::decode(&unknown).is_err());
    }

    #[test]
    fn chdir_launch_failure_is_stage_14_and_projects_126() {
        let o = Outcome::failure(FailureKind::LaunchFailed, Stage::Chdir, Cleanup::Drained, libc::ENOENT, "chdir");
        let bytes = Frame::Outcome(o.clone()).encode().unwrap();
        assert_eq!(&bytes[16..32], b"\x02\x00\x02\x00\x00\x00\x00\x00\x06\x00\x0e\x00\x02\x00\x00\x00");
        assert_eq!(Frame::decode(&bytes).unwrap(), Frame::Outcome(o.clone()));
        assert_eq!(o.projection(), 126);
        let mut unknown = bytes.clone(); unknown[26] = 16;
        assert!(Frame::decode(&unknown).is_err());
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
