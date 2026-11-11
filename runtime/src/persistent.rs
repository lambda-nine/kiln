use std::ffi::CString;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::unistd::{ForkResult, fork, pipe2, read, setsid};

use crate::container::{self, Config};
use crate::exec_options::{self, ExecOptions};
use crate::exec_protocol::{self as protocol, Capabilities, Cleanup, FailureKind, Frame, Outcome, Stage};
use crate::validation::{
    MAX_ARGC, MAX_EXEC_REQUEST_BYTES as MAX_REQUEST, valid_persistent_id, validate_exec_argv,
};

const MAX_REQUEST_FDS: usize = 3;
const RUNS_ROOT: &str = "/var/lib/kiln/runs";
/// Exit code of `kiln exec` when kiln itself fails (bad ID, sandbox gone,
/// terminal stdio) rather than the command.
pub const EXEC_FAILED: i32 = 125;

/// One complete, validated request from a persistent control connection.
#[derive(Debug)]
pub enum Request {
    Exec(Vec<CString>, Vec<OwnedFd>),
    TypedExec(Vec<CString>, Vec<OwnedFd>),
    /// Operation 5: operation 4's argv block followed by an exec options frame.
    OptionsExec(Vec<CString>, ExecOptions, Vec<OwnedFd>),
    Capabilities,
    Remove,
}

/// Result of advancing a nonblocking frame reader.
#[derive(Debug)]
pub enum ReadState<T> {
    Pending,
    Complete(T),
}

/// The fixed portion of a control request. Descriptors may arrive with any
/// byte of the header, so the reader retains them across partial recvmsg calls.
#[derive(Debug)]
pub struct Header {
    pub op: u8,
    pub len: u32,
    pub fds: Vec<OwnedFd>,
}

pub struct HeaderReader {
    bytes: [u8; 8],
    read: usize,
    fds: Vec<OwnedFd>,
    rights_messages: usize,
}

impl HeaderReader {
    pub fn new() -> Self {
        Self { bytes: [0; 8], read: 0, fds: Vec::new(), rights_messages: 0 }
    }

    /// Reads as much of one header as is available without blocking. All
    /// received descriptors become OwnedFd immediately, including on an error,
    /// so malformed or truncated ancillary data cannot leak them in PID 1.
    pub fn read(&mut self, stream: &UnixStream) -> Result<ReadState<Header>> {
        while self.read < self.bytes.len() {
            let chunk = recv_chunk(stream, &mut self.bytes[self.read..])?;
            let RecvChunk::Data { bytes, mut fds, rights_messages } = chunk else {
                return match chunk {
                    RecvChunk::Pending => Ok(ReadState::Pending),
                    RecvChunk::Eof => bail!("truncated request header"),
                    RecvChunk::Data { .. } => unreachable!(),
                };
            };
            self.read += bytes;
            self.rights_messages += rights_messages;
            if self.rights_messages > 1 {
                bail!("request has more than one SCM_RIGHTS message");
            }
            if self.fds.len() + fds.len() > MAX_REQUEST_FDS {
                bail!("request has too many descriptors");
            }
            self.fds.append(&mut fds);
        }
        if self.bytes[1..4] != [0, 0, 0] {
            bail!("request reserved header bytes must be zero");
        }
        Ok(ReadState::Complete(Header {
            op: self.bytes[0],
            len: if is_typed(self.bytes[0]) {
                u32::from_le_bytes(self.bytes[4..].try_into().unwrap())
            } else { u32::from_ne_bytes(self.bytes[4..].try_into().unwrap()) },
            fds: mem::take(&mut self.fds),
        }))
    }
}

/// Incremental decoder for one connection's one request. The caller owns the
/// absolute deadline and polls between Pending results.
pub struct RequestReader {
    header: HeaderReader,
    frame: Option<Header>,
    body: Vec<u8>,
    body_read: usize,
    complete: bool,
}

impl RequestReader {
    pub fn new() -> Self {
        Self {
            header: HeaderReader::new(),
            frame: None,
            body: Vec::new(),
            body_read: 0,
            complete: false,
        }
    }

    pub fn read(&mut self, stream: &UnixStream) -> Result<ReadState<Request>> {
        if self.complete {
            bail!("request reader is already complete");
        }
        if self.frame.is_none() {
            let ReadState::Complete(header) = self.header.read(stream)? else {
                return Ok(ReadState::Pending);
            };
            if header.len as usize > max_body(header.op) {
                bail!("request is too large");
            }
            match header.op {
                1 | 4 | 5 if header.fds.len() != MAX_REQUEST_FDS => {
                    bail!("exec request needs stdin, stdout and stderr")
                }
                1 | 4 | 5 => {
                    self.body = vec![0; header.len as usize];
                    self.frame = Some(header);
                }
                2 if header.len != 0 || !header.fds.is_empty() => {
                    bail!("remove request must have an empty body and no descriptors")
                }
                2 => {
                    self.complete = true;
                    return Ok(ReadState::Complete(Request::Remove));
                }
                3 if header.len == 0 && header.fds.is_empty() => {
                    self.complete = true;
                    return Ok(ReadState::Complete(Request::Capabilities));
                }
                op => bail!("unknown request operation {op}"),
            }
        }

        if self.body_read < self.body.len() {
            match recv_chunk(stream, &mut self.body[self.body_read..])? {
                RecvChunk::Pending => return Ok(ReadState::Pending),
                RecvChunk::Eof => bail!("truncated request body"),
                RecvChunk::Data { bytes, fds, rights_messages } => {
                    if rights_messages != 0 || !fds.is_empty() {
                        bail!("SCM_RIGHTS is only allowed with the request header");
                    }
                    self.body_read += bytes;
                }
            }
            if self.body_read < self.body.len() {
                // Return to the caller after every successful body receive so
                // it can enforce the absolute deadline and service signals.
                return Ok(ReadState::Pending);
            }
        }

        let header = self.frame.take().unwrap();
        self.complete = true;
        if header.op == 5 {
            let (argv, at) = parse_argv_prefix(&self.body, true)?;
            if at > MAX_REQUEST {
                bail!("command is too large");
            }
            let options = ExecOptions::decode(&self.body[at..])?;
            return Ok(ReadState::Complete(Request::OptionsExec(argv, options, header.fds)));
        }
        let argv = parse_argv_ordered(&self.body, header.op == 4)?;
        Ok(ReadState::Complete(if header.op == 4 { Request::TypedExec(argv, header.fds) }
            else { Request::Exec(argv, header.fds) }))
    }
}

/// Operations 3, 4 and 5 use little-endian lengths; 1 and 2 keep native order.
fn is_typed(op: u8) -> bool { matches!(op, 3..=5) }

/// The largest body an operation may announce. Operation 5 adds at most one
/// exec options frame to operation 4's argv block.
pub fn max_body(op: u8) -> usize {
    if op == 5 { MAX_REQUEST + exec_options::MAX_FRAME } else { MAX_REQUEST }
}

enum RecvChunk {
    Pending,
    Eof,
    Data {
        bytes: usize,
        fds: Vec<OwnedFd>,
        rights_messages: usize,
    },
}

/// Only this error, emitted before `new_id`, proves a persistent create made
/// no sandbox allocation. All failures after that boundary remain ambiguous.
#[derive(Debug)]
pub struct CreatePreflightFailure;

impl std::fmt::Display for CreatePreflightFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("persistent create rejected before allocation")
    }
}
impl std::error::Error for CreatePreflightFailure {}

pub const CREATE_PREFLIGHT_EXIT: i32 = 124;

pub fn before_allocation<T>(result: Result<T>) -> Result<T> {
    result.context(CreatePreflightFailure)
}

pub fn create(cfg: &Config) -> Result<String> {
    before_allocation(container::validate_image(cfg))?;
    let id = container::new_id();
    let (ready_rx, ready_tx) = pipe2(OFlag::O_CLOEXEC).context("pipe")?;
    // SAFETY: the CLI is single-threaded here.
    match unsafe { fork() }.context("fork shim")? {
        ForkResult::Parent { child } => {
            drop(ready_tx);
            let mut byte = [0u8; 1];
            if read(&ready_rx, &mut byte).context("wait for shim")? != 1 {
                let _ = nix::sys::wait::waitpid(child, None);
                bail!("sandbox shim failed during setup");
            }
            Ok(id)
        }
        ForkResult::Child => {
            drop(ready_rx);
            let _ = setsid();
            redirect_stdio();
            let code = match container::supervise_persistent(cfg, &id, &ready_tx) {
                Ok(()) => 0,
                Err(_) => 1,
            };
            std::process::exit(code);
        }
    }
}

pub fn exec(id: &str, cmd: &[String]) -> Result<i32> {
    validate_id(id)?;
    let encoded_len = validate_exec_argv(cmd)?;
    let mut payload = Vec::with_capacity(encoded_len);
    payload.extend_from_slice(&(cmd.len() as u32).to_ne_bytes());
    for arg in cmd {
        let bytes = arg.as_bytes();
        payload.extend_from_slice(&(bytes.len() as u32).to_ne_bytes());
        payload.extend_from_slice(bytes);
    }
    debug_assert_eq!(payload.len(), encoded_len);
    let stdio = [0, 1, 2];
    refuse_terminal_stdio(&stdio)?;
    let mut stream = connect(id)?;
    send_header(&stream, 1, payload.len() as u32, &stdio)?;
    stream.write_all(&payload)?;
    let mut status = [0u8; 4];
    stream
        .read_exact(&mut status)
        .context("sandbox did not report an exec status")?;
    Ok(i32::from_ne_bytes(status))
}

pub fn capabilities(id: Option<&str>, version: u16) -> Result<()> {
    anyhow::ensure!(version == protocol::VERSION, "unsupported persistent-exec protocol {version}");
    let frame = match id {
        None => Frame::Capabilities(Capabilities::current()),
        Some(id) => {
            validate_id(id)?;
            let deadline = Instant::now() + protocol::FRAME_TIMEOUT;
            let mut stream = connect_bounded(id, deadline)?;
            stream.set_write_timeout(Some(deadline.checked_duration_since(Instant::now())
                .context("capability exchange deadline")?))?;
            send_header(&stream, 3, 0, &[])?;
            match protocol::read_reply(&mut stream, Some(deadline))? {
                Frame::Capabilities(c) => { c.require_v1()?; Frame::Capabilities(c) }
                _ => bail!("expected sandbox capabilities"),
            }
        }
    };
    std::io::stdout().write_all(&frame.encode()?)?;
    Ok(())
}

/// Own the private status socket before validating the rest, so host-side
/// failures can still be reported. No workload FD is ever used for diagnostics.
pub fn machine_exec(id: &str, cmd: &[String], version: u16, status: RawFd,
    stdio: [RawFd; 3], options: Option<RawFd>) -> Result<i32> {
    validate_status_fd(status)?;
    restore_cloexec(status)?;
    let status = unsafe { OwnedFd::from_raw_fd(status) };
    let outcome = machine_request(id, cmd, version, status.as_raw_fd(), stdio, options);
    protocol::write_bounded(status.as_raw_fd(), &Frame::Outcome(outcome.clone()).encode()?, || Ok(()))?;
    Ok(outcome.projection())
}

fn machine_request(id: &str, cmd: &[String], version: u16, status: RawFd, stdio: [RawFd; 3],
    options_fd: Option<RawFd>) -> Outcome {
    let mut cleanup = Cleanup::NoChildStarted;
    let mut stage = Stage::Validate;
    let run = (|| -> Result<Outcome> {
        validate_machine_stdio(status, stdio)?;
        let fds: Vec<OwnedFd> = stdio.into_iter().map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }).collect();
        let options = options_fd.map(|fd| read_options_fd(fd, status, stdio)).transpose()?;
        anyhow::ensure!(version == protocol::VERSION, "unsupported persistent-exec protocol {version}");
        validate_id(id)?;
        let (op, payload) = typed_request(cmd, options.as_deref())?;
        stage = Stage::Connect;
        if options.is_some() {
            let path = container::run_dir(id).join("control.sock");
            if let Some(refusal) = require_exec_options(&path, &mut stage)
                .with_context(|| format!("probe sandbox {id}"))? {
                return Ok(refusal);
            }
            stage = Stage::Connect;
        }
        let mut stream = connect_bounded(id, Instant::now() + protocol::FRAME_TIMEOUT)?;
        stage = Stage::Request;
        stream.set_write_timeout(Some(protocol::FRAME_TIMEOUT))?;
        // From the first send onward a partial transfer may have reached PID 1.
        cleanup = Cleanup::Unconfirmed;
        send_header(&stream, op, payload.len() as u32, &stdio)?;
        if let Err(error) = stream.write_all(&payload) {
            // Busy may be returned as soon as the header arrives, before a
            // large body can finish writing. Only that explicit no-child
            // acknowledgement overrides an interrupted request write.
            let reply = protocol::read_reply(&mut stream, Some(Instant::now() + protocol::FRAME_TIMEOUT));
            if let Ok(Frame::Outcome(o)) = reply && o.kind == FailureKind::Busy
                && o.cleanup == Cleanup::NoChildStarted && o.status.is_none() {
                return Ok(o);
            }
            return Err(error).context("send exec request body");
        }
        drop(fds);
        stage = Stage::Report;
        match protocol::read_reply(&mut stream, None)? {
            Frame::Outcome(o) => Ok(o),
            _ => bail!("expected typed exec outcome"),
        }
    })();
    match run {
        Ok(o) => o,
        Err(e) => {
            let errno = e.chain().find_map(|cause| cause.downcast_ref::<std::io::Error>()
                .and_then(|e| e.raw_os_error())).unwrap_or(0);
            let kind = match stage {
                Stage::Validate if version != protocol::VERSION => FailureKind::Incompatible,
                Stage::Validate => FailureKind::InvalidRequest,
                Stage::Connect if errno == libc::ENOENT => FailureKind::NotFound,
                Stage::Connect => FailureKind::Unavailable,
                Stage::Handshake => FailureKind::Protocol,
                Stage::Report => FailureKind::Protocol,
                _ => FailureKind::Io,
            };
            Outcome::failure(kind, stage, cleanup, errno, &format!("{e:#}"))
        }
    }
}

/// The operation and body of a typed exec. Operation 4's body is unchanged by
/// options support; operation 5 appends the validated frame, byte for byte as
/// the caller sealed it.
fn typed_request(cmd: &[String], options: Option<&[u8]>) -> Result<(u8, Vec<u8>)> {
    let encoded_len = validate_exec_argv(cmd)?;
    let mut payload = Vec::with_capacity(encoded_len + options.map_or(0, <[u8]>::len));
    payload.extend_from_slice(&(cmd.len() as u32).to_le_bytes());
    for arg in cmd {
        payload.extend_from_slice(&(arg.len() as u32).to_le_bytes());
        payload.extend_from_slice(arg.as_bytes());
    }
    debug_assert_eq!(payload.len(), encoded_len);
    Ok(match options {
        Some(frame) => { payload.extend_from_slice(frame); (5, payload) }
        None => (4, payload),
    })
}

/// Asks the sandbox's PID 1 for its capabilities on a separate connection
/// before any exec byte is sent. Returns the refusal outcome when PID 1 does
/// not advertise exec options; nothing reaches it except operation 3.
fn require_exec_options(path: &Path, stage: &mut Stage) -> Result<Option<Outcome>> {
    let deadline = Instant::now() + protocol::FRAME_TIMEOUT;
    let mut probe = connect_path_bounded(path, deadline)?;
    *stage = Stage::Handshake;
    probe.set_write_timeout(Some(deadline.checked_duration_since(Instant::now())
        .context("capability exchange deadline")?))?;
    send_header(&probe, 3, 0, &[])?;
    let Frame::Capabilities(capabilities) = protocol::read_reply(&mut probe, Some(deadline))? else {
        bail!("expected sandbox capabilities");
    };
    if capabilities.require_v1().is_err() || capabilities.features & protocol::EXEC_OPTIONS_FEATURE == 0 {
        return Ok(Some(Outcome::failure(FailureKind::Incompatible, Stage::Handshake, Cleanup::NoChildStarted, 0,
            &format!("sandbox PID 1 does not support exec options (features {:#010x}); recreate the sandbox",
                capabilities.features))));
    }
    Ok(None)
}

/// Reads the exec options frame from the caller's sealed memfd: exactly
/// F_SEAL_SEAL|SHRINK|GROW|WRITE, so its bytes can't change after this read.
/// The descriptor is closed on return. The path in the frame is never opened,
/// stat'ed or chdir'ed here; it is sandbox-interior data.
fn read_options_fd(fd: RawFd, status: RawFd, stdio: [RawFd; 3]) -> Result<Vec<u8>> {
    anyhow::ensure!(fd >= 3 && fd != status && !stdio.contains(&fd),
        "exec options fd must be distinct from the other descriptors and >=3");
    restore_cloexec(fd).context("invalid exec options fd")?;
    let file = fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    anyhow::ensure!(flags >= 0 && flags & libc::O_PATH == 0
        && matches!(flags & libc::O_ACCMODE, libc::O_RDONLY | libc::O_RDWR), "exec options fd must be readable");
    let mut info = unsafe { mem::zeroed::<libc::stat>() };
    anyhow::ensure!(unsafe { libc::fstat(fd, &mut info) } == 0, "invalid exec options fd");
    // memfd_create files are unlinked regular files named "/memfd:NAME".
    let link = fs::read_link(format!("/proc/self/fd/{fd}")).context("inspect exec options fd")?;
    anyhow::ensure!(info.st_mode & libc::S_IFMT == libc::S_IFREG && info.st_nlink == 0
        && link.as_os_str().as_bytes().starts_with(b"/memfd:"), "exec options fd must be a memfd");
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    anyhow::ensure!(seals == exec_options::REQUIRED_SEALS,
        "exec options memfd must have exactly the write, shrink, grow and seal seals (has {seals:#x})");
    for workload in stdio {
        let mut other = unsafe { mem::zeroed::<libc::stat>() };
        anyhow::ensure!(unsafe { libc::fstat(workload, &mut other) } == 0
            && (other.st_dev, other.st_ino) != (info.st_dev, info.st_ino), "exec options fd aliases workload stdio");
    }
    let size = usize::try_from(info.st_size).ok().filter(|&n| n <= exec_options::MAX_FRAME)
        .context("exec options exceed the frame bound")?;
    let mut frame = vec![0u8; size];
    let mut at = 0;
    // pread: the shared file offset belongs to the caller and is ignored.
    while at < size {
        match std::os::unix::fs::FileExt::read_at(&file, &mut frame[at..], at as u64) {
            Ok(0) => bail!("exec options memfd changed size"),
            Ok(n) => at += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("read exec options"),
        }
    }
    anyhow::ensure!(std::os::unix::fs::FileExt::read_at(&file, &mut [0u8; 1], size as u64)? == 0,
        "exec options memfd changed size");
    ExecOptions::decode(&frame)?;
    Ok(frame)
}

fn restore_cloexec(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("restore descriptor CLOEXEC");
    }
    Ok(())
}

fn validate_status_fd(fd: RawFd) -> Result<()> {
    anyhow::ensure!(fd >= 3, "status fd must be private (>=3)");
    for (option, expected) in [(libc::SO_TYPE, libc::SOCK_STREAM), (libc::SO_DOMAIN, libc::AF_UNIX)] {
        let mut value = 0i32;
        let mut len = mem::size_of_val(&value) as libc::socklen_t;
        let n = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, option, (&mut value as *mut i32).cast(), &mut len) };
        anyhow::ensure!(n == 0 && value == expected, "status fd must be an anonymous Unix stream socket");
    }
    // A socketpair has no local or peer pathname. Reject listeners, unconnected
    // sockets and named endpoints rather than assuming this channel is private.
    for peer in [false, true] {
        let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&addr) as libc::socklen_t;
        let n = unsafe {
            let addr = (&mut addr as *mut libc::sockaddr_un).cast();
            if peer { libc::getpeername(fd, addr, &mut len) } else { libc::getsockname(fd, addr, &mut len) }
        };
        anyhow::ensure!(n == 0 && len as usize == mem::offset_of!(libc::sockaddr_un, sun_path),
            "status fd must be a connected anonymous Unix socketpair");
    }
    Ok(())
}

fn validate_machine_stdio(status: RawFd, stdio: [RawFd; 3]) -> Result<()> {
    let mut identity = unsafe { mem::zeroed::<libc::stat>() };
    anyhow::ensure!(unsafe { libc::fstat(status, &mut identity) } == 0, "invalid status fd");
    for (i, fd) in stdio.into_iter().enumerate() {
        anyhow::ensure!(fd >= 3 && fd != status && !stdio[..i].contains(&fd), "machine descriptors must be distinct and >=3");
        restore_cloexec(fd)?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        anyhow::ensure!(flags >= 0 && flags & libc::O_PATH == 0, "invalid workload fd");
        let mode = flags & libc::O_ACCMODE;
        anyhow::ensure!(mode == libc::O_RDWR || mode == if i == 0 { libc::O_RDONLY } else { libc::O_WRONLY },
            "wrong workload fd direction");
        let mut info = unsafe { mem::zeroed::<libc::stat>() };
        anyhow::ensure!(unsafe { libc::fstat(fd, &mut info) } == 0, "invalid workload fd");
        anyhow::ensure!(identity.st_dev != info.st_dev || identity.st_ino != info.st_ino,
            "status fd aliases workload stdio");
    }
    refuse_terminal_stdio(&stdio)
}

pub fn remove(id: &str) -> Result<()> {
    validate_id(id)?;
    let mut stream = connect(id)?;
    send_header(&stream, 2, 0, &[])?;
    let mut status = [0u8; 4];
    stream
        .read_exact(&mut status)
        .context("wait for sandbox removal")?;
    let dir = container::run_dir(id);
    for _ in 0..200 {
        if !dir.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    bail!("sandbox {id} did not finish cleanup")
}

pub fn list() -> Result<()> {
    let root = Path::new(RUNS_ROOT);
    let mut records = Vec::new();
    for entry in registry_entries(root)? {
        let id = entry
            .file_name()
            .into_string()
            .map_err(|name| anyhow::anyhow!("sandbox registry entry is not UTF-8: {name:?}"))?;
        let dir = entry.path();
        if !dir
            .join("shim.pid")
            .try_exists()
            .with_context(|| format!("inspect sandbox registry entry {id}"))?
        {
            continue;
        }
        // A present PID is the identity-complete marker. Once it exists,
        // missing, malformed or unreadable companion metadata is an error,
        // never evidence that the shim is dead.
        let shim = read_shim(&dir)?;
        let live = shim.is_live()?;
        if !dir
            .join("control.sock")
            .try_exists()
            .with_context(|| format!("inspect sandbox registry entry {id}"))?
        {
            continue;
        }
        records.push((id, live, shim.pid_text));
    }
    records.sort_by(|a, b| a.0.cmp(&b.0));

    println!("ID\tSTATUS\tSHIM");
    for (id, live, pid) in records {
        println!(
            "{id}\t{}\t{}",
            if live { "running" } else { "stale" },
            pid.trim()
        );
    }
    Ok(())
}

pub fn gc(ids: &[String]) -> Result<()> {
    let root = Path::new(RUNS_ROOT);
    let mut failures = Vec::new();
    for (id, dir) in stale_gc_candidates(root, ids)? {
        // Attempt both independent resources, but retain identity until every
        // teardown and its postconditions succeeded.
        let cgroup = crate::cgroup::remove(&id);
        let network = crate::net::remove_run(&id);
        match finish_gc(&dir, cgroup, network) {
            Ok(()) => eprintln!("kiln: removed stale sandbox {id}"),
            Err(e) => failures.push(format!("{id}: {e:#}")),
        }
    }
    if !failures.is_empty() {
        bail!("partial sandbox cleanup; run state retained for retry: {}", failures.join("; "));
    }
    Ok(())
}

fn finish_gc(dir: &Path, cgroup: Result<()>, network: Result<()>) -> Result<()> {
    cgroup.context("cgroup teardown")?;
    network.context("network teardown")?;
    fs::remove_dir_all(dir).with_context(|| format!("remove stale sandbox {}", dir.display()))
}

fn stale_gc_candidates(root: &Path, ids: &[String]) -> Result<Vec<(String, PathBuf)>> {
    let entries: Vec<(Option<String>, PathBuf)> = if ids.is_empty() {
        registry_entries(root)?
            .into_iter()
            .map(|entry| (None, entry.path()))
            .collect()
    } else {
        let mut unique = std::collections::BTreeSet::new();
        for id in ids {
            validate_id(id)?;
            unique.insert(id.clone());
        }
        unique
            .into_iter()
            .map(|id| {
                let dir = root.join(&id);
                (Some(id), dir)
            })
            .collect()
    };

    let mut stale = Vec::new();
    for (id, dir) in entries {
        if !dir
            .join("shim.pid")
            .try_exists()
            .with_context(|| format!("inspect sandbox registry entry {}", dir.display()))?
        {
            continue;
        }
        let id = match id {
            Some(id) => id,
            None => dir
                .file_name()
                .with_context(|| format!("sandbox registry entry has no name: {}", dir.display()))?
                .to_os_string()
                .into_string()
                .map_err(|name| anyhow::anyhow!("sandbox registry entry is not UTF-8: {name:?}"))?,
        };
        // Validate identity before considering cleanup, even if the control
        // socket is absent. A live shim can be between socket creation and
        // identity publication, or its socket may have been removed.
        if !read_shim(&dir)?.is_live()? {
            stale.push((id, dir));
        }
    }
    Ok(stale)
}

fn registry_entries(root: &Path) -> Result<Vec<fs::DirEntry>> {
    fs::read_dir(root)
        .with_context(|| format!("read sandbox registry {}", root.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("enumerate sandbox registry {}", root.display()))
}

#[derive(Debug)]
struct RecordedShim {
    pid_text: String,
    pid: u32,
    start: u64,
}

impl RecordedShim {
    fn is_live(&self) -> Result<bool> {
        let Some((state, actual_start)) = process_state_and_start(self.pid)? else {
            return Ok(false);
        };
        Ok(state != 'Z' && state != 'X' && actual_start == self.start)
    }
}

fn read_shim(dir: &Path) -> Result<RecordedShim> {
    let pid_path = dir.join("shim.pid");
    let start_path = dir.join("shim.start");
    let pid_text = fs::read_to_string(&pid_path)
        .with_context(|| format!("read sandbox registry file {}", pid_path.display()))?;
    let start_text = fs::read_to_string(&start_path)
        .with_context(|| format!("read sandbox registry file {}", start_path.display()))?;
    let pid = pid_text
        .trim()
        .parse::<u32>()
        .with_context(|| format!("parse sandbox registry file {}", pid_path.display()))?;
    if pid == 0 || pid > i32::MAX as u32 {
        bail!("invalid shim PID in {}", pid_path.display());
    }
    let start = start_text
        .trim()
        .parse::<u64>()
        .with_context(|| format!("parse sandbox registry file {}", start_path.display()))?;
    Ok(RecordedShim { pid_text, pid, start })
}

fn process_state_and_start(pid: u32) -> Result<Option<(char, u64)>> {
    let path = format!("/proc/{pid}/stat");
    let stat = match fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(e) if process_disappeared(&e) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read process identity {path}")),
    };
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .with_context(|| format!("parse process identity {path}"))?;
    let mut fields = fields.split_whitespace();
    let state = fields
        .next()
        .and_then(|field| field.chars().next())
        .with_context(|| format!("parse process state {path}"))?;
    let start = fields
        .nth(18)
        .with_context(|| format!("parse process start time {path}"))?
        .parse::<u64>()
        .with_context(|| format!("parse process start time {path}"))?;
    Ok(Some((state, start)))
}

fn process_disappeared(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn parse_argv_ordered(data: &[u8], little_endian: bool) -> Result<Vec<CString>> {
    let (argv, at) = parse_argv_prefix(data, little_endian)?;
    if at != data.len() {
        bail!("trailing request data");
    }
    Ok(argv)
}

/// Parses one argv block from the start of `data` and returns it with the
/// number of bytes it used.
fn parse_argv_prefix(data: &[u8], little_endian: bool) -> Result<(Vec<CString>, usize)> {
    let mut at = 0;
    let take = |at: &mut usize| -> Result<u32> {
        let n = take_u32(data, at)?;
        Ok(if little_endian { u32::from_le_bytes(n.to_ne_bytes()) } else { n })
    };
    let argc = take(&mut at)? as usize;
    if argc == 0 || argc > MAX_ARGC {
        bail!("invalid argument count");
    }
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        let n = take(&mut at)? as usize;
        let bytes = data.get(at..at + n).context("truncated argument")?;
        argv.push(CString::new(bytes).context("argument contains a NUL byte")?);
        at += n;
    }
    if argv[0].as_bytes().is_empty() {
        bail!("argv must name a program");
    }
    Ok((argv, at))
}

/// Whether `fd` is a terminal.
fn is_terminal(fd: RawFd) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

/// The sandbox's command gets these exact descriptors over SCM_RIGHTS. A
/// terminal among them would hand the sandbox the caller's own tty, outside
/// any PTY kiln controls, so `kiln exec` only accepts redirected stdio until
/// it allocates PTYs itself.
fn refuse_terminal_stdio(fds: &[RawFd]) -> Result<()> {
    if let Some(&fd) = fds.iter().find(|&&fd| is_terminal(fd)) {
        let name = match fd {
            0 => "stdin".to_string(),
            1 => "stdout".to_string(),
            2 => "stderr".to_string(),
            _ => format!("fd {fd}"),
        };
        bail!(
            "{name} is a terminal, and interactive (PTY) exec is not implemented: \
             redirect all of stdin, stdout and stderr away from the terminal, \
             e.g. kiln exec ID -- CMD </dev/null >out.log 2>err.log"
        );
    }
    Ok(())
}

fn connect(id: &str) -> Result<UnixStream> {
    let path = container::run_dir(id).join("control.sock");
    UnixStream::connect(&path).with_context(|| format!("connect to sandbox {id}"))
}

/// Unix connect may otherwise wait indefinitely when PID 1's backlog is full.
/// Both the connect and the subsequent probe share the caller's deadline.
fn connect_bounded(id: &str, deadline: Instant) -> Result<UnixStream> {
    let path = container::run_dir(id).join("control.sock");
    connect_path_bounded(&path, deadline).with_context(|| format!("connect to sandbox {id}"))
}

fn connect_path_bounded(path: &Path, deadline: Instant) -> Result<UnixStream> {
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 { return Err(std::io::Error::last_os_error()).context("create control socket"); }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let mut addr: libc::sockaddr_un = unsafe { mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let name = path.as_os_str().as_bytes();
    anyhow::ensure!(name.len() < addr.sun_path.len() && !name.contains(&0), "invalid control socket path");
    for (target, &byte) in addr.sun_path.iter_mut().zip(name) { *target = byte as libc::c_char; }
    let len = (mem::offset_of!(libc::sockaddr_un, sun_path) + name.len() + 1) as libc::socklen_t;
    loop {
        anyhow::ensure!(Instant::now() < deadline, "control connect deadline exceeded");
        let n = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len) };
        if n == 0 { break; }
        let e = std::io::Error::last_os_error();
        match e.raw_os_error() {
            Some(libc::EISCONN) => break,
            Some(libc::EINTR) => continue,
            Some(libc::EAGAIN) => {
                // AF_UNIX backlog pressure means retry connect, not SO_ERROR=0.
                unsafe { libc::poll(std::ptr::null_mut(), 0, 10); }
            }
            Some(libc::EINPROGRESS | libc::EALREADY) => {
                let mut wait = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
                let timeout = deadline.saturating_duration_since(Instant::now()).as_millis().min(20) as i32;
                if unsafe { libc::poll(&mut wait, 1, timeout) } < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == ErrorKind::Interrupted { continue; }
                    return Err(e).context("poll control connect");
                }
                if wait.revents != 0 {
                    let mut error = 0i32;
                    let mut size = mem::size_of_val(&error) as libc::socklen_t;
                    if unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR,
                        (&mut error as *mut i32).cast(), &mut size) } < 0 {
                        return Err(std::io::Error::last_os_error()).context("control connect result");
                    }
                    if error != 0 { return Err(std::io::Error::from_raw_os_error(error).into()); }
                    break;
                }
            }
            _ => return Err(e).context("connect control socket"),
        }
    }
    anyhow::ensure!(Instant::now() < deadline, "control connect deadline exceeded");
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn validate_id(id: &str) -> Result<()> {
    if !valid_persistent_id(id) {
        bail!("invalid sandbox ID {id:?}");
    }
    Ok(())
}

fn take_u32(data: &[u8], at: &mut usize) -> Result<u32> {
    let bytes: [u8; 4] = data
        .get(*at..*at + 4)
        .context("truncated request")?
        .try_into()
        .unwrap();
    *at += 4;
    Ok(u32::from_ne_bytes(bytes))
}

fn redirect_stdio() {
    if let Ok(devnull) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    {
        for fd in 0..=2 {
            unsafe {
                libc::dup2(devnull.as_raw_fd(), fd);
            }
        }
    }
}

fn send_header(stream: &UnixStream, op: u8, len: u32, fds: &[RawFd]) -> Result<()> {
    let mut header = [0u8; 8];
    header[0] = op;
    header[4..].copy_from_slice(&if is_typed(op) { len.to_le_bytes() } else { len.to_ne_bytes() });
    send_with_fds(stream, &header, fds)
}

fn send_with_fds(stream: &UnixStream, bytes: &[u8], fds: &[RawFd]) -> Result<()> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let space = unsafe { libc::CMSG_SPACE(mem::size_of_val(fds) as u32) as usize };
    let mut control = vec![0u8; space];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    if !fds.is_empty() {
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(mem::size_of_val(fds) as u32) as usize;
            std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(cmsg).cast(), fds.len());
        }
    }
    let n = loop {
        let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
        if n >= 0 { break n as usize; }
        let e = std::io::Error::last_os_error();
        if e.kind() == ErrorKind::Interrupted { continue; }
        return Err(e).context("send exec request");
    };
    anyhow::ensure!(n != 0, "send exec request made no progress");
    // SCM_RIGHTS was transferred with the first successful byte; never resend
    // it when finishing a short header write.
    (&*stream).write_all(&bytes[n..]).context("finish exec request header")?;
    Ok(())
}

/// Receives one available stream chunk and every descriptor attached to it.
/// The descriptor buffer is deliberately capped at the protocol maximum. If
/// the kernel reports truncation, the visible descriptors are already owned
/// here and the kernel closes any excess, so the error path leaks nothing.
fn recv_chunk(stream: &UnixStream, bytes: &mut [u8]) -> Result<RecvChunk> {
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = vec![
        0u8;
        unsafe {
            libc::CMSG_SPACE((MAX_REQUEST_FDS * mem::size_of::<RawFd>()) as u32) as usize
        }
    ];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    let n = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n < 0 {
        return match Errno::last() {
            Errno::EAGAIN | Errno::EINTR => Ok(RecvChunk::Pending),
            e => Err(e).context("read control request"),
        };
    }
    if n == 0 {
        return Ok(RecvChunk::Eof);
    }

    let mut fds = Vec::new();
    let mut rights_messages = 0;
    let mut invalid_ancillary = false;
    unsafe {
        let control_start = control.as_ptr() as usize;
        let control_end = control_start + msg.msg_controllen;
        let minimum = libc::CMSG_LEN(0) as usize;
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let address = cmsg as usize;
            let length = (*cmsg).cmsg_len;
            if length < minimum || address.checked_add(length).is_none_or(|end| end > control_end) {
                invalid_ancillary = true;
                break;
            }
            if (*cmsg).cmsg_level != libc::SOL_SOCKET || (*cmsg).cmsg_type != libc::SCM_RIGHTS {
                invalid_ancillary = true;
            } else {
                let payload = length - minimum;
                if !payload.is_multiple_of(mem::size_of::<RawFd>()) {
                    invalid_ancillary = true;
                } else {
                    rights_messages += 1;
                    let count = payload / mem::size_of::<RawFd>();
                    for &fd in std::slice::from_raw_parts(
                        libc::CMSG_DATA(cmsg).cast::<RawFd>(), count,
                    ) {
                        if fd < 0 {
                            invalid_ancillary = true;
                        } else {
                            fds.push(OwnedFd::from_raw_fd(fd));
                        }
                    }
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        bail!("truncated SCM_RIGHTS control message");
    }
    if msg.msg_flags & libc::MSG_TRUNC != 0 {
        bail!("truncated control request data");
    }
    if invalid_ancillary {
        bail!("invalid control message");
    }
    Ok(RecvChunk::Data { bytes: n as usize, fds, rights_messages })
}

#[cfg(test)]
mod tests {
    use std::os::fd::IntoRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::UnixListener;

    use super::*;

    fn open(path: &str) -> fs::File {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(path)
            .unwrap()
    }

    #[test]
    fn machine_descriptors_restore_cloexec_and_refuse_aliases_and_directions() {
        let (status, alias) = UnixStream::pair().unwrap();
        let status_alias = status.try_clone().unwrap();
        let source = fs::File::open("/dev/null").unwrap();
        let (_rx, output) = pipe2(OFlag::O_CLOEXEC).unwrap();
        let (_rx2, error) = pipe2(OFlag::O_CLOEXEC).unwrap();
        let stdio = [source.as_raw_fd(), output.as_raw_fd(), error.as_raw_fd()];
        for fd in stdio { assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0); }
        validate_machine_stdio(status.as_raw_fd(), stdio).unwrap();
        for fd in stdio { assert_ne!(unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC, 0); }
        assert!(validate_machine_stdio(status.as_raw_fd(), [stdio[0], status_alias.as_raw_fd(), stdio[2]]).is_err());
        assert!(validate_machine_stdio(status.as_raw_fd(), [stdio[1], stdio[0], stdio[2]]).is_err());
        assert!(validate_machine_stdio(status.as_raw_fd(), [stdio[0], stdio[1], stdio[1]]).is_err());
        assert!(validate_status_fd(source.as_raw_fd()).is_err());
        drop(alias);
    }

    #[test]
    fn capability_connect_deadline_covers_full_listener_backlog() {
        let path = std::env::temp_dir().join(format!("kiln-connect-deadline-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let _queued = UnixStream::connect(&path).unwrap();
        let start = Instant::now();
        assert!(connect_path_bounded(&path, start + Duration::from_millis(30)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        drop(listener);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn machine_host_failures_use_only_private_status() {
        for version in [1, 2] {
            let (status, mut receiver) = UnixStream::pair().unwrap();
            let input = fs::File::open("/dev/null").unwrap();
            let (out_rx, out_tx) = pipe2(OFlag::O_CLOEXEC).unwrap();
            let (err_rx, err_tx) = pipe2(OFlag::O_CLOEXEC).unwrap();
            let stdio = [input.into_raw_fd(), out_tx.into_raw_fd(), err_tx.into_raw_fd()];
            assert_eq!(machine_exec("invalid/id", &["true".into()], version, status.into_raw_fd(), stdio, None).unwrap(), 125);
            let Frame::Outcome(o) = protocol::read_reply(&mut receiver, Some(Instant::now() + protocol::FRAME_TIMEOUT)).unwrap()
                else { panic!("not an outcome") };
            assert_eq!((o.kind, o.stage, o.cleanup), (if version == 1 { FailureKind::InvalidRequest }
                else { FailureKind::Incompatible }, Stage::Validate, Cleanup::NoChildStarted));
            let mut out = Vec::new(); let mut err = Vec::new();
            fs::File::from(out_rx).read_to_end(&mut out).unwrap();
            fs::File::from(err_rx).read_to_end(&mut err).unwrap();
            assert!(out.is_empty() && err.is_empty());
        }
    }

    #[test]
    fn typed_requests_have_le_argv_and_strict_probe_descriptors() {
        let (client, server) = UnixStream::pair().unwrap();
        send_header(&client, 3, 0, &[]).unwrap();
        assert!(matches!(RequestReader::new().read(&server).unwrap(), ReadState::Complete(Request::Capabilities)));
        for (len, fds) in [(1, vec![]), (0, vec![open("/dev/null")])] {
            let (client, server) = UnixStream::pair().unwrap();
            send_header(&client, 3, len, &fds.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>()).unwrap();
            assert!(RequestReader::new().read(&server).is_err());
        }
        for op in [1, 4] {
            let (client, server) = UnixStream::pair().unwrap();
            let null = open("/dev/null");
            send_header(&client, op, 12, &[null.as_raw_fd(); 3]).unwrap();
            (&client).write_all(&[1, 0, 0, 0, 4, 0, 0, 0, b't', b'r', b'u', b'e']).unwrap();
            let request = RequestReader::new().read(&server).unwrap();
            assert!(match request {
                ReadState::Complete(Request::TypedExec(argv, fds)) if op == 4 => argv[0].to_bytes() == b"true" && fds.len() == 3,
                ReadState::Complete(Request::Exec(argv, fds)) if op == 1 => argv[0].to_bytes() == b"true" && fds.len() == 3,
                _ => false,
            });
        }
    }

    #[test]
    fn raw_exec_protocol_rejects_an_empty_argv0() {
        for op in [1, 4] {
            let (client, server) = UnixStream::pair().unwrap();
            let null = open("/dev/null");
            send_header(&client, op, 8, &[null.as_raw_fd(); 3]).unwrap();
            (&client).write_all(&[1, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            let error = RequestReader::new().read(&server).unwrap_err().to_string();
            assert!(error.contains("name a program"), "{error}");
        }
    }

    #[test]
    fn header_only_read_leaves_the_body_and_keeps_descriptors() {
        let (client, mut server) = UnixStream::pair().unwrap();
        let null = open("/dev/null");
        let fd = null.as_raw_fd();
        send_header(&client, 1, 5, &[fd, fd, fd]).unwrap();
        (&client).write_all(b"hello").unwrap();
        let ReadState::Complete(header) = HeaderReader::new().read(&server).unwrap() else {
            panic!("complete header was reported pending");
        };
        assert_eq!((header.op, header.len, header.fds.len()), (1, 5, 3));
        let mut body = [0u8; 5];
        server.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"hello", "the header read must not consume the body");
    }

    #[test]
    fn rm_header_has_no_body_or_descriptors() {
        let (client, server) = UnixStream::pair().unwrap();
        send_header(&client, 2, 0, &[]).unwrap();
        let ReadState::Complete(header) = HeaderReader::new().read(&server).unwrap() else {
            panic!("complete header was reported pending");
        };
        assert_eq!((header.op, header.len, header.fds.len()), (2, 0, 0));
    }

    #[test]
    fn nonzero_reserved_header_bytes_are_rejected() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&[2, 1, 0, 0, 0, 0, 0, 0]).unwrap();
        let err = HeaderReader::new().read(&server).unwrap_err().to_string();
        assert!(err.contains("reserved header bytes"), "{err}");
    }

    #[test]
    fn truncated_headers_fail_and_stalled_headers_are_pending() {
        let (client, server) = UnixStream::pair().unwrap();
        (&client).write_all(&[1, 0, 0, 0]).unwrap();
        drop(client);
        assert!(HeaderReader::new().read(&server).is_err(), "a truncated header must be rejected");

        let (_client, server) = UnixStream::pair().unwrap();
        assert!(matches!(HeaderReader::new().read(&server).unwrap(), ReadState::Pending));
    }

    #[test]
    fn oversized_bodies_are_rejected_before_reading() {
        let (client, server) = UnixStream::pair().unwrap();
        send_header(&client, 1, MAX_REQUEST as u32 + 1, &[]).unwrap();
        let err = RequestReader::new().read(&server).unwrap_err().to_string();
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn truncated_rights_are_rejected() {
        let (client, server) = UnixStream::pair().unwrap();
        let null = open("/dev/null");
        let fd = null.as_raw_fd();
        // CMSG_SPACE for three i32s has enough alignment padding for a fourth
        // on 64-bit Linux; the fifth forces MSG_CTRUNC.
        send_header(&client, 1, 0, &[fd, fd, fd, fd, fd]).unwrap();
        let err = HeaderReader::new().read(&server).unwrap_err().to_string();
        assert!(err.contains("truncated SCM_RIGHTS"), "{err}");
    }

    #[test]
    fn rights_attached_to_the_body_are_rejected() {
        let (client, server) = UnixStream::pair().unwrap();
        let null = open("/dev/null");
        let fd = null.as_raw_fd();
        send_header(&client, 1, 1, &[fd, fd, fd]).unwrap();
        send_with_fds(&client, b"x", &[fd]).unwrap();
        let err = RequestReader::new().read(&server).unwrap_err().to_string();
        assert!(err.contains("only allowed with the request header"), "{err}");
    }

    #[test]
    fn malformed_remove_frame_is_rejected() {
        let (client, server) = UnixStream::pair().unwrap();
        let null = open("/dev/null");
        send_header(&client, 2, 1, &[null.as_raw_fd()]).unwrap();
        let err = RequestReader::new().read(&server).unwrap_err().to_string();
        assert!(err.contains("empty body and no descriptors"), "{err}");
    }

    #[test]
    fn detects_terminals() {
        let pty = open("/dev/ptmx");
        let null = open("/dev/null");
        let (rx, tx) = pipe2(OFlag::O_CLOEXEC).unwrap();
        assert!(is_terminal(pty.as_raw_fd()));
        assert!(!is_terminal(null.as_raw_fd()));
        assert!(!is_terminal(rx.as_raw_fd()));
        assert!(!is_terminal(tx.as_raw_fd()));
    }

    #[test]
    fn refuses_any_terminal_stdio() {
        let pty = open("/dev/ptmx");
        let null = open("/dev/null");
        let (pty, null) = (pty.as_raw_fd(), null.as_raw_fd());
        refuse_terminal_stdio(&[null, null, null]).unwrap();
        for fds in [[pty, null, null], [null, pty, null], [null, null, pty]] {
            let err = refuse_terminal_stdio(&fds).unwrap_err().to_string();
            assert!(err.contains("interactive (PTY) exec is not implemented"), "{err}");
            assert!(err.contains("redirect all of stdin, stdout and stderr"), "{err}");
        }
    }

    #[test]
    fn live_shim_requires_the_recorded_process_start_time() {
        let dir = std::env::temp_dir().join(format!("kiln-shim-identity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();

        let pid = std::process::id();
        let (_, start) = process_state_and_start(pid).unwrap().unwrap();
        fs::write(dir.join("shim.pid"), pid.to_string()).unwrap();
        fs::write(dir.join("shim.start"), start.to_string()).unwrap();
        assert!(read_shim(&dir).unwrap().is_live().unwrap());

        fs::write(dir.join("shim.start"), (start + 1).to_string()).unwrap();
        assert!(!read_shim(&dir).unwrap().is_live().unwrap());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn registry_metadata_read_errors_are_not_liveness_answers() {
        let dir = std::env::temp_dir().join(format!("kiln-shim-read-error-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("shim.pid"), std::process::id().to_string()).unwrap();
        fs::create_dir(dir.join("shim.start")).unwrap();

        let err = read_shim(&dir).unwrap_err().to_string();
        assert!(err.contains("read sandbox registry file"), "{err}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_or_malformed_identity_is_not_a_dead_shim() {
        let dir = std::env::temp_dir().join(format!(
            "kiln-shim-incomplete-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("shim.pid"), std::process::id().to_string()).unwrap();

        let err = read_shim(&dir).unwrap_err().to_string();
        assert!(err.contains("read sandbox registry file"), "{err}");
        fs::write(dir.join("shim.start"), "not-a-start-time").unwrap();
        let err = read_shim(&dir).unwrap_err().to_string();
        assert!(err.contains("parse sandbox registry file"), "{err}");
        fs::write(dir.join("shim.start"), "1").unwrap();
        fs::write(dir.join("shim.pid"), "not-a-pid").unwrap();
        let err = read_shim(&dir).unwrap_err().to_string();
        assert!(err.contains("parse sandbox registry file"), "{err}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_teardown_retains_registry_for_retry() {
        let root = std::env::temp_dir().join(format!("kiln-gc-retry-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("shim.pid"), "123").unwrap();
        for (cgroup, network) in [(Err(anyhow::anyhow!("busy")), Ok(())),
            (Ok(()), Err(anyhow::anyhow!("nft failed")))] {
            assert!(finish_gc(&root, cgroup, network).is_err());
            assert_eq!(fs::read_to_string(root.join("shim.pid")).unwrap(), "123");
        }
        finish_gc(&root, Ok(()), Ok(())).unwrap();
        assert!(!root.exists());
    }

    #[test]
    fn scoped_gc_selects_only_requested_stale_sandboxes() {
        let root = std::env::temp_dir().join(format!(
            "kiln-scoped-gc-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        for id in ["aaaa-1", "bbbb-2"] {
            let dir = root.join(id);
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("shim.pid"), i32::MAX.to_string()).unwrap();
            fs::write(dir.join("shim.start"), "1").unwrap();
        }
        fs::create_dir(root.join(std::ffi::OsString::from_vec(vec![0xff]))).unwrap();
        let global = stale_gc_candidates(&root, &[]).unwrap();
        assert_eq!(
            global
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            ["aaaa-1", "bbbb-2"].into_iter().collect()
        );

        let malformed = root.join("cccc-3");
        fs::create_dir(&malformed).unwrap();
        fs::write(malformed.join("shim.pid"), "not-a-pid").unwrap();
        fs::write(malformed.join("shim.start"), "1").unwrap();

        let scoped = stale_gc_candidates(
            &root,
            &["aaaa-1".into(), "aaaa-1".into(), "dddd-4".into()],
        )
        .unwrap();
        assert_eq!(
            scoped
                .iter()
                .map(|(id, _)| id.as_str())
                .collect::<Vec<_>>(),
            ["aaaa-1"]
        );
        assert!(
            stale_gc_candidates(&root, &["invalid/id".into()]).is_err(),
            "a scoped ID must not escape the registry root"
        );
        assert!(
            stale_gc_candidates(&root, &[]).is_err(),
            "global GC must still fail closed on malformed registry identity"
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn esrch_means_the_process_disappeared() {
        assert!(process_disappeared(&std::io::Error::from_raw_os_error(libc::ESRCH)));
        assert!(!process_disappeared(&std::io::Error::from_raw_os_error(libc::EACCES)));
    }

    fn options(cwd: Option<&str>, env: &[(&str, &str)]) -> ExecOptions {
        ExecOptions::new(cwd.map(Into::into),
            env.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()).unwrap()
    }

    /// A sealed memfd holding `bytes`, with `seals` added after writing.
    fn memfd(bytes: &[u8], allow_sealing: bool, seals: i32) -> OwnedFd {
        let flags = libc::MFD_CLOEXEC | if allow_sealing { libc::MFD_ALLOW_SEALING } else { 0 };
        let fd = unsafe { libc::memfd_create(c"kiln-test-options".as_ptr(), flags) };
        assert!(fd >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        fs::File::from(fd.try_clone().unwrap()).write_all(bytes).unwrap();
        if seals != 0 { assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) }, 0); }
        fd
    }

    /// Distinct status and stdio numbers for read_options_fd's checks.
    fn machine_fds() -> (UnixStream, UnixStream, [fs::File; 3]) {
        let (status, peer) = UnixStream::pair().unwrap();
        (status, peer, [open("/dev/null"), open("/dev/null"), open("/dev/null")])
    }

    fn raw(files: &[fs::File; 3]) -> [RawFd; 3] { [files[0].as_raw_fd(), files[1].as_raw_fd(), files[2].as_raw_fd()] }

    #[test]
    fn operation_4_bytes_are_unchanged_and_operation_5_appends_the_frame() {
        // Operation 4's golden, as before exec options existed.
        let (op, body) = typed_request(&["true".into()], None).unwrap();
        assert_eq!((op, body.as_slice()), (4, &b"\x01\0\0\0\x04\0\0\0true"[..]));
        let (client, mut server) = UnixStream::pair().unwrap();
        send_header(&client, op, body.len() as u32, &[]).unwrap();
        let mut header = [0u8; 8]; server.read_exact(&mut header).unwrap();
        assert_eq!(header, [4, 0, 0, 0, 12, 0, 0, 0]);
        // Operation 5: the same argv block, then the options golden (45 bytes).
        let frame = options(Some("/w"), &[("B", "2"), ("A", "")]).encode();
        let (op, body5) = typed_request(&["true".into()], Some(&frame)).unwrap();
        assert_eq!((op, &body5[..12]), (5, &body[..]));
        assert_eq!(&body5[12..], frame.as_slice());
        assert_eq!(body5.len(), 57);
        let (client, mut server) = UnixStream::pair().unwrap();
        send_header(&client, op, body5.len() as u32, &[]).unwrap();
        server.read_exact(&mut header).unwrap();
        assert_eq!(header, [5, 0, 0, 0, 57, 0, 0, 0]);
    }

    #[test]
    fn operation_5_parses_at_every_split() {
        let expected = options(Some("/tmp/../w"), &[("PATH", "/opt/bin"), ("V", "雪 x")]);
        let (op, body) = typed_request(&["sh".into(), "-c".into(), "env".into()], Some(&expected.encode())).unwrap();
        let mut message = vec![op, 0, 0, 0];
        message.extend_from_slice(&(body.len() as u32).to_le_bytes());
        message.extend_from_slice(&body);
        let null = open("/dev/null");
        for split in 1..=message.len() {
            let (client, server) = UnixStream::pair().unwrap();
            send_with_fds(&client, &message[..split], &[null.as_raw_fd(); 3]).unwrap();
            (&client).write_all(&message[split..]).unwrap();
            let mut reader = RequestReader::new();
            let request = loop {
                if let ReadState::Complete(request) = reader.read(&server).unwrap() { break request; }
            };
            let Request::OptionsExec(argv, options, fds) = request else { panic!("split {split}: not operation 5") };
            assert_eq!(argv.iter().map(|a| a.to_str().unwrap()).collect::<Vec<_>>(), ["sh", "-c", "env"]);
            assert_eq!((options, fds.len()), (expected.clone(), 3), "split {split}");
        }
    }

    #[test]
    fn operation_5_is_revalidated_by_the_reader() {
        let good = options(Some("/w"), &[("A", "1")]).encode();
        let argv = typed_request(&["true".into()], None).unwrap().1;
        let mut bad_cwd = good.clone(); bad_cwd[24] = b'w';
        let mut bad_name = good.clone(); bad_name[30] = b'1';
        let mut trailing = good.clone(); trailing.push(0);
        let cases: [(Vec<u8>, &str); 5] = [
            (argv.clone(), "truncated exec options header"),
            ([argv.clone(), bad_cwd].concat(), "cwd must start with /"),
            ([argv.clone(), bad_name].concat(), "must match"),
            ([argv.clone(), trailing].concat(), "length does not match"),
            ([b"\x01\0\0\0\0\0\0\0".to_vec(), good.clone()].concat(), "name a program"),
        ];
        for (body, expected) in cases {
            let (client, server) = UnixStream::pair().unwrap();
            let null = open("/dev/null");
            send_header(&client, 5, body.len() as u32, &[null.as_raw_fd(); 3]).unwrap();
            (&client).write_all(&body).unwrap();
            let error = format!("{:#}", RequestReader::new().read(&server).unwrap_err());
            assert!(error.contains(expected), "{error}");
        }
        for (op, len, ok) in [(5, MAX_REQUEST + exec_options::MAX_FRAME, true), (5, MAX_REQUEST + exec_options::MAX_FRAME + 1, false),
            (4, MAX_REQUEST + 1, false)] {
            let (client, server) = UnixStream::pair().unwrap();
            let null = open("/dev/null");
            send_header(&client, op, len as u32, &[null.as_raw_fd(); 3]).unwrap();
            let read = RequestReader::new().read(&server);
            assert_eq!(read.is_ok(), ok, "op {op} len {len}");
        }
        // Operation 5's argv block keeps operation 4's 1 MiB bound.
        let big = typed_request(&["x".repeat(MAX_REQUEST - 8)], None).unwrap().1;
        assert_eq!(big.len(), MAX_REQUEST);
        let mut too_big = big.clone(); too_big[4] += 1; too_big.push(b'x');
        let (client, server) = UnixStream::pair().unwrap();
        let null = open("/dev/null");
        let body = [too_big, good].concat();
        send_header(&client, 5, body.len() as u32, &[null.as_raw_fd(); 3]).unwrap();
        let writer = std::thread::spawn(move || (&client).write_all(&body).unwrap());
        let mut reader = RequestReader::new();
        let error = loop {
            match reader.read(&server) { Ok(ReadState::Pending) => continue, Ok(_) => panic!("accepted"), Err(e) => break e };
        };
        writer.join().unwrap();
        assert!(error.to_string().contains("too large"), "{error}");
    }

    #[test]
    fn options_fd_must_be_an_exactly_sealed_memfd() {
        let (status, _peer, stdio) = machine_fds();
        let stdio_fds = raw(&stdio);
        let frame = options(Some("/w"), &[("A", "1")]).encode();
        let all = exec_options::REQUIRED_SEALS;
        let fd = memfd(&frame, true, all);
        // Taking the frame closes the caller's descriptor.
        let number = fd.into_raw_fd();
        assert_eq!(read_options_fd(number, status.as_raw_fd(), stdio_fds).unwrap(), frame);
        assert_eq!(unsafe { libc::fcntl(number, libc::F_GETFD) }, -1);
        // The caller's file offset is irrelevant: the frame is read with pread.
        let fd = memfd(&frame, true, all);
        assert_eq!(unsafe { libc::lseek(fd.as_raw_fd(), 9, libc::SEEK_SET) }, 9);
        assert_eq!(read_options_fd(fd.into_raw_fd(), status.as_raw_fd(), stdio_fds).unwrap(), frame);

        let refused = |fd: RawFd, expected: &str| {
            let error = format!("{:#}", read_options_fd(fd, status.as_raw_fd(), stdio_fds).unwrap_err());
            assert!(error.contains(expected), "{expected}: {error}");
        };
        for missing in [libc::F_SEAL_SEAL, libc::F_SEAL_SHRINK, libc::F_SEAL_GROW, libc::F_SEAL_WRITE] {
            refused(memfd(&frame, true, all & !missing).into_raw_fd(), "exactly");
        }
        refused(memfd(&frame, true, 0).into_raw_fd(), "exactly");
        refused(memfd(&frame, false, 0).into_raw_fd(), "exactly");
        refused(memfd(&frame, true, all | libc::F_SEAL_FUTURE_WRITE).into_raw_fd(), "exactly");
        let regular = std::env::temp_dir().join(format!("kiln-options-{}", std::process::id()));
        fs::write(&regular, &frame).unwrap();
        refused(fs::File::open(&regular).unwrap().into_raw_fd(), "must be a memfd");
        fs::remove_file(&regular).unwrap();
        let (pipe_rx, _pipe_tx) = pipe2(OFlag::O_CLOEXEC).unwrap();
        refused(pipe_rx.into_raw_fd(), "must be a memfd");
        refused(fs::File::open("/").unwrap().into_raw_fd(), "must be a memfd");
        // One byte past the bound, sealed, is refused before it is read.
        refused(memfd(&vec![0; exec_options::MAX_FRAME + 1], true, all).into_raw_fd(), "frame bound");
        // Sealed but malformed or out-of-bounds contents.
        let mut bad = frame.clone(); bad[24] = b'w';
        refused(memfd(&bad, true, all).into_raw_fd(), "cwd must start with /");
        refused(memfd(&[], true, all).into_raw_fd(), "truncated");
        // A write-only or O_PATH descriptor of a valid memfd can't be read.
        let fd = memfd(&frame, true, all);
        let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
        refused(fs::OpenOptions::new().write(true).open(&path).unwrap().into_raw_fd(), "readable");
        let opath = unsafe { libc::open(std::ffi::CString::new(path).unwrap().as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        assert!(opath >= 0);
        refused(opath, "readable");
        // Private numbers only, distinct from status and stdio; no aliasing.
        refused(status.as_raw_fd(), "distinct");
        refused(stdio_fds[1], "distinct");
        refused(2, "distinct");
        refused(9999, "invalid exec options fd");
        let shared = memfd(&frame, true, all);
        let alias = shared.try_clone().unwrap();
        let error = format!("{:#}", read_options_fd(alias.into_raw_fd(), status.as_raw_fd(),
            [stdio_fds[0], shared.as_raw_fd(), stdio_fds[2]]).unwrap_err());
        assert!(error.contains("aliases workload stdio"), "{error}");
    }

    #[test]
    fn options_refuse_a_pid1_without_the_feature_before_sending_an_exec() {
        for (features, refused) in [(0x1f, true), (0x0f, true), (0x2f, false), (0x3f, false), (0x2e, true)] {
            let path = std::env::temp_dir().join(format!("kiln-options-probe-{}-{features}.sock", std::process::id()));
            let listener = UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut header = [0u8; 8];
                stream.read_exact(&mut header).unwrap();
                let caps = Capabilities { features, ..Capabilities::current() };
                stream.write_all(&Frame::Capabilities(caps).encode().unwrap()).unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
                let mut rest = Vec::new();
                stream.read_to_end(&mut rest).unwrap();
                listener.set_nonblocking(true).unwrap();
                // Exactly one connection carrying only the operation 3 header.
                (header, rest, listener.accept().is_err())
            });
            let mut stage = Stage::Connect;
            let outcome = require_exec_options(&path, &mut stage).unwrap();
            let (header, rest, no_second) = server.join().unwrap();
            assert_eq!((header, rest.len(), no_second), ([3, 0, 0, 0, 0, 0, 0, 0], 0, true));
            assert_eq!(outcome.is_some(), refused, "{features:#x}");
            if let Some(o) = outcome {
                assert_eq!((o.kind, o.stage, o.cleanup, o.status), (FailureKind::Incompatible, Stage::Handshake,
                    Cleanup::NoChildStarted, None));
            }
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn invalid_options_fd_is_reported_on_status_with_no_child() {
        let (status, mut receiver) = UnixStream::pair().unwrap();
        let input = fs::File::open("/dev/null").unwrap();
        let (out_rx, out_tx) = pipe2(OFlag::O_CLOEXEC).unwrap();
        let (_err_rx, err_tx) = pipe2(OFlag::O_CLOEXEC).unwrap();
        let unsealed = memfd(&options(None, &[]).encode(), true, 0);
        let stdio = [input.into_raw_fd(), out_tx.into_raw_fd(), err_tx.into_raw_fd()];
        assert_eq!(machine_exec("1-1", &["true".into()], 1, status.into_raw_fd(), stdio,
            Some(unsealed.into_raw_fd())).unwrap(), 125);
        let Frame::Outcome(o) = protocol::read_reply(&mut receiver, Some(Instant::now() + protocol::FRAME_TIMEOUT)).unwrap()
            else { panic!("not an outcome") };
        assert_eq!((o.kind, o.stage, o.cleanup), (FailureKind::InvalidRequest, Stage::Validate, Cleanup::NoChildStarted));
        let mut out = Vec::new();
        fs::File::from(out_rx).read_to_end(&mut out).unwrap();
        assert!(out.is_empty());
    }
}
