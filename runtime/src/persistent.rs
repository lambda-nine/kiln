use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::signal::kill;
use nix::unistd::{ForkResult, Pid, fork, pipe2, read, setsid};

use crate::container::{self, Config};

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_REQUEST_FDS: usize = 3;
/// Exit code of `kiln exec` when kiln itself fails (bad ID, sandbox gone,
/// terminal stdio) rather than the command.
pub const EXEC_FAILED: i32 = 125;

/// One complete, validated request from a persistent control connection.
#[derive(Debug)]
pub enum Request {
    Exec(Vec<CString>, Vec<OwnedFd>),
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
            len: u32::from_ne_bytes(self.bytes[4..].try_into().unwrap()),
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
            if header.len as usize > MAX_REQUEST {
                bail!("request is too large");
            }
            match header.op {
                1 if header.fds.len() != MAX_REQUEST_FDS => {
                    bail!("exec request needs stdin, stdout and stderr")
                }
                1 => {
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
        let argv = parse_argv(&self.body)?;
        self.complete = true;
        Ok(ReadState::Complete(Request::Exec(argv, header.fds)))
    }
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

pub fn create(cfg: &Config) -> Result<String> {
    container::validate_image(cfg)?;
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
    if cmd.is_empty() {
        bail!("a command is required");
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(&(cmd.len() as u32).to_ne_bytes());
    for arg in cmd {
        let bytes = arg.as_bytes();
        payload.extend_from_slice(&(bytes.len() as u32).to_ne_bytes());
        payload.extend_from_slice(bytes);
    }
    if payload.len() > MAX_REQUEST {
        bail!("command is too large");
    }
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
    println!("ID\tSTATUS\tSHIM");
    let root = Path::new("/var/lib/kiln/runs");
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(());
    };
    let mut ids: Vec<_> = entries
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    ids.sort();
    for id in ids {
        let dir = container::run_dir(&id);
        if !dir.join("control.sock").exists() {
            continue;
        }
        let pid = fs::read_to_string(dir.join("shim.pid")).unwrap_or_default();
        let live = pid.trim().parse::<i32>().ok().is_some_and(pid_alive);
        println!(
            "{id}\t{}\t{}",
            if live { "running" } else { "stale" },
            pid.trim()
        );
    }
    Ok(())
}

pub fn gc() -> Result<()> {
    let root = Path::new("/var/lib/kiln/runs");
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(());
    };
    for entry in entries.flatten() {
        if !entry.path().join("shim.pid").exists() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        let pid = fs::read_to_string(entry.path().join("shim.pid"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        if entry.path().join("control.sock").exists() && pid.is_some_and(pid_alive) {
            continue;
        }
        crate::cgroup::remove(&id);
        crate::net::remove_run(&id);
        fs::remove_dir_all(entry.path()).with_context(|| format!("remove stale sandbox {id}"))?;
        eprintln!("kiln: removed stale sandbox {id}");
    }
    Ok(())
}

fn parse_argv(data: &[u8]) -> Result<Vec<CString>> {
    let mut at = 0;
    let argc = take_u32(data, &mut at)? as usize;
    if argc == 0 || argc > 4096 {
        bail!("invalid argument count");
    }
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        let n = take_u32(data, &mut at)? as usize;
        let bytes = data.get(at..at + n).context("truncated argument")?;
        argv.push(CString::new(bytes).context("argument contains a NUL byte")?);
        at += n;
    }
    if at != data.len() {
        bail!("trailing request data");
    }
    Ok(argv)
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

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        bail!("invalid sandbox ID {id:?}");
    }
    Ok(())
}

fn pid_alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
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
    header[4..].copy_from_slice(&len.to_ne_bytes());
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
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, 0) };
    if n < 0 {
        bail!("send exec request: {}", std::io::Error::last_os_error());
    }
    if n as usize != bytes.len() {
        bail!("send exec request: short write ({n} of {} bytes)", bytes.len());
    }
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
            Errno::EAGAIN => Ok(RecvChunk::Pending),
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
                if payload % mem::size_of::<RawFd>() != 0 {
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
    use std::os::unix::fs::OpenOptionsExt;

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
}
