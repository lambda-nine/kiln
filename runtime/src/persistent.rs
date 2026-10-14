use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::fcntl::OFlag;
use nix::sys::signal::kill;
use nix::unistd::{ForkResult, Pid, fork, pipe2, read, setsid};

use crate::container::{self, Config};

const MAX_REQUEST: usize = 1024 * 1024;
/// Exit code of `kiln exec` when kiln itself fails (bad ID, sandbox gone,
/// terminal stdio) rather than the command.
pub const EXEC_FAILED: i32 = 125;

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
        .context("sandbox exited during exec")?;
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

pub fn receive(stream: &mut UnixStream) -> Result<(u8, Vec<CString>, Vec<OwnedFd>)> {
    let (op, len, fds) = recv_header(stream)?;
    if len as usize > MAX_REQUEST {
        bail!("request is too large");
    }
    let mut data = vec![0; len as usize];
    stream.read_exact(&mut data)?;
    if op != 1 {
        return Ok((op, Vec::new(), fds));
    }
    let mut at = 0;
    let argc = take_u32(&data, &mut at)? as usize;
    if argc == 0 || argc > 4096 {
        bail!("invalid argument count");
    }
    let mut argv = Vec::with_capacity(argc);
    for _ in 0..argc {
        let n = take_u32(&data, &mut at)? as usize;
        let bytes = data.get(at..at + n).context("truncated argument")?;
        argv.push(CString::new(bytes).context("argument contains a NUL byte")?);
        at += n;
    }
    if at != data.len() {
        bail!("trailing request data");
    }
    Ok((op, argv, fds))
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
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
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
    if n != 8 {
        bail!("send exec request: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

fn recv_header(stream: &UnixStream) -> Result<(u8, u32, Vec<OwnedFd>)> {
    let mut header = [0u8; 8];
    let mut iov = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    let mut control =
        vec![0u8; unsafe { libc::CMSG_SPACE((3 * mem::size_of::<RawFd>()) as u32) as usize }];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();
    let n = unsafe {
        libc::recvmsg(
            stream.as_raw_fd(),
            &mut msg,
            libc::MSG_WAITALL | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if n != 8 {
        bail!("read exec request");
    }
    let mut fds = Vec::new();
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if !cmsg.is_null()
            && (*cmsg).cmsg_level == libc::SOL_SOCKET
            && (*cmsg).cmsg_type == libc::SCM_RIGHTS
        {
            let count = ((*cmsg).cmsg_len - libc::CMSG_LEN(0) as usize) / mem::size_of::<RawFd>();
            for &fd in std::slice::from_raw_parts(libc::CMSG_DATA(cmsg).cast::<RawFd>(), count) {
                fds.push(OwnedFd::from_raw_fd(fd));
            }
        }
    }
    Ok((
        header[0],
        u32::from_ne_bytes(header[4..].try_into().unwrap()),
        fds,
    ))
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
