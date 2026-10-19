//! kiln-init: what runs as PID 1 inside the sandbox.
//!
//! The kernel treats a PID namespace's init specially: signals sent from inside
//! the namespace are dropped unless init installed a handler, and every orphaned
//! process is reparented to it. A normal command as PID 1 therefore ignores
//! `kill` and `timeout`, and never reaps orphans, which pile up as zombies.
//! So instead of exec'ing the command, PID 1 forks it and stays behind to
//! forward signals and reap children, like `tini` does for Docker.

use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::signal::{SigSet, Signal, kill};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execvp, fork, pipe2, read, setpgid, write};

use crate::cgroup::ExecCgroup;
use crate::persistent::EXEC_FAILED;

/// Signals passed on to the command. SIGINT, SIGQUIT and SIGWINCH are left
/// out on purpose: the terminal sends those to the whole foreground process
/// group, so the command already gets them directly. Forwarding would deliver
/// them twice.
pub const FORWARDED: [Signal; 4] =
    [Signal::SIGTERM, Signal::SIGHUP, Signal::SIGUSR1, Signal::SIGUSR2];

/// How long the header of a request that arrives during an exec may take.
const BUSY_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Starts `argv` as a child and supervises it until it exits. Returns its
/// shell-style exit code (128 + signal number if it was killed).
pub fn run(argv: &[CString]) -> Result<i32> {
    // Block everything so signals queue up for sigwait() below instead of
    // running default actions. The child inherits the mask, so it clears it.
    let all = SigSet::all();
    all.thread_block().context("block signals")?;

    // SAFETY: single-threaded, so the child can safely run any code.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            prepare_command_signals();
            let err = execvp(&argv[0], argv).unwrap_err();
            eprintln!("kiln: exec {}: {err}", argv[0].to_string_lossy());
            // 127 is the shell's "command not found" code.
            std::process::exit(127);
        }
        ForkResult::Parent { child } => loop {
            match all.wait().context("sigwait")? {
                Signal::SIGCHLD => {
                    if let Some(code) = reap(Some(child))? {
                        crate::trace::mark("init: command exited");
                        return Ok(code);
                    }
                }
                sig if FORWARDED.contains(&sig) => {
                    let _ = kill(child, sig);
                }
                _ => {}
            }
        },
    }
}

/// Serves commands for a persistent sandbox. The listener was opened by the
/// host shim before pivot_root; accepted sockets and passed stdio descriptors
/// are the only host objects exposed after lockdown. One exec runs at a time,
/// inside `scope`, the sandbox's exec cgroup.
pub fn serve(listener: &UnixListener, scope: &ExecCgroup) -> Result<i32> {
    let all = SigSet::all();
    all.thread_block().context("block signals")?;
    // Readiness may become stale before accept(), especially when signals and
    // connections wake the same poll. Never let PID 1 block in accept().
    listener.set_nonblocking(true).context("set control listener nonblocking")?;
    // Blocked signals queue up on the signalfd, so one poll() waits for them,
    // the client hanging up and new requests.
    let signals = SignalFd::with_flags(&all, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .context("signalfd")?;
    loop {
        let mut stream = match wait_for_request(listener, &signals)? {
            IdleEvent::Request(stream) => stream,
            IdleEvent::Stop(code) => return Ok(code),
        };
        let (op, argv, fds) = match crate::persistent::receive(&mut stream) {
            Ok(request) => request,
            Err(e) => { eprintln!("kiln: bad exec request: {e:#}"); continue; }
        };
        if op == 2 {
            stream.write_all(&0i32.to_ne_bytes())?;
            return Ok(0);
        }
        if op != 1 || fds.len() != 3 {
            eprintln!("kiln: exec request needs stdin, stdout and stderr");
            continue;
        }
        // A client that went away can't take the status; failing to send it
        // must not end PID 1 and with it the sandbox.
        match run_exec(&argv, fds, &stream, listener, scope, &signals)? {
            Outcome::Exited(code) => if let Err(e) = stream.write_all(&code.to_ne_bytes()) {
                eprintln!("kiln: report exec status: {e}");
            },
            Outcome::Disconnected => eprintln!("kiln: exec client disconnected; stopped its command"),
            Outcome::Stop(code) => return Ok(code),
            // A request-local setup failure such as fork() returning EAGAIN
            // at pids.max must fail this exec, not unwind PID 1 and destroy
            // the persistent sandbox. Dropping the stream makes the CLI
            // report kiln's own failure code (125).
            Outcome::RequestFailed => eprintln!("kiln: exec request failed before launch"),
            Outcome::Removed(mut remover) => {
                remover.write_all(&0i32.to_ne_bytes())?;
                return Ok(0);
            }
        }
    }
}

/// How an exec ended. Every exec ends with its cgroup empty.
enum Outcome {
    /// The command exited with this shell-style status.
    Exited(i32),
    /// The client hung up first (killed, or timed out by a caller like kilnd).
    Disconnected,
    /// An idle shutdown signal arrived after request acceptance but before
    /// command admission. It belongs to the sandbox, not the next command.
    Stop(i32),
    /// Trusted request setup failed before any child was created.
    RequestFailed,
    /// `kiln rm` arrived; this is its connection, still to be acknowledged.
    Removed(UnixStream),
}

/// What wakes PID 1 while no exec request is active.
enum IdleEvent {
    /// A client connected with a new exec or removal request.
    Request(UnixStream),
    /// A forwarded signal has its normal no-workload meaning: stop the
    /// persistent sandbox instead of saving it for an unrelated later exec.
    Stop(i32),
}

/// Runs one exec request inside the exec cgroup. Process groups and sessions
/// are the command's to change, so they can't bound what it started; the
/// cgroup can. Whatever ends the exec, every process it started is killed and
/// gone before this returns, so the client's stdout and stderr reach EOF and
/// the next exec starts from an empty cgroup.
fn run_exec(argv: &[CString], stdio: Vec<OwnedFd>, client: &UnixStream, listener: &UnixListener,
    scope: &ExecCgroup, signals: &SignalFd) -> Result<Outcome> {
    // Request reception is deliberately still part of the idle state. Drain
    // once at the admission boundary so a shutdown signal received after
    // accept() cannot cross into and terminate this unrelated command.
    if let Some(code) = drain_idle_signals(signals)? {
        return Ok(Outcome::Stop(code));
    }

    // The child reports whether it joined the exec cgroup, then waits to be
    // released. It runs only kiln's code until then.
    let (joined_rx, joined_tx) = match pipe2(OFlag::O_CLOEXEC) {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("kiln: create exec admission pipe: {e}");
            return Ok(Outcome::RequestFailed);
        }
    };
    let (release_rx, release_tx) = match pipe2(OFlag::O_CLOEXEC) {
        Ok(pipe) => pipe,
        Err(e) => {
            eprintln!("kiln: create exec release pipe: {e}");
            return Ok(Outcome::RequestFailed);
        }
    };
    // SAFETY: PID 1 is single-threaded.
    let leader = match unsafe { fork() } {
        Err(e) => {
            eprintln!("kiln: fork exec request: {e}");
            return Ok(Outcome::RequestFailed);
        }
        Ok(ForkResult::Child) => {
            drop(joined_rx);
            drop(release_tx);
            launch(argv, &stdio, scope, &joined_tx, &release_rx)
        }
        Ok(ForkResult::Parent { child }) => child,
    };
    drop(joined_tx);
    drop(release_rx);
    // Only the command holds the client's stdio from here on.
    drop(stdio);
    let _ = setpgid(leader, leader);

    let mut byte = [0u8; 1];
    if !matches!(read(&joined_rx, &mut byte), Ok(1) if byte[0] == b'1') {
        // It never joined, so the cgroup can't reach it: kill it directly.
        eprintln!("kiln: exec could not join its cgroup; not running {}", argv[0].to_string_lossy());
        let _ = kill(leader, Signal::SIGKILL);
        let _ = waitpid(leader, None);
        return finish(scope, Outcome::Exited(126));
    }

    // Last check before the command runs: a client that already left or a
    // pending `kiln rm` stops it here. Anything later is still contained.
    let mut wait = watch(signals, client, listener);
    poll(&mut wait, 0)?;
    if let Some(outcome) = interrupted(&wait, listener)? {
        return finish(scope, outcome);
    }
    // If the child died meanwhile, its SIGCHLD ends the loop below.
    let _ = write(&release_tx, b"1");
    drop(release_tx);

    let outcome = loop {
        let mut wait = watch(signals, client, listener);
        poll(&mut wait, -1)?;
        if let Some(outcome) = interrupted(&wait, listener)? {
            break outcome;
        }
        let mut status = None;
        while let Some(info) = signals.read_signal().context("read signalfd")? {
            match Signal::try_from(info.ssi_signo as i32) {
                Ok(Signal::SIGCHLD) => if let Some(code) = reap(Some(leader))? {
                    status = Some(code);
                },
                Ok(sig) if FORWARDED.contains(&sig) && status.is_none() => {
                    forward_to_group(leader, sig);
                }
                _ => {}
            }
        }
        if let Some(code) = status {
            break Outcome::Exited(code);
        }
    };
    finish(scope, outcome)
}

/// The forked child: joins the exec cgroup, waits for PID 1 to release it,
/// then becomes the command. Every instruction of the command, and of all it
/// starts, runs inside the cgroup.
fn launch(argv: &[CString], stdio: &[OwnedFd], scope: &ExecCgroup, joined: &OwnedFd, release: &OwnedFd) -> ! {
    let ok = match scope.join_self() {
        Ok(()) => true,
        Err(e) => { eprintln!("kiln: {e:#}"); false }
    };
    let _ = write(joined, if ok { b"1" } else { b"0" });
    let mut byte = [0u8; 1];
    if !ok || !matches!(read(release, &mut byte), Ok(1)) {
        std::process::exit(126);
    }
    // The command must not be able to move or kill processes in cgroups.
    scope.close_in_child();
    for (target, source) in stdio.iter().enumerate() {
        if unsafe { libc::dup2(source.as_raw_fd(), target as i32) } < 0 {
            std::process::exit(126);
        }
    }
    // Its own process group only so forwarded signals have a clear target;
    // containment doesn't depend on it.
    let _ = setpgid(Pid::from_raw(0), Pid::from_raw(0));
    prepare_command_signals();
    let err = execvp(&argv[0], argv).unwrap_err();
    eprintln!("kiln: exec {}: {err}", argv[0].to_string_lossy());
    std::process::exit(127);
}

/// The one way an exec ends, whether its command exited, its client left, it
/// couldn't start or `kiln rm` interrupted it: kill everything left in the
/// exec cgroup, wait until it's empty, and reap every last process. An error
/// here ends PID 1, and with it the sandbox, rather than run the next exec
/// beside leftovers.
fn finish(scope: &ExecCgroup, outcome: Outcome) -> Result<Outcome> {
    scope.kill_and_wait_empty()?;
    reap_all_blocking()?;
    Ok(outcome)
}

/// Waits for and reaps every remaining child, direct or adopted, until none
/// are left. The exec cgroup reads empty as soon as its processes pass
/// cgroup_exit(), slightly before they become zombies, and a zombie still
/// holds its slot in `pids.max` until it's reaped. Only after this may the
/// next exec fork. Every child of a persistent PID 1 was in the now-empty exec
/// cgroup, so each is already dying and this can't block on a live process.
fn reap_all_blocking() -> Result<()> {
    loop {
        match waitpid(Pid::from_raw(-1), None) {
            Ok(_) | Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => return Ok(()),
            Err(e) => return Err(e).context("waitpid"),
        }
    }
}

/// What a running exec waits on: signals, its client hanging up, and new
/// connections.
fn watch(signals: &SignalFd, client: &UnixStream, listener: &UnixListener) -> [libc::pollfd; 3] {
    [
        libc::pollfd { fd: signals.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: client.as_raw_fd(), events: libc::POLLRDHUP, revents: 0 },
        libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
    ]
}

fn poll(fds: &mut [libc::pollfd], timeout: i32) -> Result<()> {
    loop {
        // SAFETY: `fds` points to initialized pollfds for the supplied length.
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) } >= 0 {
            return Ok(());
        }
        match Errno::last() {
            Errno::EINTR => continue,
            e => return Err(e).context("poll"),
        }
    }
}

/// Waits for work without abandoning PID 1's other lifetime duties. Adopted
/// children can exit long after their launching command, so SIGCHLD is reaped
/// even while the control listener is otherwise idle. A forwarded signal with
/// no active command stops the sandbox with the signal's shell-style status;
/// it is never retained for the next command.
fn wait_for_request(listener: &UnixListener, signals: &SignalFd) -> Result<IdleEvent> {
    loop {
        let mut wait = [
            libc::pollfd { fd: signals.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        poll(&mut wait, -1)?;

        poll_error(wait[0].revents, "signalfd")?;
        poll_error(wait[1].revents, "control listener")?;
        if let Some(code) = drain_idle_signals(signals)? {
            return Ok(IdleEvent::Stop(code));
        }
        if wait[1].revents & libc::POLLIN != 0 {
            match listener.accept() {
                Ok((stream, _)) => return Ok(IdleEvent::Request(stream)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e).context("accept exec request"),
            }
        }
    }
}

/// Performs PID 1's idle signal duties and returns the first requested stop.
/// Reading until EAGAIN matters because standard signals can coalesce and a
/// SIGCHLD may share a readiness notification with a shutdown signal.
fn drain_idle_signals(signals: &SignalFd) -> Result<Option<i32>> {
    let mut stop = None;
    while let Some(info) = signals.read_signal().context("read signalfd")? {
        match Signal::try_from(info.ssi_signo as i32) {
            Ok(Signal::SIGCHLD) => { reap(None)?; }
            Ok(sig) if FORWARDED.contains(&sig) && stop.is_none() => {
                stop = Some(128 + sig as i32);
            }
            _ => {}
        }
    }
    Ok(stop)
}

fn poll_error(revents: i16, source: &str) -> Result<()> {
    let errors = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;
    if revents & errors != 0 {
        return Err(anyhow::anyhow!("{source} poll failure: revents={revents:#x}"));
    }
    Ok(())
}

/// Sends a signal to the command's process group. Descendants may create
/// other groups or sessions, so the exec cgroup remains the cleanup boundary;
/// this group delivery supplies normal signal semantics to cooperating work.
fn forward_to_group(leader: Pid, sig: Signal) {
    let _ = kill(Pid::from_raw(-leader.as_raw()), sig);
}

/// Rust ignores SIGPIPE for its own process. An exec'd command must receive
/// the Unix default instead, or pipeline writers observe EPIPE and return an
/// application error rather than terminating with SIGPIPE.
fn prepare_command_signals() {
    let _ = SigSet::empty().thread_set_mask();
    // SAFETY: SIG_DFL installs no function pointer and SIGPIPE is valid.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL); }
}

/// Whether the exec must stop because its client hung up or `kiln rm` came.
fn interrupted(wait: &[libc::pollfd; 3], listener: &UnixListener) -> Result<Option<Outcome>> {
    poll_error(wait[0].revents, "signalfd")?;
    poll_error(wait[2].revents, "control listener")?;
    if wait[1].revents != 0 {
        return Ok(Some(Outcome::Disconnected));
    }
    if wait[2].revents & libc::POLLIN != 0 {
        return Ok(accept_while_busy(listener)?.map(Outcome::Removed));
    }
    Ok(None)
}

/// Handles a connection that arrives while an exec runs. Execs run one at a
/// time, so another exec request fails with EXEC_FAILED instead of queueing.
/// Returns a `kiln rm` connection, which interrupts the running exec.
fn accept_while_busy(listener: &UnixListener) -> Result<Option<UnixStream>> {
    let mut stream = match listener.accept() {
        Ok((stream, _)) => stream,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
        Err(e) => return Err(e).context("accept exec request"),
    };
    // Only the fixed-size header is read, in one recvmsg, so a client that
    // stalls holds up the running exec for at most this once. An exec's body
    // is never read: the request is refused either way.
    if let Err(e) = stream.set_read_timeout(Some(BUSY_READ_TIMEOUT)) {
        eprintln!("kiln: set request timeout: {e}");
        return Ok(None);
    }
    match crate::persistent::receive_header(&stream) {
        Ok((2, 0, fds)) if fds.is_empty() => Ok(Some(stream)),
        Ok((1, _, fds)) => {
            drop(fds);
            eprintln!("kiln: refused an exec request while another exec runs");
            let _ = stream.write_all(&EXEC_FAILED.to_ne_bytes());
            Ok(None)
        }
        Ok((op, len, fds)) => {
            eprintln!("kiln: bad request during exec: op {op}, {len} bytes, {} fds", fds.len());
            Ok(None)
        }
        Err(e) => { eprintln!("kiln: bad request during exec: {e:#}"); Ok(None) }
    }
}

/// Reaps every child that has exited, including orphans that were reparented
/// to us. Several exits can collapse into one SIGCHLD, so loop until none are
/// left. Returns the command's exit code once it has exited.
fn reap(command: Option<Pid>) -> Result<Option<i32>> {
    let mut code = None;
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, c)) if Some(pid) == command => code = Some(c),
            Ok(WaitStatus::Signaled(pid, sig, _)) if Some(pid) == command => {
                code = Some(128 + sig as i32)
            }
            Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => return Ok(code),
            Ok(_) => continue,
            Err(e) => return Err(e).context("waitpid"),
        }
    }
}
