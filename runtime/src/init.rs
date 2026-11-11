//! kiln-init: what runs as PID 1 inside the sandbox.
//!
//! The kernel treats a PID namespace's init specially: signals sent from inside
//! the namespace are dropped unless init installed a handler, and every orphaned
//! process is reparented to it. A normal command as PID 1 therefore ignores
//! `kill` and `timeout`, and never reaps orphans, which pile up as zombies.
//! So instead of exec'ing the command, PID 1 forks it and stays behind to
//! forward signals and reap children, like `tini` does for Docker.

use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::signal::{SigSet, Signal, kill};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::unistd::{ForkResult, Pid, execvp, fork, pipe2, read, setpgid, write};

use crate::cgroup::ExecCgroup;
use crate::exec_options::{ExecOptions, LaunchOptions};
use crate::persistent::{EXEC_FAILED, Header, HeaderReader, ReadState, Request, RequestReader, max_body};
use crate::exec_protocol::{self as protocol, Capabilities, Cleanup, CommandStatus, FailureKind,
    Frame, Outcome as ExecOutcome, Stage};

/// Signals passed on to the command. SIGINT, SIGQUIT and SIGWINCH are left
/// out on purpose: the terminal sends those to the whole foreground process
/// group, so the command already gets them directly. Forwarding would deliver
/// them twice.
pub const FORWARDED: [Signal; 4] =
    [Signal::SIGTERM, Signal::SIGHUP, Signal::SIGUSR1, Signal::SIGUSR2];

/// One absolute window for a complete local control frame, from its first
/// accept through its final payload byte. Progress does not reset it.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Connections a running exec keeps with an incomplete header. One header holds
/// at most three descriptors, so this also bounds what they can pin in PID 1.
const MAX_BUSY_PENDING: usize = 16;

/// Connections a running exec accepts per wake. The rest stay queued until the
/// signalfd, the client and the bootstrap channel have been serviced again.
const MAX_BUSY_ACCEPTS: usize = 8;
/// Explicit kernel backlog and a finite finalization budget large enough to
/// consume that backlog (Linux may queue one extra connection). Replenishing
/// clients cannot make finalization wait for an empty listener indefinitely.
const CONTROL_BACKLOG: i32 = 128;
const MAX_BUSY_FINALIZE_BATCHES: usize = (CONTROL_BACKLOG as usize + 1).div_ceil(MAX_BUSY_ACCEPTS);

/// The exec loop's fixed pollfds, ahead of the pending busy headers: signals,
/// client, listener and bootstrap channel.
const EXEC_WATCH: usize = 4;

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
                        return Ok(code.projection());
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
    // SAFETY: the descriptor is a live, bound Unix listener; listen updates its backlog.
    Errno::result(unsafe { libc::listen(listener.as_raw_fd(), CONTROL_BACKLOG) })
        .context("set control listener backlog")?;
    // Blocked signals queue up on the signalfd, so one poll() waits for them,
    // the client hanging up and new requests.
    let signals = SignalFd::with_flags(&all, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .context("signalfd")?;
    loop {
        let mut stream = match wait_for_request(listener, &signals)? {
            IdleEvent::Request(stream) => stream,
            IdleEvent::Stop(code) => return Ok(code),
        };
        let request = match receive_idle_request(&mut stream, &signals) {
            Ok(FramingOutcome::Request(request)) => request,
            Ok(FramingOutcome::Stop(code)) => return Ok(code),
            Err(e) => { eprintln!("kiln: bad exec request: {e:#}"); continue; }
        };
        let (argv, fds, typed, options) = match request {
            Request::Remove => {
                respond(&stream, &0i32.to_ne_bytes(), &signals, true);
                return Ok(0);
            }
            Request::Capabilities => {
                respond(&stream, &Frame::Capabilities(Capabilities::current()).encode()?, &signals, true);
                continue;
            }
            Request::Exec(argv, fds) => (argv, fds, false, None),
            Request::TypedExec(argv, fds) => (argv, fds, true, None),
            Request::OptionsExec(argv, options, fds) => (argv, fds, true, Some(options)),
        };
        // A client that went away can't take the status; failing to send it
        // must not end PID 1 and with it the sandbox.
        match run_exec(&argv, options.as_ref(), fds, &stream, listener, scope, &signals)? {
            Outcome::Completed(outcome) => report(&stream, &outcome, typed, &signals)?,
            Outcome::Fatal(outcome) => {
                report(&stream, &outcome, typed, &signals)?;
                anyhow::bail!("exec cleanup failed; stopping sandbox");
            }
            Outcome::Disconnected => eprintln!("kiln: exec client disconnected; stopped its command"),
            Outcome::Stop(code) => {
                if typed {
                    report(&stream, &ExecOutcome::failure(FailureKind::Stopped, Stage::Admission,
                        Cleanup::NoChildStarted, 0, "sandbox stopping before admission"), true, &signals)?;
                }
                return Ok(code);
            }
            Outcome::Removed(remover) => {
                if typed {
                    report(&stream, &ExecOutcome::failure(FailureKind::Stopped, Stage::Cleanup,
                        Cleanup::Drained, 0, "sandbox removed during exec"), true, &signals)?;
                }
                respond(&remover, &0i32.to_ne_bytes(), &signals, true);
                return Ok(0);
            }
        }
    }
}

/// How an exec ended. Cleanup must be confirmed before reuse.
enum Outcome {
    /// Typed command or request-local runtime result.
    Completed(ExecOutcome),
    Fatal(ExecOutcome),
    /// The client hung up first (killed, or timed out by a caller like kilnd).
    Disconnected,
    /// An idle shutdown signal arrived after request acceptance but before
    /// command admission. It belongs to the sandbox, not the next command.
    Stop(i32),
    /// `kiln rm` arrived; this is its connection, still to be acknowledged.
    Removed(UnixStream),
}

fn report(stream: &UnixStream, outcome: &ExecOutcome, typed: bool, signals: &SignalFd) -> Result<()> {
    let bytes = if typed { Frame::Outcome(outcome.clone()).encode()? }
        else { outcome.projection().to_ne_bytes().to_vec() };
    #[cfg(test)]
    if typed && injected("response-backpressure").is_some() {
        fixture_response_backpressure(stream, outcome)?;
    }
    respond(stream, &bytes, signals, true);
    Ok(())
}

/// Request-local write failure never unwinds PID 1. Leave signals queued for
/// the lifetime or exec loop so this writer cannot steal leader/stop ownership.
fn respond(stream: &UnixStream, bytes: &[u8], signals: &SignalFd, idle: bool) {
    let result = protocol::write_bounded(stream.as_raw_fd(), bytes, || {
        #[cfg(test)]
        if let Some(root) = std::env::var_os("KILN_PROTOCOL_FIXTURE") {
            let root = std::path::PathBuf::from(root);
            if root.join("response-started").exists() {
                // The saturated fixture reaches this callback only after the
                // real bounded writer has received EAGAIN.
                std::fs::write(root.join("response-blocked"), b"")?;
            }
        }
        // Leave signals queued for the lifetime/exec loop; in particular this
        // must never reap the active leader while replying to a busy probe.
        let mut p = [libc::pollfd { fd: signals.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
        poll(&mut p, 0)?;
        anyhow::ensure!(p[0].revents == 0, "signal pending during {} response", if idle { "idle" } else { "busy" });
        Ok(())
    });
    if let Err(e) = result { eprintln!("kiln: report status: {e:#}"); }
}

/// What wakes PID 1 while no exec request is active.
enum IdleEvent {
    /// A client connected with a new exec or removal request.
    Request(UnixStream),
    /// A forwarded signal has its normal no-workload meaning: stop the
    /// persistent sandbox instead of saving it for an unrelated later exec.
    Stop(i32),
}

/// A fully framed idle request, or the sandbox signal that preempted it.
enum FramingOutcome {
    Request(Request),
    Stop(i32),
}

/// Reads one idle request without abandoning PID 1's signal duties. Framing
/// has one absolute deadline; a slow byte stream cannot extend it by making
/// occasional progress.
fn receive_idle_request(stream: &mut UnixStream, signals: &SignalFd) -> Result<FramingOutcome> {
    stream.set_nonblocking(true).context("set control request nonblocking")?;
    let deadline = Instant::now() + REQUEST_READ_TIMEOUT;
    let mut reader = RequestReader::new();
    loop {
        if let Some(code) = drain_idle_signals(signals)? {
            return Ok(FramingOutcome::Stop(code));
        }
        if Instant::now() >= deadline {
            return Err(anyhow::anyhow!("control request framing deadline exceeded"));
        }
        let (state, stop) = read_frame_before_deadline(
            deadline,
            || reader.read(stream),
            || drain_idle_signals(signals),
            Instant::now,
        )?;
        if let Some(code) = stop {
            return Ok(FramingOutcome::Stop(code));
        }
        if let ReadState::Complete(request) = state {
            return Ok(FramingOutcome::Request(request));
        }
        wait_for_frame(stream, signals, deadline)?;
    }
}

/// Advances framing once, services signals, then samples the clock. Keeping
/// the clock injectable makes the post-read deadline boundary deterministic
/// under test: a read that completes after expiration must not be accepted.
fn read_frame_before_deadline<T>(
    deadline: Instant,
    read: impl FnOnce() -> Result<ReadState<T>>,
    after_read: impl FnOnce() -> Result<Option<i32>>,
    now: impl FnOnce() -> Instant,
) -> Result<(ReadState<T>, Option<i32>)> {
    let state = read()?;
    let stop = after_read()?;
    if stop.is_none() && now() >= deadline {
        return Err(anyhow::anyhow!("control request framing deadline exceeded"));
    }
    Ok((state, stop))
}

fn poll_millis(remaining: Duration) -> i32 {
    remaining.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32
}

fn wait_for_frame(stream: &UnixStream, signals: &SignalFd, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("control request framing deadline exceeded")?;
    let timeout = poll_millis(remaining);
    let mut wait = [
        libc::pollfd { fd: signals.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN | libc::POLLRDHUP,
            revents: 0,
        },
    ];
    if poll(&mut wait, timeout)? == 0 {
        return Err(anyhow::anyhow!("control request framing deadline exceeded"));
    }
    poll_error(wait[0].revents, "signalfd")?;
    socket_poll_error(wait[1].revents, "control request")
}

/// Runs one exec request inside the exec cgroup. Process groups and sessions
/// are the command's to change, so they can't bound what it started; the
/// cgroup can. Whatever ends the exec, every process it started is killed and
/// gone before this returns, so the client's stdout and stderr reach EOF and
/// the next exec starts from an empty cgroup.
fn run_exec(argv: &[CString], options: Option<&ExecOptions>, stdio: Vec<OwnedFd>, client: &UnixStream,
    listener: &UnixListener, scope: &ExecCgroup, signals: &SignalFd) -> Result<Outcome> {
    // Request reception is deliberately still part of the idle state. Drain
    // once at the admission boundary so a shutdown signal received after
    // accept() cannot cross into and terminate this unrelated command.
    if let Some(code) = drain_idle_signals(signals)? {
        return Ok(Outcome::Stop(code));
    }
    // Built before fork, so the child only calls chdir and swaps a pointer.
    // PID 1 itself never takes the cwd or environment.
    let options = options.map(LaunchOptions::new);
    #[cfg(test)]
    if let Some(errno) = injected("pipe") {
        return Ok(launch_failure(Stage::Prepare, Cleanup::NoChildStarted, errno, "injected pipe failure"));
    }

    // The child reports whether it joined the exec cgroup, then waits to be
    // released. It runs only kiln's code until then.
    let (joined_rx, joined_tx) = match pipe2(OFlag::O_CLOEXEC) {
        Ok(pipe) => pipe,
        Err(e) => {
            return Ok(launch_failure(Stage::Prepare, Cleanup::NoChildStarted, e as i32, "create exec admission pipe"));
        }
    };
    let (release_rx, release_tx) = match pipe2(OFlag::O_CLOEXEC) {
        Ok(pipe) => pipe,
        Err(e) => {
            return Ok(launch_failure(Stage::Prepare, Cleanup::NoChildStarted, e as i32, "create exec release pipe"));
        }
    };
    // SAFETY: PID 1 is single-threaded.
    #[cfg(test)]
    if let Some(errno) = injected("fork") {
        return Ok(launch_failure(Stage::Fork, Cleanup::NoChildStarted, errno, "injected fork failure"));
    }
    let leader = match unsafe { fork() } {
        Err(e) => {
            return Ok(launch_failure(Stage::Fork, Cleanup::NoChildStarted, e as i32, "fork exec request"));
        }
        Ok(ForkResult::Child) => {
            drop(joined_rx);
            drop(release_tx);
            launch(argv, options.as_ref(), &stdio, scope, &joined_tx, &release_rx)
        }
        Ok(ForkResult::Parent { child }) => child,
    };
    drop(joined_tx);
    drop(release_rx);
    // Only the command holds the client's stdio from here on.
    drop(stdio);
    let _ = setpgid(leader, leader);

    let mut status = None;
    let mut busy = BusyHeaders::new();
    // Every fallible parent operation after fork is inside this region. Its
    // result always crosses direct-child kill, cgroup drainage and reaping.
    let outcome = (|| -> Result<Outcome> {
        let flags = unsafe { libc::fcntl(joined_rx.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(joined_rx.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error()).context("nonblocking bootstrap channel");
        }
        let mut bootstrap = BootstrapReader::new();
        let mut release = Some(release_tx);
        loop {
            bootstrap.advance(&joined_rx)?;
            if let Some((stage, errno)) = bootstrap.failure {
                return Ok(launch_failure(stage, Cleanup::Unconfirmed, errno, "exec bootstrap failed"));
            }
            let mut wait = watch(signals, client, listener);
            // Negative descriptors in the unused slots are ignored by poll().
            let mut fds = [libc::pollfd { fd: -1, events: 0, revents: 0 }; EXEC_WATCH + MAX_BUSY_PENDING];
            fds[..3].copy_from_slice(&wait);
            fds[3] = libc::pollfd {
                fd: if bootstrap.eof { -1 } else { joined_rx.as_raw_fd() }, events: libc::POLLIN, revents: 0 };
            busy.watch(&mut fds[EXEC_WATCH..]);
            poll(&mut fds, if bootstrap.joined && release.is_some() { 0 } else { busy.timeout() })?;
            wait.copy_from_slice(&fds[..3]);
            if let Some(outcome) = interrupted(&wait, &fds[EXEC_WATCH..], &mut busy, listener, signals)? {
                return Ok(outcome);
            }
            while let Some(info) = signals.read_signal().context("read signalfd")? {
                match Signal::try_from(info.ssi_signo as i32) {
                    Ok(Signal::SIGCHLD) => if let Some(s) = reap(Some(leader))? { status = Some(s); },
                    Ok(sig) if FORWARDED.contains(&sig) => forward_to_group(leader, sig),
                    _ => {}
                }
            }
            // Read bootstrap failures before interpreting a reaped 126/127.
            bootstrap.advance(&joined_rx)?;
            if let Some((stage, errno)) = bootstrap.failure {
                return Ok(launch_failure(stage, Cleanup::Unconfirmed, errno, "exec bootstrap failed"));
            }
            if let Some(s) = status {
                if !bootstrap.joined || release.is_some() {
                    return Ok(launch_failure(Stage::Admission, Cleanup::Unconfirmed, 0, "bootstrap exited before release"));
                }
                if bootstrap.eof { return Ok(Outcome::Completed(ExecOutcome::command(s))); }
            }
            if bootstrap.joined && let Some(tx) = release.take() {
                #[cfg(test)]
                if let Some(errno) = injected("release") {
                    return Ok(launch_failure(Stage::Admission, Cleanup::Unconfirmed, errno, "injected release failure"));
                }
                loop {
                    match write(&tx, b"1") {
                        Ok(1) => break,
                        Err(Errno::EINTR) => continue,
                        Err(e) => return Ok(launch_failure(Stage::Admission, Cleanup::Unconfirmed, e as i32, "release exec bootstrap")),
                        _ => return Ok(launch_failure(Stage::Admission, Cleanup::Unconfirmed, 0, "short bootstrap release")),
                    }
                }
            }
        }
    })();
    // An admission failure may leave the child outside the exec cgroup.
    if status.is_none() { let _ = kill(leader, Signal::SIGKILL); }
    // Classify the queued backlog before cleanup. A new exec connecting while
    // the old cgroup drains must remain eligible for immediate idle reuse.
    // Keep classifier errors inside the same mandatory cleanup boundary.
    let outcome = outcome.and_then(|outcome| {
        // Kill descendants before any finalization work, even if local callers
        // continuously refill the bounded listener backlog. finish() still
        // confirms drainage and reaps before reporting or idle reuse.
        scope.kill()?;
        #[cfg(test)]
        if injected("finalize-signal").is_some() {
            kill(Pid::this(), Signal::SIGTERM).context("fixture finalization signal")?;
        }
        if matches!(outcome, Outcome::Completed(_) | Outcome::Disconnected) {
            Ok(busy.finish_backlog(listener, signals)?.unwrap_or(outcome))
        } else { Ok(outcome) }
    });
    let outcome = match outcome {
        Ok(o) => o,
        Err(e) => {
            let mut o = ExecOutcome::failure(FailureKind::Io, Stage::Wait, Cleanup::Unconfirmed,
                error_errno(&e), &format!("{e:#}"));
            o.status = status;
            Outcome::Completed(o)
        }
    };
    finish(scope, outcome)
}

fn error_errno(e: &anyhow::Error) -> i32 {
    e.chain().find_map(|e| e.downcast_ref::<std::io::Error>().and_then(|e| e.raw_os_error())
        .or_else(|| e.downcast_ref::<Errno>().map(|e| *e as i32))).unwrap_or(0)
}

fn launch_failure(stage: Stage, cleanup: Cleanup, errno: i32, message: &str) -> Outcome {
    Outcome::Completed(ExecOutcome::failure(FailureKind::LaunchFailed, stage, cleanup, errno, message))
}

/// Fixed 8-byte records: stage u16, two zero bytes, errno i32, all LE.
/// A zero record means Joined; errors remain reportable after release until
/// CLOEXEC closes the writer. This channel contains trusted bootstrap code only.
struct BootstrapReader {
    bytes: [u8; 8], at: usize, joined: bool, eof: bool, failure: Option<(Stage, i32)>,
}

impl BootstrapReader {
    fn new() -> Self { Self { bytes: [0; 8], at: 0, joined: false, eof: false, failure: None } }
    fn advance(&mut self, fd: &OwnedFd) -> Result<()> {
        while !self.eof && self.failure.is_none() {
            match read(fd, &mut self.bytes[self.at..]) {
                Ok(0) => {
                    anyhow::ensure!(self.at == 0, "truncated bootstrap record");
                    self.eof = true;
                    if !self.joined { self.failure = Some((Stage::Admission, 0)); }
                }
                Ok(n) => {
                    self.at += n;
                    if self.at == 8 {
                        let stage = Stage::try_from(u16::from_le_bytes(self.bytes[..2].try_into().unwrap()))?;
                        let errno = i32::from_le_bytes(self.bytes[4..].try_into().unwrap());
                        anyhow::ensure!(self.bytes[2..4] == [0; 2] && errno >= 0, "invalid bootstrap record");
                        if stage == Stage::None {
                            anyhow::ensure!(!self.joined && errno == 0, "duplicate bootstrap admission");
                            self.joined = true;
                        } else { self.failure = Some((stage, errno)); }
                        self.at = 0;
                    }
                }
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => break,
                Err(e) => return Err(e).context("read bootstrap status"),
            }
        }
        Ok(())
    }
}

fn bootstrap_record(fd: &OwnedFd, stage: Stage, errno: i32) -> bool {
    let mut bytes = [0u8; 8];
    bytes[..2].copy_from_slice(&(stage as u16).to_le_bytes());
    bytes[4..].copy_from_slice(&errno.max(0).to_le_bytes());
    loop {
        match write(fd, &bytes) { Ok(8) => return true, Err(Errno::EINTR) => continue, _ => return false }
    }
}

fn bootstrap_fail(fd: &OwnedFd, stage: Stage, errno: i32) -> ! {
    bootstrap_record(fd, stage, errno);
    unsafe { libc::_exit(if stage == Stage::Exec { 127 } else { 126 }) }
}

unsafe extern "C" {
    /// The C library's process environment, read by execvp(3).
    static mut environ: *mut *mut libc::c_char;
}

/// The forked child: joins the exec cgroup, waits for PID 1 to release it,
/// then becomes the command. Every instruction of the command, and of all it
/// starts, runs inside the cgroup.
fn launch(argv: &[CString], options: Option<&LaunchOptions>, stdio: &[OwnedFd], scope: &ExecCgroup,
    joined: &OwnedFd, release: &OwnedFd) -> ! {
    #[cfg(test)]
    if let Some(errno) = injected("admission") { bootstrap_fail(joined, Stage::Admission, errno); }
    if let Err(e) = scope.join_self() { bootstrap_fail(joined, Stage::Admission, error_errno(&e)); }
    if !bootstrap_record(joined, Stage::None, 0) { unsafe { libc::_exit(126) } }
    let mut byte = [0u8; 1];
    loop {
        match read(release, &mut byte) {
            Ok(1) if byte[0] == b'1' => break,
            Err(Errno::EINTR) => continue,
            Err(e) => bootstrap_fail(joined, Stage::Admission, e as i32),
            _ => bootstrap_fail(joined, Stage::Admission, 0),
        }
    }
    // The command must not be able to move or kill processes in cgroups.
    scope.close_in_child();
    #[cfg(test)]
    if let Some(errno) = injected("stdio") { bootstrap_fail(joined, Stage::Stdio, errno); }
    for (target, source) in stdio.iter().enumerate() {
        if unsafe { libc::dup2(source.as_raw_fd(), target as i32) } < 0 {
            bootstrap_fail(joined, Stage::Stdio, Errno::last() as i32);
        }
    }
    // Its own process group only so forwarded signals have a clear target;
    // containment doesn't depend on it.
    if let Err(e) = setpgid(Pid::from_raw(0), Pid::from_raw(0)) {
        bootstrap_fail(joined, Stage::Stdio, e as i32);
    }
    if let Err(e) = crate::container::close_fds_except(&[joined.as_raw_fd()]) {
        bootstrap_fail(joined, Stage::Stdio, error_errno(&e));
    }
    if let Err(e) = SigSet::empty().thread_set_mask() { bootstrap_fail(joined, Stage::Stdio, e as i32); }
    if unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) } == libc::SIG_ERR {
        bootstrap_fail(joined, Stage::Stdio, Errno::last() as i32);
    }
    // Operation 5 only, and in this order: every descriptor except stdio and
    // the bootstrap channel is already closed, so no inherited directory can
    // become the cwd through /proc/self/fd/N. No fallback to /.
    if let Some(options) = options {
        if let Some(cwd) = &options.cwd
            && unsafe { libc::chdir(cwd.as_ptr()) } != 0 {
            bootstrap_fail(joined, Stage::Chdir, Errno::last() as i32);
        }
        // execvp searches the PATH of, and passes, the process environment:
        // make that exactly the effective envp. Only this child changes.
        // SAFETY: the pointers stay valid until exec; nothing else runs here.
        unsafe { *std::ptr::addr_of_mut!(environ) = options.environ().cast_mut().cast(); }
    }
    #[cfg(test)]
    if let Some(errno) = injected("exec") { bootstrap_fail(joined, Stage::Exec, errno); }
    let err = execvp(&argv[0], argv).unwrap_err();
    bootstrap_fail(joined, Stage::Exec, err as i32);
}

// Test binaries only: a consumed fixture file injects one request-local fault.
// No environment variable, path, or injection hook exists in shipped binaries.
#[cfg(test)]
fn injected(point: &str) -> Option<i32> {
    let root = std::env::var_os("KILN_PROTOCOL_FIXTURE")?;
    let path = std::path::PathBuf::from(root).join("inject");
    let text = std::fs::read_to_string(&path).ok()?;
    let (name, errno) = text.split_once(' ')?;
    if name != point { return None; }
    std::fs::remove_file(path).ok()?;
    errno.parse().ok()
}

#[cfg(test)]
fn fixture_response_backpressure(stream: &UnixStream, outcome: &ExecOutcome) -> Result<()> {
    anyhow::ensure!(outcome.cleanup == Cleanup::Drained, "response preceded exec cleanup");
    let size: libc::c_int = 4096;
    let fd = stream.as_raw_fd();
    // SAFETY: size is an initialized socket option of the specified length.
    if unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_SNDBUF,
        (&size as *const libc::c_int).cast(), std::mem::size_of_val(&size) as libc::socklen_t) } < 0 {
        return Err(std::io::Error::last_os_error()).context("fixture send buffer");
    }
    // Fill even the space for a minimum-sized response. The peer never reads,
    // so reaching EAGAIN guarantees the following writer must wait for space.
    let filler = [b'x'; 40];
    loop {
        let n = unsafe { libc::send(fd, filler.as_ptr().cast(), filler.len(),
            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
        if n >= 0 { anyhow::ensure!(n > 0, "fixture send made no progress"); continue; }
        match Errno::last() {
            Errno::EINTR => continue,
            Errno::EAGAIN => break,
            e => return Err(e).context("fixture saturate response"),
        }
    }
    let root = std::path::PathBuf::from(
        std::env::var_os("KILN_PROTOCOL_FIXTURE").context("missing protocol fixture")?);
    // report() is reached only after run_exec() has finished drainage/reaping.
    std::fs::write(root.join("response-started.pending"), b"drained\n")?;
    std::fs::rename(root.join("response-started.pending"), root.join("response-started"))?;
    Ok(())
}

/// The one way an exec ends, whether its command exited, its client left, it
/// couldn't start or `kiln rm` interrupted it: kill everything left in the
/// exec cgroup, wait until it's empty, and reap every last process. An error
/// here ends PID 1, and with it the sandbox, rather than run the next exec
/// beside leftovers.
fn finish(scope: &ExecCgroup, mut outcome: Outcome) -> Result<Outcome> {
    let cleanup = scope.kill_and_wait_empty().and_then(|()| reap_all_blocking());
    match cleanup {
        Ok(()) => {
            if let Outcome::Completed(o) = &mut outcome { o.cleanup = Cleanup::Drained; }
            Ok(outcome)
        }
        Err(e) => {
            let mut o = ExecOutcome::failure(FailureKind::CleanupFailed, Stage::Cleanup,
                Cleanup::Unconfirmed, error_errno(&e), &format!("{e:#}"));
            if let Outcome::Completed(old) = outcome { o.status = old.status; }
            Ok(Outcome::Fatal(o))
        }
    }
}

/// Waits for and reaps every remaining child, direct or adopted, until none
/// are left. The exec cgroup reads empty as soon as its processes pass
/// cgroup_exit(), slightly before they become zombies, and a zombie still
/// holds its slot in `pids.max` until it's reaped. Only after this may the
/// next exec fork. Every child of a persistent PID 1 was in the now-empty exec
/// cgroup, so each is already dying and this can't block on a live process.
fn reap_all_blocking() -> Result<()> {
    loop {
        match wait_raw(-1, 0) {
            Ok(_) => continue,
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
        // POLLHUP is reported even when not requested and means the peer's
        // read side is gone. Do not request POLLRDHUP: a peer may legitimately
        // shutdown(SHUT_WR) after its complete length-framed request while it
        // keeps reading the response.
        libc::pollfd { fd: client.as_raw_fd(), events: 0, revents: 0 },
        libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
    ]
}

fn poll(fds: &mut [libc::pollfd], timeout: i32) -> Result<usize> {
    loop {
        // SAFETY: `fds` points to initialized pollfds for the supplied length.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if ready >= 0 {
            return Ok(ready as usize);
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

fn socket_poll_error(revents: i16, source: &str) -> Result<()> {
    let errors = libc::POLLERR | libc::POLLNVAL;
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
/// Headers are only read here, never waited for, so a slow connection can't
/// keep the exec loop from its client, its signals or the listener.
fn interrupted(wait: &[libc::pollfd; 3], ready: &[libc::pollfd], busy: &mut BusyHeaders,
    listener: &UnixListener, signals: &SignalFd) -> Result<Option<Outcome>> {
    poll_error(wait[0].revents, "signalfd")?;
    poll_error(wait[2].revents, "control listener")?;
    let mut completed = busy.advance(ready, wait[2].revents & libc::POLLIN != 0, listener)?;
    if let Some(outcome) = answer_busy_headers(&mut completed, signals)? { return Ok(Some(outcome)); }
    // Ready headers, including removal, win over a simultaneous disconnect.
    let disconnected = libc::POLLERR | libc::POLLHUP | libc::POLLNVAL;
    Ok((wait[1].revents & disconnected != 0).then_some(Outcome::Disconnected))
}

fn answer_busy_headers(completed: &mut Vec<(UnixStream, Header)>, signals: &SignalFd) -> Result<Option<Outcome>> {
    // Removal wins this pass before anything else is answered.
    let remover = completed.iter().position(|(_, header)| is_remove(header))
        .map(|at| completed.swap_remove(at).0);
    for (stream, header) in completed.drain(..) {
        answer_busy_header(&stream, header, signals)?;
    }
    Ok(remover.map(Outcome::Removed))
}

/// One connection whose fixed header hasn't fully arrived while an exec runs.
struct BusyHeader {
    stream: UnixStream,
    reader: HeaderReader,
    deadline: Instant,
}

/// Connections accepted during an exec, oldest first. Their deadlines are
/// therefore in order too, and the first one is the next to expire.
struct BusyHeaders {
    pending: Vec<BusyHeader>,
}

impl BusyHeaders {
    fn new() -> Self { Self { pending: Vec::new() } }

    /// Keep connections already queued at exec completion classified as busy,
    /// even beyond one accept burst. Bound total work as well as each batch;
    /// leave shutdown signals queued for idle so a completed command retains
    /// its real outcome. New connections during cleanup are left for idle.
    fn finish_backlog(&mut self, listener: &UnixListener, signals: &SignalFd) -> Result<Option<Outcome>> {
        for _ in 0..MAX_BUSY_FINALIZE_BATCHES {
            let ready = [libc::pollfd { fd: -1, events: 0, revents: libc::POLLIN }; MAX_BUSY_PENDING];
            let mut completed = self.advance(&ready, true, listener)?;
            // Incomplete requests cannot become an exec in the next idle turn.
            self.pending.clear();
            if let Some(outcome) = answer_busy_headers(&mut completed, signals)? { return Ok(Some(outcome)); }
            let mut wait = [libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 }];
            poll(&mut wait, 0)?;
            poll_error(wait[0].revents, "control listener")?;
            if wait[0].revents & libc::POLLIN == 0 { return Ok(None); }
        }
        Ok(None)
    }

    fn watch(&self, slots: &mut [libc::pollfd]) {
        for (slot, entry) in slots.iter_mut().zip(&self.pending) {
            *slot = libc::pollfd { fd: entry.stream.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        }
    }

    /// How long poll() may sleep before the oldest header expires.
    fn timeout(&self) -> i32 {
        self.pending.first().map_or(-1, |oldest| {
            poll_millis(oldest.deadline.saturating_duration_since(Instant::now()))
        })
    }

    /// Reads the streams `ready` reports, expires the overdue ones and then
    /// accepts a bounded number of new ones. Returns the requests whose headers
    /// are now complete; no request body is read or allocated.
    fn advance(&mut self, ready: &[libc::pollfd], listening: bool,
        listener: &UnixListener) -> Result<Vec<(UnixStream, Header)>> {
        let now = Instant::now();
        let mut completed = Vec::new();
        for (entry, slot) in std::mem::take(&mut self.pending).into_iter().zip(ready) {
            if slot.revents == 0 && now < entry.deadline {
                self.pending.push(entry);
            } else {
                self.read(entry, &mut completed);
            }
        }
        if !listening { return Ok(completed); }
        for _ in 0..MAX_BUSY_ACCEPTS {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e).context("accept exec request"),
            };
            if let Err(e) = stream.set_nonblocking(true) {
                eprintln!("kiln: set busy request nonblocking: {e}");
                continue;
            }
            // Read before storing: a complete request never needs a slot, so a
            // full table can't turn away a removal already in the queue.
            self.read(BusyHeader {
                stream,
                reader: HeaderReader::new(),
                deadline: Instant::now() + REQUEST_READ_TIMEOUT,
            }, &mut completed);
        }
        Ok(completed)
    }

    /// Advances one header once. An error drops the stream and whatever
    /// descriptors its reader holds; it belongs to that request alone.
    fn read(&mut self, mut entry: BusyHeader, completed: &mut Vec<(UnixStream, Header)>) {
        let read = read_frame_before_deadline(
            entry.deadline,
            || entry.reader.read(&entry.stream),
            || Ok(None),
            Instant::now,
        );
        match read {
            Ok((ReadState::Complete(header), _)) => completed.push((entry.stream, header)),
            Ok((ReadState::Pending, _)) => {
                // Older streams give way, so a flood of partial headers can't
                // keep the listener's later connections from being read.
                if self.pending.len() == MAX_BUSY_PENDING {
                    self.pending.remove(0);
                    eprintln!("kiln: dropped the oldest incomplete request during exec");
                }
                self.pending.push(entry);
            }
            Err(e) => eprintln!("kiln: bad request during exec: {e:#}"),
        }
    }
}

fn is_remove(header: &Header) -> bool {
    header.op == 2 && header.len == 0 && header.fds.is_empty()
}

/// Answers a complete header that arrived while an exec runs. Execs run one at
/// a time, so another exec request fails with EXEC_FAILED instead of queueing.
fn answer_busy_header(stream: &UnixStream, header: Header, signals: &SignalFd) -> Result<()> {
    match header.op {
        2 if is_remove(&header) => eprintln!("kiln: dropped a second removal during exec"),
        3 if header.len == 0 && header.fds.is_empty() => {
            respond(stream, &Frame::Capabilities(Capabilities::current()).encode()?, signals, false);
        }
        1 | 4 | 5 if header.fds.len() == 3 && header.len as usize <= max_body(header.op) => {
            let typed = header.op != 1;
            // A competing exec can be classified from its fixed header. Close
            // its descriptors before replying; never read or allocate its body.
            drop(header);
            eprintln!("kiln: refused an exec request while another exec runs");
            let bytes = if typed {
                Frame::Outcome(ExecOutcome::failure(FailureKind::Busy, Stage::Validate,
                    Cleanup::NoChildStarted, 0, "another exec is active")).encode()?
            } else { EXEC_FAILED.to_ne_bytes().to_vec() };
            respond(stream, &bytes, signals, false);
        }
        _ => eprintln!("kiln: invalid request header during exec"),
    }
    Ok(())
}

/// Reaps every child that has exited, including orphans that were reparented
/// to us. Several exits can collapse into one SIGCHLD, so loop until none are
/// left. Returns the command's exit code once it has exited.
fn reap(command: Option<Pid>) -> Result<Option<CommandStatus>> {
    let mut code = None;
    loop {
        match wait_raw(-1, libc::WNOHANG) {
            Ok(Some((pid, RawWaitStatus::Exited(c)))) if Some(pid) == command => code = Some(CommandStatus::Exited(c)),
            Ok(Some((pid, RawWaitStatus::Signaled { signal, core_dumped }))) if Some(pid) == command => {
                code = Some(CommandStatus::Signaled { signal, core_dumped })
            }
            Ok(None) | Err(Errno::ECHILD) => return Ok(code),
            Ok(_) => continue,
            Err(e) => return Err(e).context("waitpid"),
        }
    }
}

enum RawWaitStatus {
    Exited(i32),
    Signaled { signal: i32, core_dumped: bool },
    Other,
}

/// Decode without nix's Signal enum, which excludes Linux real-time signals.
/// Keep ECHILD separate from WNOHANG's no-status result for caller ownership.
fn wait_raw(pid: libc::pid_t, options: libc::c_int) -> nix::Result<Option<(Pid, RawWaitStatus)>> {
    loop {
        let mut status = 0;
        // SAFETY: status points to a valid wait-status output slot.
        let child = unsafe { libc::waitpid(pid, &mut status, options) };
        if child < 0 {
            let e = Errno::last();
            if e == Errno::EINTR { continue; }
            return Err(e);
        }
        if child == 0 { return Ok(None); }
        let status = if libc::WIFEXITED(status) {
            RawWaitStatus::Exited(libc::WEXITSTATUS(status))
        } else if libc::WIFSIGNALED(status) {
            RawWaitStatus::Signaled { signal: libc::WTERMSIG(status), core_dumped: libc::WCOREDUMP(status) }
        } else { RawWaitStatus::Other };
        return Ok(Some((Pid::from_raw(child), status)));
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::io::{Read, Write};
    use std::os::fd::RawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    use super::*;
    use crate::exec_options;

    /// This is a protocol/bootstrap fixture, not a cgroup containment test.
    /// A separate process keeps signal masks, fork, and close_range away from
    /// the parallel Rust test runner. Real cgroups remain in the root suite.
    #[test]
    fn protocol_server_fixture() {
        let Some(path) = std::env::var_os("KILN_PROTOCOL_FIXTURE") else { return; };
        let root = std::path::PathBuf::from(path);
        // Model PID 1 adoption without requiring a privileged PID namespace.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) }, 0);
        // A directory descriptor PID 1 holds across fork: only descriptor
        // closure keeps /proc/self/fd/N from naming it as a cwd.
        let held = fs::File::open(&root).unwrap();
        fs::write(root.join("held-dir-fd"), held.as_raw_fd().to_string()).unwrap();
        let listener = UnixListener::bind(root.join("control.sock")).unwrap();
        let scope = ExecCgroup::protocol_fixture(&root);
        let result = serve(&listener, &scope);
        if root.join("expect-fatal").exists() { assert!(result.is_err()); }
        else { result.unwrap(); }
    }

    struct Server { child: Child, root: std::path::PathBuf }
    impl Server {
        fn start() -> Self {
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!("kiln-protocol-{}-{id}", std::process::id()));
            fs::create_dir(&root).unwrap();
            for (file, text) in [("procs", ""), ("kill", ""), ("events", "populated 0\n")] {
                fs::write(root.join(file), text).unwrap();
            }
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.args(["--exact", "init::tests::protocol_server_fixture", "--test-threads=1"])
                .env("KILN_PROTOCOL_FIXTURE", &root).stdout(Stdio::null()).stderr(Stdio::inherit());
            unsafe { command.pre_exec(|| {
                let mut mask: libc::sigset_t = std::mem::zeroed();
                libc::sigfillset(&mut mask);
                if libc::sigprocmask(libc::SIG_SETMASK, &mask, std::ptr::null_mut()) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            }); }
            let child = command.spawn().unwrap();
            let server = Self { child, root };
            server.wait_for("control.sock");
            server
        }
        fn wait_for(&self, name: &str) {
            let start = Instant::now();
            while !self.root.join(name).exists() {
                assert!(start.elapsed() < Duration::from_secs(5), "fixture never reached {name}");
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        fn connect(&self) -> UnixStream { UnixStream::connect(self.root.join("control.sock")).unwrap() }
        fn exec(&self, args: &[&str]) -> (ExecOutcome, Vec<u8>, Vec<u8>) {
            let (mut stream, out, err) = self.start_exec(args);
            let frame = protocol::read_reply(&mut stream, Some(Instant::now() + Duration::from_secs(5))).unwrap();
            let Frame::Outcome(o) = frame else { panic!("not an outcome") };
            let mut stdout = Vec::new(); let mut stderr = Vec::new();
            fs::File::from(out).read_to_end(&mut stdout).unwrap();
            fs::File::from(err).read_to_end(&mut stderr).unwrap();
            (o, stdout, stderr)
        }
        fn exec_options(&self, args: &[&str], options: &ExecOptions) -> (ExecOutcome, Vec<u8>, Vec<u8>) {
            let (mut stream, out, err) = self.start_exec_with(args, Some(options));
            let frame = protocol::read_reply(&mut stream, Some(Instant::now() + Duration::from_secs(5))).unwrap();
            let Frame::Outcome(o) = frame else { panic!("not an outcome") };
            let mut stdout = Vec::new(); let mut stderr = Vec::new();
            fs::File::from(out).read_to_end(&mut stdout).unwrap();
            fs::File::from(err).read_to_end(&mut stderr).unwrap();
            (o, stdout, stderr)
        }
        fn start_exec(&self, args: &[&str]) -> (UnixStream, OwnedFd, OwnedFd) { self.start_exec_with(args, None) }
        fn start_exec_with(&self, args: &[&str], options: Option<&ExecOptions>) -> (UnixStream, OwnedFd, OwnedFd) {
            let mut body = (args.len() as u32).to_le_bytes().to_vec();
            for arg in args { body.extend_from_slice(&(arg.len() as u32).to_le_bytes()); body.extend_from_slice(arg.as_bytes()); }
            let op = match options { Some(options) => { body.extend_from_slice(&options.encode()); 5 } None => 4 };
            let (stream, out, err) = self.start_exec_header(op, body.len() as u32);
            if let Err(e) = (&stream).write_all(&body) {
                assert!(matches!(e.kind(), std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset), "{e}");
            }
            (stream, out, err)
        }
        fn start_exec_header(&self, op: u8, len: u32) -> (UnixStream, OwnedFd, OwnedFd) {
            self.start_exec_prefix(op, len, 8)
        }
        /// Sends the descriptors with the first `sent` bytes of an exec header.
        fn start_exec_prefix(&self, op: u8, len: u32, sent: usize) -> (UnixStream, OwnedFd, OwnedFd) {
            let stream = self.connect();
            let input = fs::File::open("/dev/null").unwrap();
            let (out_rx, out_tx) = pipe2(OFlag::O_CLOEXEC).unwrap();
            let (err_rx, err_tx) = pipe2(OFlag::O_CLOEXEC).unwrap();
            let mut header = vec![op, 0, 0, 0];
            header.extend_from_slice(&if op == 1 { len.to_ne_bytes() } else { len.to_le_bytes() });
            let fds: [RawFd; 3] = [input.as_raw_fd(), out_tx.as_raw_fd(), err_tx.as_raw_fd()];
            let mut control = vec![0u8; unsafe { libc::CMSG_SPACE(12) as usize }];
            let mut iov = libc::iovec { iov_base: header.as_mut_ptr().cast(), iov_len: sent };
            unsafe {
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_iov = &mut iov; msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast(); msg.msg_controllen = control.len();
                let c = libc::CMSG_FIRSTHDR(&msg); (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS; (*c).cmsg_len = libc::CMSG_LEN(12) as usize;
                std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(c).cast(), 3);
                assert_eq!(libc::sendmsg(stream.as_raw_fd(), &msg, 0), sent as isize);
            }
            (stream, out_rx, err_rx)
        }
        /// Starts a sleeping exec and returns once it runs, with its host PID.
        fn start_sleeper(&self) -> (UnixStream, OwnedFd, OwnedFd, i32) {
            let marker = self.root.join("sleeper-pid");
            let command = format!("echo $$ > {0}.pending; mv {0}.pending {0}; exec /bin/sleep 30", marker.display());
            let (active, out, err) = self.start_exec(&["/bin/sh", "-c", &command]);
            self.wait_for("sleeper-pid");
            let pid = fs::read_to_string(marker).unwrap().trim().parse().unwrap();
            (active, out, err, pid)
        }
        /// A capabilities round trip. The listener is first-in first-out, so an
        /// answer also proves every earlier connection has been accepted.
        fn probe(&self) {
            let mut probe = self.connect();
            probe.write_all(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            assert!(matches!(protocol::read_reply(&mut probe, Some(Instant::now() + BUSY_PROMPT)).unwrap(),
                Frame::Capabilities(_)));
        }
        fn partial_header(&self) -> UnixStream {
            let partial = self.connect();
            (&partial).write_all(&[4]).unwrap();
            partial
        }
    }
    impl Drop for Server {
        fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); let _ = fs::remove_dir_all(&self.root); }
    }

    /// Below the two seconds one stalled header used to cost; normally a few ms.
    const BUSY_PROMPT: Duration = Duration::from_millis(1500);

    /// The descriptors' other end has closed: the read side reports EOF.
    fn assert_closed(fd: OwnedFd, within: Duration, what: &str) {
        let mut pollfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, within.as_millis() as i32) }, 1, "{what}");
        assert_eq!(fs::File::from(fd).read(&mut [0u8; 1]).unwrap(), 0, "{what}");
    }

    /// PID 1 closed this stream. A byte it never read turns EOF into a reset.
    fn assert_eof(mut stream: &UnixStream, within: Duration, what: &str) {
        stream.set_read_timeout(Some(within)).unwrap();
        match stream.read(&mut [0u8; 1]) {
            Ok(0) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
            other => panic!("{what}: {other:?}"),
        }
    }

    #[test]
    fn typed_exec_bootstrap_signals_busy_and_recovery() {
        let server = Server::start();
        let (o, out, err) = server.exec(&["/bin/sh", "-c", "printf 'a\\000\\377'; printf 'b\\000\\376' >&2; exit 125"]);
        assert_eq!(o, ExecOutcome::command(CommandStatus::Exited(125)));
        assert_eq!(out, b"a\0\xff"); assert_eq!(err, b"b\0\xfe");
        assert_eq!(server.exec(&["/bin/sh", "-c", "for f in /proc/self/fd/*; do [ -e \"$f\" ] || continue; [ \"${f##*/}\" -lt 3 ] || exit 91; done"]).0.status,
            Some(CommandStatus::Exited(0)), "bootstrap exposed an inherited descriptor");
        let fake = Frame::Outcome(ExecOutcome::command(CommandStatus::Exited(42))).encode().unwrap();
        let octal = fake.iter().map(|byte| format!("\\{byte:03o}")).collect::<String>();
        let (o, out, err) = server.exec(&["/bin/sh", "-c", &format!("printf '{octal}'; printf '{octal}' >&2; exit 125")]);
        assert_eq!(o.status, Some(CommandStatus::Exited(125)));
        assert_eq!(out, fake); assert_eq!(err, fake);
        for code in [126, 127, 143] {
            assert_eq!(server.exec(&["/bin/sh", "-c", &format!("exit {code}")]).0.status, Some(CommandStatus::Exited(code)));
        }
        let o = server.exec(&["/bin/sh", "-c", "kill -TERM $$"]).0;
        assert_eq!(o.status, Some(CommandStatus::Signaled { signal: 15, core_dumped: false }));
        for signal in [34, 64] {
            assert_eq!(server.exec(&["/bin/sh", "-c", &format!("kill -{signal} $$")]).0,
                ExecOutcome::command(CommandStatus::Signaled { signal, core_dumped: false }));
        }
        let (o, _, err) = server.exec(&["/no/such/executable"]);
        assert_eq!((o.kind, o.stage, o.errno, o.status), (FailureKind::LaunchFailed, Stage::Exec, libc::ENOENT, None));
        assert!(err.is_empty());
        for (point, stage, errno, cleanup) in [
            ("pipe", Stage::Prepare, libc::EMFILE, Cleanup::NoChildStarted),
            ("fork", Stage::Fork, libc::EAGAIN, Cleanup::NoChildStarted),
            ("admission", Stage::Admission, libc::EPERM, Cleanup::Drained),
            ("release", Stage::Admission, libc::EPIPE, Cleanup::Drained),
            ("stdio", Stage::Stdio, libc::EBADF, Cleanup::Drained),
            ("exec", Stage::Exec, libc::ENOENT, Cleanup::Drained),
        ] {
            fs::write(server.root.join("inject"), format!("{point} {errno}")).unwrap();
            let (o, out, err) = server.exec(&["/bin/true"]);
            assert_eq!((o.kind, o.stage, o.errno, o.cleanup, o.status),
                (FailureKind::LaunchFailed, stage, errno, cleanup, None), "{point}");
            assert!(out.is_empty() && err.is_empty(), "bootstrap leaked output at {point}");
            assert_eq!(server.exec(&["/bin/true"]).0.status, Some(CommandStatus::Exited(0)));
        }
        let (active, out, err) = server.start_exec(&["/bin/sleep", "10"]);
        // A complete probe is accepted even with the active exec's output held.
        let mut probe = server.connect();
        probe.write_all(&[3, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert!(matches!(protocol::read_reply(&mut probe, Some(Instant::now() + Duration::from_secs(5))).unwrap(), Frame::Capabilities(_)));
        let busy = server.exec(&["/bin/true"]).0;
        assert_eq!((busy.kind, busy.cleanup), (FailureKind::Busy, Cleanup::NoChildStarted));
        let large = "x".repeat(700_000);
        assert_eq!(server.exec(&["/bin/true", &large]).0.kind, FailureKind::Busy);
        drop((active, out, err));
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(server.exec(&["/bin/true"]).0.status, Some(CommandStatus::Exited(0)));
        // Complete request followed by a peer close must remain request-local.
        for _ in 0..5 { drop(server.start_exec(&["/bin/true"])); }
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(server.exec(&["/bin/true"]).0.status, Some(CommandStatus::Exited(0)));
        fs::write(server.root.join("expect-fatal"), "").unwrap();
        fs::write(server.root.join("events"), "malformed cleanup observation\n").unwrap();
        let (o, out, err) = server.exec(&["/bin/sh", "-c", "printf retained; exit 125"]);
        assert_eq!((o.kind, o.stage, o.cleanup, o.status), (FailureKind::CleanupFailed,
            Stage::Cleanup, Cleanup::Unconfirmed, Some(CommandStatus::Exited(125))));
        assert_eq!(out, b"retained"); assert!(err.is_empty());
    }

    fn options(cwd: Option<&str>, env: &[(&str, &str)]) -> ExecOptions {
        ExecOptions::new(cwd.map(Into::into), env.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()).unwrap()
    }

    #[test]
    fn exec_options_set_cwd_and_exact_environment_for_the_command_only() {
        let server = Server::start();
        let root = server.root.to_str().unwrap().to_owned();
        let show_env = ["/bin/cat", "/proc/self/environ"];
        let (o, out, err) = server.exec_options(&show_env, &options(None, &[]));
        assert_eq!((o, err), (ExecOutcome::command(CommandStatus::Exited(0)), Vec::new()));
        assert_eq!(out, b"HOME=/root\0PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0TERM=xterm\0",
            "operation 5 starts from the fixed base, not PID 1's environment");
        let overrides = options(None, &[("TERM", "dumb"), ("A0", "x"), ("A", ""), ("_", "雪 =$x"), ("a", "l")]);
        let (o, out, _) = server.exec_options(&show_env, &overrides);
        assert_eq!(o.status, Some(CommandStatus::Exited(0)));
        assert_eq!(out, "A=\0A0=x\0HOME=/root\0PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\0TERM=dumb\0_=雪 =$x\0a=l\0".as_bytes());

        // PATH is an override like any other, for lookup as well as for the
        // command's environment; relative names resolve in the new cwd.
        fs::create_dir(server.root.join("bin")).unwrap();
        let tool = server.root.join("bin/kiln-options-tool");
        fs::write(&tool, "#!/bin/sh\nprintf '%s|%s' \"$PWD\" \"$PATH\"\n").unwrap();
        fs::set_permissions(&tool, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let bin = format!("{root}/bin");
        let (o, out, _) = server.exec_options(&["kiln-options-tool"], &options(Some(&root), &[("PATH", &bin)]));
        assert_eq!(o.status, Some(CommandStatus::Exited(0)));
        assert_eq!(out, format!("{root}|{bin}").as_bytes());
        let (o, out, _) = server.exec_options(&["./kiln-options-tool"], &options(Some(&bin), &[]));
        assert_eq!((o.status, out), (Some(CommandStatus::Exited(0)), format!("{bin}|{}",
            exec_options::BASE_ENV[1].1).into_bytes()));
        let (o, _, _) = server.exec_options(&["kiln-options-tool"], &options(None, &[]));
        assert_eq!((o.kind, o.stage, o.errno), (FailureKind::LaunchFailed, Stage::Exec, libc::ENOENT));
        // `..` resolves inside the command's own root; no normalization.
        let (o, out, _) = server.exec_options(&["/bin/pwd", "-P"], &options(Some(&format!("{bin}/..")), &[]));
        assert_eq!((o.status, out), (Some(CommandStatus::Exited(0)), format!("{root}\n").into_bytes()));

        // PID 1 never took the cwd or the overrides.
        let (_, out, _) = server.exec(&["/bin/pwd"]);
        assert_eq!(out, format!("{}\n", std::env::current_dir().unwrap().display()).as_bytes());
        let (_, out, _) = server.exec(&["/bin/cat", "/proc/self/environ"]);
        assert!(!out.windows(5).any(|w| w == b"A0=x\0") && out.windows(16).any(|w| w == b"KILN_PROTOCOL_FI"));
    }

    #[test]
    fn chdir_failure_is_launch_failed_chdir_with_errno_after_drainage() {
        let server = Server::start();
        let root = server.root.to_str().unwrap().to_owned();
        fs::write(server.root.join("file"), "").unwrap();
        std::os::unix::fs::symlink(server.root.join("loop"), server.root.join("loop")).unwrap();
        // Restore access on every exit so the fixture's directory can be removed.
        struct Locked(std::path::PathBuf);
        impl Drop for Locked {
            fn drop(&mut self) { let _ = fs::set_permissions(&self.0, std::os::unix::fs::PermissionsExt::from_mode(0o700)); }
        }
        fs::create_dir(server.root.join("locked")).unwrap();
        let _locked = Locked(server.root.join("locked"));
        fs::set_permissions(server.root.join("locked"), std::os::unix::fs::PermissionsExt::from_mode(0o000)).unwrap();
        let longest = format!("/{}", "a".repeat(exec_options::MAX_CWD - 1));
        let mut cases = vec![
            (format!("{root}/missing"), libc::ENOENT),
            (format!("{root}/file"), libc::ENOTDIR),
            (format!("{root}/file/below"), libc::ENOTDIR),
            (format!("{root}/loop"), libc::ELOOP),
            (longest, libc::ENAMETOOLONG),
        ];
        // Root bypasses directory permissions; the real sandbox suite covers
        // EACCES there through /proc/1/cwd.
        if unsafe { libc::geteuid() } != 0 { cases.push((format!("{root}/locked"), libc::EACCES)); }
        for (cwd, errno) in cases {
            fs::write(server.root.join("kill"), "").unwrap();
            let (o, out, err) = server.exec_options(&["/bin/sh", "-c", "echo ran; echo ran >&2"], &options(Some(&cwd), &[]));
            assert_eq!((o.kind, o.stage, o.errno, o.cleanup, o.status),
                (FailureKind::LaunchFailed, Stage::Chdir, errno, Cleanup::Drained, None), "{}", &cwd[..cwd.len().min(80)]);
            assert_eq!(o.projection(), 126);
            assert!(out.is_empty() && err.is_empty(), "command ran or bootstrap leaked output");
            assert_eq!(fs::read(server.root.join("kill")).unwrap(), b"1", "exec cgroup was not drained");
            assert_eq!(server.exec(&["/bin/true"]).0, ExecOutcome::command(CommandStatus::Exited(0)));
        }
    }

    #[test]
    fn chdir_runs_after_descriptor_closure() {
        let server = Server::start();
        let held: i32 = fs::read_to_string(server.root.join("held-dir-fd")).unwrap().parse().unwrap();
        let pid = server.child.id();
        let open: Vec<i32> = fs::read_dir(format!("/proc/{pid}/fd")).unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().parse().unwrap()).collect();
        // PID 1 really holds a directory a cwd could name before closure.
        assert!(open.contains(&held) && fs::metadata(format!("/proc/{pid}/fd/{held}")).unwrap().is_dir());
        let highest = open.iter().copied().max().unwrap() + 4;
        for n in 0..=highest {
            let (o, out, _) = server.exec_options(&["/bin/pwd"], &options(Some(&format!("/proc/self/fd/{n}")), &[]));
            assert_eq!((o.kind, o.stage, o.status, out.as_slice()), (FailureKind::LaunchFailed, Stage::Chdir, None, &b""[..]),
                "/proc/self/fd/{n} became a cwd");
            assert!(matches!(o.errno, libc::ENOENT | libc::ENOTDIR), "fd {n}: errno {}", o.errno);
        }
        let (o, out, _) = server.exec_options(&["/bin/pwd"], &options(Some("/proc/1/cwd"), &[]));
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!((o.kind, o.stage, o.errno, out.as_slice()), (FailureKind::LaunchFailed, Stage::Chdir, libc::EACCES, &b""[..]));
        }
    }

    #[test]
    fn busy_exec_headers_close_fds_without_waiting_for_body_or_removal() {
        for op in [1, 4, 5] {
            let server = Server::start();
            let marker = server.root.join("busy-started");
            let command = format!("echo ready > {}; exec /bin/sleep 30", marker.display());
            let (_active, _out, _err) = server.start_exec(&["/bin/sh", "-c", &command]);
            server.wait_for("busy-started");
            let start = Instant::now();
            let (mut busy, out, err) = server.start_exec_header(op, 1024 * 1024);
            busy.write_all(b"x").unwrap();
            // Removal is already queued while the refused body is incomplete.
            let mut remover = server.connect();
            remover.write_all(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap();
            if op != 1 {
                let Frame::Outcome(o) = protocol::read_reply(&mut busy,
                    Some(start + Duration::from_millis(800))).unwrap() else { panic!("missing busy outcome") };
                assert_eq!((o.kind, o.cleanup), (FailureKind::Busy, Cleanup::NoChildStarted));
            } else {
                busy.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
                let mut code = [0u8; 4]; busy.read_exact(&mut code).unwrap();
                assert_eq!(i32::from_ne_bytes(code), EXEC_FAILED);
            }
            for fd in [out, err] {
                let mut pollfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 400) }, 1, "refused descriptors still open");
                assert_eq!(fs::File::from(fd).read(&mut [0u8; 1]).unwrap(), 0);
            }
            remover.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
            let mut status = [0u8; 4]; remover.read_exact(&mut status).unwrap();
            assert_eq!(i32::from_ne_bytes(status), 0);
            assert!(start.elapsed() < Duration::from_millis(800));
        }
    }

    #[test]
    fn queued_removal_preempts_partial_busy_headers() {
        let mut server = Server::start();
        let (mut active, _out, _err, _pid) = server.start_sleeper();
        // More partial headers than the table holds, ahead of the removal.
        let partials: Vec<_> = (0..MAX_BUSY_PENDING + MAX_BUSY_ACCEPTS + 1).map(|_| server.partial_header()).collect();
        let start = Instant::now();
        let mut remover = server.connect();
        remover.write_all(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        remover.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut status = [0u8; 4]; remover.read_exact(&mut status).unwrap();
        assert_eq!(i32::from_ne_bytes(status), 0);
        assert!(start.elapsed() < BUSY_PROMPT, "partial headers delayed removal: {:?}", start.elapsed());
        let Frame::Outcome(o) = protocol::read_reply(&mut active, Some(Instant::now() + BUSY_PROMPT)).unwrap()
            else { panic!("missing removal outcome") };
        assert_eq!((o.kind, o.cleanup), (FailureKind::Stopped, Cleanup::Drained));
        for partial in &partials { assert_eof(partial, BUSY_PROMPT, "partial header outlived removal"); }
        assert!(server.child.wait().unwrap().success(), "removal did not end the fixture");
    }

    #[test]
    fn active_disconnect_preempts_partial_busy_headers() {
        let server = Server::start();
        let (active, out, err, pid) = server.start_sleeper();
        let partials: Vec<_> = (0..4).map(|_| server.partial_header()).collect();
        let (rights, rights_out, rights_err) = server.start_exec_prefix(4, 1024, 1);
        // Every partial header is now in the table, and none of them holds up
        // a later complete request.
        server.probe();
        let start = Instant::now();
        drop(active);
        while kill(Pid::from_raw(pid), None).is_ok() {
            assert!(start.elapsed() < BUSY_PROMPT, "disconnect waited on partial headers");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_closed(rights_out, BUSY_PROMPT, "partial descriptors outlived the exec");
        assert_closed(rights_err, BUSY_PROMPT, "partial descriptors outlived the exec");
        assert_eof(&rights, BUSY_PROMPT, "partial descriptors' stream outlived the exec");
        for partial in &partials { assert_eof(partial, BUSY_PROMPT, "partial header carried into idle"); }
        drop((out, err));
        assert_eq!(server.exec(&["/bin/true"]).0, ExecOutcome::command(CommandStatus::Exited(0)));
    }

    #[test]
    fn shutdown_during_finalization_preserves_completed_side_effects() {
        let mut server = Server::start();
        fs::write(server.root.join("inject"), "finalize-signal 15").unwrap();
        let marker = server.root.join("side-effect");
        let command = format!("echo committed > {}; exit 37", marker.display());
        let (outcome, _, _) = server.exec(&["/bin/sh", "-c", &command]);
        assert_eq!(outcome, ExecOutcome::command(CommandStatus::Exited(37)));
        assert_eq!(fs::read_to_string(marker).unwrap(), "committed\n");
        assert!(server.child.wait().unwrap().success(), "idle shutdown did not end the fixture");
    }

    #[test]
    fn disconnect_drains_backlog_beyond_one_accept_burst() {
        let mut server = Server::start();
        let (active, _out, _err, _pid) = server.start_sleeper();
        let init = Pid::from_raw(server.child.id() as i32);
        kill(init, Signal::SIGSTOP).unwrap();
        let partials: Vec<_> = (0..25).map(|_| server.partial_header()).collect();
        let marker = server.root.join("must-not-execute");
        let command = format!("echo bad > {}", marker.display());
        let (mut competing, _stdout, _stderr) = server.start_exec(&["/bin/sh", "-c", &command]);
        let mut remover = server.connect();
        remover.write_all(&[2, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        drop(active);
        let start = Instant::now();
        kill(init, Signal::SIGCONT).unwrap();
        let Frame::Outcome(o) = protocol::read_reply(&mut competing, Some(start + BUSY_PROMPT)).unwrap()
            else { panic!("missing busy outcome") };
        assert_eq!(o.kind, FailureKind::Busy);
        remover.set_read_timeout(Some(BUSY_PROMPT)).unwrap();
        let mut status = [0u8; 4]; remover.read_exact(&mut status).unwrap();
        assert_eq!(i32::from_ne_bytes(status), 0);
        assert!(start.elapsed() < BUSY_PROMPT);
        assert!(!marker.exists(), "a queued busy exec crossed into idle");
        for partial in &partials { assert_eof(partial, BUSY_PROMPT, "queued partial outlived removal"); }
        assert!(server.child.wait().unwrap().success());
    }

    #[test]
    fn partial_busy_header_descriptors_close_at_its_deadline() {
        let server = Server::start();
        let (active, out, err, _pid) = server.start_sleeper();
        let start = Instant::now();
        let (partial, partial_out, partial_err) = server.start_exec_prefix(4, 1024, 1);
        server.probe();
        let mut held = libc::pollfd { fd: partial_out.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        assert_eq!(unsafe { libc::poll(&mut held, 1, 500) }, 0, "descriptors closed before the deadline");
        // Nothing else wakes the exec loop: only the deadline's own timeout can.
        let limit = REQUEST_READ_TIMEOUT + BUSY_PROMPT;
        assert_closed(partial_out, limit, "expired header kept its descriptors");
        assert_closed(partial_err, limit, "expired header kept its descriptors");
        assert_eof(&partial, limit, "expired header kept its stream");
        let elapsed = start.elapsed();
        assert!(elapsed >= REQUEST_READ_TIMEOUT - Duration::from_millis(100) && elapsed < limit, "{elapsed:?}");
        // The active exec is untouched and still refuses competitors.
        server.probe();
        let busy = server.exec(&["/bin/true"]).0;
        assert_eq!((busy.kind, busy.cleanup), (FailureKind::Busy, Cleanup::NoChildStarted));
        drop((active, out, err));
    }

    #[test]
    fn cleanup_reaps_adopted_realtime_signal_before_reuse() {
        let server = Server::start();
        // The orphan stays alive until finish() writes the fake cgroup.kill.
        // Therefore reap(leader)'s WNOHANG loop cannot consume its status:
        // reap_all_blocking() must observe its real-time signal termination.
        let script = r#"/bin/sh -c 'while [ ! -s "$KILN_PROTOCOL_FIXTURE/kill" ]; do sleep 0.005; done; kill -64 $$' & exit 0"#;
        assert_eq!(server.exec(&["/bin/sh", "-c", script]).0,
            ExecOutcome::command(CommandStatus::Exited(0)));
        assert_eq!(fs::read(server.root.join("kill")).unwrap(), b"1");
        assert_eq!(server.exec(&["/bin/true"]).0, ExecOutcome::command(CommandStatus::Exited(0)));
    }

    #[test]
    fn response_backpressure_services_sigchld_and_recovers() {
        let mut server = Server::start();
        fs::write(server.root.join("inject"), "response-backpressure 0").unwrap();
        let (peer, out, err) = server.start_exec(&["/bin/true"]);
        // Do not read any filler or response bytes: publication can only begin
        // after finish(), and EAGAIN must occur inside the real bounded writer.
        server.wait_for("response-started");
        assert_eq!(fs::read(server.root.join("response-started")).unwrap(), b"drained\n");
        assert_eq!(fs::read(server.root.join("kill")).unwrap(), b"1");
        server.wait_for("response-blocked");
        let mut wait = [libc::pollfd { fd: peer.as_raw_fd(), events: libc::POLLRDHUP, revents: 0 }];
        assert_eq!(poll(&mut wait, 0).unwrap(), 0, "writer stopped before the injected signal");
        let start = Instant::now();
        kill(Pid::from_raw(server.child.id() as i32), Signal::SIGCHLD).unwrap();
        let signal_timeout = protocol::FRAME_TIMEOUT / 2;
        assert!(poll(&mut wait, signal_timeout.as_millis() as i32).unwrap() > 0,
            "backpressured response did not service SIGCHLD before its write deadline");
        assert_ne!(wait[0].revents & (libc::POLLRDHUP | libc::POLLHUP), 0);
        assert!(start.elapsed() < signal_timeout);
        assert!(server.child.try_wait().unwrap().is_none(), "response failure stopped PID 1");
        drop((peer, out, err));
        assert_eq!(server.exec(&["/bin/true"]).0, ExecOutcome::command(CommandStatus::Exited(0)));
    }

    #[test]
    fn completed_frame_is_rejected_when_clock_expires_during_read() {
        let start = Instant::now();
        let deadline = start + REQUEST_READ_TIMEOUT;
        let read_finished = Cell::new(false);

        let err = read_frame_before_deadline(
            deadline,
            || {
                read_finished.set(true);
                Ok(ReadState::Complete(()))
            },
            || {
                assert!(read_finished.get(), "signals must be checked after the read");
                Ok(None)
            },
            || {
                assert!(read_finished.get(), "the clock must be sampled after the read");
                deadline
            },
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains("framing deadline exceeded"), "{err}");
    }
}
