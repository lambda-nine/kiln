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
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixListener;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::signal::{SigSet, Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, execvp, fork};

/// Signals passed on to the command. SIGINT, SIGQUIT and SIGWINCH are left
/// out on purpose: the terminal sends those to the whole foreground process
/// group, so the command already gets them directly. Forwarding would deliver
/// them twice.
pub const FORWARDED: [Signal; 4] =
    [Signal::SIGTERM, Signal::SIGHUP, Signal::SIGUSR1, Signal::SIGUSR2];

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
            let _ = SigSet::empty().thread_set_mask();
            let err = execvp(&argv[0], argv).unwrap_err();
            eprintln!("kiln: exec {}: {err}", argv[0].to_string_lossy());
            // 127 is the shell's "command not found" code.
            std::process::exit(127);
        }
        ForkResult::Parent { child } => loop {
            match all.wait().context("sigwait")? {
                Signal::SIGCHLD => {
                    if let Some(code) = reap(child)? {
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
/// are the only host objects exposed after lockdown.
pub fn serve(listener: &UnixListener) -> Result<i32> {
    loop {
        let (mut stream, _) = listener.accept().context("accept exec request")?;
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
        let code = run_with_stdio(&argv, &fds)?;
        stream.write_all(&code.to_ne_bytes())?;
    }
}

fn run_with_stdio(argv: &[CString], fds: &[std::os::fd::OwnedFd]) -> Result<i32> {
    let all = SigSet::all();
    all.thread_block().context("block signals")?;
    // SAFETY: PID 1 is single-threaded.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            for (target, source) in fds.iter().enumerate() {
                if unsafe { libc::dup2(source.as_raw_fd(), target as i32) } < 0 {
                    std::process::exit(126);
                }
            }
            let _ = SigSet::empty().thread_set_mask();
            let err = execvp(&argv[0], argv).unwrap_err();
            eprintln!("kiln: exec {}: {err}", argv[0].to_string_lossy());
            std::process::exit(127);
        }
        ForkResult::Parent { child } => loop {
            match all.wait().context("sigwait")? {
                Signal::SIGCHLD => if let Some(code) = reap(child)? { return Ok(code); },
                sig if FORWARDED.contains(&sig) => { let _ = kill(child, sig); }
                _ => {}
            }
        },
    }
}

/// Reaps every child that has exited, including orphans that were reparented
/// to us. Several exits can collapse into one SIGCHLD, so loop until none are
/// left. Returns the command's exit code once it has exited.
fn reap(command: Pid) -> Result<Option<i32>> {
    let mut code = None;
    loop {
        match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, c)) if pid == command => code = Some(c),
            Ok(WaitStatus::Signaled(pid, sig, _)) if pid == command => {
                code = Some(128 + sig as i32)
            }
            Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => return Ok(code),
            Ok(_) => continue,
            Err(e) => return Err(e).context("waitpid"),
        }
    }
}
