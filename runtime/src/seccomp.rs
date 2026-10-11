//! A seccomp-bpf filter: a tiny BPF program the kernel runs on every syscall
//! the sandbox makes, deciding to allow it or fail it with an errno.
//!
//! This is a denylist of syscalls that a sandboxed agent has no use for and
//! that have a history of kernel bugs reachable from inside user namespaces.
//! Docker's default profile is an allowlist (~350 syscalls) instead, which is
//! stricter but much longer; a denylist is easier to read and reason about.
//!
//! The filter is inherited by every child and can never be removed.

use anyhow::{Context, Result};
use libc::{
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_RET, BPF_W, SECCOMP_RET_ALLOW,
    SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_SET_MODE_FILTER, sock_filter, sock_fprog,
};
use nix::errno::Errno;

/// The `AUDIT_ARCH_*` value the kernel reports for this build's syscall ABI.
/// Syscall numbers differ per architecture, so a filter must check it first.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;

// Offsets into `struct seccomp_data`: int nr; u32 arch; u64 ip; u64 args[6].
const NR: u32 = 0;
const ARCH: u32 = 4;
const ARG0_LOW: u32 = 16; // low 32 bits of args[0] (little-endian)
const ARG1_LOW: u32 = 24; // low 32 bits of args[1]

/// Terminal ioctls denied with EPERM. TIOCSTI pushes bytes into a terminal's
/// input queue and TIOCLINUX can paste the console selection back as input,
/// so a sandbox holding the user's terminal could type commands into the
/// shell that started it. The kernel reads the request as a 32-bit `unsigned
/// int`, so the low half of args[1] is exactly what it acts on. Same values
/// on aarch64 and x86_64.
const TIOCSTI: u32 = 0x5412;
const TIOCLINUX: u32 = 0x541C;

/// Every CLONE_NEW* flag. Sandbox root holds every capability inside its user
/// namespace, so without this it could create fresh namespaces and reach
/// kernel code (netfilter, mounts) that's normally root-only.
const CLONE_NEW_ANY: u32 = (libc::CLONE_NEWTIME
    | libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET) as u32;

/// Denied outright with EPERM.
const DENIED: &[i64] = &[
    // Kernel modules and replacing the kernel.
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    libc::SYS_reboot,
    // Big, bug-prone kernel subsystems.
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    // The kernel keyring isn't namespaced.
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    // Opening files by handle bypasses path checks ("Shocker" container escape).
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    // Joining namespaces, and the mount API.
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    // Host-wide state: clock, swap, accounting, kernel log, quotas.
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_syslog,
    libc::SYS_quotactl,
    libc::SYS_quotactl_fd,
];

fn stmt(code: u32, k: u32) -> sock_filter {
    sock_filter { code: code as u16, jt: 0, jf: 0, k }
}

/// Conditional jump: `jt`/`jf` are how many instructions to skip.
fn jump(code: u32, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code: code as u16, jt, jf, k }
}

fn errno(e: Errno) -> u32 {
    SECCOMP_RET_ERRNO | (e as u32)
}

fn program() -> Vec<sock_filter> {
    let mut p = vec![
        // Wrong architecture means the numbers below mean something else
        // (e.g. a 32-bit binary): kill rather than guess.
        stmt(BPF_LD | BPF_W | BPF_ABS, ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD | BPF_W | BPF_ABS, NR),
    ];
    #[cfg(target_arch = "x86_64")]
    p.extend([
        // x32 syscalls share the x86_64 arch value but set bit 30.
        jump(BPF_JMP | libc::BPF_JGE | BPF_K, 0x4000_0000, 0, 1),
        stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    ]);

    for &nr in DENIED {
        // if (nr == X) return EPERM; else skip the return.
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 1));
        p.push(stmt(BPF_RET | BPF_K, errno(Errno::EPERM)));
    }

    // ioctl: deny only the terminal-injection requests; every other ioctl
    // falls through to the remaining rules.
    p.extend([
        jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_ioctl as u32, 0, 5),
        stmt(BPF_LD | BPF_W | BPF_ABS, ARG1_LOW),
        jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 1, 0),
        jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCLINUX, 0, 1),
        stmt(BPF_RET | BPF_K, errno(Errno::EPERM)),
        stmt(BPF_LD | BPF_W | BPF_ABS, NR), // reload nr for the next check
    ]);

    // clone3 passes its flags in a struct the filter can't read, so make it
    // look unimplemented; libc then falls back to clone, which we can check.
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_clone3 as u32, 0, 1));
    p.push(stmt(BPF_RET | BPF_K, errno(Errno::ENOSYS)));

    // clone and unshare take their flags in args[0]: deny any CLONE_NEW*.
    for nr in [libc::SYS_clone, libc::SYS_unshare] {
        p.extend([
            jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 4),
            stmt(BPF_LD | BPF_W | BPF_ABS, ARG0_LOW),
            jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NEW_ANY, 0, 1),
            stmt(BPF_RET | BPF_K, errno(Errno::EPERM)),
            stmt(BPF_LD | BPF_W | BPF_ABS, NR), // reload nr for the next check
        ]);
    }

    p.push(stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    p
}

/// Installs the filter on every thread of the calling process (TSYNC: a
/// single-threaded no-op today, but a daemon with a thread pool would
/// otherwise leave the other threads unfiltered). Needs no_new_privs (or
/// CAP_SYS_ADMIN) first, so a filtered process can't exec a setuid binary
/// that would run with the filter but more privilege.
pub fn install() -> Result<()> {
    install_filter(&program())
}

fn install_filter(filter: &[sock_filter]) -> Result<()> {
    let prog = sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut _ };
    // SAFETY: prog points at a valid BPF program that outlives the call; the
    // kernel copies it.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const sock_fprog,
        )
    };
    Errno::result(ret).context("install seccomp filter")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libc::{BPF_JGE, BPF_JSET};

    /// Runs the filter on a `seccomp_data` the way the kernel's classic BPF
    /// interpreter does, for the handful of opcodes `program` emits.
    fn eval(nr: i64, args: [u64; 6]) -> u32 {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(&(nr as i32).to_ne_bytes());
        data.extend_from_slice(&AUDIT_ARCH.to_ne_bytes());
        data.extend_from_slice(&0u64.to_ne_bytes()); // instruction pointer
        for a in args {
            data.extend_from_slice(&a.to_ne_bytes());
        }
        let prog = program();
        let (mut pc, mut acc) = (0usize, 0u32);
        loop {
            let ins = prog[pc];
            pc += 1;
            let code = u32::from(ins.code);
            if code == BPF_LD | BPF_W | BPF_ABS {
                let at = ins.k as usize;
                acc = u32::from_ne_bytes(data[at..at + 4].try_into().unwrap());
            } else if code == BPF_RET | BPF_K {
                return ins.k;
            } else {
                let taken = match code {
                    c if c == BPF_JMP | BPF_JEQ | BPF_K => acc == ins.k,
                    c if c == BPF_JMP | BPF_JGE | BPF_K => acc >= ins.k,
                    c if c == BPF_JMP | BPF_JSET | BPF_K => acc & ins.k != 0,
                    c => panic!("unexpected BPF opcode {c:#x} at {}", pc - 1),
                };
                pc += usize::from(if taken { ins.jt } else { ins.jf });
            }
        }
    }

    fn ioctl(request: u64) -> u32 {
        eval(libc::SYS_ioctl, [1, request, 0, 0, 0, 0])
    }

    #[test]
    fn request_values_match_libc() {
        assert_eq!(u64::from(TIOCSTI), libc::TIOCSTI);
        assert_eq!(u64::from(TIOCLINUX), libc::TIOCLINUX);
    }

    #[test]
    fn denies_terminal_injection_ioctls() {
        let eperm = errno(Errno::EPERM);
        assert_eq!(ioctl(TIOCSTI.into()), eperm);
        assert_eq!(ioctl(TIOCLINUX.into()), eperm);
        // The kernel truncates the request to 32 bits, so high garbage
        // must not slip past the filter.
        assert_eq!(ioctl(0xdead_beef_0000_0000 | u64::from(TIOCSTI)), eperm);
        assert_eq!(ioctl(0xffff_ffff_0000_0000 | u64::from(TIOCLINUX)), eperm);
    }

    #[test]
    fn allows_other_ioctls() {
        for request in [
            libc::TCGETS,
            libc::TCSETS,
            libc::TIOCGWINSZ,
            libc::TIOCSWINSZ,
            libc::FIONREAD,
            libc::FIONBIO,
            u64::from(TIOCSTI) + 1,
            u64::from(TIOCLINUX) - 1,
            0,
        ] {
            assert_eq!(ioctl(request), SECCOMP_RET_ALLOW, "ioctl {request:#x}");
        }
        // Requests that equal a syscall number a later rule matches on: the
        // accumulator must hold nr again, not args[1], when those rules run.
        let later = [libc::SYS_clone3, libc::SYS_clone, libc::SYS_unshare];
        for &nr in DENIED.iter().chain(&later) {
            assert_eq!(ioctl(nr as u64), SECCOMP_RET_ALLOW, "ioctl {nr:#x}");
        }
    }

    #[test]
    fn later_rules_still_see_the_syscall_number() {
        let eperm = errno(Errno::EPERM);
        // Another syscall whose args[1] happens to equal TIOCSTI is allowed.
        assert_eq!(eval(libc::SYS_write, [1, TIOCSTI.into(), 1, 0, 0, 0]), SECCOMP_RET_ALLOW);
        // Rules after the ioctl check still match on nr, not on args[1].
        assert_eq!(eval(libc::SYS_clone3, [0; 6]), errno(Errno::ENOSYS));
        let newuser = libc::CLONE_NEWUSER as u64;
        assert_eq!(eval(libc::SYS_unshare, [newuser, 0, 0, 0, 0, 0]), eperm);
        assert_eq!(eval(libc::SYS_unshare, [libc::CLONE_FILES as u64, 0, 0, 0, 0, 0]), SECCOMP_RET_ALLOW);
        for &nr in DENIED {
            assert_eq!(eval(nr, [0; 6]), eperm, "syscall {nr}");
        }
        assert_eq!(eval(libc::SYS_getpid, [0; 6]), SECCOMP_RET_ALLOW);
    }

    /// Installs the real filter in a forked child and checks the kernel's
    /// answers on a pseudo-terminal: TIOCSTI and TIOCLINUX fail with EPERM,
    /// while an ordinary terminal ioctl still works.
    #[test]
    fn kernel_enforces_ioctl_rule() {
        let prog = program();
        // SAFETY: the child only makes raw syscalls (no allocation or locks)
        // before _exit, so forking the multi-threaded test process is fine.
        match unsafe { libc::fork() } {
            -1 => panic!("fork: {}", std::io::Error::last_os_error()),
            0 => unsafe {
                // Exit codes say which step failed.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    libc::_exit(10);
                }
                if install_filter(&prog).is_err() {
                    libc::_exit(11);
                }
                let fd = libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY);
                if fd < 0 {
                    libc::_exit(12);
                }
                let c = b'x';
                if libc::ioctl(fd, libc::TIOCSTI, &c) != -1 || Errno::last() != Errno::EPERM {
                    libc::_exit(13);
                }
                let mut sel = [0u8; 1];
                if libc::ioctl(fd, libc::TIOCLINUX, sel.as_mut_ptr()) != -1
                    || Errno::last() != Errno::EPERM
                {
                    libc::_exit(14);
                }
                let mut ws: libc::winsize = std::mem::zeroed();
                if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) != 0 {
                    libc::_exit(15);
                }
                libc::_exit(0);
            },
            child => {
                let mut status = 0;
                assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
                assert!(libc::WIFEXITED(status), "child status {status:#x}");
                assert_eq!(libc::WEXITSTATUS(status), 0, "child failed at step");
            }
        }
    }
}
