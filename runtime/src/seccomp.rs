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
    let filter = program();
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
