use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, chown, symlink};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use nix::fcntl::OFlag;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::sched::{CloneFlags, clone, unshare};
use nix::sys::signal::{SigSet, Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, chdir, pipe2, pivot_root, read, sethostname, write};

use crate::cgroup::{Cgroup, Limits};
use crate::init;
use crate::landlock;
use crate::net;
use crate::seccomp;
use crate::storage;
use crate::quota;
use crate::userns;

const STACK_SIZE: usize = 1024 * 1024;
const KILN_ROOT: &str = "/var/lib/kiln";
const SANDBOX_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const DEVICES: [&str; 6] = ["null", "zero", "full", "random", "urandom", "tty"];

pub struct Config {
    pub hostname: String,
    pub image: String,
    pub keep: bool,
    pub limits: Limits,
    pub disk: Option<u64>,
    pub read_only: bool,
    pub writable: Vec<PathBuf>,
    pub net: net::Plan,
    pub stats: bool,
    pub cmd: Vec<String>,
}

/// The overlayfs layers for one run. `lower` is the shared, read-only image;
/// every write lands in `upper`, which belongs to this run only. `merged` is
/// the combined view that becomes the sandbox's `/`.
struct Layers {
    lower: PathBuf,
    upper: PathBuf,
    work: PathBuf,
    merged: PathBuf,
}

/// Runs `cfg.cmd` in a fresh sandbox, waits for it, and returns a shell-style
/// exit code (128 + signal number if it was killed).
pub fn run(cfg: &Config) -> Result<i32> {
    // A plain name, so `--image ../../somewhere` can't pick an arbitrary host
    // directory (or another run's upper layer) as the root filesystem.
    let safe = |c: char| c.is_ascii_alphanumeric() || "-_.".contains(c);
    if cfg.image.is_empty() || cfg.image.starts_with('.') || !cfg.image.chars().all(safe) {
        bail!("invalid image name {:?}", cfg.image);
    }
    let lower = Path::new(KILN_ROOT).join("images").join(&cfg.image);
    if !lower.is_dir() {
        bail!(
            "image {:?} not found at {} (try: sudo scripts/fetch-alpine.sh)",
            cfg.image,
            lower.display()
        );
    }
    // The image's files must belong to the sandbox's ID range, or sandbox
    // root would see them all as owned by "nobody" and couldn't change them.
    if lower.metadata()?.uid() != userns::ID_BASE {
        bail!(
            "image {:?} isn't owned by the sandbox ID range (re-run: sudo scripts/fetch-alpine.sh)",
            cfg.image
        );
    }

    let id = run_id();
    storage::prepare(&Path::new(KILN_ROOT).join("runs"))?;
    let run_dir = run_dir(&id);
    let layers = Layers {
        lower,
        upper: run_dir.join("upper"),
        work: run_dir.join("work"),
        merged: run_dir.join("merged"),
    };
    fs::create_dir_all(&run_dir)
        .with_context(|| format!("create {} (are you root?)", run_dir.display()))?;

    let result = prepare(cfg, &run_dir, &layers).and_then(|()| spawn_and_wait(cfg, &id, &layers));

    // The overlay mount lived in the sandbox's mount namespace, so it vanished
    // with the sandbox. Only the directories are left to clean up.
    if cfg.keep {
        eprintln!("kiln: kept {} (changes are in upper/)", run_dir.display());
    } else if let Err(e) = fs::remove_dir_all(&run_dir) {
        eprintln!("kiln: failed to remove {}: {e}", run_dir.display());
    }
    result
}

fn prepare(cfg: &Config, run_dir: &Path, layers: &Layers) -> Result<()> {
    // The quota goes on the run dir while it's still empty, so upper/ and
    // work/ (and everything the sandbox writes) inherit its project.
    quota::limit(run_dir, cfg.disk)?;
    for dir in [&layers.upper, &layers.work, &layers.merged] {
        fs::create_dir(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    // The sandbox's "/" takes its owner from upper/, so hand it to sandbox root.
    let id = Some(userns::ID_BASE);
    chown(&layers.upper, id, id).context("chown upper")?;
    Ok(())
}

fn spawn_and_wait(cfg: &Config, id: &str, layers: &Layers) -> Result<i32> {
    let cgroup = Cgroup::create(id, &cfg.limits)?;

    // Two one-byte handshakes over a pair of pipes. Parent → child: "you're in
    // your cgroup" and later "your ID maps are written". Child → parent: "I've
    // created my user namespace". O_CLOEXEC keeps them out of the command.
    let (to_child_rx, to_child_tx) = pipe2(OFlag::O_CLOEXEC).context("pipe")?;
    let (to_parent_rx, to_parent_tx) = pipe2(OFlag::O_CLOEXEC).context("pipe")?;

    // Handle signals by waiting for them (see wait_for) instead of dying, so
    // Ctrl-C or `kill` can't skip cleanup.
    let mut signals = SigSet::empty();
    for sig in [Signal::SIGCHLD, Signal::SIGINT, Signal::SIGQUIT].iter().chain(&init::FORWARDED) {
        signals.add(*sig);
    }
    signals.thread_block().context("block signals")?;

    // Each flag asks the kernel for a fresh copy of one namespace for the child:
    //   NEWUTS - its own hostname
    //   NEWPID - its own PID numbering; the child becomes PID 1
    //   NEWNS  - its own mount table, so its mounts never touch the host
    //   NEWNET - its own interfaces, routes and firewall (only lo at first)
    //   NEWIPC - its own System V shared memory, semaphores and message
    //            queues, freed when the sandbox ends. Without it, sandboxes
    //            could read and destroy each other's (they share host IDs).
    let flags = CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWNET
        | CloneFlags::CLONE_NEWIPC;

    let mut stack = vec![0u8; STACK_SIZE];
    let child = Box::new(|| match init(cfg, layers, &to_child_rx, &to_parent_tx) {
        Ok(code) => code as isize,
        Err(e) => {
            eprintln!("kiln: {e:#}");
            1
        }
    });

    // SAFETY: we're single-threaded and the child gets its own copy of the
    // address space (no CLONE_VM), so it can't race with the parent.
    let pid = unsafe { clone(child, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .context("clone (are you root?)")?;

    // Our copy of the child's write end must go, or we'd never see EOF if the
    // child dies before writing.
    drop(to_parent_tx);

    let mut network = None;
    let setup = (|| -> Result<()> {
        // Move the child into its cgroup before it runs anything, then let it
        // go. Doing this from the parent avoids a race where the command
        // starts before its limits apply.
        cgroup.add(pid)?;
        // Plug its network namespace in from the outside, same reasoning.
        network = net::setup(pid, id, &cfg.net)?;
        write(&to_child_tx, b"1").context("signal child")?;

        // The child does its mounts as real root, then creates its user
        // namespace and waits for us to write its ID maps.
        let mut buf = [0u8; 1];
        if read(&to_parent_rx, &mut buf).context("wait for child")? == 0 {
            return Ok(()); // Child failed and printed why; wait_for collects it.
        }
        userns::write_maps(pid)?;
        write(&to_child_tx, b"1").context("signal child")?;
        Ok(())
    })();
    drop(to_child_tx);
    if let Err(e) = setup {
        let _ = kill(pid, Signal::SIGKILL);
        let _ = wait_for(pid, &signals);
        return Err(e);
    }

    let code = wait_for(pid, &signals)?;
    if cgroup.stat("memory.events", "oom_kill") > 0 {
        eprintln!("kiln: sandbox ran out of memory and was killed (memory.max)");
    }
    if cfg.stats {
        print_stats(&cgroup, &layers.upper);
        if let Some(n) = &network {
            eprintln!("kiln: ip {} | egress packets rejected {}", n.ip(), n.blocked_packets());
        }
    }
    Ok(code)
}

/// Waits for the sandbox to exit, passing `init::FORWARDED` signals on to its
/// init. SIGINT and SIGQUIT come from the terminal, which already sends them
/// to the sandbox directly, so they're just swallowed here.
fn wait_for(pid: Pid, signals: &SigSet) -> Result<i32> {
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)).context("waitpid")? {
            WaitStatus::Exited(_, code) => return Ok(code),
            WaitStatus::Signaled(_, sig, _) => return Ok(128 + sig as i32),
            _ => {}
        }
        match signals.wait().context("sigwait")? {
            sig if init::FORWARDED.contains(&sig) => {
                let _ = kill(pid, sig);
            }
            _ => {}
        }
    }
}

fn print_stats(cgroup: &Cgroup, upper: &Path) {
    let mib = |b: u64| b as f64 / (1 << 20) as f64;
    let ms = |us: u64| us as f64 / 1000.0;
    eprintln!(
        "kiln: memory peak {:.1} MiB | cpu {:.0} ms (throttled {} times, {:.0} ms) | pids peak {} | oom kills {}",
        mib(cgroup.value("memory.peak")),
        ms(cgroup.stat("cpu.stat", "usage_usec")),
        cgroup.stat("cpu.stat", "nr_throttled"),
        ms(cgroup.stat("cpu.stat", "throttled_usec")),
        cgroup.value("pids.peak"),
        cgroup.stat("memory.events", "oom_kill"),
    );
    if let Some(disk) = quota::usage(upper) {
        eprintln!("kiln: disk used {:.1} MiB", mib(disk.used));
    }
}

/// Runs inside the child, already in the new namespaces. Sets up the sandbox,
/// then becomes its init and returns the command's exit code.
fn init(cfg: &Config, layers: &Layers, from_parent: &OwnedFd, to_parent: &OwnedFd) -> Result<i32> {
    close_fds_except(&[from_parent.as_raw_fd(), to_parent.as_raw_fd()])?;

    // Wait for the parent to put us in our cgroup.
    wait_for_parent(from_parent)?;

    // A cgroup namespace makes our current cgroup look like the root, so the
    // sandbox sees /sys/fs/cgroup as just its own limits and nothing above.
    // It has to happen after the move, or the host's cgroup would be the root.
    unshare(CloneFlags::CLONE_NEWCGROUP).context("unshare cgroup namespace")?;

    sethostname(&cfg.hostname).context("sethostname")?;

    // A new mount namespace starts as a copy of the parent's, and on systemd
    // hosts "/" is a shared mount, so new mounts would propagate back to the
    // host. pivot_root also refuses to work on shared mounts. Mark everything
    // private first.
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .context("make / private")?;

    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        layers.lower.display(),
        layers.upper.display(),
        layers.work.display()
    );
    mount(Some("overlay"), &layers.merged, Some("overlay"), MsFlags::empty(), Some(opts.as_str()))
        .context("mount overlay")?;

    // Device files must be bind-mounted from the host before we lose sight of it.
    setup_dev(&layers.merged.join("dev"))?;

    // Swap roots. pivot_root(".", ".") stacks the old root on top of the new
    // one at "/"; detaching "." then removes the old root, leaving no path
    // back to the host filesystem.
    chdir(&layers.merged).context("chdir to new root")?;
    pivot_root(".", ".").context("pivot_root")?;
    umount2(".", MntFlags::MNT_DETACH).context("detach old root")?;
    chdir("/").context("chdir /")?;

    // /proc reflects the PID namespace of whoever mounted it. Mount a fresh
    // one so `ps` inside the sandbox only sees the sandbox's processes.
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /proc")?;

    // /proc/sys/net belongs to the network namespace of whoever opens it, so
    // these only change ours. Sandbox root won't own this namespace, so let
    // it bind ports below 1024 and ping (ICMP sockets) anyway, like Docker.
    fs::write("/proc/sys/net/ipv4/ip_unprivileged_port_start", "0").context("sysctl")?;
    fs::write("/proc/sys/net/ipv4/ping_group_range", "0 2147483647").context("sysctl")?;

    // Read-only, so the sandbox can read its limits and usage but not raise them.
    mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /sys/fs/cgroup")?;

    // Written as real root, so it shows up inside as owned by "nobody":
    // readable, but sandbox root can't point DNS somewhere else.
    if let Some(conf) = cfg.net.resolv_conf() {
        fs::write("/etc/resolv.conf", conf).context("write /etc/resolv.conf")?;
    }

    // Last step as real root. Every namespace above was created first, so it
    // stays owned by the host's user namespace and sandbox root gets no power
    // over it: no mounting, unmounting or changing the hostname.
    unshare(CloneFlags::CLONE_NEWUSER).context("unshare user namespace")?;
    write(to_parent, b"1").context("signal parent")?;
    wait_for_parent(from_parent)?;
    userns::become_root()?;
    // If the host-side kiln dies, take the sandbox down with it rather than
    // leave it running unsupervised. Set after become_root, because changing
    // credentials clears it.
    nix::sys::prctl::set_pdeathsig(Signal::SIGKILL).context("set pdeathsig")?;

    // Start from a clean environment so host variables don't leak in.
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".into());
    // SAFETY: single-threaded, and nothing else reads the environment here.
    unsafe {
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(key);
        }
        std::env::set_var("PATH", SANDBOX_PATH);
        std::env::set_var("HOME", "/root");
        std::env::set_var("TERM", term);
    }

    // Lock the process down. no_new_privs first: setuid binaries stop granting
    // privilege, and both Landlock and seccomp require it. Order matters only
    // in that both must come before the command runs; both are inherited by
    // every child and can't be undone.
    nix::sys::prctl::set_no_new_privs().context("set no_new_privs")?;
    if cfg.read_only {
        landlock::restrict_writes(&cfg.writable)?;
    }
    seccomp::install()?;

    let argv: Vec<CString> = cfg
        .cmd
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()
        .context("argument contains a NUL byte")?;
    init::run(&argv)
}

/// Closes every file descriptor except stdin, stdout, stderr and `keep`.
/// Anything else was inherited from whoever started kiln (an open host file,
/// a directory, a socket), and namespaces, pivot_root and Landlock don't
/// revoke open descriptors: each would be a handle straight through the
/// sandbox walls. This also drops our copies of the parent's pipe ends, so a
/// parent that dies mid-setup shows up here as EOF instead of a hang.
fn close_fds_except(keep: &[RawFd]) -> Result<()> {
    let mut keep: Vec<u32> = keep.iter().map(|&fd| fd as u32).collect();
    keep.sort_unstable();
    let mut first = 3;
    for fd in keep.into_iter().chain([u32::MAX]) {
        if fd > first {
            // SAFETY: closes a range of descriptors; nothing below uses them.
            let ret = unsafe { libc::syscall(libc::SYS_close_range, first, fd - 1, 0) };
            nix::errno::Errno::result(ret).context("close_range")?;
        }
        first = fd.saturating_add(1);
    }
    Ok(())
}

/// Blocks until the parent writes its next handshake byte. EOF means it gave up.
fn wait_for_parent(from_parent: &OwnedFd) -> Result<()> {
    let mut buf = [0u8; 1];
    if read(from_parent, &mut buf).context("wait for parent")? == 0 {
        bail!("parent failed to set up the sandbox");
    }
    Ok(())
}

/// Builds a minimal /dev: a small tmpfs holding bind mounts of a few safe host
/// devices, instead of exposing the host's whole /dev (disks included).
fn setup_dev(dev: &Path) -> Result<()> {
    mount(
        Some("tmpfs"),
        dev,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=755,size=64k"),
    )
    .context("mount /dev tmpfs")?;

    for name in DEVICES {
        let target = dev.join(name);
        fs::File::create(&target).with_context(|| format!("create {}", target.display()))?;
        let source = Path::new("/dev").join(name);
        mount(Some(&source), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("bind {}", source.display()))?;
    }

    for (link, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        symlink(target, dev.join(link)).with_context(|| format!("symlink /dev/{link}"))?;
    }

    // POSIX shared memory (Python multiprocessing, Chromium, Postgres). Its
    // pages are charged to the sandbox's cgroup, so it stays inside memory.max.
    let shm = dev.join("shm");
    fs::create_dir(&shm).context("create /dev/shm")?;
    mount(
        Some("tmpfs"),
        &shm,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=1777,size=64m"),
    )
    .context("mount /dev/shm")?;
    Ok(())
}

/// A run ID is the start time in nanoseconds (hex) and kiln's PID: unique,
/// sortable, and it names the run's cgroup and run directory.
fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}-{}", std::process::id())
}

/// When run `id` started, in seconds since the Unix epoch.
pub fn run_started(id: &str) -> Option<f64> {
    let (nanos, _) = id.split_once('-')?;
    Some(u128::from_str_radix(nanos, 16).ok()? as f64 / 1e9)
}

/// /var/lib/kiln/runs/<id>: the run's overlay layers, under its disk quota.
pub fn run_dir(id: &str) -> PathBuf {
    Path::new(KILN_ROOT).join("runs").join(id)
}
