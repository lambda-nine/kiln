use std::ffi::CString;
use std::fs;
use std::os::fd::OwnedFd;
use std::os::unix::fs::symlink;
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
use crate::quota;

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
    let lower = Path::new(KILN_ROOT).join("images").join(&cfg.image);
    if !lower.is_dir() {
        bail!(
            "image {:?} not found at {} (try: sudo scripts/fetch-alpine.sh)",
            cfg.image,
            lower.display()
        );
    }

    let id = run_id();
    let run_dir = Path::new(KILN_ROOT).join("runs").join(&id);
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
    Ok(())
}

fn spawn_and_wait(cfg: &Config, id: &str, layers: &Layers) -> Result<i32> {
    let cgroup = Cgroup::create(id, &cfg.limits)?;

    // The child blocks on this pipe until the parent has finished setting it
    // up from the outside. O_CLOEXEC keeps the pipe out of the user's command.
    let (ready_rx, ready_tx) = pipe2(OFlag::O_CLOEXEC).context("pipe")?;

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
    let flags = CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS;

    let mut stack = vec![0u8; STACK_SIZE];
    let child = Box::new(|| match init(cfg, layers, &ready_rx) {
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

    // Move the child into its cgroup before it runs anything, then let it go.
    // Doing this from the parent avoids a race where the command starts
    // before its limits apply.
    let setup = cgroup.add(pid).and_then(|()| {
        write(&ready_tx, b"1").context("signal child")?;
        Ok(())
    });
    drop(ready_tx);
    if let Err(e) = setup {
        let _ = kill(pid, Signal::SIGKILL);
        let _ = wait_for(pid, &signals);
        return Err(e);
    }

    let code = wait_for(pid, &signals)?;
    if cgroup.stat("memory.events", "oom_kill").unwrap_or(0) > 0 {
        eprintln!("kiln: sandbox ran out of memory and was killed (memory.max)");
    }
    if cfg.stats {
        print_stats(&cgroup, &layers.upper);
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
    let get = |v: Option<u64>| v.unwrap_or(0);
    eprintln!(
        "kiln: memory peak {:.1} MiB | cpu {:.0} ms (throttled {} times, {:.0} ms) | pids peak {} | oom kills {}",
        mib(get(cgroup.value("memory.peak"))),
        ms(get(cgroup.stat("cpu.stat", "usage_usec"))),
        get(cgroup.stat("cpu.stat", "nr_throttled")),
        ms(get(cgroup.stat("cpu.stat", "throttled_usec"))),
        get(cgroup.value("pids.peak")),
        get(cgroup.stat("memory.events", "oom_kill")),
    );
    if let Some(bytes) = quota::usage(upper) {
        eprintln!("kiln: disk used {:.1} MiB", mib(bytes));
    }
}

/// Runs inside the child, already in the new namespaces. Sets up the sandbox,
/// then becomes its init and returns the command's exit code.
fn init(cfg: &Config, layers: &Layers, ready: &OwnedFd) -> Result<i32> {
    // Wait for the parent to put us in our cgroup. EOF means it gave up.
    let mut buf = [0u8; 1];
    if read(ready, &mut buf).context("wait for parent")? == 0 {
        bail!("parent failed to set up the sandbox");
    }

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

    // Read-only, so the sandbox can read its limits and usage but not raise them.
    fs::create_dir_all("/sys/fs/cgroup").context("create /sys/fs/cgroup")?;
    mount(
        Some("cgroup2"),
        "/sys/fs/cgroup",
        Some("cgroup2"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /sys/fs/cgroup")?;

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

    let argv: Vec<CString> = cfg
        .cmd
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()
        .context("argument contains a NUL byte")?;
    init::run(&argv)
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
    Ok(())
}

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}-{}", std::process::id())
}
