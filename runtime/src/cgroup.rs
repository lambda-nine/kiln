use std::collections::HashMap;
use std::fs;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::errno::Errno;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const PARENT: &str = "kiln";
/// The child cgroup a persistent sandbox's exec commands run in. PID 1 stays
/// in the sandbox's own cgroup, outside it.
const EXEC: &str = "exec";
const CONTROLLERS: &str = "+cpu +memory +pids +io";
const CPU_PERIOD_US: u64 = 100_000;
/// All sandboxes together get half the disk share of a host service when the
/// disk is contended (siblings like system.slice default to 100). Sandboxes
/// share their half equally (each defaults to 100 among themselves). Needs
/// iocost on the disk; see storage.rs.
const KILN_IO_WEIGHT: &str = "default 50";

/// Resource limits for one sandbox. `None` means unlimited ("max").
pub struct Limits {
    pub memory: Option<u64>,
    pub cpus: Option<f64>,
    pub pids: Option<u64>,
}

/// A cgroup v2 directory at /sys/fs/cgroup/kiln/<name>. Dropping it kills
/// anything still inside and removes the directory, and the exec cgroup
/// below it if there is one.
pub struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    pub fn create(name: &str, limits: &Limits) -> Result<Self> {
        // Controllers are enabled top-down: a cgroup can only use a controller
        // that its parent lists in cgroup.subtree_control.
        let root = Path::new(CGROUP_ROOT);
        write(&root.join("cgroup.subtree_control"), CONTROLLERS)?;
        let parent = root.join(PARENT);
        fs::create_dir_all(&parent).with_context(|| format!("create {}", parent.display()))?;
        write(&parent.join("cgroup.subtree_control"), CONTROLLERS)?;
        write(&parent.join("io.weight"), KILN_IO_WEIGHT)?;

        let path = parent.join(name);
        fs::create_dir(&path).with_context(|| format!("create {}", path.display()))?;
        let cgroup = Cgroup { path };
        cgroup.apply(limits)?;
        Ok(cgroup)
    }

    fn apply(&self, limits: &Limits) -> Result<()> {
        if let Some(bytes) = limits.memory {
            self.write("memory.max", &bytes.to_string())?;
            // Without this, a memory-hungry sandbox could spill into swap
            // instead of hitting its limit. (Absent when swap accounting is off.)
            if self.path.join("memory.swap.max").exists() {
                self.write("memory.swap.max", "0")?;
            }
        }
        // On OOM, kill the whole sandbox instead of one process inside it.
        self.write("memory.oom.group", "1")?;
        if let Some(cpus) = limits.cpus {
            // cpu.max is "<quota> <period>": the group may run for `quota`
            // microseconds of CPU time in every `period`, summed across cores.
            let quota = (cpus * CPU_PERIOD_US as f64).round() as u64;
            self.write("cpu.max", &format!("{quota} {CPU_PERIOD_US}"))?;
        }
        if let Some(pids) = limits.pids {
            self.write("pids.max", &pids.to_string())?;
        }
        Ok(())
    }

    /// The cgroup's directory, opened for clone3's CLONE_INTO_CGROUP.
    pub fn open_dir(&self) -> Result<fs::File> {
        fs::File::open(&self.path).with_context(|| format!("open {}", self.path.display()))
    }

    /// Creates /sys/fs/cgroup/kiln/<name>/exec and opens the three files PID 1
    /// needs to contain one exec command and everything it starts. They're
    /// opened here, by host root, because the kernel checks a cgroup.procs
    /// write against the credentials and cgroup namespace of whoever opened
    /// the file; inside the sandbox cgroupfs is read-only and sandbox root
    /// owns nothing in it. No controllers are enabled in the sandbox's
    /// subtree, so its limits apply to the exec cgroup's processes as before.
    pub fn create_exec_scope(&self) -> Result<ExecCgroup> {
        let path = self.path.join(EXEC);
        fs::create_dir(&path).with_context(|| format!("create {}", path.display()))?;
        let open = |file: &str, write: bool| {
            let file = path.join(file);
            // std opens with O_CLOEXEC, so no command inherits these.
            fs::OpenOptions::new()
                .read(!write)
                .write(write)
                .open(&file)
                .with_context(|| format!("open {}", file.display()))
        };
        Ok(ExecCgroup {
            procs: open("cgroup.procs", true)?,
            kill: open("cgroup.kill", true)?,
            events: open("cgroup.events", false)?,
        })
    }

    /// Reads one numeric file, like `memory.peak`. 0 if it's missing.
    pub fn value(&self, file: &str) -> u64 {
        read_value(&self.path, file).unwrap_or(0)
    }

    /// Reads one `key value` line from a flat-keyed file, like `cpu.stat`.
    /// 0 if it's missing.
    pub fn stat(&self, file: &str, key: &str) -> u64 {
        read_flat(&self.path, file).get(key).copied().unwrap_or(0)
    }

    fn write(&self, file: &str, value: &str) -> Result<()> {
        write(&self.path.join(file), value)
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        remove_tree(&self.path);
    }
}

/// The exec cgroup of a persistent sandbox, as host-opened handles to its
/// cgroup.procs, cgroup.kill and cgroup.events. PID 1 keeps them; the
/// sandbox's commands never get them. Dropping this only closes the files:
/// the directory goes with the sandbox's `Cgroup`.
pub struct ExecCgroup {
    procs: fs::File,
    kill: fs::File,
    events: fs::File,
}

impl ExecCgroup {
    #[cfg(test)]
    pub fn protocol_fixture(path: &Path) -> Self {
        let file = |name| fs::OpenOptions::new().read(true).write(true).open(path.join(name)).unwrap();
        Self { procs: file("procs"), kill: file("kill"), events: file("events") }
    }
    /// The descriptors to keep open across PID 1's setup.
    pub fn raw_fds(&self) -> [RawFd; 3] {
        [self.procs.as_raw_fd(), self.kill.as_raw_fd(), self.events.as_raw_fd()]
    }

    /// Moves the calling process into the exec cgroup. "0" means "me"; every
    /// child it starts afterwards is born inside, and no process can leave
    /// without write access to another cgroup.procs, which nothing inside the
    /// sandbox has.
    pub fn join_self(&self) -> Result<()> {
        self.procs.write_all_at(b"0", 0).context("join exec cgroup")
    }

    /// SIGKILLs everything in the exec cgroup, then waits until it's empty.
    /// The kernel handles processes forking while it kills, so once
    /// `populated` reads 0 nothing the exec started is left.
    pub fn kill_and_wait_empty(&self) -> Result<()> {
        self.kill.write_all_at(b"1", 0).context("write exec cgroup.kill")?;
        loop {
            if !self.populated()? {
                return Ok(());
            }
            // cgroup.events signals a change with POLLPRI and POLLERR. Our
            // read above armed it, so a change since then wakes us at once.
            let mut fd = libc::pollfd { fd: self.events.as_raw_fd(), events: libc::POLLPRI, revents: 0 };
            // SAFETY: `fd` is one initialized pollfd.
            if unsafe { libc::poll(&mut fd, 1, -1) } < 0 && Errno::last() != Errno::EINTR {
                return Err(Errno::last()).context("poll exec cgroup.events");
            }
        }
    }

    /// Closes this process's copies of the three descriptors, in the forked
    /// child just before it execs the command. The `File`s are left as they
    /// are: the child execs or exits and never drops them.
    pub fn close_in_child(&self) {
        for fd in self.raw_fds() {
            // SAFETY: closes descriptors nothing in this process uses again.
            unsafe { libc::close(fd) };
        }
    }

    fn populated(&self) -> Result<bool> {
        let mut buf = [0u8; 256];
        let mut len = 0;
        while len < buf.len() {
            // pread from offset 0, so each check rereads the whole file.
            match self.events.read_at(&mut buf[len..], len as u64).context("read exec cgroup.events")? {
                0 => break,
                n => len += n,
            }
        }
        match parse_populated(&String::from_utf8_lossy(&buf[..len])) {
            Some(populated) => Ok(populated),
            None => bail!("exec cgroup.events has no populated line"),
        }
    }
}

/// The `populated` value of a cgroup.events file.
fn parse_populated(events: &str) -> Option<bool> {
    events.lines().find_map(|line| match line.split_once(' ')? {
        ("populated", "0") => Some(false),
        ("populated", "1") => Some(true),
        _ => None,
    })
}

/// Kills everything in a sandbox's cgroup and removes it, children first: a
/// cgroup with a child cgroup can't be removed, and cgroup.kill only kills
/// processes. The parent's cgroup.kill also kills its children's processes.
fn remove_tree(path: &Path) {
    let _ = fs::write(path.join("cgroup.kill"), "1");
    let child = path.join(EXEC);
    let busy = |e: &std::io::Error| e.raw_os_error() == Some(Errno::EBUSY as i32);
    let gone = |e: &std::io::Error| e.kind() == std::io::ErrorKind::NotFound;
    // A cgroup directory can only be removed once it has no processes, and
    // killed processes take a moment to die.
    for _ in 0..100 {
        match fs::remove_dir(&child) {
            Ok(()) => {}
            Err(e) if gone(&e) => {}
            Err(e) if busy(&e) => { sleep(Duration::from_millis(10)); continue; }
            Err(e) => {
                eprintln!("kiln: failed to remove {}: {e}", child.display());
                return;
            }
        }
        match fs::remove_dir(path) {
            Ok(()) => return,
            Err(e) if gone(&e) => return,
            Err(e) if busy(&e) => sleep(Duration::from_millis(10)),
            Err(e) => {
                eprintln!("kiln: failed to remove {}: {e}", path.display());
                return;
            }
        }
    }
    eprintln!("kiln: gave up removing busy cgroup {}", path.display());
}

/// /sys/fs/cgroup/kiln, the parent of every sandbox's cgroup. Its counters are
/// hierarchical: they include sandboxes that have already exited.
pub fn parent_dir() -> PathBuf {
    Path::new(CGROUP_ROOT).join(PARENT)
}

/// The cgroups of running sandboxes, as (run ID, directory). Read-only: unlike
/// `Cgroup`, nothing here kills or removes anything.
pub fn sandboxes() -> Vec<(String, PathBuf)> {
    let Ok(entries) = fs::read_dir(parent_dir()) else { return Vec::new() };
    let mut found: Vec<(String, PathBuf)> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| (e.file_name().to_string_lossy().into_owned(), e.path()))
        .collect();
    found.sort();
    found
}

/// Kills and removes a cgroup left behind by a crashed persistent shim.
pub fn remove(name: &str) {
    let path = parent_dir().join(name);
    if !path.is_dir() { return; }
    remove_tree(&path);
}

/// A single-value file like `memory.current` or `pids.max`. `None` if it's
/// missing or says "max" (no limit).
pub fn read_value(dir: &Path, file: &str) -> Option<u64> {
    fs::read_to_string(dir.join(file)).ok()?.trim().parse().ok()
}

/// Every `key value` line of a flat-keyed file like `cpu.stat` or
/// `memory.events`. Empty if the file is missing.
pub fn read_flat(dir: &Path, file: &str) -> HashMap<String, u64> {
    let text = fs::read_to_string(dir.join(file)).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(' ')?;
            Some((key.to_string(), value.trim().parse().ok()?))
        })
        .collect()
}

fn write(path: &Path, value: &str) -> Result<()> {
    fs::write(path, value).with_context(|| format!("write {value:?} to {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_populated_from_cgroup_events() {
        assert_eq!(parse_populated("populated 1\nfrozen 0\n"), Some(true));
        assert_eq!(parse_populated("populated 0\nfrozen 0\n"), Some(false));
        assert_eq!(parse_populated("frozen 0\npopulated 0"), Some(false));
        assert_eq!(parse_populated("frozen 0\n"), None);
        assert_eq!(parse_populated("populated 2\n"), None);
        assert_eq!(parse_populated(""), None);
    }
}
