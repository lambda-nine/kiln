use std::fs;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::unistd::Pid;

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const PARENT: &str = "kiln";
const CONTROLLERS: &str = "+cpu +memory +pids";
const CPU_PERIOD_US: u64 = 100_000;

/// Resource limits for one sandbox. `None` means unlimited ("max").
pub struct Limits {
    pub memory: Option<u64>,
    pub cpus: Option<f64>,
    pub pids: Option<u64>,
}

/// A cgroup v2 directory at /sys/fs/cgroup/kiln/<name>. Dropping it kills
/// anything still inside and removes the directory.
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

    /// Moves a process into this cgroup. Its future children start here too.
    pub fn add(&self, pid: Pid) -> Result<()> {
        self.write("cgroup.procs", &pid.to_string())
    }

    /// Reads one numeric file, like `memory.peak`. 0 if it's missing.
    pub fn value(&self, file: &str) -> u64 {
        let text = fs::read_to_string(self.path.join(file)).unwrap_or_default();
        text.trim().parse().unwrap_or(0)
    }

    /// Reads one `key value` line from a flat-keyed file, like `cpu.stat`.
    /// 0 if it's missing.
    pub fn stat(&self, file: &str, key: &str) -> u64 {
        let text = fs::read_to_string(self.path.join(file)).unwrap_or_default();
        text.lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(' ')?.parse().ok())
            .unwrap_or(0)
    }

    fn write(&self, file: &str, value: &str) -> Result<()> {
        write(&self.path.join(file), value)
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        // A cgroup directory can only be removed once it has no processes.
        // cgroup.kill SIGKILLs everything left, but they take a moment to die.
        let _ = fs::write(self.path.join("cgroup.kill"), "1");
        for _ in 0..100 {
            match fs::remove_dir(&self.path) {
                Ok(()) => return,
                Err(e) if e.raw_os_error() == Some(Errno::EBUSY as i32) => {
                    sleep(Duration::from_millis(10))
                }
                Err(e) => {
                    eprintln!("kiln: failed to remove {}: {e}", self.path.display());
                    return;
                }
            }
        }
        eprintln!("kiln: gave up removing busy cgroup {}", self.path.display());
    }
}

fn write(path: &Path, value: &str) -> Result<()> {
    fs::write(path, value).with_context(|| format!("write {value:?} to {}", path.display()))
}
