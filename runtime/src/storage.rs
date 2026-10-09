//! The disk under /var/lib/kiln/runs: an XFS filesystem in a file, mounted
//! through a loop device (scripts/setup-storage.sh). Two kernel settings make
//! it behave, and neither survives a reboot, so kiln checks them every run.
//!
//! 1. Direct I/O on the loop device. By default the loop driver writes its
//!    backing file through the page cache, and those pages are charged to the
//!    sandbox that caused them. A sandbox writing more than its memory limit
//!    with O_DIRECT (databases, some downloaders) then gets OOM-killed, since
//!    its own writes left nothing it could reclaim. With direct I/O the loop
//!    driver skips the page cache: no double caching, no OOM.
//! 2. The iocost controller on the real disk underneath. io.weight only works
//!    with a proportional I/O controller, and this kernel's disks use
//!    mq-deadline (no BFQ). Direct I/O also lets the loop driver's writes
//!    reach the real disk tagged with the sandbox's cgroup, so iocost knows
//!    whose they are.

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

// <linux/loop.h>: loop ioctls are plain numbers, not _IOW-encoded.
nix::ioctl_write_int_bad!(loop_set_direct_io, 0x4C08);

pub fn prepare(runs: &Path) -> Result<()> {
    let mut sys = sysfs_dir(runs)?;
    if let Ok(backing) = fs::read_to_string(sys.join("loop/backing_file")) {
        loop_direct_io(&sys)?;
        sys = sysfs_dir(Path::new(backing.trim()))?;
    }
    // A partition: its parent directory in sysfs is the whole disk.
    if sys.join("partition").exists() {
        sys = fs::canonicalize(&sys)?.parent().context("partition without a disk")?.to_path_buf();
    }
    let disk = fs::read_to_string(sys.join("dev")).context("read disk number")?;
    enable_iocost(disk.trim())
}

/// /sys/dev/block/MAJ:MIN for the device holding `path`.
fn sysfs_dir(path: &Path) -> Result<PathBuf> {
    let dev = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?.dev();
    Ok(PathBuf::from(format!("/sys/dev/block/{}:{}", libc::major(dev), libc::minor(dev))))
}

fn loop_direct_io(sys: &Path) -> Result<()> {
    if fs::read_to_string(sys.join("loop/dio")).unwrap_or_default().trim() == "1" {
        return Ok(());
    }
    let name = fs::canonicalize(sys)?.file_name().context("loop device name")?.to_owned();
    let device = Path::new("/dev").join(name);
    let file = File::open(&device).with_context(|| format!("open {}", device.display()))?;
    // SAFETY: a plain ioctl on an open loop device; the argument is an int.
    unsafe { loop_set_direct_io(file.as_raw_fd(), 1) }.context("LOOP_SET_DIRECT_IO")?;
    Ok(())
}

fn enable_iocost(disk: &str) -> Result<()> {
    let qos = "/sys/fs/cgroup/io.cost.qos";
    let current = fs::read_to_string(qos).unwrap_or_default();
    if current.lines().any(|l| l.starts_with(&format!("{disk} enable=1"))) {
        return Ok(());
    }
    fs::write(qos, format!("{disk} enable=1")).with_context(|| format!("enable iocost on {disk}"))
}
