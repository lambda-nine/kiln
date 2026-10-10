//! Per-sandbox disk limits using XFS project quotas, the same way Docker's
//! overlay2 driver does it.
//!
//! XFS can tag every file and directory with a 32-bit "project ID" and count
//! the blocks used by each project. kiln tags a sandbox's run directory with
//! its own project ID, sets PROJINHERIT so everything created inside inherits
//! the tag, and then sets a hard block limit for that project. Writes past
//! the limit fail with ENOSPC ("No space left on device"): XFS treats a
//! project quota like a size-limited directory tree, so to the program it
//! looks like a full disk rather than a quota (EDQUOT).

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use nix::errno::Errno;
use nix::sys::statfs::{XFS_SUPER_MAGIC, statfs};

/// Quotas count in 512-byte "basic blocks", whatever the real block size is.
const BASIC_BLOCK: u64 = 512;

// From <linux/fs.h>.
const FS_XFLAG_PROJINHERIT: u32 = 0x200;

// From <linux/quota.h> and <linux/dqblk_xfs.h>.
const PRJQUOTA: u32 = 2;
const Q_XGETQUOTA: u32 = ((b'X' as u32) << 8) + 3;
const Q_XSETQLIM: u32 = ((b'X' as u32) << 8) + 4;
const FS_DQUOT_VERSION: i8 = 1;
const FS_PROJ_QUOTA: i8 = 1 << 1;
const FS_DQ_BSOFT: u16 = 1 << 2;
const FS_DQ_BHARD: u16 = 1 << 3;

/// `struct fsxattr` from <linux/fs.h>.
#[repr(C)]
#[derive(Default)]
struct FsXattr {
    xflags: u32,
    extsize: u32,
    nextents: u32,
    projid: u32,
    cowextsize: u32,
    pad: [u8; 8],
}

/// `struct fs_disk_quota` from <linux/dqblk_xfs.h>.
#[repr(C)]
#[derive(Default)]
struct FsDiskQuota {
    version: i8,
    flags: i8,
    fieldmask: u16,
    id: u32,
    blk_hardlimit: u64,
    blk_softlimit: u64,
    ino_hardlimit: u64,
    ino_softlimit: u64,
    bcount: u64,
    icount: u64,
    itimer: i32,
    btimer: i32,
    iwarns: u16,
    bwarns: u16,
    itimer_hi: i8,
    btimer_hi: i8,
    rtbtimer_hi: i8,
    padding2: i8,
    rtb_hardlimit: u64,
    rtb_softlimit: u64,
    rtbcount: u64,
    rtbtimer: i32,
    rtbwarns: u16,
    padding3: i16,
    padding4: [u8; 8],
}

// The kernel reads these structs as raw bytes, so a layout mistake would
// silently corrupt the call. Pin the sizes the C headers produce.
const _: () = assert!(size_of::<FsXattr>() == 28);
const _: () = assert!(size_of::<FsDiskQuota>() == 112);

nix::ioctl_read!(fs_get_xattr, b'X', 31, FsXattr);
nix::ioctl_write_ptr!(fs_set_xattr, b'X', 32, FsXattr);

/// Gives `dir` its own project and caps it at `bytes` (`None` = no limit).
/// Must be called while `dir` is empty: only files created afterwards inherit
/// the project.
pub fn limit(dir: &Path, bytes: Option<u64>) -> Result<()> {
    let on_xfs = statfs(dir)
        .map(|s| s.filesystem_type() == XFS_SUPER_MAGIC)
        .unwrap_or(false);
    if !on_xfs {
        if bytes.is_some() {
            bail!(
                "--disk needs {} on XFS with project quotas \
                 (run: sudo scripts/setup-storage.sh, or pass --disk max)",
                dir.parent().unwrap_or(dir).display()
            );
        }
        return Ok(());
    }

    let dir_file = File::open(dir).with_context(|| format!("open {}", dir.display()))?;
    // The directory's inode number is unique on this filesystem for as long
    // as the directory exists, which makes it a free, collision-free ID.
    let id = u32::try_from(dir_file.metadata()?.ino()).context("inode number too large for a project ID")?;

    let fd = dir_file.as_raw_fd();
    let mut attr = FsXattr::default();
    // SAFETY: fd is an open directory and attr has the kernel's layout.
    unsafe { fs_get_xattr(fd, &mut attr) }.context("FS_IOC_FSGETXATTR")?;
    attr.projid = id;
    attr.xflags |= FS_XFLAG_PROJINHERIT;
    // SAFETY: as above.
    unsafe { fs_set_xattr(fd, &attr) }.context("FS_IOC_FSSETXATTR")?;

    // Always write the limit, even "none" (0): IDs are inode numbers, which
    // get reused, and a reused ID would otherwise inherit an old limit.
    let blocks = bytes.map_or(0, |b| b.div_ceil(BASIC_BLOCK));
    let mut quota = FsDiskQuota {
        version: FS_DQUOT_VERSION,
        flags: FS_PROJ_QUOTA,
        fieldmask: FS_DQ_BHARD | FS_DQ_BSOFT,
        id,
        blk_hardlimit: blocks,
        blk_softlimit: blocks,
        ..Default::default()
    };
    quotactl(&dir_file, Q_XSETQLIM, id, &mut quota).context("set disk quota")
}

/// A project's disk use and hard limit, in bytes.
pub struct Usage {
    pub used: u64,
    /// `None` when the project has no limit (`--disk max`).
    pub limit: Option<u64>,
}

/// Disk use of `dir`'s project, if it has one.
pub fn usage(dir: &Path) -> Option<Usage> {
    let dir_file = File::open(dir).ok()?;
    let mut attr = FsXattr::default();
    // SAFETY: fd is an open directory and attr has the kernel's layout.
    unsafe { fs_get_xattr(dir_file.as_raw_fd(), &mut attr) }.ok()?;
    if attr.projid == 0 {
        return None;
    }
    let mut quota = FsDiskQuota::default();
    quotactl(&dir_file, Q_XGETQUOTA, attr.projid, &mut quota).ok()?;
    let limit = (quota.blk_hardlimit > 0).then(|| quota.blk_hardlimit * BASIC_BLOCK);
    Some(Usage { used: quota.bcount * BASIC_BLOCK, limit })
}

/// quotactl_fd(2) (Linux 5.14+): like quotactl, but names the filesystem by
/// any open file on it instead of by its block device path.
fn quotactl(on: &File, cmd: u32, id: u32, quota: &mut FsDiskQuota) -> Result<()> {
    let qcmd = (cmd << 8) | PRJQUOTA;
    // SAFETY: quota is a valid FsDiskQuota the kernel may read or write.
    let ret = unsafe {
        libc::syscall(libc::SYS_quotactl_fd, on.as_raw_fd(), qcmd, id, quota as *mut FsDiskQuota)
    };
    Errno::result(ret)?;
    Ok(())
}
