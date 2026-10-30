//! Landlock: an unprivileged, stackable LSM that restricts which paths a
//! process may touch. Unlike file permissions it binds root too: with
//! `--read-only`, sandbox root can't write /etc despite owning it.
//!
//! A ruleset lists the access rights it "handles"; anything handled is denied
//! unless a rule grants it beneath some directory. There are no deny rules,
//! only grants, and like seccomp it can never be lifted.
//!
//! Landlock covers file contents and directory entries (create, delete,
//! rename, truncate), not metadata: chmod and chown still work on files the
//! sandbox owns. Real immutability would need a read-only mount.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nix::errno::Errno;

// Filesystem access rights from <linux/landlock.h>, only the write-type ones.
// Rights a ruleset doesn't handle are never restricted, so leaving out
// EXECUTE (1 << 0), READ_FILE (1 << 2) and READ_DIR (1 << 3) keeps reading
// and executing allowed everywhere.
const WRITE_FILE: u64 = 1 << 1;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
const REFER: u64 = 1 << 13; // link/rename across directories
const TRUNCATE: u64 = 1 << 14;

const ABI1_WRITES: u64 = WRITE_FILE
    | REMOVE_DIR
    | REMOVE_FILE
    | MAKE_CHAR
    | MAKE_DIR
    | MAKE_REG
    | MAKE_SOCK
    | MAKE_FIFO
    | MAKE_BLOCK
    | MAKE_SYM;

const CREATE_RULESET_VERSION: u32 = 1 << 0;
const RULE_PATH_BENEATH: u32 = 1;

/// Writable when `--read-only` is on, on top of any `--writable` paths.
const DEFAULT_WRITABLE: [&str; 4] = ["/tmp", "/root", "/workspace", "/dev/shm"];

/// `struct landlock_ruleset_attr`. Only the filesystem field: network rules
/// (ABI 4) aren't used.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr`, which is `__attribute__((packed))`.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const _: () = assert!(size_of::<PathBeneathAttr>() == 12);

/// Restricts this process (and everything it starts) to writing only beneath
/// `DEFAULT_WRITABLE` and `writable`, plus the existing files in /dev.
/// Reading and executing stay allowed everywhere. Missing writable
/// directories are created first.
pub fn restrict_writes(writable: &[PathBuf]) -> Result<()> {
    // SAFETY: a NULL attr with the VERSION flag just queries the ABI version.
    let abi = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, std::ptr::null::<RulesetAttr>(), 0, CREATE_RULESET_VERSION)
    };
    // ABI 3 (Linux 6.2) is the first that can stop truncation; on anything
    // older --read-only would quietly let files be emptied.
    if abi < 3 {
        bail!("--read-only needs Landlock ABI 3 (Linux 6.2+), this kernel has {abi}");
    }
    let all = ABI1_WRITES | REFER | TRUNCATE;

    let attr = RulesetAttr { handled_access_fs: all };
    // SAFETY: attr is a valid ruleset_attr of the size passed.
    let fd = unsafe {
        libc::syscall(libc::SYS_landlock_create_ruleset, &attr as *const RulesetAttr, size_of::<RulesetAttr>(), 0)
    };
    // SAFETY: on success the syscall returns a new fd that we now own.
    let ruleset = unsafe { OwnedFd::from_raw_fd(Errno::result(fd).context("landlock_create_ruleset")? as i32) };

    // Keep resolution anchored to the pivoted root and never follow image
    // symlinks or procfs magic links, even in a parent component.
    let root: OwnedFd = File::options().read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/").context("open sandbox root")?.into();
    let dev = writable_dir(&root, Path::new("/dev"), false)?;
    allow(&ruleset, &dev, Path::new("/dev"), WRITE_FILE | TRUNCATE)?;
    for dir in DEFAULT_WRITABLE.iter().map(Path::new).chain(writable.iter().map(PathBuf::as_path)) {
        let handle = writable_dir(&root, dir, true)?;
        allow(&ruleset, &handle, dir, all)?;
    }

    // SAFETY: plain syscall on a ruleset fd we own.
    let ret = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) };
    Errno::result(ret).context("landlock_restrict_self")?;
    Ok(())
}

/// Equivalent to a RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
/// RESOLVE_NO_MAGICLINKS openat2 walk, with mkdirat for missing components.
/// Each opened parent is retained until its child is open; pathname swaps
/// cannot redirect a later component outside the sandbox root.
fn writable_dir(root: &OwnedFd, path: &Path, create: bool) -> Result<OwnedFd> {
    crate::validation::validate_writable_paths(&[path.to_owned()])?;
    let duplicate = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    let mut dir = unsafe { OwnedFd::from_raw_fd(Errno::result(duplicate).context("duplicate root fd")?) };
    for component in path.as_os_str().as_bytes()[1..].split(|byte| *byte == b'/') {
        let component = CString::new(component)?;
        let open = || unsafe { libc::openat(dir.as_raw_fd(), component.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        let mut fd = open();
        if fd < 0 && Errno::last() == Errno::ENOENT && create {
            let made = unsafe { libc::mkdirat(dir.as_raw_fd(), component.as_ptr(), 0o755) };
            if made < 0 && Errno::last() != Errno::EEXIST {
                return Err(Errno::last()).with_context(|| format!("create writable {}", path.display()));
            }
            fd = open();
        }
        let child = unsafe { OwnedFd::from_raw_fd(Errno::result(fd)
            .with_context(|| format!("open writable {} without symlinks", path.display()))?) };
        let mut root_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        let mut child_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        Errno::result(unsafe { libc::fstat(root.as_raw_fd(), &mut root_stat) }).context("stat sandbox root")?;
        Errno::result(unsafe { libc::fstat(child.as_raw_fd(), &mut child_stat) }).context("stat writable directory")?;
        if root_stat.st_dev == child_stat.st_dev && root_stat.st_ino == child_stat.st_ino {
            bail!("writable {} resolves to the sandbox root", path.display());
        }
        dir = child;
    }
    Ok(dir)
}

fn allow(ruleset: &OwnedFd, dir: &OwnedFd, path: &Path, access: u64) -> Result<()> {
    let rule = PathBeneathAttr { allowed_access: access, parent_fd: dir.as_raw_fd() };
    // SAFETY: rule is a valid path_beneath_attr and both fds are open.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            RULE_PATH_BENEATH,
            &rule as *const PathBeneathAttr,
            0,
        )
    };
    Errno::result(ret).with_context(|| format!("landlock rule for {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn root_fd(path: &Path) -> OwnedFd {
        File::options().read(true).custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(path).unwrap().into()
    }

    #[test]
    fn writable_walk_refuses_symlinks_root_and_magic_links() {
        let scratch = std::env::temp_dir().join(format!("kiln-writable-{}", std::process::id()));
        fs::create_dir(&scratch).unwrap();
        fs::create_dir(scratch.join("etc")).unwrap();
        symlink("/", scratch.join("root-link")).unwrap();
        symlink("/etc", scratch.join("etc-link")).unwrap();
        let root = root_fd(&scratch);
        for path in ["/", "/root-link", "/root-link/etc", "/etc-link", "/etc-link/must-not-create"] {
            assert!(writable_dir(&root, Path::new(path), true).is_err(), "{path}");
        }
        writable_dir(&root, Path::new("/new/nested"), true).unwrap();
        assert!(scratch.join("new/nested").is_dir());
        let host_root = root_fd(Path::new("/"));
        assert!(writable_dir(&host_root, Path::new("/proc/self/root"), false).is_err());
        fs::remove_dir_all(scratch).unwrap();
    }
}
