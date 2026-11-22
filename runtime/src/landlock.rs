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
pub(crate) const DEFAULT_WRITABLE: [&str; 4] = ["/tmp", "/root", "/workspace", "/dev/shm"];

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
/// Reading and executing stay allowed everywhere.
/// `create_missing`: create absent writable directories (ordinary creates).
/// A sandbox restored from a checkpoint passes false: its tree must be
/// exactly the checkpoint's, so an absent writable path is an error, never
/// recreated. `generated` lists the files kiln itself wrote into the root
/// (protected.rs), which no writable path may run through.
pub fn restrict_writes(writable: &[PathBuf], create_missing: bool, generated: &[&str]) -> Result<()> {
    // Keep resolution anchored to the pivoted root and never follow image
    // symlinks or procfs magic links, even in a parent component.
    let root: OwnedFd = File::options().read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/").context("open sandbox root")?.into();
    restrict_writes_under(&root, writable, create_missing, generated)
}

/// `restrict_writes` with the root it walks passed in (tests pass a scratch
/// directory).
fn restrict_writes_under(root: &OwnedFd, writable: &[PathBuf], create_missing: bool, generated: &[&str])
    -> Result<()> {
    let missing = if create_missing { Missing::Create } else { Missing::Refuse };
    let dirs = walk(root, writable, missing, generated)?;

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
    for (dir, path, scope) in dirs {
        let dir = dir.with_context(|| format!("writable {} was not opened", path.display()))?;
        allow(&ruleset, &dir, path, if scope == Scope::DevFiles { WRITE_FILE | TRUNCATE } else { all })?;
    }

    // SAFETY: plain syscall on a ruleset fd we own.
    let ret = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) };
    Errno::result(ret).context("landlock_restrict_self")?;
    Ok(())
}

/// The create preflight's copy of the shim's walk, before anything is
/// allocated: the paths `restrict_writes` will open, in its order, walked by
/// the same `walk` over the image directory instead of the sandbox root.
/// Components the image doesn't have are accepted, because an ordinary
/// create's shim makes them (`Missing::Create`); a fork's absent paths are
/// its own preflight's refusal (`checkpoint::capture::check_writable`, over
/// the image and the checkpoint together).
///
/// Returns how many entries an ordinary create's setup leaves in the
/// sandbox's upper for these paths and the `generated` files, each counted
/// once across the set, so the create can check them against the run's
/// inode quota before allocating. A path the image has in full costs nothing
/// (the shim only opens it); one the image lacks part of costs every one of
/// its components, because the shim makes the missing ones and overlayfs
/// copies the image's directories above them up first; a generated file
/// (written before the walk) costs itself and its parents. Paths on kiln's
/// /dev tmpfs aren't in the upper.
pub(crate) fn preflight(image: &OwnedFd, writable: &[PathBuf], generated: &[&str]) -> Result<u64> {
    let walked = walk(image, writable, Missing::Accept, generated)?;
    let mut upper = std::collections::BTreeSet::new();
    let mut add = |path: &str| {
        // "/a/b/c" leaves "/a", "/a/b" and "/a/b/c" in the upper.
        upper.extend(path.match_indices('/').skip(1).map(|(end, _)| path[..end].to_owned()));
        upper.insert(path.to_owned());
    };
    for (dir, path, _) in &walked {
        let text = path.to_str().context("--writable paths must be valid UTF-8")?;
        if dir.is_none() && place(text, generated)? == Place::Image {
            add(text);
        }
    }
    for file in generated {
        add(*file);
    }
    Ok(upper.len() as u64)
}

/// What the walk does with a component that doesn't exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Missing {
    /// Make it (an ordinary create's shim).
    Create,
    /// Fail (the shim of a sandbox restored from a checkpoint).
    Refuse,
    /// Stop here and accept the path (the preflight over the image, standing
    /// in for `Create`).
    Accept,
}

/// What a walked directory's Landlock rule grants: writes to the existing
/// files in /dev, or everything beneath a writable directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope { DevFiles, Writable }

/// The one walk of a read-only root's writable set that both the shim
/// (`restrict_writes`) and the create preflight (`preflight`) run, so they
/// can't disagree about a path: /dev, then `DEFAULT_WRITABLE`, then
/// `writable`, each through `writable_dir`. Each entry is the opened
/// directory (`None` where `Missing::Accept` stopped), its path and scope.
fn walk<'a>(root: &OwnedFd, writable: &'a [PathBuf], missing: Missing, generated: &[&str])
    -> Result<Vec<(Option<OwnedFd>, &'a Path, Scope)>> {
    let dev = std::iter::once((Path::new(crate::protected::DEV), Scope::DevFiles));
    let rest = DEFAULT_WRITABLE.iter().map(Path::new).chain(writable.iter().map(PathBuf::as_path));
    // /dev exists in every sandbox (kiln's own tmpfs); it's never created.
    dev.chain(rest.map(|p| (p, Scope::Writable)))
        .map(|(path, scope)| {
            let missing = if scope == Scope::DevFiles && missing != Missing::Accept { Missing::Refuse } else { missing };
            Ok((writable_dir(root, path, missing, generated)?, path, scope))
        })
        .collect()
}

/// Linux's limit on one path component (NAME_MAX).
const NAME_MAX: usize = 255;

/// Where a writable path lies once kiln has set up the sandbox's root
/// (container.rs `init`): in the image's tree (the overlay), or in the /dev
/// tmpfs kiln mounts over it (`setup_dev`), which the image doesn't show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Place { Image, DevTmpfs }

/// Refuses a writable path over a filesystem kiln mounts itself or through a
/// file it writes itself, the same rule as kilnd's writable-path validator:
/// `/proc` and `/sys` and everything under them (procfs at `/proc` and a
/// read-only cgroup2 at `/sys/fs/cgroup`, container.rs `init`), anything
/// under `/dev` but `/dev/shm` (a 0755 tmpfs owned by host root, which
/// sandbox root can't create in; `/dev/shm` is a 1777 tmpfs, `setup_dev`),
/// and a `generated` file (`/etc/resolv.conf` with DNS) or anything under
/// it. Component-wise, so `/procx` and `/system` are ordinary paths.
fn place(path: &str, generated: &[&str]) -> Result<Place> {
    let mut parts = path[1..].split('/');
    let place = match parts.next() {
        Some("proc" | "sys") => None,
        Some("dev") => matches!(parts.next(), None | Some("shm")).then_some(Place::DevTmpfs),
        _ => Some(Place::Image),
    };
    let Some(place) = place else { bail!("invalid --writable path {path:?}: kiln mounts its own filesystem there") };
    let under = |file: &str| path.strip_prefix(file).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
    if let Some(file) = generated.iter().find(|file| under(file)) {
        bail!("invalid --writable path {path:?}: kiln writes {file} there as a file");
    }
    Ok(place)
}

/// Equivalent to a RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
/// RESOLVE_NO_MAGICLINKS openat2 walk, with mkdirat for missing components
/// when `missing` is `Create`. Each opened parent is retained until its child
/// is open; pathname swaps cannot redirect a later component outside the
/// root. Every existing component must be a directory reached without
/// following a symlink: a symlink or a regular file anywhere on the path
/// refuses it. Returns `None` only where `Missing::Accept` stopped: at the
/// first absent component, or at once for a path on kiln's /dev tmpfs.
pub(crate) fn writable_dir(root: &OwnedFd, path: &Path, missing: Missing, generated: &[&str])
    -> Result<Option<OwnedFd>> {
    crate::validation::validate_writable_paths(&[path.to_owned()])?;
    let text = path.to_str().context("--writable paths must be valid UTF-8")?;
    #[cfg(test)]
    tests::WALKED.with(|w| w.borrow_mut().push((text.to_owned(), missing)));
    let place = place(text, generated)?;
    // A name the kernel can't hold fails the shim's openat or mkdirat even
    // where the preflight stops early, so it's refused up front for both.
    if text[1..].split('/').any(|component| component.len() > NAME_MAX) {
        bail!("invalid --writable path {path:?}: a component is longer than {NAME_MAX} bytes");
    }
    if place == Place::DevTmpfs && missing == Missing::Accept {
        return Ok(None);
    }
    let duplicate = unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    let mut dir = unsafe { OwnedFd::from_raw_fd(Errno::result(duplicate).context("duplicate root fd")?) };
    for component in text.as_bytes()[1..].split(|byte| *byte == b'/') {
        let component = CString::new(component)?;
        let open = || unsafe { libc::openat(dir.as_raw_fd(), component.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
        let mut fd = open();
        if fd < 0 && Errno::last() == Errno::ENOENT {
            match missing {
                Missing::Accept => return Ok(None),
                Missing::Refuse => {}
                Missing::Create => {
                    let made = unsafe { libc::mkdirat(dir.as_raw_fd(), component.as_ptr(), 0o755) };
                    if made < 0 && Errno::last() != Errno::EEXIST {
                        return Err(Errno::last()).with_context(|| format!("create writable {}", path.display()));
                    }
                    fd = open();
                }
            }
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
    Ok(Some(dir))
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
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::os::unix::fs::symlink;

    thread_local! {
        /// Every `writable_dir` call on this thread: the path and the mode.
        pub(crate) static WALKED: RefCell<Vec<(String, Missing)>> = const { RefCell::new(Vec::new()) };
    }

    fn root_fd(path: &Path) -> OwnedFd {
        File::options().read(true).custom_flags(libc::O_PATH | libc::O_DIRECTORY)
            .open(path).unwrap().into()
    }

    fn scratch(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kiln-writable-{tag}-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn writable_walk_refuses_symlinks_root_and_magic_links() {
        let scratch = scratch("links");
        fs::create_dir(scratch.join("etc")).unwrap();
        symlink("/", scratch.join("root-link")).unwrap();
        symlink("/etc", scratch.join("etc-link")).unwrap();
        let root = root_fd(&scratch);
        for path in ["/", "/root-link", "/root-link/etc", "/etc-link", "/etc-link/must-not-create"] {
            assert!(writable_dir(&root, Path::new(path), Missing::Create, &[]).is_err(), "{path}");
        }
        writable_dir(&root, Path::new("/new/nested"), Missing::Create, &[]).unwrap().unwrap();
        assert!(scratch.join("new/nested").is_dir());
        let host_root = root_fd(Path::new("/"));
        assert!(writable_dir(&host_root, Path::new("/proc/self/root"), Missing::Refuse, &[]).is_err());
        fs::remove_dir_all(scratch).unwrap();
    }

    /// A tree shaped like the default Alpine image where writable paths care:
    /// its symlinked parents (`/var/run -> ../run`, `/var/lock`, `/etc/mtab`,
    /// `/etc/os-release`, `/bin/sh`) and a regular-file parent (`/etc/passwd`).
    fn alpine_like(tag: &str) -> PathBuf {
        let dir = scratch(tag);
        for sub in ["bin", "dev", "etc", "root", "run", "tmp", "usr/lib", "var/cache"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        fs::write(dir.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n").unwrap();
        fs::write(dir.join("usr/lib/os-release"), "ID=alpine\n").unwrap();
        fs::write(dir.join("bin/busybox"), "").unwrap();
        for (link, target) in [("var/run", "../run"), ("var/lock", "../run/lock"), ("etc/mtab", "../proc/mounts"),
            ("etc/os-release", "../usr/lib/os-release"), ("bin/sh", "/bin/busybox")] {
            symlink(target, dir.join(link)).unwrap();
        }
        dir
    }

    /// Paths both walks refuse, with an Alpine-like image under the sandbox.
    fn refused() -> Vec<String> {
        let mut paths: Vec<String> = [
            // A symlinked or regular-file parent in the image (the adversarial
            // review's /var/run and /etc/passwd findings).
            "/var/run/x", "/var/lock/x", "/etc/passwd/x", "/etc/os-release/x", "/bin/sh/x", "/etc/mtab/x",
            // The links and the file themselves.
            "/var/run", "/etc/passwd", "/bin/sh",
            // Over kiln's own mounts.
            "/proc", "/proc/x", "/sys", "/sys/x", "/sys/fs/cgroup/x", "/dev/x", "/dev/null", "/dev/shmx",
            // Through the DNS file kiln writes (GENERATED).
            "/etc/resolv.conf", "/etc/resolv.conf/x",
            // Lexically invalid (validation.rs).
            "/tmp/../etc",
        ].map(String::from).to_vec();
        // One byte past the longest name the kernel holds, under an existing
        // parent and under one the shim would create.
        paths.push(format!("/tmp/{}", "a".repeat(NAME_MAX + 1)));
        paths.push(format!("/new/{}", "a".repeat(NAME_MAX + 1)));
        paths
    }

    /// Paths both walks accept; the shim's makes those the image lacks.
    fn accepted() -> Vec<String> {
        let mut paths: Vec<String> = [
            // Ordinary image directories, and kiln's /dev tmpfs and its /dev/shm.
            "/tmp/x", "/etc", "/var", "/var/cache", "/run/x", "/dev", "/dev/shm", "/dev/shm/x",
            // Not yet in the image.
            "/workspace/new/deep", "/var/new", "/devx", "/procx", "/system",
        ].map(String::from).to_vec();
        paths.push(format!("/tmp/{}", "a".repeat(NAME_MAX)));
        paths.push(format!("/new/{}", "a".repeat(NAME_MAX)));
        paths
    }

    const GENERATED: [&str; 1] = [crate::protected::RESOLV_CONF];

    /// The preflight over the image refuses exactly what the shim's walk over
    /// the same tree refuses, before anything is allocated.
    #[test]
    fn preflight_refuses_what_the_shim_walk_refuses() {
        let image = alpine_like("preflight-image");
        let image_fd = root_fd(&image);
        for path in refused() {
            let writable = [PathBuf::from(&path)];
            let error = preflight(&image_fd, &writable, &GENERATED).expect_err(&path);
            let sandbox = alpine_like("refused-sandbox");
            let shim = walk(&root_fd(&sandbox), &writable, Missing::Create, &GENERATED);
            assert!(shim.is_err(), "{path}: the shim walk accepts what the preflight refused ({error:#})");
            fs::remove_dir_all(sandbox).unwrap();
        }
        for path in accepted() {
            let writable = [PathBuf::from(&path)];
            preflight(&image_fd, &writable, &GENERATED).unwrap_or_else(|e| panic!("{path}: {e:#}"));
            let sandbox = alpine_like("accepted-sandbox");
            let opened = walk(&root_fd(&sandbox), &writable, Missing::Create, &GENERATED)
                .unwrap_or_else(|e| panic!("{path}: the preflight accepted what the shim walk refuses: {e:#}"));
            assert!(opened.iter().all(|(dir, _, _)| dir.is_some()), "{path}");
            assert!(sandbox.join(&path[1..]).is_dir(), "{path}");
            fs::remove_dir_all(sandbox).unwrap();
        }
        // Without DNS, /etc/resolv.conf is an ordinary path the shim creates.
        preflight(&image_fd, &[PathBuf::from("/etc/resolv.conf/x")], &[]).unwrap();
        // The preflight never creates anything in the image.
        assert!(!image.join("workspace").exists() && !image.join("var/new").exists());
        fs::remove_dir_all(image).unwrap();
    }

    /// Every directory under `root`, as "/a/b", without following symlinks.
    fn directories(root: &Path) -> std::collections::BTreeSet<String> {
        let mut found = std::collections::BTreeSet::new();
        let mut pending = vec![String::new()];
        while let Some(at) = pending.pop() {
            for entry in fs::read_dir(root.join(at.trim_start_matches('/'))).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    let path = format!("{at}/{}", entry.file_name().to_str().unwrap());
                    pending.push(path.clone());
                    found.insert(path);
                }
            }
        }
        found
    }

    /// The preflight counts what the shim's walk leaves in the upper, once
    /// across the set: every component of a path the image lacks part of
    /// (made, or copied up by overlayfs above what's made) and each generated
    /// file with its parents. What the walk only opens, and kiln's /dev
    /// tmpfs, cost nothing.
    #[test]
    fn preflight_counts_what_the_shim_walk_leaves_in_the_upper() {
        let image = alpine_like("count-image");
        let image_fd = root_fd(&image);
        let count = |paths: &[&str], generated: &[&str]| {
            preflight(&image_fd, &paths.iter().map(PathBuf::from).collect::<Vec<_>>(), generated).unwrap()
        };
        // The image has /tmp and /root, but not /workspace.
        assert_eq!(count(&[], &[]), 1);
        assert_eq!(count(&[], &GENERATED), 1 + 2, "/etc and /etc/resolv.conf");
        assert_eq!(count(&["/etc", "/var/cache", "/tmp", "/dev/shm/x/y"], &[]), 1);
        assert_eq!(count(&["/var/cache/a/b"], &[]), 1 + 4, "/var and /var/cache are copied up");
        assert_eq!(count(&["/new/a/b", "/new/a", "/new/c", "/new/a/b"], &[]), 1 + 4);
        assert_eq!(count(&["/workspace/x", "/workspace"], &[]), 2);
        assert_eq!(count(&["/etc/new"], &GENERATED), 1 + 3);
        // The 2026-11-22 review's set: 16 paths of 512 one-byte components
        // under top-level names the image lacks.
        let deep: Vec<String> = ('b'..='q').map(|top| format!("/{top}{}", "/a".repeat(511))).collect();
        let deep: Vec<&str> = deep.iter().map(String::as_str).collect();
        assert_eq!(count(&deep, &[]), 1 + 16 * 512);

        // The shim's walk over the same tree makes the missing components;
        // with the image's directories above them, which overlayfs copies up
        // first, that is the count (kiln's /dev tmpfs aside).
        for set in [&["/var/cache/a/b", "/new/a/b", "/new/c", "/etc", "/tmp/x"][..], &deep[..]] {
            let sandbox = alpine_like("count-sandbox");
            let before = directories(&sandbox);
            walk(&root_fd(&sandbox), &set.iter().map(PathBuf::from).collect::<Vec<_>>(), Missing::Create, &[]).unwrap();
            let made: Vec<String> = directories(&sandbox).difference(&before)
                .filter(|path| !path.starts_with("/dev/")).cloned().collect();
            let copied: std::collections::BTreeSet<&str> = made.iter()
                .flat_map(|path| path.match_indices('/').skip(1).map(|(end, _)| &path[..end]))
                .filter(|parent| before.contains(*parent)).collect();
            assert_eq!((made.len() + copied.len()) as u64, count(set, &[]), "a set of {} paths", set.len());
            fs::remove_dir_all(sandbox).unwrap();
        }
        fs::remove_dir_all(image).unwrap();
    }

    /// The default scratch directories are walked by the preflight too, so an
    /// image whose `/tmp` is a symlink is refused before allocation.
    #[test]
    fn preflight_walks_the_default_writable_directories() {
        let image = alpine_like("defaults");
        fs::remove_dir(image.join("tmp")).unwrap();
        symlink("var/cache", image.join("tmp")).unwrap();
        assert!(preflight(&root_fd(&image), &[], &[]).is_err());
        fs::remove_dir_all(image).unwrap();
    }

    /// One walk, two callers: the preflight and the shim's `restrict_writes`
    /// visit the same paths in the same order through `writable_dir`, and
    /// differ only in what a missing component means.
    #[test]
    fn preflight_and_the_shim_share_one_walk() {
        let image = alpine_like("shared-image");
        let writable = vec![PathBuf::from("/var/cache/data"), PathBuf::from("/workspace/out")];
        WALKED.with(|w| w.borrow_mut().clear());
        preflight(&root_fd(&image), &writable, &GENERATED).unwrap();
        let preflight_walk = WALKED.with(|w| w.take());

        let sandbox = alpine_like("shared-sandbox");
        let root = root_fd(&sandbox);
        // On its own thread: as root on Linux 6.2+ this really restricts that
        // thread, and the restriction ends with it.
        let (shim_walk, _) = std::thread::scope(|scope| scope.spawn(|| {
            let result = restrict_writes_under(&root, &writable, true, &GENERATED);
            (WALKED.with(|w| w.take()), result.map_err(|e| format!("{e:#}")))
        }).join().unwrap());

        let paths = |walk: &[(String, Missing)]| walk.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>();
        assert_eq!(paths(&preflight_walk), ["/dev", "/tmp", "/root", "/workspace", "/dev/shm", "/var/cache/data",
            "/workspace/out"]);
        assert_eq!(paths(&shim_walk), paths(&preflight_walk));
        assert!(preflight_walk.iter().all(|(_, m)| *m == Missing::Accept));
        assert_eq!(shim_walk[0].1, Missing::Refuse, "/dev is never created");
        assert!(shim_walk[1..].iter().all(|(_, m)| *m == Missing::Create));
        assert!(sandbox.join("var/cache/data").is_dir() && !image.join("var/cache/data").exists());
        fs::remove_dir_all(image).unwrap();
        fs::remove_dir_all(sandbox).unwrap();
    }
}
