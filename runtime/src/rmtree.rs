//! Emptying a directory tree with a fixed number of open descriptors, at any
//! depth.
//!
//! `std::fs::remove_dir_all` holds one descriptor per level, so a tree deeper
//! than the soft `RLIMIT_NOFILE` (1024 under systemd) makes it fail with
//! EMFILE partway down. A sandbox can build such a tree in its own upper
//! (kiln security review round 2, finding B), and the inode quota bounds its
//! depth only at about a million levels, so removal can't refuse a deep tree.
//!
//! This walk keeps at most `WINDOW` directories open below the top one. Going
//! deeper, it closes the oldest; coming back up past the window, it reopens
//! the parent as `..` of the child it still holds and checks that it is the
//! directory (device and inode) it went down through. It never builds a path
//! (a deep tree's paths exceed PATH_MAX): every call is relative to a held
//! descriptor. It never follows a symlink: non-directories, symlinks included,
//! are unlinked with `unlinkat`, and directories are opened with
//! `O_NOFOLLOW | O_DIRECTORY`. It never crosses into another mount: `rmdir`
//! of a mount point fails with EBUSY, and a directory that opens on another
//! device or mount is refused, all as errors; nothing is unmounted.
//!
//! Memory is 24 bytes per level of the current path (its inode, a resume
//! offset and the descriptor slot), so about 24 MiB at the deepest tree
//! kilnd's largest disk allows.

use std::ffi::CStr;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Directories held open at once below the top one. The walk's peak is this
/// plus the top, its duplicate and one `..` being reopened: well inside a
/// soft limit of 64.
pub(crate) const WINDOW: usize = 32;

/// Called with each entry's name just before the walk removes it; an error
/// stops the walk and is returned. Production passes one that does nothing;
/// tests inject failures with it.
pub(crate) type Hook<'a> = &'a mut dyn FnMut(&CStr) -> io::Result<()>;

/// One directory on the path from the top down to the one being emptied.
struct Level {
    /// Open while within the window (always for the top).
    fd: Option<OwnedFd>,
    ino: u64,
    /// Where the next scan of this directory starts: 0, or the offset just
    /// before the subdirectory the walk went down into.
    pos: i64,
}

/// Device, inode and mount ID of an open directory (the mount ID is `None`
/// when the kernel doesn't report one).
fn identity(fd: RawFd) -> io::Result<(u64, u64, Option<u64>)> {
    let mut st = unsafe { std::mem::zeroed::<libc::statx>() };
    // SAFETY: AT_EMPTY_PATH statx of an open descriptor into a valid buffer.
    let r = unsafe { libc::statx(fd, c"".as_ptr(), libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        libc::STATX_INO | libc::STATX_MNT_ID, &mut st) };
    if r != 0 { return Err(io::Error::last_os_error()); }
    let dev = libc::makedev(st.stx_dev_major, st.stx_dev_minor);
    let mnt = (st.stx_mask & libc::STATX_MNT_ID != 0).then_some(st.stx_mnt_id);
    Ok((dev, st.stx_ino, mnt))
}

fn open_dir_at(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: openat relative to an open directory; the result is owned.
    let fd = unsafe { libc::openat(dir, name.as_ptr(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn errno(e: &io::Error) -> i32 { e.raw_os_error().unwrap_or(0) }

fn context(e: io::Error, what: &str, name: &CStr, depth: usize) -> io::Error {
    io::Error::new(e.kind(), format!("{what} {name:?} at depth {depth}: {e}"))
}

enum Outcome { Removed, NotEmpty }

/// Removes one entry of `dir`: a non-directory (symlinks included) with
/// `unlinkat`, a directory with `rmdir` if it's empty.
fn remove_entry(dir: RawFd, name: &CStr, d_type: u8, hook: &mut Hook) -> io::Result<Outcome> {
    hook(name)?;
    let is_dir = match d_type {
        libc::DT_DIR => true,
        libc::DT_UNKNOWN => {
            let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
            // SAFETY: fstatat of a name in an open directory, not following.
            if unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
                let e = io::Error::last_os_error();
                return if errno(&e) == libc::ENOENT { Ok(Outcome::Removed) } else { Err(e) };
            }
            st.st_mode & libc::S_IFMT == libc::S_IFDIR
        }
        _ => false,
    };
    if !is_dir {
        // SAFETY: unlinkat of a name in an open directory.
        if unsafe { libc::unlinkat(dir, name.as_ptr(), 0) } == 0 { return Ok(Outcome::Removed); }
        let e = io::Error::last_os_error();
        match errno(&e) {
            libc::ENOENT => return Ok(Outcome::Removed),
            libc::EISDIR => {} // replaced by a directory since it was listed
            _ => return Err(e),
        }
    }
    // SAFETY: as above.
    if unsafe { libc::unlinkat(dir, name.as_ptr(), libc::AT_REMOVEDIR) } == 0 { return Ok(Outcome::Removed); }
    let e = io::Error::last_os_error();
    match errno(&e) {
        libc::ENOENT => Ok(Outcome::Removed),
        libc::ENOTEMPTY | libc::EEXIST => Ok(Outcome::NotEmpty),
        _ => Err(e),
    }
}

/// Removes everything in the directory `top` except the top-level names in
/// `keep`, with a bounded number of descriptors (see the module comment).
/// `top` itself stays. Any error stops the walk and is returned, with what
/// has been removed so far gone.
pub(crate) fn empty_dir(top: &OwnedFd, keep: &[&CStr], mut hook: Hook) -> io::Result<()> {
    let (dev, ino, mnt) = identity(top.as_raw_fd())?;
    let mut stack = vec![Level { fd: Some(top.try_clone()?), ino, pos: 0 }];
    // A directory that a scan from its start found empty, whose rmdir must
    // now succeed; another ENOTEMPTY for it would loop forever.
    let mut emptied: Option<u64> = None;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let depth = stack.len() - 1;
        let level = stack.last_mut().expect("the top level is never popped");
        let fd = level.fd.as_ref().expect("the deepest level is always open").as_raw_fd();
        let start = level.pos;
        // SAFETY: lseek on an open directory to an offset getdents returned.
        if unsafe { libc::lseek(fd, start, libc::SEEK_SET) } < 0 { return Err(io::Error::last_os_error()); }
        let mut cursor = start;
        let mut below: Option<i64> = None;
        'scan: loop {
            // SAFETY: getdents64 into a buffer of the length passed.
            let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
            if n < 0 { return Err(io::Error::last_os_error()); }
            if n == 0 { break; }
            let mut at = 0;
            while at < n as usize {
                // struct linux_dirent64: ino, off, reclen, type, NUL-terminated name.
                let ino = u64::from_ne_bytes(buf[at..at + 8].try_into().unwrap());
                let off = i64::from_ne_bytes(buf[at + 8..at + 16].try_into().unwrap());
                let reclen = u16::from_ne_bytes(buf[at + 16..at + 18].try_into().unwrap()) as usize;
                let d_type = buf[at + 18];
                let name = CStr::from_bytes_until_nul(&buf[at + 19..at + reclen])
                    .map_err(|_| io::Error::other("malformed directory entry"))?;
                at += reclen;
                let skip = name == c"." || name == c".." || (depth == 0 && keep.contains(&name));
                if !skip {
                    match remove_entry(fd, name, d_type, &mut hook).map_err(|e| context(e, "remove", name, depth))? {
                        Outcome::Removed => {}
                        Outcome::NotEmpty if emptied == Some(ino) => {
                            return Err(context(io::Error::from_raw_os_error(libc::ENOTEMPTY), "remove", name, depth));
                        }
                        Outcome::NotEmpty => {
                            // Go down into it; this scan resumes just before it.
                            #[cfg(test)]
                            tests::before_open(name);
                            let child = open_dir_at(fd, name).map_err(|e| context(e, "open", name, depth))?;
                            let (child_dev, child_ino, child_mnt) = identity(child.as_raw_fd())?;
                            if child_dev != dev || (mnt.is_some() && child_mnt.is_some() && child_mnt != mnt) {
                                return Err(context(io::Error::other("another mount; refusing to cross it"),
                                    "remove", name, depth));
                            }
                            below = Some(cursor);
                            stack.push(Level { fd: Some(child), ino: child_ino, pos: 0 });
                            break 'scan;
                        }
                    }
                }
                cursor = off;
            }
        }
        if let Some(before) = below {
            stack[depth].pos = before;
            emptied = None;
            if stack.len() > WINDOW + 1 {
                let oldest = stack.len() - 1 - WINDOW;
                stack[oldest].fd = None;
            }
            continue;
        }
        if start != 0 {
            // Offsets can shift as entries go on some filesystems, so a scan
            // that resumed partway is followed by one from the start.
            stack[depth].pos = 0;
            continue;
        }
        // A scan from the start removed everything left: this level is done.
        if depth == 0 { return Ok(()); }
        let child = stack.pop().expect("depth > 0");
        let parent = stack.last_mut().expect("depth > 0");
        if parent.fd.is_none() {
            let child_fd = child.fd.as_ref().expect("the deepest level is always open").as_raw_fd();
            let up = open_dir_at(child_fd, c"..").map_err(|e| context(e, "reopen", c"..", depth))?;
            let (up_dev, up_ino, _) = identity(up.as_raw_fd())?;
            if up_dev != dev || up_ino != parent.ino {
                return Err(context(io::Error::other("moved during removal"), "reopen", c"..", depth));
            }
            parent.fd = Some(up);
        }
        emptied = Some(child.ino);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    pub(crate) fn scratch(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("kiln-rmtree-{tag}-{}-{n}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        dir
    }

    pub(crate) fn open(path: &Path) -> OwnedFd {
        use std::os::unix::fs::OpenOptionsExt;
        fs::File::options().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path).unwrap().into()
    }

    /// Makes a chain of `depth` directories named `d` under `dir`, one
    /// descriptor at a time (its paths exceed PATH_MAX), with a file at the
    /// bottom and, every `every` levels, a sibling directory holding a file
    /// so that a scan has to resume after coming back up.
    pub(crate) fn chain(dir: &Path, depth: usize, every: usize) {
        let mut at = open(dir);
        let mkfile = |at: &OwnedFd, name: &CStr| {
            // SAFETY: openat of a new file in an open directory.
            let fd = unsafe { libc::openat(at.as_raw_fd(), name.as_ptr(), libc::O_CREAT | libc::O_EXCL
                | libc::O_WRONLY | libc::O_CLOEXEC, 0o644) };
            assert!(fd >= 0, "{}", io::Error::last_os_error());
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
        };
        for level in 0..depth {
            if level % every == every - 1 {
                assert_eq!(unsafe { libc::mkdirat(at.as_raw_fd(), c"e".as_ptr(), 0o755) }, 0);
                let side = open_dir_at(at.as_raw_fd(), c"e").unwrap();
                mkfile(&side, c"f");
            }
            assert_eq!(unsafe { libc::mkdirat(at.as_raw_fd(), c"d".as_ptr(), 0o755) }, 0,
                "{}", io::Error::last_os_error());
            at = open_dir_at(at.as_raw_fd(), c"d").unwrap();
        }
        mkfile(&at, c"bottom");
    }

    fn no_hook() -> impl FnMut(&CStr) -> io::Result<()> { |_| Ok(()) }

    type OpenHook = Option<Box<dyn FnMut(&CStr)>>;

    thread_local! {
        /// What `before_open` runs on this test's thread.
        static BEFORE_OPEN: std::cell::RefCell<OpenHook> = const { std::cell::RefCell::new(None) };
    }

    /// Called by the walk just before it opens a directory it found not
    /// empty, so a test can swap that directory the way a racing writer would.
    pub(super) fn before_open(name: &CStr) {
        BEFORE_OPEN.with(|hook| if let Some(hook) = hook.borrow_mut().as_mut() { hook(name) });
    }

    /// The `..` reopen checks what it reopened (the adversarial review's L2):
    /// below the descriptor window, a held directory moved out of the tree
    /// (into `outside/victim`, with a fresh directory put in its place) makes
    /// the climb back up past the window refuse with an error, and nothing
    /// in `outside/victim` is removed. Without the check the walk would
    /// empty `victim`, the moved directory's new parent.
    #[test]
    fn a_held_directory_moved_out_of_the_tree_is_refused_on_the_way_up() {
        let root = scratch("moved");
        let tree = root.join("tree");
        // WINDOW + 1 levels below the top: the climb reopens only level 1,
        // as `..` of level 2.
        let bottom = (0..=WINDOW).fold(tree.clone(), |dir, _| dir.join("d"));
        fs::create_dir_all(&bottom).unwrap();
        fs::write(bottom.join("bottom"), "x").unwrap();
        let victim = root.join("outside/victim");
        fs::create_dir_all(&victim).unwrap();
        fs::write(victim.join("keep"), "keep").unwrap();
        let level2 = tree.join("d/d");
        let mut moved = false;
        let mut hook = |name: &CStr| -> io::Result<()> {
            if name == c"bottom" && !moved {
                moved = true;
                fs::rename(&level2, victim.join("moved"))?;
                fs::create_dir(&level2)?;
            }
            Ok(())
        };
        let error = empty_dir(&open(&tree), &[], &mut hook).unwrap_err();
        assert!(moved);
        assert!(error.to_string().contains("moved during removal"), "{error}");
        assert_eq!(fs::read_to_string(victim.join("keep")).unwrap(), "keep");
        fs::remove_dir_all(root).unwrap();
    }

    /// The walk opens a directory without following a symlink (the
    /// adversarial review's L2): a directory swapped for a symlink to one
    /// outside the tree between its failed `rmdir` and the walk's open makes
    /// the open fail, and the outside directory keeps its contents. Without
    /// `O_NOFOLLOW` the walk would empty it.
    #[test]
    fn a_directory_swapped_for_a_symlink_before_its_open_is_not_followed() {
        let root = scratch("swap");
        let tree = root.join("tree");
        fs::create_dir_all(tree.join("x/target")).unwrap();
        fs::write(tree.join("x/target/f"), "x").unwrap();
        let outside = root.join("outside");
        fs::create_dir_all(outside.join("inner")).unwrap();
        fs::write(outside.join("inner/file"), "keep").unwrap();
        let (target, aside) = (tree.join("x/target"), root.join("aside"));
        let swap_outside = outside.clone();
        BEFORE_OPEN.with(|hook| *hook.borrow_mut() = Some(Box::new(move |name: &CStr| {
            if name == c"target" && !aside.exists() {
                fs::rename(&target, &aside).unwrap();
                symlink(&swap_outside, &target).unwrap();
            }
        })));
        let result = empty_dir(&open(&tree), &[], &mut no_hook());
        BEFORE_OPEN.with(|hook| *hook.borrow_mut() = None);
        assert!(root.join("aside").exists(), "the hook didn't run");
        assert_eq!(fs::read_to_string(outside.join("inner/file")).unwrap(), "keep");
        if let Err(error) = result {
            assert!(error.to_string().contains("open \"target\""), "{error}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empties_a_tree_and_keeps_only_the_named_top_entries() {
        let root = scratch("keep");
        fs::write(root.join("keep-me"), "x").unwrap();
        fs::create_dir_all(root.join("a/b/c")).unwrap();
        fs::write(root.join("a/b/c/f"), "x").unwrap();
        fs::write(root.join("a/g"), "x").unwrap();
        fs::create_dir(root.join("empty")).unwrap();
        // A nested name equal to a kept one isn't kept.
        fs::write(root.join("a/keep-me"), "x").unwrap();
        // Wider than one getdents buffer, so a scan spans several reads.
        fs::create_dir(root.join("wide")).unwrap();
        for i in 0..3000 { fs::create_dir(root.join(format!("wide/{i:0>200}"))).unwrap(); }
        chain(&root.join("a/b"), 3 * WINDOW + 5, WINDOW - 3);
        empty_dir(&open(&root), &[c"keep-me"], &mut no_hook()).unwrap();
        let left: Vec<_> = fs::read_dir(&root).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, ["keep-me"]);
        fs::remove_dir_all(root).unwrap();
    }

    /// A symlink is unlinked, never followed: the directory and the file it
    /// points to, outside the tree, survive.
    #[test]
    fn a_symlink_is_unlinked_not_followed() {
        let root = scratch("links");
        let outside = root.join("outside");
        fs::create_dir_all(outside.join("inner")).unwrap();
        fs::write(outside.join("inner/file"), "keep").unwrap();
        let tree = root.join("tree");
        fs::create_dir_all(tree.join("x/y")).unwrap();
        symlink(&outside, tree.join("to-dir")).unwrap();
        symlink(outside.join("inner/file"), tree.join("x/to-file")).unwrap();
        symlink("../../../outside", tree.join("x/y/relative")).unwrap();
        symlink(&outside, tree.join("x/y/.hidden")).unwrap();
        empty_dir(&open(&tree), &[], &mut no_hook()).unwrap();
        assert_eq!(fs::read_dir(&tree).unwrap().count(), 0);
        assert_eq!(fs::read_to_string(outside.join("inner/file")).unwrap(), "keep");
        fs::remove_dir_all(root).unwrap();
    }

    /// An entry the hook fails stops the walk with that error, and what
    /// hasn't been reached stays.
    #[test]
    fn the_first_error_stops_the_walk() {
        let root = scratch("hook");
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/b/victim"), "x").unwrap();
        let mut hook = |name: &CStr| if name == c"victim" { Err(io::Error::other("injected")) } else { Ok(()) };
        let error = empty_dir(&open(&root), &[], &mut hook).unwrap_err();
        assert!(error.to_string().contains("injected") && error.to_string().contains("victim"), "{error}");
        assert!(root.join("a/b/victim").exists());
        fs::remove_dir_all(root).unwrap();
    }

    /// Mode 000 directories the sandbox user left: root removes them (it
    /// bypasses permissions); anyone else gets EACCES, an error.
    #[test]
    fn mode_000_directories() {
        let root = scratch("mode000");
        fs::create_dir_all(root.join("a/locked/inner")).unwrap();
        fs::write(root.join("a/locked/inner/f"), "x").unwrap();
        fs::set_permissions(root.join("a/locked/inner"), fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(root.join("a/locked"), fs::Permissions::from_mode(0o000)).unwrap();
        let result = empty_dir(&open(&root), &[], &mut no_hook());
        if unsafe { libc::geteuid() } == 0 {
            result.unwrap();
            assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        } else {
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
            assert!(root.join("a/locked").exists());
            fs::set_permissions(root.join("a/locked"), fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(root.join("a/locked/inner"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// A mount inside the tree is an error, never emptied or unmounted (root
    /// only: it mounts a tmpfs).
    #[test]
    fn a_mount_point_is_refused() {
        if unsafe { libc::geteuid() } != 0 { eprintln!("skipped: needs root to mount"); return; }
        struct Unmount(CString);
        impl Drop for Unmount {
            fn drop(&mut self) { unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH); } }
        }
        let root = scratch("mount");
        fs::create_dir_all(root.join("a/m")).unwrap();
        let target = CString::new(root.join("a/m").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mount(c"none".as_ptr(), target.as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) },
            0, "{}", io::Error::last_os_error());
        let mounted = Unmount(target);
        fs::write(root.join("a/m/data"), "keep").unwrap();
        let error = empty_dir(&open(&root), &[], &mut no_hook()).unwrap_err();
        assert!(error.to_string().contains("\"m\""), "{error}");
        assert_eq!(fs::read_to_string(root.join("a/m/data")).unwrap(), "keep");
        drop(mounted);
        empty_dir(&open(&root), &[], &mut no_hook()).unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }
}
