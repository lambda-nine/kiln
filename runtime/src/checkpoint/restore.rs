//! Fresh-upper import: rebuilds a new, empty, unmounted upper from a
//! validated artifact, then proves the result by walking it again.
//!
//! Every entry is created exclusively relative to a held parent directory
//! descriptor (`mkdirat`, `openat(O_CREAT|O_EXCL|O_NOFOLLOW)`, `symlinkat`,
//! `mknodat`, `linkat` without following). Symlinks are created as leaves and
//! never traversed. Hardlinks only join regular files this import created
//! earlier in the same upper. File bytes are copied out of the artifact's
//! objects, never linked or cloned, and verified against their SHA-256 while
//! they are copied. Ownership goes through the destination ID map (chown
//! before chmod, xattrs after chown); a whiteout is always the fixed 0:0
//! character device. Directory times are applied after their contents.
//!
//! The upper is then walked with the capture walker: the result must equal
//! the manifest exactly, with no bookkeeping, every link count explained
//! inside the upper, and no inode shared with an artifact object.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use anyhow::{Context, Result, ensure};
use nix::errno::Errno;

use super::manifest::{Body, Manifest, Meta, components};
use super::store::Artifact;
use super::walk::{self, HashOnly, IdMap, Options, copy_and_hash, fstat, fstatat, openat, openat_mode};
use super::{Reason, reason_of, refuse};
use crate::protected::{self, Disposition};

/// Checks the checkpoint against the new sandbox's own runtime-generated
/// entries (its DNS file): the checkpoint must not hold one, and their
/// parents must be plain directories or absent. Runs before allocation.
pub fn check_generated(manifest: &Manifest, generated: &[&str]) -> Result<()> {
    for (index, e) in manifest.entries.iter().enumerate() {
        let mut absolute = vec![b'/'];
        absolute.extend_from_slice(&e.path);
        match protected::check(&absolute, e.contract_kind(), generated) {
            Ok(Disposition::Capture) => {}
            Ok(Disposition::Exclude) => return Err(refuse(Reason::LayoutUnsupported, format!("entry {index} is a \
                file this sandbox's runtime generates ({})", String::from_utf8_lossy(&absolute)))),
            Err(layout) => return Err(refuse(Reason::LayoutUnsupported, format!("entry {index}: {}", layout.0))),
        }
    }
    Ok(())
}

/// Restores `artifact` into `upper`, which must be an empty directory the
/// caller just created on the runs filesystem, then verifies it.
pub fn restore(artifact: &Artifact, upper: &OwnedFd, ids: IdMap, generated: &[&str]) -> Result<()> {
    check_generated(&artifact.manifest, generated)?;
    ensure!(walk::list_dir(upper).context("read new upper")?.is_empty(), "the new upper is not empty");
    materialize(artifact, upper, ids).map_err(full_is_too_small)?;
    verify(artifact, upper, ids, generated)
}

fn full_is_too_small(e: anyhow::Error) -> anyhow::Error {
    if reason_of(&e) == Reason::SizeLimit { refuse(Reason::DiskTooSmall, "the new sandbox's disk filled during restore") }
    else { e }
}

const OMIT: libc::timespec = libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT };

fn times(mtime: (i64, u32)) -> [libc::timespec; 2] {
    [OMIT, libc::timespec { tv_sec: mtime.0, tv_nsec: i64::from(mtime.1) }]
}

fn check(r: libc::c_int, what: &str) -> Result<()> {
    if r < 0 {
        let e = Errno::last();
        if matches!(e, Errno::ENOSPC | Errno::EDQUOT) { return Err(refuse(Reason::SizeLimit, format!("{what}: {e}"))); }
        return Err(anyhow::Error::new(e).context(what.to_owned()));
    }
    Ok(())
}

/// Owner, user xattrs, then mode: chown clears setuid and capabilities, so it
/// comes first; the opaque flag is the only overlay xattr ever written.
fn apply(fd: &OwnedFd, meta: &Meta, ids: IdMap, opaque: bool) -> Result<()> {
    let (uid, gid) = ids.to_host(meta.uid, meta.gid)?;
    // SAFETY: plain syscalls on an open descriptor this import created.
    check(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) }, "chown")?;
    for (name, value) in meta.xattrs.iter() {
        let name = CString::new(name)?;
        check(unsafe { libc::fsetxattr(fd.as_raw_fd(), name.as_ptr(), value.as_ptr().cast(), value.len(),
            libc::XATTR_CREATE) }, "set xattr")?;
    }
    if opaque {
        check(unsafe { libc::fsetxattr(fd.as_raw_fd(), c"trusted.overlay.opaque".as_ptr(), b"y".as_ptr().cast(), 1,
            libc::XATTR_CREATE) }, "set opaque")?;
    }
    check(unsafe { libc::fchmod(fd.as_raw_fd(), meta.mode) }, "chmod")
}

fn set_mtime(fd: &OwnedFd, mtime: (i64, u32)) -> Result<()> {
    // SAFETY: futimens on an open descriptor.
    check(unsafe { libc::futimens(fd.as_raw_fd(), times(mtime).as_ptr()) }, "set times")
}

fn dup(fd: &OwnedFd) -> Result<OwnedFd> { Ok(fd.try_clone()?) }

/// Opens the directory at `parts` (relative to `upper`) without following.
fn open_path(upper: &OwnedFd, parts: &[&[u8]]) -> Result<OwnedFd> {
    let mut dir = dup(upper)?;
    for part in parts {
        dir = openat(&dir, &CString::new(*part)?, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    }
    Ok(dir)
}

fn materialize(artifact: &Artifact, upper: &OwnedFd, ids: IdMap) -> Result<()> {
    let m = &artifact.manifest;
    let corrupt = |i: usize, what: &str| refuse(Reason::Corrupt, format!("entry {i}: {what}"));
    apply(upper, &m.root, ids, false)?;
    // Open directories along the current path, with the times to set once
    // their subtree is complete.
    let mut stack: Vec<(OwnedFd, (i64, u32))> = vec![(dup(upper)?, m.root.mtime)];
    let mut files: Vec<Option<(u64, u64)>> = vec![None; m.entries.len()];
    // Dirty page cache and filesystem metadata are charged to the writer's
    // memory cgroup; flushing every 512 entries or 16 MiB keeps them bounded
    // inside the worker's limit however many small, xattr-heavy files there
    // are. (Nothing is published by this: the run isn't mounted yet.)
    let mut since_sync = (0usize, 0u64);
    for (i, e) in m.entries.iter().enumerate() {
        if since_sync.0 >= 512 || since_sync.1 >= 16 << 20 {
            // SAFETY: syncfs on the new upper's open descriptor.
            check(unsafe { libc::syncfs(upper.as_raw_fd()) }, "sync the new upper")?;
            since_sync = (0, 0);
        }
        since_sync.0 += 1;
        if let Body::File { size, .. } = e.body { since_sync.1 += size; }
        let parts = components(&e.path).map_err(|w| corrupt(i, &w))?;
        while stack.len() > parts.len() {
            let (fd, mtime) = stack.pop().unwrap();
            set_mtime(&fd, mtime)?;
        }
        ensure!(stack.len() == parts.len(), corrupt(i, "parent is not a directory"));
        let parent = &stack[parts.len() - 1].0;
        let name = CString::new(*parts.last().unwrap())?;
        match &e.body {
            Body::Dir { meta, opaque } => {
                // SAFETY: mkdirat relative to a directory this import created.
                check(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) }, "create directory")?;
                let fd = openat(parent, &name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
                apply(&fd, meta, ids, *opaque)?;
                stack.push((fd, meta.mtime));
            }
            Body::File { meta, size, sha256, object } => {
                let src = artifact.object(*object, *size)?;
                let dst = openat_mode(parent, &name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, 0o600)
                    .map_err(|e| match e.downcast_ref::<Errno>() {
                        Some(Errno::ENOSPC | Errno::EDQUOT) => refuse(Reason::SizeLimit, "create file"),
                        _ => e,
                    })?;
                let digest = copy_and_hash(&src, *size, Some(&dst))?;
                ensure!(digest == *sha256, refuse(Reason::Corrupt, format!("object {object} digest mismatch")));
                apply(&dst, meta, ids, false)?;
                set_mtime(&dst, meta.mtime)?;
                let st = fstat(dst.as_raw_fd())?;
                files[i] = Some((st.st_dev, st.st_ino));
            }
            Body::Symlink { uid, gid, mtime, target } => {
                let target = CString::new(target.as_slice())?;
                let (uid, gid) = ids.to_host(*uid, *gid)?;
                // SAFETY: syscalls relative to a directory this import created;
                // the new link is never followed.
                check(unsafe { libc::symlinkat(target.as_ptr(), parent.as_raw_fd(), name.as_ptr()) }, "symlink")?;
                check(unsafe { libc::fchownat(parent.as_raw_fd(), name.as_ptr(), uid, gid, libc::AT_SYMLINK_NOFOLLOW) },
                    "chown symlink")?;
                check(unsafe { libc::utimensat(parent.as_raw_fd(), name.as_ptr(), times(*mtime).as_ptr(),
                    libc::AT_SYMLINK_NOFOLLOW) }, "set symlink times")?;
            }
            Body::HardLink { link } => {
                let first = &m.entries[*link as usize];
                let tparts = components(&first.path).map_err(|w| corrupt(i, &w))?;
                let tdir = open_path(upper, &tparts[..tparts.len() - 1])?;
                let tname = CString::new(*tparts.last().unwrap())?;
                let st = fstatat(tdir.as_raw_fd(), &tname)?;
                ensure!(st.st_mode & libc::S_IFMT == libc::S_IFREG && files[*link as usize] == Some((st.st_dev, st.st_ino)),
                    corrupt(i, "hardlink target is not the file this restore created"));
                // SAFETY: linkat between directories of this upper, not following.
                check(unsafe { libc::linkat(tdir.as_raw_fd(), tname.as_ptr(), parent.as_raw_fd(), name.as_ptr(), 0) },
                    "link")?;
            }
            Body::Whiteout => {
                // The fixed kernel whiteout; no supplied device number exists.
                // SAFETY: mknodat relative to a directory this import created.
                check(unsafe { libc::mknodat(parent.as_raw_fd(), name.as_ptr(), libc::S_IFCHR, 0) }, "whiteout")?;
            }
        }
    }
    while let Some((fd, mtime)) = stack.pop() { set_mtime(&fd, mtime)?; }
    Ok(())
}

/// Walks the restored upper and requires exactly the manifest's entries and
/// metadata, no kernel bookkeeping, and no inode shared with the artifact.
pub fn verify(artifact: &Artifact, upper: &OwnedFd, ids: IdMap, generated: &[&str]) -> Result<()> {
    let opts = Options { generated, budget: u64::MAX, ids };
    let m = &artifact.manifest;
    // Compared entry by entry as the walk produces them: no second copy.
    let walked = walk::walk_expect(upper, &opts, &m.entries, &mut HashOnly)
        .map_err(|e| refuse(Reason::Corrupt, format!("the restored upper does not validate: {e:#}")))?;
    ensure!(walked.root == m.root && walked.bookkeeping == Default::default(),
        refuse(Reason::Corrupt, "the restored upper differs from the checkpoint"));
    let mut objects = std::collections::HashSet::new();
    for e in &m.entries {
        if let Body::File { size, object, .. } = e.body {
            let st = fstat(artifact.object(object, size)?.as_raw_fd())?;
            objects.insert((st.st_dev, st.st_ino));
        }
    }
    ensure!(walked.inodes.iter().all(|i| !objects.contains(i)),
        refuse(Reason::Corrupt, "the restored upper shares an inode with the checkpoint"));
    Ok(())
}

/// Opens the merged view's directory at an absolute runtime path without
/// following any component, for scaffolding checks after the overlay mounts.
pub fn open_scaffold(root: &OwnedFd, path: &str) -> Result<OwnedFd> {
    let parts: Vec<&[u8]> = path.as_bytes().split(|b| *b == b'/').filter(|p| !p.is_empty()).collect();
    open_path(root, &parts).with_context(|| format!("runtime path {path} is not a plain directory"))
}

/// Before any privileged mount or DNS write into a merged view built from a
/// checkpoint: every mount target and the parent of every generated entry
/// must resolve, component by component and without following, to a
/// directory; a generated entry itself must be absent or a regular file.
pub fn check_scaffolding(merged: &std::path::Path, generated: &[&str]) -> Result<()> {
    let c = CString::new(merged.as_os_str().as_encoded_bytes())?;
    // SAFETY: open of the merged root, a fresh overlay mount kiln created.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    let root = unsafe { OwnedFd::from_raw_fd(Errno::result(fd).context("open merged root")?) };
    for target in protected::MOUNT_TARGETS { open_scaffold(&root, target)?; }
    for g in generated {
        let (parent, name) = g.rsplit_once('/').context("generated path")?;
        let dir = open_scaffold(&root, if parent.is_empty() { "/" } else { parent })?;
        match fstatat(dir.as_raw_fd(), &CString::new(name)?) {
            Ok(st) => ensure!(st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_nlink == 1,
                refuse(Reason::LayoutUnsupported, format!("{g} is not a plain file"))),
            Err(e) if e.downcast_ref::<Errno>() == Some(&Errno::ENOENT) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
