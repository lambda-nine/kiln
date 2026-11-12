//! The bounded, descriptor-relative walker of a raw upper layer.
//!
//! Every entry is looked up by name relative to an open parent directory with
//! `AT_SYMLINK_NOFOLLOW`, opened (directories and regular files only) with
//! `O_NOFOLLOW`, and checked to be the inode that was looked up, on the upper's
//! device and mount. Symlinks are read with `readlinkat` and never followed;
//! special files are classified from their metadata and never opened. Reads
//! use `O_NOATIME`; the walker writes nothing to the source.
//!
//! Each entry is classified against the protected-path contract and the
//! format's metadata rules. Anything the format can't represent is a typed
//! refusal; the only metadata ever left out is the kernel's own overlay
//! bookkeeping (`trusted.overlay.origin`, `impure`, `uuid`), which is counted.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{Context, Result, ensure};
use nix::errno::Errno;

use super::manifest::{Body, Entry, Meta, Xattrs};
use super::{ENTRY_ALLOWANCE, MAX_DEPTH, MAX_ENTRIES, MAX_LINK_TARGET, MAX_MANIFEST_BYTES, MAX_PATH_BYTES,
    MAX_USER_XATTRS, MAX_USER_XATTR_BYTES, Reason, refuse};
use crate::protected::{self, Disposition, Kind as Contract};
use crate::sha256::Sha256;

/// Host-to-namespace ID translation. Production uses kiln's fixed sandbox
/// range; tests map the invoking user to 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdMap { pub uid_base: u32, pub gid_base: u32, pub count: u32 }

impl IdMap {
    pub const SANDBOX: IdMap = IdMap { uid_base: crate::userns::ID_BASE, gid_base: crate::userns::ID_BASE,
        count: crate::userns::ID_COUNT };

    fn to_ns(self, uid: u32, gid: u32) -> Option<(u32, u32)> {
        let u = uid.checked_sub(self.uid_base).filter(|v| *v < self.count)?;
        let g = gid.checked_sub(self.gid_base).filter(|v| *v < self.count)?;
        Some((u, g))
    }

    pub fn to_host(self, uid: u32, gid: u32) -> Result<(u32, u32)> {
        ensure!(uid < self.count && gid < self.count, "ID outside the sandbox range");
        Ok((self.uid_base + uid, self.gid_base + gid))
    }
}

/// Counts of the excluded kernel bookkeeping xattrs, recorded in the artifact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bookkeeping { pub impure: u64, pub origin: u64, pub uuid: u64 }

/// What happens to regular-file bytes: copied into an object (capture) or
/// only hashed (verification of a restored upper).
pub trait Sink {
    /// Reads exactly `size` logical bytes from `src` and returns their SHA-256.
    fn file(&mut self, src: &OwnedFd, size: u64, object: u32) -> Result<[u8; 32]>;
}

pub struct HashOnly;
impl Sink for HashOnly {
    fn file(&mut self, src: &OwnedFd, size: u64, _: u32) -> Result<[u8; 32]> { copy_and_hash(src, size, None) }
}

pub struct Walked {
    pub root: Meta,
    pub entries: Vec<Entry>,
    pub bookkeeping: Bookkeeping,
    /// Regular-file inodes seen, for independence checks.
    pub inodes: Vec<(u64, u64)>,
}

pub struct Options<'a> {
    /// The run's generated entries (excluded, see protected.rs).
    pub generated: &'a [&'a str],
    /// The reservation R: logical blocks plus the per-entry allowance must fit.
    pub budget: u64,
    pub ids: IdMap,
}

/// The kind of entry an xattr list belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Node { Root, Dir, File, Symlink, Whiteout }

/// Sorts one entry's xattrs into user xattrs to keep, the opaque flag and
/// counted bookkeeping; everything else is refused. Kernel names appear in
/// the refusal; user names and all values never do.
pub fn classify(node: Node, xattrs: Xattrs, bk: &mut Bookkeeping, at: &str) -> Result<(Xattrs, bool)> {
    let meta = |what: &str| refuse(Reason::MetadataUnsupported, format!("{at} has {what}"));
    let mut user = Vec::new();
    let mut opaque = false;
    for (name, value) in xattrs {
        let shown = String::from_utf8_lossy(&name).into_owned();
        match (name.as_slice(), node) {
            (b"trusted.overlay.origin", Node::Dir | Node::File | Node::Symlink) => bk.origin += 1,
            (b"trusted.overlay.impure", Node::Root | Node::Dir) if value == b"y" => bk.impure += 1,
            (b"trusted.overlay.uuid", Node::Root) if value.len() == 16 => bk.uuid += 1,
            (b"trusted.overlay.opaque", Node::Root | Node::Dir) if value == b"y" => opaque = true,
            (b"trusted.overlay.opaque", _) if value == b"x" =>
                return Err(meta("an overlay xattr-whiteout marker (trusted.overlay.opaque=x)")),
            (n, _) if n.starts_with(b"trusted.overlay.overlay.") => return Err(meta(&format!("an escaped overlay xattr ({shown})"))),
            (b"trusted.overlay.redirect", _) => return Err(meta("an overlay redirect")),
            (b"trusted.overlay.metacopy", _) => return Err(meta("overlay metacopy")),
            (b"trusted.overlay.upper" | b"trusted.overlay.nlink", _) => return Err(meta(&format!("an overlay index handle ({shown})"))),
            (b"trusted.overlay.whiteout" | b"trusted.overlay.whiteouts", _) => return Err(meta("an overlay xattr whiteout")),
            (n, _) if n.starts_with(b"trusted.overlay.") => return Err(meta(&format!("an unrecognized overlay xattr form ({shown})"))),
            (n, _) if n.starts_with(b"user.overlay.") => return Err(meta("a reserved user.overlay.* xattr")),
            (n, Node::Root | Node::Dir | Node::File) if n.starts_with(b"user.") && n.len() > 5 => user.push((name, value)),
            (n, _) if n.starts_with(b"user.") => return Err(meta("a user xattr where the format has none")),
            (b"system.posix_acl_access" | b"system.posix_acl_default", _) => return Err(meta(&format!("a POSIX ACL ({shown})"))),
            (b"security.capability", _) => return Err(meta("a file capability (security.capability)")),
            // Only fixed kernel names are shown; these namespaces' other
            // names are not.
            (b"security.selinux" | b"security.ima" | b"security.evm" | b"security.apparmor", _) =>
                return Err(meta(&format!("a security xattr ({shown})"))),
            (n, _) if n.starts_with(b"security.") => return Err(meta("a security xattr")),
            (n, _) if n.starts_with(b"trusted.") => return Err(meta("a trusted xattr")),
            (n, _) if n.starts_with(b"system.") => return Err(meta("a system xattr")),
            _ => return Err(meta("an xattr in an unknown namespace")),
        }
    }
    user.sort();
    if user.len() > MAX_USER_XATTRS { return Err(meta(&format!("more than {MAX_USER_XATTRS} user xattrs"))); }
    if user.iter().map(|(n, v)| n.len() + v.len()).sum::<usize>() > MAX_USER_XATTR_BYTES {
        return Err(meta(&format!("user xattrs over {MAX_USER_XATTR_BYTES} bytes")));
    }
    Ok((user, opaque))
}

struct Group { index: u32, nlink: u64, seen: u64 }

struct Walker<'a> {
    opts: &'a Options<'a>,
    sink: &'a mut dyn Sink,
    check: &'a mut dyn FnMut() -> Result<()>,
    dev: u64,
    mnt: u64,
    entries: Vec<Entry>,
    groups: HashMap<(u64, u64), Group>,
    objects: u32,
    logical_blocks: u64,
    manifest_bytes: usize,
    bookkeeping: Bookkeeping,
    inodes: Vec<(u64, u64)>,
}

/// Walks the upper at `upper` (a directory descriptor). `check` runs every
/// 256 entries and before returning, so the caller can stop when its lease is
/// lost.
pub fn walk(upper: &OwnedFd, opts: &Options<'_>, sink: &mut dyn Sink, check: &mut dyn FnMut() -> Result<()>)
    -> Result<Walked> {
    let st = fstat(upper.as_raw_fd())?;
    ensure!(st.st_mode & libc::S_IFMT == libc::S_IFDIR, "upper is not a directory");
    let mut bookkeeping = Bookkeeping::default();
    let (xattrs, opaque) = classify(Node::Root, fd_xattrs(upper.as_raw_fd())?, &mut bookkeeping, "the upper root")?;
    protected::check(b"/", Contract::Directory { opaque }, opts.generated)?;
    let root = meta_of(&st, xattrs, opts.ids, "the upper root")?;
    let mut w = Walker { opts, sink, check, dev: st.st_dev, mnt: mount_id(upper.as_raw_fd(), None)?,
        entries: Vec::new(), groups: HashMap::new(), objects: 0, logical_blocks: 0, manifest_bytes: 0,
        bookkeeping, inodes: Vec::new() };
    w.directory(upper, &st, &mut Vec::new(), 0)?;
    for group in w.groups.values() {
        if group.seen != group.nlink {
            return Err(refuse(Reason::MetadataUnsupported, format!("entry {} has hardlinks outside the upper \
                ({} of {} names found)", group.index, group.seen, group.nlink)));
        }
    }
    (w.check)()?;
    Ok(Walked { root, entries: w.entries, bookkeeping: w.bookkeeping, inodes: w.inodes })
}

impl Walker<'_> {
    /// Admits one more entry and `bytes` more logical bytes against the
    /// entry cap and the reservation (L + 16 KiB per entry, root included).
    fn charge(&mut self, bytes: u64) -> Result<()> {
        // The root, the entries so far and this one.
        let n = self.entries.len() as u64 + 2;
        ensure!(n as usize <= MAX_ENTRIES, refuse(Reason::SizeLimit, format!("more than {MAX_ENTRIES} entries")));
        let blocks = self.logical_blocks.checked_add(bytes.div_ceil(4096).saturating_mul(4096));
        let need = blocks.and_then(|b| b.checked_add(ENTRY_ALLOWANCE.checked_mul(n)?));
        match need {
            Some(need) if need <= self.opts.budget => { self.logical_blocks = blocks.unwrap(); Ok(()) }
            _ => Err(refuse(Reason::SizeLimit, format!("the workspace exceeds the checkpoint limit of {} bytes \
                (file bytes plus {ENTRY_ALLOWANCE} bytes per entry)", self.opts.budget))),
        }
    }

    fn push(&mut self, entry: Entry) -> Result<()> {
        self.manifest_bytes = self.manifest_bytes.saturating_add(entry.to_json().encode().len() + 1);
        ensure!(self.manifest_bytes <= MAX_MANIFEST_BYTES,
            refuse(Reason::SizeLimit, format!("manifest larger than {MAX_MANIFEST_BYTES} bytes")));
        self.entries.push(entry);
        if self.entries.len().is_multiple_of(256) { (self.check)()?; }
        Ok(())
    }

    fn directory(&mut self, dir: &OwnedFd, st: &libc::stat, path: &mut Vec<u8>, depth: usize) -> Result<()> {
        for name in list_dir(dir).context("read upper directory")? {
            let at = path.len();
            if !path.is_empty() { path.push(b'/'); }
            path.extend_from_slice(&name);
            if path.len() > MAX_PATH_BYTES {
                return Err(refuse(Reason::LayoutUnsupported, format!("a path longer than {MAX_PATH_BYTES} bytes")));
            }
            self.child(dir, &name, path, depth + 1)?;
            path.truncate(at);
        }
        ensure!(unchanged(st, &fstat(dir.as_raw_fd())?),
            refuse(Reason::Io, format!("entry {} changed during capture", self.entries.len())));
        Ok(())
    }

    fn child(&mut self, dir: &OwnedFd, name: &[u8], path: &mut Vec<u8>, depth: usize) -> Result<()> {
        let index = self.entries.len() as u32;
        let at = format!("entry {index}");
        if depth > MAX_DEPTH {
            return Err(refuse(Reason::LayoutUnsupported, format!("{at} is deeper than {MAX_DEPTH} directories")));
        }
        let cname = CString::new(name)?;
        let st = fstatat(dir.as_raw_fd(), &cname)?;
        if st.st_dev != self.dev || mount_id(dir.as_raw_fd(), Some(&cname))? != self.mnt {
            return Err(refuse(Reason::LayoutUnsupported, format!("{at} crosses a mount")));
        }
        let mut absolute = Vec::with_capacity(path.len() + 1);
        absolute.push(b'/');
        absolute.extend_from_slice(path);
        let generated = self.opts.generated;
        let contract = |kind| protected::check(&absolute, kind, generated);
        let kind = st.st_mode & libc::S_IFMT;
        let linked = kind != libc::S_IFDIR && st.st_nlink > 1;
        match kind {
            libc::S_IFDIR => {
                let fd = openat(dir, &cname, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NOATIME)?;
                self.same(&fd, &st, &at)?;
                let (xattrs, opaque) = classify(Node::Dir, fd_xattrs(fd.as_raw_fd())?, &mut self.bookkeeping, &at)?;
                if contract(Contract::Directory { opaque })? == Disposition::Exclude {
                    return Err(refuse(Reason::LayoutUnsupported, format!("{at} replaces a runtime-generated file \
                        with a directory")));
                }
                self.charge(0)?;
                let meta = meta_of(&st, xattrs, self.opts.ids, &at)?;
                self.push(Entry { path: path.clone(), body: Body::Dir { meta, opaque } })?;
                self.directory(&fd, &st, path, depth)
            }
            libc::S_IFREG => {
                if linked && let Some(group) = self.groups.get_mut(&(st.st_dev, st.st_ino)) {
                    group.seen += 1;
                    let link = group.index;
                    if contract(Contract::Regular)? == Disposition::Exclude {
                        return Err(refuse(Reason::LayoutUnsupported, format!("{at} is a hardlinked runtime-generated file")));
                    }
                    self.charge(0)?;
                    return self.push(Entry { path: path.clone(), body: Body::HardLink { link } });
                }
                if contract(Contract::Regular)? == Disposition::Exclude {
                    ensure!(!linked, refuse(Reason::LayoutUnsupported, format!("{at} is a hardlinked runtime-generated file")));
                    return Ok(());
                }
                let size = st.st_size as u64;
                self.charge(size)?;
                let fd = openat(dir, &cname, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_NONBLOCK)?;
                let opened = self.same(&fd, &st, &at)?;
                let (xattrs, _) = classify(Node::File, fd_xattrs(fd.as_raw_fd())?, &mut self.bookkeeping, &at)?;
                let meta = meta_of(&st, xattrs, self.opts.ids, &at)?;
                let object = self.objects;
                let sha256 = self.sink.file(&fd, size, object)?;
                let after = fstat(fd.as_raw_fd())?;
                ensure!(unchanged(&opened, &after) && after.st_size as u64 == size,
                    refuse(Reason::Io, format!("{at} changed during capture")));
                self.objects += 1;
                self.inodes.push((st.st_dev, st.st_ino));
                if linked { self.groups.insert((st.st_dev, st.st_ino), Group { index, nlink: st.st_nlink as u64, seen: 1 }); }
                self.push(Entry { path: path.clone(), body: Body::File { meta, size, sha256, object } })
            }
            libc::S_IFLNK => {
                if contract(Contract::Symlink)? == Disposition::Exclude && !linked { return Ok(()); }
                ensure!(!linked, refuse(Reason::MetadataUnsupported, format!("{at} is a hardlinked symlink")));
                let target = readlinkat(dir, &cname, &at)?;
                classify(Node::Symlink, path_xattrs(dir, name)?, &mut self.bookkeeping, &at)?;
                let (uid, gid) = self.opts.ids.to_ns(st.st_uid, st.st_gid).ok_or_else(|| unmapped(&at))?;
                self.charge(0)?;
                self.push(Entry { path: path.clone(), body: Body::Symlink { uid, gid,
                    mtime: (st.st_mtime, st.st_mtime_nsec as u32), target } })
            }
            libc::S_IFCHR if st.st_rdev == 0 => {
                // The kernel's whiteout. Its owner, mode, times and link
                // count carry no meaning (overlayfs shares one whiteout
                // inode by hardlink, with other names in the work
                // directory); restore creates a fresh fixed form.
                classify(Node::Whiteout, path_xattrs(dir, name)?, &mut self.bookkeeping, &at)?;
                if contract(Contract::Whiteout)? == Disposition::Exclude { return Ok(()); }
                self.charge(0)?;
                self.push(Entry { path: path.clone(), body: Body::Whiteout })
            }
            other => {
                let what = match other {
                    libc::S_IFCHR => "a character device", libc::S_IFBLK => "a block device",
                    libc::S_IFIFO => "a FIFO", libc::S_IFSOCK => "a socket", _ => "an unknown file type",
                };
                // A runtime path is still checked first: its layout error is
                // the more precise refusal.
                contract(Contract::Other)?;
                Err(refuse(Reason::MetadataUnsupported, format!("{at} is {what}")))
            }
        }
    }

    /// The opened descriptor is the inode that was looked up, on our mount.
    fn same(&self, fd: &OwnedFd, looked_up: &libc::stat, at: &str) -> Result<libc::stat> {
        let opened = fstat(fd.as_raw_fd())?;
        ensure!(opened.st_dev == looked_up.st_dev && opened.st_ino == looked_up.st_ino
            && opened.st_mode == looked_up.st_mode, refuse(Reason::Io, format!("{at} was replaced during capture")));
        if mount_id(fd.as_raw_fd(), None)? != self.mnt {
            return Err(refuse(Reason::LayoutUnsupported, format!("{at} crosses a mount")));
        }
        Ok(opened)
    }
}

fn unmapped(at: &str) -> anyhow::Error {
    refuse(Reason::MetadataUnsupported, format!("{at} is owned by a host ID outside the sandbox range"))
}

fn meta_of(st: &libc::stat, xattrs: Xattrs, ids: IdMap, at: &str) -> Result<Meta> {
    let (uid, gid) = ids.to_ns(st.st_uid, st.st_gid).ok_or_else(|| unmapped(at))?;
    Ok(Meta { mode: st.st_mode & 0o7777, uid, gid, mtime: (st.st_mtime, st.st_mtime_nsec as u32), xattrs })
}

fn unchanged(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_size == b.st_size && a.st_mtime == b.st_mtime && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime && a.st_ctime_nsec == b.st_ctime_nsec
}

// ---------------------------------------------------------------------------
// File bytes

const CHUNK: usize = 64 * 1024;
static ZEROS: [u8; CHUNK] = [0; CHUNK];

/// Hashes exactly `size` logical bytes of `src` and, with `dst`, writes them
/// to the same offsets of `dst`, preserving holes (`SEEK_DATA`/`SEEK_HOLE`):
/// holes are hashed as zeros and never written. A file shorter or longer than
/// `size` is an error; so is any read past the logical length.
pub fn copy_and_hash(src: &OwnedFd, size: u64, dst: Option<&OwnedFd>) -> Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut pos = 0u64;
    let fd = src.as_raw_fd();
    ensure!(fstat(fd)?.st_size as u64 == size, refuse(Reason::Io, "a file's length differs from its record"));
    while pos < size {
        let data = match lseek(fd, pos, libc::SEEK_DATA) {
            Ok(d) => d.min(size),
            Err(Errno::ENXIO) => size,
            Err(e) => return Err(e).context("SEEK_DATA"),
        };
        hash_zeros(&mut hash, data - pos);
        pos = data;
        if pos >= size { break; }
        let hole = lseek(fd, pos, libc::SEEK_HOLE).context("SEEK_HOLE")?.min(size);
        ensure!(hole > pos, "file data map is inconsistent");
        while pos < hole {
            let want = ((hole - pos) as usize).min(CHUNK);
            // SAFETY: pread into an owned buffer of at least `want` bytes.
            let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), want, pos as libc::off_t) };
            if n < 0 {
                if Errno::last() == Errno::EINTR { continue; }
                return Err(Errno::last()).context("read file");
            }
            ensure!(n > 0, refuse(Reason::Io, "a file shrank during the copy"));
            let chunk = &buf[..n as usize];
            hash.update(chunk);
            if let Some(dst) = dst { pwrite_all(dst, chunk, pos)?; }
            pos += n as u64;
        }
    }
    // Nothing may follow the logical length.
    // SAFETY: pread of one byte into an owned buffer.
    let extra = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), 1, size as libc::off_t) };
    ensure!(extra == 0, refuse(Reason::Io, "a file grew during the copy"));
    if let Some(dst) = dst {
        Errno::result(unsafe { libc::ftruncate(dst.as_raw_fd(), size as libc::off_t) }).context("set object length")?;
    }
    Ok(hash.finish())
}

fn hash_zeros(hash: &mut Sha256, mut n: u64) {
    while n > 0 {
        let k = n.min(CHUNK as u64) as usize;
        hash.update(&ZEROS[..k]);
        n -= k as u64;
    }
}

fn lseek(fd: RawFd, at: u64, whence: i32) -> std::result::Result<u64, Errno> {
    // SAFETY: lseek on an open descriptor.
    let r = unsafe { libc::lseek(fd, at as libc::off_t, whence) };
    if r < 0 { Err(Errno::last()) } else { Ok(r as u64) }
}

fn pwrite_all(fd: &OwnedFd, mut data: &[u8], mut at: u64) -> Result<()> {
    while !data.is_empty() {
        // SAFETY: pwrite from a live slice.
        let n = unsafe { libc::pwrite(fd.as_raw_fd(), data.as_ptr().cast(), data.len(), at as libc::off_t) };
        if n < 0 {
            if Errno::last() == Errno::EINTR { continue; }
            if Errno::last() == Errno::ENOSPC || Errno::last() == Errno::EDQUOT {
                return Err(refuse(Reason::SizeLimit, "the checkpoint quota is full"));
            }
            return Err(Errno::last()).context("write");
        }
        ensure!(n > 0, "write made no progress");
        data = &data[n as usize..];
        at += n as u64;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Descriptor-relative system calls shared by capture, restore and the store

pub fn fstat(fd: RawFd) -> Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: fstat of an open descriptor into an owned struct.
    Errno::result(unsafe { libc::fstat(fd, &mut st) }).context("fstat")?;
    Ok(st)
}

pub fn fstatat(dir: RawFd, name: &CString) -> Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: a name relative to an open directory, not followed.
    Errno::result(unsafe { libc::fstatat(dir, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) }).context("stat")?;
    Ok(st)
}

/// The mount ID of `fd`, or of `name` relative to it (not following).
pub fn mount_id(fd: RawFd, name: Option<&CString>) -> Result<u64> {
    let mut st = unsafe { std::mem::zeroed::<libc::statx>() };
    let (path, flags) = match name {
        Some(n) => (n.as_ptr(), libc::AT_SYMLINK_NOFOLLOW),
        None => (c"".as_ptr(), libc::AT_EMPTY_PATH),
    };
    // SAFETY: statx relative to an open descriptor into an owned buffer.
    Errno::result(unsafe { libc::statx(fd, path, flags, libc::STATX_MNT_ID, &mut st) }).context("statx mount ID")?;
    ensure!(st.stx_mask & libc::STATX_MNT_ID != 0, "kernel did not report a mount ID");
    Ok(st.stx_mnt_id)
}

pub fn openat(dir: &OwnedFd, name: &CString, flags: i32) -> Result<OwnedFd> {
    openat_mode(dir, name, flags, 0)
}

pub fn openat_mode(dir: &OwnedFd, name: &CString, flags: i32, mode: libc::mode_t) -> Result<OwnedFd> {
    // SAFETY: openat relative to an open directory.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC, mode as libc::c_uint) };
    Ok(unsafe { OwnedFd::from_raw_fd(Errno::result(fd).context("open")?) })
}

fn readlinkat(dir: &OwnedFd, name: &CString, at: &str) -> Result<Vec<u8>> {
    let mut target = vec![0u8; MAX_LINK_TARGET + 1];
    // SAFETY: readlinkat into an owned buffer of the given length.
    let n = unsafe { libc::readlinkat(dir.as_raw_fd(), name.as_ptr(), target.as_mut_ptr().cast(), target.len()) };
    let n = Errno::result(n).context("readlink")? as usize;
    if n > MAX_LINK_TARGET {
        return Err(refuse(Reason::MetadataUnsupported, format!("{at} has a symlink target over {MAX_LINK_TARGET} bytes")));
    }
    ensure!(n > 0, "empty symlink target");
    target.truncate(n);
    Ok(target)
}

const XATTR_MAX: usize = 64 * 1024;

fn collect_xattrs(list: impl Fn(&mut [u8]) -> isize, get: impl Fn(&CString, &mut [u8]) -> isize) -> Result<Xattrs> {
    let mut names = vec![0u8; XATTR_MAX];
    let n = list(&mut names);
    if n < 0 {
        return match Errno::last() { Errno::ENOTSUP => Ok(Vec::new()), e => Err(e).context("list xattrs") };
    }
    names.truncate(n as usize);
    let mut out = Vec::new();
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        let cname = CString::new(name)?;
        let mut value = vec![0u8; XATTR_MAX];
        let n = Errno::result(get(&cname, &mut value)).context("read xattr")? as usize;
        value.truncate(n);
        out.push((name.to_vec(), value));
    }
    out.sort();
    Ok(out)
}

pub fn fd_xattrs(fd: RawFd) -> Result<Xattrs> {
    collect_xattrs(
        // SAFETY: fd is open; buffers are owned and sized.
        |buf| unsafe { libc::flistxattr(fd, buf.as_mut_ptr().cast(), buf.len()) },
        |name, buf| unsafe { libc::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) })
}

/// l*xattr through the held directory's /proc/self/fd path: only the final
/// component is looked up, and it is not followed.
pub fn path_xattrs(dir: &OwnedFd, name: &[u8]) -> Result<Xattrs> {
    let path = proc_path(dir, name)?;
    collect_xattrs(
        // SAFETY: NUL-terminated path; buffers are owned and sized.
        |buf| unsafe { libc::llistxattr(path.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) },
        |name, buf| unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) })
}

/// The names in a directory, sorted by bytes, read through a duplicate of
/// the held descriptor (so its `O_NOATIME` applies and nothing is looked up
/// by path). `.` and `..` are left out.
pub fn list_dir(dir: &OwnedFd) -> Result<Vec<Vec<u8>>> {
    // SAFETY: duplicates an open descriptor; fdopendir takes ownership of the
    // duplicate and closedir closes it.
    let dup = Errno::result(unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) }).context("dup")?;
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        let e = Errno::last();
        unsafe { libc::close(dup) };
        return Err(e).context("fdopendir");
    }
    unsafe { libc::rewinddir(stream) };
    let mut names = Vec::new();
    let result = loop {
        Errno::clear();
        // SAFETY: readdir on a live stream; the entry is copied before the
        // next call.
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            break match Errno::last_raw() { 0 => Ok(()), e => Err(Errno::from_raw(e)) };
        }
        let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." { names.push(name.to_vec()); }
    };
    unsafe { libc::closedir(stream) };
    result.context("readdir")?;
    names.sort();
    Ok(names)
}

pub fn proc_path(dir: &OwnedFd, name: &[u8]) -> Result<CString> {
    let mut path = format!("/proc/self/fd/{}/", dir.as_raw_fd()).into_bytes();
    path.extend_from_slice(name);
    Ok(CString::new(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    pub(crate) fn scratch(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("kiln-cpwalk-{tag}-{}-{n}", std::process::id()));
        fs::create_dir(&root).unwrap();
        root
    }

    pub(crate) fn me() -> IdMap {
        IdMap { uid_base: unsafe { libc::geteuid() }, gid_base: unsafe { libc::getegid() }, count: 1 }
    }

    pub(crate) fn open_dir(p: &Path) -> OwnedFd {
        let c = CString::new(p.as_os_str().as_bytes()).unwrap();
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        assert!(fd >= 0);
        unsafe { OwnedFd::from_raw_fd(fd) }
    }

    fn run(upper: &Path, budget: u64) -> Result<Walked> {
        let opts = Options { generated: &[], budget, ids: me() };
        walk(&open_dir(upper), &opts, &mut HashOnly, &mut || Ok(()))
    }

    fn reason(r: Result<Walked>) -> (Reason, String) {
        let e = r.err().expect("walk should refuse");
        (super::super::reason_of(&e), format!("{e:#}"))
    }

    #[test]
    fn classification_of_every_xattr_form() {
        let mut bk = Bookkeeping::default();
        let x = |n: &str, v: &[u8]| (n.as_bytes().to_vec(), v.to_vec());
        let (user, opaque) = classify(Node::Root, vec![x("trusted.overlay.uuid", &[7; 16]),
            x("trusted.overlay.impure", b"y"), x("user.b", b"2"), x("user.a", b"1")], &mut bk, "root").unwrap();
        assert_eq!((user, opaque), (vec![x("user.a", b"1"), x("user.b", b"2")], false));
        let (_, opaque) = classify(Node::Dir, vec![x("trusted.overlay.origin", b"\x00\xfb"),
            x("trusted.overlay.opaque", b"y"), x("trusted.overlay.impure", b"y")], &mut bk, "d").unwrap();
        assert!(opaque);
        classify(Node::File, vec![x("trusted.overlay.origin", b"h")], &mut bk, "f").unwrap();
        classify(Node::Symlink, vec![x("trusted.overlay.origin", b"h")], &mut bk, "s").unwrap();
        assert_eq!(bk, Bookkeeping { impure: 2, origin: 3, uuid: 1 });
        let refused = |node, name: &str, value: &[u8], want: &str| {
            let e = classify(node, vec![x(name, value)], &mut Bookkeeping::default(), "entry 3").unwrap_err();
            assert_eq!(super::super::reason_of(&e), Reason::MetadataUnsupported);
            let text = e.to_string();
            assert!(text.contains(want) && text.contains("entry 3"), "{name}: {text}");
            assert!(!text.contains("secret"), "a value or user name leaked: {text}");
        };
        refused(Node::File, "trusted.overlay.redirect", b"/x", "redirect");
        refused(Node::File, "trusted.overlay.metacopy", b"", "metacopy");
        refused(Node::Dir, "trusted.overlay.upper", b"h", "index handle");
        refused(Node::File, "trusted.overlay.nlink", b"U+1", "index handle");
        refused(Node::File, "trusted.overlay.whiteout", b"", "xattr whiteout");
        refused(Node::Dir, "trusted.overlay.whiteouts", b"", "xattr whiteout");
        refused(Node::Dir, "trusted.overlay.opaque", b"x", "xattr-whiteout marker");
        refused(Node::Dir, "trusted.overlay.opaque", b"n", "unrecognized overlay");
        refused(Node::File, "trusted.overlay.opaque", b"y", "unrecognized overlay");
        refused(Node::Dir, "trusted.overlay.overlay.opaque", b"y", "escaped overlay");
        refused(Node::Dir, "trusted.overlay.protattr", b"i", "unrecognized overlay");
        refused(Node::File, "trusted.overlay.impure", b"y", "unrecognized overlay");
        refused(Node::Dir, "trusted.overlay.impure", b"n", "unrecognized overlay");
        refused(Node::Dir, "trusted.overlay.uuid", &[0; 16], "unrecognized overlay");
        refused(Node::Root, "trusted.overlay.uuid", &[0; 15], "unrecognized overlay");
        refused(Node::Whiteout, "trusted.overlay.origin", b"h", "unrecognized overlay");
        refused(Node::Root, "trusted.overlay.origin", b"h", "unrecognized overlay");
        refused(Node::File, "user.overlay.secret", b"secret", "reserved user.overlay");
        refused(Node::Symlink, "user.secret", b"secret", "user xattr where");
        refused(Node::Whiteout, "user.secret", b"secret", "user xattr where");
        refused(Node::File, "user.", b"secret", "user xattr where");
        refused(Node::File, "system.posix_acl_access", b"secret", "POSIX ACL");
        refused(Node::Dir, "system.posix_acl_default", b"secret", "POSIX ACL");
        refused(Node::File, "security.capability", b"secret", "file capability");
        refused(Node::File, "security.selinux", b"secret", "security xattr (security.selinux)");
        refused(Node::File, "security.secret", b"secret", "a security xattr");
        refused(Node::File, "trusted.secret", b"secret", "trusted xattr");
        refused(Node::File, "system.secret", b"secret", "system xattr");
        refused(Node::File, "btrfs.compression", b"secret", "unknown namespace");
        // Caps on what is kept: 32 user xattrs and 4 KiB of names and values.
        let many: Xattrs = (0..33).map(|i| x(&format!("user.{i:02}"), b"")).collect();
        assert!(classify(Node::File, many[..32].to_vec(), &mut bk, "f").is_ok());
        assert!(classify(Node::File, many, &mut bk, "f").unwrap_err().to_string().contains("more than 32"));
        assert!(classify(Node::File, vec![x("user.a", &[0; 4090])], &mut bk, "f").is_ok());
        assert!(classify(Node::File, vec![x("user.a", &[0; 4091])], &mut bk, "f").unwrap_err().to_string()
            .contains("over 4096"));
    }

    #[test]
    fn walk_records_types_links_metadata_and_order() {
        let root = scratch("types");
        let u = root.join("upper");
        fs::create_dir_all(u.join("w/sub")).unwrap();
        fs::write(u.join("w/a"), b"alpha").unwrap();
        fs::hard_link(u.join("w/a"), u.join("w/z")).unwrap();
        fs::write(u.join("w-c"), b"").unwrap();
        symlink("/etc/../x", u.join("w/sub/l")).unwrap();
        fs::write(u.join(std::ffi::OsStr::from_bytes(b"w/\xff")), b"x").unwrap();
        fs::set_permissions(u.join("w/a"), fs::Permissions::from_mode(0o4750)).unwrap();
        let sparse = fs::File::create(u.join("w/sparse")).unwrap();
        sparse.set_len(3 * 65536 + 7).unwrap();
        drop(sparse);
        let walked = run(&u, 1 << 30).unwrap();
        let paths: Vec<&[u8]> = walked.entries.iter().map(|e| e.path.as_slice()).collect();
        // Pre-order with siblings by name bytes: "w" < "w-c", and "w/..." sits under "w".
        assert_eq!(paths, [&b"w"[..], b"w/a", b"w/sparse", b"w/sub", b"w/sub/l", b"w/z", b"w/\xff", b"w-c"]);
        let Body::File { meta, size, sha256, object } = &walked.entries[1].body else { panic!() };
        assert_eq!((meta.mode, meta.uid, *size, *object), (0o4750, 0, 5, 0));
        assert_eq!(*sha256, Sha256::digest(b"alpha"));
        let Body::File { size, sha256, object, .. } = &walked.entries[2].body else { panic!() };
        assert_eq!((*size, *object), (3 * 65536 + 7, 1));
        assert_eq!(*sha256, Sha256::digest(&vec![0u8; 3 * 65536 + 7]), "holes hash as zeros");
        assert!(matches!(walked.entries[4].body, Body::Symlink { ref target, .. } if target == b"/etc/../x"));
        assert_eq!(walked.entries[5].body, Body::HardLink { link: 1 });
        assert!(matches!(walked.entries[7].body, Body::File { size: 0, object: 3, .. }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn walk_refuses_special_files_outside_links_and_size() {
        let root = scratch("refuse");
        let u = root.join("upper");
        fs::create_dir(&u).unwrap();
        nix::unistd::mkfifo(&u.join("fifo"), nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let (r, text) = reason(run(&u, 1 << 30));
        assert_eq!(r, Reason::MetadataUnsupported);
        assert!(text.contains("entry 0 is a FIFO") && !text.contains("fifo"), "{text}");
        fs::remove_file(u.join("fifo")).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(u.join("sock")).unwrap();
        assert!(reason(run(&u, 1 << 30)).1.contains("is a socket"));
        drop(listener);
        fs::remove_file(u.join("sock")).unwrap();
        // A hardlink to a name outside the upper is an unexplained link count.
        fs::write(root.join("outside"), b"o").unwrap();
        fs::hard_link(root.join("outside"), u.join("inside")).unwrap();
        let (r, text) = reason(run(&u, 1 << 30));
        assert_eq!(r, Reason::MetadataUnsupported);
        assert!(text.contains("hardlinks outside the upper"), "{text}");
        fs::remove_file(u.join("inside")).unwrap();
        // A hardlinked symlink has no representation.
        symlink("t", u.join("s1")).unwrap();
        let c1 = CString::new(u.join("s1").as_os_str().as_bytes()).unwrap();
        let c2 = CString::new(u.join("s2").as_os_str().as_bytes()).unwrap();
        if unsafe { libc::linkat(libc::AT_FDCWD, c1.as_ptr(), libc::AT_FDCWD, c2.as_ptr(), 0) } == 0 {
            assert!(reason(run(&u, 1 << 30)).1.contains("hardlinked symlink"));
            fs::remove_file(u.join("s2")).unwrap();
        }
        fs::remove_file(u.join("s1")).unwrap();
        // Size: logical bytes (holes included) plus 16 KiB per entry.
        let f = fs::File::create(u.join("big")).unwrap();
        f.set_len(1 << 20).unwrap();
        drop(f);
        assert!(run(&u, (1 << 20) + 2 * 16384).is_ok());
        let (r, _) = reason(run(&u, (1 << 20) + 2 * 16384 - 1));
        assert_eq!(r, Reason::SizeLimit);
        // Symlink targets over 1,023 bytes (where the filesystem allows them).
        fs::remove_file(u.join("big")).unwrap();
        if symlink("a".repeat(1024), u.join("long")).is_ok() {
            assert!(reason(run(&u, 1 << 30)).1.contains("over 1023 bytes"));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn protected_paths_refuse_and_generated_entries_are_excluded() {
        let root = scratch("protected");
        let u = root.join("upper");
        fs::create_dir_all(u.join("etc")).unwrap();
        fs::write(u.join("etc/resolv.conf"), b"nameserver 10.88.0.1\n").unwrap();
        let generated = [crate::protected::RESOLV_CONF];
        let opts = Options { generated: &generated, budget: 1 << 30, ids: me() };
        let walked = walk(&open_dir(&u), &opts, &mut HashOnly, &mut || Ok(())).unwrap();
        assert_eq!(walked.entries.len(), 1, "resolv.conf is excluded, /etc kept");
        // Without DNS it is ordinary data.
        assert_eq!(run(&u, 1 << 30).unwrap().entries.len(), 2);
        // A generated file replaced by a directory is refused.
        fs::remove_file(u.join("etc/resolv.conf")).unwrap();
        fs::create_dir(u.join("etc/resolv.conf")).unwrap();
        let e = walk(&open_dir(&u), &opts, &mut HashOnly, &mut || Ok(())).err().unwrap();
        assert_eq!(super::super::reason_of(&e), Reason::LayoutUnsupported);
        // Anything beneath a mount target, or a mount target that is not a directory.
        fs::remove_dir_all(u.join("etc")).unwrap();
        fs::create_dir_all(u.join("proc/1")).unwrap();
        let (r, text) = reason(run(&u, 1 << 30));
        assert_eq!(r, Reason::LayoutUnsupported, "{text}");
        assert!(text.contains("/proc/1 is beneath a runtime mount"), "{text}");
        fs::remove_dir_all(u.join("proc")).unwrap();
        symlink("/", u.join("dev")).unwrap();
        let (r, text) = reason(run(&u, 1 << 30));
        assert_eq!(r, Reason::LayoutUnsupported, "{text}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn depth_and_path_bounds_are_layout_refusals() {
        let root = scratch("depth");
        let u = root.join("upper");
        let mut deep = u.clone();
        for _ in 0..=MAX_DEPTH { deep.push("d"); }
        fs::create_dir_all(&deep).unwrap();
        let (r, text) = reason(run(&u, 1 << 30));
        assert_eq!(r, Reason::LayoutUnsupported);
        assert!(text.contains("deeper than 128"), "{text}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sparse_copy_preserves_holes_and_detects_changes() {
        let root = scratch("sparse");
        let src = root.join("src");
        let f = fs::OpenOptions::new().create(true).write(true).truncate(true).open(&src).unwrap();
        f.set_len(1 << 20).unwrap();
        use std::os::unix::fs::FileExt;
        f.write_all_at(b"data", 512 * 1024).unwrap();
        drop(f);
        let open = |p: &Path, w: bool| {
            let c = CString::new(p.as_os_str().as_bytes()).unwrap();
            let flags = if w { libc::O_RDWR | libc::O_CREAT | libc::O_EXCL } else { libc::O_RDONLY };
            unsafe { OwnedFd::from_raw_fd(libc::open(c.as_ptr(), flags | libc::O_CLOEXEC, 0o600)) }
        };
        let dst = open(&root.join("dst"), true);
        let digest = copy_and_hash(&open(&src, false), 1 << 20, Some(&dst)).unwrap();
        assert_eq!(fs::read(root.join("dst")).unwrap(), fs::read(&src).unwrap());
        assert_eq!(digest, Sha256::digest(&fs::read(&src).unwrap()));
        let allocated = std::os::unix::fs::MetadataExt::blocks(&fs::metadata(root.join("dst")).unwrap());
        assert!(allocated * 512 < 1 << 20, "holes were written: {allocated} blocks");
        // Wrong declared sizes are errors, never silent truncation.
        assert!(copy_and_hash(&open(&src, false), (1 << 20) - 1, None).is_err());
        assert!(copy_and_hash(&open(&src, false), (1 << 20) + 1, None).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
