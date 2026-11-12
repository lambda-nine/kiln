//! Artifact storage: `<runs>/.checkpoints/<instance>/<checkpoint>/`.
//!
//! The namespace lives inside the runs filesystem so artifacts share its XFS
//! project quotas, and is excluded explicitly from sandbox inventory and GC
//! (its name is never a valid sandbox ID). Root owns every directory (0700)
//! and file (0600). Only validated IDs form paths, and every file inside an
//! artifact is opened relative to held directory descriptors without
//! following symlinks.
//!
//! An artifact directory holds exactly:
//!
//! - `header`: the binding record (instance, checkpoint, generation, source
//!   run and lease, image identity, layout, reservation), written first;
//! - `objects/00000000` …: one file per regular-file inode, holes preserved;
//! - `manifest.json`: the canonical manifest;
//! - `complete`: the completion marker (content and binding digests, counts
//!   and the excluded bookkeeping), written last.
//!
//! Capture builds it in `.staging-<checkpoint>-<generation>`, which gets its
//! project quota while empty, fsyncs every file, `objects/`, then the
//! directory, writes and fsyncs `complete`, renames the directory into place
//! (never replacing) and fsyncs the instance directory. A staging directory
//! is never a usable artifact. Removal renames to `.removing-…` first.

use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use nix::errno::Errno;

use super::manifest::{Body, Manifest, Stats, content_sha256};
use super::walk::{Bookkeeping, Sink, copy_and_hash, fstat, openat, openat_mode};
use super::{BINDING_DOMAIN, ENTRY_ALLOWANCE, FORMAT, MAX_LIMIT_BYTES, MAX_MANIFEST_BYTES, MIN_LIMIT_BYTES, Reason,
    hex32, refuse, validate_checkpoint_id, validate_instance};
use crate::sha256::{Sha256, hex};

pub const NAMESPACE: &str = ".checkpoints";
const HEADER: &str = "header";
const MANIFEST: &str = "manifest.json";
const COMPLETE: &str = "complete";
const OBJECTS: &str = "objects";
const HEADER_MAGIC: &str = "kiln-checkpoint 1";
const COMPLETE_MAGIC: &str = "kiln-checkpoint-complete 1";
const MAX_RECORD: usize = 4096;

pub struct Store {
    /// `<runs>/.checkpoints`.
    pub root: PathBuf,
    /// Production requires an XFS project quota on every artifact; unit tests
    /// run on filesystems without one.
    pub require_quota: bool,
}

impl Store {
    pub fn system() -> Self { Self::under(Path::new("/var/lib/kiln/runs"), true) }

    pub fn under(runs: &Path, require_quota: bool) -> Self { Self { root: runs.join(NAMESPACE), require_quota } }
}

/// `.staging-<checkpoint>-<generation>-<nonce>`: the nonce makes every
/// capture's staging directory its own, created exclusively, so no other
/// operation ever opens, locks or removes it.
pub fn staging_name(checkpoint: &str, generation: u64, nonce: u64) -> String {
    format!(".staging-{checkpoint}-{generation}-{nonce:016x}")
}

fn nonce() -> Result<u64> {
    let mut b = [0u8; 8];
    // SAFETY: getrandom into an owned buffer.
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    ensure!(n == 8, "getrandom failed");
    Ok(u64::from_le_bytes(b))
}

// Test hooks at the capture's transitions (`staged`: validated, before the
// charge check; `published`: renamed, before the reply).
#[cfg(test)]
pub(crate) type Hook = Option<Box<dyn FnMut(&str)>>;
#[cfg(test)]
thread_local! {
    pub(crate) static HOOK: std::cell::RefCell<Hook> = const { std::cell::RefCell::new(None) };
}

fn hook(_phase: &str) {
    #[cfg(test)]
    HOOK.with(|h| if let Some(f) = h.borrow_mut().as_mut() { f(_phase) });
}

pub fn object_name(n: u32) -> String { format!("{n:08x}") }

// ---------------------------------------------------------------------------
// Records

/// The binding header. Its identity fields are outside the content digest
/// and inside the binding digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub instance: String,
    pub checkpoint: String,
    pub generation: u64,
    /// The source run (backend) ID.
    pub source: String,
    /// The operation 6 lease generation the copy ran under.
    pub source_lease: u64,
    pub image: String,
    pub image_generation: u64,
    pub image_sha256: String,
    pub image_directory: String,
    /// The source overlay's verified effective features.
    pub layout: String,
    /// The reservation R the artifact was captured under.
    pub limit_bytes: u64,
}

const HEADER_KEYS: [&str; 12] = ["format", "instance", "checkpoint", "generation", "source", "source-lease", "image",
    "image-generation", "image-sha256", "image-directory", "layout", "limit-bytes"];

impl Header {
    pub fn text(&self) -> String {
        format!("{HEADER_MAGIC}\nformat {FORMAT}\ninstance {}\ncheckpoint {}\ngeneration {}\nsource {}\nsource-lease {}\n\
            image {}\nimage-generation {}\nimage-sha256 {}\nimage-directory {}\nlayout {}\nlimit-bytes {}\n",
            self.instance, self.checkpoint, self.generation, self.source, self.source_lease, self.image,
            self.image_generation, self.image_sha256, self.image_directory, self.layout, self.limit_bytes)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let f = fields(text, HEADER_MAGIC, &HEADER_KEYS)?;
        ensure!(decimal(f[0])? == u64::from(FORMAT), "unsupported checkpoint format");
        let h = Self { instance: f[1].into(), checkpoint: f[2].into(), generation: decimal(f[3])?, source: f[4].into(),
            source_lease: decimal(f[5])?, image: f[6].into(), image_generation: decimal(f[7])?,
            image_sha256: f[8].into(), image_directory: f[9].into(), layout: f[10].into(), limit_bytes: decimal(f[11])? };
        h.validate()?;
        ensure!(h.text() == text, "non-canonical checkpoint header");
        Ok(h)
    }

    pub fn validate(&self) -> Result<()> {
        validate_instance(&self.instance)?;
        validate_checkpoint_id(&self.checkpoint)?;
        ensure!(crate::validation::valid_persistent_id(&self.source), "invalid source run ID");
        crate::validation::validate_image_name(&self.image)?;
        hex32(&self.image_sha256)?;
        ensure!(self.generation > 0 && self.source_lease > 0 && self.image_generation > 0, "zero generation");
        ensure!((MIN_LIMIT_BYTES..=MAX_LIMIT_BYTES).contains(&self.limit_bytes),
            refuse(Reason::InvalidRequest, format!("limit must be {MIN_LIMIT_BYTES}..={MAX_LIMIT_BYTES} bytes")));
        Ok(())
    }
}

/// The completion marker, written and synced after everything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Marker {
    pub content: [u8; 32],
    pub binding: [u8; 32],
    pub entries: u64,
    pub objects: u32,
    pub logical: u64,
    pub manifest_bytes: u64,
    pub bookkeeping: Bookkeeping,
}

impl Marker {
    pub fn text(&self) -> String {
        let b = &self.bookkeeping;
        format!("{COMPLETE_MAGIC}\ncontent-sha256 {}\nbinding-sha256 {}\nentries {}\nobjects {}\nlogical-bytes {}\n\
            manifest-bytes {}\nexcluded-bookkeeping trusted.overlay.impure={} trusted.overlay.origin={} \
            trusted.overlay.uuid={}\n", hex(&self.content), hex(&self.binding), self.entries, self.objects,
            self.logical, self.manifest_bytes, b.impure, b.origin, b.uuid)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let f = fields(text, COMPLETE_MAGIC, &["content-sha256", "binding-sha256", "entries", "objects",
            "logical-bytes", "manifest-bytes", "excluded-bookkeeping"])?;
        let mut counts = f[6].split(' ');
        let mut count = |key: &str| -> Result<u64> {
            decimal(counts.next().and_then(|c| c.strip_prefix(key)).context("malformed bookkeeping counts")?)
        };
        let bookkeeping = Bookkeeping { impure: count("trusted.overlay.impure=")?, origin: count("trusted.overlay.origin=")?,
            uuid: count("trusted.overlay.uuid=")? };
        let m = Self { content: hex32(f[0])?, binding: hex32(f[1])?, entries: decimal(f[2])?,
            objects: u32::try_from(decimal(f[3])?)?, logical: decimal(f[4])?, manifest_bytes: decimal(f[5])?, bookkeeping };
        ensure!(m.text() == text, "non-canonical completion marker");
        Ok(m)
    }
}

/// SHA-256 over the domain, a zero byte, the header bytes and the raw content
/// digest: what ties the identity fields to the content.
pub fn binding_sha256(header: &[u8], content: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BINDING_DOMAIN);
    h.update(&[0]);
    h.update(header);
    h.update(content);
    h.finish()
}

fn fields<'a>(text: &'a str, magic: &str, keys: &[&str]) -> Result<Vec<&'a str>> {
    let mut lines = text.split_terminator('\n');
    ensure!(lines.next() == Some(magic), "unexpected record header");
    let mut values = Vec::new();
    for key in keys {
        let line = lines.next().context("truncated record")?;
        let value = line.strip_prefix(key).and_then(|v| v.strip_prefix(' ')).context("unexpected record key")?;
        ensure!(!value.is_empty() && !value.contains(['\r', '\0']), "malformed record value");
        values.push(value);
    }
    ensure!(lines.next().is_none() && text.ends_with('\n'), "trailing record data");
    Ok(values)
}

fn decimal(text: &str) -> Result<u64> {
    ensure!(!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0')),
        "malformed number");
    Ok(text.parse()?)
}

// ---------------------------------------------------------------------------
// Directories and files

fn cstr(name: &str) -> Result<CString> { Ok(CString::new(name)?) }

/// Opens (optionally creating) a root-only directory, refusing a symlink, a
/// foreign owner or group/other permissions.
fn open_private_dir(parent: Option<&OwnedFd>, path: &Path, name: &str, create: bool) -> Result<Option<OwnedFd>> {
    let c = cstr(name)?;
    let parent_fd = parent.map_or(libc::AT_FDCWD, |p| p.as_raw_fd());
    let target = if parent.is_some() { c.clone() } else { CString::new(path.as_os_str().as_bytes())? };
    if create {
        // SAFETY: mkdirat relative to an open directory (or an absolute path).
        let r = unsafe { libc::mkdirat(parent_fd, target.as_ptr(), 0o700) };
        if r != 0 && Errno::last() != Errno::EEXIST { return Err(Errno::last()).with_context(|| format!("create {}", path.display())); }
    }
    // SAFETY: as above.
    let fd = unsafe { libc::openat(parent_fd, target.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
        | libc::O_CLOEXEC) };
    if fd < 0 {
        if Errno::last() == Errno::ENOENT { return Ok(None); }
        return Err(Errno::last()).with_context(|| format!("open {}", path.display()));
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let st = fstat(fd.as_raw_fd())?;
    ensure!(st.st_uid == unsafe { libc::geteuid() } && st.st_mode & 0o077 == 0,
        "{} must be owned by this user with no group or other access", path.display());
    Ok(Some(fd))
}

fn flock(fd: &OwnedFd, exclusive: bool) -> Result<()> {
    loop {
        // SAFETY: flock on an open descriptor.
        let r = unsafe { libc::flock(fd.as_raw_fd(), if exclusive { libc::LOCK_EX } else { libc::LOCK_SH } | libc::LOCK_NB) };
        if r == 0 { return Ok(()); }
        match Errno::last() {
            Errno::EINTR => continue,
            Errno::EWOULDBLOCK => return Err(refuse(Reason::Busy, "another operation holds this checkpoint")),
            e => return Err(e).context("lock checkpoint"),
        }
    }
}

fn sync(fd: &OwnedFd) -> Result<()> {
    // SAFETY: fsync of an open descriptor.
    Errno::result(unsafe { libc::fsync(fd.as_raw_fd()) }).context("fsync")?;
    Ok(())
}

fn write_new(dir: &OwnedFd, name: &str, bytes: &[u8]) -> Result<()> {
    let fd = openat_mode(dir, &cstr(name)?, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW, 0o600)
        .map_err(|e| quota_full(e, name))?;
    let mut at = 0;
    while at < bytes.len() {
        // SAFETY: write from a live slice.
        let n = unsafe { libc::write(fd.as_raw_fd(), bytes[at..].as_ptr().cast(), bytes.len() - at) };
        if n < 0 {
            if Errno::last() == Errno::EINTR { continue; }
            return Err(quota_full(anyhow::Error::new(Errno::last()), name));
        }
        at += n as usize;
    }
    sync(&fd)
}

fn quota_full(e: anyhow::Error, what: &str) -> anyhow::Error {
    let errno = e.chain().find_map(|c| c.downcast_ref::<Errno>().copied()
        .or_else(|| c.downcast_ref::<std::io::Error>().and_then(|io| io.raw_os_error()).map(Errno::from_raw)));
    match errno {
        Some(Errno::ENOSPC | Errno::EDQUOT) => refuse(Reason::SizeLimit, format!("the checkpoint quota is full ({what})")),
        _ => e.context(format!("write {what}")),
    }
}

/// Reads a small root-only regular file (0600, one link) of at most `max`.
fn read_private(dir: &OwnedFd, name: &str, max: usize) -> Result<Vec<u8>> {
    let corrupt = |m: &str| refuse(Reason::Corrupt, format!("{name}: {m}"));
    let fd = openat(dir, &cstr(name)?, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .map_err(|e| refuse(Reason::Corrupt, format!("{name}: {e:#}")))?;
    let st = fstat(fd.as_raw_fd())?;
    ensure!(st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_mode & 0o7777 == 0o600 && st.st_nlink == 1
        && st.st_uid == unsafe { libc::geteuid() }, corrupt("not a private regular file"));
    ensure!(st.st_size as u64 <= max as u64, corrupt("too large"));
    let mut bytes = Vec::with_capacity(st.st_size as usize);
    fs::File::from(fd).take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max && bytes.len() as u64 == st.st_size as u64, corrupt("changed while read"));
    Ok(bytes)
}

fn names(dir: &OwnedFd) -> Result<Vec<Vec<u8>>> { super::walk::list_dir(dir) }

fn rename(dir: &OwnedFd, from: &str, to: &str, flags: libc::c_uint) -> Result<()> {
    let (a, b) = (cstr(from)?, cstr(to)?);
    // SAFETY: renameat2 within one open directory.
    let r = unsafe { libc::syscall(libc::SYS_renameat2, dir.as_raw_fd(), a.as_ptr(), dir.as_raw_fd(), b.as_ptr(), flags) };
    Errno::result(r).with_context(|| format!("rename {from} to {to}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Capture staging

pub struct Staging {
    path: PathBuf,
    instance: OwnedFd,
    dir: OwnedFd,
    objects: OwnedFd,
    name: String,
    header: Header,
    pub header_bytes: Vec<u8>,
    require_quota: bool,
    /// Set once the directory carries the published name; until then Drop
    /// removes it (it is ours: created exclusively under a fresh nonce).
    published: bool,
}

impl Store {
    /// Creates the staging directory for a capture, installs its quota while
    /// it is empty, and writes the header. Refused if the checkpoint, or any
    /// staging or removal for it, already exists.
    pub fn begin(&self, header: &Header) -> Result<Staging> {
        header.validate()?;
        let root = open_private_dir(None, &self.root, NAMESPACE, true)?.context("checkpoint namespace vanished")?;
        let ipath = self.root.join(&header.instance);
        let instance = open_private_dir(Some(&root), &ipath, &header.instance, true)?.context("instance vanished")?;
        let taken = names(&instance)?.into_iter().any(|n| n == header.checkpoint.as_bytes()
            || [".staging-", ".removing-"].iter().any(|p| n.starts_with(format!("{p}{}-", header.checkpoint).as_bytes())));
        ensure!(!taken, refuse(Reason::Busy, format!("checkpoint {} already exists or has an operation", header.checkpoint)));
        let name = staging_name(&header.checkpoint, header.generation, nonce()?);
        let path = ipath.join(&name);
        let cname = cstr(&name)?;
        // Exclusive: an existing directory is never adopted.
        // SAFETY: mkdirat relative to the held instance directory.
        if unsafe { libc::mkdirat(instance.as_raw_fd(), cname.as_ptr(), 0o700) } != 0 {
            return Err(match Errno::last() {
                Errno::EEXIST => refuse(Reason::Busy, "staging name collision"),
                e => anyhow::Error::new(e).context(format!("create {}", path.display())),
            });
        }
        // From here the directory is ours, and Drop removes it on failure.
        let dir = match openat(&instance, &cname, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW) {
            Ok(dir) => dir,
            Err(e) => { let _ = fs::remove_dir(&path); return Err(e); }
        };
        let mut staging = Staging { path: path.clone(), objects: dir.try_clone()?, instance, dir, name,
            header: header.clone(), header_bytes: header.text().into_bytes(), require_quota: self.require_quota,
            published: false };
        let st = fstat(staging.dir.as_raw_fd())?;
        ensure!(st.st_uid == unsafe { libc::geteuid() } && st.st_mode & 0o077 == 0, "staging directory is not private");
        flock(&staging.dir, true)?;
        // The quota goes on while the directory is empty, so everything
        // created inside inherits its project.
        if self.require_quota {
            crate::quota::limit(&path, Some(header.limit_bytes)).map_err(|e| refuse(Reason::Io,
                format!("install the checkpoint quota: {e:#}")))?;
            ensure!(crate::quota::usage(&path).is_some(), refuse(Reason::Io, "the checkpoint quota is not in effect"));
        }
        // SAFETY: mkdirat relative to the staging directory.
        Errno::result(unsafe { libc::mkdirat(staging.dir.as_raw_fd(), c"objects".as_ptr(), 0o700) })
            .map_err(|e| quota_full(anyhow::Error::new(e), OBJECTS))?;
        staging.objects = openat(&staging.dir, &cstr(OBJECTS)?, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        write_new(&staging.dir, HEADER, &staging.header_bytes.clone())?;
        Ok(staging)
    }
}

impl Sink for Staging {
    fn file(&mut self, src: &OwnedFd, size: u64, object: u32) -> Result<[u8; 32]> {
        let name = object_name(object);
        let dst = openat_mode(&self.objects, &cstr(&name)?, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
            | libc::O_NOFOLLOW, 0o600).map_err(|e| quota_full(e, "object"))?;
        let digest = copy_and_hash(src, size, Some(&dst)).map_err(|e| quota_full(e, "object"))?;
        sync(&dst).map_err(|e| quota_full(e, "object"))?;
        Ok(digest)
    }
}

impl Staging {
    /// Finishes and publishes the artifact. In order: write and sync the
    /// manifest, sync `objects/`, write and sync the marker, sync the
    /// directory; validate the staged directory as a reader would, through
    /// this operation's own locked descriptor, against the original header;
    /// measure A and S and refuse S > R; and only then rename it into place
    /// (never replacing) and sync the instance directory. A refusal at any
    /// point leaves nothing published (Drop removes the staging directory).
    /// The returned artifact still holds the exclusive lock.
    pub fn publish(mut self, manifest: Vec<u8>, marker: &Marker) -> Result<(Artifact, Charge)> {
        ensure!(manifest.len() <= MAX_MANIFEST_BYTES, refuse(Reason::SizeLimit, "manifest too large"));
        write_new(&self.dir, MANIFEST, &manifest)?;
        drop(manifest);
        sync(&self.objects)?;
        write_new(&self.dir, COMPLETE, marker.text().as_bytes())?;
        sync(&self.dir)?;
        let mut artifact = validate_dir(self.dir.try_clone()?, self.path.clone(), &self.header.instance,
            &self.header.checkpoint)?;
        ensure!(artifact.header == self.header && artifact.marker == *marker,
            refuse(Reason::Corrupt, "the staged artifact is not the one this capture wrote"));
        hook("staged");
        let charge = artifact.charge(self.require_quota)?;
        if charge.charge > self.header.limit_bytes {
            return Err(refuse(Reason::SizeLimit, format!("the checkpoint's charge {} exceeds its limit {}",
                charge.charge, self.header.limit_bytes)));
        }
        rename(&self.instance, &self.name, &self.header.checkpoint, libc::RENAME_NOREPLACE).map_err(|e|
            if e.downcast_ref::<Errno>() == Some(&Errno::EEXIST) {
                refuse(Reason::Busy, format!("checkpoint {} was published by another capture", self.header.checkpoint))
            } else { e })?;
        self.published = true;
        sync(&self.instance)?;
        artifact.path = self.path.with_file_name(&self.header.checkpoint);
        hook("published");
        Ok((artifact, charge))
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.published { let _ = fs::remove_dir_all(&self.path); }
    }
}

// ---------------------------------------------------------------------------
// Published artifacts

pub struct Artifact {
    pub path: PathBuf,
    pub dir: OwnedFd,
    objects: OwnedFd,
    pub header: Header,
    pub header_bytes: Vec<u8>,
    pub manifest: Manifest,
    /// The manifest's length (its bytes are not kept once decoded).
    pub manifest_len: usize,
    pub stats: Stats,
    pub marker: Marker,
}

/// The storage charge of a published artifact (design §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Charge {
    /// Regular-file logical bytes, once per inode (L before rounding).
    pub logical: u64,
    pub entries: u64,
    /// Allocated bytes of the artifact (A): its project's usage.
    pub allocated: u64,
    /// S = max(A, L rounded per file to 4 KiB + 16 KiB per entry + M).
    pub charge: u64,
}

impl Store {
    /// Opens and validates a published artifact without reading object
    /// bytes: names, ownership and modes, the header's binding to the path,
    /// both digests, the full manifest validation, and every object's
    /// presence, type and length. `exclusive` takes the artifact lock for
    /// removal; otherwise it is shared (inspection and restore).
    pub fn open(&self, instance: &str, checkpoint: &str, exclusive: bool) -> Result<Artifact> {
        validate_instance(instance)?;
        validate_checkpoint_id(checkpoint)?;
        let missing = || refuse(Reason::InvalidRequest, format!("checkpoint {instance}/{checkpoint} does not exist"));
        let root = open_private_dir(None, &self.root, NAMESPACE, false)?.ok_or_else(missing)?;
        let ipath = self.root.join(instance);
        let ifd = open_private_dir(Some(&root), &ipath, instance, false)?.ok_or_else(missing)?;
        let path = ipath.join(checkpoint);
        let dir = open_private_dir(Some(&ifd), &path, checkpoint, false)?.ok_or_else(missing)?;
        flock(&dir, exclusive)?;
        validate_dir(dir, path, instance, checkpoint)
    }
}

/// Validates an artifact directory through a descriptor the caller holds
/// (and has locked): exact contents, private modes, the header's binding to
/// the expected IDs, both digests, the full manifest rules and every object's
/// presence, type, mode, links and length.
fn validate_dir(dir: OwnedFd, path: PathBuf, instance: &str, checkpoint: &str) -> Result<Artifact> {
    {
        let corrupt = |m: String| refuse(Reason::Corrupt, m);
        let listed = names(&dir)?;
        ensure!(listed == [COMPLETE.as_bytes(), HEADER.as_bytes(), MANIFEST.as_bytes(), OBJECTS.as_bytes()],
            corrupt("unexpected artifact contents".into()));
        let header_bytes = read_private(&dir, HEADER, MAX_RECORD)?;
        let header = Header::parse(std::str::from_utf8(&header_bytes)?).map_err(|e| corrupt(format!("header: {e:#}")))?;
        ensure!(header.instance == instance && header.checkpoint == checkpoint,
            corrupt("header names another checkpoint".into()));
        let marker_bytes = read_private(&dir, COMPLETE, MAX_RECORD)?;
        let marker = Marker::parse(std::str::from_utf8(&marker_bytes)?).map_err(|e| corrupt(format!("marker: {e:#}")))?;
        let manifest_bytes = read_private(&dir, MANIFEST, MAX_MANIFEST_BYTES)?;
        ensure!(content_sha256(&manifest_bytes) == marker.content, corrupt("manifest digest mismatch".into()));
        ensure!(binding_sha256(&header_bytes, &marker.content) == marker.binding, corrupt("binding digest mismatch".into()));
        let (manifest, stats) = Manifest::decode(&manifest_bytes)?;
        let manifest_len = manifest_bytes.len();
        drop(manifest_bytes);
        ensure!(manifest.image_sha256 == header.image_sha256, corrupt("manifest and header images differ".into()));
        ensure!((marker.entries, marker.objects, marker.logical, marker.manifest_bytes)
            == (stats.entries, stats.objects, stats.logical, manifest_len as u64),
            corrupt("completion marker does not match the manifest".into()));
        let objects = openat(&dir, &cstr(OBJECTS)?, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        let st = fstat(objects.as_raw_fd())?;
        ensure!(st.st_uid == unsafe { libc::geteuid() } && st.st_mode & 0o7777 == 0o700, corrupt("objects directory mode".into()));
        let expected: Vec<Vec<u8>> = (0..stats.objects).map(|n| object_name(n).into_bytes()).collect();
        ensure!(names(&objects)? == expected, corrupt("missing or extra objects".into()));
        let artifact = Artifact { path, dir, objects, header, header_bytes, manifest, manifest_len, stats, marker };
        for e in &artifact.manifest.entries {
            if let Body::File { size, object, .. } = e.body { artifact.object(object, size)?; }
        }
        Ok(artifact)
    }
}

impl Artifact {
    /// Opens object `n`, checking it is a private regular file of `size` bytes.
    pub fn object(&self, n: u32, size: u64) -> Result<OwnedFd> {
        let name = object_name(n);
        let fd = openat(&self.objects, &cstr(&name)?, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOATIME)
            .map_err(|e| refuse(Reason::Corrupt, format!("object {name}: {e:#}")))?;
        let st = fstat(fd.as_raw_fd())?;
        ensure!(st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_mode & 0o7777 == 0o600 && st.st_nlink == 1
            && st.st_uid == unsafe { libc::geteuid() } && st.st_size as u64 == size,
            refuse(Reason::Corrupt, format!("object {name} has the wrong type, mode, links or length")));
        Ok(fd)
    }

    /// Rehashes every object against the manifest.
    pub fn verify_objects(&self) -> Result<()> {
        for e in &self.manifest.entries {
            if let Body::File { size, sha256, object, .. } = e.body {
                let digest = copy_and_hash(&self.object(object, size)?, size, None)?;
                ensure!(digest == sha256, refuse(Reason::Corrupt, format!("object {} digest mismatch", object_name(object))));
            }
        }
        Ok(())
    }

    pub fn charge(&self, require_quota: bool) -> Result<Charge> {
        let allocated = match crate::quota::usage(&self.path) {
            Some(usage) => usage.used,
            None if require_quota => bail!(refuse(Reason::Io, "the checkpoint has no project quota")),
            None => allocated_blocks(&self.dir)?,
        };
        let round = |n: u64| n.div_ceil(4096) * 4096;
        let metadata = round(self.manifest_len as u64) + round(self.header_bytes.len() as u64)
            + round(self.marker.text().len() as u64);
        let formula = self.stats.logical_blocks.checked_add(ENTRY_ALLOWANCE.checked_mul(self.stats.entries)
            .context("charge overflow")?).and_then(|n| n.checked_add(metadata)).context("charge overflow")?;
        let charge = allocated.max(formula);
        ensure!(charge <= i64::MAX as u64, "charge overflow");
        Ok(Charge { logical: self.stats.logical, entries: self.stats.entries, allocated, charge })
    }

    /// The record checkpoint commands print on success.
    pub fn record(&self, charge: &Charge) -> String {
        let h = &self.header;
        format!("kiln-checkpoint-record 1\ninstance {}\ncheckpoint {}\ngeneration {}\ncontent-sha256 {}\n\
            binding-sha256 {}\nimage {}\nimage-sha256 {}\nentries {}\nlogical-bytes {}\nallocated-bytes {}\n\
            charge-bytes {}\nlimit-bytes {}\n", h.instance, h.checkpoint, h.generation, hex(&self.marker.content),
            hex(&self.marker.binding), h.image, h.image_sha256, charge.entries, charge.logical, charge.allocated,
            charge.charge, h.limit_bytes)
    }
}

/// Allocated bytes of a tree by `st_blocks`, where no project quota exists.
fn allocated_blocks(dir: &OwnedFd) -> Result<u64> {
    let mut total = fstat(dir.as_raw_fd())?.st_blocks as u64 * 512;
    for name in names(dir)? {
        let c = CString::new(name)?;
        let st = super::walk::fstatat(dir.as_raw_fd(), &c)?;
        total += st.st_blocks as u64 * 512;
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            total += allocated_blocks(&openat(dir, &c, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?)?
                - st.st_blocks as u64 * 512;
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Inventory, removal and image references

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item { Published, Staging, Removing, Unknown }

impl Item {
    fn of(name: &[u8]) -> Self {
        let Ok(name) = std::str::from_utf8(name) else { return Item::Unknown };
        if validate_checkpoint_id(name).is_ok() { return Item::Published; }
        let tail = |p: &str| name.strip_prefix(p).and_then(|r| r.get(..35)).is_some_and(|id| validate_checkpoint_id(id).is_ok());
        if tail(".staging-") { Item::Staging } else if tail(".removing-") { Item::Removing } else { Item::Unknown }
    }
    fn word(&self) -> &'static str {
        match self { Item::Published => "published", Item::Staging => "staging", Item::Removing => "removing",
            Item::Unknown => "unknown" }
    }
}

impl Store {
    /// Every entry of the namespace: `(instance, name, kind)`. Entries at the
    /// root that are not instance directories are listed as unknown with an
    /// empty instance. Nothing here is removed or adopted.
    pub fn inventory(&self) -> Result<Vec<(String, String, Item)>> {
        let Some(root) = open_private_dir(None, &self.root, NAMESPACE, false)? else { return Ok(Vec::new()) };
        let mut out = Vec::new();
        for name in names(&root)? {
            let shown = String::from_utf8_lossy(&name).into_owned();
            let instance = std::str::from_utf8(&name).ok().filter(|n| validate_instance(n).is_ok());
            let Some(instance) = instance else { out.push((String::new(), shown, Item::Unknown)); continue };
            let Some(ifd) = open_private_dir(Some(&root), &self.root.join(instance), instance, false)? else { continue };
            for entry in names(&ifd)? {
                out.push((instance.to_owned(), String::from_utf8_lossy(&entry).into_owned(), Item::of(&entry)));
            }
        }
        Ok(out)
    }

    pub fn inventory_text(&self) -> Result<String> {
        let mut text = String::from("kiln-checkpoint-inventory 1\n");
        for (instance, name, item) in self.inventory()? {
            text.push_str(&format!("{} {} {}\n", item.word(), if instance.is_empty() { "-" } else { &instance }, name));
        }
        Ok(text)
    }

    /// Removes a checkpoint's published artifact and any staging or
    /// interrupted removal of it, under each one's exclusive lock (a capture
    /// or restore in progress makes this `checkpoint_busy`). Each directory is
    /// renamed to `.removing-<checkpoint>-<generation>-…` before deletion.
    /// Returns whether anything existed; the instance directory stays.
    ///
    /// With `generation`, only that capture generation is removed, and every
    /// check happens before anything is touched:
    ///
    /// - a published artifact of another generation is
    ///   `checkpoint_generation_mismatch`, and one whose header can't be read
    ///   (so its generation can't be proven) is `checkpoint_corrupt`;
    /// - staging and removal directories of another generation are left
    ///   alone, unlocked and uncounted; those of this generation are locked
    ///   like the artifact, so a live writer makes the whole removal busy;
    /// - an interrupted removal whose name and header name no generation
    ///   (an older kiln's) is left alone.
    ///
    /// Without `generation` it removes every generation, as before.
    pub fn remove(&self, instance: &str, checkpoint: &str, generation: Option<u64>) -> Result<bool> {
        validate_instance(instance)?;
        validate_checkpoint_id(checkpoint)?;
        ensure!(generation != Some(0), refuse(Reason::InvalidRequest, "the generation must be nonzero"));
        let Some(root) = open_private_dir(None, &self.root, NAMESPACE, false)? else { return Ok(false) };
        let ipath = self.root.join(instance);
        let Some(ifd) = open_private_dir(Some(&root), &ipath, instance, false)? else { return Ok(false) };
        // Every directory this removal takes, locked, before the first change.
        let mut doomed: Vec<(String, u64, OwnedFd)> = Vec::new();
        for name in names(&ifd)? {
            let Ok(name) = String::from_utf8(name) else { continue };
            let Some(kind) = Owned::of(&name, checkpoint) else { continue };
            let open = || open_private_dir(Some(&ifd), &ipath.join(&name), &name, false)?
                .with_context(|| format!("{name} vanished"));
            let header_generation = |dir: &OwnedFd| -> Option<u64> {
                let bytes = read_private(dir, HEADER, MAX_RECORD).ok()?;
                Header::parse(std::str::from_utf8(&bytes).ok()?).ok()
                    .filter(|h| h.instance == instance && h.checkpoint == checkpoint).map(|h| h.generation)
            };
            let (seen, dir) = match kind {
                Owned::Published => {
                    let dir = open()?;
                    let seen = header_generation(&dir);
                    match (generation, seen) {
                        (Some(wanted), Some(seen)) if seen != wanted => {
                            return Err(refuse(Reason::GenerationMismatch, format!(
                                "the published checkpoint is generation {seen}, not {wanted}; nothing was removed")));
                        }
                        (Some(_), None) => {
                            return Err(refuse(Reason::Corrupt,
                                "the published checkpoint's header can't prove its generation; nothing was removed"));
                        }
                        _ => (seen, dir),
                    }
                }
                Owned::Named(seen) => {
                    if generation.is_some_and(|wanted| wanted != seen) { continue; }
                    (Some(seen), open()?)
                }
                Owned::LegacyRemoving => {
                    let dir = open()?;
                    let seen = header_generation(&dir);
                    if generation.is_some() && seen != generation { continue; }
                    (seen, dir)
                }
            };
            flock(&dir, true)?;
            doomed.push((name, seen.unwrap_or(0), dir));
        }
        for (name, seen, _lock) in &doomed {
            let target = if name.starts_with(".removing-") { name.clone() }
                else { format!(".removing-{checkpoint}-{seen}-{}-{}", std::process::id(), next()) };
            if target != *name { rename(&ifd, name, &target, libc::RENAME_NOREPLACE)?; sync(&ifd)?; }
            fs::remove_dir_all(ipath.join(&target)).with_context(|| format!("delete {target}"))?;
            sync(&ifd)?;
        }
        Ok(!doomed.is_empty())
    }

    /// The image each artifact or staging directory references, for image
    /// removal: `(label, Some(image))`, or `None` when the reference can't be
    /// read (an interrupted capture before its header, or anything unknown),
    /// which blocks removal of every image.
    pub fn image_references(&self) -> Result<Vec<(String, Option<String>)>> {
        let mut out = Vec::new();
        let Some(root) = open_private_dir(None, &self.root, NAMESPACE, false)? else { return Ok(out) };
        for (instance, name, item) in self.inventory()? {
            let label = format!("checkpoint {}/{name}", if instance.is_empty() { "-" } else { &instance });
            let image = (|| -> Option<String> {
                if item == Item::Unknown { return None; }
                let ifd = open_private_dir(Some(&root), &self.root.join(&instance), &instance, false).ok()??;
                let dir = open_private_dir(Some(&ifd), &self.root.join(&instance).join(&name), &name, false).ok()??;
                let bytes = read_private(&dir, HEADER, MAX_RECORD).ok()?;
                Header::parse(std::str::from_utf8(&bytes).ok()?).ok().map(|h| h.image)
            })();
            out.push((label, image));
        }
        Ok(out)
    }
}

/// What one name in an instance directory is to a removal of `checkpoint`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Owned {
    /// `<checkpoint>`: its generation is in its header.
    Published,
    /// `.staging-<checkpoint>-<G>-<nonce>` or `.removing-<checkpoint>-<G>-<pid>-<n>`
    /// (`G` 0: removed without a known generation).
    Named(u64),
    /// `.removing-<checkpoint>-<pid>-<n>`, an older kiln's interrupted removal.
    LegacyRemoving,
}

impl Owned {
    fn of(name: &str, checkpoint: &str) -> Option<Self> {
        if name == checkpoint { return Some(Owned::Published); }
        let number = |s: &str| (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<u64>().ok()).flatten();
        if let Some(rest) = name.strip_prefix(&format!(".staging-{checkpoint}-")) {
            return rest.split_once('-').and_then(|(g, _)| number(g)).map(Owned::Named);
        }
        let rest = name.strip_prefix(&format!(".removing-{checkpoint}-"))?;
        let parts: Vec<&str> = rest.split('-').collect();
        match parts.as_slice() {
            [g, _, _] => number(g).map(Owned::Named),
            [_, _] => Some(Owned::LegacyRemoving),
            _ => None,
        }
    }
}

fn next() -> usize {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
