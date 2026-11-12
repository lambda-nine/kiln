//! Image content identity.
//!
//! An image is still selected by name (`/var/lib/kiln/images/NAME`), but a
//! name says nothing about content. `kiln image register NAME` copies the
//! image into a private stage, hashes the copy's canonical full-tree manifest
//! (types, metadata, hardlink topology, xattrs and file bytes; never device
//! contents), installs exactly that copy under the name, and records the
//! digest with the installed directory's identity in a root-owned registry,
//! one file per name under `/var/lib/kiln/image-registry`. Every new run
//! writes a durable reference, `<run>/image`, naming its image and, when the
//! directory still is the registered one, that identity. A run without an
//! identity works as before but is not a checkpoint source.
//!
//! Registration, replacement, retirement and removal take an exclusive flock
//! on the images directory; reference acquisition takes it shared. A name
//! referenced by any run, or any run whose reference can't be read (older
//! runs have none), blocks registration (other than a no-op), replacement and
//! removal: changed content must be installed under a new name. Retired
//! names keep their generation counter, so a re-registered name never repeats
//! a generation.

use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use nix::errno::Errno;

use crate::sha256::{Sha256, hex};
use crate::validation::validate_image_name;

pub const REFERENCE_FILE: &str = "image";
const ENTRY_MAGIC: &str = "kiln-image 1";
const REFERENCE_MAGIC: &str = "kiln-image-ref 1";
/// Domain separation for the tree manifest stream.
pub const TREE_DOMAIN: &[u8] = b"kiln.image-tree.1\0";
const MAX_RECORD_FILE: u64 = 4096;
const MAX_DEPTH: usize = 256;
const MAX_PATH: usize = 4096;
const MAX_ENTRIES: u64 = 4 * 1024 * 1024;
const MAX_XATTRS: usize = 1024;
const MAX_XATTR_BYTES: usize = 64 * 1024;
const MAX_LINK: usize = 4096;

/// The three host locations the registry works with. Tests use a scratch set.
#[derive(Clone, Debug)]
pub struct Roots {
    pub images: PathBuf,
    pub registry: PathBuf,
    pub runs: PathBuf,
}

impl Roots {
    pub fn system() -> Self {
        Self { images: "/var/lib/kiln/images".into(), registry: "/var/lib/kiln/image-registry".into(),
            runs: "/var/lib/kiln/runs".into() }
    }
}

/// Which directory a name resolved to: filesystem ID, inode and birth time.
/// The birth time distinguishes a reused inode number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirIdentity { pub fsid: u64, pub ino: u64, pub btime_sec: i64, pub btime_nsec: u32 }

impl DirIdentity {
    fn text(&self) -> String { format!("{:016x}:{}:{}.{:09}", self.fsid, self.ino, self.btime_sec, self.btime_nsec) }

    fn parse(text: &str) -> Result<Self> {
        let mut parts = text.split(':');
        let (Some(fsid), Some(ino), Some(btime), None) = (parts.next(), parts.next(), parts.next(), parts.next())
            else { bail!("malformed directory identity") };
        let (sec, nsec) = btime.split_once('.').context("malformed directory birth time")?;
        ensure!(fsid.len() == 16 && nsec.len() == 9, "malformed directory identity");
        let id = Self { fsid: u64::from_str_radix(fsid, 16)?, ino: decimal(ino)?, btime_sec: sec.parse()?,
            btime_nsec: decimal(nsec)? as u32 };
        ensure!(id.btime_nsec < 1_000_000_000 && id.text() == text, "non-canonical directory identity");
        Ok(id)
    }
}

fn decimal(text: &str) -> Result<u64> {
    ensure!(!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()), "malformed number {text:?}");
    Ok(text.parse()?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Registered, Retired }

/// One registry file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub generation: u64,
    pub state: State,
    pub sha256: String,
    pub directory: DirIdentity,
    pub entries: u64,
    pub bytes: u64,
}

impl Entry {
    pub fn text(&self) -> String {
        format!("{ENTRY_MAGIC}\nname {}\ngeneration {}\nstate {}\nsha256 {}\ndirectory {}\nentries {}\nbytes {}\n",
            self.name, self.generation, match self.state { State::Registered => "registered", State::Retired => "retired" },
            self.sha256, self.directory.text(), self.entries, self.bytes)
    }

    pub fn parse(text: &str) -> Result<Self> {
        let fields = fields(text, ENTRY_MAGIC, &["name", "generation", "state", "sha256", "directory", "entries", "bytes"])?;
        let entry = Self {
            name: fields[0].to_owned(),
            generation: decimal(fields[1])?,
            state: match fields[2] { "registered" => State::Registered, "retired" => State::Retired,
                _ => bail!("unknown image state") },
            sha256: digest_text(fields[3])?,
            directory: DirIdentity::parse(fields[4])?,
            entries: decimal(fields[5])?,
            bytes: decimal(fields[6])?,
        };
        validate_image_name(&entry.name)?;
        ensure!(entry.generation > 0 && entry.text() == text, "non-canonical image registry entry");
        Ok(entry)
    }
}

/// The identity a run recorded for its image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity { pub generation: u64, pub sha256: String, pub directory: DirIdentity }

/// `<run>/image`: the run's durable reference to its image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub name: String,
    /// `Err` holds why the run has no proven identity.
    pub identity: std::result::Result<Identity, String>,
}

impl Reference {
    pub fn text(&self) -> String {
        match &self.identity {
            Ok(i) => format!("{REFERENCE_MAGIC}\nname {}\ngeneration {}\nsha256 {}\ndirectory {}\n", self.name,
                i.generation, i.sha256, i.directory.text()),
            Err(reason) => format!("{REFERENCE_MAGIC}\nname {}\nidentity none {reason}\n", self.name),
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        let reference = if text.lines().nth(2).is_some_and(|l| l.starts_with("identity ")) {
            let f = fields(text, REFERENCE_MAGIC, &["name", "identity"])?;
            let reason = f[1].strip_prefix("none ").context("malformed image identity")?;
            ensure!(!reason.is_empty(), "missing reason");
            Self { name: f[0].to_owned(), identity: Err(reason.to_owned()) }
        } else {
            let f = fields(text, REFERENCE_MAGIC, &["name", "generation", "sha256", "directory"])?;
            Self { name: f[0].to_owned(), identity: Ok(Identity { generation: decimal(f[1])?,
                sha256: digest_text(f[2])?, directory: DirIdentity::parse(f[3])? }) }
        };
        validate_image_name(&reference.name)?;
        ensure!(reference.text() == text, "non-canonical image reference");
        Ok(reference)
    }
}

/// Splits a strict `key value` record with exactly these keys in this order.
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

fn digest_text(text: &str) -> Result<String> {
    ensure!(text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "malformed sha256");
    Ok(text.to_owned())
}

fn one_line(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(256).collect()
}

// ---------------------------------------------------------------------------
// Locking and file helpers

/// The registry lock: flock on the images directory itself, so taking it
/// creates no state. Released when dropped.
struct Lock(#[allow(dead_code)] File);

fn lock(images: &Path, exclusive: bool) -> Result<Lock> {
    let dir = File::open(images).with_context(|| format!("open image directory {}", images.display()))?;
    ensure!(dir.metadata()?.is_dir(), "{} is not a directory", images.display());
    loop {
        // SAFETY: flock on an open descriptor.
        if unsafe { libc::flock(dir.as_raw_fd(), if exclusive { libc::LOCK_EX } else { libc::LOCK_SH }) } == 0 {
            return Ok(Lock(dir));
        }
        if Errno::last() != Errno::EINTR { return Err(Errno::last()).context("lock image registry"); }
    }
}

fn read_small(path: &Path) -> Result<Option<String>> {
    // A record is a regular file; a symlink in its place is refused.
    let file = match fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
    };
    let mut text = String::new();
    file.take(MAX_RECORD_FILE + 1).read_to_string(&mut text).with_context(|| format!("read {}", path.display()))?;
    ensure!(text.len() as u64 <= MAX_RECORD_FILE, "{} is too large", path.display());
    Ok(Some(text))
}

pub fn read_entry(registry: &Path, name: &str) -> Result<Option<Entry>> {
    validate_image_name(name)?;
    if !trusted_registry(registry)? { return Ok(None); }
    let path = registry.join(name);
    read_small(&path)?.map(|t| Entry::parse(&t).with_context(|| format!("parse {}", path.display()))).transpose()
}

/// `None` for a run created before references existed.
pub fn read_reference(run_dir: &Path) -> Result<Option<Reference>> {
    let path = run_dir.join(REFERENCE_FILE);
    read_small(&path)?.map(|t| Reference::parse(&t).with_context(|| format!("parse {}", path.display()))).transpose()
}

/// Whether the registry root exists, after checking it may be trusted: a real
/// directory (not a symlink), owned by this user (root on a real host) and
/// not group or world writable. Every read and write goes through this.
fn trusted_registry(registry: &Path) -> Result<bool> {
    let meta = match fs::symlink_metadata(registry) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("inspect {}", registry.display())),
    };
    ensure!(meta.file_type().is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o022 == 0,
        "image registry {} must be a directory owned by this user and not group/other writable", registry.display());
    Ok(true)
}

fn ensure_registry(registry: &Path) -> Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(registry) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("create {}", registry.display())),
    }
    ensure!(trusted_registry(registry)?, "image registry {} disappeared", registry.display());
    Ok(())
}

fn write_entry(registry: &Path, entry: &Entry) -> Result<()> {
    ensure_registry(registry)?;
    let _ = fs::remove_file(registry.join(format!(".{}.tmp", entry.name)));
    crate::container::atomic_publish(&registry.join(&entry.name), entry.text().as_bytes())
}

fn open_dir_nofollow(path: &Path) -> Result<File> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: plain open of a NUL-terminated path.
    let fd = unsafe { libc::open(name.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 { return Err(std::io::Error::last_os_error()).with_context(|| format!("open {}", path.display())); }
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Opens an image directory without following a symlink at its final
/// component and checks the sandbox-ID ownership `validate_image` requires.
pub(crate) fn open_image(roots: &Roots, name: &str) -> Result<File> {
    validate_image_name(name)?;
    let dir = open_dir_nofollow(&roots.images.join(name)).with_context(|| format!("image {name:?}"))?;
    ensure!(dir.metadata()?.uid() == crate::userns::ID_BASE || cfg!(test),
        "image {name:?} isn't owned by the sandbox ID range");
    Ok(dir)
}

pub fn dir_identity(dir: &File) -> Result<DirIdentity> {
    let mut fs = unsafe { std::mem::zeroed::<libc::statfs>() };
    // SAFETY: fstatfs fills the struct for an open descriptor.
    Errno::result(unsafe { libc::fstatfs(dir.as_raw_fd(), &mut fs) }).context("fstatfs image")?;
    // fsid_t is two C ints; read it as one 64-bit value.
    let fsid: [u8; 8] = unsafe { std::mem::transmute_copy(&fs.f_fsid) };
    let mut st = unsafe { std::mem::zeroed::<libc::statx>() };
    let empty = c"";
    // SAFETY: AT_EMPTY_PATH statx of the descriptor itself.
    Errno::result(unsafe { libc::statx(dir.as_raw_fd(), empty.as_ptr(), libc::AT_EMPTY_PATH,
        libc::STATX_INO | libc::STATX_BTIME, &mut st) }).context("statx image")?;
    let (btime_sec, btime_nsec) = if st.stx_mask & libc::STATX_BTIME != 0 {
        (st.stx_btime.tv_sec, st.stx_btime.tv_nsec)
    } else { (0, 0) };
    Ok(DirIdentity { fsid: u64::from_le_bytes(fsid), ino: st.stx_ino, btime_sec, btime_nsec })
}

// ---------------------------------------------------------------------------
// Registry operations

/// Runs that block replacing or removing `name`: those referencing it, and
/// those whose reference is missing or unreadable (their image is unknown).
pub fn blocking_references(roots: &Roots, name: &str) -> Result<Vec<String>> {
    let entries = match fs::read_dir(&roots.runs) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", roots.runs.display())),
    };
    let mut blocking = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("enumerate {}", roots.runs.display()))?;
        let id = entry.file_name().to_string_lossy().into_owned();
        // Checkpoint artifacts are durable image references too: each one's
        // header names its image, and one that can't be read (an interrupted
        // capture, anything unknown) blocks every image.
        if entry.file_name() == crate::checkpoint::store::NAMESPACE {
            let store = crate::checkpoint::store::Store::under(&roots.runs, false);
            match store.image_references() {
                Ok(references) => for (label, image) in references {
                    match image {
                        Some(image) if image != name => {}
                        Some(_) => blocking.push(label),
                        None => blocking.push(format!("{label} (unreadable checkpoint header)")),
                    }
                },
                Err(e) => blocking.push(format!("checkpoints (unreadable: {e:#})")),
            }
            continue;
        }
        match read_reference(&entry.path()) {
            Ok(Some(r)) if r.name != name => {}
            Ok(Some(_)) => blocking.push(id),
            Ok(None) => blocking.push(format!("{id} (no image reference)")),
            Err(e) => blocking.push(format!("{id} (unreadable image reference: {e:#})")),
        }
    }
    blocking.sort();
    Ok(blocking)
}

fn refuse_if_referenced(roots: &Roots, name: &str, action: &str) -> Result<()> {
    let blocking = blocking_references(roots, name)?;
    ensure!(blocking.is_empty(), "refusing to {action} image {name:?}: referenced by {}; install changed \
        content under a new image name", blocking.join(", "));
    Ok(())
}

/// Registers (or re-registers) `name`. Unchanged content in the registered
/// directory is a no-op. Anything else copies the tree into a private,
/// root-only stage, hashes the copy, and installs exactly that copy in place
/// of the directory with an atomic exchange, all under the exclusive image
/// lock: the registered digest is the digest of the tree as installed, and no
/// writer of the old directory can change it. Because the directory is
/// replaced, this is refused while any run references the name.
pub fn register(roots: &Roots, name: &str) -> Result<Entry> {
    validate_image_name(name)?;
    let held = lock(&roots.images, true)?;
    let src = open_image(roots, name)?;
    let before = dir_identity(&src)?;
    remove_stale_stages(&roots.images, name)?;
    let previous = read_entry(&roots.registry, name)?;
    if let Some(e) = previous.as_ref().filter(|e| e.state == State::Registered && e.directory == before) {
        // A no-op only answers "unchanged": it writes nothing, so it cannot
        // publish any state. The registry keeps certifying the snapshot an
        // earlier registration hashed and installed.
        let tree = tree_digest(&src)?;
        if hex(&tree.sha256) == e.sha256 && tree.entries == e.entries && tree.bytes == e.bytes {
            ensure!(dir_identity(&open_image(roots, name)?)? == before, "image {name:?} was replaced while it was hashed");
            return Ok(e.clone());
        }
    }
    // Installing a copy swaps the directory under any run that uses it by
    // name, so a first registration is refused while referenced too.
    refuse_if_referenced(roots, name, "register")?;
    let generation = match &previous {
        None => 1,
        Some(e) => e.generation.checked_add(1).context("generation overflow")?,
    };

    let images = held.0.as_raw_fd();
    static STAGES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let stage_name = format!(".register-{name}-{}-{}", std::process::id(),
        STAGES.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let stage_cname = CString::new(stage_name.as_str())?;
    // SAFETY: mkdirat relative to the held images directory.
    Errno::result(unsafe { libc::mkdirat(images, stage_cname.as_ptr(), 0o700) })
        .with_context(|| format!("create {stage_name}"))?;
    let stage = StageDir(roots.images.join(&stage_name));
    let stage_fd = openat_raw(images, &stage_cname, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    private_stage(&stage_fd)?;
    copy_tree(&src, &stage_fd, c"tree").with_context(|| format!("copy image {name:?}"))?;
    let copy = File::from(openat(&stage_fd, c"tree", libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?);
    let staged = dir_identity(&copy)?;
    let tree = tree_digest(&copy)?;
    // The copy is on disk before it replaces the image (the old tree is
    // deleted below, so a crash must not leave a torn copy installed).
    // SAFETY: syncfs on an open descriptor.
    Errno::result(unsafe { libc::syncfs(copy.as_raw_fd()) }).context("sync the staged image")?;
    let cname = CString::new(name)?;
    // SAFETY: renameat2 of names relative to two held directories.
    Errno::result(unsafe { libc::renameat2(stage_fd.as_raw_fd(), c"tree".as_ptr(), images, cname.as_ptr(),
        libc::RENAME_EXCHANGE) }).with_context(|| format!("install the staged copy of image {name:?}"))?;
    held.0.sync_all().context("sync image directory")?;
    ensure!(dir_identity(&open_image(roots, name)?)? == staged && dir_identity(&copy)? == staged,
        "image {name:?} was replaced while it was installed");
    let entry = Entry { name: name.to_owned(), generation, state: State::Registered, sha256: hex(&tree.sha256),
        directory: staged, entries: tree.entries, bytes: tree.bytes };
    write_entry(&roots.registry, &entry)?;
    // The replaced tree now sits in the stage. Deleting it is best effort: a
    // leftover is deleted by the next registration of this name.
    drop(stage);
    let _ = held.0.sync_all();
    Ok(entry)
}

/// A registration's stage directory. Dropping it deletes it with whatever it
/// holds: the partial copy after a failure, the replaced tree after success.
struct StageDir(PathBuf);

impl Drop for StageDir {
    fn drop(&mut self) { let _ = remove_tree(&self.0); }
}

/// Makes a new stage reachable by its owner (root) alone: no umask or
/// inherited default ACL may widen it, and nothing created in it inherits an
/// ACL the source doesn't have.
fn private_stage(stage: &OwnedFd) -> Result<()> {
    // SAFETY: fchmod and fremovexattr on an open descriptor.
    Errno::result(unsafe { libc::fchmod(stage.as_raw_fd(), 0o700) }).context("chmod stage")?;
    for acl in [c"system.posix_acl_default", c"system.posix_acl_access"] {
        if unsafe { libc::fremovexattr(stage.as_raw_fd(), acl.as_ptr()) } < 0
            && !matches!(Errno::last(), Errno::ENODATA | Errno::EOPNOTSUPP) {
            return Err(Errno::last()).context("remove stage ACL");
        }
    }
    Ok(())
}

/// Whether `entry` in the images directory is a stage of `name`'s
/// registration: `.register-NAME-PID-N`. The two numeric fields keep one
/// name's stages apart from those of a name that extends it (`img-2`).
fn is_stage_of(entry: &[u8], name: &str) -> bool {
    let Some(rest) = entry.strip_prefix(format!(".register-{name}-").as_bytes()) else { return false };
    let digits = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_digit);
    rest.iter().position(|b| *b == b'-').is_some_and(|i| digits(&rest[..i]) && digits(&rest[i + 1..]))
}

/// Deletes stages that crashed registrations of `name` left behind. Called
/// under the exclusive lock, so none of them is in use.
fn remove_stale_stages(images: &Path, name: &str) -> Result<()> {
    for entry in fs::read_dir(images).with_context(|| format!("read {}", images.display()))? {
        let entry = entry.with_context(|| format!("enumerate {}", images.display()))?;
        if is_stage_of(entry.file_name().as_bytes(), name) {
            remove_tree(&entry.path()).with_context(|| format!("delete leftover {}", entry.path().display()))?;
        }
    }
    Ok(())
}

/// Removes a directory tree, or a single non-directory, without following
/// symlinks. Copied directories keep their image modes, which may deny their
/// owner write access (never root, but an unprivileged test user), so a
/// failed removal opens the directories up and tries again.
fn remove_tree(path: &Path) -> std::io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !meta.is_dir() { return fs::remove_file(path); }
    if fs::remove_dir_all(path).is_ok() { return Ok(()); }
    fn open_up(dir: &Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() { open_up(&entry.path())?; }
        }
        Ok(())
    }
    open_up(path)?;
    fs::remove_dir_all(path)
}

/// Retires the registration; the image directory stays usable by name.
pub fn unregister(roots: &Roots, name: &str) -> Result<Entry> {
    let _lock = lock(&roots.images, true)?;
    let mut entry = read_entry(&roots.registry, name)?.filter(|e| e.state == State::Registered)
        .with_context(|| format!("image {name:?} is not registered"))?;
    refuse_if_referenced(roots, name, "unregister")?;
    entry.state = State::Retired;
    write_entry(&roots.registry, &entry)?;
    Ok(entry)
}

/// Removes the image directory (and retires its registration). Refused while
/// any run references it or any run's image is unknown.
pub fn remove(roots: &Roots, name: &str) -> Result<()> {
    validate_image_name(name)?;
    let _lock = lock(&roots.images, true)?;
    let path = roots.images.join(name);
    fs::symlink_metadata(&path).with_context(|| format!("image {name:?}"))?;
    refuse_if_referenced(roots, name, "remove")?;
    if let Some(mut entry) = read_entry(&roots.registry, name)?.filter(|e| e.state == State::Registered) {
        entry.state = State::Retired;
        write_entry(&roots.registry, &entry)?;
    }
    // Leave the name first, then delete the private copy.
    let doomed = roots.images.join(format!(".removing-{name}-{}", std::process::id()));
    fs::rename(&path, &doomed).with_context(|| format!("detach image {name:?}"))?;
    File::open(&roots.images).and_then(|d| d.sync_all()).context("sync image directory")?;
    fs::remove_dir_all(&doomed).with_context(|| format!("delete {}", doomed.display()))
}

/// Rehashes a registered image and compares it with its registration.
pub fn verify(roots: &Roots, name: &str) -> Result<Entry> {
    let _lock = lock(&roots.images, false)?;
    let entry = read_entry(&roots.registry, name)?.filter(|e| e.state == State::Registered)
        .with_context(|| format!("image {name:?} is not registered"))?;
    let dir = open_image(roots, name)?;
    ensure!(dir_identity(&dir)? == entry.directory, "image {name:?} is not the registered directory");
    let tree = tree_digest(&dir)?;
    ensure!(hex(&tree.sha256) == entry.sha256 && tree.entries == entry.entries && tree.bytes == entry.bytes,
        "image {name:?} content differs from its registration");
    Ok(entry)
}

/// Writes `<run>/image` for a new run, under the shared lock so no
/// replacement or removal can interleave. Called after the run directory's
/// quota is set and before anything mounts the image.
pub fn acquire_reference(roots: &Roots, name: &str, run_dir: &Path) -> Result<Reference> {
    let _lock = lock(&roots.images, false)?;
    let dir = open_image(roots, name)?;
    let current = dir_identity(&dir)?;
    // An untrustworthy or unreadable registry gives the run no identity; the
    // create itself still works by name.
    let identity = match read_entry(&roots.registry, name).map_err(|e| format!("image registry unusable: {e:#}")) {
        Err(reason) => Err(reason),
        Ok(entry) => match entry {
        Some(e) if e.state == State::Registered && e.directory == current =>
            Ok(Identity { generation: e.generation, sha256: e.sha256, directory: current }),
        Some(e) if e.state == State::Registered => Err("image directory differs from its registration".into()),
        Some(_) => Err("image registration is retired".into()),
        None => Err("image is not registered".into()),
        },
    };
    let reference = Reference { name: name.to_owned(), identity: identity.map_err(|r: String| one_line(&r)) };
    // Visible before the lock is released. Losing it in a crash leaves a run
    // with an unknown image, which still blocks removal (fails closed).
    crate::container::publish_unsynced(&run_dir.join(REFERENCE_FILE), reference.text().as_bytes())?;
    Ok(reference)
}

// ---------------------------------------------------------------------------
// Canonical tree manifest

/// One manifest record. Paths are relative to the image root without a
/// leading slash; the root itself is the empty path.
pub struct Record<'a> {
    pub path: &'a [u8],
    pub kind: Kind<'a>,
    /// Permission bits including setuid, setgid and sticky (`st_mode & 07777`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime_sec: i64,
    pub mtime_nsec: u32,
    /// Sorted by name bytes.
    pub xattrs: &'a [(Vec<u8>, Vec<u8>)],
}

pub enum Kind<'a> {
    Directory,
    Regular { size: u64, sha256: [u8; 32] },
    /// A later name of a regular file already recorded at entry ordinal `first`.
    HardLink { first: u64 },
    Symlink(&'a [u8]),
    Char { major: u32, minor: u32 },
    Block { major: u32, minor: u32 },
    Fifo,
    Socket,
}

/// Appends one record: marker 1, then (all integers little endian) u32 path
/// length and path, u8 type, u32 mode, u32 uid, u32 gid, i64 mtime seconds,
/// u32 mtime nanoseconds, u32 xattr count and each u32 name length, name, u32
/// value length, value; then the type's fields.
pub fn encode_record(out: &mut Vec<u8>, r: &Record<'_>) {
    let u32le = |out: &mut Vec<u8>, n: u32| out.extend_from_slice(&n.to_le_bytes());
    out.push(1);
    u32le(out, r.path.len() as u32);
    out.extend_from_slice(r.path);
    out.push(match r.kind { Kind::Directory => 1, Kind::Regular { .. } => 2, Kind::HardLink { .. } => 3,
        Kind::Symlink(_) => 4, Kind::Char { .. } => 5, Kind::Block { .. } => 6, Kind::Fifo => 7, Kind::Socket => 8 });
    u32le(out, r.mode);
    u32le(out, r.uid);
    u32le(out, r.gid);
    out.extend_from_slice(&r.mtime_sec.to_le_bytes());
    u32le(out, r.mtime_nsec);
    u32le(out, r.xattrs.len() as u32);
    for (name, value) in r.xattrs {
        u32le(out, name.len() as u32);
        out.extend_from_slice(name);
        u32le(out, value.len() as u32);
        out.extend_from_slice(value);
    }
    match r.kind {
        Kind::Directory | Kind::Fifo | Kind::Socket => {}
        Kind::Regular { size, sha256 } => { out.extend_from_slice(&size.to_le_bytes()); out.extend_from_slice(&sha256); }
        Kind::HardLink { first } => out.extend_from_slice(&first.to_le_bytes()),
        Kind::Symlink(target) => { u32le(out, target.len() as u32); out.extend_from_slice(target); }
        Kind::Char { major, minor } | Kind::Block { major, minor } => { u32le(out, major); u32le(out, minor); }
    }
}

/// Marker 0 and the u64 record count end the stream.
pub fn encode_trailer(out: &mut Vec<u8>, entries: u64) {
    out.push(0);
    out.extend_from_slice(&entries.to_le_bytes());
}

pub struct Tree { pub sha256: [u8; 32], pub entries: u64, pub bytes: u64 }

struct Walk {
    hash: Sha256,
    entries: u64,
    bytes: u64,
    dev: u64,
    /// The image root's mount. A bind mount from the same filesystem keeps
    /// `st_dev`, so only the mount ID proves an entry is in the image's tree.
    mnt: u64,
    links: std::collections::HashMap<(u64, u64), u64>,
    buf: Vec<u8>,
}

/// SHA-256 of the canonical manifest of the tree at `root`: the domain, then
/// records in pre-order with siblings sorted by name bytes, then the trailer.
/// Directories, symlinks and special files are inspected without following;
/// device and FIFO contents are never opened. Crossing a mount, or a file
/// changing while it is read, is an error.
pub fn tree_digest(root: &File) -> Result<Tree> {
    let st = fstat(root.as_raw_fd())?;
    ensure!(st.st_mode & libc::S_IFMT == libc::S_IFDIR, "image root is not a directory");
    let mnt = mount_id(root.as_raw_fd(), None)?;
    let mut walk = Walk { hash: Sha256::new(), entries: 0, bytes: 0, dev: st.st_dev, mnt, links: Default::default(),
        buf: Vec::new() };
    walk.hash.update(TREE_DOMAIN);
    let fd = dup(root.as_raw_fd())?;
    walk.directory(&fd, &st, &mut Vec::new(), 0)?;
    let mut trailer = Vec::new();
    encode_trailer(&mut trailer, walk.entries);
    walk.hash.update(&trailer);
    Ok(Tree { sha256: walk.hash.finish(), entries: walk.entries, bytes: walk.bytes })
}

impl Walk {
    fn emit(&mut self, record: &Record<'_>) -> Result<()> {
        ensure!(self.entries < MAX_ENTRIES, "image has more than {MAX_ENTRIES} entries");
        self.buf.clear();
        encode_record(&mut self.buf, record);
        self.hash.update(&self.buf);
        self.entries += 1;
        Ok(())
    }

    fn directory(&mut self, dir: &OwnedFd, st: &libc::stat, path: &mut Vec<u8>, depth: usize) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "image is deeper than {MAX_DEPTH} directories");
        let xattrs = fd_xattrs(dir.as_raw_fd())?;
        self.emit(&record(path, Kind::Directory, st, &xattrs))?;
        let mut names: Vec<Vec<u8>> = fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
            .context("read image directory")?
            .map(|e| e.map(|e| e.file_name().as_bytes().to_vec()))
            .collect::<std::io::Result<_>>().context("read image directory")?;
        names.sort();
        for name in names {
            let at = path.len();
            if !path.is_empty() { path.push(b'/'); }
            path.extend_from_slice(&name);
            ensure!(path.len() <= MAX_PATH, "image path longer than {MAX_PATH} bytes");
            self.child(dir, &name, path, depth)
                .with_context(|| format!("image entry {}", String::from_utf8_lossy(path)))?;
            path.truncate(at);
        }
        // The entry set and the directory's own metadata were read at
        // different times; refuse a directory that changed in between.
        ensure!(unchanged(st, &fstat(dir.as_raw_fd())?), "directory {} changed while it was walked",
            String::from_utf8_lossy(path));
        Ok(())
    }

    fn child(&mut self, dir: &OwnedFd, name: &[u8], path: &mut Vec<u8>, depth: usize) -> Result<()> {
        let cname = CString::new(name)?;
        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        // SAFETY: fstatat of a name relative to an open directory, no follow.
        Errno::result(unsafe { libc::fstatat(dir.as_raw_fd(), cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })
            .context("stat")?;
        ensure!(st.st_dev == self.dev && mount_id(dir.as_raw_fd(), Some(&cname))? == self.mnt,
            "image crosses a mount");
        let kind = st.st_mode & libc::S_IFMT;
        // Hardlink topology for every non-directory type: a later name of an
        // inode already recorded is a reference to that record's ordinal.
        if kind != libc::S_IFDIR && st.st_nlink > 1 && let Some(&first) = self.links.get(&(st.st_dev, st.st_ino)) {
            let xattrs = path_xattrs(dir, name)?;
            return self.emit(&record(path, Kind::HardLink { first }, &st, &xattrs));
        }
        let ordinal = self.entries;
        self.leaf(dir, &cname, name, &st, path, depth)?;
        if kind != libc::S_IFDIR && st.st_nlink > 1 { self.links.insert((st.st_dev, st.st_ino), ordinal); }
        Ok(())
    }

    fn leaf(&mut self, dir: &OwnedFd, cname: &CString, name: &[u8], st: &libc::stat, path: &mut Vec<u8>,
        depth: usize) -> Result<()> {
        let st = *st;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let fd = openat(dir, cname, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
                same_inode(&fstat(fd.as_raw_fd())?, &st)?;
                ensure!(mount_id(fd.as_raw_fd(), None)? == self.mnt, "image crosses a mount");
                self.directory(&fd, &st, path, depth + 1)
            }
            libc::S_IFREG => {
                let fd = openat(dir, cname, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_NONBLOCK)?;
                let opened = fstat(fd.as_raw_fd())?;
                same_inode(&opened, &st)?;
                ensure!(mount_id(fd.as_raw_fd(), None)? == self.mnt, "image crosses a mount");
                let (size, sha256) = hash_file(&fd)?;
                let after = fstat(fd.as_raw_fd())?;
                ensure!(size == st.st_size as u64 && unchanged(&opened, &after), "file changed while it was hashed");
                let xattrs = fd_xattrs(fd.as_raw_fd())?;
                self.bytes = self.bytes.saturating_add(size);
                self.emit(&record(path, Kind::Regular { size, sha256 }, &st, &xattrs))
            }
            libc::S_IFLNK => {
                let mut target = vec![0u8; MAX_LINK + 1];
                // SAFETY: readlinkat into a buffer of the given length.
                let n = unsafe { libc::readlinkat(dir.as_raw_fd(), cname.as_ptr(), target.as_mut_ptr().cast(), target.len()) };
                let n = Errno::result(n).context("readlink")? as usize;
                ensure!(n <= MAX_LINK, "symlink target longer than {MAX_LINK} bytes");
                target.truncate(n);
                let xattrs = path_xattrs(dir, name)?;
                self.emit(&record(path, Kind::Symlink(&target), &st, &xattrs))
            }
            kind => {
                let (major, minor) = (libc::major(st.st_rdev), libc::minor(st.st_rdev));
                let kind = match kind {
                    libc::S_IFCHR => Kind::Char { major, minor },
                    libc::S_IFBLK => Kind::Block { major, minor },
                    libc::S_IFIFO => Kind::Fifo,
                    libc::S_IFSOCK => Kind::Socket,
                    _ => bail!("unknown file type"),
                };
                let xattrs = path_xattrs(dir, name)?;
                self.emit(&record(path, kind, &st, &xattrs))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Private copy for registration

struct Copy {
    /// The stage directory and the copy root's name in it. Later names of a
    /// hardlinked inode are linked to its first copy by a path relative to
    /// the stage. The stage is root-only (0700), so no one else can change
    /// what that path resolves to, and each link is checked against the
    /// first copy's inode.
    stage: RawFd,
    root: Vec<u8>,
    entries: u64,
    dev: u64,
    mnt: u64,
    /// Source (device, inode) of a multiply linked non-directory → its first
    /// copy's image-relative path and destination inode.
    links: std::collections::HashMap<(u64, u64), (Vec<u8>, u64)>,
    buf: Vec<u8>,
}

/// Copies the tree at `src` into a new directory `name` in `stage`: every
/// entry type, byte, mode (`st_mode & 07777`), owner, xattr, mtime and atime,
/// and the hardlink topology, which is everything the tree manifest covers.
/// The source is walked like `tree_digest` walks it (fd-relative, never
/// following a link, refusing mount crossings, entries replaced mid-walk and
/// files or directories that change while read, with the same bounds).
/// Destination entries are created exclusively, relative to held directory
/// descriptors. Devices, FIFOs and sockets are recreated, never opened.
/// Holes need not survive: runs of zero bytes become holes. On error the
/// partial copy is left for the caller to delete.
fn copy_tree(src: &File, stage: &OwnedFd, name: &CStr) -> Result<()> {
    let st = fstat(src.as_raw_fd())?;
    ensure!(st.st_mode & libc::S_IFMT == libc::S_IFDIR, "image root is not a directory");
    let mnt = mount_id(src.as_raw_fd(), None)?;
    let mut copy = Copy { stage: stage.as_raw_fd(), root: name.to_bytes().to_vec(), entries: 0, dev: st.st_dev, mnt,
        links: Default::default(), buf: vec![0u8; 64 * 1024] };
    let fd = dup(src.as_raw_fd())?;
    copy.directory(&fd, &st, stage, name, &mut Vec::new(), 0)
}

impl Copy {
    fn count(&mut self) -> Result<()> {
        ensure!(self.entries < MAX_ENTRIES, "image has more than {MAX_ENTRIES} entries");
        self.entries += 1;
        Ok(())
    }

    /// Creates `name` in `parent` as a copy of the open source directory
    /// `src`. Its own metadata is applied after its entries, which change
    /// its mtime.
    fn directory(&mut self, src: &OwnedFd, st: &libc::stat, parent: &OwnedFd, name: &CStr, path: &mut Vec<u8>,
        depth: usize) -> Result<()> {
        ensure!(depth <= MAX_DEPTH, "image is deeper than {MAX_DEPTH} directories");
        self.count()?;
        // SAFETY: mkdirat relative to a held directory.
        Errno::result(unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) }).context("create directory")?;
        let dst = openat(parent, name, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
        for child in sorted_names(src)? {
            let at = path.len();
            if !path.is_empty() { path.push(b'/'); }
            path.extend_from_slice(&child);
            ensure!(path.len() <= MAX_PATH, "image path longer than {MAX_PATH} bytes");
            self.child(src, &dst, &child, path, depth)
                .with_context(|| format!("image entry {}", String::from_utf8_lossy(path)))?;
            path.truncate(at);
        }
        let xattrs = fd_xattrs(src.as_raw_fd())?;
        ensure!(unchanged(st, &fstat(src.as_raw_fd())?), "directory {} changed while it was copied",
            String::from_utf8_lossy(path));
        apply_fd(&dst, st, &xattrs)
    }

    fn child(&mut self, src: &OwnedFd, dst: &OwnedFd, name: &[u8], path: &mut Vec<u8>, depth: usize) -> Result<()> {
        let cname = CString::new(name)?;
        let st = fstatat(src, &cname)?;
        ensure!(st.st_dev == self.dev && mount_id(src.as_raw_fd(), Some(&cname))? == self.mnt,
            "image crosses a mount");
        let linked = st.st_mode & libc::S_IFMT != libc::S_IFDIR && st.st_nlink > 1;
        if linked && let Some((first, ino)) = self.links.get(&(st.st_dev, st.st_ino)).cloned() {
            self.count()?;
            let mut old = self.root.clone();
            old.push(b'/');
            old.extend_from_slice(&first);
            let old = CString::new(old)?;
            // SAFETY: linkat between names relative to held directories;
            // flags 0 links a symlink itself, never its target.
            Errno::result(unsafe { libc::linkat(self.stage, old.as_ptr(), dst.as_raw_fd(), cname.as_ptr(), 0) })
                .context("link")?;
            ensure!(fstatat(dst, &cname)?.st_ino == ino, "hardlink did not reach its first copy");
            return Ok(());
        }
        self.leaf(src, dst, &cname, &st, path, depth)?;
        if linked { self.links.insert((st.st_dev, st.st_ino), (path.clone(), fstatat(dst, &cname)?.st_ino)); }
        Ok(())
    }

    fn leaf(&mut self, src: &OwnedFd, dst: &OwnedFd, cname: &CString, st: &libc::stat, path: &mut Vec<u8>,
        depth: usize) -> Result<()> {
        match st.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                let fd = openat(src, cname, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
                same_inode(&fstat(fd.as_raw_fd())?, st)?;
                ensure!(mount_id(fd.as_raw_fd(), None)? == self.mnt, "image crosses a mount");
                self.directory(&fd, st, dst, cname, path, depth + 1)
            }
            libc::S_IFREG => {
                let fd = openat(src, cname, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_NONBLOCK)?;
                let opened = fstat(fd.as_raw_fd())?;
                same_inode(&opened, st)?;
                ensure!(mount_id(fd.as_raw_fd(), None)? == self.mnt, "image crosses a mount");
                self.count()?;
                // SAFETY: exclusive create relative to a held directory.
                let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
                let out = unsafe { libc::openat(dst.as_raw_fd(), cname.as_ptr(), flags, 0o600 as libc::c_uint) };
                let out = unsafe { OwnedFd::from_raw_fd(Errno::result(out).context("create file")?) };
                let size = copy_bytes(&fd, &out, &mut self.buf)?;
                let xattrs = fd_xattrs(fd.as_raw_fd())?;
                let after = fstat(fd.as_raw_fd())?;
                ensure!(size == st.st_size as u64 && unchanged(&opened, &after), "file changed while it was copied");
                apply_fd(&out, &opened, &xattrs)
            }
            libc::S_IFLNK => {
                let mut target = vec![0u8; MAX_LINK + 1];
                // SAFETY: readlinkat into a buffer of the given length.
                let n = unsafe { libc::readlinkat(src.as_raw_fd(), cname.as_ptr(), target.as_mut_ptr().cast(), target.len()) };
                let n = Errno::result(n).context("readlink")? as usize;
                ensure!(n <= MAX_LINK, "symlink target longer than {MAX_LINK} bytes");
                target.truncate(n);
                let target = CString::new(target).context("symlink target contains NUL")?;
                let xattrs = path_xattrs(src, cname.as_bytes())?;
                self.count()?;
                // SAFETY: symlinkat relative to a held directory.
                Errno::result(unsafe { libc::symlinkat(target.as_ptr(), dst.as_raw_fd(), cname.as_ptr()) })
                    .context("create symlink")?;
                apply_at(dst, cname, st, &xattrs, true)
            }
            kind => {
                ensure!(matches!(kind, libc::S_IFCHR | libc::S_IFBLK | libc::S_IFIFO | libc::S_IFSOCK), "unknown file type");
                let rdev = if matches!(kind, libc::S_IFCHR | libc::S_IFBLK) { st.st_rdev } else { 0 };
                let xattrs = path_xattrs(src, cname.as_bytes())?;
                self.count()?;
                // SAFETY: mknodat relative to a held directory; never opened.
                Errno::result(unsafe { libc::mknodat(dst.as_raw_fd(), cname.as_ptr(), kind | 0o600, rdev) })
                    .context("create special file")?;
                apply_at(dst, cname, st, &xattrs, false)
            }
        }
    }
}

/// Copies a file's bytes; a 64 KiB run of zeros becomes a hole.
fn copy_bytes(src: &OwnedFd, dst: &OwnedFd, buf: &mut [u8]) -> Result<u64> {
    let mut size = 0u64;
    loop {
        // SAFETY: read into an owned buffer.
        let n = unsafe { libc::read(src.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            if Errno::last() == Errno::EINTR { continue; }
            return Err(Errno::last()).context("read");
        }
        if n == 0 { break; }
        let chunk = &buf[..n as usize];
        if chunk.iter().all(|b| *b == 0) {
            // SAFETY: lseek on an open descriptor.
            Errno::result(unsafe { libc::lseek(dst.as_raw_fd(), n as libc::off_t, libc::SEEK_CUR) }).context("seek")?;
        } else {
            let mut at = 0;
            while at < chunk.len() {
                // SAFETY: write from an owned buffer.
                let w = unsafe { libc::write(dst.as_raw_fd(), chunk[at..].as_ptr().cast(), chunk.len() - at) };
                if w < 0 {
                    if Errno::last() == Errno::EINTR { continue; }
                    return Err(Errno::last()).context("write");
                }
                at += w as usize;
            }
        }
        size += n as u64;
    }
    // SAFETY: ftruncate on an open descriptor; sets the length a trailing hole leaves short.
    Errno::result(unsafe { libc::ftruncate(dst.as_raw_fd(), size as libc::off_t) }).context("truncate")?;
    Ok(size)
}

fn times(st: &libc::stat) -> [libc::timespec; 2] {
    [libc::timespec { tv_sec: st.st_atime, tv_nsec: st.st_atime_nsec },
        libc::timespec { tv_sec: st.st_mtime, tv_nsec: st.st_mtime_nsec }]
}

/// Owner, then xattrs, then mode, then times, on an open copy. The order
/// matters: chown clears setuid, setgid and `security.capability`.
fn apply_fd(fd: &OwnedFd, st: &libc::stat, xattrs: &[(Vec<u8>, Vec<u8>)]) -> Result<()> {
    let fd = fd.as_raw_fd();
    // SAFETY: metadata calls on an open descriptor with owned buffers.
    Errno::result(unsafe { libc::fchown(fd, st.st_uid, st.st_gid) }).context("chown")?;
    for (name, value) in xattrs {
        let name = CString::new(name.as_slice())?;
        Errno::result(unsafe { libc::fsetxattr(fd, name.as_ptr(), value.as_ptr().cast(), value.len(), 0) })
            .with_context(|| format!("set xattr {}", name.to_string_lossy()))?;
    }
    Errno::result(unsafe { libc::fchmod(fd, st.st_mode & 0o7777) }).context("chmod")?;
    let times = times(st);
    Errno::result(unsafe { libc::futimens(fd, times.as_ptr()) }).context("set times")?;
    Ok(())
}

/// The same for an entry that isn't opened (a symlink or special file),
/// without following it; a symlink has no mode of its own.
fn apply_at(dir: &OwnedFd, name: &CString, st: &libc::stat, xattrs: &[(Vec<u8>, Vec<u8>)], symlink: bool)
    -> Result<()> {
    let at = dir.as_raw_fd();
    // SAFETY: metadata calls on names relative to a held directory.
    Errno::result(unsafe { libc::fchownat(at, name.as_ptr(), st.st_uid, st.st_gid, libc::AT_SYMLINK_NOFOLLOW) })
        .context("chown")?;
    let mut path = format!("/proc/self/fd/{at}/").into_bytes();
    path.extend_from_slice(name.as_bytes());
    let path = CString::new(path)?;
    for (xname, value) in xattrs {
        let xname = CString::new(xname.as_slice())?;
        Errno::result(unsafe { libc::lsetxattr(path.as_ptr(), xname.as_ptr(), value.as_ptr().cast(), value.len(), 0) })
            .with_context(|| format!("set xattr {}", xname.to_string_lossy()))?;
    }
    // A device, FIFO or socket is not a symlink, so this cannot follow one.
    if !symlink {
        Errno::result(unsafe { libc::fchmodat(at, name.as_ptr(), st.st_mode & 0o7777, 0) }).context("chmod")?;
    }
    let times = times(st);
    Errno::result(unsafe { libc::utimensat(at, name.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) })
        .context("set times")?;
    Ok(())
}

fn fstatat(dir: &OwnedFd, name: &CString) -> Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: fstatat of a name relative to an open directory, no follow.
    Errno::result(unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })
        .context("stat")?;
    Ok(st)
}

/// A directory's entry names, sorted by bytes.
fn sorted_names(dir: &OwnedFd) -> Result<Vec<Vec<u8>>> {
    let mut names: Vec<Vec<u8>> = fs::read_dir(format!("/proc/self/fd/{}", dir.as_raw_fd()))
        .context("read image directory")?
        .map(|e| e.map(|e| e.file_name().as_bytes().to_vec()))
        .collect::<std::io::Result<_>>().context("read image directory")?;
    names.sort();
    Ok(names)
}

fn record<'a>(path: &'a [u8], kind: Kind<'a>, st: &libc::stat, xattrs: &'a [(Vec<u8>, Vec<u8>)]) -> Record<'a> {
    Record { path, kind, mode: st.st_mode & 0o7777, uid: st.st_uid, gid: st.st_gid, mtime_sec: st.st_mtime,
        mtime_nsec: st.st_mtime_nsec as u32, xattrs }
}

fn fstat(fd: RawFd) -> Result<libc::stat> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: fstat of an open descriptor.
    Errno::result(unsafe { libc::fstat(fd, &mut st) }).context("fstat")?;
    Ok(st)
}

/// The mount ID of `fd` itself, or of `name` relative to it without following
/// a final symlink. Path lookup crosses into whatever is mounted on `name`, so
/// a bind mount shows up here even when it keeps the same device number.
fn mount_id(fd: RawFd, name: Option<&CString>) -> Result<u64> {
    let mut st = unsafe { std::mem::zeroed::<libc::statx>() };
    let (path, flags) = match name {
        Some(name) => (name.as_ptr(), libc::AT_SYMLINK_NOFOLLOW),
        None => (c"".as_ptr(), libc::AT_EMPTY_PATH),
    };
    // SAFETY: statx relative to an open descriptor into an owned buffer.
    Errno::result(unsafe { libc::statx(fd, path, flags, libc::STATX_MNT_ID, &mut st) }).context("statx mount ID")?;
    ensure!(st.stx_mask & libc::STATX_MNT_ID != 0, "kernel did not report a mount ID");
    Ok(st.stx_mnt_id)
}

fn same_inode(a: &libc::stat, b: &libc::stat) -> Result<()> {
    ensure!(a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode, "entry replaced while walking");
    Ok(())
}

fn unchanged(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_size == b.st_size && a.st_mtime == b.st_mtime && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime && a.st_ctime_nsec == b.st_ctime_nsec
}

fn dup(fd: RawFd) -> Result<OwnedFd> {
    // SAFETY: duplicates an open descriptor with CLOEXEC.
    let n = Errno::result(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) }).context("dup")?;
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

fn openat(dir: &OwnedFd, name: &CStr, flags: i32) -> Result<OwnedFd> {
    openat_raw(dir.as_raw_fd(), name, flags)
}

fn openat_raw(dir: RawFd, name: &CStr, flags: i32) -> Result<OwnedFd> {
    // SAFETY: openat relative to an open directory.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    Ok(unsafe { OwnedFd::from_raw_fd(Errno::result(fd).context("open")?) })
}

fn hash_file(fd: &OwnedFd) -> Result<(u64, [u8; 32])> {
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        // SAFETY: read into an owned buffer.
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            if Errno::last() == Errno::EINTR { continue; }
            return Err(Errno::last()).context("read");
        }
        if n == 0 { return Ok((size, hash.finish())); }
        hash.update(&buf[..n as usize]);
        size += n as u64;
    }
}

/// Parses a NUL-separated xattr name list and fetches each value, sorted.
fn collect_xattrs(list: impl Fn(&mut [u8]) -> isize, get: impl Fn(&CString, &mut [u8]) -> isize)
    -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut names = vec![0u8; MAX_XATTR_BYTES];
    let n = list(&mut names);
    if n < 0 {
        return match Errno::last() { Errno::ENOTSUP => Ok(Vec::new()), e => Err(e).context("list xattrs") };
    }
    names.truncate(n as usize);
    let mut out = Vec::new();
    // One reusable value buffer; each kept value is an exact-size copy (a
    // 64 KiB allocation per value would multiply the walk's memory).
    let mut value = vec![0u8; MAX_XATTR_BYTES];
    for name in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        ensure!(out.len() < MAX_XATTRS, "more than {MAX_XATTRS} xattrs");
        let cname = CString::new(name)?;
        let n = get(&cname, &mut value);
        let n = Errno::result(n).context("read xattr")? as usize;
        out.push((name.to_vec(), value[..n].to_vec()));
    }
    out.sort();
    Ok(out)
}

fn fd_xattrs(fd: RawFd) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    collect_xattrs(
        // SAFETY: fd is open; buffers are owned and sized.
        |buf| unsafe { libc::flistxattr(fd, buf.as_mut_ptr().cast(), buf.len()) },
        |name, buf| unsafe { libc::fgetxattr(fd, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) })
}

/// For entries that can't be opened (symlinks, devices, FIFOs, sockets, extra
/// hardlink names): l*xattr through the held directory's /proc/self/fd path,
/// so only the final component is looked up, and it is not followed.
fn path_xattrs(dir: &OwnedFd, name: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut path = format!("/proc/self/fd/{}/", dir.as_raw_fd()).into_bytes();
    path.extend_from_slice(name);
    let path = CString::new(path)?;
    collect_xattrs(
        // SAFETY: NUL-terminated path; buffers are owned and sized.
        |buf| unsafe { libc::llistxattr(path.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) },
        |name, buf| unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn scratch(tag: &str) -> (PathBuf, Roots) {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("kiln-image-{tag}-{}-{n}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let roots = Roots { images: root.join("images"), registry: root.join("registry"), runs: root.join("runs") };
        fs::create_dir(&roots.images).unwrap();
        fs::create_dir(&roots.runs).unwrap();
        (root, roots)
    }

    fn set_mtime(path: &Path, sec: i64, nsec: i64) {
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [libc::timespec { tv_sec: sec, tv_nsec: nsec }; 2];
        assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, name.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }, 0);
    }

    fn image(roots: &Roots, name: &str) -> PathBuf {
        let dir = roots.images.join(name);
        fs::create_dir_all(dir.join("etc")).unwrap();
        fs::write(dir.join("etc/hostname"), "kiln\n").unwrap();
        fs::write(dir.join("bin"), [0u8, 1, 2]).unwrap();
        symlink("/etc/hostname", dir.join("link")).unwrap();
        fs::hard_link(dir.join("bin"), dir.join("bin2")).unwrap();
        dir
    }

    fn digest(path: &Path) -> Tree { tree_digest(&File::open(path).unwrap()).unwrap() }

    #[test]
    fn golden_record_encoding() {
        let mut out = Vec::new();
        let xattrs = vec![(b"user.a".to_vec(), b"v".to_vec())];
        encode_record(&mut out, &Record { path: b"", kind: Kind::Directory, mode: 0o755, uid: 2_000_000_000,
            gid: 2_000_000_000, mtime_sec: 1, mtime_nsec: 2, xattrs: &[] });
        encode_record(&mut out, &Record { path: b"a", kind: Kind::Regular { size: 3, sha256: Sha256::digest(b"abc") },
            mode: 0o4755, uid: 0, gid: 0, mtime_sec: -1, mtime_nsec: 999_999_999, xattrs: &xattrs });
        encode_record(&mut out, &Record { path: b"b", kind: Kind::HardLink { first: 1 }, mode: 0o4755, uid: 0, gid: 0,
            mtime_sec: -1, mtime_nsec: 999_999_999, xattrs: &[] });
        encode_record(&mut out, &Record { path: b"c", kind: Kind::Symlink(b"/x"), mode: 0o777, uid: 0, gid: 0,
            mtime_sec: 0, mtime_nsec: 0, xattrs: &[] });
        encode_record(&mut out, &Record { path: b"d", kind: Kind::Char { major: 1, minor: 3 }, mode: 0o666, uid: 0,
            gid: 0, mtime_sec: 0, mtime_nsec: 0, xattrs: &[] });
        encode_trailer(&mut out, 5);
        assert_eq!(hex(&out), concat!(
            "01", "00000000", "01", "ed010000", "00943577", "00943577", "0100000000000000", "02000000", "00000000",
            "01", "01000000", "61", "02", "ed090000", "00000000", "00000000", "ffffffffffffffff", "ffc99a3b",
            "01000000", "06000000", "757365722e61", "01000000", "76",
            "0300000000000000", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "01", "01000000", "62", "03", "ed090000", "00000000", "00000000", "ffffffffffffffff", "ffc99a3b",
            "00000000", "0100000000000000",
            "01", "01000000", "63", "04", "ff010000", "00000000", "00000000", "0000000000000000", "00000000",
            "00000000", "02000000", "2f78",
            "01", "01000000", "64", "05", "b6010000", "00000000", "00000000", "0000000000000000", "00000000",
            "00000000", "01000000", "03000000",
            "00", "0500000000000000"));
        let mut stream = TREE_DOMAIN.to_vec(); stream.extend_from_slice(&out);
        assert_eq!(hex(&Sha256::digest(&stream)), "fca85a1249061f75d12ea03317e274ab7d0e1a2b17c675c34b207aa083b2b6a3");
    }

    #[test]
    fn digest_covers_content_metadata_links_and_order() {
        let (root, roots) = scratch("digest");
        let dir = image(&roots, "a");
        for p in ["etc/hostname", "bin", "etc", "link", ""] { set_mtime(&dir.join(p), 100, 5); }
        let base = digest(&dir);
        assert_eq!((base.entries, base.bytes), (6, 8));
        assert_eq!(digest(&dir).sha256, base.sha256, "deterministic");
        // A byte-identical copy elsewhere has the same digest.
        let copy = image(&roots, "b");
        for p in ["etc/hostname", "bin", "etc", "link", ""] { set_mtime(&copy.join(p), 100, 5); }
        assert_eq!(digest(&copy).sha256, base.sha256);
        // Entry changes also move the root's mtime; put it back each time so
        // only the change under test can alter the digest.
        let changed = |f: &dyn Fn(&Path), restore: &dyn Fn(&Path)| {
            f(&copy);
            set_mtime(&copy, 100, 5);
            assert_ne!(digest(&copy).sha256, base.sha256);
            restore(&copy);
            set_mtime(&copy, 100, 5);
            assert_eq!(digest(&copy).sha256, base.sha256);
        };
        changed(&|d| { fs::write(d.join("etc/hostname"), "kilo\n").unwrap(); set_mtime(&d.join("etc/hostname"), 100, 5); },
            &|d| { fs::write(d.join("etc/hostname"), "kiln\n").unwrap(); set_mtime(&d.join("etc/hostname"), 100, 5); });
        changed(&|d| fs::set_permissions(d.join("bin"), fs::Permissions::from_mode(0o4755)).unwrap(),
            &|d| fs::set_permissions(d.join("bin"), fs::Permissions::from_mode(fs::metadata(dir.join("bin")).unwrap().mode() & 0o7777)).unwrap());
        changed(&|d| set_mtime(&d.join("etc"), 100, 6), &|d| set_mtime(&d.join("etc"), 100, 5));
        // Hardlink topology: an independent copy instead of a second name.
        changed(&|d| { fs::remove_file(d.join("bin2")).unwrap(); fs::copy(d.join("bin"), d.join("bin2")).unwrap();
                set_mtime(&d.join("bin2"), fs::metadata(dir.join("bin2")).unwrap().mtime(), fs::metadata(dir.join("bin2")).unwrap().mtime_nsec()); },
            &|d| { fs::remove_file(d.join("bin2")).unwrap(); fs::hard_link(d.join("bin"), d.join("bin2")).unwrap(); });
        changed(&|d| { fs::remove_file(d.join("link")).unwrap(); symlink("/etc/hostnamf", d.join("link")).unwrap(); set_mtime(&d.join("link"), 100, 5); },
            &|d| { fs::remove_file(d.join("link")).unwrap(); symlink("/etc/hostname", d.join("link")).unwrap(); set_mtime(&d.join("link"), 100, 5); });
        // A user xattr counts, where the filesystem supports one.
        let name = CString::new(copy.join("bin").as_os_str().as_bytes()).unwrap();
        if unsafe { libc::setxattr(name.as_ptr(), c"user.kiln".as_ptr(), b"1".as_ptr().cast(), 1, 0) } == 0 {
            assert_ne!(digest(&copy).sha256, base.sha256);
            unsafe { libc::removexattr(name.as_ptr(), c"user.kiln".as_ptr()); }
            assert_eq!(digest(&copy).sha256, base.sha256);
        }
        // A FIFO is recorded by type; its contents are never opened.
        nix::unistd::mkfifo(&copy.join("fifo"), nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let with_fifo = digest(&copy);
        assert_eq!(with_fifo.entries, 7);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn records_and_references_are_canonical() {
        let id = DirIdentity { fsid: 0xabc, ino: 42, btime_sec: 1_700_000_000, btime_nsec: 5 };
        let entry = Entry { name: "alpine".into(), generation: 3, state: State::Registered, sha256: "a".repeat(64),
            directory: id, entries: 10, bytes: 20 };
        assert_eq!(entry.text(), format!("kiln-image 1\nname alpine\ngeneration 3\nstate registered\nsha256 {}\n\
            directory 0000000000000abc:42:1700000000.000000005\nentries 10\nbytes 20\n", "a".repeat(64)));
        assert_eq!(Entry::parse(&entry.text()).unwrap(), entry);
        let reference = Reference { name: "alpine".into(), identity: Ok(Identity { generation: 3,
            sha256: "a".repeat(64), directory: id }) };
        assert_eq!(Reference::parse(&reference.text()).unwrap(), reference);
        let none = Reference { name: "alpine".into(), identity: Err("image is not registered".into()) };
        assert_eq!(none.text(), "kiln-image-ref 1\nname alpine\nidentity none image is not registered\n");
        assert_eq!(Reference::parse(&none.text()).unwrap(), none);
        let text = entry.text();
        for bad in [text.replace("generation 3", "generation 03"), text.replace("generation 3", "generation 0"),
            text.replace("name alpine", "name ../x"), text.replace("state registered", "state other"),
            text.replace(&"a".repeat(64), &"A".repeat(64)), format!("{text}x\n"), text.trim_end().into(),
            text.replace(":42:", ":042:"), text.replace(".000000005", ".5"), text.replace("bytes 20\n", "")] {
            assert!(Entry::parse(&bad).is_err(), "{bad}");
        }
        assert!(Reference::parse("kiln-image-ref 1\nname alpine\nidentity none \n").is_err());
        assert!(Reference::parse("kiln-image-ref 1\nname alpine\nidentity some x\n").is_err());
    }

    #[test]
    fn registry_lifecycle_references_and_replacement() {
        let (root, roots) = scratch("registry");
        let dir = image(&roots, "img");
        // Registration installs a copy in place of the directory, so even a
        // first registration is refused while a run uses the name.
        let run = roots.runs.join("r-0");
        fs::create_dir(&run).unwrap();
        assert_eq!(acquire_reference(&roots, "img", &run).unwrap().identity, Err("image is not registered".into()));
        let refused = register(&roots, "img").unwrap_err().to_string();
        assert!(refused.contains("referenced by r-0") && refused.contains("new image name"), "{refused}");
        assert!(read_entry(&roots.registry, "img").unwrap().is_none());
        fs::remove_dir_all(&run).unwrap();
        let first = register(&roots, "img").unwrap();
        assert_eq!((first.generation, first.state), (1, State::Registered));
        assert_eq!(register(&roots, "img").unwrap(), first, "unchanged content is a no-op");
        assert_eq!(fs::metadata(&roots.registry).unwrap().mode() & 0o777, 0o700);
        verify(&roots, "img").unwrap();

        // A run takes a reference with the identity.
        let run = roots.runs.join("r-1");
        fs::create_dir(&run).unwrap();
        let reference = acquire_reference(&roots, "img", &run).unwrap();
        assert_eq!(reference.identity.as_ref().unwrap().sha256, first.sha256);
        assert_eq!(read_reference(&run).unwrap().unwrap(), reference);

        // Content change: verify fails, replacement refused while referenced.
        fs::write(dir.join("etc/hostname"), "changed\n").unwrap();
        assert!(verify(&roots, "img").is_err());
        let refused = register(&roots, "img").unwrap_err().to_string();
        assert!(refused.contains("referenced by r-1") && refused.contains("new image name"), "{refused}");
        assert!(unregister(&roots, "img").is_err());
        assert!(remove(&roots, "img").is_err());
        // An unknown reference (an older run) also blocks.
        fs::remove_file(run.join(REFERENCE_FILE)).unwrap();
        assert!(register(&roots, "img").unwrap_err().to_string().contains("r-1 (no image reference)"));
        fs::remove_dir(&run).unwrap();

        // Unreferenced: replacement gets a new generation.
        let second = register(&roots, "img").unwrap();
        assert_eq!(second.generation, 2);
        assert_ne!(second.sha256, first.sha256);
        // An unregistered image's run records no identity.
        image(&roots, "plain");
        let run = roots.runs.join("r-2");
        fs::create_dir(&run).unwrap();
        assert_eq!(acquire_reference(&roots, "plain", &run).unwrap().identity, Err("image is not registered".into()));
        // A run of "plain" does not block another image.
        assert_eq!(blocking_references(&roots, "img").unwrap(), Vec::<String>::new());
        fs::remove_dir_all(&run).unwrap();

        // A directory swapped behind the registry is not the registered one.
        fs::rename(&dir, roots.images.join("old")).unwrap();
        image(&roots, "img");
        let run = roots.runs.join("r-3");
        fs::create_dir(&run).unwrap();
        assert_eq!(acquire_reference(&roots, "img", &run).unwrap().identity,
            Err("image directory differs from its registration".into()));
        fs::remove_dir_all(&run).unwrap();

        // Retire, then re-register: generations are never reused.
        let retired = unregister(&roots, "img").unwrap();
        assert_eq!((retired.state, retired.generation), (State::Retired, 2));
        let run = roots.runs.join("r-4");
        fs::create_dir(&run).unwrap();
        assert_eq!(acquire_reference(&roots, "img", &run).unwrap().identity, Err("image registration is retired".into()));
        fs::remove_dir_all(&run).unwrap();
        assert_eq!(register(&roots, "img").unwrap().generation, 3);
        remove(&roots, "img").unwrap();
        assert!(!roots.images.join("img").exists());
        assert_eq!(read_entry(&roots.registry, "img").unwrap().unwrap().state, State::Retired);
        assert!(remove(&roots, "img").is_err());
        // Names are validated before any path is formed.
        for name in ["../x", ".hidden", ""] {
            assert!(register(&roots, name).is_err() && remove(&roots, name).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// A later name of any non-directory inode is a hardlink record, whatever
    /// the first record's type (here a symlink). Pinned against an
    /// independent Python encoding.
    #[test]
    fn golden_hardlinked_symlink_stream() {
        let mut out = Vec::new();
        let meta = |path, kind, mode| Record { path, kind, mode, uid: 0, gid: 0, mtime_sec: 5, mtime_nsec: 6, xattrs: &[] };
        encode_record(&mut out, &Record { mtime_sec: 0, mtime_nsec: 0, ..meta(b"", Kind::Directory, 0o755) });
        encode_record(&mut out, &meta(b"x", Kind::Symlink(b"t"), 0o777));
        encode_record(&mut out, &meta(b"y", Kind::HardLink { first: 1 }, 0o777));
        encode_record(&mut out, &meta(b"z", Kind::Fifo, 0o600));
        encode_trailer(&mut out, 4);
        let mut stream = TREE_DOMAIN.to_vec(); stream.extend_from_slice(&out);
        assert_eq!(hex(&Sha256::digest(&stream)), "6dfe3feda0e00a245470b8372fd800a2d557a7d10ef3d4a4449b65ea372166be");
    }

    /// Adversarial-review HIGH 3: hardlinked symlinks or FIFOs and independent
    /// ones with identical names and metadata must not share a digest.
    #[test]
    fn non_regular_hardlink_topology_changes_the_digest() {
        let (root, roots) = scratch("link-topology");
        for (make_fifo, label) in [(false, "symlink"), (true, "fifo")] {
            let linked = roots.images.join(format!("{label}-linked"));
            let separate = roots.images.join(format!("{label}-separate"));
            for d in [&linked, &separate] { fs::create_dir(d).unwrap(); }
            let make = |p: &Path| if make_fifo {
                nix::unistd::mkfifo(p, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap()
            } else { symlink("target", p).unwrap() };
            make(&linked.join("x"));
            fs::hard_link(linked.join("x"), linked.join("y")).unwrap();
            make(&separate.join("x"));
            make(&separate.join("y"));
            for d in [&linked, &separate] {
                for n in ["x", "y"] { set_mtime(&d.join(n), 100, 5); }
                set_mtime(d, 200, 6);
            }
            assert_eq!(fs::symlink_metadata(linked.join("x")).unwrap().ino(), fs::symlink_metadata(linked.join("y")).unwrap().ino());
            let (a, b) = (digest(&linked), digest(&separate));
            assert_eq!((a.entries, b.entries), (3, 3));
            assert_ne!(a.sha256, b.sha256, "{label} hardlink topology collided");
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// Adversarial-review HIGH 3, in place: the same name, re-registered after
    /// a symlink's hardlink was replaced by an independent symlink, is a
    /// replacement with a new generation, not a no-op.
    #[test]
    fn topology_change_is_a_new_registration() {
        let (root, roots) = scratch("topology-reregister");
        let dir = image(&roots, "img");
        let (x, y) = (dir.join("sx"), dir.join("sy"));
        symlink("target", &x).unwrap();
        fs::hard_link(&x, &y).unwrap();
        set_mtime(&x, 100, 5);
        set_mtime(&dir, 200, 6);
        let first = register(&roots, "img").unwrap();
        fs::remove_file(&y).unwrap();
        symlink("target", &y).unwrap();
        set_mtime(&y, 100, 5);
        set_mtime(&dir, 200, 6);
        assert!(verify(&roots, "img").is_err(), "verify accepted a changed topology");
        let second = register(&roots, "img").unwrap();
        assert_eq!(second.generation, first.generation + 1);
        assert_ne!(second.sha256, first.sha256);
        verify(&roots, "img").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    /// Adversarial-review HIGH 2: a bind mount from the same filesystem keeps
    /// st_dev; registration and verification must still refuse to cross it.
    /// Needs root (CI runs unprivileged and skips; the VM runs it as root).
    #[test]
    fn same_filesystem_bind_mount_is_refused() {
        if unsafe { libc::geteuid() } != 0 { eprintln!("skipped: needs root to bind mount"); return; }
        use nix::mount::{MntFlags, MsFlags, mount, umount2};
        let (root, roots) = scratch("bind-crossing");
        let dir = image(&roots, "img");
        let outside = root.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("sentinel"), "outside the image\n").unwrap();
        fs::create_dir(dir.join("crossed")).unwrap();
        let registered = register(&roots, "img").unwrap();
        struct Unmount(PathBuf);
        impl Drop for Unmount { fn drop(&mut self) { let _ = umount2(&self.0, MntFlags::MNT_DETACH); } }
        mount(Some(&outside), &dir.join("crossed"), None::<&str>, MsFlags::MS_BIND, None::<&str>).unwrap();
        let guard = Unmount(dir.join("crossed"));
        assert_eq!(fs::metadata(dir.join("crossed")).unwrap().dev(), fs::metadata(&dir).unwrap().dev(),
            "fixture must be a same-filesystem bind mount");
        assert!(format!("{:#}", verify(&roots, "img").unwrap_err()).contains("crosses a mount"));
        assert!(format!("{:#}", register(&roots, "img").unwrap_err()).contains("crosses a mount"));
        // A bind mount over a single file is refused too.
        drop(guard);
        fs::write(dir.join("covered"), "image file\n").unwrap();
        mount(Some(&outside.join("sentinel")), &dir.join("covered"), None::<&str>, MsFlags::MS_BIND, None::<&str>).unwrap();
        let guard = Unmount(dir.join("covered"));
        assert!(format!("{:#}", register(&roots, "img").unwrap_err()).contains("crosses a mount"));
        drop(guard);
        assert_eq!(read_entry(&roots.registry, "img").unwrap().unwrap(), registered, "a refusal changed the registry");
        fs::remove_dir_all(root).unwrap();
    }

    /// Hardening from the adversarial review: an unsynchronized change racing
    /// registration either fails it or lands in the copy or only in the
    /// replaced tree; a registered digest always verifies afterwards.
    #[test]
    fn registration_publishes_only_a_real_snapshot() {
        let (root, roots) = scratch("registration-race");
        let dir = image(&roots, "img");
        File::create(dir.join("a-big")).unwrap().set_len(64 * 1024 * 1024).unwrap();
        fs::write(dir.join("z-victim"), b"before").unwrap();
        let other = roots.clone();
        let registering = std::thread::spawn(move || register(&other, "img"));
        std::thread::sleep(std::time::Duration::from_millis(150));
        // The change must race the registration, not follow it (a change to
        // the installed image afterwards is a different, detected case).
        assert!(!registering.is_finished(), "registration finished before the race");
        fs::remove_file(dir.join("z-victim")).unwrap();
        fs::write(dir.join("z-victim"), b"after").unwrap();
        match registering.join().unwrap() {
            Ok(entry) => {
                assert_eq!(verify(&roots, "img").unwrap(), entry);
            }
            Err(e) => assert!(format!("{e:#}").contains("changed while it was"), "{e:#}"),
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// Adversarial-review HIGH (recheck): a writer that watches the walk with
    /// inotify can show two full walks the same mixed state, a=old with
    /// z=new, that it never installs. Registration must register the state
    /// it installs: the digest of the installed tree, which then verifies.
    #[test]
    fn coordinated_writer_cannot_register_a_mixed_snapshot() {
        let (root, roots) = scratch("mixed-snapshot");
        let dir = roots.images.join("img");
        fs::create_dir(&dir).unwrap();
        let a = dir.join("a");
        let z = dir.join("z");
        fs::write(&a, b"old\n").unwrap();
        fs::write(&z, b"old\n").unwrap();
        let delay_1 = dir.join("m-delay");
        let delay_2 = dir.join("zz-delay");
        File::create(&delay_1).unwrap().set_len(512 * 1024 * 1024).unwrap();
        File::create(&delay_2).unwrap().set_len(512 * 1024 * 1024).unwrap();
        for path in [&a, &z, &delay_1, &delay_2, &dir] { set_mtime(path, 100, 5); }

        // Watch closes from the walker. The two sparse delay files leave
        // ample time to move from old/old -> new/new after A was read, and
        // back from new/new -> old/old after Z was read. The mixed old/new
        // state a walk sees is never installed by the writer.
        let notify = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        assert!(notify >= 0, "inotify_init1: {}", std::io::Error::last_os_error());
        let watched = CString::new(dir.as_os_str().as_bytes()).unwrap();
        assert!(unsafe { libc::inotify_add_watch(notify, watched.as_ptr(), libc::IN_CLOSE_NOWRITE) } >= 0,
            "inotify_add_watch: {}", std::io::Error::last_os_error());

        let other = roots.clone();
        let registering = std::thread::spawn(move || register(&other, "img"));
        let mut a_closes = 0;
        let mut z_closes = 0;
        let mut events = [0u8; 4096];
        let give_up = std::time::Instant::now() + std::time::Duration::from_secs(900);
        // Run until the registration has finished and no event is pending.
        loop {
            let mut ready = libc::pollfd { fd: notify, events: libc::POLLIN, revents: 0 };
            let n = unsafe { libc::poll(&mut ready, 1, 100) };
            if n < 0 {
                assert_eq!(Errno::last(), Errno::EINTR, "poll inotify");
                continue;
            }
            if n == 0 {
                if registering.is_finished() { break; }
                assert!(std::time::Instant::now() < give_up, "registration did not finish");
                continue;
            }
            let count = unsafe { libc::read(notify, events.as_mut_ptr().cast(), events.len()) };
            assert!(count > 0, "read inotify: {}", std::io::Error::last_os_error());
            let mut at = 0usize;
            while at < count as usize {
                let event = unsafe { &*(events.as_ptr().add(at).cast::<libc::inotify_event>()) };
                let base = std::mem::size_of::<libc::inotify_event>();
                let raw = unsafe { std::slice::from_raw_parts(events.as_ptr().add(at + base), event.len as usize) };
                let end = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
                let name = &raw[..end];
                if name == b"a" {
                    a_closes += 1;
                    // Forward transition: never pass through old/new.
                    fs::write(&a, b"new\n").unwrap();
                    set_mtime(&a, 100, 5);
                    fs::write(&z, b"new\n").unwrap();
                    set_mtime(&z, 100, 5);
                } else if name == b"z" {
                    z_closes += 1;
                    if z_closes == 1 {
                        // Reset transition: never pass through old/new.
                        fs::write(&z, b"old\n").unwrap();
                        set_mtime(&z, 100, 5);
                        fs::write(&a, b"old\n").unwrap();
                        set_mtime(&a, 100, 5);
                    }
                }
                at += base + event.len as usize;
            }
        }
        unsafe { libc::close(notify); }
        assert!(a_closes >= 1 && z_closes >= 1, "the writer never acted ({a_closes}, {z_closes})");
        let registered = registering.join().unwrap().unwrap();
        let installed = tree_digest(&open_image(&roots, "img").unwrap()).unwrap();
        assert_eq!(registered.sha256, hex(&installed.sha256), "registered a state that is not installed");
        verify(&roots, "img").unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    /// Registration hashes a private copy and installs exactly that copy:
    /// a new directory whose tree has the source's digest, with no stage
    /// left behind; registering again is a no-op.
    #[test]
    fn registration_installs_a_private_copy_atomically() {
        use nix::sys::stat::{Mode, SFlag, mknod};
        let (root, roots) = scratch("private-copy");
        let dir = roots.images.join("img");
        fs::create_dir_all(dir.join("nested/deeper")).unwrap();
        fs::write(dir.join("regular"), b"bytes\n").unwrap();
        fs::write(dir.join("setuid"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(dir.join("setuid"), fs::Permissions::from_mode(0o4755)).unwrap();
        let regular = CString::new(dir.join("regular").as_os_str().as_bytes()).unwrap();
        let xattr = unsafe { libc::setxattr(regular.as_ptr(), c"user.kiln".as_ptr(), b"v".as_ptr().cast(), 1, 0) } == 0;
        if !xattr { eprintln!("note: no user xattrs here; that part is skipped"); }
        File::create(dir.join("sparse")).unwrap().set_len(1024 * 1024).unwrap();
        symlink("regular", dir.join("link")).unwrap();
        nix::unistd::mkfifo(&dir.join("fifo"), Mode::from_bits_truncate(0o640)).unwrap();
        let socket = mknod(&dir.join("socket"), SFlag::S_IFSOCK, Mode::from_bits_truncate(0o600), 0).is_ok();
        fs::write(dir.join("nested/deeper/file"), b"deep\n").unwrap();
        // An internal hardlink pair across directories, and a hardlinked symlink pair.
        fs::hard_link(dir.join("regular"), dir.join("nested/regular-link")).unwrap();
        symlink("target", dir.join("sym-a")).unwrap();
        fs::hard_link(dir.join("sym-a"), dir.join("nested/sym-b")).unwrap();
        let mut leaves = vec!["regular", "setuid", "sparse", "link", "fifo", "nested/deeper/file", "sym-a"];
        if socket { leaves.push("socket"); }
        for p in leaves { set_mtime(&dir.join(p), 1_700_000_000, 123_456_789); }
        for d in ["nested/deeper", "nested"] {
            fs::set_permissions(dir.join(d), fs::Permissions::from_mode(0o555)).unwrap();
            set_mtime(&dir.join(d), 1_600_000_000, 987_654_321);
        }
        set_mtime(&dir, 1_500_000_000, 1);

        let opened = open_image(&roots, "img").unwrap();
        let source_id = dir_identity(&opened).unwrap();
        let source = tree_digest(&opened).unwrap();
        drop(opened);
        let entry = register(&roots, "img").unwrap();
        assert_ne!(entry.directory, source_id, "the registered directory must be the installed copy");
        let installed = open_image(&roots, "img").unwrap();
        assert_eq!(dir_identity(&installed).unwrap(), entry.directory);
        let tree = tree_digest(&installed).unwrap();
        assert_eq!((hex(&tree.sha256), tree.entries, tree.bytes), (hex(&source.sha256), source.entries, source.bytes),
            "the copy is not faithful");
        assert_eq!(entry.sha256, hex(&source.sha256));
        // Spot checks of what the digest covers.
        assert_eq!(fs::metadata(dir.join("setuid")).unwrap().mode() & 0o7777, 0o4755);
        assert_eq!(fs::metadata(dir.join("nested")).unwrap().mode() & 0o7777, 0o555);
        assert_eq!(fs::metadata(dir.join("regular")).unwrap().ino(),
            fs::metadata(dir.join("nested/regular-link")).unwrap().ino());
        assert_eq!(fs::symlink_metadata(dir.join("sym-a")).unwrap().ino(),
            fs::symlink_metadata(dir.join("nested/sym-b")).unwrap().ino());
        assert_eq!(fs::read(dir.join("sparse")).unwrap().len(), 1024 * 1024);
        if xattr {
            let mut value = [0u8; 8];
            let n = unsafe { libc::getxattr(regular.as_ptr(), c"user.kiln".as_ptr(), value.as_mut_ptr().cast(), value.len()) };
            assert_eq!(&value[..n as usize], b"v");
        }
        let left: Vec<_> = fs::read_dir(&roots.images).unwrap().map(|e| e.unwrap().file_name())
            .filter(|n| n.as_bytes().starts_with(b".register-")).collect();
        assert!(left.is_empty(), "stages left behind: {left:?}");
        assert_eq!(register(&roots, "img").unwrap(), entry, "unchanged content is a no-op");
        assert_eq!(dir_identity(&open_image(&roots, "img").unwrap()).unwrap(), entry.directory);
        verify(&roots, "img").unwrap();
        remove_tree(&root).unwrap();
    }

    /// A crashed registration's stage is deleted by the next registration of
    /// that name; another name's stage is left alone.
    #[test]
    fn registration_deletes_leftover_stages() {
        let (root, roots) = scratch("leftover-stage");
        image(&roots, "img");
        let leftover = roots.images.join(".register-img-1-0");
        let other = roots.images.join(".register-img-2-1-0");
        for stage in [&leftover, &other] {
            fs::create_dir_all(stage.join("tree")).unwrap();
            fs::write(stage.join("tree/file"), b"partial").unwrap();
        }
        assert!(is_stage_of(b".register-img-1-0", "img") && !is_stage_of(b".register-img-2-1-0", "img"));
        assert!(is_stage_of(b".register-img-2-1-0", "img-2") && !is_stage_of(b".register-img-", "img"));
        register(&roots, "img").unwrap();
        assert!(!leftover.exists(), "leftover stage survived");
        assert!(other.join("tree/file").exists(), "another name's stage was deleted");
        fs::remove_dir_all(root).unwrap();
    }

    /// Hardening from the adversarial review: a symlinked or writable registry
    /// root is refused on every path, including reference acquisition.
    #[test]
    fn untrusted_registry_roots_are_refused_everywhere() {
        let (root, mut roots) = scratch("registry-trust");
        image(&roots, "img");
        let opened = open_image(&roots, "img").unwrap();
        let tree = tree_digest(&opened).unwrap();
        let forged = Entry { name: "img".into(), generation: 77, state: State::Registered, sha256: hex(&tree.sha256),
            directory: dir_identity(&opened).unwrap(), entries: tree.entries, bytes: tree.bytes };
        let attacker = root.join("attacker-registry");
        fs::create_dir(&attacker).unwrap();
        fs::write(attacker.join("img"), forged.text()).unwrap();
        let link = root.join("registry-link");
        symlink(&attacker, &link).unwrap();
        for (registry, mode) in [(link, 0o700), (attacker.clone(), 0o777), (attacker.clone(), 0o720)] {
            fs::set_permissions(&attacker, fs::Permissions::from_mode(mode)).unwrap();
            roots.registry = registry;
            assert!(read_entry(&roots.registry, "img").is_err());
            assert!(register(&roots, "img").is_err() && verify(&roots, "img").is_err());
            let run = roots.runs.join("r-1");
            fs::create_dir(&run).unwrap();
            let reference = acquire_reference(&roots, "img", &run).unwrap();
            assert!(reference.identity.unwrap_err().contains("image registry unusable"));
            fs::remove_dir_all(&run).unwrap();
        }
        // A symlinked entry inside a trusted registry is refused as well.
        fs::set_permissions(&attacker, fs::Permissions::from_mode(0o700)).unwrap();
        roots.registry = root.join("registry");
        fs::create_dir(&roots.registry).unwrap();
        fs::set_permissions(&roots.registry, fs::Permissions::from_mode(0o700)).unwrap();
        symlink(attacker.join("img"), roots.registry.join("img")).unwrap();
        assert!(read_entry(&roots.registry, "img").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    /// Checkpoint headers reference their image; an unreadable one (or an
    /// unknown entry in the namespace) blocks every image, an empty namespace
    /// none.
    #[test]
    fn checkpoint_artifacts_are_image_references() {
        use std::io::Write;
        let (root, roots) = scratch("checkpoint-refs");
        image(&roots, "img");
        let ns = roots.runs.join(crate::checkpoint::store::NAMESPACE);
        let private = |p: &Path| fs::DirBuilder::new().mode(0o700).create(p).unwrap();
        private(&ns);
        assert_eq!(blocking_references(&roots, "img").unwrap(), Vec::<String>::new());
        let instance = ns.join("0123456789abcdef0123456789abcdef");
        private(&instance);
        let artifact = instance.join(format!("cp-{}", "1".repeat(32)));
        private(&artifact);
        let blocked = blocking_references(&roots, "img").unwrap();
        assert_eq!(blocked.len(), 1);
        assert!(blocked[0].contains("unreadable checkpoint header"), "{blocked:?}");
        let header = crate::checkpoint::store::Header { instance: "0123456789abcdef0123456789abcdef".into(),
            checkpoint: format!("cp-{}", "1".repeat(32)), generation: 1, source: "18e0-42".into(), source_lease: 1,
            image: "img".into(), image_generation: 1, image_sha256: "ab".repeat(32),
            image_directory: "0000000000000001:2:3.000000004".into(), layout: "index=off".into(), limit_bytes: 1 << 20 };
        let path = artifact.join("header");
        fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).unwrap()
            .write_all(header.text().as_bytes()).unwrap();
        assert!(blocking_references(&roots, "img").unwrap()[0].starts_with("checkpoint 0123456789abcdef0123456789abcdef/cp-"));
        assert!(register(&roots, "img").is_err() && remove(&roots, "img").is_err());
        assert_eq!(blocking_references(&roots, "other").unwrap(), Vec::<String>::new());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exclusive_lock_serializes_reference_acquisition() {
        let (root, roots) = scratch("lock");
        image(&roots, "img");
        register(&roots, "img").unwrap();
        let held = lock(&roots.images, true).unwrap();
        let run = roots.runs.join("r-1");
        fs::create_dir(&run).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let (r2, run2) = (roots.clone(), run.clone());
        let t = std::thread::spawn(move || { tx.send(acquire_reference(&r2, "img", &run2).is_ok()).unwrap(); });
        assert!(rx.recv_timeout(std::time::Duration::from_millis(200)).is_err(), "shared lock waited");
        assert!(!run.join(REFERENCE_FILE).exists());
        drop(held);
        assert!(rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap());
        t.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
