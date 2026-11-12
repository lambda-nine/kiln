//! Capture (`kiln checkpoint capture`) and the fork preflight of
//! `kiln create --from-checkpoint`.
//!
//! Capture, in order: refuse an unsupported source before allocating
//! anything; take the source's operation 6 lease in this process; rehash the
//! source's image against the identity its run recorded; create the staging
//! directory under its quota and write the header; walk and copy the upper
//! while watching the lease; re-check the run's identity and metadata; release
//! the lease (Released is required); then write the manifest and marker and
//! publish. Source reads all happen before the release, so nothing after it
//! can observe a later write. Any failure removes the staging directory; a
//! killed worker leaves only staging, which inventory shows and `rm` removes.

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use nix::errno::Errno;

use super::manifest::{Body, Manifest};
use super::restore::check_generated;
use super::store::{Artifact, Header, Marker, Store, binding_sha256};
use super::walk::{self, IdMap, Options, fstat, openat};
use super::{Policy, Reason, read_policy, refuse, validate_checkpoint_id, validate_instance};
use crate::exec_protocol::FailureKind;
use crate::image::{self, DirIdentity, Roots};
use crate::protected;

pub struct Request {
    pub instance: String,
    pub checkpoint: String,
    pub generation: u64,
    pub limit_bytes: u64,
    pub source: String,
}

pub fn dir_text(d: &DirIdentity) -> String {
    format!("{:016x}:{}:{}.{:09}", d.fsid, d.ino, d.btime_sec, d.btime_nsec)
}

/// The run's generated entries from its layout record; only entries the
/// protected-path contract knows are accepted.
fn generated(layout: &crate::overlay::Layout) -> Result<Vec<&'static str>> {
    layout.generated.iter().map(|g| match g.as_str() {
        protected::RESOLV_CONF => Ok(protected::RESOLV_CONF),
        _ => Err(refuse(Reason::LayoutUnsupported, "the run records an unknown generated entry")),
    }).collect()
}

fn reserved_overlap(policy: &Policy, generated: &[&str]) -> Result<()> {
    for path in &policy.writable {
        ensure!(!protected::writable_overlaps_reserved(path, generated), refuse(Reason::LayoutUnsupported,
            format!("writable path {path} overlaps a reserved runtime path")));
    }
    Ok(())
}

fn open_dir(path: &Path) -> Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: open of a root-owned run directory, not following.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    Ok(unsafe { OwnedFd::from_raw_fd(Errno::result(fd).with_context(|| format!("open {}", path.display()))?) })
}

/// What the source run's metadata says, read twice: before the copy and
/// after it, still under the lease, and required to be identical.
#[derive(PartialEq, Eq)]
struct SourceFacts { run: (u64, u64), upper: (u64, u64), reference: String, layout: String, policy: String, shim: String }

fn facts(run: &Path) -> Result<SourceFacts> {
    let id = |p: &Path| -> Result<(u64, u64)> {
        let st = fstat(open_dir(p)?.as_raw_fd())?;
        Ok((st.st_dev, st.st_ino))
    };
    let text = |name: &str| std::fs::read_to_string(run.join(name)).with_context(|| format!("read run {name}"));
    Ok(SourceFacts { run: id(run)?, upper: id(&run.join("upper"))?, reference: text(image::REFERENCE_FILE)?,
        layout: text(crate::overlay::LAYOUT_FILE)?, policy: text(super::POLICY_FILE)?, shim: text("shim.pid")? })
}

pub fn capture(store: &Store, roots: &Roots, req: &Request) -> Result<String> {
    validate_instance(&req.instance)?;
    validate_checkpoint_id(&req.checkpoint)?;
    if !crate::validation::valid_persistent_id(&req.source) {
        return Err(refuse(Reason::InvalidRequest, format!("invalid sandbox ID {:?}", req.source)));
    }
    ensure!(req.generation > 0 && (super::MIN_LIMIT_BYTES..=super::MAX_LIMIT_BYTES).contains(&req.limit_bytes),
        refuse(Reason::InvalidRequest, format!("generation must be nonzero and the limit {}..={} bytes",
            super::MIN_LIMIT_BYTES, super::MAX_LIMIT_BYTES)));
    let run = roots.runs.join(&req.source);
    let support = crate::persistent::checkpoint_source_support(&run)
        .map_err(|e| refuse(Reason::InvalidRequest, format!("sandbox {}: {e:#}", req.source)))?;
    if let Err(why) = support { return Err(refuse(Reason::SandboxUnsupported, why)); }
    let policy = read_policy(&run)?.ok_or_else(|| refuse(Reason::SandboxUnsupported,
        "the run has no policy record (created by an older kiln)"))?;
    let layout = crate::overlay::read_layout(&run)?.context("layout record vanished")?;
    let generated = generated(&layout)?;
    reserved_overlap(&policy, &generated)?;
    let reference = image::read_reference(&run)?.context("image reference vanished")?;
    let identity = reference.identity.clone().map_err(|why| refuse(Reason::SandboxUnsupported, why))?;
    let before = facts(&run)?;
    let run_fd = open_dir(&run)?;
    let st = fstat(run_fd.as_raw_fd())?;
    ensure!(st.st_uid == unsafe { libc::geteuid() } && st.st_mode & 0o077 == 0, "run directory is not private");
    let upper = openat(&run_fd, &CString::from(c"upper"), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW
        | libc::O_NOATIME)?;

    let lease = match crate::persistent::acquire_lease(&req.source)? {
        Ok(lease) => lease,
        Err(o) => return Err(refuse(match o.kind {
            FailureKind::Busy => Reason::Busy,
            FailureKind::Incompatible => Reason::SandboxUnsupported,
            _ => Reason::Io,
        }, o.diagnostic)),
    };
    // The base image must still be the one the run recorded, by content.
    let entry = image::verify(roots, &reference.name)
        .map_err(|e| refuse(Reason::ImageUnavailable, format!("image {:?}: {e:#}", reference.name)))?;
    ensure!(entry.generation == identity.generation && entry.sha256 == identity.sha256
        && entry.directory == identity.directory, refuse(Reason::ImageUnavailable,
        format!("image {:?} is no longer the registration the sandbox was created from", reference.name)));

    let header = Header { instance: req.instance.clone(), checkpoint: req.checkpoint.clone(), generation: req.generation,
        source: req.source.clone(), source_lease: lease.generation, image: reference.name.clone(),
        image_generation: identity.generation, image_sha256: identity.sha256.clone(),
        image_directory: dir_text(&identity.directory), layout: layout.effective.clone().context("layout")?,
        limit_bytes: req.limit_bytes };
    let manifest = |walked: walk::Walked| Manifest { image_sha256: identity.sha256.clone(),
        read_only_root: policy.read_only_root, writable_paths: policy.writable.clone(),
        excluded_paths: protected::excluded_paths(&generated), root: walked.root, entries: walked.entries };
    let opts = Options { generated: &generated, budget: req.limit_bytes, ids: IdMap::SANDBOX };
    let image_dir = OwnedFd::from(image::open_image(roots, &reference.name)
        .map_err(|e| refuse(Reason::ImageUnavailable, format!("{e:#}")))?);
    let mut lease = Some(lease);
    write_artifact(store, &header, &upper, &opts, &manifest, &mut |walked| {
        let held = lease.as_ref().context("lease already released")?;
        ensure!(!held.lost(), refuse(Reason::Io, "the sandbox ended the checkpoint lease during capture"));
        if let Some(walked) = walked {
            // Still under the lease: every writable path exists as a plain
            // directory in what a fork will see (a fork never creates one).
            check_writable(&walked.entries, policy.read_only_root, &policy.writable, &image_dir)?;
            ensure!(facts(&run)? == before, refuse(Reason::Io, "the source sandbox changed identity during capture"));
            lease.take().unwrap().release().map_err(|e| refuse(Reason::Io, format!("{e:#}")))?;
        }
        Ok(())
    })
}

/// Stages, walks, finishes and publishes one artifact. `check(None)` runs
/// during the walk; `check(Some(walked))` runs once after the last source
/// read (capture checks writable paths and releases its lease there).
///
/// One staging directory, created exclusively and locked, is used from start
/// to reply: the manifest and marker are written and synced, the staged
/// directory is validated as any reader would through that same locked
/// descriptor, its charge S is measured and checked against R, and only then
/// is it renamed into place (never replacing). The record comes from that
/// locked artifact and the original header, never from reopening the name.
pub fn write_artifact(store: &Store, header: &Header, upper: &OwnedFd, opts: &Options<'_>,
    manifest: &dyn Fn(walk::Walked) -> Manifest, check: &mut dyn FnMut(Option<&walk::Walked>) -> Result<()>)
    -> Result<String> {
    let mut staging = store.begin(header)?;
    let walked = walk::walk(upper, opts, &mut staging, &mut || check(None))?;
    check(Some(&walked))?;
    let bookkeeping = walked.bookkeeping;
    let manifest = manifest(walked);
    // Our own output must pass the rules every reader applies.
    let stats = manifest.validate()?;
    let bytes = manifest.encode();
    drop(manifest);
    let content = super::manifest::content_sha256(&bytes);
    let marker = Marker { content, binding: binding_sha256(&staging.header_bytes, &content), entries: stats.entries,
        objects: stats.objects, logical: stats.logical, manifest_bytes: bytes.len() as u64, bookkeeping };
    let (artifact, charge) = staging.publish(bytes, &marker)?;
    Ok(artifact.record(&charge))
}

/// Whether every configured writable path (and, for a read-only root, the
/// default scratch directories Landlock opens) resolves to a plain directory
/// in the merged view: the captured upper `entries` over the verified image
/// at `image`, with overlay semantics (an upper directory merges with a lower
/// directory unless opaque; a whiteout or non-directory hides everything).
/// Image components are opened without following. A fork never creates
/// writable directories, so an absent one would make the fork differ from the
/// checkpoint: refused instead.
pub fn check_writable(entries: &[super::manifest::Entry], read_only_root: bool, writable: &[String], image: &OwnedFd)
    -> Result<()> {
    if !read_only_root { return Ok(()); }
    let defaults = crate::landlock::DEFAULT_WRITABLE.iter().filter(|p| !p.starts_with(protected::DEV));
    for path in defaults.map(|p| p.to_string()).chain(writable.iter().cloned()) {
        let missing = || refuse(Reason::LayoutUnsupported, format!("writable path {path} is absent or not a plain \
            directory in the checkpoint; a sandbox restored from it never creates one"));
        let mut lower = Some(image.try_clone()?);
        let mut prefix: Vec<u8> = Vec::new();
        for part in path.as_bytes().split(|b| *b == b'/').filter(|p| !p.is_empty()) {
            if !prefix.is_empty() { prefix.push(b'/'); }
            prefix.extend_from_slice(part);
            let name = CString::new(part)?;
            let next = lower.as_ref().and_then(|l| openat(l, &name, libc::O_RDONLY | libc::O_DIRECTORY
                | libc::O_NOFOLLOW).ok());
            let upper = entries.binary_search_by(|e| {
                let a: Vec<&[u8]> = e.path.split(|b| *b == b'/').collect();
                let b: Vec<&[u8]> = prefix.split(|b| *b == b'/').collect();
                a.cmp(&b)
            }).ok().map(|i| &entries[i].body);
            lower = match upper {
                Some(Body::Dir { opaque, .. }) => if *opaque { None } else { next },
                Some(_) => return Err(missing()),
                None => Some(next.ok_or_else(missing)?),
            };
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fork preflight

/// What a new sandbox created from a checkpoint needs after the preflight.
pub struct Fork {
    /// Holds the artifact's shared lock until the restore has finished.
    pub artifact: Artifact,
    pub info: ForkInfo,
}

/// Plain data the sandbox's init needs: the captured times of the
/// directories its own bootstrap writes can touch (the DNS file's parent and
/// the root), reapplied through no-follow descriptors after those writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkInfo {
    pub root_mtime: (i64, u32),
    pub etc_mtime: Option<(i64, u32)>,
}

/// Everything checkable before allocation, as typed refusals: the artifact
/// (structure and digests), the image by name and rehashed content, the
/// spec (root-write policy and writable set), the new sandbox's generated
/// entries, and its disk against the charge S.
pub fn preflight(store: &Store, roots: &Roots, source: &str, image_name: &str, policy: &Policy, generated: &[&str],
    disk: Option<u64>) -> Result<Fork> {
    let (instance, checkpoint) = source.split_once('/')
        .ok_or_else(|| refuse(Reason::InvalidRequest, "--from-checkpoint takes INSTANCE/CHECKPOINT"))?;
    let artifact = store.open(instance, checkpoint, false)?;
    let m = &artifact.manifest;
    ensure!(artifact.header.image == image_name, refuse(Reason::SpecMismatch,
        format!("the checkpoint was taken from image {:?}", artifact.header.image)));
    ensure!(m.read_only_root == policy.read_only_root && m.writable_paths == policy.writable,
        refuse(Reason::SpecMismatch, "the root-write policy or writable paths differ from the checkpoint's"));
    reserved_overlap(policy, generated)?;
    check_generated(m, generated)?;
    let entry = image::verify(roots, image_name)
        .map_err(|e| refuse(Reason::ImageUnavailable, format!("image {image_name:?}: {e:#}")))?;
    ensure!(entry.sha256 == m.image_sha256, refuse(Reason::ImageUnavailable,
        format!("image {image_name:?} no longer has the checkpoint's content")));
    let image_dir = OwnedFd::from(image::open_image(roots, image_name)
        .map_err(|e| refuse(Reason::ImageUnavailable, format!("{e:#}")))?);
    check_writable(&m.entries, m.read_only_root, &m.writable_paths, &image_dir)?;
    let charge = artifact.charge(store.require_quota)?;
    if let Some(disk) = disk {
        ensure!(disk >= charge.charge, refuse(Reason::DiskTooSmall,
            format!("the disk limit {disk} is below the checkpoint's size {}", charge.charge)));
    }
    let etc_mtime = m.entries.iter().find_map(|e| match &e.body {
        Body::Dir { meta, .. } if e.path == b"etc" => Some(meta.mtime),
        _ => None,
    });
    let info = ForkInfo { root_mtime: m.root.mtime, etc_mtime };
    Ok(Fork { artifact, info })
}

/// The restore step of a fork's create, after the run's quota, directories
/// and image reference exist and before anything mounts: the reference must
/// carry the checkpoint's image content, then the upper is rebuilt.
pub fn restore_into(fork: Fork, run_dir: &Path, generated: &[&str]) -> Result<()> {
    let reference = image::read_reference(run_dir)?.context("the new run has no image reference")?;
    let identity = reference.identity.map_err(|why| refuse(Reason::ImageUnavailable, why))?;
    ensure!(identity.sha256 == fork.artifact.manifest.image_sha256,
        refuse(Reason::ImageUnavailable, "the image changed between preflight and create"));
    let run = open_dir(run_dir)?;
    let upper = openat(&run, &CString::from(c"upper"), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW)?;
    super::restore::restore(&fork.artifact, &upper, IdMap::SANDBOX, generated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::store::Item;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;

    fn scratch(tag: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("kiln-cpcap-{tag}-{}-{n}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn me() -> IdMap { IdMap { uid_base: unsafe { libc::geteuid() }, gid_base: unsafe { libc::getegid() }, count: 1 } }

    const INSTANCE: &str = "0123456789abcdef0123456789abcdef";

    fn cp(n: u32) -> String { format!("cp-{n:032x}") }

    fn header(checkpoint: &str, limit: u64) -> Header {
        Header { instance: INSTANCE.into(), checkpoint: checkpoint.into(), generation: 1, source: "18e0-42".into(),
            source_lease: 7, image: "alpine".into(), image_generation: 1, image_sha256: "cd".repeat(32),
            image_directory: "0000000000000001:2:3.000000004".into(),
            layout: "index=off metacopy=off nfs_export=off redirect_dir=nofollow".into(), limit_bytes: limit }
    }

    fn manifest_of(w: walk::Walked) -> Manifest {
        Manifest { image_sha256: "cd".repeat(32), read_only_root: false, writable_paths: vec![],
            excluded_paths: protected::excluded_paths(&[]), root: w.root, entries: w.entries }
    }

    fn capture_dir(store: &Store, upper: &Path, checkpoint: &str, limit: u64) -> Result<String> {
        let opts = Options { generated: &[], budget: limit, ids: me() };
        write_artifact(store, &header(checkpoint, limit), &open_dir(upper)?, &opts, &manifest_of, &mut |_| Ok(()))
    }

    fn set_mtime(path: &Path, sec: i64, nsec: i64) {
        let name = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        let times = [libc::timespec { tv_sec: sec, tv_nsec: nsec }; 2];
        assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, name.as_ptr(), times.as_ptr(), libc::AT_SYMLINK_NOFOLLOW) }, 0);
    }

    /// A workspace with every type the format keeps, hostile names and links
    /// pointing everywhere, fixed times.
    fn workspace(u: &Path) {
        fs::create_dir_all(u.join("workspace/sub/deeper")).unwrap();
        fs::create_dir_all(u.join("tmp")).unwrap();
        fs::write(u.join("workspace/a.txt"), b"alpha\n").unwrap();
        fs::write(u.join("workspace/empty"), b"").unwrap();
        fs::hard_link(u.join("workspace/a.txt"), u.join("workspace/sub/a-link")).unwrap();
        fs::write(u.join("workspace/n\u{e9}w line\n"), b"x").unwrap();
        fs::write(u.join(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(b"workspace/raw-\xff\xfe")), b"r").unwrap();
        for (name, target) in [("abs", "/etc/shadow"), ("up", "../../../../etc/passwd"), ("self", "self"),
            ("dir-link", "/workspace/sub"), ("proc", "/proc/self/root")] {
            symlink(target, u.join("workspace").join(name)).unwrap();
        }
        let f = fs::File::create(u.join("workspace/sparse")).unwrap();
        f.set_len(5 << 20).unwrap();
        use std::os::unix::fs::FileExt;
        f.write_all_at(b"middle", 2 << 20).unwrap();
        drop(f);
        fs::set_permissions(u.join("workspace/a.txt"), fs::Permissions::from_mode(0o4751)).unwrap();
        fs::set_permissions(u.join("tmp"), fs::Permissions::from_mode(0o1777)).unwrap();
        fs::set_permissions(u.join("workspace/sub/deeper"), fs::Permissions::from_mode(0o555)).unwrap();
        let name = CString::new(u.join("workspace/empty").as_os_str().as_encoded_bytes()).unwrap();
        // Where the filesystem supports user xattrs.
        unsafe { libc::setxattr(name.as_ptr(), c"user.note".as_ptr(), b"\x00\x01v".as_ptr().cast(), 3, 0) };
        for p in ["workspace/sub/deeper", "workspace/sub", "workspace/a.txt", "workspace/abs", "tmp", "workspace", ""] {
            set_mtime(&u.join(p), 1_700_000_000 + p.len() as i64, 123_456_789);
        }
    }

    #[test]
    fn capture_restore_round_trip_is_exact_and_independent() {
        let root = scratch("roundtrip");
        let store = Store::under(&root.join("runs"), false);
        fs::create_dir(root.join("runs")).unwrap();
        let src = root.join("src");
        fs::create_dir(&src).unwrap();
        workspace(&src);
        let record = capture_dir(&store, &src, &cp(1), 64 << 20).unwrap();
        assert!(record.starts_with("kiln-checkpoint-record 1\n") && record.contains("limit-bytes 67108864\n"), "{record}");
        let artifact = store.open(INSTANCE, &cp(1), false).unwrap();
        artifact.verify_objects().unwrap();
        let charge = artifact.charge(false).unwrap();
        assert_eq!(charge.logical, 6 + 1 + 1 + (5 << 20));
        assert!(charge.charge >= charge.logical + 16384 * charge.entries && charge.allocated < (5 << 20),
            "holes stay holes in the object: {charge:?}");
        // Restore into two fresh uppers; each is exact.
        let forks: Vec<PathBuf> = (0..2).map(|i| {
            let dest = root.join(format!("fork{i}"));
            fs::create_dir(&dest).unwrap();
            super::super::restore::restore(&artifact, &open_dir(&dest).unwrap(), me(), &[]).unwrap();
            dest
        }).collect();
        drop(artifact);
        let walk_of = |p: &Path| walk::walk(&open_dir(p).unwrap(), &Options { generated: &[], budget: u64::MAX, ids: me() },
            &mut walk::HashOnly, &mut || Ok(())).unwrap();
        let original = walk_of(&src);
        for f in &forks {
            let w = walk_of(f);
            assert_eq!((&w.root, &w.entries), (&original.root, &original.entries));
            assert!(w.inodes.iter().all(|i| !original.inodes.contains(i)), "a fork shares an inode with the source");
        }
        // Hardlinks inside a fork are internal and fresh.
        let a = fs::metadata(forks[0].join("workspace/a.txt")).unwrap();
        assert_eq!((a.nlink(), a.ino()), (2, fs::metadata(forks[0].join("workspace/sub/a-link")).unwrap().ino()));
        assert_ne!(a.ino(), fs::metadata(forks[1].join("workspace/a.txt")).unwrap().ino());
        // Mutating the source or one fork changes nothing else, and the
        // checkpoint still verifies.
        fs::write(src.join("workspace/a.txt"), b"changed source\n").unwrap();
        fs::write(forks[0].join("workspace/sub/a-link"), b"changed fork\n").unwrap();
        fs::remove_file(forks[0].join("workspace/empty")).unwrap();
        assert_eq!(fs::read(forks[1].join("workspace/a.txt")).unwrap(), b"alpha\n");
        assert_eq!(fs::read(forks[1].join("workspace/sub/a-link")).unwrap(), b"alpha\n");
        assert_eq!(fs::read(src.join("workspace/sub/a-link")).unwrap(), b"changed source\n");
        let artifact = store.open(INSTANCE, &cp(1), false).unwrap();
        artifact.verify_objects().unwrap();
        // A fork can be checkpointed again with the same content digest.
        let again = capture_dir(&store, &forks[1], &cp(2), 64 << 20).unwrap();
        let digest = |r: &str| r.lines().find(|l| l.starts_with("content-sha256 ")).unwrap().to_owned();
        assert_eq!(digest(&again), digest(&record), "a fork's checkpoint has the original content digest");
        // Deleting the checkpoint leaves forks intact.
        drop(artifact);
        assert!(store.remove(INSTANCE, &cp(1), None).unwrap());
        assert_eq!(fs::read(forks[1].join("workspace/a.txt")).unwrap(), b"alpha\n");
        assert!(store.open(INSTANCE, &cp(1), false).is_err());
        fs::set_permissions(forks[1].join("workspace/sub/deeper"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(forks[0].join("workspace/sub/deeper"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(src.join("workspace/sub/deeper"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    use std::os::unix::fs::MetadataExt;

    /// A generation-checked removal: another generation's artifact is refused and left
    /// intact, other generations' staging is left alone, a live writer of this
    /// generation is busy before anything changes, and an older kiln's unnamed
    /// interrupted removal is left for an unchecked removal.
    #[test]
    fn generation_checked_removal_touches_only_its_generation() {
        let root = scratch("rmgen");
        fs::create_dir(root.join("runs")).unwrap();
        let store = Store::under(&root.join("runs"), false);
        let src = root.join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a"), b"one\n").unwrap();
        capture_dir(&store, &src, &cp(5), 1 << 20).unwrap();
        let idir = root.join("runs").join(super::super::store::NAMESPACE).join(INSTANCE);
        let private = |name: &str| {
            fs::create_dir(idir.join(name)).unwrap();
            fs::set_permissions(idir.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        };
        let listed = || -> Vec<String> {
            let mut v: Vec<String> = store.inventory().unwrap().into_iter().map(|(_, n, _)| n).collect();
            v.sort();
            v
        };
        private(&format!(".staging-{}-2-00000000000000aa", cp(5)));
        private(&format!(".staging-{}-1-00000000000000bb", cp(5)));
        private(&format!(".removing-{}-2-77-0", cp(5)));
        private(&format!(".removing-{}-77-1", cp(5)));
        let before = listed();
        // Generation 2 while generation 1 is published: refused, nothing touched.
        let e = store.remove(INSTANCE, &cp(5), Some(2)).unwrap_err();
        assert_eq!(super::super::reason_of(&e), Reason::GenerationMismatch, "{e:#}");
        assert_eq!(listed(), before);
        store.open(INSTANCE, &cp(5), false).unwrap().verify_objects().unwrap();
        // Zero is no generation.
        let e = store.remove(INSTANCE, &cp(5), Some(0)).unwrap_err();
        assert_eq!(super::super::reason_of(&e), Reason::InvalidRequest);
        // A live writer of generation 1's staging makes generation 1's removal busy,
        // with nothing removed.
        let held = fs::File::open(idir.join(format!(".staging-{}-1-00000000000000bb", cp(5)))).unwrap();
        assert_eq!(unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&held), libc::LOCK_EX) }, 0);
        let e = store.remove(INSTANCE, &cp(5), Some(1)).unwrap_err();
        assert_eq!(super::super::reason_of(&e), Reason::Busy);
        assert_eq!(listed(), before);
        drop(held);
        // Generation 1: its artifact and staging go; generation 2's and the unnamed
        // interrupted removal stay.
        assert!(store.remove(INSTANCE, &cp(5), Some(1)).unwrap());
        assert_eq!(listed(), [format!(".removing-{}-2-77-0", cp(5)), format!(".removing-{}-77-1", cp(5)),
            format!(".staging-{}-2-00000000000000aa", cp(5))]);
        assert!(store.open(INSTANCE, &cp(5), false).is_err());
        // Nothing of generation 3 exists: absent, as an unchecked removal reports it.
        assert!(!store.remove(INSTANCE, &cp(5), Some(3)).unwrap());
        // Generation 2 takes its staging and removal; the unchecked removal takes the rest.
        assert!(store.remove(INSTANCE, &cp(5), Some(2)).unwrap());
        assert_eq!(listed(), [format!(".removing-{}-77-1", cp(5))]);
        assert!(store.remove(INSTANCE, &cp(5), None).unwrap());
        assert!(listed().is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    /// Retries `f` while it is `checkpoint_busy`. Other tests in this binary
    /// fork children, and a child forked while a capture or removal held a
    /// lock keeps a copy of that descriptor (and so the lock) until it execs;
    /// the race tests below must not mistake that for the interleaving under
    /// test.
    fn unbusy<T>(mut f: impl FnMut() -> Result<T>) -> Result<T> {
        for _ in 0..200 {
            match f() {
                Err(e) if super::super::reason_of(&e) == Reason::Busy => std::thread::sleep(std::time::Duration::from_millis(10)),
                other => return other,
            }
        }
        f()
    }

    /// Runs `f` on its own thread with the store's test hook set: at each
    /// phase in `pause`, the thread reports the phase and waits for a go.
    fn paused<T: Send + 'static>(pause: &'static [&'static str], f: impl FnOnce() -> T + Send + 'static)
        -> (std::sync::mpsc::Receiver<&'static str>, std::sync::mpsc::Sender<()>, std::thread::JoinHandle<T>) {
        let (at_tx, at_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            super::super::store::HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |phase: &str| {
                if let Some(p) = pause.iter().find(|p| **p == phase) {
                    at_tx.send(*p).unwrap();
                    go_rx.recv().unwrap();
                }
            })));
            let out = f();
            super::super::store::HOOK.with(|h| *h.borrow_mut() = None);
            out
        });
        (at_rx, go_tx, thread)
    }

    fn reached(at: &std::sync::mpsc::Receiver<&'static str>, phase: &str) {
        assert_eq!(at.recv_timeout(std::time::Duration::from_secs(10)).unwrap(), phase);
    }

    fn capture_generation(store: &Store, src: &Path, checkpoint: &str, generation: u64) -> Result<String> {
        let mut h = header(checkpoint, 1 << 20);
        h.generation = generation;
        let opts = Options { generated: &[], budget: 1 << 20, ids: me() };
        write_artifact(store, &h, &open_dir(src)?, &opts, &manifest_of, &mut |_| Ok(()))
    }

    /// Adversarial review regression (rebound name): a remover that opened
    /// generation 1, then lost the race to another removal and a capture that
    /// published generation 2 under the same name, must not remove generation
    /// 2, whether it checks a generation or not.
    #[test]
    fn a_stale_removal_never_deletes_a_replacement_generation() {
        for (n, generation) in [(499, Some(1)), (498, None)] {
            let root = scratch("rm-rebound");
            let runs = root.join("runs");
            fs::create_dir(&runs).unwrap();
            let src = root.join("src");
            fs::create_dir(&src).unwrap();
            fs::write(src.join("a"), b"generation one\n").unwrap();
            let checkpoint = cp(n);
            let store = Store::under(&runs, false);
            capture_dir(&store, &src, &checkpoint, 1 << 20).unwrap();
            let (thread_runs, thread_checkpoint) = (runs.clone(), checkpoint.clone());
            let (at, go, stale) = paused(&["remove_opened"], move ||
                Store::under(&thread_runs, false).remove(INSTANCE, &thread_checkpoint, generation));
            reached(&at, "remove_opened");
            // Meanwhile another removal takes generation 1, and generation 2 is published.
            assert!(unbusy(|| store.remove(INSTANCE, &checkpoint, Some(1))).unwrap());
            fs::write(src.join("a"), b"generation two\n").unwrap();
            let record = unbusy(|| capture_generation(&store, &src, &checkpoint, 2)).unwrap();
            assert!(record.contains("\ngeneration 2\n"), "{record}");
            go.send(()).unwrap();
            let e = stale.join().unwrap().expect_err("the stale removal removed something");
            assert_eq!(super::super::reason_of(&e), Reason::Busy, "{e:#}");
            // Busy from the binding check itself, not from a forked child that
            // still holds generation 1's lock.
            let detail = format!("{checkpoint} changed while this removal checked it; nothing was removed");
            assert!(format!("{e:#}").contains(&detail), "{e:#}");
            let after = unbusy(|| store.open(INSTANCE, &checkpoint, false)).expect("generation 2 was removed");
            assert_eq!(after.header.generation, 2);
            after.verify_objects().unwrap();
            drop(after);
            assert_eq!(store.inventory().unwrap().len(), 1);
            fs::remove_dir_all(root).unwrap();
        }
    }

    /// The opposite interleaving: a capture that was admitted before
    /// generation 1 was published reaches publication while a generation-1
    /// removal holds its locks. Before the rename the name is taken and the
    /// capture is busy; after it, the capture publishes generation 2 and the
    /// removal deletes only the directory it locked.
    #[test]
    fn a_capture_publishing_during_a_removal_keeps_its_generation() {
        for (n, remover_at) in [(497, "remove_locked"), (496, "remove_renamed")] {
            let root = scratch("rm-publish");
            let runs = root.join("runs");
            fs::create_dir(&runs).unwrap();
            let (one, two) = (root.join("one"), root.join("two"));
            fs::create_dir(&one).unwrap();
            fs::create_dir(&two).unwrap();
            fs::write(one.join("a"), b"generation one\n").unwrap();
            fs::write(two.join("a"), b"generation two\n").unwrap();
            let checkpoint = cp(n);
            let store = Store::under(&runs, false);
            // Generation 2's capture finds the name free, then generation 1 is published.
            let (r, c, t) = (runs.clone(), checkpoint.clone(), two.clone());
            let (cat, cgo, capture) = paused(&["begin_checked", "staged"], move ||
                capture_generation(&Store::under(&r, false), &t, &c, 2));
            reached(&cat, "begin_checked");
            capture_dir(&store, &one, &checkpoint, 1 << 20).unwrap();
            cgo.send(()).unwrap();
            reached(&cat, "staged");
            // Generation 1's removal locks everything (generation 2's staging is
            // another generation's, left alone) and pauses.
            let (r, c) = (runs.clone(), checkpoint.clone());
            let pause: &'static [&'static str] = if remover_at == "remove_locked" { &["remove_locked"] }
                else { &["remove_renamed"] };
            let (rat, rgo, remover) = paused(pause, move || unbusy(|| Store::under(&r, false).remove(INSTANCE, &c, Some(1))));
            reached(&rat, remover_at);
            cgo.send(()).unwrap();
            let published = capture.join().unwrap();
            rgo.send(()).unwrap();
            assert!(remover.join().unwrap().unwrap());
            let names: Vec<String> = store.inventory().unwrap().into_iter().map(|(_, n, _)| n).collect();
            if remover_at == "remove_locked" {
                let e = published.expect_err("published over a locked artifact");
                assert_eq!(super::super::reason_of(&e), Reason::Busy, "{e:#}");
                assert!(names.is_empty(), "{names:?}");
            } else {
                assert!(published.unwrap().contains("\ngeneration 2\n"));
                assert_eq!(names, std::slice::from_ref(&checkpoint));
                let after = unbusy(|| store.open(INSTANCE, &checkpoint, false)).unwrap();
                assert_eq!(after.header.generation, 2);
                after.verify_objects().unwrap();
            }
            fs::remove_dir_all(root).unwrap();
        }
    }

    /// An unchecked removal sweeps every name that starts like the
    /// checkpoint's staging or removal names, as before generations were
    /// checked; a checked removal leaves the ones it can't parse alone.
    #[test]
    fn an_unchecked_removal_sweeps_malformed_names() {
        let root = scratch("rm-malformed");
        fs::create_dir(root.join("runs")).unwrap();
        let store = Store::under(&root.join("runs"), false);
        let src = root.join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a"), b"one\n").unwrap();
        capture_dir(&store, &src, &cp(6), 1 << 20).unwrap();
        let idir = root.join("runs").join(super::super::store::NAMESPACE).join(INSTANCE);
        let malformed = [format!(".staging-{}-x", cp(6)), format!(".staging-{}-5", cp(6)),
            format!(".removing-{}-a-b-c-d", cp(6)), format!(".removing-{}-x-1-2", cp(6))];
        for name in &malformed {
            fs::create_dir(idir.join(name)).unwrap();
            fs::set_permissions(idir.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let listed = || -> Vec<String> {
            let mut v: Vec<String> = store.inventory().unwrap().into_iter().map(|(_, n, _)| n).collect();
            v.sort();
            v
        };
        let mut left = malformed.to_vec();
        left.sort();
        assert!(unbusy(|| store.remove(INSTANCE, &cp(6), Some(1))).unwrap());
        assert_eq!(listed(), left);
        assert!(!unbusy(|| store.remove(INSTANCE, &cp(6), Some(1))).unwrap());
        assert_eq!(listed(), left);
        assert!(unbusy(|| store.remove(INSTANCE, &cp(6), None)).unwrap());
        assert!(listed().is_empty(), "{:?}", listed());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_upper_and_refusals_leave_no_staging() {
        let root = scratch("empty");
        fs::create_dir(root.join("runs")).unwrap();
        let store = Store::under(&root.join("runs"), false);
        let src = root.join("src");
        fs::create_dir(&src).unwrap();
        capture_dir(&store, &src, &cp(1), 1 << 20).unwrap();
        let a = store.open(INSTANCE, &cp(1), false).unwrap();
        assert_eq!((a.stats.entries, a.stats.objects), (1, 0));
        // A refusal mid-walk removes its staging directory.
        nix::unistd::mkfifo(&src.join("pipe"), nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let e = capture_dir(&store, &src, &cp(2), 1 << 20).unwrap_err();
        assert_eq!(super::super::reason_of(&e), Reason::MetadataUnsupported);
        fs::remove_file(src.join("pipe")).unwrap();
        let big = fs::File::create(src.join("big")).unwrap();
        big.set_len(2 << 20).unwrap();
        let e = capture_dir(&store, &src, &cp(3), 1 << 20).unwrap_err();
        assert_eq!(super::super::reason_of(&e), Reason::SizeLimit);
        let items: Vec<Item> = store.inventory().unwrap().into_iter().map(|(_, _, i)| i).collect();
        assert_eq!(items, [Item::Published], "refused captures left state behind");
        // The same checkpoint can't be captured twice.
        fs::remove_file(src.join("big")).unwrap();
        assert_eq!(super::super::reason_of(&capture_dir(&store, &src, &cp(1), 1 << 20).unwrap_err()), Reason::Busy);
        // A shared reader blocks removal (busy), and removal is idempotent.
        assert_eq!(super::super::reason_of(&store.remove(INSTANCE, &cp(1), None).unwrap_err()), Reason::Busy);
        drop(a);
        assert!(store.remove(INSTANCE, &cp(1), None).unwrap());
        assert!(!store.remove(INSTANCE, &cp(1), None).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn tampered_artifacts_are_corrupt_and_never_restored() {
        let root = scratch("tamper");
        fs::create_dir(root.join("runs")).unwrap();
        let store = Store::under(&root.join("runs"), false);
        let src = root.join("src");
        fs::create_dir(&src).unwrap();
        workspace(&src);
        capture_dir(&store, &src, &cp(1), 64 << 20).unwrap();
        let dir = store.root.join(INSTANCE).join(cp(1));
        let corrupt = |f: &dyn Fn(), undo: &dyn Fn(), deep: bool| {
            f();
            let result = store.open(INSTANCE, &cp(1), false).and_then(|a| if deep { a.verify_objects().map(|_| a) } else { Ok(a) });
            let e = result.err().expect("tampering was accepted");
            assert_eq!(super::super::reason_of(&e), Reason::Corrupt, "{e:#}");
            undo();
            store.open(INSTANCE, &cp(1), false).unwrap().verify_objects().unwrap();
        };
        let obj = dir.join("objects/00000000");
        let saved = fs::read(&obj).unwrap();
        corrupt(&|| fs::write(&obj, b"ALPHA\n").unwrap(), &|| fs::write(&obj, &saved).unwrap(), true);
        corrupt(&|| fs::write(&obj, b"alpha\nmore").unwrap(), &|| fs::write(&obj, &saved).unwrap(), false);
        corrupt(&|| fs::write(dir.join("objects/00000099"), b"").unwrap(),
            &|| fs::remove_file(dir.join("objects/00000099")).unwrap(), false);
        corrupt(&|| fs::write(dir.join("extra"), b"").unwrap(), &|| fs::remove_file(dir.join("extra")).unwrap(), false);
        let m = dir.join("manifest.json");
        let manifest = fs::read(&m).unwrap();
        corrupt(&|| { let mut b = manifest.clone(); let i = b.iter().position(|c| *c == b'5').unwrap(); b[i] = b'4';
                fs::write(&m, b).unwrap(); }, &|| fs::write(&m, &manifest).unwrap(), false);
        let h = dir.join("header");
        let header_text = fs::read_to_string(&h).unwrap();
        corrupt(&|| fs::write(&h, header_text.replace("source-lease 7", "source-lease 8")).unwrap(),
            &|| fs::write(&h, &header_text).unwrap(), false);
        corrupt(&|| { fs::remove_file(&obj).unwrap(); symlink(src.join("workspace/a.txt"), &obj).unwrap(); },
            &|| { fs::remove_file(&obj).unwrap(); fs::write(&obj, &saved).unwrap();
                fs::set_permissions(&obj, fs::Permissions::from_mode(0o600)).unwrap(); }, false);
        corrupt(&|| fs::set_permissions(&obj, fs::Permissions::from_mode(0o644)).unwrap(),
            &|| fs::set_permissions(&obj, fs::Permissions::from_mode(0o600)).unwrap(), false);
        // A digest-valid but hostile object never lands: restore verifies
        // each object while copying it.
        fs::write(&obj, b"ALPHA\n").unwrap();
        let a = store.open(INSTANCE, &cp(1), false).unwrap();
        let dest = root.join("fork");
        fs::create_dir(&dest).unwrap();
        let e = super::super::restore::restore(&a, &open_dir(&dest).unwrap(), me(), &[]).unwrap_err();
        assert_eq!(super::super::reason_of(&e), Reason::Corrupt);
        fs::set_permissions(src.join("workspace/sub/deeper"), fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::set_permissions(dest.join("workspace/sub/deeper"), fs::Permissions::from_mode(0o755));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_refuses_a_non_empty_destination_and_generated_conflicts() {
        let root = scratch("dest");
        fs::create_dir(root.join("runs")).unwrap();
        let store = Store::under(&root.join("runs"), false);
        let src = root.join("src");
        fs::create_dir_all(src.join("etc")).unwrap();
        fs::write(src.join("etc/resolv.conf"), b"mine\n").unwrap();
        capture_dir(&store, &src, &cp(1), 1 << 20).unwrap();
        let a = store.open(INSTANCE, &cp(1), false).unwrap();
        // A sandbox whose runtime writes /etc/resolv.conf can't take this one.
        let e = check_generated(&a.manifest, &[protected::RESOLV_CONF]).unwrap_err();
        assert_eq!(super::super::reason_of(&e), Reason::LayoutUnsupported);
        let dest = root.join("busy");
        fs::create_dir_all(dest.join("x")).unwrap();
        assert!(super::super::restore::restore(&a, &open_dir(&dest).unwrap(), me(), &[]).is_err());
        assert!(!dest.join("etc").exists(), "a refused restore wrote into the destination");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn records_are_canonical() {
        let h = header(&cp(9), 1 << 30);
        assert_eq!(Header::parse(&h.text()).unwrap(), h);
        // The binding golden, reproduced by the independent Python encoder.
        let content = super::super::manifest::content_sha256(&super::super::manifest::tests::golden().encode());
        assert_eq!(crate::sha256::hex(&binding_sha256(h.text().as_bytes(), &content)),
            "bc29aba1f548315a45d64dc0734e38365b6310f3b6b994135b9db85533537138");
        for bad in [h.text().replace("format 1", "format 2"), h.text().replace("generation 1\n", "generation 01\n"),
            h.text().replace("limit-bytes 1073741824", "limit-bytes 1"), h.text().replace("source 18e0-42", "source ../x"),
            h.text().replace(&cp(9), "cp-x"), format!("{}x\n", h.text())] {
            assert!(Header::parse(&bad).is_err(), "{bad}");
        }
        let m = Marker { content: [1; 32], binding: [2; 32], entries: 3, objects: 1, logical: 9, manifest_bytes: 400,
            bookkeeping: walk::Bookkeeping { impure: 1, origin: 2, uuid: 1 } };
        assert!(m.text().ends_with("excluded-bookkeeping trusted.overlay.impure=1 trusted.overlay.origin=2 \
            trusted.overlay.uuid=1\n"));
        assert_eq!(Marker::parse(&m.text()).unwrap(), m);
        assert!(Marker::parse(&m.text().replace("origin=2", "origin=02")).is_err());
    }

    fn upper_entries(dirs: &[(&str, bool)], whiteouts: &[&str], files: &[&str]) -> Vec<super::super::manifest::Entry> {
        use super::super::manifest::{Entry, Meta, Xattrs};
        let meta = || Meta { mode: 0o755, uid: 0, gid: 0, mtime: (0, 0), xattrs: Xattrs::new() };
        let mut e: Vec<Entry> = dirs.iter().map(|(p, opaque)| Entry { path: p.as_bytes().to_vec(),
            body: Body::Dir { meta: meta(), opaque: *opaque } }).collect();
        e.extend(whiteouts.iter().map(|p| Entry { path: p.as_bytes().to_vec(), body: Body::Whiteout }));
        e.extend(files.iter().map(|p| Entry { path: p.as_bytes().to_vec(), body: Body::File { meta: meta(), size: 0,
            sha256: [0; 32], object: 0 } }));
        e.sort_by(|a, b| a.path.split(|c| *c == b'/').cmp(b.path.split(|c| *c == b'/')));
        e
    }

    /// Break-it review H2: a fork recreated a writable directory the source
    /// had removed. Every writable path (and the default scratch
    /// directories, for a read-only root) must be a plain directory in the
    /// merged view: upper over image, with whiteouts and opacity applied.
    #[test]
    fn writable_paths_must_exist_in_the_merged_view() {
        let root = scratch("writable");
        let image = root.join("image");
        for d in ["tmp", "root", "workspace", "lower-only/deep", "data"] { fs::create_dir_all(image.join(d)).unwrap(); }
        fs::write(image.join("file"), b"").unwrap();
        symlink("/data", image.join("link")).unwrap();
        let img = open_dir(&image).unwrap();
        let ok = |entries: &[super::super::manifest::Entry], paths: &[&str]| {
            check_writable(entries, true, &paths.iter().map(|p| p.to_string()).collect::<Vec<_>>(), &img)
        };
        let none = upper_entries(&[], &[], &[]);
        ok(&none, &["/data", "/lower-only/deep"]).unwrap();
        // Upper-only directories count; so do merged ones.
        ok(&upper_entries(&[("gone-parent", false), ("gone-parent/gone", false)], &[], &[]),
            &["/gone-parent", "/gone-parent/gone"]).unwrap();
        let refused = |entries: &[super::super::manifest::Entry], paths: &[&str]| {
            let e = ok(entries, paths).unwrap_err();
            assert_eq!(super::super::reason_of(&e), Reason::LayoutUnsupported, "{e:#}");
        };
        // The reviewer's case: the child was removed (absent from upper and image).
        refused(&upper_entries(&[("gone-parent", false)], &[], &[]), &["/gone-parent", "/gone-parent/gone"]);
        // Whited out, replaced by a file, hidden by an opaque parent, a file
        // or symlink in the image, or a missing default scratch directory.
        refused(&upper_entries(&[], &["data"], &[]), &["/data"]);
        refused(&upper_entries(&[], &[], &["data"]), &["/data"]);
        refused(&upper_entries(&[("lower-only", true)], &[], &[]), &["/lower-only/deep"]);
        refused(&none, &["/file"]);
        refused(&none, &["/link"]);
        refused(&upper_entries(&[], &["workspace"], &[]), &[]);
        // A read-write root opens no writable paths, so nothing is required.
        check_writable(&upper_entries(&[], &["workspace"], &[]), false, &[], &img).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    /// Break-it review M1: two captures of one checkpoint raced; the one that
    /// lost the lock removed the winner's staging directory. Each staging
    /// directory is now its own (exclusive, nonce-named), and exactly one
    /// capture publishes.
    #[test]
    fn concurrent_captures_never_touch_each_others_staging() {
        use std::sync::{Arc, Barrier, mpsc};
        let root = scratch("lock-race");
        let runs = root.join("runs");
        fs::create_dir(&runs).unwrap();
        let checkpoint = cp(401);
        let start = Arc::new(Barrier::new(2));
        let finish = Arc::new(Barrier::new(3));
        let (tx, rx) = mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..2 {
            let (runs, checkpoint, start, finish, tx) = (runs.clone(), checkpoint.clone(), start.clone(), finish.clone(), tx.clone());
            workers.push(std::thread::spawn(move || {
                let store = Store::under(&runs, false);
                start.wait();
                let held = store.begin(&header(&checkpoint, 64 << 20));
                tx.send(held.as_ref().map(|_| ()).map_err(|e| format!("{e:#}"))).unwrap();
                finish.wait();
                drop(held);
            }));
        }
        let results = [rx.recv().unwrap(), rx.recv().unwrap()];
        let staged = |runs: &Path| fs::read_dir(runs.join(".checkpoints").join(INSTANCE)).map(|d| d.count()).unwrap_or(0);
        let live = staged(&runs);
        finish.wait();
        for w in workers { w.join().unwrap(); }
        // Whatever the pre-check let through, nobody's directory vanished
        // while its owner held it, and every one is gone after.
        assert_eq!(live, results.iter().filter(|r| r.is_ok()).count(), "{results:?}");
        assert_eq!(staged(&runs), 0);
        // Full captures racing: exactly one publishes, the other is busy.
        let src = root.join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("f"), b"x").unwrap();
        let go = Arc::new(Barrier::new(2));
        let racers: Vec<_> = (0..2).map(|_| {
            let (runs, src, checkpoint, go) = (runs.clone(), src.clone(), checkpoint.clone(), go.clone());
            std::thread::spawn(move || { go.wait(); capture_dir(&Store::under(&runs, false), &src, &checkpoint, 64 << 20) })
        }).collect();
        let outcomes: Vec<_> = racers.into_iter().map(|r| r.join().unwrap()).collect();
        assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1, "{outcomes:?}");
        for o in outcomes.iter().filter_map(|o| o.as_ref().err()) {
            assert_eq!(super::super::reason_of(o), Reason::Busy, "{o:#}");
        }
        let store = Store::under(&runs, false);
        store.open(INSTANCE, &checkpoint, false).unwrap().verify_objects().unwrap();
        assert_eq!(store.inventory().unwrap().len(), 1, "a losing capture left staging behind");
        fs::remove_dir_all(&root).unwrap();
    }

    /// Break-it review H3: a capture reopened its checkpoint by name after
    /// publishing and returned whatever was there. It now keeps its exclusive
    /// lock through the reply: nobody can remove or replace the artifact
    /// before the record (derived from the capture's own header) is returned.
    #[test]
    fn capture_never_returns_a_replacement_generation() {
        let root = scratch("rebound");
        let runs = root.join("runs");
        fs::create_dir(&runs).unwrap();
        let upper = root.join("src");
        fs::create_dir(&upper).unwrap();
        fs::write(upper.join("file"), b"generation one").unwrap();
        let checkpoint = cp(402);
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        {
            let (runs, checkpoint, seen) = (runs.clone(), checkpoint.clone(), seen.clone());
            super::super::store::HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |phase: &str| {
                if phase != "published" { return; }
                let store = Store::under(&runs, false);
                let removed = store.remove(INSTANCE, &checkpoint, None).map_err(|e| super::super::reason_of(&e));
                let opened = store.open(INSTANCE, &checkpoint, false).map(|_| ()).map_err(|e| super::super::reason_of(&e));
                seen.borrow_mut().push((removed, opened));
            })));
        }
        let first = capture_dir(&Store::under(&runs, false), &upper, &checkpoint, 64 << 20);
        super::super::store::HOOK.with(|h| *h.borrow_mut() = None);
        assert_eq!(*seen.borrow(), [(Err(Reason::Busy), Err(Reason::Busy))], "the artifact was reachable before the reply");
        let first = first.unwrap();
        assert!(first.contains("\ngeneration 1\n") && first.contains("\nlogical-bytes 14\n"), "{first}");
        let store = Store::under(&runs, false);
        assert_eq!(store.open(INSTANCE, &checkpoint, false).unwrap().header.generation, 1);
        store.remove(INSTANCE, &checkpoint, None).unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    /// Break-it review H4: an artifact with S > R was published (and opened
    /// by readers) before capture refused it. The charge is now checked on
    /// the staged directory; nothing is ever published.
    #[test]
    fn oversized_charge_is_never_published() {
        let root = scratch("charge");
        let runs = root.join("runs");
        fs::create_dir(&runs).unwrap();
        let upper = root.join("src");
        fs::create_dir(&upper).unwrap();
        // N=2 (root + file), L=32 KiB: L + 16 KiB*N = R exactly, before M.
        fs::File::create(upper.join("file")).unwrap().set_len(32 << 10).unwrap();
        let checkpoint = cp(403);
        let observed = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        {
            let (runs, checkpoint, observed) = (runs.clone(), checkpoint.clone(), observed.clone());
            super::super::store::HOOK.with(|h| *h.borrow_mut() = Some(Box::new(move |phase: &str| {
                if !["staged", "published"].contains(&phase) { return; }
                let store = Store::under(&runs, false);
                observed.borrow_mut().push((phase.to_owned(), store.open(INSTANCE, &checkpoint, false).is_ok()));
            })));
        }
        let capture = capture_dir(&Store::under(&runs, false), &upper, &checkpoint, 64 << 10);
        super::super::store::HOOK.with(|h| *h.borrow_mut() = None);
        let e = capture.unwrap_err();
        assert_eq!(super::super::reason_of(&e), Reason::SizeLimit, "{e:#}");
        assert_eq!(*observed.borrow(), [("staged".to_owned(), false)], "an S > R artifact was readable");
        let store = Store::under(&runs, false);
        assert!(store.open(INSTANCE, &checkpoint, false).is_err());
        assert_eq!(store.inventory().unwrap(), [], "a refused capture left state behind");
        fs::remove_dir_all(&root).unwrap();
    }

    /// The worst cases the caps permit, run by the VM under a 64 MiB memory
    /// cgroup, one operation per process as in production (the capture
    /// worker; the create shim's restore). `KILN_CHECKPOINT_FIXTURE` names a
    /// prepared upper built outside the cgroup, `KILN_CHECKPOINT_RUNS` a runs
    /// directory kept between steps, `KILN_CHECKPOINT_STEP` `capture` or
    /// `restore`. Skipped when unset.
    #[test]
    fn prepared_worst_case_within_the_worker_budget() {
        let (Ok(fixture), Ok(runs), Ok(step)) = (std::env::var("KILN_CHECKPOINT_FIXTURE"),
            std::env::var("KILN_CHECKPOINT_RUNS"), std::env::var("KILN_CHECKPOINT_STEP")) else {
            eprintln!("skipped: no fixture"); return;
        };
        let hwm = || fs::read_to_string("/proc/self/status").unwrap().lines()
            .find(|l| l.starts_with("VmHWM")).unwrap_or("VmHWM: ?").split_whitespace().nth(1).unwrap_or("?").to_owned();
        let store = Store::under(Path::new(&runs), false);
        let started = std::time::Instant::now();
        match step.as_str() {
            "capture" => {
                let record = capture_dir(&store, Path::new(&fixture), &cp(404), 1 << 30).unwrap();
                eprintln!("capture fixture={fixture} elapsed={:?} VmHWM={} kB", started.elapsed(), hwm());
                eprint!("{record}");
            }
            "restore" => {
                let artifact = store.open(INSTANCE, &cp(404), false).unwrap();
                eprintln!("open VmHWM={} kB entries={}", hwm(), artifact.stats.entries);
                let dest = Path::new(&runs).join("fork");
                fs::create_dir(&dest).unwrap();
                super::super::restore::restore(&artifact, &open_dir(&dest).unwrap(), me(), &[]).unwrap();
                eprintln!("restore elapsed={:?} VmHWM={} kB", started.elapsed(), hwm());
                drop(artifact);
                fs::remove_dir_all(&dest).unwrap();
                store.remove(INSTANCE, &cp(404), None).unwrap();
            }
            other => panic!("unknown step {other}"),
        }
    }
}
