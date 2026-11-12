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
    let mut lease = Some(lease);
    write_artifact(store, &header, &upper, &opts, &manifest, &mut |final_check| {
        let held = lease.as_ref().context("lease already released")?;
        ensure!(!held.lost(), refuse(Reason::Io, "the sandbox ended the checkpoint lease during capture"));
        if final_check {
            ensure!(facts(&run)? == before, refuse(Reason::Io, "the source sandbox changed identity during capture"));
            lease.take().unwrap().release().map_err(|e| refuse(Reason::Io, format!("{e:#}")))?;
        }
        Ok(())
    })
}

/// Stages, walks, finishes and publishes one artifact. `check(false)` runs
/// during the walk; `check(true)` runs once after the last source read and
/// before anything is published (capture releases its lease there).
pub fn write_artifact(store: &Store, header: &Header, upper: &OwnedFd, opts: &Options<'_>,
    manifest: &dyn Fn(walk::Walked) -> Manifest, check: &mut dyn FnMut(bool) -> Result<()>) -> Result<String> {
    let mut staging = store.begin(header)?;
    let walked = walk::walk(upper, opts, &mut staging, &mut || check(false))?;
    check(true)?;
    let bookkeeping = walked.bookkeeping;
    let manifest = manifest(walked);
    let bytes = manifest.encode();
    // Our own output must pass the rules every reader applies.
    let (_, stats) = Manifest::decode(&bytes).map_err(|e| refuse(super::reason_of(&e), format!("{e:#}")))?;
    let content = super::manifest::content_sha256(&bytes);
    let marker = Marker { content, binding: binding_sha256(&staging.header_bytes, &content), entries: stats.entries,
        objects: stats.objects, logical: stats.logical, manifest_bytes: bytes.len() as u64, bookkeeping };
    staging.publish(&bytes, &marker)?;
    let artifact = store.open(&header.instance, &header.checkpoint, false)?;
    let charge = artifact.charge(store.require_quota)?;
    if charge.charge > header.limit_bytes {
        drop(artifact);
        store.remove(&header.instance, &header.checkpoint)?;
        return Err(refuse(Reason::SizeLimit, format!("the checkpoint's charge {} exceeds its limit {}",
            charge.charge, header.limit_bytes)));
    }
    Ok(artifact.record(&charge))
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
        assert!(store.remove(INSTANCE, &cp(1)).unwrap());
        assert_eq!(fs::read(forks[1].join("workspace/a.txt")).unwrap(), b"alpha\n");
        assert!(store.open(INSTANCE, &cp(1), false).is_err());
        fs::set_permissions(forks[1].join("workspace/sub/deeper"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(forks[0].join("workspace/sub/deeper"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(src.join("workspace/sub/deeper"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    use std::os::unix::fs::MetadataExt;

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
        assert_eq!(super::super::reason_of(&store.remove(INSTANCE, &cp(1)).unwrap_err()), Reason::Busy);
        drop(a);
        assert!(store.remove(INSTANCE, &cp(1)).unwrap());
        assert!(!store.remove(INSTANCE, &cp(1)).unwrap());
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
}
