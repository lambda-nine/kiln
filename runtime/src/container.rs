use std::ffi::{CStr, CString};
use std::fs;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, chown, symlink};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use nix::fcntl::OFlag;
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use nix::errno::Errno;
use nix::sched::{CloneFlags, unshare};
use nix::sys::signal::{SigSet, Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{Pid, chdir, pipe2, pivot_root, read, sethostname, write};

use crate::cgroup::{Cgroup, ExecCgroup, Limits};
use crate::checkpoint;
use crate::image;
use crate::init;
use crate::landlock;
use crate::net;
use crate::overlay;
use crate::protected;
use crate::rmtree;
use crate::seccomp;
use crate::storage;
use crate::quota;
use crate::trace;
use crate::userns;

const KILN_ROOT: &str = "/var/lib/kiln";
const SANDBOX_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

pub struct Config {
    pub hostname: String,
    pub image: String,
    pub keep: bool,
    pub limits: Limits,
    pub disk: Option<u64>,
    pub read_only: bool,
    pub writable: Vec<PathBuf>,
    pub net: net::Plan,
    pub stats: bool,
    pub cmd: Vec<String>,
    /// Set when the new sandbox's upper is restored from a checkpoint.
    pub fork: Option<checkpoint::capture::ForkInfo>,
}

/// The overlayfs layers for one run. `lower` is the shared, read-only image;
/// every write lands in `upper`, which belongs to this run only. `merged` is
/// the combined view that becomes the sandbox's `/`.
struct Layers {
    lower: PathBuf,
    upper: PathBuf,
    work: PathBuf,
    merged: PathBuf,
}

/// Runs `cfg.cmd` in a fresh sandbox, waits for it, and returns a shell-style
/// exit code (128 + signal number if it was killed).
pub fn run(cfg: &Config) -> Result<i32> {
    // A plain name, so `--image ../../somewhere` can't pick an arbitrary host
    // directory (or another run's upper layer) as the root filesystem.
    preflight(cfg, RunKind::OneShot)?;
    let lower = Path::new(KILN_ROOT).join("images").join(&cfg.image);

    let id = run_id();
    trace::mark("host: check image");
    storage::prepare(&Path::new(KILN_ROOT).join("runs"))?;
    trace::mark("host: storage::prepare");
    let run_dir = run_dir(&id);
    let layers = Layers {
        lower,
        upper: run_dir.join("upper"),
        work: run_dir.join("work"),
        merged: run_dir.join("merged"),
    };
    create_run_dir(&run_dir)?;

    let result = prepare(cfg, &run_dir, &layers).and_then(|()| spawn_and_wait(cfg, &id, &layers));

    // The overlay mount lived in the sandbox's mount namespace, so it vanished
    // with the sandbox. Only the directories are left to clean up.
    if cfg.keep {
        eprintln!("kiln: kept {} (changes are in upper/)", run_dir.display());
    } else if let Err(e) = remove_run_dir(&run_dir) {
        eprintln!("kiln: failed to remove {}: {e}", run_dir.display());
    }
    trace::mark("host: remove run dir");
    result
}

/// Runs the long-lived init for a persistent sandbox. This function is called
/// by its detached host shim, which stays alive to own cleanup resources.
pub fn supervise_persistent(cfg: &Config, id: &str, ready: &OwnedFd, fork: Option<checkpoint::capture::Fork>)
    -> Result<()> {
    preflight(cfg, RunKind::Persistent)?;
    storage::prepare(&Path::new(KILN_ROOT).join("runs"))?;
    let run_dir = run_dir(id);
    let layers = Layers {
        lower: Path::new(KILN_ROOT).join("images").join(&cfg.image),
        upper: run_dir.join("upper"),
        work: run_dir.join("work"),
        merged: run_dir.join("merged"),
    };
    let pid = std::process::id();
    let start = process_start_time(pid)?;
    let listener = create_owned_run_dir(&run_dir, pid, &start, || {
        prepare(cfg, &run_dir, &layers)?;
        if let Some(fork) = fork {
            // The upper is rebuilt before anything mounts it; the artifact's
            // shared lock is released when `fork` is consumed here. A failed
            // restore removes the run: no sandbox starts on a partial upper.
            checkpoint::capture::restore_into(fork, &run_dir, &generated(cfg))?;
        }
        bind_control_socket(&run_dir.join(CONTROL_SOCKET))
    })?;
    let result = spawn_and_wait_mode(cfg, id, &layers, Some(listener), Some(ready));
    if let Err(e) = remove_run_dir(&run_dir) {
        let retry = if run_dir.join(IDENTITY_PID).exists() { format!("; `kiln gc {id}` retries it") } else { String::new() };
        report(&format!("kiln: sandbox {id}: teardown left {}: {e}{retry}", run_dir.display()));
    }
    result.map(|_| ())
}

/// Creates a persistent run's directory and publishes this shim's identity
/// in it at once, before its quota and everything else, then runs `setup`.
/// From the identity on, `kiln ls` lists the directory and `kiln gc` removes
/// it if this shim dies; and any error here removes it again, so a create
/// that fails before its sandbox starts leaves nothing behind. Every removal
/// (`remove_run_dir`, here, at teardown and in `kiln gc`) takes the identity
/// last, so one that fails leaves a run `kiln ls` lists and `kiln gc`
/// retries. Only a crash between the `mkdir` and the identity leaves a
/// directory without `shim.pid`. A directory that already existed is never
/// touched.
fn create_owned_run_dir<T>(run_dir: &Path, pid: u32, start: &str, setup: impl FnOnce() -> Result<T>) -> Result<T> {
    create_run_dir(run_dir)?;
    let result = publish_shim_identity(run_dir, pid, start).and_then(|()| setup());
    if result.is_err() && let Err(e) = remove_run_dir(run_dir) {
        report(&format!("kiln: failed setup left {}: {e}; `kiln gc` removes it", run_dir.display()));
    }
    result
}

/// A run directory's identity, in the order `remove_run_dir` unlinks it:
/// `shim.pid` first, so a concurrent `kiln ls` never finds `shim.pid`
/// without `shim.start`.
const IDENTITY: [&CStr; 2] = [c"shim.pid", c"shim.start"];
/// `IDENTITY[0]` as a path name.
const IDENTITY_PID: &str = "shim.pid";

/// Removes a run directory, for a one-shot run, a persistent shim's teardown
/// and `kiln gc`. Everything but the image reference and the identity goes
/// first, with a fixed number of descriptors at any depth and never across a
/// symlink or a mount (`rmtree`); then the image reference, `shim.pid`,
/// `shim.start` and the directory. Any error before the identity files are
/// removed returns with them in place: the run stays listed by `kiln ls`
/// (stale once its shim is gone), `kiln gc` retries it, kilnd keeps it
/// charged, and its image stays referenced. After them only the empty
/// directory is left to remove; nothing of the sandbox's can write there by
/// then (teardown has waited for its init, gc has drained its cgroup), but a
/// host root writer can, so an entry that appears is removed and the
/// `rmdir` retried `FINAL_RMDIR_RETRIES` times. If that still fails, the
/// directory, empty of identity, is left for node root and the error names
/// it (the shim and `kiln gc` log it by path).
pub(crate) fn remove_run_dir(run_dir: &Path) -> io::Result<()> {
    remove_run_dir_with(run_dir, &mut |_| Ok(()))
}

/// How many times `remove_run_dir` empties the run directory again and
/// retries its `rmdir` when an entry appeared after the identity went.
pub(crate) const FINAL_RMDIR_RETRIES: usize = 3;

/// `remove_run_dir` with a hook called before each removal (tests inject
/// failures and late writers with it; production passes one that does
/// nothing): with each entry's name, and with `"."` just before each `rmdir`
/// of the run directory itself.
pub(crate) fn remove_run_dir_with(run_dir: &Path, hook: rmtree::Hook) -> io::Result<()> {
    let dir: OwnedFd = fs::File::options().read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC).open(run_dir)?.into();
    let reference = CString::new(image::REFERENCE_FILE).expect("no NUL in the reference name");
    let last = [reference.as_c_str(), IDENTITY[0], IDENTITY[1]];
    rmtree::empty_dir(&dir, &last, &mut *hook)?;
    for name in last {
        hook(name)?;
        // SAFETY: unlinkat of a name in an open directory.
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } != 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::NotFound {
                return Err(io::Error::new(e.kind(), format!("remove {name:?}: {e}")));
            }
        }
    }
    let mut retries = 0;
    loop {
        hook(c".")?;
        let e = match fs::remove_dir(run_dir) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        let late = matches!(e.raw_os_error(), Some(libc::ENOTEMPTY | libc::EEXIST));
        if !late || retries == FINAL_RMDIR_RETRIES {
            let after = if late { format!(" after {retries} retries") } else { String::new() };
            return Err(io::Error::new(e.kind(), format!("remove the run directory{after}, its identity already \
                removed, so it is left for node root: {e}")));
        }
        retries += 1;
        // The identity is gone, so nothing in it is kept now.
        rmtree::empty_dir(&dir, &[], &mut *hook)?;
    }
}

/// A shim's failure that no caller is left to read: its stderr is /dev/null
/// once `kiln create` has returned, so it also goes to the system log (the
/// journal on systemd hosts: `journalctl -t kiln`).
pub(crate) fn report(message: &str) {
    eprintln!("{message}");
    if let Ok(text) = CString::new(message) {
        // SAFETY: the ident is a static C string, and "%s" takes exactly the
        // one C string passed.
        unsafe {
            libc::openlog(c"kiln".as_ptr(), libc::LOG_PID, libc::LOG_DAEMON);
            libc::syslog(libc::LOG_ERR, c"%s".as_ptr(), text.as_ptr());
            libc::closelog();
        }
    }
}

/// Linux's limit on a hostname (`HOST_NAME_MAX`); `sethostname` refuses longer.
const MAX_HOSTNAME_BYTES: usize = 64;

/// The create preflight's checks of a config, before anything is allocated:
/// its scalar settings (`validate_settings`), then its image
/// (`validate_image_in`). The shim repeats them before its run directory.
pub fn preflight(cfg: &Config, kind: RunKind) -> Result<()> {
    preflight_in(&image::Roots::system(), cfg, kind)
}

/// `preflight` over the images in `roots` (tests pass a scratch directory).
pub(crate) fn preflight_in(roots: &image::Roots, cfg: &Config, kind: RunKind) -> Result<()> {
    validate_settings(cfg)?;
    validate_image_in(roots, cfg, kind)
}

/// Limits, disk and hostname the sandbox's setup would refuse or that are
/// below kiln's floors (`cgroup::Limits::validate`, `quota::MIN_DISK`).
pub fn validate_settings(cfg: &Config) -> Result<()> {
    cfg.limits.validate()?;
    if let Some(bytes) = cfg.disk {
        ensure!(bytes >= quota::MIN_DISK,
            "invalid --disk {bytes}: expected at least {} bytes (64M), or \"max\"", quota::MIN_DISK);
    }
    ensure!(cfg.hostname.len() <= MAX_HOSTNAME_BYTES,
        "invalid --hostname: at most {MAX_HOSTNAME_BYTES} bytes");
    Ok(())
}

/// A persistent run's control socket and its PID 1's PID record: the run
/// files only a persistent run has (`RUN_ENTRIES`).
const CONTROL_SOCKET: &str = "control.sock";
const INIT_PID: &str = "init.pid";

/// Which kind of run a preflight decides for: the two leave different run
/// files under the run's inode quota (`RUN_ENTRIES`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunKind {
    /// `kiln run`.
    OneShot,
    /// `kiln create` and its shim.
    Persistent,
}

/// Every entry a run's own setup leaves under its project's inode quota
/// besides the run directory itself (which takes the project too) and the
/// sandbox's root, and whether only a persistent run has it: the overlay's
/// `upper`, `work`, overlayfs's own `work/work` (made at mount) and `merged`;
/// the `image`, `policy` and `layout` records; a persistent run's control
/// socket and `init.pid`. A persistent run's identity files are published
/// before the quota is set and stay outside it. A new run file goes here and
/// into the allowances below, or `run_inode_allowances_match_the_run_entries`
/// fails.
pub(crate) const RUN_ENTRIES: [(&str, bool); 9] = [
    ("upper", false), ("work", false), ("work/work", false), ("merged", false),
    (image::REFERENCE_FILE, false), (checkpoint::POLICY_FILE, false), (overlay::LAYOUT_FILE, false),
    (CONTROL_SOCKET, true), (INIT_PID, true),
];

/// What the create preflight allows for a run's own files under its inode
/// quota, exactly their measured peak and no margin (an allowance above it
/// refuses sandboxes that fit, the adversarial review's H1): the run
/// directory and `RUN_ENTRIES`. Measured on the VM (Linux 6.8, XFS,
/// 2026-11-22): a persistent run holds 10 at rest and a one-shot run 8, and
/// with a setup that doesn't count, the largest writable walk that still
/// creates at `--disk=64M` (4096 inodes) makes 4086 directories for a
/// persistent run and 4088 for a one-shot run: a record's temporary and
/// overlayfs's mount-time probes are gone before the walk's last mkdir.
/// `scripts/create-certainty-regressions.sh` pins both boundaries.
pub(crate) const PERSISTENT_RUN_INODES: u64 = 10;
pub(crate) const ONESHOT_RUN_INODES: u64 = 8;

/// The allowances are the run directory and its `RUN_ENTRIES`, or kiln
/// doesn't compile (`RunKind::run_inodes` evaluates this).
const ALLOWANCES_COUNT_RUN_ENTRIES: () = {
    let (mut oneshot, mut i) = (0, 0);
    while i < RUN_ENTRIES.len() {
        if !RUN_ENTRIES[i].1 { oneshot += 1; }
        i += 1;
    }
    assert!(1 + oneshot == ONESHOT_RUN_INODES && 1 + RUN_ENTRIES.len() as u64 == PERSISTENT_RUN_INODES,
        "the run inode allowances must count the run directory and RUN_ENTRIES");
};

impl RunKind {
    /// The inodes this kind of run's own files use (`PERSISTENT_RUN_INODES`,
    /// `ONESHOT_RUN_INODES`).
    pub(crate) const fn run_inodes(self) -> u64 {
        let () = ALLOWANCES_COUNT_RUN_ENTRIES;
        match self {
            RunKind::OneShot => ONESHOT_RUN_INODES,
            RunKind::Persistent => PERSISTENT_RUN_INODES,
        }
    }

    fn name(self) -> &'static str {
        match self {
            RunKind::OneShot => "one-shot",
            RunKind::Persistent => "persistent",
        }
    }
}

/// Everything about the image that a create decides before it allocates
/// (persistent create's preflight, and `kiln run` before its run directory):
/// the image opens the way the shim's image reference opens it
/// (`image::open_image`: no symlink at the name, owned by the sandbox ID
/// range), so an alias symlinked to another image is refused here rather
/// than in the shim; and with `--read-only` every writable path survives the
/// shim's Landlock walk over that directory (`landlock::preflight`), and the
/// directories that walk will make fit the run's inode quota, less what
/// `kind`'s own files use. With a generated resolver file, an ordinary
/// create's image must have a real `/etc` directory to write it into
/// (`check_resolver_parent`). The shim repeats this before its run
/// directory, so an image changed in between fails before anything exists.
fn validate_image_in(roots: &image::Roots, cfg: &Config, kind: RunKind) -> Result<()> {
    let image = OwnedFd::from(image::open_image(roots, &cfg.image).map_err(|e| {
        let missing = e.root_cause().downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound);
        if missing { e.context("image is missing (try: sudo scripts/fetch-alpine.sh)") } else { e }
    })?);
    let generated = generated(cfg);
    // A fork's upper is the checkpoint's, and its write refuses a symlink
    // itself (`write_fork_resolv_conf`).
    if cfg.fork.is_none() && !generated.is_empty() {
        check_resolver_parent(&image)?;
    }
    if cfg.read_only {
        let made = landlock::preflight(&image, &cfg.writable, &generated)?;
        // An ordinary create's shim makes the writable directories the image
        // lacks in the upper, under the run's inode quota, which runs out with
        // ENOSPC long after allocation. A fork isn't counted: its walk makes
        // nothing (absent paths are refused) and its upper is the
        // checkpoint's, though its resolver write can add up to 2 entries
        // (`write_fork_resolv_conf`).
        if cfg.fork.is_none() && let Some(limit) = quota::inode_limit(cfg.disk) {
            let own = kind.run_inodes();
            let room = limit.saturating_sub(own);
            ensure!(made <= room, "invalid --writable paths: setting them up needs {made} new entries in the \
                sandbox's root, more than the {room} that --disk leaves (its inode limit of {limit}, one per 16 KiB, \
                less the {own} a {} run's own files use); use a larger --disk or fewer, shallower paths", kind.name());
        }
    }
    Ok(())
}

/// The image side of an ordinary create's resolver write
/// (`write_resolv_conf`): `/etc` must be a directory, not a symlink, and
/// `/etc/resolv.conf` must not be a directory (anything else there is
/// replaced by a regular file). Absent `/etc` is refused too: the write
/// doesn't make it.
fn check_resolver_parent(image: &OwnedFd) -> Result<()> {
    let etc = open_nofollow_at(image.as_raw_fd(), c"etc", libc::O_PATH | libc::O_DIRECTORY).with_context(|| format!(
        "invalid image for a sandbox with DNS: its /etc must be a directory, not a symlink (kiln writes {} there)",
        protected::RESOLV_CONF))?;
    match resolver_entry(&etc)? {
        Some(libc::S_IFDIR) => bail!("invalid image for a sandbox with DNS: its {} is a directory", protected::RESOLV_CONF),
        _ => Ok(()),
    }
}

/// The file type (`S_IFMT` bits) of `resolv.conf` in the open `etc`, not
/// following a symlink; `None` if it's absent.
fn resolver_entry(etc: &OwnedFd) -> Result<Option<libc::mode_t>> {
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: fstatat of a name in an open directory into a valid buffer, not following.
    if unsafe { libc::fstatat(etc.as_raw_fd(), c"resolv.conf".as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        let e = Errno::last();
        if e == Errno::ENOENT { return Ok(None); }
        return Err(e).context("inspect /etc/resolv.conf");
    }
    Ok(Some(st.st_mode & libc::S_IFMT))
}

/// `openat` of `name` in `dir` that never follows a symlink at `name`.
fn open_nofollow_at(dir: RawFd, name: &CStr, flags: i32) -> Result<OwnedFd> {
    // SAFETY: openat relative to an open directory, not following.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o644) };
    // SAFETY: on success openat returns a new descriptor that we now own.
    Ok(unsafe { <OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(Errno::result(fd).context("open")?) })
}

pub fn new_id() -> String { run_id() }

/// Create a fresh per-run directory that only host root can traverse. Using
/// an explicit 0700 mode makes this independent of the invoking root shell's
/// umask; `create`, rather than `create_dir_all`, also rejects a collision or
/// a path an untrusted host user prepared in advance.
fn create_run_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("create fresh {} (are you root?)", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", path.display()))
}

/// Bind the persistent exec socket and make its root-only boundary explicit,
/// in addition to the containing directory's 0700 mode.
fn bind_control_socket(path: &Path) -> Result<UnixListener> {
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(listener)
}

fn process_start_time(pid: u32) -> Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).context("read shim start time")?;
    // The command name is parenthesized and may contain spaces. The fields
    // after its final ')' begin at field 3; starttime is field 22.
    stat.rsplit_once(") ")
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .map(str::to_string)
        .context("parse shim start time")
}

fn publish_shim_identity(run_dir: &Path, pid: u32, start: &str) -> Result<()> {
    publish_shim_identity_with(run_dir, pid, start, || {})
}

fn publish_shim_identity_with<F>(run_dir: &Path, pid: u32, start: &str,
    before_pid_publish: F) -> Result<()>
where
    F: FnOnce(),
{
    atomic_publish_with(&run_dir.join("shim.start"), start.as_bytes(), || {})?;
    // shim.pid is the completed identity marker. Each file is renamed from a
    // fully written, synced temporary file, and the marker is published last.
    atomic_publish_with(
        &run_dir.join("shim.pid"),
        pid.to_string().as_bytes(),
        before_pid_publish,
    )
}

/// Writes `path` through a synced temporary file and a rename, then syncs
/// the directory.
pub(crate) fn atomic_publish(path: &Path, contents: &[u8]) -> Result<()> {
    atomic_publish_with(path, contents, || {})
}

/// Run metadata that only ever fails closed if it is lost: a rename makes the
/// complete file appear at once, without the cost of syncing on the create
/// path. After a crash a missing or damaged record makes the run unknown
/// (which blocks image removal) or not a checkpoint source, never the reverse.
pub(crate) fn publish_unsynced(path: &Path, contents: &[u8]) -> Result<()> {
    let name = path.file_name().context("metadata path has no file name")?;
    let temporary = path.with_file_name(format!(".{}.tmp", name.to_string_lossy()));
    let result = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary)
        .and_then(|mut file| file.write_all(contents))
        .and_then(|()| fs::rename(&temporary, path))
        .with_context(|| format!("publish {}", path.display()));
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

fn atomic_publish_with<F>(path: &Path, contents: &[u8], before_publish: F) -> Result<()>
where
    F: FnOnce(),
{
    let name = path.file_name().context("identity path has no file name")?;
    let temporary = path.with_file_name(format!(".{}.tmp", name.to_string_lossy()));
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("create temporary identity file {}", temporary.display()))?;
        file.write_all(contents)
            .with_context(|| format!("write temporary identity file {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("sync temporary identity file {}", temporary.display()))?;
        drop(file);

        before_publish();
        fs::rename(&temporary, path)
            .with_context(|| format!("publish identity file {}", path.display()))?;
        let parent = path.parent().context("identity path has no parent")?;
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("sync identity directory {}", parent.display()))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn prepare(cfg: &Config, run_dir: &Path, layers: &Layers) -> Result<()> {
    // The quota goes on the run dir before anything of the sandbox's is in
    // it, so upper/ and work/ (and everything the sandbox writes) inherit its
    // project. A persistent shim's identity files are already there and stay
    // outside it.
    quota::limit(run_dir, cfg.disk)?;
    trace::mark("host: disk quota");
    for dir in [&layers.upper, &layers.work, &layers.merged] {
        fs::create_dir(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    // The sandbox's "/" takes its owner from upper/, so hand it to sandbox root.
    let id = Some(userns::ID_BASE);
    chown(&layers.upper, id, id).context("chown upper")?;
    trace::mark("host: overlay dirs");
    // The run's reference to its image, with the registered content identity
    // when the directory is the registered one. It exists before anything
    // mounts the image, so image replacement or removal sees this run.
    image::acquire_reference(&image::Roots::system(), &cfg.image, run_dir)?;
    trace::mark("host: image reference");
    // The root-write policy and writable set a checkpoint binds and a fork
    // must match. Lost in a crash, the run is simply not a checkpoint source.
    let policy = checkpoint::Policy::new(cfg.read_only, &cfg.writable)?;
    publish_unsynced(&run_dir.join(checkpoint::POLICY_FILE), policy.text().as_bytes())?;
    Ok(())
}

/// The upper entries this run's runtime generates (protected.rs).
pub fn generated(cfg: &Config) -> Vec<&'static str> {
    cfg.net.resolv_conf().map(|_| protected::RESOLV_CONF).into_iter().collect()
}

fn spawn_and_wait(cfg: &Config, id: &str, layers: &Layers) -> Result<i32> {
    spawn_and_wait_mode(cfg, id, layers, None, None)
}

fn spawn_and_wait_mode(cfg: &Config, id: &str, layers: &Layers,
    listener: Option<UnixListener>, ready: Option<&OwnedFd>) -> Result<i32> {
    let cgroup = Cgroup::create(id, &cfg.limits)?;
    let persistent = listener.is_some();
    // A persistent sandbox's PID 1 runs each exec in a child cgroup it can
    // kill and wait on as a whole. It's set up here, before the clone, so
    // PID 1 inherits host-opened handles to it. One-shot runs don't need it.
    let exec_scope = if persistent { Some(cgroup.create_exec_scope()?) } else { None };
    trace::mark("host: cgroup");
    // Leased before the clone, so the child knows its own address.
    let network = net::prepare(id, &cfg.net)?;
    let ip = network.as_ref().map(|n| n.ip());

    // Two one-byte handshakes over a pair of pipes. Parent → child: "your
    // network is plugged in" and later "your ID maps are written". Child →
    // parent: "I've created my user namespace". O_CLOEXEC keeps them out of
    // the command.
    let (to_child_rx, to_child_tx) = pipe2(OFlag::O_CLOEXEC).context("pipe")?;
    let (to_parent_rx, to_parent_tx) = pipe2(OFlag::O_CLOEXEC).context("pipe")?;

    // Handle signals by waiting for them (see wait_for) instead of dying, so
    // Ctrl-C or `kill` can't skip cleanup.
    let mut signals = SigSet::empty();
    for sig in [Signal::SIGCHLD, Signal::SIGINT, Signal::SIGQUIT].iter().chain(&init::FORWARDED) {
        signals.add(*sig);
    }
    signals.thread_block().context("block signals")?;

    // Each flag asks the kernel for a fresh copy of one namespace for the child:
    //   NEWUTS - its own hostname
    //   NEWPID - its own PID numbering; the child becomes PID 1
    //   NEWNS  - its own mount table, so its mounts never touch the host
    //   NEWNET - its own interfaces, routes and firewall (only lo at first)
    //   NEWIPC - its own System V shared memory, semaphores and message
    //            queues, freed when the sandbox ends. Without it, sandboxes
    //            could read and destroy each other's (they share host IDs).
    let flags = CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWNET
        | CloneFlags::CLONE_NEWIPC;

    // clone3 with CLONE_INTO_CGROUP starts the child directly inside its
    // cgroup, so its limits apply from its first instruction. The older way,
    // writing its PID to cgroup.procs after clone, migrates a running
    // process: the kernel takes cgroup_threadgroup_rwsem for writing, which
    // waits for an RCU grace period (5-15 ms on this VM when the system was
    // idle). Being born in the cgroup skips the migration entirely.
    let cgroup_dir = cgroup.open_dir()?;
    let args = CloneArgs {
        flags: flags.bits() as u64 | CLONE_INTO_CGROUP,
        exit_signal: Signal::SIGCHLD as u64,
        cgroup: cgroup_dir.as_raw_fd() as u64,
        ..Default::default()
    };
    // SAFETY: without CLONE_VM this behaves like fork(): the child gets a
    // copy-on-write copy of our memory, stack included, and we're
    // single-threaded, so nothing can be mid-update when it's copied.
    let ret = unsafe { libc::syscall(libc::SYS_clone3, &args as *const CloneArgs, size_of::<CloneArgs>()) };
    let pid = match Errno::result(ret).context("clone3 (are you root?)")? {
        0 => {
            // In the child. _exit, not exit: the parent's atexit handlers and
            // buffered output belong to the parent.
            let code = init(cfg, layers, ip, &to_child_rx, &to_parent_tx, listener.as_ref(), exec_scope.as_ref())
                .unwrap_or_else(|e| {
                    eprintln!("kiln: {e:#}");
                    1
                });
            // SAFETY: ends this process immediately; nothing is shared.
            unsafe { libc::_exit(code) }
        }
        child => Pid::from_raw(child as i32),
    };
    drop(cgroup_dir);
    // PID 1 has its own copies; the host has no use for them.
    drop(exec_scope);

    // Our copy of the child's write end must go, or we'd never see EOF if the
    // child dies before writing.
    drop(to_parent_tx);
    trace::mark("host: clone");

    let setup = (|| -> Result<()> {
        // Plug its network namespace into the bridge from the outside before
        // it runs anything, then let it go.
        if let Some(network) = &network {
            network.plug(pid)?;
        }
        write(&to_child_tx, b"1").context("signal child")?;

        // The child does its mounts as real root, then creates its user
        // namespace and waits for us to write its ID maps.
        let mut buf = [0u8; 1];
        if read(&to_parent_rx, &mut buf).context("wait for child")? == 0 {
            return Ok(()); // Child failed and printed why; wait_for collects it.
        }
        trace::mark("host: wait for child's mounts");
        userns::write_maps(pid)?;
        write(&to_child_tx, b"1").context("signal child")?;
        trace::mark("host: ID maps");
        if persistent && read(&to_parent_rx, &mut buf).context("wait for persistent init")? == 0 {
            return Ok(());
        }
        if let Some(ready) = ready {
            fs::write(run_dir(id).join(INIT_PID), pid.to_string())?;
            write(ready, b"1").context("signal create")?;
        }
        Ok(())
    })();
    drop(to_child_tx);
    if let Err(e) = setup {
        let _ = kill(pid, Signal::SIGKILL);
        let _ = wait_for(pid, &signals);
        return Err(e);
    }

    let code = wait_for(pid, &signals)?;
    trace::mark("host: sandbox exited");
    if cgroup.stat("memory.events", "oom_kill") > 0 {
        eprintln!("kiln: sandbox ran out of memory and was killed (memory.max)");
    }
    if cfg.stats {
        print_stats(&cgroup, &layers.upper);
        if let Some(n) = &network {
            eprintln!("kiln: ip {} | egress packets rejected {}", n.ip(), n.blocked_packets());
        }
    }
    // Explicit drops (in reverse creation order, as Rust would) so each
    // teardown step shows up in KILN_TRACE.
    drop(network);
    trace::mark("host: network cleanup");
    drop(cgroup);
    trace::mark("host: cgroup cleanup");
    Ok(code)
}

/// Waits for the sandbox to exit, passing `init::FORWARDED` signals on to its
/// init. SIGINT and SIGQUIT come from the terminal, which already sends them
/// to the sandbox directly, so they're just swallowed here.
fn wait_for(pid: Pid, signals: &SigSet) -> Result<i32> {
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)).context("waitpid")? {
            WaitStatus::Exited(_, code) => return Ok(code),
            WaitStatus::Signaled(_, sig, _) => return Ok(128 + sig as i32),
            _ => {}
        }
        match signals.wait().context("sigwait")? {
            sig if init::FORWARDED.contains(&sig) => {
                let _ = kill(pid, sig);
            }
            _ => {}
        }
    }
}

fn print_stats(cgroup: &Cgroup, upper: &Path) {
    let mib = |b: u64| b as f64 / (1 << 20) as f64;
    let ms = |us: u64| us as f64 / 1000.0;
    eprintln!(
        "kiln: memory peak {:.1} MiB | cpu {:.0} ms (throttled {} times, {:.0} ms) | pids peak {} | oom kills {}",
        mib(cgroup.value("memory.peak")),
        ms(cgroup.stat("cpu.stat", "usage_usec")),
        cgroup.stat("cpu.stat", "nr_throttled"),
        ms(cgroup.stat("cpu.stat", "throttled_usec")),
        cgroup.value("pids.peak"),
        cgroup.stat("memory.events", "oom_kill"),
    );
    if let Some(disk) = quota::usage(upper) {
        eprintln!("kiln: disk used {:.1} MiB", mib(disk.used));
    }
}

/// Runs inside the child, already in the new namespaces. Sets up the sandbox,
/// then becomes its init and returns the command's exit code.
fn init(cfg: &Config, layers: &Layers, ip: Option<Ipv4Addr>, from_parent: &OwnedFd, to_parent: &OwnedFd,
    listener: Option<&UnixListener>, exec_scope: Option<&ExecCgroup>) -> Result<i32> {
    let mut keep = vec![from_parent.as_raw_fd(), to_parent.as_raw_fd()];
    if let Some(listener) = listener { keep.push(listener.as_raw_fd()); }
    if let Some(scope) = exec_scope { keep.extend(scope.raw_fds()); }
    close_fds_except(&keep)?;

    // Wait for the parent to plug in our network, then configure our side.
    wait_for_parent(from_parent)?;
    trace::mark("init: released by parent");
    net::configure_inside(ip).context("configure sandbox network")?;
    trace::mark("init: network");

    // A cgroup namespace makes our current cgroup look like the root, so the
    // sandbox sees /sys/fs/cgroup as just its own limits and nothing above.
    // It's unshared here, not passed to clone3: clone3 creates namespaces
    // before it places the child in its cgroup, so the host's cgroup would
    // become the root.
    unshare(CloneFlags::CLONE_NEWCGROUP).context("unshare cgroup namespace")?;

    sethostname(&cfg.hostname).context("sethostname")?;

    // A new mount namespace starts as a copy of the parent's, and on systemd
    // hosts "/" is a shared mount, so new mounts would propagate back to the
    // host. pivot_root also refuses to work on shared mounts. Mark everything
    // private first.
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None::<&str>)
        .context("make / private")?;

    // Pinned features (overlay.rs): no index, metacopy or redirects in the upper.
    let opts = overlay::mount_data(&layers.lower, &layers.upper, &layers.work);
    mount(Some("overlay"), &layers.merged, Some("overlay"), MsFlags::empty(), Some(opts.as_str()))
        .context("mount overlay")?;
    trace::mark("init: cgroup ns, hostname, overlay");
    // Read the effective features back while the host's /proc and /sys are
    // still visible, and record them with the entries this run generates.
    let generated = generated(cfg);
    let read = overlay::read_back(&layers.merged, [&layers.lower, &layers.upper, &layers.work])
        .map_err(|e| format!("{e:#}"));
    let run_dir = layers.upper.parent().context("upper has no run directory")?;
    publish_unsynced(&run_dir.join(overlay::LAYOUT_FILE), overlay::layout_text(&read, &generated).as_bytes())?;
    trace::mark("init: overlay layout record");

    // A restored upper is hostile input: before any privileged mount or DNS
    // write follows a path into it, every mount target and the DNS file's
    // parent must be a plain directory, checked without following.
    if cfg.fork.is_some() {
        checkpoint::restore::check_scaffolding(&layers.merged, &generated)?;
        trace::mark("init: checkpoint scaffolding");
    }

    // Device files must be bind-mounted from the host before we lose sight of it.
    setup_dev(&layers.merged.join(&protected::DEV[1..]))?;
    trace::mark("init: /dev");

    // Swap roots. pivot_root(".", ".") stacks the old root on top of the new
    // one at "/"; detaching "." then removes the old root, leaving no path
    // back to the host filesystem.
    chdir(&layers.merged).context("chdir to new root")?;
    pivot_root(".", ".").context("pivot_root")?;
    umount2(".", MntFlags::MNT_DETACH).context("detach old root")?;
    chdir("/").context("chdir /")?;
    trace::mark("init: pivot_root");

    // /proc reflects the PID namespace of whoever mounted it. Mount a fresh
    // one so `ps` inside the sandbox only sees the sandbox's processes.
    mount(
        Some("proc"),
        protected::PROC,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /proc")?;

    // /proc/sys/net belongs to the network namespace of whoever opens it, so
    // these only change ours. Sandbox root won't own this namespace, so let
    // it bind ports below 1024 and ping (ICMP sockets) anyway, like Docker.
    fs::write("/proc/sys/net/ipv4/ip_unprivileged_port_start", "0").context("sysctl")?;
    fs::write("/proc/sys/net/ipv4/ping_group_range", "0 2147483647").context("sysctl")?;

    // Read-only, so the sandbox can read its limits and usage but not raise them.
    mount(
        Some("cgroup2"),
        protected::CGROUP,
        Some("cgroup2"),
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("mount /sys/fs/cgroup")?;

    // Written as real root, so it shows up inside as owned by "nobody":
    // readable, but sandbox root can't point DNS somewhere else.
    if let Some(conf) = cfg.net.resolv_conf() {
        match &cfg.fork {
            None => write_resolv_conf(conf.as_bytes())?,
            Some(info) => write_fork_resolv_conf(conf.as_bytes(), info)?,
        }
    }

    // Last step as real root. Every namespace above was created first, so it
    // stays owned by the host's user namespace and sandbox root gets no power
    // over it: no mounting, unmounting or changing the hostname.
    trace::mark("init: /proc, sysctls, cgroupfs");
    unshare(CloneFlags::CLONE_NEWUSER).context("unshare user namespace")?;
    trace::mark("init: user namespace");
    write(to_parent, b"1").context("signal parent")?;
    wait_for_parent(from_parent)?;
    userns::become_root()?;
    // If the host-side kiln dies, take the sandbox down with it rather than
    // leave it running unsupervised. Set after become_root, because changing
    // credentials clears it.
    nix::sys::prctl::set_pdeathsig(Signal::SIGKILL).context("set pdeathsig")?;
    // Not dumpable: sandbox processes run as the same user as PID 1, and
    // this is what stops them from ptracing it or opening /proc/1/fd, where
    // a persistent sandbox's PID 1 keeps the exec cgroup's handles. A command
    // becomes dumpable again when it execs.
    // SAFETY: plain prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(Errno::last()).context("clear dumpable");
    }

    // Start from a clean environment so host variables don't leak in.
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm".into());
    // SAFETY: single-threaded, and nothing else reads the environment here.
    unsafe {
        for (key, _) in std::env::vars_os() {
            std::env::remove_var(key);
        }
        std::env::set_var("PATH", SANDBOX_PATH);
        std::env::set_var("HOME", "/root");
        std::env::set_var("TERM", term);
    }

    // Lock the process down. no_new_privs first: setuid binaries stop granting
    // privilege, and both Landlock and seccomp require it. Order matters only
    // in that both must come before the command runs; both are inherited by
    // every child and can't be undone.
    nix::sys::prctl::set_no_new_privs().context("set no_new_privs")?;
    if cfg.read_only {
        // A restored tree is never extended: an absent writable path fails
        // the create (preflight already refused it; this is the no-follow
        // recheck in the merged view).
        landlock::restrict_writes(&cfg.writable, cfg.fork.is_none(), &generated).map_err(|e| if cfg.fork.is_some() {
            checkpoint::refuse(checkpoint::Reason::LayoutUnsupported, format!("{e:#}"))
        } else { e })?;
    }
    seccomp::install()?;
    trace::mark("init: credentials, env, seccomp");

    if let Some(listener) = listener {
        // Without the exec cgroup nothing could contain an exec's processes.
        let scope = exec_scope.context("persistent sandbox has no exec cgroup")?;
        write(to_parent, b"1").context("signal persistent init ready")?;
        return init::serve(listener, scope);
    }

    let argv: Vec<CString> = cfg
        .cmd
        .iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()
        .context("argument contains a NUL byte")?;
    init::run(&argv)
}

/// An ordinary create's DNS write, in the sandbox's root.
fn write_resolv_conf(conf: &[u8]) -> Result<()> {
    write_resolv_conf_under(&open_nofollow_at(libc::AT_FDCWD, c"/", libc::O_RDONLY | libc::O_DIRECTORY)?, conf)
}

/// `write_resolv_conf` under `root` (tests pass a scratch directory). No
/// symlink is followed: `/etc` opens without following (the preflight
/// refused an image whose `/etc` isn't a directory), an image's regular
/// `/etc/resolv.conf` is truncated and rewritten, and anything else there (a
/// symlink to `/dev/shm`, `/tmp` or anywhere, a FIFO) is unlinked and replaced
/// by a new regular file. The upper then holds exactly the 2 entries the
/// preflight counts for it: `/etc` and `/etc/resolv.conf`.
fn write_resolv_conf_under(root: &OwnedFd, conf: &[u8]) -> Result<()> {
    let etc = open_nofollow_at(root.as_raw_fd(), c"etc", libc::O_RDONLY | libc::O_DIRECTORY)
        .context("open /etc without symlinks")?;
    let name = c"resolv.conf";
    let file = match resolver_entry(&etc)? {
        Some(libc::S_IFREG) => open_nofollow_at(etc.as_raw_fd(), name, libc::O_WRONLY | libc::O_TRUNC | libc::O_NONBLOCK),
        kind => {
            // SAFETY: unlinkat of a name in an open directory.
            if kind.is_some() && unsafe { libc::unlinkat(etc.as_raw_fd(), name.as_ptr(), 0) } != 0 {
                return Err(Errno::last()).context("replace /etc/resolv.conf");
            }
            open_nofollow_at(etc.as_raw_fd(), name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)
        }
    }.context("open /etc/resolv.conf without symlinks")?;
    fs::File::from(file).write_all(conf).context("write /etc/resolv.conf")
}

/// The DNS write of a sandbox restored from a checkpoint: no component is
/// followed, then the captured times of `/etc` and `/` (which the write may
/// change by creating or copying up entries) are put back. The preflight
/// doesn't count a fork's setup against its inode quota, so this write's
/// `/etc` copy-up and new `resolv.conf` (up to 2 entries) aren't counted.
fn write_fork_resolv_conf(conf: &[u8], info: &checkpoint::capture::ForkInfo) -> Result<()> {
    let open = open_nofollow_at;
    let root = open(libc::AT_FDCWD, c"/", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let etc = open(root.as_raw_fd(), c"etc", libc::O_RDONLY | libc::O_DIRECTORY).context("open /etc without symlinks")?;
    let file = open(etc.as_raw_fd(), c"resolv.conf", libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC)
        .context("open /etc/resolv.conf without symlinks")?;
    fs::File::from(file).write_all(conf).context("write /etc/resolv.conf")?;
    let set = |fd: &OwnedFd, (sec, nsec): (i64, u32)| -> Result<()> {
        let times = [libc::timespec { tv_sec: 0, tv_nsec: libc::UTIME_OMIT }, libc::timespec { tv_sec: sec, tv_nsec: i64::from(nsec) }];
        // SAFETY: futimens on an open descriptor.
        Errno::result(unsafe { libc::futimens(fd.as_raw_fd(), times.as_ptr()) }).context("restore directory time")?;
        Ok(())
    };
    if let Some(mtime) = info.etc_mtime { set(&etc, mtime)?; }
    set(&root, info.root_mtime)
}

/// `struct clone_args` from <linux/sched.h> (version 2, 88 bytes: the
/// version with the `cgroup` field).
#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}
const _: () = assert!(size_of::<CloneArgs>() == 88);

/// From <linux/sched.h>: start the child in the cgroup `clone_args.cgroup`
/// (an open directory). Linux 5.7+.
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

/// Closes every file descriptor except stdin, stdout, stderr and `keep`.
/// Anything else was inherited from whoever started kiln (an open host file,
/// a directory, a socket), and namespaces, pivot_root and Landlock don't
/// revoke open descriptors: each would be a handle straight through the
/// sandbox walls. This also drops our copies of the parent's pipe ends, so a
/// parent that dies mid-setup shows up here as EOF instead of a hang.
pub(crate) fn close_fds_except(keep: &[RawFd]) -> Result<()> {
    let mut keep: Vec<u32> = keep.iter().map(|&fd| fd as u32).collect();
    keep.sort_unstable();
    let mut first = 3;
    for fd in keep.into_iter().chain([u32::MAX]) {
        if fd > first {
            // SAFETY: closes a range of descriptors; nothing below uses them.
            let ret = unsafe { libc::syscall(libc::SYS_close_range, first, fd - 1, 0) };
            nix::errno::Errno::result(ret).context("close_range")?;
        }
        first = fd.saturating_add(1);
    }
    Ok(())
}

/// Blocks until the parent writes its next handshake byte. EOF means it gave up.
fn wait_for_parent(from_parent: &OwnedFd) -> Result<()> {
    let mut buf = [0u8; 1];
    if read(from_parent, &mut buf).context("wait for parent")? == 0 {
        bail!("parent failed to set up the sandbox");
    }
    Ok(())
}

/// Builds a minimal /dev: a small tmpfs holding bind mounts of a few safe host
/// devices, instead of exposing the host's whole /dev (disks included).
fn setup_dev(dev: &Path) -> Result<()> {
    mount(
        Some("tmpfs"),
        dev,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=755,size=64k"),
    )
    .context("mount /dev tmpfs")?;

    for name in protected::DEVICES {
        let target = dev.join(name);
        fs::File::create(&target).with_context(|| format!("create {}", target.display()))?;
        let source = Path::new("/dev").join(name);
        mount(Some(&source), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>)
            .with_context(|| format!("bind {}", source.display()))?;
    }

    for (link, target) in protected::DEV_LINKS {
        symlink(target, dev.join(link)).with_context(|| format!("symlink /dev/{link}"))?;
    }

    // POSIX shared memory (Python multiprocessing, Chromium, Postgres). Its
    // pages are charged to the sandbox's cgroup, so it stays inside memory.max.
    let shm = dev.join(protected::DEV_SHM.strip_prefix("/dev/").context("/dev/shm")?);
    fs::create_dir(&shm).context("create /dev/shm")?;
    mount(
        Some("tmpfs"),
        &shm,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=1777,size=64m"),
    )
    .context("mount /dev/shm")?;
    Ok(())
}

/// A run ID is the start time in nanoseconds (hex) and kiln's PID: unique,
/// sortable, and it names the run's cgroup and run directory.
fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}-{}", std::process::id())
}

/// When run `id` started, in seconds since the Unix epoch.
pub fn run_started(id: &str) -> Option<f64> {
    let (nanos, _) = id.split_once('-')?;
    Some(u128::from_str_radix(nanos, 16).ok()? as f64 / 1e9)
}

/// /var/lib/kiln/runs/<id>: the run's overlay layers, under its disk quota.
pub fn run_dir(id: &str) -> PathBuf {
    Path::new(KILN_ROOT).join("runs").join(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(image: &str, read_only: bool, writable: &[&str], net: &str) -> Config {
        Config {
            limits: Limits { memory: Some(64 << 20), cpus: Some(1.0), pids: Some(16) },
            disk: Some(64 << 20),
            net: net::Plan::new(net, &[]).unwrap(),
            hostname: "kiln".into(), image: image.into(), keep: true, read_only,
            writable: writable.iter().map(PathBuf::from).collect(), stats: false, cmd: Vec::new(), fork: None,
        }
    }

    fn scratch_roots(tag: &str) -> (PathBuf, image::Roots) {
        let root = std::env::temp_dir().join(format!("kiln-container-{tag}-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        let roots = image::Roots { images: root.join("images"), registry: root.join("registry"), runs: root.join("runs") };
        fs::create_dir_all(roots.images.join("img/var")).unwrap();
        fs::create_dir_all(roots.images.join("img/etc")).unwrap();
        fs::create_dir_all(roots.images.join("img/run")).unwrap();
        symlink("../run", roots.images.join("img/var/run")).unwrap();
        fs::write(roots.images.join("img/etc/passwd"), "").unwrap();
        (root, roots)
    }

    fn validate_image_in_persistent(roots: &image::Roots, cfg: &Config) -> Result<()> {
        validate_image_in(roots, cfg, RunKind::Persistent)
    }

    #[test]
    fn settings_are_refused_just_past_each_floor() {
        let mut cfg = config("img", false, &[], "none");
        cfg.disk = Some(quota::MIN_DISK);
        validate_settings(&cfg).unwrap();
        cfg.disk = None;
        validate_settings(&cfg).unwrap();
        for disk in [quota::MIN_DISK - 1, 4096, 1, 0] {
            cfg.disk = Some(disk);
            assert!(validate_settings(&cfg).unwrap_err().to_string().contains("--disk"), "{disk}");
        }
        cfg.disk = Some(quota::MIN_DISK);
        cfg.hostname = "h".repeat(MAX_HOSTNAME_BYTES);
        validate_settings(&cfg).unwrap();
        cfg.hostname.push('h');
        assert!(validate_settings(&cfg).unwrap_err().to_string().contains("--hostname"));
        cfg.hostname = "kiln".into();
        cfg.limits.pids = Some(crate::cgroup::MIN_PIDS - 1);
        assert!(validate_settings(&cfg).unwrap_err().to_string().contains("--pids"));
    }

    /// The image walk is part of the create preflight: an image's symlinked or
    /// regular-file parent refuses the create before anything is allocated.
    #[test]
    fn preflight_walks_writable_paths_in_the_image() {
        let (root, roots) = scratch_roots("walk");
        for path in ["/var/run/x", "/etc/passwd/x", "/proc/x", "/dev/x"] {
            let error = validate_image_in_persistent(&roots, &config("img", true, &[path], "none")).expect_err(path);
            assert!(format!("{error:#}").contains(path), "{path}: {error:#}");
        }
        for path in ["/tmp/x", "/dev/shm/x", "/var", "/var/new/deep"] {
            validate_image_in_persistent(&roots, &config("img", true, &[path], "none")).unwrap_or_else(|e| panic!("{path}: {e:#}"));
        }
        // With DNS kiln writes /etc/resolv.conf as a file.
        validate_image_in_persistent(&roots, &config("img", true, &["/etc/resolv.conf/x"], "none")).unwrap();
        assert!(validate_image_in_persistent(&roots, &config("img", true, &["/etc/resolv.conf/x"], "full")).is_err());
        // Without a read-only root there is no Landlock walk to fail.
        validate_image_in_persistent(&roots, &config("img", false, &[], "none")).unwrap();
        let missing = validate_image_in_persistent(&roots, &config("missing", false, &[], "none")).unwrap_err();
        assert!(format!("{missing:#}").contains("fetch-alpine"), "{missing:#}");
        fs::remove_dir_all(root).unwrap();
    }

    /// Writable paths whose walk makes `made` directories in total under top
    /// names the scratch image lacks (512 components each at most).
    fn deep_set(made: u64) -> Vec<PathBuf> {
        let mut left = made;
        ('b'..='q').map_while(|top| {
            let components = left.min(512);
            left -= components;
            (components > 0).then(|| PathBuf::from(format!("/{top}{}", "/a".repeat(components as usize - 1))))
        }).collect()
    }

    /// With `--read-only`, what the shim's walk will make counts against the
    /// run's inode quota in the preflight (the 2026-11-22 review's finding A),
    /// less exactly what the run's own files use, 10 for a persistent run and
    /// 8 for a one-shot run (the adversarial review's H1: no margin). At the
    /// 64M floor (4096 inodes, the scratch image lacking /tmp, /root and
    /// /workspace) a persistent create fits 4083 more directories and a
    /// one-shot run 4085; one more is refused before allocation. The numbers
    /// are literals, so an allowance that drifts from the measured one fails
    /// here. Neither `--disk max` nor a fork, whose walk makes nothing, is
    /// counted.
    #[test]
    fn preflight_refuses_writable_paths_past_the_inode_quota() {
        let (root, roots) = scratch_roots("inodes");
        for (kind, fits, own) in [(RunKind::Persistent, 4083, 10), (RunKind::OneShot, 4085, 8)] {
            let mut cfg = config("img", true, &[], "none");
            cfg.writable = deep_set(fits);
            validate_image_in(&roots, &cfg, kind).unwrap_or_else(|e| panic!("{kind:?} {fits}: {e:#}"));
            cfg.writable = deep_set(fits + 1);
            let error = format!("{:#}", validate_image_in(&roots, &cfg, kind).unwrap_err());
            assert!(error.contains(&format!("needs {} new entries", fits + 4)), "{error}");
            assert!(error.contains(&format!("more than the {} that --disk leaves", 4096 - own)), "{error}");
            assert!(error.contains(&format!("less the {own} a {} run's own files use", kind.name())), "{error}");
            // Another 16 KiB of disk is another inode.
            cfg.disk = Some(quota::MIN_DISK + 16 * 1024);
            validate_image_in(&roots, &cfg, kind).unwrap();
        }

        // The review's set, 16 paths of 512 components, at the 64M floor.
        let mut cfg = config("img", true, &[], "none");
        cfg.writable = deep_set(16 * 512);
        assert!(validate_image_in_persistent(&roots, &cfg).is_err());
        cfg.disk = None;
        validate_image_in_persistent(&roots, &cfg).unwrap();
        cfg.disk = Some(quota::MIN_DISK);
        cfg.fork = Some(checkpoint::capture::ForkInfo { root_mtime: (0, 0), etc_mtime: None });
        validate_image_in_persistent(&roots, &cfg).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    /// The quota's inode limit rounds up, one inode per started 16 KiB, and
    /// the preflight's room uses the same limit (the adversarial review's
    /// L1): 64 MiB is 4096 inodes, one byte more is 4097, and a persistent
    /// create there has room for 4087 directories.
    #[test]
    fn the_inode_limit_rounds_up_and_the_preflight_uses_it() {
        assert_eq!(quota::inode_limit(Some(67_108_864)), Some(4096));
        assert_eq!(quota::inode_limit(Some(67_108_865)), Some(4097));
        assert_eq!(quota::inode_limit(None), None);
        let (root, roots) = scratch_roots("rounding");
        let mut cfg = config("img", true, &[], "none");
        cfg.disk = Some(67_108_865);
        // The scratch image lacks /tmp, /root and /workspace.
        cfg.writable = deep_set(4087 - 3);
        validate_image_in_persistent(&roots, &cfg).unwrap();
        cfg.writable = deep_set(4087 - 2);
        let error = format!("{:#}", validate_image_in_persistent(&roots, &cfg).unwrap_err());
        assert!(error.contains("more than the 4087 that --disk leaves (its inode limit of 4097"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    /// The preflight's allowances are exactly the run directory and the
    /// run's entries in `RUN_ENTRIES` for each kind, and every name the
    /// run's setup in this file joins onto a run directory is one of those
    /// entries or the identity (outside the quota). A new run file fails
    /// here until it's in `RUN_ENTRIES` and the allowances; the VM's
    /// `create-certainty-regressions.sh` pins the physical boundaries.
    #[test]
    fn run_inode_allowances_match_the_run_entries() {
        let oneshot = RUN_ENTRIES.iter().filter(|(_, persistent_only)| !persistent_only).count() as u64;
        assert_eq!(1 + oneshot, ONESHOT_RUN_INODES);
        assert_eq!(1 + RUN_ENTRIES.len() as u64, PERSISTENT_RUN_INODES);
        assert_eq!((ONESHOT_RUN_INODES, PERSISTENT_RUN_INODES), (8, 10));
        assert_eq!((RunKind::OneShot.run_inodes(), RunKind::Persistent.run_inodes()), (8, 10));

        let source = include_str!("container.rs");
        let code = &source[..source.find("#[cfg(test)]\nmod tests").unwrap()];
        let mut joined = std::collections::BTreeSet::new();
        for (at, _) in code.match_indices(".join(") {
            let before = &code[..at];
            if before.ends_with("run_dir") || before.ends_with("run_dir(id)") {
                let rest = &code[at + ".join(".len()..];
                joined.insert(rest[..rest.find(')').unwrap()].trim_start_matches('&'));
            }
        }
        let known = ["\"upper\"", "\"work\"", "\"merged\"", "CONTROL_SOCKET", "INIT_PID", "checkpoint::POLICY_FILE",
            "overlay::LAYOUT_FILE", "IDENTITY_PID", "\"shim.start\"", "\"shim.pid\""];
        for name in &joined {
            assert!(known.contains(name), "{name} is joined onto a run directory: add it to RUN_ENTRIES (and the \
                allowances) if setup leaves it under the quota, then here");
        }
        assert!(joined.len() >= 8, "the scan found too few names: {joined:?}");
    }

    /// An image name that is a symlink (an alias of another image) is refused
    /// by the preflight, with or without a read-only root, as the shim's
    /// no-follow image reference would refuse it after allocation.
    #[test]
    fn preflight_refuses_a_symlinked_image_name() {
        let (root, roots) = scratch_roots("alias");
        symlink("img", roots.images.join("latest")).unwrap();
        for read_only in [false, true] {
            let error = validate_image_in_persistent(&roots, &config("latest", read_only, &[], "none")).unwrap_err();
            assert!(format!("{error:#}").contains("latest"), "{error:#}");
            // The shim's reference opens the image the same way.
            assert!(image::open_image(&roots, "latest").is_err());
        }
        validate_image_in_persistent(&roots, &config("img", false, &[], "none")).unwrap();
        for bad in ["../img", ".img", "-img", ""] {
            assert!(validate_image_in_persistent(&roots, &config(bad, false, &[], "none")).is_err(), "{bad:?}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn run_directory_and_control_socket_are_root_only() {
        let root = std::env::temp_dir().join(format!(
            "kiln-permissions-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let run = root.join("run");
        create_run_dir(&run).unwrap();
        assert_eq!(run.metadata().unwrap().permissions().mode() & 0o777, 0o700);
        assert!(create_run_dir(&run).is_err(), "an existing run path must be rejected");

        let socket = run.join("control.sock");
        let listener = bind_control_socket(&socket).unwrap();
        assert_eq!(socket.metadata().unwrap().permissions().mode() & 0o777, 0o600);

        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("kiln-{tag}-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&root).unwrap();
        root
    }

    /// The identity is published before setup runs, and a failed setup (a
    /// failed quota, image reference, policy record, restore or socket)
    /// removes the run directory it created, never one that already existed.
    #[test]
    fn a_run_directory_has_its_identity_first_and_is_removed_on_failure() {
        let root = scratch_dir("owned-run");
        let run = root.join("run");
        let error = create_owned_run_dir(&run, 1234, "5678", || -> Result<()> {
            assert_eq!(fs::read_to_string(run.join("shim.pid")).unwrap(), "1234");
            assert_eq!(fs::read_to_string(run.join("shim.start")).unwrap(), "5678");
            fs::create_dir(run.join("upper")).unwrap();
            bail!("prepare failed")
        }).unwrap_err();
        assert_eq!(error.to_string(), "prepare failed");
        assert!(!run.exists(), "a failed setup left its run directory");

        let value = create_owned_run_dir(&run, 1234, "5678", || Ok(7)).unwrap();
        assert_eq!(value, 7);
        assert!(run.join("shim.pid").exists());
        // A collision fails before setup and leaves the other directory alone.
        let ran = std::cell::Cell::new(false);
        assert!(create_owned_run_dir(&run, 99, "1", || { ran.set(true); Ok(()) }).is_err());
        assert!(!ran.get());
        assert_eq!(fs::read_to_string(run.join("shim.pid")).unwrap(), "1234");
        fs::remove_dir_all(root).unwrap();
    }

    /// A run directory look-alike: the identity, the image reference and
    /// the other records, and an upper with a sandbox's files in it.
    fn run_dir_look_alike(root: &Path) -> PathBuf {
        let run = root.join("run");
        for dir in ["upper/tmp/a/b", "upper/etc", "work/work", "merged"] { fs::create_dir_all(run.join(dir)).unwrap(); }
        for file in ["shim.start", "shim.pid", image::REFERENCE_FILE, "policy", "layout", "init.pid",
            "upper/etc/resolv.conf", "upper/tmp/a/b/victim", "upper/tmp/a/z"] {
            fs::write(run.join(file), file).unwrap();
        }
        run
    }

    /// Teardown keeps the identity to the end (the 2026-11-22 review's
    /// finding B): a removal that fails on one entry returns the error and
    /// leaves `shim.pid`, `shim.start` and the image reference, so the run
    /// stays listed and `kiln gc` retries it; the retry removes everything.
    #[test]
    fn a_failed_teardown_keeps_the_identity_and_a_retry_finishes() {
        let root = scratch_dir("teardown-identity");
        let run = run_dir_look_alike(&root);
        let mut seen = Vec::new();
        let mut hook = |name: &CStr| {
            seen.push(name.to_owned());
            if name == c"victim" { Err(io::Error::other("injected removal failure")) } else { Ok(()) }
        };
        let error = remove_run_dir_with(&run, &mut hook).unwrap_err();
        assert!(error.to_string().contains("injected removal failure"), "{error}");
        for file in ["shim.pid", "shim.start", image::REFERENCE_FILE] {
            assert!(run.join(file).exists(), "{file} removed before the rest of the run directory");
        }
        assert!(!seen.iter().any(|n| [c"shim.pid", c"shim.start", c"image"].contains(&n.as_c_str())), "{seen:?}");

        let mut order = Vec::new();
        remove_run_dir_with(&run, &mut |name: &CStr| { order.push(name.to_owned()); Ok(()) }).unwrap();
        assert!(!run.exists());
        // The run directory itself (the hook's ".") comes after the identity.
        let last: Vec<&CStr> = order.iter().rev().take(4).rev().map(|n| n.as_c_str()).collect();
        assert_eq!(last, [c"image", c"shim.pid", c"shim.start", c"."], "{order:?}");
        fs::remove_dir_all(root).unwrap();
    }

    /// Without root, a mode 000 directory the sandbox left can't be emptied:
    /// the teardown fails and the identity stays. Root removes it.
    #[test]
    fn an_unremovable_directory_keeps_the_identity() {
        let root = scratch_dir("teardown-mode000");
        let run = run_dir_look_alike(&root);
        fs::set_permissions(run.join("upper/tmp/a"), fs::Permissions::from_mode(0o000)).unwrap();
        let result = remove_run_dir(&run);
        if unsafe { libc::geteuid() } == 0 {
            result.unwrap();
            assert!(!run.exists());
        } else {
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            assert!(run.join("shim.pid").exists() && run.join("shim.start").exists());
            fs::set_permissions(run.join("upper/tmp/a"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }

    /// An entry a host root writer adds once the identity is gone (the
    /// adversarial review's M1) is removed and the final `rmdir` retried:
    /// the removal succeeds and leaves nothing. A writer that adds one before
    /// every attempt gets the error after `FINAL_RMDIR_RETRIES` retries, with
    /// no hang, and the directory without its identity is what's left.
    #[test]
    fn an_entry_added_after_the_identity_is_removed_and_the_rmdir_retried() {
        let root = scratch_dir("teardown-late");
        let run = run_dir_look_alike(&root);
        let mut hook = |name: &CStr| -> io::Result<()> {
            if name == c"shim.start" { fs::create_dir_all(run.join("late/deeper"))?; }
            Ok(())
        };
        remove_run_dir_with(&run, &mut hook).unwrap();
        assert!(!run.exists());

        let run = run_dir_look_alike(&root);
        let mut attempts = 0;
        let mut hook = |name: &CStr| -> io::Result<()> {
            if name == c"." {
                attempts += 1;
                fs::write(run.join(format!("late-{attempts}")), "x")?;
            }
            Ok(())
        };
        let error = remove_run_dir_with(&run, &mut hook).unwrap_err();
        assert_eq!(attempts, 1 + FINAL_RMDIR_RETRIES);
        assert_eq!(error.kind(), io::ErrorKind::DirectoryNotEmpty, "{error}");
        assert!(error.to_string().contains(&format!("after {FINAL_RMDIR_RETRIES} retries")), "{error}");
        assert!(error.to_string().contains("left for node root"), "{error}");
        let left: Vec<_> = fs::read_dir(&run).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, [format!("late-{attempts}").as_str()]);
        fs::remove_dir_all(root).unwrap();
    }

    /// The sandbox's root, standing in for the merged view the resolver
    /// write runs in: `/etc` from an image and an `outside` directory.
    fn resolver_root(tag: &str) -> (PathBuf, OwnedFd) {
        let root = scratch_dir(tag);
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::create_dir_all(root.join("outside")).unwrap();
        let fd: OwnedFd = fs::File::options().read(true).custom_flags(libc::O_DIRECTORY).open(&root).unwrap().into();
        (root, fd)
    }

    /// An ordinary create's resolver write never follows the image's
    /// symlink (the adversarial review's M2): a symlinked
    /// `/etc/resolv.conf` (to a file outside `/etc`, to one that doesn't
    /// exist yet) or a FIFO there is replaced by a regular file with the
    /// generated content, and the symlink's target is untouched; a regular
    /// file is rewritten in place, an absent one created. A `/etc` that is a
    /// symlink, or a `resolv.conf` that is a directory, is an error.
    #[test]
    fn the_resolver_write_replaces_a_symlink_and_never_follows_it() {
        let conf = b"nameserver 10.0.0.1\n";
        let regular = |root: &Path| {
            let path = root.join("etc/resolv.conf");
            let meta = fs::symlink_metadata(&path).unwrap();
            assert!(meta.file_type().is_file(), "{meta:?}");
            assert_eq!(fs::read(&path).unwrap(), conf);
        };
        for target in ["../outside/existing", "../outside/absent"] {
            let (root, fd) = resolver_root("resolv-link");
            fs::write(root.join("outside/existing"), "keep").unwrap();
            symlink(target, root.join("etc/resolv.conf")).unwrap();
            write_resolv_conf_under(&fd, conf).unwrap_or_else(|e| panic!("{target}: {e:#}"));
            regular(&root);
            assert_eq!(fs::read_to_string(root.join("outside/existing")).unwrap(), "keep", "{target}");
            assert!(!root.join("outside/absent").exists(), "{target}");
            fs::remove_dir_all(root).unwrap();
        }
        let (root, fd) = resolver_root("resolv-fifo");
        let fifo = CString::new(root.join("etc/resolv.conf").into_os_string().into_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o644) }, 0);
        write_resolv_conf_under(&fd, conf).unwrap();
        regular(&root);
        fs::write(root.join("etc/resolv.conf"), "old, and longer than the generated file").unwrap();
        write_resolv_conf_under(&fd, conf).unwrap();
        regular(&root);
        fs::remove_file(root.join("etc/resolv.conf")).unwrap();
        write_resolv_conf_under(&fd, conf).unwrap();
        regular(&root);
        fs::remove_file(root.join("etc/resolv.conf")).unwrap();
        fs::create_dir(root.join("etc/resolv.conf")).unwrap();
        assert!(write_resolv_conf_under(&fd, conf).is_err());
        fs::remove_dir(root.join("etc/resolv.conf")).unwrap();
        fs::rename(root.join("etc"), root.join("outside/etc")).unwrap();
        symlink("outside/etc", root.join("etc")).unwrap();
        assert!(write_resolv_conf_under(&fd, conf).is_err());
        assert!(!root.join("outside/etc/resolv.conf").exists());
        fs::remove_dir_all(root).unwrap();
    }

    /// The preflight refuses, before allocation, an image the resolver write
    /// can't use (the adversarial review's M2): with DNS, its `/etc` a
    /// symlink, a regular file or absent, or its `/etc/resolv.conf` a
    /// directory. A symlinked `/etc/resolv.conf` is fine (it's replaced), and
    /// without DNS, or for a fork, none of this is checked.
    #[test]
    fn preflight_refuses_an_image_without_a_real_etc_for_dns() {
        let (root, roots) = scratch_roots("resolver");
        let image = roots.images.join("img");
        let refused = |what: &str| {
            for read_only in [false, true] {
                let error = validate_image_in_persistent(&roots, &config("img", read_only, &[], "full")).unwrap_err();
                assert!(format!("{error:#}").contains("invalid image for a sandbox with DNS"), "{what}: {error:#}");
                validate_image_in_persistent(&roots, &config("img", read_only, &[], "none")).unwrap();
                let mut fork = config("img", read_only, &[], "full");
                fork.fork = Some(checkpoint::capture::ForkInfo { root_mtime: (0, 0), etc_mtime: None });
                validate_image_in_persistent(&roots, &fork).unwrap();
            }
        };
        symlink("/dev/shm/x", image.join("etc/resolv.conf")).unwrap();
        validate_image_in_persistent(&roots, &config("img", true, &[], "full")).unwrap();
        fs::remove_file(image.join("etc/resolv.conf")).unwrap();
        fs::create_dir(image.join("etc/resolv.conf")).unwrap();
        refused("resolv.conf a directory");
        fs::remove_dir(image.join("etc/resolv.conf")).unwrap();
        fs::rename(image.join("etc"), image.join("etc.real")).unwrap();
        symlink("etc.real", image.join("etc")).unwrap();
        refused("/etc a symlink");
        fs::remove_file(image.join("etc")).unwrap();
        refused("/etc absent");
        fs::write(image.join("etc"), "").unwrap();
        refused("/etc a file");
        fs::remove_dir_all(root).unwrap();
    }

    /// The environment variable that hands `child_removes_a_deep_tree_under_a_low_descriptor_limit`
    /// its scratch directory.
    const DEEP_CHILD: &str = "KILN_TEST_DEEP_TEARDOWN_DIR";
    /// Deeper than the soft descriptor limit the child sets, many times over.
    const DEEP: usize = 5000;
    const LOW_NOFILE: libc::rlim_t = 64;

    /// A sandbox's tree 5000 levels deep, with the soft `RLIMIT_NOFILE` at
    /// 64, is removed completely; std's `remove_dir_all` fails on the same
    /// tree with EMFILE. The limit is set in a child process (this test
    /// binary, running only the test below), so it binds nothing else.
    #[test]
    fn a_tree_deeper_than_the_descriptor_limit_is_removed() {
        let root = scratch_dir("teardown-deep");
        let run = run_dir_look_alike(&root);
        crate::rmtree::tests::chain(&run.join("upper/tmp"), DEEP, 997);
        fs::create_dir(root.join("std")).unwrap();
        crate::rmtree::tests::chain(&root.join("std"), DEEP, 997);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "container::tests::child_removes_a_deep_tree_under_a_low_descriptor_limit",
                "--ignored", "--nocapture", "--test-threads=1"])
            .env(DEEP_CHILD, &root)
            .output().unwrap();
        let text = String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success() && text.contains("1 passed"), "{text}");
        assert!(!run.exists(), "the deep run directory survived: {text}");
        // std's leftover, removed here without the low limit.
        crate::rmtree::empty_dir(&crate::rmtree::tests::open(&root), &[], &mut |_| Ok(())).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    #[ignore = "run in a child process by a_tree_deeper_than_the_descriptor_limit_is_removed"]
    fn child_removes_a_deep_tree_under_a_low_descriptor_limit() {
        let Some(root) = std::env::var_os(DEEP_CHILD).map(PathBuf::from) else { return };
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) }, 0);
        limit.rlim_cur = LOW_NOFILE;
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let control = fs::remove_dir_all(root.join("std")).unwrap_err();
        assert_eq!(control.raw_os_error(), Some(libc::EMFILE), "{control}");
        remove_run_dir(&root.join("run")).unwrap();
    }

    #[test]
    fn shim_pid_is_absent_until_its_complete_identity_is_published() {
        let root = std::env::temp_dir().join(format!(
            "kiln-identity-publication-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let (paused_tx, paused_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();

        std::thread::scope(|scope| {
            let run_dir = root.clone();
            let publisher = scope.spawn(move || {
                publish_shim_identity_with(&run_dir, 1234, "5678", || {
                    paused_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                })
            });
            paused_rx.recv().unwrap();
            let start = fs::read_to_string(root.join("shim.start"));
            let pid_visible = root.join("shim.pid").exists();
            resume_tx.send(()).unwrap();
            publisher.join().unwrap().unwrap();
            assert_eq!(start.unwrap(), "5678");
            assert!(!pid_visible, "partial PID marker became visible");
        });

        assert_eq!(fs::read_to_string(root.join("shim.pid")).unwrap(), "1234");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn paused_publication_resumes_when_start_observation_fails() {
        let root = std::env::temp_dir().join(format!(
            "kiln-identity-publication-failure-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let (paused_tx, paused_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();

        let (removed, start, pid_visible, resumed, published) = std::thread::scope(|scope| {
            let run_dir = root.clone();
            let publisher = scope.spawn(move || {
                publish_shim_identity_with(&run_dir, 1234, "5678", || {
                    paused_tx.send(()).unwrap();
                    resume_rx.recv().unwrap();
                })
            });
            paused_rx.recv().unwrap();
            let removed = fs::remove_file(root.join("shim.start"));
            let start = fs::read_to_string(root.join("shim.start"));
            let pid_visible = root.join("shim.pid").exists();
            let resumed = resume_tx.send(());
            let published = publisher.join();
            (removed, start, pid_visible, resumed, published)
        });

        let final_pid = fs::read_to_string(root.join("shim.pid"));
        let cleanup = fs::remove_dir_all(&root);
        removed.unwrap();
        resumed.unwrap();
        published.unwrap().unwrap();
        assert_eq!(start.unwrap_err().kind(), std::io::ErrorKind::NotFound);
        assert!(!pid_visible, "partial PID marker became visible");
        assert_eq!(final_pid.unwrap(), "1234");
        cleanup.unwrap();
    }
}
