//! Pinned OverlayFS features and the run's layout record.
//!
//! Every new run mounts its overlay with `index=off,metacopy=off,
//! redirect_dir=nofollow,nfs_export=off`. On the supported kernel these equal
//! the effective defaults kiln already ran with, except that a redirect found
//! in a layer would no longer be followed, and kiln's layers contain none (a
//! fresh empty upper and an image without overlay xattrs). Pinning makes the
//! upper's metadata vocabulary fixed for checkpoint capture: no index, no
//! metacopy and no redirects are ever written.
//!
//! The kernel's mount options are read back after mounting, never assumed.
//! OverlayFS shows a feature in mountinfo only when it differs from the module
//! default at the time of reading, so the effective value is the shown option
//! or, when absent, the module parameter. The parameters are read before and
//! after mountinfo and must agree. The result goes in `<run>/layout`; a run
//! whose options cannot be verified still works, but is not a checkpoint
//! source.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};

/// The pinned features, in the order they are passed to mount(2).
pub const PINNED: [(&str, &str); 4] =
    [("index", "off"), ("metacopy", "off"), ("redirect_dir", "nofollow"), ("nfs_export", "off")];
pub const LAYOUT_FILE: &str = "layout";
const LAYOUT_MAGIC: &str = "kiln-layout 1";
const PARAMETERS: &str = "/sys/module/overlay/parameters";

pub fn pinned_options() -> String {
    PINNED.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",")
}

/// The data argument of the overlay mount: the three layers, then the pins.
pub fn mount_data(lower: &Path, upper: &Path, work: &Path) -> String {
    format!("lowerdir={},upperdir={},workdir={},{}", lower.display(), upper.display(), work.display(),
        pinned_options())
}

/// The overlay module defaults that decide every feature mountinfo omits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Defaults {
    pub index: bool,
    pub metacopy: bool,
    pub nfs_export: bool,
    pub redirect_dir: bool,
    pub redirect_always_follow: bool,
}

impl Defaults {
    pub fn read(dir: &Path) -> Result<Self> {
        let flag = |name: &str| -> Result<bool> {
            let path = dir.join(name);
            match fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?.trim() {
                "Y" => Ok(true),
                "N" => Ok(false),
                other => bail!("unexpected {} value {other:?}", path.display()),
            }
        };
        Ok(Self { index: flag("index")?, metacopy: flag("metacopy")?, nfs_export: flag("nfs_export")?,
            redirect_dir: flag("redirect_dir")?, redirect_always_follow: flag("redirect_always_follow")? })
    }

    /// The redirect mode a mount gets when it doesn't choose one (and what
    /// `redirect_dir=off` turns into).
    fn redirect_mode(&self) -> &'static str {
        if self.redirect_dir { "on" } else if self.redirect_always_follow { "follow" } else { "nofollow" }
    }

    fn describe(&self) -> String {
        let yn = |b: bool| if b { "Y" } else { "N" };
        format!("index={} metacopy={} nfs_export={} redirect_dir={} redirect_always_follow={}",
            yn(self.index), yn(self.metacopy), yn(self.nfs_export), yn(self.redirect_dir),
            yn(self.redirect_always_follow))
    }
}

/// The features one mounted overlay actually has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effective {
    pub index: bool,
    pub metacopy: bool,
    pub nfs_export: bool,
    pub redirect_dir: String,
    /// `xino=`, `uuid=` and `nouserxattr` as shown (they change inode
    /// numbering and origin handle encoding, or confirm the default trusted.*
    /// xattr namespace, not which metadata kinds the upper can hold).
    pub informational: Vec<String>,
}

impl Effective {
    pub fn describe(&self) -> String {
        let onoff = |b: bool| if b { "on" } else { "off" };
        let mut text = format!("index={} metacopy={} nfs_export={} redirect_dir={}", onoff(self.index),
            onoff(self.metacopy), onoff(self.nfs_export), self.redirect_dir);
        for option in &self.informational { text.push(' '); text.push_str(option); }
        text
    }

    /// Whether these are exactly the pinned features.
    pub fn check_pinned(&self) -> std::result::Result<(), String> {
        if self.index || self.metacopy || self.nfs_export || self.redirect_dir != "nofollow" {
            return Err(format!("effective {} differ from pinned {}", self.describe(), pinned_options()));
        }
        Ok(())
    }
}

/// Undoes mountinfo's octal escapes (`\040` for a space, `\054` for a comma).
fn unescape(field: &str) -> Result<Vec<u8>> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            let digits = bytes.get(i + 1..i + 4).context("truncated mountinfo escape")?;
            ensure!(digits.iter().all(|d| (b'0'..=b'7').contains(d)), "invalid mountinfo escape");
            let value = digits.iter().fold(0u32, |n, d| n * 8 + u32::from(d - b'0'));
            out.push(u8::try_from(value).context("invalid mountinfo escape")?);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// The filesystem type and super options of the mountinfo line with `id`.
fn super_options(mountinfo: &str, id: u64) -> Result<(String, String)> {
    for line in mountinfo.lines() {
        let mut fields = line.split(' ');
        if fields.next().and_then(|f| f.parse::<u64>().ok()) != Some(id) { continue; }
        let (_, tail) = line.split_once(" - ").context("malformed mountinfo line")?;
        let tail: Vec<&str> = tail.split(' ').collect();
        ensure!(tail.len() == 3, "malformed mountinfo line");
        return Ok((tail[0].to_owned(), tail[2].to_owned()));
    }
    bail!("mount {id} is not in mountinfo")
}

/// Interprets one overlay's super options against the module defaults. The
/// three layer paths must be the ones kiln mounted. Any option kiln did not
/// ask for and does not recognize makes the mount unverifiable.
pub fn effective(options: &str, defaults: &Defaults, layers: [&Path; 3]) -> Result<Effective> {
    let mut e = Effective { index: defaults.index, metacopy: defaults.metacopy, nfs_export: defaults.nfs_export,
        redirect_dir: defaults.redirect_mode().to_owned(), informational: Vec::new() };
    let mut seen = Vec::new();
    for option in options.split(',') {
        let (key, value) = option.split_once('=').unwrap_or((option, ""));
        ensure!(!seen.contains(&key), "overlay option {key} appears twice");
        seen.push(key);
        let onoff = |v: &str| match v { "on" => Ok(true), "off" => Ok(false), _ => bail!("unexpected {key}={v}") };
        match key {
            "rw" if value.is_empty() => {}
            "lowerdir" | "upperdir" | "workdir" => {
                let expected = layers[["lowerdir", "upperdir", "workdir"].iter().position(|k| *k == key).unwrap()];
                ensure!(unescape(value)? == expected.as_os_str().as_encoded_bytes(),
                    "overlay {key} is not the run's layer");
            }
            "index" => e.index = onoff(value)?,
            "metacopy" => e.metacopy = onoff(value)?,
            "nfs_export" => e.nfs_export = onoff(value)?,
            "redirect_dir" => {
                ensure!(matches!(value, "on" | "follow" | "nofollow"), "unexpected redirect_dir={value}");
                e.redirect_dir = value.to_owned();
            }
            "xino" | "uuid" => e.informational.push(option.to_owned()),
            // Shown by 6.8 on every mount: overlay metadata lives in trusted.*
            // xattrs, the namespace the checkpoint walker interprets. Its
            // opposite, `userxattr`, stays unrecognized.
            "nouserxattr" if value.is_empty() => e.informational.push(option.to_owned()),
            _ => bail!("unrecognized overlay option {option:?}"),
        }
    }
    for key in ["lowerdir", "upperdir", "workdir"] {
        ensure!(seen.contains(&key), "overlay options lack {key}");
    }
    Ok(e)
}

/// Super options with the layer paths replaced by their role, for the record.
fn redacted(options: &str) -> String {
    options.split(',').map(|o| match o.split_once('=') {
        Some((k @ ("lowerdir" | "upperdir" | "workdir"), _)) => format!("{k}=<{}>", &k[..k.len() - 3]),
        _ => o.to_owned(),
    }).collect::<Vec<_>>().join(",")
}

/// One read-back of the overlay mounted at `merged`.
pub struct ReadBack {
    pub defaults: Defaults,
    pub options: String,
    pub effective: Effective,
}

/// Reads the mounted overlay's effective features. Must run in the mount
/// namespace that holds the mount, while the host's /proc and /sys are visible.
pub fn read_back(merged: &Path, layers: [&Path; 3]) -> Result<ReadBack> {
    let id = mount_id(merged)?;
    let parameters = Path::new(PARAMETERS);
    let before = Defaults::read(parameters)?;
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").context("read mountinfo")?;
    let after = Defaults::read(parameters)?;
    ensure!(before == after, "overlay module defaults changed while reading the mount");
    let (fstype, options) = super_options(&mountinfo, id)?;
    ensure!(fstype == "overlay", "{} is a {fstype} mount, not overlay", merged.display());
    let effective = effective(&options, &before, layers)?;
    Ok(ReadBack { defaults: before, options, effective })
}

fn mount_id(path: &Path) -> Result<u64> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut st = unsafe { std::mem::zeroed::<libc::statx>() };
    // SAFETY: valid path and output buffer.
    let n = unsafe { libc::statx(libc::AT_FDCWD, name.as_ptr(), libc::AT_SYMLINK_NOFOLLOW,
        libc::STATX_MNT_ID, &mut st) };
    if n != 0 { return Err(std::io::Error::last_os_error()).context("statx mount ID"); }
    ensure!(st.stx_mask & libc::STATX_MNT_ID != 0, "kernel did not report a mount ID");
    Ok(st.stx_mnt_id)
}

/// The text of `<run>/layout`. `generated` lists the runtime-generated upper
/// entries this run writes (see protected.rs).
pub fn layout_text(read: &std::result::Result<ReadBack, String>, generated: &[&str]) -> String {
    let mut text = format!("{LAYOUT_MAGIC}\npinned {}\n", pinned_options());
    match read {
        Ok(r) => {
            text.push_str(&format!("defaults {}\nsuper {}\neffective {}\n", r.defaults.describe(),
                redacted(&r.options), r.effective.describe()));
            match r.effective.check_pinned() {
                Ok(()) => text.push_str("verified yes\n"),
                Err(reason) => text.push_str(&format!("verified no {}\n", one_line(&reason))),
            }
        }
        Err(reason) => text.push_str(&format!("verified no {}\n", one_line(reason))),
    }
    for path in generated { text.push_str(&format!("generated {path}\n")); }
    text
}

fn one_line(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(512).collect()
}

/// A parsed `<run>/layout`.
#[derive(Debug, PartialEq, Eq)]
pub struct Layout {
    pub verified: std::result::Result<(), String>,
    pub effective: Option<String>,
    pub generated: Vec<String>,
}

pub fn parse_layout(text: &str) -> Result<Layout> {
    let mut lines = text.lines();
    ensure!(lines.next() == Some(LAYOUT_MAGIC), "not a kiln layout record");
    let mut layout = Layout { verified: Err("no verification line".into()), effective: None, generated: Vec::new() };
    let mut seen = Vec::new();
    let mut verified = false;
    for line in lines {
        let (key, value) = line.split_once(' ').context("malformed layout line")?;
        ensure!(key == "generated" || !seen.contains(&key), "duplicate layout key {key}");
        seen.push(key);
        match key {
            "pinned" => ensure!(value == pinned_options(), "layout pins {value:?}"),
            "defaults" | "super" => {}
            "effective" => layout.effective = Some(value.to_owned()),
            "verified" => {
                verified = true;
                layout.verified = match value.split_once(' ').unwrap_or((value, "")) {
                    ("yes", "") => Ok(()),
                    ("no", reason) => Err(reason.to_owned()),
                    _ => bail!("malformed layout verification"),
                };
            }
            "generated" => layout.generated.push(value.to_owned()),
            _ => bail!("unknown layout key {key}"),
        }
    }
    ensure!(verified && seen.contains(&"pinned"), "incomplete layout record");
    if layout.verified.is_ok() {
        let expected = "index=off metacopy=off nfs_export=off redirect_dir=nofollow";
        ensure!(layout.effective.as_deref().is_some_and(|e| e == expected || e.starts_with(&format!("{expected} "))),
            "verified layout without the pinned effective features");
    }
    Ok(layout)
}

/// `None` for a run created before layout records existed.
pub fn read_layout(run_dir: &Path) -> Result<Option<Layout>> {
    let path = run_dir.join(LAYOUT_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => parse_layout(&text).with_context(|| format!("parse {}", path.display())).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UBUNTU: Defaults = Defaults { index: false, metacopy: false, nfs_export: false, redirect_dir: false,
        redirect_always_follow: true };

    fn layers() -> [&'static Path; 3] {
        [Path::new("/var/lib/kiln/images/alpine"), Path::new("/var/lib/kiln/runs/a-1/upper"),
            Path::new("/var/lib/kiln/runs/a-1/work")]
    }
    const PATHS: &str = "lowerdir=/var/lib/kiln/images/alpine,upperdir=/var/lib/kiln/runs/a-1/upper,workdir=/var/lib/kiln/runs/a-1/work";

    #[test]
    fn mount_data_appends_exactly_the_pins() {
        assert_eq!(pinned_options(), "index=off,metacopy=off,redirect_dir=nofollow,nfs_export=off");
        let [l, u, w] = layers();
        assert_eq!(mount_data(l, u, w), format!("{PATHS},index=off,metacopy=off,redirect_dir=nofollow,nfs_export=off"));
    }

    #[test]
    fn omitted_features_take_the_module_default() {
        // Ubuntu: only redirect_dir differs from its default (follow), so the
        // kernel shows only that one.
        let e = effective(&format!("rw,{PATHS},redirect_dir=nofollow"), &UBUNTU, layers()).unwrap();
        e.check_pinned().unwrap();
        assert_eq!(e.describe(), "index=off metacopy=off nfs_export=off redirect_dir=nofollow");
        // Without the redirect pin the default is follow, not pinned.
        let e = effective(&format!("rw,{PATHS}"), &UBUNTU, layers()).unwrap();
        assert_eq!(e.redirect_dir, "follow");
        assert!(e.check_pinned().is_err());
        // A host whose defaults enable features: shown "off" values win.
        let on = Defaults { index: true, metacopy: true, nfs_export: true, redirect_dir: true, redirect_always_follow: true };
        let e = effective(&format!("rw,{PATHS},redirect_dir=nofollow,index=off,nfs_export=off,metacopy=off"), &on, layers()).unwrap();
        e.check_pinned().unwrap();
        let e = effective(&format!("rw,{PATHS},redirect_dir=nofollow,index=off,nfs_export=off"), &on, layers()).unwrap();
        assert!(e.metacopy && e.check_pinned().is_err());
        let nofollow = Defaults { redirect_always_follow: false, ..UBUNTU };
        effective(&format!("rw,{PATHS}"), &nofollow, layers()).unwrap().check_pinned().unwrap();
    }

    #[test]
    fn unknown_duplicate_or_foreign_options_are_unverifiable() {
        for bad in [format!("rw,{PATHS},userxattr"), format!("rw,{PATHS},volatile"),
            format!("rw,{PATHS},default_permissions"), format!("rw,{PATHS},index=off,index=off"),
            format!("rw,{PATHS},redirect_dir=off"), format!("rw,{PATHS},index=maybe"),
            PATHS.replace("a-1/upper", "b-2/upper"), "rw,lowerdir=/x".into()] {
            assert!(effective(&bad, &UBUNTU, layers()).is_err(), "{bad}");
        }
        let e = effective(&format!("rw,{PATHS},redirect_dir=nofollow,xino=off,uuid=null"), &UBUNTU, layers()).unwrap();
        e.check_pinned().unwrap();
        assert_eq!(e.informational, ["xino=off", "uuid=null"]);
        // Exactly what Ubuntu 6.8.0-147 shows for kiln's pinned mount.
        let e = effective(&format!("rw,{PATHS},redirect_dir=nofollow,uuid=on,nouserxattr"), &UBUNTU, layers()).unwrap();
        e.check_pinned().unwrap();
        assert_eq!(e.describe(), "index=off metacopy=off nfs_export=off redirect_dir=nofollow uuid=on nouserxattr");
        assert!(effective(&format!("rw,{PATHS},nouserxattr=1"), &UBUNTU, layers()).is_err());
    }

    #[test]
    fn mountinfo_lookup_and_escapes() {
        let info = "22 1 0:21 / /proc rw,nosuid shared:5 - proc proc rw\n\
            97 22 0:44 / /var/lib/kiln/runs/a-1/merged rw,relatime - overlay overlay rw,lowerdir=/a\\054b,upperdir=/u\\040v,workdir=/w\n";
        let (fstype, options) = super_options(info, 97).unwrap();
        assert_eq!(fstype, "overlay");
        let e = effective(&format!("{options},redirect_dir=nofollow"), &UBUNTU,
            [Path::new("/a,b"), Path::new("/u v"), Path::new("/w")]).unwrap();
        e.check_pinned().unwrap();
        assert!(super_options(info, 98).is_err());
        assert!(unescape("\\05").is_err() && unescape("\\089").is_err() && unescape("\\777").is_err());
        assert_eq!(redacted("rw,lowerdir=/a,upperdir=/b,workdir=/c,redirect_dir=nofollow"),
            "rw,lowerdir=<lower>,upperdir=<upper>,workdir=<work>,redirect_dir=nofollow");
    }

    #[test]
    fn layout_record_round_trips_and_is_strict() {
        let read = ReadBack { defaults: UBUNTU.clone(), options: format!("rw,{PATHS},redirect_dir=nofollow"),
            effective: effective(&format!("rw,{PATHS},redirect_dir=nofollow"), &UBUNTU, layers()).unwrap() };
        let text = layout_text(&Ok(read), &["/etc/resolv.conf"]);
        assert_eq!(text, "kiln-layout 1\npinned index=off,metacopy=off,redirect_dir=nofollow,nfs_export=off\n\
            defaults index=N metacopy=N nfs_export=N redirect_dir=N redirect_always_follow=Y\n\
            super rw,lowerdir=<lower>,upperdir=<upper>,workdir=<work>,redirect_dir=nofollow\n\
            effective index=off metacopy=off nfs_export=off redirect_dir=nofollow\n\
            verified yes\ngenerated /etc/resolv.conf\n");
        let layout = parse_layout(&text).unwrap();
        assert_eq!(layout.verified, Ok(()));
        assert_eq!(layout.generated, ["/etc/resolv.conf"]);
        let failed = layout_text(&Err("no\nparams".into()), &[]);
        assert_eq!(parse_layout(&failed).unwrap().verified, Err("no params".into()));
        for bad in [text.replace("verified yes", "verified maybe"), text.replace("kiln-layout 1", "kiln-layout 2"),
            text.replace("effective index=off", "effective index=on"), format!("{text}verified yes\n"),
            text.replace("verified yes\n", ""), format!("{text}extra 1\n"),
            text.replace("pinned index=off,", "pinned ")] {
            assert!(parse_layout(&bad).is_err(), "{bad}");
        }
    }
}
