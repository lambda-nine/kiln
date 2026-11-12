//! Workspace checkpoints, format v1 (docs/checkpoint-format-v1.md).
//!
//! A checkpoint is a normalized copy of a quiescent run's raw upper layer: a
//! canonical JSON manifest plus one flat object file per regular-file inode,
//! stored under `/var/lib/kiln/runs/.checkpoints/<instance>/<checkpoint>/`.
//! Capture holds the source's operation 6 lease while it walks the upper with
//! descriptor-relative, no-follow reads (`walk`), copies file bytes into
//! objects with SHA-256 (`store`), and publishes through a quota-limited,
//! fsynced staging directory. Restore (`restore`) rebuilds a fresh, unmounted
//! upper for a new run from a fully validated artifact; it never links,
//! mounts or shares anything with the artifact or the source.
//!
//! Everything the format cannot represent is refused with a typed reason
//! (`Reason`), never dropped, with one documented exception: the kernel's own
//! overlay bookkeeping xattrs (`trusted.overlay.origin`, `impure`, `uuid`),
//! which capture excludes and counts in the artifact and restore never writes.

pub mod capture;
pub mod manifest;
pub mod restore;
pub mod store;
pub mod walk;

use std::fmt;
use std::path::Path;

use anyhow::{Context, Result, ensure};

/// The manifest format this kiln writes and reads.
pub const FORMAT: u32 = 1;
/// Domain separation for `content_sha256` (followed by one zero byte).
pub const CONTENT_DOMAIN: &[u8] = b"kilnd.workspace-checkpoint.1";
/// Domain separation for the binding digest over the header and content digest.
pub const BINDING_DOMAIN: &[u8] = b"kiln.checkpoint-binding.1";

/// Manifest entries, the root included.
pub const MAX_ENTRIES: usize = 65_536;
pub const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_NAME_BYTES: usize = 255;
pub const MAX_DEPTH: usize = 128;
/// XFS refuses symlink targets of 1,024 bytes or more (measured), so the v1
/// format bound is the filesystem's.
pub const MAX_LINK_TARGET: usize = 1023;
pub const MAX_USER_XATTRS: usize = 32;
/// Names plus values of the user xattrs of one entry. The 16 KiB per-entry
/// allowance was measured conservative only with this cap.
pub const MAX_USER_XATTR_BYTES: usize = 4096;
/// Heap a checkpoint worker may spend on retained metadata (manifest entries,
/// directory listings in progress, decoded manifests). With the 16 MiB
/// encoded manifest and buffers this keeps capture and restore inside the
/// design's 64 MiB worker memory limit.
pub const HEAP_BUDGET: usize = 32 * 1024 * 1024;
/// The per-entry metadata allowance in the storage charge.
pub const ENTRY_ALLOWANCE: u64 = 16 * 1024;
/// Bounds on the reservation a capture may be given (`--max-bytes`).
pub const MIN_LIMIT_BYTES: u64 = 64 * 1024;
pub const MAX_LIMIT_BYTES: u64 = 1 << 40;

/// The kernel-written overlay xattrs capture excludes (decision of 12 Nov
/// 2026), sorted. Every other `trusted.overlay.*` form is refused.
pub const EXCLUDED_XATTRS: [&str; 3] = ["trusted.overlay.impure", "trusted.overlay.origin", "trusted.overlay.uuid"];

/// Typed refusal and failure reasons, as the `kilnd-reason` tokens of the
/// design (§7.3). The helper maps these, never the detail text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The source cannot be checkpointed (old run or PID 1, unverified layout).
    SandboxUnsupported,
    Busy,
    LayoutUnsupported,
    MetadataUnsupported,
    ImageUnavailable,
    SizeLimit,
    SpecMismatch,
    DiskTooSmall,
    Corrupt,
    /// A generation-checked removal found another generation published.
    GenerationMismatch,
    Io,
    InvalidRequest,
}

impl Reason {
    pub fn token(self) -> &'static str {
        match self {
            Reason::SandboxUnsupported => "sandbox_unsupported:workspace_checkpoint",
            Reason::Busy => "checkpoint_busy",
            Reason::LayoutUnsupported => "checkpoint_layout_unsupported",
            Reason::MetadataUnsupported => "checkpoint_metadata_unsupported",
            Reason::ImageUnavailable => "checkpoint_image_unavailable",
            Reason::SizeLimit => "checkpoint_size_limit",
            Reason::SpecMismatch => "checkpoint_spec_mismatch",
            Reason::DiskTooSmall => "checkpoint_disk_too_small",
            Reason::Corrupt => "checkpoint_corrupt",
            Reason::GenerationMismatch => "checkpoint_generation_mismatch",
            Reason::Io => "checkpoint_io",
            Reason::InvalidRequest => "invalid_request",
        }
    }
}

/// A typed refusal. Details never carry sandbox file names, link targets,
/// xattr values or file bytes: entries are named by their manifest ordinal,
/// and only runtime paths and kernel xattr names appear verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: Reason,
    pub detail: String,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}: {}", self.reason.token(), self.detail) }
}
impl std::error::Error for Refusal {}

pub fn refuse(reason: Reason, detail: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Refusal { reason, detail: detail.into() })
}

/// The typed reason anywhere in an error chain. An untyped failure is I/O:
/// a refusal is always explicit.
pub fn reason_of(error: &anyhow::Error) -> Reason {
    error.chain().find_map(|c| c.downcast_ref::<Refusal>().map(|r| r.reason))
        .or_else(|| error.chain().find_map(|c| c.downcast_ref::<crate::protected::LayoutError>()
            .map(|_| Reason::LayoutUnsupported)))
        .unwrap_or(Reason::Io)
}

/// The failure record a checkpoint command prints on stdout before exiting 125.
pub fn failure_text(error: &anyhow::Error) -> String {
    let reason = reason_of(error);
    let detail: String = format!("{error:#}").chars().map(|c| if c.is_control() { ' ' } else { c }).take(512).collect();
    format!("kiln-checkpoint-failure 1\nreason {}\ndetail {detail}\n", reason.token())
}

/// `<instance>`: the helper's 128-bit instance identity, 32 lowercase hex.
pub fn validate_instance(id: &str) -> Result<()> {
    if !(id.len() == 32 && lower_hex(id)) {
        return Err(refuse(Reason::InvalidRequest, format!("invalid checkpoint instance {id:?}")));
    }
    Ok(())
}

/// `cp-` plus 32 lowercase hex digits.
pub fn validate_checkpoint_id(id: &str) -> Result<()> {
    let ok = id.strip_prefix("cp-").is_some_and(|h| h.len() == 32 && lower_hex(h));
    if !ok { return Err(refuse(Reason::InvalidRequest, format!("invalid checkpoint ID {id:?}"))); }
    Ok(())
}

fn lower_hex(s: &str) -> bool { s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) }

pub fn hex32(text: &str) -> Result<[u8; 32]> {
    ensure!(text.len() == 64 && lower_hex(text), "malformed sha256");
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() { *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?; }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Run policy record: `<run>/policy`

pub const POLICY_FILE: &str = "policy";
const POLICY_MAGIC: &str = "kiln-policy 1";

/// The run's root-write policy and normalized writable paths, recorded at
/// create so capture binds them and a fork must match them. A run without the
/// record (created by an older kiln) is not a checkpoint source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub read_only_root: bool,
    /// Sorted, deduplicated, absolute.
    pub writable: Vec<String>,
}

impl Policy {
    pub fn new(read_only_root: bool, writable: &[std::path::PathBuf]) -> Result<Self> {
        let mut paths = writable.iter().map(|p| p.to_str().map(str::to_owned).context("writable path is not UTF-8"))
            .collect::<Result<Vec<_>>>()?;
        paths.sort();
        paths.dedup();
        Ok(Self { read_only_root, writable: paths })
    }

    pub fn text(&self) -> String {
        let mut text = format!("{POLICY_MAGIC}\nread-only-root {}\n", if self.read_only_root { "yes" } else { "no" });
        for p in &self.writable { text.push_str(&format!("writable {p}\n")); }
        text
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut lines = text.split_terminator('\n');
        ensure!(lines.next() == Some(POLICY_MAGIC), "not a kiln policy record");
        let read_only_root = match lines.next() {
            Some("read-only-root yes") => true,
            Some("read-only-root no") => false,
            _ => anyhow::bail!("malformed policy record"),
        };
        let writable = lines.map(|l| l.strip_prefix("writable ").map(str::to_owned).context("malformed policy line"))
            .collect::<Result<Vec<_>>>()?;
        crate::validation::validate_writable_paths(&writable.iter().map(std::path::PathBuf::from).collect::<Vec<_>>())?;
        ensure!(writable.windows(2).all(|w| w[0] < w[1]), "policy writable paths are not sorted and unique");
        let policy = Self { read_only_root, writable };
        ensure!(policy.text() == text && (read_only_root || policy.writable.is_empty()), "non-canonical policy record");
        Ok(policy)
    }
}

/// `None` for a run created before policy records existed.
pub fn read_policy(run_dir: &Path) -> Result<Option<Policy>> {
    let path = run_dir.join(POLICY_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => Policy::parse(&text).with_context(|| format!("parse {}", path.display())).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_ids_and_failure_records() {
        assert_eq!(Reason::MetadataUnsupported.token(), "checkpoint_metadata_unsupported");
        let e = refuse(Reason::SizeLimit, "too big").context("capture");
        assert_eq!(reason_of(&e), Reason::SizeLimit);
        assert_eq!(failure_text(&e), "kiln-checkpoint-failure 1\nreason checkpoint_size_limit\ndetail capture: \
            checkpoint_size_limit: too big\n");
        assert_eq!(reason_of(&anyhow::anyhow!("plain")), Reason::Io);
        let layout = anyhow::Error::new(crate::protected::LayoutError("x".into()));
        assert_eq!(reason_of(&layout), Reason::LayoutUnsupported);
        validate_instance(&"a".repeat(32)).unwrap();
        validate_checkpoint_id(&format!("cp-{}", "0".repeat(32))).unwrap();
        for bad in ["", "cp-", &format!("cp-{}", "A".repeat(32)), &format!("cp-{}", "0".repeat(31)), "../x",
            &format!("xp-{}", "0".repeat(32))] {
            assert!(validate_checkpoint_id(bad).is_err(), "{bad}");
        }
        assert!(validate_instance(&"a".repeat(31)).is_err() && validate_instance(".checkpoints").is_err());
    }

    #[test]
    fn policy_records_are_canonical() {
        let p = Policy::new(true, &["/b".into(), "/a".into(), "/b".into()]).unwrap();
        assert_eq!(p.text(), "kiln-policy 1\nread-only-root yes\nwritable /a\nwritable /b\n");
        assert_eq!(Policy::parse(&p.text()).unwrap(), p);
        let open = Policy::new(false, &[]).unwrap();
        assert_eq!(Policy::parse("kiln-policy 1\nread-only-root no\n").unwrap(), open);
        for bad in ["kiln-policy 1\nread-only-root yes\nwritable /b\nwritable /a\n",
            "kiln-policy 1\nread-only-root no\nwritable /a\n", "kiln-policy 1\nread-only-root maybe\n",
            "kiln-policy 1\nread-only-root yes\nwritable relative\n", "kiln-policy 2\nread-only-root no\n",
            "kiln-policy 1\nread-only-root no"] {
            assert!(Policy::parse(bad).is_err(), "{bad}");
        }
    }
}
