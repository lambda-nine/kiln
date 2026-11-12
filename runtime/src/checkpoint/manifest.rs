//! The normalized manifest: canonical JSON (cjson.rs) describing one upper.
//!
//! Paths are base64 of their raw bytes, relative to the upper root, without a
//! leading slash; the root has its own record. Entries are in walk order: a
//! pre-order traversal with siblings sorted by name bytes, which is the order
//! of each path's list of components compared bytewise. Parents therefore
//! precede children, and the parent of every entry is the root or an earlier
//! directory entry. Regular-file bytes live in objects numbered by the order
//! of `file` entries. See docs/checkpoint-format-v1.md for the full schema.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};

use super::{CONTENT_DOMAIN, EXCLUDED_XATTRS, FORMAT, HEAP_BUDGET, MAX_DEPTH, MAX_ENTRIES, MAX_LINK_TARGET,
    MAX_MANIFEST_BYTES, MAX_NAME_BYTES, MAX_PATH_BYTES, MAX_USER_XATTRS, MAX_USER_XATTR_BYTES, Reason, refuse};
use crate::cjson::{self, Json, parse_at, unbase64};
use crate::protected::{self, Disposition, Kind as Contract};
use crate::sha256::{Sha256, hex};

pub const SCOPE: &str = "persistent_overlay";

/// One entry's user xattrs, packed into a single allocation: repeated
/// `u32 name length, name, u32 value length, value` (little endian), in
/// manifest order. Retained metadata costs its bytes, not a heap block per
/// name and value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Xattrs { buf: Vec<u8> }

impl Xattrs {
    pub fn new() -> Self { Self::default() }

    /// Packs pairs in the order given, with exact capacity.
    pub fn from_pairs<N: AsRef<[u8]>, V: AsRef<[u8]>>(pairs: impl IntoIterator<Item = (N, V)>) -> Self {
        let mut x = Self::new();
        for (n, v) in pairs { x.push(n.as_ref(), v.as_ref()); }
        x.buf.shrink_to_fit();
        x
    }

    pub fn push(&mut self, name: &[u8], value: &[u8]) {
        self.buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(name);
        self.buf.extend_from_slice(&(value.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(value);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        let mut at = 0;
        let buf = &self.buf;
        std::iter::from_fn(move || {
            if at >= buf.len() { return None; }
            let mut take = || {
                let n = u32::from_le_bytes(buf[at..at + 4].try_into().unwrap()) as usize;
                let s = &buf[at + 4..at + 4 + n];
                at += 4 + n;
                s
            };
            let name = take();
            let value = take();
            Some((name, value))
        })
    }

    /// Heap bytes this value holds.
    pub fn heap(&self) -> usize { self.buf.capacity() }

    #[cfg(test)]
    pub fn to_pairs(&self) -> Vec<(Vec<u8>, Vec<u8>)> { self.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect() }
}

/// Inode metadata of a directory, regular file or the root. IDs are in the
/// sandbox's namespace (0..=65535), never host IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    /// `st_mode & 07777`.
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: (i64, u32),
    /// `user.*` xattrs (never `user.overlay.*`), sorted by name.
    pub xattrs: Xattrs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Dir { meta: Meta, opaque: bool },
    File { meta: Meta, size: u64, sha256: [u8; 32], object: u32 },
    /// Symlinks carry owner and mtime only: their mode is always 0777 and
    /// Linux allows no user xattrs on them.
    Symlink { uid: u32, gid: u32, mtime: (i64, u32), target: Vec<u8> },
    /// Another name of the `file` entry at index `link` of `entries`.
    HardLink { link: u32 },
    Whiteout,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: Vec<u8>,
    pub body: Body,
}

/// What one retained entry costs the worker's heap budget.
pub fn entry_heap(e: &Entry) -> usize {
    let extra = match &e.body {
        Body::Dir { meta, .. } | Body::File { meta, .. } => meta.xattrs.heap(),
        Body::Symlink { target, .. } => target.capacity(),
        _ => 0,
    };
    std::mem::size_of::<Entry>() + e.path.capacity() + extra
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub image_sha256: String,
    pub read_only_root: bool,
    /// Sorted, unique, absolute (the run's policy record).
    pub writable_paths: Vec<String>,
    /// `protected::excluded_paths` of the source run's generated entries.
    pub excluded_paths: Vec<String>,
    pub root: Meta,
    pub entries: Vec<Entry>,
}

/// Sizes the storage charge and the completion record use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Manifest entries including the root (N).
    pub entries: u64,
    pub objects: u32,
    /// Regular-file logical bytes, once per inode (L).
    pub logical: u64,
    /// The same, each file rounded up to 4 KiB.
    pub logical_blocks: u64,
}

pub fn content_sha256(manifest: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONTENT_DOMAIN);
    h.update(&[0]);
    h.update(manifest);
    h.finish()
}

// ---------------------------------------------------------------------------
// Streaming canonical encoder. Keys are written in their sorted order by
// hand, so no JSON tree is ever built for a manifest.

fn key(out: &mut Vec<u8>, first: bool, k: &str) {
    if !first { out.push(b','); }
    out.push(b'"');
    out.extend_from_slice(k.as_bytes());
    out.extend_from_slice(b"\":");
}

fn b64(out: &mut Vec<u8>, bytes: &[u8]) {
    out.push(b'"');
    cjson::base64_into(out, bytes);
    out.push(b'"');
}

fn int(out: &mut Vec<u8>, n: impl std::fmt::Display) { out.extend_from_slice(n.to_string().as_bytes()); }

fn mtime_out(out: &mut Vec<u8>, m: (i64, u32)) { out.push(b'['); int(out, m.0); out.push(b','); int(out, m.1); out.push(b']'); }

fn xattrs_out(out: &mut Vec<u8>, x: &Xattrs) {
    out.push(b'[');
    for (i, (n, v)) in x.iter().enumerate() {
        if i != 0 { out.push(b','); }
        out.push(b'[');
        b64(out, n);
        out.push(b',');
        b64(out, v);
        out.push(b']');
    }
    out.push(b']');
}

fn strings_out(out: &mut Vec<u8>, v: &[impl AsRef<str>]) {
    out.push(b'[');
    for (i, s) in v.iter().enumerate() {
        if i != 0 { out.push(b','); }
        cjson::string(out, s.as_ref());
    }
    out.push(b']');
}

/// `gid`, `mode`, `mtime` then whatever sorts between `mtime` and `uid`,
/// then `uid` and `xattrs`.
fn meta_out(out: &mut Vec<u8>, m: &Meta, middle: impl FnOnce(&mut Vec<u8>)) {
    key(out, true, "gid"); int(out, m.gid);
    key(out, false, "mode"); int(out, m.mode);
    key(out, false, "mtime"); mtime_out(out, m.mtime);
    middle(out);
    key(out, false, "uid"); int(out, m.uid);
    key(out, false, "xattrs"); xattrs_out(out, &m.xattrs);
}

impl Entry {
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(b'{');
        match &self.body {
            Body::Dir { meta, opaque } => meta_out(out, meta, |out| {
                key(out, false, "opaque"); out.extend_from_slice(if *opaque { b"true" } else { b"false" });
                key(out, false, "path"); b64(out, &self.path);
                key(out, false, "type"); out.extend_from_slice(b"\"dir\"");
            }),
            Body::File { meta, size, sha256, object } => meta_out(out, meta, |out| {
                key(out, false, "object"); int(out, object);
                key(out, false, "path"); b64(out, &self.path);
                key(out, false, "sha256"); out.push(b'"'); out.extend_from_slice(hex(sha256).as_bytes()); out.push(b'"');
                key(out, false, "size"); int(out, size);
                key(out, false, "type"); out.extend_from_slice(b"\"file\"");
            }),
            Body::Symlink { uid, gid, mtime, target } => {
                key(out, true, "gid"); int(out, gid);
                key(out, false, "mtime"); mtime_out(out, *mtime);
                key(out, false, "path"); b64(out, &self.path);
                key(out, false, "target"); b64(out, target);
                key(out, false, "type"); out.extend_from_slice(b"\"symlink\"");
                key(out, false, "uid"); int(out, uid);
            }
            Body::HardLink { link } => {
                key(out, true, "link"); int(out, link);
                key(out, false, "path"); b64(out, &self.path);
                key(out, false, "type"); out.extend_from_slice(b"\"hardlink\"");
            }
            Body::Whiteout => {
                key(out, true, "path"); b64(out, &self.path);
                key(out, false, "type"); out.extend_from_slice(b"\"whiteout\"");
            }
        }
        out.push(b'}');
    }

    /// The contract kind of this entry for `protected::check`.
    pub fn contract_kind(&self) -> Contract {
        match &self.body {
            Body::Dir { opaque, .. } => Contract::Directory { opaque: *opaque },
            Body::File { .. } | Body::HardLink { .. } => Contract::Regular,
            Body::Symlink { .. } => Contract::Symlink,
            Body::Whiteout => Contract::Whiteout,
        }
    }
}

const PREFIX: &[u8] = b"{\"entries\":[";
/// Everything after the entries array is small; a larger tail is corrupt.
const MAX_TAIL: usize = 512 * 1024;

impl Manifest {
    /// The fields after `entries`, from `,"excluded_paths":` to the final `}`.
    fn encode_tail(&self, out: &mut Vec<u8>) {
        key(out, false, "excluded_paths"); strings_out(out, self.excluded_paths.as_slice());
        key(out, false, "excluded_xattrs"); strings_out(out, &EXCLUDED_XATTRS[..]);
        key(out, false, "format"); int(out, FORMAT);
        key(out, false, "image_sha256"); cjson::string(out, &self.image_sha256);
        key(out, false, "read_only_root"); out.extend_from_slice(if self.read_only_root { b"true" } else { b"false" });
        key(out, false, "root"); out.push(b'{'); meta_out(out, &self.root, |_| {}); out.push(b'}');
        key(out, false, "scope"); cjson::string(out, SCOPE);
        key(out, false, "writable_paths"); strings_out(out, self.writable_paths.as_slice());
        out.push(b'}');
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(PREFIX);
        for (i, e) in self.entries.iter().enumerate() {
            if i != 0 { out.push(b','); }
            e.encode_into(&mut out);
        }
        out.push(b']');
        self.encode_tail(&mut out);
        out
    }

    /// The runtime-generated entries the source excluded, recovered from the
    /// published exclusion list (the only list `protected` can produce).
    pub fn generated(&self) -> Result<Vec<&'static str>> {
        for generated in [&[][..], &[protected::RESOLV_CONF][..]] {
            if self.excluded_paths == protected::excluded_paths(generated) { return Ok(generated.to_vec()); }
        }
        bail!("unknown excluded path set")
    }

    /// Parses and fully validates hostile manifest bytes. Every structural
    /// rule restore depends on is checked here, before anything is created.
    /// Entries are decoded one at a time (each span re-encoded and compared,
    /// so the document is canonical) against the worker heap budget; no JSON
    /// tree of the whole document is built.
    pub fn decode(bytes: &[u8]) -> Result<(Self, Stats)> {
        let corrupt = |e: anyhow::Error| refuse(Reason::Corrupt, format!("manifest: {e:#}"));
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(refuse(Reason::Corrupt, "manifest larger than the format allows"));
        }
        let manifest = Self::decode_inner(bytes).map_err(corrupt)?;
        let stats = manifest.validate()?;
        Ok((manifest, stats))
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.starts_with(PREFIX), "manifest does not start with its entries");
        let mut at = PREFIX.len();
        let mut entries = Vec::new();
        let mut heap = 0usize;
        let mut scratch = Vec::new();
        if bytes.get(at) == Some(&b']') {
            at += 1;
        } else {
            loop {
                ensure!(entries.len() < MAX_ENTRIES - 1, "more than {MAX_ENTRIES} entries");
                let (json, end) = parse_at(bytes, at)?;
                let e = entry(&json)?;
                drop(json);
                scratch.clear();
                e.encode_into(&mut scratch);
                ensure!(bytes[at..end] == scratch[..], "manifest entry {} is not canonical", entries.len());
                heap += entry_heap(&e);
                ensure!(heap <= HEAP_BUDGET, "manifest exceeds the worker heap budget");
                entries.push(e);
                at = end;
                match bytes.get(at) {
                    Some(b',') => at += 1,
                    Some(b']') => { at += 1; break; }
                    _ => bail!("malformed entries array"),
                }
            }
        }
        // The tail: `,"excluded_paths":…}`, parsed as an object of its own.
        let tail = &bytes[at..];
        ensure!(tail.first() == Some(&b',') && tail.len() <= MAX_TAIL, "malformed manifest tail");
        let mut object_bytes = Vec::with_capacity(tail.len());
        object_bytes.push(b'{');
        object_bytes.extend_from_slice(&tail[1..]);
        let (json, end) = parse_at(&object_bytes, 0)?;
        ensure!(end == object_bytes.len(), "trailing data after the manifest");
        let top = object(&json, &["excluded_paths", "excluded_xattrs", "format", "image_sha256", "read_only_root",
            "root", "scope", "writable_paths"])?;
        let Json::Int(format) = top["format"] else { bail!("format is not an integer") };
        ensure!(format == i128::from(FORMAT), "unsupported format");
        ensure!(top["scope"] == Json::str(SCOPE), "unsupported scope");
        ensure!(strings(&top["excluded_xattrs"])? == EXCLUDED_XATTRS, "unexpected excluded xattr list");
        let image_sha256 = string(&top["image_sha256"])?.to_owned();
        super::hex32(&image_sha256)?;
        let Json::Bool(read_only_root) = top["read_only_root"] else { bail!("read_only_root is not a boolean") };
        let manifest = Self {
            image_sha256,
            read_only_root,
            writable_paths: strings(&top["writable_paths"])?,
            excluded_paths: strings(&top["excluded_paths"])?,
            root: meta(object(&top["root"], &["gid", "mode", "mtime", "uid", "xattrs"])?)?,
            entries,
        };
        let mut canonical = Vec::with_capacity(tail.len());
        manifest.encode_tail(&mut canonical);
        ensure!(canonical == tail, "manifest tail is not canonical");
        Ok(manifest)
    }

    /// Structural validation (hostile input): writable and excluded sets,
    /// metadata bounds, path grammar and order, parent types, hardlink and
    /// object references, and the protected-path contract for every entry.
    pub fn validate(&self) -> Result<Stats> {
        let corrupt = |m: String| refuse(Reason::Corrupt, format!("manifest: {m}"));
        ensure!(self.writable_paths.windows(2).all(|w| w[0] < w[1]), corrupt("writable paths not sorted".into()));
        crate::validation::validate_writable_paths(&self.writable_paths.iter().map(Into::into).collect::<Vec<_>>())
            .map_err(|e| corrupt(format!("{e:#}")))?;
        ensure!(self.read_only_root || self.writable_paths.is_empty(), corrupt("writable paths without read-only root".into()));
        let generated = self.generated().map_err(|e| corrupt(format!("{e:#}")))?;
        check_meta(&self.root).map_err(|e| corrupt(format!("root: {e:#}")))?;
        protected::check(b"/", Contract::Directory { opaque: false }, &generated)?;
        let mut stats = Stats { entries: 1, ..Stats::default() };
        // Directories on the current path: (components, index).
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut previous: Option<Vec<&[u8]>> = None;
        for (index, e) in self.entries.iter().enumerate() {
            let at = |m: &str| corrupt(format!("entry {index}: {m}"));
            let parts = components(&e.path).map_err(|m| at(&m))?;
            if let Some(prev) = &previous { ensure!(*prev < parts, at("out of order or duplicate path")); }
            // The parent is the deepest open directory; pop finished subtrees.
            let depth = parts.len();
            while stack.len() >= depth { stack.pop(); }
            ensure!(stack.len() == depth - 1 && stack.iter().zip(&parts).all(|(s, p)| s == p),
                at("parent is not a directory entry"));
            match &e.body {
                Body::Dir { meta, .. } => {
                    check_meta(meta).map_err(|m| at(&format!("{m:#}")))?;
                    stack.push(parts.last().unwrap().to_vec());
                }
                Body::File { meta, size, object, .. } => {
                    check_meta(meta).map_err(|m| at(&format!("{m:#}")))?;
                    ensure!(*object == stats.objects, at("object numbers out of sequence"));
                    stats.objects += 1;
                    stats.logical = stats.logical.checked_add(*size).ok_or_else(|| at("size overflow"))?;
                    stats.logical_blocks = stats.logical_blocks.checked_add(size.div_ceil(4096) * 4096)
                        .ok_or_else(|| at("size overflow"))?;
                }
                Body::Symlink { uid, gid, mtime, target } => {
                    ensure!(*uid <= 65535 && *gid <= 65535 && mtime.1 < 1_000_000_000, at("invalid symlink metadata"));
                    ensure!(!target.is_empty() && target.len() <= MAX_LINK_TARGET && !target.contains(&0),
                        at("invalid symlink target"));
                }
                Body::HardLink { link } => {
                    let first = self.entries.get(*link as usize).filter(|_| (*link as usize) < index);
                    ensure!(matches!(first, Some(Entry { body: Body::File { .. }, .. })),
                        at("hardlink does not name an earlier file entry"));
                }
                Body::Whiteout => {}
            }
            let mut absolute = Vec::with_capacity(e.path.len() + 1);
            absolute.push(b'/');
            absolute.extend_from_slice(&e.path);
            match protected::check(&absolute, e.contract_kind(), &generated) {
                Ok(Disposition::Capture) => {}
                Ok(Disposition::Exclude) => return Err(at("holds an excluded runtime entry")),
                Err(layout) => return Err(refuse(Reason::LayoutUnsupported, format!("entry {index}: {}", layout.0))),
            }
            stats.entries += 1;
            ensure!(stats.entries as usize <= MAX_ENTRIES, at("too many entries"));
            previous = Some(parts);
        }
        Ok(stats)
    }
}

/// Splits a relative path into components, enforcing the format's grammar.
pub fn components(path: &[u8]) -> std::result::Result<Vec<&[u8]>, String> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES { return Err("path empty or too long".into()); }
    let parts: Vec<&[u8]> = path.split(|b| *b == b'/').collect();
    if parts.len() > MAX_DEPTH { return Err(format!("deeper than {MAX_DEPTH}")); }
    for p in &parts {
        if p.is_empty() || *p == b"." || *p == b".." || p.contains(&0) || p.len() > MAX_NAME_BYTES {
            return Err("invalid path component".into());
        }
    }
    Ok(parts)
}

/// Bounds on metadata the restore applies: mapped IDs, permission bits only,
/// valid nanoseconds and the user-xattr rules.
pub fn check_meta(m: &Meta) -> Result<()> {
    ensure!(m.mode <= 0o7777 && m.uid <= 65535 && m.gid <= 65535 && m.mtime.1 < 1_000_000_000, "invalid metadata");
    check_user_xattrs(&m.xattrs)
}

pub fn check_user_xattrs(x: &Xattrs) -> Result<()> {
    let mut total = 0usize;
    let mut count = 0usize;
    let mut previous: Option<&[u8]> = None;
    for (name, value) in x.iter() {
        count += 1;
        ensure!(count <= MAX_USER_XATTRS, "more than {MAX_USER_XATTRS} user xattrs");
        ensure!(name.starts_with(b"user.") && name.len() > 5 && !name.starts_with(b"user.overlay.")
            && name.len() <= MAX_NAME_BYTES && !name.contains(&0), "xattr outside the user namespace");
        ensure!(previous.is_none_or(|p| p < name), "xattrs not sorted and unique");
        previous = Some(name);
        total += name.len() + value.len();
    }
    ensure!(total <= MAX_USER_XATTR_BYTES, "user xattrs exceed {MAX_USER_XATTR_BYTES} bytes");
    Ok(())
}

// ---------------------------------------------------------------------------
// Strict schema helpers

fn object<'a>(j: &'a Json, keys: &[&str]) -> Result<&'a BTreeMap<String, Json>> {
    let Json::Obj(o) = j else { bail!("expected an object") };
    ensure!(o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)), "unexpected object keys");
    Ok(o)
}

fn array(j: &Json) -> Result<&Vec<Json>> {
    let Json::Arr(a) = j else { bail!("expected an array") };
    Ok(a)
}

fn string(j: &Json) -> Result<&str> {
    let Json::Str(s) = j else { bail!("expected a string") };
    Ok(s)
}

fn strings(j: &Json) -> Result<Vec<String>> { array(j)?.iter().map(|s| string(s).map(str::to_owned)).collect() }

fn int_of(j: &Json) -> Result<i128> {
    let Json::Int(n) = j else { bail!("expected an integer") };
    Ok(*n)
}

fn uint<T: TryFrom<i128>>(j: &Json) -> Result<T> { T::try_from(int_of(j)?).ok().context("integer out of range") }

fn bytes(j: &Json) -> Result<Vec<u8>> { unbase64(string(j)?) }

fn mtime(j: &Json) -> Result<(i64, u32)> {
    let a = array(j)?;
    ensure!(a.len() == 2, "mtime must be [seconds, nanoseconds]");
    Ok((i64::try_from(int_of(&a[0])?).ok().context("mtime out of range")?, uint(&a[1])?))
}

fn meta(o: &BTreeMap<String, Json>) -> Result<Meta> {
    let pairs = array(&o["xattrs"])?;
    ensure!(pairs.len() <= MAX_USER_XATTRS, "more than {MAX_USER_XATTRS} user xattrs");
    let mut xattrs = Xattrs::new();
    for pair in pairs {
        let p = array(pair)?;
        ensure!(p.len() == 2, "xattr must be [name, value]");
        xattrs.push(&bytes(&p[0])?, &bytes(&p[1])?);
    }
    xattrs.buf.shrink_to_fit();
    Ok(Meta { mode: uint(&o["mode"])?, uid: uint(&o["uid"])?, gid: uint(&o["gid"])?, mtime: mtime(&o["mtime"])?, xattrs })
}

fn entry(j: &Json) -> Result<Entry> {
    let Json::Obj(o) = j else { bail!("entry is not an object") };
    let ty = string(o.get("type").context("entry without type")?)?;
    let meta_keys = ["gid", "mode", "mtime", "path", "type", "uid", "xattrs"];
    let with = |extra: &[&'static str]| -> Vec<&'static str> {
        let mut k = meta_keys.to_vec(); k.extend_from_slice(extra); k
    };
    let body = match ty {
        "dir" => { let o = object(j, &with(&["opaque"]))?;
            let Json::Bool(opaque) = o["opaque"] else { bail!("opaque is not a boolean") };
            Body::Dir { meta: meta(o)?, opaque } }
        "file" => { let o = object(j, &with(&["object", "sha256", "size"]))?;
            Body::File { meta: meta(o)?, size: uint(&o["size"])?, sha256: super::hex32(string(&o["sha256"])?)?,
                object: uint(&o["object"])? } }
        "symlink" => { let o = object(j, &["gid", "mtime", "path", "target", "type", "uid"])?;
            Body::Symlink { uid: uint(&o["uid"])?, gid: uint(&o["gid"])?, mtime: mtime(&o["mtime"])?,
                target: bytes(&o["target"])? } }
        "hardlink" => { let o = object(j, &["link", "path", "type"])?; Body::HardLink { link: uint(&o["link"])? } }
        "whiteout" => { object(j, &["path", "type"])?; Body::Whiteout }
        _ => bail!("unknown entry type"),
    };
    Ok(Entry { path: bytes(&o["path"])?, body })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn meta(mode: u32, xattrs: Vec<(Vec<u8>, Vec<u8>)>) -> Meta {
        Meta { mode, uid: 0, gid: 0, mtime: (1_700_000_000, 5), xattrs: Xattrs::from_pairs(xattrs) }
    }

    /// A small manifest with every entry type, used by the golden and by the
    /// independent Python encoder (reviews).
    pub fn golden() -> Manifest {
        let file = |path: &[u8], data: &[u8], object, mode| Entry { path: path.to_vec(), body: Body::File {
            meta: Meta { mode, uid: 1000, gid: 1000, mtime: (1_700_000_001, 999_999_999), xattrs: Xattrs::new() },
            size: data.len() as u64, sha256: Sha256::digest(data), object } };
        Manifest {
            image_sha256: "ab".repeat(32),
            read_only_root: true,
            writable_paths: vec!["/data".into()],
            excluded_paths: protected::excluded_paths(&[protected::RESOLV_CONF]),
            root: meta(0o755, vec![]),
            entries: vec![
                Entry { path: b"etc".to_vec(), body: Body::Dir { meta: meta(0o755, vec![]), opaque: false } },
                Entry { path: b"etc/motd".to_vec(), body: Body::Whiteout },
                Entry { path: b"tmp".to_vec(), body: Body::Dir { meta: meta(0o1777, vec![]), opaque: false } },
                Entry { path: b"workspace".to_vec(), body: Body::Dir { meta: meta(0o755,
                    vec![(b"user.k".to_vec(), b"\x00v".to_vec())]), opaque: true } },
                file(b"workspace/a", b"hello\n", 0, 0o4755),
                Entry { path: b"workspace/b".to_vec(), body: Body::HardLink { link: 4 } },
                file(b"workspace/c\xff", b"", 1, 0o600),
                Entry { path: b"workspace/l".to_vec(), body: Body::Symlink { uid: 0, gid: 0, mtime: (-1, 0),
                    target: b"../a".to_vec() } },
            ],
        }
    }

    #[test]
    fn golden_manifest_bytes_and_digest() {
        let m = golden();
        let bytes = m.encode();
        // Pinned against an independent Python encoder (docs/checkpoint-format-v1.md).
        assert_eq!(hex(&Sha256::digest(&bytes)), GOLDEN_BYTES_SHA256, "{}", String::from_utf8_lossy(&bytes));
        assert_eq!(hex(&content_sha256(&bytes)), GOLDEN_CONTENT_SHA256);
        let (back, stats) = Manifest::decode(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(stats, Stats { entries: 9, objects: 2, logical: 6, logical_blocks: 4096 });
        assert_eq!(m.generated().unwrap(), [protected::RESOLV_CONF]);
    }

    pub const GOLDEN_BYTES_SHA256: &str = "40f75cb126dc570bdddaf7f3c581fafa1e5df0373512a94a80f0e1de24736272";
    pub const GOLDEN_CONTENT_SHA256: &str = "a4a64bb84cfc3abc7a7604ebcafccea446513ab0f2265036c677eda37c8ed3ba";

    fn refused(m: &Manifest) -> (Reason, String) {
        let e = Manifest::decode(&m.encode()).unwrap_err();
        (super::super::reason_of(&e), format!("{e:#}"))
    }

    #[test]
    fn hostile_structure_is_refused() {
        let base = golden();
        let edit = |f: &dyn Fn(&mut Manifest)| { let mut m = base.clone(); f(&mut m); refused(&m) };
        let corrupt = |f: &dyn Fn(&mut Manifest), want: &str| {
            let (reason, text) = edit(f);
            assert_eq!(reason, Reason::Corrupt, "{text}");
            assert!(text.contains(want), "{want}: {text}");
        };
        corrupt(&|m| m.entries.swap(0, 2), "out of order");
        corrupt(&|m| { let e = m.entries[2].clone(); m.entries.insert(2, e); }, "out of order or duplicate");
        corrupt(&|m| m.entries.remove(0).path.clear(), "parent is not a directory");
        corrupt(&|m| m.entries[1].path = b"etc/../x".to_vec(), "invalid path component");
        corrupt(&|m| m.entries[1].path = b"etc//x".to_vec(), "invalid path component");
        corrupt(&|m| m.entries[1].path = b"/etc/x".to_vec(), "invalid path component");
        corrupt(&|m| m.entries[1].path = b"etc/x\0".to_vec(), "invalid path component");
        corrupt(&|m| m.entries[1].path = vec![b'a'; 256], "invalid path component");
        // Nothing may live beneath a symlink, file or whiteout.
        corrupt(&|m| m.entries.push(Entry { path: b"workspace/l/x".to_vec(), body: Body::Whiteout }), "parent");
        corrupt(&|m| m.entries.insert(5, Entry { path: b"workspace/a/x".to_vec(), body: Body::Whiteout }), "parent");
        corrupt(&|m| m.entries[5].body = Body::HardLink { link: 5 }, "hardlink");
        corrupt(&|m| m.entries[5].body = Body::HardLink { link: 0 }, "hardlink");
        corrupt(&|m| m.entries[5].body = Body::HardLink { link: 7 }, "hardlink");
        corrupt(&|m| if let Body::File { object, .. } = &mut m.entries[6].body { *object = 5 }, "object numbers");
        corrupt(&|m| if let Body::File { meta, .. } = &mut m.entries[4].body { meta.uid = 65536 }, "invalid metadata");
        corrupt(&|m| if let Body::File { meta, .. } = &mut m.entries[4].body { meta.mode = 0o10644 }, "invalid metadata");
        corrupt(&|m| if let Body::Dir { meta, .. } = &mut m.entries[3].body {
            meta.xattrs = Xattrs::from_pairs(vec![(b"user.overlay.x".to_vec(), vec![])]) }, "user namespace");
        corrupt(&|m| if let Body::Dir { meta, .. } = &mut m.entries[3].body {
            meta.xattrs = Xattrs::from_pairs(vec![(b"trusted.overlay.opaque".to_vec(), b"y".to_vec())]) }, "user namespace");
        corrupt(&|m| if let Body::Dir { meta, .. } = &mut m.entries[3].body {
            meta.xattrs = Xattrs::from_pairs(vec![(b"user.a".to_vec(), vec![0u8; 4091])]) }, "4096 bytes");
        corrupt(&|m| if let Body::Dir { meta, .. } = &mut m.entries[3].body {
            meta.xattrs = Xattrs::from_pairs((0..33u8).map(|i| (format!("user.{i:02}").into_bytes(), vec![])).collect::<Vec<(Vec<u8>, Vec<u8>)>>()) }, "32 user");
        corrupt(&|m| if let Body::Dir { meta, .. } = &mut m.entries[3].body {
            meta.xattrs = Xattrs::from_pairs(vec![(b"user.b".to_vec(), vec![]), (b"user.a".to_vec(), vec![])]) }, "sorted");
        corrupt(&|m| if let Body::Symlink { target, .. } = &mut m.entries[7].body { *target = vec![b'a'; 1024] }, "target");
        corrupt(&|m| if let Body::Symlink { target, .. } = &mut m.entries[7].body { target.clear() }, "target");
        corrupt(&|m| m.writable_paths = vec!["/z".into(), "/a".into()], "sorted");
        corrupt(&|m| m.writable_paths = vec!["relative".into()], "writable");
        corrupt(&|m| { m.read_only_root = false; }, "without read-only");
        corrupt(&|m| m.excluded_paths.pop().map(|_| ()).unwrap(), "excluded path");
        // An excluded runtime entry may not be smuggled back in.
        corrupt(&|m| m.entries.insert(2, Entry { path: b"etc/resolv.conf".to_vec(), body: Body::Whiteout }),
            "excluded runtime entry");
        // Protected paths are layout refusals.
        for (at, path, body) in [(0, &b"dev"[..], Body::Whiteout),
            (0, b"dev", Body::Dir { meta: meta(0o755, vec![]), opaque: true }),
            (2, b"proc", Body::Symlink { uid: 0, gid: 0, mtime: (0, 0), target: b"/".to_vec() })] {
            let (reason, text) = edit(&|m| m.entries.insert(at, Entry { path: path.to_vec(), body: body.clone() }));
            assert_eq!(reason, Reason::LayoutUnsupported, "{text}");
        }
    }

    #[test]
    fn hostile_bytes_are_refused() {
        let bytes = golden().encode();
        let text = String::from_utf8(bytes.clone()).unwrap();
        for bad in [text.replace("\"format\":1", "\"format\":2"), text.replace("persistent_overlay", "other"),
            text.replace("\"type\":\"whiteout\"", "\"type\":\"chardev\""),
            text.replace("\"type\":\"whiteout\"", "\"type\":\"whiteout\",\"rdev\":1"),
            text.replace("trusted.overlay.uuid", "trusted.overlay.upper"), text.replace("{\"entries\"", "{ \"entries\""),
            format!("{text}\n"), text.replace("\"read_only_root\":true", "\"read_only_root\":1"),
            text.replacen("\"mtime\":[1700000000,5]", "\"mtime\":[1700000000,1000000000]", 1),
            text.replacen("\"path\":\"ZXRj\"", "\"path\":\"ZXRj=\"", 1),
            // Entry-at-a-time decoding still requires one canonical document.
            text.replacen("},{", "}, {", 1), text.replacen("}],\"excluded_paths\"", "},],\"excluded_paths\"", 1),
            text.replacen("\"scope\"", "\"extra\":1,\"scope\"", 1), text.replacen("{\"entries\":[", "{\"entries\": [", 1),
            text.replacen("\"writable_paths\":[\"/data\"]}", "\"writable_paths\":[\"/data\"]}}", 1),
            text.replacen("\"type\":\"dir\",\"uid\":0", "\"uid\":0,\"type\":\"dir\"", 1)] {
            assert_ne!(bad, text);
            let e = Manifest::decode(bad.as_bytes()).unwrap_err();
            assert_eq!(super::super::reason_of(&e), Reason::Corrupt, "{bad}: {e:#}");
        }
        assert!(Manifest::decode(&vec![b' '; MAX_MANIFEST_BYTES + 1]).is_err());
        // A tail far larger than any canonical one is refused before parsing.
        let huge = format!("{}{}", &text[..text.len() - 1], ",\"z\":\"".to_owned() + &"a".repeat(600 * 1024) + "\"}");
        assert!(Manifest::decode(huge.as_bytes()).is_err());
    }
}
