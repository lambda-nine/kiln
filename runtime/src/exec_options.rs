//! Exec options for typed operation 5: a working directory and environment
//! overrides for one command. The frame is produced by the machine caller,
//! passed to the CLI in a sealed memfd, copied uninterpreted into operation 5
//! and validated again by PID 1. Values are sandbox-interior data: they never
//! appear in `Debug` output or in diagnostics, which name entries by index.
//! See docs/exec-protocol-v1.md, "Exec options".
use std::ffi::CString;
use std::fmt;

use anyhow::{Result, bail, ensure};

pub const MAGIC: &[u8; 8] = b"KILNOPT\0";
pub const VERSION: u16 = 1;
pub const HEADER: usize = 24;
/// The largest frame the CLI reads and PID 1 accepts. Every frame within the
/// field bounds below is smaller (at most 37,272 bytes).
pub const MAX_FRAME: usize = 40 * 1024;
pub const MAX_CWD: usize = 4096;
pub const MAX_ENV: usize = 64;
pub const MAX_NAME: usize = 128;
pub const MAX_VALUE: usize = 4096;
/// Bound on the sum of `len(name) + len(value) + 2` over all entries.
pub const MAX_ENV_BYTES: usize = 32 * 1024;
/// The seals the CLI requires on the caller's memfd, exactly: no writes,
/// no size change and no further seal changes (so no F_SEAL_FUTURE_WRITE or
/// F_SEAL_EXEC either).
pub const REQUIRED_SEALS: i32 = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
/// The environment every command under kilnd already gets from PID 1, in
/// name order. Operation 5 starts from these fixed values, not from PID 1's
/// own environment, so a frame means the same thing in every sandbox.
pub const BASE_ENV: [(&str, &str); 3] = [
    ("HOME", "/root"),
    ("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    ("TERM", "xterm"),
];

/// Validated options. `env` is strictly ascending by name bytes, so a valid
/// frame has exactly one encoding and duplicate names cannot occur.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecOptions {
    cwd: Option<String>,
    env: Vec<(String, String)>,
}

impl fmt::Debug for ExecOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.env.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("ExecOptions").field("cwd", &self.cwd)
            .field("env_names", &names).field("env_values", &"<redacted>").finish()
    }
}

impl ExecOptions {
    /// Validates caller-supplied options. Entries may come in any order;
    /// duplicate names are rejected, not resolved. The machine caller (the
    /// kilnd helper) has its own encoder; this one pins the goldens.
    #[cfg(test)]
    pub fn new(cwd: Option<String>, mut env: Vec<(String, String)>) -> Result<Self> {
        env.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let options = Self { cwd, env };
        options.validate()?;
        Ok(options)
    }

    fn validate(&self) -> Result<()> {
        if let Some(cwd) = &self.cwd { validate_cwd(cwd.as_bytes())?; }
        ensure!(self.env.len() <= MAX_ENV, "exec options have more than {MAX_ENV} environment entries");
        let mut total = 0usize;
        for (i, (name, value)) in self.env.iter().enumerate() {
            validate_name(i, name.as_bytes())?;
            validate_value(i, value.as_bytes())?;
            if i > 0 {
                let previous = self.env[i - 1].0.as_bytes();
                ensure!(previous != name.as_bytes(), "exec options environment entry {i} repeats a name");
                ensure!(previous < name.as_bytes(), "exec options environment entry {i} is out of name order");
            }
            total += name.len() + value.len() + 2;
        }
        ensure!(total <= MAX_ENV_BYTES, "exec options environment exceeds {MAX_ENV_BYTES} bytes");
        Ok(())
    }

    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        let cwd = self.cwd.as_deref().unwrap_or("");
        let mut frame = Vec::with_capacity(HEADER + cwd.len()
            + self.env.iter().map(|(n, v)| 8 + n.len() + v.len()).sum::<usize>());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&VERSION.to_le_bytes());
        frame.extend_from_slice(&[0; 2]);
        frame.extend_from_slice(&[0; 4]); // Frame length, filled in below.
        frame.extend_from_slice(&(cwd.len() as u32).to_le_bytes());
        frame.extend_from_slice(&(self.env.len() as u32).to_le_bytes());
        frame.extend_from_slice(cwd.as_bytes());
        for (name, value) in &self.env {
            frame.extend_from_slice(&(name.len() as u32).to_le_bytes());
            frame.extend_from_slice(name.as_bytes());
            frame.extend_from_slice(&(value.len() as u32).to_le_bytes());
            frame.extend_from_slice(value.as_bytes());
        }
        let len = frame.len() as u32;
        frame[12..16].copy_from_slice(&len.to_le_bytes());
        frame
    }

    /// Decodes exactly one complete frame. Every length is checked against
    /// the bytes present before it is used, and trailing bytes are invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= HEADER, "truncated exec options header");
        ensure!(bytes.len() <= MAX_FRAME, "exec options exceed {MAX_FRAME} bytes");
        ensure!(&bytes[..8] == MAGIC, "malformed exec options magic");
        ensure!(u16::from_le_bytes([bytes[8], bytes[9]]) == VERSION, "unsupported exec options version");
        ensure!(bytes[10..12] == [0; 2], "exec options reserved bytes must be zero");
        ensure!(le32(bytes, 12) as usize == bytes.len(), "exec options length does not match the frame");
        let cwd_len = le32(bytes, 16) as usize;
        let count = le32(bytes, 20) as usize;
        ensure!(cwd_len <= MAX_CWD, "exec options cwd exceeds {MAX_CWD} bytes");
        ensure!(count <= MAX_ENV, "exec options have more than {MAX_ENV} environment entries");
        let mut at = HEADER;
        let cwd = match take(bytes, &mut at, cwd_len)? {
            [] => None,
            cwd => {
                validate_cwd(cwd)?;
                Some(String::from_utf8(cwd.to_vec())?)
            }
        };
        let mut env = Vec::with_capacity(count);
        for i in 0..count {
            let n = take_len(bytes, &mut at)?;
            ensure!(n <= MAX_NAME, "exec options environment name {i} exceeds {MAX_NAME} bytes");
            let name = take(bytes, &mut at, n)?;
            validate_name(i, name)?;
            let n = take_len(bytes, &mut at)?;
            ensure!(n <= MAX_VALUE, "exec options environment value {i} exceeds {MAX_VALUE} bytes");
            let value = take(bytes, &mut at, n)?;
            validate_value(i, value)?;
            env.push((String::from_utf8(name.to_vec())?, String::from_utf8(value.to_vec())?));
        }
        ensure!(at == bytes.len(), "trailing exec options data");
        let options = Self { cwd, env };
        options.validate()?;
        Ok(options)
    }

    pub fn cwd_c(&self) -> Option<CString> {
        // Validation excluded NUL bytes.
        self.cwd.as_deref().map(|cwd| CString::new(cwd).unwrap())
    }

    /// `BASE_ENV` overlaid by the overrides (an override wins by name,
    /// `PATH` included), as `NAME=VALUE` strings sorted by name bytes.
    pub fn envp(&self) -> Vec<CString> {
        let mut merged: Vec<(&str, &str)> = BASE_ENV.to_vec();
        for (name, value) in &self.env {
            match merged.binary_search_by(|(n, _)| n.as_bytes().cmp(name.as_bytes())) {
                Ok(at) => merged[at].1 = value,
                Err(at) => merged.insert(at, (name, value)),
            }
        }
        merged.into_iter().map(|(name, value)| CString::new(format!("{name}={value}")).unwrap()).collect()
    }
}

/// What PID 1's forked child needs to apply the options, built before fork
/// so the child only calls `chdir` and swaps a pointer.
pub struct LaunchOptions {
    pub cwd: Option<CString>,
    envp: Vec<CString>,
    pointers: Vec<*const libc::c_char>,
}

impl LaunchOptions {
    pub fn new(options: &ExecOptions) -> Self {
        let envp = options.envp();
        let pointers = envp.iter().map(|entry| entry.as_ptr()).chain([std::ptr::null()]).collect();
        Self { cwd: options.cwd_c(), envp, pointers }
    }

    /// NULL-terminated `NAME=VALUE` pointers into `envp`.
    pub fn environ(&self) -> *const *const libc::c_char {
        debug_assert_eq!(self.pointers.len(), self.envp.len() + 1);
        self.pointers.as_ptr()
    }

    #[cfg(test)]
    pub fn entries(&self) -> Vec<&std::ffi::CStr> { self.envp.iter().map(CString::as_c_str).collect() }
}

fn validate_cwd(cwd: &[u8]) -> Result<()> {
    ensure!(cwd.first() == Some(&b'/'), "exec options cwd must start with /");
    ensure!(cwd.len() <= MAX_CWD, "exec options cwd exceeds {MAX_CWD} bytes");
    ensure!(!cwd.contains(&0), "exec options cwd contains NUL");
    ensure!(std::str::from_utf8(cwd).is_ok(), "exec options cwd is not UTF-8");
    Ok(())
}

fn validate_name(i: usize, name: &[u8]) -> Result<()> {
    ensure!(!name.is_empty() && name.len() <= MAX_NAME, "exec options environment name {i} must be 1 to {MAX_NAME} bytes");
    let valid = (name[0].is_ascii_alphabetic() || name[0] == b'_')
        && name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'_');
    if !valid { bail!("exec options environment name {i} must match [A-Za-z_][A-Za-z0-9_]*"); }
    Ok(())
}

fn validate_value(i: usize, value: &[u8]) -> Result<()> {
    ensure!(value.len() <= MAX_VALUE, "exec options environment value {i} exceeds {MAX_VALUE} bytes");
    ensure!(!value.contains(&0), "exec options environment value {i} contains NUL");
    ensure!(std::str::from_utf8(value).is_ok(), "exec options environment value {i} is not UTF-8");
    Ok(())
}

fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn take_len(bytes: &[u8], at: &mut usize) -> Result<usize> {
    let n = take(bytes, at, 4)?;
    Ok(u32::from_le_bytes(n.try_into().unwrap()) as usize)
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8]> {
    let Some(part) = at.checked_add(n).and_then(|end| bytes.get(*at..end)) else {
        bail!("truncated exec options");
    };
    *at += n;
    Ok(part)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

    fn strs(envp: &[CString]) -> Vec<&std::ffi::CStr> { envp.iter().map(CString::as_c_str).collect() }

    /// The goldens in docs/exec-protocol-v1.md.
    #[test]
    fn golden_frames() {
        let empty = ExecOptions::new(None, Vec::new()).unwrap().encode();
        assert_eq!(hex(&empty), concat!("4b494c4e4f505400", "0100", "0000", "18000000", "00000000", "00000000"));
        let options = ExecOptions::new(Some("/w".into()), env(&[("B", "2"), ("A", "")])).unwrap();
        let bytes = options.encode();
        assert_eq!(hex(&bytes), concat!("4b494c4e4f505400", "0100", "0000", "2d000000", "02000000",
            "02000000", "2f77", "01000000", "41", "00000000", "01000000", "42", "01000000", "32"));
        assert_eq!(bytes.len(), 45);
        assert_eq!(ExecOptions::decode(&bytes).unwrap(), options);
        assert_eq!(ExecOptions::decode(&empty).unwrap(), ExecOptions::new(None, Vec::new()).unwrap());
    }

    #[test]
    fn every_bound_and_one_past_it() {
        let cwd = |n: usize| Some(format!("/{}", "a".repeat(n - 1)));
        ExecOptions::new(cwd(MAX_CWD), Vec::new()).unwrap();
        assert!(ExecOptions::new(cwd(MAX_CWD + 1), Vec::new()).is_err());
        ExecOptions::new(Some("/".into()), Vec::new()).unwrap();
        for bad in ["", "relative", "a/b", "/a\0b", "./x"] {
            assert!(ExecOptions::new(Some(bad.into()), Vec::new()).is_err(), "{bad:?}");
        }
        // `..` and symlinks are not normalized: they resolve inside the sandbox.
        ExecOptions::new(Some("/a/../b/./c//d".into()), Vec::new()).unwrap();

        let many = |n: usize| (0..n).map(|i| (format!("V{i:03}"), String::new())).collect::<Vec<_>>();
        ExecOptions::new(None, many(MAX_ENV)).unwrap();
        assert!(ExecOptions::new(None, many(MAX_ENV + 1)).is_err());

        let name = |n: usize| format!("N{}", "_".repeat(n - 1));
        ExecOptions::new(None, vec![(name(MAX_NAME), "v".into())]).unwrap();
        assert!(ExecOptions::new(None, vec![(name(MAX_NAME + 1), "v".into())]).is_err());
        ExecOptions::new(None, vec![("V".into(), "x".repeat(MAX_VALUE))]).unwrap();
        assert!(ExecOptions::new(None, vec![("V".into(), "x".repeat(MAX_VALUE + 1))]).is_err());

        // Eight entries of 4,094 + 2 bytes are exactly 32,768 bytes.
        let total = |last: usize| (0..8).map(|i| (format!("V{i}"),
            "x".repeat(if i == 7 { last } else { 4092 }))).collect::<Vec<_>>();
        let exact = total(4092);
        assert_eq!(exact.iter().map(|(n, v)| n.len() + v.len() + 2).sum::<usize>(), MAX_ENV_BYTES);
        let frame = ExecOptions::new(None, exact).unwrap().encode();
        ExecOptions::decode(&frame).unwrap();
        assert!(ExecOptions::new(None, total(4093)).is_err());

        // The largest frame within every bound still fits under MAX_FRAME.
        let mut largest: Vec<_> = (0..MAX_ENV).map(|i| (format!("V{i:02}"), String::new())).collect();
        let mut room = MAX_ENV_BYTES - largest.iter().map(|(n, _)| n.len() + 2).sum::<usize>();
        for (_, value) in &mut largest {
            let n = room.min(MAX_VALUE);
            *value = "x".repeat(n);
            room -= n;
        }
        let frame = ExecOptions::new(cwd(MAX_CWD), largest).unwrap().encode();
        assert!(frame.len() <= 37_272 && frame.len() < MAX_FRAME, "{}", frame.len());
        ExecOptions::decode(&frame).unwrap();
    }

    #[test]
    fn names_values_and_duplicates() {
        for good in ["_", "A", "a_1", "_9", "PATH"] {
            ExecOptions::new(None, env(&[(good, "v")])).unwrap();
        }
        for bad in ["", "1A", "A-B", "A=B", "A B", "é", "A\0"] {
            assert!(ExecOptions::new(None, env(&[(bad, "v")])).is_err(), "{bad:?}");
        }
        ExecOptions::new(None, env(&[("V", "雪\n=;$(x) ")])).unwrap();
        ExecOptions::new(None, env(&[("V", "")])).unwrap();
        assert!(ExecOptions::new(None, env(&[("V", "a\0b")])).is_err());
        let error = ExecOptions::new(None, env(&[("A", "1"), ("A", "1")])).unwrap_err().to_string();
        assert!(error.contains("repeats"), "{error}");
        assert!(ExecOptions::new(None, env(&[("PATH", "/x"), ("PATH", "/y")])).is_err());
        // Names are case-sensitive and distinct.
        ExecOptions::new(None, env(&[("a", "1"), ("A", "2")])).unwrap();
    }

    #[test]
    fn decode_is_strict() {
        let bytes = ExecOptions::new(Some("/w".into()), env(&[("A", "1"), ("B", "2")])).unwrap().encode();
        for end in 0..bytes.len() { assert!(ExecOptions::decode(&bytes[..end]).is_err(), "{end}"); }
        let mut trailing = bytes.clone(); trailing.push(0);
        assert!(ExecOptions::decode(&trailing).is_err());
        let mut trailing_counted = trailing.clone();
        let len = trailing_counted.len() as u32;
        trailing_counted[12..16].copy_from_slice(&len.to_le_bytes());
        assert!(ExecOptions::decode(&trailing_counted).is_err());
        for (at, value) in [(0, b'X'), (7, 1), (8, 2), (9, 1), (10, 1), (11, 1), (12, 0), (16, 3),
            (20, 3), (20, 1), (24, b'w'), (26, 2), (30, b'1'), (31, 0), (36, 0), (40, b'A')] {
            let mut bad = bytes.clone(); bad[at] = value;
            assert!(ExecOptions::decode(&bad).is_err(), "offset {at}");
        }
        // Out-of-order and duplicate entries are rejected; a frame has one encoding.
        let mut swapped = bytes.clone();
        swapped[30] = b'B'; swapped[40] = b'A';
        assert!(ExecOptions::decode(&swapped).unwrap_err().to_string().contains("order"));
        let mut duplicate = bytes.clone(); duplicate[40] = b'A';
        assert!(ExecOptions::decode(&duplicate).unwrap_err().to_string().contains("repeats"));
        // Invalid UTF-8 in a value.
        let mut invalid = bytes.clone(); invalid[35] = 0xff;
        assert!(ExecOptions::decode(&invalid).is_err());
        // Oversized lengths fail before any allocation or read past the end.
        let mut huge = bytes.clone(); huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(ExecOptions::decode(&huge).is_err());
        let mut huge = bytes; huge[26..30].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(ExecOptions::decode(&huge).is_err());
        assert!(ExecOptions::decode(&vec![0; MAX_FRAME + 1]).is_err());
    }

    #[test]
    fn environment_is_base_overlaid_and_sorted_by_name_bytes() {
        let none = ExecOptions::new(None, Vec::new()).unwrap();
        assert_eq!(strs(&none.envp()), [c"HOME=/root",
            c"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", c"TERM=xterm"]);
        let options = ExecOptions::new(None, env(&[("PATH", "/opt/bin"), ("A0", "x"), ("A", ""),
            ("_", "u"), ("a", "l"), ("TERM", "dumb"), ("Z", "z")])).unwrap();
        // "A" sorts before "A0" by name even though "A=" sorts after "A0=".
        assert_eq!(strs(&options.envp()), [c"A=", c"A0=x", c"HOME=/root", c"PATH=/opt/bin", c"TERM=dumb",
            c"Z=z", c"_=u", c"a=l"]);
        let launch = LaunchOptions::new(&options);
        assert_eq!(launch.entries(), strs(&options.envp()));
        let pointers = unsafe { std::slice::from_raw_parts(launch.environ(), 9) };
        assert!(pointers[8].is_null());
        assert_eq!(unsafe { std::ffi::CStr::from_ptr(pointers[3]) }, c"PATH=/opt/bin");
    }

    #[test]
    fn debug_and_errors_never_show_values() {
        let options = ExecOptions::new(Some("/w".into()), env(&[("TOKEN", "canary-value-7f3a")])).unwrap();
        let debug = format!("{options:?}");
        assert!(debug.contains("TOKEN") && debug.contains("/w") && !debug.contains("canary"), "{debug}");
        let mut bad = options.encode();
        let at = bad.len() - 1;
        bad[at] = 0;
        let error = format!("{:#}", ExecOptions::decode(&bad).unwrap_err());
        assert!(!error.contains("canary"), "{error}");
        let error = format!("{:#}", ExecOptions::new(None, env(&[("1canary", "canary-value")])).unwrap_err());
        assert!(!error.contains("canary"), "{error}");
    }
}
