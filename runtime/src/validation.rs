//! Validation shared by kiln's CLI, setup and persistent protocol boundary.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Result, bail};

/// Shared by literal/resolution validation and the packet-time nft guard.
pub const PRIVATE_RANGES: &str = "10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16";

pub fn overlaps_private(address: Ipv4Addr, prefix: u8) -> bool {
    PRIVATE_RANGES.split(", ").any(|range| {
        let (network, bits) = range.split_once('/').unwrap();
        let shared = prefix.min(bits.parse::<u8>().unwrap());
        let mask = if shared == 0 { 0 } else { u32::MAX << (32 - shared) };
        u32::from(address) & mask == u32::from(network.parse::<Ipv4Addr>().unwrap()) & mask
    })
}

pub const MAX_ALLOWLIST_ENTRY_BYTES: usize = 260;
pub const MAX_ALLOWLIST_ENTRIES: usize = 64;
pub const MAX_ARGC: usize = 4096;
pub const MAX_EXEC_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_IMAGE_BYTES: usize = 128;
pub const MAX_WRITABLE_PATHS: usize = 16;
pub const MAX_WRITABLE_PATH_BYTES: usize = 1024;

#[derive(Debug)]
pub struct AllowlistEntry<'a> {
    pub destination: &'a str,
    pub port: Option<u16>,
    pub ipv4_literal: bool,
}

pub fn validate_image_name(image: &str) -> Result<()> {
    if image.is_empty()
        || image.len() > MAX_IMAGE_BYTES
        || image.starts_with(['.', '-'])
        || !image
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
    {
        bail!("invalid image name {image:?}");
    }
    Ok(())
}

/// Parses `HOST[:PORT]` or `IPv4[/PREFIX][:PORT]` without resolving it.
pub fn parse_allowlist_entry(entry: &str) -> Result<AllowlistEntry<'_>> {
    if entry.is_empty() || entry.len() > MAX_ALLOWLIST_ENTRY_BYTES {
        bail!("invalid --allow destination {entry:?}");
    }
    let (destination, port) = match entry.rsplit_once(':') {
        Some((destination, port)) if !destination.contains(':') => {
            let port = (!port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
                .then(|| port.parse::<u16>().ok())
                .flatten()
                .filter(|port| *port != 0)
                .ok_or_else(|| anyhow::anyhow!("invalid port in --allow {entry:?}"))?;
            (destination, Some(port))
        }
        Some(_) => bail!("invalid --allow destination {entry:?}"),
        None => (entry, None),
    };
    if destination.is_empty() {
        bail!("invalid --allow destination {entry:?}");
    }
    let ipv4_literal = if let Some((address, prefix)) = destination.split_once('/') {
        if address.is_empty()
            || prefix.is_empty()
            || prefix.contains('/')
            || !prefix.bytes().all(|byte| byte.is_ascii_digit())
            || address.parse::<Ipv4Addr>().is_err()
            || prefix.parse::<u8>().ok().filter(|prefix| *prefix <= 32).is_none()
        {
            bail!("invalid --allow destination {entry:?}");
        }
        true
    } else if destination.parse::<Ipv4Addr>().is_ok() {
        true
    } else {
        if destination.len() > 253 || destination.starts_with('.') || destination.ends_with('.') {
            bail!("invalid --allow destination {entry:?}");
        }
        for label in destination.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 63
                || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
            {
                bail!("invalid --allow destination {entry:?}");
            }
        }
        false
    };
    if ipv4_literal {
        let (address, prefix) = destination.split_once('/').unwrap_or((destination, "32"));
        if overlaps_private(address.parse()?, prefix.parse()?) {
            bail!("--allow {entry:?} overlaps private or link-local ranges (including metadata)");
        }
    }
    Ok(AllowlistEntry {
        destination,
        port,
        ipv4_literal,
    })
}

pub fn validate_writable_paths(paths: &[PathBuf]) -> Result<()> {
    if paths.len() > MAX_WRITABLE_PATHS {
        bail!("at most {MAX_WRITABLE_PATHS} --writable paths are allowed");
    }
    for path in paths {
        let Some(path) = path.to_str() else {
            bail!("--writable paths must be valid UTF-8");
        };
        if path.len() > MAX_WRITABLE_PATH_BYTES
            || path == "/"
            || !path.starts_with('/')
            || path.chars().any(char::is_control)
            || path[1..]
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            bail!("invalid --writable path {path:?}");
        }
    }
    Ok(())
}

/// Returns the encoded persistent request size after validating literal argv.
pub fn validate_exec_argv(argv: &[String]) -> Result<usize> {
    if argv.is_empty() || argv.len() > MAX_ARGC {
        bail!("invalid argument count (expected 1 to {MAX_ARGC})");
    }
    if argv[0].is_empty() {
        bail!("argv must name a program");
    }
    let mut size = 4usize;
    for arg in argv {
        if arg.as_bytes().contains(&0) {
            bail!("argument contains NUL");
        }
        size = size
            .checked_add(4)
            .and_then(|size| size.checked_add(arg.len()))
            .ok_or_else(|| anyhow::anyhow!("command size overflow"))?;
        if size > MAX_EXEC_REQUEST_BYTES {
            bail!("command is too large");
        }
    }
    Ok(size)
}

pub fn valid_persistent_id(id: &str) -> bool {
    let Some((time, pid)) = id.split_once('-') else {
        return false;
    };
    !time.is_empty()
        && time.len() <= 32
        && time.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !pid.is_empty()
        && !pid.starts_with('0')
        && !pid.contains('-')
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && pid.parse::<u32>().is_ok_and(|pid| pid != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_allowlist_and_path_contract_matches_the_api_boundary() {
        for image in ["alpine", "agent_3.20-x"] {
            validate_image_name(image).unwrap();
        }
        for image in ["", ".hidden", "-flag", "../etc", "snow-雪", "a/b"] {
            assert!(validate_image_name(image).is_err(), "{image:?}");
        }
        for entry in ["example.com", "sub-domain.example:443", "1.1.1.1", "8.8.8.0/24:53"] {
            parse_allowlist_entry(entry).unwrap();
        }
        for entry in [
            "",
            "/",
            "-flag",
            "bad..example",
            "example.com:0",
            "example.com:+80",
            "10.0.0.1/33",
            "10.0.0.1/+8",
            "::1",
            "snow.雪",
        ] {
            assert!(parse_allowlist_entry(entry).is_err(), "{entry:?}");
        }
        let longest_host = format!("{}.{}.{}.{}", "a".repeat(63), "b".repeat(63), "c".repeat(63), "d".repeat(61));
        assert_eq!(longest_host.len(), 253);
        parse_allowlist_entry(&format!("{longest_host}:65535")).unwrap();
        assert!(parse_allowlist_entry(&format!("{longest_host}x")).is_err());
        assert!(parse_allowlist_entry(&format!("{}.example", "a".repeat(64))).is_err());
        validate_writable_paths(&[PathBuf::from("/workspace/雪")]).unwrap();
        validate_writable_paths(&vec![PathBuf::from("/data"); MAX_WRITABLE_PATHS]).unwrap();
        assert!(
            validate_writable_paths(&vec![PathBuf::from("/data"); MAX_WRITABLE_PATHS + 1])
                .is_err()
        );
        validate_writable_paths(&[PathBuf::from(format!(
            "/{}",
            "a".repeat(MAX_WRITABLE_PATH_BYTES - 1)
        ))])
        .unwrap();
        assert!(
            validate_writable_paths(&[PathBuf::from(format!(
                "/{}",
                "a".repeat(MAX_WRITABLE_PATH_BYTES)
            ))])
            .is_err()
        );
        for path in ["/", "data", "/a/../b", "/a/./b", "/a//b", "/a/", "/a\nb"] {
            assert!(validate_writable_paths(&[PathBuf::from(path)]).is_err(), "{path:?}");
        }
    }

    #[test]
    fn private_literals_and_overlapping_prefixes_are_rejected() {
        for value in ["169.254.169.254:80", "10.0.0.0/8", "127.0.0.1", "100.64.0.1",
            "172.16.0.0/12", "192.168.1.1:443", "0.0.0.0/0", "8.0.0.0/6"] {
            assert!(parse_allowlist_entry(value).unwrap_err().to_string().contains("private"), "{value}");
        }
        for value in ["8.8.8.8:53", "1.1.1.0/24", "11.0.0.0/8"] {
            assert!(parse_allowlist_entry(value).is_ok(), "{value}");
        }
    }

    #[test]
    fn exec_contract_preserves_unicode_controls_and_exact_boundaries() {
        validate_exec_argv(&["echo".into(), "雪\n-flag".into(), String::new()]).unwrap();
        assert!(validate_exec_argv(&[String::new()]).is_err());
        assert!(validate_exec_argv(&["echo".into(), "a\0b".into()]).is_err());
        assert!(validate_exec_argv(&vec!["x".into(); MAX_ARGC]).is_ok());
        assert!(validate_exec_argv(&vec!["x".into(); MAX_ARGC + 1]).is_err());
        let exact = vec!["x".repeat(MAX_EXEC_REQUEST_BYTES - 8)];
        assert_eq!(validate_exec_argv(&exact).unwrap(), MAX_EXEC_REQUEST_BYTES);
        assert!(validate_exec_argv(&["x".repeat(MAX_EXEC_REQUEST_BYTES - 7)]).is_err());
    }

    #[test]
    fn persistent_ids_have_one_lowercase_hex_time_and_decimal_pid() {
        assert!(valid_persistent_id("18de453339a8cc89-3762"));
        assert!(valid_persistent_id(&format!("{}-4294967295", "a".repeat(32))));
        assert!(!valid_persistent_id(&format!("{}-1", "a".repeat(33))));
        assert!(!valid_persistent_id("a-4294967296"));
        for id in ["", "-1", "ab-0", "AB-1", "ab--1", "ab-c", "ab-01", "../x"] {
            assert!(!valid_persistent_id(id), "{id:?}");
        }
    }
}
