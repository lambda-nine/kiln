//! Records which source the binary was built from, for `kiln --version`.
//!
//! Sets `KILN_GIT` to `git <12-char commit>, clean`, `git <commit>, dirty`
//! (the build inputs differ from that commit) or `git unknown` (no git, not a
//! checkout, or git failed). Builds outside a checkout, such as from a source
//! tarball, can set `KILN_BUILD_COMMIT` to the commit (`<hex>`, `<hex>-dirty`
//! or `unknown`) instead.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The build's inputs, relative to the package directory: the package itself
/// and the workspace manifest and lockfile. Changes elsewhere in the
/// repository (benchmarks, docs) don't change the binary, so they don't make
/// it dirty.
const INPUTS: &[&str] = &["src", "build.rs", "Cargo.toml", "../Cargo.toml", "../Cargo.lock"];

fn main() {
    println!("cargo:rerun-if-env-changed=KILN_BUILD_COMMIT");
    for path in INPUTS {
        println!("cargo:rerun-if-changed={path}");
    }
    let dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let git = match std::env::var("KILN_BUILD_COMMIT") {
        Ok(v) if !v.is_empty() => from_override(&v),
        _ => from_checkout(&dir).unwrap_or_else(|| "git unknown".into()),
    };
    println!("cargo:rustc-env=KILN_GIT={git}");
}

fn from_override(v: &str) -> String {
    if v == "unknown" {
        return "git unknown".into();
    }
    let (commit, state) = match v.strip_suffix("-dirty") {
        Some(c) => (c, "dirty"),
        None => (v, "clean"),
    };
    if commit.len() < 12 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        panic!("KILN_BUILD_COMMIT={v:?}: expected a commit hash of at least 12 hex digits, optionally ending in -dirty, or \"unknown\"");
    }
    format!("git {}, {state}", commit[..12].to_ascii_lowercase())
}

fn from_checkout(dir: &Path) -> Option<String> {
    // Rebuild when HEAD moves: a checkout or commit changes HEAD or the
    // branch it points at, and staging changes the index. --git-path
    // resolves each for linked worktrees too.
    let mut watch = vec!["HEAD".to_string(), "index".into(), "packed-refs".into()];
    if let Some(r) = git(dir, &["symbolic-ref", "-q", "HEAD"]) {
        watch.push(r);
    }
    for name in watch {
        if let Some(p) = git(dir, &["rev-parse", "--git-path", &name]) {
            let p = dir.join(p);
            // A missing path would make cargo rerun this on every build.
            if p.exists() {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
    }

    let commit = git(dir, &["rev-parse", "--verify", "HEAD"])?;
    if commit.len() < 12 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    // Tracked changes and untracked, non-ignored files among the inputs.
    let mut args = vec!["status", "--porcelain", "--untracked-files=all", "--"];
    args.extend(INPUTS);
    let status = git_output(dir, &args)?;
    if !status.status.success() {
        return None;
    }
    let state = if status.stdout.is_empty() { "clean" } else { "dirty" };
    Some(format!("git {}, {state}", &commit[..12]))
}

/// Runs git in `dir` and returns its trimmed stdout, or None if it failed
/// or printed nothing.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = git_output(dir, args)?;
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    (out.status.success() && !s.is_empty()).then_some(s)
}

fn git_output(dir: &Path, args: &[&str]) -> Option<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        // Don't refresh the index: that would rewrite .git/index, which this
        // script watches, and rerun it on every build.
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()
}
