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
            watch_path(dir.join(p));
        }
    }

    // Do not borrow provenance from an unrelated repository that merely
    // contains an unpacked kiln source tree in an ignored subdirectory.
    let expected_root = dir.parent()?.canonicalize().ok()?;
    let discovered_root = PathBuf::from(git(dir, &["rev-parse", "--show-toplevel"])?);
    if discovered_root.canonicalize().ok()? != expected_root {
        return None;
    }
    let identity = git_output(
        dir,
        &[
            "ls-files",
            "--error-unmatch",
            "--",
            "Cargo.toml",
            "build.rs",
            "src/main.rs",
            "../Cargo.toml",
            "../Cargo.lock",
        ],
    )?;
    if !identity.status.success() {
        return None;
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

/// Cargo does not reliably notice a file that did not exist when a build
/// script declared it. Watch the nearest existing ancestor instead, so a
/// packed branch becoming a new loose ref invalidates the cached version.
fn watch_path(path: PathBuf) {
    let Some(path) = nearest_existing_ancestor(path) else { return };
    println!("cargo:rerun-if-changed={}", path.display());
}

fn nearest_existing_ancestor(mut path: PathBuf) -> Option<PathBuf> {
    while !path.exists() {
        if !path.pop() {
            return None;
        }
    }
    Some(path)
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("kiln-build-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn git_ok(root: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(root)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }

    fn commit_all(root: &Path) {
        git_ok(root, &["add", "-A"]);
        git_ok(
            root,
            &[
                "-c",
                "user.name=Kiln Test",
                "-c",
                "user.email=kiln@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
        );
    }

    #[test]
    fn missing_ref_watches_existing_ancestor() {
        let root = scratch("watch");
        let existing = root.join("refs/heads");
        fs::create_dir_all(&existing).unwrap();
        let missing = existing.join("feature/release");
        let watched = nearest_existing_ancestor(missing).unwrap();
        assert_eq!(watched, existing);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn nested_source_does_not_borrow_outer_repository() {
        let outer = scratch("outer");
        git_ok(&outer, &["init", "-q"]);
        let source = outer.join("nested/kiln");
        fs::create_dir_all(source.join("runtime/src")).unwrap();
        for path in [
            source.join("Cargo.toml"),
            source.join("Cargo.lock"),
            source.join("runtime/Cargo.toml"),
            source.join("runtime/build.rs"),
            source.join("runtime/src/main.rs"),
        ] {
            fs::write(path, "tracked by the outer repository\n").unwrap();
        }
        commit_all(&outer);
        let runtime = source.join("runtime");
        assert_eq!(from_checkout(&runtime), None);
        fs::remove_dir_all(outer).unwrap();
    }

    #[test]
    fn untracked_source_does_not_borrow_matching_repository() {
        let root = scratch("untracked");
        git_ok(&root, &["init", "-q"]);
        fs::write(root.join("README.md"), "unrelated tracked content\n").unwrap();
        commit_all(&root);
        let runtime = root.join("runtime");
        fs::create_dir_all(runtime.join("src")).unwrap();
        for path in [
            root.join("Cargo.toml"),
            root.join("Cargo.lock"),
            runtime.join("Cargo.toml"),
            runtime.join("build.rs"),
            runtime.join("src/main.rs"),
        ] {
            fs::write(path, "untracked\n").unwrap();
        }
        assert_eq!(from_checkout(&runtime), None);
        fs::remove_dir_all(root).unwrap();
    }
}
