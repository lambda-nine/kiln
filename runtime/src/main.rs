mod cgroup;
mod container;
mod dns;
mod init;
mod landlock;
mod metrics;
mod net;
mod netlink;
mod persistent;
mod quota;
mod seccomp;
mod storage;
mod trace;
mod userns;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "kiln",
    about,
    // The package version plus the commit build.rs saw, e.g.
    // "0.1.0 (git abcdef123456, clean)".
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("KILN_GIT"), ")")
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command inside a new sandbox.
    Run(Box<RunArgs>),
    /// Create a persistent sandbox and print its ID.
    Create(Box<CreateArgs>),
    /// Run a command in a persistent sandbox.
    Exec {
        id: String,
        #[arg(required = true, trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    /// List persistent sandboxes.
    Ls,
    /// Remove a persistent sandbox.
    Rm { id: String },
    /// Remove state left by crashed sandbox shims.
    Gc,
    /// Serve DNS to sandboxes on 10.88.0.1:53 (run by the kiln-dns service).
    Dns,
    /// Serve running sandboxes' resource use as Prometheus metrics.
    Metrics {
        /// Address to listen on; /metrics is the scrape path.
        #[arg(long, default_value = metrics::DEFAULT_LISTEN)]
        listen: String,
    },
    /// Show running sandboxes' resource use, sampled over one second.
    Stats,
}

#[derive(clap::Args)]
struct RunArgs {
    /// Hostname inside the sandbox (its own UTS namespace).
    #[arg(long, default_value = "kiln")]
    hostname: String,
    /// Image to use as the read-only root filesystem.
    #[arg(long, default_value = "alpine")]
    image: String,
    /// Keep the run's directory afterwards, to inspect what it changed.
    #[arg(long)]
    keep: bool,
    /// Memory limit, like 256M or 2G, or "max".
    #[arg(long, default_value = "512M")]
    memory: String,
    /// CPU limit in cores, like 0.5 or 2, or "max".
    #[arg(long, default_value = "1")]
    cpus: String,
    /// Maximum number of processes and threads, or "max".
    #[arg(long, default_value = "128")]
    pids: String,
    /// Disk limit for everything the sandbox writes, like 1G, or "max".
    #[arg(long, default_value = "1G")]
    disk: String,
    /// Block writes to files and directories (even for root) except under
    /// /tmp, /root, /workspace, /dev/shm and any --writable paths. Uses
    /// Landlock, which doesn't cover metadata: chmod/chown still work.
    #[arg(long)]
    read_only: bool,
    /// Extra writable directory with --read-only (absolute, repeatable).
    #[arg(long, value_name = "PATH", requires = "read_only")]
    writable: Vec<PathBuf>,
    /// Network access: "none" (loopback only) or "full" (internet, but no
    /// private or link-local ranges). --allow implies an allowlist.
    #[arg(long, default_value = "none")]
    net: String,
    /// Allow traffic to HOST[:PORT] or IP[/PREFIX][:PORT] (repeatable).
    /// Everything else is rejected. DNS goes only to kiln dns on 10.88.0.1,
    /// which resolves only the allowed hostnames.
    #[arg(long, value_name = "DEST")]
    allow: Vec<String>,
    /// Print resource usage when the sandbox exits.
    #[arg(long)]
    stats: bool,
    /// Command and arguments, after `--`.
    #[arg(required = true, trailing_var_arg = true)]
    cmd: Vec<String>,
}

#[derive(clap::Args)]
struct CreateArgs {
    #[arg(long, default_value = "kiln")]
    hostname: String,
    #[arg(long, default_value = "alpine")]
    image: String,
    #[arg(long, default_value = "512M")]
    memory: String,
    #[arg(long, default_value = "1")]
    cpus: String,
    #[arg(long, default_value = "128")]
    pids: String,
    #[arg(long, default_value = "1G")]
    disk: String,
    #[arg(long)]
    read_only: bool,
    #[arg(long, value_name = "PATH", requires = "read_only")]
    writable: Vec<PathBuf>,
    #[arg(long, default_value = "none")]
    net: String,
    #[arg(long, value_name = "DEST")]
    allow: Vec<String>,
}

fn main() -> Result<()> {
    trace::start();
    match Cli::parse().command {
        Command::Run(args) => {
            validate_writable(&args.writable)?;
            let cfg = container::Config {
                limits: cgroup::Limits {
                    memory: parse_size(&args.memory)?,
                    cpus: parse_cpus(&args.cpus)?,
                    pids: parse_max(&args.pids)?,
                },
                disk: parse_size(&args.disk)?,
                net: net::Plan::new(&args.net, &args.allow)?,
                hostname: args.hostname,
                image: args.image,
                keep: args.keep,
                read_only: args.read_only,
                writable: args.writable,
                stats: args.stats,
                cmd: args.cmd,
            };
            std::process::exit(container::run(&cfg)?);
        }
        Command::Create(args) => {
            validate_writable(&args.writable)?;
            let cfg = container::Config {
                limits: cgroup::Limits {
                    memory: parse_size(&args.memory)?,
                    cpus: parse_cpus(&args.cpus)?,
                    pids: parse_max(&args.pids)?,
                },
                disk: parse_size(&args.disk)?,
                net: net::Plan::new(&args.net, &args.allow)?,
                hostname: args.hostname,
                image: args.image,
                keep: true,
                read_only: args.read_only,
                writable: args.writable,
                stats: false,
                cmd: Vec::new(),
            };
            println!("{}", persistent::create(&cfg)?);
            Ok(())
        }
        Command::Exec { id, cmd } => std::process::exit(persistent::exec(&id, &cmd)?),
        Command::Ls => persistent::list(),
        Command::Rm { id } => persistent::remove(&id),
        Command::Gc => persistent::gc(),
        Command::Dns => dns::serve(),
        Command::Metrics { listen } => metrics::serve_metrics(&listen),
        Command::Stats => {
            metrics::print_stats();
            Ok(())
        }
    }
}

fn validate_writable(paths: &[PathBuf]) -> Result<()> {
    if let Some(p) = paths.iter().find(|p| !p.is_absolute()) {
        bail!("--writable needs an absolute path, got {}", p.display());
    }
    Ok(())
}

fn parse_cpus(s: &str) -> Result<Option<f64>> {
    if s == "max" {
        return Ok(None);
    }
    match s.parse::<f64>() {
        Ok(n) if n > 0.0 => Ok(Some(n)),
        _ => bail!("invalid --cpus {s:?}: expected a positive number or \"max\""),
    }
}

/// Parses a size like `512M`, `2G`, `65536` or `max`.
pub fn parse_size(s: &str) -> Result<Option<u64>> {
    if s == "max" {
        return Ok(None);
    }
    let (num, mult) = match s.char_indices().last() {
        Some((i, 'K' | 'k')) => (&s[..i], 1 << 10),
        Some((i, 'M' | 'm')) => (&s[..i], 1 << 20),
        Some((i, 'G' | 'g')) => (&s[..i], 1 << 30),
        _ => (s, 1),
    };
    let n: u64 = num.parse().with_context(|| format!("invalid size {s:?}"))?;
    Ok(Some(n.checked_mul(mult).with_context(|| format!("size {s:?} is too large"))?))
}

/// Parses a count like `128` or `max`.
pub fn parse_max(s: &str) -> Result<Option<u64>> {
    if s == "max" {
        return Ok(None);
    }
    Ok(Some(s.parse().with_context(|| format!("invalid number {s:?}"))?))
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn about_matches_package_description() {
        let about = Cli::command().get_about().unwrap().to_string();
        assert_eq!(about, "A small Linux sandbox runtime for AI agent tools");
    }

    #[test]
    fn version_reports_build_commit() {
        let err = Cli::try_parse_from(["kiln", "--version"]).err().unwrap();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        let version = err.to_string();
        let version = version.trim_end();
        let rest = version
            .strip_prefix(concat!("kiln ", env!("CARGO_PKG_VERSION"), " (git "))
            .and_then(|r| r.strip_suffix(')'))
            .unwrap_or_else(|| panic!("unexpected version {version:?}"));
        if rest != "unknown" {
            let (commit, state) = rest.split_once(", ").unwrap();
            assert_eq!(commit.len(), 12, "{version:?}");
            assert!(commit.bytes().all(|b| b.is_ascii_hexdigit()), "{version:?}");
            assert!(state == "clean" || state == "dirty", "{version:?}");
        }
    }
}
