mod cgroup;
mod container;
mod dns;
mod exec_options;
mod exec_protocol;
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
mod validation;

// Include the build-script helpers in the test target so provenance edge
// cases are covered by the ordinary `cargo test` release gate.
#[cfg(test)]
#[allow(dead_code)]
#[path = "../build.rs"]
mod build_script_tests;

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
        #[arg(long)]
        protocol: Option<u16>,
        #[arg(long, requires_all = ["protocol", "stdin_fd", "stdout_fd", "stderr_fd"])]
        status_fd: Option<i32>,
        #[arg(long, requires = "status_fd")]
        stdin_fd: Option<i32>,
        #[arg(long, requires = "status_fd")]
        stdout_fd: Option<i32>,
        #[arg(long, requires = "status_fd")]
        stderr_fd: Option<i32>,
        /// Sealed memfd holding an exec options frame (cwd and environment).
        #[arg(long, requires = "status_fd")]
        exec_options_fd: Option<i32>,
        id: String,
        #[arg(required = true, trailing_var_arg = true)]
        cmd: Vec<String>,
    },
    /// Report CLI or sandbox persistent-exec capabilities as a binary frame.
    Capabilities {
        #[arg(long, required = true)]
        protocol: u16,
        id: Option<String>,
    },
    /// List persistent sandboxes.
    Ls,
    /// Remove a persistent sandbox.
    Rm { id: String },
    /// Remove state left by crashed sandbox shims, optionally limited to IDs.
    Gc {
        #[arg(value_name = "ID")]
        ids: Vec<String>,
    },
    /// Serve DNS to sandboxes on 10.88.0.1:53 (run by the kiln-dns service).
    Dns,
    /// Prepare the host bridge and firewall (privileged, no listener).
    #[command(hide = true)]
    NetworkSetup,
    /// Publish a metrics snapshot (privileged, no listener).
    #[command(hide = true)]
    MetricsCollect,
    /// Serve running sandboxes' resource use as Prometheus metrics.
    Metrics {
        /// Address to listen on; /metrics is the scrape path.
        #[arg(long, default_value = metrics::DEFAULT_LISTEN)]
        listen: String,
        /// Serve the fixed collector snapshot instead of reading the kernel.
        #[arg(long)]
        snapshot: bool,
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
    #[arg(long)]
    require_exec_protocol: Option<u16>,
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
    let result = run();
    if let Err(error) = &result && error.is::<persistent::CreatePreflightFailure>() {
        eprintln!("Error: {error:?}");
        std::process::exit(persistent::CREATE_PREFLIGHT_EXIT);
    }
    result
}

fn run() -> Result<()> {
    trace::start();
    let cli = Cli::try_parse().unwrap_or_else(|error| {
        // Clap has not dispatched any command. Preserve normal help/version
        // statuses; persistent-create syntax errors are definite preflight.
        if error.exit_code() != 0 && std::env::args_os().nth(1).is_some_and(|a| a == "create") {
            let _ = error.print();
            std::process::exit(persistent::CREATE_PREFLIGHT_EXIT);
        }
        error.exit()
    });
    match cli.command {
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
            let cfg = persistent::before_allocation((|| -> Result<container::Config> {
                if let Some(version) = args.require_exec_protocol {
                    anyhow::ensure!(version == exec_protocol::VERSION, "unsupported persistent-exec protocol {version}");
                }
                validate_writable(&args.writable)?;
                Ok(container::Config {
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
                })
            })())?;
            println!("{}", persistent::create(&cfg)?);
            Ok(())
        }
        Command::Exec { id, cmd, protocol, status_fd, stdin_fd, stdout_fd, stderr_fd, exec_options_fd } => {
            let result = match (protocol, status_fd, stdin_fd, stdout_fd, stderr_fd) {
                (Some(version), Some(status), Some(input), Some(output), Some(error)) =>
                    persistent::machine_exec(&id, &cmd, version, status, [input, output, error], exec_options_fd),
                (None, None, None, None, None) => persistent::exec(&id, &cmd),
                _ => Err(anyhow::anyhow!("machine exec requires protocol and all four private descriptors")),
            };
            match result {
                Ok(code) => std::process::exit(code),
                // Human projection only; machine callers use the private frame.
                Err(e) => {
                    eprintln!("Error: {e:?}");
                    std::process::exit(persistent::EXEC_FAILED);
                }
            }
        }
        Command::Capabilities { protocol, id } => persistent::capabilities(id.as_deref(), protocol),
        Command::Ls => persistent::list(),
        Command::Rm { id } => persistent::remove(&id),
        Command::Gc { ids } => persistent::gc(&ids),
        Command::Dns => dns::serve(),
        Command::NetworkSetup => net::ensure_bridge(),
        Command::MetricsCollect => metrics::publish_snapshot(),
        Command::Metrics { listen, snapshot } => metrics::serve_metrics(&listen, snapshot),
        Command::Stats => {
            metrics::print_stats();
            Ok(())
        }
    }
}

fn validate_writable(paths: &[PathBuf]) -> Result<()> {
    validation::validate_writable_paths(paths)
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
    fn machine_flags_are_separate_from_workload_argv() {
        let cli = Cli::try_parse_from(["kiln", "exec", "--protocol=1", "--status-fd=3",
            "--stdin-fd=4", "--stdout-fd=5", "--stderr-fd=6", "abc", "--", "printf", "--protocol=99"]).unwrap();
        let Command::Exec { cmd, protocol, .. } = cli.command else { panic!("not exec") };
        assert_eq!(protocol, Some(1));
        assert_eq!(cmd, ["printf", "--protocol=99"]);
        assert!(Cli::try_parse_from(["kiln", "exec", "--protocol=1", "--status-fd=3", "abc", "--", "true"]).is_err());
        let cli = Cli::try_parse_from(["kiln", "exec", "--protocol=1", "--status-fd=3", "--stdin-fd=4",
            "--stdout-fd=5", "--stderr-fd=6", "--exec-options-fd=7", "abc", "--", "env", "--exec-options-fd=8"]).unwrap();
        let Command::Exec { cmd, exec_options_fd, .. } = cli.command else { panic!("not exec") };
        assert_eq!((exec_options_fd, cmd.as_slice()), (Some(7), &["env".to_string(), "--exec-options-fd=8".into()][..]));
        // Options are a machine-exec feature only.
        assert!(Cli::try_parse_from(["kiln", "exec", "--exec-options-fd=7", "abc", "--", "true"]).is_err());
    }

    #[test]
    fn gc_accepts_an_optional_explicit_scope() {
        let all = Cli::try_parse_from(["kiln", "gc"]).unwrap();
        let Command::Gc { ids } = all.command else { panic!("not gc") };
        assert!(ids.is_empty());

        let scoped = Cli::try_parse_from(["kiln", "gc", "abcd-1", "beef-2"]).unwrap();
        let Command::Gc { ids } = scoped.command else { panic!("not gc") };
        assert_eq!(ids, ["abcd-1", "beef-2"]);
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

#[cfg(test)]
mod create_certainty_tests {
    use super::*;

    #[test]
    fn preflight_errors_are_typed_but_other_failures_are_not() {
        let error = persistent::before_allocation::<()>(Err(anyhow::anyhow!("invalid config"))).unwrap_err();
        assert!(error.is::<persistent::CreatePreflightFailure>());
        assert!(!anyhow::anyhow!("shim failed after allocation").is::<persistent::CreatePreflightFailure>());
    }

    #[test]
    fn missing_image_is_rejected_before_id_or_resource_creation() {
        let cfg = container::Config {
            limits: cgroup::Limits { memory: Some(64 * 1024 * 1024), cpus: Some(1.0), pids: Some(16) },
            disk: Some(16 * 1024 * 1024),
            net: net::Plan::new("none", &[]).unwrap(),
            hostname: "kiln".into(), image: "round2-missing-image-unit-fixture".into(),
            keep: true, read_only: false, writable: Vec::new(), stats: false, cmd: Vec::new(),
        };
        let error = persistent::create(&cfg).unwrap_err();
        assert!(error.is::<persistent::CreatePreflightFailure>(), "{error:#}");
        assert!(format!("{error:#}").contains("image"));
    }
}
