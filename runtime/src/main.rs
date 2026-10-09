mod cgroup;
mod container;
mod init;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kiln", about = "A small Linux sandbox runtime for AI agent tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run a command inside a new sandbox.
    Run {
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
        /// Print resource usage when the sandbox exits.
        #[arg(long)]
        stats: bool,
        /// Command and arguments, after `--`.
        #[arg(required = true, trailing_var_arg = true)]
        cmd: Vec<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Run { hostname, image, keep, memory, cpus, pids, stats, cmd } => {
            let limits = cgroup::Limits {
                memory: cgroup::parse_size(&memory)?,
                cpus: parse_cpus(&cpus)?,
                pids: cgroup::parse_max(&pids)?,
            };
            let cfg = container::Config { hostname, image, keep, limits, stats, cmd };
            let code = container::run(&cfg)?;
            std::process::exit(code);
        }
    }
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
