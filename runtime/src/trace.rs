//! `KILN_TRACE=1`: print how long each startup and teardown phase took.
//!
//! Each `mark("phase")` prints one line to stderr with the time since kiln's
//! `main` started and the time since this process's previous mark:
//!
//! ```text
//! kiln-trace    1.92 ms  +0.31  host: cgroup
//! kiln-trace    2.05 ms  +0.08  init: overlay
//! ```
//!
//! The sandbox's init is a clone of the host-side kiln, so it inherits the
//! start time and prints its own marks ("init: ..."). Instant reads
//! CLOCK_MONOTONIC, which is system-wide, so both timelines line up.

use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

static START: OnceLock<Option<Instant>> = OnceLock::new();
static LAST: Mutex<Option<Instant>> = Mutex::new(None);

/// Reads `KILN_TRACE` once and starts the clock. Call first thing in `main`.
pub fn start() {
    START.get_or_init(|| std::env::var_os("KILN_TRACE").is_some_and(|v| v != "0").then(Instant::now));
}

/// Prints the time spent since the previous mark, labeled `phase`.
pub fn mark(phase: &str) {
    let Some(Some(start)) = START.get() else { return };
    let now = Instant::now();
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    let since_last = now - last.unwrap_or(*start);
    *last = Some(now);
    let ms = |d: std::time::Duration| d.as_secs_f64() * 1000.0;
    // Ignore write errors: eprintln! would panic if stderr is a closed pipe
    // (`kiln run ... 2>&1 | head`), and a panic here would skip cleanup.
    let _ = writeln!(std::io::stderr(), "kiln-trace {:7.2} ms {:+6.2}  {phase}", ms(now - *start), ms(since_last));
}
