//! Tests only: keeps the test binary's forks away from tests that check
//! `flock`s.
//!
//! A forked child gets copies of all its parent's descriptors, which share
//! the parent's open file descriptions, until it execs (kiln opens every
//! descriptor close-on-exec) or exits. A `flock` belongs to the open file
//! description, so a lock the parent releases by closing its descriptor
//! stays held by the child's copy meanwhile. In this binary tests run in
//! parallel threads, and some fork or spawn a child, so a test that drops a
//! lock and then finds it free (or takes it again without blocking) could
//! see it held by a child another test just forked.
//!
//! Tests that take such locks without blocking (the checkpoint store's, the
//! off-lock image verify's) or check that one is free hold `no_forks` for
//! their whole run; tests that fork hold `forking` from before the fork
//! until the child has execed or exited. No child is ever forked while a
//! lock test runs, but lock tests still run alongside each other, and
//! forking tests alongside each other, as they did without the guard. A
//! waiting fork goes first, so a stream of lock tests can't starve it. A
//! test that only waits for a lock doesn't need `no_forks`: an inherited
//! copy only delays it until the child execs. Keep `no_forks` off slow
//! tests: while one holds it, every `forking` waits, and so does every
//! later `no_forks`.

use std::process::{Child, Command, Output, Stdio};
use std::sync::{Condvar, Mutex, MutexGuard};

struct Counts { lock_tests: usize, forks: usize, waiting_forks: usize }

static COUNTS: Mutex<Counts> = Mutex::new(Counts { lock_tests: 0, forks: 0, waiting_forks: 0 });
static CHANGED: Condvar = Condvar::new();

fn counts() -> MutexGuard<'static, Counts> {
    // A panicking holder only poisons the mutex; the counts stay consistent
    // because no update can panic halfway.
    COUNTS.lock().unwrap_or_else(|e| e.into_inner())
}

fn wait(guard: MutexGuard<'static, Counts>) -> MutexGuard<'static, Counts> {
    // Sent while the counts are still locked: whoever hears it can't change
    // them, so this thread can't miss the change, until it waits.
    WAITING.with(|tx| if let Some(tx) = &*tx.borrow() { let _ = tx.send(Event::Waiting); });
    CHANGED.wait(guard).unwrap_or_else(|e| e.into_inner())
}

/// What a thread observed by `tests` reports about itself.
#[derive(Debug, PartialEq)]
enum Event { Waiting, Entered }

thread_local! {
    /// Where `wait` reports that this thread is about to wait, if anywhere.
    static WAITING: std::cell::RefCell<Option<std::sync::mpsc::Sender<Event>>> =
        const { std::cell::RefCell::new(None) };
}

/// Held for a whole test that takes `flock`s without blocking or expects
/// one free: no test forks a child until it is dropped.
pub(crate) struct NoForks(());

impl Drop for NoForks {
    fn drop(&mut self) {
        counts().lock_tests -= 1;
        CHANGED.notify_all();
    }
}

pub(crate) fn no_forks() -> NoForks {
    let mut c = counts();
    while c.forks > 0 || c.waiting_forks > 0 { c = wait(c); }
    c.lock_tests += 1;
    NoForks(())
}

/// Held from before a test forks or spawns a child until that child has
/// execed or exited (`Command::spawn` returns after the exec): no test that
/// takes `flock`s is running meanwhile.
pub(crate) struct Forking(());

impl Drop for Forking {
    fn drop(&mut self) {
        counts().forks -= 1;
        CHANGED.notify_all();
    }
}

pub(crate) fn forking() -> Forking {
    let mut c = counts();
    c.waiting_forks += 1;
    while c.lock_tests > 0 { c = wait(c); }
    c.waiting_forks -= 1;
    c.forks += 1;
    Forking(())
}

/// `command.spawn()` under `forking`.
pub(crate) fn spawn(command: &mut Command) -> std::io::Result<Child> {
    let _forking = forking();
    command.spawn()
}

/// `command.output()`, holding `forking` only until the child has execed,
/// not while it runs.
pub(crate) fn output(command: &mut Command) -> std::io::Result<Output> {
    spawn(command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()))?.wait_with_output()
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Receiver, channel};
    use std::sync::{Arc, Mutex};
    use std::thread::JoinHandle;

    use super::*;

    type Log = Arc<Mutex<Vec<&'static str>>>;

    /// Runs `take` on a new thread that reports each of its waits, and then
    /// its entry, on the returned channel. Once in, it logs `name` and lets go.
    fn party<G: 'static>(name: &'static str, log: &Log, take: fn() -> G) -> (Receiver<Event>, JoinHandle<()>) {
        let (events, observed) = channel();
        let log = log.clone();
        let thread = std::thread::spawn(move || {
            WAITING.with(|tx| *tx.borrow_mut() = Some(events.clone()));
            let held = take();
            log.lock().unwrap().push(name);
            let _ = events.send(Event::Entered);
            drop(held);
        });
        (observed, thread)
    }

    /// A waiting fork goes before a lock test that arrives after it, once the
    /// lock test that held it off is gone, so a stream of lock tests can't
    /// starve forks.
    #[test]
    fn a_waiting_fork_enters_before_a_later_lock_test() {
        let log = Log::default();
        let first = no_forks();
        let (fork, fork_thread) = party("fork", &log, forking);
        // `first` is running, so the fork has to wait.
        assert_eq!(fork.recv().unwrap(), Event::Waiting);
        let (second, second_thread) = party("second lock test", &log, no_forks);
        // The second lock test has made its choice, to wait or to go in.
        let choice = second.recv().unwrap();
        drop(first);
        fork_thread.join().unwrap();
        second_thread.join().unwrap();
        assert_eq!((choice, log.lock().unwrap().as_slice()), (Event::Waiting, &["fork", "second lock test"][..]));
    }
}
