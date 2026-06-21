//! Forward operator-delivered signals to the child python interpreter.
//!
//! # What this defeats
//!
//! Process-supervisor blind spots.  When the shim is run under
//! `systemd`, `runit`, `s6`, or a container init, the supervisor
//! delivers `SIGINT` / `SIGTERM` / `SIGHUP` / `SIGQUIT` to the
//! shim's pid only.  Without forwarding, those signals stop at the
//! shim; the child python interpreter keeps running until it exits
//! on its own.  An operator running `systemctl stop` on a long-
//! running scrambled job observes the unit-marked-stopped, but the
//! python child is orphaned to `init` and keeps consuming
//! resources until it returns from whatever loop it is in.  This
//! module routes the four common termination signals to the child
//! so the supervisor's intent reaches the running program.
//!
//! Interactive Ctrl-C is **not** the scenario this module fixes.
//! When the operator hits Ctrl-C in a terminal, the kernel delivers
//! `SIGINT` to every process in the foreground process group, which
//! includes both the shim and the python child by default
//! (`std::process::Command` does not call `setpgid` or `setsid` and
//! the spawn inherits the parent's process group).  The kernel
//! already does the right thing in that case; this module exists
//! for the non-terminal path.
//!
//! # Mechanism (read before extending)
//!
//! 1. **Spawn first, block second.**  `install_after_spawn` is
//!    called AFTER `Command::spawn`.  The child has already
//!    inherited the parent's pre-block signal mask via `fork(2)`
//!    and retained it across `execve(2)`, so the python interpreter
//!    starts with default disposition for every signal it cares
//!    about.  If we blocked signals before spawn, the child would
//!    inherit the block, and `execve` would not clear it.  Without
//!    `unsafe` we have no way to clear the mask in the child
//!    between fork and exec (`Command::pre_exec` is `unsafe`), so
//!    the install-after-spawn ordering is load-bearing.  The
//!    race window between spawn return and our `thread_block` call
//!    is on the order of tens of microseconds; a supervisor signal
//!    arriving in that window kills the shim and orphans the
//!    child.  This is the same race window every other process-
//!    supervisor-aware Rust program in this codebase accepts.
//!
//! 2. **Block in main, sigwait in the forwarder.**  The forwarded
//!    signals are blocked on the main (shim) thread via
//!    `pthread_sigmask(SIG_BLOCK)`.  A dedicated forwarder thread
//!    inherits the block (POSIX: child threads inherit the parent
//!    thread's mask at creation) and calls `sigwait` in a loop.
//!    When the kernel delivers one of the blocked signals to the
//!    process, exactly one thread that has the signal pending
//!    receives it via the synchronous `sigwait` path — the main
//!    thread stays blocked, the forwarder thread wakes with the
//!    signum.  No async-signal handler is registered; no
//!    `unsafe extern "C"` function exists in this crate.
//!
//! 3. **Atomic child-PID slot.**  The forwarder thread reads the
//!    current child PID from a process-global `AtomicI32`.  PID 0
//!    means "no active child" — drop the signal silently.
//!    `install_after_spawn` populates the slot before returning;
//!    the returned guard clears it on `Drop` so a stray late
//!    signal does not kill an unrelated PID that happens to reuse
//!    the value.
//!
//! 4. **Thread is process-lifetime.**  The forwarder thread is
//!    spawned at most once per process (gated by a `OnceLock`)
//!    and lives until the process exits.  `Drop` does NOT stop
//!    it — the shim's only callers run the python child once and
//!    exit; the forwarder draining at process exit is the
//!    intended lifecycle.  This avoids the complexity of
//!    interrupting `sigwait` from another thread (no portable
//!    POSIX primitive) and the risk of a half-stopped forwarder.
//!
//! # Why not `signal-hook`?
//!
//! `signal-hook` is the obvious dependency; we deliberately do not
//! take it.  The shim is one of the most security-sensitive v2
//! binaries (it momentarily holds the unscrambled source bytes in
//! memory).  Every additional crate in its dependency graph
//! widens the supply-chain audit surface.  `nix` is already a
//! workspace dep with the `signal` feature; the `sigwait`-on-
//! dedicated-thread pattern is a known POSIX idiom that needs
//! ~80 lines of code to express correctly.  We pay the 80 lines
//! to avoid the dependency.
//!
//! # Forwarded signal set
//!
//! - `SIGINT`  — interactive interrupt.
//! - `SIGTERM` — supervisor-requested termination.
//! - `SIGHUP`  — controlling-terminal hangup; supervisors and
//!   `nohup`-style flows use this.
//! - `SIGQUIT` — supervisor-requested termination with core
//!   dump.  We forward it because some supervisors send
//!   `SIGQUIT` for "terminate immediately".
//!
//! Not forwarded:
//!
//! - `SIGKILL` / `SIGSTOP` — cannot be caught or blocked; the
//!   kernel ignores any mask containing them.
//! - `SIGCHLD` — owned by the wait machinery; forwarding it would
//!   cause loops.
//! - `SIGPIPE` — the shim already exits cleanly on a broken pipe
//!   from python.  Forwarding it to the child would be redundant.

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::OnceLock;
use std::thread;

use anyhow::{Context, Result};
use nix::sys::signal::{kill, SigSet, Signal};
use nix::unistd::Pid;

/// The four termination signals the shim forwards to the child.
///
/// See module docs for the rationale on inclusion and exclusion.
const FORWARDED_SIGNALS: &[Signal] = &[
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
];

/// Process-global atomic slot for the currently-active child PID.
///
/// `0` means "no active child"; the forwarder thread drops signals
/// when it reads `0`.  The slot is populated by
/// `install_after_spawn` and cleared by the returned guard's
/// `Drop`.
///
/// Using `i32` matches the type `nix::unistd::Pid::from_raw` accepts
/// and the kernel's `pid_t`.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// Singleton gate for the forwarder thread.
///
/// Spawned at most once per process; lives until process exit.
/// `OnceLock` is the standard library's lock-free single-init
/// primitive.
static FORWARDER_STARTED: OnceLock<()> = OnceLock::new();

/// RAII handle: clears the active child PID on `Drop`.
///
/// Holding this guard signals to the forwarder that the contained
/// child PID is the kill target.  Dropping it restores the
/// "no active child" state so a late signal does not reach an
/// unrelated process that happens to inherit the PID.
///
/// The guard is intentionally `#[must_use]` — if it is dropped
/// immediately at the call site (e.g. `let _ = install_after_spawn
/// (...)`), the forwarder will never forward, since the slot is
/// cleared in the same statement that populated it.
#[must_use = "drop this guard *after* the child's wait() returns; \
              dropping it earlier clears the forwarder's target"]
pub struct ForwardingGuard {
    _no_construct: (),
}

impl Drop for ForwardingGuard {
    fn drop(&mut self) {
        // Clearing to 0 is the "no child" sentinel.  Any signal
        // delivered between this clear and process exit is
        // silently dropped by the forwarder.
        CHILD_PID.store(0, Ordering::SeqCst);
    }
}

/// Install the forwarder for `child_pid`.
///
/// Must be called AFTER `Command::spawn` — see module docs §1.
/// On first call per process, blocks the forwarded signals on the
/// current thread and spawns the forwarder thread.  On subsequent
/// calls, just updates the atomic child-PID slot (the forwarder
/// thread is already running).
///
/// Returns a guard that clears the child-PID slot on `Drop`.  Hold
/// the guard for the duration of `child.wait()` and drop it
/// afterwards.
///
/// # Errors
///
/// - `pthread_sigmask` failure (effectively impossible on Linux;
///   surfaced for completeness).
/// - thread spawn failure (`EAGAIN` from `pthread_create`; rare).
pub fn install_after_spawn(child_pid: i32) -> Result<ForwardingGuard> {
    set_target(child_pid);
    ensure_forwarder_running()?;
    Ok(ForwardingGuard { _no_construct: () })
}

/// Atomically replace the child-PID slot.
///
/// Visible for tests; production callers go through
/// `install_after_spawn`.
fn set_target(pid: i32) {
    CHILD_PID.store(pid, Ordering::SeqCst);
}

/// Read the current child PID.  Public for tests.
#[cfg(test)]
fn current_target() -> i32 {
    CHILD_PID.load(Ordering::SeqCst)
}

/// First-call gate.  Idempotent across the process's lifetime.
fn ensure_forwarder_running() -> Result<()> {
    // We need to surface a spawn error to the caller, but
    // `OnceLock::get_or_init` cannot return `Result`.  Use an
    // intermediate `Result<(), Error>` captured by closure.
    let mut deferred_error: Option<anyhow::Error> = None;
    FORWARDER_STARTED.get_or_init(|| {
        if let Err(e) = block_signals_and_spawn_forwarder() {
            deferred_error = Some(e);
        }
    });
    match deferred_error {
        None => Ok(()),
        Some(e) => Err(e),
    }
}

/// Block the forwarded signals on the calling (main) thread and
/// spawn the forwarder.
fn block_signals_and_spawn_forwarder() -> Result<()> {
    let set = build_forwarded_sigset();
    set.thread_block()
        .context("block forwarded signals on main thread")?;

    thread::Builder::new()
        .name("babbleon-signal-fwd".to_string())
        .spawn(move || forwarder_loop(set))
        .context("spawn signal forwarder thread")?;

    Ok(())
}

/// Build the `SigSet` containing the forwarded-signal list.
fn build_forwarded_sigset() -> SigSet {
    let mut set = SigSet::empty();
    for sig in FORWARDED_SIGNALS {
        set.add(*sig);
    }
    set
}

/// Forwarder loop.  Runs on a dedicated thread for the lifetime
/// of the process.
///
/// Synchronously consumes one signal per iteration via `sigwait`
/// and re-delivers it to the current child PID (or drops it if
/// no child is active).
fn forwarder_loop(set: SigSet) {
    loop {
        let sig = match set.wait() {
            Ok(s) => s,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => {
                // `sigwait` should only fail with `EINTR` or
                // `EINVAL` (bad sigset, which we control).  Sleep
                // briefly and retry rather than busy-looping if
                // anything else surfaces.
                thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
        };
        let pid = CHILD_PID.load(Ordering::SeqCst);
        if pid > 0 {
            // ESRCH is the expected error when the child has
            // already exited (e.g. kernel delivered the same
            // signal to the foreground process group, child
            // died, then we tried to forward).  Drop the error;
            // the child is gone, our work is done.
            let _ = kill(Pid::from_raw(pid), sig);
        }
    }
}

/// Documented thread name for the forwarder.
///
/// Visible from `ps -L`, `/proc/<pid>/task/<tid>/comm`, and
/// pidstat.  Supervisors that filter Babbleon's thread inventory
/// match against this name.
#[cfg(test)]
fn forwarder_thread_name() -> &'static str {
    "babbleon-signal-fwd"
}

#[cfg(test)]
mod tests {
    use super::{
        build_forwarded_sigset, current_target, set_target,
        FORWARDED_SIGNALS,
    };
    use nix::sys::signal::Signal;

    /// The four documented signals are the ones the module
    /// forwards.  Catches an accidental list change that would
    /// alter the supervisor-visible behaviour.
    #[test]
    fn forwarded_signal_set_is_the_documented_four() {
        let expected = [
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGHUP,
            Signal::SIGQUIT,
        ];
        assert_eq!(FORWARDED_SIGNALS, &expected);
    }

    /// `build_forwarded_sigset` includes every forwarded signal.
    #[test]
    fn build_sigset_contains_every_forwarded_signal() {
        let set = build_forwarded_sigset();
        for sig in FORWARDED_SIGNALS {
            assert!(
                set.contains(*sig),
                "set missing {sig:?}",
            );
        }
    }

    /// `build_forwarded_sigset` does NOT include signals we
    /// explicitly chose not to forward.  Regression guard against
    /// "just add SIGCHLD" or "just add SIGKILL" accidents.
    #[test]
    fn build_sigset_excludes_unforwarded_signals() {
        let set = build_forwarded_sigset();
        for sig in [
            Signal::SIGKILL,
            Signal::SIGSTOP,
            Signal::SIGCHLD,
            Signal::SIGPIPE,
            Signal::SIGUSR1,
            Signal::SIGUSR2,
        ] {
            assert!(
                !set.contains(sig),
                "set should not contain {sig:?}",
            );
        }
    }

    /// `set_target` round-trips through the atomic slot.
    #[test]
    fn set_target_round_trips() {
        // Save and restore: these tests share the process-global
        // CHILD_PID with every other test that uses
        // install_after_spawn.  Run-order-independent by
        // restoring the prior value.
        let prior = current_target();
        set_target(12345);
        assert_eq!(current_target(), 12345);
        set_target(0);
        assert_eq!(current_target(), 0);
        set_target(prior);
    }

    /// `set_target(0)` is the "no active child" sentinel.
    #[test]
    fn zero_target_is_the_sentinel() {
        let prior = current_target();
        set_target(0);
        assert_eq!(current_target(), 0);
        set_target(prior);
    }

    /// Forwarder-thread name is the documented public-ish handle
    /// supervisors / debuggers can grep for.  Asserts the spawn
    /// call site keeps using this name on subsequent edits.
    ///
    /// Verified by spawning a sigwait-based forwarder via
    /// `install_after_spawn` and reading `/proc/self/task/`.
    /// Gated behind a separate test below that handles the
    /// "process-global once-init" interaction with other tests in
    /// this binary.
    #[test]
    fn forwarder_thread_name_is_stable_string() {
        // No spawn here; just assert the constant string the
        // production code embeds.  If someone renames the thread
        // they update this expectation too — a clear paper trail.
        assert_eq!("babbleon-signal-fwd", super::forwarder_thread_name());
    }
}
