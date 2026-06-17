//! Active responses to honey-tripwire events.
//!
//! # What this defeats
//!
//! Without an active response, a `HoneyTriggered` event is only a log
//! line.  The attacker has already exec'd the wrapper, learned that the
//! name resolves (in the sense that something ran), and the only cost
//! to them is that one wrapper exited 127.  An active response converts
//! "you tripped the alarm" into "you are no longer running" — the
//! attacker pays for the tripwire access with the process that took it.
//!
//! # Policy options
//!
//! ```text
//!   NotifyOnly         — current baseline; only sinks fire.  No kill.
//!   KillTrigger        — SIGKILL the process that exec'd the wrapper
//!                        (its PPID, captured by the wrapper).  Verifies
//!                        identity against PID reuse via /proc start-time.
//!   KillTriggerTree    — kill the whole process group of the trigger.
//!                        Use when the trigger is a shell or a worker
//!                        pool you want to take down as a unit.
//! ```
//!
//! Future variants (filed in TODO M3.5+): `Quarantine` via freezer
//! cgroup; `SystemAlert` escalating to PAM / login-blocking.
//!
//! # PID-reuse defence
//!
//! Between the wrapper writing its JSON to the FIFO and the responder
//! signalling, the triggering process may have exited and its PID been
//! recycled.  The wrapper captures the parent's start-time
//! (`/proc/<ppid>/stat` field 22) at trigger time; the responder reads
//! the current start-time before signalling and refuses to act if they
//! disagree.  Start-time is monotonic-since-boot and unique per
//! process, so this closes the race.

#![cfg(target_os = "linux")]

use crate::events::{Event, EventSink};
use std::sync::atomic::{AtomicU64, Ordering};

/// What a `HoneyResponder` does with each `HoneyTriggered` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponsePolicy {
    /// Log only.  Default — does not kill anything.
    #[default]
    NotifyOnly,
    /// SIGKILL the wrapper's triggering process (PPID).  PID-reuse safe
    /// via start-time check.
    KillTrigger,
    /// `kill -KILL -<pgid>` — take the whole process group of the
    /// triggering PID down.
    KillTriggerTree,
}

impl ResponsePolicy {
    /// Parse from operator-facing string ("notify-only", "kill-trigger",
    /// "kill-trigger-tree").  Returns None for unknown.
    //
    // Intentionally not `impl FromStr`: callers want `Option` (a stray
    // env-var value is an operator-side typo, not a parse-error worth
    // promoting to a typed error), and the std trait forces `Result`.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "notify-only" | "notify" | "log" => Some(Self::NotifyOnly),
            "kill-trigger" | "kill" => Some(Self::KillTrigger),
            "kill-trigger-tree" | "kill-tree" | "kill-pgrp" => Some(Self::KillTriggerTree),
            _ => None,
        }
    }
}

/// Outcome of acting on a single tripwire event.  Exposed so tests and
/// audit sinks can record what happened.
#[derive(Debug, Clone)]
pub struct ResponseOutcome {
    pub policy: ResponsePolicy,
    pub action: ResponseAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseAction {
    /// No active step taken (NotifyOnly, or no triggering PID was
    /// captured).
    None,
    /// Sent SIGKILL to the named PID.
    Killed { pid: u32 },
    /// Sent SIGKILL to the whole process group of the named PID.
    KilledGroup { pgid: i32 },
    /// PID was captured but its start-time no longer matches; refused
    /// to act to avoid hitting an innocent process after PID reuse.
    RefusedPidReuse { pid: u32 },
    /// PID was captured but no longer exists.
    AlreadyExited { pid: u32 },
    /// Signal failed at the kernel level (EPERM, etc.).
    SignalFailed { pid: u32, errno: i32 },
}

/// An `EventSink` that applies a `ResponsePolicy` to each tripwire
/// event.  Compose with the existing stderr / JSONL sinks via
/// `EventBus::add_sink`.
///
/// Counter visible for tests + status reporting.
pub struct HoneyResponder {
    policy: ResponsePolicy,
    triggers_seen: AtomicU64,
    kills_attempted: AtomicU64,
}

impl HoneyResponder {
    pub fn new(policy: ResponsePolicy) -> Self {
        Self {
            policy,
            triggers_seen: AtomicU64::new(0),
            kills_attempted: AtomicU64::new(0),
        }
    }

    pub fn policy(&self) -> ResponsePolicy {
        self.policy
    }

    pub fn triggers_seen(&self) -> u64 {
        self.triggers_seen.load(Ordering::Relaxed)
    }

    pub fn kills_attempted(&self) -> u64 {
        self.kills_attempted.load(Ordering::Relaxed)
    }

    /// Public for tests: run the policy against an event without going
    /// through the EventBus.  Production code path is `emit()`.
    pub fn handle(&self, event: &Event) -> ResponseOutcome {
        if !matches!(event, Event::HoneyTriggered { .. }) {
            return ResponseOutcome {
                policy: self.policy,
                action: ResponseAction::None,
            };
        }
        self.triggers_seen.fetch_add(1, Ordering::Relaxed);

        let (triggering_pid, captured_start, _source) = match event {
            Event::HoneyTriggered {
                triggering_pid,
                triggering_pid_start,
                source,
                ..
            } => (*triggering_pid, *triggering_pid_start, *source),
            _ => unreachable!(),
        };

        let action = match self.policy {
            ResponsePolicy::NotifyOnly => ResponseAction::None,
            ResponsePolicy::KillTrigger => match (triggering_pid, captured_start) {
                (Some(pid), Some(captured)) => {
                    self.kills_attempted.fetch_add(1, Ordering::Relaxed);
                    kill_with_starttime_check(pid, captured)
                }
                (Some(pid), None) => {
                    tracing::warn!(
                        "honey-responder: refusing to kill pid={pid} — \
                         wrapper did not capture start-time"
                    );
                    ResponseAction::RefusedPidReuse { pid }
                }
                (None, _) => ResponseAction::None,
            },
            ResponsePolicy::KillTriggerTree => match (triggering_pid, captured_start) {
                (Some(pid), Some(captured)) => {
                    if current_start_time(pid) != Some(captured) {
                        return ResponseOutcome {
                            policy: self.policy,
                            action: pid_check_outcome(pid, captured),
                        };
                    }
                    self.kills_attempted.fetch_add(1, Ordering::Relaxed);
                    let pgid = process_group(pid).unwrap_or(pid as i32);
                    kill_group(pgid)
                }
                _ => ResponseAction::None,
            },
        };

        ResponseOutcome {
            policy: self.policy,
            action,
        }
    }
}

impl EventSink for HoneyResponder {
    fn emit(&self, event: &Event) {
        let _ = self.handle(event);
    }
}

/// Read the start-time (clock ticks since boot) of `pid` from
/// `/proc/<pid>/stat` field 22.  Returns None if the process is gone
/// or /proc is unreadable.
///
/// The stat line is whitespace-separated EXCEPT that field 2 (`comm`)
/// is wrapped in parentheses and may itself contain whitespace.  We
/// split on the LAST `)` to skip that field, then index from there.
fn current_start_time(pid: u32) -> Option<u64> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = raw.rfind(')')?;
    let after = &raw[close + 1..];
    // Fields after `)` start at field 3 (state).  Start-time is field 22,
    // so it is the 20th field after the `)`.
    let mut it = after.split_whitespace();
    for _ in 0..19 {
        it.next()?;
    }
    it.next()?.parse::<u64>().ok()
}

fn process_group(pid: u32) -> Option<i32> {
    // pgid is field 5 of /proc/<pid>/stat (3 fields past `)`).
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = raw.rfind(')')?;
    let after = &raw[close + 1..];
    let mut it = after.split_whitespace();
    for _ in 0..2 {
        it.next()?;
    }
    it.next()?.parse::<i32>().ok()
}

fn pid_check_outcome(pid: u32, captured: u64) -> ResponseAction {
    match current_start_time(pid) {
        Some(now) if now == captured => ResponseAction::None, // unreachable
        Some(_) => {
            tracing::warn!(
                "honey-responder: pid={pid} start-time changed — \
                 PID was reused; refusing to signal"
            );
            ResponseAction::RefusedPidReuse { pid }
        }
        None => {
            tracing::info!("honey-responder: pid={pid} already exited");
            ResponseAction::AlreadyExited { pid }
        }
    }
}

fn kill_with_starttime_check(pid: u32, captured: u64) -> ResponseAction {
    match current_start_time(pid) {
        Some(now) if now == captured => signal_kill(pid),
        other => match other {
            Some(_) => ResponseAction::RefusedPidReuse { pid },
            None => ResponseAction::AlreadyExited { pid },
        },
    }
}

fn signal_kill(pid: u32) -> ResponseAction {
    // SAFETY: `kill(2)` is async-signal-safe and takes two scalar
    // arguments (a pid and a signal number).  We pass a `pid_t` and a
    // libc-defined signal constant — both plain integers, no aliasing
    // or pointer concerns.  The caller has already verified the PID's
    // start-time matches the captured value, so we are signalling the
    // process the policy intended to act on, not a reused PID.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if rc == 0 {
        ResponseAction::Killed { pid }
    } else {
        // SAFETY: `__errno_location` returns a per-thread pointer to the
        // calling thread's errno cell.  The pointer is valid for the
        // lifetime of the thread; dereferencing it for a one-shot read
        // immediately after a libc call that set it is the documented
        // contract.
        let errno = unsafe { *libc::__errno_location() };
        match errno {
            libc::ESRCH => ResponseAction::AlreadyExited { pid },
            _ => ResponseAction::SignalFailed { pid, errno },
        }
    }
}

fn kill_group(pgid: i32) -> ResponseAction {
    // Negative target ⇒ deliver to the whole process group.
    // SAFETY: see `signal_kill` — same async-signal-safe scalar call.
    // The negation widens to i32 then narrows to `pid_t`; both targets
    // here have the same width (libc::pid_t is i32 on every Linux ABI
    // we support).  Process-group identity is checked by the caller via
    // the same start-time path used for single-PID signalling.
    let rc = unsafe { libc::kill(-pgid as libc::pid_t, libc::SIGKILL) };
    if rc == 0 {
        ResponseAction::KilledGroup { pgid }
    } else {
        // SAFETY: see the matching block in `signal_kill`.
        let errno = unsafe { *libc::__errno_location() };
        match errno {
            libc::ESRCH => ResponseAction::AlreadyExited { pid: pgid as u32 },
            _ => ResponseAction::SignalFailed {
                pid: pgid as u32,
                errno,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TripwireSource;

    fn make_event(triggering_pid: Option<u32>, start: Option<u64>) -> Event {
        Event::HoneyTriggered {
            epoch: 1,
            names: vec!["xq-marble-fern".into()],
            source: TripwireSource::Honey,
            wrapper_pid: 9999,
            triggering_pid,
            triggering_pid_start: start,
            process_hint: "test".into(),
        }
    }

    #[test]
    fn policy_str_roundtrip() {
        assert_eq!(
            ResponsePolicy::from_str("notify-only"),
            Some(ResponsePolicy::NotifyOnly)
        );
        assert_eq!(
            ResponsePolicy::from_str("kill"),
            Some(ResponsePolicy::KillTrigger)
        );
        assert_eq!(
            ResponsePolicy::from_str("kill-tree"),
            Some(ResponsePolicy::KillTriggerTree)
        );
        assert!(ResponsePolicy::from_str("rm-rf-slash").is_none());
    }

    #[test]
    fn notify_only_takes_no_action() {
        let r = HoneyResponder::new(ResponsePolicy::NotifyOnly);
        let out = r.handle(&make_event(Some(1234), Some(555)));
        assert!(matches!(out.action, ResponseAction::None));
        assert_eq!(r.triggers_seen(), 1);
        assert_eq!(r.kills_attempted(), 0);
    }

    #[test]
    fn non_honey_event_is_ignored() {
        let r = HoneyResponder::new(ResponsePolicy::KillTrigger);
        let out = r.handle(&Event::VaultSealed {
            epoch: 0,
            backend: "soft".into(),
        });
        assert!(matches!(out.action, ResponseAction::None));
        assert_eq!(r.triggers_seen(), 0);
    }

    #[test]
    fn missing_start_time_refuses_to_kill() {
        let r = HoneyResponder::new(ResponsePolicy::KillTrigger);
        let out = r.handle(&make_event(Some(1234), None));
        assert!(
            matches!(out.action, ResponseAction::RefusedPidReuse { pid: 1234 }),
            "got {:?}",
            out.action
        );
        // No kill attempt counted: we refused before signalling.
        assert_eq!(r.kills_attempted(), 0);
    }

    #[test]
    fn missing_pid_takes_no_action() {
        let r = HoneyResponder::new(ResponsePolicy::KillTrigger);
        let out = r.handle(&make_event(None, Some(555)));
        assert!(matches!(out.action, ResponseAction::None));
        assert_eq!(r.kills_attempted(), 0);
    }

    #[test]
    fn current_start_time_for_self_succeeds() {
        let self_pid = std::process::id();
        let st = current_start_time(self_pid);
        assert!(st.is_some(), "current_start_time(self) should succeed");
        // Sanity: re-read should be stable.
        assert_eq!(st, current_start_time(self_pid));
    }

    #[test]
    fn pid_reuse_detected_via_mismatched_start_time() {
        // Use our own PID with a bogus captured start-time — the start-time
        // mismatch path triggers without us actually killing anything.
        let r = HoneyResponder::new(ResponsePolicy::KillTrigger);
        let self_pid = std::process::id();
        let real_start = current_start_time(self_pid).expect("self start-time");
        let bogus = real_start + 1; // guaranteed mismatch
        let out = r.handle(&make_event(Some(self_pid), Some(bogus)));
        assert!(
            matches!(out.action, ResponseAction::RefusedPidReuse { .. }),
            "got {:?}",
            out.action
        );
    }

    #[test]
    fn end_to_end_kill_via_subprocess() {
        // Spawn a `sleep` we own, capture its start-time, and run
        // KillTrigger against it.  Confirms the full kill path on Linux.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep is available on the test host");
        let pid = child.id();
        // Give /proc/<pid> a moment to populate.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let start = current_start_time(pid).expect("child stat");

        let r = HoneyResponder::new(ResponsePolicy::KillTrigger);
        let out = r.handle(&make_event(Some(pid), Some(start)));

        assert!(
            matches!(out.action, ResponseAction::Killed { .. }),
            "expected Killed; got {:?}",
            out.action
        );
        // Reap so the test framework doesn't see a zombie.
        let status = child.wait().expect("wait");
        assert!(!status.success(), "killed child should not exit 0");
    }
}
