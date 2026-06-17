//! Tripwire response policy.
//!
//! # What this defeats
//!
//! Detection without response is just telemetry.  A tripwire firing
//! means an attacker is interactively probing the scrambled namespace;
//! the responder is what converts that signal into an action
//! (kill the offending process, quarantine it, escalate to SIEM).
//!
//! # Mechanism
//!
//! - [`TripwireResponsePolicy`] is the operator-configurable policy
//!   knob: what to do when a [`crate::Event::Tripwire`] fires.
//! - [`TripwireResponder`] is the trait the daemon-side actor
//!   implements.  This crate only defines the abstraction and a
//!   policy-only [`LogOnlyResponder`]; the syscall-level responders
//!   (kill, quarantine) live in the launcher crate where the
//!   necessary capabilities are held.
//!
//! # Trust placement
//!
//! Responders run in the daemon process, which is the only Babbleon
//! component that holds the credentials to act on PIDs (signal
//! permission via matching uid, or `CAP_KILL` for cross-uid signals).
//! The runtime preprocessor and the wrapper template MUST NOT act
//! directly; they only report.
//!
//! # PID-reuse defence
//!
//! Every responder MUST re-read `/proc/<pid>/stat` start-time before
//! signalling.  The [`crate::Event::Tripwire`] carries
//! `triggering_pid_start` for exactly this comparison; if the recorded
//! start-time does not match the current value, the PID has been
//! reused since the tripwire fired and the responder MUST NOT act.

use serde::{Deserialize, Serialize};

use crate::events::Event;

/// What the responder should do on a tripwire.
///
/// Names mirror the v1 enum but with one rename: v1's `KillTrigger`
/// becomes `KillTriggeringProcess` to make the target unambiguous in
/// audit logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TripwireResponsePolicy {
    /// Emit the event; take no further action.  Default for new
    /// deployments — operators opt in to active response.
    NotifyOnly,
    /// Send SIGKILL to the triggering process.  PID-reuse re-check
    /// is mandatory in the responder.
    KillTriggeringProcess,
    /// Send SIGKILL to the triggering process and every descendant
    /// in its process tree.  Use when the attacker may have already
    /// forked workers.
    KillTriggeringProcessTree,
    /// Move the triggering process into an isolated network
    /// namespace with no routes.  Preserves forensic state.
    Quarantine,
    /// Forward to the configured SIEM sink.  Does not kill or
    /// quarantine; pairs with one of the above on a multi-policy
    /// deployment.
    SystemAlert,
}

impl Default for TripwireResponsePolicy {
    fn default() -> Self {
        Self::NotifyOnly
    }
}

/// A responder consumes a single [`Event::Tripwire`] and applies the
/// configured policy.
///
/// Implementations are typically `Send + Sync` because the daemon
/// drives them from the FIFO reader thread; this crate does not
/// enforce that bound at the trait level (lets a test responder be
/// `!Send`), but production responders SHOULD satisfy it.
pub trait TripwireResponder {
    /// React to a tripwire.  Events that are not `Event::Tripwire`
    /// MUST be ignored.
    fn react(&self, event: &Event);
}

/// Policy-only responder: records the policy that would have been
/// applied but takes no syscall-level action.  Used in tests and in
/// the `NotifyOnly` deployment path.
pub struct LogOnlyResponder {
    policy: TripwireResponsePolicy,
}

impl LogOnlyResponder {
    /// Construct a responder configured with `policy`.
    #[must_use]
    pub fn new(policy: TripwireResponsePolicy) -> Self {
        Self { policy }
    }

    /// Return the configured policy.
    #[must_use]
    pub fn policy(&self) -> TripwireResponsePolicy {
        self.policy
    }
}

impl TripwireResponder for LogOnlyResponder {
    fn react(&self, event: &Event) {
        if let Event::Tripwire { epoch, source, names, triggering_pid, .. } =
            event
        {
            tracing::warn!(
                target: "babbleon.tripwire",
                ?source,
                epoch,
                names = ?names,
                triggering_pid = ?triggering_pid,
                policy = ?self.policy,
                "tripwire fired",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TripwireSource;

    fn tripwire() -> Event {
        Event::Tripwire {
            epoch: 1,
            source: TripwireSource::Stale,
            names: vec!["x".into()],
            wrapper_pid: 1,
            triggering_pid: Some(2),
            triggering_pid_start: Some(0),
        }
    }

    #[test]
    fn default_policy_is_notify_only() {
        assert_eq!(
            TripwireResponsePolicy::default(),
            TripwireResponsePolicy::NotifyOnly,
        );
    }

    #[test]
    fn log_only_responder_does_not_panic_on_non_tripwire() {
        let r = LogOnlyResponder::new(TripwireResponsePolicy::KillTriggeringProcess);
        r.react(&Event::RotationComplete { old_epoch: 0, new_epoch: 1 });
        r.react(&tripwire());
    }

    #[test]
    fn policy_serializes_as_kebab_case() {
        let p = TripwireResponsePolicy::KillTriggeringProcessTree;
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, "\"kill-triggering-process-tree\"");
    }
}
