//! The enforcement seam — traits the Android layer implements to give a
//! [`crate::response::DecisionAction`] teeth.
//!
//! # What this defeats
//!
//! A decision with no consequence.  [`resolve_name`](crate::response::resolve_name)
//! decides *what* to do (`Allow` / `Deny` / `Terminate`), but "deny a
//! binder resolution" and "terminate this process" have no portable,
//! in-crate implementation — they are Android mechanisms
//! (`SecurityException`, `Process.killProcess`, a binder transaction
//! rejection).  This module defines the *contract* for those mechanisms
//! so the crate can drive them without owning them, and
//! [`enforce`] wires a decision to that contract in one place.
//!
//! Keeping the mechanism above the FFI, behind these traits, is the same
//! discipline the Linux tier uses (its responder is a trait the daemon
//! implements) and is what lets this crate stay pure and host-testable.

use crate::event::{EventSink, MobileEvent};
use crate::response::{DecisionAction, ResolutionDecision};

/// Refuses a name resolution without killing the caller.  The app
/// implements this over whatever its dispatch layer uses to say "no"
/// (a binder `SecurityException`, a null service handle, an error code).
pub trait ResolutionGuard {
    /// Deny the resolution of `name`.  `reason` is a short, non-secret
    /// string for the app's own logging.
    fn deny(&self, name: &str, reason: &str);
}

/// Tears the offending caller down.  The app implements this over
/// `android.os.Process.killProcess`, a watchdog signal, or a policy
/// escalation.  Separate from [`ResolutionGuard`] because termination is
/// a strictly higher-privilege action an app may gate differently.
pub trait CallerTerminator {
    /// Terminate the current caller.  `reason` is a short, non-secret
    /// string for the app's own logging.
    fn terminate(&self, reason: &str);
}

/// Apply a [`ResolutionDecision`] for a presented `name`: record the
/// corresponding event (if any) to `sink`, then invoke the guard or
/// terminator the action calls for.
///
/// This is the single place a decision becomes an effect, so the app's
/// only responsibility is to supply correct trait implementations.
pub fn enforce(
    decision: &ResolutionDecision,
    name: &str,
    sink: &dyn EventSink,
    guard: &dyn ResolutionGuard,
    terminator: &dyn CallerTerminator,
) {
    if let Some(event) = MobileEvent::from_decision(decision, name) {
        sink.record(&event);
    }
    match decision.action {
        DecisionAction::Allow => {}
        DecisionAction::Deny => guard.deny(name, describe(decision)),
        DecisionAction::Terminate => terminator.terminate(describe(decision)),
    }
}

fn describe(decision: &ResolutionDecision) -> &'static str {
    use crate::response::ResolutionOutcome as O;
    match decision.outcome {
        O::CanonicalNameUsed => "canonical identifier used directly",
        O::DecoyNameUsed => "decoy name probed",
        O::Resolved(_) => "resolved",
        O::Unknown => "unknown name",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::MobileEvent;
    use crate::response::{ResolutionDecision, ResolutionOutcome};
    use std::cell::RefCell;

    #[derive(Default)]
    struct Spy {
        events: RefCell<Vec<MobileEvent>>,
        denied: RefCell<Vec<String>>,
        terminated: RefCell<Vec<String>>,
    }
    impl EventSink for Spy {
        fn record(&self, e: &MobileEvent) {
            self.events.borrow_mut().push(e.clone());
        }
    }
    impl ResolutionGuard for Spy {
        fn deny(&self, name: &str, _reason: &str) {
            self.denied.borrow_mut().push(name.to_string());
        }
    }
    impl CallerTerminator for Spy {
        fn terminate(&self, reason: &str) {
            self.terminated.borrow_mut().push(reason.to_string());
        }
    }

    fn decision(
        outcome: ResolutionOutcome,
        action: DecisionAction,
        is_intrusion: bool,
    ) -> ResolutionDecision {
        ResolutionDecision {
            outcome,
            action,
            is_intrusion,
        }
    }

    #[test]
    fn allow_records_but_takes_no_action() {
        let spy = Spy::default();
        let d = decision(
            ResolutionOutcome::Resolved("netd".into()),
            DecisionAction::Allow,
            false,
        );
        enforce(&d, "scrambled", &spy, &spy, &spy);
        assert_eq!(spy.events.borrow().len(), 1);
        assert!(spy.denied.borrow().is_empty());
        assert!(spy.terminated.borrow().is_empty());
    }

    #[test]
    fn deny_calls_the_guard() {
        let spy = Spy::default();
        let d = decision(
            ResolutionOutcome::DecoyNameUsed,
            DecisionAction::Deny,
            true,
        );
        enforce(&d, "honey42", &spy, &spy, &spy);
        assert_eq!(spy.denied.borrow().as_slice(), &["honey42".to_string()]);
        assert!(spy.terminated.borrow().is_empty());
    }

    #[test]
    fn terminate_calls_the_terminator() {
        let spy = Spy::default();
        let d = decision(
            ResolutionOutcome::CanonicalNameUsed,
            DecisionAction::Terminate,
            true,
        );
        enforce(&d, "netd", &spy, &spy, &spy);
        assert_eq!(spy.terminated.borrow().len(), 1);
        assert!(spy.denied.borrow().is_empty());
    }

    #[test]
    fn unknown_outcome_records_no_event() {
        let spy = Spy::default();
        let d = decision(
            ResolutionOutcome::Unknown,
            DecisionAction::Allow,
            false,
        );
        enforce(&d, "unrelated", &spy, &spy, &spy);
        assert!(spy.events.borrow().is_empty());
    }
}
