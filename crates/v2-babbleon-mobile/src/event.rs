//! The mobile event vocabulary and sink seam.
//!
//! # What this defeats
//!
//! Silent enforcement.  A tripwire is only useful if its hits are
//! observable; [`MobileEvent`] is the structured record and [`EventSink`]
//! is where the app routes them (logcat, an on-device telemetry buffer,
//! an SIEM upload).  This is the Android analogue of the Linux tier's
//! event model, minus everything Linux-welded: **no `/proc` start-time,
//! no JSONL file sink, no ed25519 audit chain** — those assume a
//! filesystem and a long-lived daemon the app model does not have.  The
//! app provides the sink; the crate provides the vocabulary and severity.

use crate::response::{ResolutionDecision, ResolutionOutcome};

/// A structured record of something the tripwire observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileEvent {
    /// A tracked canonical identifier was used verbatim (cached-knowledge
    /// attack).
    CanonicalNameUsed {
        /// The canonical identifier presented.
        name: String,
    },
    /// A decoy (honey) name was probed.
    DecoyNameUsed {
        /// The decoy name presented.
        name: String,
    },
    /// A scrambled compound resolved cleanly to its canonical identifier.
    NameResolved {
        /// The canonical identifier the compound resolved to.
        canonical: String,
    },
    /// The per-device mapping was rotated to a new epoch.
    MappingRotated {
        /// The new epoch now in force.
        epoch: u64,
    },
}

/// How urgent an event is, for routing / alerting on the app side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Routine, expected traffic.
    Info,
    /// An intrusion signal worth surfacing.
    Alert,
}

impl MobileEvent {
    /// The severity of this event.  Intrusion signals are [`Severity::Alert`];
    /// clean resolutions and rotations are [`Severity::Info`].
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            MobileEvent::CanonicalNameUsed { .. }
            | MobileEvent::DecoyNameUsed { .. } => Severity::Alert,
            MobileEvent::NameResolved { .. }
            | MobileEvent::MappingRotated { .. } => Severity::Info,
        }
    }

    /// Build the event that corresponds to a [`ResolutionDecision`] for a
    /// presented `name`, or `None` for an `Unknown` outcome (nothing to
    /// record — the name was unrelated to the obfuscated surface).
    #[must_use]
    pub fn from_decision(
        decision: &ResolutionDecision,
        name: &str,
    ) -> Option<MobileEvent> {
        match &decision.outcome {
            ResolutionOutcome::Resolved(canonical) => {
                Some(MobileEvent::NameResolved {
                    canonical: canonical.clone(),
                })
            }
            ResolutionOutcome::CanonicalNameUsed => {
                Some(MobileEvent::CanonicalNameUsed {
                    name: name.to_string(),
                })
            }
            ResolutionOutcome::DecoyNameUsed => Some(MobileEvent::DecoyNameUsed {
                name: name.to_string(),
            }),
            ResolutionOutcome::Unknown => None,
        }
    }
}

/// Where a consumer routes events.  The app implements this over logcat,
/// a ring buffer, or an upload path.
pub trait EventSink {
    /// Record one event.  Must not block the calling (dispatch) thread
    /// for long — the tripwire sits on a hot path.
    fn record(&self, event: &MobileEvent);
}

/// A sink that drops every event.  Useful as a default and in tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl EventSink for NullSink {
    fn record(&self, _event: &MobileEvent) {}
}

/// A sink that forwards each event to a closure — the simplest bridge to
/// an app-side logger without the app implementing the trait by hand.
pub struct CallbackSink<F: Fn(&MobileEvent)> {
    callback: F,
}

impl<F: Fn(&MobileEvent)> CallbackSink<F> {
    /// Wrap a closure as a sink.
    pub fn new(callback: F) -> Self {
        Self { callback }
    }
}

impl<F: Fn(&MobileEvent)> EventSink for CallbackSink<F> {
    fn record(&self, event: &MobileEvent) {
        (self.callback)(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::response::{DecisionAction, ResolutionDecision};
    use std::cell::RefCell;

    #[test]
    fn intrusion_events_are_alerts() {
        assert_eq!(
            MobileEvent::DecoyNameUsed { name: "x".into() }.severity(),
            Severity::Alert
        );
        assert_eq!(
            MobileEvent::CanonicalNameUsed { name: "x".into() }.severity(),
            Severity::Alert
        );
    }

    #[test]
    fn routine_events_are_info() {
        assert_eq!(
            MobileEvent::NameResolved { canonical: "netd".into() }.severity(),
            Severity::Info
        );
        assert_eq!(
            MobileEvent::MappingRotated { epoch: 4 }.severity(),
            Severity::Info
        );
    }

    #[test]
    fn unknown_outcome_yields_no_event() {
        let d = ResolutionDecision {
            outcome: ResolutionOutcome::Unknown,
            action: DecisionAction::Allow,
            is_intrusion: false,
        };
        assert_eq!(MobileEvent::from_decision(&d, "whatever"), None);
    }

    #[test]
    fn canonical_use_decision_maps_to_alert_event() {
        let d = ResolutionDecision {
            outcome: ResolutionOutcome::CanonicalNameUsed,
            action: DecisionAction::Deny,
            is_intrusion: true,
        };
        let ev = MobileEvent::from_decision(&d, "netd").unwrap();
        assert_eq!(ev, MobileEvent::CanonicalNameUsed { name: "netd".into() });
        assert_eq!(ev.severity(), Severity::Alert);
    }

    #[test]
    fn callback_sink_forwards_every_event() {
        let seen = RefCell::new(0u32);
        let sink = CallbackSink::new(|_e: &MobileEvent| {
            *seen.borrow_mut() += 1;
        });
        sink.record(&MobileEvent::MappingRotated { epoch: 1 });
        sink.record(&MobileEvent::DecoyNameUsed { name: "d".into() });
        assert_eq!(*seen.borrow(), 2);
    }

    #[test]
    fn null_sink_is_a_no_op() {
        NullSink.record(&MobileEvent::MappingRotated { epoch: 1 });
    }
}
