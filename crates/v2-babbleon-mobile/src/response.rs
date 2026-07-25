//! The name-resolution tripwire: turn a name an agent wants to use into
//! a policy decision.
//!
//! # What this defeats
//!
//! The core Babbleon attack on Android: an agent that reaches for a
//! capability by its **canonical** name (cached knowledge), or probes a
//! **decoy** name.  [`resolve_name`] classifies the name against the
//! per-device table and returns a [`ResolutionDecision`] the caller acts
//! on.  It decides; it does not act — acting (deny, terminate) is the
//! Android layer's job via the [`crate::enforcement`] seam, because
//! "terminate a process" has no portable, in-crate meaning.

use crate::mapping_handle::MobileMapping;

/// What the presented name turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionOutcome {
    /// A live scrambled compound for this epoch.  Carries the canonical
    /// identifier the runtime should actually dispatch to.
    Resolved(String),
    /// The **canonical** identifier, used directly — the cached-knowledge
    /// attack Babbleon exists to catch.
    CanonicalNameUsed,
    /// A decoy (honey) name — nothing legitimate ever uses one, so this
    /// is an unambiguous intrusion signal.
    DecoyNameUsed,
    /// Not tracked, not a decoy, not a live compound.  Unrelated to the
    /// obfuscated surface; pass through.
    Unknown,
}

/// What the caller must do about a resolution, per the active policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionAction {
    /// Proceed with the dispatch (a resolved compound, or an unrelated
    /// name).
    Allow,
    /// Refuse the resolution but let the caller keep running.
    Deny,
    /// Refuse and tear the caller down.
    Terminate,
}

/// How aggressively to answer an intrusion signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsePolicy {
    /// Observe only — record the event, take no action.  For rollout /
    /// shadow mode.
    LogOnly,
    /// Deny the resolution on an intrusion signal; keep the caller alive.
    DenyResolution,
    /// Terminate the caller on an intrusion signal.
    TerminateCaller,
}

/// The classification plus the action the policy dictates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionDecision {
    /// What the name was.
    pub outcome: ResolutionOutcome,
    /// What to do about it.
    pub action: DecisionAction,
    /// True iff this decision represents an intrusion signal (a decoy or
    /// a direct canonical-name use), regardless of the action the policy
    /// chose.  Lets telemetry count attempts even in `LogOnly` mode.
    pub is_intrusion: bool,
}

/// Classify `name` against `mapping` and apply `policy`.
///
/// Resolution order is deliberate: a live scrambled compound wins first
/// (the fast, legitimate path), then decoys, then a direct canonical-name
/// use, then unknown.  A legitimate caller only ever presents scrambled
/// compounds, so every other branch is, to some degree, suspicious.
#[must_use]
pub fn resolve_name(
    mapping: &MobileMapping,
    name: &str,
    policy: ResponsePolicy,
) -> ResolutionDecision {
    if let Some(canonical) = mapping.reveal(name) {
        return ResolutionDecision {
            outcome: ResolutionOutcome::Resolved(canonical.to_string()),
            action: DecisionAction::Allow,
            is_intrusion: false,
        };
    }
    if mapping.is_decoy(name) {
        return intrusion(ResolutionOutcome::DecoyNameUsed, policy);
    }
    if mapping.scramble(name).is_some() {
        // The name is a tracked canonical identifier used verbatim.
        return intrusion(ResolutionOutcome::CanonicalNameUsed, policy);
    }
    ResolutionDecision {
        outcome: ResolutionOutcome::Unknown,
        action: DecisionAction::Allow,
        is_intrusion: false,
    }
}

fn intrusion(
    outcome: ResolutionOutcome,
    policy: ResponsePolicy,
) -> ResolutionDecision {
    let action = match policy {
        ResponsePolicy::LogOnly => DecisionAction::Allow,
        ResponsePolicy::DenyResolution => DecisionAction::Deny,
        ResponsePolicy::TerminateCaller => DecisionAction::Terminate,
    };
    ResolutionDecision {
        outcome,
        action,
        is_intrusion: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tools() -> Vec<String> {
        ["activity", "package", "netd", "wifi"]
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }

    fn mapping() -> MobileMapping {
        MobileMapping::from_device_secret(&[11u8; 32], &tools(), 5).unwrap()
    }

    #[test]
    fn scrambled_compound_resolves_and_is_allowed() {
        let m = mapping();
        let scrambled = m.scramble("netd").unwrap().to_string();
        let d = resolve_name(&m, &scrambled, ResponsePolicy::TerminateCaller);
        assert_eq!(d.outcome, ResolutionOutcome::Resolved("netd".into()));
        assert_eq!(d.action, DecisionAction::Allow);
        assert!(!d.is_intrusion);
    }

    #[test]
    fn canonical_name_used_directly_is_an_intrusion() {
        let m = mapping();
        let d = resolve_name(&m, "netd", ResponsePolicy::DenyResolution);
        assert_eq!(d.outcome, ResolutionOutcome::CanonicalNameUsed);
        assert_eq!(d.action, DecisionAction::Deny);
        assert!(d.is_intrusion);
    }

    #[test]
    fn unknown_name_passes_through() {
        let m = mapping();
        let d = resolve_name(&m, "com.example.unrelated", ResponsePolicy::TerminateCaller);
        assert_eq!(d.outcome, ResolutionOutcome::Unknown);
        assert_eq!(d.action, DecisionAction::Allow);
        assert!(!d.is_intrusion);
    }

    #[test]
    fn log_only_records_intrusion_but_allows() {
        let m = mapping();
        let d = resolve_name(&m, "netd", ResponsePolicy::LogOnly);
        assert!(d.is_intrusion);
        assert_eq!(d.action, DecisionAction::Allow);
    }

    #[test]
    fn terminate_policy_tears_down_on_canonical_use() {
        let m = mapping();
        let d = resolve_name(&m, "wifi", ResponsePolicy::TerminateCaller);
        assert_eq!(d.action, DecisionAction::Terminate);
    }
}
