//! Adversary capability tier classification — bench-hygiene metadata.
//!
//! # What this defeats
//!
//! Conflating scramble strength with adversary capability.  A
//! sandbox-equipped adversary that can `python3 -c` an expression
//! defeats *any* scramble that operates on syntactic form alone
//! (the `computed-secret` deprecated challenge demonstrated this:
//! `chr(115) + chr(105) + chr(108) + ...` survives every textual
//! scramble but the adversary just runs it).  The bench
//! measurement is only meaningful per-tier.
//!
//! Per [`BENCHMARK-DESIGN.md`] §"Adversary execution capability —
//! axis split", the bench MUST record which capability tier each
//! adversary had access to.  This module declares the canonical
//! enum.
//!
//! # Mechanism
//!
//! Three tiers, ordered by power:
//!
//! 1. **`TextOnly`** — adversary reads source and reasons; no
//!    execution.  Example: an API model with no tools.
//! 2. **`Sandboxed`** — adversary can run `python3`, `bash`, `node`
//!    on supplied source.  Example: an API model with a
//!    code-interpreter tool.
//! 3. **`Network`** — adversary can fetch arbitrary URLs while
//!    reasoning.  Example: an API model with `WebFetch` /
//!    browser-tool access.
//!
//! Each is a strict superset of the prior tier in observable
//! capability.  Bench cells must NOT be compared across tiers
//! without an explicit note in the summary; cross-tier comparisons
//! mix two confounded variables (scramble vs capability).

use serde::{Deserialize, Serialize};

/// What the adversary can do with the source they receive during
/// their reasoning step.
///
/// Recorded on [`crate::run_record::RunRecord`] for every attempt
/// so the summary can be filtered or grouped per-tier.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum AdversaryCapabilityTier {
    /// Adversary reads source and reasons in-context.  No
    /// execution, no tools that touch external state.
    TextOnly,
    /// Adversary can execute supplied source through a sandboxed
    /// interpreter or shell.  Most modern code-interpreter
    /// equipped LLMs.
    Sandboxed,
    /// Adversary can additionally make outbound network requests
    /// during reasoning.  Most browser-augmented LLMs and any
    /// agent harness with an unrestricted `WebFetch` / shell tool.
    Network,
}

impl AdversaryCapabilityTier {
    /// All three tiers in ascending-power order.  Useful for
    /// test fixtures and for the summary's tier-filter loop.
    pub const ALL: [AdversaryCapabilityTier; 3] = [
        AdversaryCapabilityTier::TextOnly,
        AdversaryCapabilityTier::Sandboxed,
        AdversaryCapabilityTier::Network,
    ];

    /// Stable kebab-case label used in summary rows and on the
    /// JSONL wire.  `text-only`, `sandboxed`, `network`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            AdversaryCapabilityTier::TextOnly => "text-only",
            AdversaryCapabilityTier::Sandboxed => "sandboxed",
            AdversaryCapabilityTier::Network => "network",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AdversaryCapabilityTier;

    #[test]
    fn labels_are_stable_kebab_case() {
        assert_eq!(AdversaryCapabilityTier::TextOnly.label(), "text-only");
        assert_eq!(AdversaryCapabilityTier::Sandboxed.label(), "sandboxed");
        assert_eq!(AdversaryCapabilityTier::Network.label(), "network");
    }

    #[test]
    fn all_contains_three_distinct_tiers() {
        let all = AdversaryCapabilityTier::ALL;
        assert_eq!(all.len(), 3);
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j], "duplicate tier at {i}/{j}");
            }
        }
    }

    #[test]
    fn json_round_trip_uses_kebab_case() {
        for tier in AdversaryCapabilityTier::ALL {
            let j = serde_json::to_string(&tier).unwrap();
            let label = tier.label();
            assert!(
                j.contains(label),
                "json {j} missing label {label}",
            );
            let back: AdversaryCapabilityTier =
                serde_json::from_str(&j).unwrap();
            assert_eq!(back, tier);
        }
    }

    #[test]
    fn json_decodes_known_labels() {
        let cases = [
            ("\"text-only\"", AdversaryCapabilityTier::TextOnly),
            ("\"sandboxed\"", AdversaryCapabilityTier::Sandboxed),
            ("\"network\"", AdversaryCapabilityTier::Network),
        ];
        for (raw, expected) in cases {
            let got: AdversaryCapabilityTier =
                serde_json::from_str(raw).unwrap();
            assert_eq!(got, expected, "{raw}");
        }
    }

    #[test]
    fn json_rejects_unknown_label() {
        let res: Result<AdversaryCapabilityTier, _> =
            serde_json::from_str("\"super-network\"");
        assert!(res.is_err(), "should reject unknown tier label");
    }
}
