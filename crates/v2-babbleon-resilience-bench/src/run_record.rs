//! Persistable record of one evaluator attempt on one
//! `(challenge, layer_config)` cell.
//!
//! # What this defeats
//!
//! Bench result amnesia.  A bench run produces dozens of cells; the
//! operator's eventual decision ("ship L2+L3") cites the aggregate
//! crack-fraction at each cell, and that aggregate is only honest
//! if every individual attempt was logged with all the inputs that
//! produced it.  [`RunRecord`] is the on-disk record of one attempt;
//! the summary module reduces a list of these into the operator-
//! facing markdown table.
//!
//! # Mechanism
//!
//! One JSON file per `RunRecord` (or one JSONL file with many).
//! The schema:
//!
//! ```json
//! {
//!   "challenge_name": "auth-literal-string",
//!   "layer_config": { "layer2_keyword_scramble": true,
//!                     "layer3_whitespace_as_words": true,
//!                     "seed_byte": 171, "epoch": 0 },
//!   "evaluator_label": "claude-sonnet-4-6@2026-06-22",
//!   "attempt_index": 0,
//!   "outcome": "pass"
//! }
//! ```
//!
//! `evaluator_label` is operator-supplied (model id + run date), so
//! the summary table can break results down by model version and the
//! operator can re-run a previously-cracked cell against a newer
//! model without overwriting the historical data.
//!
//! # Threat model boundaries
//!
//! - Defeats: lost bench history.
//! - Does NOT defeat: an operator who edits the JSON by hand to
//!   change an outcome.  Bench files are not signed; the bench is a
//!   measurement tool, not a notarisation system.

use serde::{Deserialize, Serialize};

use crate::adversary_capability::AdversaryCapabilityTier;
use crate::layer_config::LayerConfig;
use crate::scoring::ScoreOutcome;

/// One attempt's worth of bench data, JSON-serializable.
///
/// # Schema-evolution discipline
///
/// New fields are added with `#[serde(default)]` so old JSONL logs
/// continue to parse.  Hygiene metadata fields (`wordlist_size`,
/// `adversary_capability_tier`, `disclosed`) are `Option`-wrapped
/// with default `None` so a caller that does not yet populate
/// them gets the same byte layout as the pre-hygiene record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunRecord {
    /// `Challenge::name` of the challenge that was scrambled.
    pub challenge_name: String,
    /// Layer config the source was scrambled under.
    pub layer_config: LayerConfig,
    /// Operator-supplied label naming the evaluator (model id, run
    /// date, agent harness).  Free-form text; the summary groups
    /// by exact-equality of this field.
    pub evaluator_label: String,
    /// 0-based attempt index within the `(challenge, config,
    /// evaluator)` tuple.  Lets multi-attempt sampling reduce to
    /// fraction-cracked.
    pub attempt_index: u32,
    /// Pass / Fail / `FormatError` as determined by [`crate::score`].
    pub outcome: ScoreOutcome,

    /// Bench-hygiene metadata: size of the wordlist the scramble
    /// drew from.  Smaller wordlists are subject to rainbow-table
    /// precomputation attacks the bench does not test for; the
    /// summary table can filter or warn on small wordlists.
    /// Defaults to `None` for back-compat with pre-hygiene records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wordlist_size: Option<usize>,

    /// Bench-hygiene metadata: what the adversary could do with
    /// the source.  See [`AdversaryCapabilityTier`] for the
    /// per-tier semantics.  Defaults to `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adversary_capability_tier: Option<AdversaryCapabilityTier>,

    /// Bench-hygiene metadata: did the prompt disclose which
    /// scramble layers were applied?
    ///
    /// Per `BENCHMARK-DESIGN.md` §"Layer-config disclosure
    /// decision", a disclosed-mode cell measures the
    /// recognition-floor (the adversary can see L7 is active and
    /// may give up); an undisclosed-mode cell measures naive
    /// attack rate.  The gap between the two characterises the
    /// layer's resistance against an adversary unaware of the
    /// construction.  Defaults to `None` (mode not recorded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosed: Option<bool>,
}

impl RunRecord {
    /// Construct a new record.  All required fields are taken at
    /// construction time so the operator cannot accidentally file
    /// a partial outcome.  Hygiene fields default to `None`; use
    /// the builder methods [`Self::with_wordlist_size`],
    /// [`Self::with_adversary_capability_tier`], and
    /// [`Self::with_disclosed`] to populate them.
    #[must_use]
    pub fn new(
        challenge_name: impl Into<String>,
        layer_config: LayerConfig,
        evaluator_label: impl Into<String>,
        attempt_index: u32,
        outcome: ScoreOutcome,
    ) -> Self {
        Self {
            challenge_name: challenge_name.into(),
            layer_config,
            evaluator_label: evaluator_label.into(),
            attempt_index,
            outcome,
            wordlist_size: None,
            adversary_capability_tier: None,
            disclosed: None,
        }
    }

    /// Builder: attach the wordlist size used to derive the
    /// scramble.  Returns `self` so the call chains.
    #[must_use]
    pub fn with_wordlist_size(mut self, size: usize) -> Self {
        self.wordlist_size = Some(size);
        self
    }

    /// Builder: attach the adversary's capability tier.
    #[must_use]
    pub fn with_adversary_capability_tier(
        mut self,
        tier: AdversaryCapabilityTier,
    ) -> Self {
        self.adversary_capability_tier = Some(tier);
        self
    }

    /// Builder: attach the layer-config-disclosure mode.  `true`
    /// means the prompt told the adversary which layers were
    /// applied; `false` means undisclosed.
    #[must_use]
    pub fn with_disclosed(mut self, disclosed: bool) -> Self {
        self.disclosed = Some(disclosed);
        self
    }

    /// Render this record as one JSONL line (object + trailing `\n`).
    /// Used by callers that append records to a long-running bench
    /// log file.
    ///
    /// # Errors
    ///
    /// `Error::SerdeJson` if serialization fails — should be
    /// effectively impossible for this fixed schema.
    pub fn to_jsonl(&self) -> crate::errors::Result<String> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Parse a list of records from a JSONL string (one JSON object
    /// per non-blank line).  Blank lines are silently skipped.
    ///
    /// # Errors
    ///
    /// `Error::SerdeJson` if any non-blank line fails to parse.
    pub fn from_jsonl(s: &str) -> crate::errors::Result<Vec<Self>> {
        let mut out = Vec::new();
        for line in s.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let record: Self = serde_json::from_str(line)?;
            out.push(record);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::RunRecord;
    use crate::layer_config::LayerConfig;
    use crate::scoring::ScoreOutcome;

    #[test]
    fn new_and_field_round_trip() {
        let r = RunRecord::new(
            "auth-literal-string",
            LayerConfig::l2_plus_l3(),
            "claude-sonnet-4-6@2026-06-22",
            7,
            ScoreOutcome::Fail,
        );
        assert_eq!(r.challenge_name, "auth-literal-string");
        assert_eq!(r.layer_config, LayerConfig::l2_plus_l3());
        assert_eq!(r.evaluator_label, "claude-sonnet-4-6@2026-06-22");
        assert_eq!(r.attempt_index, 7);
        assert_eq!(r.outcome, ScoreOutcome::Fail);
    }

    #[test]
    fn json_round_trip() {
        let r = RunRecord::new(
            "x",
            LayerConfig::l3_only(),
            "adv",
            0,
            ScoreOutcome::Pass,
        );
        let j = serde_json::to_string(&r).unwrap();
        let back: RunRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn jsonl_round_trip_three_records() {
        let records = vec![
            RunRecord::new(
                "c1",
                LayerConfig::l2_only(),
                "adv-a",
                0,
                ScoreOutcome::Pass,
            ),
            RunRecord::new(
                "c1",
                LayerConfig::l2_only(),
                "adv-a",
                1,
                ScoreOutcome::Fail,
            ),
            RunRecord::new(
                "c2",
                LayerConfig::l3_only(),
                "adv-b",
                0,
                ScoreOutcome::FormatError,
            ),
        ];
        let mut buf = String::new();
        for r in &records {
            buf.push_str(&r.to_jsonl().unwrap());
        }
        let back = RunRecord::from_jsonl(&buf).unwrap();
        assert_eq!(back, records);
    }

    #[test]
    fn jsonl_skips_blank_lines() {
        let r = RunRecord::new(
            "x",
            LayerConfig::baseline_no_scramble(),
            "y",
            0,
            ScoreOutcome::Pass,
        );
        let line = r.to_jsonl().unwrap();
        let buf = format!("\n\n{line}\n\n");
        let back = RunRecord::from_jsonl(&buf).unwrap();
        assert_eq!(back, vec![r]);
    }

    #[test]
    fn jsonl_parse_propagates_malformed_line() {
        let err = RunRecord::from_jsonl("not json").unwrap_err();
        match err {
            crate::errors::Error::SerdeJson { message } => {
                assert!(!message.is_empty());
            }
            other => panic!("expected SerdeJson, got {other:?}"),
        }
    }

    // ----- Bench-hygiene metadata (wordlist_size,
    //        adversary_capability_tier, disclosed) -----

    #[test]
    fn new_record_has_none_hygiene_fields_by_default() {
        let r = RunRecord::new(
            "x",
            LayerConfig::l2_plus_l3(),
            "y",
            0,
            ScoreOutcome::Pass,
        );
        assert!(r.wordlist_size.is_none());
        assert!(r.adversary_capability_tier.is_none());
        assert!(r.disclosed.is_none());
    }

    #[test]
    fn with_wordlist_size_builder_sets_field() {
        let r = RunRecord::new(
            "x",
            LayerConfig::l3_only(),
            "y",
            0,
            ScoreOutcome::Pass,
        )
        .with_wordlist_size(369_652);
        assert_eq!(r.wordlist_size, Some(369_652));
    }

    #[test]
    fn with_adversary_capability_tier_builder_sets_field() {
        use crate::adversary_capability::AdversaryCapabilityTier;
        for tier in AdversaryCapabilityTier::ALL {
            let r = RunRecord::new(
                "x",
                LayerConfig::baseline_no_scramble(),
                "y",
                0,
                ScoreOutcome::Pass,
            )
            .with_adversary_capability_tier(tier);
            assert_eq!(r.adversary_capability_tier, Some(tier));
        }
    }

    #[test]
    fn with_disclosed_builder_sets_field() {
        for disclosed in [true, false] {
            let r = RunRecord::new(
                "x",
                LayerConfig::l2_only(),
                "y",
                0,
                ScoreOutcome::Pass,
            )
            .with_disclosed(disclosed);
            assert_eq!(r.disclosed, Some(disclosed));
        }
    }

    #[test]
    fn builders_chain_through_all_three_hygiene_fields() {
        use crate::adversary_capability::AdversaryCapabilityTier;
        let r = RunRecord::new(
            "c",
            LayerConfig::l2_plus_l3(),
            "adv",
            3,
            ScoreOutcome::Pass,
        )
        .with_wordlist_size(370_000)
        .with_adversary_capability_tier(AdversaryCapabilityTier::Sandboxed)
        .with_disclosed(true);
        assert_eq!(r.wordlist_size, Some(370_000));
        assert_eq!(
            r.adversary_capability_tier,
            Some(AdversaryCapabilityTier::Sandboxed),
        );
        assert_eq!(r.disclosed, Some(true));
        // Core fields preserved.
        assert_eq!(r.challenge_name, "c");
        assert_eq!(r.attempt_index, 3);
        assert_eq!(r.outcome, ScoreOutcome::Pass);
    }

    #[test]
    fn json_round_trip_preserves_populated_hygiene_fields() {
        use crate::adversary_capability::AdversaryCapabilityTier;
        let r = RunRecord::new(
            "c",
            LayerConfig::l2_plus_l3(),
            "adv",
            0,
            ScoreOutcome::Pass,
        )
        .with_wordlist_size(100_000)
        .with_adversary_capability_tier(AdversaryCapabilityTier::Network)
        .with_disclosed(false);
        let j = serde_json::to_string(&r).unwrap();
        // Schema spot-check: the kebab-case field names appear and
        // the tier serializes by its kebab-case label.
        assert!(j.contains("\"wordlist_size\":100000"), "{j}");
        assert!(j.contains("\"adversary_capability_tier\":\"network\""), "{j}");
        assert!(j.contains("\"disclosed\":false"), "{j}");
        let back: RunRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn json_omits_hygiene_fields_when_none() {
        // skip_serializing_if = Option::is_none keeps the wire-
        // format unchanged for pre-hygiene-using callers.  This
        // protects existing JSONL log files from re-serialization
        // drift.
        let r = RunRecord::new(
            "c",
            LayerConfig::l2_plus_l3(),
            "adv",
            0,
            ScoreOutcome::Pass,
        );
        let j = serde_json::to_string(&r).unwrap();
        assert!(!j.contains("wordlist_size"), "{j}");
        assert!(!j.contains("adversary_capability_tier"), "{j}");
        assert!(!j.contains("disclosed"), "{j}");
    }

    #[test]
    fn json_parses_old_records_without_hygiene_fields() {
        // The pre-hygiene wire format must still parse — back-compat
        // promise for the on-disk JSONL files the operator already
        // has from prior bench runs.
        let raw = r#"{
            "challenge_name": "c",
            "layer_config": {
                "layer2_keyword_scramble": true,
                "layer2b_operator_scramble": false,
                "layer3_whitespace_as_words": true,
                "layer7_secret_literal": false,
                "seed_byte": 0,
                "epoch": 0
            },
            "evaluator_label": "old-adv",
            "attempt_index": 0,
            "outcome": "pass"
        }"#;
        let r: RunRecord = serde_json::from_str(raw).unwrap();
        assert_eq!(r.challenge_name, "c");
        assert!(r.wordlist_size.is_none());
        assert!(r.adversary_capability_tier.is_none());
        assert!(r.disclosed.is_none());
    }

    #[test]
    fn json_parses_new_records_with_all_hygiene_fields() {
        use crate::adversary_capability::AdversaryCapabilityTier;
        let raw = r#"{
            "challenge_name": "c",
            "layer_config": {
                "layer2_keyword_scramble": true,
                "layer2b_operator_scramble": false,
                "layer3_whitespace_as_words": true,
                "layer7_secret_literal": false,
                "seed_byte": 0,
                "epoch": 0
            },
            "evaluator_label": "new-adv",
            "attempt_index": 7,
            "outcome": "fail",
            "wordlist_size": 250000,
            "adversary_capability_tier": "sandboxed",
            "disclosed": true
        }"#;
        let r: RunRecord = serde_json::from_str(raw).unwrap();
        assert_eq!(r.wordlist_size, Some(250_000));
        assert_eq!(
            r.adversary_capability_tier,
            Some(AdversaryCapabilityTier::Sandboxed),
        );
        assert_eq!(r.disclosed, Some(true));
    }
}
