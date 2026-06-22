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

use crate::layer_config::LayerConfig;
use crate::scoring::ScoreOutcome;

/// One attempt's worth of bench data, JSON-serializable.
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
}

impl RunRecord {
    /// Construct a new record.  All fields are required at
    /// construction time so the operator cannot accidentally file
    /// a partial outcome.
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
        }
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
}
