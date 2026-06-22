//! Reduce a list of [`RunRecord`]s into the operator-facing
//! markdown table.
//!
//! # What this defeats
//!
//! Operator hand-aggregation of per-cell crack fractions.  A bench
//! produces (challenges × `layer_configs` × adversaries × attempts)
//! rows; the operator's decision wants one number per
//! `(challenge, layer_config)` pair per evaluator.  This module is
//! the single audited aggregation point.
//!
//! # Mechanism
//!
//! 1. Group records by `(challenge_name, layer_config, evaluator_label)`.
//! 2. Per group, compute `crack_fraction = pass_count / total_count`
//!    where `total_count` excludes `FormatError` outcomes (a model
//!    that cannot follow the prompt format is not the same as a
//!    model that tried and failed — calling format errors `Fail`
//!    would understate model capability).
//! 3. Emit a markdown table with one row per
//!    `(challenge, layer_config)` and one column per evaluator
//!    label, each cell showing `pass / total` plus the percentage.
//!
//! # Threat model boundaries
//!
//! - Defeats: aggregation bugs.
//! - Does NOT defeat: cherry-picking — an operator who deletes
//!   `Fail` records before invoking the aggregator gets inflated
//!   crack fractions.  The bench is a measurement tool, not an
//!   adversarial audit.

use std::collections::BTreeMap;

use crate::run_record::RunRecord;
use crate::scoring::ScoreOutcome;

/// One aggregated cell of the summary table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellSummary {
    /// Number of `ScoreOutcome::Pass` records in this group.
    pub pass_count: u32,
    /// Number of `ScoreOutcome::Fail` records in this group.
    pub fail_count: u32,
    /// Number of `ScoreOutcome::FormatError` records in this group.
    /// Reported separately so the operator can spot a model whose
    /// JSON discipline is weak.
    pub format_error_count: u32,
    /// Number of `ScoreOutcome::RefusedByPolicy` records in this
    /// group.  Reported separately so safety-filter trips do not
    /// inflate or deflate the crack-fraction; the bench measures
    /// scramble strength, not provider safety tuning.
    pub refused_by_policy_count: u32,
}

impl CellSummary {
    /// Total attempts whose outcome counted toward
    /// `crack_fraction` (excludes format errors and policy refusals).
    #[must_use]
    pub fn graded_count(&self) -> u32 {
        self.pass_count + self.fail_count
    }

    /// Fraction in `[0, 1]` of *graded* attempts that cracked the
    /// scramble.  Returns `None` if no attempts were graded (all
    /// were format errors / policy refusals / there were zero
    /// records).
    #[must_use]
    pub fn crack_fraction(&self) -> Option<f64> {
        let graded = self.graded_count();
        if graded == 0 {
            None
        } else {
            Some(f64::from(self.pass_count) / f64::from(graded))
        }
    }
}

/// Aggregate a flat list of `RunRecord`s into the table cells.
/// The returned `BTreeMap` is keyed by `(challenge_name,
/// layer_config_label, evaluator_label)` so the row + column order
/// in the rendered table is deterministic.
#[must_use]
pub fn aggregate(
    records: &[RunRecord],
) -> BTreeMap<(String, String, String), CellSummary> {
    let mut cells: BTreeMap<(String, String, String), CellSummary> =
        BTreeMap::new();
    for r in records {
        let key = (
            r.challenge_name.clone(),
            r.layer_config.label(),
            r.evaluator_label.clone(),
        );
        let cell = cells.entry(key).or_insert(CellSummary {
            pass_count: 0,
            fail_count: 0,
            format_error_count: 0,
            refused_by_policy_count: 0,
        });
        match r.outcome {
            ScoreOutcome::Pass => cell.pass_count += 1,
            ScoreOutcome::Fail => cell.fail_count += 1,
            ScoreOutcome::FormatError => cell.format_error_count += 1,
            ScoreOutcome::RefusedByPolicy => {
                cell.refused_by_policy_count += 1;
            }
        }
    }
    cells
}

/// Render the bench results as a markdown table the operator can
/// paste into HANDOFF.md.  One header row per evaluator label; one
/// body row per `(challenge_name, layer_config_label)` pair.
///
/// Cell format: `cracked/graded (XX%) [+E fmt-err]` where `E` is
/// the format-error count and the suffix is omitted if `E == 0`.
///
/// If `records` is empty, returns a fenced placeholder so the
/// operator-facing rendering is consistent.
#[must_use]
pub fn render_markdown(records: &[RunRecord]) -> String {
    if records.is_empty() {
        return "_(no bench records)_\n".to_string();
    }
    let cells = aggregate(records);

    // Collect distinct challenge/config rows and evaluator
    // columns, preserving sorted order from the BTreeMap keys.
    let mut rows: Vec<(String, String)> = cells
        .keys()
        .map(|(c, l, _)| (c.clone(), l.clone()))
        .collect();
    rows.sort();
    rows.dedup();
    let mut cols: Vec<String> =
        cells.keys().map(|(_, _, a)| a.clone()).collect();
    cols.sort();
    cols.dedup();

    let mut out = String::new();
    // Header.
    out.push_str("| challenge | layer config |");
    for adv in &cols {
        out.push(' ');
        out.push_str(adv);
        out.push_str(" |");
    }
    out.push('\n');
    out.push_str("|---|---|");
    for _ in &cols {
        out.push_str("---|");
    }
    out.push('\n');

    for (challenge, label) in &rows {
        out.push_str("| ");
        out.push_str(challenge);
        out.push_str(" | ");
        out.push_str(label);
        out.push_str(" |");
        for adv in &cols {
            let key = (challenge.clone(), label.clone(), adv.clone());
            let cell_text = match cells.get(&key) {
                Some(cell) => format_cell(cell),
                None => "—".to_string(),
            };
            out.push(' ');
            out.push_str(&cell_text);
            out.push_str(" |");
        }
        out.push('\n');
    }
    out
}

/// Render one `CellSummary` as the table cell body text.
fn format_cell(cell: &CellSummary) -> String {
    let graded = cell.graded_count();
    let mut suffix = String::new();
    if cell.format_error_count > 0 {
        use std::fmt::Write as _;
        let _ = write!(
            suffix,
            " [+{} fmt-err]",
            cell.format_error_count,
        );
    }
    if cell.refused_by_policy_count > 0 {
        use std::fmt::Write as _;
        let _ = write!(
            suffix,
            " [+{} refused]",
            cell.refused_by_policy_count,
        );
    }
    match cell.crack_fraction() {
        None => format!("0/0 (n/a){suffix}"),
        Some(frac) => {
            // Round to nearest integer percent.  `frac` is in [0, 1]
            // (enforced by construction: pass_count <= graded_count
            // <= u32::MAX, so the product fits a u32 and the cast
            // cannot overflow or lose sign).
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            let pct = (frac * 100.0).round() as u32;
            format!(
                "{cracked}/{graded} ({pct}%){suffix}",
                cracked = cell.pass_count,
            )
        }
    }
}

/// Convenience: render a single-evaluator, single-layer-config
/// fraction as a one-line summary string.  Used by tests and by
/// callers that want the headline number for one cell without
/// rebuilding the whole table.
#[must_use]
pub fn render_single_cell_fraction(
    cell: &CellSummary,
) -> String {
    format_cell(cell)
}

#[cfg(test)]
mod tests {
    use super::{aggregate, render_markdown, CellSummary};
    use crate::layer_config::LayerConfig;
    use crate::run_record::RunRecord;
    use crate::scoring::ScoreOutcome;

    fn make_record(
        challenge: &str,
        cfg: LayerConfig,
        adv: &str,
        idx: u32,
        outcome: ScoreOutcome,
    ) -> RunRecord {
        RunRecord::new(challenge, cfg, adv, idx, outcome)
    }

    #[test]
    fn cell_summary_crack_fraction_basic() {
        let cell = CellSummary {
            pass_count: 3,
            fail_count: 7,
            format_error_count: 0,
            refused_by_policy_count: 0,
        };
        assert_eq!(cell.graded_count(), 10);
        assert!((cell.crack_fraction().unwrap() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn cell_summary_excludes_format_errors_from_graded_count() {
        let cell = CellSummary {
            pass_count: 1,
            fail_count: 1,
            format_error_count: 8,
            refused_by_policy_count: 0,
        };
        assert_eq!(cell.graded_count(), 2);
        assert!((cell.crack_fraction().unwrap() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn cell_summary_no_grades_returns_none() {
        let cell = CellSummary {
            pass_count: 0,
            fail_count: 0,
            format_error_count: 3,
            refused_by_policy_count: 0,
        };
        assert_eq!(cell.graded_count(), 0);
        assert!(cell.crack_fraction().is_none());
    }

    #[test]
    fn cell_summary_excludes_policy_refusals_from_graded_count() {
        let cell = CellSummary {
            pass_count: 2,
            fail_count: 0,
            format_error_count: 0,
            refused_by_policy_count: 5,
        };
        // Refusals do not credit the scramble even though they
        // look like "the model did not crack."  graded = 2.
        assert_eq!(cell.graded_count(), 2);
        assert!((cell.crack_fraction().unwrap() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn render_markdown_shows_refused_suffix() {
        let cfg = LayerConfig::l2_plus_l3();
        let records = vec![
            make_record("c1", cfg, "adv-a", 0, ScoreOutcome::Pass),
            make_record(
                "c1",
                cfg,
                "adv-a",
                1,
                ScoreOutcome::RefusedByPolicy,
            ),
            make_record(
                "c1",
                cfg,
                "adv-a",
                2,
                ScoreOutcome::RefusedByPolicy,
            ),
        ];
        let table = render_markdown(&records);
        assert!(
            table.contains("[+2 refused]"),
            "expected refused suffix; got: {table}",
        );
    }

    #[test]
    fn render_markdown_shows_both_suffixes_when_both_present() {
        let cfg = LayerConfig::l2_plus_l3();
        let records = vec![
            make_record("c1", cfg, "adv-a", 0, ScoreOutcome::Pass),
            make_record(
                "c1",
                cfg,
                "adv-a",
                1,
                ScoreOutcome::FormatError,
            ),
            make_record(
                "c1",
                cfg,
                "adv-a",
                2,
                ScoreOutcome::RefusedByPolicy,
            ),
        ];
        let table = render_markdown(&records);
        assert!(
            table.contains("[+1 fmt-err]"),
            "expected fmt-err suffix; got: {table}",
        );
        assert!(
            table.contains("[+1 refused]"),
            "expected refused suffix; got: {table}",
        );
    }

    #[test]
    fn aggregate_groups_by_full_tuple() {
        let cfg = LayerConfig::l2_plus_l3();
        let records = vec![
            make_record("c1", cfg, "adv-a", 0, ScoreOutcome::Pass),
            make_record("c1", cfg, "adv-a", 1, ScoreOutcome::Fail),
            make_record("c1", cfg, "adv-b", 0, ScoreOutcome::Pass),
            make_record("c2", cfg, "adv-a", 0, ScoreOutcome::Fail),
        ];
        let cells = aggregate(&records);
        assert_eq!(cells.len(), 3);
        let c1_adva = cells
            .get(&(
                "c1".into(),
                cfg.label(),
                "adv-a".into(),
            ))
            .unwrap();
        assert_eq!(c1_adva.pass_count, 1);
        assert_eq!(c1_adva.fail_count, 1);
    }

    #[test]
    fn empty_records_render_placeholder() {
        let out = render_markdown(&[]);
        assert!(out.contains("no bench records"));
    }

    #[test]
    fn render_markdown_emits_header_and_rows() {
        let cfg2 = LayerConfig::l2_plus_l3();
        let cfg3 = LayerConfig::l3_only();
        let records = vec![
            make_record("c1", cfg2, "adv-a", 0, ScoreOutcome::Pass),
            make_record("c1", cfg2, "adv-a", 1, ScoreOutcome::Pass),
            make_record("c1", cfg3, "adv-a", 0, ScoreOutcome::Fail),
            make_record("c2", cfg2, "adv-a", 0, ScoreOutcome::Fail),
        ];
        let table = render_markdown(&records);

        // Header pieces.
        assert!(table.contains("| challenge | layer config |"));
        assert!(table.contains(" adv-a |"));

        // Per-row fractions.
        assert!(
            table.contains("| c1 | l2-plus-l3 | 2/2 (100%) |"),
            "{table}",
        );
        assert!(
            table.contains("| c1 | l3-only | 0/1 (0%) |"),
            "{table}",
        );
        assert!(
            table.contains("| c2 | l2-plus-l3 | 0/1 (0%) |"),
            "{table}",
        );
    }

    #[test]
    fn render_markdown_marks_missing_cells_with_em_dash() {
        let cfg = LayerConfig::l2_plus_l3();
        // adv-a has c1, adv-b has c2 — neither covers the cross.
        let records = vec![
            make_record("c1", cfg, "adv-a", 0, ScoreOutcome::Pass),
            make_record("c2", cfg, "adv-b", 0, ScoreOutcome::Pass),
        ];
        let table = render_markdown(&records);
        // Two evaluator columns; each row has one filled and one
        // missing.  Check the missing cell renders as the em dash
        // (without surrounding spaces — the renderer pads with one
        // space on each side of the cell content).
        assert!(table.contains("| — |"), "{table}");
    }

    #[test]
    fn render_markdown_shows_format_error_suffix() {
        let cfg = LayerConfig::l2_plus_l3();
        let records = vec![
            make_record("c1", cfg, "adv-a", 0, ScoreOutcome::Pass),
            make_record("c1", cfg, "adv-a", 1, ScoreOutcome::FormatError),
            make_record("c1", cfg, "adv-a", 2, ScoreOutcome::FormatError),
        ];
        let table = render_markdown(&records);
        assert!(
            table.contains("[+2 fmt-err]"),
            "expected format-error suffix; got: {table}",
        );
    }
}
