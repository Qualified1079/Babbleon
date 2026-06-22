//! Layer configuration selecting which scramble passes are applied.
//!
//! # What this defeats
//!
//! Ad-hoc "L3 alone is fine" vs "L2+L3 is fine" framings.  Each
//! bench run is parameterised by an explicit [`LayerConfig`] that
//! names which layers were active; the summary table groups results
//! by `LayerConfig`, so the operator's eventual decision ("ship
//! L2+L3") cites the cell in the table whose configuration matches.
//!
//! # Mechanism
//!
//! A `LayerConfig` is a small Copy struct of three fields:
//!
//! - `layer2_keyword_scramble` — apply layer-2 (Python keyword
//!   substitution) before layer 3.
//! - `layer3_whitespace_as_words` — apply layer-3 (whitespace as
//!   wordlist compounds).
//! - `seed_byte` — the byte the deterministic synthetic per-host
//!   secret is filled with (`[seed_byte; 32]`).  Surfaces the
//!   bench-determinism choice in the `LayerConfig` itself so two
//!   operators running the same `(challenge, config)` pair against
//!   the same model see byte-identical scrambled output.
//!
//! Future commits add `layer4_chunk_reorder`, `layer5_decoy_injection`,
//! `wordlist_locale` (multi-language wordlists), etc.  Every addition
//! is a new field; old TOML/JSON keeps deserializing via serde
//! defaults.
//!
//! # Threat model boundaries
//!
//! - Defeats: confusion between which configuration produced which
//!   cell in the summary.
//! - Does NOT defeat: an operator who mixes configurations within a
//!   single bench run.  The harness enforces one config per
//!   `RunRecord`; aggregation across configs is the summary's job.

use serde::{Deserialize, Serialize};

/// Layer toggles + seed for one bench run.
///
/// `Default::default()` returns the "L2+L3 floor" config recommended
/// by the HANDOFF analysis: both keyword scramble and whitespace
/// scramble on, seed byte = `0xAB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerConfig {
    /// Apply layer-2 (Python keyword scramble) before layer 3.
    pub layer2_keyword_scramble: bool,
    /// Apply layer-2b (Python operator scramble) after L2 and before L3.
    /// Substitutes per-epoch wordlist compounds for the 37 Python
    /// operators tracked by the preprocessor (parens, comparison
    /// operators, `:`, `=`, brackets, etc.).
    #[serde(default)]
    pub layer2b_operator_scramble: bool,
    /// Apply layer-3 (whitespace-as-words).
    pub layer3_whitespace_as_words: bool,
    /// Apply experimental layer-7 secret-literal substitution
    /// (bench-only prototype; see
    /// `crates/v2-babbleon-resilience-bench/src/secret_literal_layer.rs`).
    /// Defaults to `false` because the production preprocessor
    /// does not yet implement it; bench cells that set this to
    /// `true` measure crack-fraction of the proposed mechanism.
    #[serde(default)]
    pub layer7_secret_literal: bool,
    /// Fill byte for the synthetic per-host secret `[u8; 32]`.
    /// Reproducibility seed; carries zero security weight.
    pub seed_byte: u8,
    /// Epoch the wordlists are derived at.  Combined with
    /// `seed_byte`, two runs with identical fields here produce
    /// byte-identical scrambled output for the same source.
    pub epoch: u64,
}

impl LayerConfig {
    /// Construct an explicit config — useful in tests and CLI
    /// argument parsing.
    #[must_use]
    pub fn new(
        layer2_keyword_scramble: bool,
        layer3_whitespace_as_words: bool,
        seed_byte: u8,
        epoch: u64,
    ) -> Self {
        Self {
            layer2_keyword_scramble,
            layer2b_operator_scramble: false,
            layer3_whitespace_as_words,
            layer7_secret_literal: false,
            seed_byte,
            epoch,
        }
    }

    /// L3-only: whitespace-as-words on, keyword scramble off.
    /// Matches the original phase-3 MVP framing.
    #[must_use]
    pub fn l3_only() -> Self {
        Self::new(false, true, 0xAB, 0)
    }

    /// L2 + L3: both layers on.  The operator-confirmed floor per
    /// HANDOFF 2026-06-21 evening: "L2+L3 is the correct floor, not
    /// L3-alone."
    #[must_use]
    pub fn l2_plus_l3() -> Self {
        Self::new(true, true, 0xAB, 0)
    }

    /// L2 + L2b + L3: the post-2026-06-22 corrected floor.  The
    /// operator's 2026-06-22 directive made operator scrambling
    /// part of the floor: "operators should be scrambled too as
    /// the floor.  ' ', (), **, -, etc."  This config measures
    /// the resilience of the corrected floor.
    #[must_use]
    pub fn l2_plus_l2b_plus_l3() -> Self {
        Self {
            layer2_keyword_scramble: true,
            layer2b_operator_scramble: true,
            layer3_whitespace_as_words: true,
            layer7_secret_literal: false,
            seed_byte: 0xAB,
            epoch: 0,
        }
    }

    /// L2 only: keyword scramble on, whitespace scramble off.
    /// Diagnostic config that isolates the keyword-scramble effect
    /// when reasoning about an unexpected bench result.
    #[must_use]
    pub fn l2_only() -> Self {
        Self::new(true, false, 0xAB, 0)
    }

    /// All layers off — the unscrambled baseline.  Crack-fraction
    /// against this configuration is the floor every other
    /// configuration must beat to claim any defensive value.
    #[must_use]
    pub fn baseline_no_scramble() -> Self {
        Self::new(false, false, 0xAB, 0)
    }

    /// L2 + L3 + L7 (experimental).  L2+L3 floor PLUS bench-only
    /// secret-literal substitution.  Measures whether operator-
    /// marked secret literals defeat the literal-leak finding.
    #[must_use]
    pub fn l2_plus_l3_plus_l7() -> Self {
        Self {
            layer2_keyword_scramble: true,
            layer2b_operator_scramble: false,
            layer3_whitespace_as_words: true,
            layer7_secret_literal: true,
            seed_byte: 0xAB,
            epoch: 0,
        }
    }

    /// L2 + L2b + L3 + L7: full corrected floor + experimental
    /// secret-literal substitution.  Bench-only cell that measures
    /// whether the full stack defeats literal-extraction.
    #[must_use]
    pub fn l2_plus_l2b_plus_l3_plus_l7() -> Self {
        Self {
            layer2_keyword_scramble: true,
            layer2b_operator_scramble: true,
            layer3_whitespace_as_words: true,
            layer7_secret_literal: true,
            seed_byte: 0xAB,
            epoch: 0,
        }
    }

    /// Short kebab-case label, used as the column header in the
    /// summary table.
    #[must_use]
    pub fn label(&self) -> String {
        let base = match (
            self.layer2_keyword_scramble,
            self.layer2b_operator_scramble,
            self.layer3_whitespace_as_words,
        ) {
            (false, false, false) => "baseline".to_string(),
            (true, false, false) => "l2-only".to_string(),
            (false, false, true) => "l3-only".to_string(),
            (true, false, true) => "l2-plus-l3".to_string(),
            (true, true, true) => "l2-plus-l2b-plus-l3".to_string(),
            (a, b, c) => format!(
                "custom-l2={a}-l2b={b}-l3={c}"
            ),
        };
        if self.layer7_secret_literal {
            format!("{base}-plus-l7")
        } else {
            base
        }
    }
}

impl Default for LayerConfig {
    fn default() -> Self {
        Self::l2_plus_l3()
    }
}

#[cfg(test)]
mod tests {
    use super::LayerConfig;

    #[test]
    fn default_is_l2_plus_l3() {
        let c = LayerConfig::default();
        assert!(c.layer2_keyword_scramble);
        assert!(c.layer3_whitespace_as_words);
        assert_eq!(c.label(), "l2-plus-l3");
    }

    #[test]
    fn preset_labels_are_distinct() {
        let labels = [
            LayerConfig::baseline_no_scramble().label(),
            LayerConfig::l2_only().label(),
            LayerConfig::l3_only().label(),
            LayerConfig::l2_plus_l3().label(),
            LayerConfig::l2_plus_l2b_plus_l3().label(),
            LayerConfig::l2_plus_l3_plus_l7().label(),
            LayerConfig::l2_plus_l2b_plus_l3_plus_l7().label(),
        ];
        let mut set: Vec<_> = labels.to_vec();
        set.sort();
        set.dedup();
        assert_eq!(set.len(), 7, "labels must be pairwise distinct");
    }

    #[test]
    fn l2_plus_l2b_plus_l3_label() {
        assert_eq!(
            LayerConfig::l2_plus_l2b_plus_l3().label(),
            "l2-plus-l2b-plus-l3"
        );
    }

    #[test]
    fn layer7_appends_plus_l7_to_label() {
        let c = LayerConfig::l2_plus_l3_plus_l7();
        assert_eq!(c.label(), "l2-plus-l3-plus-l7");
        assert!(c.layer7_secret_literal);
    }

    #[test]
    fn label_baseline_when_both_off() {
        let c = LayerConfig::new(false, false, 0xAB, 0);
        assert_eq!(c.label(), "baseline");
    }

    #[test]
    fn label_l2_only_when_only_l2_on() {
        let c = LayerConfig::new(true, false, 0xAB, 0);
        assert_eq!(c.label(), "l2-only");
    }

    #[test]
    fn label_l3_only_when_only_l3_on() {
        let c = LayerConfig::new(false, true, 0xAB, 0);
        assert_eq!(c.label(), "l3-only");
    }

    #[test]
    fn equality_is_byte_for_byte() {
        let a = LayerConfig::new(true, true, 0xAB, 0);
        let b = LayerConfig::new(true, true, 0xAB, 0);
        let c = LayerConfig::new(true, true, 0xCD, 0);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn epoch_affects_equality() {
        let a = LayerConfig::new(true, true, 0xAB, 0);
        let b = LayerConfig::new(true, true, 0xAB, 1);
        assert_ne!(a, b);
    }

    #[test]
    fn json_round_trip() {
        let c = LayerConfig::l2_plus_l3();
        let j = serde_json::to_string(&c).unwrap();
        let back: LayerConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }
}
