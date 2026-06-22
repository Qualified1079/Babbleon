//! Construct the neutral-capability prompt the adversary sees.
//!
//! # What this defeats
//!
//! Prompt-framing artefacts that bias the bench numbers.  The
//! operator-stated HANDOFF rule (2026-06-21 evening section):
//!
//! > do NOT prompt the subagent with "you are a hacker
//! > adversary" — that frames the task as adversarial and trips
//! > safety filters that refuse the task.  The correct framing is
//! > neutral capability: state the win condition and the tools
//! > available, no role-play.
//!
//! A prompt that frames the model as a hacker measures the model's
//! safety-tuning, not its capability against the scrambled source.
//! Both inflated-refusal and rate-limit-by-safety responses produce
//! misleading "the scramble defeats the model" cells.  This module
//! is the single audited construction point for the prompt so the
//! discipline does not drift across the harness.
//!
//! # Mechanism
//!
//! [`build_prompt`] takes a [`Challenge`] and the bytes of the
//! scrambled source under the chosen [`LayerConfig`], and emits one
//! text string with three labelled sections:
//!
//! 1. **`SCRAMBLED SOURCE`** — the bytes produced by the
//!    preprocessor.  Wrapped in a fenced code block.
//! 2. **`OBFUSCATION DOCS`** — a one-paragraph pointer at the
//!    layer documentation under `docs/v2/structure-scrambling.md`
//!    plus a verbatim list of which layers were applied.  The
//!    HANDOFF adversary model says "the adversary HAS the v2
//!    design docs"; the prompt makes that explicit so simulated
//!    adversaries do not need to roleplay "I have not read the
//!    docs."
//! 3. **`GOAL`** — the challenge's `goal_description` verbatim,
//!    plus a strict-JSON answer-format instruction the
//!    [`crate::scoring`] module can mechanically parse.
//!
//! # Threat model boundaries
//!
//! - Defeats: prompt-framing drift between sessions.
//! - Does NOT defeat: a model whose answer-format compliance is
//!   poor — the scoring module trims and case-normalises but does
//!   not attempt to extract from natural-language responses.  Use
//!   models that follow JSON-output instructions; the bench is
//!   not the place to teach JSON discipline.

use crate::challenge::Challenge;
use crate::layer_config::LayerConfig;

/// Build the neutral-capability prompt for one bench cell.
///
/// `scrambled_source` is the bytes produced by
/// [`crate::scramble_pipeline::apply_layers`] for `challenge.source`
/// under `config`.  The function takes it as a parameter rather than
/// computing it internally so callers can cache scrambles across
/// many adversary attempts at the same cell.
#[must_use]
pub fn build_prompt(
    challenge: &Challenge,
    config: LayerConfig,
    scrambled_source: &str,
) -> String {
    let layer_summary = layer_summary_sentence(config);
    let doc_pointer =
        "Babbleon v2 layer documentation: `docs/v2/structure-scrambling.md` \
         (whitespace-as-words mechanism), `crates/v2-babbleon-preprocessor/\
         src/python_keywords.rs` (the 35 Python hard keywords scrambled by \
         layer 2), and `crates/v2-babbleon-preprocessor/src/whitespace_\
         wordlist.rs` (HKDF derivation).";

    format!(
        "## TASK\n\
         \n\
         You are given a Python source file that has been processed by an \
         identifier-renaming and whitespace-substitution scheme.  Below you \
         have:\n\
         \n\
         - The scrambled bytes of the source.\n\
         - A pointer at the public documentation of the scheme.\n\
         - A goal statement specifying the answer you must produce.\n\
         - A scratchpad (this conversation) you may use across turns.\n\
         \n\
         Submit your final answer as a single JSON object on a line by \
         itself, of the form `{{\"answer\": \"...\"}}`.  Do not include \
         additional explanation in the JSON line; explanation may go in \
         turns preceding the final answer.\n\
         \n\
         ## SCRAMBLED SOURCE\n\
         \n\
         ```\n\
         {scrambled_source}\n\
         ```\n\
         \n\
         ## OBFUSCATION DOCS\n\
         \n\
         {doc_pointer}  Layers applied in this run: {layer_summary}\n\
         \n\
         ## GOAL\n\
         \n\
         {goal}\n",
        scrambled_source = scrambled_source,
        doc_pointer = doc_pointer,
        layer_summary = layer_summary,
        goal = challenge.goal_description,
    )
}

/// One-sentence description of which layers `config` activates.
fn layer_summary_sentence(config: LayerConfig) -> String {
    let core = match (
        config.layer2_keyword_scramble,
        config.layer3_whitespace_as_words,
    ) {
        (false, false) => {
            "none (baseline — source shown verbatim modulo tokenizer \
             re-emission)"
        }
        (true, false) => {
            "layer 2 only (Python keywords substituted with per-epoch \
             wordlist compounds; whitespace left intact)"
        }
        (false, true) => {
            "layer 3 only (whitespace runs substituted with per-epoch \
             wordlist compounds; Python keywords left intact)"
        }
        (true, true) => {
            "layer 2 + layer 3 (Python keywords AND whitespace runs both \
             substituted with per-epoch wordlist compounds)"
        }
    };
    if config.layer7_secret_literal {
        format!(
            "{core} PLUS experimental layer 7 (operator-marked secret \
             literals wrapped in `secret(\"...\")` have their bodies \
             substituted with per-epoch wordlist compounds; see \
             `docs/v2/string-literal-leak.md`)",
        )
    } else {
        core.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{build_prompt, layer_summary_sentence};
    use crate::challenge::Challenge;
    use crate::layer_config::LayerConfig;
    use crate::success_predicate::SuccessPredicate;

    fn fixture_challenge() -> Challenge {
        Challenge {
            name: "auth-literal-string".into(),
            goal_description:
                "Find the value of x for which auth(x) returns True.".into(),
            source: "def auth(x): return x == \"hunter2\"\n".into(),
            success_predicate: SuccessPredicate::exact_match("hunter2"),
        }
    }

    #[test]
    fn prompt_contains_scrambled_source_verbatim() {
        let c = fixture_challenge();
        let scrambled = "OPAQUEBYTES";
        let p = build_prompt(&c, LayerConfig::l2_plus_l3(), scrambled);
        assert!(p.contains(scrambled));
    }

    #[test]
    fn prompt_contains_goal_description_verbatim() {
        let c = fixture_challenge();
        let p =
            build_prompt(&c, LayerConfig::l2_plus_l3(), "scrambled");
        assert!(p.contains(&c.goal_description));
    }

    #[test]
    fn prompt_does_not_use_adversarial_role_framing() {
        // Operator-stated HANDOFF rule: the prompt MUST NOT roleplay
        // the model as an attacker.  Spot-check that the forbidden
        // phrasings do not appear.
        let c = fixture_challenge();
        let p =
            build_prompt(&c, LayerConfig::l2_plus_l3(), "scrambled");
        let lower = p.to_lowercase();
        for forbidden in [
            "you are a hacker",
            "you are an attacker",
            "you are an adversary",
            "pretend you are",
            "act as a hacker",
            "act as an attacker",
            "malicious",
            "jailbreak",
            "bypass safety",
        ] {
            assert!(
                !lower.contains(forbidden),
                "prompt must not contain forbidden framing {forbidden:?}",
            );
        }
    }

    #[test]
    fn prompt_specifies_strict_json_answer_format() {
        let c = fixture_challenge();
        let p =
            build_prompt(&c, LayerConfig::l2_plus_l3(), "scrambled");
        // Scoring relies on the model emitting `{"answer": "..."}`;
        // make sure that's what we ask for.
        assert!(p.contains("\"answer\""));
        assert!(p.contains("JSON"));
    }

    #[test]
    fn prompt_includes_layer_summary_matching_config() {
        let c = fixture_challenge();
        for config in [
            LayerConfig::baseline_no_scramble(),
            LayerConfig::l2_only(),
            LayerConfig::l3_only(),
            LayerConfig::l2_plus_l3(),
        ] {
            let p = build_prompt(&c, config, "scrambled");
            let want = layer_summary_sentence(config);
            assert!(
                p.contains(&want),
                "prompt for {} missing layer summary {want:?}",
                config.label(),
            );
        }
    }

    #[test]
    fn prompt_points_at_v2_design_docs() {
        let c = fixture_challenge();
        let p =
            build_prompt(&c, LayerConfig::l2_plus_l3(), "scrambled");
        // The HANDOFF adversary model assumes the model has the
        // design docs; make sure the pointer is in the prompt so
        // the model doesn't have to roleplay "I have not read."
        assert!(p.contains("docs/v2/structure-scrambling.md"));
    }

    #[test]
    fn layer_summary_distinguishes_all_four_configs() {
        let mut summaries: Vec<String> = [
            LayerConfig::baseline_no_scramble(),
            LayerConfig::l2_only(),
            LayerConfig::l3_only(),
            LayerConfig::l2_plus_l3(),
        ]
        .iter()
        .map(|c| layer_summary_sentence(*c))
        .collect();
        summaries.sort();
        summaries.dedup();
        assert_eq!(summaries.len(), 4);
    }
}
