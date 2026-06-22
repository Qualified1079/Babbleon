//! Score a model's answer against a [`SuccessPredicate`].
//!
//! # What this defeats
//!
//! Inconsistent grading.  Two operators running the same bench
//! against the same model output must agree on Pass / Fail per
//! challenge.  This module is the single audited grading point;
//! everywhere else in the harness goes through [`score`].
//!
//! # Mechanism
//!
//! The model's prompt instructs it to emit `{"answer": "..."}` on
//! a single line.  [`score`] extracts the JSON object (the first
//! brace-balanced substring whose `kind`-free shape matches
//! `{"answer": "..."}`), pulls the `answer` field, trims
//! surrounding whitespace, and runs the predicate's decision rule:
//!
//! - `ExactMatch { expected }`: trimmed answer must equal
//!   `expected` byte-for-byte.
//! - `CaseInsensitiveMatch { expected }`: trimmed answer must
//!   equal `expected` under ASCII-lowercase normalisation on both
//!   sides.
//!
//! If the model output does not contain a valid `{"answer": "..."}`
//! JSON object, [`score`] returns `ScoreOutcome::FormatError`.
//! Format errors are distinct from `Fail` so the summary table can
//! show "the model produced unparseable output" separately from
//! "the model produced an incorrect answer."
//!
//! # Threat model boundaries
//!
//! - Defeats: grading drift.
//! - Does NOT defeat: a model that emits the correct answer wrapped
//!   in markdown code fences inside the JSON value (`"answer":
//!   "```hunter2```"`).  Today's extractor pulls the literal string
//!   value; the operator-facing remediation is "phrase the goal so
//!   the answer is a literal value, not a code block."  The four
//!   seed challenges all conform to that.
//!
//! # `RefusedByPolicy` vs `FormatError`
//!
//! A model that returns `"API Error: ... violate our Usage
//! Policy"` or `"I cannot help with that request"` is semantically
//! distinct from a model that produced unparseable output: the
//! first is a *refusal* the bench should report separately because
//! it conflates safety-tuning artefacts with scramble strength,
//! while the second is genuine harness drift (model emitted prose
//! when the prompt asked for JSON).  [`score`] detects refusals
//! by case-insensitive substring match against the patterns in
//! [`POLICY_REFUSAL_PATTERNS`] BEFORE attempting JSON extraction.
//! If any pattern matches, the outcome is
//! [`ScoreOutcome::RefusedByPolicy`].

use crate::success_predicate::SuccessPredicate;

/// Substrings (case-insensitive match) that indicate a safety /
/// policy refusal rather than a genuine attempt + format failure.
///
/// Sourced from observed refusal patterns across major LLM
/// providers (Anthropic, `OpenAI`, Google).  Patterns are
/// intentionally narrow to avoid false-positive classification of
/// chatty model preambles that happen to mention "policy" or
/// "cannot."  Add new patterns by PR with the observed-output
/// citation alongside.
pub const POLICY_REFUSAL_PATTERNS: &[&str] = &[
    // Anthropic Claude refusal envelopes.
    "violate our usage policy",
    "violates our usage policy",
    "violate our acceptable use policy",
    "violates our acceptable use policy",
    // The provider-side wrapper Claude Code prints when the API
    // refused the prompt outright.
    "api error: claude code is unable to respond",
    // OpenAI policy-refusal preamble.
    "i can't help with that",
    "i cannot assist with that",
    "i can't assist with that",
    // Common shared refusal opener (any provider).
    "i'm sorry, but i cannot",
    "i'm sorry, but i can't",
];

/// Outcome of one scored run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScoreOutcome {
    /// The model's answer satisfied the predicate — the scramble
    /// was cracked for this run.
    Pass,
    /// The model's answer parsed but did not satisfy the predicate.
    Fail,
    /// The model's output did not contain a parseable
    /// `{"answer": "..."}` object AND did not match a known
    /// policy-refusal pattern.  Genuine harness drift.
    FormatError,
    /// The model declined to engage with the prompt for safety /
    /// usage-policy reasons.  Distinct from `FormatError` so the
    /// bench summary can report safety-filter trips separately
    /// from "the model tried and produced unparseable output."
    /// Does NOT credit the scramble — neither Pass nor Fail.
    RefusedByPolicy,
}

/// Score `model_output` against `predicate`.
///
/// `model_output` is the raw text returned by the evaluator; this
/// function:
///
/// 1. Checks for a policy refusal first ([`POLICY_REFUSAL_PATTERNS`]).
///    If matched, returns [`ScoreOutcome::RefusedByPolicy`].
/// 2. Otherwise extracts the JSON answer object; if absent,
///    returns [`ScoreOutcome::FormatError`].
/// 3. Otherwise applies the predicate and returns Pass or Fail.
#[must_use]
pub fn score(
    predicate: &SuccessPredicate,
    model_output: &str,
) -> ScoreOutcome {
    if looks_like_policy_refusal(model_output) {
        return ScoreOutcome::RefusedByPolicy;
    }
    let Some(answer) = extract_answer_field(model_output) else {
        return ScoreOutcome::FormatError;
    };
    let trimmed = answer.trim();
    match predicate {
        SuccessPredicate::ExactMatch { expected } => {
            if trimmed == expected {
                ScoreOutcome::Pass
            } else {
                ScoreOutcome::Fail
            }
        }
        SuccessPredicate::CaseInsensitiveMatch { expected } => {
            if trimmed.eq_ignore_ascii_case(expected) {
                ScoreOutcome::Pass
            } else {
                ScoreOutcome::Fail
            }
        }
    }
}

/// True iff `model_output` contains any
/// [`POLICY_REFUSAL_PATTERNS`] substring (case-insensitive).
fn looks_like_policy_refusal(model_output: &str) -> bool {
    let lower = model_output.to_ascii_lowercase();
    POLICY_REFUSAL_PATTERNS
        .iter()
        .any(|pat| lower.contains(*pat))
}

/// Extract the value of the first `"answer": "..."` field that
/// appears in `model_output` inside a JSON object literal.
///
/// Implementation: scan for `{` characters; for each, find a
/// matching `}` accounting for string-literal quoting (so a `}`
/// inside an answer value does not close the object early); attempt
/// to parse the substring as a `serde_json::Value`; if it has an
/// `"answer"` string field, return that.  We do NOT pull a regex
/// dependency for this — the small character-state scanner here
/// covers the cases the prompt asks the model to produce.
fn extract_answer_field(model_output: &str) -> Option<String> {
    let bytes = model_output.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(end) = find_balanced_object_end(&model_output[i..]) {
                let slice = &model_output[i..i + end];
                if let Ok(value) =
                    serde_json::from_str::<serde_json::Value>(slice)
                {
                    if let Some(answer) =
                        value.get("answer").and_then(|v| v.as_str())
                    {
                        return Some(answer.to_string());
                    }
                }
            }
        }
        i += 1;
    }
    None
}

/// Return the byte offset (exclusive) of the closing brace that
/// balances the opening brace at offset 0 of `s`, accounting for
/// double-quoted strings with backslash-escaped quotes.
///
/// Returns `None` if `s` does not start with `{` or if no balancing
/// brace is found.
fn find_balanced_object_end(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes[0] != b'{' {
        return None;
    }
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape_next = false;
    for (i, &b) in bytes.iter().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if in_string {
            match b {
                b'\\' => escape_next = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{score, ScoreOutcome, POLICY_REFUSAL_PATTERNS};
    use crate::success_predicate::SuccessPredicate;

    #[test]
    fn pass_on_exact_match() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(&p, r#"{"answer": "hunter2"}"#);
        assert_eq!(out, ScoreOutcome::Pass);
    }

    #[test]
    fn fail_on_exact_mismatch() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(&p, r#"{"answer": "hunter3"}"#);
        assert_eq!(out, ScoreOutcome::Fail);
    }

    #[test]
    fn format_error_when_no_json() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(&p, "I think the answer is hunter2");
        assert_eq!(out, ScoreOutcome::FormatError);
    }

    #[test]
    fn format_error_when_json_lacks_answer_field() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(&p, r#"{"guess": "hunter2"}"#);
        assert_eq!(out, ScoreOutcome::FormatError);
    }

    #[test]
    fn pass_when_json_is_inside_chatty_preamble() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(
            &p,
            "After analysis, my answer:\n\n{\"answer\": \"hunter2\"}\n",
        );
        assert_eq!(out, ScoreOutcome::Pass);
    }

    #[test]
    fn pass_when_answer_has_surrounding_whitespace() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(&p, r#"{"answer": "  hunter2  "}"#);
        assert_eq!(out, ScoreOutcome::Pass);
    }

    #[test]
    fn case_insensitive_match_passes_on_different_casing() {
        let p = SuccessPredicate::case_insensitive_match("Hunter2");
        for body in [
            r#"{"answer": "hunter2"}"#,
            r#"{"answer": "HUNTER2"}"#,
            r#"{"answer": "HuNtEr2"}"#,
        ] {
            assert_eq!(score(&p, body), ScoreOutcome::Pass, "body: {body}");
        }
    }

    #[test]
    fn case_insensitive_match_fails_on_distinct_content() {
        let p = SuccessPredicate::case_insensitive_match("hunter2");
        let out = score(&p, r#"{"answer": "rabbit"}"#);
        assert_eq!(out, ScoreOutcome::Fail);
    }

    #[test]
    fn skips_pre_json_brace_substrings_that_are_not_objects() {
        // First `{` opens a non-object run; the second is the real
        // answer object.  Today's scanner finds the first balanced
        // brace; a non-object value that's NOT a valid serde_json
        // object should not block discovery of the later one.
        let p = SuccessPredicate::exact_match("found");
        let out = score(
            &p,
            "Some thought {not json here\nfinal:\n{\"answer\": \"found\"}",
        );
        assert_eq!(out, ScoreOutcome::Pass);
    }

    #[test]
    fn nested_braces_inside_answer_value_are_handled() {
        let p = SuccessPredicate::exact_match("{nested}");
        let out = score(&p, r#"{"answer": "{nested}"}"#);
        assert_eq!(out, ScoreOutcome::Pass);
    }

    #[test]
    fn escaped_quote_inside_answer_value_is_handled() {
        let p = SuccessPredicate::exact_match("he said \"hi\"");
        let out = score(&p, r#"{"answer": "he said \"hi\""}"#);
        assert_eq!(out, ScoreOutcome::Pass);
    }

    #[test]
    fn picks_first_well_formed_answer_object_when_multiple_present() {
        // Multiple objects: scoring takes the first.  A model that
        // emits two answers gets graded on the first one — there is
        // no "best of" semantics.
        let p = SuccessPredicate::exact_match("first");
        let out = score(
            &p,
            r#"{"answer": "first"} then {"answer": "second"}"#,
        );
        assert_eq!(out, ScoreOutcome::Pass);
    }

    #[test]
    fn format_error_on_empty_model_output() {
        let p = SuccessPredicate::exact_match("x");
        let out = score(&p, "");
        assert_eq!(out, ScoreOutcome::FormatError);
    }

    #[test]
    fn score_outcome_serializes_kebab_case() {
        let j = serde_json::to_string(&ScoreOutcome::FormatError).unwrap();
        assert_eq!(j, "\"format-error\"");
        let j = serde_json::to_string(&ScoreOutcome::Pass).unwrap();
        assert_eq!(j, "\"pass\"");
        let j = serde_json::to_string(&ScoreOutcome::Fail).unwrap();
        assert_eq!(j, "\"fail\"");
        let j =
            serde_json::to_string(&ScoreOutcome::RefusedByPolicy).unwrap();
        assert_eq!(j, "\"refused-by-policy\"");
    }

    #[test]
    fn refused_by_policy_on_anthropic_usage_policy_message() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(
            &p,
            "API Error: Claude Code is unable to respond to this \
             request, which appears to violate our Usage Policy",
        );
        assert_eq!(out, ScoreOutcome::RefusedByPolicy);
    }

    #[test]
    fn refused_by_policy_on_acceptable_use_message() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(
            &p,
            "Sorry — this request violates our Acceptable Use Policy.",
        );
        assert_eq!(out, ScoreOutcome::RefusedByPolicy);
    }

    #[test]
    fn refused_by_policy_on_openai_style_refusal() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out =
            score(&p, "I can't help with that.  Try rephrasing.");
        assert_eq!(out, ScoreOutcome::RefusedByPolicy);
    }

    #[test]
    fn refused_by_policy_is_case_insensitive() {
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(
            &p,
            "API ERROR: ... VIOLATES OUR USAGE POLICY ...",
        );
        assert_eq!(out, ScoreOutcome::RefusedByPolicy);
    }

    #[test]
    fn refused_by_policy_takes_precedence_over_correct_answer() {
        // A model that emits a refusal preamble AND a JSON answer
        // is still a refusal — we don't credit the scramble for a
        // refusal-shaped output even if a literal `{"answer":
        // "hunter2"}` appears later in the body.  This is
        // intentional: refusal envelopes often include canned
        // reasoning that mentions the original prompt's content
        // and could trip a coincidental match.
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(
            &p,
            "I'm sorry, but I cannot. {\"answer\": \"hunter2\"}",
        );
        assert_eq!(out, ScoreOutcome::RefusedByPolicy);
    }

    #[test]
    fn chatty_preamble_that_mentions_policy_in_passing_is_not_refusal() {
        // Negative case: a preamble that uses the word "policy"
        // in unrelated context should NOT trip the classifier.
        // The patterns require the canned-phrase shape.
        let p = SuccessPredicate::exact_match("hunter2");
        let out = score(
            &p,
            "The challenge mentions an authentication policy. \
             {\"answer\": \"hunter2\"}",
        );
        assert_eq!(out, ScoreOutcome::Pass);
    }

    #[test]
    fn policy_refusal_patterns_are_lowercase_and_distinct() {
        // Defensive: patterns must be lowercase (the matcher
        // lowercases the haystack) and pairwise non-duplicate.
        for pat in POLICY_REFUSAL_PATTERNS {
            assert_eq!(
                *pat,
                pat.to_ascii_lowercase(),
                "pattern {pat:?} must be lowercase",
            );
        }
        let mut sorted: Vec<&&str> =
            POLICY_REFUSAL_PATTERNS.iter().collect();
        sorted.sort();
        let len_before = sorted.len();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            len_before,
            "POLICY_REFUSAL_PATTERNS contains duplicates",
        );
    }
}
