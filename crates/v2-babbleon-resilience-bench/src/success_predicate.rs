//! Success predicates declaring when a model output "cracks" a
//! challenge.
//!
//! # What this defeats
//!
//! Subjective grading of adversarial runs.  A challenge that says
//! "find the secret string" is only useful if "the model found it"
//! is mechanically decidable.  Each variant of [`SuccessPredicate`]
//! is a different mechanical decision rule.
//!
//! # Mechanism
//!
//! Each variant is constructible from the TOML in a `[predicate]`
//! table on a challenge file:
//!
//! ```toml
//! [predicate]
//! kind = "exact-match"
//! expected = "secret123"
//! ```
//!
//! The serializer uses `#[serde(tag = "kind")]` so the variant is
//! selected by a single `kind = "..."` line; future variants
//! (`PythonScript { script }`, `RegexMatch { pattern }`, ...) add
//! one branch per kind without breaking the wire format.
//!
//! # Threat model boundaries
//!
//! - Defeats: ambiguous grading.  Two reviewers running the same
//!   bench against the same model output must agree on Pass / Fail.
//! - Does NOT defeat: a model that fingerprints the success
//!   predicate's reasoning and outputs a string crafted to satisfy
//!   `ExactMatch` without actually solving the underlying program.
//!   `ExactMatch` predicates therefore should hash, hide, or compute
//!   the expected value such that the model has to do the real
//!   work — not just guess what the challenge author wrote.  The
//!   `success_predicate.expected` field on `auth-literal-string`
//!   is the literal answer the model would have to extract from a
//!   string-literal compare in the scrambled source; trivially
//!   greppable, so the harness operator's job is to make the
//!   scramble strong enough that grep does not find it.

use serde::{Deserialize, Serialize};

/// Decision rule for whether a model's answer cracks a challenge.
///
/// Tagged `#[serde(tag = "kind", rename_all = "kebab-case")]` so the
/// TOML / JSON form is `kind = "exact-match"` (etc.) with the
/// remaining variant fields flat at the same level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SuccessPredicate {
    /// The model's answer (trimmed of surrounding whitespace) must
    /// be exactly the `expected` string.  Use this for challenges
    /// whose win condition is a single literal value: a password
    /// string, a state-machine input sequence, an integer encoded
    /// as text.
    ExactMatch {
        /// The literal answer the model must produce.  Operator-
        /// chosen on the challenge file.
        expected: String,
    },

    /// The model's answer must match the regex `pattern` (full-
    /// string match, not partial).  Useful when the answer space
    /// has multiple equivalent forms (e.g. integers permitting
    /// leading zeros, case-insensitive identifiers).  Implemented
    /// without pulling `regex` into the workspace by hand-rolling
    /// a small case-insensitive equality matcher for the MVP; the
    /// `pattern` field today is interpreted as a case-insensitive
    /// literal, NOT a full regex.  When a future commit pulls in
    /// the `regex` crate this variant's interpretation upgrades
    /// silently without a wire-format change.
    CaseInsensitiveMatch {
        /// The literal answer in any letter casing.
        expected: String,
    },

    /// The model's answer must match any one of `synonyms`
    /// (case-insensitive, trimmed).  Use this for challenges whose
    /// canonical answer is a Python keyword or short token with
    /// multiple acceptable forms — e.g. an L2-target challenge
    /// asking "which control structure does this loop use?" should
    /// accept `if`, `if-else`, `if/else`, `if statement` as the
    /// same answer.
    ///
    /// `synonyms` must contain at least one entry; the validator on
    /// `Challenge::validate` rejects an empty list.  All matching
    /// is case-insensitive (ASCII) and the model answer is trimmed
    /// before comparison.
    KeywordMatch {
        /// The set of acceptable answer forms.  Must be non-empty.
        synonyms: Vec<String>,
    },
}

impl SuccessPredicate {
    /// Construct an `ExactMatch` predicate.
    #[must_use]
    pub fn exact_match(expected: impl Into<String>) -> Self {
        SuccessPredicate::ExactMatch {
            expected: expected.into(),
        }
    }

    /// Construct a `CaseInsensitiveMatch` predicate.
    #[must_use]
    pub fn case_insensitive_match(expected: impl Into<String>) -> Self {
        SuccessPredicate::CaseInsensitiveMatch {
            expected: expected.into(),
        }
    }

    /// Construct a `KeywordMatch` predicate from an iterable of
    /// acceptable synonyms.  The returned predicate accepts any one
    /// of the supplied synonyms (case-insensitive ASCII, trimmed).
    ///
    /// The constructor does NOT deduplicate or reject an empty
    /// iterator — the `Challenge::validate` path is the canonical
    /// non-empty enforcement point so deserialised challenges fail
    /// at load time, not at constructor time.
    #[must_use]
    pub fn keyword_match<I, S>(synonyms: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        SuccessPredicate::KeywordMatch {
            synonyms: synonyms.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SuccessPredicate;

    #[test]
    fn exact_match_constructor_round_trips() {
        let p = SuccessPredicate::exact_match("hunter2");
        match p {
            SuccessPredicate::ExactMatch { expected } => {
                assert_eq!(expected, "hunter2");
            }
            SuccessPredicate::CaseInsensitiveMatch { .. }
            | SuccessPredicate::KeywordMatch { .. } => {
                panic!("constructor produced wrong variant")
            }
        }
    }

    #[test]
    fn case_insensitive_constructor_round_trips() {
        let p = SuccessPredicate::case_insensitive_match("HUNTER2");
        match p {
            SuccessPredicate::CaseInsensitiveMatch { expected } => {
                assert_eq!(expected, "HUNTER2");
            }
            SuccessPredicate::ExactMatch { .. }
            | SuccessPredicate::KeywordMatch { .. } => {
                panic!("constructor produced wrong variant")
            }
        }
    }

    #[test]
    fn keyword_match_constructor_round_trips() {
        let p =
            SuccessPredicate::keyword_match(["if", "if-else", "if/else"]);
        match p {
            SuccessPredicate::KeywordMatch { synonyms } => {
                assert_eq!(
                    synonyms,
                    vec![
                        "if".to_string(),
                        "if-else".to_string(),
                        "if/else".to_string(),
                    ],
                );
            }
            SuccessPredicate::ExactMatch { .. }
            | SuccessPredicate::CaseInsensitiveMatch { .. } => {
                panic!("constructor produced wrong variant")
            }
        }
    }

    #[test]
    fn keyword_match_accepts_empty_iter_at_constructor_level() {
        // The constructor itself is unopinionated about emptiness;
        // Challenge::validate is the enforcement point.  This keeps
        // the constructor symmetrical with exact_match / case_-
        // insensitive_match — none of them validate at construct.
        let empty: Vec<&str> = Vec::new();
        let p = SuccessPredicate::keyword_match(empty);
        match p {
            SuccessPredicate::KeywordMatch { synonyms } => {
                assert!(synonyms.is_empty());
            }
            SuccessPredicate::ExactMatch { .. }
            | SuccessPredicate::CaseInsensitiveMatch { .. } => {
                panic!("constructor produced wrong variant")
            }
        }
    }

    #[test]
    fn toml_round_trip_for_exact_match() {
        let p = SuccessPredicate::exact_match("password");
        let s = toml::to_string(&p).unwrap();
        // The serialized form should mention the kind tag and the
        // expected value.  Layout is up to toml-rs; assert the
        // semantic content, not the byte layout.
        assert!(s.contains("kind"));
        assert!(s.contains("exact-match"));
        assert!(s.contains("password"));
        let back: SuccessPredicate = toml::from_str(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn toml_round_trip_for_case_insensitive_match() {
        let p = SuccessPredicate::case_insensitive_match("Token");
        let s = toml::to_string(&p).unwrap();
        assert!(s.contains("case-insensitive-match"));
        let back: SuccessPredicate = toml::from_str(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn json_round_trip_for_exact_match() {
        let p = SuccessPredicate::exact_match("xyz");
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"kind\":\"exact-match\""));
        let back: SuccessPredicate = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn variants_are_distinct_under_equality() {
        let a = SuccessPredicate::exact_match("X");
        let b = SuccessPredicate::case_insensitive_match("X");
        assert_ne!(a, b);
        let c = SuccessPredicate::keyword_match(["X"]);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn toml_round_trip_for_keyword_match() {
        let p = SuccessPredicate::keyword_match(["if", "if-else"]);
        let s = toml::to_string(&p).unwrap();
        assert!(s.contains("kind"));
        assert!(s.contains("keyword-match"));
        assert!(s.contains("if"));
        let back: SuccessPredicate = toml::from_str(&s).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn toml_parses_keyword_match_with_inline_synonyms() {
        // The TOML form the operator types in a challenge file.
        let raw = r#"
            kind = "keyword-match"
            synonyms = ["if", "if-else", "if/else"]
        "#;
        let p: SuccessPredicate = toml::from_str(raw).unwrap();
        match p {
            SuccessPredicate::KeywordMatch { synonyms } => {
                assert_eq!(synonyms.len(), 3);
                assert_eq!(synonyms[0], "if");
                assert_eq!(synonyms[1], "if-else");
                assert_eq!(synonyms[2], "if/else");
            }
            other => panic!("expected KeywordMatch, got {other:?}"),
        }
    }

    #[test]
    fn json_round_trip_for_keyword_match() {
        let p = SuccessPredicate::keyword_match(["foo", "bar"]);
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"kind\":\"keyword-match\""));
        let back: SuccessPredicate = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p);
    }
}
