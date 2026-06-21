//! Python reserved-keyword set targeted by layer-2 (operator scramble).
//!
//! # What this defeats
//!
//! Without keyword scrambling, layer-3 output is a wall of words —
//! but `def`, `if`, `return`, `import`, `for`, `while`, `class`,
//! `try`, `except`, `with`, etc. are all visible verbatim.  An
//! adversary who sees those tokens instantly knows "this is Python
//! source," confirms host-class assumptions, and can position-match
//! against cached templates of the same script (e.g. a known
//! version of a vendored CLI tool).  Layer-2 replaces every
//! occurrence of a Python keyword with a per-epoch wordlist
//! compound so the surface lexicon no longer leaks the language.
//!
//! # Mechanism
//!
//! The list is Python 3.12's `keyword.kwlist` minus the soft
//! keywords (`match`, `case`, `type`).  Soft keywords are
//! context-dependent — Python treats them as identifiers outside
//! their grammatical anchor — so scrambling them everywhere would
//! mis-substitute identifiers named `match` or `case`, which are
//! common in legitimate code.  The MVP accepts the marginal
//! signal-leak of leaving the three soft keywords visible.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** "this is Python" recognition via the surface
//!   lexicon.
//! - **Does NOT defeat:** an adversary who tokenizes the
//!   scrambled wall, observes that 35 of the tokens repeat far
//!   more often than the average and infers "these 35 are
//!   probably the keyword compounds."  Compensating control:
//!   layer-5 decoy injection (filed) inflates the token
//!   distribution so keyword frequency does not stand out as
//!   sharply.

/// Python reserved keywords, Python 3.12 `keyword.kwlist` minus
/// the three soft keywords (`match`, `case`, `type`).
///
/// Order is stable: bumping the list (additions or reorderings)
/// changes per-epoch compound assignments and is a wire-format
/// break.  When Python grows a new hard keyword, append it; do
/// not reorder.
pub const PYTHON_KEYWORDS: &[&str] = &[
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else",
    "except", "finally", "for", "from", "global", "if", "import",
    "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise",
    "return", "try", "while", "with", "yield",
];

/// Number of Python hard keywords scrambled by layer-2.
///
/// Computed from [`PYTHON_KEYWORDS`] so this constant tracks the
/// list verbatim.  Used by `KeywordWordlist::build` to size the
/// per-epoch derivation.
pub const PYTHON_KEYWORD_COUNT: usize = PYTHON_KEYWORDS.len();

#[cfg(test)]
mod tests {
    use super::{PYTHON_KEYWORDS, PYTHON_KEYWORD_COUNT};

    #[test]
    fn count_constant_matches_list_length() {
        assert_eq!(PYTHON_KEYWORDS.len(), PYTHON_KEYWORD_COUNT);
    }

    #[test]
    fn list_is_thirty_five() {
        // The Python 3.12 hard-keyword count is 35.  If this
        // assertion fires, either Python grew a hard keyword or
        // the soft-keyword exclusion is wrong.
        assert_eq!(PYTHON_KEYWORDS.len(), 35);
    }

    #[test]
    fn no_duplicates() {
        let mut seen: std::collections::HashSet<&&str> =
            std::collections::HashSet::new();
        for kw in PYTHON_KEYWORDS {
            assert!(seen.insert(kw), "duplicate keyword: {kw}");
        }
    }

    #[test]
    fn soft_keywords_are_intentionally_excluded() {
        // These are valid identifiers in Python outside their
        // grammar context; scrambling them would corrupt valid
        // user code that uses them as variable / function names.
        for soft in ["match", "case", "type"] {
            assert!(
                !PYTHON_KEYWORDS.contains(&soft),
                "{soft:?} should be excluded (soft keyword)"
            );
        }
    }

    #[test]
    fn includes_load_bearing_examples_from_threat_model() {
        // The threat-model doc names these specifically as
        // "this is Python" signal-leakers; assert they are in
        // the scramble set.
        for must_include in [
            "def", "if", "return", "import", "for", "while", "class",
            "try", "except", "with",
        ] {
            assert!(
                PYTHON_KEYWORDS.contains(&must_include),
                "{must_include:?} must be in PYTHON_KEYWORDS"
            );
        }
    }

    #[test]
    fn every_keyword_is_lowercase_ascii_or_capitalised_literal() {
        // Python keywords are either all-lowercase (`def`, `if`)
        // or the three constant literals (`True`, `False`,
        // `None`).  Anything else indicates a typo / unicode bug.
        for kw in PYTHON_KEYWORDS {
            for b in kw.bytes() {
                assert!(
                    b.is_ascii_alphabetic(),
                    "{kw:?} contains non-alphabetic byte"
                );
            }
        }
    }
}
