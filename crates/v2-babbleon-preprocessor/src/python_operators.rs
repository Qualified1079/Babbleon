//! Python operator strings scrambled by the operator-substitute pass.
//!
//! # What this defeats
//!
//! Layers L2 (keyword scramble) + L3 (whitespace-as-words) do not
//! touch operator characters.  After L2+L3 the scrambled wall-of-
//! text still reveals:
//!
//! - `( ) [ ] { }` — function-call shape, list / dict literals.
//! - `:` — block headers (`def foo():`), slice notation, dict
//!   entries, type annotations.
//! - `=` — assignments.
//! - `== != < > <= >=` — conditionals.
//! - `, ; .` — argument lists, attribute access.
//! - `** // ** << >>` — composite arithmetic / bitwise.
//!
//! Cross-reference the operator skeleton against the unscrambled
//! baseline of the same script and you locate function boundaries
//! and assignment targets trivially.  Operator scrambling closes
//! the gap so the scrambled output reveals neither keyword
//! identity nor structural skeleton.
//!
//! # Why this is part of the floor
//!
//! The HANDOFF rule (2026-06-22 entry): "operators should be
//! scrambled too as the floor.  ` `, `()`, `**`, `-`, etc."  This
//! module + `operator_wordlist` + `operator_scrambler` ship the
//! operator scramble alongside L2 keyword scramble; together they
//! constitute the actual phase-3 floor.
//!
//! # What this MVP does NOT scramble
//!
//! Three operator characters interact with Python's lexical
//! recognition of numeric literals: `.` (decimal point), `+` /
//! `-` (signs and binary), and `e` / `E` (exponent in scientific
//! notation).  Naively splitting on these would corrupt round-trip
//! for numeric literals like `1.5e10` or `3.14`.  The MVP omits
//! them; the proper fix is a number-literal-aware splitter that
//! treats a numeric literal as an opaque token before the operator
//! splitter runs.  Filed as a follow-up.
//!
//! The MVP also omits `*` and `/` for symmetry with `+ -` (they
//! can appear adjacent to numeric literals in `n*2` where the
//! tokenizer produces a single `Word("n*2")` — splitting on `*`
//! would expose `2` as a literal but that's fine; the worry is
//! `1e2` where `e` looks operator-like but is part of the literal).
//! `*` / `/` are filed for the same follow-up.
//!
//! Operators DO scrambled by the MVP (37 entries):

/// Python operators substituted by the layer-2b operator scramble.
///
/// **Longest-first ordering is load-bearing.**  The operator
/// scrambler does longest-prefix match against this list at each
/// byte position; reordering shuffles which operator matches at a
/// position where multiple candidates are prefixes of each other
/// (`**=` vs `**` vs `*`, `==` vs `=`, `<=` vs `<`).
///
/// Order is also the slot index for the per-epoch wordlist
/// derivation.  Bumping the list (additions or reorderings)
/// invalidates every previously-derived operator mapping and is
/// equivalent to forcing an immediate rotation of every host's
/// operator compounds.
pub const PYTHON_OPERATORS: &[&str] = &[
    // 3-char (longest first).
    "**=", "//=", ">>=", "<<=", "...",
    // 2-char.
    "**", "//", ">>", "<<", "==", "!=", "<=", ">=",
    "+=", "-=", "*=", "/=", "%=", "@=", "&=", "|=", "^=",
    ":=", "->",
    // 1-char.  Excludes `+ - * / % @ . e E` per the MVP note in
    // the module docs (numeric-literal interaction).
    "=", "(", ")", "[", "]", "{", "}",
    ",", ":", ";",
    "<", ">",
    "&", "|", "^", "~",
];

/// Number of Python operator strings scrambled by layer 2b.
///
/// Computed from [`PYTHON_OPERATORS`] so this constant tracks the
/// list verbatim.  Used by `OperatorWordlist::build` to size the
/// per-epoch derivation.
pub const PYTHON_OPERATOR_COUNT: usize = PYTHON_OPERATORS.len();

#[cfg(test)]
mod tests {
    use super::{PYTHON_OPERATORS, PYTHON_OPERATOR_COUNT};

    #[test]
    fn count_constant_matches_list_length() {
        assert_eq!(PYTHON_OPERATORS.len(), PYTHON_OPERATOR_COUNT);
    }

    #[test]
    fn no_duplicates() {
        let mut seen: std::collections::HashSet<&&str> =
            std::collections::HashSet::new();
        for op in PYTHON_OPERATORS {
            assert!(seen.insert(op), "duplicate operator: {op}");
        }
    }

    #[test]
    fn longest_first_ordering_is_preserved() {
        // For every pair (a, b) where a starts with b, a must come
        // before b in the list.  Otherwise longest-prefix match
        // would select b first and corrupt the splitter.
        for (i, a) in PYTHON_OPERATORS.iter().enumerate() {
            for (j, b) in PYTHON_OPERATORS.iter().enumerate() {
                if i == j {
                    continue;
                }
                if a.starts_with(b) && a.len() > b.len() {
                    assert!(
                        i < j,
                        "{a:?} (longer prefix of {b:?}) must appear before \
                         {b:?}; got {a:?}@{i} and {b:?}@{j}",
                    );
                }
            }
        }
    }

    #[test]
    fn includes_structural_skeleton_operators() {
        // These operators reveal program structure without
        // disclosing identifiers.  All must be in the scramble
        // set or the floor leaks the structural skeleton.
        for must_include in [
            "(", ")", "[", "]", "{", "}", "=", ":", ",", ";",
            "==", "!=", "<=", ">=", "<", ">", "->",
        ] {
            assert!(
                PYTHON_OPERATORS.contains(&must_include),
                "{must_include:?} must be in PYTHON_OPERATORS"
            );
        }
    }

    #[test]
    fn excludes_numeric_literal_interacting_chars() {
        // These chars appear inside numeric literals and the
        // MVP intentionally omits them; see module docs.
        for must_exclude in [".", "+", "-", "*", "/", "e", "E"] {
            assert!(
                !PYTHON_OPERATORS.contains(&must_exclude),
                "{must_exclude:?} must NOT be in MVP PYTHON_OPERATORS \
                 (numeric-literal interaction)"
            );
        }
    }
}
