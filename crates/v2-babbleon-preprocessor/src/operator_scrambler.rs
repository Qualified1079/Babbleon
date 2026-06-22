//! Layer-2b operator scramble — Token-stream transform.
//!
//! # What this defeats
//!
//! See [`crate::python_operators`] for the threat-model framing.
//! This module is the pass that walks the Token stream, splits
//! each `Token::Word` body on operator substrings, replaces the
//! operator substrings with per-epoch wordlist compounds, and
//! inserts `Token::Whitespace(Space)` markers around the splits
//! so the downstream L3 whitespace scramble produces a wall of
//! compounds with whitespace-compounds as unambiguous delimiters.
//!
//! # Composition order
//!
//! Layers compose at the Token level in this order at scramble
//! time:
//!
//! 1. tokenize
//! 2. [`scramble_keywords`](crate::scramble_keywords)
//! 3. [`scramble_operators`] (this module)
//! 4. [`scrambler::scramble`](crate::scrambler::scramble)
//!    (whitespace-as-words)
//! 5. bytes
//!
//! Inverse on unscramble.  Step 3 must run AFTER step 2 because
//! the keyword pass rewrites `Word("def")` to `Word(<compound>)`
//! before this pass can incorrectly try to split a compound
//! against an operator (compounds are pure-ASCII-lowercase and
//! contain no operator characters, so step ordering is a defence
//! in depth not a correctness requirement, but the order is
//! deterministic and documented).
//!
//! # String / comment / number guards
//!
//! The pass DOES NOT split:
//!
//! - Words whose first byte is `"`, `'`, or `#` (string literal or
//!   line comment — already opaque per the tokenizer's
//!   `LineState::DoubleQuoteString` / `SingleQuoteString` /
//!   `Comment` states).
//! - Words that are number literals.  The MVP operator list omits
//!   `. + - * / e E` for this reason; see
//!   `python_operators.rs` module docs.  Numeric literals
//!   therefore contain none of the MVP operator chars and pass
//!   through unchanged by construction.
//! - Empty Word fragments (created by adjacent operators) — they
//!   are dropped to keep the Token stream tight.
//!
//! # Round-trip semantics
//!
//! Source `x=1` round-trips to `x = 1` (operator splitter
//! inserts a Space around `=`).  This is a normalisation, not a
//! corruption — Python's tokenizer accepts whitespace around
//! every operator in the MVP scramble list.  Test cases in this
//! module assert the normalised round-trip explicitly.

use crate::operator_wordlist::OperatorWordlist;
use crate::python_operators::PYTHON_OPERATORS;
use crate::tokens::{Token, WhitespaceKind};

/// Walk the Token stream and rewrite each non-literal, non-
/// comment `Token::Word(body)` by splitting on operator
/// substrings, replacing them with per-epoch compounds, and
/// inserting `Whitespace(Space)` around the splits.
///
/// Allocates a new `Vec<Token>` because the splits change the
/// token count.  Token-count invariant (L2's "one in, one out")
/// is NOT preserved by this pass — it cannot be, the split is
/// the whole point.
#[must_use]
pub fn scramble_operators(tokens: Vec<Token>, owl: &OperatorWordlist) -> Vec<Token> {
    let mut out: Vec<Token> = Vec::with_capacity(tokens.len() * 2);
    for token in tokens {
        match token {
            Token::Whitespace(_) => out.push(token),
            Token::Word(body) => {
                if is_string_or_comment_word(&body) {
                    out.push(Token::Word(body));
                    continue;
                }
                split_word_into_tokens(&body, owl, &mut out);
            }
        }
    }
    out
}

/// Inverse of [`scramble_operators`].
///
/// For every `Token::Word(body)` whose body matches an operator
/// compound under the per-epoch table, replace the body with the
/// original operator string.  The surrounding Whitespace(Space)
/// tokens that the scramble pass inserted are NOT removed — they
/// re-emit as visible spaces in the unscrambled source, which
/// Python accepts.  The original source's spacing around
/// operators is therefore not reconstructed exactly; this is the
/// documented normalisation.
///
/// Token count invariant: one in, one out.  Faster than the
/// scrambler (no allocation if no rewrites trigger).
pub fn unscramble_operators(tokens: &mut [Token], owl: &OperatorWordlist) {
    for token in tokens.iter_mut() {
        if let Token::Word(body) = token {
            if let Some(op) = owl.reverse_lookup(body.as_str()) {
                *body = op.to_string();
            }
        }
    }
}

/// True iff `body` is a Word the splitter should leave alone.
fn is_string_or_comment_word(body: &str) -> bool {
    matches!(body.as_bytes().first(), Some(b'"' | b'\'' | b'#'))
}

/// State of the per-Word splitter as it walks bytes.  String
/// literals inside the Word body (`"..."`, `'...'`, including
/// f/r/b prefixes) must NOT have their interior split on
/// operators — `"a=b"` should pass through, not become
/// `"a` + `<compound for =>` + `b"`.
#[derive(Debug)]
enum SplitState {
    /// Default: split operators normally.
    Code,
    /// Inside a `"..."` literal.  Reset to `Code` on the closing
    /// `"`.  Escapes (`\X`) consume two bytes.
    DoubleString,
    /// Inside a `'...'` literal.  Same shape as `DoubleString`.
    SingleString,
}

/// Split `body` on operator substrings (longest match) and push
/// the resulting `Word` + `Whitespace(Space)` sequence onto `out`.
///
/// Tracks an internal string-literal state so operators inside
/// `"..."` and `'...'` are never split.  This handles `print(f"hi")`
/// and similar cases where the tokenizer produces a single Word
/// containing both code and string content.
fn split_word_into_tokens(
    body: &str,
    owl: &OperatorWordlist,
    out: &mut Vec<Token>,
) {
    let bytes = body.as_bytes();
    let mut frag = String::new();
    let mut state = SplitState::Code;
    let mut i = 0;
    while i < bytes.len() {
        match state {
            SplitState::DoubleString | SplitState::SingleString => {
                // Inside a string literal: never split on operators.
                // Just accumulate bytes (handling backslash escapes
                // so an escaped quote doesn't close the string).
                let b = bytes[i];
                let ch_len = utf8_char_len(b);
                frag.push_str(
                    std::str::from_utf8(&bytes[i..i + ch_len])
                        .expect("source is UTF-8 by construction"),
                );
                if b == b'\\' && i + 1 + ch_len <= bytes.len() {
                    // Consume the next byte verbatim too.
                    let next_len = utf8_char_len(bytes[i + ch_len]);
                    frag.push_str(
                        std::str::from_utf8(
                            &bytes[i + ch_len..i + ch_len + next_len],
                        )
                        .expect("source is UTF-8 by construction"),
                    );
                    i += ch_len + next_len;
                    continue;
                }
                if matches!(state, SplitState::DoubleString) && b == b'"' {
                    state = SplitState::Code;
                } else if matches!(state, SplitState::SingleString) && b == b'\'' {
                    state = SplitState::Code;
                }
                i += ch_len;
            }
            SplitState::Code => {
                if bytes[i] == b'"' {
                    // Quote opens a string literal.  Accumulate
                    // the quote into the current fragment so it
                    // re-emerges verbatim on round-trip.
                    frag.push('"');
                    state = SplitState::DoubleString;
                    i += 1;
                    continue;
                }
                if bytes[i] == b'\'' {
                    frag.push('\'');
                    state = SplitState::SingleString;
                    i += 1;
                    continue;
                }
                if let Some((op, op_len)) = match_operator_at(&bytes[i..]) {
                    if !frag.is_empty() {
                        out.push(Token::Word(std::mem::take(&mut frag)));
                        out.push(Token::whitespace(WhitespaceKind::Space));
                    }
                    let compound = owl
                        .compound_for(op)
                        .expect("operator from match_operator_at must be in OWL");
                    out.push(Token::Word(compound.to_string()));
                    out.push(Token::whitespace(WhitespaceKind::Space));
                    i += op_len;
                } else {
                    let ch_len = utf8_char_len(bytes[i]);
                    frag.push_str(
                        std::str::from_utf8(&bytes[i..i + ch_len])
                            .expect("source is UTF-8 by construction"),
                    );
                    i += ch_len;
                }
            }
        }
    }
    if !frag.is_empty() {
        out.push(Token::Word(frag));
    }
}

/// Find the longest operator that prefixes `bytes`, or `None`.
///
/// Walks [`PYTHON_OPERATORS`] in declaration order — which is
/// longest-first per the unit test in `python_operators` — and
/// returns the first match.  O(N × max-op-len); N is 37 and
/// max-op-len is 3, so this is effectively constant time per call.
fn match_operator_at(bytes: &[u8]) -> Option<(&'static str, usize)> {
    for op in PYTHON_OPERATORS {
        let op_bytes = op.as_bytes();
        if bytes.len() >= op_bytes.len() && &bytes[..op_bytes.len()] == op_bytes {
            return Some((op, op_bytes.len()));
        }
    }
    None
}

/// UTF-8 byte width of the character whose leading byte is
/// `leading`.  Returns 1 for ASCII (which covers all operator
/// chars and most code).
const fn utf8_char_len(leading: u8) -> usize {
    if leading & 0x80 == 0 {
        1
    } else if leading & 0xE0 == 0xC0 {
        2
    } else if leading & 0xF0 == 0xE0 {
        3
    } else {
        4
    }
}

#[cfg(test)]
mod tests {
    use super::{scramble_operators, unscramble_operators};
    use crate::operator_wordlist::OperatorWordlist;
    use crate::python_operators::PYTHON_OPERATORS;
    use crate::tokens::{Token, WhitespaceKind};
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn owl() -> OperatorWordlist {
        let s = PerHostSecret::from_bytes(&[3u8; 32]).unwrap();
        OperatorWordlist::build(&s, Wordlist::english_baseline(), 0).unwrap()
    }

    #[test]
    fn empty_token_stream_returns_empty() {
        let out = scramble_operators(vec![], &owl());
        assert!(out.is_empty());
    }

    #[test]
    fn word_with_no_operators_passes_through() {
        let out = scramble_operators(vec![Token::word("hello")], &owl());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], Token::word("hello"));
    }

    #[test]
    fn single_operator_word_splits_to_compound() {
        let owl = owl();
        let compound_eq = owl.compound_for("=").unwrap().to_string();
        let out = scramble_operators(vec![Token::word("=")], &owl);
        assert_eq!(out.len(), 2, "got {out:?}");
        assert_eq!(out[0], Token::Word(compound_eq));
        assert_eq!(out[1], Token::whitespace(WhitespaceKind::Space));
    }

    #[test]
    fn x_equals_one_splits_into_three_chunks() {
        let owl = owl();
        let out = scramble_operators(vec![Token::word("x=1")], &owl);
        // Expected sequence (token kinds in order):
        // Word("x"), Space, Word(compound_for_eq), Space, Word("1")
        assert_eq!(out.len(), 5, "got {out:?}");
        assert_eq!(out[0], Token::word("x"));
        assert_eq!(out[1], Token::whitespace(WhitespaceKind::Space));
        assert_eq!(
            out[2],
            Token::Word(owl.compound_for("=").unwrap().to_string()),
        );
        assert_eq!(out[3], Token::whitespace(WhitespaceKind::Space));
        assert_eq!(out[4], Token::word("1"));
    }

    #[test]
    fn longest_match_picks_two_char_over_one_char() {
        let owl = owl();
        // `==` should NOT split into two `=` operators.
        let out = scramble_operators(vec![Token::word("a==b")], &owl);
        // Expect: Word("a"), Space, Word(compound_for_eq_eq), Space, Word("b")
        assert_eq!(out.len(), 5);
        assert_eq!(
            out[2],
            Token::Word(owl.compound_for("==").unwrap().to_string()),
        );
    }

    #[test]
    fn longest_match_picks_three_char_over_two_char() {
        let owl = owl();
        // `**=` should NOT split into `**` then `=`.
        let out = scramble_operators(vec![Token::word("a**=b")], &owl);
        assert_eq!(out.len(), 5);
        assert_eq!(
            out[2],
            Token::Word(owl.compound_for("**=").unwrap().to_string()),
        );
    }

    #[test]
    fn adjacent_operators_each_get_their_own_compound() {
        // `()` is two operators: `(` and `)`.  Should produce two
        // compounds, no merged Word between them.
        let owl = owl();
        let out = scramble_operators(vec![Token::word("()")], &owl);
        // Expect: Word(compound_for_open), Space, Word(compound_for_close), Space
        assert_eq!(out.len(), 4);
        assert_eq!(
            out[0],
            Token::Word(owl.compound_for("(").unwrap().to_string()),
        );
        assert_eq!(out[1], Token::whitespace(WhitespaceKind::Space));
        assert_eq!(
            out[2],
            Token::Word(owl.compound_for(")").unwrap().to_string()),
        );
        assert_eq!(out[3], Token::whitespace(WhitespaceKind::Space));
    }

    #[test]
    fn string_literal_words_pass_through_untouched() {
        let owl = owl();
        // Word starting with `"` is a string literal in the
        // tokenizer's framing.  Even if it contains operator
        // chars inside, do not split.
        let original = Token::word("\"a=b()\"");
        let out = scramble_operators(vec![original.clone()], &owl);
        assert_eq!(out, vec![original]);
    }

    #[test]
    fn single_quote_string_literal_passes_through() {
        let owl = owl();
        let original = Token::word("'a=b'");
        let out = scramble_operators(vec![original.clone()], &owl);
        assert_eq!(out, vec![original]);
    }

    #[test]
    fn comment_word_passes_through() {
        let owl = owl();
        let original = Token::word("# x = 1");
        let out = scramble_operators(vec![original.clone()], &owl);
        assert_eq!(out, vec![original]);
    }

    #[test]
    fn whitespace_tokens_are_preserved_in_order() {
        let owl = owl();
        let input = vec![
            Token::whitespace(WhitespaceKind::Newline),
            Token::word("a"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("b"),
        ];
        let out = scramble_operators(input.clone(), &owl);
        // No operators in any Word — output should equal input.
        assert_eq!(out, input);
    }

    #[test]
    fn round_trip_x_equals_one_via_normalised_form() {
        // Source `x=1` round-trips to a Token sequence that, when
        // unscrambled and re-emitted, normalises to `x = 1`
        // (Python-equivalent).  Test asserts the scramble +
        // unscramble cycle restores `=` (not the compound) in the
        // middle position.
        let owl = owl();
        let scrambled = scramble_operators(vec![Token::word("x=1")], &owl);
        let mut unscrambled = scrambled;
        unscramble_operators(&mut unscrambled, &owl);
        // Expected: Word("x"), Space, Word("="), Space, Word("1")
        assert_eq!(unscrambled.len(), 5);
        assert_eq!(unscrambled[0], Token::word("x"));
        assert_eq!(unscrambled[1], Token::whitespace(WhitespaceKind::Space));
        assert_eq!(unscrambled[2], Token::word("="));
        assert_eq!(unscrambled[3], Token::whitespace(WhitespaceKind::Space));
        assert_eq!(unscrambled[4], Token::word("1"));
    }

    #[test]
    fn every_operator_round_trips() {
        let owl = owl();
        for op in PYTHON_OPERATORS {
            let input = vec![Token::Word(format!("a{op}b"))];
            let scrambled = scramble_operators(input, &owl);
            let mut unscrambled = scrambled;
            unscramble_operators(&mut unscrambled, &owl);
            // Expect: Word("a"), Space, Word(op), Space, Word("b")
            assert_eq!(
                unscrambled.len(),
                5,
                "operator {op:?}: got {unscrambled:?}",
            );
            assert_eq!(unscrambled[0], Token::word("a"));
            assert_eq!(unscrambled[2], Token::Word((*op).to_string()));
            assert_eq!(unscrambled[4], Token::word("b"));
        }
    }

    #[test]
    fn function_signature_skeleton_is_scrambled() {
        // The structural skeleton of `def foo(x, y):`.  After
        // operator scramble + reverse, the `(`, `,`, `)`, `:`
        // are restored — but in the scrambled middle form their
        // compounds should NOT contain the original ASCII
        // characters.
        let owl = owl();
        // Pretend keyword scramble already converted `def` to
        // `<keyword-compound-for-def>`; here we just track the
        // operator pass.  Input as it would arrive after the L2
        // keyword pass:
        let input = vec![
            Token::word("def"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("foo(x,"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("y):"),
        ];
        let out = scramble_operators(input, &owl);
        // No `(`, `,`, `)`, `:` should survive as standalone
        // bytes in any Word body.  Walk Words and check.
        for tok in &out {
            if let Token::Word(b) = tok {
                for op in [":", "(", ")", ","] {
                    assert!(
                        !b.contains(op) || b.starts_with('"') || b.starts_with('#'),
                        "operator {op:?} survives in Word body {b:?}",
                    );
                }
            }
        }
    }
}
