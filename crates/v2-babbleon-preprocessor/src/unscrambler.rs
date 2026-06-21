//! Scrambled byte string → reconstructed source.
//!
//! # What this defeats
//!
//! Cooperates with `scrambler` to defeat structural fingerprinting
//! (see crate-level docs).  The unscrambler is the runtime
//! transform: it reads the scrambled byte string, recovers the
//! `Token` stream by greedy longest-prefix matching against the
//! per-epoch whitespace wordlist, and re-emits the source with
//! canonicalised whitespace and `INDENT_WIDTH`-space-per-level
//! indentation.
//!
//! # `COLLISION_NOTE`
//!
//! The greedy matcher assumes whitespace compounds and `Word`
//! bytes are unambiguously distinguishable: no real `Word` byte
//! run contains a whitespace compound as a substring.  With
//! `COMPOUND_N = 4` words drawn from a 370 k-entry wordlist, the
//! odds of a non-decoy compound appearing in real source are
//! astronomically low for any realistic file (a typical Python
//! file's longest contiguous identifier is ~30 characters; a
//! whitespace compound averages ~25 bytes of four random words,
//! and the four-word sequence appearing in code is bounded by
//! `1 / 370 000⁴ ≈ 5 × 10⁻²³` per substring start position).  The
//! `scrambler` pre-flight check raises
//! `Error::WhitespaceCompoundCollision` if it ever happens.
//!
//! A future-MVP fix that eliminates this class of collision
//! entirely is the reserved-pool design in `docs/v2/structure-
//! scrambling.md` Open Question §1: allocate a disjoint
//! whitespace sub-pool from the main wordlist at build time so
//! identifier compounds and whitespace compounds are drawn from
//! mutually exclusive word sets.  Not in MVP scope; this note
//! exists so the next session doesn't re-derive the analysis.

use crate::errors::Result;
use crate::python_tokenizer::INDENT_WIDTH;
use crate::tokens::{Token, WhitespaceKind};
use crate::whitespace_wordlist::WhitespaceWordlist;

/// Parse a scrambled string back into the `Token` stream.
///
/// Greedy longest-prefix match against the five whitespace
/// compounds.  Bytes between two whitespace matches form one
/// `Token::Word`.
///
/// # Errors
///
/// - `Error::TruncatedScrambledInput` is *not* raised by this
///   function in MVP scope; any leftover bytes after the last
///   whitespace match are emitted as a final `Token::Word`.  The
///   variant is reserved for a future stricter mode.
#[must_use]
pub fn unscramble_to_tokens(
    scrambled: &str,
    wl: &WhitespaceWordlist,
) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut word_buf = String::new();
    let mut i = 0;
    let bytes = scrambled.as_bytes();

    while i < bytes.len() {
        if let Some((kind, len)) = wl.match_prefix(&scrambled[i..]) {
            if !word_buf.is_empty() {
                tokens.push(Token::Word(std::mem::take(&mut word_buf)));
            }
            tokens.push(Token::whitespace(kind));
            i += len;
        } else {
            // Advance one UTF-8 character into the word buffer.
            // String slicing requires character boundaries; find
            // the next char boundary.
            let ch_len = next_char_len(bytes, i);
            // Copy the char's bytes via the original &str.
            word_buf.push_str(&scrambled[i..i + ch_len]);
            i += ch_len;
        }
    }
    if !word_buf.is_empty() {
        tokens.push(Token::Word(word_buf));
    }
    tokens
}

/// UTF-8 length of the character starting at `i` in `bytes`.
///
/// Assumes `bytes` is valid UTF-8 (it came from a `&str`).  Returns
/// 1, 2, 3, or 4.
fn next_char_len(bytes: &[u8], i: usize) -> usize {
    let b = bytes[i];
    if b < 0x80 {
        1
    } else if b < 0xC0 {
        // Continuation byte — shouldn't happen at char boundary,
        // but be conservative and advance one byte.
        1
    } else if b < 0xE0 {
        2
    } else if b < 0xF0 {
        3
    } else {
        4
    }
}

/// Re-emit a `Token` stream as canonical source bytes.
///
/// # Indent state machine
///
/// - `IndentOpen` increments the running level; emits no bytes
///   itself.
/// - `IndentClose` decrements; emits no bytes itself.
/// - `Newline` emits `\n` and clears `leading_emitted` so the
///   next non-newline whitespace can fire the leading-indent block.
/// - `Word`, `Tab`, and `Space` all fire the leading-indent block
///   on first occurrence of the line (`leading_emitted` gates
///   it).  After the block fires, they each push their content.
///
/// # Why `Space` at line start is not suppressed
///
/// An earlier revision suppressed `Space` tokens whenever the
/// line had not yet started any content, reasoning that the
/// indent state machine had "already" emitted `level × 4` spaces
/// at the first `Word`.  That guard discarded `Space` tokens the
/// tokenizer emitted as **residuals** of an unaligned indent —
/// e.g. a line of seven leading spaces decomposes to `(level=1,
/// residual_spaces=3)`; the three residuals were dropped on
/// re-emission and the recovered source was `level × 4 = 4`
/// spaces instead of seven.  This broke round-trip for
/// continuation lines inside triple-quoted strings whose indent
/// was not a multiple of `INDENT_WIDTH`.
///
/// The fix: track `leading_emitted` (did we already fire the
/// indent block for *this* line?) instead of `at_line_start`
/// (have we seen any content for this line?).  `Space` at the
/// first column fires the indent block if not yet fired, then
/// pushes ' ' — so a line with seven leading spaces re-emits
/// as `INDENT_WIDTH + 3 = 7` spaces, preserving the residual.
/// `Tab` and `Word` keep the same behaviour: fire indent, then
/// push content.
#[must_use]
pub fn tokens_to_source(tokens: &[Token]) -> String {
    let mut out = String::new();
    let mut level: usize = 0;
    // True iff the leading-indent block has already been emitted
    // for the line currently being constructed.  Reset on every
    // `Newline`.  Distinct from "have we seen any content" because
    // a leading `Space` is content but must still fire the block
    // exactly once.
    let mut leading_emitted = false;

    for token in tokens {
        match token {
            Token::Whitespace(WhitespaceKind::Newline) => {
                out.push('\n');
                leading_emitted = false;
            }
            Token::Whitespace(WhitespaceKind::IndentOpen) => {
                level = level.saturating_add(1);
            }
            Token::Whitespace(WhitespaceKind::IndentClose) => {
                level = level.saturating_sub(1);
            }
            Token::Whitespace(WhitespaceKind::Space) => {
                fire_indent_block_if_needed(&mut out, level, &mut leading_emitted);
                out.push(' ');
            }
            Token::Whitespace(WhitespaceKind::Tab) => {
                fire_indent_block_if_needed(&mut out, level, &mut leading_emitted);
                out.push('\t');
            }
            Token::Word(s) => {
                fire_indent_block_if_needed(&mut out, level, &mut leading_emitted);
                out.push_str(s);
            }
        }
    }
    out
}

/// Emit the line's leading `level × INDENT_WIDTH` spaces if and only
/// if the block has not already been emitted for this line.
///
/// Idempotent within a line; reset on every `Newline` via the
/// caller's `leading_emitted` flag.
fn fire_indent_block_if_needed(
    out: &mut String,
    level: usize,
    leading_emitted: &mut bool,
) {
    if !*leading_emitted {
        emit_indent(out, level);
        *leading_emitted = true;
    }
}

/// Push `INDENT_WIDTH × level` spaces onto `out`.
fn emit_indent(out: &mut String, level: usize) {
    for _ in 0..(level * INDENT_WIDTH) {
        out.push(' ');
    }
}

/// One-shot unscramble: scrambled bytes → reconstructed source.
///
/// Convenience wrapper over `unscramble_to_tokens` +
/// `tokens_to_source`.
///
/// # Errors
///
/// Currently infallible in MVP scope; signature returns `Result`
/// so future strict-mode failures can be added without a wire
/// break.  Returns the wrapped string in the `Ok` case.
pub fn unscramble(
    scrambled: &str,
    wl: &WhitespaceWordlist,
) -> Result<String> {
    let tokens = unscramble_to_tokens(scrambled, wl);
    Ok(tokens_to_source(&tokens))
}

#[cfg(test)]
mod tests {
    use super::{tokens_to_source, unscramble, unscramble_to_tokens};
    use crate::python_tokenizer::tokenize;
    use crate::scrambler::scramble;
    use crate::tokens::{Token, WhitespaceKind};
    use crate::whitespace_wordlist::WhitespaceWordlist;
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn fixed_wl() -> WhitespaceWordlist {
        let s = PerHostSecret::from_bytes(&[11u8; 32]).unwrap();
        WhitespaceWordlist::build(&s, Wordlist::english_baseline(), 0).unwrap()
    }

    #[test]
    fn empty_scrambled_yields_empty_token_stream() {
        let wl = fixed_wl();
        assert!(unscramble_to_tokens("", &wl).is_empty());
    }

    #[test]
    fn pure_word_yields_single_word_token() {
        let wl = fixed_wl();
        assert_eq!(
            unscramble_to_tokens("hello", &wl),
            vec![Token::word("hello")]
        );
    }

    #[test]
    fn pure_whitespace_compound_yields_single_whitespace_token() {
        let wl = fixed_wl();
        let s = wl.compound_for(WhitespaceKind::Newline).to_string();
        assert_eq!(
            unscramble_to_tokens(&s, &wl),
            vec![Token::whitespace(WhitespaceKind::Newline)]
        );
    }

    #[test]
    fn tokens_to_source_emits_newline_for_newline_token() {
        let out = tokens_to_source(&[
            Token::word("a"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::word("b"),
        ]);
        assert_eq!(out, "a\nb");
    }

    #[test]
    fn indent_open_indents_subsequent_line() {
        let out = tokens_to_source(&[
            Token::word("a"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::whitespace(WhitespaceKind::IndentOpen),
            Token::word("b"),
        ]);
        assert_eq!(out, "a\n    b");
    }

    #[test]
    fn indent_close_dedents_subsequent_line() {
        let out = tokens_to_source(&[
            Token::word("a"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::whitespace(WhitespaceKind::IndentOpen),
            Token::word("b"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::whitespace(WhitespaceKind::IndentClose),
            Token::word("c"),
        ]);
        assert_eq!(out, "a\n    b\nc");
    }

    #[test]
    fn round_trip_through_tokenize_scramble_unscramble_for_simple_source() {
        let wl = fixed_wl();
        let src = "def f(x):\n    return x\n";
        let tokens = tokenize(src);
        let scrambled = scramble(&tokens, &wl).unwrap();
        let reconstructed = unscramble(&scrambled, &wl).unwrap();
        assert_eq!(reconstructed, src);
    }

    #[test]
    fn round_trip_preserves_string_with_internal_spaces() {
        let wl = fixed_wl();
        let src = "x = \"a  b  c\"\n";
        let tokens = tokenize(src);
        let scrambled = scramble(&tokens, &wl).unwrap();
        let reconstructed = unscramble(&scrambled, &wl).unwrap();
        assert_eq!(reconstructed, src);
    }

    #[test]
    fn round_trip_preserves_comment_with_internal_spaces() {
        let wl = fixed_wl();
        let src = "x = 1  # one  two  three\n";
        let tokens = tokenize(src);
        let scrambled = scramble(&tokens, &wl).unwrap();
        let reconstructed = unscramble(&scrambled, &wl).unwrap();
        assert_eq!(reconstructed, src);
    }

    #[test]
    fn round_trip_preserves_nested_indent() {
        let wl = fixed_wl();
        let src = "def f(x):\n    if x:\n        return 1\n    return 0\n";
        let tokens = tokenize(src);
        let scrambled = scramble(&tokens, &wl).unwrap();
        let reconstructed = unscramble(&scrambled, &wl).unwrap();
        assert_eq!(reconstructed, src);
    }

    #[test]
    fn round_trip_preserves_fizzbuzz_puzzle_skeleton() {
        let wl = fixed_wl();
        let src = "def fizzbuzz(n):\n    \
                   results = []\n    \
                   for i in range(1, n + 1):\n        \
                   results.append(str(i))\n    \
                   return results\n";
        let tokens = tokenize(src);
        let scrambled = scramble(&tokens, &wl).unwrap();
        let reconstructed = unscramble(&scrambled, &wl).unwrap();
        assert_eq!(reconstructed, src);
    }

    /// Regression: a line with non-multiple-of-4 leading spaces
    /// inside a multi-line triple-quoted string used to lose the
    /// residual whitespace on round-trip (the `tokens_to_source`
    /// pass suppressed `Space` tokens at line start).  This test
    /// asserts the residuals are preserved.
    #[test]
    fn round_trip_preserves_3_space_residual_inside_multi_line_string() {
        let wl = fixed_wl();
        let src = "x = \"\"\"hello\n   world\"\"\"\n";
        let tokens = tokenize(src);
        let scrambled = scramble(&tokens, &wl).unwrap();
        let reconstructed = unscramble(&scrambled, &wl).unwrap();
        assert_eq!(reconstructed, src);
    }

    /// Regression: a line with seven leading spaces (one indent
    /// level + three residual) used to re-emit as four spaces.
    #[test]
    fn round_trip_preserves_seven_leading_spaces_one_level_plus_three_residual() {
        let wl = fixed_wl();
        let src = "x = \"\"\"hello\n       world\"\"\"\n";
        let tokens = tokenize(src);
        let scrambled = scramble(&tokens, &wl).unwrap();
        let reconstructed = unscramble(&scrambled, &wl).unwrap();
        assert_eq!(reconstructed, src);
    }

    /// `tokens_to_source` directly: leading `Space` tokens at
    /// `level=0` re-emit as visible leading spaces (not swallowed).
    #[test]
    fn tokens_to_source_preserves_leading_spaces_at_level_zero() {
        let out = tokens_to_source(&[
            Token::whitespace(WhitespaceKind::Space),
            Token::whitespace(WhitespaceKind::Space),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("x"),
        ]);
        assert_eq!(out, "   x");
    }

    /// `tokens_to_source` directly: leading `Space` tokens at
    /// `level=1` re-emit AFTER the level-driven indent block.
    /// Catches a regression where `Space` would fire its own indent
    /// AND the Word also fired a duplicate indent.
    #[test]
    fn tokens_to_source_emits_indent_once_per_line_with_leading_residuals() {
        let out = tokens_to_source(&[
            Token::whitespace(WhitespaceKind::IndentOpen),
            Token::whitespace(WhitespaceKind::Space),
            Token::whitespace(WhitespaceKind::Space),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("x"),
        ]);
        // level=1 → 4 spaces from indent + 3 residual + "x" = 7 spaces + x.
        assert_eq!(out, "       x");
    }

    /// Empty lines stay empty — no spurious indent emitted for a
    /// line that has only a `Newline` token.
    #[test]
    fn tokens_to_source_does_not_indent_empty_lines() {
        let out = tokens_to_source(&[
            Token::whitespace(WhitespaceKind::IndentOpen),
            Token::word("body"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::whitespace(WhitespaceKind::Newline),
            Token::word("more"),
        ]);
        assert_eq!(out, "    body\n\n    more");
    }

    #[test]
    fn scrambled_output_has_no_visible_indent_or_newline_chars() {
        let wl = fixed_wl();
        let src = "def f():\n    return 1\n";
        let tokens = tokenize(src);
        let scrambled = scramble(&tokens, &wl).unwrap();
        // The whole point of layer 3: scrambled bytes contain no
        // newline or leading-space cluster — only word characters.
        assert!(!scrambled.contains('\n'));
        // Spaces *can* appear if the original source had them
        // between identifiers and operators (e.g. `x = 1`), but
        // they shouldn't form a long leading cluster.  Our test
        // input has them, so we don't assert the no-space
        // property; instead check that no `\n` appears.
    }
}
