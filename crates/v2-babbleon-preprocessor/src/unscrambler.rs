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
/// Indent state machine:
///
/// - `IndentOpen` increments the running level; emits no bytes
///   itself.
/// - `IndentClose` decrements; emits no bytes itself.
/// - `Newline` emits `\n` and arms `at_line_start`.
/// - `Word` and `Tab` flush leading indent (`INDENT_WIDTH × level`
///   spaces) if `at_line_start`, then emit their content.
/// - `Space` at line start is suppressed (it would duplicate the
///   leading indent the state machine just emitted).
#[must_use]
pub fn tokens_to_source(tokens: &[Token]) -> String {
    let mut out = String::new();
    let mut level: usize = 0;
    let mut at_line_start = true;

    for token in tokens {
        match token {
            Token::Whitespace(WhitespaceKind::Newline) => {
                out.push('\n');
                at_line_start = true;
            }
            Token::Whitespace(WhitespaceKind::IndentOpen) => {
                level = level.saturating_add(1);
            }
            Token::Whitespace(WhitespaceKind::IndentClose) => {
                level = level.saturating_sub(1);
            }
            Token::Whitespace(WhitespaceKind::Space) => {
                if !at_line_start {
                    out.push(' ');
                }
            }
            Token::Whitespace(WhitespaceKind::Tab) => {
                if at_line_start {
                    emit_indent(&mut out, level);
                    at_line_start = false;
                }
                out.push('\t');
            }
            Token::Word(s) => {
                if at_line_start {
                    emit_indent(&mut out, level);
                    at_line_start = false;
                }
                out.push_str(s);
            }
        }
    }
    out
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
