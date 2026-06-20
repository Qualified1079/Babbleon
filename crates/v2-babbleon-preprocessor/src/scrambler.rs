//! Token-stream → scrambled byte string.
//!
//! # What this defeats
//!
//! Cooperates with `unscrambler` to defeat structural fingerprinting
//! (see crate-level docs).  The scrambler is the source-side
//! transform: it takes a `Token` stream produced by a tokenizer and
//! emits one continuous byte string where every whitespace marker
//! has been replaced by the per-epoch wordlist compound for its
//! kind.  Non-whitespace `Word` bytes are concatenated verbatim.
//!
//! # Mechanism
//!
//! For each token:
//!
//! - `Token::Word(s)` → append `s` to the output.
//! - `Token::Whitespace(kind)` → append
//!   `whitespace_wordlist.compound_for(kind)` to the output.
//!
//! That is the entire algorithm.  Layer 3 deliberately does not
//! transform `Word` bodies — layers 1 (identifier scramble) and 2
//! (operator scramble) operate at the `Token` level by rewriting
//! `Word` content before scramble; layer 4 (chunk reorder) and
//! layer 5 (decoy injection) operate as `Token`-stream passes
//! before scramble.  The composition story lives in
//! `docs/v2/structure-scrambling.md`.
//!
//! # Collision detection
//!
//! Before emitting, the scrambler checks every `Word` for a
//! whitespace-compound substring.  If found, `Error::
//! WhitespaceCompoundCollision` is raised — the operator's
//! workaround is to rotate the epoch (which picks new compounds).
//! The reserved-pool design that eliminates this collision class
//! entirely is filed in `docs/v2/structure-scrambling.md` Open
//! Question §1; not in MVP scope.

use crate::errors::{Error, Result};
use crate::tokens::Token;
use crate::whitespace_wordlist::WhitespaceWordlist;

/// Emit the scrambled byte string for a `Token` stream.
///
/// # Errors
///
/// - `Error::WhitespaceCompoundCollision` if any `Word` contains
///   one of the per-epoch whitespace compounds as a substring.
pub fn scramble(
    tokens: &[Token],
    wl: &WhitespaceWordlist,
) -> Result<String> {
    // Pre-flight collision check.  Done once over all words before
    // any output is written so we never produce a partial
    // ambiguous scramble.
    let mut output_len_hint = 0;
    for token in tokens {
        if let Token::Word(s) = token {
            check_word_against_wordlist(s, wl)?;
            output_len_hint += s.len();
        } else {
            // Each whitespace compound is small (4 words of average
            // ~6 chars = ~25 bytes), use that as a rough estimate.
            output_len_hint += 25;
        }
    }

    let mut out = String::with_capacity(output_len_hint);
    for token in tokens {
        match token {
            Token::Word(s) => out.push_str(s),
            Token::Whitespace(kind) => out.push_str(wl.compound_for(*kind)),
        }
    }
    Ok(out)
}

/// Raise `Error::WhitespaceCompoundCollision` if any of the five
/// compounds appears as a substring of `word`.
fn check_word_against_wordlist(
    word: &str,
    wl: &WhitespaceWordlist,
) -> Result<()> {
    for kind in crate::tokens::WhitespaceKind::ALL {
        let compound = wl.compound_for(kind);
        if word.contains(compound) {
            return Err(Error::WhitespaceCompoundCollision {
                kind,
                at: 0, // word-local offset is enough for diagnosis
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::scramble;
    use crate::tokens::{Token, WhitespaceKind};
    use crate::whitespace_wordlist::WhitespaceWordlist;
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn fixed_wl() -> WhitespaceWordlist {
        let s = PerHostSecret::from_bytes(&[9u8; 32]).unwrap();
        WhitespaceWordlist::build(&s, Wordlist::english_baseline(), 0).unwrap()
    }

    #[test]
    fn empty_token_stream_scrambles_to_empty_string() {
        let wl = fixed_wl();
        let out = scramble(&[], &wl).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn single_word_scrambles_to_itself() {
        let wl = fixed_wl();
        let out = scramble(&[Token::word("hello")], &wl).unwrap();
        assert_eq!(out, "hello");
    }

    #[test]
    fn single_whitespace_scrambles_to_compound() {
        let wl = fixed_wl();
        let out =
            scramble(&[Token::whitespace(WhitespaceKind::Space)], &wl).unwrap();
        assert_eq!(out, wl.compound_for(WhitespaceKind::Space));
    }

    #[test]
    fn whitespace_compounds_concatenate_words_with_no_separator() {
        let wl = fixed_wl();
        let out = scramble(
            &[
                Token::word("a"),
                Token::whitespace(WhitespaceKind::Space),
                Token::word("b"),
            ],
            &wl,
        )
        .unwrap();
        let expected = format!("a{}b", wl.compound_for(WhitespaceKind::Space));
        assert_eq!(out, expected);
    }

    #[test]
    fn collision_detected_when_word_contains_a_whitespace_compound() {
        let wl = fixed_wl();
        // Synthesize a word that includes the SPACE compound.
        let poison = wl.compound_for(WhitespaceKind::Space).to_string();
        let toks = vec![Token::word(format!("prefix{poison}suffix"))];
        let err = scramble(&toks, &wl).unwrap_err();
        match err {
            crate::errors::Error::WhitespaceCompoundCollision { kind, .. } => {
                assert_eq!(kind, WhitespaceKind::Space);
            }
            other => panic!("expected collision, got {other:?}"),
        }
    }

    #[test]
    fn all_kinds_round_trip_at_scramble_level() {
        let wl = fixed_wl();
        let mut tokens = Vec::new();
        for kind in WhitespaceKind::ALL {
            tokens.push(Token::word("w"));
            tokens.push(Token::whitespace(kind));
        }
        tokens.push(Token::word("w"));
        let out = scramble(&tokens, &wl).unwrap();
        // Output must contain each compound once, in order, with
        // 'w' separators.
        let mut expected = String::new();
        for kind in WhitespaceKind::ALL {
            expected.push('w');
            expected.push_str(wl.compound_for(kind));
        }
        expected.push('w');
        assert_eq!(out, expected);
    }
}
