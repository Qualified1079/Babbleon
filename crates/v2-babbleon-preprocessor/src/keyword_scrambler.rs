//! Layer-2 keyword scramble — Token-stream transform.
//!
//! # What this defeats
//!
//! See [`crate::python_keywords`] and [`crate::keyword_wordlist`]
//! for the threat-model framing.  This module is the pass that
//! actually rewrites a `Token::Word("def")` to
//! `Token::Word("<per-epoch-compound-for-def>")` at scramble
//! time, and the inverse at unscramble time.
//!
//! # Composition
//!
//! Layer 2 runs at the `Token` level, BEFORE layer 3
//! (whitespace-as-words).  Order: tokenize → `scramble_keywords`
//! → `scrambler::scramble` → bytes.  Inverse:
//! bytes → `unscrambler::unscramble` → `unscramble_keywords` →
//! re-emit.
//!
//! # Why a pass rather than a Token-variant change
//!
//! Adding `Token::Keyword(KeywordKind)` would have required a
//! wire-format-style break across every existing
//! `Token`-consuming module (scrambler, unscrambler, tokenizer,
//! tests).  A pass that mutates a `Vec<Token>` in place keeps
//! the IR stable: a keyword on the way out is just a
//! `Word(compound)`; a keyword on the way in is just a
//! `Word(keyword)`.  The unscrambler's existing greedy-whitespace
//! match logic does not change.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** "this is Python source" recognition via the
//!   surface lexicon (see `python_keywords.rs`).
//! - **Does NOT defeat:** an adversary who counts token
//!   frequencies and infers "these N compounds occur far more
//!   often than the average — probably keywords."  Compensating
//!   control: layer-5 decoy injection inflates the distribution.
//! - **Does NOT defeat:** an adversary who tokenises the
//!   scrambled wall and runs a statistical n-gram analysis
//!   keyed on whitespace boundaries.  L3 disrupts the
//!   whitespace signal that would enable that analysis; L2 alone
//!   without L3 is weaker.  Both layers compose on purpose.

use crate::keyword_wordlist::KeywordWordlist;
use crate::tokens::Token;

/// Replace every `Token::Word` whose body is a Python keyword
/// with the per-epoch compound for that keyword.
///
/// In-place mutation: callers pass `&mut Vec<Token>` so a
/// scramble pipeline can chain L2 → L3 without allocating
/// intermediate vectors.
///
/// Non-Word tokens (whitespace markers) are untouched.  Words
/// that are not Python keywords are untouched.  The pass is
/// idempotent only in the sense that running it on
/// already-scrambled output would substitute compounds for
/// compounds (no-op since compounds are not keywords); do not
/// rely on that.
///
/// # Token counts unchanged
///
/// One in, one out per token.  The scramble does not add or
/// remove tokens; only rewrites `Word` bodies.
pub fn scramble_keywords(tokens: &mut [Token], kwl: &KeywordWordlist) {
    for token in tokens.iter_mut() {
        if let Token::Word(body) = token {
            if let Some(compound) = kwl.compound_for(body.as_str()) {
                *body = compound.to_string();
            }
        }
    }
}

/// Inverse of [`scramble_keywords`].
///
/// Walks the token stream and, for every `Token::Word`, looks
/// the body up in `kwl.reverse_lookup`.  If the body matches
/// one of the per-epoch keyword compounds, the body is
/// replaced with the original keyword.  Otherwise the word is
/// left untouched (it was a real identifier, not a keyword
/// scramble).
///
/// Token counts unchanged; whitespace markers untouched.
pub fn unscramble_keywords(tokens: &mut [Token], kwl: &KeywordWordlist) {
    for token in tokens.iter_mut() {
        if let Token::Word(body) = token {
            if let Some(keyword) = kwl.reverse_lookup(body.as_str()) {
                *body = keyword.to_string();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{scramble_keywords, unscramble_keywords};
    use crate::keyword_wordlist::KeywordWordlist;
    use crate::python_keywords::PYTHON_KEYWORDS;
    use crate::tokens::{Token, WhitespaceKind};
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn kwl() -> KeywordWordlist {
        let s = PerHostSecret::from_bytes(&[3u8; 32]).unwrap();
        KeywordWordlist::build(&s, Wordlist::english_baseline(), 0).unwrap()
    }

    #[test]
    fn scramble_then_unscramble_round_trips_every_keyword() {
        let kwl = kwl();
        for kw in PYTHON_KEYWORDS {
            let mut toks = vec![Token::word(*kw)];
            scramble_keywords(&mut toks, &kwl);
            // After scramble, the body is NOT the keyword.
            assert_ne!(
                toks[0],
                Token::word(*kw),
                "{kw:?} should have been rewritten",
            );
            unscramble_keywords(&mut toks, &kwl);
            assert_eq!(toks[0], Token::word(*kw), "round-trip for {kw:?}");
        }
    }

    #[test]
    fn non_keyword_words_pass_through_untouched() {
        let kwl = kwl();
        let mut toks = vec![
            Token::word("hello"),
            Token::word("world"),
            Token::word("my_function"),
            Token::word("CONSTANT"),
        ];
        let before = toks.clone();
        scramble_keywords(&mut toks, &kwl);
        assert_eq!(toks, before, "non-keywords must not be rewritten");
        unscramble_keywords(&mut toks, &kwl);
        assert_eq!(toks, before, "inverse must also be a no-op");
    }

    #[test]
    fn whitespace_markers_are_never_touched() {
        let kwl = kwl();
        let mut toks = vec![
            Token::whitespace(WhitespaceKind::Newline),
            Token::word("def"),
            Token::whitespace(WhitespaceKind::Space),
        ];
        scramble_keywords(&mut toks, &kwl);
        assert_eq!(
            toks[0],
            Token::whitespace(WhitespaceKind::Newline),
            "Newline marker preserved",
        );
        assert_eq!(
            toks[2],
            Token::whitespace(WhitespaceKind::Space),
            "Space marker preserved",
        );
        // Middle token IS rewritten.
        assert_ne!(toks[1], Token::word("def"));
    }

    #[test]
    fn token_count_invariant() {
        let kwl = kwl();
        let mut toks = vec![
            Token::word("def"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("hello"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::word("return"),
        ];
        let before = toks.len();
        scramble_keywords(&mut toks, &kwl);
        assert_eq!(toks.len(), before);
        unscramble_keywords(&mut toks, &kwl);
        assert_eq!(toks.len(), before);
    }

    #[test]
    fn unscramble_of_compound_under_wrong_epoch_passes_through() {
        // Property: a compound that's valid under epoch 0 must
        // NOT be recognised under epoch 1 — the unscrambler
        // would otherwise unwrap an old scramble against the
        // current key, corrupting valid identifiers that
        // happened to look like a previous-epoch compound.
        let s = PerHostSecret::from_bytes(&[3u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let kwl_a = KeywordWordlist::build(&s, wl, 0).unwrap();
        let kwl_b = KeywordWordlist::build(&s, wl, 1).unwrap();
        let compound_for_def_at_epoch_0 =
            kwl_a.compound_for("def").unwrap().to_string();
        let mut toks =
            vec![Token::word(compound_for_def_at_epoch_0.clone())];
        unscramble_keywords(&mut toks, &kwl_b);
        // Under epoch 1's table, the epoch-0 compound is just an
        // unknown identifier — left untouched.
        assert_eq!(toks[0], Token::word(compound_for_def_at_epoch_0));
    }

    #[test]
    fn full_python_snippet_roundtrips_at_token_level() {
        // Hand-built token stream that mirrors:
        //   def hello():
        //       return 42
        let kwl = kwl();
        let mut toks = vec![
            Token::word("def"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("hello():"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::whitespace(WhitespaceKind::IndentOpen),
            Token::word("return"),
            Token::whitespace(WhitespaceKind::Space),
            Token::word("42"),
            Token::whitespace(WhitespaceKind::Newline),
            Token::whitespace(WhitespaceKind::IndentClose),
        ];
        let original = toks.clone();
        scramble_keywords(&mut toks, &kwl);
        // After scramble, neither "def" nor "return" should
        // appear verbatim.
        for tok in &toks {
            if let Token::Word(body) = tok {
                assert_ne!(body, "def");
                assert_ne!(body, "return");
            }
        }
        unscramble_keywords(&mut toks, &kwl);
        assert_eq!(toks, original);
    }
}
