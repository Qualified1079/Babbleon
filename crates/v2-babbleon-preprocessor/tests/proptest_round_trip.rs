//! Property-based tests for the layer-3 round-trip invariant.
//!
//! The deterministic tests in `src/*.rs` and the corpus tests in
//! `tests/example_puzzles.rs` cover known-good inputs.  This file
//! covers the *adversarial* surface: arbitrary `Vec<Token>` streams
//! within the MVP's supported subset, asserting the source-level
//! inverse property
//!
//! ```text
//! tokens_to_source(unscramble_to_tokens(scramble(tokens))) ==
//! tokens_to_source(tokens)
//! ```
//!
//! for every generated token stream.
//!
//! # Why source-level, not token-level
//!
//! `unscramble_to_tokens` does NOT recover the original
//! `Vec<Token>` byte-for-byte: adjacent `Token::Word(_)` tokens
//! have no delimiter on the wire and merge back into a single
//! `Word` on the round-trip.  Likewise, the unscrambler emits a
//! single `Word` for any contiguous non-whitespace run, regardless
//! of how the original tokenizer split it.
//!
//! The invariant we DO maintain — and the one operators actually
//! care about — is that re-emission to source produces the same
//! source string.  `tokens_to_source` is the canonical re-emission
//! step the unscramble pipeline applies, so the round-trip is
//! defined relative to it on both sides.

#![allow(clippy::doc_markdown, clippy::naive_bytecount)]

use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::wordlist::Wordlist;
use babbleon_preprocessor_v2::scrambler::scramble;
use babbleon_preprocessor_v2::tokens::{Token, WhitespaceKind};
use babbleon_preprocessor_v2::unscrambler::{
    tokens_to_source, unscramble_to_tokens,
};
use babbleon_preprocessor_v2::WhitespaceWordlist;
use proptest::collection::vec;
use proptest::prelude::*;

// ----- Strategies -----

/// Short ASCII-lowercase identifier-like Word body.
///
/// Constrained to `[a-z0-9_]{1,10}` so:
/// - Whitespace compounds (each ~25-100 chars from 4 long-ish
///   wordlist entries) can never appear as a substring of a Word
///   — keeps the scrambler's collision check out of the noise.
/// - Each Word is non-empty (the empty Word is invalid per
///   `tokens.rs` semantics).
fn arb_word_body() -> impl Strategy<Value = String> {
    "[a-z0-9_]{1,10}".prop_map(String::from)
}

/// Arbitrary whitespace kind.  All five are sampled equiprobably.
fn arb_whitespace_kind() -> impl Strategy<Value = WhitespaceKind> {
    prop_oneof![
        Just(WhitespaceKind::Newline),
        Just(WhitespaceKind::Space),
        Just(WhitespaceKind::Tab),
        Just(WhitespaceKind::IndentOpen),
        Just(WhitespaceKind::IndentClose),
    ]
}

/// Arbitrary token (Word or Whitespace).
fn arb_token() -> impl Strategy<Value = Token> {
    prop_oneof![
        arb_word_body().prop_map(Token::Word),
        arb_whitespace_kind().prop_map(Token::Whitespace),
    ]
}

/// A short token stream.  Capped at 32 tokens per generation so
/// the proptest budget covers many drawn cases without each one
/// taking milliseconds on the wordlist build.
fn arb_token_stream() -> impl Strategy<Value = Vec<Token>> {
    vec(arb_token(), 0..32)
}

// ----- Fixtures -----

/// Build the test wordlist once for the whole test binary.
///
/// `WhitespaceWordlist::build` does Fisher-Yates over the 369 652-
/// entry English baseline — building it per-case turns a 256-case
/// proptest into a > 100-second wall-clock test (rebuild dominates;
/// the actual scramble + unscramble work is microseconds).  One
/// build, hand out borrows for every case.
fn fixed_wl() -> &'static WhitespaceWordlist {
    use std::sync::OnceLock;
    static CACHED: OnceLock<WhitespaceWordlist> = OnceLock::new();
    CACHED.get_or_init(|| {
        let s = PerHostSecret::from_bytes(&[3u8; 32]).unwrap();
        WhitespaceWordlist::build(&s, Wordlist::english_baseline(), 0)
            .unwrap()
    })
}

// ----- Properties -----

proptest! {
    #![proptest_config(ProptestConfig {
        // 1024 cases matches the daemon-protocol proptest budget.
        // The wordlist is cached via OnceLock so per-case cost is
        // the actual scramble + unscramble work (tens of µs).
        cases: 1024,
        ..ProptestConfig::default()
    })]

    /// Source-level inverse property.  This is the operator-facing
    /// invariant the round-trip pipeline must hold.
    #[test]
    fn source_level_round_trip(tokens in arb_token_stream()) {
        let wl = fixed_wl();
        // Scramble may legitimately fail with
        // WhitespaceCompoundCollision if a generated Word happens
        // to contain a compound substring.  The arb_word_body
        // alphabet + length cap make this vanishingly unlikely but
        // not impossible; we skip collisions cleanly so a single
        // unlucky draw does not noisy-fail the property.
        let Ok(scrambled) = scramble(&tokens, wl) else {
            return Ok(());
        };
        let recovered_tokens = unscramble_to_tokens(&scrambled, wl);
        let original_source = tokens_to_source(&tokens);
        let recovered_source = tokens_to_source(&recovered_tokens);
        prop_assert_eq!(original_source, recovered_source);
    }

    /// Scrambling is deterministic for a given (tokens, wl) pair.
    /// Catches an accidental nondeterminism slip (e.g. iterating a
    /// HashMap during scramble emission).
    #[test]
    fn scramble_is_deterministic(tokens in arb_token_stream()) {
        let wl = fixed_wl();
        let a = scramble(&tokens, wl);
        let b = scramble(&tokens, wl);
        prop_assert_eq!(format!("{a:?}"), format!("{b:?}"));
    }

    /// Unscrambling is deterministic for a given (scrambled, wl)
    /// pair.  Same rationale as scramble_is_deterministic.
    #[test]
    fn unscramble_is_deterministic(tokens in arb_token_stream()) {
        let wl = fixed_wl();
        let Ok(scrambled) = scramble(&tokens, wl) else {
            return Ok(());
        };
        let a = unscramble_to_tokens(&scrambled, wl);
        let b = unscramble_to_tokens(&scrambled, wl);
        prop_assert_eq!(a, b);
    }

    /// Layer-3 promise: scrambled output never contains a visible
    /// '\n' byte.  This is the central security claim of the
    /// layer-3 mechanism — a snapshot reader sees one continuous
    /// text wall.  Property version of the deterministic
    /// `scrambled_output_has_no_visible_indent_or_newline_chars`
    /// test in `src/unscrambler.rs`.
    #[test]
    fn scrambled_output_has_no_newline_byte(tokens in arb_token_stream()) {
        let wl = fixed_wl();
        let Ok(scrambled) = scramble(&tokens, wl) else {
            return Ok(());
        };
        let nl_count = scrambled.bytes().filter(|b| *b == b'\n').count();
        prop_assert_eq!(nl_count, 0);
    }

    /// Tab characters in the scrambled output are also suppressed.
    /// `Whitespace(Tab)` is replaced by a compound, not an
    /// inline `\t`; non-whitespace `Word`s never contain literal
    /// tabs (the generator's alphabet excludes them).
    #[test]
    fn scrambled_output_has_no_tab_byte(tokens in arb_token_stream()) {
        let wl = fixed_wl();
        let Ok(scrambled) = scramble(&tokens, wl) else {
            return Ok(());
        };
        let tab_count = scrambled.bytes().filter(|b| *b == b'\t').count();
        prop_assert_eq!(tab_count, 0);
    }
}
