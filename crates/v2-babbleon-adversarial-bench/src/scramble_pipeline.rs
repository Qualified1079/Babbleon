//! Apply scramble layers to a Python source string in pure-compute
//! mode.
//!
//! # What this defeats
//!
//! Bench non-reproducibility.  The operator-facing
//! `babbleon scramble` subcommand round-trips a daemon over a Unix
//! socket, which means the scramble depends on the live per-host
//! secret on the box running the bench.  Two operators on two
//! different machines would get two different scrambled outputs for
//! the same challenge, and the bench's crack-fraction numbers would
//! not be comparable.
//!
//! This module sidesteps that by driving the preprocessor's library
//! API directly with a *synthetic* per-host secret derived from
//! [`LayerConfig::seed_byte`].  Same seed + same source ⇒
//! byte-identical scrambled bytes everywhere.  The synthetic secret
//! is bench-deterministic; it carries zero security weight and the
//! crate-level docs flag it as such.
//!
//! # Mechanism
//!
//! 1. Build `PerHostSecret::from_bytes(&[config.seed_byte; 32])`.
//! 2. If `config.layer3_whitespace_as_words`, derive a
//!    `WhitespaceWordlist` at `config.epoch` from the synthetic
//!    secret + the embedded English baseline wordlist.
//! 3. If `config.layer2_keyword_scramble`, derive a
//!    `KeywordWordlist` similarly.
//! 4. Tokenize the source via `python_tokenizer::tokenize`.
//! 5. If L2: apply `scramble_keywords` in place.
//! 6. If L3: apply `scrambler::scramble` to produce bytes; otherwise
//!    re-emit the (possibly L2-mutated) token stream via
//!    `tokens_to_source` from the preprocessor's unscrambler.
//! 7. Return the resulting bytes as a `String`.
//!
//! # Threat model boundaries
//!
//! - Defeats: bench drift across hosts.
//! - Does NOT defeat: a future preprocessor change that alters the
//!   HKDF info label or the wordlist baseline.  The bench's
//!   crack-fraction is meaningful only against a fixed preprocessor
//!   version; the bench's `RunRecord` captures the preprocessor
//!   crate's package version so old results stay attributable.

use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::wordlist::Wordlist;
use babbleon_preprocessor_v2::keyword_scrambler::scramble_keywords;
use babbleon_preprocessor_v2::keyword_wordlist::KeywordWordlist;
use babbleon_preprocessor_v2::python_tokenizer::tokenize;
use babbleon_preprocessor_v2::scrambler::scramble;
use babbleon_preprocessor_v2::tokens::Token;
use babbleon_preprocessor_v2::whitespace_wordlist::WhitespaceWordlist;

use crate::errors::{Error, Result};
use crate::layer_config::LayerConfig;
use crate::secret_literal_layer::scramble_secret_literals;

/// Scramble `source` under `config` and return the resulting bytes.
///
/// # Errors
///
/// - `Error::Scramble` if the preprocessor returns
///   `WhitespaceCompoundCollision`, `KeywordCompoundCollision`, or
///   any other downstream error.  The inner message is the
///   preprocessor's `Display`, which carries no secret bytes (the
///   preprocessor itself satisfies security-baseline rule 13).
pub fn apply_layers(source: &str, config: LayerConfig) -> Result<String> {
    let synthetic_secret = PerHostSecret::from_bytes(&[config.seed_byte; 32])
        .map_err(|e| Error::Scramble {
            message: format!("synthetic per-host secret: {e}"),
        })?;
    let wordlist = Wordlist::english_baseline();

    // Layer 7 is the OUTERMOST pass — it operates on source text
    // before tokenization so L2 and L3 downstream do not need to
    // know about secret literals.  The mapping is discarded; the
    // bench does not round-trip and the model never gets the
    // mapping.
    let source_after_l7: String = if config.layer7_secret_literal {
        let (s, _mapping) =
            scramble_secret_literals(source, &synthetic_secret, config.epoch)?;
        s
    } else {
        source.to_string()
    };

    let mut tokens: Vec<Token> = tokenize(&source_after_l7);

    if config.layer2_keyword_scramble {
        let kwl = KeywordWordlist::build(
            &synthetic_secret,
            wordlist,
            config.epoch,
        )
        .map_err(|e| Error::Scramble {
            message: format!("build keyword wordlist: {e}"),
        })?;
        scramble_keywords(&mut tokens, &kwl);
    }

    if config.layer3_whitespace_as_words {
        let wl = WhitespaceWordlist::build(
            &synthetic_secret,
            wordlist,
            config.epoch,
        )
        .map_err(|e| Error::Scramble {
            message: format!("build whitespace wordlist: {e}"),
        })?;
        scramble(&tokens, &wl).map_err(|e| Error::Scramble {
            message: format!("layer-3 scramble: {e}"),
        })
    } else {
        // No L3: re-emit the token stream as plain source.  Useful
        // for L2-only and baseline configurations.
        Ok(reemit_tokens(&tokens))
    }
}

/// Re-emit a token stream as a plain source string.  Used by the
/// non-L3 paths where we want the (possibly L2-mutated) tokens in
/// readable form rather than as a wall of compound bytes.
///
/// Re-emission preserves the per-token `Word` body verbatim and
/// converts each whitespace marker back to its conventional ASCII
/// form (`Space → ' '`, `Tab → '\t'`, `Newline → '\n'`,
/// `IndentOpen → ""` / `IndentClose → ""` — indent geometry is
/// already encoded in the surrounding `Space` tokens by the MVP
/// tokenizer).
///
/// We do NOT call the preprocessor's `tokens_to_source` because that
/// function applies indent-level canonicalisation that would mangle
/// L2-only output for the baseline / l2-only configurations.  This
/// emitter is intentionally simpler: it concatenates word bodies
/// and whitespace markers verbatim.
fn reemit_tokens(tokens: &[Token]) -> String {
    use babbleon_preprocessor_v2::tokens::WhitespaceKind;
    let mut out = String::new();
    for tok in tokens {
        match tok {
            Token::Word(s) => out.push_str(s),
            Token::Whitespace(WhitespaceKind::Space) => out.push(' '),
            Token::Whitespace(WhitespaceKind::Tab) => out.push('\t'),
            Token::Whitespace(WhitespaceKind::Newline) => out.push('\n'),
            // Indent open / close are *structural* markers the MVP
            // tokenizer emits at the same positions as the leading
            // run of Spaces.  Drop them in re-emission so we do not
            // double-count indent.
            Token::Whitespace(
                WhitespaceKind::IndentOpen | WhitespaceKind::IndentClose,
            ) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::apply_layers;
    use crate::layer_config::LayerConfig;

    const SAMPLE: &str = "def auth(x):\n    return x == \"hunter2\"\n";

    #[test]
    fn baseline_returns_source_modulo_reemission() {
        let out = apply_layers(SAMPLE, LayerConfig::baseline_no_scramble())
            .unwrap();
        // The baseline path goes tokenize -> re-emit, so the byte
        // string may differ from the input by the indent-marker
        // collapse our re-emitter performs.  The visible content
        // (def, auth, hunter2, return) must all survive.
        assert!(out.contains("def"));
        assert!(out.contains("auth"));
        assert!(out.contains("return"));
        assert!(out.contains("hunter2"));
    }

    #[test]
    fn l3_only_eliminates_visible_whitespace() {
        let out = apply_layers(SAMPLE, LayerConfig::l3_only()).unwrap();
        // 'def', 'return', and the secret should still be visible
        // (L2 not applied) but newline and space should not.
        assert!(out.contains("def"));
        assert!(out.contains("return"));
        assert!(out.contains("hunter2"));
        assert!(
            !out.contains('\n'),
            "L3 must eliminate literal newlines: {out}",
        );
        // The single ASCII space inside `def auth(x):` should be
        // consumed by the whitespace compound substitution.
        assert!(
            !out.contains("def auth"),
            "L3 must scramble the space between def and auth: {out}",
        );
    }

    #[test]
    fn l2_only_replaces_def_and_return_but_leaves_newlines() {
        let out = apply_layers(SAMPLE, LayerConfig::l2_only()).unwrap();
        assert!(
            !out.contains("def "),
            "L2 must rewrite 'def' as a compound: {out}",
        );
        assert!(
            !out.contains(" return "),
            "L2 must rewrite 'return' as a compound: {out}",
        );
        assert!(out.contains('\n'), "L2 alone keeps newlines: {out}");
        // The secret must still be visible since L2 only touches
        // keywords.
        assert!(out.contains("hunter2"));
    }

    #[test]
    fn l2_plus_l3_eliminates_both_keywords_and_whitespace() {
        let out =
            apply_layers(SAMPLE, LayerConfig::l2_plus_l3()).unwrap();
        assert!(!out.contains("def "));
        assert!(!out.contains(" return "));
        assert!(!out.contains('\n'));
        // hunter2 is a string literal, not a keyword; it survives.
        // The bench's point is that the *attacker* still has to find
        // it inside the wall of text.
        assert!(out.contains("hunter2"));
    }

    #[test]
    fn deterministic_under_fixed_seed() {
        let a = apply_layers(SAMPLE, LayerConfig::l2_plus_l3()).unwrap();
        let b = apply_layers(SAMPLE, LayerConfig::l2_plus_l3()).unwrap();
        assert_eq!(a, b, "same seed must produce identical bytes");
    }

    #[test]
    fn different_seeds_produce_different_output() {
        let a = apply_layers(
            SAMPLE,
            LayerConfig::new(true, true, 0xAB, 0),
        )
        .unwrap();
        let b = apply_layers(
            SAMPLE,
            LayerConfig::new(true, true, 0xCD, 0),
        )
        .unwrap();
        assert_ne!(a, b, "different seeds must produce different output");
    }

    #[test]
    fn different_epochs_produce_different_output() {
        let a = apply_layers(
            SAMPLE,
            LayerConfig::new(true, true, 0xAB, 0),
        )
        .unwrap();
        let b = apply_layers(
            SAMPLE,
            LayerConfig::new(true, true, 0xAB, 1),
        )
        .unwrap();
        assert_ne!(a, b, "different epochs must produce different output");
    }

    #[test]
    fn empty_source_returns_empty_bytes() {
        // The tokenizer accepts empty input; the bench should not
        // panic on a degenerate (but validation-rejected at the
        // challenge level) empty source.
        let out = apply_layers("", LayerConfig::l2_plus_l3()).unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn non_python_text_passes_through_under_baseline() {
        // The bench is Python-specific but should not crash on
        // arbitrary bytes; under baseline the round-trip is the
        // identity (modulo our re-emitter's whitespace marker
        // collapse).
        let s = "hello world\n";
        let out =
            apply_layers(s, LayerConfig::baseline_no_scramble()).unwrap();
        assert!(out.contains("hello"));
        assert!(out.contains("world"));
    }
}
