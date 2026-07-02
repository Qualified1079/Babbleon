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
//! 3. If `config.layer2_keyword_scramble`, build an `IdentifierMapping`
//!    via `MappingBuilder` covering every unique word token.
//!    `layer2b_operator_scramble` is a no-op: operators (`==`, `(`, `:`,
//!    etc.) are ordinary word tokens already handled by the dynamic L2.
//! 4. Tokenize the source via `python_tokenizer::tokenize`.
//! 5. If L2: apply `scramble_identifiers` in place.
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

use babbleon_core_v2::{per_host_secret::PerHostSecret, wordlist::Wordlist, MappingBuilder};
use babbleon_preprocessor_v2::chunk_reorder::scramble_chunks;
use babbleon_preprocessor_v2::decoy_injection::inject_decoys;
use babbleon_preprocessor_v2::direction_reversal::reverse_chunks;
use babbleon_preprocessor_v2::identifier_scrambler::{
    alias_count_for_epoch, collect_unique_tokens, scramble_identifiers,
    IdentifierMapping, ALIAS_COUNT, ALIAS_COUNT_VARIABLE_FROM_VERSION,
    MAX_ALIAS_COUNT,
};
use babbleon_preprocessor_v2::python_tokenizer::tokenize;
use babbleon_preprocessor_v2::scrambler::scramble;
use babbleon_preprocessor_v2::tokenizer_noise::inject_noise as inject_tokenizer_noise;
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

    // L4: chunk reorder + position markers.  Runs before L5 so decoys
    // land into the already-shuffled stream.
    if config.layer4_chunk_reorder {
        tokens = scramble_chunks(tokens, config.epoch);
    }

    // L5: decoy injection at depth-0 positions.  Runs before L2 so
    // decoy marker bodies go through the identifier scramble.
    if config.layer5_decoy_injection {
        tokens = inject_decoys(tokens, config.epoch);
    }

    if config.layer2_keyword_scramble {
        let id_wordlist = Wordlist::english_baseline();
        let builder = MappingBuilder::new(&synthetic_secret, id_wordlist);
        let sorted_tokens = collect_unique_tokens(&tokens);
        // Pick stride + alias_count matching the production daemon's
        // legacy vs variable regimes — see
        // `crates/v2-babbleon-daemon/src/state.rs::token_mapping`.
        // Legacy: stride 3, count 3.  Variable: stride MAX, count
        // alias_count_for_epoch(2, epoch) ∈ [2, 5].
        let (alias_count, stride) = if config.variable_alias_count {
            (
                alias_count_for_epoch(
                    ALIAS_COUNT_VARIABLE_FROM_VERSION,
                    config.epoch,
                ),
                MAX_ALIAS_COUNT,
            )
        } else {
            (ALIAS_COUNT, ALIAS_COUNT)
        };
        let base = config.epoch.saturating_mul(stride as u64);
        let mut per_alias: Vec<Vec<String>> = Vec::with_capacity(alias_count);
        for ai in 0..alias_count {
            let virtual_epoch = base + ai as u64;
            let epoch_mapping = builder
                .build(&sorted_tokens, virtual_epoch)
                .map_err(|e| Error::Scramble {
                    message: format!("build identifier mapping: {e}"),
                })?;
            let compounds: Vec<String> = sorted_tokens
                .iter()
                .map(|t| epoch_mapping.scramble(t).unwrap_or(t.as_str()).to_string())
                .collect();
            per_alias.push(compounds);
        }
        let mut aliases: Vec<Vec<String>> = sorted_tokens
            .iter()
            .map(|_| Vec::with_capacity(alias_count))
            .collect();
        for alias_compounds in per_alias {
            for (ti, compound) in alias_compounds.into_iter().enumerate() {
                aliases[ti].push(compound);
            }
        }
        let mapping = IdentifierMapping::from_tokens_and_aliases(
            sorted_tokens,
            config.epoch,
            aliases,
        )
        .map_err(|e| Error::Scramble {
            message: format!("identifier mapping collision: {e}"),
        })?;
        scramble_identifiers(&mut tokens, &mapping);
    }
    // layer2b_operator_scramble is a no-op: operators are word tokens
    // already handled by the dynamic identifier scramble above.
    let _ = config.layer2b_operator_scramble;

    let body = if config.layer3_whitespace_as_words {
        let wl = WhitespaceWordlist::build(
            &synthetic_secret,
            Wordlist::english_baseline(),
            config.epoch,
        )
        .map_err(|e| Error::Scramble {
            message: format!("build whitespace wordlist: {e}"),
        })?;
        scramble(&tokens, &wl).map_err(|e| Error::Scramble {
            message: format!("layer-3 scramble: {e}"),
        })?
    } else {
        // No L3: re-emit the token stream as plain source.  Useful
        // for L2-only and baseline configurations.
        reemit_tokens(&tokens)
    };

    // L6: direction segment reversal on the body bytes.  Only
    // meaningful after L3 produces a compact byte sequence.
    let body = if config.layer6_direction_reversal {
        reverse_chunks(&body, config.epoch)
    } else {
        body
    };

    // L12: tokenizer-hostile noise on body bytes.  Applied last so it
    // lands on the already-reversed wall.
    let body = if config.layer12_noise {
        inject_tokenizer_noise(&body, config.epoch)
    } else {
        body
    };

    Ok(body)
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
    }

    #[test]
    fn l2_plus_l3_eliminates_both_keywords_and_whitespace() {
        let out =
            apply_layers(SAMPLE, LayerConfig::l2_plus_l3()).unwrap();
        assert!(!out.contains("def "));
        assert!(!out.contains(" return "));
        assert!(!out.contains('\n'));
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
    fn l2_plus_l2b_plus_l3_eliminates_parens_and_colon() {
        // The L2b operator scramble should remove `(`, `)`, `:`,
        // and `==` as visible ASCII from the scrambled output.
        let out = apply_layers(
            SAMPLE,
            LayerConfig::l2_plus_l2b_plus_l3(),
        )
        .unwrap();
        assert!(!out.contains("("), "L2b must scramble `(`: {out}");
        assert!(!out.contains(")"), "L2b must scramble `)`: {out}");
        assert!(!out.contains("=="), "L2b must scramble `==`: {out}");
        assert!(!out.contains(": "), "L2b must scramble `:`: {out}");
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

    // ----- variable_alias_count -----

    #[test]
    fn variable_alias_count_produces_different_output_than_legacy() {
        // L2+L3 with the legacy fixed cycle vs the per-epoch variable
        // cycle: at host_epoch >= 1 the regimes' virtual-epoch
        // strides diverge (3 vs MAX_ALIAS_COUNT), so the L2 compounds
        // diverge and the L3 body differs.  At host_epoch == 0 both
        // strides yield virtual_epoch = 0 for the first alias and
        // bodies that don't cycle past occurrence 0 coincide (see
        // the documented genesis-epoch coincidence in the daemon
        // state tests); pick epoch 1 to surface the regime
        // difference.
        let legacy_cfg = LayerConfig {
            epoch: 1,
            ..LayerConfig::l2_plus_l3()
        };
        let variable_cfg = LayerConfig {
            epoch: 1,
            ..LayerConfig::l2_plus_l3_with_variable_alias_count()
        };
        let legacy = apply_layers(SAMPLE, legacy_cfg).unwrap();
        let variable = apply_layers(SAMPLE, variable_cfg).unwrap();
        assert_ne!(
            legacy, variable,
            "variable-alias-count L2+L3 must diverge from legacy at host_epoch >= 1",
        );
    }

    #[test]
    fn variable_alias_count_coincides_with_legacy_at_genesis() {
        // Documents the genesis-epoch coincidence at the bench
        // layer: at epoch 0 both strides yield virtual_epoch = 0
        // for the first alias, and SAMPLE's tokens only cycle
        // through occurrence 0.  Pinning this avoids the
        // accidentally-equal failure mode masking a real bug if a
        // future cache rework breaks the genesis coincidence
        // silently.
        let legacy =
            apply_layers(SAMPLE, LayerConfig::l2_plus_l3()).unwrap();
        let variable = apply_layers(
            SAMPLE,
            LayerConfig::l2_plus_l3_with_variable_alias_count(),
        )
        .unwrap();
        assert_eq!(
            legacy, variable,
            "epoch 0 + non-repeating tokens: regimes coincide on the first alias",
        );
    }

    #[test]
    fn variable_alias_count_is_deterministic() {
        // Same seed + epoch + flag must produce identical bytes
        // across runs — the bench's reproducibility contract.
        let a = apply_layers(
            SAMPLE,
            LayerConfig::l2_plus_l3_with_variable_alias_count(),
        )
        .unwrap();
        let b = apply_layers(
            SAMPLE,
            LayerConfig::l2_plus_l3_with_variable_alias_count(),
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn variable_alias_count_full_stack_still_eliminates_l3_whitespace() {
        // Sanity check that turning on variable_alias_count does
        // not regress the downstream layers: L3 must still erase
        // every newline regardless of how many aliases L2 cycled
        // through.
        let out = apply_layers(
            SAMPLE,
            LayerConfig::full_stack_with_variable_alias_count(),
        )
        .unwrap();
        assert!(
            !out.contains('\n'),
            "L3 must eliminate newlines under variable-alias-count: {out}",
        );
    }
}
