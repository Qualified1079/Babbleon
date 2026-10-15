//! Per-layer BPE token cost across the shipped layer configurations.
//!
//! # What this defeats
//!
//! "The scramble imposes a context tax on the adversary" asserted
//! without a number.  `TODO.md` F6 asks which of L2-L12 to delete and
//! records that "no layer has a known contribution"; this test
//! produces the contribution table in the unit that actually matters
//! to an LLM adversary — BPE tokens, not bytes.
//!
//! Bytes understate L12 badly and overstate it at the same time: its
//! zero-width characters and Cyrillic homoglyphs are multi-byte UTF-8
//! (inflating byte counts for free) while *also* fragmenting BPE
//! tokenization (inflating token counts for real).  Only a tokenizer
//! can separate the two.
//!
//! # Running
//!
//! Requires the `token-metrics` feature, which is off by default
//! because `tiktoken-rs` bundles ~2 MB of merge tables per tokenizer:
//!
//! ```text
//! cargo test -p v2-babbleon-resilience-bench --features token-metrics \
//!     --test layer_token_cost -- --nocapture
//! ```
//!
//! Without the feature the whole file compiles to nothing.
//!
//! # Threat model boundaries
//!
//! - Measures: how much context the scramble costs an adversary that
//!   must read the whole artifact, per layer configuration.
//! - Does NOT measure: whether that cost buys any *recovery*
//!   resistance.  Token count is a price, not a defence — a layer can
//!   be expensive and useless.  Pair with a recovery measurement
//!   before concluding anything about a layer's worth.

#![cfg(feature = "token-metrics")]

use babbleon_resilience_bench_v2::{apply_layers, Challenge, LayerConfig};

/// The configurations to table, in roughly increasing strength.
fn configs() -> Vec<(&'static str, LayerConfig)> {
    vec![
        ("baseline", LayerConfig::baseline_no_scramble()),
        ("l9-only", LayerConfig::l9_only()),
        ("l2-only", LayerConfig::l2_only()),
        ("l3-only", LayerConfig::l3_only()),
        ("l2-plus-l3", LayerConfig::l2_plus_l3()),
        (
            "l2-plus-l3-plus-l4-plus-l5",
            LayerConfig::l2_plus_l3_plus_l4_plus_l5(),
        ),
        (
            "full-stack-no-l9",
            LayerConfig {
                layer9_constant_unfolding: false,
                ..LayerConfig::full_stack()
            },
        ),
        ("full-stack", LayerConfig::full_stack()),
    ]
}

fn challenge_paths() -> Vec<&'static str> {
    vec![
        "challenges/recover-nesting-depth.toml",
        "challenges/which-statement-runs-first.toml",
        "challenges/count-real-statements.toml",
        "challenges/which-keyword-controls-flow.toml",
    ]
}

#[test]
fn print_per_layer_token_cost() {
    println!(
        "\n{:<30} {:>8} {:>8} {:>8} {:>9}",
        "CONFIG", "BYTES", "CL100K", "O200K", "xBASE(cl)"
    );

    for path in challenge_paths() {
        let challenge = Challenge::from_toml_file(path)
            .unwrap_or_else(|e| panic!("load {path}: {e}"));
        println!("\n-- {} --", challenge.name);

        let mut baseline_cl = 0usize;
        for (label, config) in configs() {
            let scrambled = apply_layers(&challenge.source, config)
                .unwrap_or_else(|e| panic!("{label} on {}: {e}", challenge.name));
            let counts =
                babbleon_resilience_bench_v2::token_metrics::compute(&scrambled, false);
            if label == "baseline" {
                baseline_cl = counts.cl100k;
            }
            #[allow(clippy::cast_precision_loss)]
            let ratio = if baseline_cl == 0 {
                0.0
            } else {
                counts.cl100k as f64 / baseline_cl as f64
            };
            println!(
                "{:<30} {:>8} {:>8} {:>8} {:>8.2}x",
                label,
                scrambled.len(),
                counts.cl100k,
                counts.o200k,
                ratio
            );
        }
    }
    println!();
}

/// Pins the one claim this file makes that a future layer change
/// could silently break: the full production stack must cost an
/// adversary strictly more context than the unscrambled baseline.
///
/// Deliberately weak — a strict inequality, not a target ratio.  A
/// target would encode today's measurement as a requirement, and the
/// right ratio is an open question (`TODO.md` F6), not a constant.
#[test]
fn full_stack_costs_more_tokens_than_baseline() {
    for path in challenge_paths() {
        let challenge = Challenge::from_toml_file(path)
            .unwrap_or_else(|e| panic!("load {path}: {e}"));

        let base = apply_layers(
            &challenge.source,
            LayerConfig::baseline_no_scramble(),
        )
        .expect("baseline scramble");
        let full = apply_layers(&challenge.source, LayerConfig::full_stack())
            .expect("full-stack scramble");

        let base_t =
            babbleon_resilience_bench_v2::token_metrics::compute(&base, false);
        let full_t =
            babbleon_resilience_bench_v2::token_metrics::compute(&full, false);

        assert!(
            full_t.cl100k > base_t.cl100k,
            "{}: full-stack ({} cl100k tokens) must exceed baseline ({})",
            challenge.name,
            full_t.cl100k,
            base_t.cl100k,
        );
    }
}
