//! Optional per-run BPE token-count measurement.
//!
//! # What this defeats
//!
//! Nothing directly — this is bench-hygiene instrumentation, not a
//! security control.  It exists so the operator can correlate a
//! `(challenge, layer_config)` cell's crack-fraction with how
//! token-dense its scrambled source is under a given tokenizer
//! family, the same "vocab-size sensitivity axis"
//! `tools/tokenizer-benchmark --include-smaller` measures in
//! isolation (see that tool's `RESULTS.md` §"Smaller-model
//! tokenizer comparison").  Wiring the same tokenizer set into this
//! crate's `RunRecord`s lets a future analysis ask "did the model
//! that cracked L2+L3 also see a token-dense encoding, or a
//! token-sparse one?" without cross-referencing two separate tools
//! by hand.
//!
//! # Why this module is feature-gated
//!
//! `tiktoken-rs` bundles roughly 2 MB of BPE merge-rank tables per
//! tokenizer.  `tools/tokenizer-benchmark` keeps it out of the
//! default Babbleon workspace build entirely by being a standalone
//! Cargo workspace (see that crate's `Cargo.toml` comment).  This
//! crate — `crates/v2-babbleon-resilience-bench` — is a member of
//! the *default* workspace (listed in the root `Cargo.toml`), so
//! the same isolation trick isn't available; the dependency would
//! land in every `cargo build`/`cargo test` in the workspace if
//! declared unconditionally.  Instead this crate uses Cargo's
//! optional-dependency + feature mechanism (`token-metrics`,
//! default off) — the same pattern `crates/babbleon/Cargo.toml`
//! already uses for its `tpm` / `fido2` hardware-backend features.
//! `cargo build -p v2-babbleon-resilience-bench` (no `--features`)
//! never touches `tiktoken-rs`.
//!
//! [`crate::run_record::TokenCounts`], the data type this module
//! populates, has no such dependency and is always compiled in — so
//! `RunRecord`'s JSONL schema is identical regardless of how the
//! producing binary was built; only the *code that computes* the
//! field is optional.

use tiktoken_rs::{cl100k_base, o200k_base, p50k_base, r50k_base, CoreBPE};

use crate::run_record::TokenCounts;

/// Count `source`'s tokens under `cl100k_base` and `o200k_base`
/// (always), plus `r50k_base` and `p50k_base` when `include_smaller`
/// is `true` — the same tokenizer set
/// `tools/tokenizer-benchmark --include-smaller` measures.
///
/// # Panics
///
/// Panics if `tiktoken-rs` fails to load its bundled BPE ranks for
/// any requested tokenizer.  That is an environment/packaging
/// failure (a corrupted or missing embedded asset), not a runtime
/// condition callers can meaningfully recover from; `tools/
/// tokenizer-benchmark` uses the same `.expect(...)` pattern for
/// the same reason.
#[must_use]
pub fn compute(source: &str, include_smaller: bool) -> TokenCounts {
    let cl100k = cl100k_base().expect("cl100k_base ranks failed to load");
    let o200k = o200k_base().expect("o200k_base ranks failed to load");
    let (r50k, p50k) = if include_smaller {
        let r = r50k_base().expect("r50k_base ranks failed to load");
        let p = p50k_base().expect("p50k_base ranks failed to load");
        (Some(count(&r, source)), Some(count(&p, source)))
    } else {
        (None, None)
    };
    TokenCounts {
        cl100k: count(&cl100k, source),
        o200k: count(&o200k, source),
        r50k,
        p50k,
    }
}

fn count(bpe: &CoreBPE, s: &str) -> usize {
    bpe.encode_with_special_tokens(s).len()
}

#[cfg(test)]
mod tests {
    use super::compute;

    #[test]
    fn without_smaller_leaves_r50k_p50k_none() {
        let counts = compute("hello world this is a test", false);
        assert!(counts.cl100k > 0);
        assert!(counts.o200k > 0);
        assert!(counts.r50k.is_none());
        assert!(counts.p50k.is_none());
    }

    #[test]
    fn with_smaller_populates_all_four_tokenizers() {
        let counts = compute("hello world this is a test", true);
        assert!(counts.cl100k > 0);
        assert!(counts.o200k > 0);
        assert!(counts.r50k.unwrap() > 0);
        assert!(counts.p50k.unwrap() > 0);
    }

    #[test]
    fn longer_source_never_yields_fewer_tokens() {
        let short = compute("hi", false);
        let long_text = "hi ".repeat(50);
        let long = compute(long_text.trim(), false);
        assert!(long.cl100k >= short.cl100k);
        assert!(long.o200k >= short.o200k);
    }

    #[test]
    fn empty_source_yields_zero_tokens() {
        let counts = compute("", true);
        assert_eq!(counts.cl100k, 0);
        assert_eq!(counts.o200k, 0);
        assert_eq!(counts.r50k, Some(0));
        assert_eq!(counts.p50k, Some(0));
    }
}
