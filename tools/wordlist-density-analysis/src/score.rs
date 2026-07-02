//! Per-word BPE token counting under cl100k_base + o200k_base.
//!
//! These are the two production frontier-model tokenizers whose
//! behaviour on Babbleon compounds is the anchoring measurement in
//! `tools/tokenizer-benchmark/`.  The wordlist filter must be scored
//! against the same tokenizers to keep the numbers commensurable.
//!
//! Loading BPE tables is expensive (~50 ms each); the `Tokenizers`
//! struct constructs both once and reuses them across the walk.

use anyhow::{Context, Result};
use tiktoken_rs::{cl100k_base, o200k_base, CoreBPE};

/// Tokenizers we score under.  Add a variant here + wire it through
/// `count_all` if a new production tokenizer needs coverage.
pub struct Tokenizers {
    cl100k: CoreBPE,
    o200k: CoreBPE,
}

impl Tokenizers {
    /// Load both BPE tables.  Fails only if the tiktoken-rs vendored
    /// assets are corrupt (never in practice for a released crate).
    pub fn load() -> Result<Self> {
        let cl100k = cl100k_base().context("load cl100k_base BPE")?;
        let o200k = o200k_base().context("load o200k_base BPE")?;
        Ok(Self { cl100k, o200k })
    }

    pub fn count_cl100k(&self, s: &str) -> usize {
        self.cl100k.encode_with_special_tokens(s).len()
    }

    pub fn count_o200k(&self, s: &str) -> usize {
        self.o200k.encode_with_special_tokens(s).len()
    }
}

/// A word's density measurement.  `bytes` is redundant with
/// `word.len()` but we materialise it so the CSV rows are
/// self-describing without downstream joins.
#[derive(Debug, Clone)]
pub struct WordScore {
    pub word: String,
    pub bytes: usize,
    pub cl100k: usize,
    pub o200k: usize,
}

impl WordScore {
    pub fn compute(word: &str, tokenizers: &Tokenizers) -> Self {
        Self {
            word: word.to_owned(),
            bytes: word.len(),
            cl100k: tokenizers.count_cl100k(word),
            o200k: tokenizers.count_o200k(word),
        }
    }
}

/// Score every word in the input slice.  Sequential; tiktoken is
/// fast enough (~1 µs / word) that 370k entries clear in seconds.
pub fn score_all(words: &[String], tokenizers: &Tokenizers) -> Vec<WordScore> {
    words
        .iter()
        .map(|w| WordScore::compute(w, tokenizers))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_english_word_is_one_or_two_tokens_under_cl100k() {
        let t = Tokenizers::load().expect("tokenizers");
        // "hello" is a canonical single-token word for cl100k.
        let hello = WordScore::compute("hello", &t);
        assert!(
            hello.cl100k <= 2,
            "expected 'hello' <= 2 cl100k tokens, got {}",
            hello.cl100k
        );
        assert_eq!(hello.bytes, 5);
    }

    #[test]
    fn nonsense_word_costs_multiple_tokens() {
        let t = Tokenizers::load().expect("tokenizers");
        // A rare pseudo-word should require BPE fallback to smaller merges.
        let score = WordScore::compute("zyzzogeton", &t);
        assert!(
            score.cl100k >= 3,
            "expected rare word to cost >= 3 cl100k tokens, got {}",
            score.cl100k
        );
    }

    #[test]
    fn score_all_preserves_input_order() {
        let t = Tokenizers::load().expect("tokenizers");
        let words = vec!["alpha".to_owned(), "beta".to_owned(), "gamma".to_owned()];
        let scores = score_all(&words, &t);
        assert_eq!(scores.len(), 3);
        assert_eq!(scores[0].word, "alpha");
        assert_eq!(scores[1].word, "beta");
        assert_eq!(scores[2].word, "gamma");
    }

    #[test]
    fn different_tokenizers_can_disagree() {
        // We do not require agreement; the whole point of measuring
        // both is that they differ for interesting words.  This test
        // just documents that our two-tokenizer coverage is not a
        // duplicated column.
        let t = Tokenizers::load().expect("tokenizers");
        let words: Vec<String> = ["hello", "zyzzogeton", "aardvark", "quantum"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let scores = score_all(&words, &t);
        let any_disagreement = scores.iter().any(|s| s.cl100k != s.o200k);
        assert!(
            any_disagreement,
            "cl100k and o200k gave identical counts on every probe; \
             either both crates are misloaded or the probe set is degenerate"
        );
    }
}
