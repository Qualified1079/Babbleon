//! Mid-tail percentile filter over scored words.
//!
//! Given a scored corpus and a `[min_pct, max_pct]` band on a chosen
//! tokenizer, produce the subset of words whose token count falls
//! within the corresponding value cutoffs.  The output is a
//! `FilterResult` that carries both the kept words and enough
//! metadata to reproduce the filter (cutoffs, drop counts) — the
//! manifest emitter in `report` writes that metadata beside the
//! filtered wordlist.

use crate::score::WordScore;
use crate::stats::Distribution;
use std::fmt;

/// Which tokenizer's counts the filter operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tokenizer {
    Cl100k,
    O200k,
}

impl Tokenizer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Tokenizer::Cl100k => "cl100k",
            Tokenizer::O200k => "o200k",
        }
    }

    pub fn count(&self, score: &WordScore) -> usize {
        match self {
            Tokenizer::Cl100k => score.cl100k,
            Tokenizer::O200k => score.o200k,
        }
    }
}

impl fmt::Display for Tokenizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Filter parameters.  `min_percentile` and `max_percentile` are
/// inclusive on both sides in *value* space (not rank space): we
/// compute the value cutoffs from the percentiles, then keep every
/// word whose count is `[low, high]`.
#[derive(Debug, Clone)]
pub struct FilterSpec {
    pub tokenizer: Tokenizer,
    pub min_percentile: f64,
    pub max_percentile: f64,
}

/// Result of applying a filter.
#[derive(Debug, Clone)]
pub struct FilterResult {
    pub spec: FilterSpec,
    pub cutoff_low: usize,
    pub cutoff_high: usize,
    pub kept: Vec<WordScore>,
    pub dropped_below: usize,
    pub dropped_above: usize,
}

impl FilterResult {
    pub fn total_input(&self) -> usize {
        self.kept.len() + self.dropped_below + self.dropped_above
    }

    pub fn kept_fraction(&self) -> f64 {
        let total = self.total_input();
        if total == 0 {
            return 0.0;
        }
        self.kept.len() as f64 / total as f64
    }
}

impl FilterSpec {
    /// Sanity-check the percentile band.  Rejects reversed or
    /// out-of-range inputs; the caller should surface the error
    /// directly to the operator.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=100.0).contains(&self.min_percentile) {
            return Err(format!(
                "min_percentile {} out of range [0, 100]",
                self.min_percentile
            ));
        }
        if !(0.0..=100.0).contains(&self.max_percentile) {
            return Err(format!(
                "max_percentile {} out of range [0, 100]",
                self.max_percentile
            ));
        }
        if self.min_percentile > self.max_percentile {
            return Err(format!(
                "min_percentile {} > max_percentile {}",
                self.min_percentile, self.max_percentile
            ));
        }
        Ok(())
    }

    /// Apply the filter to a pre-scored corpus.  Preserves the input
    /// order of `scores` in `FilterResult.kept`.
    pub fn apply(&self, scores: &[WordScore]) -> FilterResult {
        let counts = scores.iter().map(|s| self.tokenizer.count(s));
        let dist = Distribution::from(counts);
        let cutoff_low = dist.value_at_percentile(self.min_percentile);
        let cutoff_high = dist.value_at_percentile(self.max_percentile);

        let mut kept = Vec::with_capacity(scores.len());
        let mut dropped_below = 0usize;
        let mut dropped_above = 0usize;
        for s in scores {
            let c = self.tokenizer.count(s);
            if c < cutoff_low {
                dropped_below += 1;
            } else if c > cutoff_high {
                dropped_above += 1;
            } else {
                kept.push(s.clone());
            }
        }

        FilterResult {
            spec: self.clone(),
            cutoff_low,
            cutoff_high,
            kept,
            dropped_below,
            dropped_above,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_scores(cl_counts: &[usize]) -> Vec<WordScore> {
        cl_counts
            .iter()
            .enumerate()
            .map(|(i, &c)| WordScore {
                word: format!("w{i}"),
                bytes: 5,
                cl100k: c,
                o200k: c, // dummy alignment; not exercised in these tests
            })
            .collect()
    }

    #[test]
    fn tokenizer_variants_read_the_right_field() {
        let s = WordScore {
            word: "x".to_owned(),
            bytes: 1,
            cl100k: 7,
            o200k: 11,
        };
        assert_eq!(Tokenizer::Cl100k.count(&s), 7);
        assert_eq!(Tokenizer::O200k.count(&s), 11);
    }

    #[test]
    fn full_range_keeps_everything() {
        let scores = make_scores(&[1, 2, 3, 4, 5]);
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min_percentile: 0.0,
            max_percentile: 100.0,
        };
        let r = spec.apply(&scores);
        assert_eq!(r.kept.len(), 5);
        assert_eq!(r.dropped_below, 0);
        assert_eq!(r.dropped_above, 0);
    }

    #[test]
    fn mid_band_drops_extremes() {
        // Counts: 1 2 3 4 5 6 7 8 9 10.  Nearest-rank 30th = 3, 70th = 7.
        let scores = make_scores(&(1..=10).collect::<Vec<_>>());
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min_percentile: 30.0,
            max_percentile: 70.0,
        };
        let r = spec.apply(&scores);
        assert_eq!(r.cutoff_low, 3);
        assert_eq!(r.cutoff_high, 7);
        // Kept: 3,4,5,6,7 → 5 entries.
        assert_eq!(r.kept.len(), 5);
        assert_eq!(r.dropped_below, 2); // 1, 2
        assert_eq!(r.dropped_above, 3); // 8, 9, 10
        assert_eq!(r.total_input(), 10);
    }

    #[test]
    fn filter_preserves_input_order() {
        // Input counts [9, 3, 5, 1, 7, 4, 6] (n=7).  Sorted:
        // [1, 3, 4, 5, 6, 7, 9].  Nearest-rank 30th = ceil(0.3·7) = 3
        // → sorted[2] = 4.  Nearest-rank 70th = ceil(0.7·7) = 5 →
        // sorted[4] = 6.  Kept counts: any c with 4 ≤ c ≤ 6.
        let scores = make_scores(&[9, 3, 5, 1, 7, 4, 6]);
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min_percentile: 30.0,
            max_percentile: 70.0,
        };
        let r = spec.apply(&scores);
        let kept_names: Vec<String> = r.kept.iter().map(|s| s.word.clone()).collect();
        assert_eq!(r.cutoff_low, 4);
        assert_eq!(r.cutoff_high, 6);
        // Input positions of counts in [4, 6]: 5 at idx 2 (w2),
        // 4 at idx 5 (w5), 6 at idx 6 (w6).
        assert_eq!(kept_names, vec!["w2", "w5", "w6"]);
    }

    #[test]
    fn validate_rejects_reversed_band() {
        let bad = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min_percentile: 70.0,
            max_percentile: 30.0,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn validate_rejects_out_of_range() {
        let bad = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min_percentile: -10.0,
            max_percentile: 50.0,
        };
        assert!(bad.validate().is_err());

        let bad = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min_percentile: 30.0,
            max_percentile: 110.0,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn kept_fraction_matches_ratio() {
        let scores = make_scores(&(1..=10).collect::<Vec<_>>());
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min_percentile: 30.0,
            max_percentile: 70.0,
        };
        let r = spec.apply(&scores);
        assert!((r.kept_fraction() - 0.5).abs() < 1e-9);
    }
}
