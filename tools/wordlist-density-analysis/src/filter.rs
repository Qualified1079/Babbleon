//! Mid-tail token-count filter over scored words.
//!
//! Given a scored corpus and a `[low, high]` inclusive band on token
//! counts under a chosen tokenizer, produce the subset of words
//! whose token count falls within the band.  Cutoffs may be supplied
//! either as absolute token counts (`Bound::Tokens(n)`) or as
//! nearest-rank percentiles of the corpus distribution
//! (`Bound::Percentile(p)`).  Percentiles are resolved to token
//! counts at filter time.
//!
//! The output is a `FilterResult` that carries both the kept words
//! and enough metadata to reproduce the filter (resolved cutoffs,
//! drop counts) — the manifest emitter in `report` writes that
//! metadata beside the filtered wordlist.
//!
//! Absolute token cutoffs are the natural knob for the Babbleon
//! wordlist: the distribution is heavily peaked (73% of the corpus
//! sits at 2–3 tokens under cl100k), so a percentile band of
//! e.g. 30–70 collapses to just three values [2, 4], keeping ~92%
//! of the corpus.  Operators wanting a stricter mid-tail should use
//! `Bound::Tokens(3)..=Bound::Tokens(5)` — see the tool README.

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

/// One side of the filter band.  A `Percentile` bound is resolved
/// against the input distribution at filter time; a `Tokens` bound
/// is a literal token-count cutoff.
#[derive(Debug, Clone, Copy)]
pub enum Bound {
    Percentile(f64),
    Tokens(usize),
}

impl fmt::Display for Bound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bound::Percentile(p) => write!(f, "p{p}"),
            Bound::Tokens(n) => write!(f, "t{n}"),
        }
    }
}

impl Bound {
    fn resolve(&self, dist: &Distribution) -> usize {
        match *self {
            Bound::Percentile(p) => dist.value_at_percentile(p),
            Bound::Tokens(n) => n,
        }
    }

    fn validate(&self, side: &str) -> Result<(), String> {
        match *self {
            Bound::Percentile(p) => {
                if !(0.0..=100.0).contains(&p) {
                    return Err(format!("{side} percentile {p} out of range [0, 100]"));
                }
            }
            Bound::Tokens(_) => {}
        }
        Ok(())
    }
}

/// Filter parameters.  `min` and `max` are inclusive on both sides
/// after being resolved to token-count values against the input
/// distribution.
#[derive(Debug, Clone)]
pub struct FilterSpec {
    pub tokenizer: Tokenizer,
    pub min: Bound,
    pub max: Bound,
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
    /// Sanity-check the bounds independently; cross-bound
    /// (`min <= max`) is checked at `apply` time because the answer
    /// depends on the resolved cutoffs, not on the raw bounds when
    /// they mix percentiles and tokens.
    pub fn validate(&self) -> Result<(), String> {
        self.min.validate("min")?;
        self.max.validate("max")?;
        Ok(())
    }

    /// Apply the filter to a pre-scored corpus.  Preserves the input
    /// order of `scores` in `FilterResult.kept`.  Percentile bounds
    /// are resolved against `scores` (per the requested tokenizer).
    /// Returns an error if the resolved `cutoff_low > cutoff_high`.
    pub fn apply(&self, scores: &[WordScore]) -> Result<FilterResult, String> {
        let counts = scores.iter().map(|s| self.tokenizer.count(s));
        let dist = Distribution::from(counts);
        let cutoff_low = self.min.resolve(&dist);
        let cutoff_high = self.max.resolve(&dist);

        if cutoff_low > cutoff_high {
            return Err(format!(
                "resolved cutoffs invalid: low={cutoff_low} > high={cutoff_high} \
                 (min={}, max={})",
                self.min, self.max
            ));
        }

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

        Ok(FilterResult {
            spec: self.clone(),
            cutoff_low,
            cutoff_high,
            kept,
            dropped_below,
            dropped_above,
        })
    }
}

/// Intersect two `FilterResult`s by word, preserving the input
/// order of the primary result.  A word survives iff both filter
/// results kept it.  The returned `FilterResult` mirrors the shape
/// of a single-filter result: its `spec` is `primary.spec`, its
/// cutoffs are `primary`'s cutoffs, and `dropped_below` /
/// `dropped_above` count the words the primary dropped.  The words
/// the primary kept but the secondary dropped are folded into
/// `dropped_by_secondary`, returned separately, so the caller can
/// report the intersection stats without losing information.
pub struct IntersectedResult {
    pub primary: FilterResult,
    pub secondary: FilterResult,
    pub kept: Vec<WordScore>,
    pub dropped_by_secondary_only: usize,
}

impl IntersectedResult {
    pub fn total_input(&self) -> usize {
        self.primary.total_input()
    }

    pub fn kept_fraction(&self) -> f64 {
        let total = self.total_input();
        if total == 0 {
            return 0.0;
        }
        self.kept.len() as f64 / total as f64
    }
}

/// Compute the intersection of two `FilterResult`s.  Both results
/// must have been produced from the same input `scores` slice;
/// this is enforced structurally by requiring the caller to pass
/// the primary's `kept` order — words present in both `kept` vectors
/// (compared by `word`) survive.
///
/// Runs in O(P + S) time where P and S are the two kept-vector
/// lengths, using a `HashSet` on the secondary's word column.
pub fn intersect(primary: FilterResult, secondary: FilterResult) -> IntersectedResult {
    use std::collections::HashSet;
    let secondary_words: HashSet<&str> = secondary.kept.iter().map(|s| s.word.as_str()).collect();
    let mut kept = Vec::with_capacity(primary.kept.len().min(secondary.kept.len()));
    let mut dropped_by_secondary_only = 0usize;
    for w in &primary.kept {
        if secondary_words.contains(w.word.as_str()) {
            kept.push(w.clone());
        } else {
            dropped_by_secondary_only += 1;
        }
    }
    IntersectedResult {
        primary,
        secondary,
        kept,
        dropped_by_secondary_only,
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

    fn make_scores_split(cl_counts: &[usize], o2_counts: &[usize]) -> Vec<WordScore> {
        assert_eq!(cl_counts.len(), o2_counts.len());
        cl_counts
            .iter()
            .zip(o2_counts.iter())
            .enumerate()
            .map(|(i, (&c, &o))| WordScore {
                word: format!("w{i}"),
                bytes: 5,
                cl100k: c,
                o200k: o,
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
            min: Bound::Percentile(0.0),
            max: Bound::Percentile(100.0),
        };
        let r = spec.apply(&scores).unwrap();
        assert_eq!(r.kept.len(), 5);
        assert_eq!(r.dropped_below, 0);
        assert_eq!(r.dropped_above, 0);
    }

    #[test]
    fn mid_band_drops_extremes_via_percentile() {
        // Counts: 1 2 3 4 5 6 7 8 9 10.  Nearest-rank 30th = 3, 70th = 7.
        let scores = make_scores(&(1..=10).collect::<Vec<_>>());
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Percentile(30.0),
            max: Bound::Percentile(70.0),
        };
        let r = spec.apply(&scores).unwrap();
        assert_eq!(r.cutoff_low, 3);
        assert_eq!(r.cutoff_high, 7);
        // Kept: 3,4,5,6,7 → 5 entries.
        assert_eq!(r.kept.len(), 5);
        assert_eq!(r.dropped_below, 2); // 1, 2
        assert_eq!(r.dropped_above, 3); // 8, 9, 10
        assert_eq!(r.total_input(), 10);
    }

    #[test]
    fn absolute_token_bounds_take_the_literal_cutoffs() {
        let scores = make_scores(&(1..=10).collect::<Vec<_>>());
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Tokens(4),
            max: Bound::Tokens(6),
        };
        let r = spec.apply(&scores).unwrap();
        assert_eq!(r.cutoff_low, 4);
        assert_eq!(r.cutoff_high, 6);
        assert_eq!(r.kept.len(), 3); // 4, 5, 6
        assert_eq!(r.dropped_below, 3); // 1, 2, 3
        assert_eq!(r.dropped_above, 4); // 7, 8, 9, 10
    }

    #[test]
    fn mixed_bounds_percentile_low_tokens_high() {
        let scores = make_scores(&(1..=10).collect::<Vec<_>>());
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Percentile(30.0), // → 3
            max: Bound::Tokens(5),
        };
        let r = spec.apply(&scores).unwrap();
        assert_eq!(r.cutoff_low, 3);
        assert_eq!(r.cutoff_high, 5);
        assert_eq!(r.kept.len(), 3); // 3, 4, 5
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
            min: Bound::Percentile(30.0),
            max: Bound::Percentile(70.0),
        };
        let r = spec.apply(&scores).unwrap();
        let kept_names: Vec<String> = r.kept.iter().map(|s| s.word.clone()).collect();
        assert_eq!(r.cutoff_low, 4);
        assert_eq!(r.cutoff_high, 6);
        assert_eq!(kept_names, vec!["w2", "w5", "w6"]);
    }

    #[test]
    fn apply_rejects_when_resolved_low_exceeds_high() {
        let scores = make_scores(&(1..=10).collect::<Vec<_>>());
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Tokens(7),
            max: Bound::Tokens(3),
        };
        assert!(spec.apply(&scores).is_err());
    }

    #[test]
    fn apply_rejects_when_percentile_resolves_high_below_token_max() {
        // 90th of 1..=10 = 9; if operator caps max at Tokens(4),
        // resolved cutoffs are low=9, high=4 → rejected.
        let scores = make_scores(&(1..=10).collect::<Vec<_>>());
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Percentile(90.0),
            max: Bound::Tokens(4),
        };
        assert!(spec.apply(&scores).is_err());
    }

    #[test]
    fn validate_rejects_out_of_range_percentile() {
        let bad = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Percentile(-10.0),
            max: Bound::Percentile(50.0),
        };
        assert!(bad.validate().is_err());

        let bad = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Percentile(30.0),
            max: Bound::Percentile(110.0),
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn intersect_keeps_only_words_passing_both_filters() {
        // Word w0: cl100k=3, o200k=3 → passes cl [3,4] AND o [3,4]
        // Word w1: cl100k=3, o200k=5 → passes cl [3,4] but NOT o [3,4]
        // Word w2: cl100k=5, o200k=3 → fails cl [3,4] → excluded from primary
        // Word w3: cl100k=4, o200k=4 → passes both
        let scores = make_scores_split(&[3, 3, 5, 4], &[3, 5, 3, 4]);
        let cl_spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Tokens(3),
            max: Bound::Tokens(4),
        };
        let o2_spec = FilterSpec {
            tokenizer: Tokenizer::O200k,
            min: Bound::Tokens(3),
            max: Bound::Tokens(4),
        };
        let cl_res = cl_spec.apply(&scores).unwrap();
        let o2_res = o2_spec.apply(&scores).unwrap();
        assert_eq!(cl_res.kept.len(), 3); // w0, w1, w3
        assert_eq!(o2_res.kept.len(), 3); // w0, w2, w3
        let inter = intersect(cl_res, o2_res);
        let kept_names: Vec<String> = inter.kept.iter().map(|s| s.word.clone()).collect();
        assert_eq!(kept_names, vec!["w0", "w3"]);
        assert_eq!(inter.dropped_by_secondary_only, 1); // w1
        assert_eq!(inter.total_input(), 4);
    }

    #[test]
    fn intersect_matches_primary_when_secondary_keeps_all() {
        let scores = make_scores(&(1..=5).collect::<Vec<_>>());
        let a = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Tokens(2),
            max: Bound::Tokens(4),
        };
        let b = FilterSpec {
            tokenizer: Tokenizer::O200k,
            min: Bound::Tokens(0),
            max: Bound::Tokens(100),
        };
        let a_res = a.apply(&scores).unwrap();
        let b_res = b.apply(&scores).unwrap();
        let inter = intersect(a_res, b_res);
        assert_eq!(inter.kept.len(), 3);
        assert_eq!(inter.dropped_by_secondary_only, 0);
    }

    #[test]
    fn kept_fraction_matches_ratio() {
        let scores = make_scores(&(1..=10).collect::<Vec<_>>());
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Percentile(30.0),
            max: Bound::Percentile(70.0),
        };
        let r = spec.apply(&scores).unwrap();
        assert!((r.kept_fraction() - 0.5).abs() < 1e-9);
    }
}
