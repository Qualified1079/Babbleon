//! Integer-count percentile + histogram computation.
//!
//! Token counts are small integers (nearly all words fall in [1, 6]
//! tokens for cl100k/o200k), so we avoid float-approximate quantile
//! algorithms and just sort.  For a 370k-entry corpus the sort is
//! sub-second and the memory doubles once — trivial.

/// Sorted view of a set of integer counts (typically token counts).
/// Owns its data; construct once, query many times.
pub struct Distribution {
    sorted: Vec<usize>,
}

impl Distribution {
    /// Build a `Distribution` from an unsorted iterator of counts.
    /// Empty inputs are allowed; percentile queries on them return 0
    /// (with a special-case in `value_at_percentile`).
    pub fn from(counts: impl IntoIterator<Item = usize>) -> Self {
        let mut sorted: Vec<usize> = counts.into_iter().collect();
        sorted.sort_unstable();
        Self { sorted }
    }

    pub fn min(&self) -> usize {
        *self.sorted.first().unwrap_or(&0)
    }

    pub fn max(&self) -> usize {
        *self.sorted.last().unwrap_or(&0)
    }

    pub fn mean(&self) -> f64 {
        if self.sorted.is_empty() {
            return 0.0;
        }
        let sum: usize = self.sorted.iter().sum();
        sum as f64 / self.sorted.len() as f64
    }

    /// Nearest-rank percentile.  `pct` in `[0.0, 100.0]`.  Returns 0
    /// on an empty distribution; clamps out-of-range percentiles.
    pub fn value_at_percentile(&self, pct: f64) -> usize {
        if self.sorted.is_empty() {
            return 0;
        }
        let pct = pct.clamp(0.0, 100.0);
        let n = self.sorted.len();
        // rank is 1-based in the classical formulation; we index
        // 0-based so subtract one after rounding.
        let rank = (pct / 100.0 * n as f64).ceil() as usize;
        let idx = rank.saturating_sub(1).min(n - 1);
        self.sorted[idx]
    }

    /// Bucketed histogram: `buckets[k]` is the count of entries that
    /// equal `k`, up to and including `max_bucket`.  Entries above
    /// `max_bucket` fall into the final overflow bucket at index
    /// `max_bucket + 1`.  Length is always `max_bucket + 2`.
    pub fn histogram(&self, max_bucket: usize) -> Vec<usize> {
        let mut buckets = vec![0usize; max_bucket + 2];
        for &v in &self.sorted {
            if v <= max_bucket {
                buckets[v] += 1;
            } else {
                buckets[max_bucket + 1] += 1;
            }
        }
        buckets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_bounds_are_min_and_max() {
        let d = Distribution::from([1usize, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(d.value_at_percentile(0.0), 1);
        assert_eq!(d.value_at_percentile(100.0), 10);
    }

    #[test]
    fn percentile_midpoint_matches_expected_position() {
        let d = Distribution::from(1usize..=100);
        // Nearest-rank: 50th percentile of 1..=100 → index 49 → value 50.
        assert_eq!(d.value_at_percentile(50.0), 50);
    }

    #[test]
    fn percentile_handles_out_of_range_input() {
        let d = Distribution::from([2usize, 4, 6, 8]);
        assert_eq!(d.value_at_percentile(-5.0), 2);
        assert_eq!(d.value_at_percentile(200.0), 8);
    }

    #[test]
    fn empty_distribution_returns_zeros() {
        let d = Distribution::from(std::iter::empty::<usize>());
        assert_eq!(d.min(), 0);
        assert_eq!(d.max(), 0);
        assert_eq!(d.mean(), 0.0);
        assert_eq!(d.value_at_percentile(50.0), 0);
    }

    #[test]
    fn histogram_counts_buckets_and_overflow() {
        let d = Distribution::from([0usize, 1, 1, 2, 2, 2, 5, 9, 100]);
        let h = d.histogram(5);
        // Length = max_bucket + 2 = 7.
        assert_eq!(h.len(), 7);
        assert_eq!(h[0], 1); // one 0
        assert_eq!(h[1], 2); // two 1s
        assert_eq!(h[2], 3); // three 2s
        assert_eq!(h[3], 0);
        assert_eq!(h[4], 0);
        assert_eq!(h[5], 1); // one 5
        assert_eq!(h[6], 2); // overflow: 9 and 100
    }

    #[test]
    fn mean_matches_manual_calculation() {
        let d = Distribution::from([1usize, 2, 3, 4]);
        assert!((d.mean() - 2.5).abs() < 1e-9);
    }
}
