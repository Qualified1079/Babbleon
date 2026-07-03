//! Per-role disjoint-subset extractor.
//!
//! # What this does
//!
//! Given
//!
//! - an [`AllocationTable`](crate::allocation::AllocationTable)
//!   (from `allocation::compute`),
//! - the actual wordlist (one word per line),
//! - a caller-supplied seed (arbitrary bytes),
//!
//! produce one [`RoleSubset`] per role: a `Vec<String>` of exactly
//! `pool_size` words drawn from the wordlist, disjoint from every
//! other role's subset.
//!
//! # Why this exists
//!
//! [`crate::allocation`] outputs *sizes* (per-role pool budgets).
//! Wiring those sizes into `v2-babbleon-core::wordlist` needs
//! actual per-role wordlist files.  This module produces them,
//! deterministically, so the operator can commit the emitted files
//! into the runtime and reproduce them exactly on re-run.
//!
//! # Determinism
//!
//! - Input seed is hashed with SHA-256 (32 bytes of key material).
//! - The 32 bytes seed a ChaCha20 PRNG.
//! - Roles are processed in the `AllocationTable`'s row order.
//! - For each role, Fisher-Yates over the *remaining* (not-yet-
//!   assigned) wordlist indices produces the role's subset.
//! - The extractor never re-uses an index across roles, so
//!   disjointness is guaranteed by construction.
//!
//! Same wordlist + same seed + same `AllocationTable` → same
//! per-role subsets, byte-for-byte.  A wordlist edit (add a word,
//! remove a word) is a deliberate re-derivation event; the caller
//! is responsible for versioning the seed alongside the wordlist.

use crate::allocation::AllocationTable;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// One role's disjoint slice of the wordlist.
#[derive(Debug, Clone)]
pub struct RoleSubset {
    pub role_name: String,
    pub words: Vec<String>,
}

/// The disjoint-subset extraction verdict.
#[derive(Debug)]
pub struct Extraction {
    pub subsets: Vec<RoleSubset>,
}

impl Extraction {
    /// Sum of subset lengths.
    #[must_use]
    pub fn total_words(&self) -> usize {
        self.subsets.iter().map(|s| s.words.len()).sum()
    }

    /// Verifies disjointness in O(sum(sizes)) time.  Returns
    /// `Ok(())` iff every word appears in at most one subset.
    /// Debug-only sanity check; extraction itself is disjoint by
    /// construction.
    ///
    /// # Errors
    ///
    /// Returns the first duplicate word encountered.
    pub fn assert_disjoint(&self) -> Result<(), String> {
        let mut seen: HashSet<&str> = HashSet::with_capacity(self.total_words());
        for subset in &self.subsets {
            for w in &subset.words {
                if !seen.insert(w.as_str()) {
                    return Err(format!("word {w:?} appears in more than one subset"));
                }
            }
        }
        Ok(())
    }
}

/// Errors the extractor emits.
#[derive(Debug)]
pub enum ExtractError {
    /// The wordlist is too small to satisfy the aggregate role
    /// allocation.  Same shape as
    /// [`AllocationTable::fits`](crate::allocation::AllocationTable::fits)
    /// = false at a different point in the pipeline.
    WordlistTooSmall {
        needed: usize,
        available: usize,
    },
    /// A role's pool size exceeds the wordlist even before any
    /// other role has drawn.  Happens under `--paranoid` posture.
    RolePoolExceedsWordlist {
        role: String,
        needed: usize,
        available: usize,
    },
    /// `weights.len() != wordlist.len()` in
    /// [`extract_disjoint_subsets_weighted`].  Internal-invariant
    /// error: the CLI builds `weights` 1:1 alongside the unioned
    /// wordlist, so a mismatch means a caller-side bug, not a
    /// user-input problem.
    WeightsLengthMismatch {
        wordlist_len: usize,
        weights_len: usize,
    },
    /// A source weight was non-finite or `<= 0.0`.  Zero or negative
    /// weight would mean "never select this source's words", which
    /// is what `--wordlist-path` omission already expresses more
    /// directly; the extractor rejects it here rather than silently
    /// producing a skewed or NaN-propagating draw.
    InvalidWeight {
        index: usize,
        weight: f64,
    },
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WordlistTooSmall { needed, available } => write!(
                f,
                "wordlist has {available} words but the aggregate role allocation needs {needed}"
            ),
            Self::RolePoolExceedsWordlist {
                role,
                needed,
                available,
            } => write!(
                f,
                "role {role:?} needs {needed} words but only {available} remain in the wordlist"
            ),
            Self::WeightsLengthMismatch {
                wordlist_len,
                weights_len,
            } => write!(
                f,
                "wordlist has {wordlist_len} entries but {weights_len} weights were supplied"
            ),
            Self::InvalidWeight { index, weight } => write!(
                f,
                "weight at index {index} is {weight}; weights must be finite and > 0.0"
            ),
        }
    }
}

impl std::error::Error for ExtractError {}

/// Extract disjoint per-role subsets from `wordlist` in the row
/// order of `allocation`, driven by `seed`.
///
/// # Errors
///
/// - [`ExtractError::WordlistTooSmall`] if the aggregate exceeds
///   the wordlist size.
/// - [`ExtractError::RolePoolExceedsWordlist`] if one role's pool
///   exceeds the wordlist even individually.
pub fn extract_disjoint_subsets(
    wordlist: &[&str],
    allocation: &AllocationTable,
    seed: &[u8],
) -> Result<Extraction, ExtractError> {
    let total_needed: usize = allocation.rows.iter().map(|r| r.pool_size).sum();
    if total_needed > wordlist.len() {
        return Err(ExtractError::WordlistTooSmall {
            needed: total_needed,
            available: wordlist.len(),
        });
    }

    // Guard against a single role exceeding the wordlist even if
    // the sum test above passed (paranoid pool sizes can wrap or
    // saturate on the caller side; be defensive).
    for row in &allocation.rows {
        if row.pool_size > wordlist.len() {
            return Err(ExtractError::RolePoolExceedsWordlist {
                role: row.role.name.clone(),
                needed: row.pool_size,
                available: wordlist.len(),
            });
        }
    }

    let mut rng = derive_prng(seed);

    // Available indices, in insertion order.  Roles draw from this
    // pool via Fisher-Yates partial shuffle so we never touch the
    // wordlist string data more than once per index.
    let mut available_indices: Vec<usize> = (0..wordlist.len()).collect();
    let mut subsets = Vec::with_capacity(allocation.rows.len());

    for row in &allocation.rows {
        let take = row.pool_size;
        // Fisher-Yates the first `take` positions of
        // `available_indices`, then move them out.
        for i in 0..take {
            let j = i + (rng.next_u64_range(available_indices.len() - i) as usize);
            available_indices.swap(i, j);
        }
        let chosen: Vec<String> = available_indices
            .drain(0..take)
            .map(|idx| wordlist[idx].to_string())
            .collect();

        subsets.push(RoleSubset {
            role_name: row.role.name.clone(),
            words: chosen,
        });
    }

    Ok(Extraction { subsets })
}

/// Weighted variant of [`extract_disjoint_subsets`].
///
/// # Why this exists
///
/// The unweighted extractor draws every word from the union with
/// equal probability, which is right for a single-language corpus
/// but wrong once an operator unions multiple `--wordlist-path`
/// sources of very different sizes (e.g. a 370k-word English
/// baseline plus a 40k-word filtered German list) and wants a
/// specific per-source representation in the output instead of
/// "whatever the size ratio happens to produce" — without
/// maintaining a hand-shuffled pre-mixed file.
///
/// `weights[i]` is the relative draw weight of `wordlist[i]`
/// (typically: every word from the same source shares one weight).
/// A word with weight `2.0` is twice as likely to be drawn ahead of
/// a weight-`1.0` word, source-size differences aside.
///
/// # Algorithm
///
/// [Efraimidis–Spirakis A-Res weighted sampling without
/// replacement](https://en.wikipedia.org/wiki/Reservoir_sampling#Algorithm_A-Res):
/// draw `u_i ~ Uniform(0, 1)` per index, compute priority key
/// `k_i = u_i^(1/w_i)`, and take indices in descending-key order.
/// Higher weight pulls `k_i` closer to 1 (since `1/w_i < 1` for
/// `w_i > 1` flattens the curve toward the upper end), so
/// higher-weight items are more likely to sort early.  With every
/// weight equal, this reduces to a uniform random permutation — the
/// same distribution [`extract_disjoint_subsets`] produces, though
/// NOT the same seed→output mapping (different algorithm, different
/// RNG draw sequence), which is exactly why the two functions are
/// kept separate rather than merged behind an "all weights 1.0"
/// fast path: existing extractions' documented seed→hash pairs in
/// `RESULTS.md` and `HANDOFF.md` must stay reproducible against
/// [`extract_disjoint_subsets`] forever.
///
/// The full index set is sorted once by key (`O(N log N)`), then
/// each role in `allocation`'s row order drains the next
/// `pool_size` indices off the front — the same "roles sequentially
/// drain a shared shuffled pool" shape as the unweighted extractor,
/// generalized to a weighted shuffle.
///
/// # Errors
///
/// - [`ExtractError::WeightsLengthMismatch`] if `weights.len() !=
///   wordlist.len()`.
/// - [`ExtractError::InvalidWeight`] if any weight is non-finite or
///   `<= 0.0`.
/// - [`ExtractError::WordlistTooSmall`] / `RolePoolExceedsWordlist`
///   as in the unweighted extractor.
pub fn extract_disjoint_subsets_weighted(
    wordlist: &[&str],
    weights: &[f64],
    allocation: &AllocationTable,
    seed: &[u8],
) -> Result<Extraction, ExtractError> {
    if weights.len() != wordlist.len() {
        return Err(ExtractError::WeightsLengthMismatch {
            wordlist_len: wordlist.len(),
            weights_len: weights.len(),
        });
    }
    for (index, &w) in weights.iter().enumerate() {
        if !w.is_finite() || w <= 0.0 {
            return Err(ExtractError::InvalidWeight { index, weight: w });
        }
    }

    let total_needed: usize = allocation.rows.iter().map(|r| r.pool_size).sum();
    if total_needed > wordlist.len() {
        return Err(ExtractError::WordlistTooSmall {
            needed: total_needed,
            available: wordlist.len(),
        });
    }
    for row in &allocation.rows {
        if row.pool_size > wordlist.len() {
            return Err(ExtractError::RolePoolExceedsWordlist {
                role: row.role.name.clone(),
                needed: row.pool_size,
                available: wordlist.len(),
            });
        }
    }

    let mut rng = derive_prng(seed);
    use rand::Rng;
    let mut keyed: Vec<(f64, usize)> = (0..wordlist.len())
        .map(|idx| {
            // `gen_range` excludes 1.0 and (in practice) never
            // returns exactly 0.0 for a 52-bit-mantissa f64 draw;
            // clamp defensively so `ln`/`powf` never sees a literal
            // zero even in that astronomically unlikely case.
            let u: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
            let key = u.powf(1.0 / weights[idx]);
            (key, idx)
        })
        .collect();
    // Descending by key: highest-priority (most likely to be a
    // weighted sample) first.  `partial_cmp` is safe here because
    // `key` is a finite `powf` of two finite, in-range operands.
    keyed.sort_by(|a, b| b.0.partial_cmp(&a.0).expect("keys are always finite"));

    let mut ordered = keyed.into_iter().map(|(_, idx)| idx);
    let mut subsets = Vec::with_capacity(allocation.rows.len());
    for row in &allocation.rows {
        let words: Vec<String> = ordered
            .by_ref()
            .take(row.pool_size)
            .map(|idx| wordlist[idx].to_string())
            .collect();
        subsets.push(RoleSubset {
            role_name: row.role.name.clone(),
            words,
        });
    }

    Ok(Extraction { subsets })
}

/// SHA-256(seed) → 32 bytes → ChaCha20Rng.  Public so tests can
/// verify determinism explicitly.
#[must_use]
pub fn derive_prng(seed: &[u8]) -> ChaCha20Rng {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    let key: [u8; 32] = hasher.finalize().into();
    ChaCha20Rng::from_seed(key)
}

// Thin adapter that lets us call a ChaCha20Rng with a bounded
// upper limit without pulling in `rand::Rng`'s trait every time.
trait NextU64Range {
    fn next_u64_range(&mut self, upper: usize) -> u64;
}

impl NextU64Range for ChaCha20Rng {
    fn next_u64_range(&mut self, upper: usize) -> u64 {
        use rand::Rng;
        assert!(upper > 0);
        self.gen_range(0..(upper as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        derive_prng, extract_disjoint_subsets, extract_disjoint_subsets_weighted, ExtractError,
    };
    use crate::allocation::AllocationTable;
    use crate::params::{AttackerModel, Role, WordlistModel};

    fn tiny_wordlist() -> Vec<&'static str> {
        // 10 words is enough to test disjointness + determinism at
        // trivial cost.
        vec![
            "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota", "kappa",
        ]
    }

    fn tiny_allocation() -> AllocationTable {
        let roles = vec![
            Role {
                name: "role_a".into(),
                compound_n: 1,
                entropy_model: crate::params::EntropyModel::Uniqueness,
                alias_count: 1,
                uniqueness_safety_factor: 1,
                target_bits_override: Some(0.0),
                tokens_per_compound: None,
                pool_size_floor: 3,
                events_per_epoch_override: None,
            },
            Role {
                name: "role_b".into(),
                compound_n: 1,
                entropy_model: crate::params::EntropyModel::Uniqueness,
                alias_count: 1,
                uniqueness_safety_factor: 1,
                target_bits_override: Some(0.0),
                tokens_per_compound: None,
                pool_size_floor: 4,
                events_per_epoch_override: None,
            },
        ];
        // Small hypothetical wordlist (size=10) so the allocation
        // does not run out of pool.
        let mut wordlist = WordlistModel::cl100k_baseline();
        wordlist.size = 10;
        AllocationTable::compute(
            &roles,
            &AttackerModel::developer_laptop_default(),
            &wordlist,
        )
    }

    #[test]
    fn same_seed_yields_same_subsets() {
        let wl = tiny_wordlist();
        let alloc = tiny_allocation();
        let a = extract_disjoint_subsets(&wl, &alloc, b"seed").unwrap();
        let b = extract_disjoint_subsets(&wl, &alloc, b"seed").unwrap();
        assert_eq!(a.subsets.len(), b.subsets.len());
        for (r1, r2) in a.subsets.iter().zip(b.subsets.iter()) {
            assert_eq!(r1.role_name, r2.role_name);
            assert_eq!(r1.words, r2.words);
        }
    }

    #[test]
    fn different_seeds_yield_different_subsets() {
        let wl = tiny_wordlist();
        let alloc = tiny_allocation();
        let a = extract_disjoint_subsets(&wl, &alloc, b"seed-A").unwrap();
        let b = extract_disjoint_subsets(&wl, &alloc, b"seed-B").unwrap();
        // Not asserting inequality on every position (a small
        // fraction of positions could accidentally match) — but the
        // whole vec should not match.
        let identical = a
            .subsets
            .iter()
            .zip(b.subsets.iter())
            .all(|(x, y)| x.words == y.words);
        assert!(!identical, "different seeds produced identical output");
    }

    #[test]
    fn subsets_are_disjoint() {
        let wl = tiny_wordlist();
        let alloc = tiny_allocation();
        let e = extract_disjoint_subsets(&wl, &alloc, b"seed").unwrap();
        e.assert_disjoint().expect("subsets must be disjoint");
    }

    #[test]
    fn subsets_have_the_requested_sizes() {
        let wl = tiny_wordlist();
        let alloc = tiny_allocation();
        let e = extract_disjoint_subsets(&wl, &alloc, b"seed").unwrap();
        assert_eq!(e.subsets.len(), alloc.rows.len());
        for (row, subset) in alloc.rows.iter().zip(e.subsets.iter()) {
            assert_eq!(subset.words.len(), row.pool_size);
        }
    }

    #[test]
    fn subsets_cover_at_most_the_wordlist() {
        let wl = tiny_wordlist();
        let alloc = tiny_allocation();
        let e = extract_disjoint_subsets(&wl, &alloc, b"seed").unwrap();
        assert!(e.total_words() <= wl.len());
    }

    #[test]
    fn wordlist_too_small_errors_early() {
        let wl = vec!["alpha", "beta", "gamma"];
        // 10-word allocation cannot fit in a 3-word wordlist.
        let alloc = tiny_allocation();
        let err = extract_disjoint_subsets(&wl, &alloc, b"seed").unwrap_err();
        matches!(err, ExtractError::WordlistTooSmall { .. })
            .then_some(())
            .expect("expected WordlistTooSmall");
    }

    #[test]
    fn derive_prng_is_deterministic() {
        let mut a = derive_prng(b"seed");
        let mut b = derive_prng(b"seed");
        use rand::RngCore;
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn weighted_same_seed_yields_same_subsets() {
        let wl = tiny_wordlist();
        let weights = vec![1.0; wl.len()];
        let alloc = tiny_allocation();
        let a = extract_disjoint_subsets_weighted(&wl, &weights, &alloc, b"seed").unwrap();
        let b = extract_disjoint_subsets_weighted(&wl, &weights, &alloc, b"seed").unwrap();
        for (r1, r2) in a.subsets.iter().zip(b.subsets.iter()) {
            assert_eq!(r1.words, r2.words);
        }
    }

    #[test]
    fn weighted_subsets_are_disjoint_and_correctly_sized() {
        let wl = tiny_wordlist();
        let weights = vec![1.0; wl.len()];
        let alloc = tiny_allocation();
        let e = extract_disjoint_subsets_weighted(&wl, &weights, &alloc, b"seed").unwrap();
        e.assert_disjoint().expect("subsets must be disjoint");
        for (row, subset) in alloc.rows.iter().zip(e.subsets.iter()) {
            assert_eq!(subset.words.len(), row.pool_size);
        }
    }

    #[test]
    fn weighted_rejects_length_mismatch() {
        let wl = tiny_wordlist();
        let weights = vec![1.0; wl.len() - 1];
        let alloc = tiny_allocation();
        let err = extract_disjoint_subsets_weighted(&wl, &weights, &alloc, b"seed").unwrap_err();
        assert!(matches!(err, ExtractError::WeightsLengthMismatch { .. }));
    }

    #[test]
    fn weighted_rejects_non_positive_weight() {
        let wl = tiny_wordlist();
        let mut weights = vec![1.0; wl.len()];
        weights[2] = 0.0;
        let alloc = tiny_allocation();
        let err = extract_disjoint_subsets_weighted(&wl, &weights, &alloc, b"seed").unwrap_err();
        assert!(matches!(
            err,
            ExtractError::InvalidWeight { index: 2, weight } if weight == 0.0
        ));
    }

    #[test]
    fn weighted_rejects_nan_weight() {
        let wl = tiny_wordlist();
        let mut weights = vec![1.0; wl.len()];
        weights[0] = f64::NAN;
        let alloc = tiny_allocation();
        let err = extract_disjoint_subsets_weighted(&wl, &weights, &alloc, b"seed").unwrap_err();
        assert!(matches!(err, ExtractError::InvalidWeight { index: 0, .. }));
    }

    #[test]
    fn heavily_weighted_source_dominates_a_large_role() {
        // 500 "hi" words (weight 10x) + 500 "lo" words (weight 1x).
        // Allocate a single role that draws 100 words — the heavy
        // source should supply a large majority, not ~50%.
        let hi_words: Vec<String> = (0..500).map(|i| format!("hi{i}")).collect();
        let lo_words: Vec<String> = (0..500).map(|i| format!("lo{i}")).collect();
        let wl: Vec<&str> = hi_words
            .iter()
            .chain(lo_words.iter())
            .map(String::as_str)
            .collect();
        let weights: Vec<f64> = std::iter::repeat(10.0)
            .take(500)
            .chain(std::iter::repeat(1.0).take(500))
            .collect();

        let roles = vec![Role {
            name: "big".into(),
            compound_n: 1,
            entropy_model: crate::params::EntropyModel::Uniqueness,
            alias_count: 1,
            uniqueness_safety_factor: 1,
            target_bits_override: Some(0.0),
            tokens_per_compound: None,
            pool_size_floor: 100,
            events_per_epoch_override: None,
        }];
        let mut wordlist_model = WordlistModel::cl100k_baseline();
        wordlist_model.size = wl.len();
        let alloc = AllocationTable::compute(
            &roles,
            &AttackerModel::developer_laptop_default(),
            &wordlist_model,
        );

        let e = extract_disjoint_subsets_weighted(&wl, &weights, &alloc, b"weight-skew-seed")
            .unwrap();
        let hi_count = e.subsets[0]
            .words
            .iter()
            .filter(|w| w.starts_with("hi"))
            .count();
        // Expected value under a 10:1 weight with equal source sizes
        // is ~91/9; assert clearly more than an even split to avoid
        // seed-dependent flakiness while still proving the bias.
        assert!(
            hi_count > 70,
            "expected the 10x-weighted source to dominate; got {hi_count}/100 from it"
        );
    }

    #[test]
    fn empty_wordlist_with_zero_allocation_returns_no_subsets() {
        let wl: Vec<&str> = vec![];
        let alloc = AllocationTable::compute(
            &[],
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        let e = extract_disjoint_subsets(&wl, &alloc, b"seed").unwrap();
        assert!(e.subsets.is_empty());
        assert_eq!(e.total_words(), 0);
    }
}
