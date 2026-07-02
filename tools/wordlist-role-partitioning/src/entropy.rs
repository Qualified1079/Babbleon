//! Pure-math entropy primitives used by the role-partitioning tool.
//!
//! # What lives here
//!
//! Only the closed-form functions that map between three quantities:
//!
//! - `P` — role pool size (`usize`, number of distinct words available
//!   to the role for the current epoch).
//! - `N` — compound length (`usize`, how many words concatenate to
//!   form one compound emitted by the scrambler).
//! - `H` — compound entropy in bits (`f64`, `H = N * log2(P)` for a
//!   with-replacement draw, which matches the identifier scrambler's
//!   permutation-with-repetition semantics at compound-N).
//!
//! Plus one collision primitive: given `H` and `N_events`, return the
//! birthday-bound collision probability.  This is the discriminator
//! for "is the pool big enough for the role?".
//!
//! # Why these three primitives and not more
//!
//! The role-partitioning question decomposes into (a) how much entropy
//! does each role need against its threat, and (b) does the sum of
//! per-role pool sizes fit inside the on-host wordlist.  Every other
//! quantity the tool prints is derived from these three primitives;
//! keeping them here lets `allocation` and `report` stay free of
//! floating-point subtlety.
//!
//! # Numerical notes
//!
//! `compound_entropy_bits` and `required_pool_size` are inverses of
//! each other under `H = N * log2(P)`.  Round-trip is exact modulo
//! `f64` rounding for realistic inputs (`P ≤ 10^7`, `N ≤ 8`); the
//! unit tests pin the round-trip.
//!
//! `birthday_collision_probability` uses the standard
//! `1 - exp(-N² / 2S)` approximation.  Exact for `N << sqrt(S)` and a
//! conservative over-estimate otherwise.  Practical inputs
//! (`N ≤ 10^4`, `S ≥ 2^64`) sit deep in the accurate regime.

/// Bits of entropy in a compound of `compound_n` words drawn
/// independently from a pool of size `pool_size`.
///
/// Returns `0.0` if either dimension is zero (an empty role does not
/// exist and its "compound" is meaningless — the caller should treat
/// zero as the sentinel for "role disabled").
///
/// # Model
///
/// The scrambler picks `compound_n` words with replacement; each pick
/// is independently uniform over the pool.  Space size therefore
/// `pool_size ^ compound_n`; entropy `compound_n * log2(pool_size)`.
#[must_use]
pub fn compound_entropy_bits(pool_size: usize, compound_n: usize) -> f64 {
    if pool_size == 0 || compound_n == 0 {
        return 0.0;
    }
    (compound_n as f64) * (pool_size as f64).log2()
}

/// Smallest pool size `P` such that
/// `compound_entropy_bits(P, compound_n) >= target_bits`.
///
/// Returns `1` if `target_bits <= 0` (any non-empty pool satisfies a
/// non-positive target).  Panics on `compound_n == 0` — a role with a
/// zero-length compound is a caller bug, not a runtime condition.
///
/// # Model
///
/// Inverts `H = N * log2(P)` and takes the ceiling.  Because
/// `log2(P)` grows step-wise across integer `P`, the returned pool
/// size is guaranteed to satisfy the target; the caller does not
/// need to add a safety pad.
#[must_use]
pub fn required_pool_size(target_bits: f64, compound_n: usize) -> usize {
    assert!(compound_n > 0, "compound_n must be positive");
    if target_bits <= 0.0 {
        return 1;
    }
    let ideal = (target_bits / compound_n as f64).exp2();
    // `ideal` is real; ceil then clamp to usize::MAX.
    if ideal.is_infinite() || ideal > usize::MAX as f64 {
        return usize::MAX;
    }
    let ceil = ideal.ceil() as usize;
    // Guard against floating point undershoot at the boundary
    // (e.g. `ideal = 4.0000000000000001` rounding to 4 despite the
    // exact answer being 5).
    if compound_entropy_bits(ceil, compound_n) >= target_bits {
        ceil
    } else {
        ceil + 1
    }
}

/// Birthday-bound collision probability for `n_events` independent
/// uniform draws from a space of size `2^entropy_bits`.
///
/// Uses `1 - exp(-n² / (2·S))`.  Returns `0.0` when
/// `n_events <= 1` (no pair, no collision possible).  Saturates at
/// `1.0` at very large `n_events`.
///
/// # When to trust the number
///
/// Exact in the small-`n / large-S` regime this tool operates in
/// (`n <= 10^4`, `S >= 2^60`).  For `n` approaching `sqrt(S)` it
/// remains a valid upper bound but under-estimates slightly.
#[must_use]
pub fn birthday_collision_probability(entropy_bits: f64, n_events: u64) -> f64 {
    if n_events <= 1 {
        return 0.0;
    }
    if entropy_bits <= 0.0 {
        return 1.0;
    }
    let n = n_events as f64;
    // `S = 2^entropy_bits`; compute `n² / (2S)` in log-space so
    // huge entropies do not overflow.
    let log2_pairs = 2.0 * n.log2() - 1.0; // log2(n² / 2)
    let log2_ratio = log2_pairs - entropy_bits; // log2(n² / (2S))
    if log2_ratio > 0.0 {
        // n²/2 > S — collision practically certain; short-circuit
        // rather than compute exp of a huge negative.
        return 1.0;
    }
    let ratio = log2_ratio.exp2();
    let p = 1.0 - (-ratio).exp();
    p.clamp(0.0, 1.0)
}

/// Attention-cost multiplier for a compound at the given mean
/// token count vs the baseline compound token count.
///
/// Transformer self-attention scales as O(T²) with sequence length
/// `T`; the ratio `(T_role / T_baseline)²` is the leading-order
/// change in per-compound attacker work when swapping in a
/// density-filtered wordlist.
///
/// Returns `1.0` when either argument is non-positive (undefined
/// ratio → identity multiplier is the safe fallback).
#[must_use]
pub fn attention_cost_multiplier(role_tokens: f64, baseline_tokens: f64) -> f64 {
    if role_tokens <= 0.0 || baseline_tokens <= 0.0 {
        return 1.0;
    }
    let ratio = role_tokens / baseline_tokens;
    ratio * ratio
}

#[cfg(test)]
mod tests {
    use super::{
        attention_cost_multiplier, birthday_collision_probability, compound_entropy_bits,
        required_pool_size,
    };

    fn approx(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn compound_entropy_zero_arguments_yield_zero() {
        assert_eq!(compound_entropy_bits(0, 4), 0.0);
        assert_eq!(compound_entropy_bits(1024, 0), 0.0);
    }

    #[test]
    fn compound_entropy_matches_hand_calculation() {
        // log2(2) = 1 → 4 * 1 = 4 bits
        assert!(approx(compound_entropy_bits(2, 4), 4.0, 1e-12));
        // log2(256) = 8 → 3 * 8 = 24 bits
        assert!(approx(compound_entropy_bits(256, 3), 24.0, 1e-12));
        // Real baseline: pool = 223 009, N = 4 → 4 * log2(223009) ≈ 70.99
        let h = compound_entropy_bits(223_009, 4);
        assert!(h > 70.9 && h < 71.1, "got {h}");
    }

    #[test]
    fn required_pool_size_inverts_compound_entropy() {
        for &(n, bits) in &[(4usize, 64.0), (3, 48.0), (2, 16.0), (5, 100.0)] {
            let p = required_pool_size(bits, n);
            let h = compound_entropy_bits(p, n);
            assert!(
                h >= bits,
                "required_pool_size({bits}, {n}) = {p} yields {h} < {bits}"
            );
            // But the pool size just below fails to reach `bits`.
            if p > 1 {
                let h_below = compound_entropy_bits(p - 1, n);
                assert!(
                    h_below < bits + 1e-9,
                    "pool {p} is not the ceiling: {p}-1 = {} yields {h_below} >= {bits}",
                    p - 1
                );
            }
        }
    }

    #[test]
    fn required_pool_size_returns_one_for_non_positive_target() {
        assert_eq!(required_pool_size(0.0, 4), 1);
        assert_eq!(required_pool_size(-5.0, 4), 1);
    }

    #[test]
    #[should_panic(expected = "compound_n must be positive")]
    fn required_pool_size_panics_on_zero_compound_n() {
        let _ = required_pool_size(64.0, 0);
    }

    #[test]
    fn birthday_zero_events_yields_zero_probability() {
        assert_eq!(birthday_collision_probability(64.0, 0), 0.0);
        assert_eq!(birthday_collision_probability(64.0, 1), 0.0);
    }

    #[test]
    fn birthday_zero_entropy_yields_certain_collision() {
        assert_eq!(birthday_collision_probability(0.0, 10), 1.0);
    }

    #[test]
    fn birthday_matches_hand_calculation() {
        // Classic 23-people-364-days: p ≈ 0.507 exact; approx form
        // gives 1 - exp(-23² / (2·365)) ≈ 0.516.  Accept 0.5±0.05.
        let entropy = 365f64.log2();
        let p = birthday_collision_probability(entropy, 23);
        assert!((0.45..=0.55).contains(&p), "got {p}");
    }

    #[test]
    fn birthday_saturates_when_pairs_exceed_space() {
        let p = birthday_collision_probability(4.0, 1_000_000);
        assert!(p >= 0.999_999, "expected ~1.0, got {p}");
    }

    #[test]
    fn attention_multiplier_squares_ratio() {
        assert!(approx(attention_cost_multiplier(11.96, 11.96), 1.0, 1e-9));
        // intersect[3,5]: 13.80 / 11.96 = 1.1538 → squared = 1.3313
        let mult = attention_cost_multiplier(13.80, 11.96);
        assert!((1.32..=1.34).contains(&mult), "got {mult}");
    }

    #[test]
    fn attention_multiplier_handles_zeros() {
        assert_eq!(attention_cost_multiplier(0.0, 10.0), 1.0);
        assert_eq!(attention_cost_multiplier(10.0, 0.0), 1.0);
        assert_eq!(attention_cost_multiplier(-1.0, 10.0), 1.0);
    }
}
