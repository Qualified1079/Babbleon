//! Bijective permutation of `[0, N)` keyed by an HKDF-derived seed.
//!
//! # What this defeats
//!
//! Babbleon's per-host scramble needs a bijective function from tool
//! indices into wordlist positions: a permutation of `[0, N)`.  An
//! attacker who learns one mapping entry must learn nothing about the
//! others; given the public algorithm, the only way to "guess" the
//! mapping is to brute-force the seed.
//!
//! v1 used a Fisher-Yates shuffle of `[0, N)` driven by `ChaCha20`
//! seeded from `HMAC-SHA-256(host_secret, "babbleon-fpe-v1" ||
//! epoch_be)`.  v2 simplifies: the seed comes directly from
//! `key_derivation::derive_subkey` and we drop the prior ad-hoc HMAC
//! step.  Same security shape; one fewer hand-rolled construction.
//!
//! # Mechanism
//!
//! 1. Caller derives a 32-byte subkey via
//!    `key_derivation::derive_subkey(secret, epoch, purpose, 32)`.
//! 2. Seed a `ChaCha20Rng` from those 32 bytes.
//! 3. Build `perm = (0..N as u32).collect::<Vec<_>>()`.
//! 4. `perm.shuffle(&mut rng)` — Knuth-Fisher-Yates.
//! 5. Build the inverse for O(1) reverse lookups.
//!
//! # Security properties
//!
//! - **Bijective.**  Fisher-Yates produces a permutation by
//!   construction; no two inputs map to the same output and every
//!   output has exactly one preimage.  The unit tests check this.
//! - **PRF-strong.**  Under the PRF assumption on HMAC-SHA-256 (which
//!   HKDF uses internally) the output is computationally
//!   indistinguishable from a uniformly random permutation.
//! - **Rotation-fresh.**  Different epochs produce statistically
//!   independent permutations because the HKDF info string includes
//!   the big-endian epoch.
//!
//! # What this does NOT defeat
//!
//! - **Side-channel attacks during permutation construction.**  The
//!   Fisher-Yates inner swap reads from a data-dependent index;
//!   timing channels on the cache hierarchy can leak swap positions
//!   to a co-tenant attacker.  Mitigation lives in the launcher
//!   (mlockall + Landlock + seccomp); the math itself is not
//!   constant-time.
//! - **Memory-disclosure attacks against the permutation cache.**
//!   v2 does not cache permutations in the core library; callers
//!   that need warm-path performance build a cache at the next
//!   layer up with explicit lifetime control.

use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use crate::errors::{Error, Result};
use crate::key_derivation::derive_subkey;
use crate::per_host_secret::PerHostSecret;

/// A bijective permutation of `[0, N)`.
///
/// Stores the forward map (`perm[i]` = where `i` lands) and the
/// inverse (`inverse[perm[i]] = i`).  Both vectors hold `u32`
/// indices; the chosen width caps `N` at `u32::MAX` (4.29 × 10⁹),
/// far beyond any wordlist we'd plausibly use.
#[derive(Debug, Clone)]
pub struct Permutation {
    /// Forward map: `perm[i]` is the output position of input `i`.
    perm: Vec<u32>,
    /// Inverse map: `inverse[p]` is the input that mapped to `p`.
    inverse: Vec<u32>,
}

impl Permutation {
    /// Build a permutation of `[0, n)` keyed by `(secret, epoch, purpose)`.
    ///
    /// `purpose` is the HKDF info argument; distinct purposes produce
    /// independent permutations under the same secret + epoch.
    ///
    /// # Errors
    ///
    /// - `Error::OutOfRange` if `n == 0` or `n > u32::MAX as usize`.
    /// - `Error::Crypto` if subkey derivation fails (only possible
    ///   when HKDF's expand limit is exceeded; not possible for our
    ///   32-byte subkeys).
    ///
    /// # Panics
    ///
    /// Internally uses `u32::try_from(n).expect(...)` after the
    /// `n > u32::MAX as usize` bounds check above; the `expect` is
    /// statically unreachable.  If the bounds check is ever removed
    /// or relaxed without revisiting the cast site, the function
    /// will panic on `n > u32::MAX`.
    pub fn build(
        secret: &PerHostSecret,
        epoch: u64,
        purpose: &[u8],
        n: usize,
    ) -> Result<Self> {
        if n == 0 {
            return Err(Error::OutOfRange { index: 0, size: 1 });
        }
        if n > u32::MAX as usize {
            return Err(Error::OutOfRange {
                index: n,
                size: u32::MAX as usize,
            });
        }

        let seed = derive_subkey(secret, epoch, purpose, 32)?;
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(&seed[..]);
        let mut rng = ChaCha20Rng::from_seed(seed_arr);

        // Fisher-Yates.
        // SAFETY of the casts below: line 94 already guards
        // `n > u32::MAX as usize`, so every index up to n-1 fits in u32.
        // try_from documents the precondition; expect() carries the
        // invariant statement so a future refactor cannot silently
        // truncate.
        let n_u32 = u32::try_from(n).expect("bounds-checked: n <= u32::MAX above");
        let mut perm: Vec<u32> = (0..n_u32).collect();
        perm.shuffle(&mut rng);

        // Build inverse for O(1) reverse lookups.
        let mut inverse = vec![0u32; n];
        for (input, &output) in perm.iter().enumerate() {
            let input_u32 = u32::try_from(input)
                .expect("bounds-checked: input < n <= u32::MAX above");
            inverse[output as usize] = input_u32;
        }

        Ok(Self { perm, inverse })
    }

    /// Apply the permutation to `input`.  Returns `None` if `input >= n`.
    #[must_use]
    pub fn apply(&self, input: usize) -> Option<usize> {
        self.perm.get(input).map(|&x| x as usize)
    }

    /// Reverse the permutation: returns the `input` such that
    /// `apply(input) == Some(output)`, or `None` if `output >= n`.
    #[must_use]
    pub fn reverse(&self, output: usize) -> Option<usize> {
        self.inverse.get(output).map(|&x| x as usize)
    }

    /// Size of the domain (and codomain) of this permutation.
    #[must_use]
    pub fn len(&self) -> usize {
        self.perm.len()
    }

    /// True iff the permutation is empty (never; we reject `n == 0`
    /// at construction, so this is provided only to satisfy
    /// `clippy::len_without_is_empty`).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.perm.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::Permutation;
    use crate::per_host_secret::PerHostSecret;

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn bijective_small() {
        let s = fixed_secret();
        let p = Permutation::build(&s, 0, b"v2-test", 100).unwrap();
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let out = p.apply(i).unwrap();
            assert!(out < 100);
            assert!(seen.insert(out), "duplicate output for input {i}: {out}");
        }
    }

    #[test]
    fn roundtrip_apply_reverse() {
        let s = fixed_secret();
        let p = Permutation::build(&s, 3, b"v2-test", 1000).unwrap();
        for i in 0..1000 {
            let out = p.apply(i).unwrap();
            assert_eq!(p.reverse(out), Some(i));
        }
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let s = fixed_secret();
        let a = Permutation::build(&s, 0, b"v2-test", 500).unwrap();
        let b = Permutation::build(&s, 0, b"v2-test", 500).unwrap();
        for i in 0..500 {
            assert_eq!(a.apply(i), b.apply(i));
        }
    }

    #[test]
    fn different_epoch_changes_most_outputs() {
        let s = fixed_secret();
        let a = Permutation::build(&s, 0, b"v2-test", 1000).unwrap();
        let b = Permutation::build(&s, 1, b"v2-test", 1000).unwrap();
        let differ = (0..1000)
            .filter(|&i| a.apply(i) != b.apply(i))
            .count();
        // A random permutation should change roughly N(1 - 1/N) entries.
        // We expect > 99% change; allow generous slack to avoid flakes.
        assert!(
            differ > 950,
            "epoch change moved only {differ}/1000 entries"
        );
    }

    #[test]
    fn different_purpose_changes_most_outputs() {
        let s = fixed_secret();
        let a = Permutation::build(&s, 0, b"v2-purpose-a", 1000).unwrap();
        let b = Permutation::build(&s, 0, b"v2-purpose-b", 1000).unwrap();
        let differ = (0..1000)
            .filter(|&i| a.apply(i) != b.apply(i))
            .count();
        assert!(differ > 950);
    }

    #[test]
    fn out_of_range_input_returns_none() {
        let s = fixed_secret();
        let p = Permutation::build(&s, 0, b"v2-test", 100).unwrap();
        assert!(p.apply(100).is_none());
        assert!(p.apply(999).is_none());
        assert!(p.reverse(100).is_none());
    }

    #[test]
    fn large_n_bijection_property() {
        // Property: for a large permutation, every input in
        // [0, n) maps to a unique output in [0, n).  Stronger
        // than `bijective_small`: catches off-by-one or hash-
        // collision regressions that only surface at scale.
        const N: usize = 10_000;
        let s = fixed_secret();
        let p =
            Permutation::build(&s, 42, b"v2-property-large", N).unwrap();
        let mut seen = vec![false; N];
        for i in 0..N {
            let out = p.apply(i).unwrap();
            assert!(out < N, "output {out} out of range for N={N}");
            assert!(!seen[out], "duplicate output {out} from input {i}");
            seen[out] = true;
        }
        assert!(
            seen.iter().all(|&b| b),
            "permutation is not surjective"
        );
    }

    #[test]
    fn distribution_is_well_spread() {
        // Property: a random permutation over N should have its
        // outputs roughly uniformly distributed.  We bucket
        // outputs into 16 bins and assert no bin holds more than
        // 2x the expected count — catches a regression where the
        // permutation maps every input to the first 1/16 of
        // outputs (a classic "off by one in mask" bug).
        const N: usize = 16_000;
        const BUCKETS: usize = 16;
        let s = fixed_secret();
        let p = Permutation::build(
            &s,
            7,
            b"v2-property-distribution",
            N,
        )
        .unwrap();
        let mut bucket_counts = [0usize; BUCKETS];
        for i in 0..N {
            let out = p.apply(i).unwrap();
            bucket_counts[out * BUCKETS / N] += 1;
        }
        let expected = N / BUCKETS;
        for (idx, &count) in bucket_counts.iter().enumerate() {
            assert!(
                count <= 2 * expected,
                "bucket {idx} has {count} entries, expected ~{expected}",
            );
        }
    }

    #[test]
    fn reverse_is_inverse_for_large_n() {
        // Property: reverse(apply(i)) == i for every i in [0, n).
        // Together with `large_n_bijection_property` this fully
        // pins down the bijection inverse.
        const N: usize = 5_000;
        let s = fixed_secret();
        let p = Permutation::build(&s, 0, b"v2-property-inverse", N).unwrap();
        for i in 0..N {
            let out = p.apply(i).unwrap();
            assert_eq!(p.reverse(out), Some(i));
        }
    }

    #[test]
    fn many_secrets_all_produce_distinct_permutations() {
        // Property: distinct per-host secrets produce distinct
        // permutations.  If they didn't, two hosts with different
        // secrets would have the same scrambled names — fatal for
        // the per-host obfuscation claim.  We test this by
        // hashing the per-secret output at a fixed input.
        const N: usize = 1_000;
        let mut signatures = std::collections::HashSet::new();
        for byte in 0u8..32 {
            let s = PerHostSecret::from_bytes(&[byte; 32]).unwrap();
            let p = Permutation::build(&s, 0, b"v2-property-host", N).unwrap();
            // Use the output of input 0 + input 1 as a tiny
            // signature; with N=1000 the chance of two distinct
            // permutations colliding at both points is ~1/10^6.
            let sig = (p.apply(0).unwrap(), p.apply(1).unwrap());
            assert!(
                signatures.insert(sig),
                "two distinct secrets produced colliding signature {sig:?}",
            );
        }
    }

    #[test]
    fn zero_size_rejected() {
        let s = fixed_secret();
        let err = Permutation::build(&s, 0, b"v2-test", 0);
        assert!(err.is_err());
    }
}
