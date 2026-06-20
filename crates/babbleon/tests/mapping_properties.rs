//! Property-based tests for the per-host mapping layer.
//!
//! The unit tests in `mapping/mapper.rs` cover a handful of hand-picked
//! cases (no-collision on 6 tools, rotation moves all names, etc.).
//! That's a good baseline but the security claim is universal — every
//! tracked-list, every secret, every epoch — so the proptest harness
//! generalises it.
//!
//! Properties exercised:
//!   - **Bijection.**  `build_table(tracked, epoch)` produces N unique
//!     scrambled names for N unique tracked names; every scrambled name
//!     reveals back to its real name.
//!   - **Honey disjointness.**  No honey name collides with a real
//!     scrambled name in the same epoch.
//!   - **Determinism.**  Same (host_secret, tracked, epoch) builds the
//!     same table — both halves of the bijection are stable.
//!   - **Rotation.**  Different epochs rename every entry (≥ 99 % of
//!     positions move; perfectly-stable rotations on small N can leave
//!     one position by chance, but for the input shapes below the
//!     probability is far below the test cycle count).
//!   - **Secret separation.**  Different host secrets diverge: not a
//!     single real name maps to the same scrambled name under two
//!     different secrets at the same epoch.
//!   - **FPE bijection over `[0, N)`.**  The encrypt/decrypt round-trip
//!     is the identity for every input in range.

use babbleon::mapping::{fpe, Mapper};
use proptest::collection::vec;
use proptest::prelude::*;

/// A 32-byte host-secret strategy.  We use bytes of bounded value to
/// keep the proptest output legible without sacrificing coverage.
fn secret_strategy() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

/// A list of 1..=20 distinct lowercase ASCII tool names.  We dedup
/// inside the test rather than via a Strategy to keep the generated
/// vector size predictable.
fn tracked_strategy() -> impl Strategy<Value = Vec<String>> {
    vec("[a-z]{2,8}", 1..=20)
}

fn dedup(mut tracked: Vec<String>) -> Vec<String> {
    tracked.sort();
    tracked.dedup();
    tracked
}

// Each `build_table` cold-builds the ~370k-entry wordlist permutation
// (~18 ms; see tools/rotation-benchmark/RESULTS.md), so the per-case
// cost is dominated by FPE construction.  16 cases per property keeps
// the full suite under ~60 s while still exploring the input space.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        ..ProptestConfig::default()
    })]

    #[test]
    fn build_table_is_bijective(
        secret in secret_strategy(),
        tracked in tracked_strategy(),
        epoch in 0u64..1_000_000,
    ) {
        let tracked = dedup(tracked);
        let m = Mapper::new(&secret);
        let table = m.build_table(&tracked, epoch);

        // Forward map has one scrambled per real, with no collisions.
        prop_assert_eq!(table.real_to_scrambled.len(), tracked.len());
        let mut scrambled: Vec<&str> =
            table.real_to_scrambled.values().map(|s| s.as_str()).collect();
        scrambled.sort();
        let before = scrambled.len();
        scrambled.dedup();
        prop_assert_eq!(scrambled.len(), before, "scrambled names must be unique");

        // Inverse map round-trips every entry.
        for real in &tracked {
            let s = table.scramble(real).expect("real must scramble");
            let back = table.reveal(s).expect("scrambled must reveal");
            prop_assert_eq!(back, real.as_str());
        }
    }

    #[test]
    fn honey_disjoint_from_real(
        secret in secret_strategy(),
        tracked in tracked_strategy(),
        epoch in 0u64..1_000_000,
    ) {
        let tracked = dedup(tracked);
        let table = Mapper::new(&secret).build_table(&tracked, epoch);
        let real_scrambled: std::collections::HashSet<&str> =
            table.real_to_scrambled.values().map(|s| s.as_str()).collect();
        for honey in &table.honey_names {
            prop_assert!(
                !real_scrambled.contains(honey.as_str()),
                "honey name {honey:?} collides with a real scrambled name"
            );
        }
    }

    #[test]
    fn build_table_is_deterministic(
        secret in secret_strategy(),
        tracked in tracked_strategy(),
        epoch in 0u64..1_000_000,
    ) {
        let tracked = dedup(tracked);
        let m = Mapper::new(&secret);
        let a = m.build_table(&tracked, epoch);
        let b = m.build_table(&tracked, epoch);
        // Maps compare equal as HashMaps; iterate to give a nice error.
        for real in &tracked {
            prop_assert_eq!(a.scramble(real), b.scramble(real));
        }
        prop_assert_eq!(a.honey_names, b.honey_names);
    }

    #[test]
    fn distinct_secrets_diverge(
        s1 in secret_strategy(),
        s2 in secret_strategy(),
        tracked in tracked_strategy(),
        epoch in 0u64..1_000_000,
    ) {
        let tracked = dedup(tracked);
        // Skip the degenerate case where the strategy happens to draw
        // identical secrets (vanishingly rare but proptest will find it).
        prop_assume!(s1 != s2);
        let t1 = Mapper::new(&s1).build_table(&tracked, epoch);
        let t2 = Mapper::new(&s2).build_table(&tracked, epoch);
        for real in &tracked {
            prop_assert_ne!(t1.scramble(real), t2.scramble(real));
        }
    }

    #[test]
    fn fpe_roundtrip_is_identity(
        seed in any::<[u8; 32]>(),
        epoch in 0u64..1_000_000,
        n in 1usize..=4096,
        x_offset in 0usize..4096,
    ) {
        let x = x_offset % n;
        let y = fpe::encrypt(&seed, epoch, n, x).expect("in-range encrypt");
        prop_assert!(y < n);
        let back = fpe::decrypt(&seed, epoch, n, y).expect("in-range decrypt");
        prop_assert_eq!(back, x);
    }

    #[test]
    fn rotation_moves_almost_everything(
        secret in secret_strategy(),
        tracked in tracked_strategy(),
        e1 in 0u64..1_000_000,
    ) {
        let tracked = dedup(tracked);
        prop_assume!(tracked.len() >= 4);
        let e2 = e1.wrapping_add(1);
        let m = Mapper::new(&secret);
        let t1 = m.build_table(&tracked, e1);
        let t2 = m.build_table(&tracked, e2);
        let moved = tracked
            .iter()
            .filter(|r| t1.scramble(r) != t2.scramble(r))
            .count();
        // With wordlist N ≈ 370k and a 4-word compound, the chance of any
        // single entry coinciding is ~(1/N)^4 — astronomically below 1
        // in this test budget.  Insist on ALL entries moving.
        prop_assert_eq!(moved, tracked.len(),
            "rotation left {} of {} entries in place", tracked.len() - moved, tracked.len());
    }
}
