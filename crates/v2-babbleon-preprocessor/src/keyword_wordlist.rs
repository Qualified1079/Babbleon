//! Per-epoch Python-keyword wordlist for layer-2 (operator scramble).
//!
//! # What this defeats
//!
//! See [`crate::python_keywords`] for the threat-model framing.
//! This module holds the per-epoch derivation that maps each
//! Python hard keyword to a wordlist compound drawn from the
//! per-host secret + epoch via HKDF.  An adversary that learns
//! the keyword mapping at epoch N has compounds that are useless
//! at epoch N+1.
//!
//! # Mechanism
//!
//! Mirrors `whitespace_wordlist::WhitespaceWordlist`:
//!
//! 1. HKDF info label `b"v2-keyword-mapping"` — distinct from
//!    `b"v2-identifier-mapping"`, `b"v2-honey-mapping"`, and
//!    `b"v2-whitespace-mapping"`, so the keyword permutation is
//!    statistically independent of every other per-epoch
//!    permutation under the same `(secret, epoch)`.
//! 2. One compound per keyword, [`COMPOUND_N`]-words per compound.
//!    With 35 keywords × 4 words = 140 wordlist positions per
//!    epoch.
//! 3. Forward lookup: `compound_for(keyword)` returns the
//!    per-epoch compound for that keyword.
//! 4. Reverse lookup: `reverse_lookup(compound)` returns the
//!    original keyword if the compound is in this epoch's
//!    keyword table — used by the unscrambler.
//!
//! # Disjointness with other per-epoch wordlists
//!
//! The keyword compounds are drawn from the same baseline
//! wordlist as the whitespace, identifier, and honey compounds,
//! but each lives under a distinct HKDF purpose label.  In the
//! worst case (small wordlist, large keyword set, bad luck) a
//! keyword compound could collide with a whitespace compound,
//! an identifier compound, or another keyword compound.  The
//! MVP relies on the v2 baseline wordlist (369 652 entries)
//! making collisions astronomically unlikely; the reserved-pool
//! design that eliminates collision entirely is filed against
//! `docs/v2/structure-scrambling.md` Open Question §1.
//!
//! Tests assert per-epoch keyword-vs-keyword disjointness; the
//! cross-table check (keyword vs whitespace vs identifier) is
//! filed as a future invariant.

use std::collections::HashMap;

use babbleon_core_v2::mapping::COMPOUND_N;
use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::permutation::Permutation;
use babbleon_core_v2::wordlist::Wordlist;

use crate::errors::{Error, Result};
use crate::python_keywords::{PYTHON_KEYWORDS, PYTHON_KEYWORD_COUNT};

/// HKDF info label that namespaces the keyword permutation.
///
/// Bumping the trailing version suffix invalidates every previously
/// derived keyword mapping.
const PURPOSE_KEYWORD: &[u8] = b"v2-keyword-mapping";

/// Minimum wordlist size required to derive a keyword mapping.
///
/// `PYTHON_KEYWORD_COUNT × COMPOUND_N` = 140 with the current
/// constants.  Wordlists smaller than this cannot satisfy the
/// derivation; [`KeywordWordlist::build`] returns
/// [`Error::WordlistTooSmall`].
pub const MIN_WORDLIST_SIZE: usize = PYTHON_KEYWORD_COUNT * COMPOUND_N;

/// Per-epoch Python-keyword compound table.
///
/// Held in plain `String`s, matching the v2-core `EpochMapping`
/// and `WhitespaceWordlist` patterns.  Process-level hardening
/// (mlockall, dumpable=0) at the preprocessor binary protects the
/// in-memory mapping; this struct does NOT layer its own
/// secret-bytes wrapper.
///
/// Intentionally NOT `Default` — every instance must be tied to
/// a `(secret, epoch)` pair.
#[derive(Debug, Clone)]
pub struct KeywordWordlist {
    /// The epoch this table was built for.  Diagnostic field;
    /// not security-relevant.
    epoch: u64,
    /// Forward map: keyword (e.g. `"def"`) → per-epoch compound.
    /// Indexed by `&'static str` from [`PYTHON_KEYWORDS`].
    forward: HashMap<&'static str, String>,
    /// Reverse map: compound → keyword.  Populated alongside
    /// `forward` so the unscrambler does linear-time stream
    /// rewriting with O(1) per-token lookup.
    reverse: HashMap<String, &'static str>,
}

impl KeywordWordlist {
    /// Derive the per-epoch keyword mapping for `(secret, epoch)`
    /// over `wordlist`.
    ///
    /// Builds [`PYTHON_KEYWORD_COUNT`] compounds, one per
    /// keyword in [`PYTHON_KEYWORDS`].  Keywords are processed in
    /// list order; slot N consumes wordlist positions
    /// `N × COMPOUND_N` through `(N+1) × COMPOUND_N - 1` (after
    /// HKDF permutation).
    ///
    /// # Errors
    ///
    /// - [`Error::WordlistTooSmall`] if `wordlist.len() < MIN_WORDLIST_SIZE`.
    /// - [`Error::Core`] if the underlying [`Permutation::build`]
    ///   fails (only possible if `secret` is in an invalid
    ///   state, which `PerHostSecret`'s constructor prevents).
    /// - [`Error::KeywordCompoundCollision`] if two keywords end
    ///   up assigned the same compound (HKDF + Fisher-Yates
    ///   makes this astronomically unlikely with the baseline
    ///   wordlist but we check defensively).
    pub fn build(
        secret: &PerHostSecret,
        wordlist: &Wordlist,
        epoch: u64,
    ) -> Result<Self> {
        if wordlist.len() < MIN_WORDLIST_SIZE {
            return Err(Error::WordlistTooSmall {
                needed: MIN_WORDLIST_SIZE,
                have: wordlist.len(),
            });
        }
        let perm = Permutation::build(
            secret,
            epoch,
            PURPOSE_KEYWORD,
            wordlist.len(),
        )?;

        let mut forward: HashMap<&'static str, String> =
            HashMap::with_capacity(PYTHON_KEYWORD_COUNT);
        let mut reverse: HashMap<String, &'static str> =
            HashMap::with_capacity(PYTHON_KEYWORD_COUNT);

        for (slot, kw) in PYTHON_KEYWORDS.iter().enumerate() {
            let mut compound = String::new();
            for j in 0..COMPOUND_N {
                let in_idx = slot * COMPOUND_N + j;
                let out_idx = perm.apply(in_idx).ok_or(
                    Error::KeywordCompoundCollision { slot },
                )?;
                let word = wordlist.get(out_idx).ok_or(
                    Error::KeywordCompoundCollision { slot },
                )?;
                compound.push_str(word);
            }
            if reverse.contains_key(&compound) {
                return Err(Error::KeywordCompoundCollision { slot });
            }
            forward.insert(kw, compound.clone());
            reverse.insert(compound, kw);
        }

        Ok(Self {
            epoch,
            forward,
            reverse,
        })
    }

    /// The epoch this table was built for.  Diagnostic only.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Return the per-epoch compound for `keyword`.
    ///
    /// Returns `None` if `keyword` is not in
    /// [`PYTHON_KEYWORDS`].  Callers in the scrambler use this
    /// to test "is this Word a keyword?" — `None` means "leave
    /// the Word verbatim."
    #[must_use]
    pub fn compound_for(&self, keyword: &str) -> Option<&str> {
        self.forward.get(keyword).map(String::as_str)
    }

    /// Inverse of [`compound_for`].  Returns the original keyword
    /// if `compound` is in this epoch's keyword table.
    ///
    /// Used by the unscrambler: every `Word` token in the scrambled
    /// stream is looked up here; on `Some`, the word is replaced
    /// with the original keyword.  `None` leaves the word
    /// untouched (it was a real identifier, not a keyword
    /// scramble).
    #[must_use]
    pub fn reverse_lookup(&self, compound: &str) -> Option<&'static str> {
        self.reverse.get(compound).copied()
    }

    /// All [`PYTHON_KEYWORD_COUNT`] compounds in
    /// [`PYTHON_KEYWORDS`] static order — `out[i]` is the per-epoch
    /// compound for `PYTHON_KEYWORDS[i]`.
    ///
    /// Used by the daemon's wire surface to emit
    /// `Response::KeywordCompounds` without exposing the underlying
    /// map representation, and by callers that need a stable index
    /// for serialisation.
    ///
    /// # Panics
    ///
    /// Panics if the internal `forward` map is missing an entry for
    /// any keyword in [`PYTHON_KEYWORDS`].  This is an invariant
    /// violation: both [`Self::build`] and [`Self::from_compounds`]
    /// populate one entry per static keyword before returning, so a
    /// missing entry indicates memory corruption rather than user
    /// input.
    #[must_use]
    pub fn all_compounds_in_static_order(
        &self,
    ) -> [String; PYTHON_KEYWORD_COUNT] {
        std::array::from_fn(|i| {
            self.forward
                .get(PYTHON_KEYWORDS[i])
                .expect(
                    "KeywordWordlist forward map missing a PYTHON_KEYWORDS \
                     entry; invariant violated",
                )
                .clone()
        })
    }

    /// Construct a `KeywordWordlist` from caller-supplied compounds.
    ///
    /// # When to use this
    ///
    /// The **trust-tier client** entry point, paired with the
    /// daemon's `Response::KeywordCompounds` wire reply.  The
    /// operator-facing CLI (`babbleon scramble` / `babbleon
    /// unscramble`) receives the per-epoch compounds over the local
    /// Unix socket and reconstructs the mapping locally without
    /// ever holding the per-host secret in its own address space.
    ///
    /// `compounds` MUST be in [`PYTHON_KEYWORDS`] static order —
    /// `compounds[i]` is the compound for `PYTHON_KEYWORDS[i]`.
    ///
    /// # Validation
    ///
    /// Compounds are validated for the same invariants the
    /// HKDF-derived path enforces by construction:
    ///
    /// - Each compound non-empty.
    /// - Each byte ASCII-lowercase (matches the v2 baseline
    ///   wordlist's vocabulary; defeats homoglyph injection on the
    ///   wire).
    /// - All compounds pairwise distinct (`reverse_lookup`
    ///   correctness depends on this).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidSuppliedKeywordCompounds`] on any
    ///   validation failure.  The variant carries the slot index
    ///   and a structural reason; it does NOT carry the compound
    ///   bytes (rule 13).
    pub fn from_compounds(
        epoch: u64,
        compounds: [String; PYTHON_KEYWORD_COUNT],
    ) -> Result<Self> {
        for (slot, compound) in compounds.iter().enumerate() {
            if compound.is_empty() {
                return Err(Error::InvalidSuppliedKeywordCompounds {
                    slot,
                    reason: "empty",
                });
            }
            if !compound.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err(Error::InvalidSuppliedKeywordCompounds {
                    slot,
                    reason: "non-ascii-lowercase",
                });
            }
        }
        // Pairwise distinct: O(n^2) over 35 items (~600 comparisons)
        // is microseconds; the simple form keeps the invariant
        // obvious to a reviewer.
        for i in 0..compounds.len() {
            for j in (i + 1)..compounds.len() {
                if compounds[i] == compounds[j] {
                    return Err(Error::InvalidSuppliedKeywordCompounds {
                        slot: j,
                        reason: "duplicate",
                    });
                }
            }
        }
        let mut forward: HashMap<&'static str, String> =
            HashMap::with_capacity(PYTHON_KEYWORD_COUNT);
        let mut reverse: HashMap<String, &'static str> =
            HashMap::with_capacity(PYTHON_KEYWORD_COUNT);
        // Consume `compounds`: one clone per entry (forward needs an
        // owned `String` value; reverse needs an owned `String` key).
        // The into_iter form keeps clippy::needless_pass_by_value
        // satisfied — the parameter is fully moved through.
        for (i, compound) in compounds.into_iter().enumerate() {
            forward.insert(PYTHON_KEYWORDS[i], compound.clone());
            reverse.insert(compound, PYTHON_KEYWORDS[i]);
        }
        Ok(Self {
            epoch,
            forward,
            reverse,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{KeywordWordlist, MIN_WORDLIST_SIZE};
    use crate::python_keywords::{PYTHON_KEYWORDS, PYTHON_KEYWORD_COUNT};
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn secret(byte: u8) -> PerHostSecret {
        PerHostSecret::from_bytes(&[byte; 32]).unwrap()
    }

    #[test]
    fn build_succeeds_for_baseline_wordlist() {
        let kwl = KeywordWordlist::build(
            &secret(7),
            Wordlist::english_baseline(),
            0,
        )
        .unwrap();
        assert_eq!(kwl.epoch(), 0);
        for kw in PYTHON_KEYWORDS {
            assert!(
                kwl.compound_for(kw).is_some(),
                "missing compound for {kw:?}"
            );
        }
    }

    #[test]
    fn every_compound_is_distinct() {
        let kwl = KeywordWordlist::build(
            &secret(1),
            Wordlist::english_baseline(),
            0,
        )
        .unwrap();
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for kw in PYTHON_KEYWORDS {
            let c = kwl.compound_for(kw).unwrap();
            assert!(seen.insert(c), "duplicate compound: {c}");
        }
    }

    #[test]
    fn reverse_lookup_is_inverse_of_forward() {
        let kwl = KeywordWordlist::build(
            &secret(13),
            Wordlist::english_baseline(),
            5,
        )
        .unwrap();
        for kw in PYTHON_KEYWORDS {
            let c = kwl.compound_for(kw).unwrap();
            assert_eq!(kwl.reverse_lookup(c), Some(*kw));
        }
    }

    #[test]
    fn unknown_keyword_returns_none() {
        let kwl = KeywordWordlist::build(
            &secret(7),
            Wordlist::english_baseline(),
            0,
        )
        .unwrap();
        assert!(kwl.compound_for("not_a_keyword").is_none());
        assert!(kwl.compound_for("foo").is_none());
        assert!(kwl.compound_for("").is_none());
    }

    #[test]
    fn reverse_lookup_of_unknown_compound_returns_none() {
        let kwl = KeywordWordlist::build(
            &secret(7),
            Wordlist::english_baseline(),
            0,
        )
        .unwrap();
        assert!(kwl.reverse_lookup("not-a-real-compound").is_none());
        assert!(kwl.reverse_lookup("").is_none());
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let wl = Wordlist::english_baseline();
        let a = KeywordWordlist::build(&secret(9), wl, 42).unwrap();
        let b = KeywordWordlist::build(&secret(9), wl, 42).unwrap();
        for kw in PYTHON_KEYWORDS {
            assert_eq!(a.compound_for(kw), b.compound_for(kw));
        }
    }

    #[test]
    fn rotation_changes_every_compound() {
        let wl = Wordlist::english_baseline();
        let a = KeywordWordlist::build(&secret(9), wl, 0).unwrap();
        let b = KeywordWordlist::build(&secret(9), wl, 1).unwrap();
        let mut differ = 0usize;
        for kw in PYTHON_KEYWORDS {
            if a.compound_for(kw) != b.compound_for(kw) {
                differ += 1;
            }
        }
        // We expect all 35 to change.  Allow generous slack to
        // avoid flakes if HKDF + Fisher-Yates happens to leave
        // one fixed point.
        assert!(
            differ >= PYTHON_KEYWORD_COUNT - 1,
            "rotation changed only {differ}/{PYTHON_KEYWORD_COUNT} compounds",
        );
    }

    #[test]
    fn different_secrets_produce_different_mappings() {
        let wl = Wordlist::english_baseline();
        let a = KeywordWordlist::build(&secret(1), wl, 0).unwrap();
        let b = KeywordWordlist::build(&secret(2), wl, 0).unwrap();
        for kw in PYTHON_KEYWORDS {
            assert_ne!(
                a.compound_for(kw),
                b.compound_for(kw),
                "two different secrets produced same compound for {kw}",
            );
        }
    }

    #[test]
    fn tiny_wordlist_rejected_with_clear_error() {
        let tiny =
            Wordlist::from_static_entries(vec!["a", "b", "c"]).unwrap();
        let err =
            KeywordWordlist::build(&secret(0), &tiny, 0).unwrap_err();
        match err {
            crate::errors::Error::WordlistTooSmall { have, needed } => {
                assert_eq!(have, 3);
                assert_eq!(needed, MIN_WORDLIST_SIZE);
            }
            other => panic!("expected WordlistTooSmall, got {other:?}"),
        }
    }

    // ----- all_compounds_in_static_order -----

    #[test]
    fn all_compounds_in_static_order_indexes_match_python_keywords() {
        let kwl = KeywordWordlist::build(
            &secret(11),
            Wordlist::english_baseline(),
            3,
        )
        .unwrap();
        let arr = kwl.all_compounds_in_static_order();
        assert_eq!(arr.len(), PYTHON_KEYWORD_COUNT);
        for (i, kw) in PYTHON_KEYWORDS.iter().enumerate() {
            // Slot agreement: array index ↔ static-list index ↔
            // forward-map keyword.
            assert_eq!(arr[i], kwl.compound_for(kw).unwrap());
        }
    }

    #[test]
    fn all_compounds_in_static_order_yields_pairwise_distinct_entries() {
        let kwl = KeywordWordlist::build(
            &secret(2),
            Wordlist::english_baseline(),
            0,
        )
        .unwrap();
        let arr = kwl.all_compounds_in_static_order();
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for c in &arr {
            assert!(seen.insert(c.as_str()), "duplicate compound: {c}");
        }
    }

    // ----- from_compounds (operator-CLI-side constructor) -----

    fn synth_distinct_keyword_compounds()
        -> [String; PYTHON_KEYWORD_COUNT]
    {
        // 35 deterministic, distinct, all-ASCII-lowercase strings.
        // Bytes are unrelated to any real wordlist entry.  We
        // encode the index in base-26 lowercase to keep the
        // ASCII-lowercase invariant the validator enforces.
        std::array::from_fn(|i| {
            // Two-letter suffix `aa..bj` gives 35 distinct codes
            // (35 = 1*26 + 9 ≤ 26*2).  `u8::try_from` cannot fail
            // because both quotient and remainder are below 26.
            let hi = u8::try_from(i / 26).expect("i/26 < 26") + b'a';
            let lo = u8::try_from(i % 26).expect("i%26 < 26") + b'a';
            format!("synthkeyword{}{}", hi as char, lo as char)
        })
    }

    #[test]
    fn from_compounds_round_trips_through_all_compounds() {
        let arr = synth_distinct_keyword_compounds();
        let kwl =
            KeywordWordlist::from_compounds(9, arr.clone()).unwrap();
        assert_eq!(kwl.epoch(), 9);
        assert_eq!(kwl.all_compounds_in_static_order(), arr);
        // Reverse lookup: each compound resolves to its keyword.
        for (i, kw) in PYTHON_KEYWORDS.iter().enumerate() {
            assert_eq!(kwl.reverse_lookup(&arr[i]), Some(*kw));
            assert_eq!(kwl.compound_for(kw), Some(arr[i].as_str()));
        }
    }

    #[test]
    fn from_compounds_matches_hkdf_path_for_same_compounds() {
        // Derive via HKDF, snapshot the compounds, reconstruct via
        // from_compounds, assert reverse_lookup agrees on every kw.
        let derived = KeywordWordlist::build(
            &secret(13),
            Wordlist::english_baseline(),
            5,
        )
        .unwrap();
        let snapshot = derived.all_compounds_in_static_order();
        let reconstructed =
            KeywordWordlist::from_compounds(5, snapshot).unwrap();
        for kw in PYTHON_KEYWORDS {
            assert_eq!(
                derived.compound_for(kw),
                reconstructed.compound_for(kw),
            );
            let c = derived.compound_for(kw).unwrap();
            assert_eq!(
                derived.reverse_lookup(c),
                reconstructed.reverse_lookup(c),
            );
        }
    }

    #[test]
    fn from_compounds_rejects_empty_compound() {
        let mut arr = synth_distinct_keyword_compounds();
        arr[7].clear();
        let err = KeywordWordlist::from_compounds(0, arr).unwrap_err();
        match err {
            crate::errors::Error::InvalidSuppliedKeywordCompounds {
                slot,
                reason,
            } => {
                assert_eq!(slot, 7);
                assert_eq!(reason, "empty");
            }
            other => panic!(
                "expected InvalidSuppliedKeywordCompounds, got {other:?}"
            ),
        }
    }

    #[test]
    fn from_compounds_rejects_non_ascii_lowercase() {
        let mut arr = synth_distinct_keyword_compounds();
        arr[2] = "SYNTH02KEYWORD".to_string();
        let err = KeywordWordlist::from_compounds(0, arr).unwrap_err();
        match err {
            crate::errors::Error::InvalidSuppliedKeywordCompounds {
                slot,
                reason,
            } => {
                assert_eq!(slot, 2);
                assert_eq!(reason, "non-ascii-lowercase");
            }
            other => panic!(
                "expected InvalidSuppliedKeywordCompounds, got {other:?}"
            ),
        }
    }

    #[test]
    fn from_compounds_rejects_non_ascii_byte() {
        let mut arr = synth_distinct_keyword_compounds();
        arr[4] = "synth\u{1F600}04keyword".to_string();
        let err = KeywordWordlist::from_compounds(0, arr).unwrap_err();
        match err {
            crate::errors::Error::InvalidSuppliedKeywordCompounds {
                slot,
                reason,
            } => {
                assert_eq!(slot, 4);
                assert_eq!(reason, "non-ascii-lowercase");
            }
            other => panic!(
                "expected InvalidSuppliedKeywordCompounds, got {other:?}"
            ),
        }
    }

    #[test]
    fn from_compounds_rejects_duplicate_pair() {
        let mut arr = synth_distinct_keyword_compounds();
        arr[20] = arr[3].clone();
        let err = KeywordWordlist::from_compounds(0, arr).unwrap_err();
        match err {
            crate::errors::Error::InvalidSuppliedKeywordCompounds {
                slot,
                reason,
            } => {
                // Higher of the colliding pair is reported.
                assert_eq!(slot, 20);
                assert_eq!(reason, "duplicate");
            }
            other => panic!(
                "expected InvalidSuppliedKeywordCompounds, got {other:?}"
            ),
        }
    }

    #[test]
    fn from_compounds_preserves_supplied_epoch() {
        for epoch in [0, 1, 42, u64::MAX] {
            let kwl = KeywordWordlist::from_compounds(
                epoch,
                synth_distinct_keyword_compounds(),
            )
            .unwrap();
            assert_eq!(kwl.epoch(), epoch);
        }
    }
}
