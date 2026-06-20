//! Per-epoch whitespace wordlist.
//!
//! # What this defeats
//!
//! The layer-3 scramble replaces every visible whitespace character
//! and every indent-block boundary with a wordlist compound.  An
//! attacker that learns "in this epoch, the SPACE token is the
//! compound `riverstoneanvilfreckle`" can locate every intra-line
//! boundary in the scrambled source and start tokenizing.  The
//! attacker must therefore brute-force the per-epoch whitespace
//! mapping to make progress — or steal the host secret.
//!
//! # Mechanism
//!
//! Mirrors `v2-babbleon-core::mapping::EpochMapping`'s identifier
//! derivation, with two changes:
//!
//! 1. The HKDF info label is `b"v2-whitespace-mapping"`.  Distinct
//!    purpose label from `b"v2-identifier-mapping"` and
//!    `b"v2-honey-mapping"`, so the whitespace permutation is
//!    statistically independent of the identifier and honey
//!    permutations under the same secret + epoch.
//! 2. The number of compounds is fixed: one per `WhitespaceKind`.
//!    With `COMPOUND_N = 4` words per compound and five kinds, the
//!    derivation consumes 20 wordlist positions per epoch.
//!
//! # Disjointness from identifier compounds
//!
//! The five whitespace compounds and the identifier compounds are
//! drawn from the *same* wordlist via *different* permutations.  In
//! the worst case (small wordlist, large tracked-tool set, bad
//! luck) a whitespace compound and an identifier compound could
//! collide.  The MVP does not yet enforce wordlist-pool partition
//! (reserved-pool layer-3 design filed in `docs/v2/structure-
//! scrambling.md` Open Question §1).  For now we rely on the v2
//! baseline wordlist (369 652 entries) making collisions
//! astronomically unlikely; tests assert per-epoch
//! distinct-from-each-other invariants.

use babbleon_core_v2::mapping::COMPOUND_N;
use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::permutation::Permutation;
use babbleon_core_v2::wordlist::Wordlist;

use crate::errors::{Error, Result};
use crate::tokens::WhitespaceKind;

/// HKDF info label that namespaces the whitespace permutation.
///
/// Bumping the trailing version suffix invalidates every previously
/// derived whitespace mapping — equivalent to forcing an immediate
/// rotation of every host's whitespace compounds.
const PURPOSE_WHITESPACE: &[u8] = b"v2-whitespace-mapping";

/// Number of distinct whitespace compounds per epoch.
///
/// Fixed at the size of `WhitespaceKind::ALL`.  Bumping requires a
/// wire-format change and a coordinated update to `tokens::WhitespaceKind`.
pub const WHITESPACE_COMPOUND_COUNT: usize = WhitespaceKind::ALL.len();

/// Minimum wordlist size required to derive a whitespace mapping.
///
/// `WHITESPACE_COMPOUND_COUNT × COMPOUND_N` = 20 with the current
/// constants.  Wordlists smaller than this cannot satisfy the
/// derivation; `WhitespaceWordlist::build` returns
/// `Error::WordlistTooSmall`.
pub const MIN_WORDLIST_SIZE: usize = WHITESPACE_COMPOUND_COUNT * COMPOUND_N;

/// Per-epoch whitespace compound table.
///
/// Held in plain `String`s, matching the v2-core `EpochMapping`
/// pattern.  Process-level hardening (mlockall, dumpable=0) at the
/// preprocessor binary protects the in-memory mapping; this struct
/// does NOT layer its own secret-bytes wrapper.
#[derive(Debug, Clone)]
pub struct WhitespaceWordlist {
    /// The epoch this table was built for.
    epoch: u64,
    /// One compound per `WhitespaceKind`, indexed by `kind.slot()`.
    compounds: [String; WHITESPACE_COMPOUND_COUNT],
}

impl WhitespaceWordlist {
    /// Derive the whitespace mapping for `(secret, epoch)` over
    /// `wordlist`.
    ///
    /// # Errors
    ///
    /// - `Error::WordlistTooSmall` if `wordlist.len() < MIN_WORDLIST_SIZE`.
    /// - `Error::Core` if the underlying `Permutation::build`
    ///   fails (only possible for `n == 0` or `n > u32::MAX`; both
    ///   ruled out by the size check above).
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
            PURPOSE_WHITESPACE,
            wordlist.len(),
        )?;

        // Build the five compounds.  Each compound consumes
        // `COMPOUND_N` consecutive slot positions, identical to
        // `MappingBuilder::build_compound`.  We inline the logic
        // here to avoid coupling to a v2-core private helper.
        let mut compounds: [String; WHITESPACE_COMPOUND_COUNT] =
            Default::default();
        for kind in WhitespaceKind::ALL {
            let slot_base = kind.slot() * COMPOUND_N;
            compounds[kind.slot()] = build_compound(&perm, wordlist, slot_base)?;
        }

        Ok(Self { epoch, compounds })
    }

    /// Epoch this mapping was derived for.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Compound bytes for a given whitespace kind.
    #[must_use]
    pub fn compound_for(&self, kind: WhitespaceKind) -> &str {
        &self.compounds[kind.slot()]
    }

    /// All five compounds in `WhitespaceKind::ALL` order.
    ///
    /// Useful for the unscrambler's prefix-match scan and for
    /// debug pretty-printing.
    #[must_use]
    pub fn all_compounds(&self) -> &[String; WHITESPACE_COMPOUND_COUNT] {
        &self.compounds
    }

    /// Return the `WhitespaceKind` if `s` starts with one of the
    /// five compounds, along with the compound's byte length.
    ///
    /// Greedy longest-prefix match: if two compounds share a
    /// prefix (possible across hash collisions), the longer match
    /// wins.  Returns `None` if no compound is a prefix of `s`.
    ///
    /// Used by the unscrambler to chunk the scrambled byte stream
    /// into whitespace-compound + word runs.
    #[must_use]
    pub fn match_prefix(&self, s: &str) -> Option<(WhitespaceKind, usize)> {
        let mut best: Option<(WhitespaceKind, usize)> = None;
        for kind in WhitespaceKind::ALL {
            let compound = self.compound_for(kind);
            if s.as_bytes().starts_with(compound.as_bytes()) {
                let len = compound.len();
                match best {
                    Some((_, best_len)) if best_len >= len => {}
                    _ => best = Some((kind, len)),
                }
            }
        }
        best
    }
}

/// Concatenate `COMPOUND_N` wordlist entries indexed by `perm`,
/// starting at `slot_base`.
///
/// Mirrors `v2-babbleon-core::mapping::MappingBuilder::build_compound`;
/// inlined here because that helper is private to the v2-core
/// crate.  Same semantics: modular wrap-around for slot indices
/// beyond `wordlist.len()`.
fn build_compound(
    perm: &Permutation,
    wordlist: &Wordlist,
    slot_base: usize,
) -> Result<String> {
    let n = wordlist.len();
    let mut s = String::new();
    for j in 0..COMPOUND_N {
        let idx_in = (slot_base + j) % n;
        let idx_out = perm.apply(idx_in).ok_or_else(|| {
            Error::Core(babbleon_core_v2::errors::Error::Internal(format!(
                "whitespace permutation index {idx_in} out of range for size {n}"
            )))
        })?;
        let word = wordlist.get(idx_out).ok_or_else(|| {
            Error::Core(babbleon_core_v2::errors::Error::Internal(format!(
                "whitespace wordlist index {idx_out} out of range for size {n}"
            )))
        })?;
        s.push_str(word);
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::{WhitespaceWordlist, MIN_WORDLIST_SIZE};
    use crate::errors::Error;
    use crate::tokens::WhitespaceKind;
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[7u8; 32]).unwrap()
    }

    #[test]
    fn build_succeeds_against_english_baseline() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let w = WhitespaceWordlist::build(&s, wl, 0).unwrap();
        assert_eq!(w.epoch(), 0);
        for kind in WhitespaceKind::ALL {
            let compound = w.compound_for(kind);
            assert!(!compound.is_empty(), "compound for {kind} is empty");
            assert!(
                compound.bytes().all(|b| b.is_ascii_lowercase()),
                "compound for {kind} contains non-lowercase byte: {compound:?}"
            );
        }
    }

    #[test]
    fn five_compounds_are_pairwise_distinct() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let w = WhitespaceWordlist::build(&s, wl, 0).unwrap();
        let mut seen: Vec<&str> =
            w.all_compounds().iter().map(String::as_str).collect();
        seen.sort_unstable();
        let len = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), len, "compounds must be pairwise distinct");
    }

    #[test]
    fn rotation_changes_every_compound() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let w0 = WhitespaceWordlist::build(&s, wl, 0).unwrap();
        let w1 = WhitespaceWordlist::build(&s, wl, 1).unwrap();
        for kind in WhitespaceKind::ALL {
            assert_ne!(
                w0.compound_for(kind),
                w1.compound_for(kind),
                "compound for {kind} unchanged across epoch rotation"
            );
        }
    }

    #[test]
    fn derivation_is_deterministic_on_secret_epoch_wordlist() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let a = WhitespaceWordlist::build(&s, wl, 42).unwrap();
        let b = WhitespaceWordlist::build(&s, wl, 42).unwrap();
        for kind in WhitespaceKind::ALL {
            assert_eq!(a.compound_for(kind), b.compound_for(kind));
        }
    }

    #[test]
    fn different_secrets_produce_different_compounds() {
        let a_secret = PerHostSecret::from_bytes(&[1u8; 32]).unwrap();
        let b_secret = PerHostSecret::from_bytes(&[2u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let a = WhitespaceWordlist::build(&a_secret, wl, 0).unwrap();
        let b = WhitespaceWordlist::build(&b_secret, wl, 0).unwrap();
        for kind in WhitespaceKind::ALL {
            assert_ne!(
                a.compound_for(kind),
                b.compound_for(kind),
                "compound for {kind} matched across distinct secrets"
            );
        }
    }

    #[test]
    fn match_prefix_returns_kind_at_compound_boundary() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let w = WhitespaceWordlist::build(&s, wl, 0).unwrap();
        for kind in WhitespaceKind::ALL {
            let compound = w.compound_for(kind);
            let with_trailer = format!("{compound}rest");
            let (matched, len) = w
                .match_prefix(&with_trailer)
                .expect("prefix should match");
            assert_eq!(matched, kind);
            assert_eq!(len, compound.len());
        }
    }

    #[test]
    fn match_prefix_returns_none_for_arbitrary_word() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let w = WhitespaceWordlist::build(&s, wl, 0).unwrap();
        // "xyzzy" is unlikely to be a prefix of any 4-word
        // compound built from `dwyl/english-words`.  If this test
        // ever fails on a future wordlist, the fix is to pick a
        // longer arbitrary string, not to relax the assertion.
        assert!(w.match_prefix("xyzzy").is_none());
    }

    #[test]
    fn wordlist_too_small_is_reported() {
        let s = fixed_secret();
        let words: Vec<&'static str> = vec!["a", "b", "c"];
        let wl = Wordlist::from_static_entries(words).unwrap();
        let err = WhitespaceWordlist::build(&s, &wl, 0).unwrap_err();
        match err {
            Error::WordlistTooSmall { needed, have } => {
                assert_eq!(needed, MIN_WORDLIST_SIZE);
                assert_eq!(have, 3);
            }
            other => panic!("expected WordlistTooSmall, got {other:?}"),
        }
    }
}
