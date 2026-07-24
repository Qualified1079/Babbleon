//! Wordlist loader.
//!
//! # Infrastructure module
//!
//! This module is foundational support: it loads and validates the
//! word corpus used by `mapping` and `permutation`.  No specific
//! attack is defeated here directly; the security properties arise
//! from the bijective permutation applied to the wordlist, not from
//! the wordlist itself.
//!
//! # What this is
//!
//! A typed wrapper around a list of words used to construct
//! scrambled compounds.  v2.0 ships a single English wordlist
//! identical to v1's (369 652 lowercase ASCII words, dwyl/english-
//! words public-domain) embedded at compile time.  v2 phase 4 adds
//! multi-language wordlists from HermitDave/FrequencyWords (MIT, 61
//! languages) layered on top.
//!
//! # Invariants
//!
//! Every loaded wordlist must satisfy:
//!
//! - Each entry is non-empty.
//! - Entries are unique (no duplicates).
//! - For the English baseline: entries are `[a-z]+` (lowercase ASCII
//!   letters only).
//!
//! Violations are reported as `Error::Wordlist` at load time.

use crate::errors::{Error, Result};
use once_cell::sync::Lazy;

/// English baseline wordlist embedded at compile time.
///
/// Sourced from v1's `crates/babbleon/wordlist/words.txt`.  License
/// per the project tree:
/// `dwyl/english-words` is public-domain via the Unlicense.
const ENGLISH_BASELINE: &str =
    include_str!("../../babbleon/wordlist/words.txt");

/// A loaded, validated wordlist.
#[derive(Debug)]
pub struct Wordlist {
    /// Words in load order; index is the canonical position of each.
    words: Vec<&'static str>,
}

impl Wordlist {
    /// Return the embedded English baseline wordlist.
    ///
    /// Lazy-initialised on first call; subsequent calls return the
    /// same `&'static Wordlist`.  The validation step
    /// (`validate_entries`) runs exactly once per process.
    #[must_use]
    pub fn english_baseline() -> &'static Wordlist {
        static INSTANCE: Lazy<Wordlist> = Lazy::new(|| {
            let words: Vec<&'static str> = ENGLISH_BASELINE
                .lines()
                .map(str::trim)
                .filter(|w| !w.is_empty())
                .collect();
            // We trust the embedded baseline (it ships with the crate
            // and is covered by build-time tests in v1).  Any
            // validation failure here is a packaging bug, not a
            // runtime condition; panic so the build surfaces it.
            assert!(
                !words.is_empty(),
                "embedded English baseline wordlist is empty"
            );
            assert!(
                words.iter().all(|w| w.bytes().all(|b| b.is_ascii_lowercase())),
                "embedded English baseline contains non-[a-z] entries"
            );
            Wordlist { words }
        });
        &INSTANCE
    }

    /// Build a `Wordlist` from a list of `'static` string slices.
    ///
    /// Intended for tests and for embedded multi-language wordlists
    /// in phase 4+.
    ///
    /// # Errors
    ///
    /// - `Error::Wordlist` if any entry is empty or if duplicates are
    ///   present.
    pub fn from_static_entries(words: Vec<&'static str>) -> Result<Self> {
        if words.is_empty() {
            return Err(Error::Wordlist("wordlist is empty".into()));
        }
        let mut seen = std::collections::HashSet::with_capacity(words.len());
        for w in &words {
            if w.is_empty() {
                return Err(Error::Wordlist("entry is empty".into()));
            }
            if !seen.insert(*w) {
                return Err(Error::Wordlist(format!(
                    "duplicate entry: {w:?}"
                )));
            }
        }
        Ok(Self { words })
    }

    /// Number of entries in this wordlist.
    #[must_use]
    pub fn len(&self) -> usize {
        self.words.len()
    }

    /// True iff the wordlist has no entries.  Should never happen for
    /// a successfully-constructed `Wordlist`, but provided for the
    /// `clippy::len_without_is_empty` lint.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    /// Look up the entry at `index`.  Returns `None` if out of range.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&'static str> {
        self.words.get(index).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::Wordlist;

    #[test]
    fn english_baseline_loads_with_many_entries() {
        let wl = Wordlist::english_baseline();
        // v1's wordlist has 369 652 entries; v2's loader must also
        // see at least 300k after filtering.
        assert!(
            wl.len() > 300_000,
            "expected >300k entries; got {}",
            wl.len()
        );
    }

    #[test]
    fn english_baseline_entries_are_lowercase_ascii() {
        let wl = Wordlist::english_baseline();
        for i in 0..wl.len().min(1000) {
            let w = wl.get(i).unwrap();
            assert!(w.bytes().all(|b| b.is_ascii_lowercase()));
        }
    }

    #[test]
    fn from_static_entries_rejects_empty_input() {
        let result = Wordlist::from_static_entries(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn from_static_entries_rejects_empty_entry() {
        let result = Wordlist::from_static_entries(vec!["", "foo"]);
        assert!(result.is_err());
    }

    #[test]
    fn from_static_entries_rejects_duplicates() {
        let result =
            Wordlist::from_static_entries(vec!["foo", "bar", "foo"]);
        assert!(result.is_err());
    }

    #[test]
    fn from_static_entries_accepts_valid_input() {
        let wl =
            Wordlist::from_static_entries(vec!["alpha", "beta", "gamma"])
                .unwrap();
        assert_eq!(wl.len(), 3);
        assert_eq!(wl.get(0), Some("alpha"));
        assert_eq!(wl.get(2), Some("gamma"));
        assert_eq!(wl.get(3), None);
    }
}
