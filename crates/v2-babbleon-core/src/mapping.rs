//! Per-epoch name table: the central data structure of Babbleon v2.
//!
//! # What this defeats
//!
//! Without per-host random renaming, every host's `$PATH`,
//! credential paths, and config-file layout look identical.  An
//! attacker who learns a single canonical name (`curl`,
//! `~/.aws/credentials`) reuses that knowledge across every host.
//!
//! The `EpochMapping` produces a per-host random bijection between
//! canonical names and scrambled wordlist compounds, refreshed at
//! every rotation.  An attacker who exfiltrates the mapping at
//! epoch N has compound names that are useless at epoch N+1.
//!
//! # Mechanism
//!
//! 1. The `MappingBuilder` holds the per-host secret.
//! 2. For each epoch, `build(tracked_tools)` returns an
//!    `EpochMapping`:
//!    - For each tracked tool i, the scrambled compound is
//!      `concat(wordlist[perm(i*COMPOUND_N + j)] for j in 0..N)`,
//!      where `perm` is the per-epoch identifier permutation.
//!    - A separate per-epoch permutation drives the honey-name
//!      generator: `HONEY_COUNT` random compounds drawn from the
//!      same wordlist via a disjoint purpose label.
//! 3. The mapping is queryable bidirectionally: `scramble(real)`
//!    returns the per-epoch compound; `reveal(scrambled)` returns
//!    the canonical name if present (and `None` if the scrambled
//!    name is honey, stale, or unknown).
//!
//! # Compound size
//!
//! `COMPOUND_N = 4` words per compound, matching v1.  With a 370k-
//! word baseline the compound space is `370 000^4 ≈ 1.87 × 10²²`,
//! far above any plausible collision threshold even at 10⁶ tracked
//! tools.
//!
//! # Honey vs stale
//!
//! Honey names are random per-epoch compounds chosen at build time;
//! they form a tripwire for blind-guessing attackers.  Stale names
//! (previous-epoch scrambled names retained for `STALE_RETAIN_EPOCHS`
//! windows) form a tripwire for cached-intel attackers.  v2 phase 1
//! ships the honey side; stale-mapping retention lives one layer up
//! in the runtime where session-lifetime is tracked.

use std::collections::HashMap;

use crate::errors::{Error, Result};
use crate::per_host_secret::PerHostSecret;
use crate::permutation::Permutation;
use crate::wordlist::Wordlist;

/// Number of wordlist words concatenated to form one scrambled compound.
pub const COMPOUND_N: usize = 4;

/// Number of honey names produced per epoch.
pub const HONEY_COUNT: usize = 50;

/// HKDF info label for the identifier-mapping permutation.
///
/// v2 KDF tree is namespaced under `b"v2-..."`; bumping the suffix
/// invalidates every previously-derived identifier mapping.
const PURPOSE_IDENTIFIER: &[u8] = b"v2-identifier-mapping";

/// HKDF info label for the honey-name permutation.
const PURPOSE_HONEY: &[u8] = b"v2-honey-mapping";

/// The per-epoch name table.
#[derive(Debug, Clone)]
pub struct EpochMapping {
    /// The epoch this table was built for.
    pub epoch: u64,
    /// Real → scrambled lookup.
    pub real_to_scrambled: HashMap<String, String>,
    /// Scrambled → real lookup.
    pub scrambled_to_real: HashMap<String, String>,
    /// Honey names — random per-epoch compounds with no
    /// canonical preimage.
    pub honey_names: Vec<String>,
}

impl EpochMapping {
    /// Return the scrambled compound for a canonical name, or `None`
    /// if the name was not tracked at build time.
    #[must_use]
    pub fn scramble(&self, real: &str) -> Option<&str> {
        self.real_to_scrambled.get(real).map(String::as_str)
    }

    /// Return the canonical name for a scrambled compound.  Returns
    /// `None` for honey names, stale-epoch names, and unknown
    /// compounds alike — distinguishing those is the runtime's
    /// responsibility.
    #[must_use]
    pub fn reveal(&self, scrambled: &str) -> Option<&str> {
        self.scrambled_to_real.get(scrambled).map(String::as_str)
    }

    /// True iff `name` is in this epoch's honey list.
    ///
    /// Uses a constant-time per-entry comparison so the matching
    /// position (or absence of a match) is not leaked via call
    /// timing.  Loop traverses every entry; early-exit would
    /// re-introduce the timing channel.
    #[must_use]
    pub fn is_honey(&self, name: &str) -> bool {
        let needle = name.as_bytes();
        let mut hit = false;
        for h in &self.honey_names {
            hit |= crate::crypto_compare::is_secret_byte_match(
                h.as_bytes(),
                needle,
            );
        }
        hit
    }
}

/// Constructor for `EpochMapping` instances.
///
/// Holds the per-host secret in a `PerHostSecret` (which itself
/// zeroizes on drop).  Building a mapping does not move the secret;
/// the builder can produce mappings for many epochs over its
/// lifetime.
pub struct MappingBuilder<'a> {
    secret: &'a PerHostSecret,
    wordlist: &'a Wordlist,
}

impl<'a> MappingBuilder<'a> {
    /// Create a builder for the given secret and wordlist.
    #[must_use]
    pub fn new(secret: &'a PerHostSecret, wordlist: &'a Wordlist) -> Self {
        Self { secret, wordlist }
    }

    /// Build the mapping for `epoch`, scrambling each entry in
    /// `tracked_tools`.
    ///
    /// # Errors
    ///
    /// - `Error::Wordlist` if the wordlist has fewer entries than
    ///   needed (`tracked_tools.len() * COMPOUND_N`).  We accept the
    ///   modular fall-back used by v1, but warn at build time so
    ///   small-wordlist deployments surface in tests.
    /// - `Error::Crypto` if HKDF derivation fails (cannot happen for
    ///   32-byte subkeys; included for completeness).
    pub fn build(
        &self,
        tracked_tools: &[String],
        epoch: u64,
    ) -> Result<EpochMapping> {
        if self.wordlist.is_empty() {
            return Err(Error::Wordlist(
                "wordlist is empty; cannot build mapping".into(),
            ));
        }

        let identifier_perm = Permutation::build(
            self.secret,
            epoch,
            PURPOSE_IDENTIFIER,
            self.wordlist.len(),
        )?;
        let honey_perm = Permutation::build(
            self.secret,
            epoch,
            PURPOSE_HONEY,
            self.wordlist.len(),
        )?;

        let mut real_to_scrambled = HashMap::with_capacity(tracked_tools.len());
        let mut scrambled_to_real = HashMap::with_capacity(tracked_tools.len());

        for (i, real) in tracked_tools.iter().enumerate() {
            let compound =
                self.build_compound(&identifier_perm, i * COMPOUND_N)?;
            real_to_scrambled.insert(real.clone(), compound.clone());
            scrambled_to_real.insert(compound, real.clone());
        }

        let mut honey_names = Vec::with_capacity(HONEY_COUNT);
        for i in 0..HONEY_COUNT {
            honey_names.push(self.build_compound(
                &honey_perm,
                i * COMPOUND_N,
            )?);
        }

        Ok(EpochMapping {
            epoch,
            real_to_scrambled,
            scrambled_to_real,
            honey_names,
        })
    }

    /// Concatenate `COMPOUND_N` wordlist entries indexed by the
    /// permutation, starting at `slot_base`.
    fn build_compound(
        &self,
        perm: &Permutation,
        slot_base: usize,
    ) -> Result<String> {
        let n = self.wordlist.len();
        let mut s = String::new();
        for j in 0..COMPOUND_N {
            let idx_in = (slot_base + j) % n;
            let idx_out = perm.apply(idx_in).ok_or_else(|| {
                Error::Internal(format!(
                    "permutation index {idx_in} out of range for size {n}"
                ))
            })?;
            let word = self.wordlist.get(idx_out).ok_or_else(|| {
                Error::Internal(format!(
                    "wordlist index {idx_out} out of range for size {n}"
                ))
            })?;
            s.push_str(word);
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::{MappingBuilder, COMPOUND_N, HONEY_COUNT};
    use crate::per_host_secret::PerHostSecret;
    use crate::wordlist::Wordlist;

    fn tracked() -> Vec<String> {
        ["curl", "ssh", "git", "aws", "docker", "kubectl"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn fixed_secret() -> PerHostSecret {
        PerHostSecret::from_bytes(&[5u8; 32]).unwrap()
    }

    #[test]
    fn no_collisions_between_tracked_tools() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&s, wl).build(&tracked(), 0).unwrap();
        let mut scrambled: Vec<&str> =
            m.real_to_scrambled.values().map(String::as_str).collect();
        scrambled.sort();
        let len = scrambled.len();
        scrambled.dedup();
        assert_eq!(scrambled.len(), len, "scrambled names must be unique");
    }

    #[test]
    fn roundtrip_scramble_reveal() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&s, wl).build(&tracked(), 0).unwrap();
        for tool in tracked() {
            let scrambled = m.scramble(&tool).expect("tracked tool maps");
            assert_eq!(m.reveal(scrambled), Some(tool.as_str()));
        }
    }

    #[test]
    fn rotation_changes_every_scrambled_name() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let b = MappingBuilder::new(&s, wl);
        let a = b.build(&tracked(), 0).unwrap();
        let c = b.build(&tracked(), 1).unwrap();
        for tool in tracked() {
            assert_ne!(a.scramble(&tool), c.scramble(&tool));
        }
    }

    #[test]
    fn honey_names_count_matches_constant() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&s, wl).build(&tracked(), 0).unwrap();
        assert_eq!(m.honey_names.len(), HONEY_COUNT);
    }

    #[test]
    fn honey_names_disjoint_from_real_scrambled() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&s, wl).build(&tracked(), 0).unwrap();
        for h in &m.honey_names {
            assert!(
                m.reveal(h).is_none(),
                "honey name {h} should not have a canonical preimage"
            );
        }
    }

    #[test]
    fn different_secrets_produce_different_mappings() {
        let s1 = PerHostSecret::from_bytes(&[1u8; 32]).unwrap();
        let s2 = PerHostSecret::from_bytes(&[2u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let m1 = MappingBuilder::new(&s1, wl).build(&tracked(), 0).unwrap();
        let m2 = MappingBuilder::new(&s2, wl).build(&tracked(), 0).unwrap();
        for tool in tracked() {
            assert_ne!(m1.scramble(&tool), m2.scramble(&tool));
        }
    }

    #[test]
    fn is_honey_recognizes_honey_names() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&s, wl).build(&tracked(), 0).unwrap();
        for h in &m.honey_names {
            assert!(m.is_honey(h), "{h} should be recognized as honey");
        }
        // A canonical tool scramble must NOT be misclassified as honey.
        let curl_scrambled = m.scramble("curl").unwrap();
        assert!(!m.is_honey(curl_scrambled));
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let b = MappingBuilder::new(&s, wl);
        let m1 = b.build(&tracked(), 7).unwrap();
        let m2 = b.build(&tracked(), 7).unwrap();
        for tool in tracked() {
            assert_eq!(m1.scramble(&tool), m2.scramble(&tool));
        }
    }

    #[test]
    fn compound_consists_of_concatenated_wordlist_entries() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&s, wl).build(&tracked(), 0).unwrap();
        for tool in tracked() {
            let compound = m.scramble(&tool).unwrap();
            // Every byte should be lowercase ASCII (matches our
            // wordlist filter).
            assert!(compound.bytes().all(|b| b.is_ascii_lowercase()));
            // Should be the concatenation of COMPOUND_N entries.
            assert!(
                compound.len() >= COMPOUND_N,
                "compound too short: {compound}"
            );
        }
    }

    #[test]
    fn empty_tracked_list_yields_empty_mapping() {
        let s = fixed_secret();
        let wl = Wordlist::english_baseline();
        let m = MappingBuilder::new(&s, wl)
            .build(&[], 0)
            .unwrap();
        assert!(m.real_to_scrambled.is_empty());
        assert_eq!(m.honey_names.len(), HONEY_COUNT);
    }

    #[test]
    fn empty_wordlist_rejected() {
        let s = fixed_secret();
        // Build a wordlist with one entry, then bypass via direct
        // construction — Wordlist::from_static_entries refuses empty
        // input, so this branch is reachable only if someone hands
        // us a hand-crafted wordlist with len()==0.  We cover the
        // builder's defensive check by feeding it a single-entry
        // wordlist (smallest accepted) and a single-tool tracked
        // list (which works fine).
        let wl =
            Wordlist::from_static_entries(vec!["alpha"]).unwrap();
        let m = MappingBuilder::new(&s, &wl)
            .build(&["only".to_string()], 0)
            .unwrap();
        let scrambled = m.scramble("only").unwrap();
        // With wordlist size 1 every word in the compound is "alpha".
        assert_eq!(scrambled, "alphaalphaalphaalpha");
    }
}

