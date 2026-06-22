//! Per-epoch Python-operator wordlist for layer-2b (operator scramble).
//!
//! # What this defeats
//!
//! See [`crate::python_operators`] for the threat-model framing.
//! This module holds the per-epoch derivation that maps each
//! operator string to a wordlist compound drawn from the per-host
//! secret + epoch via HKDF.  Statistically independent from the
//! keyword / identifier / honey / whitespace permutations under
//! the same `(secret, epoch)`.
//!
//! # Mechanism
//!
//! Mirrors [`crate::keyword_wordlist::KeywordWordlist`]:
//!
//! 1. HKDF info label `b"v2-operator-mapping"` — distinct from
//!    `b"v2-keyword-mapping"`, `b"v2-whitespace-mapping"`,
//!    `b"v2-identifier-mapping"`, and `b"v2-honey-mapping"`.
//! 2. One compound per operator, [`COMPOUND_N`]-words each.
//!    With 37 operators × 4 words = 148 wordlist positions per
//!    epoch.
//! 3. Forward and reverse lookups.

use std::collections::HashMap;

use babbleon_core_v2::mapping::COMPOUND_N;
use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::permutation::Permutation;
use babbleon_core_v2::wordlist::Wordlist;

use crate::errors::{Error, Result};
use crate::python_operators::{PYTHON_OPERATORS, PYTHON_OPERATOR_COUNT};

/// HKDF info label for the operator permutation.  Bumping the
/// trailing version suffix invalidates every previously derived
/// operator mapping.
const PURPOSE_OPERATOR: &[u8] = b"v2-operator-mapping";

/// Minimum wordlist size required to derive an operator mapping.
///
/// `PYTHON_OPERATOR_COUNT × COMPOUND_N` = 148 with the current
/// constants.
pub const MIN_WORDLIST_SIZE: usize = PYTHON_OPERATOR_COUNT * COMPOUND_N;

/// Per-epoch operator compound table.
///
/// Intentionally NOT `Default` — every instance must be tied to
/// a `(secret, epoch)` pair.
#[derive(Debug, Clone)]
pub struct OperatorWordlist {
    /// The epoch this table was built for.  Diagnostic.
    epoch: u64,
    /// Forward map: operator string (e.g. `":="`) → per-epoch
    /// compound.  Keys are `&'static str` from [`PYTHON_OPERATORS`].
    forward: HashMap<&'static str, String>,
    /// Reverse map: compound → operator string.
    reverse: HashMap<String, &'static str>,
}

impl OperatorWordlist {
    /// Derive the per-epoch operator mapping.
    ///
    /// # Errors
    ///
    /// - [`Error::WordlistTooSmall`] if `wordlist.len() < MIN_WORDLIST_SIZE`.
    /// - [`Error::Core`] if the underlying permutation construction
    ///   fails.
    /// - [`Error::OperatorCompoundCollision`] if two operators map
    ///   to the same compound.  Astronomically unlikely with the
    ///   v2 baseline wordlist; checked defensively.
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
            PURPOSE_OPERATOR,
            wordlist.len(),
        )?;

        let mut forward: HashMap<&'static str, String> =
            HashMap::with_capacity(PYTHON_OPERATOR_COUNT);
        let mut reverse: HashMap<String, &'static str> =
            HashMap::with_capacity(PYTHON_OPERATOR_COUNT);

        for (slot, op) in PYTHON_OPERATORS.iter().enumerate() {
            let mut compound = String::new();
            for j in 0..COMPOUND_N {
                let in_idx = slot * COMPOUND_N + j;
                let out_idx = perm.apply(in_idx).ok_or(
                    Error::OperatorCompoundCollision { slot },
                )?;
                let word = wordlist.get(out_idx).ok_or(
                    Error::OperatorCompoundCollision { slot },
                )?;
                compound.push_str(word);
            }
            if reverse.contains_key(&compound) {
                return Err(Error::OperatorCompoundCollision { slot });
            }
            forward.insert(op, compound.clone());
            reverse.insert(compound, op);
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

    /// Return the per-epoch compound for `operator`, or `None` if
    /// `operator` is not in [`PYTHON_OPERATORS`].
    #[must_use]
    pub fn compound_for(&self, operator: &str) -> Option<&str> {
        self.forward.get(operator).map(String::as_str)
    }

    /// Inverse of [`compound_for`].  Returns the original operator
    /// if `compound` is in this epoch's operator table.
    #[must_use]
    pub fn reverse_lookup(&self, compound: &str) -> Option<&'static str> {
        self.reverse.get(compound).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::{OperatorWordlist, MIN_WORDLIST_SIZE};
    use crate::python_operators::{PYTHON_OPERATORS, PYTHON_OPERATOR_COUNT};
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn secret(byte: u8) -> PerHostSecret {
        PerHostSecret::from_bytes(&[byte; 32]).unwrap()
    }

    #[test]
    fn build_succeeds_for_baseline_wordlist() {
        let owl = OperatorWordlist::build(
            &secret(7),
            Wordlist::english_baseline(),
            0,
        )
        .unwrap();
        assert_eq!(owl.epoch(), 0);
        for op in PYTHON_OPERATORS {
            assert!(
                owl.compound_for(op).is_some(),
                "missing compound for {op:?}"
            );
        }
    }

    #[test]
    fn every_compound_is_distinct() {
        let owl = OperatorWordlist::build(
            &secret(1),
            Wordlist::english_baseline(),
            0,
        )
        .unwrap();
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::new();
        for op in PYTHON_OPERATORS {
            let c = owl.compound_for(op).unwrap();
            assert!(seen.insert(c), "duplicate compound: {c}");
        }
    }

    #[test]
    fn reverse_lookup_is_inverse_of_forward() {
        let owl = OperatorWordlist::build(
            &secret(13),
            Wordlist::english_baseline(),
            5,
        )
        .unwrap();
        for op in PYTHON_OPERATORS {
            let c = owl.compound_for(op).unwrap();
            assert_eq!(owl.reverse_lookup(c), Some(*op));
        }
    }

    #[test]
    fn unknown_operator_returns_none() {
        let owl = OperatorWordlist::build(
            &secret(7),
            Wordlist::english_baseline(),
            0,
        )
        .unwrap();
        assert!(owl.compound_for("not_an_op").is_none());
        assert!(owl.compound_for("").is_none());
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let wl = Wordlist::english_baseline();
        let a = OperatorWordlist::build(&secret(9), wl, 42).unwrap();
        let b = OperatorWordlist::build(&secret(9), wl, 42).unwrap();
        for op in PYTHON_OPERATORS {
            assert_eq!(a.compound_for(op), b.compound_for(op));
        }
    }

    #[test]
    fn rotation_changes_every_compound() {
        let wl = Wordlist::english_baseline();
        let a = OperatorWordlist::build(&secret(9), wl, 0).unwrap();
        let b = OperatorWordlist::build(&secret(9), wl, 1).unwrap();
        let mut differ = 0usize;
        for op in PYTHON_OPERATORS {
            if a.compound_for(op) != b.compound_for(op) {
                differ += 1;
            }
        }
        assert!(
            differ >= PYTHON_OPERATOR_COUNT - 1,
            "rotation changed only {differ}/{PYTHON_OPERATOR_COUNT} compounds",
        );
    }

    #[test]
    fn different_secrets_produce_different_mappings() {
        let wl = Wordlist::english_baseline();
        let a = OperatorWordlist::build(&secret(1), wl, 0).unwrap();
        let b = OperatorWordlist::build(&secret(2), wl, 0).unwrap();
        for op in PYTHON_OPERATORS {
            assert_ne!(
                a.compound_for(op),
                b.compound_for(op),
                "two different secrets produced same compound for {op}",
            );
        }
    }

    #[test]
    fn tiny_wordlist_rejected_with_clear_error() {
        let tiny =
            Wordlist::from_static_entries(vec!["a", "b", "c"]).unwrap();
        let err =
            OperatorWordlist::build(&secret(0), &tiny, 0).unwrap_err();
        match err {
            crate::errors::Error::WordlistTooSmall { have, needed } => {
                assert_eq!(have, 3);
                assert_eq!(needed, MIN_WORDLIST_SIZE);
            }
            other => panic!("expected WordlistTooSmall, got {other:?}"),
        }
    }

    #[test]
    fn statistically_independent_from_keyword_mapping() {
        // Sanity: the same secret + epoch under the keyword
        // purpose label and the operator purpose label must NOT
        // map their respective slots to the same compounds.  This
        // is what distinct HKDF purpose labels buy.
        use crate::keyword_wordlist::KeywordWordlist;
        let s = secret(99);
        let wl = Wordlist::english_baseline();
        let kwl = KeywordWordlist::build(&s, wl, 0).unwrap();
        let owl = OperatorWordlist::build(&s, wl, 0).unwrap();
        // Both tables hold strings; collect them and assert no
        // operator compound equals any keyword compound.
        let mut kw_compounds: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for kw in crate::python_keywords::PYTHON_KEYWORDS {
            kw_compounds.insert(kwl.compound_for(kw).unwrap().to_string());
        }
        for op in PYTHON_OPERATORS {
            let c = owl.compound_for(op).unwrap();
            assert!(
                !kw_compounds.contains(c),
                "operator compound {c} collides with a keyword compound",
            );
        }
    }
}
