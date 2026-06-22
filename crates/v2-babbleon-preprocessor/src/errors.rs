//! Flat error enum for the preprocessor.
//!
//! # Infrastructure module
//!
//! No specific attack is defeated here.  Error paths exist to
//! surface bugs and degraded inputs cleanly; per security-baseline
//! rule 13 (errors must not leak secrets), none of the variants
//! carry secret-derived bytes — they carry positions, sizes, and
//! structural counts only.

use thiserror::Error;

/// Result alias for the preprocessor crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Flat preprocessor error.
///
/// Variants are kept narrow and structural; none carries
/// secret-derived material.  In particular, no variant ever
/// records the bytes of a scrambled compound, a wordlist entry,
/// or any per-host-secret-derived quantity — only their positions
/// and lengths.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The wordlist available at preprocessor construction was too
    /// small to derive five distinct whitespace compounds.
    ///
    /// The whitespace mapping needs five compounds of
    /// `COMPOUND_N` words each (currently 5 × 4 = 20 wordlist
    /// positions); a wordlist with fewer entries cannot satisfy
    /// the requirement.
    ///
    /// Layer-2 (keyword scramble) uses the same variant: 35 × 4
    /// = 140 wordlist positions required.
    #[error("wordlist too small ({have} entries, needed {needed})")]
    WordlistTooSmall {
        /// Minimum number of wordlist entries required.
        needed: usize,
        /// Number of entries the supplied wordlist holds.
        have: usize,
    },

    /// Two keywords were assigned the same per-epoch compound by
    /// `KeywordWordlist::build`.  Astronomically unlikely with
    /// the v2 baseline wordlist (369 652 entries × 35 keyword
    /// slots × 4 words/compound), but checked defensively.  The
    /// operator's workaround is to rotate the epoch.
    #[error("keyword compound collision at slot {slot}; rotate epoch and retry")]
    KeywordCompoundCollision {
        /// Index in [`crate::python_keywords::PYTHON_KEYWORDS`]
        /// where the second of the colliding pair lives.
        slot: usize,
    },

    /// Two operators were assigned the same per-epoch compound
    /// by `OperatorWordlist::build`.  Same defensive shape as
    /// `KeywordCompoundCollision`.
    #[error("operator compound collision at slot {slot}; rotate epoch and retry")]
    OperatorCompoundCollision {
        /// Index in [`crate::python_operators::PYTHON_OPERATORS`]
        /// where the second of the colliding pair lives.
        slot: usize,
    },

    /// A v2-core primitive failed.  The wrapped error preserves
    /// the original cause; this variant exists only to bridge the
    /// two crates' error types without dropping information.
    #[error("v2-babbleon-core error: {0}")]
    Core(#[from] babbleon_core_v2::errors::Error),

    /// The scrambler produced a whitespace compound that occurs as
    /// a substring of a non-whitespace `Word` in the same source.
    ///
    /// Per `unscrambler::COLLISION_NOTE`, this is the rare case the
    /// MVP does NOT yet repair via reserved-pool allocation.  When
    /// it triggers, the operator should rotate the epoch
    /// (different per-epoch compounds) or wait for the
    /// reserved-pool fix.
    #[error(
        "whitespace compound (kind {kind:?}) collides with a non-whitespace \
         token at scrambled-byte offset {at}"
    )]
    WhitespaceCompoundCollision {
        /// Which whitespace kind's compound collided.
        kind: crate::tokens::WhitespaceKind,
        /// Byte offset within the scrambled output where the
        /// collision was detected.
        at: usize,
    },

    /// Layer-7 HKDF derivation or wordlist indexing failed.
    ///
    /// Practically impossible with the v2 baseline wordlist; present
    /// as a defensive check.  Per rule 13, the `message` field
    /// carries structural context (e.g. "wordlist index out of range")
    /// but never the compound bytes or the per-host secret.
    #[error("secret-literal derivation failed: {message}")]
    SecretLiteralDerivation {
        /// Structural reason without secret-adjacent bytes.
        message: String,
    },

    /// The unscrambler ran out of input mid-compound.
    ///
    /// Indicates the supplied scrambled bytes were truncated, or
    /// were never produced by this crate's scrambler under the
    /// active whitespace wordlist.  No secret material is
    /// disclosed by this error.
    #[error("scrambled input truncated at byte {at} (expected continuation of whitespace compound)")]
    TruncatedScrambledInput {
        /// Byte offset in the scrambled input where parsing
        /// failed.
        at: usize,
    },

    /// A `WhitespaceWordlist::from_compounds` caller supplied
    /// compounds that violate the table's invariants — empty
    /// compound, non-ASCII-lowercase byte, duplicate compound.
    ///
    /// The variant carries the offending slot index and a short
    /// structural reason; it deliberately does NOT carry the
    /// compound bytes themselves (rule 13 — even
    /// daemon-derived compounds are secret-adjacent and must not
    /// flow into operator logs through an error path).
    #[error(
        "supplied whitespace compounds invalid at slot {slot}: {reason}"
    )]
    InvalidSuppliedCompounds {
        /// Index in `WhitespaceKind::ALL` where the violation was
        /// detected.  For duplicate-pair violations, the higher of
        /// the two slot indices.
        slot: usize,
        /// Structural reason without compound bytes.  One of:
        /// `"empty"`, `"non-ascii-lowercase"`, `"duplicate"`.
        reason: &'static str,
    },

    /// A `KeywordWordlist::from_compounds` caller supplied
    /// compounds that violate the table's invariants — empty
    /// compound, non-ASCII-lowercase byte, duplicate compound.
    ///
    /// Mirrors `InvalidSuppliedCompounds` for the
    /// `PYTHON_KEYWORDS`-indexed keyword pool.  Distinct variant so
    /// operator logs can disambiguate which wire response carried
    /// the malformed payload and so a future per-pool validator can
    /// diverge without touching the whitespace path.
    ///
    /// Per security-baseline rule 13, carries the offending slot
    /// index and a structural reason only; never the compound
    /// bytes themselves.
    #[error(
        "supplied keyword compounds invalid at slot {slot}: {reason}"
    )]
    InvalidSuppliedKeywordCompounds {
        /// Index in
        /// [`crate::python_keywords::PYTHON_KEYWORDS`] where the
        /// violation was detected.  For duplicate-pair violations,
        /// the higher of the two slot indices.
        slot: usize,
        /// Structural reason without compound bytes.  One of:
        /// `"empty"`, `"non-ascii-lowercase"`, `"duplicate"`.
        reason: &'static str,
    },
}
