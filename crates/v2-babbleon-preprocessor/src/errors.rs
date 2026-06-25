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

    /// A generic scramble-level failure.  Used by
    /// `IdentifierMapping::from_tokens_and_aliases` when two tokens
    /// would map to the same compound across all aliases (i.e. a
    /// cross-alias collision).  The operator's workaround is to
    /// rotate the epoch.
    #[error("scramble error: {0}")]
    Scramble(String),

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

    /// A scrambled-file header could not be parsed.
    ///
    /// Returned when `scramble_lifecycle` encounters a file that
    /// does not begin with the `babbleon-v2` magic line or whose
    /// `epoch:` / `tokens:` / `---` fields are malformed.  The
    /// message carries structural context (line numbers, field
    /// names) but never scrambled-compound bytes.
    #[error("scrambled-file header parse error: {0}")]
    HeaderParse(String),
}

// Layer-2 (dynamic identifier scramble) uses the same wordlist minimum as
// layer 3 — the actual minimum is `max(tracked_tools.len(), 5) * COMPOUND_N`
// entries; with any non-trivial file the v2 baseline wordlist (369 652
// entries) satisfies this trivially.
