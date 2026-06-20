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
    #[error("wordlist too small for whitespace mapping (needed {needed}, have {have})")]
    WordlistTooSmall {
        /// Minimum number of wordlist entries required.
        needed: usize,
        /// Number of entries the supplied wordlist holds.
        have: usize,
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
}
