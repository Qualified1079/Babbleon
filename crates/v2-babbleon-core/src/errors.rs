//! Error type for the v2 core library.
//!
//! # Infrastructure module
//!
//! This module is foundational support: it defines the shared error
//! type used by every other v2 module.  No specific attack is defeated
//! here directly; the modules that USE this type (`permutation`,
//! `mapping`, `wrapper`, etc.) are where the security invariants live.
//!
//! Errors are flat and human-readable.  Internal failures wrap the
//! upstream error message; we do NOT preserve `std::io::Error`
//! kinds across the boundary because doing so leaks structural
//! information about the call site (filename, errno) into anything
//! that displays the error.

use thiserror::Error;

/// The v2 core library error.
#[derive(Debug, Error)]
pub enum Error {
    /// A cryptographic operation failed.  Reasons include unsupported
    /// algorithm parameters or invalid HKDF inputs.
    #[error("crypto operation failed: {0}")]
    Crypto(String),

    /// The wordlist was empty, malformed, or missing required entries.
    #[error("wordlist invalid: {0}")]
    Wordlist(String),

    /// A request asked for a value outside the valid range
    /// (e.g. permutation index >= N).
    #[error("index {index} out of range for size {size}")]
    OutOfRange {
        /// The requested index.
        index: usize,
        /// The valid range size.
        size: usize,
    },

    /// Generic wrapper for internal invariant violations.  Should not
    /// be reachable in production; if it is, it's a bug in this crate.
    #[error("internal invariant violated: {0}")]
    Internal(String),
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
