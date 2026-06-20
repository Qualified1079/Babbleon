//! Vault error type.
//!
//! # Infrastructure module
//!
//! Defines the shared error type for the vault layer.  No specific
//! attack is defeated here directly; the modules that USE this type
//! (`vault`, `soft_backend`, `payload`) are where the security
//! invariants live.
//!
//! Variants are flat and human-readable.  Per security-baseline
//! rule 13, NO variant carries secret bytes, secret-derived bytes,
//! or paths under a secret-controlled directory.

use thiserror::Error;

/// Vault-layer error.
#[derive(Debug, Error)]
pub enum Error {
    /// Argon2id KDF or `age` cipher failed during seal.
    #[error("vault seal failed: {0}")]
    Seal(String),

    /// `age` decrypt failed or the unsealed payload did not parse.
    #[error("vault unseal failed: {0}")]
    Unseal(String),

    /// The supplied passphrase did not unlock the vault.  This is the
    /// only variant where the wrong-passphrase path lands; an attacker
    /// holding the ciphertext sees the same `WrongPassphrase` discriminant
    /// regardless of how the KDF disagreed with age's MAC.
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// Vault payload structure mismatch — wrong schema version or
    /// missing required field.  Carries the schema version that was
    /// observed, never the field contents.
    #[error("vault payload schema mismatch: {0}")]
    Schema(String),

    /// Vault file I/O failed.  Carries the operation (`read` / `write`)
    /// and the OS error kind name; does NOT carry the file path
    /// (paths under user-config dirs may leak operator identity).
    #[error("vault file I/O failed during {op}: {kind}")]
    Io {
        /// The operation that failed.
        op: &'static str,
        /// `std::io::ErrorKind` `Debug`-formatted name.
        kind: String,
    },

    /// Caller passed input that was structurally invalid before any
    /// crypto ran (e.g. wrong-length host-secret bytes).  Distinct
    /// from `Schema` so callers can branch on "garbage-in" vs
    /// "wrong-version-in".
    #[error("vault input invalid: {0}")]
    Input(String),
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
