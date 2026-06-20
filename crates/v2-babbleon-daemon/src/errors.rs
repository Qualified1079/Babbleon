//! Daemon error type.
//!
//! # Infrastructure module
//!
//! Errors carry no secret material (security-baseline rule 13).
//! Underlying I/O errors are stringified via `Display`, which for
//! `nix::Errno` and `std::io::Error` is the kernel's
//! human-readable name (`"EPERM: operation not permitted"` etc).

use thiserror::Error;

/// The daemon error.
#[derive(Debug, Error)]
pub enum Error {
    /// Vault load / unseal failed.  Wraps the underlying message
    /// without disclosing key material.
    #[error("vault load failed: {0}")]
    Vault(String),

    /// Mapping construction failed.  Bridges
    /// `babbleon_core_v2::Error` from the core crate.
    #[error("mapping construction failed: {0}")]
    Mapping(String),

    /// Wrapper materialisation failed.  Filesystem or HKDF error.
    #[error("wrapper materialisation failed: {0}")]
    Wrapper(String),

    /// Activated-table emission failed.  Wraps the JSONL writer.
    #[error("activated-table emission failed: {0}")]
    ActivatedTable(String),

    /// IPC socket / pipe / fd-passing error.
    #[error("ipc failed: {0}")]
    Ipc(String),

    /// CLI argument validation failed.
    #[error("cli: {0}")]
    Cli(String),
}

impl From<babbleon_core_v2::Error> for Error {
    fn from(e: babbleon_core_v2::Error) -> Self {
        // Default category is Mapping (the most common core-error
        // surface for daemon callers); specific call sites should
        // construct a more accurate variant before this `From`
        // fires.
        Self::Mapping(e.to_string())
    }
}

impl From<babbleon_daemon_protocol_v2::Error> for Error {
    fn from(e: babbleon_daemon_protocol_v2::Error) -> Self {
        // The protocol crate's error is a strict subset of this enum;
        // bridge variant-for-variant so the message text is preserved.
        match e {
            babbleon_daemon_protocol_v2::Error::Ipc(m) => Self::Ipc(m),
            babbleon_daemon_protocol_v2::Error::ActivatedTable(m) => {
                Self::ActivatedTable(m)
            }
        }
    }
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
