//! Launch-artefacts error type.
//!
//! # Infrastructure module
//!
//! Errors carry no secret material — the types in this crate
//! never see any.

use thiserror::Error;

/// The launch-artefacts error.
#[derive(Debug, Error)]
pub enum Error {
    /// Activated-table parse or validation error.  Wraps the
    /// underlying message; no secret material is reachable from
    /// here.
    #[error("activated-table: {0}")]
    ActivatedTable(String),
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
