//! Protocol crate error type.
//!
//! # Infrastructure module
//!
//! Errors carry no secret material (security-baseline rule 13).
//! Underlying I/O errors are stringified via `Display`, which for
//! `std::io::Error` is the kernel's human-readable name
//! (`"EPERM: operation not permitted"` etc).
//!
//! Two variants, mirroring the daemon's full enum on the surfaces the
//! protocol+client touch:
//!
//! - [`Error::Ipc`] — connection / read / write / wire-format failures.
//! - [`Error::ActivatedTable`] — UTF-8 validation when re-encoding a
//!   daemon-side activated-table response.  The daemon only emits
//!   valid UTF-8, so this variant indicates a daemon bug rather than
//!   a peer-supplied problem; it nonetheless lives here because it is
//!   raised from inside [`crate::protocol::Response::to_wire`].
//!
//! The daemon crate's `Error` is a superset and bridges via
//! `From<babbleon_daemon_protocol_v2::Error>`.

use thiserror::Error;

/// Protocol crate's error.
#[derive(Debug, Error)]
pub enum Error {
    /// Wire-level or IPC-layer failure: connect / read / write /
    /// parse / schema validation.
    #[error("ipc: {0}")]
    Ipc(String),

    /// Activated-table emission failed (typically: jsonl payload was
    /// not valid UTF-8 at re-encoding time).
    #[error("activated-table emission failed: {0}")]
    ActivatedTable(String),
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
