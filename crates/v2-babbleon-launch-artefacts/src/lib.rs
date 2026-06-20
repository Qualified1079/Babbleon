//! Babbleon v2 launch artefacts — the secret-free per-host data
//! the daemon hands the launcher (and PAM module) at runtime.
//!
//! # What this defeats
//!
//! The launcher (`v2-babbleon-launch-untrusted`) holds
//! `CAP_SYS_ADMIN` long enough to bind-mount the per-epoch
//! scrambled view, but it MUST NOT hold the per-host secret —
//! and, by extension, must not even transitively pull in the
//! HKDF / Ed25519 / Argon2 / SHA-2 stack that derives keys from
//! the secret.  A parser-crash exploit against the launcher must
//! land in a process whose linked-code audit surface is bounded.
//!
//! This crate carries the data shapes the launcher needs
//! (`ActivatedTable`, credential-path policy, env-var deny list)
//! with no crypto dependencies.  When the launcher depends on
//! this crate instead of `v2-babbleon-core`, the launcher's
//! production `cargo tree` drops the crypto graph entirely.
//!
//! # Compartmentalization rationale
//!
//! The v2 dependency story is now three peers:
//!
//! - **`v2-babbleon-daemon-protocol`**: the wire schema for the
//!   Unix-socket request / response the daemon serves.  Owned by
//!   the protocol crate; carved out in commit `9574c23`.
//! - **`v2-babbleon-launch-artefacts`** (this crate): the in-NS
//!   data shapes the launcher reads after the socket round-trip
//!   returns.
//! - **`v2-babbleon-core`**: the daemon-side primitives that
//!   produce these artefacts — `EpochMapping`, `MappingBuilder`,
//!   `PerHostSecret`, `Wordlist`, `wrapper::write_all_wrappers`.
//!   Pulls in the full crypto stack; only the daemon (and
//!   integration tests) depend on it.
//!
//! The bridge function `build_activated_table_from_mapping` that
//! turns an `EpochMapping` into an `ActivatedTable` lives in core
//! (it needs both ends visible).
//!
//! # Threat model boundaries
//!
//! - **Defeats:** launcher inadvertently linking the key-
//!   derivation graph via a `babbleon_core_v2::*` import.
//! - **Does NOT defeat:** the daemon's own audit surface (the
//!   daemon must depend on core to derive keys, so it pulls in
//!   the crypto stack by necessity).
//!
//! # Module map
//!
//! - [`activated_table`]: the per-epoch
//!   `(scrambled, wrapper_path)` table the daemon ships to the
//!   launcher.
//! - [`credentials`]: the canonical credential-path list and the
//!   env-var deny list / suffix patterns.
//! - [`errors`]: the crate-local error enum.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod activated_table;
pub mod credentials;
pub mod errors;

pub use activated_table::{
    ActivatedEntry, ActivatedTable, ActivatedTableBuilder, MAX_TABLE_BYTES,
};
pub use credentials::{
    discover_credential_dirs, is_credential_env_var,
    scrub_credential_env_vars, CREDENTIAL_DIRS_RELATIVE_TO_HOME,
    SCRUB_ENV_SUFFIXES, SCRUB_ENV_VAR_NAMES,
};
pub use errors::{Error, Result};
