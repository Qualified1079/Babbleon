//! Babbleon v2 — vault: at-rest encryption for the per-host secret.
//!
//! # What this defeats
//!
//! The per-host secret is the only secret on a Babbleon-protected host
//! (`v2-babbleon-core::per_host_secret`).  Between sessions it lives on
//! disk inside the vault file.  Without an at-rest encryption layer the
//! per-host secret would be a single root-owned file an attacker who
//! lands as root reads with `cat`.
//!
//! The vault seals the secret with a key derived from a user
//! credential (passphrase in v2.0; TPM / FIDO2 / USB tier in later
//! phases).  Bringing the host secret back into memory requires the
//! operator to present the unlock credential.  This raises the cost
//! of automated credential-theft attacks: the per-host secret is not
//! reachable from a cold-boot disk image or from a process with read
//! access but no live operator input.
//!
//! # Compartmentalization
//!
//! This crate is linked by the **user-facing CLI only** (`v2-babbleon`,
//! the `babbleon init` and `babbleon unlock` subcommands).  The
//! **daemon does NOT link this crate**.  The daemon receives 32
//! unwrapped bytes over its Unix socket via
//! `babbleon_daemon_protocol_v2::Request::Unlock`; the unwrap (age
//! decrypt + Argon2id KDF) happens inside the user-CLI process where
//! the passphrase already exists and is short-lived.
//!
//! Two reasons to keep this crate out of the daemon's dependency
//! graph:
//!
//! - **Audit surface.**  `age` and `argon2` are non-trivial
//!   crates.  The daemon is the most security-sensitive binary
//!   (long-running, holds the per-host secret in memory) — every
//!   transitive dependency on it widens the surface auditors must
//!   trace.
//! - **`DoS` resistance.**  Argon2id is intentionally expensive
//!   (~250 ms / unlock on a laptop).  If the daemon performed the
//!   KDF, an adversarial unlock request would burn the daemon's
//!   CPU and slow legitimate `Status` / `RotateMapping` calls.
//!
//! # Mechanism
//!
//! Vault on-disk format: `age` passphrase-encrypted ciphertext
//! whose plaintext is a JSON [`VaultPayload`].  The age passphrase is
//! NOT the operator's passphrase — it is the [`KekBackend`]-derived
//! "age passphrase" (Argon2id-stretched in the soft backend; TPM-
//! sealed in later backends).
//!
//! - [`VaultPayload`] — the plaintext-inside-age JSON.  Contains the
//!   per-host secret as **bytes** (`Zeroizing<Vec<u8>>` — NOT a
//!   `String`, per security-baseline rule 11), the epoch counter,
//!   the soft-tier profile metadata, and the schema version.
//! - [`KekBackend`] — trait the vault depends on; one
//!   `derive_age_passphrase(credential)` method.
//! - [`SoftBackend`] — Argon2id implementation; two named profiles
//!   (`Laptop` / `Headless`) per `docs/v2/least-privilege.md`'s
//!   "cost budget" note.
//! - [`Vault`] — the seal / unseal API; one struct generic over a
//!   `KekBackend`.
//! - [`default_vault_path`] — `$XDG_CONFIG_HOME/babbleon/vault.age`
//!   when present; falls back to `/etc/babbleon/vault.age` on
//!   non-user installs.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** cold-boot disk reads of the per-host secret;
//!   single-image attacks against the vault file alone.
//! - **Does NOT defeat:** live operator with the passphrase typed
//!   into a compromised TTY (no v2-layer defense beyond the operator's
//!   own TTY hygiene); kernel-level memory disclosure while the
//!   daemon holds the unwrapped secret.
//! - **Does NOT defeat:** persistent attackers who tamper with the
//!   vault file between unlocks (no integrity beyond age's own MAC;
//!   detection would require an HMAC checkpoint outside the vault,
//!   filed for v2.1).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod backend;
pub mod errors;
pub mod file_layout;
pub mod payload;
pub mod soft_backend;
pub mod vault;

pub use backend::KekBackend;
pub use errors::{Error, Result};
pub use file_layout::{default_vault_path, ensure_parent_dir};
pub use payload::{VaultPayload, PAYLOAD_SCHEMA_CURRENT};
pub use soft_backend::{SoftBackend, SoftProfile, SOFT_BACKEND_NAME};
pub use vault::Vault;
