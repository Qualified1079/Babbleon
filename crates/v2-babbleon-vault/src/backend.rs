//! KEK backend trait — the only contract [`crate::Vault`] depends on.
//!
//! # What this defeats
//!
//! Without a backend abstraction the vault would be hardwired to one
//! credential type (passphrase, TPM, FIDO2).  Operators would have to
//! pick at install time and migrate by rotating every vault on every
//! hardware-tier change.  The trait keeps the soft-tier (Argon2id)
//! implementation in `soft_backend.rs` and leaves room for
//! `tpm_backend.rs` / `fido2_backend.rs` / `hsm_backend.rs` in later
//! phases without churning the vault module's public API.
//!
//! # Mechanism
//!
//! Backend hands `Vault` an "age passphrase" — the secret material
//! `age::Encryptor::with_user_passphrase` ingests.  The backend is
//! responsible for stretching whatever credential the operator
//! supplied into a value strong enough to seed an AEAD key:
//!
//! - **Soft (Argon2id):** stretches a passphrase via memory-hard
//!   KDF; ~250 ms / unlock on a modern laptop.
//! - **TPM (future):** asks the TPM to unseal a session key bound to
//!   the host's measured boot state; no user input.
//! - **FIDO2 (future):** asks a hardware token to derive an HMAC
//!   over a per-vault salt; user touches the token.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** algorithm-substitution attacks at vault swap (the
//!   backend's `name()` is recorded in the vault payload's `tier`
//!   field, so a vault sealed with one tier and unsealed with
//!   another fails at the cipher layer before reaching this trait).
//! - **Does NOT defeat:** a backend implementation bug.  The trait
//!   only enforces the API shape; correctness lives in the
//!   implementation.

use crate::errors::Result;

/// One backend produces one age passphrase per operator credential
/// presentation.
///
/// Implementors:
///
/// - **MUST** return a passphrase whose entropy upper-bounds the
///   downstream `age` cipher's effective key (32 bytes / 256 bits).
/// - **MUST** be deterministic for the same `(credential, backend
///   state)` tuple — `seal` and `unseal` must produce equal age
///   passphrases for equal inputs or every vault is unreadable.
/// - **MUST NOT** retain the credential after returning.  The
///   credential string lives on the operator's stack; a backend
///   that stashes it (in a cache, in a static, anywhere) widens the
///   leakage surface.
pub trait KekBackend {
    /// Stretch the supplied credential into the age passphrase the
    /// vault will encrypt under.  The credential is `None` for
    /// backends that take their input from elsewhere (TPM, FIDO2);
    /// callers that pass `None` to a backend that requires a
    /// credential see [`crate::errors::Error::Input`].
    ///
    /// # Errors
    ///
    /// Backend-specific; per security-baseline rule 13, no error
    /// variant carries the credential bytes or any KDF intermediate.
    fn derive_age_passphrase(&self, credential: Option<&str>) -> Result<String>;

    /// Human-readable backend name used as the `tier` field in
    /// [`crate::VaultPayload`].  Convention: lowercase ASCII, single
    /// word, no spaces.  Examples: `"soft"`, `"tpm"`, `"fido2"`.
    fn name(&self) -> &'static str;
}
