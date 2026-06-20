//! Babbleon v2 — core library.
//!
//! # What this defeats
//!
//! Per-host randomized namespace obfuscation: every host has its own
//! mapping from canonical tool names (`curl`, `ssh`, `aws`) to
//! per-host scrambled wordlist compounds.  The attacker model is an
//! automated LLM-driven agent that runs in an untrusted-tier process
//! and reasons about exploits using cached knowledge of canonical
//! names.  See `docs/threat-model.md` (v1) and `docs/v2/threat-model.md`
//! (v2; in flight) for the full model.
//!
//! v2 (this crate) extends v1's identifier-only scramble with the
//! structural-scrambling layers from `docs/v2/structure-scrambling.md`
//! (phase 3+).  This crate ships the foundational primitives that
//! every later phase builds on:
//!
//! - **`per_host_secret`** — the only secret on the box.  Held in
//!   `zeroize::Zeroizing<[u8; 32]>` so its plaintext is wiped from
//!   memory on drop.
//! - **`key_derivation`** — HKDF-SHA-256 (RFC 5869) sub-key
//!   derivation per `(epoch, purpose)` tuple.  Replaces v1's
//!   hand-rolled `SHA256(host_secret || label)`.
//! - **`permutation`** — bijective Fisher-Yates over a wordlist,
//!   seeded by HKDF.  Replaces v1's `mapping/fpe.rs`.
//! - **`wordlist`** — wordlist loader.
//! - **`mapping`** — `EpochMapping` (the per-epoch name table) and
//!   `MappingBuilder` (the constructor).
//!
//! # Security baseline applied
//!
//! Every v2 crate satisfies (see `docs/v2/security-baseline.md`):
//!
//! - `#![forbid(unsafe_code)]` at the crate root.  This crate uses
//!   only safe Rust; any v2 crate that needs unsafe quarantines it to
//!   one syscall module.
//! - Secret-holding types wrap their bytes in `zeroize::Zeroizing`
//!   or `secrecy::SecretBox`.
//! - Secret-derived compares go through
//!   `crypto_compare::secret_bytes_equal` (constant-time).
//! - Domain separation uses HKDF, NOT hand-rolled hash-of-concat.
//! - Every public function / type / module has a name that reads as
//!   plain English (see `docs/v2/naming-conventions.md`).
//!
//! # Differential testing against v1
//!
//! `tests/v1_compat.rs` asserts that v2's identifier scramble
//! produces the same compound name as v1 for the same
//! `(host_secret, epoch, tool)` triple.  This is the go/no-go gate
//! for phase 1 — if v2's primitive doesn't match v1's, we have
//! introduced a regression in the only piece v1 reliably got right.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
// Pedantic lints we explicitly relax — none yet; reconsider per file
// as the crate grows.

pub mod activated_table_bridge;
pub mod crypto_compare;
pub mod errors;
pub mod events;
pub mod key_derivation;
pub mod mapping;
pub mod per_host_secret;
pub mod permutation;
pub mod tripwire;
pub mod wordlist;
pub mod wrapper;

// The `activated_table` and `credentials` modules were extracted
// to `v2-babbleon-launch-artefacts` so the launcher and PAM can
// consume them without pulling in the crypto stack.  Core
// re-exports the same public surface so existing
// `babbleon_core_v2::ActivatedTable` / `babbleon_core_v2::discover_credential_dirs`
// call sites keep working.  New code should prefer the artefacts
// crate directly when it does not need core's primitives.
pub use activated_table_bridge::build_activated_table_from_mapping;
pub use babbleon_launch_artefacts_v2::{
    discover_credential_dirs, is_credential_env_var,
    scrub_credential_env_vars, ActivatedEntry, ActivatedTable,
    ActivatedTableBuilder, CREDENTIAL_DIRS_RELATIVE_TO_HOME,
    MAX_TABLE_BYTES, SCRUB_ENV_SUFFIXES, SCRUB_ENV_VAR_NAMES,
};
pub use errors::{Error, Result};
pub use events::{
    AuditChainSink, Event, EventSink, JsonlFileSink, Severity, StderrSink,
    TripwireSource,
};
pub use mapping::{EpochMapping, MappingBuilder, COMPOUND_N, HONEY_COUNT};
pub use per_host_secret::{PerHostSecret, PER_HOST_SECRET_LEN};
pub use permutation::Permutation;
pub use tripwire::{TripwireResponder, TripwireResponsePolicy};
pub use wordlist::Wordlist;
pub use wrapper::{
    write_all_tripwire_wrappers, write_all_wrappers, write_honey_list,
    write_stale_list, write_tripwire_wrapper, write_wrapper,
    TRIPWIRE_EVENTS_FIFO, TRIPWIRE_HONEY_LIST, TRIPWIRE_STALE_LIST,
};
