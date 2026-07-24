//! Babbleon v2 — Linux detection/response tier.
//!
//! # What this is
//!
//! The OS-welded half of Babbleon v2, carved out of `v2-babbleon-core`
//! (see `docs/v2/scramble-core-carve.md`) so the pure scramble engine
//! (`v2-babbleon-scramble`) can be shared with a mobile fork that
//! rebuilds enforcement.  Everything here assumes Linux:
//!
//! - **`events`** — the event model plus its sinks: a JSONL file sink
//!   and an ed25519 audit-chain sink.  `/proc`-start-time semantics and
//!   filesystem paths live at this tier, never in the scramble engine.
//! - **`tripwire`** — decoy-access detection and the response policy
//!   knob (what to do when a [`Event::Tripwire`] fires).
//! - **`wrapper`** — emits the `/bin/sh` tripwire wrapper scripts that
//!   reference `/proc/self/ns/mnt`, `stat`, `grep`; derives per-wrapper
//!   sub-keys from the scramble engine's `key_derivation`.
//! - **`activated_table_bridge`** — builds a launch-artefact
//!   `ActivatedTable` from a scramble-engine `EpochMapping`.
//!
//! A mobile fork (Android/enterprise) depends on `v2-babbleon-scramble`
//! directly and replaces this crate wholesale with an SELinux /
//! zygote / binder-property implementation.
//!
//! # Security baseline applied
//!
//! Per `docs/v2/security-baseline.md`: `#![forbid(unsafe_code)]` at the
//! crate root; secret-holding types wrap their bytes in
//! `zeroize::Zeroizing`; the audit chain signs with ed25519 (RustCrypto).

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod activated_table_bridge;
pub mod events;
pub mod tripwire;
pub mod wrapper;

pub use activated_table_bridge::build_activated_table_from_mapping;
pub use events::{
    AuditChainSink, Event, EventSink, JsonlFileSink, Severity, StderrSink,
    TripwireSource,
};
pub use tripwire::{TripwireResponder, TripwireResponsePolicy};
pub use wrapper::{
    write_all_tripwire_wrappers, write_all_wrappers, write_honey_list,
    write_stale_list, write_tripwire_wrapper, write_wrapper,
    TRIPWIRE_EVENTS_FIFO, TRIPWIRE_HONEY_LIST, TRIPWIRE_STALE_LIST,
};
