//! Babbleon v2 — Android/mobile tier.
//!
//! # What this defeats
//!
//! An on-device, LLM-driven agent that plans against Android using
//! cached knowledge of canonical identifiers (system-service / binder
//! names, `getprop` keys, package names, intent actions).  This crate
//! reuses the OS-agnostic scramble engine (`v2-babbleon-scramble`) to
//! rename that surface per-device, and rebuilds enforcement for the
//! Android app model — there is no PAM, no login shell, no `/bin/sh`
//! wrapper and no `/proc` to watch, so the Linux tier
//! (`v2-babbleon-linux`) is not reused.  See `docs/v2/android-tier.md`.
//!
//! # Layout
//!
//! - [`mapping_handle`] — [`MobileMapping`], the owned per-device name
//!   table (the reusable core; identical math to the server).
//! - [`response`] — the name-resolution tripwire: classify a presented
//!   name and pick an action under a [`response::ResponsePolicy`].
//! - [`event`] — the event vocabulary + [`event::EventSink`] seam.
//! - [`enforcement`] — the traits the Android layer implements to give a
//!   decision teeth, plus [`enforcement::enforce`] to wire the two.
//!
//! The genuinely Android-welded pieces — SELinux app-domain policy, the
//! zygote seccomp filter, binder mediation, Keystore secret custody —
//! live **above** this crate and are consumed, not reimplemented (see the
//! design doc's boundary table).
//!
//! # FFI
//!
//! The default build is pure Rust with `#![forbid(unsafe_code)]` and no
//! `jni` dependency, so `cargo test -p v2-babbleon-mobile` exercises the
//! whole decision core on a host with no Android toolchain.  The JNI
//! bridge is gated behind the `android-jni` feature and built with
//! `cargo-ndk`; the `jni` 0.21 safe string path means even that surface
//! needs no `unsafe`, so the crate keeps `forbid(unsafe_code)`
//! unconditionally.
//!
//! **NOTE (increment 1):** the `android-jni` bridge module
//! (`jni_bridge.rs`) and the crate's workspace registration are not yet
//! landed — see the 2026-07-24 HANDOFF entry.  The pure decision core
//! below is complete and self-contained.
//!
//! # Security baseline
//!
//! Rule 1 (`forbid(unsafe_code)`) and Rule 2 (`deny(missing_docs)` +
//! `warn(clippy::pedantic)`) hold below.  Rule 6 (plain-English names)
//! and Rule 7 ("What this defeats" per module) are applied throughout.
//! Rule 15 (unit tests per primitive) — each module carries its tests.
//! The crate handles a device secret only transiently in
//! [`MobileMapping::from_device_secret`], which hands it straight to the
//! scramble engine's zeroize-on-drop `PerHostSecret`; Rules 3/4/5 are
//! satisfied there and in the engine.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod enforcement;
pub mod event;
pub mod mapping_handle;
pub mod response;

pub use enforcement::{enforce, CallerTerminator, ResolutionGuard};
pub use event::{CallbackSink, EventSink, MobileEvent, NullSink, Severity};
pub use mapping_handle::MobileMapping;
pub use response::{
    resolve_name, DecisionAction, ResolutionDecision, ResolutionOutcome,
    ResponsePolicy,
};
