//! Babbleon: per-host randomized namespace obfuscation.
//!
//! Public modules form a layered stack:
//!   mapping     — FPE permutation, wordlist compounds, honey names
//!   vault       — sealed payload (epoch + host_secret + honey) with pluggable KEK
//!   manifest    — tracked-tool list, loadable from TOML
//!   storage     — XDG paths
//!   enforcement — view drivers (Simulated, LinuxNamespace, ...)
//!   session     — orchestration: init / unlock / rotate
//!   events      — detection + audit event bus
//!   plugins     — enterprise extension boundary (compile-time today; dynamic later)
//!   platform    — single source of truth for platform detection
//!   errors      — error hierarchy
//!
//! Enterprise extensions implement the `KekBackend` and `EnforcementDriver`
//! traits and register via the babbleon-enterprise crate, which depends on this
//! one. No public-package code changes required.

pub mod audit;
pub mod backup;
pub mod credentials;
pub mod enforcement;
pub mod errors;
pub mod events;
pub mod manifest;
pub mod mapping;
pub mod platform;
pub mod plugins;
pub mod session;
pub mod storage;
pub mod vault;

pub use errors::{BabbleonError, Result};
