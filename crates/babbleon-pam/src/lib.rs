//! **DEPRECATED v1 — see `crates/DEPRECATED-V1.md`.  v2 PAM module is
//! filed for phase 2; the v1 PAM ABI shim here will be rewritten under
//! v2 conventions.  Do not extend this crate; v2 is the source of truth
//! for new work.**
//!
//! Stub: the real artifact is `pam_babbleon.so`, built by `build.rs`
//! from `src/pam_babbleon.c`.  This Rust lib exists only so `cargo`
//! has a manifest to drive — the `.so` lands in `target/<profile>/`
//! and is installed by the packaging step.
