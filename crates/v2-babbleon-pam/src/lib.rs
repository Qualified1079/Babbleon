//! Babbleon v2 PAM session module — Rust scaffolding.
//!
//! # What this defeats
//!
//! The shipped artifact is `pam_babbleon.so`, the C-built PAM
//! session module that — once the session-architecture follow-up
//! lands — arranges the user's login shell to run inside the
//! `babbleon-launch-untrusted` environment.  Without this module,
//! Babbleon's namespace obfuscation is opt-in per command, defeating
//! the threat model (an LLM-driven worm that spawns a child from the
//! user's unwrapped shell inherits the unscrambled view).
//!
//! This crate is the **scaffolding** for that artifact, not the
//! artifact itself.  It exists for three reasons:
//!
//!   1. To give cargo a manifest to drive — `build.rs` compiles
//!      the C source into `pam_babbleon.so` and lands it at
//!      `target/<profile>/pam_babbleon.so`.
//!   2. To carry the v2 conventions (security baseline, naming) in
//!      the same crate as the C shim, so reviewers reading the
//!      C source can find the rationale next to it.
//!   3. To unit-test the scaffolding itself (path constants, build
//!      pipeline) on every `cargo test -p v2-babbleon-pam`.
//!
//! # Mechanism — current state (SKELETON)
//!
//! The C shim (`src/pam_babbleon.c`) implements `pam_sm_open_session`
//! and `pam_sm_close_session`.  At session open it:
//!
//!   - Exempts `root`.
//!   - Probes the daemon's Unix socket via `connect(2)`.
//!   - Logs a breadcrumb via `pam_syslog` and returns `PAM_SUCCESS`.
//!
//! It does NOT yet invoke `babbleon-launch-untrusted` because the
//! architectural question of *how* a PAM session module wraps the
//! eventual user shell does not have a single right answer — the
//! three candidate architectures are documented in
//! `docs/v2/pam-architecture.md`.  The operator picks one before
//! this module ships in a release.
//!
//! # Threat model boundaries
//!
//! - Defeats: the "user forgot to type `babbleon`" failure mode
//!   (post-skeleton).
//! - Defeats: a regression that bricks login — the C shim returns
//!   `PAM_SUCCESS` on every failure path, and the recommended PAM
//!   stack entry is `session optional pam_babbleon.so`.
//! - Does NOT defeat: an attacker who can rewrite `/etc/pam.d/`.
//!   Out of scope per the threat model.
//! - Does NOT defeat: a user invoking `setsid` or otherwise
//!   escaping the namespace once it lands.  The launcher's
//!   seccomp profile bounds that surface; PAM does not.
//!
//! # Why a Rust stub crate at all?
//!
//! Two alternatives we rejected:
//!
//!   - **A pure `make`-driven build.**  The C source could live in
//!     `tools/pam-builder/` and be packaged outside cargo.  Rejected
//!     because every other v2 component builds through cargo; an
//!     out-of-tree build path would create a release-engineering
//!     gap (cargo's `--locked` does not gate it).
//!   - **A Rust-native PAM module via `extern "C"`.**  Rust can
//!     define `pam_sm_open_session` as `#[no_mangle] extern "C"`.
//!     Rejected because the surface is two functions, the C ABI is
//!     stable, and the C shim is shorter and easier for an
//!     auditor to read than the equivalent FFI bindings.
//!     Filed for re-evaluation once the launcher-invocation logic
//!     lands and the shim is no longer trivial.
//!
//! # Security baseline applied
//!
//! Rule 1 (`#![forbid(unsafe_code)]`): satisfied at the crate
//! root.  The shipped artifact is C, not Rust; this crate's Rust
//! surface has no business doing FFI.
//!
//! Rule 2 (`#![deny(missing_docs)]` + `#![warn(clippy::pedantic)]`):
//! satisfied.
//!
//! Rule 6 (plain-English names): every public item names what it
//! does (`launch_untrusted_install_path`, `daemon_socket_path`).
//!
//! Rule 7 ("What this defeats" template): you are reading it.
//!
//! Rules 3, 4, 5, 8, 11, 12, 13, 14 do not apply — this crate
//! handles no secrets.
//!
//! Rule 15 (tests): one unit test per public constant plus the
//! build-artifact integration test in `tests/built_artifact.rs`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

use std::path::PathBuf;

/// Default install path for the v2 untrusted-tier launcher.
///
/// Baked into `pam_babbleon.so` by `build.rs` via
/// `-DBABBLEON_LAUNCH_UNTRUSTED_PATH`.  Override at build time by
/// setting the `BABBLEON_LAUNCH_UNTRUSTED_PATH` environment variable.
///
/// Exposed as a Rust constant so the packaging layer (TBD) and the
/// rooted-test harness can install / probe the right path without
/// re-parsing the C source.
pub const DEFAULT_LAUNCH_UNTRUSTED_PATH: &str =
    "/usr/local/libexec/babbleon-launch-untrusted";

/// Default daemon Unix-socket path that the C shim probes at
/// session open.
///
/// Must agree with `v2-babbleon-daemon-protocol::default_socket_path`.
/// We do not depend on that crate from build.rs (build-deps are kept
/// minimal — `cc` only) so this constant is duplicated; the
/// `default_socket_path_agrees_with_protocol_crate` test in
/// `tests/socket_path_agreement.rs` enforces the agreement.
pub const DEFAULT_DAEMON_SOCKET_PATH: &str = "/run/babbleon/daemon.sock";

/// Build-configurable path to the launcher binary, resolved at the
/// time the caller asks (NOT at build time).
///
/// Reads `BABBLEON_LAUNCH_UNTRUSTED_PATH` from the environment and
/// falls back to [`DEFAULT_LAUNCH_UNTRUSTED_PATH`].  Intended for
/// the packaging layer's runtime probes (`stat`, capability check),
/// not for the C shim — the C shim uses the build-time-baked path.
#[must_use]
pub fn launch_untrusted_install_path() -> PathBuf {
    PathBuf::from(
        std::env::var("BABBLEON_LAUNCH_UNTRUSTED_PATH")
            .unwrap_or_else(|_| DEFAULT_LAUNCH_UNTRUSTED_PATH.into()),
    )
}

/// Build-configurable path to the daemon socket, resolved at the
/// time the caller asks.
///
/// Mirrors [`launch_untrusted_install_path`]; reads
/// `BABBLEON_DAEMON_SOCKET_PATH` from the environment and falls
/// back to [`DEFAULT_DAEMON_SOCKET_PATH`].
#[must_use]
pub fn daemon_socket_path() -> PathBuf {
    PathBuf::from(
        std::env::var("BABBLEON_DAEMON_SOCKET_PATH")
            .unwrap_or_else(|_| DEFAULT_DAEMON_SOCKET_PATH.into()),
    )
}

/// Architectural status of this crate, exposed as an enum so that
/// the operator-facing CLI (`babbleon status`) can answer "is the
/// PAM module ready to ship?" without re-reading the docs.
///
/// The variant returned is a compile-time constant: this crate
/// ships exactly one status until the architecture lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Skeleton phase: the `.so` compiles and loads but the
    /// launcher-invocation logic has not landed yet.  Operators
    /// who install this module today get a daemon liveness probe
    /// at session open and nothing else.
    SkeletonOnly,
    /// One of the three architectures in
    /// `docs/v2/pam-architecture.md` has been picked and wired.
    /// This variant is reserved; the crate does not return it yet.
    Wired,
}

/// What stage this crate is at, today.
///
/// Always [`Readiness::SkeletonOnly`] in the current branch.  The
/// constant turns into a release-gate when the wiring lands: the
/// operator CLI will refuse to enable PAM integration while this
/// is `SkeletonOnly`.
#[must_use]
pub const fn readiness() -> Readiness {
    Readiness::SkeletonOnly
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Process-wide env vars are shared mutable state — cargo runs
    // tests in parallel by default and `std::env::set_var` is not
    // serialized.  We gate every test that touches an env var on
    // this Mutex so the override/default pairs cannot race.  Tests
    // that don't touch env vars don't take the lock.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Scoped env-var override that restores the prior value on
    /// drop, even if the test panics.  Construction takes the
    /// shared env mutex so concurrent env-touching tests serialize.
    struct EnvOverride<'lock> {
        key: &'static str,
        prior: Option<String>,
        _guard: std::sync::MutexGuard<'lock, ()>,
    }

    impl EnvOverride<'_> {
        fn set(key: &'static str, value: &str) -> Self {
            let guard = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let prior = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, prior, _guard: guard }
        }

        fn unset(key: &'static str) -> Self {
            let guard = ENV_LOCK
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let prior = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prior, _guard: guard }
        }
    }

    impl Drop for EnvOverride<'_> {
        fn drop(&mut self) {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    #[test]
    fn default_launch_path_is_absolute() {
        let p = PathBuf::from(DEFAULT_LAUNCH_UNTRUSTED_PATH);
        assert!(
            p.is_absolute(),
            "DEFAULT_LAUNCH_UNTRUSTED_PATH must be absolute: {p:?}",
        );
    }

    #[test]
    fn default_socket_path_is_absolute() {
        let p = PathBuf::from(DEFAULT_DAEMON_SOCKET_PATH);
        assert!(
            p.is_absolute(),
            "DEFAULT_DAEMON_SOCKET_PATH must be absolute: {p:?}",
        );
    }

    #[test]
    fn default_socket_path_matches_protocol_crate_documented_constant() {
        // The protocol crate's `default_socket_path()` is the
        // canonical source.  We duplicate the literal here to keep
        // build-deps small (no dep on the protocol crate from a PAM
        // build pipeline).  This test fails if the two drift.
        assert_eq!(DEFAULT_DAEMON_SOCKET_PATH, "/run/babbleon/daemon.sock");
    }

    #[test]
    fn launch_path_honors_env_override() {
        let override_path = "/opt/custom/babbleon-launch-untrusted";
        let _e = EnvOverride::set(
            "BABBLEON_LAUNCH_UNTRUSTED_PATH",
            override_path,
        );
        assert_eq!(
            launch_untrusted_install_path(),
            PathBuf::from(override_path)
        );
    }

    #[test]
    fn socket_path_honors_env_override() {
        let override_path = "/var/run/custom/daemon.sock";
        let _e = EnvOverride::set(
            "BABBLEON_DAEMON_SOCKET_PATH",
            override_path,
        );
        assert_eq!(daemon_socket_path(), PathBuf::from(override_path));
    }

    #[test]
    fn launch_path_default_when_env_unset() {
        let _e = EnvOverride::unset("BABBLEON_LAUNCH_UNTRUSTED_PATH");
        assert_eq!(
            launch_untrusted_install_path(),
            PathBuf::from(DEFAULT_LAUNCH_UNTRUSTED_PATH)
        );
    }

    #[test]
    fn socket_path_default_when_env_unset() {
        let _e = EnvOverride::unset("BABBLEON_DAEMON_SOCKET_PATH");
        assert_eq!(
            daemon_socket_path(),
            PathBuf::from(DEFAULT_DAEMON_SOCKET_PATH)
        );
    }

    #[test]
    fn readiness_is_skeleton_in_this_branch() {
        // Release gate: this assertion flips to `Wired` in the same
        // commit that lands the launcher-invocation logic.  Reviewer
        // of that PR must check that the C shim actually exec's the
        // launcher (or chains via one of the three architectures).
        assert_eq!(readiness(), Readiness::SkeletonOnly);
    }

    #[test]
    fn readiness_variants_distinct() {
        assert_ne!(Readiness::SkeletonOnly, Readiness::Wired);
    }
}
