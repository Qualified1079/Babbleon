//! Lifecycle step 6 (continued) — overlay empty tmpfs over each
//! credential-bearing directory in the new mount namespace.
//!
//! # What this defeats
//!
//! The untrusted-tier child must not see `~/.aws/credentials`,
//! `~/.ssh/id_*`, browser cookie databases, etc.  Bind-mounting an
//! empty tmpfs OVER each cred dir makes the path exist (avoids
//! "no such file" telltales) but renders the contents
//! inaccessible.  Compared with `chmod 000` this approach:
//!
//! - Leaves the host-side files untouched.
//! - Is reversible by exiting the mount namespace.
//! - Is invisible to a process inside the namespace — `mount(2)`
//!   metadata is not exposed without privileged introspection.
//!
//! Live trust handles that leak via *environment* variables
//! (`SSH_AUTH_SOCK`, `KUBECONFIG`, `ANTHROPIC_API_KEY`) are
//! handled by env scrubbing in the launcher's exec path; see
//! `babbleon_launch_artefacts_v2::credentials::scrub_credential_env_vars`.
//!
//! # Mechanism
//!
//! [`hide_credential_dirs_with_tmpfs`] takes a list of absolute
//! paths produced by
//! `babbleon_launch_artefacts_v2::discover_credential_dirs`, and for each:
//!
//! 1. Mounts an empty tmpfs over the path with `mode=0700,size=64k`.
//! 2. On `EPERM` / `EACCES` returns a hard error (we are
//!    post-unshare and hold `CAP_SYS_ADMIN`; failure indicates a
//!    seccomp filter installed too early or a stacked LSM denial).
//! 3. On other errors (`ENOENT` if the path vanished between
//!    discovery and mount) logs and continues — we already know
//!    the path *was* there at discovery time; a race is benign.
//!
//! The 64 KiB cap matches v1; large enough to absorb the
//! occasional `mkdir`/`touch` an unsuspecting tool will do
//! (which we want to silently swallow), small enough to make
//! storing real data impractical.
//!
//! # Compartmentalization
//!
//! Discovery (which paths) lives in
//! `babbleon_launch_artefacts_v2::credentials` (no syscalls).  This module
//! handles only the privileged mount step.  Tests for the path
//! list run in core; tests for the mount semantics need root and
//! belong in the rooted-test harness filed in HANDOFF.md.
//!
//! # Threat model boundaries
//!
//! - Defeats: an untrusted-tier process reading host credential
//!   files via the usual paths.
//! - Does NOT defeat: a credential held in memory by an
//!   already-running agent (e.g. `ssh-agent`).  Compensating
//!   control: env scrub drops `SSH_AUTH_SOCK` so the agent is
//!   unreachable.
//! - Does NOT defeat: credentials embedded *inside* non-
//!   credential files (e.g. inline API key in a script).  See
//!   structure-scrambling phase 3+ for that vector.

#![cfg(target_os = "linux")]

use std::path::Path;

use nix::mount::{mount, MsFlags};

use crate::errors::{Error, Result};

/// `size=` parameter for the credential-overlay tmpfs.  Sized to
/// tolerate the occasional `mkdir`/`touch` that an unsuspecting
/// tool will perform without giving a real-data storage budget.
pub const CREDENTIAL_OVERLAY_SIZE: &str = "64k";

/// `mode=` parameter for the credential-overlay tmpfs.  `0700`
/// matches the access mode users expect on their cred dirs so
/// `ls -la $HOME` doesn't suddenly show world-readable
/// directories where the cred dirs used to be.
pub const CREDENTIAL_OVERLAY_MODE: &str = "0700";

/// Overlay every entry in `cred_dirs` with an empty tmpfs.
///
/// Pre-conditions:
///
/// 1. The launcher is inside its fresh mount namespace (step 4
///    has run).
/// 2. The root has been marked `MS_PRIVATE|MS_REC` (step 5).
/// 3. Every path in `cred_dirs` was returned by
///    `discover_credential_dirs` and existed on disk at that
///    time.
///
/// Returns the subset of paths actually overlaid.  A path that
/// vanished between discovery and mount is logged and skipped;
/// every other error aborts the loop.
///
/// CAPABILITY: `CAP_SYS_ADMIN` for `mount(2)` (post-unshare).
/// Dropped at step 10.
///
/// # Errors
///
/// - [`Error::Mount`] on any `mount(2)` error other than `ENOENT`.
///   `ENOENT` is treated as a benign race (the path vanished
///   between discovery and mount) and is logged + skipped.
pub fn hide_credential_dirs_with_tmpfs(
    cred_dirs: &[std::path::PathBuf],
) -> Result<Vec<std::path::PathBuf>> {
    let options = format!(
        "mode={CREDENTIAL_OVERLAY_MODE},size={CREDENTIAL_OVERLAY_SIZE}"
    );
    let mut overlaid = Vec::with_capacity(cred_dirs.len());
    for dir in cred_dirs {
        match mount_one(dir, &options) {
            Ok(()) => overlaid.push(dir.clone()),
            Err(MountOneError::Vanished) => {
                tracing::info!(
                    path = %dir.display(),
                    "credential dir vanished between discovery and mount; skipping",
                );
            }
            Err(MountOneError::Hard(message)) => {
                return Err(Error::Mount(format!(
                    "credential-overlay {}: {message}",
                    dir.display(),
                )));
            }
        }
    }
    Ok(overlaid)
}

enum MountOneError {
    /// `ENOENT` from `mount(2)` — the target path no longer exists.
    Vanished,
    /// Any other kernel error.  Wrapped error message.
    Hard(String),
}

fn mount_one(dir: &Path, options: &str) -> std::result::Result<(), MountOneError> {
    // CAPABILITY: CAP_SYS_ADMIN for mount(2).  Dropped at step 10.
    let result = mount(
        Some("tmpfs"),
        dir,
        Some("tmpfs"),
        MsFlags::empty(),
        Some(options),
    );
    match result {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ENOENT) => Err(MountOneError::Vanished),
        Err(e) => Err(MountOneError::Hard(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{CREDENTIAL_OVERLAY_MODE, CREDENTIAL_OVERLAY_SIZE};

    #[test]
    fn overlay_size_is_small() {
        // Guardrail: a future maintainer who bumps this to e.g.
        // 1G would silently turn the overlay into usable storage
        // for a child process.  Force a deliberate edit.
        assert!(CREDENTIAL_OVERLAY_SIZE.ends_with('k'));
    }

    #[test]
    fn overlay_mode_is_0700() {
        assert_eq!(CREDENTIAL_OVERLAY_MODE, "0700");
    }

    // The mount path itself needs CAP_SYS_ADMIN inside a fresh
    // mount NS; covered by the rooted-test harness filed in
    // HANDOFF.md.
}
