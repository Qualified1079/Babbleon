//! Lifecycle step 6 — materialize the scrambled view inside the
//! fresh mount namespace.
//!
//! # What this defeats
//!
//! The scrambled view is the user-visible product of Babbleon.
//! Inside the untrusted-tier mount NS the launcher creates a tmpfs
//! at `/run/babbleon/scrambled` and bind-mounts each per-host
//! scrambled wrapper into it; the child process then sees, e.g.,
//! `flibsnortglarp` at the place `curl` would be on the trusted
//! tier.
//!
//! # Status (phase 2, in flight)
//!
//! The bind-mount loop lives in [`bind_mount_entries`].  It takes a
//! pre-validated [`babbleon_core_v2::ActivatedTable`] (see
//! [`crate::activated_table_input`] for the input path) and binds
//! each `(scrambled, wrapper_path)` entry into the scrambled-view
//! tmpfs.  When no table is supplied the orchestrator skips this
//! call and exec()s into an empty view — useful for
//! namespace+caps+seccomp smoke tests, NOT a functional deployment.
//!
//! Follow-ups still owed:
//!
//! 1. Daemon-side socket-activation channel that hands the launcher
//!    an FD instead of a path.  The CLI already accepts
//!    `--activated-table-fd N`; what's missing is the daemon binary
//!    that produces such a channel.
//! 2. Credential-dir tmpfs overlay (port of v1's
//!    `credentials::apply_untrusted_gate`).
//!
//! # Mechanism (planned)
//!
//! 1. `mkdir -p /run/babbleon/scrambled` (only inside our new NS).
//! 2. tmpfs over it with `mode=0555`.
//! 3. For each `(scrambled_name, source_path)` in the activated
//!    mapping table: create an empty file at the scrambled name,
//!    bind-mount the source over it.
//! 4. `/proc` remount with `hidepid=2` — meaningful only inside
//!    our new PID NS.
//! 5. Credential-dir tmpfs overlay (port from v1's
//!    `credentials::apply_untrusted_gate`).
//!
//! # Threat model boundaries
//!
//! - Defeats: identifier-shape recognition by the untrusted-tier
//!   child (combined with v2's structural scrambling layers,
//!   phase 3+).
//! - Does NOT defeat: a child that knows the trusted-tier names
//!   and looks them up via `/proc/<self>/root/usr/bin/...` from
//!   inside its mount NS.  Compensating control: the mount NS's
//!   `/usr/bin` is private and the scrambled tmpfs is the only
//!   path on PATH.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};

use babbleon_core_v2::ActivatedTable;
use nix::mount::{mount, MsFlags};

use crate::errors::{Error, Result};

/// Default scrambled-view root.  Inside the launcher's mount NS
/// this becomes a fresh tmpfs; outside (host NS) it remains the
/// regular directory the daemon created at install time.
pub const SCRAMBLED_ROOT: &str = "/run/babbleon/scrambled";

/// Step 6 (partial) — create the scrambled-view tmpfs.
///
/// CAPABILITY: `CAP_SYS_ADMIN` for `mount(2)` (post-unshare, but
/// still required at this stage).
///
/// Bind-mount-each-tool wiring is deferred to the daemon-IPC
/// follow-up; see module docs.
///
/// # Errors
///
/// Returns [`Error::Mount`] if the tmpfs mount is rejected by the
/// kernel.  Returns [`Error::Mount`] if `SCRAMBLED_ROOT` doesn't
/// exist (the daemon creates it at install time; missing it is
/// a configuration error worth surfacing).
pub fn mount_scrambled_view_tmpfs() -> Result<()> {
    let target = Path::new(SCRAMBLED_ROOT);
    if !target.exists() {
        return Err(Error::Mount(format!(
            "scrambled-view root {SCRAMBLED_ROOT} does not exist; \
             daemon installer should have created it"
        )));
    }
    // CAPABILITY: CAP_SYS_ADMIN for mount(2).  Dropped at step 10.
    mount(
        Some("tmpfs"),
        target,
        Some("tmpfs"),
        MsFlags::empty(),
        Some("mode=0555"),
    )
    .map_err(|e| Error::Mount(format!("tmpfs at {SCRAMBLED_ROOT}: {e}")))
}

/// Resolve the scrambled-view path for one entry.
///
/// Joins `scrambled_root` with the per-entry scrambled name.  Pure
/// function; no syscalls.  Extracted so the unit tests can verify
/// the path-construction logic without needing real mount privileges.
#[must_use]
pub fn scrambled_entry_path(scrambled_root: &Path, scrambled_name: &str) -> PathBuf {
    scrambled_root.join(scrambled_name)
}

/// Bind-mount each entry of the activated table into the
/// scrambled-view tmpfs.
///
/// Pre-conditions:
///
/// 1. The scrambled-view tmpfs is already mounted at `scrambled_root`
///    (call [`mount_scrambled_view_tmpfs`] first).
/// 2. Every `entry.wrapper_path` exists on the launcher's filesystem
///    view at the moment of the call — the daemon places the
///    wrapper binary there at install time.
/// 3. Every `entry.scrambled` has already been validated by
///    `ActivatedTable::read_jsonl` (lowercase ASCII, no path
///    separators).
///
/// For each entry: create a zero-byte file at
/// `{scrambled_root}/{scrambled}`, then bind-mount the wrapper over
/// it.  The bind-mount is a regular (not recursive) bind so a
/// later remount of `wrapper_path` on the host does not propagate
/// into the launcher's namespace.
///
/// On failure of any entry the loop aborts and returns
/// [`Error::Mount`] naming the offending scrambled name.  Earlier
/// successful binds remain in place — they live in the launcher's
/// new mount NS and tear down automatically when the process exits.
///
/// CAPABILITY: `CAP_SYS_ADMIN` for `mount(2)` (post-unshare).
/// Dropped at step 10.
///
/// # Errors
///
/// - [`Error::Mount`] for any I/O or `mount(2)` failure.  The
///   message names the scrambled entry and the underlying kernel
///   error.
pub fn bind_mount_entries(
    scrambled_root: &Path,
    table: &ActivatedTable,
) -> Result<()> {
    for entry in &table.entries {
        let target = scrambled_entry_path(scrambled_root, &entry.scrambled);

        // Create the bind target.  An existing file is treated as a
        // hard error: the scrambled-view tmpfs is fresh in this
        // namespace, so any pre-existing entry is a duplicate-name
        // attack or a launcher bug.  Either way refuse.
        match std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&target)
        {
            Ok(_) => {}
            Err(e) => {
                return Err(Error::Mount(format!(
                    "create bind target {} for {:?}: {e}",
                    target.display(),
                    entry.scrambled,
                )));
            }
        }

        // CAPABILITY: CAP_SYS_ADMIN for mount(2).  Dropped at step 10.
        mount(
            Some(entry.wrapper_path.as_path()),
            target.as_path(),
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| {
            Error::Mount(format!(
                "bind {} -> {} for {:?}: {e}",
                entry.wrapper_path.display(),
                target.display(),
                entry.scrambled,
            ))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::scrambled_entry_path;
    use std::path::Path;

    #[test]
    fn scrambled_entry_path_joins_root_and_name() {
        let p = scrambled_entry_path(
            Path::new("/run/babbleon/scrambled"),
            "flibsnortglarp",
        );
        assert_eq!(
            p,
            Path::new("/run/babbleon/scrambled/flibsnortglarp"),
        );
    }

    #[test]
    fn scrambled_entry_path_preserves_root_trailing_slash() {
        // Path::join normalises trailing slashes; the result is the
        // same whether the input ends with / or not.  We assert the
        // normalised form so a future Path::join semantics change is
        // caught.
        let with_slash = scrambled_entry_path(
            Path::new("/run/babbleon/scrambled/"),
            "alpha",
        );
        let without_slash = scrambled_entry_path(
            Path::new("/run/babbleon/scrambled"),
            "alpha",
        );
        assert_eq!(with_slash, without_slash);
    }

    // bind_mount_entries needs CAP_SYS_ADMIN inside a fresh mount NS
    // to exercise the real path.  The rooted-test harness
    // (filed in HANDOFF.md "phase-2 next steps") covers it.
}
