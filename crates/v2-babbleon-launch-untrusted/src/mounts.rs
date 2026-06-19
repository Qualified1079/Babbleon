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
//! Wiring of the `EpochMapping` from `v2-babbleon-core` into the
//! bind-mount loop is NOT YET PORTED.  v1's reference
//! implementation lives at `crates/babbleon/src/enforcement/linux_ns.rs::mount_scrambled_view`
//! and ports forward verbatim under the v2 conventions once:
//!
//! 1. A daemon-side IPC channel exists for the launcher to receive
//!    the activated mapping table (the launcher must not hold the
//!    per-host secret itself — see `V2_PLAN.md` compartmentalization).
//! 2. The runtime-table read path (replacing v1's per-tool wrapper
//!    bind-mount with a single unified wrapper + table file) lands
//!    in `v2-babbleon-core::wrapper`.  The unified template is
//!    already filed at `wrapper.rs`; the table-file reader is
//!    follow-up.
//!
//! Until those land, this module exposes only the tmpfs bring-up
//! call that runs unconditionally — bind-mounting nothing produces
//! an empty scrambled view, which the orchestrator detects and
//! refuses to exec.  Safer than a half-set-up view.
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

use std::path::Path;

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
