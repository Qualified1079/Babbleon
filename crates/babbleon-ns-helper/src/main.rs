//! `babbleon-ns-helper`: tiny setuid helper that sets up an untrusted
//! mount + PID namespace for a child process, drops capabilities, then
//! exec's into the requested command.
//!
//! DEFERRED(M3): full implementation. Skeleton only this session — the
//! point is the build-system seam: when M3 lands, the helper is a single
//! statically-linked binary, easy to audit, no Python interpreter on the
//! privileged path.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use anyhow::Result;

fn main() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        eprintln!(
            "babbleon-ns-helper: M3 skeleton; not yet implemented (see DEFERRED.md)"
        );
        std::process::exit(2);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("babbleon-ns-helper: Linux-only");
        std::process::exit(2);
    }
}
