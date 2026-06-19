//! Canonical daemon socket path.
//!
//! Lives here (and not in [`crate::client`]) so that callers who only
//! need the path constant — for example, a CLI that hasn't decided
//! whether it will speak the protocol yet — don't pull in
//! `UnixStream` and its transitive imports.

use std::path::PathBuf;

/// Sentinel for the daemon's default socket path:
/// `/run/babbleon/daemon.sock`.
///
/// Exposed so the CLI, the launcher, and the daemon's own listener
/// reference the same constant.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/babbleon/daemon.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_is_absolute() {
        assert!(default_socket_path().is_absolute());
    }

    #[test]
    fn default_path_matches_documented_constant() {
        assert_eq!(
            default_socket_path(),
            std::path::Path::new("/run/babbleon/daemon.sock"),
        );
    }
}
