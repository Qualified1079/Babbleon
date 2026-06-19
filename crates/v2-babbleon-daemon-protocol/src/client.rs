//! Client side of the daemon socket — operator one-shots.
//!
//! # Infrastructure module
//!
//! The daemon binary supports two operating modes (see
//! `v2-babbleon-daemon::cli`):
//!
//! - **Long-running mode** (`run`): bind a listener, serve requests
//!   in a loop.  Lives in `v2-babbleon-daemon::socket`.
//! - **One-shot subcommands** (`status`, `emit-activated-table`,
//!   `rotate-mapping`): connect to the running daemon's socket,
//!   send one request, read one response, exit.  Lives here.
//!
//! Splitting the client side into its own module (and now its own
//! crate) keeps the daemon-side serve loop free of any code that
//! could conceivably be reused by an attacker who replays its
//! traffic.  The client side is what an integration test against
//! a real daemon binary uses, and what the user CLI uses, so it
//! ships as a public library function.
//!
//! Integration tests that exercise [`round_trip`] against a real
//! [`v2-babbleon-daemon::DaemonState`] live in the daemon crate
//! (`crates/v2-babbleon-daemon/tests/client_round_trip.rs`).  The
//! unit tests here cover only the connection-error path, which
//! does not need a serving peer.
//!
//! No I/O timeouts in phase 2 — a missing daemon presents as a
//! `connect` error at startup, not a hang.  Read/write timeouts can
//! be added in v2.1 if the protocol grows multi-round flows.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::errors::{Error, Result};
use crate::protocol::{Request, Response};

/// Connect to the daemon at `socket_path`, send one request, read
/// one response, close.
///
/// Wraps [`UnixStream::connect`] and the wire framing so callers
/// don't have to know the protocol's byte-level layout.  Used by
/// the user-CLI one-shots and by the daemon's integration tests.
///
/// # Errors
///
/// - [`Error::Ipc`] for: connect failure, write failure, read
///   failure, response parse failure.
pub fn round_trip(socket_path: &Path, request: &Request) -> Result<Response> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        Error::Ipc(format!(
            "connect to {} failed: {e}",
            socket_path.display()
        ))
    })?;
    stream.write_all(&request.to_wire()).map_err(|e| {
        Error::Ipc(format!("write request to daemon failed: {e}"))
    })?;
    // Half-close the write side so the daemon's read loop returns
    // EOF after consuming our one line.  Without this, the daemon's
    // line-capped reader would block waiting for additional input
    // and the protocol would deadlock.
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|e| Error::Ipc(format!("shutdown write side: {e}")))?;
    let mut reader = BufReader::new(stream);
    let mut line = Vec::with_capacity(256);
    reader
        .read_until(b'\n', &mut line)
        .map_err(|e| Error::Ipc(format!("read response from daemon: {e}")))?;
    Response::parse(&line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_returns_ipc_error_when_socket_missing() {
        // No server.  Connect must fail.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.sock");
        let result = round_trip(&path, &Request::Status);
        match result {
            Ok(r) => panic!("expected Err, got Ok({r:?})"),
            Err(Error::Ipc(msg)) => assert!(msg.contains("connect")),
            Err(other) => panic!("expected Error::Ipc, got {other:?}"),
        }
    }
}
