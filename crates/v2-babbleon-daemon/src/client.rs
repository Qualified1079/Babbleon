//! Client side of the daemon socket — operator one-shots.
//!
//! # Infrastructure module
//!
//! The daemon binary supports two operating modes (see
//! [`crate::cli`]):
//!
//! - **Long-running mode** (`run`): bind a listener, serve requests
//!   in a loop.  Lives in [`crate::socket`].
//! - **One-shot subcommands** (`status`, `emit-activated-table`,
//!   `rotate-mapping`): connect to the running daemon's socket,
//!   send one request, read one response, exit.  Lives here.
//!
//! Splitting the client side into its own module keeps the
//! daemon-side serve loop ([`crate::socket`]) free of any code that
//! could conceivably be reused by an attacker who replays its
//! traffic.  The client side is also what an integration test
//! against a real daemon binary would use, so it ships as a public
//! library function.
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
/// the [`crate::cli::Cmd::Status`] / [`crate::cli::Cmd::EmitActivatedTable`]
/// / [`crate::cli::Cmd::RotateMapping`] one-shots in `main.rs`, and
/// by the integration tests in `tests/`.
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
    use crate::socket::{bind_socket, handle_one_request};
    use crate::state::DaemonState;
    use babbleon_core_v2::{PerHostSecret, Wordlist};
    use std::path::PathBuf;
    use std::thread;

    fn make_state() -> DaemonState {
        use crate::materialization::{MaterializationConfig, TrackedTool};
        DaemonState::new_without_materialization(
            PerHostSecret::from_bytes(&[2u8; 32]).unwrap(),
            Wordlist::english_baseline(),
            vec![
                TrackedTool {
                    name: "curl".into(),
                    real_path: PathBuf::from("/usr/bin/curl"),
                },
                TrackedTool {
                    name: "git".into(),
                    real_path: PathBuf::from("/usr/bin/git"),
                },
            ],
            MaterializationConfig {
                wrapper_dir: PathBuf::from("/wrappers"),
                honey_list_path: None,
                stale_list_path: None,
                trusted_ns_inode: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn status_round_trip_against_inline_server() {
        // Inline server: bind, accept once, handle, return.  Run on
        // a child thread so the test thread can connect and read.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.sock");
        let listener = bind_socket(&path).unwrap();

        let server = thread::spawn(move || {
            let mut state = make_state();
            let (stream, _) = listener.accept().unwrap();
            let read_clone = stream.try_clone().unwrap();
            let mut reader = BufReader::new(read_clone);
            let mut writer = stream;
            handle_one_request(&mut state, &mut reader, &mut writer).unwrap();
            writer.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let resp = round_trip(&path, &Request::Status).unwrap();
        match resp {
            Response::Status {
                epoch,
                tracked_count,
                ..
            } => {
                assert_eq!(epoch, 0);
                assert_eq!(tracked_count, 2);
            }
            other => panic!("expected Status, got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn rotate_round_trip_against_inline_server() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.sock");
        let listener = bind_socket(&path).unwrap();

        let server = thread::spawn(move || {
            let mut state = make_state();
            let (stream, _) = listener.accept().unwrap();
            let read_clone = stream.try_clone().unwrap();
            let mut reader = BufReader::new(read_clone);
            let mut writer = stream;
            handle_one_request(&mut state, &mut reader, &mut writer).unwrap();
            writer.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let resp = round_trip(&path, &Request::RotateMapping).unwrap();
        match resp {
            Response::Rotated { new_epoch } => assert_eq!(new_epoch, 1),
            other => panic!("expected Rotated, got {other:?}"),
        }
        server.join().unwrap();
    }

    #[test]
    fn emit_activated_table_round_trip_against_inline_server() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("d.sock");
        let listener = bind_socket(&path).unwrap();

        let server = thread::spawn(move || {
            let mut state = make_state();
            let (stream, _) = listener.accept().unwrap();
            let read_clone = stream.try_clone().unwrap();
            let mut reader = BufReader::new(read_clone);
            let mut writer = stream;
            handle_one_request(&mut state, &mut reader, &mut writer).unwrap();
            writer.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let resp =
            round_trip(&path, &Request::EmitActivatedTable).unwrap();
        match resp {
            Response::ActivatedTable { epoch, jsonl } => {
                assert_eq!(epoch, 0);
                let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
                    std::io::Cursor::new(&jsonl),
                )
                .unwrap();
                assert_eq!(parsed.entries.len(), 2);
            }
            other => panic!("expected ActivatedTable, got {other:?}"),
        }
        server.join().unwrap();
    }

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
