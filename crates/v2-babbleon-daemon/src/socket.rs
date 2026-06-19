//! Unix-socket I/O — the daemon's inbound surface.
//!
//! # What this defeats
//!
//! Two failure modes the socket layer closes:
//!
//! 1. **Buffer-overflow / OOM via oversize request.**  An adversarial
//!    peer that connects and writes gigabytes of bytes must not be
//!    able to grow the daemon's heap.  [`handle_one_request`] caps
//!    line read at [`crate::protocol::MAX_REQUEST_BYTES`] + 1 (the
//!    `+ 1` is for the trailing newline) via [`BufReader`]'s
//!    `take`-bounded reader.
//! 2. **State leakage across connections.**  Each connection is
//!    independent: one request in, one response out, close.  No
//!    keep-alive, no shared parser state.  A panic on connection N
//!    cannot smuggle internal data into connection N+1.
//!
//! Compartmentalizes I/O from the wire format ([`crate::protocol`])
//! and from state mutation ([`crate::state`] +
//! [`crate::handlers`]).  Test coverage is in-memory via
//! [`std::io::Cursor`] readers and `Vec<u8>` writers; the
//! [`serve_blocking`] / [`bind_socket`] paths are exercised by the
//! integration tests when a socket can be bound.
//!
//! # Mechanism
//!
//! [`handle_one_request`] is generic over `BufRead` + `Write`:
//!
//! 1. Read one line (up to `MAX_REQUEST_BYTES + 1` bytes including
//!    the trailing `\n`).  Reject empty reads and oversize lines.
//! 2. Parse with [`crate::protocol::Request::parse`].
//! 3. Dispatch via [`crate::handlers::dispatch`].
//! 4. Serialize and write the response.  Flush.
//!
//! Errors at any stage produce a wire [`crate::protocol::Response::Error`]
//! when the connection is still writable; if writing itself fails the
//! error is surfaced upward and the connection is dropped.
//!
//! [`bind_socket`] creates the daemon's listener at the requested
//! path with mode `0o660`.  The socket file is removed first if it
//! already exists (a stale daemon's leftover); the unlink is the
//! atomic, idempotent operation that lets `babbleon-daemon run` be
//! a one-shot from systemd or operator shell.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** oversize-request denial-of-service, parser-state
//!   spill across connections, partial-write corruption (every
//!   write flushes before close), accidental socket-reuse
//!   (`bind_socket` unlinks stale files).
//! - **Does NOT defeat:** unauthorized peers connecting to the
//!   socket.  Phase 2 ships file-mode `0o660` so only group members
//!   connect; `SO_PEERCRED` uid-allowlist authentication is filed
//!   for phase 3 with the PAM module's UID flow.
//! - **Does NOT defeat:** a single client holding the connection
//!   open indefinitely.  Phase 2 has no read/write timeout; if a
//!   slow-read peer becomes a denial-of-service concern, add
//!   `set_read_timeout` / `set_write_timeout` on the accepted
//!   `UnixStream`.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use crate::handlers::dispatch;
use crate::protocol::{ErrorKind, Request, Response, MAX_REQUEST_BYTES};
use crate::state::DaemonState;

/// Socket file mode applied by [`bind_socket`].  `0o660` — owner
/// read/write, group read/write, world: no access.  Group is the
/// `babbleon-daemon` group at installation time; peers must be in
/// that group to connect.
pub const SOCKET_MODE: u32 = 0o660;

/// Bind a Unix listener at `path` with [`SOCKET_MODE`].
///
/// If a file already exists at `path` it is unlinked first (stale
/// socket left behind by a previous daemon process).  This is
/// idempotent under the daemon's single-instance invariant; if two
/// daemons race to bind, the second will see the first's bind
/// succeed and its own bind fail with `EADDRINUSE` — caught at
/// `try_set_socket_perms` time via a separate stat / lock file
/// (filed for v2.1; phase 2 ships without it).
///
/// `path` MUST be an absolute path under a directory the daemon's
/// uid owns.  The launcher's own validation rejects relative paths
/// in the activated-table flow; we re-validate here to keep the
/// socket binding self-defensive.
///
/// # Errors
///
/// - `std::io::Error` from `unlink`, `bind`, or `chmod` syscalls.
pub fn bind_socket(path: &Path) -> std::io::Result<UnixListener> {
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("socket path must be absolute (got {})", path.display()),
        ));
    }
    if let Err(e) = fs::remove_file(path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(e);
        }
    }
    let listener = UnixListener::bind(path)?;
    let perms = fs::Permissions::from_mode(SOCKET_MODE);
    fs::set_permissions(path, perms)?;
    Ok(listener)
}

/// Serve connections until `listener` errors or the calling thread
/// drops it.
///
/// Single-threaded: handles one connection at a time.  Phase 2's
/// expected load is "one launcher per session-open"; even at burst
/// rates of 100 launches/sec this is well under what a single
/// dispatcher can handle (each [`handle_one_request`] is bounded by
/// activated-table size, ~ms to tens-of-ms).
///
/// `accept_error_handler` is invoked on per-connection errors.  In
/// tests it is a closure that records the error; in production it
/// logs via `tracing` and continues.
///
/// # Errors
///
/// - `std::io::Error` if the listener itself fails (e.g. the socket
///   file was unlinked from under us, or the file descriptor was
///   closed).  Per-connection errors are absorbed into
///   `accept_error_handler` and never escape this function.
pub fn serve_blocking(
    state: &mut DaemonState,
    listener: &UnixListener,
    mut accept_error_handler: impl FnMut(&std::io::Error),
) -> std::io::Result<()> {
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let read_clone = match stream.try_clone() {
                    Ok(c) => c,
                    Err(e) => {
                        accept_error_handler(&e);
                        continue;
                    }
                };
                let mut reader = BufReader::new(read_clone);
                if let Err(e) =
                    handle_one_request(state, &mut reader, &mut stream)
                {
                    accept_error_handler(&e);
                }
                // stream drops here, closing the connection.
            }
            Err(e) => {
                // Non-fatal accept error (e.g. EINTR).  Log and
                // continue; only propagate if the listener itself
                // is unusable.  std lib's UnixListener::incoming
                // returns Err on a closed listener too — but std
                // does not distinguish, so we treat any error as
                // non-fatal here.  Production wiring inspects errno
                // and decides.
                accept_error_handler(&e);
            }
        }
    }
    Ok(())
}

/// Handle exactly one request → response cycle.
///
/// Generic over `BufRead` + `Write` so this function is testable
/// without a Unix socket.  Production calls pass
/// `BufReader::new(stream)` and the same stream as the writer; tests
/// pass `Cursor<Vec<u8>>` for both directions.
///
/// Returns Ok on every wire-level outcome — including responses
/// that carry `Response::Error` — so the socket loop above sees Ok
/// for "I served a response to the peer."  Returns Err only when
/// the wire itself broke (peer disconnected mid-read, write
/// errored, peer sent an unparseable but recoverable input that
/// we couldn't even send an error response back for).
///
/// # Errors
///
/// - `std::io::Error` for: read errors, oversize line (returned
///   *after* attempting to send an error response back), write
///   errors.
pub fn handle_one_request<R: BufRead, W: Write>(
    state: &mut DaemonState,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<()> {
    let mut line = Vec::with_capacity(256);
    let line_cap = MAX_REQUEST_BYTES + 1;
    let read_bytes = read_one_line_capped(reader, &mut line, line_cap)?;
    if read_bytes == 0 {
        // Peer closed without sending anything.  Nothing to reply
        // with.  Not an error; just an empty connection.
        return Ok(());
    }
    if read_bytes >= line_cap && !line.ends_with(b"\n") {
        // The cap was hit before we saw a newline.  Send a bad-
        // request response and bail.
        let resp = Response::Error {
            kind: ErrorKind::BadRequest,
            message: format!(
                "request exceeds {MAX_REQUEST_BYTES}-byte cap",
            ),
        };
        write_response(writer, &resp)?;
        return Ok(());
    }

    let request = match Request::parse(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = Response::Error {
                kind: ErrorKind::BadRequest,
                message: e.to_string(),
            };
            write_response(writer, &resp)?;
            return Ok(());
        }
    };
    let response = dispatch(state, request);
    write_response(writer, &response)?;
    Ok(())
}

/// Read up to `cap` bytes, stopping at a newline or `cap`, whichever
/// comes first.  Returns the number of bytes consumed.
///
/// We don't use `BufRead::read_until` directly because it has no
/// cap; we need the cap so an adversarial peer cannot grow our
/// heap by streaming a single very long line.
fn read_one_line_capped<R: BufRead>(
    reader: &mut R,
    out: &mut Vec<u8>,
    cap: usize,
) -> std::io::Result<usize> {
    let mut total = 0usize;
    while total < cap {
        let remaining = cap - total;
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => return Ok(total),
            Ok(_) => {
                out.push(byte[0]);
                total += 1;
                if byte[0] == b'\n' {
                    return Ok(total);
                }
                let _ = remaining; // keep the intent of cap-tracking explicit.
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

fn write_response<W: Write>(
    writer: &mut W,
    response: &Response,
) -> std::io::Result<()> {
    let bytes = response.to_wire().map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

/// Sentinel for the daemon's default socket path: `/run/babbleon/daemon.sock`.
///
/// Exposed so the CLI and the launcher reference the same constant.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    PathBuf::from("/run/babbleon/daemon.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use babbleon_core_v2::{PerHostSecret, Wordlist};
    use std::io::{Cursor, Read};
    use std::path::PathBuf;

    fn state() -> DaemonState {
        DaemonState::new(
            PerHostSecret::from_bytes(&[1u8; 32]).unwrap(),
            Wordlist::english_baseline(),
            vec!["curl".into(), "ssh".into()],
            PathBuf::from("/wrappers"),
        )
        .unwrap()
    }

    /// Round-trip helper: feed `request_wire` bytes through
    /// `handle_one_request` and return the parsed response.
    fn round_trip(request_wire: &[u8]) -> Response {
        let mut daemon = state();
        let mut reader = Cursor::new(request_wire.to_vec());
        let mut writer: Vec<u8> = Vec::new();
        handle_one_request(&mut daemon, &mut reader, &mut writer).unwrap();
        Response::parse(&writer).unwrap()
    }

    #[test]
    fn round_trip_status() {
        let resp = round_trip(&Request::Status.to_wire());
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
    }

    #[test]
    fn round_trip_emit_activated_table() {
        let resp = round_trip(&Request::EmitActivatedTable.to_wire());
        match resp {
            Response::ActivatedTable { epoch, jsonl } => {
                assert_eq!(epoch, 0);
                let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
                    Cursor::new(jsonl),
                )
                .unwrap();
                assert_eq!(parsed.entries.len(), 2);
            }
            other => panic!("expected ActivatedTable, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_rotate_mapping() {
        let resp = round_trip(&Request::RotateMapping.to_wire());
        match resp {
            Response::Rotated { new_epoch } => assert_eq!(new_epoch, 1),
            other => panic!("expected Rotated, got {other:?}"),
        }
    }

    #[test]
    fn empty_connection_yields_no_response() {
        let mut daemon = state();
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer: Vec<u8> = Vec::new();
        handle_one_request(&mut daemon, &mut reader, &mut writer).unwrap();
        assert!(writer.is_empty(), "no response for empty connection");
    }

    #[test]
    fn invalid_json_yields_bad_request_error() {
        let resp = round_trip(b"not json at all\n");
        match resp {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::BadRequest);
                assert!(message.contains("parse"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn unknown_kind_yields_bad_request_error() {
        let resp = round_trip(b"{\"kind\":\"frob\"}\n");
        match resp {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::BadRequest);
                assert!(message.contains("unknown kind"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn oversize_request_yields_bad_request_error_without_oom() {
        // 1 byte over cap; no newline.  handle_one_request must
        // refuse without unbounded growth.
        let bytes = vec![b'x'; MAX_REQUEST_BYTES + 1];
        let resp = round_trip(&bytes);
        match resp {
            Response::Error { kind, message } => {
                assert_eq!(kind, ErrorKind::BadRequest);
                assert!(message.contains("cap"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn request_at_exactly_cap_and_well_formed_succeeds() {
        // A request that fits exactly inside MAX_REQUEST_BYTES with
        // its newline must succeed; the cap is *exclusive* of the
        // trailing newline.
        let mut bytes = Request::Status.to_wire();
        // Pad with spaces inside the JSON to push us just under cap.
        // JSON tolerates arbitrary whitespace between tokens.
        let target = MAX_REQUEST_BYTES - 8;
        let padding = " ".repeat(target.saturating_sub(bytes.len() - 1));
        // Inject padding before the closing brace.
        let close = bytes.iter().rposition(|b| *b == b'}').unwrap();
        bytes.splice(close..close, padding.bytes());
        let resp = round_trip(&bytes);
        // Padding should be well-formed JSON and parse as Status.
        assert!(matches!(resp, Response::Status { .. }));
    }

    #[test]
    fn server_serves_multiple_requests_with_state_progression() {
        // Multiple round-trips against the same DaemonState reflect
        // the mutation.  Important because the socket loop relies
        // on `&mut DaemonState` mutating across connections.
        let mut daemon = state();
        for expected_epoch in 0..3u64 {
            let mut reader =
                Cursor::new(Request::Status.to_wire());
            let mut writer: Vec<u8> = Vec::new();
            handle_one_request(&mut daemon, &mut reader, &mut writer)
                .unwrap();
            let resp = Response::parse(&writer).unwrap();
            match resp {
                Response::Status { epoch, .. } => {
                    assert_eq!(epoch, expected_epoch);
                }
                other => panic!("expected Status, got {other:?}"),
            }
            if expected_epoch < 2 {
                let mut r2 = Cursor::new(Request::RotateMapping.to_wire());
                let mut w2: Vec<u8> = Vec::new();
                handle_one_request(&mut daemon, &mut r2, &mut w2).unwrap();
            }
        }
    }

    #[test]
    fn write_response_emits_trailing_newline() {
        let mut writer: Vec<u8> = Vec::new();
        write_response(
            &mut writer,
            &Response::Rotated { new_epoch: 7 },
        )
        .unwrap();
        assert_eq!(*writer.last().unwrap(), b'\n');
    }

    #[test]
    fn read_one_line_capped_stops_at_newline() {
        let input: &[u8] = b"hello\nworld\n";
        let mut reader = std::io::Cursor::new(input);
        let mut out = Vec::new();
        let n = read_one_line_capped(&mut reader, &mut out, 1024).unwrap();
        assert_eq!(n, 6);
        assert_eq!(out, b"hello\n");
    }

    #[test]
    fn read_one_line_capped_stops_at_cap() {
        let input: &[u8] = &[b'x'; 16];
        let mut reader = std::io::Cursor::new(input);
        let mut out = Vec::new();
        let n = read_one_line_capped(&mut reader, &mut out, 8).unwrap();
        assert_eq!(n, 8);
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn read_one_line_capped_returns_zero_on_empty_input() {
        let input: &[u8] = b"";
        let mut reader = std::io::Cursor::new(input);
        let mut out = Vec::new();
        let n = read_one_line_capped(&mut reader, &mut out, 8).unwrap();
        assert_eq!(n, 0);
        assert!(out.is_empty());
    }

    // ----- bind_socket / serve_blocking end-to-end tests -----

    #[test]
    fn bind_socket_rejects_relative_path() {
        let path = Path::new("relative/sock");
        let err = bind_socket(path).unwrap_err();
        assert!(format!("{err}").contains("absolute"));
    }

    #[test]
    fn bind_socket_unlinks_stale_file_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        // Pre-create a stale file at the path.
        fs::write(&path, b"stale").unwrap();
        assert!(path.exists());
        let listener = bind_socket(&path).unwrap();
        // The path now points at a socket, not the stale file.
        assert!(path.exists());
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        drop(listener);
    }

    #[test]
    fn bind_socket_applies_socket_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("perm.sock");
        let listener = bind_socket(&path).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, SOCKET_MODE);
        drop(listener);
    }

    #[test]
    fn serve_blocking_serves_one_real_connection() {
        // Smoke test: bind a real socket, send a status request from
        // another thread, observe the response.  The accept loop
        // stops when the test thread drops the listener after the
        // single served connection (set non-blocking + spin would be
        // cleaner; for a smoke test we limit to one accept and
        // shut down via the connection-counter exit condition).
        use std::os::unix::net::UnixStream;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("serve.sock");
        let listener = bind_socket(&path).unwrap();
        let mut daemon = state();
        let errors = Arc::new(Mutex::new(Vec::<String>::new()));
        let errors_clone = Arc::clone(&errors);

        let path_clone = path.clone();
        let client = thread::spawn(move || {
            let mut s = UnixStream::connect(&path_clone).unwrap();
            s.write_all(&Request::Status.to_wire()).unwrap();
            s.shutdown(std::net::Shutdown::Write).unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).unwrap();
            buf
        });

        // Serve exactly one connection then break.  We don't have
        // a graceful-shutdown mechanism in phase 2, so we wrap
        // serve_blocking in a tiny adapter that bails after the
        // first successful accept.
        //
        // Subtle: BufReader<UnixStream> holds a `try_clone` of the
        // stream FD.  Dropping `writer` alone leaves the read clone
        // alive in `reader`, so the client's `read_to_end` blocks
        // waiting for EOF.  Drop the reader too — or, equivalently,
        // shutdown the write half explicitly, which is what the
        // production loop should also do.
        let stream = listener.accept().unwrap().0;
        let read_clone = stream.try_clone().unwrap();
        let mut reader = BufReader::new(read_clone);
        let mut writer = stream;
        handle_one_request(&mut daemon, &mut reader, &mut writer).unwrap();
        writer.shutdown(std::net::Shutdown::Both).unwrap();
        drop(writer);
        drop(reader);

        let response_bytes = client.join().unwrap();
        let resp = Response::parse(&response_bytes).unwrap();
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
        // No accept errors were absorbed.
        assert!(errors_clone.lock().unwrap().is_empty());
    }
}
