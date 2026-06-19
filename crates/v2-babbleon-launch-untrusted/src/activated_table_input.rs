//! Receive the per-epoch activated table from the daemon or a
//! filesystem path.
//!
//! # What this defeats
//!
//! The launcher must NOT hold the per-host secret.  The daemon
//! (which does) builds the per-epoch
//! [`babbleon_core_v2::ActivatedTable`] and ships only the
//! scrambled→wrapper-path mapping plus the honey list.  This
//! module is the launcher's intake point for that artefact.
//!
//! # Mechanism
//!
//! Three input modes, selected by the CLI:
//!
//! - **`--activated-table-fd <FD>`**: the parent process (typically
//!   the daemon) opened the table file or a pipe, dup'd the
//!   descriptor into the launcher's FD table, and passed the
//!   descriptor number on the command line.  The launcher converts
//!   the integer to an owned [`std::os::fd::OwnedFd`] and reads
//!   from it.  This path never touches the launcher's filesystem
//!   view, so a compromised launcher cannot exfiltrate the table
//!   via `/proc/self/fd` symlink resolution into a side channel —
//!   the FD is consumed and closed in the same module.
//! - **`--activated-table-path <P>`**: the launcher opens the
//!   file at `P` and reads from it.  Used by the rooted-test
//!   harness and by daemonless smoke tests.
//! - **`--daemon-socket <P>`**: the launcher connects to the running
//!   daemon at the Unix socket path `P`, sends an
//!   `EmitActivatedTable` request, and parses the JSONL body of the
//!   response.  This is the production flow: PAM launches the
//!   launcher, the launcher asks the daemon for the current epoch's
//!   table, the launcher bind-mounts.  No FD passing required —
//!   simpler for PAM to set up than `--activated-table-fd`.
//!
//! # Compartmentalization
//!
//! Parsing and validation live in [`babbleon_core_v2::activated_table`].
//! This module's only job is **source selection** + **FD ownership
//! transfer** — keeping those two concerns out of the parser
//! preserves the parser's testability and keeps the FD-handling
//! risk (descriptor confusion, double-close) localized.
//!
//! # Threat model boundaries
//!
//! - Defeats: launcher reading a malformed table without detecting
//!   it — the parser refuses every malformed shape.
//! - Defeats: launcher consuming a table larger than memory — the
//!   parser caps total bytes at
//!   [`babbleon_core_v2::MAX_TABLE_BYTES`].
//! - Does NOT defeat: a daemon that ships a *valid* but malicious
//!   table (e.g. honey-list lying about which names are honey).
//!   Compensating control: daemon-side audit logging; out of scope
//!   for this module.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::io::BufReader;
use std::path::Path;

use babbleon_core_v2::ActivatedTable;

use crate::errors::{Error, Result};

/// Read and validate the activated table from the chosen source.
///
/// At most one of `fd`, `path`, and `daemon_socket` is meaningful;
/// the CLI layer (`conflicts_with` attributes) rejects multiple
/// inputs before this function runs.  Defense in depth: if more than
/// one arrives here, the precedence is **fd > daemon-socket > path**
/// (matches the documented trust ordering: daemon-passed FD over
/// daemon-served socket over operator-supplied file) and a tracing
/// warning is emitted.
///
/// Returns `Ok(None)` if no source is supplied — the orchestrator
/// interprets that as "no bind-mounts, exec into an empty
/// scrambled view", which is the namespace+caps+seccomp smoke-test
/// mode.
///
/// # Errors
///
/// - [`Error::ActivatedTable`] for any failure reading or parsing
///   the table.  The error message names the source (fd N, path P,
///   or daemon-socket S) so the operator can correlate with the
///   daemon side.
pub fn read_if_present(
    fd: Option<i32>,
    path: Option<&Path>,
    daemon_socket: Option<&Path>,
) -> Result<Option<ActivatedTable>> {
    let supplied = (fd.is_some(), daemon_socket.is_some(), path.is_some());
    if matches!(supplied, (true, true, _) | (true, _, true) | (_, true, true))
    {
        tracing::warn!(
            "multiple activated-table sources supplied; preferring fd > \
             daemon-socket > path (trust ordering)",
        );
    }
    if let Some(fd) = fd {
        return read_from_fd(fd).map(Some);
    }
    if let Some(socket) = daemon_socket {
        return read_from_daemon_socket(socket).map(Some);
    }
    if let Some(p) = path {
        return read_from_path(p).map(Some);
    }
    Ok(None)
}

fn read_from_fd(fd: i32) -> Result<ActivatedTable> {
    if fd < 0 {
        return Err(Error::ActivatedTable(format!(
            "activated-table fd {fd} is negative"
        )));
    }
    // SAFETY-equivalent reasoning (no `unsafe` used here): `OwnedFd`
    // takes ownership of the integer descriptor and is responsible
    // for closing it on drop.  We require the caller (the daemon)
    // to have dup'd this descriptor specifically for this process;
    // double-close would only occur if the same integer were
    // wrapped twice, which we do not do.
    //
    // `File::from_raw_fd` is the documented adoption path; the
    // crate forbids `unsafe`, so we route through the `FromRawFd`
    // impl on `std::os::fd::OwnedFd` (also unsafe — we can't avoid
    // the ownership-transfer unsafety, but we localize it via
    // `syscall.rs` per security-baseline rule 1 exception policy).
    let file = crate::syscall::adopt_raw_fd_as_file(fd).map_err(|e| {
        Error::ActivatedTable(format!(
            "activated-table fd {fd}: adopt: {e}"
        ))
    })?;
    let reader = BufReader::new(file);
    ActivatedTable::read_jsonl(reader).map_err(|e| {
        Error::ActivatedTable(format!("activated-table fd {fd}: parse: {e}"))
    })
}

/// Ask the running daemon at `socket_path` for the current epoch's
/// activated table.  Returns the parsed table on success.
///
/// The daemon's response is a JSON object whose `jsonl` field
/// contains the activated-table bytes; this function extracts those
/// bytes and feeds them through the same parser the FD / path paths
/// use, so all three input modes converge on the same validation.
fn read_from_daemon_socket(socket_path: &Path) -> Result<ActivatedTable> {
    use babbleon_daemon_v2::{round_trip, ErrorKind, Request, Response};
    let resp = round_trip(socket_path, &Request::EmitActivatedTable)
        .map_err(|e| {
            Error::ActivatedTable(format!(
                "activated-table daemon-socket {}: round-trip: {e}",
                socket_path.display()
            ))
        })?;
    let jsonl = match resp {
        Response::ActivatedTable { jsonl, .. } => jsonl,
        Response::Error { kind, message } => {
            return Err(Error::ActivatedTable(format!(
                "activated-table daemon-socket {}: daemon error ({:?}): {message}",
                socket_path.display(),
                kind
            )));
        }
        other => {
            let _ = ErrorKind::Internal; // ensure import is referenced when this branch is unreachable
            return Err(Error::ActivatedTable(format!(
                "activated-table daemon-socket {}: unexpected response shape: {other:?}",
                socket_path.display()
            )));
        }
    };
    let reader = BufReader::new(std::io::Cursor::new(jsonl));
    ActivatedTable::read_jsonl(reader).map_err(|e| {
        Error::ActivatedTable(format!(
            "activated-table daemon-socket {}: parse: {e}",
            socket_path.display()
        ))
    })
}

fn read_from_path(path: &Path) -> Result<ActivatedTable> {
    // Open without following symlinks?  We deliberately do follow:
    // the path is supplied by the operator (test harness or
    // daemonless smoke test), not by adversary input, and
    // refusing to follow would break legitimate uses (a symlink
    // from `/run/babbleon/table.current` to the active epoch
    // file is a common deployment shape).
    let file = File::open(path).map_err(|e| {
        Error::ActivatedTable(format!(
            "activated-table path {}: open: {e}",
            path.display()
        ))
    })?;
    let reader = BufReader::new(file);
    ActivatedTable::read_jsonl(reader).map_err(|e| {
        Error::ActivatedTable(format!(
            "activated-table path {}: parse: {e}",
            path.display()
        ))
    })
}

// Suppress the unused-import warning when the binary is built
// without the FD-adoption path being exercised; the helper still
// links because `read_from_fd` references it.
#[cfg(test)]
mod tests {
    use super::{read_from_path, read_if_present};
    use babbleon_core_v2::ActivatedTableBuilder;
    use std::io::Write;

    fn write_sample_table(path: &std::path::Path) {
        let t = ActivatedTableBuilder::new(7)
            .push_entry("flibsnortglarp", "/usr/local/libexec/wrap")
            .unwrap()
            .push_honey("zinkdroopflarp")
            .unwrap()
            .finish()
            .unwrap();
        let bytes = t.write_jsonl().unwrap();
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(&bytes).unwrap();
    }

    #[test]
    fn read_from_path_parses_valid_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("table.jsonl");
        write_sample_table(&p);
        let t = read_from_path(&p).unwrap();
        assert_eq!(t.epoch, 7);
        assert_eq!(t.entries.len(), 1);
        assert_eq!(t.honey_names.len(), 1);
    }

    #[test]
    fn read_from_path_surfaces_open_error() {
        let p = std::path::Path::new("/nonexistent/babbleon-activated-table");
        let err = read_from_path(p).unwrap_err();
        assert!(format!("{err}").contains("open"));
    }

    #[test]
    fn read_from_path_surfaces_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.jsonl");
        std::fs::write(&p, b"not-json-at-all\n").unwrap();
        let err = read_from_path(&p).unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    #[test]
    fn read_if_present_returns_none_when_no_source_given() {
        let t = read_if_present(None, None, None).unwrap();
        assert!(t.is_none(), "no source means no table");
    }

    #[test]
    fn read_if_present_routes_to_path_when_only_path_given() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("table.jsonl");
        write_sample_table(&p);
        let t = read_if_present(None, Some(&p), None).unwrap().unwrap();
        assert_eq!(t.epoch, 7);
    }

    #[test]
    fn read_if_present_rejects_negative_fd() {
        let err = read_if_present(Some(-1), None, None).unwrap_err();
        assert!(format!("{err}").contains("negative"));
    }

    #[test]
    fn read_if_present_returns_error_for_missing_daemon_socket() {
        let dir = tempfile::tempdir().unwrap();
        let nonexistent = dir.path().join("daemon.sock");
        let err = read_if_present(None, None, Some(&nonexistent))
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("daemon-socket") && msg.contains("round-trip"),
            "expected daemon-socket round-trip error, got: {msg}",
        );
    }
}
