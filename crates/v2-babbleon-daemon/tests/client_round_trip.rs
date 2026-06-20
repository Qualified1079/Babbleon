//! End-to-end tests of `round_trip` against an inline `DaemonState`.
//!
//! These tests used to live next to `client.rs` inside the daemon crate's
//! source tree.  When the wire protocol + client were carved out into
//! `v2-babbleon-daemon-protocol`, the round-trip-against-DaemonState
//! tests stayed behind: the protocol crate has no knowledge of state,
//! materialisation, or wordlists, and pulling those in would re-create
//! the audit-surface coupling the extraction was meant to break.
//!
//! The protocol crate keeps the connection-error test (no daemon needed)
//! and the wire-format roundtrip tests (no daemon needed).  Everything
//! that exercises the daemon as a peer lives here.

use std::io::BufReader;
use std::path::PathBuf;
use std::thread;

use babbleon_core_v2::{PerHostSecret, Wordlist};
use babbleon_daemon_protocol_v2::{round_trip, Request, Response};
use babbleon_daemon_v2::materialization::{MaterializationConfig, TrackedTool};
use babbleon_daemon_v2::socket::{bind_socket, handle_one_request};
use babbleon_daemon_v2::state::DaemonState;

fn make_state() -> DaemonState {
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

fn serve_one(socket_path: &std::path::Path) -> thread::JoinHandle<()> {
    let listener = bind_socket(socket_path).unwrap();
    thread::spawn(move || {
        let mut state = make_state();
        let (stream, _) = listener.accept().unwrap();
        let read_clone = stream.try_clone().unwrap();
        let mut reader = BufReader::new(read_clone);
        let mut writer = stream;
        handle_one_request(&mut state, &mut reader, &mut writer).unwrap();
        writer.shutdown(std::net::Shutdown::Both).unwrap();
    })
}

#[test]
fn status_round_trip_against_inline_server() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d.sock");
    let server = serve_one(&path);

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
    let server = serve_one(&path);

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
    let server = serve_one(&path);

    let resp = round_trip(&path, &Request::EmitActivatedTable).unwrap();
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
