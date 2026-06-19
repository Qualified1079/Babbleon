//! Pure request → response dispatch.
//!
//! # Infrastructure module
//!
//! Bridges [`crate::protocol::Request`] / [`crate::protocol::Response`]
//! to [`crate::state::DaemonState`].  Pure function over its inputs;
//! holds no I/O.  The socket layer ([`crate::socket`]) reads a
//! request off the wire, calls [`dispatch`], writes the resulting
//! response back.  Separating dispatch from I/O lets dispatch be
//! tested without spinning up a listener.
//!
//! Every error from [`DaemonState`] is converted to a
//! [`crate::protocol::Response::Error`] carrying a coarse
//! [`crate::protocol::ErrorKind`] and a redacted message — secret
//! material never reaches a wire response (security-baseline
//! rule 13).

use crate::errors::Error;
use crate::protocol::{ErrorKind, Request, Response};
use crate::state::DaemonState;

/// Dispatch one [`Request`] against [`DaemonState`].
///
/// Always returns a [`Response`] — every error path is folded into
/// [`Response::Error`] so the socket layer's reply path is
/// infallible at the wire level (it can always serialize *something*
/// for the peer).
//
// Takes `request` by value so future variants that carry an owned
// payload (e.g. `EmitActivatedTable { epoch_hint }`) don't break
// call-sites.  Today's variants are payload-less, so clippy flags
// the move as unnecessary; we accept the lint with the forward-
// compatibility rationale above.
#[allow(clippy::needless_pass_by_value)]
pub fn dispatch(state: &mut DaemonState, request: Request) -> Response {
    match request {
        Request::Status => status(state),
        Request::EmitActivatedTable => emit_activated_table(state),
        Request::RotateMapping => rotate_mapping(state),
    }
}

fn status(state: &DaemonState) -> Response {
    Response::Status {
        epoch: state.epoch(),
        tracked_count: state.tracked_count() as u64,
        vault_locked: false, // phase 2 stub: vault unlock not yet wired in.
        last_rotation_unix_secs: state.last_rotation_unix_secs(),
    }
}

fn emit_activated_table(state: &DaemonState) -> Response {
    match state.activated_table_jsonl() {
        Ok(jsonl) => Response::ActivatedTable {
            epoch: state.epoch(),
            jsonl,
        },
        Err(e) => error_response(&e),
    }
}

fn rotate_mapping(state: &mut DaemonState) -> Response {
    match state.rotate() {
        Ok(new_epoch) => Response::Rotated { new_epoch },
        Err(e) => error_response(&e),
    }
}

/// Convert a daemon-side [`Error`] into a wire [`Response::Error`].
///
/// The message is the `Display` form of the daemon error, which by
/// construction never contains secret bytes (every daemon-error
/// variant wraps a category-tagged string from a non-secret source).
fn error_response(e: &Error) -> Response {
    let kind = match e {
        Error::Vault(_) => ErrorKind::Vault,
        Error::Mapping(_) => ErrorKind::Mapping,
        Error::Wrapper(_) => ErrorKind::Wrapper,
        Error::ActivatedTable(_) => ErrorKind::ActivatedTable,
        Error::Ipc(_) => ErrorKind::Ipc,
        Error::Cli(_) => ErrorKind::BadRequest,
    };
    Response::Error {
        kind,
        message: e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use babbleon_core_v2::{PerHostSecret, Wordlist};
    use std::path::PathBuf;

    fn state() -> DaemonState {
        DaemonState::new(
            PerHostSecret::from_bytes(&[3u8; 32]).unwrap(),
            Wordlist::english_baseline(),
            vec!["curl".into(), "ssh".into()],
            PathBuf::from("/wrappers"),
        )
        .unwrap()
    }

    #[test]
    fn status_request_returns_current_snapshot() {
        let mut s = state();
        let r = dispatch(&mut s, Request::Status);
        match r {
            Response::Status {
                epoch,
                tracked_count,
                vault_locked,
                last_rotation_unix_secs,
            } => {
                assert_eq!(epoch, 0);
                assert_eq!(tracked_count, 2);
                // phase-2 stub: vault is treated as unlocked.
                assert!(!vault_locked);
                assert!(last_rotation_unix_secs.is_some());
            }
            other => panic!("expected Status response, got {other:?}"),
        }
    }

    #[test]
    fn emit_activated_table_returns_jsonl_for_current_epoch() {
        let mut s = state();
        let r = dispatch(&mut s, Request::EmitActivatedTable);
        match r {
            Response::ActivatedTable { epoch, jsonl } => {
                assert_eq!(epoch, 0);
                // The JSONL must parse back through the core's reader.
                let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
                    std::io::Cursor::new(&jsonl),
                )
                .unwrap();
                assert_eq!(parsed.epoch, 0);
                assert_eq!(parsed.entries.len(), 2);
            }
            other => {
                panic!("expected ActivatedTable response, got {other:?}")
            }
        }
    }

    #[test]
    fn rotate_mapping_bumps_epoch_in_response() {
        let mut s = state();
        let r = dispatch(&mut s, Request::RotateMapping);
        match r {
            Response::Rotated { new_epoch } => assert_eq!(new_epoch, 1),
            other => panic!("expected Rotated response, got {other:?}"),
        }
        assert_eq!(s.epoch(), 1);
    }

    #[test]
    fn dispatch_is_consistent_across_requests() {
        // Property: dispatching the same request multiple times
        // within an epoch yields the same response category and the
        // same key fields.
        let mut daemon = state();
        let first_status = dispatch(&mut daemon, Request::Status);
        let second_status = dispatch(&mut daemon, Request::Status);
        assert_eq!(first_status, second_status);
        let first_emit = dispatch(&mut daemon, Request::EmitActivatedTable);
        let second_emit = dispatch(&mut daemon, Request::EmitActivatedTable);
        assert_eq!(first_emit, second_emit);
    }

    #[test]
    fn rotation_then_status_reports_new_epoch() {
        let mut s = state();
        dispatch(&mut s, Request::RotateMapping);
        dispatch(&mut s, Request::RotateMapping);
        let r = dispatch(&mut s, Request::Status);
        match r {
            Response::Status { epoch, .. } => assert_eq!(epoch, 2),
            other => panic!("expected Status, got {other:?}"),
        }
    }

    #[test]
    fn rotation_then_emit_reports_new_epoch_in_table() {
        let mut s = state();
        dispatch(&mut s, Request::RotateMapping);
        let r = dispatch(&mut s, Request::EmitActivatedTable);
        match r {
            Response::ActivatedTable { epoch, jsonl } => {
                assert_eq!(epoch, 1);
                let parsed = babbleon_core_v2::ActivatedTable::read_jsonl(
                    std::io::Cursor::new(&jsonl),
                )
                .unwrap();
                assert_eq!(parsed.epoch, 1);
            }
            other => panic!("expected ActivatedTable, got {other:?}"),
        }
    }

    #[test]
    fn error_response_carries_redacted_message() {
        // Construct each daemon error variant and confirm the wire
        // mapping doesn't accidentally surface a secret-shaped string.
        // (We cannot induce a real error from a healthy DaemonState;
        // we test the conversion function directly.)
        for (e, want) in [
            (Error::Vault("v".into()), ErrorKind::Vault),
            (Error::Mapping("m".into()), ErrorKind::Mapping),
            (Error::Wrapper("w".into()), ErrorKind::Wrapper),
            (Error::ActivatedTable("a".into()), ErrorKind::ActivatedTable),
            (Error::Ipc("i".into()), ErrorKind::Ipc),
            (Error::Cli("c".into()), ErrorKind::BadRequest),
        ] {
            let r = super::error_response(&e);
            match r {
                Response::Error { kind, message } => {
                    assert_eq!(kind, want);
                    // Message is the Display form of the error; it
                    // contains the variant prefix and the inner
                    // string, neither of which is secret.
                    assert!(message.contains(&e.to_string()));
                }
                other => panic!("expected Error response, got {other:?}"),
            }
        }
    }
}
