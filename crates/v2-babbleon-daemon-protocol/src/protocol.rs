//! Daemon socket protocol — request and response types, wire format.
//!
//! # What this defeats
//!
//! The daemon's Unix-socket surface is the only inbound channel into a
//! process that holds the per-host secret.  Without a strict, hand-
//! validated wire format, a malformed or hostile request could turn
//! the daemon into a deserialization gadget (via `serde::Deserialize`
//! producing un-zeroized `String`s, oversize allocations, or
//! field-substitution attacks via untrusted serde-derived types).
//!
//! This module is the only place that decides what bytes coming in on
//! the socket mean.  It carries no I/O — the socket layer
//! (`v2-babbleon-daemon::socket`) owns the readers and writers; this
//! module owns the parser and serializer.  Compartmentalizing the
//! wire format away from I/O lets the parse path be fuzz-tested
//! without spinning up a listener.
//!
//! # Mechanism
//!
//! The wire format is one JSON object per line, mirroring the
//! activated-table format (`babbleon_core_v2::activated_table`).
//! Each request line and each response line is hand-parsed via
//! `serde_json::Value` against a documented schema.  No
//! `#[derive(Deserialize)]` — see security-baseline rule 11.
//!
//! - Request: `{"kind": "<command>", ...}` — exactly one line, then
//!   the client half-closes the write side.
//! - Response: `{"ok": true|false, "kind": "<command>", ...}` — exactly
//!   one line.  For [`Response::ActivatedTable`] the JSONL body is
//!   embedded as a JSON-encoded string field.
//!
//! Size caps:
//!
//! - Request: [`MAX_REQUEST_BYTES`] (8 KiB; any plausible request is
//!   under 1 KiB).
//! - Response: bounded transitively by
//!   `babbleon_core_v2::MAX_TABLE_BYTES` (16 MiB).
//!
//! # Threat model boundaries
//!
//! - **Defeats:** untrusted-deserializer gadgets, oversize-request
//!   denial-of-service, schema-mismatch confused-deputy,
//!   missing-field silent defaults.
//! - **Does NOT defeat:** a peer holding the right uid/gid that the
//!   daemon's socket permissions are set up to admit.  Caller
//!   authentication (`SO_PEERCRED`, peer-uid check) lives in the
//!   socket layer; this module assumes a valid peer.

use crate::errors::{Error, Result};

/// Hard cap on request size on the wire.  Any legitimate request is
/// JSON with a small object, well under 1 KiB; the cap exists to
/// bound parser allocation under an adversarial peer.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Inbound request from a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Read-only state report.  Daemon answers with [`Response::Status`].
    Status,
    /// Build the per-epoch activated table and send it back inline.
    /// Daemon answers with [`Response::ActivatedTable`].
    EmitActivatedTable,
    /// Bump the epoch counter and rebuild the cached mapping.
    /// Daemon answers with [`Response::Rotated`].
    RotateMapping,
}

/// Outbound response from the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// State snapshot.
    Status {
        /// Current epoch number.
        epoch: u64,
        /// Number of tools the daemon currently scrambles.
        tracked_count: u64,
        /// Whether the per-host secret is loaded (vault unlocked).
        vault_locked: bool,
        /// `SystemTime::UNIX_EPOCH`-relative seconds at which the
        /// current mapping was last built.  `None` if no mapping has
        /// been built yet (vault still locked, or fresh state).
        last_rotation_unix_secs: Option<u64>,
    },
    /// The per-epoch activated table, serialized as JSONL.
    ActivatedTable {
        /// Epoch this table was built for (mirrors the JSONL
        /// header's `epoch` field).
        epoch: u64,
        /// Raw activated-table JSONL bytes.  Consumers feed this
        /// verbatim into
        /// `babbleon_core_v2::ActivatedTable::read_jsonl`.
        jsonl: Vec<u8>,
    },
    /// Rotation succeeded; the daemon now holds a mapping for
    /// `new_epoch`.
    Rotated {
        /// Epoch number the daemon advanced to.
        new_epoch: u64,
    },
    /// Daemon-side error.  Message does not leak secret material
    /// (security-baseline rule 13).
    Error {
        /// Coarse category for programmatic dispatch.
        kind: ErrorKind,
        /// Human-readable detail; safe to log.
        message: String,
    },
}

/// Coarse-grained error category in [`Response::Error`].
///
/// Mirrors the daemon's [`crate::Error`] variants on the wire, so
/// callers can branch on category without parsing prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    /// Vault is locked or vault load failed.
    Vault,
    /// Mapping construction failed.
    Mapping,
    /// Wrapper materialisation failed.
    Wrapper,
    /// Activated-table emission failed.
    ActivatedTable,
    /// IPC layer failure (should not appear in a well-formed reply
    /// but reserved for future framing-level errors).
    Ipc,
    /// Request was syntactically or semantically invalid.
    BadRequest,
    /// Internal daemon error.  Catch-all.
    Internal,
}

impl ErrorKind {
    fn as_wire_str(self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::Mapping => "mapping",
            Self::Wrapper => "wrapper",
            Self::ActivatedTable => "activated-table",
            Self::Ipc => "ipc",
            Self::BadRequest => "bad-request",
            Self::Internal => "internal",
        }
    }

    fn from_wire_str(s: &str) -> Self {
        match s {
            "vault" => Self::Vault,
            "mapping" => Self::Mapping,
            "wrapper" => Self::Wrapper,
            "activated-table" => Self::ActivatedTable,
            "ipc" => Self::Ipc,
            "bad-request" => Self::BadRequest,
            _ => Self::Internal,
        }
    }
}

impl Request {
    /// Parse one line of wire bytes into a `Request`.
    ///
    /// The input must be a single JSON object (no trailing data, no
    /// newlines past the object's closing brace).  Trailing
    /// whitespace including a single trailing newline is tolerated.
    ///
    /// # Errors
    ///
    /// - [`Error::Ipc`] for: oversize input, non-JSON bytes,
    ///   non-object top level, missing `kind`, unknown `kind`, or
    ///   any per-variant validation failure.
    pub fn parse(line: &[u8]) -> Result<Self> {
        if line.len() > MAX_REQUEST_BYTES {
            return Err(Error::Ipc(format!(
                "request exceeds {MAX_REQUEST_BYTES}-byte cap ({} bytes)",
                line.len()
            )));
        }
        let v: serde_json::Value = serde_json::from_slice(line)
            .map_err(|e| Error::Ipc(format!("request parse: {e}")))?;
        let obj = v.as_object().ok_or_else(|| {
            Error::Ipc("request: top-level value is not a JSON object".into())
        })?;
        let kind = obj
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::Ipc("request: missing or non-string `kind`".into())
            })?;
        match kind {
            "status" => Ok(Self::Status),
            "emit-activated-table" => Ok(Self::EmitActivatedTable),
            "rotate-mapping" => Ok(Self::RotateMapping),
            other => Err(Error::Ipc(format!("request: unknown kind {other:?}"))),
        }
    }

    /// Serialize this request to its one-line wire form (trailing
    /// `\n` included).
    ///
    /// Used by the operator-side `babbleon-daemon emit-activated-table`
    /// / `status` / `rotate-mapping` one-shots, by the rooted-test
    /// harness, and by `v2-babbleon-daemon::socket`-side tests.
    ///
    /// # Panics
    ///
    /// Does not panic in practice.  `serde_json::to_vec` only fails
    /// on serializer errors (non-stringifiable map keys, custom
    /// serializer abort); the JSON value built here is a fixed
    /// `{"kind": <static str>}` object that always serializes.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let kind = match self {
            Self::Status => "status",
            Self::EmitActivatedTable => "emit-activated-table",
            Self::RotateMapping => "rotate-mapping",
        };
        let v = serde_json::json!({ "kind": kind });
        let mut out = serde_json::to_vec(&v)
            .expect("serializing a JSON object cannot fail");
        out.push(b'\n');
        out
    }
}

impl Response {
    /// Serialize this response to its one-line wire form (trailing
    /// `\n` included).
    ///
    /// For [`Response::ActivatedTable`] the JSONL bytes are embedded
    /// as a JSON-encoded string; serde handles the per-byte escape.
    ///
    /// # Errors
    ///
    /// - [`Error::ActivatedTable`] if `jsonl` is not valid UTF-8 (the
    ///   activated-table writer only emits valid UTF-8, so this
    ///   indicates a daemon bug rather than a peer-supplied
    ///   problem).
    ///
    /// # Panics
    ///
    /// Does not panic in practice.  `serde_json::to_vec` builds
    /// against finite, well-formed JSON values constructed inline;
    /// the only failure mode is the UTF-8 check above, which is
    /// returned as an error.
    pub fn to_wire(&self) -> Result<Vec<u8>> {
        let v = match self {
            Self::Status {
                epoch,
                tracked_count,
                vault_locked,
                last_rotation_unix_secs,
            } => serde_json::json!({
                "ok": true,
                "kind": "status",
                "epoch": epoch,
                "tracked_count": tracked_count,
                "vault_locked": vault_locked,
                "last_rotation_unix_secs": last_rotation_unix_secs,
            }),
            Self::ActivatedTable { epoch, jsonl } => {
                let body = std::str::from_utf8(jsonl).map_err(|e| {
                    Error::ActivatedTable(format!(
                        "activated-table jsonl not valid UTF-8: {e}"
                    ))
                })?;
                serde_json::json!({
                    "ok": true,
                    "kind": "activated-table",
                    "epoch": epoch,
                    "jsonl": body,
                })
            }
            Self::Rotated { new_epoch } => serde_json::json!({
                "ok": true,
                "kind": "rotated",
                "new_epoch": new_epoch,
            }),
            Self::Error { kind, message } => serde_json::json!({
                "ok": false,
                "kind": "error",
                "error_kind": kind.as_wire_str(),
                "message": message,
            }),
        };
        let mut out = serde_json::to_vec(&v)
            .expect("serializing a JSON object cannot fail");
        out.push(b'\n');
        Ok(out)
    }

    /// Parse one line of wire bytes into a `Response`.
    ///
    /// Used by the operator-side one-shots and by the rooted-test
    /// harness; the daemon itself only writes responses, it does
    /// not read them.
    ///
    /// # Errors
    ///
    /// - [`Error::Ipc`] for parse / schema / validation failures.
    pub fn parse(line: &[u8]) -> Result<Self> {
        let v: serde_json::Value = serde_json::from_slice(line)
            .map_err(|e| Error::Ipc(format!("response parse: {e}")))?;
        let obj = v.as_object().ok_or_else(|| {
            Error::Ipc(
                "response: top-level value is not a JSON object".into(),
            )
        })?;
        let ok = obj
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| {
                Error::Ipc("response: missing or non-bool `ok`".into())
            })?;
        let kind = obj
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                Error::Ipc("response: missing or non-string `kind`".into())
            })?;
        if !ok {
            let error_kind = obj
                .get("error_kind")
                .and_then(serde_json::Value::as_str)
                .map_or(ErrorKind::Internal, ErrorKind::from_wire_str);
            let message = obj
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned();
            return Ok(Self::Error {
                kind: error_kind,
                message,
            });
        }
        match kind {
            "status" => parse_status(obj),
            "activated-table" => parse_activated_table(obj),
            "rotated" => parse_rotated(obj),
            other => Err(Error::Ipc(format!(
                "response: unknown kind {other:?}"
            ))),
        }
    }
}

fn parse_status(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Response> {
    let epoch = obj
        .get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            Error::Ipc("status response: missing/non-u64 epoch".into())
        })?;
    let tracked_count = obj
        .get("tracked_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            Error::Ipc(
                "status response: missing/non-u64 tracked_count".into(),
            )
        })?;
    let vault_locked = obj
        .get("vault_locked")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            Error::Ipc(
                "status response: missing/non-bool vault_locked".into(),
            )
        })?;
    // `last_rotation_unix_secs` is allowed to be null (no rotation yet).
    let last_rotation_unix_secs = match obj.get("last_rotation_unix_secs") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or_else(|| {
            Error::Ipc(
                "status response: last_rotation_unix_secs non-u64".into(),
            )
        })?),
    };
    Ok(Response::Status {
        epoch,
        tracked_count,
        vault_locked,
        last_rotation_unix_secs,
    })
}

fn parse_activated_table(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Response> {
    let epoch = obj
        .get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            Error::Ipc(
                "activated-table response: missing/non-u64 epoch".into(),
            )
        })?;
    let jsonl_str = obj
        .get("jsonl")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::Ipc(
                "activated-table response: missing/non-string jsonl".into(),
            )
        })?;
    Ok(Response::ActivatedTable {
        epoch,
        jsonl: jsonl_str.as_bytes().to_vec(),
    })
}

fn parse_rotated(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Response> {
    let new_epoch = obj
        .get("new_epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            Error::Ipc(
                "rotated response: missing/non-u64 new_epoch".into(),
            )
        })?;
    Ok(Response::Rotated { new_epoch })
}

#[cfg(test)]
mod tests {
    // `naive_bytecount` would have us pull in the `bytecount` crate
    // for a single test assertion that counts newlines in a tiny
    // buffer — overkill for non-hot test code.
    #![allow(clippy::naive_bytecount)]

    use super::*;

    // ----- Request side -----

    #[test]
    fn status_request_roundtrips() {
        let wire = Request::Status.to_wire();
        let parsed = Request::parse(&wire).unwrap();
        assert_eq!(parsed, Request::Status);
    }

    #[test]
    fn emit_activated_table_request_roundtrips() {
        let wire = Request::EmitActivatedTable.to_wire();
        let parsed = Request::parse(&wire).unwrap();
        assert_eq!(parsed, Request::EmitActivatedTable);
    }

    #[test]
    fn rotate_mapping_request_roundtrips() {
        let wire = Request::RotateMapping.to_wire();
        let parsed = Request::parse(&wire).unwrap();
        assert_eq!(parsed, Request::RotateMapping);
    }

    #[test]
    fn request_parse_rejects_unknown_kind() {
        let bytes = br#"{"kind":"frob"}"#;
        let err = Request::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("unknown kind"));
    }

    #[test]
    fn request_parse_rejects_missing_kind() {
        let bytes = br#"{"epoch":42}"#;
        let err = Request::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("missing or non-string"));
    }

    #[test]
    fn request_parse_rejects_non_string_kind() {
        let bytes = br#"{"kind":42}"#;
        let err = Request::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("missing or non-string"));
    }

    #[test]
    fn request_parse_rejects_non_object_top_level() {
        let bytes = br#"["status"]"#;
        let err = Request::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("not a JSON object"));
    }

    #[test]
    fn request_parse_rejects_invalid_json() {
        let bytes = b"not json at all";
        let err = Request::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    #[test]
    fn request_parse_rejects_oversize_input() {
        let bytes = vec![b'a'; MAX_REQUEST_BYTES + 1];
        let err = Request::parse(&bytes).unwrap_err();
        assert!(format!("{err}").contains("cap"));
    }

    #[test]
    fn request_parse_tolerates_trailing_whitespace() {
        let bytes = b"{\"kind\":\"status\"}\n";
        let parsed = Request::parse(bytes).unwrap();
        assert_eq!(parsed, Request::Status);
    }

    #[test]
    fn request_wire_format_is_one_line() {
        for r in [
            Request::Status,
            Request::EmitActivatedTable,
            Request::RotateMapping,
        ] {
            let wire = r.to_wire();
            assert_eq!(
                wire.iter().filter(|b| **b == b'\n').count(),
                1,
                "wire form must contain exactly one newline: {wire:?}",
            );
            assert_eq!(*wire.last().unwrap(), b'\n');
        }
    }

    // ----- Response side -----

    #[test]
    fn status_response_roundtrips() {
        let r = Response::Status {
            epoch: 7,
            tracked_count: 12,
            vault_locked: false,
            last_rotation_unix_secs: Some(1_700_000_000),
        };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn status_response_with_null_last_rotation_roundtrips() {
        let r = Response::Status {
            epoch: 0,
            tracked_count: 0,
            vault_locked: true,
            last_rotation_unix_secs: None,
        };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn activated_table_response_roundtrips() {
        let jsonl = b"{\"epoch\":42,\"honey\":[]}\n{\"scrambled\":\"abc\",\"wrapper_path\":\"/wrap\"}\n";
        let r = Response::ActivatedTable {
            epoch: 42,
            jsonl: jsonl.to_vec(),
        };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn activated_table_response_preserves_jsonl_byte_for_byte() {
        // Payload contains every JSON-sensitive ASCII byte; we want
        // the round-trip to come back exactly as it went in.  Catches
        // any encoder that "helpfully" normalises the JSONL.
        let jsonl = br#"{"epoch":1,"honey":["zink"]}
{"scrambled":"alpha","wrapper_path":"/wrap with spaces"}
{"scrambled":"beta","wrapper_path":"/wrap\\backslash"}
"#;
        let r = Response::ActivatedTable {
            epoch: 1,
            jsonl: jsonl.to_vec(),
        };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        let Response::ActivatedTable {
            jsonl: parsed_bytes,
            ..
        } = parsed
        else {
            panic!("expected ActivatedTable");
        };
        assert_eq!(parsed_bytes, jsonl);
    }

    #[test]
    fn rotated_response_roundtrips() {
        let r = Response::Rotated { new_epoch: 99 };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn error_response_roundtrips_for_every_kind() {
        for kind in [
            ErrorKind::Vault,
            ErrorKind::Mapping,
            ErrorKind::Wrapper,
            ErrorKind::ActivatedTable,
            ErrorKind::Ipc,
            ErrorKind::BadRequest,
            ErrorKind::Internal,
        ] {
            let r = Response::Error {
                kind,
                message: "explanatory".into(),
            };
            let wire = r.to_wire().unwrap();
            let parsed = Response::parse(&wire).unwrap();
            assert_eq!(parsed, r);
        }
    }

    #[test]
    fn error_response_unknown_kind_decodes_to_internal() {
        let bytes = br#"{"ok":false,"kind":"error","error_kind":"who-knows","message":"x"}"#;
        let parsed = Response::parse(bytes).unwrap();
        assert_eq!(
            parsed,
            Response::Error {
                kind: ErrorKind::Internal,
                message: "x".into(),
            }
        );
    }

    #[test]
    fn response_parse_rejects_missing_ok() {
        let bytes = br#"{"kind":"status","epoch":0}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("missing or non-bool `ok`"));
    }

    #[test]
    fn response_parse_rejects_missing_kind() {
        let bytes = br#"{"ok":true,"epoch":0}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("missing or non-string `kind`"));
    }

    #[test]
    fn response_parse_rejects_unknown_kind() {
        let bytes = br#"{"ok":true,"kind":"frob"}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("unknown kind"));
    }

    #[test]
    fn response_parse_rejects_invalid_json() {
        let bytes = b"not json";
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("parse"));
    }

    #[test]
    fn response_wire_format_is_one_line() {
        let r = Response::Status {
            epoch: 0,
            tracked_count: 0,
            vault_locked: true,
            last_rotation_unix_secs: None,
        };
        let wire = r.to_wire().unwrap();
        assert_eq!(wire.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(*wire.last().unwrap(), b'\n');
    }

    #[test]
    fn error_kind_wire_str_roundtrips_for_every_kind() {
        for kind in [
            ErrorKind::Vault,
            ErrorKind::Mapping,
            ErrorKind::Wrapper,
            ErrorKind::ActivatedTable,
            ErrorKind::Ipc,
            ErrorKind::BadRequest,
            ErrorKind::Internal,
        ] {
            let s = kind.as_wire_str();
            assert_eq!(ErrorKind::from_wire_str(s), kind);
        }
    }
}
