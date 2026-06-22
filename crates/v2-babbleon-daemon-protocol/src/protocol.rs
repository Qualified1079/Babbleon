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
use crate::unlock_secret::{UnlockSecret, UNLOCK_SECRET_HEX_LEN};

/// Hard cap on request size on the wire.  Any legitimate request is
/// JSON with a small object, well under 1 KiB; the cap exists to
/// bound parser allocation under an adversarial peer.
pub const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Number of whitespace compounds in the `WhitespaceCompounds`
/// response, mirroring `v2-babbleon-preprocessor`'s
/// `WHITESPACE_COMPOUND_COUNT`.
///
/// The protocol crate is independent of `v2-babbleon-preprocessor`
/// (the launcher and CLI must not transitively pick up preprocessor
/// surface they don't need).  Cross-crate agreement is enforced by
/// a compile-time `static_assertions`-style check on the
/// preprocessor side: if the preprocessor ever bumps its
/// `WhitespaceKind::ALL` count, the bump lands in the same commit
/// as the constant update here and a wire-format break is filed
/// in the same commit's HANDOFF entry.
pub const WHITESPACE_COMPOUND_COUNT_WIRE: usize = 5;

/// Reasonable upper bound on the byte length of a single whitespace
/// compound on the wire.
///
/// The preprocessor produces compounds of `COMPOUND_N = 4` words
/// from a wordlist whose longest entry in the English baseline is
/// under 50 bytes; the worst-case compound is well under 256 bytes.
/// The cap is defensive — a peer that supplies a 16-MiB single
/// compound to gum up the CLI's `from_compounds` validator must be
/// stopped at the protocol parser.
const WHITESPACE_COMPOUND_MAX_BYTES: usize = 1024;

/// Number of Python keyword compounds in the `KeywordCompounds`
/// response, mirroring `v2-babbleon-preprocessor`'s
/// `PYTHON_KEYWORD_COUNT` (Python 3.12 hard keywords).
///
/// As with [`WHITESPACE_COMPOUND_COUNT_WIRE`], the protocol crate
/// is independent of `v2-babbleon-preprocessor`; cross-crate
/// agreement is enforced by tests on both sides — if the
/// preprocessor's static list grows or shrinks (a hard-keyword set
/// is a wire-format break for layer 2), this constant updates in
/// the same commit and a HANDOFF entry records the break.
pub const PYTHON_KEYWORD_COMPOUND_COUNT_WIRE: usize = 35;

/// Reasonable upper bound on the byte length of a single keyword
/// compound on the wire.  Same rationale as
/// [`WHITESPACE_COMPOUND_MAX_BYTES`]; sized to comfortably hold any
/// 4-word compound from the v2 baseline wordlist while bounding a
/// hostile-peer allocation.
const KEYWORD_COMPOUND_MAX_BYTES: usize = 1024;

/// Inbound request from a peer.
///
/// `Clone` is derived because the proptest harness requires it
/// (see [`UnlockSecret`] module docs).  Production paths do not
/// clone requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// Read-only state report.  Daemon answers with [`Response::Status`].
    Status,
    /// Build the per-epoch activated table and send it back inline.
    /// Daemon answers with [`Response::ActivatedTable`].  Requires
    /// the vault to be unlocked; the daemon answers
    /// `Response::Error { kind: ErrorKind::Vault, ... }` otherwise.
    EmitActivatedTable,
    /// Bump the epoch counter and rebuild the cached mapping.
    /// Daemon answers with [`Response::Rotated`].  Requires the vault
    /// to be unlocked.
    RotateMapping,
    /// Transition the daemon from the `Locked` to the `Unlocked`
    /// state by installing the supplied per-host secret.
    ///
    /// The user-CLI has already performed the at-rest unwrap (age
    /// decrypt + Argon2id KDF, see `v2-babbleon-vault`) before issuing
    /// this request.  The daemon answers with [`Response::Unlocked`]
    /// on success or [`Response::Error`] (`ErrorKind::Vault`) if the
    /// daemon is already unlocked or the secret install failed.
    Unlock(UnlockSecret),
    /// Read the per-epoch whitespace compounds the daemon is
    /// currently serving.  Daemon answers with
    /// [`Response::WhitespaceCompounds`].  Requires the vault to be
    /// unlocked; the daemon answers `Response::Error
    /// { kind: ErrorKind::Vault, ... }` otherwise.
    ///
    /// Issued by the operator-facing `babbleon scramble` /
    /// `babbleon unscramble` subcommands so the CLI can locally
    /// derive a `WhitespaceWordlist` without ever holding the
    /// per-host secret.  Trust-tier-only — caller authentication
    /// (peer-uid check on the socket layer) gates the request.
    GetWhitespaceCompounds,
    /// Read the per-epoch Python-keyword compounds the daemon is
    /// currently serving (layer 2 — operator scramble).  Daemon
    /// answers with [`Response::KeywordCompounds`].  Requires the
    /// vault to be unlocked; the daemon answers `Response::Error
    /// { kind: ErrorKind::Vault, ... }` otherwise.
    ///
    /// Same trust-boundary as [`Self::GetWhitespaceCompounds`]:
    /// the daemon retains the per-host secret; only the HKDF-derived
    /// per-keyword compounds cross the socket.  Trust-tier-only —
    /// caller authentication (peer-uid check on the socket layer)
    /// gates the request.
    GetKeywordCompounds,
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
    /// Unlock succeeded; the daemon now holds the per-host secret in
    /// memory and the cached mapping is built for the returned
    /// `epoch`.  Read-only and mutator requests work after this
    /// point.
    Unlocked {
        /// Epoch number the daemon is now holding a mapping for.
        epoch: u64,
    },
    /// The daemon's per-epoch whitespace compounds.
    ///
    /// Indexed by `WhitespaceKind::ALL` slot order
    /// (`Newline`, `Space`, `Tab`, `IndentOpen`, `IndentClose`).
    /// The receiving CLI feeds `compounds` directly into
    /// `v2-babbleon-preprocessor::WhitespaceWordlist::from_compounds`.
    ///
    /// The compounds are secret-derived (HKDF over per-host secret +
    /// epoch) but not secret-equivalent: a worm that gets one epoch's
    /// compounds can scramble against that epoch but cannot recover
    /// the per-host secret.  Wire-side rotation (epoch bump)
    /// invalidates a leaked compound set.
    WhitespaceCompounds {
        /// Epoch the compounds were derived for.  Mirrors the
        /// `epoch` field of [`Self::Status`] when the daemon is
        /// unlocked.
        epoch: u64,
        /// Five compounds in `WhitespaceKind::ALL` slot order.
        /// Each is a non-empty ASCII-lowercase byte string; the
        /// receiver's `from_compounds` enforces the invariants
        /// against tampering on the local-socket path.
        compounds: [String; WHITESPACE_COMPOUND_COUNT_WIRE],
    },
    /// The daemon's per-epoch Python-keyword compounds (layer 2 —
    /// operator scramble).
    ///
    /// Indexed by `v2-babbleon-preprocessor::PYTHON_KEYWORDS` static
    /// order — `compounds[i]` is the per-epoch compound for the
    /// `i`-th keyword in `PYTHON_KEYWORDS`.  The receiving CLI feeds
    /// `compounds` directly into
    /// `v2-babbleon-preprocessor::KeywordWordlist::from_compounds`.
    ///
    /// Same secret-adjacency note as
    /// [`Self::WhitespaceCompounds`]: a worm that gets one epoch's
    /// compounds can scramble keywords against that epoch but cannot
    /// recover the per-host secret.  Wire-side rotation invalidates
    /// a leaked compound set.
    KeywordCompounds {
        /// Epoch the compounds were derived for.  Mirrors
        /// [`Self::Status`]'s `epoch` when the daemon is unlocked.
        epoch: u64,
        /// 35 compounds in `PYTHON_KEYWORDS` slot order.  Each is
        /// non-empty ASCII-lowercase; the receiver's
        /// `KeywordWordlist::from_compounds` enforces the
        /// invariants against tampering on the local-socket path.
        ///
        /// The fixed-size array is heap-boxed so the
        /// [`Response`] enum stays small (without the box this
        /// variant alone would inflate every `Response` value to
        /// ~848 bytes on the stack, dominating the discriminant +
        /// other variants).  Production paths consume the box
        /// exactly once via `*compounds` into
        /// `KeywordWordlist::from_compounds`.
        compounds: Box<[String; PYTHON_KEYWORD_COMPOUND_COUNT_WIRE]>,
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
            "unlock" => parse_unlock(obj),
            "get-whitespace-compounds" => Ok(Self::GetWhitespaceCompounds),
            "get-keyword-compounds" => Ok(Self::GetKeywordCompounds),
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
    /// serializer abort); the JSON values built here are fixed
    /// `{"kind": <static str>, ...}` objects that always serialize.
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let v = match self {
            Self::Status => serde_json::json!({ "kind": "status" }),
            Self::EmitActivatedTable => {
                serde_json::json!({ "kind": "emit-activated-table" })
            }
            Self::RotateMapping => {
                serde_json::json!({ "kind": "rotate-mapping" })
            }
            Self::Unlock(secret) => serde_json::json!({
                "kind": "unlock",
                "host_secret_hex": secret.to_hex_wire(),
            }),
            Self::GetWhitespaceCompounds => {
                serde_json::json!({ "kind": "get-whitespace-compounds" })
            }
            Self::GetKeywordCompounds => {
                serde_json::json!({ "kind": "get-keyword-compounds" })
            }
        };
        let mut out = serde_json::to_vec(&v)
            .expect("serializing a JSON object cannot fail");
        out.push(b'\n');
        out
    }
}

/// Parse an `unlock` request's `host_secret_hex` field into an
/// [`UnlockSecret`].
fn parse_unlock(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Request> {
    let hex_str = obj
        .get("host_secret_hex")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::Ipc(
                "unlock request: missing or non-string host_secret_hex".into(),
            )
        })?;
    // Defensive length guard: the cap is already enforced by
    // `MAX_REQUEST_BYTES`, but this gives a clean error message
    // distinct from the catch-all if a peer sends the wrong size.
    if hex_str.len() != UNLOCK_SECRET_HEX_LEN {
        return Err(Error::Ipc(format!(
            "unlock request: host_secret_hex length {} != required {UNLOCK_SECRET_HEX_LEN}",
            hex_str.len(),
        )));
    }
    let secret = UnlockSecret::from_hex_wire(hex_str)?;
    Ok(Request::Unlock(secret))
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
            Self::Unlocked { epoch } => serde_json::json!({
                "ok": true,
                "kind": "unlocked",
                "epoch": epoch,
            }),
            Self::WhitespaceCompounds { epoch, compounds } => {
                serde_json::json!({
                    "ok": true,
                    "kind": "whitespace-compounds",
                    "epoch": epoch,
                    "compounds": compounds,
                })
            }
            Self::KeywordCompounds { epoch, compounds } => {
                // serde_json's built-in `Serialize` impl for `[T;N]`
                // only covers `N <= 32`.  Pass a slice view so the
                // 35-element array serialises through the
                // slice-Serialize impl instead of the fixed-size-
                // array one.
                serde_json::json!({
                    "ok": true,
                    "kind": "keyword-compounds",
                    "epoch": epoch,
                    "compounds": compounds.as_slice(),
                })
            }
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
            "unlocked" => parse_unlocked(obj),
            "whitespace-compounds" => parse_whitespace_compounds(obj),
            "keyword-compounds" => parse_keyword_compounds(obj),
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

fn parse_unlocked(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Response> {
    let epoch = obj
        .get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            Error::Ipc(
                "unlocked response: missing/non-u64 epoch".into(),
            )
        })?;
    Ok(Response::Unlocked { epoch })
}

/// Parse a `whitespace-compounds` response into a typed
/// [`Response::WhitespaceCompounds`].
///
/// Strict on:
/// - `epoch` present + u64.
/// - `compounds` present + JSON array.
/// - Exactly `WHITESPACE_COMPOUND_COUNT_WIRE` entries.
/// - Each entry a string with length in
///   `1..=WHITESPACE_COMPOUND_MAX_BYTES`.
///
/// Leaves structural-invariant checking (ASCII-lowercase, pairwise
/// distinct) to the consumer's
/// `WhitespaceWordlist::from_compounds`.  Keeps the parser focused
/// on the wire schema; layering responsibility avoids two crates
/// disagreeing on what counts as valid.
fn parse_whitespace_compounds(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Response> {
    let epoch = obj
        .get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            Error::Ipc(
                "whitespace-compounds response: missing/non-u64 epoch".into(),
            )
        })?;
    let arr = obj
        .get("compounds")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::Ipc(
                "whitespace-compounds response: missing/non-array compounds"
                    .into(),
            )
        })?;
    if arr.len() != WHITESPACE_COMPOUND_COUNT_WIRE {
        return Err(Error::Ipc(format!(
            "whitespace-compounds response: compounds array length {} != \
             expected {WHITESPACE_COMPOUND_COUNT_WIRE}",
            arr.len(),
        )));
    }
    // Build the fixed-size array.  Use array::try_from_fn equivalent
    // via a Vec roundtrip to keep the loop explicit (no nightly
    // try_from_fn yet).
    let mut compounds: Vec<String> = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let s = entry.as_str().ok_or_else(|| {
            Error::Ipc(format!(
                "whitespace-compounds response: entry {i} is not a string"
            ))
        })?;
        if s.is_empty() {
            return Err(Error::Ipc(format!(
                "whitespace-compounds response: entry {i} is empty"
            )));
        }
        if s.len() > WHITESPACE_COMPOUND_MAX_BYTES {
            return Err(Error::Ipc(format!(
                "whitespace-compounds response: entry {i} length {} exceeds \
                 cap {WHITESPACE_COMPOUND_MAX_BYTES}",
                s.len(),
            )));
        }
        compounds.push(s.to_owned());
    }
    // Vec -> fixed-size array.  The length check above guarantees
    // this conversion succeeds.
    let compounds: [String; WHITESPACE_COMPOUND_COUNT_WIRE] = compounds
        .try_into()
        .map_err(|_| {
            Error::Ipc(
                "whitespace-compounds response: internal length mismatch"
                    .into(),
            )
        })?;
    Ok(Response::WhitespaceCompounds { epoch, compounds })
}

/// Parse a `keyword-compounds` response into a typed
/// [`Response::KeywordCompounds`].
///
/// Strict on:
/// - `epoch` present + u64.
/// - `compounds` present + JSON array.
/// - Exactly [`PYTHON_KEYWORD_COMPOUND_COUNT_WIRE`] entries.
/// - Each entry a string with length in
///   `1..=KEYWORD_COMPOUND_MAX_BYTES`.
///
/// Leaves structural-invariant checking (ASCII-lowercase, pairwise
/// distinct) to the consumer's
/// `KeywordWordlist::from_compounds`.  Keeps the parser focused on
/// the wire schema; layering responsibility avoids two crates
/// disagreeing on what counts as valid.
fn parse_keyword_compounds(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<Response> {
    let epoch = obj
        .get("epoch")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            Error::Ipc(
                "keyword-compounds response: missing/non-u64 epoch".into(),
            )
        })?;
    let arr = obj
        .get("compounds")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            Error::Ipc(
                "keyword-compounds response: missing/non-array compounds"
                    .into(),
            )
        })?;
    if arr.len() != PYTHON_KEYWORD_COMPOUND_COUNT_WIRE {
        return Err(Error::Ipc(format!(
            "keyword-compounds response: compounds array length {} != \
             expected {PYTHON_KEYWORD_COMPOUND_COUNT_WIRE}",
            arr.len(),
        )));
    }
    let mut compounds: Vec<String> = Vec::with_capacity(arr.len());
    for (i, entry) in arr.iter().enumerate() {
        let s = entry.as_str().ok_or_else(|| {
            Error::Ipc(format!(
                "keyword-compounds response: entry {i} is not a string"
            ))
        })?;
        if s.is_empty() {
            return Err(Error::Ipc(format!(
                "keyword-compounds response: entry {i} is empty"
            )));
        }
        if s.len() > KEYWORD_COMPOUND_MAX_BYTES {
            return Err(Error::Ipc(format!(
                "keyword-compounds response: entry {i} length {} exceeds \
                 cap {KEYWORD_COMPOUND_MAX_BYTES}",
                s.len(),
            )));
        }
        compounds.push(s.to_owned());
    }
    let compounds: [String; PYTHON_KEYWORD_COMPOUND_COUNT_WIRE] = compounds
        .try_into()
        .map_err(|_| {
            Error::Ipc(
                "keyword-compounds response: internal length mismatch"
                    .into(),
            )
        })?;
    Ok(Response::KeywordCompounds {
        epoch,
        compounds: Box::new(compounds),
    })
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
        let unlock = Request::Unlock(
            UnlockSecret::from_bytes(&[0x33; 32]).unwrap(),
        );
        for r in [
            Request::Status,
            Request::EmitActivatedTable,
            Request::RotateMapping,
            unlock,
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

    // ----- Unlock request -----

    #[test]
    fn unlock_request_roundtrips() {
        let secret = UnlockSecret::from_bytes(&[0x77; 32]).unwrap();
        let req = Request::Unlock(secret);
        let wire = req.to_wire();
        let parsed = Request::parse(&wire).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn unlock_request_with_distinct_bytes_does_not_collide() {
        // Distinct secrets must serialise to distinct wires (and
        // round-trip back to distinct values).  Belt-and-braces
        // against an encoder that "helpfully" normalised the hex.
        let a = Request::Unlock(
            UnlockSecret::from_bytes(&[0x11; 32]).unwrap(),
        );
        let b = Request::Unlock(
            UnlockSecret::from_bytes(&[0x22; 32]).unwrap(),
        );
        let wa = a.to_wire();
        let wb = b.to_wire();
        assert_ne!(wa, wb);
        assert_eq!(Request::parse(&wa).unwrap(), a);
        assert_eq!(Request::parse(&wb).unwrap(), b);
    }

    #[test]
    fn unlock_request_rejects_missing_secret_field() {
        let bytes = br#"{"kind":"unlock"}"#;
        let err = Request::parse(bytes).unwrap_err();
        assert!(
            format!("{err}").contains("host_secret_hex"),
            "{err}",
        );
    }

    #[test]
    fn unlock_request_rejects_short_secret() {
        let short_hex = "00".repeat(16);
        let body = format!(
            r#"{{"kind":"unlock","host_secret_hex":"{short_hex}"}}"#,
        );
        let err = Request::parse(body.as_bytes()).unwrap_err();
        assert!(
            format!("{err}").contains("length"),
            "{err}",
        );
    }

    #[test]
    fn unlock_request_rejects_non_hex_secret() {
        let body = format!(
            r#"{{"kind":"unlock","host_secret_hex":"{}"}}"#,
            "zz".repeat(32),
        );
        let err = Request::parse(body.as_bytes()).unwrap_err();
        assert!(
            format!("{err}").contains("hex"),
            "{err}",
        );
    }

    #[test]
    fn unlock_request_debug_does_not_expose_bytes() {
        let req = Request::Unlock(
            UnlockSecret::from_bytes(&[0xAB; 32]).unwrap(),
        );
        let dbg = format!("{req:?}");
        assert!(dbg.contains("redacted"), "{dbg}");
        // Hex of the secret should not appear.
        assert!(!dbg.contains(&"ab".repeat(8)), "{dbg}");
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
    fn unlocked_response_roundtrips() {
        let r = Response::Unlocked { epoch: 0 };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn unlocked_response_carries_distinct_epoch() {
        let a = Response::Unlocked { epoch: 0 };
        let b = Response::Unlocked { epoch: u64::MAX };
        let wa = a.to_wire().unwrap();
        let wb = b.to_wire().unwrap();
        assert_ne!(wa, wb);
        assert_eq!(Response::parse(&wa).unwrap(), a);
        assert_eq!(Response::parse(&wb).unwrap(), b);
    }

    #[test]
    fn unlocked_response_rejects_missing_epoch() {
        let bytes = br#"{"ok":true,"kind":"unlocked"}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("epoch"));
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

    // ----- GetWhitespaceCompounds request -----

    #[test]
    fn get_whitespace_compounds_request_roundtrips() {
        let wire = Request::GetWhitespaceCompounds.to_wire();
        let parsed = Request::parse(&wire).unwrap();
        assert_eq!(parsed, Request::GetWhitespaceCompounds);
    }

    #[test]
    fn get_whitespace_compounds_request_wire_form_is_one_line() {
        let wire = Request::GetWhitespaceCompounds.to_wire();
        assert_eq!(wire.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(*wire.last().unwrap(), b'\n');
    }

    // ----- WhitespaceCompounds response -----

    fn sample_compounds() -> [String; WHITESPACE_COMPOUND_COUNT_WIRE] {
        [
            "alpha".to_string(),
            "bravo".to_string(),
            "charlie".to_string(),
            "delta".to_string(),
            "echo".to_string(),
        ]
    }

    #[test]
    fn whitespace_compounds_response_roundtrips() {
        let r = Response::WhitespaceCompounds {
            epoch: 7,
            compounds: sample_compounds(),
        };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn whitespace_compounds_response_preserves_slot_order() {
        // Distinct compounds; if the encoder ever sorted the array
        // this test catches it.
        let r = Response::WhitespaceCompounds {
            epoch: 0,
            compounds: sample_compounds(),
        };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        match parsed {
            Response::WhitespaceCompounds {
                compounds: parsed, ..
            } => {
                assert_eq!(parsed[0], "alpha");
                assert_eq!(parsed[1], "bravo");
                assert_eq!(parsed[2], "charlie");
                assert_eq!(parsed[3], "delta");
                assert_eq!(parsed[4], "echo");
            }
            other => panic!("expected WhitespaceCompounds, got {other:?}"),
        }
    }

    #[test]
    fn whitespace_compounds_response_rejects_missing_epoch() {
        let bytes = br#"{"ok":true,"kind":"whitespace-compounds","compounds":["a","b","c","d","e"]}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("epoch"));
    }

    #[test]
    fn whitespace_compounds_response_rejects_missing_compounds() {
        let bytes = br#"{"ok":true,"kind":"whitespace-compounds","epoch":0}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("compounds"));
    }

    #[test]
    fn whitespace_compounds_response_rejects_wrong_array_length() {
        for body in [
            r#"{"ok":true,"kind":"whitespace-compounds","epoch":0,"compounds":["a"]}"#,
            r#"{"ok":true,"kind":"whitespace-compounds","epoch":0,"compounds":["a","b","c","d"]}"#,
            r#"{"ok":true,"kind":"whitespace-compounds","epoch":0,"compounds":["a","b","c","d","e","f"]}"#,
        ] {
            let err = Response::parse(body.as_bytes()).unwrap_err();
            assert!(
                format!("{err}").contains("length"),
                "expected length error for {body}, got {err}",
            );
        }
    }

    #[test]
    fn whitespace_compounds_response_rejects_non_array_compounds() {
        let bytes = br#"{"ok":true,"kind":"whitespace-compounds","epoch":0,"compounds":"notarray"}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("non-array"));
    }

    #[test]
    fn whitespace_compounds_response_rejects_non_string_entry() {
        let bytes = br#"{"ok":true,"kind":"whitespace-compounds","epoch":0,"compounds":["a","b",42,"d","e"]}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("not a string"));
    }

    #[test]
    fn whitespace_compounds_response_rejects_empty_entry() {
        let bytes = br#"{"ok":true,"kind":"whitespace-compounds","epoch":0,"compounds":["a","","c","d","e"]}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn whitespace_compounds_response_rejects_oversize_entry() {
        // An entry longer than WHITESPACE_COMPOUND_MAX_BYTES (1024)
        // must be rejected by the parser before reaching the
        // consumer's validator.  The whole request stays well under
        // MAX_REQUEST_BYTES (8 KiB) so the size-cap doesn't fire
        // first.
        let big = "a".repeat(2000);
        let body = format!(
            r#"{{"ok":true,"kind":"whitespace-compounds","epoch":0,"compounds":["{big}","b","c","d","e"]}}"#
        );
        let err = Response::parse(body.as_bytes()).unwrap_err();
        assert!(format!("{err}").contains("exceeds cap"), "{err}");
    }

    #[test]
    fn whitespace_compounds_response_wire_format_is_one_line() {
        let r = Response::WhitespaceCompounds {
            epoch: 0,
            compounds: sample_compounds(),
        };
        let wire = r.to_wire().unwrap();
        assert_eq!(wire.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(*wire.last().unwrap(), b'\n');
    }

    // ----- GetKeywordCompounds request -----

    #[test]
    fn get_keyword_compounds_request_roundtrips() {
        let wire = Request::GetKeywordCompounds.to_wire();
        let parsed = Request::parse(&wire).unwrap();
        assert_eq!(parsed, Request::GetKeywordCompounds);
    }

    #[test]
    fn get_keyword_compounds_request_wire_form_is_one_line() {
        let wire = Request::GetKeywordCompounds.to_wire();
        assert_eq!(wire.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(*wire.last().unwrap(), b'\n');
    }

    // ----- KeywordCompounds response -----

    fn sample_keyword_compounds()
        -> [String; PYTHON_KEYWORD_COMPOUND_COUNT_WIRE]
    {
        // 35 deterministic, distinct, all-ASCII-lowercase strings.
        // Wire-side validators don't require lowercase, but real
        // payloads from the daemon are; tests using this helper
        // exercise the realistic case.  Index-encoded so a parser
        // that scrambles slot order is caught by the "preserves
        // slot order" test below.
        std::array::from_fn(|i| {
            let hi =
                u8::try_from(i / 26).expect("i/26 < 26") + b'a';
            let lo =
                u8::try_from(i % 26).expect("i%26 < 26") + b'a';
            format!("kw{}{}sample", hi as char, lo as char)
        })
    }

    #[test]
    fn keyword_compounds_response_roundtrips() {
        let r = Response::KeywordCompounds {
            epoch: 11,
            compounds: Box::new(sample_keyword_compounds()),
        };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn keyword_compounds_response_preserves_slot_order() {
        let original = sample_keyword_compounds();
        let r = Response::KeywordCompounds {
            epoch: 0,
            compounds: Box::new(original.clone()),
        };
        let wire = r.to_wire().unwrap();
        let parsed = Response::parse(&wire).unwrap();
        match parsed {
            Response::KeywordCompounds { compounds, .. } => {
                for (i, c) in compounds.iter().enumerate() {
                    assert_eq!(c, &original[i], "slot {i} mismatch");
                }
            }
            other => {
                panic!("expected KeywordCompounds, got {other:?}");
            }
        }
    }

    #[test]
    fn keyword_compounds_response_rejects_missing_epoch() {
        let arr_json: Vec<String> = (0..PYTHON_KEYWORD_COMPOUND_COUNT_WIRE)
            .map(|i| format!("\"kw{i}\""))
            .collect();
        let body = format!(
            r#"{{"ok":true,"kind":"keyword-compounds","compounds":[{}]}}"#,
            arr_json.join(",")
        );
        let err = Response::parse(body.as_bytes()).unwrap_err();
        assert!(format!("{err}").contains("epoch"));
    }

    #[test]
    fn keyword_compounds_response_rejects_missing_compounds() {
        let bytes = br#"{"ok":true,"kind":"keyword-compounds","epoch":0}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("compounds"));
    }

    #[test]
    fn keyword_compounds_response_rejects_wrong_array_length() {
        // Too short (34) and too long (36).  The 35-entry case is
        // the happy path covered by `roundtrips` above.
        let short: Vec<String> =
            (0..(PYTHON_KEYWORD_COMPOUND_COUNT_WIRE - 1))
                .map(|i| format!("\"kw{i}\""))
                .collect();
        let long: Vec<String> =
            (0..=PYTHON_KEYWORD_COMPOUND_COUNT_WIRE)
                .map(|i| format!("\"kw{i}\""))
                .collect();
        for arr in [short, long] {
            let body = format!(
                r#"{{"ok":true,"kind":"keyword-compounds","epoch":0,"compounds":[{}]}}"#,
                arr.join(",")
            );
            let err = Response::parse(body.as_bytes()).unwrap_err();
            assert!(
                format!("{err}").contains("length"),
                "expected length error for {body}, got {err}",
            );
        }
    }

    #[test]
    fn keyword_compounds_response_rejects_non_array_compounds() {
        let bytes = br#"{"ok":true,"kind":"keyword-compounds","epoch":0,"compounds":"notarray"}"#;
        let err = Response::parse(bytes).unwrap_err();
        assert!(format!("{err}").contains("non-array"));
    }

    #[test]
    fn keyword_compounds_response_rejects_non_string_entry() {
        // 35 entries with a single number at slot 10.
        let mut arr: Vec<String> =
            (0..PYTHON_KEYWORD_COMPOUND_COUNT_WIRE)
                .map(|i| format!("\"kw{i}\""))
                .collect();
        arr[10] = "42".to_string();
        let body = format!(
            r#"{{"ok":true,"kind":"keyword-compounds","epoch":0,"compounds":[{}]}}"#,
            arr.join(",")
        );
        let err = Response::parse(body.as_bytes()).unwrap_err();
        assert!(format!("{err}").contains("not a string"));
    }

    #[test]
    fn keyword_compounds_response_rejects_empty_entry() {
        let mut arr: Vec<String> =
            (0..PYTHON_KEYWORD_COMPOUND_COUNT_WIRE)
                .map(|i| format!("\"kw{i}\""))
                .collect();
        arr[5] = "\"\"".to_string();
        let body = format!(
            r#"{{"ok":true,"kind":"keyword-compounds","epoch":0,"compounds":[{}]}}"#,
            arr.join(",")
        );
        let err = Response::parse(body.as_bytes()).unwrap_err();
        assert!(format!("{err}").contains("empty"));
    }

    #[test]
    fn keyword_compounds_response_rejects_oversize_entry() {
        // An entry above KEYWORD_COMPOUND_MAX_BYTES must be rejected
        // before reaching the consumer's from_compounds validator.
        // Total request must stay under MAX_REQUEST_BYTES (8 KiB) so
        // the size cap doesn't fire first — 35 small entries + one
        // ~2 KiB blob is ~2.3 KiB total, fits comfortably.
        let big = "a".repeat(2000);
        let mut arr: Vec<String> =
            (0..PYTHON_KEYWORD_COMPOUND_COUNT_WIRE)
                .map(|i| format!("\"kw{i}\""))
                .collect();
        arr[0] = format!("\"{big}\"");
        let body = format!(
            r#"{{"ok":true,"kind":"keyword-compounds","epoch":0,"compounds":[{}]}}"#,
            arr.join(",")
        );
        let err = Response::parse(body.as_bytes()).unwrap_err();
        assert!(format!("{err}").contains("exceeds cap"), "{err}");
    }

    #[test]
    fn keyword_compounds_response_wire_format_is_one_line() {
        let r = Response::KeywordCompounds {
            epoch: 0,
            compounds: Box::new(sample_keyword_compounds()),
        };
        let wire = r.to_wire().unwrap();
        assert_eq!(wire.iter().filter(|b| **b == b'\n').count(), 1);
        assert_eq!(*wire.last().unwrap(), b'\n');
    }
}
