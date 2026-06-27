//! Full unscramble pipeline for the runtime shim.
//!
//! # Infrastructure module
//!
//! No specific attack is defeated here.  This module wires the
//! daemon round-trips and the preprocessor's
//! [`babbleon_preprocessor_v2::pipeline::unscramble_pipeline`] into
//! the contract the shim's [`crate::exec_python`] stage consumes.
//!
//! # Pipeline
//!
//! 1. `parse_scrambled_file(scrambled)` — header decode (format
//!    version + epoch + sorted-token list + L3 body).
//! 2. `fetch_whitespace_wordlist(socket)` — `GetWhitespaceCompounds`
//!    against the daemon's Unix socket; build a local
//!    [`WhitespaceWordlist`].
//! 3. `fetch_identifier_mapping(socket, sorted_tokens, epoch)` —
//!    `GetTokenMapping` against the daemon for the file's token set,
//!    pinning to the header's epoch.  Epoch mismatch is an error
//!    (the operator rotated past the file's window — they must
//!    re-scramble or roll back).
//! 4. `babbleon_preprocessor_v2::pipeline::unscramble_pipeline(
//!    version, epoch, body, &wl, &id_mapping)` — applies L12⁻¹,
//!    L6⁻¹ (if version >= 1), L3⁻¹, L2⁻¹, L5⁻¹, L4⁻¹, and
//!    `tokens_to_source`.
//!
//! The result is the original Python source ready for
//! [`crate::exec_python::run`].
//!
//! # Why not call the v2-babbleon CLI's lifecycle directly
//!
//! The CLI is a binary, not a library — its `scramble_lifecycle` and
//! `corpus_lifecycle` modules are not crate-public.  Both consume the
//! same shared modules from `v2-babbleon-preprocessor` that this
//! module consumes.  All three call sites agree on layer order +
//! file format because the format and order live in
//! `v2-babbleon-preprocessor::{file_format, pipeline}`.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

use babbleon_daemon_protocol_v2::{round_trip, Request, Response};
use babbleon_preprocessor_v2::file_format::{decode, DecodedFile};
use babbleon_preprocessor_v2::identifier_scrambler::IdentifierMapping;
use babbleon_preprocessor_v2::pipeline::unscramble_pipeline;
use babbleon_preprocessor_v2::WhitespaceWordlist;

/// Round-trip `Request::GetWhitespaceCompounds` against the daemon
/// at `socket_path` and return the resulting [`WhitespaceWordlist`].
///
/// # Errors
///
/// - Daemon round-trip failure (socket missing, daemon refused
///   connection, request size cap exceeded).
/// - [`Response::Error`] from the daemon (vault locked, internal).
/// - Unexpected response variant.
/// - `WhitespaceWordlist::from_compounds` validation failure
///   (slot index returned in the error, not the bytes).
pub fn fetch_whitespace_wordlist(
    socket_path: &Path,
) -> Result<WhitespaceWordlist> {
    let resp = round_trip(socket_path, &Request::GetWhitespaceCompounds)
        .with_context(|| {
            format!("daemon round-trip via {}", socket_path.display())
        })?;
    match resp {
        Response::WhitespaceCompounds { epoch, compounds } => {
            WhitespaceWordlist::from_compounds(epoch, compounds).map_err(
                |e| anyhow!("daemon returned invalid whitespace compounds: {e}"),
            )
        }
        Response::Error { kind, message } => {
            Err(anyhow!("daemon error ({kind:?}): {message}"))
        }
        other => Err(anyhow!(
            "expected WhitespaceCompounds response, got {other:?}",
        )),
    }
}

/// Round-trip `Request::GetTokenMapping` for `tokens` at the
/// `expected_epoch` from the scrambled file's header.
///
/// The daemon serves the L2 alias compounds at its current epoch; if
/// the daemon's current epoch differs from the file's header epoch
/// the file was scrambled at a different mapping window and the
/// operator must rotate or re-scramble.
///
/// # Errors
///
/// - Daemon round-trip failure.
/// - Epoch mismatch between the header's epoch and the daemon's
///   current epoch.
/// - [`Response::Error`] from the daemon.
/// - Unexpected response variant.
/// - `IdentifierMapping::from_tokens_and_aliases` build failure
///   (compound collision — astronomically rare).
pub fn fetch_identifier_mapping(
    socket_path: &Path,
    tokens: &[String],
    expected_epoch: u64,
    format_version: u32,
) -> Result<IdentifierMapping> {
    let resp = round_trip(
        socket_path,
        &Request::GetTokenMapping {
            tokens: tokens.to_vec(),
            format_version,
        },
    )
    .with_context(|| {
        format!("daemon round-trip via {}", socket_path.display())
    })?;
    match resp {
        Response::TokenMapping { epoch, aliases } => {
            if epoch != expected_epoch {
                return Err(anyhow!(
                    "epoch mismatch: file was scrambled at epoch {expected_epoch}, \
                     daemon is at epoch {epoch}; rotate or re-scramble",
                ));
            }
            IdentifierMapping::from_tokens_and_aliases(
                tokens.to_vec(),
                epoch,
                aliases,
            )
            .map_err(|e| anyhow!("identifier mapping build failed: {e}"))
        }
        Response::Error { kind, message } => {
            Err(anyhow!("daemon error ({kind:?}): {message}"))
        }
        other => Err(anyhow!(
            "expected TokenMapping response, got {other:?}",
        )),
    }
}

/// Parse a scrambled-file string into header fields + body.
///
/// Thin wrapper over [`decode`]; carries an `anyhow::Context` for the
/// shim's error chain.
///
/// # Errors
///
/// Whatever [`decode`] returns; today
/// [`babbleon_preprocessor_v2::Error::HeaderParse`] is the only
/// failure mode.
pub fn parse_scrambled_file(scrambled: &str) -> Result<DecodedFile> {
    decode(scrambled).with_context(|| "parse scrambled-file header")
}

/// Drive the full unscramble pipeline given a scrambled file string
/// and a daemon socket path.
///
/// Composes the three preceding helpers into the one operation the
/// shim's main path cares about: scrambled bytes → original Python
/// source.  Each daemon round-trip carries its own error context so
/// a failure surfaces the responsible stage.
///
/// # Errors
///
/// Header-parse, daemon round-trip, mapping-build, or epoch-mismatch
/// failures wrapped in `anyhow::Error`.
pub fn unscramble_full(
    socket_path: &Path,
    scrambled: &str,
) -> Result<String> {
    let DecodedFile { version, epoch, sorted_tokens, body } =
        parse_scrambled_file(scrambled)?;
    let wl = fetch_whitespace_wordlist(socket_path)?;
    let mapping = fetch_identifier_mapping(
        socket_path,
        &sorted_tokens,
        epoch,
        version,
    )?;
    Ok(unscramble_pipeline(version, epoch, &body, &wl, &mapping))
}

#[cfg(test)]
mod tests {
    use super::unscramble_full;
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;
    use babbleon_preprocessor_v2::identifier_scrambler::{
        IdentifierMapping, ALIAS_COUNT,
    };
    use babbleon_preprocessor_v2::pipeline::scramble_pipeline;
    use babbleon_preprocessor_v2::WhitespaceWordlist;

    fn fixed_wl(epoch: u64) -> WhitespaceWordlist {
        let s = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        WhitespaceWordlist::build(&s, Wordlist::english_baseline(), epoch).unwrap()
    }

    fn synthetic_mapping(
        sorted_tokens: &[String],
        epoch: u64,
    ) -> babbleon_preprocessor_v2::errors::Result<IdentifierMapping> {
        let aliases: Vec<Vec<String>> = sorted_tokens
            .iter()
            .enumerate()
            .map(|(t_idx, _)| {
                (0..ALIAS_COUNT)
                    .map(|a| format!("__shimt{t_idx}_e{epoch}_a{a}__"))
                    .collect()
            })
            .collect();
        IdentifierMapping::from_tokens_and_aliases(
            sorted_tokens.to_vec(),
            epoch,
            aliases,
        )
    }

    #[test]
    fn unscramble_full_requires_a_daemon_socket() {
        // No daemon: unscramble_full must return Err, not panic.
        // We construct a syntactically-valid scrambled file using the
        // preprocessor pipeline and feed it to a missing-socket call.
        // The error surfaces as a daemon round-trip failure.
        let epoch = 0;
        let wl = fixed_wl(epoch);
        let scrambled =
            scramble_pipeline("x = 1\n", epoch, &wl, synthetic_mapping)
                .unwrap();
        let no_such = std::path::PathBuf::from("/no/such/babbleon.sock");
        let r = unscramble_full(&no_such, &scrambled.file);
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(
            msg.contains("daemon round-trip") || msg.contains("/no/such"),
            "expected daemon-round-trip context, got: {msg}",
        );
    }

    #[test]
    fn parse_scrambled_file_surfaces_header_parse_error() {
        let r = super::parse_scrambled_file("not-a-babbleon-file");
        assert!(r.is_err());
    }

    #[test]
    fn parse_scrambled_file_round_trips_a_valid_header() {
        let epoch = 0;
        let wl = fixed_wl(epoch);
        let scrambled =
            scramble_pipeline("y = 2\n", epoch, &wl, synthetic_mapping)
                .unwrap();
        let decoded = super::parse_scrambled_file(&scrambled.file).unwrap();
        assert_eq!(decoded.epoch, epoch);
        assert_eq!(decoded.sorted_tokens, scrambled.sorted_tokens);
    }
}
