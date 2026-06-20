//! Layer-3 unscramble pipeline: scrambled bytes → Python source.
//!
//! # Infrastructure module
//!
//! No specific attack is defeated here.  This module wires together
//! the daemon round-trip and the preprocessor's unscramble path into
//! the contract the [`crate::exec_python`] pipeline consumes.  Each
//! stage's threat-model header lives in its source crate.
//!
//! # Pipeline
//!
//! 1. `fetch_whitespace_wordlist(socket)` — round-trip
//!    `Request::GetWhitespaceCompounds` against the daemon's Unix
//!    socket; build a local `WhitespaceWordlist` via
//!    `from_compounds` (validates non-empty / ASCII-lowercase /
//!    pairwise-distinct).
//! 2. `unscramble_source(scrambled, &wl)` —
//!    `unscrambler::unscramble`.
//!
//! Both stages are pure on their inputs; the only I/O is the
//! socket round-trip in stage 1.

use std::path::Path;

use anyhow::{anyhow, Context, Result};

use babbleon_daemon_protocol_v2::{round_trip, Request, Response};
use babbleon_preprocessor_v2::unscrambler::unscramble;
use babbleon_preprocessor_v2::WhitespaceWordlist;

/// Round-trip `Request::GetWhitespaceCompounds` against the daemon
/// at `socket_path`, return the resulting `WhitespaceWordlist`.
///
/// # Errors
///
/// - Daemon round-trip failure (socket missing, daemon refused
///   connection, request size cap exceeded — none plausible for a
///   four-byte request).
/// - `Response::Error` from the daemon (vault locked, internal).
/// - Unexpected response variant.
/// - `from_compounds` validation failure on the returned compounds
///   (delegated; error variant carries slot index, not bytes).
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
                |e| {
                    anyhow!(
                        "daemon returned invalid whitespace compounds: {e}"
                    )
                },
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

/// Unscramble the raw scrambled bytes into Python source.
///
/// Thin wrapper over `unscrambler::unscramble`; carries an
/// `anyhow::Context` for the shim's error chain.
///
/// # Errors
///
/// Returns whatever `unscrambler::unscramble` returns; MVP is
/// effectively infallible (the signature reserves room for future
/// strict-mode failures without a wire break).
pub fn unscramble_source(
    scrambled: &str,
    wl: &WhitespaceWordlist,
) -> Result<String> {
    unscramble(scrambled, wl).with_context(|| "unscramble layer-3 source")
}

#[cfg(test)]
mod tests {
    use super::unscramble_source;
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;
    use babbleon_preprocessor_v2::python_tokenizer::tokenize;
    use babbleon_preprocessor_v2::scrambler::scramble;
    use babbleon_preprocessor_v2::WhitespaceWordlist;

    fn fixed_wl() -> WhitespaceWordlist {
        let s = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        WhitespaceWordlist::build(&s, Wordlist::english_baseline(), 0).unwrap()
    }

    #[test]
    fn unscramble_source_round_trips_known_python() {
        let wl = fixed_wl();
        let original = "x = 1\nif x:\n    print(\"hi\")\n";
        let tokens = tokenize(original);
        let scrambled = scramble(&tokens, &wl).unwrap();
        let reconstructed = unscramble_source(&scrambled, &wl).unwrap();
        assert_eq!(reconstructed, original);
    }

    #[test]
    fn unscramble_source_empty_input_yields_empty_output() {
        let wl = fixed_wl();
        let r = unscramble_source("", &wl).unwrap();
        assert_eq!(r, "");
    }

    #[test]
    fn unscramble_source_with_only_word_yields_same_word() {
        let wl = fixed_wl();
        let r = unscramble_source("hello", &wl).unwrap();
        assert_eq!(r, "hello");
    }
}
