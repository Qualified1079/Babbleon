//! `babbleon scramble` and `babbleon unscramble` lifecycle.
//!
//! # What this defeats
//!
//! Operator-side structural fingerprinting.  The phase-3 layer-3
//! preprocessor replaces every whitespace marker in a Python source
//! with the per-epoch wordlist compound for its kind, producing a
//! wall-of-text artifact that any tool reading the file by `read()`
//! sees as opaque bytes.  These two subcommands are the operator's
//! entry point: convert a normal `.py` to scrambled bytes and back.
//!
//! # Compartmentalisation
//!
//! This module runs in the CLI process's address space, which
//! [`crate::main`] guarantees does NOT hold the per-host secret for
//! any longer than one `unlock` call needs.  The compounds the
//! scramble / unscramble pipeline consumes are obtained from the
//! daemon over a one-shot socket round-trip (`Request::GetWhitespaceCompounds`);
//! the CLI sees only HKDF-derived per-epoch output, not the secret
//! that produced it.
//!
//! The compounds are themselves secret-adjacent — an attacker that
//! learns "in this epoch, the SPACE compound is `riverstoneanvil`"
//! can scramble against that epoch — but rotation invalidates them
//! at the next `babbleon rotate-mapping`.  See
//! `docs/v2/structure-scrambling.md` §"Trust placement" for the
//! full attack-surface analysis.
//!
//! # Pipeline
//!
//! `scramble`:
//!
//! 1. Read source bytes (UTF-8) from FILE (`-` or absent ⇒ stdin).
//! 2. Round-trip `Request::GetWhitespaceCompounds` AND
//!    `Request::GetKeywordCompounds` against the daemon's socket
//!    (two one-shots; both cheap, both gated by the same Locked /
//!    Unlocked vault check).
//! 3. Build a `WhitespaceWordlist` and a `KeywordWordlist` from the
//!    returned compounds via the respective `from_compounds`
//!    constructors.
//! 4. `python_tokenizer::tokenize` →
//!    `keyword_scrambler::scramble_keywords` (layer 2, in-place) →
//!    `scrambler::scramble` (layer 3, token-stream-to-bytes).
//! 5. Write scrambled bytes to OUTPUT (`-` or absent ⇒ stdout).
//!
//! `unscramble` reverses steps 4-5 via
//! `unscrambler::unscramble_to_tokens` →
//! `keyword_scrambler::unscramble_keywords` (in-place inverse of
//! layer 2) → `unscrambler::tokens_to_source`; steps 1-3 are
//! identical to `scramble`.
//!
//! ## L2 wiring rationale (2026-06-22)
//!
//! Until this commit the CLI emitted L3-only output even though the
//! preprocessor library has had L2 since its first release.  The
//! bench's 2026-06-21 N=1 data (`docs/v2/string-literal-leak.md`)
//! showed the L3-only surface cracks at 100% under in-sandbox
//! Claude Opus 4.7 attack.  L2 raises the cost meaningfully without
//! disturbing L3's wall-of-words property — the keyword
//! substitution happens at the token level and the same byte stream
//! L3 emits today survives the additional pass.
//!
//! # Errors
//!
//! Wrapped in `anyhow::Error` so the CLI's top-level error chain
//! formatter prints the cause sequence.  Per security-baseline rule
//! 13, no error message echoes secret material — the compounds the
//! daemon returns are dropped before any error path runs, and the
//! daemon's own error messages are validated to be non-secret
//! before they ever reach the wire.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use babbleon_daemon_protocol_v2::{round_trip, Request, Response};
use babbleon_preprocessor_v2::keyword_scrambler::{
    scramble_keywords, unscramble_keywords,
};
use babbleon_preprocessor_v2::python_tokenizer::tokenize;
use babbleon_preprocessor_v2::scrambler::scramble;
use babbleon_preprocessor_v2::unscrambler::{
    tokens_to_source, unscramble_to_tokens,
};
use babbleon_preprocessor_v2::{KeywordWordlist, WhitespaceWordlist};

/// Operator-supplied options for the `scramble` and `unscramble`
/// subcommands.
///
/// Same shape for both directions; the calling code decides which
/// pipeline to run.
pub struct ScrambleOptions {
    /// Input source.  `None` means stdin.
    pub input: InputSource,
    /// Output destination.  `None` means stdout.
    pub output: OutputSink,
    /// Daemon socket path.  Defaults to
    /// `babbleon_daemon_protocol_v2::default_socket_path()` in the
    /// caller.
    pub socket_path: PathBuf,
}

/// Where the operator's source bytes come from.
pub enum InputSource {
    /// Read all of stdin until EOF.
    Stdin,
    /// Read the file at this path.
    File(PathBuf),
}

/// Where the operator's output bytes go.
pub enum OutputSink {
    /// Write to stdout.
    Stdout,
    /// Truncate-write to the file at this path.
    File(PathBuf),
}

/// Run `babbleon scramble`.
///
/// # Errors
///
/// - I/O failure reading input or writing output.
/// - Daemon round-trip failure (socket missing, daemon refused).
/// - Daemon returned `Response::Error` (vault locked, internal).
/// - Daemon returned unexpected response variant.
/// - Compound validation failure (`from_compounds`).
/// - Scramble failure (`WhitespaceCompoundCollision`).
pub fn run_scramble(opts: ScrambleOptions) -> Result<()> {
    let ScrambleOptions {
        input,
        output,
        socket_path,
    } = opts;
    let source = read_input(&input)?;
    let wl = fetch_whitespace_wordlist(&socket_path)?;
    let kwl = fetch_keyword_wordlist(&socket_path)?;
    let mut tokens = tokenize(&source);
    scramble_keywords(&mut tokens, &kwl);
    let scrambled = scramble(&tokens, &wl)
        .with_context(|| "scramble")?;
    write_output(&output, scrambled.as_bytes())?;
    Ok(())
}

/// Run `babbleon unscramble`.
///
/// # Errors
///
/// - I/O failure reading input or writing output.
/// - Daemon round-trip failure / error response / unexpected
///   variant.
/// - Compound validation failure.
/// - Unscramble failure (currently infallible at MVP).
pub fn run_unscramble(opts: ScrambleOptions) -> Result<()> {
    let ScrambleOptions {
        input,
        output,
        socket_path,
    } = opts;
    let scrambled = read_input(&input)?;
    let wl = fetch_whitespace_wordlist(&socket_path)?;
    let kwl = fetch_keyword_wordlist(&socket_path)?;
    // `unscramble_to_tokens` is infallible at MVP scope (any
    // leftover bytes are emitted as a final Word); no error fold-in
    // needed.
    let mut tokens = unscramble_to_tokens(&scrambled, &wl);
    unscramble_keywords(&mut tokens, &kwl);
    let source = tokens_to_source(&tokens);
    write_output(&output, source.as_bytes())?;
    Ok(())
}

/// Read input bytes as a UTF-8 string.
///
/// Non-UTF-8 input is rejected with a clear error rather than
/// silently corrupted — the preprocessor IR (`Token::Word`) holds a
/// Rust `String`, so non-UTF-8 bytes cannot survive the round-trip.
fn read_input(source: &InputSource) -> Result<String> {
    match source {
        InputSource::Stdin => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .context("read stdin")?;
            Ok(buf)
        }
        InputSource::File(path) => fs::read_to_string(path)
            .with_context(|| format!("read {}", path.display())),
    }
}

fn write_output(sink: &OutputSink, bytes: &[u8]) -> Result<()> {
    match sink {
        OutputSink::Stdout => {
            io::stdout()
                .write_all(bytes)
                .context("write stdout")?;
            // Flush so a downstream pipe (e.g. into `python3`) sees
            // the bytes before the CLI process exits.
            io::stdout().flush().context("flush stdout")?;
            Ok(())
        }
        OutputSink::File(path) => fs::write(path, bytes)
            .with_context(|| format!("write {}", path.display())),
    }
}

/// Round-trip `Request::GetWhitespaceCompounds` against the daemon,
/// then construct a `WhitespaceWordlist` from the returned compounds.
///
/// Public to the binary crate so the batch [`crate::corpus_lifecycle`]
/// path can share one round-trip across a multi-file walk.
pub fn fetch_whitespace_wordlist_pub(
    socket_path: &Path,
) -> Result<WhitespaceWordlist> {
    fetch_whitespace_wordlist(socket_path)
}

/// Sister of [`fetch_whitespace_wordlist_pub`] for layer-2 (keyword
/// scramble).  Public so the directory-batch
/// [`crate::corpus_lifecycle`] path can share one round-trip
/// across a multi-file walk instead of paying per-file socket
/// chatter.
///
/// # Errors
///
/// Same shape as `fetch_whitespace_wordlist_pub`: connect /
/// round-trip / error-response / wrong-variant / compound
/// validation failures fold into `anyhow::Error`.
pub fn fetch_keyword_wordlist_pub(
    socket_path: &Path,
) -> Result<KeywordWordlist> {
    fetch_keyword_wordlist(socket_path)
}

fn fetch_whitespace_wordlist(socket_path: &Path) -> Result<WhitespaceWordlist> {
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

/// Sister of [`fetch_whitespace_wordlist`] for layer-2 (operator-
/// scramble) compounds.  Round-trips
/// [`Request::GetKeywordCompounds`] against the daemon and
/// reconstructs a [`KeywordWordlist`] from the boxed 35-element
/// reply.
///
/// Two daemon round-trips per scramble call is the right shape for
/// v2.0: each request is microseconds against a local Unix socket,
/// and the two compounds rotate together (the daemon's epoch is
/// the same for both replies issued back-to-back).  A future
/// combined `GetEpochCompounds` request that returns both pools in
/// one wire reply is a v2.1 optimisation, filed under
/// HANDOFF "wire optimisations."
fn fetch_keyword_wordlist(socket_path: &Path) -> Result<KeywordWordlist> {
    let resp = round_trip(socket_path, &Request::GetKeywordCompounds)
        .with_context(|| {
            format!("daemon round-trip via {}", socket_path.display())
        })?;
    match resp {
        Response::KeywordCompounds { epoch, compounds } => {
            // `compounds` is a Box<[String; 35]>; move the array
            // out of the box (`*compounds` consumes the box and
            // yields the array by value) so `from_compounds` can
            // take ownership of the strings.
            KeywordWordlist::from_compounds(epoch, *compounds).map_err(
                |e| {
                    anyhow!(
                        "daemon returned invalid keyword compounds: {e}"
                    )
                },
            )
        }
        Response::Error { kind, message } => {
            Err(anyhow!("daemon error ({kind:?}): {message}"))
        }
        other => Err(anyhow!(
            "expected KeywordCompounds response, got {other:?}",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{InputSource, OutputSink, ScrambleOptions};

    #[test]
    fn input_source_variants_construct() {
        // Smoke test that the enum is matchable in both forms; the
        // wire-side behaviour is exercised in
        // tests/cli_against_daemon.rs.
        let _ = InputSource::Stdin;
        let _ = InputSource::File(std::path::PathBuf::from("/tmp/x.py"));
    }

    #[test]
    fn output_sink_variants_construct() {
        let _ = OutputSink::Stdout;
        let _ = OutputSink::File(std::path::PathBuf::from("/tmp/x.scr"));
    }

    #[test]
    fn scramble_options_struct_field_visibility() {
        // Compile-time guard: every field must be pub so main.rs can
        // construct from clap args.  This test exists to fail loudly
        // if a future refactor removes the pub visibility.
        let _ = ScrambleOptions {
            input: InputSource::Stdin,
            output: OutputSink::Stdout,
            socket_path: std::path::PathBuf::from("/run/babbleon/daemon.sock"),
        };
    }
}
