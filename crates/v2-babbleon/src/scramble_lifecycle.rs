//! `babbleon scramble` and `babbleon unscramble` lifecycle.
//!
//! # What this defeats
//!
//! Structural fingerprinting.  See `lib.rs` and
//! `docs/v2/structure-scrambling.md` for the threat model.  This
//! module owns the operator-visible `scramble` / `unscramble`
//! subcommands.  The actual layer composition + file-format logic
//! lives in `babbleon_preprocessor_v2::pipeline` and
//! `babbleon_preprocessor_v2::file_format` so the python-shim runtime
//! and the corpus-batch CLI consume the same canonical pipeline.
//!
//! # What stays here
//!
//! - Daemon round-trip wrappers (`GetWhitespaceCompounds` /
//!   `GetTokenMapping`) — the daemon protocol is application-level,
//!   not preprocessor-level.
//! - Operator I/O (`stdin` / `stdout` / file paths).
//! - Seccomp install timing — applied *after* the last daemon socket
//!   call so the filter can drop `socket` / `connect`.
//!
//! # Pipeline (re-stated for context; the canonical implementation
//! lives in `babbleon_preprocessor_v2::pipeline`)
//!
//! `scramble`:
//!
//! 1. Read source bytes (UTF-8) from FILE or stdin.
//! 2. Fetch whitespace wordlist from daemon → epoch is its `.epoch()`.
//! 3. `pipeline::scramble_pipeline(source, epoch, &wl, fetch_mapping)`
//!    drives tokenise + L4 + L5 + L2 + L3 + L6 + L12 + encode.  The
//!    `fetch_mapping` closure calls `GetTokenMapping` against the
//!    daemon at the same epoch.
//! 4. Install seccomp (after the last daemon call; the closure has
//!    already run by the time the function returns).
//! 5. Write encoded bytes to OUTPUT or stdout.
//!
//! `unscramble`:
//!
//! 1. Read scrambled file; `file_format::decode` recovers
//!    `(version, epoch, sorted_tokens, body)`.
//! 2. Fetch L2 mapping (epoch-pinned to the header epoch) and
//!    whitespace wordlist from daemon.
//! 3. Install seccomp.
//! 4. `pipeline::unscramble_pipeline(version, epoch, &body, &wl,
//!    &mapping)` drives L12⁻¹ + L6⁻¹ + L3⁻¹ + L2⁻¹ + L5⁻¹ + L4⁻¹ +
//!    `tokens_to_source`.
//! 5. Write source bytes to OUTPUT or stdout.

use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use babbleon_daemon_protocol_v2::{round_trip, Request, Response};
use babbleon_preprocessor_v2::file_format::{decode as decode_file, DecodedFile};
use babbleon_preprocessor_v2::identifier_scrambler::IdentifierMapping;
use babbleon_preprocessor_v2::pipeline::{
    scramble_pipeline, unscramble_pipeline,
};
use babbleon_preprocessor_v2::WhitespaceWordlist;

/// Operator-supplied options for the `scramble` and `unscramble`
/// subcommands.
pub struct ScrambleOptions {
    /// Input source.  `None` means stdin.
    pub input: InputSource,
    /// Output destination.  `None` means stdout.
    pub output: OutputSink,
    /// Daemon socket path.
    pub socket_path: PathBuf,
    /// If true, skip installing the seccomp allowlist after the daemon
    /// round-trip.  Default (false) is to install; only skip for
    /// debugging with `--no-seccomp`.
    pub no_seccomp: bool,
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
/// I/O, daemon, or scramble failures wrapped in `anyhow::Error`.
pub fn run_scramble(opts: ScrambleOptions) -> Result<()> {
    let ScrambleOptions { input, output, socket_path, no_seccomp } = opts;
    let source = read_input(&input)?;

    // Stage 1: get the live epoch via the whitespace round-trip.
    // L4/L5/L2 all derive from this epoch; the L2 mapping fetch must
    // request the same value or the unscramble side will not
    // converge.
    let wl = fetch_whitespace_wordlist(&socket_path)?;
    let epoch = wl.epoch();

    // The pipeline's closure runs in the middle of scramble_pipeline.
    // We let it perform its daemon round-trip; install_seccomp fires
    // afterwards so the filter can drop socket/connect once the last
    // daemon call has returned.  Use a Cell to detect whether the
    // closure ran (it must) and any error it produced.
    let socket_for_closure = socket_path.clone();
    let mapping_err: RefCell<Option<anyhow::Error>> = RefCell::new(None);
    // scramble emits the latest file format; the daemon must use the
    // matching alias-count regime so the unscramble side derives an
    // identical mapping when it reads the same format-version line
    // from the header.
    let scramble_format_version =
        babbleon_preprocessor_v2::FORMAT_VERSION_LATEST;
    let fetch_mapping = |toks: &[String], epoch: u64| -> babbleon_preprocessor_v2::errors::Result<IdentifierMapping> {
        match fetch_identifier_mapping_at_epoch(
            &socket_for_closure,
            toks,
            epoch,
            scramble_format_version,
        ) {
            Ok(m) => Ok(m),
            Err(e) => {
                *mapping_err.borrow_mut() = Some(e);
                Err(babbleon_preprocessor_v2::errors::Error::Scramble(
                    "daemon round-trip failed (see error chain)".to_string(),
                ))
            }
        }
    };

    let scrambled = scramble_pipeline(&source, epoch, &wl, fetch_mapping)
        .map_err(|e| {
            // Prefer the captured daemon error over the synthetic
            // wrapper if present.
            if let Some(daemon_err) = mapping_err.borrow_mut().take() {
                daemon_err.context("scramble pipeline")
            } else {
                anyhow!("scramble pipeline: {e}")
            }
        })?;

    install_seccomp(no_seccomp)?;

    write_output(&output, scrambled.file.as_bytes())?;
    Ok(())
}

/// Run `babbleon unscramble`.
///
/// # Errors
///
/// I/O, daemon, header-parse, or unscramble failures.
pub fn run_unscramble(opts: ScrambleOptions) -> Result<()> {
    let ScrambleOptions { input, output, socket_path, no_seccomp } = opts;
    let raw = read_input(&input)?;

    // Parse header up-front so a malformed file fails before any
    // daemon traffic.
    let DecodedFile { version, epoch, sorted_tokens, body } =
        decode_file(&raw).with_context(|| "parse scrambled-file header")?;

    let id_mapping = fetch_identifier_mapping_at_epoch(
        &socket_path,
        &sorted_tokens,
        epoch,
        version,
    )?;
    let wl = fetch_whitespace_wordlist(&socket_path)?;

    install_seccomp(no_seccomp)?;

    let source =
        unscramble_pipeline(version, epoch, &body, &wl, &id_mapping);
    write_output(&output, source.as_bytes())?;
    Ok(())
}

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
            io::stdout().write_all(bytes).context("write stdout")?;
            io::stdout().flush().context("flush stdout")?;
            Ok(())
        }
        OutputSink::File(path) => fs::write(path, bytes)
            .with_context(|| format!("write {}", path.display())),
    }
}

/// Round-trip `GetWhitespaceCompounds` against the daemon.
///
/// Public so `corpus_lifecycle` (sibling module) can share the same
/// wire-error message format.
pub fn fetch_whitespace_wordlist_pub(
    socket_path: &Path,
) -> Result<WhitespaceWordlist> {
    fetch_whitespace_wordlist(socket_path)
}

fn fetch_whitespace_wordlist(socket_path: &Path) -> Result<WhitespaceWordlist> {
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
            "expected WhitespaceCompounds response, got {other:?}"
        )),
    }
}

fn fetch_identifier_mapping(
    socket_path: &Path,
    tokens: &[String],
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
            "expected TokenMapping response, got {other:?}"
        )),
    }
}

/// Round-trip `GetTokenMapping` for `tokens` at a specific `expected_epoch`
/// + `format_version`.
///
/// Public entry point for corpus-level callers that parse the per-file
/// header epoch and need to validate it against the daemon's current
/// epoch before unscrambling.
pub fn fetch_identifier_mapping_at_epoch_pub(
    socket_path: &Path,
    tokens: &[String],
    expected_epoch: u64,
    format_version: u32,
) -> Result<IdentifierMapping> {
    fetch_identifier_mapping_at_epoch(
        socket_path,
        tokens,
        expected_epoch,
        format_version,
    )
}

/// The daemon always uses its current epoch; this function validates
/// that the daemon's current epoch matches the one from the file
/// header.  If they differ, the file was scrambled at a different
/// epoch than the daemon is currently serving — the caller must
/// rotate the mapping back or use a different daemon state.
///
/// `format_version` is the file-format version the caller is
/// producing or consuming; the daemon uses it to pick the legacy /
/// variable alias-count regime.  See [`Request::GetTokenMapping`]
/// for the regime semantics.
fn fetch_identifier_mapping_at_epoch(
    socket_path: &Path,
    tokens: &[String],
    expected_epoch: u64,
    format_version: u32,
) -> Result<IdentifierMapping> {
    let mapping = fetch_identifier_mapping(socket_path, tokens, format_version)?;
    if mapping.epoch != expected_epoch {
        return Err(anyhow!(
            "epoch mismatch: file was scrambled at epoch {expected_epoch}, \
             daemon is at epoch {}; rotate mapping or use correct epoch",
            mapping.epoch,
        ));
    }
    Ok(mapping)
}

/// Install the seccomp filter unless `no_seccomp` is true.
///
/// On non-Linux targets the filter is unavailable; the function
/// succeeds silently (no filter installed).  On Linux this calls
/// `seccomp_profile::apply()` and returns any error.
///
/// When `no_seccomp` is true the function prints a warning to stderr
/// and returns `Ok(())` — the caller continues unfiltered.
fn install_seccomp(no_seccomp: bool) -> Result<()> {
    if no_seccomp {
        eprintln!(
            "babbleon: WARNING: seccomp filter NOT installed (--no-seccomp). \
             Do NOT use in production.",
        );
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        crate::seccomp_profile::apply()
            .context("seccomp filter install failed")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn input_output_variants_construct() {
        let _ = super::InputSource::Stdin;
        let _ = super::InputSource::File(std::path::PathBuf::from("/tmp/x"));
        let _ = super::OutputSink::Stdout;
        let _ = super::OutputSink::File(std::path::PathBuf::from("/tmp/y"));
    }
}
