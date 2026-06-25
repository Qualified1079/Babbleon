//! `babbleon scramble` and `babbleon unscramble` lifecycle.
//!
//! # What this defeats
//!
//! Structural fingerprinting.  The preprocessor (L3) replaces every
//! whitespace marker with a per-epoch wordlist compound producing a
//! wall-of-text artifact.  The dynamic identifier scrambler (L2) then
//! replaces every whitespace-delimited token with a per-epoch compound
//! derived from the per-host secret, with multi-alias cycling so
//! repeated tokens produce varied output.
//!
//! Together L2+L3 make the scrambled file look like a run-on sequence
//! of random English words with no language, structure, or identifier
//! fingerprint visible.
//!
//! # File format
//!
//! Scrambled files have a four-line header followed by the L3 body:
//!
//! ```text
//! babbleon-v2
//! epoch:<N>
//! tokens:<tab-separated sorted unique tokens>
//! ---
//! <L3 scrambled body>
//! ```
//!
//! The token list (from `collect_unique_tokens`) is embedded so the
//! unscrambler can ask the daemon for the same mapping without the
//! original source.  Security comes from the compounds being derived
//! from the per-host secret, not from hiding which tokens exist.
//!
//! # Pipeline
//!
//! `scramble`:
//!
//! 1. Read source bytes (UTF-8) from FILE or stdin.
//! 2. `python_tokenizer::tokenize` → `Vec<Token>`.
//! 3. `scramble_chunks` (L4, position markers + per-epoch shuffle).
//! 4. `inject_decoys` (L5, depth-0 decoy injection).
//! 5. `collect_unique_tokens` → sorted unique token list.
//! 6. Round-trip `Request::GetTokenMapping` against the daemon to
//!    get per-token aliases.
//! 7. `scramble_identifiers` (L2, in-place).
//! 8. Round-trip `Request::GetWhitespaceCompounds` (L3).
//! 9. `scrambler::scramble` (L3, token-stream-to-bytes).
//! 10. `reverse_chunks` (L6, per-epoch direction reversal of body
//!     char-chunks).
//! 11. `inject_noise` (L12, tokenizer-hostile noise on body bytes).
//! 12. Prepend header; write to OUTPUT or stdout.
//!
//! `unscramble`:
//!
//! 1. Read scrambled file; parse header (epoch + token list).
//! 2. Round-trip `Request::GetTokenMapping` with the header's
//!    token list → same mapping (deterministic from secret+epoch).
//! 3. Round-trip `Request::GetWhitespaceCompounds`.
//! 4. `strip_noise` (L12, content-based zero-width + homoglyph
//!    removal — idempotent for back-compat).
//! 5. `unreverse_chunks` (L6, re-applies same per-epoch reversal
//!    pattern since reversal is involutive).
//! 6. `unscrambler::unscramble_to_tokens` (L3).
//! 7. `unscramble_identifiers` (L2).
//! 8. `strip_decoys` (L5).
//! 9. `unscramble_chunks` (L4).
//! 10. `unscrambler::tokens_to_source`.
//! 11. Write to OUTPUT or stdout.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use babbleon_daemon_protocol_v2::{round_trip, Request, Response};
use babbleon_preprocessor_v2::chunk_reorder::{scramble_chunks, unscramble_chunks};
use babbleon_preprocessor_v2::decoy_injection::{inject_decoys, strip_decoys};
use babbleon_preprocessor_v2::direction_reversal::{reverse_chunks, unreverse_chunks};
use babbleon_preprocessor_v2::identifier_scrambler::{
    collect_unique_tokens, scramble_identifiers, unscramble_identifiers,
    IdentifierMapping,
};
use babbleon_preprocessor_v2::python_tokenizer::tokenize;
use babbleon_preprocessor_v2::scrambler::scramble;
use babbleon_preprocessor_v2::tokenizer_noise::{inject_noise, strip_noise};
use babbleon_preprocessor_v2::unscrambler::{
    tokens_to_source, unscramble_to_tokens,
};
use babbleon_preprocessor_v2::WhitespaceWordlist;

/// Magic string that opens every scrambled file header.
const HEADER_MAGIC: &str = "babbleon-v2";
/// Separator between the header and the L3 scrambled body.
const HEADER_SEP: &str = "---";

/// Scrambled-file format version the current scrambler emits.
///
/// Stamped into the header as `version:<N>`.  The unscrambler reads
/// this to know which optional layers to apply on the inverse side.
///
/// History:
///
/// - **0** — legacy.  L4 (chunk reorder) + L5 (decoy injection) +
///   L2 (identifier scramble) + L3 (whitespace-as-words).  Pre-L6
///   and pre-L12 files lacked an explicit `version` line; the
///   reader infers version 0 from the missing line.
/// - **1** — current.  Adds **L6** (direction segment reversal,
///   per-epoch xorshift) and **L12** (zero-width + Cyrillic-
///   homoglyph noise on body bytes).  Files at version 1 carry the
///   explicit `version:1` header line; unscramble applies L6
///   inverse and L12 strip in addition to the legacy inverses.
pub const FORMAT_VERSION_LATEST: u32 = 1;

/// Legacy format version (pre-L6, pre-L12).  The scrambler never
/// emits this; the reader infers it when the `version` header line
/// is absent.
pub const FORMAT_VERSION_LEGACY: u32 = 0;

/// Operator-supplied options for the `scramble` and `unscramble`
/// subcommands.
pub struct ScrambleOptions {
    /// Input source.  `None` means stdin.
    pub input: InputSource,
    /// Output destination.  `None` means stdout.
    pub output: OutputSink,
    /// Daemon socket path.
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
/// I/O, daemon, or scramble failures wrapped in `anyhow::Error`.
pub fn run_scramble(opts: ScrambleOptions) -> Result<()> {
    let ScrambleOptions { input, output, socket_path } = opts;
    let source = read_input(&input)?;

    // Tokenize for structure (L3) and collect unique tokens (L2).
    let raw_tokens = tokenize(&source);

    // Pre-L4 mapping fetch is only needed for its epoch (so the L4
    // shuffle seed and the L2 mapping share the same epoch).  We
    // re-fetch after L4 with the marker-augmented token set.
    let pre_unique = collect_unique_tokens(&raw_tokens);
    let pre_mapping =
        fetch_identifier_mapping(&socket_path, &pre_unique)?;

    // L4: insert position markers + shuffle top-level chunks.
    let l4_tokens = scramble_chunks(raw_tokens, pre_mapping.epoch);
    // L5: inject decoy tokens at depth-0 positions.
    let mut tokens = inject_decoys(l4_tokens, pre_mapping.epoch);
    let unique_tokens = collect_unique_tokens(&tokens);

    let wl = fetch_whitespace_wordlist(&socket_path)?;
    let id_mapping = fetch_identifier_mapping_at_epoch(
        &socket_path,
        &unique_tokens,
        pre_mapping.epoch,
    )?;

    // L2 in-place: replace each token body with its alias compound.
    scramble_identifiers(&mut tokens, &id_mapping);

    // L3: whitespace markers → compounds.
    let body = scramble(&tokens, &wl).with_context(|| "scramble L3")?;

    // L6: per-epoch direction reversal of variable-length char
    // chunks.  Runs while the body is still pure ASCII so the
    // char-based reversal stays simple; the inverse re-applies the
    // same per-epoch pattern (reversal is involutive).
    let reversed_body = reverse_chunks(&body, id_mapping.epoch);

    // L12: tokenizer-hostile noise injection on the body bytes.
    // Operates after L6 so the header (which holds the token list,
    // potentially non-ASCII) round-trips byte-for-byte.
    let noisy_body = inject_noise(&reversed_body, id_mapping.epoch);

    // Encode file: header + body.
    let out = encode_scrambled_file(id_mapping.epoch, &unique_tokens, &noisy_body);
    write_output(&output, out.as_bytes())?;
    Ok(())
}

/// Run `babbleon unscramble`.
///
/// # Errors
///
/// I/O, daemon, header-parse, or unscramble failures.
pub fn run_unscramble(opts: ScrambleOptions) -> Result<()> {
    let ScrambleOptions { input, output, socket_path } = opts;
    let raw = read_input(&input)?;

    // Parse header to recover (version, epoch, token list).
    let (version, epoch, sorted_tokens, body) = decode_scrambled_file(&raw)
        .with_context(|| "parse scrambled-file header")?;

    // Re-derive the identifier mapping from the same inputs.
    let id_mapping = fetch_identifier_mapping_at_epoch(
        &socket_path,
        &sorted_tokens,
        epoch,
    )?;
    let wl = fetch_whitespace_wordlist(&socket_path)?;

    // L12 inverse: strip tokenizer-hostile noise from the body BEFORE
    // L3's greedy prefix match.  Content-based and idempotent on a
    // clean body — safe to run unconditionally (v0 files have no
    // noise; the strip is a no-op).
    let body = strip_noise(&body);

    // L6 inverse: undo the per-epoch direction reversal.  GATED on
    // version: v0 files were scrambled before L6 landed and never
    // had their chunks reversed, so applying the inverse would
    // corrupt them.  v1+ files get the inverse applied.
    let body = if version >= 1 {
        unreverse_chunks(&body, id_mapping.epoch)
    } else {
        body
    };

    // L3 unscramble: body → token stream.
    let mut tokens = unscramble_to_tokens(&body, &wl);

    // L2 unscramble: replace alias compounds with original tokens.
    unscramble_identifiers(&mut tokens, &id_mapping);

    // L5 inverse: strip decoy tokens BEFORE L4 reorder so chunk
    // boundary computation isn't disturbed by decoy positions.
    let dedecoyed = strip_decoys(tokens);
    // L4 inverse: sort chunks back to original order, strip markers.
    // No-op for single-chunk files that didn't get markers on scramble.
    let reordered = unscramble_chunks(dedecoyed);

    let source = tokens_to_source(&reordered);
    write_output(&output, source.as_bytes())?;
    Ok(())
}

/// Encode a scrambled file using the latest format version.
///
/// The header is five lines:
///
/// ```text
/// babbleon-v2
/// version:1
/// epoch:<N>
/// tokens:<tab-separated sorted unique tokens>
/// ---
/// <body bytes>
/// ```
///
/// The reader accepts either this layout or the legacy 4-line
/// layout (no `version` line); see [`decode_scrambled_file`].
pub(crate) fn encode_scrambled_file(
    epoch: u64,
    sorted_tokens: &[String],
    body: &str,
) -> String {
    encode_scrambled_file_versioned(FORMAT_VERSION_LATEST, epoch, sorted_tokens, body)
}

/// Encode at an explicit format version.  Test-friendly entry point;
/// production callers use [`encode_scrambled_file`].
pub(crate) fn encode_scrambled_file_versioned(
    version: u32,
    epoch: u64,
    sorted_tokens: &[String],
    body: &str,
) -> String {
    let tokens_line = sorted_tokens.join("\t");
    if version == FORMAT_VERSION_LEGACY {
        // The legacy reader expects no `version` line; emit the
        // 4-line layout so a v0 file round-trips byte-identical.
        format!("{HEADER_MAGIC}\nepoch:{epoch}\ntokens:{tokens_line}\n{HEADER_SEP}\n{body}")
    } else {
        format!(
            "{HEADER_MAGIC}\nversion:{version}\nepoch:{epoch}\ntokens:{tokens_line}\n{HEADER_SEP}\n{body}"
        )
    }
}

/// Parse the header from a scrambled file, returning
/// `(version, epoch, sorted_tokens, body)`.
///
/// Forward- and back-compatible: if line 2 starts with `version:`
/// the rest of the file is the v1+ layout (`version`, `epoch`,
/// `tokens`, sep, body); if line 2 starts with `epoch:` the file is
/// the legacy v0 layout (`epoch`, `tokens`, sep, body) and the
/// reader returns version = [`FORMAT_VERSION_LEGACY`] so the
/// unscrambler knows to skip L6 + L12 inverses.
///
/// # Errors
///
/// `Error::HeaderParse` (wrapped in anyhow at the call site) if
/// any header field is missing or malformed.
pub(crate) fn decode_scrambled_file(
    content: &str,
) -> std::result::Result<
    (u32, u64, Vec<String>, String),
    babbleon_preprocessor_v2::Error,
> {
    use babbleon_preprocessor_v2::Error;

    // Reserve enough split positions for the v1+ layout (5 lines +
    // body).  splitn caps the chunk count, so requesting 6 chunks
    // means line 6 is "everything after line 5's newline" — the
    // body, which may itself contain non-newline content.
    let mut lines = content.splitn(6, '\n');

    let magic = lines.next().unwrap_or("");
    if magic != HEADER_MAGIC {
        return Err(Error::HeaderParse(format!(
            "expected {HEADER_MAGIC:?} on line 1, got {magic:?}"
        )));
    }

    // Line 2 is either `version:<N>` (v1+) or `epoch:<N>` (legacy).
    let second_line = lines.next().unwrap_or("");
    let (version, epoch_line) =
        if let Some(version_str) = second_line.strip_prefix("version:") {
            let version: u32 = version_str.parse().map_err(|_| {
                Error::HeaderParse(format!(
                    "version value {version_str:?} is not a valid u32"
                ))
            })?;
            (version, lines.next().unwrap_or(""))
        } else {
            (FORMAT_VERSION_LEGACY, second_line)
        };

    let epoch_str = epoch_line.strip_prefix("epoch:").ok_or_else(|| {
        Error::HeaderParse(format!(
            "expected 'epoch:<N>' after magic/version, got {epoch_line:?}"
        ))
    })?;
    let epoch: u64 = epoch_str.parse().map_err(|_| {
        Error::HeaderParse(format!(
            "epoch value {epoch_str:?} is not a valid u64"
        ))
    })?;

    let tokens_line = lines.next().unwrap_or("");
    let tokens_str =
        tokens_line.strip_prefix("tokens:").ok_or_else(|| {
            Error::HeaderParse(format!(
                "expected 'tokens:...' line, got {tokens_line:?}"
            ))
        })?;
    let sorted_tokens: Vec<String> = if tokens_str.is_empty() {
        Vec::new()
    } else {
        tokens_str.split('\t').map(str::to_owned).collect()
    };

    let sep = lines.next().unwrap_or("");
    if sep != HEADER_SEP {
        return Err(Error::HeaderParse(format!(
            "expected {HEADER_SEP:?} separator line, got {sep:?}"
        )));
    }

    let body = lines.next().unwrap_or("").to_owned();
    Ok((version, epoch, sorted_tokens, body))
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
            io::stdout()
                .write_all(bytes)
                .context("write stdout")?;
            io::stdout().flush().context("flush stdout")?;
            Ok(())
        }
        OutputSink::File(path) => fs::write(path, bytes)
            .with_context(|| format!("write {}", path.display())),
    }
}

/// Round-trip `GetWhitespaceCompounds` against the daemon.
pub fn fetch_whitespace_wordlist_pub(
    socket_path: &Path,
) -> Result<WhitespaceWordlist> {
    fetch_whitespace_wordlist(socket_path)
}

fn fetch_whitespace_wordlist(socket_path: &Path) -> Result<WhitespaceWordlist> {
    let resp =
        round_trip(socket_path, &Request::GetWhitespaceCompounds)
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

/// Round-trip `GetTokenMapping` for `tokens` and build an
/// `IdentifierMapping`.  Uses the epoch the daemon reports.
pub fn fetch_identifier_mapping_pub(
    socket_path: &Path,
    tokens: &[String],
) -> Result<IdentifierMapping> {
    fetch_identifier_mapping(socket_path, tokens)
}

fn fetch_identifier_mapping(
    socket_path: &Path,
    tokens: &[String],
) -> Result<IdentifierMapping> {
    let resp = round_trip(
        socket_path,
        &Request::GetTokenMapping { tokens: tokens.to_vec() },
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

/// Round-trip `GetTokenMapping` for `tokens` at a specific `epoch`.
///
/// Public entry point for corpus-level callers that parse the per-file
/// header epoch and need to validate it against the daemon's current
/// epoch before unscrambling.
pub fn fetch_identifier_mapping_at_epoch_pub(
    socket_path: &Path,
    tokens: &[String],
    expected_epoch: u64,
) -> Result<IdentifierMapping> {
    fetch_identifier_mapping_at_epoch(socket_path, tokens, expected_epoch)
}

/// The daemon always uses its current epoch; this function validates
/// that the daemon's current epoch matches the one from the file
/// header.  If they differ, the file was scrambled at a different
/// epoch than the daemon is currently serving — the caller must
/// rotate the mapping back or use a different daemon state.
fn fetch_identifier_mapping_at_epoch(
    socket_path: &Path,
    tokens: &[String],
    expected_epoch: u64,
) -> Result<IdentifierMapping> {
    let mapping = fetch_identifier_mapping(socket_path, tokens)?;
    if mapping.epoch != expected_epoch {
        return Err(anyhow!(
            "epoch mismatch: file was scrambled at epoch {expected_epoch}, \
             daemon is at epoch {}; rotate mapping or use correct epoch",
            mapping.epoch,
        ));
    }
    Ok(mapping)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_scrambled_file, encode_scrambled_file,
        encode_scrambled_file_versioned, FORMAT_VERSION_LATEST,
        FORMAT_VERSION_LEGACY,
    };

    #[test]
    fn header_round_trips_empty_token_list() {
        let encoded =
            encode_scrambled_file(7, &[], "thequickbrownfox");
        let (version, epoch, tokens, body) =
            decode_scrambled_file(&encoded).unwrap();
        assert_eq!(version, FORMAT_VERSION_LATEST);
        assert_eq!(epoch, 7);
        assert!(tokens.is_empty());
        assert_eq!(body, "thequickbrownfox");
    }

    #[test]
    fn header_round_trips_nonempty_token_list() {
        let toks = vec!["apple".to_string(), "def".to_string(), "zoo".to_string()];
        let encoded = encode_scrambled_file(42, &toks, "body_here");
        let (version, epoch, tokens, body) = decode_scrambled_file(&encoded).unwrap();
        assert_eq!(version, FORMAT_VERSION_LATEST);
        assert_eq!(epoch, 42);
        assert_eq!(tokens, toks);
        assert_eq!(body, "body_here");
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let bad = "not-babbleon\nepoch:0\ntokens:\n---\nbody";
        assert!(decode_scrambled_file(bad).is_err());
    }

    #[test]
    fn decode_rejects_missing_separator() {
        let bad = "babbleon-v2\nepoch:0\ntokens:\nXXX\nbody";
        assert!(decode_scrambled_file(bad).is_err());
    }

    #[test]
    fn decode_rejects_non_numeric_epoch() {
        let bad = "babbleon-v2\nepoch:abc\ntokens:\n---\nbody";
        assert!(decode_scrambled_file(bad).is_err());
    }

    #[test]
    fn decode_legacy_v0_layout_without_version_line() {
        // The 4-line legacy layout: no `version:` line; line 2 is
        // straight to `epoch:`.  Reader must accept this and report
        // version = FORMAT_VERSION_LEGACY so the unscrambler skips
        // L6 inverse on the body.
        let legacy = "babbleon-v2\nepoch:5\ntokens:foo\tbar\n---\nlegacybody";
        let (version, epoch, tokens, body) =
            decode_scrambled_file(legacy).unwrap();
        assert_eq!(version, FORMAT_VERSION_LEGACY);
        assert_eq!(epoch, 5);
        assert_eq!(tokens, vec!["foo".to_string(), "bar".to_string()]);
        assert_eq!(body, "legacybody");
    }

    #[test]
    fn encode_at_legacy_version_emits_4_line_layout() {
        let encoded =
            encode_scrambled_file_versioned(FORMAT_VERSION_LEGACY, 9, &[], "b");
        assert!(
            !encoded.contains("version:"),
            "legacy encoder must NOT emit a version line: {encoded:?}"
        );
        let (version, epoch, tokens, body) =
            decode_scrambled_file(&encoded).unwrap();
        assert_eq!(version, FORMAT_VERSION_LEGACY);
        assert_eq!(epoch, 9);
        assert!(tokens.is_empty());
        assert_eq!(body, "b");
    }

    #[test]
    fn decode_rejects_non_numeric_version() {
        let bad = "babbleon-v2\nversion:abc\nepoch:0\ntokens:\n---\nbody";
        assert!(decode_scrambled_file(bad).is_err());
    }

    #[test]
    fn decode_accepts_future_version_field() {
        // An unscrambler should not panic on a higher version
        // string; the layer-application logic gates on `version >=
        // 1`, so any version >= 1 follows the same code path.
        let future = "babbleon-v2\nversion:99\nepoch:1\ntokens:foo\n---\nbody";
        let (version, epoch, tokens, body) =
            decode_scrambled_file(future).unwrap();
        assert_eq!(version, 99);
        assert_eq!(epoch, 1);
        assert_eq!(tokens, vec!["foo".to_string()]);
        assert_eq!(body, "body");
    }

    #[test]
    fn current_encode_round_trips_through_decode_byte_identical() {
        // The default encoder + decoder pair must produce the same
        // logical fields back.  Body containing odd ASCII (no \n,
        // no \t) round-trips byte-for-byte.
        let toks = vec!["alpha".to_string(), "beta".to_string()];
        let body = "abcdefghijklmnopqrstuvwxyz";
        let encoded = encode_scrambled_file(12345, &toks, body);
        let (version, epoch, decoded_tokens, decoded_body) =
            decode_scrambled_file(&encoded).unwrap();
        assert_eq!(version, FORMAT_VERSION_LATEST);
        assert_eq!(epoch, 12345);
        assert_eq!(decoded_tokens, toks);
        assert_eq!(decoded_body, body);
    }

    #[test]
    fn input_output_variants_construct() {
        let _ = super::InputSource::Stdin;
        let _ = super::InputSource::File(std::path::PathBuf::from("/tmp/x"));
        let _ = super::OutputSink::Stdout;
        let _ = super::OutputSink::File(std::path::PathBuf::from("/tmp/y"));
    }
}
