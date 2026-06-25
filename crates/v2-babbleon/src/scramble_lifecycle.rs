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
//! 10. `inject_noise` (L12, tokenizer-hostile noise on body bytes).
//! 11. Prepend header; write to OUTPUT or stdout.
//!
//! `unscramble`:
//!
//! 1. Read scrambled file; parse header (epoch + token list).
//! 2. Round-trip `Request::GetTokenMapping` with the header's
//!    token list → same mapping (deterministic from secret+epoch).
//! 3. Round-trip `Request::GetWhitespaceCompounds`.
//! 4. `strip_noise` (L12, content-based zero-width + homoglyph
//!    removal — idempotent for back-compat).
//! 5. `unscrambler::unscramble_to_tokens` (L3).
//! 6. `unscramble_identifiers` (L2).
//! 7. `strip_decoys` (L5).
//! 8. `unscramble_chunks` (L4).
//! 9. `unscrambler::tokens_to_source`.
//! 10. Write to OUTPUT or stdout.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

use babbleon_daemon_protocol_v2::{round_trip, Request, Response};
use babbleon_preprocessor_v2::chunk_reorder::{scramble_chunks, unscramble_chunks};
use babbleon_preprocessor_v2::decoy_injection::{inject_decoys, strip_decoys};
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

    // L12: tokenizer-hostile noise injection on the body bytes.
    // Operates after L3 so the header (which holds the token list,
    // potentially non-ASCII) round-trips byte-for-byte.
    let noisy_body = inject_noise(&body, id_mapping.epoch);

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

    // Parse header to recover epoch + token list.
    let (epoch, sorted_tokens, body) = decode_scrambled_file(&raw)
        .with_context(|| "parse scrambled-file header")?;

    // Re-derive the identifier mapping from the same inputs.
    let id_mapping = fetch_identifier_mapping_at_epoch(
        &socket_path,
        &sorted_tokens,
        epoch,
    )?;
    let wl = fetch_whitespace_wordlist(&socket_path)?;

    // L12 inverse: strip tokenizer-hostile noise from the body BEFORE
    // L3's greedy prefix match.  Content-based — idempotent on a
    // clean body (back-compat for files scrambled before L12 landed).
    let body = strip_noise(&body);

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

/// Encode a scrambled file: 4-line header followed by the body.
pub(crate) fn encode_scrambled_file(
    epoch: u64,
    sorted_tokens: &[String],
    body: &str,
) -> String {
    let tokens_line = sorted_tokens.join("\t");
    format!("{HEADER_MAGIC}\nepoch:{epoch}\ntokens:{tokens_line}\n{HEADER_SEP}\n{body}")
}

/// Parse the header from a scrambled file, returning
/// `(epoch, sorted_tokens, body)`.
///
/// # Errors
///
/// `Error::HeaderParse` (wrapped in anyhow) if any header field is
/// missing or malformed.
pub(crate) fn decode_scrambled_file(
    content: &str,
) -> std::result::Result<
    (u64, Vec<String>, String),
    babbleon_preprocessor_v2::Error,
> {
    use babbleon_preprocessor_v2::Error;

    let mut lines = content.splitn(5, '\n');

    let magic = lines.next().unwrap_or("");
    if magic != HEADER_MAGIC {
        return Err(Error::HeaderParse(format!(
            "expected {HEADER_MAGIC:?} on line 1, got {magic:?}"
        )));
    }

    let epoch_line = lines.next().unwrap_or("");
    let epoch_str = epoch_line.strip_prefix("epoch:").ok_or_else(|| {
        Error::HeaderParse(format!(
            "expected 'epoch:<N>' on line 2, got {epoch_line:?}"
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
                "expected 'tokens:...' on line 3, got {tokens_line:?}"
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
            "expected {HEADER_SEP:?} separator on line 4, got {sep:?}"
        )));
    }

    let body = lines.next().unwrap_or("").to_owned();
    Ok((epoch, sorted_tokens, body))
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
    use super::{decode_scrambled_file, encode_scrambled_file};

    #[test]
    fn header_round_trips_empty_token_list() {
        let encoded =
            encode_scrambled_file(7, &[], "thequickbrownfox");
        let (epoch, tokens, body) =
            decode_scrambled_file(&encoded).unwrap();
        assert_eq!(epoch, 7);
        assert!(tokens.is_empty());
        assert_eq!(body, "thequickbrownfox");
    }

    #[test]
    fn header_round_trips_nonempty_token_list() {
        let toks = vec!["apple".to_string(), "def".to_string(), "zoo".to_string()];
        let encoded = encode_scrambled_file(42, &toks, "body_here");
        let (epoch, tokens, body) = decode_scrambled_file(&encoded).unwrap();
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
    fn input_output_variants_construct() {
        let _ = super::InputSource::Stdin;
        let _ = super::InputSource::File(std::path::PathBuf::from("/tmp/x"));
        let _ = super::OutputSink::Stdout;
        let _ = super::OutputSink::File(std::path::PathBuf::from("/tmp/y"));
    }
}
