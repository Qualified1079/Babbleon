//! Scrambled-file header encode + decode (format version 0 / 1).
//!
//! # Infrastructure module
//!
//! No specific attack is defeated here.  The header carries the
//! metadata both the scrambler and the unscrambler need: the format
//! version (so the unscrambler knows which layer inverses to apply),
//! the epoch (so the L4/L5/L6/L12 PRNGs reproduce the same per-epoch
//! choices), and the sorted unique-token list (so the unscrambler can
//! ask the daemon for the same L2 mapping without the original
//! source).
//!
//! # File format
//!
//! Current — version 1, five lines + body:
//!
//! ```text
//! babbleon-v2
//! version:1
//! epoch:<N>
//! tokens:<tab-separated sorted unique tokens>
//! ---
//! <L3 body, post-L6, post-L12>
//! ```
//!
//! Legacy — version 0, four lines + body (no `version:` line):
//!
//! ```text
//! babbleon-v2
//! epoch:<N>
//! tokens:<tab-separated sorted unique tokens>
//! ---
//! <L3 body, pre-L6, pre-L12>
//! ```
//!
//! The reader accepts either layout.  A version 1 file emitted by the
//! current scrambler triggers L6 inverse + L12 strip on unscramble; a
//! version 0 file (from before those layers landed) skips L6 inverse
//! so the body is not corrupted, and the L12 strip is content-based
//! and idempotent on clean ASCII.
//!
//! # Security baseline
//!
//! The token list is not a secret — security comes from the per-host
//! HKDF derivation of the per-epoch compounds, not from hiding which
//! tokens exist in the file.  See `docs/v2/structure-scrambling.md`
//! §"Kerckhoffs's principle for the token list."

use crate::errors::Error;

/// Magic string that opens every scrambled file header.
pub const HEADER_MAGIC: &str = "babbleon-v2";

/// Separator line between the header and the L3 body.
pub const HEADER_SEP: &str = "---";

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

/// Encode a scrambled file at the latest format version.
///
/// Production callers should use this entry point.  Tests that want
/// to exercise the legacy layout use [`encode_versioned`].
#[must_use]
pub fn encode(epoch: u64, sorted_tokens: &[String], body: &str) -> String {
    encode_versioned(FORMAT_VERSION_LATEST, epoch, sorted_tokens, body)
}

/// Encode at an explicit format version.
///
/// Version 0 emits the legacy 4-line layout (no `version` line);
/// every other version emits the 5-line layout with `version:<N>`.
#[must_use]
pub fn encode_versioned(
    version: u32,
    epoch: u64,
    sorted_tokens: &[String],
    body: &str,
) -> String {
    let tokens_line = sorted_tokens.join("\t");
    if version == FORMAT_VERSION_LEGACY {
        format!(
            "{HEADER_MAGIC}\nepoch:{epoch}\ntokens:{tokens_line}\n{HEADER_SEP}\n{body}"
        )
    } else {
        format!(
            "{HEADER_MAGIC}\nversion:{version}\nepoch:{epoch}\ntokens:{tokens_line}\n{HEADER_SEP}\n{body}"
        )
    }
}

/// Parsed scrambled-file header + body.
///
/// `version` is the integer from the `version:` line or
/// [`FORMAT_VERSION_LEGACY`] if the line is absent.  `sorted_tokens`
/// is the (already-sorted) unique-token list embedded in the header
/// in the same order the daemon's `GetTokenMapping` response will
/// align with.  `body` is the bytes between the `---` separator line
/// and end-of-file, owned (so the caller can drop the original
/// scrambled string).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFile {
    /// Format version inferred from the header.  Drives which
    /// optional layer inverses (L6, L12) the unscramble path applies.
    pub version: u32,
    /// Per-host-secret-derived epoch the file was scrambled at.
    pub epoch: u64,
    /// Sorted unique tokens; the daemon's L2 mapping response aligns
    /// to this order.
    pub sorted_tokens: Vec<String>,
    /// L3 body bytes (still under L6 + L12 transforms when version >= 1).
    pub body: String,
}

/// Parse the header from a scrambled-file string.
///
/// Forward- and back-compatible: if line 2 starts with `version:` the
/// rest of the file is the v1+ layout; if line 2 starts with `epoch:`
/// the file is the legacy v0 layout and the reader returns
/// `version = `[`FORMAT_VERSION_LEGACY`].
///
/// # Errors
///
/// [`Error::HeaderParse`] if any header field is missing or
/// malformed.  No I/O is performed; the caller owns the input bytes.
pub fn decode(content: &str) -> Result<DecodedFile, Error> {
    let mut lines = content.splitn(6, '\n');

    let magic = lines.next().unwrap_or("");
    if magic != HEADER_MAGIC {
        return Err(Error::HeaderParse(format!(
            "expected {HEADER_MAGIC:?} on line 1, got {magic:?}"
        )));
    }

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
    let tokens_str = tokens_line.strip_prefix("tokens:").ok_or_else(|| {
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
    Ok(DecodedFile { version, epoch, sorted_tokens, body })
}

#[cfg(test)]
mod tests {
    use super::{
        decode, encode, encode_versioned, FORMAT_VERSION_LATEST,
        FORMAT_VERSION_LEGACY,
    };

    #[test]
    fn header_round_trips_empty_token_list() {
        let encoded = encode(7, &[], "thequickbrownfox");
        let d = decode(&encoded).unwrap();
        assert_eq!(d.version, FORMAT_VERSION_LATEST);
        assert_eq!(d.epoch, 7);
        assert!(d.sorted_tokens.is_empty());
        assert_eq!(d.body, "thequickbrownfox");
    }

    #[test]
    fn header_round_trips_nonempty_token_list() {
        let toks =
            vec!["apple".to_string(), "def".to_string(), "zoo".to_string()];
        let encoded = encode(42, &toks, "body_here");
        let d = decode(&encoded).unwrap();
        assert_eq!(d.version, FORMAT_VERSION_LATEST);
        assert_eq!(d.epoch, 42);
        assert_eq!(d.sorted_tokens, toks);
        assert_eq!(d.body, "body_here");
    }

    #[test]
    fn decode_rejects_wrong_magic() {
        let bad = "not-babbleon\nepoch:0\ntokens:\n---\nbody";
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_rejects_missing_separator() {
        let bad = "babbleon-v2\nepoch:0\ntokens:\nXXX\nbody";
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_rejects_non_numeric_epoch() {
        let bad = "babbleon-v2\nepoch:abc\ntokens:\n---\nbody";
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_legacy_v0_layout_without_version_line() {
        let legacy =
            "babbleon-v2\nepoch:5\ntokens:foo\tbar\n---\nlegacybody";
        let d = decode(legacy).unwrap();
        assert_eq!(d.version, FORMAT_VERSION_LEGACY);
        assert_eq!(d.epoch, 5);
        assert_eq!(d.sorted_tokens, vec!["foo".to_string(), "bar".to_string()]);
        assert_eq!(d.body, "legacybody");
    }

    #[test]
    fn encode_at_legacy_version_emits_4_line_layout() {
        let encoded = encode_versioned(FORMAT_VERSION_LEGACY, 9, &[], "b");
        assert!(
            !encoded.contains("version:"),
            "legacy encoder must NOT emit a version line: {encoded:?}"
        );
        let d = decode(&encoded).unwrap();
        assert_eq!(d.version, FORMAT_VERSION_LEGACY);
        assert_eq!(d.epoch, 9);
        assert!(d.sorted_tokens.is_empty());
        assert_eq!(d.body, "b");
    }

    #[test]
    fn decode_rejects_non_numeric_version() {
        let bad =
            "babbleon-v2\nversion:abc\nepoch:0\ntokens:\n---\nbody";
        assert!(decode(bad).is_err());
    }

    #[test]
    fn decode_accepts_future_version_field() {
        // A higher-than-current version must parse without panic so a
        // newer scrambler's file can be inspected by an older
        // unscrambler at the parser layer; the unscramble pipeline
        // decides what to do with the version number.
        let future =
            "babbleon-v2\nversion:99\nepoch:1\ntokens:foo\n---\nbody";
        let d = decode(future).unwrap();
        assert_eq!(d.version, 99);
        assert_eq!(d.epoch, 1);
        assert_eq!(d.sorted_tokens, vec!["foo".to_string()]);
        assert_eq!(d.body, "body");
    }

    #[test]
    fn round_trip_byte_identical_for_ascii_body() {
        let toks = vec!["alpha".to_string(), "beta".to_string()];
        let body = "abcdefghijklmnopqrstuvwxyz";
        let encoded = encode(12345, &toks, body);
        let d = decode(&encoded).unwrap();
        assert_eq!(d.version, FORMAT_VERSION_LATEST);
        assert_eq!(d.epoch, 12345);
        assert_eq!(d.sorted_tokens, toks);
        assert_eq!(d.body, body);
    }

    #[test]
    fn body_may_contain_dashes_without_aliasing_separator() {
        // splitn caps the line count at 6, so the body chunk is
        // "everything after the 5th newline" and can include arbitrary
        // text including the literal "---" sequence.  This is what
        // makes L12's homoglyphs and L6's reversal safe in the body
        // even if a chunk happens to look like the separator line.
        let body = "---also-this---\nand-this\n---";
        let encoded = encode(1, &[], body);
        let d = decode(&encoded).unwrap();
        assert_eq!(d.body, body);
    }

    #[test]
    fn decoded_file_clone_and_eq() {
        // Cheap sanity that the derive-implemented impls do what they
        // say; this is the public surface a downstream test or fuzz
        // harness will reach for.
        let toks = vec!["t".to_string()];
        let d = decode(&encode(1, &toks, "b")).unwrap();
        let d2 = d.clone();
        assert_eq!(d, d2);
    }
}
