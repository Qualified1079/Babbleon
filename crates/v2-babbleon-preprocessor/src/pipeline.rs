//! Full scramble / unscramble composition over the layer modules.
//!
//! # Infrastructure module
//!
//! No specific attack is defeated here.  This module composes the
//! L4 / L5 / L2 / L3 / L6 / L12 layer modules into the two operator-
//! visible operations: `scramble_pipeline` (source → scrambled file
//! string) and `unscramble_pipeline` (scrambled body → source).
//!
//! Compartmentalisation lives in the layer modules themselves; this
//! module's only job is to call them in the right order with the
//! shared `epoch`.
//!
//! # Why this lives in the preprocessor crate
//!
//! Two callers consume the full pipeline: the operator CLI
//! (`v2-babbleon`) for `babbleon scramble` / `babbleon unscramble`,
//! and the Python shim (`v2-babbleon-python-shim`) for the runtime
//! interpreter-feed path.  Both need byte-identical composition or
//! they will not agree on the file format.  Owning the composition
//! here removes the duplication and forecloses the drift class.
//!
//! # I/O placement
//!
//! This module is **pure**: no file I/O, no network I/O, no daemon
//! round-trip.  Callers fetch the [`WhitespaceWordlist`] and the
//! [`IdentifierMapping`] over the daemon protocol and pass them in.
//! That keeps the daemon-client implementation outside the layer
//! crate (matches the trust placement in `lib.rs §"Trust placement"`).
//!
//! # Pipeline order (must match between scramble and unscramble)
//!
//! Scramble: `tokenize → L4 → L5 → L2 → L3 → L6 → L12 → encode`
//!
//! Unscramble: `decode → L12⁻¹ → L6⁻¹ → L3⁻¹ → L2⁻¹ → L5⁻¹ → L4⁻¹ →
//! tokens_to_source`
//!
//! L6 is involutive (same call inverts), so the unscramble side
//! literally re-invokes `reverse_chunks` via the alias
//! `unreverse_chunks`.  L12's strip is content-based and idempotent,
//! so it can run unconditionally — version-0 files contain no L12
//! noise and the strip is a no-op.  L6's inverse is GATED on
//! `version >= 1` because version-0 files were scrambled before L6
//! landed and applying the inverse would corrupt their bodies.

use crate::chunk_reorder::{scramble_chunks, unscramble_chunks};
use crate::decoy_injection::{inject_decoys, strip_decoys};
use crate::direction_reversal::{reverse_chunks, unreverse_chunks};
use crate::errors::{Error, Result};
use crate::file_format::{
    decode as decode_file, encode as encode_file, DecodedFile,
    FORMAT_VERSION_LATEST,
};
use crate::identifier_scrambler::{
    collect_unique_tokens, scramble_identifiers, unscramble_identifiers,
    IdentifierMapping,
};
use crate::python_tokenizer::tokenize;
use crate::scrambler::scramble;
use crate::tokenizer_noise::{inject_noise, strip_noise};
use crate::unscrambler::{tokens_to_source, unscramble_to_tokens};
use crate::whitespace_wordlist::WhitespaceWordlist;

/// Output of a full scramble run.
///
/// The encoded `file` is what the caller writes to disk (or pipes to
/// the next stage); `sorted_tokens` is the same list embedded in the
/// file header, surfaced separately for caller assertions and for
/// tests that want to inspect the L2 token universe.
#[derive(Debug, Clone)]
pub struct ScrambledFile {
    /// The encoded scrambled-file string (header + body).  Already
    /// includes the latest format version.
    pub file: String,
    /// Sorted unique tokens fed to the daemon's `GetTokenMapping`
    /// request.  Includes L4 position markers and L5 decoy tokens.
    pub sorted_tokens: Vec<String>,
}

/// Inputs to the L2 mapping fetch.
///
/// `scramble_pipeline` produces this once it has tokenised + applied
/// L4 + L5 so the caller can round-trip `GetTokenMapping` against the
/// daemon, build the mapping, and pass it back into the second half
/// of the pipeline.  Kept as a borrow-friendly handle so the caller's
/// daemon-client code does not need to clone the inner Vec.
pub struct UniqueTokenList<'a> {
    /// Sorted unique tokens to send to the daemon.
    pub sorted_tokens: &'a [String],
    /// Daemon-supplied epoch the L4 / L5 PRNGs were already seeded
    /// with — the caller's `GetTokenMapping` response must report the
    /// same epoch or the unscramble side will not converge.
    pub epoch: u64,
}

/// Run the full scramble pipeline.
///
/// # Pipeline
///
/// 1. `tokenize(source)` — minimal Python tokenizer to `Vec<Token>`.
/// 2. `scramble_chunks(tokens, epoch)` — L4 position-marker insertion
///    + per-epoch chunk shuffle.
/// 3. `inject_decoys(tokens, epoch)` — L5 depth-0 decoy injection.
/// 4. `collect_unique_tokens(tokens)` — sorted unique-token list for
///    the L2 mapping fetch.  *Includes* L4 markers and L5 decoys so
///    the daemon assigns aliases for them too.
/// 5. `scramble_identifiers(tokens, mapping)` — L2 in-place token
///    body replacement.
/// 6. `scramble(tokens, wl)` — L3 token-stream → bytes.
/// 7. `reverse_chunks(body, epoch)` — L6 per-epoch direction reversal
///    of variable-length char chunks.
/// 8. `inject_noise(body, epoch)` — L12 zero-width + Cyrillic-
///    homoglyph noise on body bytes.
/// 9. `encode_file(version, epoch, sorted_tokens, body)` — header +
///    body.
///
/// The caller is expected to:
///
/// 1. Call [`stage_one`] to drive steps 1-4 and obtain the unique-
///    token list + epoch.
/// 2. Round-trip `GetTokenMapping` against the daemon to get the L2
///    mapping for those tokens at that epoch.
/// 3. Call this function with the mapping + wordlist + the
///    intermediate `tokens` to drive steps 5-9.
///
/// Two-phase split: step 4 depends on L4 / L5 having run; step 5
/// depends on the mapping the daemon round-trip produced.  Callers
/// that want a single-call entry point can use [`scramble_pipeline`]
/// which takes a closure for the daemon round-trip.
///
/// # Errors
///
/// L3's [`scramble`] may return an error for malformed input; that
/// error propagates verbatim.
fn scramble_after_mapping(
    tokens: &mut [crate::tokens::Token],
    sorted_tokens: Vec<String>,
    epoch: u64,
    wl: &WhitespaceWordlist,
    id_mapping: &IdentifierMapping,
) -> Result<ScrambledFile> {
    scramble_identifiers(tokens, id_mapping);
    let body = scramble(tokens, wl)?;
    let reversed = reverse_chunks(&body, epoch);
    let noisy = inject_noise(&reversed, epoch);
    let file =
        encode_file(epoch, &sorted_tokens, &noisy);
    Ok(ScrambledFile { file, sorted_tokens })
}

/// Drive the scramble pipeline end-to-end given a closure that
/// fetches the identifier mapping for a (`sorted_tokens`, epoch)
/// pair.
///
/// # Mapping closure contract
///
/// `fetch_mapping(sorted_tokens, epoch)` must return an
/// [`IdentifierMapping`] whose `epoch` field matches the supplied
/// `epoch` argument exactly.  Production callers wrap a
/// `GetTokenMapping` daemon round-trip; tests stub it with a static
/// table.
///
/// # Errors
///
/// - Any `Error` returned by `fetch_mapping`.
/// - L3 [`scramble`] failure.
///
/// # Why a closure
///
/// The daemon round-trip lives in the application crate (operator
/// CLI / Python shim); pulling the daemon protocol into the
/// preprocessor would invert the dependency direction.  A closure
/// keeps the preprocessor pure and lets every caller wire its own
/// daemon-client.
pub fn scramble_pipeline<F>(
    source: &str,
    epoch: u64,
    wl: &WhitespaceWordlist,
    fetch_mapping: F,
) -> Result<ScrambledFile>
where
    F: FnOnce(&[String], u64) -> Result<IdentifierMapping>,
{
    let raw = tokenize(source);
    let l4 = scramble_chunks(raw, epoch);
    let mut l5 = inject_decoys(l4, epoch);
    let sorted_tokens = collect_unique_tokens(&l5);
    let mapping = fetch_mapping(&sorted_tokens, epoch)?;
    if mapping.epoch != epoch {
        return Err(Error::Scramble(format!(
            "fetch_mapping returned epoch {} but caller asked for epoch {epoch}",
            mapping.epoch,
        )));
    }
    scramble_after_mapping(&mut l5, sorted_tokens, epoch, wl, &mapping)
}

/// Run the full unscramble pipeline on a parsed scrambled file.
///
/// # Pipeline
///
/// 1. `strip_noise(body)` — L12 inverse, content-based, idempotent.
/// 2. `unreverse_chunks(body, epoch)` if `version >= 1` — L6 inverse.
///    Skipped for legacy version-0 files which were scrambled before
///    L6 landed.
/// 3. `unscramble_to_tokens(body, wl)` — L3 inverse (greedy prefix
///    match over the per-epoch compounds).
/// 4. `unscramble_identifiers(tokens, mapping)` — L2 inverse.
/// 5. `strip_decoys(tokens)` — L5 inverse, runs BEFORE L4 so the
///    chunk boundary computation is not disturbed by decoy positions.
/// 6. `unscramble_chunks(tokens)` — L4 inverse, sorts chunks back to
///    original order and strips position markers.
/// 7. `tokens_to_source(tokens)` — emit source with canonical
///    whitespace.
///
/// The `version` is the integer from the header; the `body` is the
/// content from after the `---` separator.  Both come from
/// [`decode`](crate::file_format::decode).
#[must_use]
pub fn unscramble_pipeline(
    version: u32,
    epoch: u64,
    body: &str,
    wl: &WhitespaceWordlist,
    id_mapping: &IdentifierMapping,
) -> String {
    let stripped = strip_noise(body);
    let oriented = if version >= 1 {
        unreverse_chunks(&stripped, epoch)
    } else {
        stripped
    };
    let mut tokens = unscramble_to_tokens(&oriented, wl);
    unscramble_identifiers(&mut tokens, id_mapping);
    let dedecoyed = strip_decoys(tokens);
    let reordered = unscramble_chunks(dedecoyed);
    tokens_to_source(&reordered)
}

/// Convenience wrapper: parse a scrambled-file string + run the full
/// unscramble pipeline against the supplied wordlist + mapping.
///
/// Callers that already parsed the header for their own purposes
/// should use [`unscramble_pipeline`] directly with the parsed
/// fields.
///
/// # Errors
///
/// [`Error::HeaderParse`] from [`decode_file`].
pub fn unscramble_full_file(
    scrambled: &str,
    wl: &WhitespaceWordlist,
    fetch_mapping: impl FnOnce(&[String], u64) -> Result<IdentifierMapping>,
) -> Result<String> {
    let DecodedFile { version, epoch, sorted_tokens, body } =
        decode_file(scrambled)?;
    let mapping = fetch_mapping(&sorted_tokens, epoch)?;
    if mapping.epoch != epoch {
        return Err(Error::Scramble(format!(
            "fetch_mapping returned epoch {} but header is epoch {epoch}",
            mapping.epoch,
        )));
    }
    Ok(unscramble_pipeline(version, epoch, &body, wl, &mapping))
}

/// Format version every fresh scrambled file is stamped with.
///
/// Re-exported for callers that want to assert against the latest
/// version without pulling in [`crate::file_format`].
pub const SCRAMBLE_VERSION_LATEST: u32 = FORMAT_VERSION_LATEST;

#[cfg(test)]
mod tests {
    use super::{
        scramble_pipeline, unscramble_full_file, unscramble_pipeline,
        SCRAMBLE_VERSION_LATEST,
    };
    use crate::file_format::decode as decode_file;
    use crate::identifier_scrambler::{IdentifierMapping, ALIAS_COUNT};
    use crate::whitespace_wordlist::WhitespaceWordlist;
    use babbleon_core_v2::per_host_secret::PerHostSecret;
    use babbleon_core_v2::wordlist::Wordlist;

    fn fixed_wl(epoch: u64) -> WhitespaceWordlist {
        let s = PerHostSecret::from_bytes(&[7u8; 32]).unwrap();
        WhitespaceWordlist::build(&s, Wordlist::english_baseline(), epoch).unwrap()
    }

    fn synthetic_mapping(
        sorted_tokens: &[String],
        epoch: u64,
    ) -> crate::errors::Result<IdentifierMapping> {
        let aliases: Vec<Vec<String>> = sorted_tokens
            .iter()
            .enumerate()
            .map(|(t_idx, _)| {
                (0..ALIAS_COUNT)
                    .map(|a| format!("__bbnt{t_idx}_e{epoch}_a{a}__"))
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
    fn full_round_trip_recovers_original_python() {
        let epoch = 0;
        let wl = fixed_wl(epoch);
        let original = "x = 1\nif x:\n    print(\"hi\")\n";

        let scrambled = scramble_pipeline(
            original,
            epoch,
            &wl,
            synthetic_mapping,
        )
        .unwrap();

        let recovered = unscramble_full_file(
            &scrambled.file,
            &wl,
            synthetic_mapping,
        )
        .unwrap();

        assert_eq!(recovered, original);
    }

    #[test]
    fn full_round_trip_for_multi_chunk_program() {
        let epoch = 0;
        let wl = fixed_wl(epoch);
        // Multi-top-level-chunk program exercises L4 reorder + L5
        // decoy injection in addition to the byte-level layers.
        let original = "\
def f(x):
    return x + 1

def g(y):
    return y * 2

print(f(g(3)))
";

        let scrambled =
            scramble_pipeline(original, epoch, &wl, synthetic_mapping).unwrap();

        let recovered =
            unscramble_full_file(&scrambled.file, &wl, synthetic_mapping).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn scrambled_file_header_is_latest_version() {
        let epoch = 0;
        let wl = fixed_wl(epoch);
        let scrambled = scramble_pipeline(
            "x = 1\n",
            epoch,
            &wl,
            synthetic_mapping,
        )
        .unwrap();
        let parsed = decode_file(&scrambled.file).unwrap();
        assert_eq!(parsed.version, SCRAMBLE_VERSION_LATEST);
        assert_eq!(parsed.epoch, epoch);
        assert_eq!(parsed.sorted_tokens, scrambled.sorted_tokens);
    }

    #[test]
    fn scramble_rejects_mismatched_mapping_epoch() {
        let epoch = 0;
        let wl = fixed_wl(epoch);
        let r = scramble_pipeline(
            "x = 1\n",
            epoch,
            &wl,
            |toks, _| synthetic_mapping(toks, 999),
        );
        assert!(r.is_err());
    }

    #[test]
    fn unscramble_full_file_rejects_mismatched_mapping_epoch() {
        let epoch = 0;
        let wl = fixed_wl(epoch);
        let s = scramble_pipeline("x = 1\n", epoch, &wl, synthetic_mapping)
            .unwrap();
        let r = unscramble_full_file(&s.file, &wl, |toks, _| {
            synthetic_mapping(toks, 999)
        });
        assert!(r.is_err());
    }

    #[test]
    fn unscramble_pipeline_handles_legacy_v0_file() {
        // Construct a v0 file in-line: scramble through L4/L5/L2/L3
        // only (skip L6, L12).  This is the historical pre-2026-06-26
        // pipeline; the unscrambler must skip L6 inverse to avoid
        // corrupting the body.
        use crate::chunk_reorder::scramble_chunks;
        use crate::decoy_injection::inject_decoys;
        use crate::identifier_scrambler::{
            collect_unique_tokens, scramble_identifiers,
        };
        use crate::python_tokenizer::tokenize;
        use crate::scrambler::scramble;

        let epoch = 0;
        let wl = fixed_wl(epoch);
        let original = "x = 1\n";
        let raw = tokenize(original);
        let l4 = scramble_chunks(raw, epoch);
        let mut l5 = inject_decoys(l4, epoch);
        let sorted_tokens = collect_unique_tokens(&l5);
        let mapping = synthetic_mapping(&sorted_tokens, epoch).unwrap();
        scramble_identifiers(&mut l5, &mapping);
        let body = scramble(&l5, &wl).unwrap();
        // No L6, no L12.  Unscramble with version=0; the pipeline
        // must skip the L6 inverse and treat the body as L3-only.
        let recovered = unscramble_pipeline(0, epoch, &body, &wl, &mapping);
        assert_eq!(recovered, original);
    }

    #[test]
    fn fetch_mapping_error_propagates_through_scramble() {
        let epoch = 0;
        let wl = fixed_wl(epoch);
        let r: crate::errors::Result<_> = scramble_pipeline(
            "x = 1\n",
            epoch,
            &wl,
            |_, _| Err(crate::errors::Error::Scramble("synthetic".into())),
        );
        assert!(r.is_err());
    }
}
