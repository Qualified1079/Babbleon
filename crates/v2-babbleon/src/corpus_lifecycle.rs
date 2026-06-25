//! `babbleon scramble-dir` and `babbleon unscramble-dir` lifecycle.
//!
//! # What this defeats
//!
//! Install-time corpus scrambling.  A vendored Python tree (a
//! library install, a `pip install --target` output, a frozen
//! application bundle) is hundreds-to-thousands of `.py` files.
//! The per-file `babbleon scramble` subcommand works on each, but
//! invoking it a thousand times has two costs:
//!
//! 1. **Process spawn overhead.**  fork + exec + Rust runtime init
//!    per file is wall-clock-significant against the < 50 µs of
//!    actual layer-3 compute (see `tools/preprocessor-benchmark/`).
//! 2. **Whitespace-compound fetch per file.**  Each invocation does
//!    one `Request::GetWhitespaceCompounds` exchange even though the
//!    compounds are identical for every file in the same epoch.
//!
//! `scramble-dir` collapses the whitespace fetch: ONE
//! `GetWhitespaceCompounds` round-trip, reused across the whole tree.
//! Each file still requires its own `GetTokenMapping` round-trip
//! (the dynamic identifier scrambler is per-file since each file
//! has a unique token set), but the whitespace compounds are shared.
//!
//! # Compartmentalisation
//!
//! Same as the per-file pipeline (see `scramble_lifecycle.rs`): the
//! CLI process never holds the per-host secret.  The daemon round-trip
//! yields only HKDF-derived compounds per request.
//!
//! # Pipeline
//!
//! 1. Validate input / output directories.  Output dir must not
//!    exist (or must be empty) unless `--force`.
//! 2. Fetch whitespace compounds (one daemon round-trip).
//! 3. Walk input dir recursively.  For each `.py` file:
//!    - Compute the relative path.
//!    - Read source bytes, tokenize, collect unique tokens.
//!    - `GetTokenMapping` for this file's tokens (L2 daemon call).
//!    - `scramble_identifiers` (L2, in-place).
//!    - `scramble` to bytes (L3, reusing shared whitespace wordlist).
//!    - Prepend per-file header (epoch + sorted token list).
//!    - Write to `output_dir / relative_path`.
//! 4. Report counts to stdout: files processed, bytes in / out,
//!    wall-clock elapsed.
//!
//! Non-`.py` files are skipped silently in MVP; future revision
//! can add a `--include-glob` flag.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{anyhow, Context, Result};

use babbleon_preprocessor_v2::chunk_reorder::{scramble_chunks, unscramble_chunks};
use babbleon_preprocessor_v2::decoy_injection::{inject_decoys, strip_decoys};
use babbleon_preprocessor_v2::direction_reversal::{reverse_chunks, unreverse_chunks};
use babbleon_preprocessor_v2::identifier_scrambler::{
    collect_unique_tokens, scramble_identifiers, unscramble_identifiers,
};
use babbleon_preprocessor_v2::python_tokenizer::tokenize;
use babbleon_preprocessor_v2::scrambler::scramble;
use babbleon_preprocessor_v2::tokenizer_noise::{inject_noise, strip_noise};
use babbleon_preprocessor_v2::unscrambler::{tokens_to_source, unscramble_to_tokens};

use crate::scramble_lifecycle::{
    decode_scrambled_file, encode_scrambled_file,
    fetch_identifier_mapping_at_epoch_pub as fetch_identifier_mapping_at_epoch,
    fetch_identifier_mapping_pub as fetch_identifier_mapping,
    fetch_whitespace_wordlist_pub as fetch_whitespace_wordlist,
};

/// Operator options for the directory-batch subcommands.
pub struct CorpusOptions {
    /// Source tree to read.
    pub input_dir: PathBuf,
    /// Destination tree to write.  Must not exist (or be empty)
    /// unless `allow_overwrite` is set.
    pub output_dir: PathBuf,
    /// Permit writing into a non-empty output directory.  Existing
    /// files at colliding paths are overwritten; existing files at
    /// non-colliding paths are left alone.
    pub allow_overwrite: bool,
    /// Daemon socket path.
    pub socket_path: PathBuf,
}

/// Result counters reported on stdout.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CorpusReport {
    /// Number of `.py` files transformed.
    pub files_transformed: usize,
    /// Total source bytes read.
    pub bytes_in: u64,
    /// Total bytes written.
    pub bytes_out: u64,
    /// Wall-clock elapsed milliseconds.
    pub elapsed_ms: u128,
}

/// Run `babbleon scramble-dir`.
///
/// # Errors
///
/// - Input dir missing or unreadable.
/// - Output dir exists + non-empty without `--force`.
/// - Daemon round-trip / compound-validation failure.
/// - Filesystem failure on any read or write inside the walk.
/// - Per-file scramble failure (whitespace-compound collision).
pub fn run_scramble_dir(opts: CorpusOptions) -> Result<CorpusReport> {
    let CorpusOptions {
        input_dir,
        output_dir,
        allow_overwrite,
        socket_path,
    } = opts;
    validate_input_dir(&input_dir)?;
    prepare_output_dir(&output_dir, allow_overwrite)?;

    let wl = fetch_whitespace_wordlist(&socket_path)?;
    let start = Instant::now();
    let mut report = CorpusReport::default();

    walk_and_apply(
        &input_dir,
        &input_dir,
        &output_dir,
        &mut |src| {
            let raw_tokens = tokenize(src);
            // Pre-L4 daemon call: just to obtain the live epoch.  The
            // L4/L5 shuffle seed and the L2 mapping share the same
            // epoch so unscramble re-derives the same stream shape.
            let unique = collect_unique_tokens(&raw_tokens);
            let mapping = fetch_identifier_mapping(&socket_path, &unique)
                .context("GetTokenMapping for file (pre-L4)")?;
            // L4: chunk-shuffle + position markers.
            let l4_tokens = scramble_chunks(raw_tokens, mapping.epoch);
            // L5: decoy injection at depth-0 positions.
            let mut tokens = inject_decoys(l4_tokens, mapping.epoch);
            // Refetch mapping covering the L4+L5 augmented token set.
            let unique_post = collect_unique_tokens(&tokens);
            let mapping = fetch_identifier_mapping_at_epoch(
                &socket_path,
                &unique_post,
                mapping.epoch,
            )?;
            scramble_identifiers(&mut tokens, &mapping);
            let body =
                scramble(&tokens, &wl).map_err(|e| anyhow!("scramble: {e}"))?;
            // L6: direction reversal of variable-length char chunks.
            let reversed_body = reverse_chunks(&body, mapping.epoch);
            // L12: tokenizer-hostile noise on body bytes.  Applied
            // after L6 so the header round-trips byte-for-byte and
            // the noise lands on the reversed wall.
            let noisy_body = inject_noise(&reversed_body, mapping.epoch);
            Ok(encode_scrambled_file(mapping.epoch, &unique_post, &noisy_body))
        },
        &mut report,
    )?;

    report.elapsed_ms = start.elapsed().as_millis();
    Ok(report)
}

/// Run `babbleon unscramble-dir`.  Inverse of `run_scramble_dir`.
///
/// # Errors
///
/// Same shape as [`run_scramble_dir`], minus the
/// whitespace-compound-collision path (unscramble is currently
/// infallible in MVP).
pub fn run_unscramble_dir(opts: CorpusOptions) -> Result<CorpusReport> {
    let CorpusOptions {
        input_dir,
        output_dir,
        allow_overwrite,
        socket_path,
    } = opts;
    validate_input_dir(&input_dir)?;
    prepare_output_dir(&output_dir, allow_overwrite)?;

    let wl = fetch_whitespace_wordlist(&socket_path)?;
    let start = Instant::now();
    let mut report = CorpusReport::default();

    walk_and_apply(
        &input_dir,
        &input_dir,
        &output_dir,
        &mut |src| {
            let (version, epoch, sorted_tokens, body) =
                decode_scrambled_file(src)
                    .map_err(|e| anyhow!("parse header: {e}"))?;
            let mapping = fetch_identifier_mapping_at_epoch(
                &socket_path,
                &sorted_tokens,
                epoch,
            )?;
            // L12 inverse: strip noise before L3's greedy prefix
            // match.  Content-based and idempotent — safe on v0
            // files (no-op when body has no noise).
            let body = strip_noise(&body);
            // L6 inverse: undo the per-epoch direction reversal,
            // gated on format version.  v0 files predate L6.
            let body = if version >= 1 {
                unreverse_chunks(&body, epoch)
            } else {
                body
            };
            let mut tokens = unscramble_to_tokens(&body, &wl);
            unscramble_identifiers(&mut tokens, &mapping);
            // L5 inverse: strip decoy tokens BEFORE L4 reorder so
            // chunk-boundary detection isn't disturbed by decoys.
            let dedecoyed = strip_decoys(tokens);
            // L4 inverse: sort chunks back to original order, strip
            // markers.  No-op when the file went through the
            // single-chunk fast path on scramble (no markers present).
            let reordered = unscramble_chunks(dedecoyed);
            Ok(tokens_to_source(&reordered))
        },
        &mut report,
    )?;

    report.elapsed_ms = start.elapsed().as_millis();
    Ok(report)
}

fn validate_input_dir(input_dir: &Path) -> Result<()> {
    let meta = fs::metadata(input_dir)
        .with_context(|| format!("stat input dir {}", input_dir.display()))?;
    if !meta.is_dir() {
        return Err(anyhow!(
            "input dir {} is not a directory",
            input_dir.display(),
        ));
    }
    Ok(())
}

fn prepare_output_dir(output_dir: &Path, allow_overwrite: bool) -> Result<()> {
    if output_dir.exists() {
        let meta = fs::metadata(output_dir).with_context(|| {
            format!("stat output dir {}", output_dir.display())
        })?;
        if !meta.is_dir() {
            return Err(anyhow!(
                "output path {} exists and is not a directory",
                output_dir.display(),
            ));
        }
        if !allow_overwrite {
            let mut entries = fs::read_dir(output_dir).with_context(|| {
                format!("read output dir {}", output_dir.display())
            })?;
            if entries.next().is_some() {
                return Err(anyhow!(
                    "output dir {} is non-empty; pass --force to permit overwrite",
                    output_dir.display(),
                ));
            }
        }
    } else {
        fs::create_dir_all(output_dir).with_context(|| {
            format!("create output dir {}", output_dir.display())
        })?;
    }
    Ok(())
}

/// Recursively walk `dir`, transforming each `.py` file via `apply`
/// and writing the result to `output_root / relative_path`.
fn walk_and_apply(
    walk_root: &Path,
    dir: &Path,
    output_root: &Path,
    apply: &mut dyn FnMut(&str) -> Result<String>,
    report: &mut CorpusReport,
) -> Result<()> {
    let entries = fs::read_dir(dir)
        .with_context(|| format!("read dir {}", dir.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| {
            format!("iterate dir {}", dir.display())
        })?;
        let path = entry.path();
        let file_type = entry.file_type().with_context(|| {
            format!("stat {}", path.display())
        })?;
        if file_type.is_dir() {
            walk_and_apply(walk_root, &path, output_root, apply, report)?;
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }
        let rel = path.strip_prefix(walk_root).with_context(|| {
            format!(
                "compute relative path of {} against {}",
                path.display(),
                walk_root.display(),
            )
        })?;
        let out_path = output_root.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("create {}", parent.display())
            })?;
        }
        let src = fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?;
        let bytes_in = u64::try_from(src.len()).unwrap_or(u64::MAX);
        let out = apply(&src)?;
        let bytes_out = u64::try_from(out.len()).unwrap_or(u64::MAX);
        fs::write(&out_path, out.as_bytes()).with_context(|| {
            format!("write {}", out_path.display())
        })?;
        report.files_transformed = report.files_transformed.saturating_add(1);
        report.bytes_in = report.bytes_in.saturating_add(bytes_in);
        report.bytes_out = report.bytes_out.saturating_add(bytes_out);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        prepare_output_dir, validate_input_dir, walk_and_apply,
        CorpusReport,
    };
    use anyhow::Result;
    use std::fs;

    #[test]
    fn validate_input_dir_accepts_existing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        validate_input_dir(tmp.path()).unwrap();
    }

    #[test]
    fn validate_input_dir_rejects_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let bad = tmp.path().join("no-such-dir");
        assert!(validate_input_dir(&bad).is_err());
    }

    #[test]
    fn validate_input_dir_rejects_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("x.py");
        fs::write(&f, "x = 1").unwrap();
        let err = validate_input_dir(&f).unwrap_err();
        assert!(err.to_string().contains("not a directory"));
    }

    #[test]
    fn prepare_output_dir_creates_new_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("new-output");
        prepare_output_dir(&out, false).unwrap();
        assert!(out.is_dir());
    }

    #[test]
    fn prepare_output_dir_accepts_empty_existing_dir() {
        let tmp = tempfile::tempdir().unwrap();
        prepare_output_dir(tmp.path(), false).unwrap();
    }

    #[test]
    fn prepare_output_dir_refuses_non_empty_without_force() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("existing.txt"), "x").unwrap();
        let err = prepare_output_dir(tmp.path(), false).unwrap_err();
        assert!(err.to_string().contains("non-empty"));
    }

    #[test]
    fn prepare_output_dir_accepts_non_empty_with_force() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("existing.txt"), "x").unwrap();
        prepare_output_dir(tmp.path(), true).unwrap();
    }

    #[test]
    fn walk_and_apply_transforms_every_py_file_and_skips_others() {
        // Build a tree with .py and non-.py files; assert the
        // visitor sees only .py paths and the output tree mirrors
        // the input layout.
        let tmp = tempfile::tempdir().unwrap();
        let inp = tmp.path().join("in");
        let out = tmp.path().join("out");
        fs::create_dir_all(inp.join("sub")).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(inp.join("a.py"), "x = 1\n").unwrap();
        fs::write(inp.join("b.txt"), "not python\n").unwrap();
        fs::write(inp.join("sub").join("c.py"), "y = 2\n").unwrap();
        fs::write(inp.join("sub").join("README"), "doc\n").unwrap();

        let mut report = CorpusReport::default();
        let mut apply = |src: &str| -> Result<String> {
            Ok(format!("# transformed\n{src}"))
        };
        walk_and_apply(&inp, &inp, &out, &mut apply, &mut report).unwrap();

        assert_eq!(report.files_transformed, 2);
        assert!(out.join("a.py").exists());
        assert!(out.join("sub").join("c.py").exists());
        assert!(!out.join("b.txt").exists(), ".txt must be skipped");
        assert!(
            !out.join("sub").join("README").exists(),
            "non-extensioned files must be skipped",
        );

        let out_a = fs::read_to_string(out.join("a.py")).unwrap();
        assert_eq!(out_a, "# transformed\nx = 1\n");
        let out_c = fs::read_to_string(out.join("sub").join("c.py")).unwrap();
        assert_eq!(out_c, "# transformed\ny = 2\n");
    }

    #[test]
    fn walk_and_apply_handles_empty_input_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let inp = tmp.path().join("in");
        let out = tmp.path().join("out");
        fs::create_dir_all(&inp).unwrap();
        fs::create_dir_all(&out).unwrap();
        let mut report = CorpusReport::default();
        let mut apply = |src: &str| -> Result<String> { Ok(src.to_string()) };
        walk_and_apply(&inp, &inp, &out, &mut apply, &mut report).unwrap();
        assert_eq!(report.files_transformed, 0);
    }

    #[test]
    fn walk_and_apply_propagates_apply_error_with_path_context() {
        let tmp = tempfile::tempdir().unwrap();
        let inp = tmp.path().join("in");
        let out = tmp.path().join("out");
        fs::create_dir_all(&inp).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(inp.join("boom.py"), "x = 1\n").unwrap();
        let mut report = CorpusReport::default();
        let mut apply = |_src: &str| -> Result<String> {
            Err(anyhow::anyhow!("synthetic"))
        };
        let err =
            walk_and_apply(&inp, &inp, &out, &mut apply, &mut report)
                .unwrap_err();
        assert!(err.to_string().contains("synthetic"));
    }
}
