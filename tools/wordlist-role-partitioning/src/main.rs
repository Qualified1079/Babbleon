//! CLI orchestration.
//!
//! # Why this exists
//!
//! `HANDOFF.md` 2026-07-02 refreshed next-session priorities item 5:
//! "Wordlist role-partitioning formula.  A formula `N_role =
//! f(rotation_hz, work_factor, compound_n)` would let the density
//! filter and the role budget be tuned jointly rather than by
//! back-of-envelope."  This is the executable form of that formula.
//!
//! # What the CLI does
//!
//! Given a wordlist model (baseline or `intersect[3,5]`), an attacker
//! model (developer-laptop default or custom knobs), and a role
//! table (provisional-v2 or `--roles-toml` in future), print the
//! per-role pool allocation plus a fit-in-wordlist verdict.  Emit an
//! optional markdown fragment for drop-in inclusion in `docs/v2/`.
//!
//! # What it does NOT do
//!
//! - Does not touch `v2-babbleon-core::wordlist`.  Same discipline as
//!   the sibling `wordlist-density-analysis` tool: analysis only,
//!   wiring is a separate diff.
//! - Does not run the tokenizer.  It consumes the mean tokens-per-
//!   compound number the sibling tool produced.
//! - Does not decide which filtered wordlist to ship.  It reports
//!   the pool math so the operator can make that call informed.

mod allocation;
mod entropy;
mod extract;
mod normalise;
mod params;
mod report;
mod seed;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use crate::allocation::AllocationTable;
use crate::params::{AttackerModel, Role, WordlistModel};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum WordlistPreset {
    /// `crates/babbleon/wordlist/words.txt` under cl100k_base:
    /// 369 652 entries, 11.96 tokens/compound (compound_n=4).
    Cl100kBaseline,
    /// `intersect[3, 5]` cl100k+o200k filter output: 223 009
    /// entries, 13.80 tokens/compound (compound_n=4).
    Cl100kIntersect35,
}

impl WordlistPreset {
    fn resolve(self) -> WordlistModel {
        match self {
            Self::Cl100kBaseline => WordlistModel::cl100k_baseline(),
            Self::Cl100kIntersect35 => WordlistModel::cl100k_intersect_3_5(),
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RolePreset {
    /// Six roles from `docs/v2/phase0-research-notes.md` §11.
    ProvisionalV2,
}

impl RolePreset {
    fn resolve(self) -> Vec<Role> {
        match self {
            Self::ProvisionalV2 => Role::provisional_v2_table(),
        }
    }
}

fn parse_role_tokens_arg(raw: &str) -> Result<(String, f64), String> {
    let (name, value) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected `name=value`, got {raw:?}"))?;
    let value: f64 = value
        .parse()
        .map_err(|e| format!("invalid tokens value for role {name}: {e}"))?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!("tokens value for role {name} must be finite and non-negative"));
    }
    Ok((name.to_string(), value))
}

fn apply_role_tokens_overrides(
    roles: &mut [Role],
    overrides: &[(String, f64)],
) -> Result<(), String> {
    for (name, value) in overrides {
        let matched = roles.iter_mut().find(|r| r.name == *name);
        match matched {
            Some(role) => role.tokens_per_compound = Some(*value),
            None => {
                let available: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
                return Err(format!(
                    "unknown role {name:?} for --role-tokens; available: {available:?}"
                ));
            }
        }
    }
    Ok(())
}

#[derive(Parser)]
#[command(
    version,
    about = "Compute per-role wordlist pool sizes for Babbleon v2 using birthday-bound entropy budgets."
)]
struct Args {
    /// Which wordlist to allocate against.
    #[arg(long, value_enum, default_value_t = WordlistPreset::Cl100kBaseline)]
    wordlist: WordlistPreset,

    /// Override the wordlist size (defaults to the preset's number).
    /// Useful for what-if analysis (e.g. what happens if we swap in
    /// a smaller filter output).
    #[arg(long)]
    wordlist_size: Option<usize>,

    /// Override the wordlist mean tokens-per-compound number.
    #[arg(long)]
    wordlist_mean_tokens: Option<f64>,

    /// Which role table to use.
    #[arg(long, value_enum, default_value_t = RolePreset::ProvisionalV2)]
    roles: RolePreset,

    /// Per-role tokens-per-compound overrides.  Repeated `--role-tokens
    /// name=value` pairs each set `Role.tokens_per_compound` for the
    /// matching role.  Unknown names error out.  Attention multiplier
    /// = `(role_value / wordlist.baseline_mean_tokens)^2`, so setting
    /// e.g. `--role-tokens identifier=13.80 --wordlist-mean-tokens
    /// 11.96` reports the intersect-vs-baseline attention gain for
    /// the identifier role directly.
    #[arg(long = "role-tokens", value_parser = parse_role_tokens_arg)]
    role_tokens: Vec<(String, f64)>,

    /// Switch to the `paranoid_default` attacker preset (1e-12
    /// lifetime collision probability, 2 000 events/epoch, 8 760-
    /// epoch lifetime).  Under this preset the provisional-v2 role
    /// table does NOT fit in the baseline wordlist — the tool
    /// reports the shortfall as expected output.
    #[arg(long, default_value_t = false)]
    paranoid: bool,

    /// Attacker: distinct compound-observations per epoch.  Defaults
    /// to the developer-laptop preset (2 000).
    #[arg(long)]
    events_per_epoch: Option<u64>,

    /// Attacker: acceptable collision probability per lifetime.
    /// Default depends on `--paranoid`: 1e-6 (default) or 1e-12
    /// (paranoid).
    #[arg(long)]
    collision_probability: Option<f64>,

    /// Attacker: how many epochs the same host secret must survive.
    /// Defaults to 8 760 (one year at 24 rotations/day).
    #[arg(long)]
    lifetime_epochs: Option<u64>,

    /// Write the markdown report to this path (in addition to
    /// printing the text report on stdout).
    #[arg(long)]
    report_out: Option<PathBuf>,

    /// Path to a raw wordlist (one lowercase-ASCII word per line).
    /// Required for `--extract-to`.  May be repeated to union
    /// multiple wordlists — the extractor concatenates them in
    /// order and dedupes; per-source SHA-256 hashes land in the
    /// extraction manifest.  Defaults to the v1 baseline when
    /// unset.
    #[arg(long)]
    wordlist_path: Vec<PathBuf>,

    /// Extract disjoint per-role subsets into this directory.
    /// Emits one text file per role — for example
    /// `identifier.txt`, `decoy.txt`, ... — plus a `MANIFEST.txt`
    /// with the seed, wordlist hash, and per-role sizes.  The
    /// directory must not already contain per-role files; the tool
    /// refuses to overwrite.
    #[arg(long)]
    extract_to: Option<PathBuf>,

    /// Seed bytes for the extractor's PRNG, passed as a UTF-8
    /// string.  SHA-256'd internally.  If unset and no
    /// `--extract-seed-file` is provided, the tool uses a fixed
    /// developer default so reruns without a seed are deterministic
    /// (and match published RESULTS).  Production use should prefer
    /// `--extract-seed-file` + `--extract-domain-label`.
    #[arg(long, default_value = "babbleon-role-partitioning-dev-seed",
          conflicts_with = "extract_seed_file")]
    extract_seed: String,

    /// Path to a file containing the raw per-host secret (any
    /// bytes).  When present, the extractor derives its 32-byte
    /// ChaCha seed via HKDF-Expand-SHA256(secret, label) where
    /// `label = --extract-domain-label`.  This is the production
    /// path: the secret never appears on the command line, and
    /// the domain label lets the same secret drive both this tool
    /// and unrelated runtime paths without cross-purpose
    /// correlation.
    #[arg(long, requires = "extract_domain_label")]
    extract_seed_file: Option<PathBuf>,

    /// HKDF-Expand `info` parameter — the domain-separator label
    /// that scopes the derived seed.  Required with
    /// `--extract-seed-file`.  Convention:
    /// `babbleon/v2/role-partitioning/<epoch>` so consecutive
    /// epochs deterministically produce different subsets from
    /// the same host secret.
    #[arg(long)]
    extract_domain_label: Option<String>,

    /// Verify a previously-extracted directory.  Reads MANIFEST.txt,
    /// re-loads every `<role>.txt`, checks that each role's line
    /// count matches the manifest, and re-verifies disjointness
    /// across all files.  Exits non-zero on any mismatch.  Nice
    /// operator audit for a checked-in extraction.  Mutually
    /// exclusive with `--extract-to`.
    #[arg(long, conflicts_with = "extract_to")]
    verify_extracted: Option<PathBuf>,

    /// Skip the stdout summary; useful when scripting `--report-out`.
    #[arg(long, default_value_t = false)]
    quiet: bool,

    /// NFKD-normalise + fold diacritics on every wordlist entry
    /// before union/dedupe, mirroring
    /// `tools/wordlist-density-analysis --normalise-diacritics`.
    /// `café` becomes `cafe`; entries that collide after folding are
    /// deduped (first-occurrence wins).  Off by default so the
    /// English-baseline path is byte-identical to before.  Required
    /// before extracting from any non-English source, since the
    /// runtime loader (`crates/v2-babbleon-core::wordlist`) rejects
    /// non-`[a-z]+` entries outright.
    #[arg(long, default_value_t = false)]
    normalise_diacritics: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut wordlist = args.wordlist.resolve();
    if let Some(size) = args.wordlist_size {
        wordlist.size = size;
    }
    if let Some(mean_tokens) = args.wordlist_mean_tokens {
        wordlist.baseline_mean_tokens_per_compound = mean_tokens;
    }

    let default_attacker = if args.paranoid {
        AttackerModel::paranoid_default()
    } else {
        AttackerModel::developer_laptop_default()
    };
    let attacker = AttackerModel {
        n_events_per_epoch: args
            .events_per_epoch
            .unwrap_or(default_attacker.n_events_per_epoch),
        target_collision_probability: args
            .collision_probability
            .unwrap_or(default_attacker.target_collision_probability),
        secret_lifetime_epochs: args
            .lifetime_epochs
            .unwrap_or(default_attacker.secret_lifetime_epochs),
    };

    let mut roles = args.roles.resolve();
    apply_role_tokens_overrides(&mut roles, &args.role_tokens)
        .map_err(|e| anyhow::anyhow!("--role-tokens: {e}"))?;
    let table = AllocationTable::compute(&roles, &attacker, &wordlist);

    if !args.quiet {
        print!("{}", report::render_text(&table));
    }

    if let Some(path) = &args.report_out {
        let markdown = report::render_markdown(&table);
        std::fs::write(path, markdown)
            .with_context(|| format!("write markdown report to {}", path.display()))?;
        if !args.quiet {
            println!("\nWrote markdown report to {}", path.display());
        }
    }

    if let Some(dir) = &args.extract_to {
        let extract_input = build_extract_seed(&args)?;
        let wordlist_paths: Vec<PathBuf> = if args.wordlist_path.is_empty() {
            vec![PathBuf::from("../../crates/babbleon/wordlist/words.txt")]
        } else {
            args.wordlist_path.clone()
        };
        extract_and_write(
            &table,
            &wordlist_paths,
            dir,
            &extract_input,
            args.quiet,
            args.normalise_diacritics,
        )?;
    }

    if let Some(dir) = &args.verify_extracted {
        verify_extracted_dir(dir, args.quiet)?;
    }

    Ok(())
}

/// Read `<dir>/MANIFEST.txt`, parse the `role,size,file` block, then
/// re-load every listed file and cross-check the line counts against
/// the manifest.  Also re-verify disjointness across all files.
/// Errors out on the first mismatch.
fn verify_extracted_dir(dir: &std::path::Path, quiet: bool) -> Result<()> {
    let manifest_path = dir.join("MANIFEST.txt");
    let manifest = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;

    // The role block starts with a line beginning `role,size,file`
    // and consists of `name,count,filename` rows until an empty line
    // or end of file.
    let mut rows: Vec<(String, usize, String)> = Vec::new();
    let mut in_block = false;
    for line in manifest.lines() {
        if line.starts_with("role,size,file") {
            in_block = true;
            continue;
        }
        if !in_block {
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        let parts: Vec<&str> = trimmed.split(',').collect();
        if parts.len() != 3 {
            anyhow::bail!("malformed manifest row: {trimmed:?}");
        }
        let size: usize = parts[1]
            .parse()
            .with_context(|| format!("parse size in row {trimmed:?}"))?;
        rows.push((parts[0].to_string(), size, parts[2].to_string()));
    }
    if rows.is_empty() {
        anyhow::bail!(
            "manifest {} has no role rows (expected `role,size,file` block)",
            manifest_path.display()
        );
    }

    let mut all_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut total_verified = 0usize;
    for (role, expected_size, filename) in &rows {
        let path = dir.join(filename);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("read role file {}", path.display()))?;
        let words: Vec<&str> = content
            .lines()
            .map(str::trim)
            .filter(|w| !w.is_empty())
            .collect();
        if words.len() != *expected_size {
            anyhow::bail!(
                "role {role}: file {} has {} words, manifest says {}",
                path.display(),
                words.len(),
                expected_size,
            );
        }
        for w in &words {
            if !all_seen.insert(w.to_string()) {
                anyhow::bail!(
                    "role {role}: word {w:?} in {} also appears in an earlier role file",
                    path.display(),
                );
            }
        }
        total_verified += words.len();
        if !quiet {
            println!("  verified {role}: {} words in {}", words.len(), path.display());
        }
    }

    if !quiet {
        println!("\nVerified {total_verified} words across {} roles.  OK.", rows.len());
    }
    Ok(())
}

/// Concatenated wordlist plus per-source provenance for the
/// manifest.
struct UnionedWordlist {
    /// Deduped-in-order concatenation of every source.
    union: Vec<String>,
    /// Manifest rows, one per source file.
    sources: Vec<UnionSourceRow>,
}

struct UnionSourceRow {
    path: PathBuf,
    raw_entries: usize,
    contributed: usize,
    sha256_hex: String,
}

fn load_and_union_wordlists(
    paths: &[PathBuf],
    quiet: bool,
    normalise_diacritics: bool,
) -> Result<UnionedWordlist> {
    use sha2::{Digest, Sha256};

    let mut union: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    let mut sources: Vec<UnionSourceRow> = Vec::with_capacity(paths.len());

    for path in paths {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read wordlist at {}", path.display()))?;
        let raw_entries = raw.lines().filter(|w| !w.trim().is_empty()).count();
        let mut contributed = 0usize;
        for line in raw.lines() {
            let w = line.trim();
            if w.is_empty() {
                continue;
            }
            // Normalise BEFORE the union-wide dedupe check so a word
            // that only differs by diacritics from an already-seen
            // entry (in this source or an earlier one) collapses to
            // one entry — same first-occurrence-wins rule the density
            // tool uses.
            let w = if normalise_diacritics {
                normalise::strip_combining_marks(w)
            } else {
                w.to_string()
            };
            if w.is_empty() {
                continue;
            }
            if seen.insert(w.clone()) {
                union.push(w);
                contributed += 1;
            }
        }
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        let sha = hasher.finalize();
        if !quiet {
            println!(
                "\nLoaded {raw_entries} words from {} ({contributed} new after dedupe)",
                path.display(),
            );
        }
        sources.push(UnionSourceRow {
            path: path.clone(),
            raw_entries,
            contributed,
            sha256_hex: format!("{sha:x}"),
        });
    }

    if union.is_empty() {
        anyhow::bail!("union of {} wordlists is empty", paths.len());
    }
    if !quiet && paths.len() > 1 {
        println!("Union: {} words across {} sources", union.len(), paths.len());
    }
    Ok(UnionedWordlist { union, sources })
}

/// Bytes that will be fed to `extract::extract_disjoint_subsets` +
/// audit metadata for the manifest.
struct ExtractSeedInput {
    /// Raw bytes handed to the extractor's PRNG derivation.
    seed_bytes: Vec<u8>,
    /// Human-readable provenance for the manifest.
    source: ExtractSeedSource,
}

enum ExtractSeedSource {
    /// `--extract-seed <utf8>` used.  We record the string so the
    /// manifest is fully reproducible.  Safe for the dev seed;
    /// production paths use `File` instead.
    String(String),
    /// `--extract-seed-file <path> --extract-domain-label <label>`
    /// used.  The manifest records `path`, `label`, and the
    /// SHA-256 of the file contents so integrity can be verified
    /// without exposing the secret.
    File {
        path: PathBuf,
        label: String,
        secret_sha256_hex: String,
    },
}

fn build_extract_seed(args: &Args) -> Result<ExtractSeedInput> {
    if let Some(path) = &args.extract_seed_file {
        let label = args
            .extract_domain_label
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "--extract-seed-file requires --extract-domain-label (clap should have caught this)"
                )
            })?;
        let secret = std::fs::read(path)
            .with_context(|| format!("read extract seed file {}", path.display()))?;
        let derived = seed::derive_seed_bytes(&secret, label.as_bytes());
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&secret);
        let secret_hash = hasher.finalize();
        Ok(ExtractSeedInput {
            seed_bytes: derived.to_vec(),
            source: ExtractSeedSource::File {
                path: path.clone(),
                label: label.to_string(),
                secret_sha256_hex: format!("{secret_hash:x}"),
            },
        })
    } else {
        Ok(ExtractSeedInput {
            seed_bytes: args.extract_seed.as_bytes().to_vec(),
            source: ExtractSeedSource::String(args.extract_seed.clone()),
        })
    }
}

fn extract_and_write(
    table: &AllocationTable,
    wordlist_paths: &[PathBuf],
    out_dir: &std::path::Path,
    seed_input: &ExtractSeedInput,
    quiet: bool,
    normalise_diacritics: bool,
) -> Result<()> {
    let sources = load_and_union_wordlists(wordlist_paths, quiet, normalise_diacritics)?;
    // Vec<String> in insertion order.  Convert to &str borrow so
    // extract::extract_disjoint_subsets can take it directly.
    let words_borrow: Vec<&str> = sources.union.iter().map(String::as_str).collect();

    let extraction =
        extract::extract_disjoint_subsets(&words_borrow, table, &seed_input.seed_bytes)
            .map_err(|e| anyhow::anyhow!("extraction failed: {e}"))?;
    extraction
        .assert_disjoint()
        .map_err(|e| anyhow::anyhow!("disjointness sanity check failed: {e}"))?;

    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("create output dir {}", out_dir.display()))?;

    // Refuse to overwrite existing per-role files — the operator
    // must delete them intentionally if they want to re-extract.
    for subset in &extraction.subsets {
        let path = out_dir.join(format!("{}.txt", subset.role_name));
        if path.exists() {
            anyhow::bail!(
                "refusing to overwrite {} — delete it first if intentional",
                path.display()
            );
        }
    }

    for subset in &extraction.subsets {
        let path = out_dir.join(format!("{}.txt", subset.role_name));
        let mut body = String::with_capacity(subset.words.iter().map(|w| w.len() + 1).sum());
        for w in &subset.words {
            body.push_str(w);
            body.push('\n');
        }
        std::fs::write(&path, body)
            .with_context(|| format!("write role subset to {}", path.display()))?;
        if !quiet {
            println!("  wrote {} words to {}", subset.words.len(), path.display());
        }
    }

    // Emit a manifest so re-extraction is auditable.
    let mut manifest = String::new();
    manifest.push_str("Babbleon v2 wordlist role-partitioning — extraction manifest\n\n");
    manifest.push_str(&format!("union_size: {}\n", sources.union.len()));
    manifest.push_str(&format!("source_count: {}\n", sources.sources.len()));
    manifest.push_str(&format!("normalise_diacritics: {normalise_diacritics}\n"));
    manifest.push_str("\nsources (path,raw_entries,contributed,sha256):\n");
    for src in &sources.sources {
        manifest.push_str(&format!(
            "  {},{},{},{}\n",
            src.path.display(),
            src.raw_entries,
            src.contributed,
            src.sha256_hex,
        ));
    }
    manifest.push('\n');
    match &seed_input.source {
        ExtractSeedSource::String(s) => {
            manifest.push_str("seed_source: string\n");
            manifest.push_str(&format!("seed_utf8: {s:?}\n"));
        }
        ExtractSeedSource::File {
            path,
            label,
            secret_sha256_hex,
        } => {
            manifest.push_str("seed_source: hkdf-file\n");
            manifest.push_str(&format!("secret_path: {}\n", path.display()));
            manifest.push_str(&format!("secret_sha256: {secret_sha256_hex}\n"));
            manifest.push_str(&format!("domain_label: {label:?}\n"));
        }
    }
    manifest.push_str(&format!("total_extracted_words: {}\n", extraction.total_words()));
    manifest.push_str("\nrole,size,file\n");
    for subset in &extraction.subsets {
        manifest.push_str(&format!(
            "{},{},{}.txt\n",
            subset.role_name,
            subset.words.len(),
            subset.role_name,
        ));
    }
    let manifest_path = out_dir.join("MANIFEST.txt");
    std::fs::write(&manifest_path, manifest)
        .with_context(|| format!("write manifest to {}", manifest_path.display()))?;
    if !quiet {
        println!("  wrote manifest to {}", manifest_path.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{apply_role_tokens_overrides, parse_role_tokens_arg};
    use crate::params::Role;

    #[test]
    fn parse_role_tokens_arg_accepts_valid_input() {
        let (name, value) = parse_role_tokens_arg("identifier=13.80").unwrap();
        assert_eq!(name, "identifier");
        assert!((value - 13.80).abs() < 1e-9);
    }

    #[test]
    fn parse_role_tokens_arg_rejects_missing_equals() {
        assert!(parse_role_tokens_arg("identifier13.80").is_err());
    }

    #[test]
    fn parse_role_tokens_arg_rejects_non_numeric_value() {
        assert!(parse_role_tokens_arg("identifier=abc").is_err());
    }

    #[test]
    fn parse_role_tokens_arg_rejects_negative_value() {
        assert!(parse_role_tokens_arg("identifier=-1").is_err());
    }

    #[test]
    fn parse_role_tokens_arg_rejects_nan_value() {
        assert!(parse_role_tokens_arg("identifier=nan").is_err());
    }

    #[test]
    fn apply_overrides_sets_the_role_field() {
        let mut roles = Role::provisional_v2_table();
        apply_role_tokens_overrides(&mut roles, &[("identifier".into(), 13.80)]).unwrap();
        let ident = roles.iter().find(|r| r.name == "identifier").unwrap();
        assert_eq!(ident.tokens_per_compound, Some(13.80));
    }

    #[test]
    fn apply_overrides_rejects_unknown_role() {
        let mut roles = Role::provisional_v2_table();
        let err = apply_role_tokens_overrides(&mut roles, &[("nonesuch".into(), 5.0)]);
        assert!(err.is_err(), "expected unknown-role error");
        let msg = err.err().unwrap();
        assert!(msg.contains("nonesuch"), "error message missing role name: {msg}");
    }

    #[test]
    fn apply_overrides_leaves_other_roles_untouched() {
        let mut roles = Role::provisional_v2_table();
        apply_role_tokens_overrides(&mut roles, &[("identifier".into(), 13.80)]).unwrap();
        let decoy = roles.iter().find(|r| r.name == "decoy").unwrap();
        assert_eq!(decoy.tokens_per_compound, None);
    }

    #[test]
    fn verify_extracted_accepts_a_well_formed_directory() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("rp-verify-ok-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut manifest = std::fs::File::create(dir.join("MANIFEST.txt")).unwrap();
        writeln!(manifest, "some_header: 1").unwrap();
        writeln!(manifest).unwrap();
        writeln!(manifest, "role,size,file").unwrap();
        writeln!(manifest, "alpha,3,alpha.txt").unwrap();
        writeln!(manifest, "beta,2,beta.txt").unwrap();
        drop(manifest);

        std::fs::write(dir.join("alpha.txt"), "one\ntwo\nthree\n").unwrap();
        std::fs::write(dir.join("beta.txt"), "four\nfive\n").unwrap();

        super::verify_extracted_dir(&dir, true).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_extracted_detects_count_mismatch() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("rp-verify-count-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut manifest = std::fs::File::create(dir.join("MANIFEST.txt")).unwrap();
        writeln!(manifest, "role,size,file").unwrap();
        writeln!(manifest, "alpha,3,alpha.txt").unwrap();
        drop(manifest);

        std::fs::write(dir.join("alpha.txt"), "one\ntwo\n").unwrap();
        let err = super::verify_extracted_dir(&dir, true).unwrap_err().to_string();
        assert!(err.contains("has 2 words"), "actual: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_and_union_without_normalise_rejects_nothing_and_keeps_diacritics() {
        let dir = std::env::temp_dir().join(format!("rp-union-raw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wl.txt");
        std::fs::write(&path, "cafe\ncafé\n").unwrap();

        let result = super::load_and_union_wordlists(&[path], true, false).unwrap();
        assert_eq!(result.union, vec!["cafe", "café"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_and_union_with_normalise_folds_and_dedupes() {
        let dir = std::env::temp_dir().join(format!("rp-union-norm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wl.txt");
        // "café" normalises to "cafe", which we already saw — dropped.
        std::fs::write(&path, "cafe\ncafé\nnaïve\n").unwrap();

        let result = super::load_and_union_wordlists(&[path], true, true).unwrap();
        assert_eq!(result.union, vec!["cafe", "naive"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_and_union_with_normalise_dedupes_across_sources() {
        let dir = std::env::temp_dir().join(format!("rp-union-cross-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path_a = dir.join("a.txt");
        let path_b = dir.join("b.txt");
        std::fs::write(&path_a, "café\n").unwrap();
        std::fs::write(&path_b, "cafe\n").unwrap();

        let result =
            super::load_and_union_wordlists(&[path_a, path_b], true, true).unwrap();
        assert_eq!(result.union, vec!["cafe"]);
        assert_eq!(result.sources[0].contributed, 1);
        // Second source's "cafe" normalises to something already
        // seen from the first source, so it contributes nothing new.
        assert_eq!(result.sources[1].contributed, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn verify_extracted_detects_disjoint_violation() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("rp-verify-dup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut manifest = std::fs::File::create(dir.join("MANIFEST.txt")).unwrap();
        writeln!(manifest, "role,size,file").unwrap();
        writeln!(manifest, "alpha,2,alpha.txt").unwrap();
        writeln!(manifest, "beta,2,beta.txt").unwrap();
        drop(manifest);

        std::fs::write(dir.join("alpha.txt"), "one\ntwo\n").unwrap();
        // "two" is in both files — same size, but disjoint check fails
        std::fs::write(dir.join("beta.txt"), "two\nthree\n").unwrap();

        let err = super::verify_extracted_dir(&dir, true).unwrap_err().to_string();
        assert!(err.contains("also appears"), "actual: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
