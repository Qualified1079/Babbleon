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
mod params;
mod report;

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

    /// Path to the raw wordlist (one lowercase-ASCII word per line).
    /// Required for `--extract-to`.  Defaults to the v1 baseline.
    #[arg(long, default_value = "../../crates/babbleon/wordlist/words.txt")]
    wordlist_path: PathBuf,

    /// Extract disjoint per-role subsets into this directory.
    /// Emits one text file per role — for example
    /// `identifier.txt`, `decoy.txt`, ... — plus a `MANIFEST.txt`
    /// with the seed, wordlist hash, and per-role sizes.  The
    /// directory must not already contain per-role files; the tool
    /// refuses to overwrite.
    #[arg(long)]
    extract_to: Option<PathBuf>,

    /// Seed bytes for the extractor's PRNG.  Passed as a UTF-8
    /// string; SHA-256'd internally.  If unset, the tool uses a
    /// fixed developer default so reruns without a seed are
    /// deterministic (and match published RESULTS).  Production
    /// use MUST supply a per-host secret here.
    #[arg(long, default_value = "babbleon-role-partitioning-dev-seed")]
    extract_seed: String,

    /// Skip the stdout summary; useful when scripting `--report-out`.
    #[arg(long, default_value_t = false)]
    quiet: bool,
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

    let roles = args.roles.resolve();
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
        extract_and_write(&table, &args.wordlist_path, dir, &args.extract_seed, args.quiet)?;
    }

    Ok(())
}

fn extract_and_write(
    table: &AllocationTable,
    wordlist_path: &std::path::Path,
    out_dir: &std::path::Path,
    seed: &str,
    quiet: bool,
) -> Result<()> {
    use sha2::{Digest, Sha256};

    let raw = std::fs::read_to_string(wordlist_path)
        .with_context(|| format!("read wordlist at {}", wordlist_path.display()))?;
    let words: Vec<&str> = raw.lines().map(str::trim).filter(|w| !w.is_empty()).collect();
    if !quiet {
        println!("\nLoaded {} words from {}", words.len(), wordlist_path.display());
    }

    let extraction = extract::extract_disjoint_subsets(&words, table, seed.as_bytes())
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
    let mut wordlist_hasher = Sha256::new();
    wordlist_hasher.update(raw.as_bytes());
    let wordlist_hash = wordlist_hasher.finalize();
    let mut manifest = String::new();
    manifest.push_str("Babbleon v2 wordlist role-partitioning — extraction manifest\n\n");
    manifest.push_str(&format!("wordlist_path: {}\n", wordlist_path.display()));
    manifest.push_str(&format!("wordlist_entries: {}\n", words.len()));
    manifest.push_str(&format!("wordlist_sha256: {wordlist_hash:x}\n"));
    manifest.push_str(&format!("seed_utf8: {seed:?}\n"));
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
