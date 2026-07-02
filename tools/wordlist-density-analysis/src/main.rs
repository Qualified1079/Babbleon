//! Wordlist density analysis — CLI orchestration.
//!
//! # Why this exists
//!
//! The Babbleon baseline wordlist (`crates/babbleon/wordlist/words.txt`,
//! 369 652 entries) mixes trivially-tokenizable common English words
//! (`hello`, `about`) with the mid-tail of rare-but-still-shaped
//! entries (`aardwolf`, `zymase`).  TODO.md §"Benchmarks +
//! measurements" and HANDOFF.md 2026-06-27 priority 4 both name a
//! **wordlist post-filter by tokenization density** as the next
//! measurable follow-on to the variable-alias-count regime: pick
//! wordlist entries that score in the mid-tail of cl100k / o200k
//! token density and hypothesise that the filtered subset raises the
//! attention cost of the scrambler without shrinking the wordlist
//! below the disjoint-role budget (see
//! `docs/v2/phase0-research-notes.md` §11).
//!
//! This tool is the measurement + filter, not the wiring.  Wiring
//! the filtered wordlist into `v2-babbleon-core::wordlist` is a
//! separate change gated on the adversarial-LLM re-test producing a
//! baseline number.
//!
//! # Usage
//!
//! Score every word in the baseline and write per-word tokens to a
//! CSV:
//!
//! ```text
//!   cargo run --release -- \
//!     --wordlist ../../crates/babbleon/wordlist/words.txt \
//!     --scores-out scores.csv
//! ```
//!
//! Emit a filtered wordlist at cl100k's 30th–70th percentile band:
//!
//! ```text
//!   cargo run --release -- \
//!     --wordlist ../../crates/babbleon/wordlist/words.txt \
//!     --filter cl100k \
//!     --min-percentile 30 \
//!     --max-percentile 70 \
//!     --filtered-out filtered.txt \
//!     --manifest-out filtered.manifest
//! ```
//!
//! The scoring pass is deterministic (no RNG); the same input
//! wordlist and tokenizer version produce the same CSV bit-for-bit.

mod filter;
mod load;
mod report;
mod score;
mod stats;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

use crate::filter::{FilterSpec, Tokenizer};
use crate::load::Wordlist;
use crate::score::{score_all, Tokenizers};

#[derive(Copy, Clone, Debug, ValueEnum)]
enum TokenizerArg {
    Cl100k,
    O200k,
}

impl From<TokenizerArg> for Tokenizer {
    fn from(t: TokenizerArg) -> Self {
        match t {
            TokenizerArg::Cl100k => Tokenizer::Cl100k,
            TokenizerArg::O200k => Tokenizer::O200k,
        }
    }
}

#[derive(Parser)]
#[command(
    version,
    about = "Score Babbleon wordlist entries by BPE token density and filter to a mid-tail band."
)]
struct Args {
    /// Path to the wordlist (one lowercase-ASCII word per line).
    #[arg(long, default_value = "../../crates/babbleon/wordlist/words.txt")]
    wordlist: PathBuf,

    /// Write per-word `word,bytes,cl100k,o200k` CSV to this path.
    #[arg(long)]
    scores_out: Option<PathBuf>,

    /// Enable filter mode using the given tokenizer's counts.
    #[arg(long, value_enum)]
    filter: Option<TokenizerArg>,

    /// Inclusive lower percentile bound for the filter band.
    #[arg(long, default_value_t = 30.0)]
    min_percentile: f64,

    /// Inclusive upper percentile bound for the filter band.
    #[arg(long, default_value_t = 70.0)]
    max_percentile: f64,

    /// Write the surviving wordlist (one word per line) to this path.
    /// Only meaningful with `--filter`.
    #[arg(long)]
    filtered_out: Option<PathBuf>,

    /// Write the filter parameters + resulting cutoffs to this path.
    /// Only meaningful with `--filter`.
    #[arg(long)]
    manifest_out: Option<PathBuf>,

    /// Skip the summary print (useful when driving from a script).
    #[arg(long, default_value_t = false)]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let wordlist = Wordlist::from_path(&args.wordlist)
        .with_context(|| format!("load {}", args.wordlist.display()))?;
    if !args.quiet {
        println!("Loaded {} words from {}", wordlist.len(), args.wordlist.display());
    }

    let tokenizers = Tokenizers::load()?;
    if !args.quiet {
        println!("Scoring {} entries under cl100k_base + o200k_base ...", wordlist.len());
    }
    let scores = score_all(&wordlist.words, &tokenizers);

    if !args.quiet {
        report::print_summary(&scores);
    }

    if let Some(path) = &args.scores_out {
        report::write_scores_csv(&scores, path)
            .with_context(|| format!("write scores csv to {}", path.display()))?;
        if !args.quiet {
            println!("\nWrote per-word CSV to {}", path.display());
        }
    }

    if let Some(tok) = args.filter {
        let spec = FilterSpec {
            tokenizer: tok.into(),
            min_percentile: args.min_percentile,
            max_percentile: args.max_percentile,
        };
        if let Err(msg) = spec.validate() {
            bail!("invalid filter spec: {msg}");
        }
        let result = spec.apply(&scores);
        if !args.quiet {
            println!(
                "\nFilter: tokenizer={} percentile=[{}, {}] cutoff=[{}, {}]",
                spec.tokenizer,
                spec.min_percentile,
                spec.max_percentile,
                result.cutoff_low,
                result.cutoff_high
            );
            println!(
                "  kept {} / {} ({:.2}%) — dropped {} below, {} above",
                result.kept.len(),
                result.total_input(),
                result.kept_fraction() * 100.0,
                result.dropped_below,
                result.dropped_above
            );
        }
        if let Some(path) = &args.filtered_out {
            report::write_filtered_wordlist(&result, path)
                .with_context(|| format!("write filtered wordlist to {}", path.display()))?;
            if !args.quiet {
                println!("Wrote filtered wordlist to {}", path.display());
            }
        }
        if let Some(path) = &args.manifest_out {
            report::write_filter_manifest(&result, path)
                .with_context(|| format!("write manifest to {}", path.display()))?;
            if !args.quiet {
                println!("Wrote filter manifest to {}", path.display());
            }
        }
    } else if args.filtered_out.is_some() || args.manifest_out.is_some() {
        bail!("--filtered-out / --manifest-out require --filter <tokenizer>");
    }

    Ok(())
}
