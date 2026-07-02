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

use crate::filter::{intersect, Bound, FilterSpec, Tokenizer};
use crate::load::{Mode, Wordlist};
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

    /// Inclusive lower percentile bound.  Mutually exclusive with
    /// `--min-tokens`.  Defaults to 30 when neither is supplied.
    #[arg(long, conflicts_with = "min_tokens")]
    min_percentile: Option<f64>,

    /// Inclusive upper percentile bound.  Mutually exclusive with
    /// `--max-tokens`.  Defaults to 70 when neither is supplied.
    #[arg(long, conflicts_with = "max_tokens")]
    max_percentile: Option<f64>,

    /// Inclusive lower cutoff as an absolute token count.  Mutually
    /// exclusive with `--min-percentile`.
    #[arg(long)]
    min_tokens: Option<usize>,

    /// Inclusive upper cutoff as an absolute token count.  Mutually
    /// exclusive with `--max-percentile`.
    #[arg(long)]
    max_tokens: Option<usize>,

    /// Write the surviving wordlist (one word per line) to this path.
    /// Only meaningful with `--filter`.
    #[arg(long)]
    filtered_out: Option<PathBuf>,

    /// Write the filter parameters + resulting cutoffs to this path.
    /// Only meaningful with `--filter`.
    #[arg(long)]
    manifest_out: Option<PathBuf>,

    /// When set, apply the same L/H bounds under both cl100k and
    /// o200k and keep only the intersection.  The `--filter`
    /// choice becomes the "primary" tokenizer for reporting
    /// (drop-below / drop-above counts refer to it); the other
    /// tokenizer acts as the secondary gate.
    #[arg(long, default_value_t = false)]
    intersect_tokenizers: bool,

    /// Skip the summary print (useful when driving from a script).
    #[arg(long, default_value_t = false)]
    quiet: bool,

    /// Opt-in: accept any Unicode lowercase character (`café`,
    /// `naïve`, `köln`) instead of the runtime's `[a-z]+`
    /// invariant.  Analysis-side only — a wordlist that loads
    /// under this mode must still be normalised or the runtime
    /// loader relaxed before it can ship.  Used for phase-4
    /// multi-language exploration.  See
    /// `docs/v2/multi-language-density-notes.md`.
    #[arg(long, default_value_t = false)]
    unicode_lowercase: bool,

    /// Opt-in: NFKD-decompose each entry and drop combining marks
    /// before validation (`café` → `cafe`).  Composes cleanly with
    /// the default `AsciiLowercase` mode so the runtime `[a-z]+`
    /// invariant stays satisfied while a multi-language corpus
    /// still loads.  Duplicates arising from normalisation are
    /// dropped silently (first-occurrence wins).
    #[arg(long, default_value_t = false)]
    normalise_diacritics: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mode = if args.unicode_lowercase {
        Mode::UnicodeLowercase
    } else {
        Mode::AsciiLowercase
    };
    let wordlist =
        Wordlist::from_path_with_mode(&args.wordlist, mode, args.normalise_diacritics)
            .with_context(|| format!("load {}", args.wordlist.display()))?;
    if !args.quiet {
        println!(
            "Loaded {} words from {} (mode={:?}, normalise_diacritics={})",
            wordlist.len(),
            args.wordlist.display(),
            mode,
            args.normalise_diacritics
        );
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
        let min = match (args.min_percentile, args.min_tokens) {
            (Some(p), None) => Bound::Percentile(p),
            (None, Some(n)) => Bound::Tokens(n),
            (None, None) => Bound::Percentile(30.0),
            (Some(_), Some(_)) => unreachable!("clap enforces conflicts_with"),
        };
        let max = match (args.max_percentile, args.max_tokens) {
            (Some(p), None) => Bound::Percentile(p),
            (None, Some(n)) => Bound::Tokens(n),
            (None, None) => Bound::Percentile(70.0),
            (Some(_), Some(_)) => unreachable!("clap enforces conflicts_with"),
        };
        let primary_tok: Tokenizer = tok.into();
        let primary_spec = FilterSpec {
            tokenizer: primary_tok,
            min,
            max,
        };
        if let Err(msg) = primary_spec.validate() {
            bail!("invalid filter spec: {msg}");
        }
        let primary_result = primary_spec
            .apply(&scores)
            .map_err(|msg| anyhow::anyhow!("filter apply failed: {msg}"))?;

        if args.intersect_tokenizers {
            let secondary_tok = match primary_tok {
                Tokenizer::Cl100k => Tokenizer::O200k,
                Tokenizer::O200k => Tokenizer::Cl100k,
            };
            let secondary_spec = FilterSpec {
                tokenizer: secondary_tok,
                min,
                max,
            };
            let secondary_result = secondary_spec
                .apply(&scores)
                .map_err(|msg| anyhow::anyhow!("secondary filter failed: {msg}"))?;
            let inter = intersect(primary_result, secondary_result);
            if !args.quiet {
                println!(
                    "\nIntersection filter:  primary={} bounds=[{}, {}] cutoff=[{}, {}]",
                    inter.primary.spec.tokenizer,
                    inter.primary.spec.min,
                    inter.primary.spec.max,
                    inter.primary.cutoff_low,
                    inter.primary.cutoff_high,
                );
                println!(
                    "                     secondary={} cutoff=[{}, {}]",
                    inter.secondary.spec.tokenizer,
                    inter.secondary.cutoff_low,
                    inter.secondary.cutoff_high,
                );
                println!(
                    "  primary kept        {} / {} ({:.2}%)",
                    inter.primary.kept.len(),
                    inter.total_input(),
                    inter.primary.kept_fraction() * 100.0
                );
                println!(
                    "  intersection kept   {} / {} ({:.2}%) — {} passed primary only",
                    inter.kept.len(),
                    inter.total_input(),
                    inter.kept_fraction() * 100.0,
                    inter.dropped_by_secondary_only
                );
            }
            if let Some(path) = &args.filtered_out {
                report::write_intersected_wordlist(&inter, path)
                    .with_context(|| format!("write filtered wordlist to {}", path.display()))?;
                if !args.quiet {
                    println!("Wrote intersected wordlist to {}", path.display());
                }
            }
            if let Some(path) = &args.manifest_out {
                report::write_intersection_manifest(&inter, path)
                    .with_context(|| format!("write manifest to {}", path.display()))?;
                if !args.quiet {
                    println!("Wrote intersection manifest to {}", path.display());
                }
            }
        } else {
            if !args.quiet {
                println!(
                    "\nFilter: tokenizer={} bounds=[{}, {}] resolved-cutoff=[{}, {}]",
                    primary_result.spec.tokenizer,
                    primary_result.spec.min,
                    primary_result.spec.max,
                    primary_result.cutoff_low,
                    primary_result.cutoff_high
                );
                println!(
                    "  kept {} / {} ({:.2}%) — dropped {} below, {} above",
                    primary_result.kept.len(),
                    primary_result.total_input(),
                    primary_result.kept_fraction() * 100.0,
                    primary_result.dropped_below,
                    primary_result.dropped_above
                );
            }
            if let Some(path) = &args.filtered_out {
                report::write_filtered_wordlist(&primary_result, path)
                    .with_context(|| format!("write filtered wordlist to {}", path.display()))?;
                if !args.quiet {
                    println!("Wrote filtered wordlist to {}", path.display());
                }
            }
            if let Some(path) = &args.manifest_out {
                report::write_filter_manifest(&primary_result, path)
                    .with_context(|| format!("write manifest to {}", path.display()))?;
                if !args.quiet {
                    println!("Wrote filter manifest to {}", path.display());
                }
            }
        }
    } else if args.filtered_out.is_some()
        || args.manifest_out.is_some()
        || args.min_percentile.is_some()
        || args.max_percentile.is_some()
        || args.min_tokens.is_some()
        || args.max_tokens.is_some()
        || args.intersect_tokenizers
    {
        bail!("filter parameters require --filter <tokenizer>");
    }

    Ok(())
}
