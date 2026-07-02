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

    Ok(())
}
