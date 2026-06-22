//! `babbleon-bench` — operator-facing CLI for the adversarial bench.
//!
//! # What this defeats
//!
//! Operators having to write Rust to drive the bench library.  The
//! CLI exposes three subcommands matching the HANDOFF spec:
//!
//! - `babbleon-bench prompt` — read a challenge file, scramble its
//!   source under a chosen [`LayerConfig`], and write the
//!   neutral-capability prompt to stdout.  The operator copies the
//!   prompt into a chat / API call out-of-band.
//! - `babbleon-bench score` — read a model's raw output, score it
//!   against the challenge's success predicate, and write a JSONL
//!   [`RunRecord`] line to stdout (`>> runs.jsonl`).
//! - `babbleon-bench summary` — read one or more JSONL files of
//!   `RunRecord`s and emit the markdown crack-fraction table.
//!
//! # Trust placement
//!
//! Same as the library (see `crates/v2-babbleon-resilience-bench/
//! src/lib.rs`): no privileges, no daemon round-trip, no real
//! per-host secret.  The binary loads no secrets and writes no
//! state outside its argv-named output paths.
//!
//! # Compartmentalisation
//!
//! `main` parses argv into [`Cli`] and dispatches one subcommand.
//! Each subcommand is its own free function (`subcommand_prompt`,
//! `subcommand_score`, `subcommand_summary`) so the CLI is testable
//! by integration tests against the binary, and the dispatch table
//! has nothing in common with the rest of the program state.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use babbleon_resilience_bench_v2::{
    apply_layers, build_prompt, render_markdown, run_attempts, score,
    Challenge, LayerConfig, RunRecord, SubprocessEvaluator,
};

/// CLI entry struct parsed by clap.
#[derive(Parser)]
#[command(
    name = "babbleon-bench",
    version,
    about = "Adversarial regression bench for Babbleon v2 \
             structural scrambling.",
    long_about = "Drives the bench library: read a challenge file, \
                  scramble it under a chosen layer configuration, \
                  emit the neutral-capability prompt, score a model's \
                  answer, and aggregate run records into a markdown \
                  crack-fraction table.",
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read a challenge, scramble its source under the chosen layer
    /// config, and write the neutral-capability prompt to stdout.
    Prompt {
        /// Path to a challenge TOML file under `challenges/`.
        #[arg(short, long, value_name = "FILE")]
        challenge: PathBuf,
        /// Which preset layer configuration to scramble under.
        #[arg(long, value_enum, default_value_t = LayerConfigPreset::L2PlusL3)]
        layer_config: LayerConfigPreset,
    },

    /// Score a model's raw output against a challenge and emit a
    /// JSONL `RunRecord` line.  Appendable to a bench log file with
    /// shell `>>`.
    Score {
        /// Path to a challenge TOML file.
        #[arg(short, long, value_name = "FILE")]
        challenge: PathBuf,
        /// Which preset layer configuration this attempt was made
        /// against.  Recorded verbatim in the `RunRecord`.
        #[arg(long, value_enum, default_value_t = LayerConfigPreset::L2PlusL3)]
        layer_config: LayerConfigPreset,
        /// Path to a file containing the model's raw output (the
        /// text the model returned in response to the prompt).
        /// `-` reads from stdin.
        #[arg(short = 'm', long, value_name = "FILE")]
        model_output: PathBuf,
        /// Operator-supplied label identifying the evaluator.  Free
        /// text (e.g. `claude-sonnet-4-6@2026-06-22`).  Recorded
        /// verbatim in the `RunRecord`.
        #[arg(short, long, value_name = "LABEL")]
        evaluator: String,
        /// 0-based attempt index within the
        /// `(challenge, layer_config, evaluator)` tuple.  Defaults
        /// to 0 for one-shot scoring.
        #[arg(long, default_value_t = 0)]
        attempt: u32,
    },

    /// Aggregate one or more JSONL files of `RunRecord`s and emit
    /// the operator-facing markdown crack-fraction table.
    Summary {
        /// Paths to JSONL files containing `RunRecord` lines.  May
        /// be repeated.
        #[arg(short, long, value_name = "FILE", required = true)]
        records: Vec<PathBuf>,
        /// Optional crack-fraction CI gate: if any (challenge,
        /// `layer_config`, evaluator) cell's pass-rate exceeds this
        /// percent (0-100), `summary` exits with status 2 after
        /// printing the table.  The HANDOFF spec calls this the
        /// "regression gate" — a PR that weakens the scramble
        /// shows up as a higher crack-fraction here.  Cells
        /// without graded attempts (all format-errors or all
        /// refused-by-policy) are ignored.
        #[arg(long, value_name = "PCT")]
        pass_threshold_pct: Option<u32>,
    },

    /// Drive an external evaluator command across the full
    /// product of (challenges × layer configs) for N attempts
    /// per cell.  One invocation produces the entire bench
    /// matrix as JSONL on stdout.
    ///
    /// Each cell is run sequentially.  An evaluator failure on
    /// any cell aborts the matrix with a non-zero exit; the
    /// JSONL emitted before the failure is on stdout and the
    /// operator can resume from a partial log.
    ///
    /// Example operator command:
    ///
    ///   babbleon-bench run-matrix \
    ///     --challenges-dir crates/v2-babbleon-resilience-bench/challenges \
    ///     --layer-config baseline --layer-config l3-only \
    ///     --layer-config l2-plus-l3 --layer-config l2-plus-l3-plus-l7 \
    ///     --evaluator "claude-cli@2026-06-22" \
    ///     --attempts 5 \
    ///     --command claude-cli --command=--quiet \
    ///     > runs.jsonl
    RunMatrix {
        /// Directory containing challenge `*.toml` files.  All
        /// `*.toml` files in this directory are loaded.
        #[arg(long, value_name = "DIR")]
        challenges_dir: PathBuf,
        /// Layer configs to run against each challenge.  Repeat
        /// the flag once per config.
        #[arg(long, value_enum, required = true)]
        layer_config: Vec<LayerConfigPreset>,
        /// Operator-supplied evaluator label.
        #[arg(short, long, value_name = "LABEL")]
        evaluator: String,
        /// Number of attempts per cell.
        #[arg(long, default_value_t = 1)]
        attempts: u32,
        /// Evaluator command argv.  Same syntax as `run`.
        #[arg(long = "command", value_name = "ARG", required = true)]
        command: Vec<String>,
    },

    /// Drive an external evaluator command end-to-end for N
    /// attempts on one `(challenge, layer_config)` cell.  Writes
    /// the resulting JSONL `RunRecord`s to stdout.  Combine with
    /// shell `>>` to build a long-running bench log file.
    ///
    /// Example operator command:
    ///
    ///   babbleon-bench run --challenge auth-literal-string.toml \
    ///                      --layer-config l2-plus-l3 \
    ///                      --evaluator "claude-cli@2026-06-22" \
    ///                      --attempts 5 \
    ///                      --command claude-cli --command --quiet
    ///
    /// Each `--command` flag appends one argv entry; the operator
    /// is in full control of the subprocess.  Wrap with timeout(1)
    /// if you want a per-call wall-clock cap.
    Run {
        /// Path to a challenge TOML file.
        #[arg(short, long, value_name = "FILE")]
        challenge: PathBuf,
        /// Layer config to scramble under.
        #[arg(long, value_enum, default_value_t = LayerConfigPreset::L2PlusL3)]
        layer_config: LayerConfigPreset,
        /// Operator-supplied evaluator label recorded on each
        /// `RunRecord`.
        #[arg(short, long, value_name = "LABEL")]
        evaluator: String,
        /// Number of attempts to run against this cell.
        #[arg(long, default_value_t = 1)]
        attempts: u32,
        /// Evaluator command argv.  Repeat the flag once per
        /// argv entry.  The first occurrence is the program name.
        #[arg(long = "command", value_name = "ARG", required = true)]
        command: Vec<String>,
    },
}

/// Preset layer configurations exposed on the CLI.  Mirrors
/// [`LayerConfig`]'s preset constructors so the operator does not
/// have to set bit flags manually.
#[derive(Copy, Clone, Debug, ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum LayerConfigPreset {
    /// No scramble (baseline cell).
    Baseline,
    /// Layer 2 only (keyword scramble).
    L2Only,
    /// Layer 3 only (whitespace-as-words).
    L3Only,
    /// Layer 2 + Layer 3 (the HANDOFF-recommended floor; pre-2026-06-22).
    L2PlusL3,
    /// Layer 2 + Layer 2b + Layer 3 (the corrected post-2026-06-22 floor:
    /// keywords + operators + whitespace).
    L2PlusL2bPlusL3,
    /// Layer 2 + Layer 3 + experimental Layer 7 (secret-literal
    /// substitution; bench-only prototype per
    /// `docs/v2/string-literal-leak.md`).
    L2PlusL3PlusL7,
    /// Layer 2 + Layer 2b + Layer 3 + experimental Layer 7.
    L2PlusL2bPlusL3PlusL7,
}

impl LayerConfigPreset {
    fn to_config(self) -> LayerConfig {
        match self {
            LayerConfigPreset::Baseline => LayerConfig::baseline_no_scramble(),
            LayerConfigPreset::L2Only => LayerConfig::l2_only(),
            LayerConfigPreset::L3Only => LayerConfig::l3_only(),
            LayerConfigPreset::L2PlusL3 => LayerConfig::l2_plus_l3(),
            LayerConfigPreset::L2PlusL2bPlusL3 => {
                LayerConfig::l2_plus_l2b_plus_l3()
            }
            LayerConfigPreset::L2PlusL3PlusL7 => {
                LayerConfig::l2_plus_l3_plus_l7()
            }
            LayerConfigPreset::L2PlusL2bPlusL3PlusL7 => {
                LayerConfig::l2_plus_l2b_plus_l3_plus_l7()
            }
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Prompt {
            challenge,
            layer_config,
        } => subcommand_prompt(&challenge, layer_config.to_config()),
        Command::Score {
            challenge,
            layer_config,
            model_output,
            evaluator,
            attempt,
        } => subcommand_score(
            &challenge,
            layer_config.to_config(),
            &model_output,
            &evaluator,
            attempt,
        ),
        Command::Summary {
            records,
            pass_threshold_pct,
        } => subcommand_summary(&records, pass_threshold_pct),
        Command::RunMatrix {
            challenges_dir,
            layer_config,
            evaluator,
            attempts,
            command,
        } => subcommand_run_matrix(
            &challenges_dir,
            &layer_config
                .into_iter()
                .map(LayerConfigPreset::to_config)
                .collect::<Vec<_>>(),
            &evaluator,
            attempts,
            command,
        ),
        Command::Run {
            challenge,
            layer_config,
            evaluator,
            attempts,
            command,
        } => subcommand_run(
            &challenge,
            layer_config.to_config(),
            &evaluator,
            attempts,
            command,
        ),
    }
}

fn subcommand_prompt(challenge_path: &Path, config: LayerConfig) -> Result<()> {
    let challenge = Challenge::from_toml_file(challenge_path)
        .with_context(|| format!("load challenge {}", challenge_path.display()))?;
    let scrambled = apply_layers(&challenge.source, config)
        .map_err(|e| anyhow!("scramble: {e}"))?;
    let prompt = build_prompt(&challenge, config, &scrambled);
    let mut stdout = io::stdout().lock();
    stdout.write_all(prompt.as_bytes()).context("write stdout")?;
    stdout.flush().context("flush stdout")?;
    Ok(())
}

fn subcommand_score(
    challenge_path: &Path,
    config: LayerConfig,
    model_output_path: &Path,
    evaluator: &str,
    attempt: u32,
) -> Result<()> {
    let challenge = Challenge::from_toml_file(challenge_path)
        .with_context(|| format!("load challenge {}", challenge_path.display()))?;
    let model_output = read_input_path(model_output_path)
        .with_context(|| {
            format!("read model output {}", model_output_path.display())
        })?;
    let outcome = score(&challenge.success_predicate, &model_output);
    let record = RunRecord::new(
        challenge.name.clone(),
        config,
        evaluator,
        attempt,
        outcome,
    );
    let line = record
        .to_jsonl()
        .map_err(|e| anyhow!("serialize run record: {e}"))?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(line.as_bytes()).context("write stdout")?;
    stdout.flush().context("flush stdout")?;
    Ok(())
}

fn subcommand_summary(
    record_paths: &[PathBuf],
    pass_threshold_pct: Option<u32>,
) -> Result<()> {
    let mut all_records: Vec<RunRecord> = Vec::new();
    for path in record_paths {
        let body = read_input_path(path).with_context(|| {
            format!("read run records {}", path.display())
        })?;
        let mut parsed = RunRecord::from_jsonl(&body).map_err(|e| {
            anyhow!("parse run records from {}: {e}", path.display())
        })?;
        all_records.append(&mut parsed);
    }
    let table = render_markdown(&all_records);
    {
        let mut stdout = io::stdout().lock();
        stdout.write_all(table.as_bytes()).context("write stdout")?;
        stdout.flush().context("flush stdout")?;
    }

    if let Some(threshold_pct) = pass_threshold_pct {
        let breaches = cells_above_threshold(&all_records, threshold_pct);
        if !breaches.is_empty() {
            // Print the breach list to stderr so the markdown
            // table on stdout stays clean for the operator to
            // paste into HANDOFF.
            eprintln!(
                "\nCI gate breach: {} cell(s) exceed pass-threshold {}%:",
                breaches.len(),
                threshold_pct,
            );
            for breach in &breaches {
                eprintln!("  {breach}");
            }
            std::process::exit(2);
        }
    }
    Ok(())
}

/// Identify `(challenge, layer_config, evaluator)` cells whose
/// crack-fraction exceeds the threshold (as a percent).  Returns
/// a list of operator-friendly breach descriptions.
fn cells_above_threshold(
    records: &[RunRecord],
    threshold_pct: u32,
) -> Vec<String> {
    use babbleon_resilience_bench_v2::summary::aggregate;
    let cells = aggregate(records);
    let threshold_frac = f64::from(threshold_pct) / 100.0;
    let mut breaches = Vec::new();
    for ((challenge, config_label, evaluator), cell) in &cells {
        if let Some(frac) = cell.crack_fraction() {
            if frac > threshold_frac {
                breaches.push(format!(
                    "{challenge} / {config_label} / {evaluator}: \
                     {}/{} pass ({:.1}% > {threshold_pct}%)",
                    cell.pass_count,
                    cell.graded_count(),
                    frac * 100.0,
                ));
            }
        }
    }
    breaches.sort();
    breaches
}

fn subcommand_run_matrix(
    challenges_dir: &Path,
    layer_configs: &[LayerConfig],
    evaluator_label: &str,
    attempts: u32,
    command: Vec<String>,
) -> Result<()> {
    // Load every challenge file in the directory.
    let mut challenge_paths: Vec<PathBuf> = fs::read_dir(challenges_dir)
        .with_context(|| {
            format!("read challenges dir {}", challenges_dir.display())
        })?
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    challenge_paths.sort();
    if challenge_paths.is_empty() {
        return Err(anyhow!(
            "no *.toml challenge files in {}",
            challenges_dir.display(),
        ));
    }

    let adv = SubprocessEvaluator::new(command, evaluator_label)
        .map_err(|e| anyhow!("evaluator config: {e}"))?;
    let mut stdout = io::stdout().lock();
    for path in &challenge_paths {
        let challenge = Challenge::from_toml_file(path)
            .with_context(|| format!("load challenge {}", path.display()))?;
        for config in layer_configs {
            let records = run_attempts(&challenge, *config, &adv, attempts)
                .map_err(|e| {
                    anyhow!(
                        "run cell {}/{}: {e}",
                        challenge.name,
                        config.label(),
                    )
                })?;
            for record in &records {
                let line = record
                    .to_jsonl()
                    .map_err(|e| anyhow!("serialize: {e}"))?;
                stdout.write_all(line.as_bytes()).context("write stdout")?;
                // Flush after every record so a tail-watching
                // operator sees progress as the matrix runs.
                stdout.flush().context("flush stdout")?;
            }
        }
    }
    Ok(())
}

fn subcommand_run(
    challenge_path: &Path,
    config: LayerConfig,
    evaluator_label: &str,
    attempts: u32,
    command: Vec<String>,
) -> Result<()> {
    let challenge = Challenge::from_toml_file(challenge_path)
        .with_context(|| format!("load challenge {}", challenge_path.display()))?;
    let adv = SubprocessEvaluator::new(command, evaluator_label)
        .map_err(|e| anyhow!("evaluator config: {e}"))?;
    let records = run_attempts(&challenge, config, &adv, attempts)
        .map_err(|e| anyhow!("run attempts: {e}"))?;
    let mut stdout = io::stdout().lock();
    for record in &records {
        let line = record
            .to_jsonl()
            .map_err(|e| anyhow!("serialize run record: {e}"))?;
        stdout.write_all(line.as_bytes()).context("write stdout")?;
    }
    stdout.flush().context("flush stdout")?;
    Ok(())
}

/// Read the contents of `path` to a `String`.  A literal `-` reads
/// from stdin; everything else reads from disk.
fn read_input_path(path: &Path) -> io::Result<String> {
    if path == Path::new("-") {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        Ok(buf)
    } else {
        fs::read_to_string(path)
    }
}
