//! Per-file latency microbenchmark for the v2 preprocessor.
//!
//! # Why this exists
//!
//! `docs/v2/structure-scrambling.md` §"Recommended phase-3 prototype"
//! step 5 calls for a sub-50 ms per-file preprocessor latency
//! measurement before the operator's adversarial-LLM test runs.  This
//! tool produces that number on the same hardware tier as the
//! existing `tools/rotation-benchmark/` (same machine, same Cargo
//! profile), so the phase-3 latency budget can be measured against
//! the phase-2 rotation budget without a hardware delta.
//!
//! # What we measure
//!
//! Selected via `--mode`:
//!
//! - **`l3-only`** (default).  The original phase-3 measurement.
//!   `python_tokenizer::tokenize` + `scrambler::scramble` +
//!   `unscrambler::unscramble`.  The L3 path is what
//!   `docs/v2/structure-scrambling.md` §5 specified the 50 ms budget
//!   against, so this measurement remains the canonical phase-3
//!   number even as further layers land.
//! - **`full`**.  Production composition.
//!   `pipeline::scramble_pipeline` (L4 + L5 + L2 + L3 + L6 + L12 +
//!   header encode) + `file_format::decode` +
//!   `pipeline::unscramble_pipeline` (L12⁻¹ + L6⁻¹ + L3⁻¹ + L2⁻¹ +
//!   L5⁻¹ + L4⁻¹ + tokens_to_source).  Same layer order the
//!   operator-facing `babbleon scramble` / `babbleon unscramble`
//!   CLI runs in production.  **Cold-cache measurement**: every
//!   iteration rebuilds the L2 permutation via `MappingBuilder`
//!   (`ALIAS_COUNT * 2` Fisher-Yates passes over the wordlist per
//!   scramble + unscramble pair).  The production daemon caches
//!   the permutation per epoch across requests, so steady-state
//!   per-file cost is much lower than this number reports.  The
//!   bench number is the worst-case "first file of the epoch"
//!   latency — useful for understanding rotation-tick blast
//!   radius, not for sustained-throughput SLAs.
//!
//! In both modes the per-host-secret + epoch derivation is built
//! once before the loop and shared.  In production the daemon caches
//! the same mapping across requests, so excluding the build cost
//! matches the steady-state cost the operator sees.
//!
//! # What we do NOT measure
//!
//! - The Unix socket round-trip to the daemon.  That's a one-shot
//!   4-KiB JSONL exchange that amortises across N calls per session;
//!   not the per-file compute cost.
//! - File I/O.  Reading the puzzle source from disk once before the
//!   timing loop is excluded so we measure pure pipeline cost.
//!
//! # Output
//!
//! Per-puzzle table: mean / median / p95 / min / max in microseconds
//! over `--iterations` runs (default 1000, plus 100 warmup).  A
//! final aggregate row reports the worst-case median across all
//! puzzles versus the target.  Exit code 0 if the target is met for
//! every puzzle; exit code 1 if any puzzle's median exceeds the
//! target.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::wordlist::Wordlist;
use babbleon_core_v2::MappingBuilder;
use babbleon_preprocessor_v2::file_format::decode as decode_file;
use babbleon_preprocessor_v2::identifier_scrambler::{
    IdentifierMapping, ALIAS_COUNT,
};
use babbleon_preprocessor_v2::pipeline::{
    scramble_pipeline, unscramble_pipeline,
};
use babbleon_preprocessor_v2::python_tokenizer::tokenize;
use babbleon_preprocessor_v2::scrambler::scramble;
use babbleon_preprocessor_v2::unscrambler::unscramble;
use babbleon_preprocessor_v2::WhitespaceWordlist;

/// CLI surface.
#[derive(Parser)]
#[command(
    name = "preprocessor-benchmark",
    about = "Per-file latency microbenchmark for the v2 layer-3 preprocessor",
)]
struct Args {
    /// Path to the directory of example puzzles.  Defaults to
    /// `tools/scrambler/example-puzzles/` relative to the workspace
    /// root.
    #[arg(
        long,
        default_value = "../scrambler/example-puzzles",
        value_name = "PATH"
    )]
    puzzles_dir: PathBuf,

    /// Timed iterations per puzzle.  Warmup is `--warmup` extra
    /// iterations before the timer starts.
    #[arg(long, default_value_t = 1000)]
    iterations: usize,

    /// Warmup iterations per puzzle (excluded from stats).
    #[arg(long, default_value_t = 100)]
    warmup: usize,

    /// Per-file latency target in microseconds.  Defaults to 50 000
    /// (= 50 ms), the phase-3 spec target for L3-only mode.  Full
    /// mode is a cold-cache measurement and will typically exceed
    /// this — set `--target-micros 250000` for a 250 ms cold-cache
    /// budget.  Exit code is 1 if any puzzle's median exceeds the
    /// target.
    #[arg(long, default_value_t = 50_000)]
    target_micros: u128,

    /// Epoch to derive the whitespace mapping for.  Defaults to 0;
    /// override to confirm latency is epoch-independent.
    #[arg(long, default_value_t = 0)]
    epoch: u64,

    /// Which pipeline to measure.  `l3-only` is the historical
    /// phase-3 measurement (tokenize + L3 scramble + L3 unscramble);
    /// `full` measures the production composition (L4 + L5 + L2 +
    /// L3 + L6 + L12 + header encode/decode).  Default `l3-only`
    /// preserves backward compatibility with prior RESULTS.md
    /// numbers; switch to `full` for production-path budget checks.
    #[arg(long, default_value = "l3-only", value_parser = ["l3-only", "full"])]
    mode: String,
}

/// Pipeline mode selected via `--mode`.
#[derive(Clone, Copy)]
enum Mode {
    L3Only,
    Full,
}

impl Mode {
    fn from_str(s: &str) -> Self {
        match s {
            "full" => Self::Full,
            _ => Self::L3Only,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::L3Only => "l3-only",
            Self::Full => "full",
        }
    }
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.iterations == 0 {
        eprintln!("preprocessor-benchmark: --iterations must be positive");
        return ExitCode::from(2);
    }

    let puzzles = match load_puzzles(&args.puzzles_dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("preprocessor-benchmark: {e}");
            return ExitCode::from(2);
        }
    };
    if puzzles.is_empty() {
        eprintln!(
            "preprocessor-benchmark: no .py files found in {}",
            args.puzzles_dir.display(),
        );
        return ExitCode::from(2);
    }

    let mode = Mode::from_str(&args.mode);

    // Fixed secret + wordlist + epoch.  The secret value is
    // arbitrary; benchmarks must be reproducible across runs on the
    // same hardware so we lock the seed.
    let secret = PerHostSecret::from_bytes(&[0xA5u8; 32])
        .expect("32-byte constant secret constructs");
    let wl = WhitespaceWordlist::build(
        &secret,
        Wordlist::english_baseline(),
        args.epoch,
    )
    .expect("baseline wordlist exceeds the 20-entry minimum");

    // Full-mode reuses MappingBuilder across iterations.  The
    // builder caches HKDF derivation state across `build` calls,
    // matching the production daemon's behaviour where the same
    // secret + wordlist are kept warm in memory.
    let builder = MappingBuilder::new(&secret, &Wordlist::english_baseline());

    println!(
        "mode: {}    epoch: {}    target: {} µs/file (median)",
        mode.label(),
        args.epoch,
        args.target_micros,
    );
    println!(
        "{:<28} {:>8} {:>8} {:>8} {:>8} {:>8}  vs {} µs",
        "puzzle", "mean", "median", "p95", "min", "max", args.target_micros,
    );
    println!("{}", "-".repeat(88));

    let mut all_pass = true;
    for puzzle in &puzzles {
        let stats = measure_puzzle(
            &puzzle.source,
            &wl,
            mode,
            &builder,
            args.epoch,
            args.iterations,
            args.warmup,
        );
        let pass = stats.median.as_micros() <= args.target_micros;
        if !pass {
            all_pass = false;
        }
        println!(
            "{:<28} {:>8} {:>8} {:>8} {:>8} {:>8}  {}",
            puzzle.name,
            stats.mean.as_micros(),
            stats.median.as_micros(),
            stats.p95.as_micros(),
            stats.min.as_micros(),
            stats.max.as_micros(),
            if pass { "PASS" } else { "FAIL" },
        );
    }
    println!();
    println!(
        "phase-3 target: {} µs per file (median).  result: {}",
        args.target_micros,
        if all_pass { "PASS" } else { "FAIL" },
    );

    if all_pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// One example puzzle on disk.
struct Puzzle {
    name: String,
    source: String,
}

fn load_puzzles(dir: &std::path::Path) -> Result<Vec<Puzzle>, String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("py") {
            continue;
        }
        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("read {}: {e}", path.display()))?;
        let name = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("(unknown)")
            .to_owned();
        out.push(Puzzle { name, source });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Per-puzzle latency stats.  All in `Duration` so the caller picks
/// the display unit.
struct Stats {
    mean: Duration,
    median: Duration,
    p95: Duration,
    min: Duration,
    max: Duration,
}

fn measure_puzzle(
    source: &str,
    wl: &WhitespaceWordlist,
    mode: Mode,
    builder: &MappingBuilder<'_>,
    epoch: u64,
    iterations: usize,
    warmup: usize,
) -> Stats {
    // Warmup: same pipeline, results discarded.  Warms up the
    // tokenizer's internal allocations and any branch-predictor
    // state.
    for _ in 0..warmup {
        run_once(source, wl, mode, builder, epoch);
    }

    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        run_once(source, wl, mode, builder, epoch);
        times.push(start.elapsed());
    }
    times.sort_unstable();

    let sum: Duration = times.iter().sum();
    let mean = sum / u32::try_from(times.len()).unwrap_or(u32::MAX);
    let median = times[times.len() / 2];
    let p95_index = times.len().saturating_sub(1) * 95 / 100;
    let p95 = times[p95_index];
    let min = times[0];
    let max = *times.last().expect("iterations > 0 was checked above");

    Stats {
        mean,
        median,
        p95,
        min,
        max,
    }
}

/// One end-to-end pipeline pass.  Mode-dispatched.
///
/// `#[inline(never)]` keeps the compiler from hoisting any of the
/// stages out of the timer when the loop body is short.  Without
/// this, the optimiser was inlining `tokenize` and observing the
/// result was unused, which collapsed the measurement.
#[inline(never)]
fn run_once(
    source: &str,
    wl: &WhitespaceWordlist,
    mode: Mode,
    builder: &MappingBuilder<'_>,
    epoch: u64,
) -> String {
    match mode {
        Mode::L3Only => run_once_l3_only(source, wl),
        Mode::Full => run_once_full(source, wl, builder, epoch),
    }
}

/// Historical phase-3 path: tokenize + L3 scramble + L3 unscramble.
fn run_once_l3_only(source: &str, wl: &WhitespaceWordlist) -> String {
    let tokens = tokenize(source);
    let scrambled =
        scramble(&tokens, wl).expect("scramble must succeed on MVP corpus");
    unscramble(&scrambled, wl).expect("unscramble is infallible in MVP")
}

/// Production-path: full layer composition + header encode/decode.
///
/// Drives the same `scramble_pipeline` + `unscramble_pipeline`
/// modules the operator-facing CLI uses.  The L2 mapping is built
/// in-proc via `MappingBuilder` so the daemon socket round-trip is
/// excluded — same scope rule as the L3-only path's whitespace-
/// wordlist exclusion.
fn run_once_full(
    source: &str,
    wl: &WhitespaceWordlist,
    builder: &MappingBuilder<'_>,
    epoch: u64,
) -> String {
    let scrambled = scramble_pipeline(source, epoch, wl, |toks, e| {
        build_mapping(builder, toks, e)
    })
    .expect("scramble_pipeline must succeed on MVP corpus");

    let decoded = decode_file(&scrambled.file).expect("decode header");
    let mapping = build_mapping(builder, &decoded.sorted_tokens, epoch)
        .expect("identifier mapping rebuild must succeed");
    unscramble_pipeline(
        decoded.version,
        decoded.epoch,
        &decoded.body,
        wl,
        &mapping,
    )
}

/// Build an `IdentifierMapping` for `tokens` at `epoch` using the
/// production virtual-epoch scheme (`epoch * ALIAS_COUNT + alias_idx`).
fn build_mapping(
    builder: &MappingBuilder<'_>,
    tokens: &[String],
    epoch: u64,
) -> babbleon_preprocessor_v2::errors::Result<IdentifierMapping> {
    let base = epoch.saturating_mul(ALIAS_COUNT as u64);
    let mut per_alias: Vec<Vec<String>> = Vec::with_capacity(ALIAS_COUNT);
    for ai in 0..ALIAS_COUNT {
        let virtual_epoch = base + ai as u64;
        let mapping = builder
            .build(tokens, virtual_epoch)
            .expect("MappingBuilder::build should not fail for the test corpus");
        let compounds: Vec<String> = tokens
            .iter()
            .map(|t| mapping.scramble(t).unwrap_or(t.as_str()).to_string())
            .collect();
        per_alias.push(compounds);
    }
    let mut aliases: Vec<Vec<String>> =
        tokens.iter().map(|_| Vec::with_capacity(ALIAS_COUNT)).collect();
    for one_alias_set in per_alias {
        for (ti, compound) in one_alias_set.into_iter().enumerate() {
            aliases[ti].push(compound);
        }
    }
    IdentifierMapping::from_tokens_and_aliases(
        tokens.to_vec(),
        epoch,
        aliases,
    )
}
