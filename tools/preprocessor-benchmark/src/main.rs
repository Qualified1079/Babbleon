//! Per-file latency microbenchmark for the v2 layer-3 preprocessor.
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
//! For each example puzzle file at
//! `tools/scrambler/example-puzzles/*.py`:
//!
//! 1. **Tokenize**: `python_tokenizer::tokenize(source) -> Vec<Token>`.
//! 2. **Scramble**: `scrambler::scramble(&tokens, &wl) -> String`.
//! 3. **Unscramble**: `unscrambler::unscramble(&scrambled, &wl) -> String`.
//! 4. **End-to-end**: the sum of the above, which is what an operator
//!    wraps with `babbleon scramble` / `babbleon unscramble` on the
//!    socket-fetch fast path.
//!
//! The per-host-secret + epoch WhitespaceWordlist derivation is
//! built once before the loop and shared.  In production the daemon
//! caches the same mapping across requests, so excluding the build
//! cost matches the steady-state cost the operator sees.
//!
//! # What we do NOT measure
//!
//! - The Unix socket round-trip to the daemon for the whitespace
//!   compounds.  That's a one-shot 4-KiB JSONL exchange that
//!   amortises across N scramble calls per session; not the layer-3
//!   per-file cost.  The phase-3 spec's sub-50ms budget is the
//!   preprocessor's local compute path.
//! - File I/O.  Reading the puzzle source from disk once before the
//!   timing loop is excluded so we measure pure pipeline cost.
//!
//! # Output
//!
//! Per-puzzle table: mean / median / p95 / min / max in microseconds
//! over `--iterations` runs (default 1000, plus 100 warmup).  A
//! final aggregate row reports the worst-case median across all
//! puzzles versus the 50 000-µs phase-3 target.  Exit code 0 if the
//! target is met for every puzzle; exit code 1 if any puzzle's
//! median exceeds the target.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;

use babbleon_core_v2::per_host_secret::PerHostSecret;
use babbleon_core_v2::wordlist::Wordlist;
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

    /// Phase-3 target: per-file latency must be at most this many
    /// microseconds.  Defaults to 50 000 (= 50 ms).  Exit code is 1
    /// if any puzzle's median exceeds this.
    #[arg(long, default_value_t = 50_000)]
    target_micros: u128,

    /// Epoch to derive the whitespace mapping for.  Defaults to 0;
    /// override to confirm latency is epoch-independent.
    #[arg(long, default_value_t = 0)]
    epoch: u64,
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
    iterations: usize,
    warmup: usize,
) -> Stats {
    // Warmup: same pipeline, results discarded.  Warms up the
    // tokenizer's internal allocations and any branch-predictor
    // state.
    for _ in 0..warmup {
        run_once(source, wl);
    }

    let mut times = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        run_once(source, wl);
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

/// One end-to-end pipeline pass: tokenize -> scramble -> unscramble.
///
/// `#[inline(never)]` keeps the compiler from hoisting any of the
/// stages out of the timer when the loop body is short.  Without
/// this, the optimiser was inlining `tokenize` and observing the
/// result was unused, which collapsed the measurement.
#[inline(never)]
fn run_once(source: &str, wl: &WhitespaceWordlist) -> String {
    let tokens = tokenize(source);
    let scrambled = scramble(&tokens, wl).expect("scramble must succeed on MVP corpus");
    unscramble(&scrambled, wl).expect("unscramble is infallible in MVP")
}
