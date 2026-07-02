//! Tokenizer benchmark — measures token-count cost for Babbleon scrambled
//! compounds against a matched spaced-English baseline.
//!
//! # Why this exists
//!
//! RESEARCH.md T6 hypothesized that lowercase-concatenated N-word compounds
//! impose a 2–3× token-cost tax on a BPE tokenizer (cl100k_base /
//! o200k_base) relative to spaced English of the same word content.  That
//! number has never been verified locally.  This binary is the actual
//! measurement.  No PLAN- or README-level claim about token-cost inflation
//! should be made until this benchmark has been run on the production
//! wordlist and the result is recorded.
//!
//! # Experimental design
//!
//! Same draw of N words per sample is used for both conditions:
//!   - `compound`: words concatenated, all lowercase, no separator.
//!   - `spaced`:   same words, single-space separator.
//!
//! This isolates the *no-whitespace* effect from word-frequency confounds.
//! For each sample we record the cl100k_base and o200k_base token count of
//! both forms; the comparison statistic is `compound_tokens / spaced_tokens`
//! per sample.
//!
//! # Usage
//!
//!   cargo run --release -- \
//!     --wordlist ../../crates/babbleon/wordlist/words.txt \
//!     --samples 1000
//!
//! The report is plain text on stdout; nothing is written to disk unless
//! `--out <path>` is given.

use clap::Parser;
use rand::seq::SliceRandom;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use tiktoken_rs::{cl100k_base, o200k_base, p50k_base, r50k_base, CoreBPE};

#[derive(Parser)]
#[command(about = "BPE tokenizer cost benchmark for Babbleon compound names")]
struct Args {
    /// Path to the Babbleon wordlist (one word per line, lowercase a-z).
    #[arg(long, default_value = "../../crates/babbleon/wordlist/words.txt")]
    wordlist: PathBuf,

    /// Number of samples per condition.
    #[arg(short, long, default_value_t = 1000)]
    samples: usize,

    /// Number of words per compound (and per spaced baseline phrase).
    #[arg(short = 'n', long, default_value_t = 4)]
    compound_n: usize,

    /// Deterministic seed so a run is reproducible.
    #[arg(long, default_value_t = 0xBABB_1E00_1122_3344u64)]
    seed: u64,

    /// Optional path to write a CSV of per-sample counts for further analysis.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Include the older GPT-3-era `r50k_base` and Codex-era
    /// `p50k_base` tokenizers.  Tests the "smaller-vocab tokenizer
    /// pays more per compound" superlinear hypothesis (TODO.md
    /// phase 4 supporting research).  Off by default so existing
    /// runs keep their two-tokenizer output shape.
    #[arg(long, default_value_t = false)]
    include_smaller: bool,
}

struct Stats {
    mean: f64,
    median: usize,
    p95: usize,
    min: usize,
    max: usize,
}

fn summarize(counts: &[usize]) -> Stats {
    let mut sorted: Vec<usize> = counts.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let mean = counts.iter().sum::<usize>() as f64 / n as f64;
    let median = sorted[n / 2];
    let p95_idx = ((n as f64 - 1.0) * 0.95).round() as usize;
    let p95 = sorted[p95_idx];
    Stats {
        mean,
        median,
        p95,
        min: sorted[0],
        max: sorted[n - 1],
    }
}

fn print_row(label: &str, s: &Stats) {
    println!(
        "  {label:<30}  mean={:>7.2}  median={:>4}  p95={:>4}  min={:>3}  max={:>4}",
        s.mean, s.median, s.p95, s.min, s.max
    );
}

fn load_wordlist(path: &PathBuf) -> Vec<String> {
    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read wordlist {}: {e}", path.display()));
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_lowercase()))
        .map(|l| l.to_string())
        .collect()
}

fn count_tokens(bpe: &CoreBPE, s: &str) -> usize {
    bpe.encode_with_special_tokens(s).len()
}

fn main() {
    let args = Args::parse();

    println!("Loading wordlist: {}", args.wordlist.display());
    let words = load_wordlist(&args.wordlist);
    println!("  {} usable words (lowercase ASCII)", words.len());
    assert!(words.len() >= args.compound_n);

    println!("Loading tokenizers...");
    let cl100k = cl100k_base().expect("cl100k_base");
    let o200k = o200k_base().expect("o200k_base");
    let smaller = if args.include_smaller {
        Some((
            r50k_base().expect("r50k_base"),
            p50k_base().expect("p50k_base"),
        ))
    } else {
        None
    };

    println!(
        "Sampling {} compounds × {} words (seed=0x{:x})",
        args.samples, args.compound_n, args.seed
    );

    let mut rng = ChaCha20Rng::seed_from_u64(args.seed);

    let mut compound_cl: Vec<usize> = Vec::with_capacity(args.samples);
    let mut compound_o2: Vec<usize> = Vec::with_capacity(args.samples);
    let mut spaced_cl: Vec<usize> = Vec::with_capacity(args.samples);
    let mut spaced_o2: Vec<usize> = Vec::with_capacity(args.samples);
    let mut ratios_cl: Vec<f64> = Vec::with_capacity(args.samples);
    let mut ratios_o2: Vec<f64> = Vec::with_capacity(args.samples);
    // Vectors for the smaller tokenizers, empty when --include-smaller is off.
    let mut compound_r50: Vec<usize> = Vec::with_capacity(args.samples);
    let mut compound_p50: Vec<usize> = Vec::with_capacity(args.samples);
    let mut spaced_r50: Vec<usize> = Vec::with_capacity(args.samples);
    let mut spaced_p50: Vec<usize> = Vec::with_capacity(args.samples);
    let mut ratios_r50: Vec<f64> = Vec::with_capacity(args.samples);
    let mut ratios_p50: Vec<f64> = Vec::with_capacity(args.samples);

    let mut csv = args.out.as_ref().map(|p| {
        let mut f = fs::File::create(p).expect("create csv");
        writeln!(f, "compound,spaced,compound_cl100k,spaced_cl100k,compound_o200k,spaced_o200k")
            .unwrap();
        f
    });

    for _ in 0..args.samples {
        let picks: Vec<&String> = words
            .choose_multiple(&mut rng, args.compound_n)
            .collect();
        let compound: String = picks.iter().map(|s| s.as_str()).collect();
        let spaced: String = picks
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" ");

        let c_cl = count_tokens(&cl100k, &compound);
        let s_cl = count_tokens(&cl100k, &spaced);
        let c_o2 = count_tokens(&o200k, &compound);
        let s_o2 = count_tokens(&o200k, &spaced);

        compound_cl.push(c_cl);
        spaced_cl.push(s_cl);
        compound_o2.push(c_o2);
        spaced_o2.push(s_o2);
        ratios_cl.push(c_cl as f64 / s_cl as f64);
        ratios_o2.push(c_o2 as f64 / s_o2 as f64);

        if let Some((r50, p50)) = &smaller {
            let c_r50 = count_tokens(r50, &compound);
            let s_r50 = count_tokens(r50, &spaced);
            let c_p50 = count_tokens(p50, &compound);
            let s_p50 = count_tokens(p50, &spaced);
            compound_r50.push(c_r50);
            spaced_r50.push(s_r50);
            compound_p50.push(c_p50);
            spaced_p50.push(s_p50);
            ratios_r50.push(c_r50 as f64 / s_r50 as f64);
            ratios_p50.push(c_p50 as f64 / s_p50 as f64);
        }

        if let Some(f) = &mut csv {
            writeln!(
                f,
                "{compound},{spaced},{c_cl},{s_cl},{c_o2},{s_o2}"
            )
            .unwrap();
        }
    }

    println!("\nToken-count distributions (per sample):");
    println!("  cl100k_base:");
    print_row("    compound (no separator)", &summarize(&compound_cl));
    print_row("    spaced (control)       ", &summarize(&spaced_cl));
    println!("  o200k_base:");
    print_row("    compound (no separator)", &summarize(&compound_o2));
    print_row("    spaced (control)       ", &summarize(&spaced_o2));
    if smaller.is_some() {
        println!("  r50k_base (GPT-3 era):");
        print_row("    compound (no separator)", &summarize(&compound_r50));
        print_row("    spaced (control)       ", &summarize(&spaced_r50));
        println!("  p50k_base (Codex era):");
        print_row("    compound (no separator)", &summarize(&compound_p50));
        print_row("    spaced (control)       ", &summarize(&spaced_p50));
    }

    let mean_ratio_cl = ratios_cl.iter().sum::<f64>() / ratios_cl.len() as f64;
    let mean_ratio_o2 = ratios_o2.iter().sum::<f64>() / ratios_o2.len() as f64;
    let mut sorted_cl = ratios_cl.clone();
    let mut sorted_o2 = ratios_o2.clone();
    sorted_cl.sort_by(|a, b| a.partial_cmp(b).unwrap());
    sorted_o2.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median_cl = sorted_cl[sorted_cl.len() / 2];
    let median_o2 = sorted_o2[sorted_o2.len() / 2];

    println!("\nPer-sample ratio (compound / spaced):");
    println!(
        "  cl100k_base:  mean={:.3}×  median={:.3}×",
        mean_ratio_cl, median_cl
    );
    println!(
        "  o200k_base:   mean={:.3}×  median={:.3}×",
        mean_ratio_o2, median_o2
    );
    if smaller.is_some() {
        let mean_ratio_r50 = ratios_r50.iter().sum::<f64>() / ratios_r50.len() as f64;
        let mean_ratio_p50 = ratios_p50.iter().sum::<f64>() / ratios_p50.len() as f64;
        let mut sorted_r50 = ratios_r50.clone();
        let mut sorted_p50 = ratios_p50.clone();
        sorted_r50.sort_by(|a, b| a.partial_cmp(b).unwrap());
        sorted_p50.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median_r50 = sorted_r50[sorted_r50.len() / 2];
        let median_p50 = sorted_p50[sorted_p50.len() / 2];
        println!(
            "  r50k_base:    mean={:.3}×  median={:.3}×",
            mean_ratio_r50, median_r50
        );
        println!(
            "  p50k_base:    mean={:.3}×  median={:.3}×",
            mean_ratio_p50, median_p50
        );
    }

    if let Some(p) = &args.out {
        println!("\nPer-sample CSV written to {}", p.display());
    }
    println!(
        "\nReport these numbers in PLAN.md / README only with the wordlist + \
         seed + sample size that produced them."
    );
}
