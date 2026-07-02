//! Stdout summary and file emitters.
//!
//! Three sinks:
//!  - `print_summary` — human-readable stats to stdout, including
//!    the cl100k / o200k histograms and a small percentile table.
//!  - `write_scores_csv` — one row per word, tokenizer counts +
//!    byte length.  Ready for spreadsheet joins.
//!  - `write_filtered_wordlist` and `write_filter_manifest` — for
//!    a filter run, the surviving wordlist (one word per line, sorted
//!    the same way the input was) plus a manifest recording the
//!    filter parameters so the run is reproducible from disk alone.

use anyhow::{Context, Result};
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::filter::{FilterResult, IntersectedResult};
use crate::score::WordScore;
use crate::stats::Distribution;

const PERCENTILE_PROBES: &[f64] = &[1.0, 5.0, 10.0, 25.0, 50.0, 75.0, 90.0, 95.0, 99.0];
const HISTOGRAM_MAX_BUCKET: usize = 10;

pub fn print_summary(scores: &[WordScore]) {
    println!("Scored {} words.\n", scores.len());
    let cl_dist = Distribution::from(scores.iter().map(|s| s.cl100k));
    let o2_dist = Distribution::from(scores.iter().map(|s| s.o200k));
    println!("cl100k_base:");
    print_dist_row(&cl_dist);
    println!("o200k_base:");
    print_dist_row(&o2_dist);

    println!("\nPercentile → token-count cutoff:");
    println!(
        "  {:>7}  {:>10}  {:>10}",
        "pctile", "cl100k", "o200k"
    );
    for &p in PERCENTILE_PROBES {
        println!(
            "  {:>7.1}  {:>10}  {:>10}",
            p,
            cl_dist.value_at_percentile(p),
            o2_dist.value_at_percentile(p)
        );
    }

    println!("\ncl100k histogram (tokens per word):");
    print_histogram(&cl_dist, HISTOGRAM_MAX_BUCKET);
    println!("\no200k histogram (tokens per word):");
    print_histogram(&o2_dist, HISTOGRAM_MAX_BUCKET);
}

fn print_dist_row(d: &Distribution) {
    println!(
        "  mean={:.3}  median={}  min={}  max={}",
        d.mean(),
        d.value_at_percentile(50.0),
        d.min(),
        d.max()
    );
}

fn print_histogram(d: &Distribution, max_bucket: usize) {
    let buckets = d.histogram(max_bucket);
    let total: usize = buckets.iter().sum();
    if total == 0 {
        println!("  (empty)");
        return;
    }
    for (k, count) in buckets.iter().enumerate() {
        let label = if k == max_bucket + 1 {
            format!(">{max_bucket}")
        } else {
            format!("{k:>2}")
        };
        let pct = *count as f64 / total as f64 * 100.0;
        let bar_len = ((*count as f64 / total as f64) * 60.0).round() as usize;
        let bar = "#".repeat(bar_len);
        println!(
            "  {label}  {count:>8}  ({pct:>5.2}%)  {bar}"
        );
    }
}

pub fn write_scores_csv(scores: &[WordScore], path: &Path) -> Result<()> {
    let f = fs::File::create(path)
        .with_context(|| format!("create scores csv {}", path.display()))?;
    let mut w = BufWriter::new(f);
    writeln!(w, "word,bytes,cl100k,o200k")?;
    for s in scores {
        writeln!(w, "{},{},{},{}", s.word, s.bytes, s.cl100k, s.o200k)?;
    }
    w.flush()?;
    Ok(())
}

/// Write the surviving wordlist, one word per line.  Preserves the
/// order of `result.kept`, which mirrors the input scoring order.
pub fn write_filtered_wordlist(result: &FilterResult, path: &Path) -> Result<()> {
    write_wordlist_lines(&result.kept, path)
}

/// Write the intersection of two `FilterResult`s (see
/// `filter::intersect`), one word per line, in the primary's input
/// order.
pub fn write_intersected_wordlist(result: &IntersectedResult, path: &Path) -> Result<()> {
    write_wordlist_lines(&result.kept, path)
}

fn write_wordlist_lines(scores: &[WordScore], path: &Path) -> Result<()> {
    let f = fs::File::create(path)
        .with_context(|| format!("create filtered wordlist {}", path.display()))?;
    let mut w = BufWriter::new(f);
    for score in scores {
        writeln!(w, "{}", score.word)?;
    }
    w.flush()?;
    Ok(())
}

/// Emit a small human-readable manifest capturing the filter
/// parameters + resulting cutoffs + drop stats.  We intentionally do
/// NOT use JSON here — the file is meant for operator eyeballs, not
/// downstream tooling; a downstream consumer should re-run the tool.
pub fn write_filter_manifest(result: &FilterResult, path: &Path) -> Result<()> {
    let f = fs::File::create(path)
        .with_context(|| format!("create manifest {}", path.display()))?;
    let mut w = BufWriter::new(f);
    writeln!(w, "# wordlist-density-analysis filter manifest")?;
    write_filter_manifest_fields(&mut w, "", result)?;
    w.flush()?;
    Ok(())
}

pub fn write_intersection_manifest(
    result: &IntersectedResult,
    path: &Path,
) -> Result<()> {
    let f = fs::File::create(path)
        .with_context(|| format!("create manifest {}", path.display()))?;
    let mut w = BufWriter::new(f);
    writeln!(
        w,
        "# wordlist-density-analysis intersection manifest"
    )?;
    writeln!(w, "# primary filter (drop-below/above counts and cutoffs refer to this):")?;
    write_filter_manifest_fields(&mut w, "primary_", &result.primary)?;
    writeln!(w, "# secondary filter:")?;
    write_filter_manifest_fields(&mut w, "secondary_", &result.secondary)?;
    writeln!(w)?;
    writeln!(w, "input_total                {}", result.total_input())?;
    writeln!(w, "kept_intersection          {}", result.kept.len())?;
    writeln!(
        w,
        "dropped_by_secondary_only  {}",
        result.dropped_by_secondary_only
    )?;
    writeln!(
        w,
        "kept_fraction              {:.6}",
        result.kept_fraction()
    )?;
    w.flush()?;
    Ok(())
}

fn write_filter_manifest_fields<W: Write>(
    w: &mut W,
    prefix: &str,
    result: &FilterResult,
) -> Result<()> {
    writeln!(w, "{prefix}tokenizer        {}", result.spec.tokenizer)?;
    writeln!(w, "{prefix}min_bound        {}", result.spec.min)?;
    writeln!(w, "{prefix}max_bound        {}", result.spec.max)?;
    writeln!(w, "{prefix}cutoff_low       {}", result.cutoff_low)?;
    writeln!(w, "{prefix}cutoff_high      {}", result.cutoff_high)?;
    writeln!(w, "{prefix}input_total      {}", result.total_input())?;
    writeln!(w, "{prefix}kept             {}", result.kept.len())?;
    writeln!(w, "{prefix}dropped_below    {}", result.dropped_below)?;
    writeln!(w, "{prefix}dropped_above    {}", result.dropped_above)?;
    writeln!(
        w,
        "{prefix}kept_fraction    {:.6}",
        result.kept_fraction()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{Bound, FilterSpec, Tokenizer};

    fn tmp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "wla-report-{}-{}.txt",
            tag,
            std::process::id()
        ))
    }

    fn dummy_scores() -> Vec<WordScore> {
        (1..=10)
            .map(|i| WordScore {
                word: format!("w{i}"),
                bytes: 2,
                cl100k: i,
                o200k: i,
            })
            .collect()
    }

    #[test]
    fn scores_csv_round_trips_row_count() {
        let scores = dummy_scores();
        let p = tmp_path("csv");
        write_scores_csv(&scores, &p).unwrap();
        let body = fs::read_to_string(&p).unwrap();
        // Header + one row per score.
        assert_eq!(body.lines().count(), 1 + scores.len());
        assert!(body.starts_with("word,bytes,cl100k,o200k"));
    }

    #[test]
    fn filtered_wordlist_emits_one_word_per_line() {
        let scores = dummy_scores();
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Percentile(30.0),
            max: Bound::Percentile(70.0),
        };
        let r = spec.apply(&scores).unwrap();
        let p = tmp_path("kept");
        write_filtered_wordlist(&r, &p).unwrap();
        let body = fs::read_to_string(&p).unwrap();
        assert_eq!(body.lines().count(), r.kept.len());
    }

    #[test]
    fn manifest_records_all_fields() {
        let scores = dummy_scores();
        let spec = FilterSpec {
            tokenizer: Tokenizer::Cl100k,
            min: Bound::Percentile(30.0),
            max: Bound::Percentile(70.0),
        };
        let r = spec.apply(&scores).unwrap();
        let p = tmp_path("manifest");
        write_filter_manifest(&r, &p).unwrap();
        let body = fs::read_to_string(&p).unwrap();
        for needle in [
            "tokenizer",
            "min_bound",
            "max_bound",
            "cutoff_low",
            "cutoff_high",
            "input_total",
            "kept",
            "dropped_below",
            "dropped_above",
            "kept_fraction",
        ] {
            assert!(body.contains(needle), "manifest missing {needle}:\n{body}");
        }
    }
}
