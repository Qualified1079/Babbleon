//! Parse `tools/wordlist-density-analysis/RESULTS.md`'s filter-matrix
//! table into per-wordlist-variant compound-token means.
//!
//! # Why this exists
//!
//! `--role-tokens name=value` (see `main.rs`) already lets an
//! operator plug a measured tokens-per-compound number into the
//! calculator, but the operator has to hand-copy the number out of
//! a benchmark `RESULTS.md` table first — error-prone, and stale the
//! moment the benchmark reruns.  This module reads the table
//! directly so `--role-wordlist-variant identifier=intersect35` can
//! resolve to the current measured number instead of a hand-typed
//! literal.
//!
//! # What it parses
//!
//! The five-column markdown pipe-table that
//! `tools/wordlist-density-analysis/RESULTS.md` §"Compound-cost
//! measurement" emits:
//!
//! ```text
//! |                        Wordlist |  cl100k mean |    Δ cl100k |   o200k mean |    Δ o200k |
//! |--------------------------------:|-------------:|------------:|-------------:|-----------:|
//! |              Baseline (369 652) |        11.96 |           — |        11.53 |          — |
//! |    **intersect [3, 5]** (223 009) |    **13.80** | **+15.4 %** |    **13.38** | **+16.1 %** |
//! ```
//!
//! Each data row's first cell is `<label> (<kept>)`, optionally
//! wrapped in `**...**` for emphasis on the recommended row. This
//! module strips the emphasis markers and derives a lookup `key`
//! from the label: lowercase, `[`/`]`/`,`/whitespace stripped, so
//! `"cl100k [3, 5]"` → `"cl10035"`... — see [`normalise_key`]'s
//! doc comment for the exact rule and worked examples.
//!
//! # What it does NOT do
//!
//! - Does not decide which variant a role should use.  That
//!   assignment (identifier → intersect[3,5]? decoy → baseline?) is
//!   still an open operator decision per
//!   `docs/v2/phase0-research-notes.md` §11 — this module only
//!   removes the copy-paste step once the assignment is made.
//! - Does not touch the hard-coded numbers in
//!   [`crate::params::WordlistModel`] (`cl100k_baseline`,
//!   `cl100k_intersect_3_5`) — those describe the *overall* wordlist
//!   a run allocates against, a different knob from a *per-role*
//!   token-cost override.

use std::path::Path;

/// One row of the parsed filter-matrix table.
#[derive(Debug, Clone, PartialEq)]
pub struct WordlistVariant {
    /// Normalised lookup key, e.g. `"intersect35"`.  See
    /// [`normalise_key`].
    pub key: String,
    /// Original label text, e.g. `"intersect [3, 5]"`.
    pub label: String,
    /// Kept-entry count parsed from the `(NNN)` suffix, if present.
    pub kept: Option<usize>,
    /// Mean cl100k tokens per compound, if the column parsed as a
    /// number (a `—` em-dash or `n/a` cell yields `None`).
    pub cl100k_mean: Option<f64>,
    /// Mean o200k tokens per compound, if the column parsed as a
    /// number.
    pub o200k_mean: Option<f64>,
}

/// Read `path` and parse its filter-matrix table.
///
/// # Errors
///
/// Returns a description string on I/O failure or if the file
/// contains no parseable data rows at all (a malformed-input
/// signal worth surfacing rather than silently returning an empty
/// list).
pub fn load_variants(path: &Path) -> Result<Vec<WordlistVariant>, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("read {}: {e}", path.display()))?;
    let variants = parse_filter_matrix(&text);
    if variants.is_empty() {
        return Err(format!(
            "{} parsed but yielded no wordlist-variant rows — is this a \
             wordlist-density-analysis RESULTS.md-shaped file?",
            path.display()
        ));
    }
    Ok(variants)
}

/// Parse every data row of the filter-matrix table out of
/// `markdown`.  Non-table lines, the header row, and the
/// `---:|---:|...` separator row are all silently skipped.  Rows
/// that don't have exactly 5 pipe-delimited cells are skipped too
/// (defensive — a future RESULTS.md revision with a different table
/// shape should degrade to "found nothing", not panic or misparse).
#[must_use]
pub fn parse_filter_matrix(markdown: &str) -> Vec<WordlistVariant> {
    markdown
        .lines()
        .filter_map(parse_row)
        .collect()
}

fn parse_row(line: &str) -> Option<WordlistVariant> {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') {
        return None;
    }
    let cells: Vec<&str> = trimmed
        .trim_matches('|')
        .split('|')
        .map(str::trim)
        .collect();
    if cells.len() != 5 {
        return None;
    }
    // Header row ("Wordlist", "cl100k mean", ...) and the
    // `---:` separator row both fail the label-cell parse below
    // (no trailing `(NNN)`), so no special-case skip is needed for
    // either — `parse_label` returning `None` handles both.
    let (label, kept) = parse_label(cells[0])?;
    Some(WordlistVariant {
        key: normalise_key(&label),
        label,
        kept,
        cl100k_mean: parse_number_cell(cells[1]),
        o200k_mean: parse_number_cell(cells[3]),
    })
}

/// `"**intersect [3, 5]** (223 009)"` → `("intersect [3, 5]",
/// Some(223009))`.  Returns `None` if the cell has no trailing
/// `(NNN)` group (header/separator rows, or a malformed data row).
fn parse_label(cell: &str) -> Option<(String, Option<usize>)> {
    let unbolded = cell.replace("**", "");
    let unbolded = unbolded.trim();
    let open = unbolded.rfind('(')?;
    let close = unbolded.rfind(')')?;
    if close < open {
        return None;
    }
    let label = unbolded[..open].trim().to_string();
    if label.is_empty() {
        return None;
    }
    let count_str: String = unbolded[open + 1..close]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let kept = count_str.parse::<usize>().ok();
    Some((label, kept))
}

/// `"**13.80**"` → `Some(13.80)`.  `"—"`, `"n/a"`, and anything else
/// that doesn't parse as `f64` (including delta cells like
/// `"+15.4 %"`, which callers should not pass here) yields `None`.
fn parse_number_cell(cell: &str) -> Option<f64> {
    let unbolded = cell.replace("**", "");
    unbolded.trim().parse::<f64>().ok()
}

/// Derive a stable lookup key from a variant label: lowercase,
/// strip `[`, `]`, `,`, and whitespace.  Worked examples (matching
/// the current `wordlist-density-analysis/RESULTS.md` table):
///
/// - `"Baseline"` → `"baseline"`
/// - `"cl100k [3, 4]"` → `"cl100k34"`
/// - `"cl100k [3, 5]"` → `"cl100k35"`
/// - `"o200k [3, 5]"` → `"o200k35"`
/// - `"intersect [3, 5]"` → `"intersect35"`
#[must_use]
pub fn normalise_key(label: &str) -> String {
    label
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{load_variants, normalise_key, parse_filter_matrix};

    const SAMPLE: &str = "\
Mean tokens per 4-word compound, averaged over three seeds:

|                        Wordlist |  cl100k mean |    Δ cl100k |   o200k mean |    Δ o200k |
|--------------------------------:|-------------:|------------:|-------------:|-----------:|
|              Baseline (369 652) |        11.96 |           — |        11.53 |          — |
|        cl100k [3, 4] (225 886) |        13.11 |     +9.6 %  |        12.55 |    +8.8 %  |
|        cl100k [3, 5] (244 804) |        13.60 |    +13.7 %  |        12.97 |   +12.5 %  |
|    **intersect [3, 5]** (223 009) |    **13.80** | **+15.4 %** |    **13.38** | **+16.1 %** |

The intersection row is the clear winner.
";

    #[test]
    fn normalise_key_matches_worked_examples() {
        assert_eq!(normalise_key("Baseline"), "baseline");
        assert_eq!(normalise_key("cl100k [3, 4]"), "cl100k34");
        assert_eq!(normalise_key("cl100k [3, 5]"), "cl100k35");
        assert_eq!(normalise_key("o200k [3, 5]"), "o200k35");
        assert_eq!(normalise_key("intersect [3, 5]"), "intersect35");
    }

    #[test]
    fn parses_all_data_rows_and_skips_header_and_prose() {
        let rows = parse_filter_matrix(SAMPLE);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].key, "baseline");
        assert_eq!(rows[3].key, "intersect35");
    }

    #[test]
    fn parses_numeric_cells_including_bold() {
        let rows = parse_filter_matrix(SAMPLE);
        let baseline = &rows[0];
        assert_eq!(baseline.cl100k_mean, Some(11.96));
        assert_eq!(baseline.o200k_mean, Some(11.53));
        assert_eq!(baseline.kept, Some(369_652));

        let intersect = &rows[3];
        assert_eq!(intersect.cl100k_mean, Some(13.80));
        assert_eq!(intersect.o200k_mean, Some(13.38));
        assert_eq!(intersect.kept, Some(223_009));
    }

    #[test]
    fn em_dash_delta_cell_is_not_confused_with_a_number() {
        // The Δ columns (index 2 and 4) are never parsed by this
        // module — confirm the parser only reads columns 1 and 3
        // by checking baseline's em-dash Δ cell did not leak into
        // either mean field as a spurious `None`-vs-error case.
        let rows = parse_filter_matrix(SAMPLE);
        assert!(rows[0].cl100k_mean.is_some());
        assert!(rows[0].o200k_mean.is_some());
    }

    #[test]
    fn load_variants_reads_from_disk() {
        let dir = std::env::temp_dir().join(format!(
            "rp-tokresults-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("RESULTS.md");
        std::fs::write(&path, SAMPLE).unwrap();

        let rows = load_variants(&path).unwrap();
        assert_eq!(rows.len(), 4);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn load_variants_errors_on_missing_file() {
        let err = load_variants(std::path::Path::new("/no/such/file.md")).unwrap_err();
        assert!(err.contains("/no/such/file.md"));
    }

    #[test]
    fn load_variants_errors_on_table_less_input() {
        let dir = std::env::temp_dir().join(format!(
            "rp-tokresults-empty-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("RESULTS.md");
        std::fs::write(&path, "no tables here, just prose.\n").unwrap();

        let err = load_variants(&path).unwrap_err();
        assert!(err.contains("no wordlist-variant rows"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
