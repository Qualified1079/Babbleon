//! Wordlist loader with baseline invariants.
//!
//! The Babbleon baseline wordlist ships as one lowercase-ASCII word
//! per line.  The security posture depends on those invariants (see
//! `crates/v2-babbleon-core/src/wordlist.rs` for the runtime loader
//! that this analysis mirrors).  A filter that emits a subset of the
//! baseline must preserve them; the same validation code runs on
//! load so we cannot analyse something that would fail the runtime
//! loader.
//!
//! # `Mode::UnicodeLowercase` opt-in
//!
//! Phase-4 multi-language exploration (see
//! `docs/v2/multi-language-density-notes.md`) needs to score
//! wordlists with diacritics (`café`, `naïve`, `köln`) that the
//! runtime loader currently refuses.  The `UnicodeLowercase` mode
//! accepts any character that reports `is_lowercase()` per Unicode.
//! This is analysis-side only — a wordlist that loads under
//! Unicode mode must still be normalised or the loader relaxed on
//! the runtime side before it can ship.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use unicode_normalization::UnicodeNormalization;

/// Which character set the loader will accept.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Default: matches the runtime's `[a-z]+` invariant.
    AsciiLowercase,
    /// Opt-in: accepts any Unicode lowercase character.  For
    /// exploratory phase-4 multi-language analysis.
    UnicodeLowercase,
}

/// A loaded, validated Babbleon-baseline wordlist.
#[derive(Debug)]
pub struct Wordlist {
    pub words: Vec<String>,
}

impl Wordlist {
    /// Load and validate a wordlist file under the default
    /// `AsciiLowercase` mode.  Kept as a shim so existing call
    /// sites (this crate's tests + external tools that link the
    /// module) do not need to plumb a mode argument.
    #[allow(dead_code)]
    pub fn from_path(path: &Path) -> Result<Self> {
        Self::from_path_with_mode(path, Mode::AsciiLowercase, false)
    }

    /// Load and validate a wordlist file.  When
    /// `normalise_diacritics` is true, each entry is NFKD-decomposed
    /// and combining marks are dropped BEFORE validation, so `café`
    /// under `AsciiLowercase` mode becomes `cafe` and passes.
    /// Duplicates arising from normalisation are dropped
    /// (first-occurrence wins) rather than erroring so a
    /// multi-language corpus loads gracefully.
    pub fn from_path_with_mode(
        path: &Path,
        mode: Mode,
        normalise_diacritics: bool,
    ) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read wordlist {}", path.display()))?;
        let mut words: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        if normalise_diacritics {
            let mut seen: HashSet<String> = HashSet::with_capacity(words.len());
            let mut kept: Vec<String> = Vec::with_capacity(words.len());
            for w in words.drain(..) {
                let normalised = strip_combining_marks(&w);
                if !normalised.is_empty() && seen.insert(normalised.clone()) {
                    kept.push(normalised);
                }
            }
            words = kept;
        }
        validate(&words, mode)?;
        Ok(Self { words })
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }
}

/// NFKD-decompose `w`, drop combining marks
/// (`char::is_mark_nonspacing`), and fold the handful of Latin
/// ligatures Unicode does not decompose on its own (`œ` → `oe`,
/// `æ` → `ae`, `ß` → `ss`, `ø` → `o`).  `café` → `cafe`,
/// `naïve` → `naive`, `köln` → `koln`, `cœur` → `coeur`, `groß`
/// → `gross`.  Non-Latin characters that decompose to combining
/// sequences (e.g. Devanagari) collapse to their base glyph.
fn strip_combining_marks(w: &str) -> String {
    let mut out = String::with_capacity(w.len());
    for c in w.nfkd() {
        if unicode_normalization::char::is_combining_mark(c) {
            continue;
        }
        match c {
            'œ' => out.push_str("oe"),
            'æ' => out.push_str("ae"),
            'ß' => out.push_str("ss"),
            'ø' => out.push('o'),
            'ð' => out.push('d'),
            'þ' => out.push_str("th"),
            other => out.push(other),
        }
    }
    out
}

fn validate(words: &[String], mode: Mode) -> Result<()> {
    if words.is_empty() {
        bail!("wordlist is empty");
    }
    let mut seen: HashSet<&str> = HashSet::with_capacity(words.len());
    for w in words {
        if w.is_empty() {
            bail!("wordlist entry is empty");
        }
        match mode {
            Mode::AsciiLowercase => {
                if !w.chars().all(|c| c.is_ascii_lowercase()) {
                    bail!("wordlist entry {:?} contains non-[a-z] characters", w);
                }
            }
            Mode::UnicodeLowercase => {
                if !w.chars().all(char::is_lowercase) {
                    bail!(
                        "wordlist entry {:?} contains non-lowercase characters (Unicode mode)",
                        w
                    );
                }
            }
        }
        if !seen.insert(w) {
            bail!("wordlist entry {:?} appears more than once", w);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(tag: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "wla-load-test-{}-{tag}.txt",
            std::process::id()
        ));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        path
    }

    #[test]
    fn loads_valid_wordlist_and_trims_whitespace() {
        let path = write_tmp("valid", "alpha\nbeta\n  gamma  \n\n");
        let wl = Wordlist::from_path(&path).unwrap();
        assert_eq!(wl.words, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn rejects_uppercase_entry() {
        let path = write_tmp("upper", "alpha\nBeta\ngamma\n");
        let err = Wordlist::from_path(&path).unwrap_err().to_string();
        assert!(err.contains("Beta"), "actual: {err}");
    }

    #[test]
    fn rejects_digit_entry() {
        let path = write_tmp("digit", "alpha\nbeta2\ngamma\n");
        let err = Wordlist::from_path(&path).unwrap_err().to_string();
        assert!(err.contains("beta2"), "actual: {err}");
    }

    #[test]
    fn rejects_duplicate_entry() {
        let path = write_tmp("dup", "alpha\nbeta\nalpha\n");
        let err = Wordlist::from_path(&path).unwrap_err().to_string();
        assert!(err.contains("alpha"), "actual: {err}");
        assert!(err.contains("more than once"), "actual: {err}");
    }

    #[test]
    fn rejects_empty_wordlist() {
        let path = write_tmp("empty", "\n\n  \n");
        let err = Wordlist::from_path(&path).unwrap_err().to_string();
        assert!(err.contains("empty"), "actual: {err}");
    }

    #[test]
    fn ascii_mode_rejects_diacritic() {
        let path = write_tmp("dia-ascii", "cafe\ncafé\n");
        let err = Wordlist::from_path(&path).unwrap_err().to_string();
        assert!(err.contains("café"), "actual: {err}");
    }

    #[test]
    fn unicode_mode_accepts_diacritics() {
        let path = write_tmp("dia-uni", "cafe\ncafé\nnaïve\nköln\n");
        let wl = Wordlist::from_path_with_mode(&path, Mode::UnicodeLowercase, false).unwrap();
        assert_eq!(wl.words, vec!["cafe", "café", "naïve", "köln"]);
    }

    #[test]
    fn unicode_mode_still_rejects_uppercase() {
        let path = write_tmp("uni-upper", "alpha\nBeta\n");
        let err = Wordlist::from_path_with_mode(&path, Mode::UnicodeLowercase, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Beta"), "actual: {err}");
    }

    #[test]
    fn unicode_mode_still_rejects_digits() {
        let path = write_tmp("uni-digit", "alpha\nbeta2\n");
        let err = Wordlist::from_path_with_mode(&path, Mode::UnicodeLowercase, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("beta2"), "actual: {err}");
    }

    #[test]
    fn unicode_mode_rejects_duplicates() {
        let path = write_tmp("uni-dup", "café\ncafé\n");
        let err = Wordlist::from_path_with_mode(&path, Mode::UnicodeLowercase, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("café"), "actual: {err}");
        assert!(err.contains("more than once"), "actual: {err}");
    }

    #[test]
    fn strip_combining_marks_normalises_accents() {
        assert_eq!(super::strip_combining_marks("café"), "cafe");
        assert_eq!(super::strip_combining_marks("naïve"), "naive");
        assert_eq!(super::strip_combining_marks("köln"), "koln");
        // Pure ASCII is a no-op.
        assert_eq!(super::strip_combining_marks("alpha"), "alpha");
    }

    #[test]
    fn strip_combining_marks_folds_common_ligatures() {
        assert_eq!(super::strip_combining_marks("cœur"), "coeur");
        assert_eq!(super::strip_combining_marks("æther"), "aether");
        assert_eq!(super::strip_combining_marks("groß"), "gross");
        assert_eq!(super::strip_combining_marks("bjørn"), "bjorn");
    }

    #[test]
    fn normalisation_lets_ascii_mode_accept_diacritics() {
        let path = write_tmp("norm-ascii", "cafe\ncafé\nnaïve\nköln\n");
        // `cafe` and `café` collide after normalisation; the first
        // occurrence wins (first-occurrence dedupe).
        let wl = Wordlist::from_path_with_mode(&path, Mode::AsciiLowercase, true).unwrap();
        assert_eq!(wl.words, vec!["cafe", "naive", "koln"]);
    }

    #[test]
    fn normalisation_drops_duplicates_silently() {
        let path = write_tmp("norm-dup", "cafe\ncafé\n");
        // `café` normalises to `cafe` which we already saw → drop.
        let wl = Wordlist::from_path_with_mode(&path, Mode::AsciiLowercase, true).unwrap();
        assert_eq!(wl.words, vec!["cafe"]);
    }

    #[test]
    fn normalisation_still_flags_non_diacritic_illegals() {
        let path = write_tmp("norm-uppercase", "alpha\nBeta\n");
        let err = Wordlist::from_path_with_mode(&path, Mode::AsciiLowercase, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Beta"), "actual: {err}");
    }
}
