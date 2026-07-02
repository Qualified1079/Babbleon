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
        Self::from_path_with_mode(path, Mode::AsciiLowercase)
    }

    /// Load and validate a wordlist file in the given mode.
    pub fn from_path_with_mode(path: &Path, mode: Mode) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read wordlist {}", path.display()))?;
        let words: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        validate(&words, mode)?;
        Ok(Self { words })
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }
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
        let wl = Wordlist::from_path_with_mode(&path, Mode::UnicodeLowercase).unwrap();
        assert_eq!(wl.words, vec!["cafe", "café", "naïve", "köln"]);
    }

    #[test]
    fn unicode_mode_still_rejects_uppercase() {
        let path = write_tmp("uni-upper", "alpha\nBeta\n");
        let err = Wordlist::from_path_with_mode(&path, Mode::UnicodeLowercase)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Beta"), "actual: {err}");
    }

    #[test]
    fn unicode_mode_still_rejects_digits() {
        let path = write_tmp("uni-digit", "alpha\nbeta2\n");
        let err = Wordlist::from_path_with_mode(&path, Mode::UnicodeLowercase)
            .unwrap_err()
            .to_string();
        assert!(err.contains("beta2"), "actual: {err}");
    }

    #[test]
    fn unicode_mode_rejects_duplicates() {
        let path = write_tmp("uni-dup", "café\ncafé\n");
        let err = Wordlist::from_path_with_mode(&path, Mode::UnicodeLowercase)
            .unwrap_err()
            .to_string();
        assert!(err.contains("café"), "actual: {err}");
        assert!(err.contains("more than once"), "actual: {err}");
    }
}
