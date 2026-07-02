//! Wordlist loader with baseline invariants.
//!
//! The Babbleon baseline wordlist ships as one lowercase-ASCII word
//! per line.  The security posture depends on those invariants (see
//! `crates/v2-babbleon-core/src/wordlist.rs` for the runtime loader
//! that this analysis mirrors).  A filter that emits a subset of the
//! baseline must preserve them; the same validation code runs on
//! load so we cannot analyse something that would fail the runtime
//! loader.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// A loaded, validated Babbleon-baseline wordlist.
#[derive(Debug)]
pub struct Wordlist {
    pub words: Vec<String>,
}

impl Wordlist {
    /// Load and validate a wordlist file.
    ///
    /// Every entry must be non-empty, unique, and match `[a-z]+`.
    /// A malformed file returns an error naming the first offender.
    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read wordlist {}", path.display()))?;
        let words: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect();
        validate(&words)?;
        Ok(Self { words })
    }

    pub fn len(&self) -> usize {
        self.words.len()
    }
}

fn validate(words: &[String]) -> Result<()> {
    if words.is_empty() {
        bail!("wordlist is empty");
    }
    let mut seen: HashSet<&str> = HashSet::with_capacity(words.len());
    for w in words {
        if w.is_empty() {
            bail!("wordlist entry is empty");
        }
        if !w.chars().all(|c| c.is_ascii_lowercase()) {
            bail!("wordlist entry {:?} contains non-[a-z] characters", w);
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
}
