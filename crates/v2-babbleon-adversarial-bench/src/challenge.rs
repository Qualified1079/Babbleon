//! Adversarial challenge definitions.
//!
//! # What this defeats
//!
//! Ad-hoc per-session benchmarks where the input the model was
//! given drifts between runs and the "did it crack it?" decision is
//! retroactively rationalised.  A `Challenge` is a frozen artifact
//! on disk: a name, a goal sentence, the Python source to scramble,
//! and a [`SuccessPredicate`] that mechanically grades the answer.
//! Two operators running the same file against the same scrambled
//! output must compute the same Pass / Fail outcome.
//!
//! # Mechanism
//!
//! Challenges live under `crates/v2-babbleon-adversarial-bench/
//! challenges/<name>.toml`.  Schema:
//!
//! ```toml
//! name = "auth-literal-string"
//! goal_description = "Find the value of x for which auth(x) returns True."
//! source = """
//! def auth(x):
//!     return x == \"hunter2\"
//! """
//!
//! [predicate]
//! kind = "exact-match"
//! expected = "hunter2"
//! ```
//!
//! `Challenge::from_toml_file` reads, parses, and validates in one
//! call.  Validation enforces non-empty `name`, non-empty `source`,
//! and (for `ExactMatch` / `CaseInsensitiveMatch`) non-empty
//! `expected` — empty-string predicates would Pass on every model
//! that emits a trimmed empty line, a degenerate "always cracked"
//! state we file as a validation error rather than a runtime
//! surprise.
//!
//! # Threat model boundaries
//!
//! - Defeats: bench drift between sessions.  Challenges are pinned
//!   files committed to the repo.
//! - Does NOT defeat: a challenge author who picks too easy or too
//!   hard a goal.  Goal-difficulty calibration is a meta-concern;
//!   the seed challenges in `challenges/` cover an escalating
//!   difficulty curve documented in this module's tests.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::{Error, Result};
use crate::success_predicate::SuccessPredicate;

/// A bench challenge.  See module docs for the on-disk TOML schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    /// Short kebab-case identifier, used as the row label in the
    /// summary table and as the filename stem.  Validated non-empty.
    pub name: String,
    /// One-sentence English statement of what the model must achieve.
    /// Surfaced verbatim in the prompt the adversary sees.
    pub goal_description: String,
    /// The Python source the harness scrambles before showing to the
    /// adversary.  Validated non-empty.
    pub source: String,
    /// The decision rule for whether the model's answer cracks the
    /// challenge.  Renamed to `predicate` on the wire so the TOML
    /// section header reads as a normal English word.
    #[serde(rename = "predicate")]
    pub success_predicate: SuccessPredicate,
}

impl Challenge {
    /// Read a challenge from a TOML file, parse it, and validate.
    ///
    /// # Errors
    ///
    /// - `Error::ReadChallenge` if `path` cannot be read.
    /// - `Error::ParseChallenge` if the file is not valid TOML or
    ///   does not deserialize to the schema.
    /// - `Error::ValidateChallenge` if a field fails semantic
    ///   validation (empty name, empty source, empty `expected`).
    pub fn from_toml_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read_to_string(path).map_err(|source| {
            Error::ReadChallenge {
                path: path.to_path_buf(),
                source,
            }
        })?;
        Self::from_toml_str(&bytes).map_err(|e| match e {
            // Re-wrap the "no path attached" parse / validate errors
            // with the path so the operator gets a usable diagnostic.
            Error::ParseChallenge { message, .. } => {
                Error::ParseChallenge {
                    path: path.to_path_buf(),
                    message,
                }
            }
            Error::ValidateChallenge { message, .. } => {
                Error::ValidateChallenge {
                    path: path.to_path_buf(),
                    message,
                }
            }
            other => other,
        })
    }

    /// Parse a challenge from a TOML byte string in memory.
    ///
    /// Used by `from_toml_file` and exposed for unit tests that
    /// embed their TOML inline.
    ///
    /// # Errors
    ///
    /// - `Error::ParseChallenge { path: "<inline>", .. }` on TOML
    ///   parse failure; the caller is expected to re-wrap with the
    ///   true path if reading from disk.
    /// - `Error::ValidateChallenge { path: "<inline>", .. }` on
    ///   semantic validation failure.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let parsed: Challenge = toml::from_str(s).map_err(|e| {
            Error::ParseChallenge {
                path: PathBuf::from("<inline>"),
                message: e.to_string(),
            }
        })?;
        parsed.validate()?;
        Ok(parsed)
    }

    /// Run semantic validation.  Called automatically by both
    /// loader entry points; exposed for tests and for downstream
    /// crates that construct `Challenge` in memory.
    ///
    /// # Errors
    ///
    /// `Error::ValidateChallenge` describing the first rule that
    /// the challenge violates.  Stops at first failure (no
    /// accumulation) so the diagnostic stays focused.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::ValidateChallenge {
                path: PathBuf::from("<inline>"),
                message: "name must not be empty".into(),
            });
        }
        if self.source.trim().is_empty() {
            return Err(Error::ValidateChallenge {
                path: PathBuf::from("<inline>"),
                message: "source must not be empty".into(),
            });
        }
        match &self.success_predicate {
            SuccessPredicate::ExactMatch { expected }
            | SuccessPredicate::CaseInsensitiveMatch { expected } => {
                if expected.is_empty() {
                    return Err(Error::ValidateChallenge {
                        path: PathBuf::from("<inline>"),
                        message:
                            "predicate.expected must not be empty (would Pass on any blank answer)"
                                .into(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Challenge;
    use crate::errors::Error;
    use crate::success_predicate::SuccessPredicate;

    fn sample_toml() -> &'static str {
        r#"
name = "auth-literal-string"
goal_description = "Find x such that auth(x) is True."
source = """
def auth(x):
    return x == \"hunter2\"
"""

[predicate]
kind = "exact-match"
expected = "hunter2"
"#
    }

    #[test]
    fn parses_and_validates_a_well_formed_challenge() {
        let c = Challenge::from_toml_str(sample_toml()).unwrap();
        assert_eq!(c.name, "auth-literal-string");
        assert!(c.goal_description.starts_with("Find x"));
        assert!(c.source.contains("hunter2"));
        match c.success_predicate {
            SuccessPredicate::ExactMatch { expected } => {
                assert_eq!(expected, "hunter2");
            }
            SuccessPredicate::CaseInsensitiveMatch { .. } => {
                panic!("expected ExactMatch, got CaseInsensitiveMatch")
            }
        }
    }

    #[test]
    fn rejects_empty_name() {
        let toml = r#"
name = ""
goal_description = "x"
source = "def f(): pass"

[predicate]
kind = "exact-match"
expected = "y"
"#;
        let err = Challenge::from_toml_str(toml).unwrap_err();
        match err {
            Error::ValidateChallenge { message, .. } => {
                assert!(message.contains("name"));
            }
            other => panic!("expected ValidateChallenge, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_source() {
        let toml = r#"
name = "x"
goal_description = "x"
source = ""

[predicate]
kind = "exact-match"
expected = "y"
"#;
        let err = Challenge::from_toml_str(toml).unwrap_err();
        match err {
            Error::ValidateChallenge { message, .. } => {
                assert!(message.contains("source"));
            }
            other => panic!("expected ValidateChallenge, got {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_expected_on_exact_match() {
        let toml = r#"
name = "x"
goal_description = "x"
source = "def f(): pass"

[predicate]
kind = "exact-match"
expected = ""
"#;
        let err = Challenge::from_toml_str(toml).unwrap_err();
        match err {
            Error::ValidateChallenge { message, .. } => {
                assert!(message.contains("expected"));
            }
            other => panic!("expected ValidateChallenge, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_toml() {
        let err = Challenge::from_toml_str("this is not toml [[[").unwrap_err();
        match err {
            Error::ParseChallenge { .. } => {}
            other => panic!("expected ParseChallenge, got {other:?}"),
        }
    }

    #[test]
    fn from_toml_file_attaches_path_to_read_error() {
        let err =
            Challenge::from_toml_file("/nonexistent/path/to/challenge.toml")
                .unwrap_err();
        match err {
            Error::ReadChallenge { path, .. } => {
                assert_eq!(
                    path.as_os_str(),
                    "/nonexistent/path/to/challenge.toml"
                );
            }
            other => panic!("expected ReadChallenge, got {other:?}"),
        }
    }

    #[test]
    fn from_toml_file_attaches_path_to_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "not toml [[[").unwrap();
        let err = Challenge::from_toml_file(&path).unwrap_err();
        match err {
            Error::ParseChallenge { path: p, .. } => {
                assert_eq!(p, path);
            }
            other => panic!("expected ParseChallenge, got {other:?}"),
        }
    }

    #[test]
    fn from_toml_file_attaches_path_to_validate_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty-name.toml");
        let toml = r#"
name = ""
goal_description = "x"
source = "def f(): pass"

[predicate]
kind = "exact-match"
expected = "y"
"#;
        std::fs::write(&path, toml).unwrap();
        let err = Challenge::from_toml_file(&path).unwrap_err();
        match err {
            Error::ValidateChallenge { path: p, .. } => {
                assert_eq!(p, path);
            }
            other => panic!("expected ValidateChallenge, got {other:?}"),
        }
    }
}
