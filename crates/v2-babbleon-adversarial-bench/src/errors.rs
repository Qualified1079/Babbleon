//! Error type for the bench harness.
//!
//! # Infrastructure module
//!
//! No specific attack is defeated here.  Per security-baseline
//! rule 13 every `Error` variant carries only operator-diagnostic
//! context (file paths the operator pointed at, validation
//! messages naming which field rejected); no secret bytes appear
//! anywhere in this enum.  The bench has no secrets in its address
//! space by design.

use std::path::PathBuf;

use thiserror::Error;

/// Crate-wide `Result` alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Operator-diagnostic error produced by the bench harness.
#[derive(Debug, Error)]
pub enum Error {
    /// Reading a challenge file from disk failed.
    #[error("read challenge file {path}: {source}")]
    ReadChallenge {
        /// The path the operator pointed at.  Public input; safe to
        /// surface verbatim.
        path: PathBuf,
        /// Underlying `io::Error`.
        source: std::io::Error,
    },

    /// TOML parse failure on a challenge file.
    #[error("parse challenge file {path} as TOML: {message}")]
    ParseChallenge {
        /// The path the operator pointed at.
        path: PathBuf,
        /// The parser's diagnostic, copied as a `String` so the TOML
        /// error type does not appear in our public API surface.
        message: String,
    },

    /// A challenge field failed semantic validation (empty name,
    /// empty source, unsupported predicate variant, etc.).
    #[error("validate challenge file {path}: {message}")]
    ValidateChallenge {
        /// The path the operator pointed at.
        path: PathBuf,
        /// What the validator rejected.
        message: String,
    },

    /// A scramble pipeline failure surfaced from the preprocessor
    /// crate.  The inner message is the preprocessor `Error`'s
    /// `Display`, copied as a `String` so the preprocessor's
    /// `Error` type does not leak into our public API.
    #[error("scramble pipeline: {message}")]
    Scramble {
        /// Why the scramble failed (`WhitespaceCompoundCollision`,
        /// `KeywordCompoundCollision`, etc.).  Public; no secret.
        message: String,
    },

    /// JSON serialization / deserialization of a `RunRecord` or
    /// summary payload failed.  Wraps `serde_json::Error`'s message
    /// as a `String`.
    #[error("serialize / deserialize run record: {message}")]
    SerdeJson {
        /// Underlying parser diagnostic.
        message: String,
    },
}

impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Error::SerdeJson {
            message: source.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Result};

    #[test]
    fn error_display_contains_path_for_read_failure() {
        let e = Error::ReadChallenge {
            path: std::path::PathBuf::from("/tmp/missing.toml"),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };
        let s = e.to_string();
        assert!(s.contains("/tmp/missing.toml"));
    }

    #[test]
    fn error_display_contains_message_for_validate_failure() {
        let e = Error::ValidateChallenge {
            path: std::path::PathBuf::from("/tmp/x.toml"),
            message: "name must not be empty".into(),
        };
        let s = e.to_string();
        assert!(s.contains("name must not be empty"));
        assert!(s.contains("/tmp/x.toml"));
    }

    #[test]
    fn result_alias_is_usable() {
        // Demonstrates the alias compiles into a real Result<T, Error>.
        // The branchful body avoids `clippy::unnecessary_wraps` on a
        // function that always returns Ok.
        fn ok_or(flag: bool) -> Result<i32> {
            if flag {
                Ok(42)
            } else {
                Err(Error::SerdeJson {
                    message: "unused".into(),
                })
            }
        }
        assert_eq!(ok_or(true).unwrap(), 42);
        assert!(ok_or(false).is_err());
    }

    #[test]
    fn from_serde_json_error_yields_serdejson_variant() {
        // Force a parse failure to construct a serde_json::Error.
        let parsed: std::result::Result<i32, _> =
            serde_json::from_str("not-json");
        let err = parsed.unwrap_err();
        let our_err: Error = err.into();
        match our_err {
            Error::SerdeJson { message } => assert!(!message.is_empty()),
            other => panic!("expected SerdeJson, got {other:?}"),
        }
    }
}
