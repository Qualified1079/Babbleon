//! Passphrase acquisition — interactive prompt and non-interactive
//! stdin paths.
//!
//! # Infrastructure module
//!
//! `babbleon init` and `babbleon unlock` need a passphrase from the
//! operator.  Two acquisition paths:
//!
//! - **Interactive** (default): read from the controlling TTY via
//!   `rpassword`.  Echoes nothing; cannot land in shell history.
//! - **Non-interactive** (via `--passphrase-stdin`): read the first
//!   line of stdin.  Trailing newline / carriage return stripped.
//!   This is the path CI scripts and integration tests use.
//!
//! Both paths return a [`Passphrase`] wrapper whose drop zeroizes
//! the bytes.  The plaintext passphrase string lives in memory only
//! for the duration of the [`Passphrase`]'s scope.
//!
//! # What this defeats
//!
//! Without the `Zeroizing` wrapper the operator's passphrase would
//! linger in the heap pool indefinitely (rule 11).  Without the
//! split between interactive and stdin paths, integration tests
//! couldn't exercise the unlock flow end-to-end without a TTY
//! emulator.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** post-drop heap-reuse leakage of the passphrase
//!   string.
//! - **Does NOT defeat:** a compromised TTY (keylogger,
//!   shoulder-surf).  Out of the vault's threat model.

use std::io::BufRead;

use zeroize::Zeroizing;

/// Operator passphrase.  Drops zeroize the underlying bytes.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    /// Construct from an already-owned string.
    #[must_use]
    pub fn from_string(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Borrow the passphrase as `&str` for the duration of `f`.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

/// Prompt the operator for a passphrase via the controlling TTY.
/// No echo.  The leading prompt text is written to stderr (so it
/// does not contaminate stdout in piped invocations).
///
/// # Errors
///
/// - Forwarded `rpassword` I/O errors when no TTY is present (e.g.
///   the CLI was invoked from a script without
///   `--passphrase-stdin`).
pub fn prompt_passphrase(label: &str) -> std::io::Result<Passphrase> {
    let p = rpassword::prompt_password(label)?;
    Ok(Passphrase::from_string(p))
}

/// Prompt twice and confirm the operator typed the same passphrase
/// both times.  Used by `babbleon init` so a typo at vault creation
/// does not leave the operator unable to unlock later.
///
/// # Errors
///
/// - Forwarded TTY errors from [`prompt_passphrase`].
/// - `io::ErrorKind::InvalidInput` when the two passphrases differ.
pub fn prompt_passphrase_confirmed(
    first_label: &str,
    second_label: &str,
) -> std::io::Result<Passphrase> {
    let a = prompt_passphrase(first_label)?;
    let b = prompt_passphrase(second_label)?;
    if a.expose() != b.expose() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "passphrases did not match",
        ));
    }
    Ok(a)
}

/// Read the first line of `reader` and return it as a passphrase.
/// Strips a single trailing `\n` and, if present, a preceding `\r`.
/// Used by the `--passphrase-stdin` path.
///
/// # Errors
///
/// - Forwarded `io::Read` errors.
/// - `io::ErrorKind::UnexpectedEof` if the reader is empty (no
///   passphrase to consume).
pub fn read_passphrase_from_reader<R: BufRead>(
    reader: &mut R,
) -> std::io::Result<Passphrase> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "no passphrase on stdin",
        ));
    }
    // Strip trailing newline + carriage return.  read_line preserves
    // the `\n`; on CRLF it also preserves the `\r`.
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    Ok(Passphrase::from_string(line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn passphrase_from_string_round_trips() {
        let p = Passphrase::from_string("hello".into());
        assert_eq!(p.expose(), "hello");
    }

    #[test]
    fn read_passphrase_from_reader_strips_newline() {
        let mut r = Cursor::new(b"correct horse\n");
        let p = read_passphrase_from_reader(&mut r).unwrap();
        assert_eq!(p.expose(), "correct horse");
    }

    #[test]
    fn read_passphrase_from_reader_strips_crlf() {
        let mut r = Cursor::new(b"correct horse\r\n");
        let p = read_passphrase_from_reader(&mut r).unwrap();
        assert_eq!(p.expose(), "correct horse");
    }

    #[test]
    fn read_passphrase_from_reader_accepts_no_newline_at_eof() {
        let mut r = Cursor::new(b"correct horse");
        let p = read_passphrase_from_reader(&mut r).unwrap();
        assert_eq!(p.expose(), "correct horse");
    }

    #[test]
    fn read_passphrase_from_reader_rejects_empty_input() {
        let mut r = Cursor::new(b"");
        let r = read_passphrase_from_reader(&mut r);
        assert!(r.is_err());
    }

    #[test]
    fn read_passphrase_from_reader_consumes_only_first_line() {
        let mut r = Cursor::new(b"first line\nsecond line\n");
        let p = read_passphrase_from_reader(&mut r).unwrap();
        assert_eq!(p.expose(), "first line");
    }
}
