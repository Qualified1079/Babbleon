//! Spawn `python3 -` and feed it the unscrambled source via `pipe(2)`.
//!
//! # What this defeats
//!
//! Snapshot attacks between unscramble and exec.  If the shim wrote
//! the unscrambled source to a tempfile or `/dev/shm`, an attacker
//! with read access to that location during the window between
//! file-write and `python3` consumption recovers the plaintext.
//! Piping over a kernel pipe `(2)` instead keeps the bytes in
//! kernel-managed memory only, accessible only to the two endpoints
//! of the pipe.
//!
//! # Mechanism
//!
//! 1. `Command::new(python_bin).arg("-").stdin(piped)`.  Pass `-`
//!    to python so it reads source from stdin (the kernel pipe).
//! 2. `cmd.args(forward_args)` — forward every argv beyond the
//!    script path to python verbatim.  Operator's `babbleon-python
//!    foo.py bar baz` reaches python as `python3 - bar baz`.
//! 3. Spawn.  `stdout` / `stderr` inherit so script output / tracebacks
//!    reach the operator's terminal.
//! 4. `child.stdin.write_all(source)` then drop stdin (sends EOF).
//! 5. `child.wait()`; propagate the child's exit status as our own.
//!
//! `Command` clears the close-on-exec flag for the piped stdin fd
//! by default; the unscrambled source never escapes the parent
//! process via an unrelated child's fd table.

use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{anyhow, Context, Result};

/// Spawn `python_bin -`, feed `source` to its stdin, wait, return
/// the child's exit status.
///
/// `forward_args` are the trailing argv pieces beyond the script
/// path — they are passed verbatim to python after the `-` sentinel.
///
/// # Errors
///
/// - Spawn failure (interpreter not on `$PATH`, executable missing).
/// - I/O failure writing source bytes to the child's stdin (broken
///   pipe, kernel out-of-memory).
/// - Wait failure (child reaped by signal handler, EINTR loop
///   unwound by the OS).
pub fn run(
    python_bin: &Path,
    forward_args: &[String],
    source: &str,
) -> Result<ExitStatus> {
    let mut cmd = Command::new(python_bin);
    cmd.arg("-");
    for arg in forward_args {
        cmd.arg(arg);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn().with_context(|| {
        format!("spawn {}", python_bin.display())
    })?;

    {
        // Scoped take: `stdin` is dropped at the end of this block,
        // sending EOF to the child.  The wait below blocks until
        // python exits.
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("python3 stdin pipe missing post-spawn"))?;
        stdin
            .write_all(source.as_bytes())
            .context("write unscrambled source to python stdin")?;
    }

    let status = child.wait().context("wait on python child")?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::run;
    use std::path::PathBuf;

    fn python_bin() -> PathBuf {
        PathBuf::from("/usr/bin/python3")
    }

    fn find_python() -> Option<PathBuf> {
        // CI may have python at /usr/local/bin/python3 (containers).
        // Try the conventional locations and skip the test if none
        // exists; the shim's real-deployment dispatch via $PATH is
        // exercised in the integration tests.
        for p in [
            "/usr/bin/python3",
            "/usr/local/bin/python3",
            "/opt/homebrew/bin/python3",
        ] {
            let pb = PathBuf::from(p);
            if pb.exists() {
                return Some(pb);
            }
        }
        None
    }

    #[test]
    fn run_passes_source_to_python_and_returns_exit_status() {
        let Some(py) = find_python() else {
            return;
        };
        // `import sys; sys.exit(7)` — confirms python receives our
        // source via stdin and the shim propagates the exit code.
        let source = "import sys\nsys.exit(7)\n";
        let status = run(&py, &[], source).unwrap();
        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn run_zero_exit_for_successful_script() {
        let Some(py) = find_python() else {
            eprintln!("skipping: no python3 binary on conventional paths");
            return;
        };
        let status = run(&py, &[], "x = 1\n").unwrap();
        assert!(status.success());
    }

    #[test]
    fn run_propagates_argv_to_python() {
        let Some(py) = find_python() else {
            eprintln!("skipping: no python3 binary on conventional paths");
            return;
        };
        // python3 - --has-arg
        // Exits 2 if --has-arg is absent from sys.argv.
        let source = r#"import sys
sys.exit(0 if "--has-arg" in sys.argv else 2)
"#;
        let status = run(&py, &["--has-arg".to_string()], source).unwrap();
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn run_returns_error_for_missing_interpreter() {
        let bogus = PathBuf::from("/no/such/python3");
        let r = run(&bogus, &[], "x = 1\n");
        assert!(r.is_err());
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("spawn"), "{msg}");
    }

    // Suppress the unused warning when no python is found at all —
    // some sandboxes ship without python; the runtime test skips,
    // but unused-imports inside the suppressed `super::run` would
    // not be reported because the function is still referenced.
    #[test]
    fn _placeholder_python_bin_referenced() {
        let _ = python_bin();
    }
}
