//! Adversary trait + subprocess plugin.
//!
//! # What this defeats
//!
//! Hand-driving the bench: copy the prompt to a chat window, paste
//! the response back, run `babbleon-bench score`.  Tractable at
//! N=1 per cell; not tractable at N=10 per cell across 5
//! challenges × 4 configs × 3 adversaries.  The [`Adversary`]
//! trait + [`run_attempts`] driver replace the manual loop with
//! one subcommand invocation per bench cell.
//!
//! # Mechanism
//!
//! - [`Adversary::query`] is the single method an adversary
//!   implementor wires: given a prompt string, produce one
//!   response string.
//! - [`SubprocessAdversary`] is the only built-in implementation.
//!   It runs a configurable command (e.g.
//!   `["curl", "-sf", "-X", "POST", "https://api.anthropic.com/v1/messages", ...]`,
//!   or `["claude-cli", "--quiet"]`, or `["ollama", "run",
//!   "llama3"]`), writes the prompt to the child's stdin, reads
//!   stdout to EOF, and returns it.  Stderr is captured for
//!   error reporting.  Same trust model as `babbleon-bench score`
//!   — no secrets, no privileges, the operator controls the
//!   command line.
//! - The HTTP plugins listed in the HANDOFF spec (Claude API,
//!   `OpenAI` API) are NOT built-in.  Operators wire them by
//!   pointing `SubprocessAdversary` at the provider's official
//!   CLI (or at a shell script that calls `curl`).  This keeps
//!   the bench's dependency graph zero-network: no `reqwest`,
//!   no provider SDK, no API-key handling in our address space.
//!
//! # Trust placement
//!
//! Identical to the rest of the bench: no privileges, no daemon
//! round-trip, no per-host secret.  The subprocess inherits the
//! operator's environment (which may carry `ANTHROPIC_API_KEY`,
//! `OPENAI_API_KEY`, etc.) — that's the operator's call, not
//! the bench's.  We do NOT scrub or filter the child's
//! environment; the operator who invokes
//! `babbleon-bench run --adversary-cmd "..."` knows what
//! credentials they are exposing.
//!
//! # Threat model boundaries
//!
//! - Defeats: manual hand-driving of bench cells.
//! - Does NOT defeat: an adversary command that loops forever
//!   (no per-call timeout — caller's call), prints chatty
//!   markdown that confuses the JSON extractor (scoring already
//!   handles this), or hangs reading stdin (the driver closes
//!   stdin after writing the prompt).

use std::io::Write;
use std::process::{Command, Stdio};

use crate::challenge::Challenge;
use crate::errors::{Error, Result};
use crate::layer_config::LayerConfig;
use crate::prompt::build_prompt;
use crate::run_record::RunRecord;
use crate::scoring::score;
use crate::scramble_pipeline::apply_layers;

/// One adversary's query interface.
///
/// `query` takes a prompt and returns one response.  Errors are
/// adversary-side problems (subprocess spawn failure, non-zero
/// exit, I/O error) — they are not bench scoring outcomes.  A
/// model that returns garbage scores as `FormatError`; a model
/// whose CLI binary cannot be spawned errors out of [`query`].
pub trait Adversary {
    /// Issue one query to the adversary.
    ///
    /// # Errors
    ///
    /// Implementation-defined; see each impl's docs.
    fn query(&self, prompt: &str) -> Result<String>;

    /// Operator-supplied label recorded in every [`RunRecord`].
    /// Used by the summary table to group results by adversary.
    fn label(&self) -> &str;
}

/// Adversary that runs an external subprocess.  Writes the prompt
/// to the child's stdin; reads stdout to EOF; returns it.
///
/// # Configuration
///
/// - `command`: the program + argv to spawn.  E.g. `["curl",
///   "-sf", "-X", "POST", "..."]`.  Empty `command` is rejected
///   by [`SubprocessAdversary::new`].
/// - `label`: free-text identifier recorded on each `RunRecord`.
///   By convention `"<provider>-<model>@<run-date>"`.
///
/// # Errors from [`Adversary::query`]
///
/// - [`Error::AdversarySpawn`] if the subprocess cannot be
///   launched (binary not on `$PATH`, permission denied).
/// - [`Error::AdversaryNonZeroExit`] if the subprocess exited
///   with a non-zero status.  Stderr is captured and included
///   in the error message (truncated to avoid log spam).
/// - [`Error::AdversaryIo`] for stdin write / stdout read I/O
///   failures (broken pipe, etc.).
///
/// # No per-call timeout
///
/// The driver does not impose a wall-clock timeout on the
/// subprocess.  An adversary that hangs forever blocks the bench
/// indefinitely.  Operators who want a timeout should wrap the
/// command in `timeout(1)` (`["timeout", "60s", "curl", ...]`).
/// The bench is a single-tenant benchmark tool; the timeout
/// policy lives at the operator's command-line level, not in
/// the harness.
#[derive(Debug)]
pub struct SubprocessAdversary {
    command: Vec<String>,
    label: String,
    stderr_capture_limit: usize,
}

impl SubprocessAdversary {
    /// Construct a `SubprocessAdversary`.
    ///
    /// # Errors
    ///
    /// `Error::AdversaryConfig` if `command` is empty (no
    /// executable to spawn).
    pub fn new(
        command: Vec<String>,
        label: impl Into<String>,
    ) -> Result<Self> {
        if command.is_empty() {
            return Err(Error::AdversaryConfig {
                message: "command must not be empty".into(),
            });
        }
        Ok(Self {
            command,
            label: label.into(),
            stderr_capture_limit: 4096,
        })
    }
}

impl Adversary for SubprocessAdversary {
    fn query(&self, prompt: &str) -> Result<String> {
        let mut cmd = Command::new(&self.command[0]);
        cmd.args(&self.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child =
            cmd.spawn().map_err(|source| Error::AdversarySpawn {
                program: self.command[0].clone(),
                message: source.to_string(),
            })?;
        {
            let stdin = child.stdin.as_mut().ok_or_else(|| {
                Error::AdversaryIo {
                    message: "child stdin handle missing".into(),
                }
            })?;
            stdin.write_all(prompt.as_bytes()).map_err(|source| {
                Error::AdversaryIo {
                    message: format!("write prompt to stdin: {source}"),
                }
            })?;
        }
        drop(child.stdin.take());
        let output = child.wait_with_output().map_err(|source| {
            Error::AdversaryIo {
                message: format!("wait_with_output: {source}"),
            }
        })?;
        if !output.status.success() {
            let stderr = truncate(
                &String::from_utf8_lossy(&output.stderr),
                self.stderr_capture_limit,
            );
            return Err(Error::AdversaryNonZeroExit {
                program: self.command[0].clone(),
                exit: output.status.code(),
                stderr,
            });
        }
        String::from_utf8(output.stdout).map_err(|source| {
            Error::AdversaryIo {
                message: format!(
                    "child stdout was not UTF-8: {source}",
                ),
            }
        })
    }

    fn label(&self) -> &str {
        &self.label
    }
}

/// Truncate `s` to at most `limit` bytes, appending an ellipsis
/// note if the string was truncated.  Used for stderr capture to
/// keep error messages within a reasonable log line width.
fn truncate(s: &str, limit: usize) -> String {
    if s.len() <= limit {
        s.to_string()
    } else {
        let cut = floor_char_boundary(s, limit);
        format!("{}…(truncated, total {} bytes)", &s[..cut], s.len())
    }
}

/// Round `idx` down to the nearest UTF-8 char boundary in `s`.
/// Stable since Rust 1.80 has `str::floor_char_boundary` but
/// that's behind a feature gate; this is the cross-version
/// helper.
fn floor_char_boundary(s: &str, idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    let mut i = idx;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Run `attempts` adversary queries against one `(challenge,
/// layer_config)` cell, scoring each and returning the resulting
/// `RunRecord`s.
///
/// Adversary errors abort the loop and bubble up via `Result` —
/// a subprocess that fails to spawn is an operator-environment
/// problem the bench cannot grade.  In contrast, an adversary
/// that returns chatty / unparseable / refused output continues
/// the loop with the appropriate `ScoreOutcome`.
///
/// # Errors
///
/// - `Error::Scramble` if the layer-config'd scramble fails
///   (collision or preprocessor error).
/// - Any adversary-side error from [`Adversary::query`].
pub fn run_attempts<A: Adversary>(
    challenge: &Challenge,
    config: LayerConfig,
    adversary: &A,
    attempts: u32,
) -> Result<Vec<RunRecord>> {
    let scrambled = apply_layers(&challenge.source, config)?;
    let prompt = build_prompt(challenge, config, &scrambled);
    let mut out = Vec::with_capacity(attempts as usize);
    for i in 0..attempts {
        let response = adversary.query(&prompt)?;
        let outcome = score(&challenge.success_predicate, &response);
        out.push(RunRecord::new(
            challenge.name.clone(),
            config,
            adversary.label(),
            i,
            outcome,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        floor_char_boundary, run_attempts, truncate, Adversary,
        SubprocessAdversary,
    };
    use crate::challenge::Challenge;
    use crate::errors::Error;
    use crate::layer_config::LayerConfig;
    use crate::scoring::ScoreOutcome;
    use crate::success_predicate::SuccessPredicate;

    /// In-process Adversary that returns a canned answer.  Lets
    /// the `run_attempts` driver be tested without a subprocess.
    struct CannedAdversary {
        canned: String,
        label: String,
    }
    impl Adversary for CannedAdversary {
        fn query(&self, _prompt: &str) -> crate::errors::Result<String> {
            Ok(self.canned.clone())
        }
        fn label(&self) -> &str {
            &self.label
        }
    }

    fn fixture_challenge() -> Challenge {
        Challenge {
            name: "x".into(),
            goal_description: "find x".into(),
            source: "def auth(x): return x == \"hunter2\"\n".into(),
            success_predicate: SuccessPredicate::exact_match("hunter2"),
        }
    }

    #[test]
    fn run_attempts_records_each_outcome() {
        let adv = CannedAdversary {
            canned: r#"{"answer": "hunter2"}"#.into(),
            label: "canned-pass".into(),
        };
        let recs = run_attempts(
            &fixture_challenge(),
            LayerConfig::l2_plus_l3(),
            &adv,
            3,
        )
        .unwrap();
        assert_eq!(recs.len(), 3);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(
                r.attempt_index,
                u32::try_from(i).unwrap(),
            );
            assert_eq!(r.outcome, ScoreOutcome::Pass);
            assert_eq!(r.adversary_label, "canned-pass");
            assert_eq!(r.challenge_name, "x");
        }
    }

    #[test]
    fn run_attempts_handles_mixed_outcomes_from_dynamic_adversary() {
        // An adversary whose response varies per call; uses a
        // shared Cell to round-robin between three canned answers.
        struct VaryingAdversary {
            answers: Vec<String>,
            counter: std::cell::Cell<usize>,
            label: String,
        }
        impl Adversary for VaryingAdversary {
            fn query(
                &self,
                _prompt: &str,
            ) -> crate::errors::Result<String> {
                let i = self.counter.get();
                self.counter.set(i + 1);
                Ok(self.answers[i % self.answers.len()].clone())
            }
            fn label(&self) -> &str {
                &self.label
            }
        }
        let adv = VaryingAdversary {
            answers: vec![
                r#"{"answer": "hunter2"}"#.into(),       // pass
                r#"{"answer": "rabbit"}"#.into(),        // fail
                "chatty unstructured response".into(),   // format-error
            ],
            counter: std::cell::Cell::new(0),
            label: "varying".into(),
        };
        let recs = run_attempts(
            &fixture_challenge(),
            LayerConfig::l3_only(),
            &adv,
            3,
        )
        .unwrap();
        assert_eq!(recs[0].outcome, ScoreOutcome::Pass);
        assert_eq!(recs[1].outcome, ScoreOutcome::Fail);
        assert_eq!(recs[2].outcome, ScoreOutcome::FormatError);
    }

    #[test]
    fn empty_command_is_rejected() {
        let err = SubprocessAdversary::new(vec![], "x").unwrap_err();
        match err {
            Error::AdversaryConfig { message } => {
                assert!(message.contains("empty"));
            }
            other => panic!("expected AdversaryConfig, got {other:?}"),
        }
    }

    #[test]
    fn subprocess_adversary_runs_cat_as_echo() {
        // `cat` writes stdin to stdout — a trivial echo adversary.
        // The "model output" is the prompt itself, which contains
        // "find x" but no JSON; expect FormatError.
        let adv =
            SubprocessAdversary::new(vec!["cat".into()], "cat-echo")
                .unwrap();
        let response = adv.query("hello world").unwrap();
        assert_eq!(response, "hello world");
    }

    #[test]
    fn subprocess_adversary_propagates_non_zero_exit() {
        let adv = SubprocessAdversary::new(
            vec!["false".into()],
            "always-fails",
        )
        .unwrap();
        let err = adv.query("any prompt").unwrap_err();
        match err {
            Error::AdversaryNonZeroExit { program, exit, .. } => {
                assert_eq!(program, "false");
                // `false` exits 1 on every POSIX system.
                assert_eq!(exit, Some(1));
            }
            other => panic!("expected AdversaryNonZeroExit, got {other:?}"),
        }
    }

    #[test]
    fn subprocess_adversary_reports_unknown_program() {
        let adv = SubprocessAdversary::new(
            vec!["this-binary-does-not-exist-anywhere".into()],
            "missing",
        )
        .unwrap();
        let err = adv.query("any prompt").unwrap_err();
        match err {
            Error::AdversarySpawn { program, .. } => {
                assert_eq!(
                    program,
                    "this-binary-does-not-exist-anywhere",
                );
            }
            other => panic!("expected AdversarySpawn, got {other:?}"),
        }
    }

    #[test]
    fn subprocess_adversary_drives_run_attempts_end_to_end() {
        // `sh -c 'printf {"answer": "hunter2"}'` produces a JSON
        // answer regardless of the prompt.  Verifies the trait
        // boundary plus the scoring loop in one test against a
        // real subprocess.
        let adv = SubprocessAdversary::new(
            vec![
                "sh".into(),
                "-c".into(),
                "cat > /dev/null; printf '%s' '{\"answer\": \"hunter2\"}'"
                    .into(),
            ],
            "sh-echo-hunter2",
        )
        .unwrap();
        let recs = run_attempts(
            &fixture_challenge(),
            LayerConfig::l2_plus_l3(),
            &adv,
            2,
        )
        .unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].outcome, ScoreOutcome::Pass);
        assert_eq!(recs[1].outcome, ScoreOutcome::Pass);
    }

    #[test]
    fn truncate_leaves_short_strings_alone() {
        assert_eq!(truncate("hi", 100), "hi");
    }

    #[test]
    fn truncate_trims_long_strings_with_ellipsis_note() {
        let s = "a".repeat(200);
        let out = truncate(&s, 50);
        assert!(out.starts_with(&"a".repeat(50)));
        assert!(out.contains("truncated"));
        assert!(out.contains("200"));
    }

    #[test]
    fn truncate_respects_utf8_char_boundary() {
        // "é" is two UTF-8 bytes (0xC3 0xA9).  Cutting at byte 1
        // would split it.  The helper must back up to a boundary.
        let s = "x".to_string() + &"é".repeat(50);
        let out = truncate(&s, 2);
        // Out should still be valid UTF-8 (which String guarantees);
        // assert via successful from_utf8 round-trip.
        assert!(out.starts_with('x'));
    }

    #[test]
    fn floor_char_boundary_at_or_beyond_end_returns_len() {
        let s = "hello";
        assert_eq!(floor_char_boundary(s, 5), 5);
        assert_eq!(floor_char_boundary(s, 10), 5);
    }
}
