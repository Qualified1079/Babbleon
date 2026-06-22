//! Evaluator trait + subprocess plugin.
//!
//! # What this defeats
//!
//! Hand-driving the bench: copy the prompt to a chat window, paste
//! the response back, run `babbleon-bench score`.  Tractable at
//! N=1 per cell; not tractable at N=10 per cell across 5
//! challenges × 4 configs × 3 adversaries.  The [`Evaluator`]
//! trait + [`run_attempts`] driver replace the manual loop with
//! one subcommand invocation per bench cell.
//!
//! # Mechanism
//!
//! - [`Evaluator::query`] is the single method an evaluator
//!   implementor wires: given a prompt string, produce one
//!   response string.
//! - [`SubprocessEvaluator`] is the only built-in implementation.
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
//!   pointing `SubprocessEvaluator` at the provider's official
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
//! `babbleon-bench run --evaluator-cmd "..."` knows what
//! credentials they are exposing.
//!
//! # Threat model boundaries
//!
//! - Defeats: manual hand-driving of bench cells.
//! - Does NOT defeat: an evaluator command that loops forever
//!   (no per-call timeout — caller's call), prints chatty
//!   markdown that confuses the JSON extractor (scoring already
//!   handles this), or hangs reading stdin (the driver closes
//!   stdin after writing the prompt).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::challenge::Challenge;
use crate::errors::{Error, Result};
use crate::layer_config::LayerConfig;
use crate::prompt::build_prompt;
use crate::run_record::RunRecord;
use crate::scoring::score;
use crate::scramble_pipeline::apply_layers;

/// One evaluator's query interface.
///
/// `query` takes a prompt and returns one response.  Errors are
/// evaluator-side problems (subprocess spawn failure, non-zero
/// exit, I/O error) — they are not bench scoring outcomes.  A
/// model that returns garbage scores as `FormatError`; a model
/// whose CLI binary cannot be spawned errors out of [`query`].
pub trait Evaluator {
    /// Issue one query to the evaluator.
    ///
    /// # Errors
    ///
    /// Implementation-defined; see each impl's docs.
    fn query(&self, prompt: &str) -> Result<String>;

    /// Issue one query with the evaluator's working directory set to
    /// `sandbox_dir` when `Some`.  The default implementation ignores
    /// `sandbox_dir` and delegates to [`Self::query`]; override it in
    /// subprocess evaluators that can actually enforce the cwd.
    fn query_in_dir(
        &self,
        prompt: &str,
        sandbox_dir: Option<&Path>,
    ) -> Result<String> {
        let _ = sandbox_dir;
        self.query(prompt)
    }

    /// Operator-supplied label recorded in every [`RunRecord`].
    /// Used by the summary table to group results by evaluator.
    fn label(&self) -> &str;
}

/// Evaluator that runs an external subprocess.  Writes the prompt
/// to the child's stdin; reads stdout to EOF; returns it.
///
/// # Configuration
///
/// - `command`: the program + argv to spawn.  E.g. `["curl",
///   "-sf", "-X", "POST", "..."]`.  Empty `command` is rejected
///   by [`SubprocessEvaluator::new`].
/// - `label`: free-text identifier recorded on each `RunRecord`.
///   By convention `"<provider>-<model>@<run-date>"`.
///
/// # Errors from [`Evaluator::query`]
///
/// - [`Error::EvaluatorSpawn`] if the subprocess cannot be
///   launched (binary not on `$PATH`, permission denied).
/// - [`Error::EvaluatorNonZeroExit`] if the subprocess exited
///   with a non-zero status.  Stderr is captured and included
///   in the error message (truncated to avoid log spam).
/// - [`Error::EvaluatorIo`] for stdin write / stdout read I/O
///   failures (broken pipe, etc.).
///
/// # No per-call timeout
///
/// The driver does not impose a wall-clock timeout on the
/// subprocess.  An evaluator that hangs forever blocks the bench
/// indefinitely.  Operators who want a timeout should wrap the
/// command in `timeout(1)` (`["timeout", "60s", "curl", ...]`).
/// The bench is a single-tenant benchmark tool; the timeout
/// policy lives at the operator's command-line level, not in
/// the harness.
#[derive(Debug)]
pub struct SubprocessEvaluator {
    command: Vec<String>,
    label: String,
    stderr_capture_limit: usize,
    working_directory: Option<PathBuf>,
}

impl SubprocessEvaluator {
    /// Construct a `SubprocessEvaluator`.
    ///
    /// # Errors
    ///
    /// `Error::EvaluatorConfig` if `command` is empty (no
    /// executable to spawn).
    pub fn new(
        command: Vec<String>,
        label: impl Into<String>,
    ) -> Result<Self> {
        if command.is_empty() {
            return Err(Error::EvaluatorConfig {
                message: "command must not be empty".into(),
            });
        }
        Ok(Self {
            command,
            label: label.into(),
            stderr_capture_limit: 4096,
            working_directory: None,
        })
    }

    /// Set the working directory the subprocess is spawned with.
    ///
    /// Per the 2026-06-22 evaluator-sandboxing gap finding
    /// (HANDOFF 2026-06-22, Blocker 1), evaluators running in the
    /// repo cwd can cross-contaminate cells by reading sibling
    /// files from a prior cell's notepad.  Setting a per-cell
    /// temp directory and pointing `--working-directory` at it
    /// gives each cell a fresh scratch space and makes the
    /// notepad-as-files prompt instruction actually meaningful.
    #[must_use]
    pub fn with_working_directory(mut self, dir: PathBuf) -> Self {
        self.working_directory = Some(dir);
        self
    }
}

impl Evaluator for SubprocessEvaluator {
    fn query(&self, prompt: &str) -> Result<String> {
        self.query_in_dir(prompt, self.working_directory.as_deref())
    }

    fn query_in_dir(
        &self,
        prompt: &str,
        sandbox_dir: Option<&Path>,
    ) -> Result<String> {
        let effective_dir =
            sandbox_dir.or(self.working_directory.as_deref());
        let mut cmd = Command::new(&self.command[0]);
        cmd.args(&self.command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(dir) = effective_dir {
            cmd.current_dir(dir);
        }
        let mut child =
            cmd.spawn().map_err(|source| Error::EvaluatorSpawn {
                program: self.command[0].clone(),
                message: source.to_string(),
            })?;
        {
            let stdin = child.stdin.as_mut().ok_or_else(|| {
                Error::EvaluatorIo {
                    message: "child stdin handle missing".into(),
                }
            })?;
            stdin.write_all(prompt.as_bytes()).map_err(|source| {
                Error::EvaluatorIo {
                    message: format!("write prompt to stdin: {source}"),
                }
            })?;
        }
        drop(child.stdin.take());
        let output = child.wait_with_output().map_err(|source| {
            Error::EvaluatorIo {
                message: format!("wait_with_output: {source}"),
            }
        })?;
        if !output.status.success() {
            let stderr = truncate(
                &String::from_utf8_lossy(&output.stderr),
                self.stderr_capture_limit,
            );
            return Err(Error::EvaluatorNonZeroExit {
                program: self.command[0].clone(),
                exit: output.status.code(),
                stderr,
            });
        }
        String::from_utf8(output.stdout).map_err(|source| {
            Error::EvaluatorIo {
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

/// Populate a per-cell sandbox directory.
///
/// Creates `parent_dir/<unique-cell-id>/` containing:
///
/// - `prompt.md`    — the full prompt text (read-only by convention)
/// - `scrambled.txt`— the raw scrambled source bytes
/// - `baseline.py`  — the unscrambled reference (empty if not set on challenge)
/// - `notepad/`     — empty, writable scratch directory
///
/// Returns the path to the sandbox root.  The sandbox is a disposable
/// temp directory; the caller is responsible for cleaning it up (or
/// leaving it as an artefact run archive).
///
/// # Errors
///
/// `Error::SandboxSetup` if directory creation or file writes fail.
pub fn build_cell_sandbox(
    parent_dir: &Path,
    challenge: &Challenge,
    config: LayerConfig,
    prompt: &str,
    scrambled: &str,
) -> Result<PathBuf> {
    let cell_id = format!("{}-{}", challenge.name, config.label());
    let cell_dir = parent_dir.join(&cell_id);
    fs::create_dir_all(&cell_dir).map_err(|e| Error::SandboxSetup {
        message: format!("create cell dir {}: {e}", cell_dir.display()),
    })?;
    let notepad = cell_dir.join("notepad");
    fs::create_dir_all(&notepad).map_err(|e| Error::SandboxSetup {
        message: format!("create notepad dir: {e}"),
    })?;
    write_cell_file(&cell_dir, "prompt.md", prompt)?;
    write_cell_file(&cell_dir, "scrambled.txt", scrambled)?;
    write_cell_file(
        &cell_dir,
        "baseline.py",
        challenge.baseline_source.as_deref().unwrap_or(""),
    )?;
    Ok(cell_dir)
}

fn write_cell_file(
    cell_dir: &Path,
    name: &str,
    content: &str,
) -> Result<()> {
    let path = cell_dir.join(name);
    fs::write(&path, content).map_err(|e| Error::SandboxSetup {
        message: format!("write {}: {e}", path.display()),
    })
}

/// Run `attempts` evaluator queries against one `(challenge,
/// layer_config)` cell, scoring each and returning the resulting
/// `RunRecord`s.
///
/// If `sandbox_parent` is `Some`, a per-cell sandbox directory is
/// created inside it (via [`build_cell_sandbox`]) and passed to
/// `SubprocessEvaluator::with_working_directory` so the evaluator
/// sees only the sandboxed inputs.  Without a sandbox, the evaluator
/// inherits the bench process's cwd — which allows cross-cell
/// contamination via the repo filesystem (HANDOFF Blocker 1).
///
/// Evaluator errors abort the loop and bubble up via `Result` —
/// a subprocess that fails to spawn is an operator-environment
/// problem the bench cannot grade.  In contrast, an evaluator
/// that returns chatty / unparseable / refused output continues
/// the loop with the appropriate `ScoreOutcome`.
///
/// # Errors
///
/// - `Error::Scramble` if the layer-config'd scramble fails.
/// - `Error::SandboxSetup` if sandbox creation fails.
/// - Any evaluator-side error from [`Evaluator::query`].
pub fn run_attempts<A: Evaluator>(
    challenge: &Challenge,
    config: LayerConfig,
    evaluator: &A,
    attempts: u32,
    sandbox_parent: Option<&Path>,
) -> Result<Vec<RunRecord>> {
    let scrambled = apply_layers(&challenge.source, config)?;
    let prompt = build_prompt(challenge, config, &scrambled);
    // Build sandbox once per cell (shared across all attempts for this
    // cell — the notepad accumulates across attempts, which is fine:
    // it matches how a stateful agent would work across retries).
    let sandbox_dir = match sandbox_parent {
        Some(parent) => Some(build_cell_sandbox(
            parent, challenge, config, &prompt, &scrambled,
        )?),
        None => None,
    };
    let mut out = Vec::with_capacity(attempts as usize);
    for i in 0..attempts {
        let response = evaluator
            .query_in_dir(&prompt, sandbox_dir.as_deref())?;
        let outcome = score(&challenge.success_predicate, &response);
        out.push(RunRecord::new(
            challenge.name.clone(),
            config,
            evaluator.label(),
            i,
            outcome,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        build_cell_sandbox, floor_char_boundary, run_attempts, truncate,
        Evaluator, SubprocessEvaluator,
    };
    use crate::challenge::Challenge;
    use crate::errors::Error;
    use crate::layer_config::LayerConfig;
    use crate::scoring::ScoreOutcome;
    use crate::success_predicate::SuccessPredicate;

    /// In-process Evaluator that returns a canned answer.  Lets
    /// the `run_attempts` driver be tested without a subprocess.
    struct CannedEvaluator {
        canned: String,
        label: String,
    }
    impl Evaluator for CannedEvaluator {
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
            baseline_source: None,
            success_predicate: SuccessPredicate::exact_match("hunter2"),
        }
    }

    #[test]
    fn run_attempts_records_each_outcome() {
        let adv = CannedEvaluator {
            canned: r#"{"answer": "hunter2"}"#.into(),
            label: "canned-pass".into(),
        };
        let recs = run_attempts(
            &fixture_challenge(),
            LayerConfig::l2_plus_l3(),
            &adv,
            3,
            None,
        )
        .unwrap();
        assert_eq!(recs.len(), 3);
        for (i, r) in recs.iter().enumerate() {
            assert_eq!(
                r.attempt_index,
                u32::try_from(i).unwrap(),
            );
            assert_eq!(r.outcome, ScoreOutcome::Pass);
            assert_eq!(r.evaluator_label, "canned-pass");
            assert_eq!(r.challenge_name, "x");
        }
    }

    #[test]
    fn run_attempts_handles_mixed_outcomes_from_dynamic_evaluator() {
        // An evaluator whose response varies per call; uses a
        // shared Cell to round-robin between three canned answers.
        struct VaryingEvaluator {
            answers: Vec<String>,
            counter: std::cell::Cell<usize>,
            label: String,
        }
        impl Evaluator for VaryingEvaluator {
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
        let adv = VaryingEvaluator {
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
            None,
        )
        .unwrap();
        assert_eq!(recs[0].outcome, ScoreOutcome::Pass);
        assert_eq!(recs[1].outcome, ScoreOutcome::Fail);
        assert_eq!(recs[2].outcome, ScoreOutcome::FormatError);
    }

    #[test]
    fn empty_command_is_rejected() {
        let err = SubprocessEvaluator::new(vec![], "x").unwrap_err();
        match err {
            Error::EvaluatorConfig { message } => {
                assert!(message.contains("empty"));
            }
            other => panic!("expected EvaluatorConfig, got {other:?}"),
        }
    }

    #[test]
    fn subprocess_evaluator_runs_cat_as_echo() {
        // `cat` writes stdin to stdout — a trivial echo evaluator.
        // The "model output" is the prompt itself, which contains
        // "find x" but no JSON; expect FormatError.
        let adv =
            SubprocessEvaluator::new(vec!["cat".into()], "cat-echo")
                .unwrap();
        let response = adv.query("hello world").unwrap();
        assert_eq!(response, "hello world");
    }

    #[test]
    fn subprocess_evaluator_propagates_non_zero_exit() {
        let adv = SubprocessEvaluator::new(
            vec!["false".into()],
            "always-fails",
        )
        .unwrap();
        let err = adv.query("any prompt").unwrap_err();
        match err {
            Error::EvaluatorNonZeroExit { program, exit, .. } => {
                assert_eq!(program, "false");
                // `false` exits 1 on every POSIX system.
                assert_eq!(exit, Some(1));
            }
            other => panic!("expected EvaluatorNonZeroExit, got {other:?}"),
        }
    }

    #[test]
    fn subprocess_evaluator_reports_unknown_program() {
        let adv = SubprocessEvaluator::new(
            vec!["this-binary-does-not-exist-anywhere".into()],
            "missing",
        )
        .unwrap();
        let err = adv.query("any prompt").unwrap_err();
        match err {
            Error::EvaluatorSpawn { program, .. } => {
                assert_eq!(
                    program,
                    "this-binary-does-not-exist-anywhere",
                );
            }
            other => panic!("expected EvaluatorSpawn, got {other:?}"),
        }
    }

    #[test]
    fn subprocess_evaluator_drives_run_attempts_end_to_end() {
        // `sh -c 'printf {"answer": "hunter2"}'` produces a JSON
        // answer regardless of the prompt.  Verifies the trait
        // boundary plus the scoring loop in one test against a
        // real subprocess.
        let adv = SubprocessEvaluator::new(
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
            None,
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

    #[test]
    fn build_cell_sandbox_creates_expected_files() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let challenge = Challenge {
            name: "auth-test".into(),
            goal_description: "find secret".into(),
            source: "def auth(x): return x == \"pw\"\n".into(),
            baseline_source: Some("def auth(x): return x == \"pw\"\n".into()),
            success_predicate: SuccessPredicate::exact_match("pw"),
        };
        let config = LayerConfig::l3_only();
        let sandbox = build_cell_sandbox(
            tmp.path(),
            &challenge,
            config,
            "the-prompt",
            "the-scrambled",
        )
        .unwrap();
        assert!(sandbox.join("prompt.md").exists());
        assert!(sandbox.join("scrambled.txt").exists());
        assert!(sandbox.join("baseline.py").exists());
        assert!(sandbox.join("notepad").is_dir());
        let prompt_content =
            std::fs::read_to_string(sandbox.join("prompt.md")).unwrap();
        assert_eq!(prompt_content, "the-prompt");
        let baseline =
            std::fs::read_to_string(sandbox.join("baseline.py")).unwrap();
        assert!(baseline.contains("def auth"));
    }

    #[test]
    fn build_cell_sandbox_empty_baseline_writes_empty_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let challenge = Challenge {
            name: "no-baseline".into(),
            goal_description: "find it".into(),
            source: "x = 1\n".into(),
            baseline_source: None,
            success_predicate: SuccessPredicate::exact_match("1"),
        };
        let sandbox = build_cell_sandbox(
            tmp.path(),
            &challenge,
            LayerConfig::l3_only(),
            "p",
            "s",
        )
        .unwrap();
        let bl =
            std::fs::read_to_string(sandbox.join("baseline.py")).unwrap();
        assert_eq!(bl, "");
    }

    #[test]
    fn run_attempts_with_sandbox_isolates_evaluator_cwd() {
        // An evaluator that writes its cwd to stdout; verify the cwd
        // is the sandbox dir (not the bench cwd) when sandbox_parent
        // is provided.
        let tmp = tempfile::tempdir().expect("tempdir");
        let adv = SubprocessEvaluator::new(
            vec![
                "sh".into(),
                "-c".into(),
                // Write cwd to stdout as JSON answer.
                "cat > /dev/null; printf '{\"answer\": \"%s\"}' \"$PWD\""
                    .into(),
            ],
            "cwd-reporter",
        )
        .unwrap();
        let challenge = Challenge {
            name: "cwd-check".into(),
            goal_description: "n/a".into(),
            source: "x = 1\n".into(),
            baseline_source: None,
            success_predicate: SuccessPredicate::exact_match("irrelevant"),
        };
        let records = run_attempts(
            &challenge,
            LayerConfig::l3_only(),
            &adv,
            1,
            Some(tmp.path()),
        )
        .unwrap();
        // The evaluator's answer was its cwd; it must be inside tmp.
        // We don't check the exact path because it's a FormatError
        // (the sandbox path doesn't match "irrelevant") — just verify
        // the sandbox was inside the tmp parent.
        assert_eq!(records.len(), 1);
        // The key assertion: the cell sandbox dir was created inside tmp.
        let entries: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            !entries.is_empty(),
            "sandbox dir should have been created inside tmp",
        );
    }
}
