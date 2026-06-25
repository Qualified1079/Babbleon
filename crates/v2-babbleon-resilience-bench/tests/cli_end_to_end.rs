//! End-to-end test of the `babbleon-bench` CLI binary.
//!
//! # What this defeats
//!
//! Regression of any of the three subcommand entry points: a future
//! refactor that breaks `babbleon-bench prompt`, `score`, or
//! `summary` shows up here, not in production bench runs.
//!
//! # Mechanism
//!
//! Locates the compiled binary via `env!("CARGO_BIN_EXE_<name>")`,
//! drives the three subcommands against the `auth-literal-string`
//! seed challenge with synthetic model outputs, and asserts the
//! resulting JSONL + markdown table match expectations.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bench_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_babbleon-bench"))
}

fn challenges_dir() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR set during cargo test");
    PathBuf::from(manifest_dir).join("challenges")
}

#[test]
fn prompt_subcommand_emits_well_formed_prompt() {
    let challenge =
        challenges_dir().join("auth-literal-string.toml");
    let output = Command::new(bench_binary())
        .arg("prompt")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--layer-config")
        .arg("l2-plus-l3")
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "prompt subcommand failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 prompt");
    assert!(stdout.contains("## TASK"));
    assert!(stdout.contains("## SCRAMBLED SOURCE"));
    assert!(stdout.contains("## GOAL"));
    assert!(stdout.contains("\"answer\""));
    // The scrambled source must NOT contain literal newlines mid-
    // section in the fenced code block — but the surrounding prompt
    // has many.  Smoke check: the goal description sentence we
    // recognise must be present verbatim.
    assert!(stdout.contains("auth(x)"));
}

#[test]
fn score_subcommand_marks_correct_answer_as_pass() {
    let challenge =
        challenges_dir().join("auth-literal-string.toml");
    let tmp = tempfile::tempdir().unwrap();
    let model = tmp.path().join("model.txt");
    std::fs::write(&model, r#"{"answer": "hunter2"}"#).unwrap();

    let output = Command::new(bench_binary())
        .arg("score")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--layer-config")
        .arg("l2-plus-l3")
        .arg("--model-output")
        .arg(&model)
        .arg("--evaluator")
        .arg("test-adv")
        .arg("--attempt")
        .arg("0")
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "score subcommand failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let line = String::from_utf8(output.stdout).expect("UTF-8 jsonl");
    assert!(line.contains("\"outcome\":\"pass\""), "expected pass: {line}");
    assert!(line.contains("\"challenge_name\":\"auth-literal-string\""));
    assert!(line.contains("\"evaluator_label\":\"test-adv\""));
}

#[test]
fn score_subcommand_marks_wrong_answer_as_fail() {
    let challenge =
        challenges_dir().join("auth-literal-string.toml");
    let tmp = tempfile::tempdir().unwrap();
    let model = tmp.path().join("model.txt");
    std::fs::write(&model, r#"{"answer": "rabbit"}"#).unwrap();

    let output = Command::new(bench_binary())
        .arg("score")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--model-output")
        .arg(&model)
        .arg("--evaluator")
        .arg("test-adv")
        .output()
        .expect("invoke babbleon-bench");
    assert!(output.status.success());
    let line = String::from_utf8(output.stdout).unwrap();
    assert!(line.contains("\"outcome\":\"fail\""), "{line}");
}

#[test]
fn score_subcommand_marks_unparseable_answer_as_format_error() {
    let challenge =
        challenges_dir().join("auth-literal-string.toml");
    let tmp = tempfile::tempdir().unwrap();
    let model = tmp.path().join("model.txt");
    std::fs::write(&model, "I think the answer is hunter2").unwrap();

    let output = Command::new(bench_binary())
        .arg("score")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--model-output")
        .arg(&model)
        .arg("--evaluator")
        .arg("test-adv")
        .output()
        .expect("invoke babbleon-bench");
    assert!(output.status.success());
    let line = String::from_utf8(output.stdout).unwrap();
    assert!(line.contains("\"outcome\":\"format-error\""), "{line}");
}

#[test]
fn summary_with_threshold_exits_2_on_breach() {
    let tmp = tempfile::tempdir().unwrap();
    let runs = tmp.path().join("runs.jsonl");
    let body = r#"{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":0,"outcome":"pass"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":1,"outcome":"pass"}
"#;
    std::fs::write(&runs, body).unwrap();

    let output = Command::new(bench_binary())
        .arg("summary")
        .arg("--records")
        .arg(&runs)
        .arg("--pass-threshold-pct")
        .arg("50")
        // Opt out of the N>=5 floor for this fixture — this test
        // covers the pass-threshold path only; the floor is
        // exercised in its own test below.
        .arg("--min-attempts")
        .arg("1")
        .output()
        .expect("invoke babbleon-bench");
    // Pass-fraction is 100% (2/2); threshold is 50% → breach →
    // exit code 2.
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 on threshold breach, got {:?}",
        output.status.code(),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("CI gate breach"),
        "expected breach diagnostic on stderr: {stderr}",
    );
    assert!(
        stderr.contains("pass-threshold"),
        "expected pass-threshold-specific diagnostic: {stderr}",
    );
    // The markdown table still lands on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("| c | l2-plus-l3 | 2/2 (100%) |"));
}

#[test]
fn summary_with_threshold_exits_0_when_under_threshold() {
    let tmp = tempfile::tempdir().unwrap();
    let runs = tmp.path().join("runs.jsonl");
    // 1/4 = 25% pass rate.
    let body = r#"{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":0,"outcome":"pass"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":1,"outcome":"fail"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":2,"outcome":"fail"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":3,"outcome":"fail"}
"#;
    std::fs::write(&runs, body).unwrap();

    let output = Command::new(bench_binary())
        .arg("summary")
        .arg("--records")
        .arg(&runs)
        .arg("--pass-threshold-pct")
        .arg("50")
        // Opt out of the N>=5 floor — 4 records are still
        // undersampled by the default; this test only cares about
        // the pass-rate threshold check.
        .arg("--min-attempts")
        .arg("1")
        .output()
        .expect("invoke babbleon-bench");
    // 25% < 50% threshold → no breach → exit code 0.
    assert!(
        output.status.success(),
        "expected exit 0 under threshold, got {:?}",
        output.status.code(),
    );
}

#[test]
fn summary_default_min_attempts_breaches_on_under_5_when_threshold_set() {
    // 2 attempts is below the default min_attempts=5 floor.  With
    // --pass-threshold-pct set, summary must exit 2 even though the
    // pass-fraction (50%) is exactly at threshold (not above).
    let tmp = tempfile::tempdir().unwrap();
    let runs = tmp.path().join("runs.jsonl");
    let body = r#"{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":0,"outcome":"pass"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":1,"outcome":"fail"}
"#;
    std::fs::write(&runs, body).unwrap();

    let output = Command::new(bench_binary())
        .arg("summary")
        .arg("--records")
        .arg(&runs)
        .arg("--pass-threshold-pct")
        .arg("50")
        .output()
        .expect("invoke babbleon-bench");
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2 for undersampled cell, got {:?}",
        output.status.code(),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("min_attempts=5"),
        "expected min_attempts diagnostic on stderr: {stderr}",
    );
    assert!(
        stderr.contains("N=2"),
        "expected actual-count in diagnostic: {stderr}",
    );
}

#[test]
fn summary_min_attempts_breach_at_5_passes() {
    // Boundary: exactly 5 attempts is at the floor — must pass.
    // 0 passes / 5 fails keeps the pass-fraction safely below any
    // threshold > 0% so the only thing under test is the floor.
    let tmp = tempfile::tempdir().unwrap();
    let runs = tmp.path().join("runs.jsonl");
    let mut body = String::new();
    for i in 0..5 {
        body.push_str(&format!(
            "{{\"challenge_name\":\"c\",\"layer_config\":{{\"layer2_keyword_scramble\":true,\"layer3_whitespace_as_words\":true,\"layer7_secret_literal\":false,\"seed_byte\":171,\"epoch\":0}},\"evaluator_label\":\"adv\",\"attempt_index\":{i},\"outcome\":\"fail\"}}\n"
        ));
    }
    std::fs::write(&runs, body).unwrap();

    let output = Command::new(bench_binary())
        .arg("summary")
        .arg("--records")
        .arg(&runs)
        .arg("--pass-threshold-pct")
        .arg("50")
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "expected exit 0 at the 5-attempt floor, got {:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn summary_min_attempts_counts_total_not_graded() {
    // 5 attempts total: 1 pass + 1 fail + 3 format-error.  Graded
    // is only 2, but total is 5 — the floor is on total so this
    // must pass.  This documents the choice that running the bench
    // 5 times satisfies the smoke-test floor even if most outputs
    // were malformed.
    let tmp = tempfile::tempdir().unwrap();
    let runs = tmp.path().join("runs.jsonl");
    let body = r#"{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":0,"outcome":"pass"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":1,"outcome":"fail"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":2,"outcome":"format-error"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":3,"outcome":"format-error"}
{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":4,"outcome":"format-error"}
"#;
    std::fs::write(&runs, body).unwrap();

    let output = Command::new(bench_binary())
        .arg("summary")
        .arg("--records")
        .arg(&runs)
        // Threshold is irrelevant here — pass-fraction is 50% (1/2
        // graded), well above 10%, but the test wants the
        // floor-only branch to pass.  Use threshold 100 so the
        // pass-threshold check itself never breaches.
        .arg("--pass-threshold-pct")
        .arg("100")
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "expected exit 0 at total=5, got {:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn summary_without_threshold_ignores_min_attempts() {
    // Render-only (no --pass-threshold-pct) is a valid use case at
    // any N — operators paste the table into HANDOFF without
    // CI-gating.  Even N=1 must not breach.
    let tmp = tempfile::tempdir().unwrap();
    let runs = tmp.path().join("runs.jsonl");
    let body = r#"{"challenge_name":"c","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":0,"outcome":"pass"}
"#;
    std::fs::write(&runs, body).unwrap();

    let output = Command::new(bench_binary())
        .arg("summary")
        .arg("--records")
        .arg(&runs)
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "expected exit 0 without --pass-threshold-pct, got {:?}",
        output.status.code(),
    );
}

#[test]
fn summary_reports_both_breaches_in_one_pass() {
    // Two undersampled cells (N=2 each) BOTH 100% pass.  The
    // operator sees both the min-attempts breach and the
    // pass-threshold breach in the single stderr block.
    let tmp = tempfile::tempdir().unwrap();
    let runs = tmp.path().join("runs.jsonl");
    let body = r#"{"challenge_name":"c1","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":0,"outcome":"pass"}
{"challenge_name":"c1","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"layer7_secret_literal":false,"seed_byte":171,"epoch":0},"evaluator_label":"adv","attempt_index":1,"outcome":"pass"}
"#;
    std::fs::write(&runs, body).unwrap();

    let output = Command::new(bench_binary())
        .arg("summary")
        .arg("--records")
        .arg(&runs)
        .arg("--pass-threshold-pct")
        .arg("50")
        .output()
        .expect("invoke babbleon-bench");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("min_attempts=5"),
        "expected min-attempts diagnostic: {stderr}",
    );
    assert!(
        stderr.contains("pass-threshold"),
        "expected pass-threshold diagnostic: {stderr}",
    );
}

#[test]
fn summary_subcommand_aggregates_jsonl_into_markdown() {
    let tmp = tempfile::tempdir().unwrap();
    let runs = tmp.path().join("runs.jsonl");
    // Synthesize two records — one pass, one fail, same cell.
    let body = r#"{"challenge_name":"auth-literal-string","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"seed_byte":171,"epoch":0},"evaluator_label":"adv-x","attempt_index":0,"outcome":"pass"}
{"challenge_name":"auth-literal-string","layer_config":{"layer2_keyword_scramble":true,"layer3_whitespace_as_words":true,"seed_byte":171,"epoch":0},"evaluator_label":"adv-x","attempt_index":1,"outcome":"fail"}
"#;
    std::fs::write(&runs, body).unwrap();

    let output = Command::new(bench_binary())
        .arg("summary")
        .arg("--records")
        .arg(&runs)
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "summary subcommand failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let table = String::from_utf8(output.stdout).unwrap();
    assert!(table.contains("| challenge | layer config |"), "{table}");
    assert!(table.contains("adv-x"), "{table}");
    assert!(
        table.contains("| auth-literal-string | l2-plus-l3 | 1/2 (50%) |"),
        "{table}",
    );
}

#[test]
fn run_matrix_subcommand_drives_full_matrix() {
    // 5 challenges × 2 configs × 2 attempts = 20 JSONL records.
    let output = Command::new(bench_binary())
        .arg("run-matrix")
        .arg("--challenges-dir")
        .arg(challenges_dir())
        .arg("--layer-config")
        .arg("l3-only")
        .arg("--layer-config")
        .arg("l2-plus-l3")
        .arg("--evaluator")
        .arg("matrix-test")
        .arg("--attempts")
        .arg("2")
        .arg("--command")
        .arg("sh")
        .arg("--command=-c")
        .arg(r#"--command=cat > /dev/null; printf '%s' '{"answer": "hunter2"}'"#)
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "run-matrix failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let lines: Vec<&str> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    // N challenges (the seed set) × 2 configs × 2 attempts.
    // Read N from the challenges directory so future challenge
    // additions don't break the test.
    let n_challenges = std::fs::read_dir(challenges_dir())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.path().extension().is_some_and(|x| x == "toml")
        })
        .count();
    let expected = n_challenges * 2 * 2;
    assert_eq!(
        lines.len(),
        expected,
        "expected {expected} records for {n_challenges} challenges × 2 configs × 2 attempts, got {}",
        lines.len(),
    );

    // Only `auth-literal-string` should pass with this canned
    // answer; the others fail because hunter2 is not their
    // expected answer.  2 configs × 2 attempts = 4 pass records.
    let pass_count = lines
        .iter()
        .filter(|l| l.contains("\"outcome\":\"pass\""))
        .count();
    assert_eq!(pass_count, 4, "expected 4 pass records, got {pass_count}");
}

#[test]
fn run_matrix_requires_at_least_one_layer_config() {
    let output = Command::new(bench_binary())
        .arg("run-matrix")
        .arg("--challenges-dir")
        .arg(challenges_dir())
        .arg("--evaluator")
        .arg("x")
        .arg("--command")
        .arg("sh")
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        !output.status.success(),
        "expected failure when --layer-config not supplied",
    );
}

#[test]
fn run_matrix_errors_on_empty_challenges_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let output = Command::new(bench_binary())
        .arg("run-matrix")
        .arg("--challenges-dir")
        .arg(tmp.path())
        .arg("--layer-config")
        .arg("l2-plus-l3")
        .arg("--evaluator")
        .arg("x")
        .arg("--command")
        .arg("sh")
        .output()
        .expect("invoke babbleon-bench");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no") && stderr.contains("toml"),
        "expected empty-dir diagnostic: {stderr}",
    );
}

#[test]
fn run_subcommand_drives_subprocess_end_to_end() {
    let challenge =
        challenges_dir().join("auth-literal-string.toml");
    // sh -c that ignores stdin and prints the correct answer.
    // Use --command=<val> so clap doesn't try to interpret the -c
    // as a flag.
    let output = Command::new(bench_binary())
        .arg("run")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--layer-config")
        .arg("l2-plus-l3")
        .arg("--evaluator")
        .arg("sh-canned@cli-test")
        .arg("--attempts")
        .arg("3")
        .arg("--command")
        .arg("sh")
        .arg("--command=-c")
        .arg(r#"--command=cat > /dev/null; printf '%s' '{"answer": "hunter2"}'"#)
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "run subcommand failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );
    let lines: Vec<&str> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 3, "expected 3 JSONL lines, got {lines:?}");
    for (i, line) in lines.iter().enumerate() {
        assert!(line.contains("\"outcome\":\"pass\""), "line {i}: {line}");
        assert!(line.contains("\"evaluator_label\":\"sh-canned@cli-test\""));
        let want_idx = format!("\"attempt_index\":{i}");
        assert!(line.contains(&want_idx), "line {i} missing index: {line}");
    }
}

#[test]
fn run_subcommand_rejects_empty_command() {
    let challenge =
        challenges_dir().join("auth-literal-string.toml");
    let output = Command::new(bench_binary())
        .arg("run")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--evaluator")
        .arg("x")
        .output()
        .expect("invoke babbleon-bench");
    // clap's `required = true` returns non-zero exit with a usage
    // message on stderr.
    assert!(
        !output.status.success(),
        "expected failure when --command not supplied",
    );
}

#[test]
fn run_subcommand_reports_subprocess_failure() {
    let challenge =
        challenges_dir().join("auth-literal-string.toml");
    let output = Command::new(bench_binary())
        .arg("run")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--evaluator")
        .arg("always-fails")
        .arg("--command")
        .arg("false")
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        !output.status.success(),
        "expected failure when evaluator exits non-zero",
    );
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    // Two acceptable error shapes depending on parallel-execution
    // timing.  The intent of the test is "the bench correctly
    // surfaces a meaningful diagnostic for a failed subprocess" —
    // either shape satisfies it:
    //
    // - "evaluator subprocess false exited with status Some(1)"
    //   when the bench observed the exit status (slow `false`).
    // - "broken pipe" / "os error 32" when `false` exited so fast
    //   the bench got EPIPE writing the prompt to stdin first
    //   (fast `false`; happens reliably under heavy test
    //   parallelism).
    let mentions_program = stderr.contains("false");
    let mentions_broken_pipe = stderr.contains("broken pipe")
        || stderr.contains("os error 32");
    assert!(
        mentions_program || mentions_broken_pipe,
        "stderr should mention the failing program or report EPIPE: \
         {stderr}",
    );
}

#[test]
fn score_subcommand_reads_stdin_when_model_output_is_dash() {
    let challenge =
        challenges_dir().join("auth-literal-string.toml");
    let mut child = Command::new(bench_binary())
        .arg("score")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--model-output")
        .arg("-")
        .arg("--evaluator")
        .arg("test-adv")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn babbleon-bench");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(br#"{"answer": "hunter2"}"#)
        .unwrap();
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let line = String::from_utf8(output.stdout).unwrap();
    assert!(line.contains("\"outcome\":\"pass\""), "{line}");
}

// ----- --sandbox-parent-dir flag (HANDOFF Blocker 1 CLI followup) -----

/// `run` populates the per-cell sandbox directory with the four
/// expected files (`prompt.md`, `scrambled.txt`, `baseline.py`,
/// `notepad/`) and the evaluator subprocess's reported cwd matches
/// the sandbox directory.  The evaluator command (`pwd`) writes its
/// cwd to stdout; the bench scores that as the model's answer.
/// We don't assert pass/fail — we assert the sandbox layout.
#[test]
fn run_with_sandbox_parent_dir_creates_per_cell_sandbox_files() {
    let challenge = challenges_dir().join("auth-literal-string.toml");
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().to_path_buf();

    let output = Command::new(bench_binary())
        .arg("run")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--layer-config")
        .arg("l2-plus-l3")
        .arg("--evaluator")
        .arg("sandbox-test")
        .arg("--attempts")
        .arg("1")
        .arg("--sandbox-parent-dir")
        .arg(&parent)
        // Trivial evaluator: read prompt from stdin (discard) and
        // emit a fixed answer.  We just want the side effect of the
        // sandbox files being created.
        .arg("--command")
        .arg("sh")
        .arg("--command=-c")
        .arg(r#"--command=cat > /dev/null; printf '%s' '{"answer": "x"}'"#)
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "run failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );

    // The sandbox dir is named `<challenge>-<layer-config-label>`.
    let cell_dir = parent.join("auth-literal-string-l2-plus-l3");
    assert!(
        cell_dir.is_dir(),
        "cell sandbox dir {} not created",
        cell_dir.display(),
    );
    for f in ["prompt.md", "scrambled.txt", "baseline.py"] {
        assert!(
            cell_dir.join(f).is_file(),
            "sandbox file {} missing",
            cell_dir.join(f).display(),
        );
    }
    assert!(
        cell_dir.join("notepad").is_dir(),
        "sandbox notepad dir missing in {}",
        cell_dir.display(),
    );
    // prompt.md must contain the full prompt (asserted by spotting
    // a known section header).
    let prompt = std::fs::read_to_string(cell_dir.join("prompt.md"))
        .expect("read prompt.md");
    assert!(prompt.contains("## TASK"), "prompt.md missing ## TASK");
    assert!(
        prompt.contains("## SCRAMBLED SOURCE"),
        "prompt.md missing scrambled-source header",
    );
}

/// `run-matrix` honours `--sandbox-parent-dir` the same way as `run`:
/// each `(challenge, layer_config)` cell gets its own subdir.
#[test]
fn run_matrix_with_sandbox_parent_dir_creates_one_dir_per_cell() {
    let tmp = tempfile::tempdir().unwrap();
    let parent = tmp.path().to_path_buf();

    let output = Command::new(bench_binary())
        .arg("run-matrix")
        .arg("--challenges-dir")
        .arg(challenges_dir())
        .arg("--layer-config")
        .arg("l3-only")
        .arg("--layer-config")
        .arg("l2-plus-l3")
        .arg("--evaluator")
        .arg("matrix-sandbox-test")
        .arg("--attempts")
        .arg("1")
        .arg("--sandbox-parent-dir")
        .arg(&parent)
        .arg("--command")
        .arg("sh")
        .arg("--command=-c")
        .arg(r#"--command=cat > /dev/null; printf '%s' '{"answer": "x"}'"#)
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        output.status.success(),
        "run-matrix failed: stderr={}",
        String::from_utf8_lossy(&output.stderr),
    );

    // Count subdirs created: one per (challenge, layer_config).
    let subdirs: Vec<_> = std::fs::read_dir(&parent)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .collect();
    let n_challenges = std::fs::read_dir(challenges_dir())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
        .count();
    let expected = n_challenges * 2;
    assert_eq!(
        subdirs.len(),
        expected,
        "expected {expected} per-cell sandbox dirs ({n_challenges} \
         challenges × 2 layer configs), got {}: {:?}",
        subdirs.len(),
        subdirs.iter().map(std::fs::DirEntry::file_name).collect::<Vec<_>>(),
    );

    // Each must contain prompt.md.
    for entry in &subdirs {
        let prompt = entry.path().join("prompt.md");
        assert!(
            prompt.is_file(),
            "missing prompt.md in {}",
            entry.path().display(),
        );
    }
}

/// `--sandbox-parent-dir` rejects a non-existent parent with a
/// clear error before launching the evaluator.
#[test]
fn run_rejects_missing_sandbox_parent_dir() {
    let challenge = challenges_dir().join("auth-literal-string.toml");
    let tmp = tempfile::tempdir().unwrap();
    let bogus = tmp.path().join("does-not-exist");

    let output = Command::new(bench_binary())
        .arg("run")
        .arg("--challenge")
        .arg(&challenge)
        .arg("--evaluator")
        .arg("sandbox-missing-test")
        .arg("--sandbox-parent-dir")
        .arg(&bogus)
        .arg("--command")
        .arg("true")
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        !output.status.success(),
        "expected failure when sandbox parent dir does not exist",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sandbox-parent-dir")
            || stderr.contains("does not exist"),
        "stderr should mention the missing-dir error: {stderr}",
    );
}

/// `run-matrix --sandbox-parent-dir <missing>` errors the same way.
#[test]
fn run_matrix_rejects_missing_sandbox_parent_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let bogus = tmp.path().join("does-not-exist");

    let output = Command::new(bench_binary())
        .arg("run-matrix")
        .arg("--challenges-dir")
        .arg(challenges_dir())
        .arg("--layer-config")
        .arg("l3-only")
        .arg("--evaluator")
        .arg("matrix-sandbox-missing-test")
        .arg("--sandbox-parent-dir")
        .arg(&bogus)
        .arg("--command")
        .arg("true")
        .output()
        .expect("invoke babbleon-bench");
    assert!(
        !output.status.success(),
        "expected failure when sandbox parent dir does not exist",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("sandbox-parent-dir")
            || stderr.contains("does not exist"),
        "stderr should mention the missing-dir error: {stderr}",
    );
}
