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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.to_lowercase().contains("false"),
        "stderr should mention the failing program: {stderr}",
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
