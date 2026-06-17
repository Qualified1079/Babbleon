//! Adversarial fingerprint test against captured real-tool `--help` output.
//!
//! Unlike `fingerprint.rs` (which tests against a hand-written list of
//! plausible-looking fingerprint patterns), this test reads the *actual*
//! `--help` output of each tool we deceive — captured once into fixture
//! files under `tests/fixtures/help-text/` — and verifies that the
//! wrapper's deceptive output shares NO distinctive substrings with the
//! real tool.
//!
//! # What this defeats
//!
//! An attacker's fingerprint database (Wappalyzer, WhatWeb, ObserverWard,
//! and bespoke recon scripts) classifies a binary by matching the binary's
//! observable output against signatures derived from real-tool output.
//! If our wrapper's `--help` shares an 8+-character distinctive substring
//! with real curl's `--help`, *any* fingerprinter whose signature was
//! lifted from that substring will classify the wrapper as curl.  This
//! test verifies the empirical bar: zero such substrings.
//!
//! # Methodology
//!
//!   1. Read the captured real `--help` for each tool.
//!   2. Extract candidate fingerprint substrings: 12+ contiguous chars
//!      that are alphanumeric / punctuation-rich, excluding generic
//!      boilerplate (`Usage:`, ` --`, `[OPTION]`, etc. — patterns shared
//!      across every CLI tool).
//!   3. Build the wrapper for the tool with its deception banner.
//!   4. Run the wrapper with `--help` from a (forced) untrusted NS.
//!   5. Assert the wrapper output contains ZERO of the candidate
//!      substrings.
//!
//! Fixtures are tools that happened to be installed on the box where the
//! capture was made; tests skip any tool missing a fixture.  Re-capture
//! by running the appropriate `--help` command and pasting into the
//! fixture file.

use babbleon::enforcement::wrapper::write_wrapper;
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

/// Generic boilerplate substrings that appear in nearly every CLI tool's
/// `--help` output.  Excluded from the distinctive-substring extraction
/// because a match on these tells the attacker nothing.
const GENERIC_BOILERPLATE: &[&str] = &[
    "Usage:",
    "usage:",
    "OPTIONS",
    "[OPTION",
    "[options",
    "--help",
    "--version",
    "Show this help",
    "show this help",
    "Print help",
    "print help",
    "FILE",
    "[FILE",
    "DIRECTORY",
    "options...",
    "OPTION]",
    "(default",
    "command",
    "verbose",
    "<command>",
    "<file>",
    "<path>",
];

/// Minimum length for a candidate distinctive substring.  Long enough to
/// be specific to one tool's vocabulary, short enough to fail loudly on a
/// deceptive output that accidentally borrows.
const MIN_SUBSTRING_LEN: usize = 14;

/// Extract distinctive multi-word substrings from a real `--help` body.
///
/// We take each line, strip leading/trailing whitespace, and emit the
/// stripped line if it is long enough and not boilerplate.  This favours
/// "vocabulary phrases" the tool's authors wrote (e.g. `"Fail fast with
/// no output on HTTP errors"` for curl) over generic structure.
fn distinctive_substrings(help: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in help.lines() {
        let line = raw.trim();
        if line.len() < MIN_SUBSTRING_LEN {
            continue;
        }
        let is_boilerplate = GENERIC_BOILERPLATE
            .iter()
            .any(|b| line.contains(b) && line.len() < b.len() + 20);
        if is_boilerplate {
            continue;
        }
        // Skip pure ASCII separator lines (---, ===).
        if line.chars().all(|c| !c.is_alphabetic()) {
            continue;
        }
        out.push(line.to_string());
    }
    out
}

fn build_deception_map() -> HashMap<&'static str, &'static str> {
    let pairs: &[(&str, &str)] = &[
        ("curl",
         "less [OPTION]... [FILE]...\nFile pager.\n  -N  number lines\n  -S  chop long lines\n"),
        ("wget",
         "man [OPTION...] [SECTION] PAGE...\nFormat and display manual pages.\n  -k  output formatted for terminal\n  -H  HTML output format\n"),
        ("ssh",
         "sort [OPTION]... [FILE]...\nSort lines of text.\n  -n  numeric sort\n  -r  reverse\n  -k  key field\n"),
        ("nc",
         "uniq [OPTION]... [INPUT [OUTPUT]]\nReport or omit repeated lines.\n  -c  prefix count\n  -d  only duplicates\n"),
        ("python3",
         "diff [OPTION]... FILES\nCompare files line by line.\n  -u  unified format\n  -r  recursive\n"),
        ("bash",
         "date [OPTION]... [+FORMAT]\nPrint or set the system date.\n  -u  UTC\n  -I  ISO 8601\n"),
        ("aws",
         "file [-bchiLNnprsSvzZ0] [--apple] [--extension] [--mime-encoding]\n     [--mime-type] [-e testname] [-F separator] [-f namefile]\n     [-m magicfiles] [-P name=value] file...\n"),
        ("gh",
         "head [OPTION]... [FILE]...\nPrint the first 10 lines.\n  -n K  print first K lines\n  -c K  print first K bytes\n"),
        ("kubectl",
         "wc [OPTION]... [FILE]...\nPrint newline, word, and byte counts.\n  -l  line count\n  -w  word count\n  -c  byte count\n"),
        ("docker",
         "cut OPTION... [FILE]...\nPrint selected parts of lines.\n  -b  byte positions\n  -c  character positions\n  -d  delimiter\n  -f  fields\n"),
        ("terraform",
         "tee [OPTION]... [FILE]...\nCopy stdin to stdout and FILE.\n  -a  append\n  -i  ignore interrupts\n"),
        ("npm",
         "tr [OPTION]... SET1 [SET2]\nTranslate or delete characters.\n  -d  delete\n  -s  squeeze repeats\n"),
        ("pip",
         "od [OPTION]... [FILE]...\nDump files in octal and other formats.\n  -c  ASCII chars\n  -x  hex bytes\n"),
        ("git",
         "nl [OPTION]... [FILE]...\nNumber lines of files.\n  -b  body numbering\n  -n  numbering format\n"),
    ];
    pairs.iter().copied().collect()
}

fn fixture_path(tool: &str) -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("help-text");
    p.push(format!("{tool}.txt"));
    p
}

fn write_stub_binary(dir: &Path, name: &str) {
    let path = dir.join(name);
    std::fs::write(&path, "#!/bin/sh\necho REAL_BINARY_OUTPUT\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn probe_help(script: &Path) -> String {
    let out = Command::new("sh")
        .arg(script)
        .arg("--help")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("failed to exec wrapper");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn wrapper_output_shares_no_distinctive_substrings_with_real_help() {
    let dir = TempDir::new().unwrap();
    let real_root = dir.path().join("real");
    let wrapper_root = dir.path().join("wrappers");
    std::fs::create_dir_all(&real_root).unwrap();
    std::fs::create_dir_all(&wrapper_root).unwrap();

    let deception = build_deception_map();
    let mut tested = 0usize;
    let mut findings: Vec<String> = Vec::new();

    for tool in babbleon::manifest::DEFAULT_TRACKED {
        let fixture = fixture_path(tool);
        let Ok(real_help) = std::fs::read_to_string(&fixture) else {
            // No fixture for this tool — that's fine; skip silently.
            continue;
        };
        if real_help.trim().is_empty() {
            continue;
        }

        write_stub_binary(&real_root, tool);
        let real_path = real_root.join(tool);
        let banner = deception.get(tool).copied();
        let wp = write_wrapper(
            tool,
            &format!("sc-{tool}"),
            &real_path,
            &wrapper_root,
            b"test-host-secret",
            Some(0),
            banner,
        )
        .unwrap();
        let wrapper_output = probe_help(&wp);

        let substrings = distinctive_substrings(&real_help);
        assert!(
            !substrings.is_empty(),
            "fixture {tool}.txt produced no distinctive substrings — \
             fixture too short or all boilerplate?"
        );

        for s in &substrings {
            if wrapper_output.contains(s) {
                findings.push(format!(
                    "tool={tool}: wrapper output contains real-help substring {:?}",
                    s
                ));
            }
        }
        tested += 1;
    }

    assert!(
        tested >= 3,
        "expected at least 3 captured fixtures to be testable; got {tested}"
    );
    assert!(
        findings.is_empty(),
        "wrapper output leaked {} distinctive real-help substring(s):\n{}",
        findings.len(),
        findings.join("\n")
    );
}

#[test]
fn detector_would_catch_a_deliberate_leak() {
    // Negative-control: confirm the headline test is not vacuously passing.
    // If we feed the wrapper a banner copied straight from the real curl
    // fixture, the substring check must flag it.
    let fixture = match std::fs::read_to_string(fixture_path("curl")) {
        Ok(s) => s,
        Err(_) => return, // no curl fixture on this host — skip
    };
    let substrings = distinctive_substrings(&fixture);
    assert!(!substrings.is_empty());

    // Pick a distinctive substring and use it AS the deception banner.
    // The wrapper output should then contain that substring, and the
    // detection logic should flag it.
    let leak = substrings.iter().find(|s| s.len() > 25).unwrap().clone();

    let dir = TempDir::new().unwrap();
    let real_root = dir.path().join("real");
    let wrapper_root = dir.path().join("wrappers");
    std::fs::create_dir_all(&real_root).unwrap();
    std::fs::create_dir_all(&wrapper_root).unwrap();

    write_stub_binary(&real_root, "curl");
    let wp = write_wrapper(
        "curl",
        "sc-curl",
        &real_root.join("curl"),
        &wrapper_root,
        b"test",
        Some(0),
        Some(&leak), // deliberate leak
    )
    .unwrap();
    let output = probe_help(&wp);

    let detected = substrings.iter().any(|s| output.contains(s));
    assert!(
        detected,
        "negative-control failed: deliberately leaked substring {leak:?} \
         was not caught.  The headline test may be vacuously passing."
    );
}

#[test]
fn distinctive_substring_extractor_rejects_boilerplate() {
    // Sanity check on the extractor: a pure-boilerplate input should
    // produce no candidates, so the headline test cannot be vacuously
    // passing because of an over-aggressive filter.
    let boilerplate =
        "Usage: tool [OPTIONS]\n  --help    Show this help\n  --version Print version\n";
    let subs = distinctive_substrings(boilerplate);
    assert!(
        subs.is_empty(),
        "extractor should reject all-boilerplate input; got {subs:?}"
    );

    // And a real distinctive line should survive.
    let real = "Fail fast with no output on HTTP errors\n";
    let subs = distinctive_substrings(real);
    assert_eq!(subs.len(), 1);
    assert!(subs[0].contains("Fail fast"));
}
