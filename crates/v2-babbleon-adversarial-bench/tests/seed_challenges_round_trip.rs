//! Integration test: every TOML file under `challenges/` loads,
//! validates, and produces non-empty scrambled output under the
//! HANDOFF-recommended L2+L3 floor.
//!
//! # What this defeats
//!
//! Drift between a seed challenge file and the loader.  A future
//! refactor that breaks `Challenge::from_toml_file` for a real
//! seed challenge surfaces here, not in production bench runs.
//!
//! # Mechanism
//!
//! Walks `<crate>/challenges/*.toml`, loads each via the public
//! `Challenge::from_toml_file` API, asserts the loaded fields are
//! non-empty, and runs `apply_layers` under `LayerConfig::l2_plus_l3()`.
//! Every cell must produce a non-empty scramble; cells where the
//! scrambled source equals the input source are also flagged
//! (would mean the preprocessor was a no-op for that input, which
//! should never happen for a real Python snippet).

use std::path::PathBuf;

use babbleon_adversarial_bench_v2::{
    apply_layers, build_prompt, score, Challenge, LayerConfig, ScoreOutcome,
    SuccessPredicate,
};

fn challenges_dir() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR set during cargo test");
    PathBuf::from(manifest_dir).join("challenges")
}

fn seed_challenge_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(challenges_dir())
        .expect("read challenges dir")
        .filter_map(std::result::Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "expected at least one *.toml under challenges/",
    );
    paths
}

#[test]
fn every_seed_challenge_loads_and_validates() {
    for path in seed_challenge_paths() {
        let c = Challenge::from_toml_file(&path).unwrap_or_else(|e| {
            panic!("load {path:?} failed: {e}")
        });
        assert!(!c.name.is_empty(), "name empty in {path:?}");
        assert!(!c.source.is_empty(), "source empty in {path:?}");
        assert!(
            !c.goal_description.is_empty(),
            "goal_description empty in {path:?}",
        );
    }
}

#[test]
fn seed_challenge_file_stem_matches_name_field() {
    // A consistency property — the file stem and the `name` field
    // should agree so the operator's `bench --challenge X` argument
    // unambiguously identifies one file.
    for path in seed_challenge_paths() {
        let c = Challenge::from_toml_file(&path).unwrap();
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("UTF-8 file stem");
        assert_eq!(
            stem, c.name,
            "file stem must equal name field for {path:?}",
        );
    }
}

#[test]
fn every_seed_challenge_scrambles_under_l2_plus_l3() {
    for path in seed_challenge_paths() {
        let c = Challenge::from_toml_file(&path).unwrap();
        let scrambled =
            apply_layers(&c.source, LayerConfig::l2_plus_l3()).unwrap_or_else(
                |e| panic!("scramble {path:?} failed: {e}"),
            );
        assert!(
            !scrambled.is_empty(),
            "L2+L3 must produce non-empty output for {path:?}",
        );
        assert_ne!(
            scrambled, c.source,
            "L2+L3 must change the source for {path:?}",
        );
        // Layer 3 must eliminate literal newlines.
        assert!(
            !scrambled.contains('\n'),
            "L2+L3 must eliminate literal newlines for {path:?}: {scrambled}",
        );
    }
}

#[test]
fn every_seed_challenge_builds_a_prompt_under_l2_plus_l3() {
    for path in seed_challenge_paths() {
        let c = Challenge::from_toml_file(&path).unwrap();
        let scrambled =
            apply_layers(&c.source, LayerConfig::l2_plus_l3()).unwrap();
        let prompt = build_prompt(&c, LayerConfig::l2_plus_l3(), &scrambled);
        // Sanity: the prompt embeds the scrambled bytes and the goal
        // description verbatim, and asks for a JSON answer.
        assert!(prompt.contains(&scrambled), "prompt missing scramble for {path:?}");
        assert!(
            prompt.contains(&c.goal_description),
            "prompt missing goal for {path:?}",
        );
        assert!(
            prompt.contains("\"answer\""),
            "prompt missing JSON answer instruction for {path:?}",
        );
    }
}

#[test]
fn each_seed_challenge_predicate_passes_on_its_expected_answer() {
    // Self-check: the canonical expected answer recorded in each
    // challenge file must actually `Pass` the predicate.  This
    // catches typos in the seed-challenge files.
    for path in seed_challenge_paths() {
        let c = Challenge::from_toml_file(&path).unwrap();
        let expected = match &c.success_predicate {
            SuccessPredicate::ExactMatch { expected }
            | SuccessPredicate::CaseInsensitiveMatch { expected } => expected,
        };
        let model_output = format!(r#"{{"answer": "{}"}}"#, escape_for_json(expected));
        let outcome = score(&c.success_predicate, &model_output);
        assert_eq!(
            outcome,
            ScoreOutcome::Pass,
            "self-check failed for {path:?}: predicate did not pass on the \
             recorded expected answer {expected:?}",
        );
    }
}

fn escape_for_json(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // Cannot fail: writing to a String never errors.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
