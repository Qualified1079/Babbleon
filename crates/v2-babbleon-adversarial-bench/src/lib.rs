//! Babbleon v2 — adversarial regression bench.
//!
//! # What this defeats
//!
//! Subjective opinion about whether layer-2, layer-3, or layer-2 + 3
//! is "enough" to defeat an LLM/agent adversary at a given crack
//! budget.  v2 phase-3 escalation decisions ("ship L2+L3 or escalate
//! to L4?") are operator-blocked until we have *data* showing the
//! crack-fraction per layer config against a faithful adversary
//! simulation.  This crate is the harness that produces that data
//! and the regression gate that keeps a future preprocessor change
//! from silently weakening the scramble.
//!
//! # Mechanism
//!
//! A *challenge* (`challenge::Challenge`) is a Python source snippet
//! plus a `goal_description` and a `success_predicate` declaring the
//! win condition.  The harness:
//!
//! 1. Loads a challenge from a TOML file under `challenges/`.
//! 2. Scrambles the snippet under a chosen `LayerConfig` (L3-only,
//!    L2+L3, future L2+L3+L4, ...) using the preprocessor library
//!    directly with a deterministic synthetic per-host secret so the
//!    run is reproducible across machines.
//! 3. Builds a *neutral capability* prompt (`prompt::build_prompt`)
//!    that states the win condition and the available materials with
//!    NO adversarial / role-play framing — the operator's
//!    HANDOFF-stated constraint that "you are a hacker" framings
//!    trip safety filters and degrade signal.
//! 4. Hands the prompt to an adversary (an `Adversary` impl) — Claude
//!    API, `OpenAI` API, or an in-sandbox Agent subagent — and collects
//!    its answer.
//! 5. Scores the answer against the challenge's `success_predicate`
//!    (`scoring::score`).
//! 6. Aggregates many `(challenge, layer_config, adversary)` runs
//!    into a markdown table (`summary::render_markdown`) showing the
//!    crack-fraction at every cell.
//!
//! # Trust placement
//!
//! The bench crate runs on the operator's host with **no privileged
//! access** and **no per-host-secret access**.  Bench runs use a
//! synthetic `PerHostSecret::from_bytes(&[seed; 32])` so the
//! scramble is deterministic from the seed and the per-host secret
//! never appears.  The bench therefore needs neither the daemon
//! socket nor any capability the daemon holds.  Live-secret runs
//! against an operator's real daemon are intentionally out of scope:
//! the goal is repeatable cross-host bench data, not validation of
//! one operator's compounds.
//!
//! # Compartmentalisation
//!
//! Each module owns one concern and exposes one or two functions /
//! types:
//!
//! - **`errors`** — `Error` enum + `Result` alias.  Per
//!   security-baseline rule 13, no variant carries secret bytes.  The
//!   bench has no secret bytes by design, so this is trivial — every
//!   variant is operator-diagnostic context.
//! - **`challenge`** — `Challenge` struct + `Challenge::from_toml`
//!   loader.  TOML format (not YAML) because `toml` is already a
//!   workspace dep and YAML would pull in `serde_yaml` for one
//!   feature; the spec's `name / goal_description / source /
//!   success_predicate` shape is identical either way.
//! - **`success_predicate`** — `SuccessPredicate` enum.  Variants
//!   `ExactMatch`, `PythonScript` (deferred to its own commit; uses
//!   the same python3 binary the python-shim crate uses).  The enum
//!   is the wire-format the TOML serializes to / from.
//! - **`layer_config`** — `LayerConfig` struct.  Booleans for L2 /
//!   L3 (plus a `seed` field for the deterministic per-host secret).
//!   Future commits add L4 / L5 booleans as those layers land.
//! - **`scramble_pipeline`** — `apply_layers` takes a `LayerConfig`
//!   and a Python source string and returns the scrambled bytes.
//!   Pure-compute; no daemon, no I/O.
//! - **`prompt`** — `build_prompt` constructs the neutral-capability
//!   prompt per the HANDOFF spec (lists the scrambled source, the
//!   layer documentation pointers, the goal, and the answer-format
//!   instructions).  No role-play framing.
//! - **`scoring`** — `score(predicate, &model_output)` returns
//!   `ScoreOutcome::Pass | Fail`.
//! - **`summary`** — `render_markdown(runs)` aggregates `RunRecord`s
//!   into the operator-facing crack-fraction table.
//! - **`run_record`** — the canonical record of one `(challenge,
//!   layer_config, adversary, attempt)` outcome, JSON-serializable
//!   so runs are persistable to disk between subcommand invocations.
//!
//! # Security baseline
//!
//! Per `docs/v2/security-baseline.md`:
//!
//! - `#![forbid(unsafe_code)]` at the crate root.  This crate is pure
//!   safe Rust.
//! - `#![deny(missing_docs)]` — every public item documented.
//! - `#![warn(clippy::pedantic)]` — pedantic linting enforced.
//! - No secrets in this crate's address space.  The synthetic
//!   `PerHostSecret` is a bench-deterministic seed, NOT a host
//!   secret; it carries zero security weight and the bench docs flag
//!   it as such.
//! - All `Error` variants carry only operator-diagnostic context
//!   (paths, validation messages); rule 13 is trivially satisfied.
//!
//! # MVP scope (this commit family)
//!
//! - Challenge loader (TOML).
//! - Layer-config-driven scramble pipeline (L2 + L3 toggles).
//! - Neutral-framing prompt builder.
//! - `ExactMatch` scoring.
//! - Markdown summary aggregator.
//! - 4 seed challenges: `auth-literal-string`, `auth-hash-check`,
//!   `state-machine`, `realistic-cli`.
//!
//! # Out of scope for the MVP (filed for future commits)
//!
//! - The standalone bench binary (`babbleon-bench` CLI subcommands
//!   `scramble`, `score`, `summary`) — lands in its own commit once
//!   the library API stabilises.
//! - `PythonScript` success predicate — needs subprocess-to-`python3`
//!   wiring, same shape as the python-shim crate; commit-deferred.
//! - Adversary plugins (`Adversary` trait impls for Claude API,
//!   `OpenAI` API, in-sandbox Agent subagent) — each is a separate
//!   commit gated on its own env-var / sandbox capability.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod challenge;
pub mod errors;
pub mod layer_config;
pub mod prompt;
pub mod run_record;
pub mod scoring;
pub mod scramble_pipeline;
pub mod success_predicate;
pub mod summary;

pub use challenge::Challenge;
pub use errors::{Error, Result};
pub use layer_config::LayerConfig;
pub use prompt::build_prompt;
pub use run_record::RunRecord;
pub use scoring::{score, ScoreOutcome, POLICY_REFUSAL_PATTERNS};
pub use scramble_pipeline::apply_layers;
pub use success_predicate::SuccessPredicate;
pub use summary::render_markdown;
