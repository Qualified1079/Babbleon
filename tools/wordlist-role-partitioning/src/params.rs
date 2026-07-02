//! Input configuration for the role-partitioning calculator.
//!
//! Three groups of parameters, each with a small named constructor
//! for the "current v2 provisional table" (from
//! `docs/v2/phase0-research-notes.md` §11 and the 2026-07-02 addendum):
//!
//! 1. [`Role`] — one obfuscator role (identifier, decoy, keyword, ...).
//! 2. [`AttackerModel`] — the threat context: how many targets, what
//!    collision probability the operator is willing to tolerate, and
//!    how long a compromised mapping is "worth" attacking.
//! 3. [`WordlistModel`] — the physical corpus the roles carve out of:
//!    total size, plus the mean compound-token count under the
//!    tokenizer of interest (used to weight attention cost).
//!
//! # Why these three
//!
//! Every knob the tool exposes belongs to exactly one of these
//! groups.  The [`allocation`](crate::allocation) module then takes
//! `(Vec<Role>, AttackerModel, WordlistModel)` and produces the
//! allocation table — no other state.

use std::fmt;

/// Entropy model that governs how a role's target-bits budget is
/// derived from the attacker model.
///
/// - `Birthday` — strict birthday bound
///   `2·log2(N) + collision_margin + union_bound`.  Correct for
///   compound_N ≥ 2 roles where the attacker's task looks like
///   collision detection over a compound space that is not much
///   bigger than the observation count.
/// - `Uniqueness` — minimum pool that lets a bijective permutation
///   from `(source_item, alias_index)` into the compound space exist:
///   `log2(N_events × alias_count × safety_factor)`.  The scrambler's
///   L2 permutation is bijective by construction, so accidental
///   collisions within one mapping are impossible; only the
///   pool-must-be-large-enough constraint remains.  Correct for
///   compound_N = 1 roles (keyword) where the birthday bound would
///   demand an astronomically large pool that no realistic wordlist
///   supplies.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EntropyModel {
    Birthday,
    Uniqueness,
}

/// A named obfuscator role that draws compounds from a disjoint pool.
///
/// - `compound_n` — number of words concatenated to build one
///   emitted compound.
/// - `entropy_model` — see [`EntropyModel`].
/// - `alias_count` — how many aliases the L2 scrambler generates per
///   source item.  Only meaningful for `EntropyModel::Uniqueness`;
///   Birthday-mode roles ignore it.  Defaults to 5 (v2's
///   `MAX_ALIAS_COUNT`) for a conservative estimate.
/// - `uniqueness_safety_factor` — safety multiplier applied to the
///   uniqueness bound so the derived pool is a few bits above the
///   minimum feasible.  Ignored under Birthday mode.  Default 4.
/// - `target_bits_override` — optional pin on the per-role bit budget
///   (bypasses both derived formulas).
/// - `tokens_per_compound` — optional measured mean cost under the
///   tokenizer of interest; if `None` the allocator uses the
///   wordlist's baseline value.
/// - `pool_size_floor` — hard external lower bound (Python's 35
///   reserved keywords, garak's ~500 payloads).  Overrides the
///   entropy-derived pool if larger.
/// - `events_per_epoch_override` — optional per-role event count.
///   Different roles see different compound volumes; if `None`, the
///   allocator falls back to `AttackerModel::n_events_per_epoch`.
#[derive(Clone, Debug)]
pub struct Role {
    pub name: String,
    pub compound_n: usize,
    pub entropy_model: EntropyModel,
    pub alias_count: usize,
    pub uniqueness_safety_factor: usize,
    pub target_bits_override: Option<f64>,
    pub tokens_per_compound: Option<f64>,
    pub pool_size_floor: usize,
    pub events_per_epoch_override: Option<u64>,
}

impl Role {
    /// Standard role table from `phase0-research-notes.md` §11.
    ///
    /// Per-role event counts reflect the different compound volumes
    /// each role produces per epoch:
    ///
    /// - identifier: 2 000 (matches §11's `N=2000 tools`).
    /// - decoy: 500 (~25 % of depth-0 positions in a typical Python
    ///   file after L5 decoy injection).
    /// - direction_marker: 200 (per-file marker density from L6).
    /// - whitespace: 1 000 (whitespace tokens per typical file — L3).
    /// - keyword: 35 (Python reserved word count, tight upper bound).
    /// - prompt_injection: 5 (typical prompt-injection injection
    ///   density per file, phase0 research §10).
    ///
    /// These are the "distinct-compound-observations per epoch"
    /// inputs to the birthday bound.  Actual on-host counts will
    /// vary; operators should override via `--events-per-epoch` or
    /// per-role knobs when their workload profile differs.
    #[must_use]
    pub fn provisional_v2_table() -> Vec<Self> {
        vec![
            Self {
                name: "identifier".into(),
                compound_n: 4,
                entropy_model: EntropyModel::Birthday,
                alias_count: 5,
                uniqueness_safety_factor: 4,
                target_bits_override: None,
                tokens_per_compound: None,
                pool_size_floor: 0,
                events_per_epoch_override: Some(2_000),
            },
            Self {
                name: "decoy".into(),
                compound_n: 3,
                entropy_model: EntropyModel::Birthday,
                alias_count: 5,
                uniqueness_safety_factor: 4,
                target_bits_override: None,
                tokens_per_compound: None,
                pool_size_floor: 0,
                events_per_epoch_override: Some(500),
            },
            Self {
                name: "direction_marker".into(),
                compound_n: 3,
                entropy_model: EntropyModel::Birthday,
                alias_count: 5,
                uniqueness_safety_factor: 4,
                target_bits_override: None,
                tokens_per_compound: None,
                pool_size_floor: 0,
                events_per_epoch_override: Some(200),
            },
            Self {
                name: "whitespace".into(),
                compound_n: 2,
                // L3 whitespace substitution is a bijective
                // permutation over the whitespace pool — accidental
                // collisions within one mapping are impossible.
                // Uniqueness is the correct model; Birthday would
                // demand a whitespace pool larger than the whole
                // wordlist, which is a real-world blocker.
                entropy_model: EntropyModel::Uniqueness,
                alias_count: 5,
                uniqueness_safety_factor: 4,
                target_bits_override: None,
                tokens_per_compound: None,
                pool_size_floor: 0,
                events_per_epoch_override: Some(1_000),
            },
            Self {
                name: "keyword".into(),
                compound_n: 1,
                // Keyword compounds are single-word substitutions
                // (Python `def` → one alias per epoch).  The L2
                // permutation is bijective, so accidental collisions
                // within one mapping are impossible; the pool only
                // needs to be big enough to hold the bijection.
                entropy_model: EntropyModel::Uniqueness,
                alias_count: 5,
                uniqueness_safety_factor: 4,
                target_bits_override: None,
                tokens_per_compound: None,
                pool_size_floor: 35,
                events_per_epoch_override: Some(35),
            },
            Self {
                name: "prompt_injection".into(),
                compound_n: 1,
                entropy_model: EntropyModel::Uniqueness,
                alias_count: 1,
                uniqueness_safety_factor: 1,
                target_bits_override: Some(0.0),
                tokens_per_compound: None,
                // garak (Apache 2.0) primary vendoring plan yields
                // ~500 payloads (phase0 research §10).  Pool is the
                // payload set itself, not derived from entropy.
                pool_size_floor: 500,
                events_per_epoch_override: Some(5),
            },
        ]
    }
}

/// Attacker context that drives the target-bits calculation.
///
/// - `n_events_per_epoch` — how many independent compounds an
///   attacker gets to observe per epoch.  For the identifier role
///   this is `~= tools_per_host * compound_occurrences_per_tool`;
///   for smaller roles it is the total compound population.
/// - `target_collision_probability` — the operator's acceptable
///   birthday-collision probability per epoch (e.g. `2^-40` ~=
///   9.1e-13 for cryptographic-hygiene defaults).
/// - `secret_lifetime_epochs` — how many rotations the same host
///   secret must last before compromise.  Longer lifetimes multiply
///   the observed event count when the attacker aggregates across
///   epochs.
#[derive(Clone, Debug)]
pub struct AttackerModel {
    pub n_events_per_epoch: u64,
    pub target_collision_probability: f64,
    pub secret_lifetime_epochs: u64,
}

impl AttackerModel {
    /// Sensible starting values for the developer-laptop use case.
    ///
    /// `n_events_per_epoch = 2 000` matches phase0-research-notes
    /// §11's `N=2000 tools` line — the distinct compounds one epoch's
    /// mapping is expected to expose in real use.  Each rotation
    /// regenerates the whole mapping, so a compromised epoch does
    /// NOT amplify the next one's compound space; the epoch-scoped
    /// birthday bound is what protects the identifier role.
    ///
    /// The union bound across `secret_lifetime_epochs` still matters
    /// for the operator's "no collision anywhere in the secret's
    /// lifetime" goal.  `AttackerModel::total_collision_margin_bits`
    /// bakes that union bound into the target directly (1 year × 24
    /// epochs/day = 8 760 rotations).
    ///
    /// `target_collision_probability = 1e-6` is calibrated for
    /// obfuscation, not cryptography — a one-in-a-million lifetime
    /// collision is acceptable for a defense-in-depth transformation
    /// whose leak-probability floor comes from other layers (host
    /// secret, sandbox, permission model).  Use
    /// [`paranoid_default`] for the 1e-12 posture that treats
    /// Babbleon as if it were the last line of defense.
    #[must_use]
    pub fn developer_laptop_default() -> Self {
        Self {
            n_events_per_epoch: 2_000,
            target_collision_probability: 1e-6,
            secret_lifetime_epochs: 8_760,
        }
    }

    /// 1e-12-collision-probability variant of
    /// [`developer_laptop_default`], used when the operator wants
    /// the pool math to survive the strictest reasonable threat
    /// (Babbleon is the only obfuscation layer + the attacker sees
    /// every compound + the host secret already leaked).  Under this
    /// preset the provisional-v2 role table does NOT fit in the
    /// 369 652-word English baseline — the tool reports the
    /// shortfall so the operator knows the strict posture demands a
    /// larger corpus (multi-language pool, phase 4).
    #[must_use]
    pub fn paranoid_default() -> Self {
        Self {
            n_events_per_epoch: 2_000,
            target_collision_probability: 1e-12,
            secret_lifetime_epochs: 8_760,
        }
    }

    /// Total distinct compounds an attacker might observe across the
    /// secret's lifetime.  Kept as a report-side metric.  The
    /// per-epoch collision analysis uses `n_events_per_epoch`
    /// directly because each rotation regenerates the mapping and
    /// cross-epoch compounds are independent.
    #[must_use]
    pub fn total_events(&self) -> u64 {
        self.n_events_per_epoch.saturating_mul(self.secret_lifetime_epochs)
    }

    /// Log2 of the acceptable collision probability *per epoch*,
    /// negated so the result is positive.  E.g. `1e-12` per epoch →
    /// `≈ 39.86` bits margin above the birthday-bound event count.
    #[must_use]
    pub fn collision_margin_bits(&self) -> f64 {
        if self.target_collision_probability <= 0.0 {
            // A zero collision probability is unachievable; treat as
            // "as much margin as f64 can express" so the calculator
            // reports the true budget rather than a bogus 0.
            return f64::MAX / 2.0;
        }
        -self.target_collision_probability.log2()
    }

    /// Extra bits demanded by the union bound: the operator wants
    /// the whole lifetime to be collision-free, not just one epoch.
    /// Union bound: `P(any epoch collides) <= lifetime × P(one epoch
    /// collides)`.  Solving for the per-epoch target yields
    /// `+log2(lifetime_epochs)` extra bits.
    #[must_use]
    pub fn union_bound_bits(&self) -> f64 {
        (self.secret_lifetime_epochs.max(1) as f64).log2()
    }

    /// Total bits of margin above the birthday-bound event count.
    /// This is the number added to `2·log2(n_events_per_epoch)` when
    /// deriving a role's target bits.
    #[must_use]
    pub fn total_collision_margin_bits(&self) -> f64 {
        self.collision_margin_bits() + self.union_bound_bits()
    }
}

/// The physical corpus the roles carve pool sizes out of.
///
/// - `size` — total number of words in the on-host wordlist.  If a
///   filter is in play (e.g. `intersect[3,5]` filter from the
///   2026-07-02 wordlist-density session), pass the filtered size.
/// - `baseline_mean_tokens_per_compound` — the measured mean
///   compound token count under the tokenizer of interest.  Used to
///   weight attention cost when a role does not override
///   `tokens_per_compound`.
/// - `tokenizer_label` — free-form label ("cl100k" / "o200k" /
///   "cl100k intersect[3,5]") emitted in reports.
#[derive(Clone, Debug)]
pub struct WordlistModel {
    pub size: usize,
    pub baseline_mean_tokens_per_compound: f64,
    pub tokenizer_label: String,
}

impl WordlistModel {
    /// Baseline (unfiltered) English wordlist under cl100k_base:
    /// 369 652 entries, 11.96 tokens per compound at compound-n=4.
    /// Numbers from `tools/wordlist-density-analysis/RESULTS.md`.
    #[must_use]
    pub fn cl100k_baseline() -> Self {
        Self {
            size: 369_652,
            baseline_mean_tokens_per_compound: 11.96,
            tokenizer_label: "cl100k baseline".into(),
        }
    }

    /// `intersect[3, 5]` filtered wordlist under cl100k_base:
    /// 223 009 entries, 13.80 tokens per compound.  Leading
    /// candidate per HANDOFF 2026-07-02 next-session priorities.
    #[must_use]
    pub fn cl100k_intersect_3_5() -> Self {
        Self {
            size: 223_009,
            baseline_mean_tokens_per_compound: 13.80,
            tokenizer_label: "cl100k intersect[3,5]".into(),
        }
    }
}

impl fmt::Display for WordlistModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (size={}, mean tokens/compound={:.2})",
            self.tokenizer_label, self.size, self.baseline_mean_tokens_per_compound
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{AttackerModel, Role, WordlistModel};

    #[test]
    fn provisional_v2_table_has_all_six_roles() {
        let table = Role::provisional_v2_table();
        assert_eq!(table.len(), 6);
        let names: Vec<&str> = table.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"identifier"));
        assert!(names.contains(&"decoy"));
        assert!(names.contains(&"direction_marker"));
        assert!(names.contains(&"whitespace"));
        assert!(names.contains(&"keyword"));
        assert!(names.contains(&"prompt_injection"));
    }

    #[test]
    fn keyword_role_has_python_reserved_floor() {
        let table = Role::provisional_v2_table();
        let kw = table.iter().find(|r| r.name == "keyword").unwrap();
        // Python has 35 reserved keywords (phase0-research-notes §4)
        assert!(kw.pool_size_floor >= 35);
    }

    #[test]
    fn prompt_injection_uses_fixed_payload_pool() {
        let table = Role::provisional_v2_table();
        let pi = table.iter().find(|r| r.name == "prompt_injection").unwrap();
        assert_eq!(pi.target_bits_override, Some(0.0));
        assert!(pi.pool_size_floor >= 500);
    }

    #[test]
    fn developer_laptop_default_matches_phase0_numbers() {
        let m = AttackerModel::developer_laptop_default();
        assert!(m.n_events_per_epoch >= 2_000);
        assert!(m.target_collision_probability > 0.0);
        assert!(m.target_collision_probability <= 1e-6);
        assert!(m.secret_lifetime_epochs > 0);
    }

    #[test]
    fn paranoid_default_is_stricter_than_laptop_default() {
        let laptop = AttackerModel::developer_laptop_default();
        let paranoid = AttackerModel::paranoid_default();
        assert!(paranoid.target_collision_probability < laptop.target_collision_probability);
        assert!(paranoid.collision_margin_bits() > laptop.collision_margin_bits());
    }

    #[test]
    fn total_events_saturates_on_overflow() {
        let m = AttackerModel {
            n_events_per_epoch: u64::MAX,
            target_collision_probability: 1e-12,
            secret_lifetime_epochs: 2,
        };
        assert_eq!(m.total_events(), u64::MAX);
    }

    #[test]
    fn collision_margin_bits_matches_hand_calc() {
        let m = AttackerModel {
            n_events_per_epoch: 1,
            target_collision_probability: 2f64.powi(-40),
            secret_lifetime_epochs: 1,
        };
        assert!((m.collision_margin_bits() - 40.0).abs() < 1e-9);
    }

    #[test]
    fn collision_margin_bits_is_finite_for_zero_target() {
        let m = AttackerModel {
            n_events_per_epoch: 1,
            target_collision_probability: 0.0,
            secret_lifetime_epochs: 1,
        };
        let margin = m.collision_margin_bits();
        assert!(margin.is_finite());
        assert!(margin > 0.0);
    }

    #[test]
    fn wordlist_display_includes_all_three_fields() {
        let s = format!("{}", WordlistModel::cl100k_intersect_3_5());
        assert!(s.contains("cl100k intersect[3,5]"));
        assert!(s.contains("223009"));
        assert!(s.contains("13.80"));
    }
}
