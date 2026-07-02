//! Role-to-pool allocation.
//!
//! # What this does
//!
//! Takes the three inputs from [`crate::params`] and produces one
//! [`Allocation`] per role: the pool size the role needs, the
//! achieved entropy per compound, and how much attention cost each
//! compound imposes on the attacker.  The full run is packaged as
//! an [`AllocationTable`] which also carries the disjoint-fit
//! verdict — does the sum of per-role pools fit inside the wordlist?
//!
//! # The formula (derivation)
//!
//! For each role:
//!
//! 1. Compute the target bit budget:
//!    ```text
//!    H_role_target = 2·log2(N_events_per_epoch)
//!                  + collision_margin_bits
//!                  + log2(secret_lifetime_epochs)
//!    ```
//!    The first term is the birthday bound (with `N` compound
//!    observations uniform over a `2^H`-sized space, the per-epoch
//!    collision probability `≈ N²/2^(H+1)`).  The `collision_margin`
//!    bakes in the operator's acceptable per-epoch collision
//!    probability (`= -log2(target_p)`).  The last term is the
//!    union bound: making the *lifetime* collision-free needs
//!    `log2(lifetime_epochs)` extra bits so the per-epoch
//!    probability, multiplied by the number of epochs, still sits
//!    below the target.  Every rotation regenerates the mapping,
//!    so cross-epoch compounds are independent — this is why
//!    events are not summed across epochs.  Roles that override
//!    this budget (`prompt_injection`) use their override; roles
//!    with an intrinsically small compound space (`keyword` at
//!    compound_n=1) will show `achieved < target` — a real
//!    invariant the operator must accept, not a bug.
//!
//! 2. Solve for pool size at the role's compound-N:
//!    ```text
//!    P_role_needed = ceil(2^(H_role_target / N_role))
//!    ```
//!    which is the smallest pool that meets the target under
//!    with-replacement draws.
//!
//! 3. Take `max(P_role_needed, pool_size_floor)` so external
//!    constraints (Python keyword count, garak payload count) are
//!    honored.
//!
//! 4. Report the *achieved* entropy at the chosen pool size, plus
//!    the attention-cost multiplier vs the wordlist's baseline
//!    tokens-per-compound.  When the achieved entropy is below the
//!    target (compound_n=1 with a small pool floor), the collision
//!    probability field surfaces the shortfall directly.
//!
//! # Disjoint fit
//!
//! The allocation is disjoint by role by design (phase0-research-
//! notes §11: "disjoint subsets per role per epoch prevents leakage
//! between roles").  The table's `fits` verdict simply checks
//! `sum(pool_sizes) <= wordlist.size` and reports the utilization
//! percentage so the operator can see how much headroom remains.

use crate::entropy::{
    attention_cost_multiplier, birthday_collision_probability, compound_entropy_bits,
    required_pool_size,
};
use crate::params::{AttackerModel, EntropyModel, Role, WordlistModel};

/// One row of the allocation table.
///
/// `collision_probability_per_epoch` is the per-epoch birthday-bound
/// value.  `collision_probability_lifetime` is the union bound over
/// `secret_lifetime_epochs` and is the number the operator compares
/// against `AttackerModel::target_collision_probability`.
#[derive(Clone, Debug)]
pub struct Allocation {
    pub role: Role,
    pub target_bits: f64,
    pub pool_size: usize,
    pub achieved_bits: f64,
    pub attention_cost_multiplier: f64,
    pub collision_probability_per_epoch: f64,
    pub collision_probability_lifetime: f64,
}

/// The full allocation across a role table + attacker + wordlist.
#[derive(Debug)]
pub struct AllocationTable {
    pub wordlist: WordlistModel,
    pub attacker: AttackerModel,
    pub rows: Vec<Allocation>,
}

impl AllocationTable {
    /// Compute the full table.  Total order preserves the input
    /// order of `roles`.
    #[must_use]
    pub fn compute(
        roles: &[Role],
        attacker: &AttackerModel,
        wordlist: &WordlistModel,
    ) -> Self {
        let rows = roles
            .iter()
            .map(|role| allocate_role(role, attacker, wordlist))
            .collect();
        Self {
            wordlist: wordlist.clone(),
            attacker: attacker.clone(),
            rows,
        }
    }

    /// Sum of per-role pool sizes.  Saturates at `usize::MAX` if the
    /// individual role pools sum past that — happens only when one
    /// role uses Birthday mode at compound_n=1 with an aggressive
    /// event count, which is already a "this configuration is
    /// infeasible" verdict.
    #[must_use]
    pub fn total_pool_size(&self) -> usize {
        self.rows
            .iter()
            .map(|r| r.pool_size)
            .fold(0usize, |acc, x| acc.saturating_add(x))
    }

    /// Percentage of the wordlist consumed by the allocation.
    /// `100.0 * total_pool_size() / wordlist.size`.  Returns `f64::INFINITY`
    /// if the wordlist is empty (should never happen for a real
    /// wordlist but keeps the report code branch-free).
    #[must_use]
    pub fn utilization_percent(&self) -> f64 {
        if self.wordlist.size == 0 {
            return f64::INFINITY;
        }
        100.0 * (self.total_pool_size() as f64) / (self.wordlist.size as f64)
    }

    /// True iff every role's pool fits inside the wordlist with room
    /// for the others.
    #[must_use]
    pub fn fits(&self) -> bool {
        self.total_pool_size() <= self.wordlist.size
    }

    /// How many words remain unused after the allocation.  Signed
    /// so an over-allocation is visible in the report as a negative
    /// number without saturating at zero.  Saturates at `i64::MIN /
    /// i64::MAX` on extreme inputs (Birthday-mode at compound_n=1
    /// with huge event counts) rather than wrapping.
    #[must_use]
    pub fn headroom_words(&self) -> i64 {
        let ws = i64::try_from(self.wordlist.size).unwrap_or(i64::MAX);
        let total = i64::try_from(self.total_pool_size()).unwrap_or(i64::MAX);
        ws.saturating_sub(total)
    }
}

fn allocate_role(role: &Role, attacker: &AttackerModel, wordlist: &WordlistModel) -> Allocation {
    let effective_events = role
        .events_per_epoch_override
        .unwrap_or(attacker.n_events_per_epoch);
    let effective_attacker = AttackerModel {
        n_events_per_epoch: effective_events,
        target_collision_probability: attacker.target_collision_probability,
        secret_lifetime_epochs: attacker.secret_lifetime_epochs,
    };
    let target_bits = role.target_bits_override.unwrap_or_else(|| match role.entropy_model {
        EntropyModel::Birthday => derive_birthday_target_bits(&effective_attacker),
        EntropyModel::Uniqueness => derive_uniqueness_target_bits(
            effective_events,
            role.alias_count.max(1),
            role.uniqueness_safety_factor.max(1),
        ),
    });

    let derived_pool = if target_bits <= 0.0 {
        // A role with zero entropy target does not derive its pool
        // from entropy at all (prompt injection is the canonical
        // case); the floor is authoritative.
        0
    } else {
        required_pool_size(target_bits, role.compound_n)
    };
    let pool_size = derived_pool.max(role.pool_size_floor).max(1);
    let achieved_bits = compound_entropy_bits(pool_size, role.compound_n);

    let role_tokens = role.tokens_per_compound.unwrap_or(
        wordlist.baseline_mean_tokens_per_compound,
    );
    let multiplier =
        attention_cost_multiplier(role_tokens, wordlist.baseline_mean_tokens_per_compound);

    let p_epoch = birthday_collision_probability(achieved_bits, effective_events);
    // Union bound over the lifetime.  Clamped in
    // `birthday_collision_probability`, but we clamp again after
    // multiplying by the lifetime count.
    let p_lifetime =
        (p_epoch * (attacker.secret_lifetime_epochs as f64)).min(1.0);

    Allocation {
        role: role.clone(),
        target_bits,
        pool_size,
        achieved_bits,
        attention_cost_multiplier: multiplier,
        collision_probability_per_epoch: p_epoch,
        collision_probability_lifetime: p_lifetime,
    }
}

fn derive_birthday_target_bits(attacker: &AttackerModel) -> f64 {
    let n = attacker.n_events_per_epoch.max(1) as f64;
    // Birthday-bound requirement per epoch (2·log2(N)), plus the
    // per-epoch collision margin, plus the union bound over the
    // secret's lifetime so the operator's probability applies to
    // the whole lifetime rather than to one epoch.
    2.0 * n.log2() + attacker.total_collision_margin_bits()
}

fn derive_uniqueness_target_bits(
    events: u64,
    alias_count: usize,
    safety_factor: usize,
) -> f64 {
    // A bijective permutation from (source, alias_index) into the
    // compound space needs `pool^N >= events × alias_count`.  Add
    // `safety_factor` bits so an operator has some slack for the
    // rare-event tail (e.g. a specialty codebase exposing more
    // events per epoch than the model assumes).
    let base = (events.max(1) as f64) * (alias_count as f64);
    (base * (safety_factor as f64)).log2().max(0.0)
}

#[cfg(test)]
mod tests {
    use super::{
        allocate_role, derive_birthday_target_bits, derive_uniqueness_target_bits, AllocationTable,
    };
    use crate::params::{AttackerModel, EntropyModel, Role, WordlistModel};

    fn identifier_role() -> Role {
        Role {
            name: "identifier".into(),
            compound_n: 4,
            entropy_model: EntropyModel::Birthday,
            alias_count: 5,
            uniqueness_safety_factor: 4,
            target_bits_override: None,
            tokens_per_compound: None,
            pool_size_floor: 0,
            events_per_epoch_override: Some(2_000),
        }
    }

    #[test]
    fn identifier_pool_fits_baseline_wordlist_under_default_attacker() {
        // Under the developer-laptop default (2 000 events/epoch,
        // 1e-12 collision probability, 8 760-epoch lifetime) the
        // identifier role at compound_n=4 needs a pool that is
        // well below the 369 652-word baseline.  The concrete
        // number will shift when defaults change; the invariant is
        // "identifier fits in the baseline with margin".
        let table = AllocationTable::compute(
            &[identifier_role()],
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        let row = &table.rows[0];
        assert!(row.pool_size >= 1_000, "pool too small: {}", row.pool_size);
        assert!(
            row.pool_size <= WordlistModel::cl100k_baseline().size,
            "pool exceeds wordlist: {} > {}",
            row.pool_size,
            WordlistModel::cl100k_baseline().size,
        );
        // The provisional-v2 §11 table pinned identifier at 370 k;
        // the calculator should be strictly lower (proving the
        // provisional table was conservative — the useful design
        // signal this tool exists to surface).
        assert!(row.pool_size < 370_000);
    }

    #[test]
    fn prompt_injection_role_ignores_derived_bits() {
        let role = Role {
            name: "prompt_injection".into(),
            compound_n: 1,
            entropy_model: EntropyModel::Uniqueness,
            alias_count: 1,
            uniqueness_safety_factor: 1,
            target_bits_override: Some(0.0),
            tokens_per_compound: None,
            pool_size_floor: 500,
            events_per_epoch_override: Some(5),
        };
        let alloc = allocate_role(
            &role,
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        assert_eq!(alloc.pool_size, 500);
    }

    #[test]
    fn keyword_role_respects_python_floor() {
        let role = Role {
            name: "keyword".into(),
            compound_n: 1,
            entropy_model: EntropyModel::Uniqueness,
            alias_count: 5,
            uniqueness_safety_factor: 4,
            target_bits_override: None,
            tokens_per_compound: None,
            pool_size_floor: 35,
            events_per_epoch_override: Some(35),
        };
        let alloc = allocate_role(
            &role,
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        assert!(alloc.pool_size >= 35);
    }

    #[test]
    fn provisional_table_fits_baseline_under_laptop_default() {
        // With the identifier role in Birthday mode and the
        // permutation-driven roles (whitespace, keyword,
        // prompt_injection) in Uniqueness mode, the provisional-v2
        // table fits comfortably in the 369 652-word baseline.
        let table = AllocationTable::compute(
            &Role::provisional_v2_table(),
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        assert!(
            table.fits(),
            "unexpected overflow: total {} > wordlist {}",
            table.total_pool_size(),
            table.wordlist.size,
        );
        assert!(table.headroom_words() > 0);
    }

    #[test]
    fn every_role_meets_or_exceeds_its_entropy_target() {
        // Every role (regardless of Birthday/Uniqueness mode) must
        // meet the target its own model derived.  Roles that use
        // `target_bits_override = Some(0.0)` (prompt_injection) are
        // excused because they pin the pool via the floor instead.
        let table = AllocationTable::compute(
            &Role::provisional_v2_table(),
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        for row in &table.rows {
            if row.role.target_bits_override == Some(0.0) {
                continue;
            }
            assert!(
                row.achieved_bits >= row.target_bits - 1e-9,
                "role {} achieved {} < target {}",
                row.role.name,
                row.achieved_bits,
                row.target_bits,
            );
        }
    }

    #[test]
    fn birthday_roles_meet_collision_target() {
        // Birthday-mode roles must meet the operator's lifetime
        // collision target.  Uniqueness-mode roles have a
        // permutation guarantee (accidental collisions impossible
        // within a mapping) so their probabilistic-collision
        // number is defined but not meaningful — skip them here.
        let attacker = AttackerModel::developer_laptop_default();
        let table = AllocationTable::compute(
            &Role::provisional_v2_table(),
            &attacker,
            &WordlistModel::cl100k_baseline(),
        );
        for row in &table.rows {
            if row.role.entropy_model != EntropyModel::Birthday {
                continue;
            }
            if row.role.target_bits_override == Some(0.0) {
                continue;
            }
            assert!(
                row.collision_probability_lifetime <= attacker.target_collision_probability,
                "role {} lifetime collision {} > threshold {}",
                row.role.name,
                row.collision_probability_lifetime,
                attacker.target_collision_probability,
            );
        }
    }

    #[test]
    fn keyword_under_birthday_mode_flags_infeasibility() {
        // Under Birthday mode (over-conservative for a bijective
        // permutation) the keyword role at compound_n=1 blows up:
        // pool_size saturates far past the wordlist.  This test
        // proves the tool surfaces the infeasibility instead of
        // silently pretending it fits.  Uniqueness mode is the
        // correct default (checked in `provisional_table_fits_...`).
        let role = Role {
            name: "keyword".into(),
            compound_n: 1,
            entropy_model: EntropyModel::Birthday,
            alias_count: 5,
            uniqueness_safety_factor: 4,
            target_bits_override: None,
            tokens_per_compound: None,
            pool_size_floor: 35,
            events_per_epoch_override: Some(35),
        };
        let table = AllocationTable::compute(
            &[role],
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        let kw = &table.rows[0];
        assert!(
            kw.pool_size > WordlistModel::cl100k_baseline().size,
            "birthday-mode keyword should demand more than the wordlist provides; got pool {}",
            kw.pool_size,
        );
        assert!(!table.fits());
    }

    #[test]
    fn keyword_under_uniqueness_mode_fits() {
        let table = AllocationTable::compute(
            &Role::provisional_v2_table(),
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        let kw = table
            .rows
            .iter()
            .find(|r| r.role.name == "keyword")
            .expect("keyword role missing");
        // Uniqueness mode with events=35, alias=5, safety=4 →
        // target = log2(35 * 5 * 4) = log2(700) ≈ 9.45 bits →
        // pool = 700 (well under the wordlist).
        assert!(kw.pool_size < 10_000, "keyword pool too large: {}", kw.pool_size);
    }

    #[test]
    fn intersect_3_5_filter_bumps_attention_multiplier() {
        let table = AllocationTable::compute(
            &[identifier_role()],
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_intersect_3_5(),
        );
        let row = &table.rows[0];
        // 13.80 / 11.96 → the filter itself is baseline in this
        // WordlistModel, so multiplier is 1.0 (attention is measured
        // vs the *chosen* wordlist's baseline).  A downstream user
        // supplies role.tokens_per_compound if they want to compare
        // against the unfiltered baseline; check the identity path.
        assert!((row.attention_cost_multiplier - 1.0).abs() < 1e-9);
    }

    #[test]
    fn override_role_tokens_produces_expected_multiplier() {
        let role = Role {
            name: "identifier".into(),
            compound_n: 4,
            entropy_model: EntropyModel::Birthday,
            alias_count: 5,
            uniqueness_safety_factor: 4,
            target_bits_override: None,
            // Pretend this role runs on the intersect[3,5] filter
            // while the wordlist model tracks the unfiltered
            // baseline: the multiplier should be (13.80/11.96)^2.
            tokens_per_compound: Some(13.80),
            pool_size_floor: 0,
            events_per_epoch_override: Some(2_000),
        };
        let alloc = allocate_role(
            &role,
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        let expected = (13.80f64 / 11.96).powi(2);
        assert!(
            (alloc.attention_cost_multiplier - expected).abs() < 1e-6,
            "got {}, expected {}",
            alloc.attention_cost_multiplier,
            expected,
        );
    }

    #[test]
    fn utilization_percent_reflects_pool_sum() {
        let table = AllocationTable::compute(
            &Role::provisional_v2_table(),
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        let expected = 100.0 * (table.total_pool_size() as f64)
            / (table.wordlist.size as f64);
        assert!((table.utilization_percent() - expected).abs() < 1e-9);
    }

    #[test]
    fn paranoid_default_overflows_baseline_wordlist() {
        // Documented behavior: the 1e-12 posture is deliberately
        // stricter than what the baseline wordlist supports.  The
        // tool reports the shortfall so the operator can decide to
        // (a) loosen the collision probability, (b) shrink compound
        // N, or (c) grow the corpus (phase-4 multi-language pool).
        let table = AllocationTable::compute(
            &Role::provisional_v2_table(),
            &AttackerModel::paranoid_default(),
            &WordlistModel::cl100k_baseline(),
        );
        assert!(!table.fits(), "paranoid preset unexpectedly fits");
    }

    #[test]
    fn tiny_wordlist_flags_overflow() {
        // Wordlist of 100 words cannot host the provisional table
        // (identifier alone at compound_n=4 needs ~4-5 k words even
        // under the most relaxed defaults).
        let mut wordlist = WordlistModel::cl100k_baseline();
        wordlist.size = 100;
        let table = AllocationTable::compute(
            &Role::provisional_v2_table(),
            &AttackerModel::developer_laptop_default(),
            &wordlist,
        );
        assert!(!table.fits());
        assert!(table.headroom_words() < 0);
    }

    #[test]
    fn derive_target_bits_grows_with_events() {
        let base = derive_birthday_target_bits(&AttackerModel::developer_laptop_default());
        let heavier = derive_birthday_target_bits(&AttackerModel {
            n_events_per_epoch: 800_000,
            target_collision_probability: 1e-12,
            secret_lifetime_epochs: 8_760,
        });
        assert!(heavier > base);
    }

    #[test]
    fn derive_target_bits_grows_with_lifetime() {
        let short = derive_birthday_target_bits(&AttackerModel {
            n_events_per_epoch: 2_000,
            target_collision_probability: 1e-12,
            secret_lifetime_epochs: 24,
        });
        let long = derive_birthday_target_bits(&AttackerModel {
            n_events_per_epoch: 2_000,
            target_collision_probability: 1e-12,
            secret_lifetime_epochs: 8_760,
        });
        // Longer lifetime → tighter per-epoch probability →
        // more bits demanded.  Difference should be exactly
        // log2(8760/24) ≈ 8.51 bits.
        let expected_delta = (8_760f64 / 24f64).log2();
        assert!(
            (long - short - expected_delta).abs() < 1e-9,
            "delta {} != expected {}",
            long - short,
            expected_delta,
        );
    }

    #[test]
    fn derive_uniqueness_target_bits_matches_hand_calc() {
        // events=35, alias=5, safety=4 → log2(35*5*4) = log2(700)
        let t = derive_uniqueness_target_bits(35, 5, 4);
        assert!((t - 700f64.log2()).abs() < 1e-9, "got {t}");
    }

    #[test]
    fn derive_uniqueness_target_bits_grows_with_alias_count() {
        let low = derive_uniqueness_target_bits(35, 1, 4);
        let high = derive_uniqueness_target_bits(35, 5, 4);
        assert!(high > low);
    }

    #[test]
    fn derive_uniqueness_target_bits_never_negative() {
        // Zero events shouldn't produce -inf / NaN.
        let t = derive_uniqueness_target_bits(0, 1, 1);
        assert!(t >= 0.0);
    }

    #[test]
    fn compound_n_one_role_uses_pool_directly() {
        let role = Role {
            name: "keyword".into(),
            compound_n: 1,
            entropy_model: EntropyModel::Uniqueness,
            alias_count: 5,
            uniqueness_safety_factor: 4,
            target_bits_override: Some(20.0),
            tokens_per_compound: None,
            pool_size_floor: 0,
            events_per_epoch_override: None,
        };
        let alloc = allocate_role(
            &role,
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        );
        // 20 bits of entropy at compound-n=1 requires pool >= 2^20 = 1 048 576.
        assert!(alloc.pool_size >= 1_048_576);
    }
}
