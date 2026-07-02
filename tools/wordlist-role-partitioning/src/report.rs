//! Text + markdown rendering of an [`AllocationTable`].
//!
//! Two output modes:
//!
//! - `render_text` — human-readable stdout summary; the CLI default.
//! - `render_markdown` — same numbers arranged as a
//!   docs/v2-friendly markdown fragment.  Written to
//!   `--report-out <path>` when the operator wants a snapshot to
//!   drop into a session note.
//!
//! Both renderings answer the same three questions in the same order:
//!
//! 1. What are the inputs (wordlist, attacker model)?
//! 2. What did the allocator return for each role?
//! 3. Does the allocation fit in the wordlist, and if so with how
//!    much headroom?

use crate::allocation::AllocationTable;
use std::fmt::Write as _;

/// Render the allocation table as a plain-text report suitable for
/// stdout.  Output is deterministic given the same inputs.
#[must_use]
pub fn render_text(table: &AllocationTable) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "Babbleon v2 wordlist role-partitioning report");
    let _ = writeln!(out, "==============================================");
    let _ = writeln!(out);
    let _ = writeln!(out, "Wordlist:  {}", table.wordlist);
    let _ = writeln!(
        out,
        "Attacker:  events/epoch={}, lifetime_epochs={}, target_p={:.3e}",
        table.attacker.n_events_per_epoch,
        table.attacker.secret_lifetime_epochs,
        table.attacker.target_collision_probability,
    );
    let _ = writeln!(
        out,
        "           lifetime total events={}, collision margin={:.2} bits",
        table.attacker.total_events(),
        table.attacker.collision_margin_bits(),
    );
    let _ = writeln!(out);

    let _ = writeln!(
        out,
        "  Role                 N     Pool      Target   Achieved   Attn×   p/epoch     p/lifetime"
    );
    let _ = writeln!(
        out,
        "  -------------------  --  ---------  --------  ---------  -----  -----------  -----------"
    );
    for row in &table.rows {
        let _ = writeln!(
            out,
            "  {:<20} {:>2}  {:>9}  {:>7.2}b  {:>8.2}b  {:>4.2}x  {:>11}  {:>11}",
            row.role.name,
            row.role.compound_n,
            row.pool_size,
            row.target_bits,
            row.achieved_bits,
            row.attention_cost_multiplier,
            format_collision(row.collision_probability_per_epoch),
            format_collision(row.collision_probability_lifetime),
        );
    }
    let _ = writeln!(out);

    let total = table.total_pool_size();
    let headroom = table.headroom_words();
    let util = table.utilization_percent();
    let _ = writeln!(
        out,
        "  Total pool:          {total:>9} / {ws} words  ({util:.2}% utilization)",
        ws = table.wordlist.size,
    );
    let verdict = if table.fits() { "FITS" } else { "OVERFLOW" };
    let _ = writeln!(out, "  Verdict:             {verdict}  (headroom={headroom} words)");

    out
}

/// Render the allocation table as a markdown fragment.  Same rows
/// as `render_text`, but table-formatted for drop-in inclusion in
/// `docs/v2/` or a HANDOFF session note.
#[must_use]
pub fn render_markdown(table: &AllocationTable) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Wordlist role-partitioning report");
    let _ = writeln!(out);
    let _ = writeln!(out, "**Wordlist**: {}", table.wordlist);
    let _ = writeln!(
        out,
        "\n**Attacker model**: {} events/epoch, {} lifetime epochs, target collision \
         probability {:.3e} (collision margin {:.2} bits).  Lifetime total events: {}.",
        table.attacker.n_events_per_epoch,
        table.attacker.secret_lifetime_epochs,
        table.attacker.target_collision_probability,
        table.attacker.collision_margin_bits(),
        table.attacker.total_events(),
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "| Role | Compound N | Pool size | Target bits | Achieved bits | Attention× | p/epoch | p/lifetime |"
    );
    let _ = writeln!(
        out,
        "|------|-----------:|----------:|------------:|--------------:|-----------:|--------:|-----------:|"
    );
    for row in &table.rows {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {:.2} | {:.2} | {:.2}× | {} | {} |",
            row.role.name,
            row.role.compound_n,
            row.pool_size,
            row.target_bits,
            row.achieved_bits,
            row.attention_cost_multiplier,
            format_collision(row.collision_probability_per_epoch),
            format_collision(row.collision_probability_lifetime),
        );
    }
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "**Total pool**: {} / {} words ({:.2}% utilization).  Headroom: {} words.  Verdict: **{}**.",
        table.total_pool_size(),
        table.wordlist.size,
        table.utilization_percent(),
        table.headroom_words(),
        if table.fits() { "FITS" } else { "OVERFLOW" },
    );
    out
}

fn format_collision(p: f64) -> String {
    if p == 0.0 {
        "0".into()
    } else if p < 1e-300 {
        // f64 underflow — the compound entropy is so large that the
        // birthday model produces an unrepresentable probability.
        // Report the qualitative fact rather than a bogus 0.
        "<1e-300".into()
    } else {
        format!("{p:.2e}")
    }
}

#[cfg(test)]
mod tests {
    use super::{format_collision, render_markdown, render_text};
    use crate::allocation::AllocationTable;
    use crate::params::{AttackerModel, Role, WordlistModel};

    fn baseline_table() -> AllocationTable {
        AllocationTable::compute(
            &Role::provisional_v2_table(),
            &AttackerModel::developer_laptop_default(),
            &WordlistModel::cl100k_baseline(),
        )
    }

    #[test]
    fn text_report_contains_all_role_names() {
        let out = render_text(&baseline_table());
        for role in Role::provisional_v2_table() {
            assert!(out.contains(&role.name), "missing role {}", role.name);
        }
    }

    #[test]
    fn text_report_shows_fit_verdict() {
        let out = render_text(&baseline_table());
        assert!(out.contains("FITS") || out.contains("OVERFLOW"));
    }

    #[test]
    fn text_report_shows_wordlist_line() {
        let out = render_text(&baseline_table());
        assert!(out.contains("cl100k baseline"));
    }

    #[test]
    fn markdown_report_uses_table_syntax() {
        let out = render_markdown(&baseline_table());
        assert!(out.contains("| Role |"));
        assert!(out.contains("|------|"));
        // Every role emitted as a markdown row.
        for role in Role::provisional_v2_table() {
            assert!(out.contains(&format!("`{}`", role.name)));
        }
    }

    #[test]
    fn markdown_reports_verdict_and_utilization() {
        let out = render_markdown(&baseline_table());
        assert!(out.contains("FITS") || out.contains("OVERFLOW"));
        assert!(out.contains("utilization"));
        assert!(out.contains("Headroom"));
    }

    #[test]
    fn format_collision_handles_zero() {
        assert_eq!(format_collision(0.0), "0");
    }

    #[test]
    fn format_collision_handles_underflow() {
        assert_eq!(format_collision(1e-320), "<1e-300");
    }

    #[test]
    fn format_collision_scientific_for_regular_probabilities() {
        let s = format_collision(1.5e-20);
        assert!(s.contains("e-20"), "got {s}");
    }

}
