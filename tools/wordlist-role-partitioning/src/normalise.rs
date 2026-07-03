//! Optional diacritics-normalisation shim for extractor input.
//!
//! # Why this exists
//!
//! `tools/wordlist-density-analysis` already ships
//! `--normalise-diacritics` so multi-language corpora (`café`,
//! `naïve`, `köln`) can be folded down to the runtime's `[a-z]+`
//! invariant instead of being rejected outright.  The extractor in
//! this crate consumes raw wordlist files the same way the density
//! tool does — one word per line, unioned across `--wordlist-path`
//! sources — so a multi-language source handed to `--extract-to`
//! without this shim would carry diacritics straight into the
//! per-role `.txt` files, which the runtime loader
//! (`crates/v2-babbleon-core::wordlist`) then refuses to load.
//!
//! This module is a deliberate duplicate of
//! `tools/wordlist-density-analysis/src/load.rs::strip_combining_marks`
//! rather than a shared dependency: both tools are standalone
//! workspaces by design (see each crate's `Cargo.toml` comment), and
//! the function is small, pure, and unlikely to drift — the shared-
//! crate alternative would cost a workspace boundary for a dozen
//! lines of NFKD folding.

use unicode_normalization::UnicodeNormalization;

/// NFKD-decompose `w`, drop combining marks, and fold the handful of
/// Latin ligatures Unicode does not decompose on its own (`œ` →
/// `oe`, `æ` → `ae`, `ß` → `ss`, `ø` → `o`, `ð` → `d`, `þ` → `th`).
/// `café` → `cafe`, `naïve` → `naive`, `köln` → `koln`.
#[must_use]
pub fn strip_combining_marks(w: &str) -> String {
    let mut out = String::with_capacity(w.len());
    for c in w.nfkd() {
        if unicode_normalization::char::is_combining_mark(c) {
            continue;
        }
        match c {
            'œ' => out.push_str("oe"),
            'æ' => out.push_str("ae"),
            'ß' => out.push_str("ss"),
            'ø' => out.push('o'),
            'ð' => out.push('d'),
            'þ' => out.push_str("th"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::strip_combining_marks;

    #[test]
    fn ascii_is_a_no_op() {
        assert_eq!(strip_combining_marks("alpha"), "alpha");
    }

    #[test]
    fn strips_accents() {
        assert_eq!(strip_combining_marks("café"), "cafe");
        assert_eq!(strip_combining_marks("naïve"), "naive");
        assert_eq!(strip_combining_marks("köln"), "koln");
    }

    #[test]
    fn folds_common_ligatures() {
        assert_eq!(strip_combining_marks("cœur"), "coeur");
        assert_eq!(strip_combining_marks("æther"), "aether");
        assert_eq!(strip_combining_marks("groß"), "gross");
        assert_eq!(strip_combining_marks("bjørn"), "bjorn");
    }
}
