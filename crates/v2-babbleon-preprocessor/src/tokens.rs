//! Abstract token IR shared by tokenizer, scrambler, and unscrambler.
//!
//! # Infrastructure module
//!
//! No specific attack is defeated here.  This module exists so the
//! tokenizer (which decides what is whitespace vs. what is a code
//! token) is replaceable independently of the scramble / unscramble
//! logic.  Phase-3 MVP uses `python_tokenizer::tokenize`; future
//! phases can swap in `rustpython-parser`, `tree-sitter-python`, or
//! a per-language tokenizer family without touching scramble code.
//!
//! # IR shape
//!
//! A source file is a `Vec<Token>`.  Each `Token` is one of:
//!
//! - `Whitespace(WhitespaceKind)` — a marker for one of the five
//!   whitespace classes (`Newline`, `Space`, `Tab`, `IndentOpen`,
//!   `IndentClose`).  In scrambled form, every whitespace marker is
//!   replaced by the per-epoch wordlist compound assigned to its
//!   kind.
//! - `Word(String)` — a contiguous non-whitespace byte run.  The
//!   string holds the original bytes verbatim; the scrambler does
//!   not transform them in layer 3.
//!
//! Layer 3 deliberately treats `Word`s as opaque: layers 1 (identifier
//! scramble), 2 (operator scramble), 4 (chunk reorder) and 5 (decoy
//! injection) each compose their own `Token` rewrite passes on top.
//!
//! # Indent semantics
//!
//! `IndentOpen` and `IndentClose` appear at logical-line boundaries.
//! The convention is:
//!
//! - When the next non-blank line's indent level is strictly
//!   greater than the previous's, the tokenizer emits one
//!   `IndentOpen` per level increase.
//! - When strictly less, one `IndentClose` per level decrease.
//! - When equal, no indent marker — `Newline` is enough.
//!
//! The unscrambler tracks a running indent level and re-emits four
//! spaces per level at each new line.  Tabs in the original source
//! are preserved as `Whitespace(Tab)` tokens but the canonical
//! re-emission uses spaces, matching PEP 8.

use std::fmt;

/// Five whitespace classes the layer-3 scramble treats as
/// independent compound slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WhitespaceKind {
    /// A logical line terminator (`\n`).  CRLF is normalised to a
    /// single `Newline` by the tokenizer.
    Newline,
    /// A single intra-line space.  Runs of spaces collapse to one
    /// `Space` token at scramble time, matching how the
    /// unscrambler emits them.
    Space,
    /// A literal tab (`\t`).  Distinct from `Space` for parity with
    /// languages that treat the two differently; Python source is
    /// expected to be space-indented per PEP 8 but tabs are
    /// preserved as-tokenized.
    Tab,
    /// Beginning of an indented block.  Emitted at the start of a
    /// logical line whose indent level exceeds the previous
    /// logical line's.
    IndentOpen,
    /// End of an indented block.  Emitted at the start of a logical
    /// line whose indent level is below the previous's.
    IndentClose,
}

impl WhitespaceKind {
    /// All five kinds in canonical iteration order.
    ///
    /// Useful for callers that need to enumerate every class once
    /// (whitespace-wordlist derivation, debug pretty-printing).
    /// Order is fixed by the wordlist derivation; reordering this
    /// constant changes the scramble output for every existing
    /// epoch and is a wire-format break.
    pub const ALL: [Self; 5] = [
        Self::Newline,
        Self::Space,
        Self::Tab,
        Self::IndentOpen,
        Self::IndentClose,
    ];

    /// Zero-based index of this kind in `ALL`, matching the
    /// wordlist-derivation slot.
    #[must_use]
    pub const fn slot(self) -> usize {
        match self {
            Self::Newline => 0,
            Self::Space => 1,
            Self::Tab => 2,
            Self::IndentOpen => 3,
            Self::IndentClose => 4,
        }
    }
}

impl fmt::Display for WhitespaceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Newline => "newline",
            Self::Space => "space",
            Self::Tab => "tab",
            Self::IndentOpen => "indent-open",
            Self::IndentClose => "indent-close",
        };
        f.write_str(name)
    }
}

/// A single token in the layer-3 IR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A whitespace marker; scrambled form is the per-epoch
    /// wordlist compound for `kind`.
    Whitespace(WhitespaceKind),
    /// A contiguous non-whitespace byte run; passed through
    /// untransformed in layer 3.
    Word(String),
}

impl Token {
    /// Convenience constructor for `Token::Word`.
    #[must_use]
    pub fn word<S: Into<String>>(s: S) -> Self {
        Self::Word(s.into())
    }

    /// Convenience constructor for `Token::Whitespace`.
    #[must_use]
    pub const fn whitespace(kind: WhitespaceKind) -> Self {
        Self::Whitespace(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::{Token, WhitespaceKind};

    #[test]
    fn all_kinds_match_slot_indices() {
        for (i, kind) in WhitespaceKind::ALL.iter().enumerate() {
            assert_eq!(kind.slot(), i);
        }
    }

    #[test]
    fn all_kinds_are_distinct() {
        let mut sorted: Vec<_> = WhitespaceKind::ALL.to_vec();
        sorted.sort_by_key(|k| k.slot());
        sorted.dedup();
        assert_eq!(sorted.len(), 5);
    }

    #[test]
    fn token_constructors_round_trip() {
        let w = Token::word("foo");
        assert_eq!(w, Token::Word("foo".to_string()));
        let s = Token::whitespace(WhitespaceKind::Space);
        assert_eq!(s, Token::Whitespace(WhitespaceKind::Space));
    }

    #[test]
    fn display_names_are_stable() {
        assert_eq!(WhitespaceKind::Newline.to_string(), "newline");
        assert_eq!(WhitespaceKind::Space.to_string(), "space");
        assert_eq!(WhitespaceKind::Tab.to_string(), "tab");
        assert_eq!(WhitespaceKind::IndentOpen.to_string(), "indent-open");
        assert_eq!(WhitespaceKind::IndentClose.to_string(), "indent-close");
    }
}
