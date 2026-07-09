//! Minimal Python tokenizer for the phase-3 MVP.
//!
//! # Infrastructure module
//!
//! No specific attack is defeated here; this is the source-side
//! pre-pass that produces the `Token` IR scramble / unscramble
//! operate on.  The tokenizer is *replaceable* — future commits may
//! swap in `rustpython-parser`, `tree-sitter-python`, or a
//! per-language tokenizer family without touching this crate's
//! scramble or unscramble code, as long as the replacement preserves
//! the round-trip invariant in `MVP_INVARIANT` below.
//!
//! # MVP invariant
//!
//! For every input `source` in the **MVP-supported subset** (see
//! `MVP_LIMITATIONS`), the round-trip
//!
//! ```text
//! unscramble(scramble(tokenize(source), wl), wl)
//! ```
//!
//! produces a byte-identical reconstruction of `source` modulo:
//!
//! - trailing newline normalization (a final newline that may or may
//!   not exist in the input is reflected in the output),
//! - canonical indent re-emission (the unscrambler emits four spaces
//!   per indent level regardless of the input's original indent
//!   characters).
//!
//! Within those normalizations, the reconstruction is exact.
//!
//! # `MVP_LIMITATIONS` (read before extending)
//!
//! 1. **Multi-line triple-quoted strings ARE preserved, as a single
//!    opaque `Word` token.**  `"""..."""` / `'''...'''` spanning any
//!    number of newlines is scanned as one contiguous run (escape-
//!    aware, nested-quote-aware) and kept as one `Token::Word` whose
//!    content includes the embedded `\n` characters and each
//!    continuation line's original leading whitespace verbatim.  No
//!    indent-transition or whitespace tokens are emitted for lines
//!    *inside* the triple-quoted run — see `tokenize_body_char` and
//!    its `TripleSingle`/`TripleDouble` arms — which is what keeps
//!    the string's interior formatting byte-exact through
//!    `tokens_to_source`'s per-line indent re-emission (that
//!    machinery only fires on `Newline`-token boundaries, and none
//!    are emitted mid-string). An *unterminated* triple-quoted
//!    string (invalid Python) is flushed as one `Word` at EOF,
//!    consistent with limitation 6 (no validation). Single/double
//!    quoted strings still do NOT span raw newlines (matches real
//!    Python — an un-escaped newline inside `'...'`/`"..."` is a
//!    `SyntaxError`); hitting one flushes the partial word and
//!    resumes fresh at the next line, same as before this was fixed.
//! 2. **Mixed-width indent's level component is normalized to four
//!    spaces per level; residuals are preserved verbatim.**  A line
//!    with seven leading spaces decomposes to one level (`4 / 4`)
//!    plus three residual `Space` tokens; on re-emission the
//!    level fires `INDENT_WIDTH` spaces and the three residuals
//!    follow, recovering seven leading spaces total.  A tab-
//!    indented line re-emits the level as four spaces (tabs are
//!    canonicalised); residual spaces after the tab survive.
//! 3. **Operators are not split from adjacent identifiers.**  `x+y`
//!    is one `Word("x+y")`, not three tokens.  Layer-3-only this
//!    is fine; layers 1 and 2 will eventually need a richer
//!    tokenizer.
//! 4. **f-string interpolations are treated as opaque string
//!    bodies.**  `f"hello {name}"` becomes one `Word`; the
//!    `{name}` interior is preserved literally but not tokenized.
//!    Spaces inside the interpolation survive verbatim because the
//!    whole f-string is a single `Word`.  A triple-quoted f-string
//!    (`f"""..."""`) gets the same multi-line handling as any other
//!    triple-quoted string per limitation 1.
//! 5. **Trailing whitespace on a line is preserved.**  Lines with
//!    only whitespace produce only `Whitespace` tokens; this is
//!    fine for round-trip.
//! 6. **The tokenizer does NOT validate Python.**  Syntax errors
//!    pass through unchanged.  A scrambled invalid program is
//!    still an invalid program after unscramble.

use crate::tokens::{Token, WhitespaceKind};

/// Number of spaces per indent level the unscrambler re-emits.
///
/// Matches PEP 8.  Bumping requires re-deriving every example
/// test fixture; not a knob the operator turns at runtime.
pub const INDENT_WIDTH: usize = 4;

/// Per-line lexer state for the character-by-character walk.
///
/// `TripleSingle`/`TripleDouble` are the only variants that persist
/// across a raw `\n` — see `MVP_LIMITATIONS` #1 (module docs).  Every
/// other state treats an unescaped `\n` as "flush and start a fresh
/// logical line," matching how the pre-fix line-split design worked.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    /// At the start of a logical line: about to measure indent.
    LineStart,
    /// Outside any string or comment.
    Code,
    /// Inside a `'...'` string literal (single-line only).
    SingleQuote,
    /// Inside a `"..."` string literal (single-line only).
    DoubleQuote,
    /// Inside a `'''...'''` string literal (spans newlines).
    TripleSingle,
    /// Inside a `"""..."""` string literal (spans newlines).
    TripleDouble,
    /// Inside a `#...` comment; everything to EOL is one word.
    Comment,
}

/// Tokenize a Python source string into the layer-3 IR.
///
/// See `MVP_LIMITATIONS` (module docs) for the supported subset.
#[must_use]
pub fn tokenize(source: &str) -> Vec<Token> {
    let chars: Vec<char> = source.chars().collect();
    let n = chars.len();
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut prev_level: usize = 0;
    let mut state = State::LineStart;
    let mut i = 0usize;

    while i < n {
        match state {
            State::LineStart => {
                i = tokenize_line_start(&chars, i, &mut prev_level, &mut tokens, &mut state);
            }
            _ => {
                i = tokenize_body_char(&chars, i, &mut word, &mut tokens, &mut state);
            }
        }
    }

    // EOF while mid-word (including an unterminated string/comment —
    // limitation 6, no validation) flushes whatever was accumulated.
    flush_word(&mut word, &mut tokens);

    // Close any indents still open at EOF.
    while prev_level > 0 {
        tokens.push(Token::whitespace(WhitespaceKind::IndentClose));
        prev_level -= 1;
    }

    tokens
}

/// Handle the `State::LineStart` case: measure leading indent,
/// decide blank vs. content, and transition to `Code` (or stay in
/// `LineStart` after consuming a fully blank line).
///
/// Returns the new cursor position; mutates `prev_level`, `tokens`,
/// and `state` in place.
fn tokenize_line_start(
    chars: &[char],
    i: usize,
    prev_level: &mut usize,
    tokens: &mut Vec<Token>,
    state: &mut State,
) -> usize {
    let start = i;
    let mut i = i;
    while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
        i += 1;
    }
    let is_blank_line = i >= chars.len() || chars[i] == '\n';

    if is_blank_line {
        // Blank line: emit the leading whitespace verbatim (rare for
        // valid Python; harmless for round-trip).  Indent level is
        // untouched — blank lines don't change Python's logical
        // indent structure.
        for &ch in &chars[start..i] {
            tokens.push(whitespace_for_char(ch));
        }
        if i < chars.len() {
            // chars[i] == '\n'
            tokens.push(Token::whitespace(WhitespaceKind::Newline));
            i += 1;
        }
        *state = State::LineStart;
    } else {
        let (level, residual_spaces) = indent_level(&chars[start..i]);
        emit_indent_transition(*prev_level, level, tokens);
        for _ in 0..residual_spaces {
            tokens.push(Token::whitespace(WhitespaceKind::Space));
        }
        *prev_level = level;
        *state = State::Code;
    }
    i
}

/// Handle one character while inside `Code`, `SingleQuote`,
/// `DoubleQuote`, `TripleSingle`, `TripleDouble`, or `Comment`.
///
/// Returns the new cursor position; mutates `word`, `tokens`, and
/// `state` in place.
fn tokenize_body_char(
    chars: &[char],
    i: usize,
    word: &mut String,
    tokens: &mut Vec<Token>,
    state: &mut State,
) -> usize {
    let ch = chars[i];

    // Every state except the two triple-quote states treats a raw
    // newline as "flush the current word, emit Newline, start a
    // fresh logical line" — this is the line-boundary behavior the
    // pre-fix design got for free by re-splitting on '\n' and
    // resetting state every line.  Triple-quoted strings are the
    // one case that must carry `word` and `state` across the
    // newline instead (MVP_LIMITATIONS #1).
    if ch == '\n' && !matches!(state, State::TripleSingle | State::TripleDouble) {
        flush_word(word, tokens);
        tokens.push(Token::whitespace(WhitespaceKind::Newline));
        *state = State::LineStart;
        return i + 1;
    }

    match *state {
        State::LineStart => unreachable!("caller dispatches LineStart separately"),
        State::Code => match ch {
            ' ' => {
                flush_word(word, tokens);
                tokens.push(Token::whitespace(WhitespaceKind::Space));
                i + 1
            }
            '\t' => {
                flush_word(word, tokens);
                tokens.push(Token::whitespace(WhitespaceKind::Tab));
                i + 1
            }
            '#' => {
                word.push(ch);
                *state = State::Comment;
                i + 1
            }
            '"' if starts_triple(chars, i, '"') => {
                word.push_str("\"\"\"");
                *state = State::TripleDouble;
                i + 3
            }
            '\'' if starts_triple(chars, i, '\'') => {
                word.push_str("'''");
                *state = State::TripleSingle;
                i + 3
            }
            '"' => {
                word.push(ch);
                *state = State::DoubleQuote;
                i + 1
            }
            '\'' => {
                word.push(ch);
                *state = State::SingleQuote;
                i + 1
            }
            _ => {
                word.push(ch);
                i + 1
            }
        },
        State::Comment => {
            word.push(ch);
            i + 1
        }
        State::SingleQuote | State::DoubleQuote => {
            let closing = if *state == State::SingleQuote { '\'' } else { '"' };
            word.push(ch);
            if ch == '\\' {
                if let Some(&next) = chars.get(i + 1) {
                    word.push(next);
                    return i + 2;
                }
                return i + 1;
            }
            if ch == closing {
                *state = State::Code;
            }
            i + 1
        }
        State::TripleSingle | State::TripleDouble => {
            let closing = if *state == State::TripleSingle { '\'' } else { '"' };
            if ch == '\\' {
                word.push(ch);
                if let Some(&next) = chars.get(i + 1) {
                    word.push(next);
                    return i + 2;
                }
                return i + 1;
            }
            if ch == closing && starts_triple(chars, i, closing) {
                word.push(closing);
                word.push(closing);
                word.push(closing);
                *state = State::Code;
                return i + 3;
            }
            word.push(ch);
            i + 1
        }
    }
}

/// True iff `chars[i..i+3]` is `[q, q, q]`.
fn starts_triple(chars: &[char], i: usize, q: char) -> bool {
    chars.get(i) == Some(&q) && chars.get(i + 1) == Some(&q) && chars.get(i + 2) == Some(&q)
}

/// Map a single whitespace character to its `WhitespaceKind`.
///
/// Falls back to `Space` for any non-`\t`, non-`\n` whitespace
/// (e.g. form feed).  Layer-3 MVP treats unusual whitespace as a
/// space; full fidelity is filed for a richer tokenizer.
fn whitespace_for_char(ch: char) -> Token {
    let kind = match ch {
        '\t' => WhitespaceKind::Tab,
        '\n' => WhitespaceKind::Newline,
        _ => WhitespaceKind::Space,
    };
    Token::whitespace(kind)
}

/// Compute the `(level, residual_spaces)` decomposition of a leading
/// whitespace run.
///
/// `level` is the number of full indent-width quanta (tab = one
/// level; four spaces = one level).  `residual_spaces` is the
/// leftover (`0..INDENT_WIDTH`).
fn indent_level(leading: &[char]) -> (usize, usize) {
    let mut level = 0;
    let mut spaces = 0;
    for &ch in leading {
        match ch {
            '\t' => {
                level += 1;
                spaces = 0;
            }
            ' ' => {
                spaces += 1;
                if spaces == INDENT_WIDTH {
                    level += 1;
                    spaces = 0;
                }
            }
            _ => break,
        }
    }
    (level, spaces)
}

/// Push `IndentOpen` / `IndentClose` tokens for the transition
/// between `prev_level` and `new_level`.
fn emit_indent_transition(
    prev_level: usize,
    new_level: usize,
    tokens: &mut Vec<Token>,
) {
    if new_level > prev_level {
        for _ in 0..(new_level - prev_level) {
            tokens.push(Token::whitespace(WhitespaceKind::IndentOpen));
        }
    } else if new_level < prev_level {
        for _ in 0..(prev_level - new_level) {
            tokens.push(Token::whitespace(WhitespaceKind::IndentClose));
        }
    }
}

/// Move `word` into the tokens vec if non-empty, leaving `word`
/// empty.
fn flush_word(word: &mut String, tokens: &mut Vec<Token>) {
    if !word.is_empty() {
        tokens.push(Token::Word(std::mem::take(word)));
    }
}

#[cfg(test)]
mod tests {
    use super::{tokenize, INDENT_WIDTH};
    use crate::tokens::{Token, WhitespaceKind};

    fn word(s: &str) -> Token {
        Token::word(s)
    }
    fn ws(k: WhitespaceKind) -> Token {
        Token::whitespace(k)
    }

    #[test]
    fn empty_source_produces_empty_token_stream() {
        assert_eq!(tokenize(""), Vec::<Token>::new());
    }

    #[test]
    fn single_word_no_trailing_newline() {
        assert_eq!(tokenize("hello"), vec![word("hello")]);
    }

    #[test]
    fn single_word_with_trailing_newline() {
        assert_eq!(
            tokenize("hello\n"),
            vec![word("hello"), ws(WhitespaceKind::Newline)]
        );
    }

    #[test]
    fn space_between_words_emits_space_token() {
        assert_eq!(
            tokenize("a b"),
            vec![word("a"), ws(WhitespaceKind::Space), word("b")]
        );
    }

    #[test]
    fn two_indent_levels_emit_indent_open_tokens() {
        let src = "a\n    b\n";
        let expected = vec![
            word("a"),
            ws(WhitespaceKind::Newline),
            ws(WhitespaceKind::IndentOpen),
            word("b"),
            ws(WhitespaceKind::Newline),
            ws(WhitespaceKind::IndentClose),
        ];
        assert_eq!(tokenize(src), expected);
    }

    #[test]
    fn descending_indent_emits_indent_close() {
        let src = "a\n    b\nc\n";
        let expected = vec![
            word("a"),
            ws(WhitespaceKind::Newline),
            ws(WhitespaceKind::IndentOpen),
            word("b"),
            ws(WhitespaceKind::Newline),
            ws(WhitespaceKind::IndentClose),
            word("c"),
            ws(WhitespaceKind::Newline),
        ];
        assert_eq!(tokenize(src), expected);
    }

    #[test]
    fn double_quoted_string_preserves_internal_spaces() {
        let src = "x = \"hello  world\"";
        let toks = tokenize(src);
        // Should have: x, Space, =, Space, "hello  world"
        let words: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word(s) => Some(s.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect();
        assert_eq!(words, vec!["x", "=", "\"hello  world\""]);
    }

    #[test]
    fn single_quoted_string_preserves_internal_spaces() {
        let toks = tokenize("a 'b  c'");
        let words: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word(s) => Some(s.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect();
        assert_eq!(words, vec!["a", "'b  c'"]);
    }

    #[test]
    fn escaped_quote_inside_string_does_not_close_string() {
        let toks = tokenize("x = \"he said \\\"hi\\\"\"");
        let words: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word(s) => Some(s.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect();
        assert_eq!(words, vec!["x", "=", "\"he said \\\"hi\\\"\""]);
    }

    #[test]
    fn comment_swallows_rest_of_line_including_spaces() {
        let toks = tokenize("x # a  b  c");
        let words: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word(s) => Some(s.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect();
        assert_eq!(words, vec!["x", "# a  b  c"]);
    }

    #[test]
    fn tab_indent_treated_as_one_level() {
        let src = "a\n\tb\n";
        let toks = tokenize(src);
        // Expect: a, NL, IndentOpen, b, NL, IndentClose
        assert_eq!(toks[0], word("a"));
        assert_eq!(toks[2], ws(WhitespaceKind::IndentOpen));
        assert_eq!(toks[3], word("b"));
    }

    #[test]
    fn indent_width_constant_matches_pep8() {
        assert_eq!(INDENT_WIDTH, 4);
    }

    #[test]
    fn dedent_at_eof_emits_remaining_indent_closes() {
        // No trailing newline; last indent is at the final line.
        let src = "def f():\n    return 1";
        let toks = tokenize(src);
        // Must end with IndentClose (one open, one close).
        assert_eq!(
            toks.last(),
            Some(&ws(WhitespaceKind::IndentClose))
        );
        // And exactly one IndentOpen/Close pair must appear.
        let opens = toks
            .iter()
            .filter(|t| matches!(t, Token::Whitespace(WhitespaceKind::IndentOpen)))
            .count();
        let closes = toks
            .iter()
            .filter(|t| matches!(t, Token::Whitespace(WhitespaceKind::IndentClose)))
            .count();
        assert_eq!(opens, 1);
        assert_eq!(closes, 1);
    }

    // ---- multi-line triple-quoted strings (MVP_LIMITATIONS #1) ----

    #[test]
    fn single_line_triple_quoted_string_is_one_word() {
        let toks = tokenize("x = \"\"\"hello\"\"\"");
        let words: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word(s) => Some(s.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect();
        assert_eq!(words, vec!["x", "=", "\"\"\"hello\"\"\""]);
    }

    #[test]
    fn multi_line_triple_double_quoted_string_is_one_word_with_embedded_newlines() {
        let src = "x = \"\"\"line one\nline two\"\"\"\ny = 1\n";
        let toks = tokenize(src);
        let words: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word(s) => Some(s.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect();
        assert_eq!(
            words,
            vec!["x", "=", "\"\"\"line one\nline two\"\"\"", "y", "=", "1"]
        );
        // Exactly two Newline tokens: one after the closing `"""`,
        // one after `y = 1`. None inside the string body.
        let newlines = toks
            .iter()
            .filter(|t| matches!(t, Token::Whitespace(WhitespaceKind::Newline)))
            .count();
        assert_eq!(newlines, 2);
    }

    #[test]
    fn multi_line_triple_single_quoted_string_round_trips() {
        use crate::unscrambler::tokens_to_source;
        let src = "def f():\n    \"\"\"Docstring.\n\n    Second paragraph.\n    \"\"\"\n    return 1\n";
        let toks = tokenize(src);
        assert_eq!(tokens_to_source(&toks), src);
    }

    #[test]
    fn docstring_with_arbitrary_continuation_indent_preserved_verbatim() {
        use crate::unscrambler::tokens_to_source;
        // Continuation-line indentation inside the string is part of
        // the string content, not Python indent structure — it must
        // survive exactly, including a line indented LESS than the
        // opening line (which would be nonsensical as a real indent
        // transition but is perfectly legal inside string content).
        let src = "x = '''first\n  second\nthird\n        fourth'''\n";
        let toks = tokenize(src);
        assert_eq!(tokens_to_source(&toks), src);
    }

    #[test]
    fn unterminated_triple_quoted_string_flushes_at_eof() {
        // Invalid Python (limitation 6: no validation) but must not
        // panic or infinite-loop; everything accumulated flushes as
        // one trailing Word.
        let src = "x = \"\"\"never closed\nmore text";
        let toks = tokenize(src);
        match toks.last() {
            Some(Token::Word(s)) => assert!(s.ends_with("more text")),
            other => panic!("expected trailing Word, got {other:?}"),
        }
    }

    #[test]
    fn escaped_triple_quote_inside_triple_string_does_not_close_it() {
        use crate::unscrambler::tokens_to_source;
        let src = "x = \"\"\"a \\\"\\\"\\\" b\nc\"\"\"\n";
        let toks = tokenize(src);
        assert_eq!(tokens_to_source(&toks), src);
    }

    #[test]
    fn code_after_multiline_triple_string_closes_on_same_line_is_tokenized_normally() {
        let src = "x = \"\"\"a\nb\"\"\" + y\n";
        let toks = tokenize(src);
        let words: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word(s) => Some(s.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect();
        assert_eq!(words, vec!["x", "=", "\"\"\"a\nb\"\"\"", "+", "y"]);
    }

    #[test]
    fn multiline_triple_string_followed_by_dedent_tracks_indent_correctly() {
        use crate::unscrambler::tokens_to_source;
        let src =
            "def f():\n    \"\"\"doc\n    more\n    \"\"\"\n    return 1\nx = 2\n";
        let toks = tokenize(src);
        assert_eq!(tokens_to_source(&toks), src);
    }

    #[test]
    fn single_quoted_string_still_does_not_span_raw_newline() {
        // Matches real Python: an unescaped newline inside a
        // single/double-quoted (non-triple) string is a SyntaxError.
        // The tokenizer doesn't validate (limitation 6), but it must
        // not accidentally start swallowing lines the way triple-
        // quote handling does — this pins the boundary between the
        // two behaviors.
        let src = "x = 'abc\ny = 2\n";
        let toks = tokenize(src);
        let words: Vec<&str> = toks
            .iter()
            .filter_map(|t| match t {
                Token::Word(s) => Some(s.as_str()),
                Token::Whitespace(_) => None,
            })
            .collect();
        assert_eq!(words, vec!["x", "=", "'abc", "y", "=", "2"]);
    }
}
