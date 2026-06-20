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
//! 1. **Multi-line string literals** (`"""..."""` or `'''...'''`
//!    spanning newlines) are NOT preserved correctly — the
//!    tokenizer's string-state resets at every line boundary.  Use
//!    single-line string literals only; embed newlines via `\n`.
//! 2. **Mixed-width indent** is normalized to four spaces per
//!    level.  A line with seven leading spaces is treated as level
//!    one (4 / 4) with three residual `Space` tokens; on
//!    re-emission the residuals come back as three intra-line
//!    spaces before the first word.  Mixed tab-and-space indent is
//!    similarly approximate.
//! 3. **Operators are not split from adjacent identifiers.**  `x+y`
//!    is one `Word("x+y")`, not three tokens.  Layer-3-only this
//!    is fine; layers 1 and 2 will eventually need a richer
//!    tokenizer.
//! 4. **f-string interpolations are treated as opaque string
//!    bodies.**  `f"hello {name}"` becomes one `Word`; the
//!    `{name}` interior is preserved literally but not tokenized.
//!    Spaces inside the interpolation survive verbatim because the
//!    whole f-string is a single `Word`.
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

/// Tokenize a Python source string into the layer-3 IR.
///
/// See `MVP_LIMITATIONS` (module docs) for the supported subset.
#[must_use]
pub fn tokenize(source: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut prev_level: usize = 0;

    // `split('\n')` produces a trailing empty element iff the input
    // ends in a newline.  We use that to decide whether to emit a
    // final `Newline` token.
    let parts: Vec<&str> = source.split('\n').collect();
    let trailing_newline =
        parts.last().is_some_and(|s| s.is_empty()) && parts.len() > 1;
    let line_count = if trailing_newline {
        parts.len() - 1
    } else {
        parts.len()
    };

    for (idx, line) in parts.iter().take(line_count).enumerate() {
        let (indent_chars, content) = split_leading_whitespace(line);
        let is_blank = content.is_empty();

        // Indent-level transitions only fire on non-blank lines —
        // blank lines don't change Python's logical indent
        // structure.
        if is_blank {
            // Blank line: emit the leading whitespace verbatim if
            // any (rare for valid Python; harmless for round-trip).
            for ch in indent_chars.chars() {
                tokens.push(whitespace_for_char(ch));
            }
        } else {
            let (level, residual_spaces) = indent_level(indent_chars);
            emit_indent_transition(prev_level, level, &mut tokens);
            for _ in 0..residual_spaces {
                tokens.push(Token::whitespace(WhitespaceKind::Space));
            }
            prev_level = level;
            tokenize_intra_line(content, &mut tokens);
        }

        // Newline at end of each line except possibly the last.
        let is_last_line = idx + 1 == line_count;
        if !is_last_line || trailing_newline {
            tokens.push(Token::whitespace(WhitespaceKind::Newline));
        }
    }

    // Close any indents still open at EOF.
    while prev_level > 0 {
        tokens.push(Token::whitespace(WhitespaceKind::IndentClose));
        prev_level -= 1;
    }

    tokens
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

/// Split a line into `(leading_whitespace, content)`.
///
/// Leading whitespace is the maximal run of `\t` or ` ` at the
/// start; `content` is everything after.
fn split_leading_whitespace(line: &str) -> (&str, &str) {
    let idx = line
        .find(|c: char| c != ' ' && c != '\t')
        .unwrap_or(line.len());
    line.split_at(idx)
}

/// Compute the `(level, residual_spaces)` decomposition of a leading
/// whitespace run.
///
/// `level` is the number of full indent-width quanta (tab = one
/// level; four spaces = one level).  `residual_spaces` is the
/// leftover (`0..INDENT_WIDTH`).
fn indent_level(leading: &str) -> (usize, usize) {
    let mut level = 0;
    let mut spaces = 0;
    for ch in leading.chars() {
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

/// Per-line lexer state for the intra-line walk.
#[derive(Clone, Copy)]
enum LineState {
    /// Outside any string or comment.
    Code,
    /// Inside a `'...'` string literal.
    SingleQuoteString,
    /// Inside a `"..."` string literal.
    DoubleQuoteString,
    /// Inside a `#...` comment; everything to EOL is one word.
    Comment,
}

/// Tokenize the post-indent content of one line.
///
/// Maintains a small state machine so quoted strings preserve
/// internal spaces verbatim, comments preserve internal spaces
/// verbatim, and ordinary code splits on whitespace.
fn tokenize_intra_line(content: &str, tokens: &mut Vec<Token>) {
    let mut state = LineState::Code;
    let mut word = String::new();
    let mut chars = content.chars().peekable();

    while let Some(ch) = chars.next() {
        match state {
            LineState::Code => match ch {
                ' ' => {
                    flush_word(&mut word, tokens);
                    tokens.push(Token::whitespace(WhitespaceKind::Space));
                }
                '\t' => {
                    flush_word(&mut word, tokens);
                    tokens.push(Token::whitespace(WhitespaceKind::Tab));
                }
                '#' => {
                    word.push(ch);
                    state = LineState::Comment;
                }
                '"' => {
                    word.push(ch);
                    state = LineState::DoubleQuoteString;
                }
                '\'' => {
                    word.push(ch);
                    state = LineState::SingleQuoteString;
                }
                _ => word.push(ch),
            },
            LineState::DoubleQuoteString => {
                word.push(ch);
                if ch == '\\' {
                    if let Some(next) = chars.next() {
                        word.push(next);
                    }
                } else if ch == '"' {
                    state = LineState::Code;
                }
            }
            LineState::SingleQuoteString => {
                word.push(ch);
                if ch == '\\' {
                    if let Some(next) = chars.next() {
                        word.push(next);
                    }
                } else if ch == '\'' {
                    state = LineState::Code;
                }
            }
            LineState::Comment => {
                word.push(ch);
            }
        }
    }
    flush_word(&mut word, tokens);
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
}
