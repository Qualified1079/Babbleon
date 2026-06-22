//! Full L2 + L2b + L3 round-trip integration test.
//!
//! Runs the complete scramble + unscramble pipeline on real
//! Python snippets and asserts the unscrambled output is exec'd
//! by Python with the same observable behaviour as the original.
//! This is the load-bearing test that the operator scramble
//! lands without corrupting valid Python (per the round-trip
//! check the operator asked for before the bench reruns).

use babbleon_core_v2::{per_host_secret::PerHostSecret, wordlist::Wordlist};
use babbleon_preprocessor_v2::{
    scramble_keywords, scramble_operators, unscramble_keywords,
    unscramble_operators, KeywordWordlist, OperatorWordlist, Token,
    WhitespaceWordlist,
};

fn secret() -> PerHostSecret {
    PerHostSecret::from_bytes(&[42u8; 32]).unwrap()
}

fn build_wordlists() -> (
    KeywordWordlist,
    OperatorWordlist,
    WhitespaceWordlist,
) {
    let s = secret();
    let wl = Wordlist::english_baseline();
    (
        KeywordWordlist::build(&s, wl, 0).unwrap(),
        OperatorWordlist::build(&s, wl, 0).unwrap(),
        WhitespaceWordlist::build(&s, wl, 0).unwrap(),
    )
}

/// Scramble a Python source string through every layer in
/// composition order; emit the scrambled byte string.
fn scramble_full(source: &str) -> String {
    let (kwl, owl, wsl) = build_wordlists();
    let tokens = babbleon_preprocessor_v2::python_tokenizer::tokenize(source);
    let mut after_keywords = tokens;
    scramble_keywords(&mut after_keywords, &kwl);
    let after_operators = scramble_operators(after_keywords, &owl);
    babbleon_preprocessor_v2::scrambler::scramble(&after_operators, &wsl)
        .expect("scramble must succeed for valid Python input")
}

/// Inverse of `scramble_full`.  Returns the reconstructed Python
/// source bytes.
fn unscramble_full(scrambled: &str) -> String {
    let (kwl, owl, wsl) = build_wordlists();
    // L3 inverse → Tokens.  We use the Token-level entry point
    // so the keyword/operator compounds are NOT lost to a re-
    // tokenisation pass that would treat them as opaque Words.
    let mut tokens =
        babbleon_preprocessor_v2::unscrambler::unscramble_to_tokens(
            scrambled, &wsl,
        );
    unscramble_operators(&mut tokens, &owl);
    unscramble_keywords(&mut tokens, &kwl);
    re_emit(&tokens)
}

/// Re-emit a Token stream as a string.  No scramble, no
/// transformation — just `Word::body` and a single space per
/// `Whitespace::Space`, newline per Newline, etc.
fn re_emit(tokens: &[Token]) -> String {
    use babbleon_preprocessor_v2::WhitespaceKind;
    let mut out = String::new();
    let mut indent_level = 0usize;
    let mut at_line_start = true;
    for token in tokens {
        match token {
            Token::Word(body) => {
                if at_line_start {
                    out.push_str(&"    ".repeat(indent_level));
                    at_line_start = false;
                }
                out.push_str(body);
            }
            Token::Whitespace(WhitespaceKind::Space) => {
                if at_line_start {
                    out.push_str(&"    ".repeat(indent_level));
                    at_line_start = false;
                }
                out.push(' ');
            }
            Token::Whitespace(WhitespaceKind::Tab) => {
                if at_line_start {
                    out.push_str(&"    ".repeat(indent_level));
                    at_line_start = false;
                }
                out.push('\t');
            }
            Token::Whitespace(WhitespaceKind::Newline) => {
                out.push('\n');
                at_line_start = true;
            }
            Token::Whitespace(WhitespaceKind::IndentOpen) => {
                indent_level += 1;
            }
            Token::Whitespace(WhitespaceKind::IndentClose) => {
                indent_level = indent_level.saturating_sub(1);
            }
        }
    }
    out
}

/// Run a Python program and capture stdout.  Returns
/// `Some(stdout)` on success, `None` on any failure.
fn python_exec(program: &str) -> Option<String> {
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(program)
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        eprintln!(
            "python3 failed: stderr = {}",
            String::from_utf8_lossy(&out.stderr)
        );
        None
    }
}

#[test]
fn round_trip_simple_function_def_executes_identically() {
    let original = "def greet(name):\n    print(f\"hello {name}\")\n\ngreet(\"world\")\n";
    let scrambled = scramble_full(original);
    let unscrambled = unscramble_full(&scrambled);

    // Sanity: the scrambled middle should NOT contain the
    // original keywords or operators.
    assert!(
        !scrambled.contains("def "),
        "L2 should have scrambled `def`",
    );
    assert!(
        !scrambled.contains("):"),
        "L2b should have scrambled `(`, `)`, `:`",
    );

    let original_out = python_exec(original)
        .expect("baseline must execute");
    let unscrambled_out = python_exec(&unscrambled)
        .unwrap_or_else(|| panic!("unscrambled must execute:\n---\n{unscrambled}\n---"));
    assert_eq!(original_out, unscrambled_out, "output diverged");
}

#[test]
fn round_trip_branching_logic_executes_identically() {
    let original = "\
def classify(n):
    if n < 0:
        return \"negative\"
    elif n == 0:
        return \"zero\"
    else:
        return \"positive\"

print(classify(-5))
print(classify(0))
print(classify(42))
";
    let scrambled = scramble_full(original);
    let unscrambled = unscramble_full(&scrambled);

    assert!(!scrambled.contains("def "));
    assert!(!scrambled.contains("if "));
    assert!(!scrambled.contains("elif "));
    assert!(!scrambled.contains("else:"));
    assert!(!scrambled.contains("=="));

    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled)
        .unwrap_or_else(|| panic!("unscrambled failed:\n{unscrambled}"));
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn round_trip_with_list_comprehension_and_brackets() {
    let original = "\
xs = [i * 2 for i in range(5)]
print(xs)
print(sum(xs))
";
    let scrambled = scramble_full(original);
    let unscrambled = unscramble_full(&scrambled);

    // Brackets must be scrambled.
    assert!(!scrambled.contains("[i"));
    assert!(!scrambled.contains("]"));

    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled)
        .unwrap_or_else(|| panic!("unscrambled failed:\n{unscrambled}"));
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn round_trip_class_definition() {
    let original = "\
class Counter:
    def __init__(self):
        self.value = 0
    def increment(self):
        self.value = self.value + 1
        return self.value

c = Counter()
print(c.increment())
print(c.increment())
print(c.increment())
";
    let scrambled = scramble_full(original);
    let unscrambled = unscramble_full(&scrambled);

    assert!(!scrambled.contains("class "));
    assert!(!scrambled.contains("def "));
    assert!(!scrambled.contains("return "));

    let original_out = python_exec(original).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled)
        .unwrap_or_else(|| panic!("unscrambled failed:\n{unscrambled}"));
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn scrambled_output_is_not_trivially_readable() {
    // Sanity check that the scrambler is doing meaningful work
    // — the scrambled output should not contain any of the
    // structural skeleton characters as standalone ASCII.
    let source = "if x == 0: return None";
    let scrambled = scramble_full(source);

    // None of these short structural strings should survive
    // verbatim in the scrambled wall-of-text.
    for needle in ["if ", " == ", ": ", "None"] {
        assert!(
            !scrambled.contains(needle),
            "structural fragment {needle:?} survives in scrambled output",
        );
    }
}
