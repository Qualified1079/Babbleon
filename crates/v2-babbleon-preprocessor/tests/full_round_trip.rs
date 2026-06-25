//! Full L2 + L3 round-trip integration test.
//!
//! Runs the complete scramble + unscramble pipeline on real
//! Python snippets and asserts the unscrambled output is exec'd
//! by Python with the same observable behaviour as the original.
//! This is the load-bearing test that the dynamic identifier scramble
//! (L2) + whitespace-as-words (L3) lands without corrupting valid
//! Python (per the round-trip check the operator asked for).

use babbleon_core_v2::{
    per_host_secret::PerHostSecret, wordlist::Wordlist, MappingBuilder,
};
use babbleon_preprocessor_v2::{
    collect_unique_tokens, scramble_identifiers, unscramble_identifiers,
    IdentifierMapping, Token, WhitespaceWordlist, ALIAS_COUNT,
};

fn secret() -> PerHostSecret {
    PerHostSecret::from_bytes(&[42u8; 32]).unwrap()
}

fn build_whitespace_wordlist() -> WhitespaceWordlist {
    let s = secret();
    let wl = Wordlist::english_baseline();
    WhitespaceWordlist::build(&s, wl, 0).unwrap()
}

/// Build an IdentifierMapping in-proc (no daemon) using MappingBuilder.
/// Uses the same virtual-epoch scheme as DaemonState::token_mapping.
fn build_identifier_mapping(
    tokens: &[Token],
    epoch: u64,
) -> IdentifierMapping {
    let s = secret();
    let wl = Wordlist::english_baseline();
    let builder = MappingBuilder::new(&s, &wl);
    let sorted_tokens = collect_unique_tokens(tokens);
    let base = epoch.saturating_mul(ALIAS_COUNT as u64);
    let mut per_alias: Vec<Vec<String>> = Vec::with_capacity(ALIAS_COUNT);
    for ai in 0..ALIAS_COUNT {
        let virtual_epoch = base + ai as u64;
        let mapping = builder.build(&sorted_tokens, virtual_epoch).unwrap();
        let compounds: Vec<String> = sorted_tokens
            .iter()
            .map(|t| mapping.scramble(t).unwrap_or(t.as_str()).to_string())
            .collect();
        per_alias.push(compounds);
    }
    // Transpose: per_alias[alias][token] → aliases[token][alias]
    let mut aliases: Vec<Vec<String>> = sorted_tokens
        .iter()
        .map(|_| Vec::with_capacity(ALIAS_COUNT))
        .collect();
    for alias_compounds in per_alias {
        for (ti, compound) in alias_compounds.into_iter().enumerate() {
            aliases[ti].push(compound);
        }
    }
    IdentifierMapping::from_tokens_and_aliases(sorted_tokens, epoch, aliases)
        .expect("in-proc identifier mapping must not collide")
}

/// Scramble a Python source string through L2 + L3.
fn scramble_full(source: &str) -> String {
    let wsl = build_whitespace_wordlist();
    let mut tokens = babbleon_preprocessor_v2::python_tokenizer::tokenize(source);
    let mapping = build_identifier_mapping(&tokens, 0);
    scramble_identifiers(&mut tokens, &mapping);
    babbleon_preprocessor_v2::scrambler::scramble(&tokens, &wsl)
        .expect("scramble must succeed for valid input")
}

/// Inverse of `scramble_full`.  Returns the reconstructed source bytes.
fn unscramble_full(source: &str, scrambled: &str) -> String {
    let wsl = build_whitespace_wordlist();
    // Rebuild the same mapping from the original source's token stream.
    let original_tokens =
        babbleon_preprocessor_v2::python_tokenizer::tokenize(source);
    let mapping = build_identifier_mapping(&original_tokens, 0);
    let mut tokens = babbleon_preprocessor_v2::unscrambler::unscramble_to_tokens(
        scrambled, &wsl,
    );
    unscramble_identifiers(&mut tokens, &mapping);
    babbleon_preprocessor_v2::unscrambler::tokens_to_source(&tokens)
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
    let original =
        "def greet(name):\n    print(f\"hello {name}\")\n\ngreet(\"world\")\n";
    let scrambled = scramble_full(original);
    let unscrambled = unscramble_full(original, &scrambled);

    // Sanity: the scrambled body should NOT contain the identifier `def`.
    assert!(
        !scrambled.contains("def "),
        "L2 should have scrambled `def`",
    );

    let original_out = python_exec(original).expect("baseline must execute");
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
    let unscrambled = unscramble_full(original, &scrambled);

    assert!(!scrambled.contains("def "));
    assert!(!scrambled.contains("if "));

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
    let unscrambled = unscramble_full(original, &scrambled);

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
    let source = "if x == 0: return None";
    let scrambled = scramble_full(source);

    // The scrambled body should not contain these structural tokens verbatim.
    for needle in ["if ", "None"] {
        assert!(
            !scrambled.contains(needle),
            "structural fragment {needle:?} survives in scrambled output",
        );
    }
}

#[test]
fn l2_scrambles_every_unique_token() {
    let source = "def foo(x):\n    return x\n";
    let tokens = babbleon_preprocessor_v2::python_tokenizer::tokenize(source);
    let unique = collect_unique_tokens(&tokens);
    let scrambled = scramble_full(source);
    for tok in &unique {
        assert!(
            !scrambled.contains(tok.as_str()),
            "token {tok:?} survives in scrambled output — L2 did not run",
        );
    }
}
