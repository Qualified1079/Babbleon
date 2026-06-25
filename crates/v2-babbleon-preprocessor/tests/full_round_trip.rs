//! Full L4 + L2 + L3 round-trip integration test.
//!
//! Runs the complete scramble + unscramble pipeline on real
//! Python snippets and asserts the unscrambled output is exec'd
//! by Python with the same observable behaviour as the original.
//! This is the load-bearing test that L4 (chunk reorder) + L2
//! (dynamic identifier scramble) + L3 (whitespace-as-words) compose
//! without corrupting valid Python.

use babbleon_core_v2::{
    per_host_secret::PerHostSecret, wordlist::Wordlist, MappingBuilder,
};
use babbleon_preprocessor_v2::{
    collect_unique_tokens, inject_decoys, scramble_chunks,
    scramble_identifiers, strip_decoys, unscramble_chunks,
    unscramble_identifiers, IdentifierMapping, Token, WhitespaceWordlist,
    ALIAS_COUNT,
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

/// Scramble a Python source string through L4 + L5 + L2 + L3.
fn scramble_full(source: &str) -> String {
    let wsl = build_whitespace_wordlist();
    let raw_tokens = babbleon_preprocessor_v2::python_tokenizer::tokenize(source);
    // L4: chunk-shuffle + position markers.
    let l4_tokens = scramble_chunks(raw_tokens, 0);
    // L5: inject decoys among top-level positions.
    let mut tokens = inject_decoys(l4_tokens, 0);
    // L2 mapping must cover the post-L5 token set (markers + decoys).
    let mapping = build_identifier_mapping(&tokens, 0);
    scramble_identifiers(&mut tokens, &mapping);
    babbleon_preprocessor_v2::scrambler::scramble(&tokens, &wsl)
        .expect("scramble must succeed for valid input")
}

/// Inverse of `scramble_full`.  Returns the reconstructed source bytes.
fn unscramble_full(source: &str, scrambled: &str) -> String {
    let wsl = build_whitespace_wordlist();
    // Rebuild the same mapping by repeating the scramble-side L4 +
    // L5 passes on the original source.  Production paths read the
    // sorted token list from the scrambled-file header instead; this
    // test helper reuses the original source for simplicity.
    let original_tokens =
        babbleon_preprocessor_v2::python_tokenizer::tokenize(source);
    let marked_tokens = scramble_chunks(original_tokens, 0);
    let augmented = inject_decoys(marked_tokens, 0);
    let mapping = build_identifier_mapping(&augmented, 0);
    let mut tokens = babbleon_preprocessor_v2::unscrambler::unscramble_to_tokens(
        scrambled, &wsl,
    );
    unscramble_identifiers(&mut tokens, &mapping);
    // L5 inverse: strip decoys BEFORE L4 reorder so the chunk
    // boundary computation isn't disturbed by decoy positions.
    let dedecoyed = strip_decoys(tokens);
    let reordered = unscramble_chunks(dedecoyed);
    babbleon_preprocessor_v2::unscrambler::tokens_to_source(&reordered)
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
fn l6_reverses_chunks_and_round_trips_executable_python() {
    use babbleon_preprocessor_v2::{reverse_chunks, unreverse_chunks};

    let source = "def add(a, b):\n    return a + b\n\nprint(add(2, 3))\n";

    // L3 body via the existing helper.
    let scrambled = scramble_full(source);
    // Apply L6 to the body.
    let reversed = reverse_chunks(&scrambled, 0);

    // For a non-trivial body L6 must change at least one chunk.
    assert_ne!(reversed, scrambled, "L6 should mutate a long body");
    assert_eq!(
        reversed.chars().count(),
        scrambled.chars().count(),
        "L6 must preserve char count",
    );

    let undone = unreverse_chunks(&reversed, 0);
    assert_eq!(undone, scrambled, "L6 must round-trip its body");

    // Full pipeline: L6 strip then L3⁻¹ then upper layers.
    let unscrambled = unscramble_full(source, &undone);
    let original_out = python_exec(source).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled)
        .unwrap_or_else(|| panic!("unscrambled failed:\n{unscrambled}"));
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn l6_then_l12_compose_and_invert_in_correct_order() {
    use babbleon_preprocessor_v2::{
        inject_tokenizer_noise, reverse_chunks, strip_tokenizer_noise,
        unreverse_chunks,
    };

    let source = "def greet(name):\n    print(f\"hi {name}\")\n\ngreet(\"world\")\n";
    let body = scramble_full(source);

    // Compose L6 then L12 as the production lifecycle does.
    let reversed = reverse_chunks(&body, 0);
    let noisy = inject_tokenizer_noise(&reversed, 0);

    // Inverse order: L12 strip then L6 unreverse.
    let stripped = strip_tokenizer_noise(&noisy);
    let recovered = unreverse_chunks(&stripped, 0);
    assert_eq!(recovered, body, "L6+L12 must round-trip");
}

#[test]
fn l12_noise_survives_full_pipeline_round_trip() {
    use babbleon_preprocessor_v2::{
        has_any_tokenizer_noise, inject_tokenizer_noise, strip_tokenizer_noise,
    };

    let source = "def add(a, b):\n    return a + b\n\nprint(add(2, 3))\n";

    // Scramble through L4/L5/L2/L3 then apply L12 to the body bytes.
    let scrambled = scramble_full(source);
    let noisy = inject_tokenizer_noise(&scrambled, 0);
    assert!(
        has_any_tokenizer_noise(&noisy),
        "L12 must add at least one noise character to a non-trivial body",
    );

    // Strip L12 noise content-based; should byte-recover the original
    // L3 body.
    let cleaned = strip_tokenizer_noise(&noisy);
    assert_eq!(
        cleaned, scrambled,
        "strip_noise must reverse inject_noise byte-for-byte",
    );

    // The full pipeline (with L12 strip up front) must round-trip
    // back to a Python program that executes identically.
    let unscrambled = unscramble_full(source, &cleaned);
    let original_out = python_exec(source).expect("baseline executes");
    let unscrambled_out = python_exec(&unscrambled)
        .unwrap_or_else(|| panic!("unscrambled failed:\n{unscrambled}"));
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn l12_strip_is_back_compat_for_pre_l12_files() {
    // A file scrambled by an older revision (no L12 noise) must
    // unscramble correctly when the strip step is added in front.
    // strip_noise on a clean body must be a no-op.
    use babbleon_preprocessor_v2::strip_tokenizer_noise;

    let source = "x = 1\nprint(x)\n";
    let scrambled = scramble_full(source);
    let stripped = strip_tokenizer_noise(&scrambled);
    assert_eq!(stripped, scrambled, "strip on clean body must be identity");
    let unscrambled = unscramble_full(source, &stripped);
    let original_out = python_exec(source).unwrap();
    let unscrambled_out = python_exec(&unscrambled).unwrap();
    assert_eq!(original_out, unscrambled_out);
}

#[test]
fn l2_scrambles_every_unique_token() {
    // Use multi-letter tokens so a substring search isn't fooled by
    // an arbitrary single letter appearing inside an L2 compound by
    // chance.  This test asserts L2 actually mutated the body — not
    // that no compound happens to contain the letter 'x'.
    let source = "def hello(name):\n    return name\n";
    let tokens = babbleon_preprocessor_v2::python_tokenizer::tokenize(source);
    let unique = collect_unique_tokens(&tokens);
    let scrambled = scramble_full(source);
    for tok in &unique {
        if tok.len() < 3 {
            continue; // too short — substring collisions are noise
        }
        assert!(
            !scrambled.contains(tok.as_str()),
            "token {tok:?} survives in scrambled output — L2 did not run",
        );
    }
}
