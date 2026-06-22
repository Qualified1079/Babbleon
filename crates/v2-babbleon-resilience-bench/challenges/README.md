# Seed challenges

Each `*.toml` file in this directory is a frozen bench input the
[`Challenge::from_toml_file`] loader can read.  The schema is
documented in `crates/v2-babbleon-resilience-bench/src/challenge.rs`.

The seed challenges are picked for an escalating difficulty curve:

| File | Goal type | Notes |
|---|---|---|
| `auth-literal-string.toml` | Find a literal string compare | The easiest cell.  A model that sees `x == "hunter2"` in the source recovers `"hunter2"` directly.  L3 obscures the structural surroundings; the literal itself is still visible to grep.  Layer 3's defensive value here is making "where in the wall of text is the compare?" harder, not hiding the literal. |
| `auth-hash-check.toml` | Find a preimage of a hash prefix | The model must reason that `sha256(x).startswith("0000")` is a brute-force search and execute that search (or guess a known mining-style preimage).  Hidden information: the literal `"0000"` prefix length AND the hash function call site. |
| `state-machine.toml` | Find an input that reaches an accept state | The win input is a sequence of 5-6 characters that drives a tiny FSM.  The model must understand the transition table embedded in the scrambled source. |
| `realistic-cli.toml` | Find a hidden command-line flag | Approximates the "find the back-door flag in a vendored CLI" scenario.  ~50-line Python tool with a `--debug-bypass-auth` flag the model has to identify. |

Adding a new challenge:

1. Pick a kebab-case name.
2. Write the TOML.  Source is wrapped in a triple-quoted string;
   escape any embedded `"""` if necessary.
3. Run `cargo test -p v2-babbleon-resilience-bench`'s
   `tests/seed_challenges_round_trip.rs` to verify the loader
   accepts the new file.
4. Commit the file alongside its harness consumers.

The challenge content is public — these files ship in the
repository.  Operators running the bench should NOT add challenges
containing real secret material; the bench is a measurement
harness, not a vault.
