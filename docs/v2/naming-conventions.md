# Naming conventions — v2

The v1 audit-readability rename pass landed mid-project (`present_trusted`
→ `mount_real_view`, `apply_untrusted_filter` →
`block_process_inspection_syscalls`, etc.) and was the right
discipline.  v2 adopts it from day one for binaries, crates, modules,
public functions, and types.

The rule, repeated for emphasis: **the name describes what the
thing does in plain English.  Not what it's called by convention.
Not what the literature calls it.  What it does.**

## Why this rule

Babbleon is a security tool.  The runtime obfuscation is the
product; the source code should be maximally readable so security
auditors can verify the implementation is honest.  Names that
require domain knowledge to interpret hide intent from auditors;
they are an anti-feature.

If a reader cannot guess what a function does from its name alone,
the name fails.

## Examples — wrong vs right

### Binary names

| Wrong | Right | Why |
|---|---|---|
| `babbleon-ns-helper` | `babbleon-launch-untrusted` | "ns" is opaque; "launch-untrusted" says what the operator does with it. |
| `babbleon-rotator` | `babbleon-rotate-mapping` | Verb-first, plain English. |
| `babbleon-mapd` | `babbleon-mapping-worker` | No undocumented `-d` suffix; spell it out. |
| `babbleon-ppd` | `babbleon-preprocessor` | No three-letter codes. |

### Crate names

| Wrong | Right | Why |
|---|---|---|
| `babbleon` (lib) | `babbleon-core` | Reserve the bare name for the user-facing CLI. |
| `babbleon-ns` | `babbleon-launch-untrusted` | See above. |
| `babbleon-fp` | `babbleon-preprocessor` | No two-letter codes. |

### Module names

| Wrong | Right | Why |
|---|---|---|
| `ns.rs` | `mount_namespace.rs` | Spell it out. |
| `fpe.rs` | `permutation.rs` | "FPE" is a literature term; the module produces a permutation. |
| `kek.rs` | `key_encryption_key.rs` or just `vault_key.rs` | No undefined acronyms. |
| `seccomp.rs` | `syscall_deny_list.rs` | seccomp is the mechanism, not the purpose. |

### Function names

The v1 rename pass set the standard:

| Wrong | Right |
|---|---|
| `present_untrusted` | `mount_scrambled_view` |
| `present_trusted` | `mount_real_view` |
| `apply_untrusted_filter` | `block_process_inspection_syscalls` |
| `write_honey_wrapper` | `write_tripwire_script` |
| `decoy_for` | `fake_tool_for` |
| `banner_for_decoy` | `fake_help_text_for` |
| `do_unshare` | `enter_new_mount_namespace` |
| `make_root_private` | `block_mount_propagation_to_host` |

The pattern: **verb-first, plain English statement of what the
function changes about the world.**  Boolean predicates start with
`is_`, `has_`, `can_`.

### Type names

| Wrong | Right |
|---|---|
| `KekBackend` | `VaultKeyBackend` (still abbreviated but clearer) or `KeyDerivationBackend` |
| `FPEPermutation` | `WordlistPermutation` |
| `NSDriver` | `NamespaceDriver` or `MountNamespaceDriver` |

## Acronym aliases (optional fast path)

Plain English names are the primary, authoritative names.  They
are what appears in code, audit trails, documentation, and error
messages.

For operator-facing CLI subcommands and environment variable names
that operators type repeatedly, v2 also exposes abbreviated
aliases.  The rule: **the alias is only the initials of each word
in the plain English name.**

| Plain English (primary) | Acronym alias |
|---|---|
| `block-process-inspection-syscalls` | `bpis` |
| `mount-scrambled-view` | `msv` |
| `mount-real-view` | `mrv` |
| `enter-new-mount-namespace` | `enms` |
| `block-mount-propagation-to-host` | `bmph` |
| `tripwire-response-policy` | `trp` |
| `rotate-mapping` | `rm` |

**Scope:** aliases exist for CLI subcommands and env-var short
forms only.  They do NOT exist as function names, type names,
module names, or log message identifiers.  The plain English name
is the only truth at the code level.

**Discovery:** `babbleon help` always shows the plain English name
first, with the alias in parentheses.  `babbleon ALIAS` routes to
the subcommand as if the full name were typed.  Autocomplete
exposes both.

**Alias stability:** once assigned, an acronym alias is frozen.
If the plain English name is renamed (rare), the alias stays the
same to avoid breaking operator scripts.  The old plain English
name becomes a deprecated alias too, with a deprecation warning
for one minor version cycle before removal.

## What NOT to rename

Names baked into kernel ABIs, RFCs, or external standards stay:

- `seccomp` — kernel feature name; renaming hides the mechanism
  from auditors who want to check our use against the kernel docs.
- `Landlock` — kernel LSM name.
- `Argon2id` — RFC 9106.
- `HKDF` — RFC 5869.
- `SHA-256` — FIPS 180-4.
- `Ed25519` — RFC 8032.
- `CTAP2` — FIDO Alliance spec.
- `TPM2` — TCG spec.

When these appear, they appear under modules whose names describe
*purpose* (e.g. `syscall_deny_list.rs` containing the `seccomp`
filter), not *mechanism*.

## Module-level doc comments

Every file's top doc-comment opens with **what attack it defeats**,
not what it contains.  The v1 rename pass landed this discipline
for `enforcement/*`; v2 enforces it crate-wide.

Template:

```rust
//! <One-sentence statement of the module's role.>
//!
//! # What this defeats
//!
//! <The attacker behaviour this module disrupts, named concretely.>
//!
//! # Mechanism
//!
//! <How — kernel features used, primitive types involved.>
//!
//! # Module map
//!
//! <If the module has submodules or significant public items.>
```

## Renames carried into v2

When v2 phase 1 lands, every v1 name that violates this convention
gets renamed.  No back-compat aliases; the v1 source is preserved
on the `v1.0-reference` tag for archeology.

The renames I've identified so far (non-exhaustive):

- `babbleon` (lib crate) → `babbleon-core`
- `babbleon-ns-helper` → `babbleon-launch-untrusted`
- `fpe.rs` → `permutation.rs`
- `Mapper` → `MappingBuilder`
- `MappingTable` → `EpochMapping`
- `Vault::seal` / `unseal` → `Vault::write_sealed` / `read_sealed`
- `KekBackend` → `VaultKeyBackend`
- `EnforcementDriver` trait → `TierDriver`
- `HoneyResponder` → `TripwireResponder`
- `ResponsePolicy` → `TripwireResponsePolicy`

Module-doc rewrites for every file in `enforcement/`, `vault/`,
`mapping/`, `events.rs`, `credentials.rs`, `audit.rs`.

## Test names

Tests get the same treatment.  The rule:
`<what_property>_<under_what_conditions>`.

Examples:

| Wrong | Right |
|---|---|
| `test_unlock` | `unlock_with_correct_passphrase_returns_session` |
| `test_rotate` | `rotation_changes_all_scrambled_names_for_tracked_set` |
| `test_honey` | `honey_wrapper_writes_source_stale_to_fifo_when_name_in_stale_list` |

Tests are documentation that runs.  A failing test should tell
the reader what invariant broke without them having to read the
test body.

## Operator-facing names

CLI subcommands, environment variables, file paths, and log
messages count too.  v1 has some of these wrong:

| Wrong | Right |
|---|---|
| `babbleon apply-ns` | `babbleon mount-scrambled-view` |
| `BABBLEON_HONEY_POLICY` | `BABBLEON_TRIPWIRE_RESPONSE_POLICY` (or shorter — `BABBLEON_TRIPWIRE_POLICY`) |
| `/run/babbleon/honey.list` | `/run/babbleon/tripwire-honey.list` (paired with `tripwire-stale.list`) |
| `/run/babbleon/honey.fifo` | `/run/babbleon/tripwire-events.fifo` |

v2 ships with these names from day one.  No `--legacy-name`
fallbacks.
