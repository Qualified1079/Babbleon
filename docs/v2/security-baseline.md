# Security baseline — v2

Every v2 crate satisfies this checklist before merge.  The rule
list is short.  Each rule names a concrete code shape, a
rationale that's load-bearing for the threat model, and a
mechanical check.  If a rule cannot be satisfied, the crate does
not merge until either the rule is amended in this document (with
operator sign-off) or the crate is changed.

The discipline carries over from v1's late additions (zeroize,
constant-time compare, `SAFETY:` comments, daemon hardening).
The v1 problem was that those were bolted on after architecture
froze.  v2 adopts them from day one so every crate ships honest
from its first commit.

See also:

- `V2_PLAN.md` §"Security conventions designed in from day one"
- `docs/v2/naming-conventions.md` — rule 6
- `docs/v2/least-privilege.md` — rule 10
- `docs/v2/standards-alignment.md` — which auditor framework each
  rule satisfies

The rule, repeated for emphasis: **every v2 crate must pass every
rule below before merge.**  Skipping a rule is not a TODO; it is
a merge blocker.

---

## Rules

### Rule 1 — `#![forbid(unsafe_code)]` at the crate root

```rust
#![forbid(unsafe_code)]
```

at the top of every `lib.rs` and `main.rs`.

**Why:** unsafe Rust is a vulnerability surface auditors must
trace by hand.  Most v2 crates have no business doing FFI, raw
pointer arithmetic, or unchecked transmutes.  The default is
forbid so the type system is the boundary; opt-out is per-crate
and per-module, never per-block.

**Exception policy:** crates that wrap libc syscalls (PAM shim,
`mlockall` wrapper, `prctl`, capability manipulation) replace
`forbid` with `deny` at the crate root and `allow` inside ONE
module named `syscall.rs` (or `unsafe_<thing>.rs`).  That module
has a top-of-file comment explaining why it exists, lists every
syscall the module wraps, and every `unsafe` block inside it
carries a `SAFETY:` comment per rule 9.

**Mechanical check:** `git grep -l 'unsafe' crates/v2-*/src/ |
grep -v syscall.rs | grep -v unsafe_.*.rs` must return empty.

### Rule 2 — `#![deny(missing_docs)]` + `#![warn(clippy::pedantic)]`

```rust
#![deny(missing_docs)]
#![warn(clippy::pedantic)]
```

**Why:** Babbleon's product *is* the runtime obfuscation; the
source is for auditors to read.  Missing docs hide intent from
auditors.  Pedantic clippy catches the small idiomatic mistakes
that compound into hard-to-audit code over time.

**Exception policy:** clippy::pedantic relaxations live next to
the `#![warn(...)]` line in `lib.rs` with a one-line comment per
relaxation explaining why.  No file-local `#[allow(clippy::...)]`
without an inline comment justifying the relaxation.

**Mechanical check:** `cargo doc --no-deps -p <crate>` succeeds
with no warnings; `cargo clippy -p <crate>` succeeds at the
default deny level.  Pedantic warnings are informational by
design (`warn` not `deny`); reviewers scan them per PR and either
fix or annotate with an inline-justified `#[allow(...)]`.

### Rule 3 — secrets wear `Zeroizing` or `SecretBox`; never `Clone`/`Copy`/`Debug`

Every type that carries plaintext secret bytes — keying material,
KDF output, per-host secret, derived sub-keys — holds them in
`zeroize::Zeroizing<[u8; N]>` (fixed size) or
`zeroize::Zeroizing<Vec<u8>>` (variable size), or in
`secrecy::SecretBox<T>` (when `T` carries other secret-derived
data alongside).

Secret-holding types do NOT derive `Clone`, `Copy`, or `Debug`.

```rust
pub struct PerHostSecret(Zeroizing<[u8; PER_HOST_SECRET_LEN]>);
// no Clone, no Copy, no Debug.
```

**Why:** the per-host secret is the only secret Babbleon defends.
Leakage paths to close:

- *Heap reuse.*  Without zero-on-drop, the allocator hands the
  bytes to a subsequent allocation and the next caller sees
  secret bytes.
- *Core dumps.*  Paired with the launcher's `PR_SET_DUMPABLE=0`
  + `RLIMIT_CORE=0`, even a coerced abort cannot ship secret
  bytes to disk.
- *Debug printing.*  A casual `dbg!(secret)` or
  `tracing::info!(?secret)` writes plaintext to stderr or the
  audit log.  No `Debug` derive on secret types makes that line
  fail at compile time.
- *Accidental clone.*  `Clone` on a `Zeroizing` type defeats the
  drop guarantee — the original drops zeroed but the clone
  outlives it.  Refuse the derive; force callers to think about
  lifetimes.

**Exception policy:** `secrecy::SecretBox<T>` for variable-sized
or compound secret structs is acceptable in place of
`Zeroizing<Vec<u8>>`.  Either way the rule is the same: no
clone/copy/debug.

**Mechanical check:** `git grep -nE '#\[derive\([^)]*(Clone|Copy|
Debug)[^)]*\)\] *\n[^\n]*Zeroizing' crates/v2-*/src/` must return
empty.

### Rule 4 — secret-derived compares go through constant-time

Any compare whose *truth value* depends on a secret-derived byte
sequence routes through `crypto_compare::secret_bytes_equal`
(which wraps `subtle::ConstantTimeEq`).

```rust
use crate::crypto_compare::secret_bytes_equal;

if secret_bytes_equal(&candidate, &honey_name_bytes) {
    // tripwire path
}
```

**Why:** an attacker who can time the compare can recover the
common prefix byte-by-byte.  For honey-name compares this leaks
which scrambled compound is honey-flagged.  For HMAC/signature
verification it leaks the expected MAC byte-by-byte.

**Boundary:** this rule applies to compares of secret-derived
bytes.  Compares of public bytes (file paths, public wordlist
entries that the attacker also has) do NOT require constant-time;
forcing them through it is theatre and costs CPU.

**Exception policy:** none.  If a compare's truth value depends
on a secret, it routes through `secret_bytes_equal`.

**Mechanical check:** code review.  No mechanical tool catches
this universally (Rust's `==` on `&[u8]` short-circuits); the
crate's reviewer scans every compare against a secret-derived
binding.

### Rule 5 — domain separation uses HKDF, never hand-rolled

```rust
// good
let subkey = derive_subkey(&host_secret, epoch, b"v2-identifier-mapping", 32)?;

// bad — do not write this
let subkey = sha256_concat(&host_secret, format!("epoch-{}-id", epoch));
```

**Why:** v1 used `SHA-256(host_secret || label)` for purpose
separation.  Functionally fine for the input shape we have, but
not an audit-recognisable primitive.  HKDF-SHA-256 (RFC 5869) is
the primitive every auditor expects to see; it is the one with
the security proof for cross-purpose independence.

The HKDF wrapper in `crates/v2-babbleon-core/src/key_derivation.rs`
fixes the salt format (epoch as 8-byte big-endian), enforces
distinct purpose labels per call site, and rejects requests
longer than HKDF's `255 × HashLen` ceiling.

**Exception policy:** none.  Every purpose-separated derivation
goes through HKDF.

**Mechanical check:** `git grep -n 'sha2\|Sha256\|hmac' crates/v2-*/src/`
review — any direct use must be a building block of HKDF itself,
not a hand-rolled derivation.

### Rule 6 — plain-English names

Cross-ref: `docs/v2/naming-conventions.md`.  A crate, module,
function, or type that requires domain knowledge to interpret
fails review.  Names describe what the thing does, not what the
literature calls it.

The audit case: a reader who has never seen Babbleon should be
able to guess what `mount_real_view` or `block_process_inspection_syscalls`
or `write_tripwire_wrapper` does.  They should NOT have to look
up what `ns-helper` or `apply-ns` does.

**Exception policy:** acronyms that auditors universally
recognise (HKDF, FIDO2, PAM, TPM, eBPF) are fine in code as type
or function names — but every public item still has a module-doc
comment that spells out what the acronym is and why it's here.

**Mechanical check:** code review.

### Rule 7 — module docs use the "What this defeats" template

Every public module starts with this docstring shape:

```rust
//! <one-sentence summary of what the module is>.
//!
//! # What this defeats
//!
//! <plain-English description of the concrete attacker action
//! this module prevents>.
//!
//! # Mechanism
//!
//! <one to three paragraphs of how the module does it>.
//!
//! # Threat model boundaries
//!
//! - Defeats: <attacker capability defeated>.
//! - Does NOT defeat: <attacker capability NOT defeated, and
//!   what layer is responsible for that>.
```

`per_host_secret.rs`, `key_derivation.rs`, `permutation.rs`,
`mapping.rs` all already follow this shape.  Read those for
model.

**Why:** module docs that say "this module does X" are
documentation; module docs that say "this module defeats Y, by
doing X, but does not defeat Z" are a threat-model commitment.
The latter is what an auditor needs.  The former is what we
already have too much of.

**Exception policy:** infrastructure modules (error enums,
constants, re-exports) replace the body sections with a
single-line "Infrastructure module" note.  See `errors.rs` and
`wordlist.rs` for examples.

**Mechanical check:** `cargo doc` rendered output — every public
module's landing page should show the four headers above (or the
infrastructure exception note).

### Rule 8 — process hardening at startup

Launchers and CLI binaries that load secret material into memory
call, in order, before any secret enters the process:

```rust
prctl(PR_SET_DUMPABLE, 0)?;   // refuse core dumps
setrlimit(RLIMIT_CORE, 0)?;   // belt-and-braces against core dumps
mlockall(MCL_CURRENT | MCL_FUTURE)?;  // refuse swap
```

The library crate (`v2-babbleon-core`) does NOT call these
itself — they're process-wide and the library doesn't own the
process.  The launcher does, and the library refuses to construct
a `PerHostSecret` if its caller has not declared hardening
applied.  (Mechanism for that declaration is filed as a follow-up;
for v2.0 the rule is by convention plus a runtime check on
`/proc/self/coredump_filter`.)

**Why:**

- *Core dumps* hit disk and bypass zeroize.
- *Swap pages* hit disk and bypass zeroize.

Both turn an in-memory-only secret into an on-disk artifact
recoverable across reboots.

**Boundary:** these calls require either capabilities
(`CAP_IPC_LOCK` for `mlockall` if `RLIMIT_MEMLOCK` is below the
working set) or no capabilities at all if the limit is high
enough.  Containers without `CAP_IPC_LOCK` and with the default
`RLIMIT_MEMLOCK` of 64 KiB fail this step; the launcher in that
case logs a warning and degrades to "swap may leak secret bytes;
operator's call whether to continue."  Refusing to run is a
denial-of-service vector for hostile container hosts.

**Exception policy:** test binaries skip this rule; their
secrets are synthetic.  All production binaries apply it.

**Mechanical check:** capability-set test in the launcher crate
asserts the three calls fired before the first `PerHostSecret`
construction in process lifetime.

### Rule 9 — every `unsafe` block carries a `SAFETY:` comment

```rust
// SAFETY: caller has ensured `fd` is a valid open file descriptor
// owned by this process; libc::close transfers ownership back to
// the kernel and may not race with another close on the same fd.
unsafe { libc::close(fd) };
```

The comment names the invariants the unsafe block relies on AND
identifies who is responsible for upholding each invariant
(caller, OS guarantee, type invariant).

**Why:** unsafe in Rust requires the writer to take on the
soundness obligation the compiler can no longer prove.  The
`SAFETY:` comment is the receipt — a reviewer can audit whether
the obligation is actually met by reading the comment plus a
small radius of context.  No comment, no receipt, no merge.

**Exception policy:** none.  If unsafe is needed, the comment is
needed.

**Mechanical check:** clippy lint `clippy::undocumented_unsafe_blocks`
flips to deny in the syscall crate's module-level config.

### Rule 10 — capability documentation per syscall site

Cross-ref: `docs/v2/least-privilege.md`.  Every syscall site that
requires a Linux capability gets a `CAPABILITY:` comment that
names:

- the capability required (e.g. `CAP_SYS_ADMIN`)
- the specific syscall (e.g. `mount(2)` MS_PRIVATE remount)
- where in the program lifecycle the capability is dropped
  (e.g. "before `execve` of child")

```rust
// CAPABILITY: CAP_SYS_ADMIN required for mount(2) with MS_PRIVATE;
// dropped before child execve via prctl(PR_SET_KEEPCAPS, 0) +
// capset(capabilities cleared).
mount_private(target)?;
```

**Why:** when an auditor asks "why does this binary have
CAP_SYS_ADMIN in its file capabilities," the answer must be
findable in the source by `git grep CAPABILITY:`.  Each result
is one syscall site, one justification.  Capabilities that
appear in the binary's file caps but have no `CAPABILITY:`
comment in the source are an audit defect.

**Exception policy:** none.

**Mechanical check:** the capability-set test compares the
unique set of `CAPABILITY:` annotations under
`crates/v2-babbleon-launch-untrusted/` against the file caps the
release pipeline installs.  Mismatch fails the release gate.

### Rule 11 — no long-lived secrets in `serde::Deserialize`-derived types

`serde::Deserialize` produces `String` and `Vec<u8>` values by
default.  Neither zeroizes on drop.  If a secret is
deserialized from a vault payload into a `String`, the deserialized
value lingers in the heap pool indefinitely.

The rule: vault-payload types that carry secret material declare
the secret-bearing field with a custom deserializer that
produces `Zeroizing<Vec<u8>>` or `SecretBox<...>`.  The plain
`String` form of the secret never exists in memory.

**Why:** v1 hit this exact bug — `host_secret_hex: String` in
`VaultPayload`.  We worked around it by zeroizing only the
decoded byte buffer (the original `String` was not zeroizable
post-serde).  v2 fixes the root cause: the secret is never a
`String` at any point in its in-memory representation.

**Exception policy:** none.

**Mechanical check:** `git grep -nE 'host_secret.*: *String|secret.*: *String' crates/v2-*/`
must return empty.  Reviewer scans every `#[derive(Deserialize)]`
struct field whose name contains "secret", "key", "hash", "hmac",
or "signature" for the custom-deserializer pattern.

### Rule 12 — RFC-recognisable primitives only; no custom crypto

The allowed list:

| Purpose | Primitive | RFC / standard |
|---|---|---|
| KDF | HKDF-SHA-256 | RFC 5869 |
| MAC | HMAC-SHA-256 | RFC 2104 |
| Hash | SHA-256, SHA-512 | FIPS 180-4 |
| AEAD | ChaCha20-Poly1305 | RFC 8439 |
| Signature | Ed25519 | RFC 8032 |
| Password hash | Argon2id | RFC 9106 |
| RNG | OS RNG via `rand::rngs::OsRng` | platform CSPRNG |

Anything not on this list requires operator sign-off recorded in
the commit message.  "Roll our own" is denied by default.

**Why:** custom crypto has a near-100% historical failure rate.
Auditors must spend their attention budget on the application-
level invariants, not on whether our private hash construction
preserves second-preimage resistance.

**Exception policy:** new primitives can be added to the table by
PR that names the standard, the implementing crate, the use site,
and the deprecation plan for whatever the new primitive replaces.

**Mechanical check:** `cargo deny`'s ban list — every crypto
crate not on the allow-list is denied at dependency-resolution
time.

### Rule 13 — errors do not leak secrets

Error enum variants do NOT carry secret bytes, secret-derived
hashes, raw key material, or paths under a secret-controlled
directory.  Error `Display` and `Debug` impls do not format any
secret.

```rust
// bad
Error::AuthFailed { expected_mac: Vec<u8>, actual_mac: Vec<u8> }

// good
Error::AuthFailed  // no fields — the user does not need them
```

**Why:** errors propagate up the stack into logs, audit
records, telemetry, stderr, and user-visible CLI output.  Any
secret that lands in an error variant lands in all of those.  The
v1 audit found one such case (an early version of vault unlock
that included the wrong-KEK first byte in the error string for
"debugging"); v2 forbids the pattern.

**Exception policy:** errors MAY carry contextual identifiers
(epoch number, file path that does NOT contain a secret-derived
name, OS error kind name).  They MAY NOT carry the secret bytes
themselves, the secret-derived bytes the compare disagreed on, or
filesystem paths under `/run/babbleon/scrambled/` (which leak
mapping state to logs).

**Mechanical check:** code review of every `Error::*` variant and
its `Display` / `Debug` impls.

### Rule 14 — secret-bearing arguments are `&` references, not owned values

When a function takes a secret as input, it takes `&PerHostSecret`
or `&Zeroizing<[u8; 32]>`, not `PerHostSecret` by value.  The
secret stays under its owner's drop guarantee.

```rust
// good
pub fn derive_subkey(secret: &PerHostSecret, epoch: u64, purpose: &[u8], len: usize) -> Result<...>

// bad
pub fn derive_subkey(secret: PerHostSecret, ...) -> ...
```

**Why:** an owned argument moves the secret into the callee's
stack frame.  If the callee panics before returning, the secret's
zeroize-on-drop runs in the panic-unwinding path — which is fine
on stable Rust but produces a complex liveness window for the
auditor to reason about.  Reference arguments keep the secret's
lifetime explicit and bounded by the caller.

**Exception policy:** constructors (`new`, `from_bytes`) accept
owned values because they wrap them.  Once wrapped, every
subsequent passing is by reference.

**Mechanical check:** code review.

### Rule 15 — tests are unit tests for primitives, property tests for invariants

- Unit tests live in `#[cfg(test)] mod tests {}` at the bottom of
  each source file, one per logical case.
- Cross-module invariants — bijection, determinism, secret-
  independence — get property tests in `tests/<topic>_properties.rs`
  using `proptest`.
- Integration tests (full CLI invocations, real namespace mounts)
  live in `tests/<scenario>.rs` and are gated behind features
  when they require root or special hardware.

**Why:** unit tests verify "this function does what its name
says"; property tests verify "this function's invariant survives
across the input space."  Both are required for primitives that
the rest of the codebase trusts.

**Exception policy:** infrastructure modules (errors, re-exports)
need only the smoke-test "module compiles" check.

**Mechanical check:** `cargo test -p <crate>` passes; for every
public function on the `Mapping` / `Permutation` / `Wordlist` /
`KeyDerivation` types, there is at least one corresponding
property-test in `tests/`.

---

## Rule summary table

| # | Rule | Lint/test | Where applied |
|---|---|---|---|
| 1 | `forbid(unsafe_code)` at root | grep | every crate |
| 2 | `deny(missing_docs)` + `warn(clippy::pedantic)` | clippy | every crate |
| 3 | Secrets wear `Zeroizing` / `SecretBox`; no Clone/Copy/Debug | grep + review | every secret-handling type |
| 4 | Constant-time compare for secret-derived bytes | review | every compare against a secret-derived binding |
| 5 | HKDF for domain separation | grep + review | every per-purpose derivation |
| 6 | Plain-English names | review | every public item |
| 7 | "What this defeats" module-doc template | `cargo doc` review | every public module |
| 8 | Process hardening before secrets enter memory | capability test | every launcher binary |
| 9 | `SAFETY:` comment per `unsafe` block | clippy lint | every `unsafe` block |
| 10 | `CAPABILITY:` comment per syscall site | release-gate test | every privileged syscall site |
| 11 | No `String` secrets in serde-derived types | grep + review | every serde-deserialized vault type |
| 12 | RFC-recognisable primitives only | cargo deny ban list | every crypto crate dep |
| 13 | Errors do not leak secrets | review | every `Error::*` variant |
| 14 | Secret-bearing arguments by reference | review | every function taking a secret |
| 15 | Unit tests + property tests + integration tests | `cargo test` | every primitive + invariant |

---

## How a new v2 crate gets certified

1. **Bootstrap.**  Copy the `v2-babbleon-core` crate root config
   (lint attributes, deny block, `Cargo.toml` lints section) so
   rules 1, 2 are satisfied by construction.
2. **Module skeleton.**  Every new public module starts with the
   "What this defeats" template (rule 7).  Filling it in is the
   first commit, not the last.
3. **Type design pass.**  Before writing the first secret-
   handling type, check rules 3, 4, 11, 13, 14.  Adding zeroize
   late produces the v1 awkward seams V2_PLAN.md warns about.
4. **Sit-check.**  Before opening the crate's first integration
   PR, scan the rule summary table and check each rule against
   the crate's actual code.  Open the PR with the table copied
   into the PR description and each box ticked or explicitly
   marked "N/A — reason."
5. **Reviewer pass.**  Reviewer re-scans the table independently.
   Disagreement on any "N/A" goes to operator before merge.

The rule list is not exhaustive — it is the minimum every crate
must satisfy.  Crate-specific invariants (e.g. the launcher's
capability drop sequence, the preprocessor's seccomp profile)
live in their own crate docs.

---

## What this baseline does NOT cover

- **Build-time supply chain.**  Covered by `docs/v2/standards-alignment.md`
  §SLSA / sigstore / cosign.
- **Release-time signing and attestations.**  Same.
- **Threat model.**  Covered by `docs/v2/threat-model.md` (TBD).
- **ATT&CK / D3FEND mapping per defended technique.**  Covered by
  `docs/v2/attack-mapping.md` (TBD).
- **OS-level profiles (AppArmor, SELinux).**  v1's templates port
  forward verbatim; landing on v2 is a phase-6 release-engineering
  task.

The baseline is the *crate-level* discipline.  The other documents
are the *system-level* discipline.  Both are required; they do
not substitute for each other.
