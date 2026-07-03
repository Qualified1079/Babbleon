# OWASP Top 10 (2021) audit — v2

Documentary sweep of `crates/v2-*` against the OWASP Top 10 (2021)
web-application categories, filed per `docs/v2/standards-alignment.md`
§"OWASP Top 10 (2021)" ("v2 stance: web-app-shaped, so most items
don't apply. Documentary sweep ... confirming none of the top 10
manifest in Babbleon's code, analogous to v1's CWE Top 25 audit").

Babbleon v2 is a local host-security daemon + CLI (per-host code and
credential obfuscation against LLM-driven attackers) with a Unix
domain socket as its only IPC surface — not a web application. Most
of the Top 10 is genuinely N/A by absence of the surface it targets
(no HTTP server, no browser client, no SQL store, no server-side URL
fetch). Where a category maps onto an analogous local-daemon
concern (access control, crypto, injection, integrity), this audit
traces the actual mechanism instead of asserting N/A by category
name alone — a SAST tool or auditor unfamiliar with the threat model
would ask the same question a web-app reviewer would, just applied
to a different attack surface.

Each section follows the same **Surface / Mechanism / Finding**
structure as `docs/cwe-top25-audit.md` (the v1 precedent this sweep
is explicitly analogous to). Where an existing v2 doc already covers
the finding in more depth, this audit cross-references it rather
than duplicating; where the sweep surfaced a gap not tracked
anywhere else, it says so plainly and files it in `TODO.md`.

Scope: `crates/v2-*` only. `crates/babbleon*/` (v1) is out of scope —
see `docs/cwe-top25-audit.md` for the v1 audit and `crates/
DEPRECATED-V1.md` for why v1 is reference-only.

---

## A01:2021 — Broken Access Control

**Surface.** Trust-tier separation (trusted vs. untrusted view) and
the daemon's IPC socket.

**Mechanism.** Every wrapper script embeds a trust check:
`crates/v2-babbleon-core/src/wrapper.rs`'s `render`/`TEMPLATE`
generates `_bl_in_trusted_ns()`, which compares the caller's
`/proc/self/ns/mnt` inode against a value baked into the script at
render time and exits 127 with no output if the comparison fails —
the untrusted tier cannot observe *why* it failed, only that it did.
Capability dropping for the untrusted launcher is implemented
end-to-end across `crates/v2-babbleon-launch-untrusted/src/
{bounding_set,identity_drop,seccomp_profile,namespaces,mounts,
syscall}.rs`, each privileged call site carrying a `CAPABILITY:`
comment per security-baseline rule 10 (`docs/v2/least-privilege.md`
covers this in full — cross-reference, not duplicated here).

**Finding — gap found, closed 2026-07-03.** At audit time the
daemon's Unix domain socket
(`crates/v2-babbleon-daemon/src/socket.rs::bind_socket`) was created
at mode `0o660` (group-gated, not world-writable) but had no
peer-credential check — any process in the socket's group could open
a session, not just the intended caller.

Closed via `SO_PEERCRED`: `socket.rs::check_peer_uid` reads the
kernel-populated peer credentials via `getsockopt(SO_PEERCRED)`
(through `nix::sys::socket`, keeping `#![forbid(unsafe_code)]` intact)
and rejects any connection whose peer uid does not match the daemon
process's own uid, before a byte of the request is ever read.
`serve_blocking` takes the expected uid as a parameter rather than
calling `getuid()` internally — the daemon's own uid is computed once
in `main.rs`, **before** the seccomp filter installs, specifically so
`getuid` never needs to join the post-filter allowlist. `getsockopt`
itself DOES need to join it (per-connection, unavoidable): this was
discovered the hard way when the daemon subprocess in
`tests/end_to_end_binary.rs` started dying with `SIGSYS` mid-fix — see
the A05 section below for the corrected understanding that finding
produced.

New `ErrorKind::Unauthorized` wire variant so a rejected peer gets an
explicit, minimal-detail response instead of a mysterious dropped
connection; the detailed uid mismatch goes to the daemon's own logs
via `accept_error_handler`, not over the wire. Two new unit tests in
`socket.rs` (`check_peer_uid_accepts_the_actual_peer_uid`,
`check_peer_uid_rejects_a_mismatched_uid`) plus two new seccomp-list
tests confirming `getsockopt` is allowed and `getuid` deliberately is
not.

---

## A02:2021 — Cryptographic Failures

**Surface.** Domain-separated key derivation, secret-in-memory
handling, secret comparison, KEK stretching, and the audit log's
signing.

**Mechanism.** `crates/v2-babbleon-core/src/key_derivation.rs`
derives every per-purpose sub-key via `HKDF-SHA-256` (RFC 5869) —
`derive_subkey` (epoch-salted) and `derive_domain_seed` (unsalted,
for the role-partitioning seed path; see that module's doc comment)
— replacing v1's hand-rolled `SHA256(secret||label)` construction.
`per_host_secret.rs::PerHostSecret` wraps the 32-byte secret in
`Zeroizing` and deliberately omits `Clone`/`Copy`/`Debug` so the
value cannot proliferate or leak via a stray `{:?}`.
`crypto_compare.rs` exposes constant-time comparison via
`subtle::ConstantTimeEq`. KEK stretching is Argon2id
(`crates/v2-babbleon-vault/src/soft_backend.rs`, RFC 9106 profile)
feeding an `age`-format AEAD envelope. Audit-log entries can be
Ed25519-signed (`core/src/events.rs::AuditChainSink`). No
home-rolled cryptographic primitive was found anywhere in `crates/
v2-*`.

**Finding — no fix; cross-reference.** `docs/v2/security-baseline.md`
rules 3 (Zeroizing/SecretBox), 4 (constant-time compare), and 12
(RFC-recognisable primitives only) already certify every v2 crate
against this exact category. Nothing new to file.

---

## A03:2021 — Injection

**Surface.** The wrapper-script renderer (the v2 analogue of the
v1 CWE-78/CWE-94 surface `docs/cwe-top25-audit.md` already audited)
and every `std::process::Command` call site across `crates/v2-*`.

**Mechanism.** `crates/v2-babbleon-core/src/wrapper.rs::validate_name`
(allowlist `[a-z0-9-]`) and `validate_path` (rejects `"`, `$`,
backtick, `\`, `\n`, `\r`, NUL) gate every value `render()`
interpolates into the shell template via `String::replace` — the
same discipline the v1 audit verified, ported forward. Every
`Command::new` call site found across `crates/v2-*`
(`v2-babbleon/src/enroll.rs::SystemHost::current_login_shell`/
`chsh`, `v2-babbleon-python-shim/src/exec_python.rs`,
`v2-babbleon-launch-untrusted/src/main.rs`) passes a fixed argv —
none of them build a command string and hand it to a shell (`sh
-c`). No shell-metacharacter injection surface was found.

**Finding — no fix.** Equivalent to the v1 finding in
`docs/cwe-top25-audit.md` §"CWE-78 / CWE-77 / CWE-94" — ported
forward cleanly, no regression. Nothing new to file.

---

## A04:2021 — Insecure Design

**Surface.** The development process itself, not a code surface.

**Mechanism.** `docs/v2/threat-model.md` §4's STRIDE matrix
(Spoofing/Tampering/Repudiation/Information-disclosure/Denial-of-
service/Elevation rows, each with a Shipped / Carry-from-v1 /
New-in-v2 status and a code citation) is the per-surface secure-
design analysis. `docs/v2/security-baseline.md`'s 15-rule
certification checklist plus its "how a new v2 crate gets
certified" bootstrap procedure is the process control that keeps
new code from shipping insecure-by-design.

**Finding — no fix; cross-reference.** Both docs directly and fully
cover this category; a documentary "does Babbleon do threat
modelling" sweep would just restate their existence. Nothing new to
file.

---

## A05:2021 — Security Misconfiguration

**Surface.** Seccomp profiles and default policy values.

**Mechanism.** `docs/v2/preprocessor-seccomp-envelope.md` documents
a 34-syscall allowlist (backed by `v2-babbleon-launch-untrusted/src/
seccomp_profile.rs` and `v2-babbleon/src/seccomp_profile.rs`).
Observed secure-by-default values: the daemon socket is `0o660`
(not world-writable, see A01), and
`crates/v2-babbleon-core/src/tripwire.rs::TripwireResponsePolicy`
defaults to `NotifyOnly` — no automatic kill/quarantine action
unless an operator opts in, so a misconfigured tripwire cannot
itself become a denial-of-service vector.

**Finding — corrected 2026-07-03; not a gap.** The original pass of
this audit read `docs/v2/daemon-seccomp-envelope.md`'s own banner
("DRAFT for operator confirmation... before it lands in code") and
concluded the daemon runs unfiltered — without actually running the
daemon to check. It was wrong. Directly testing confirmed
`crates/v2-babbleon-daemon/src/seccomp_profile.rs::apply()` installs
a 40-syscall (now 41, see below) allowlist **by default** at daemon
startup (`cli.rs`'s `disable_seccomp` field defaults to `false`, pinned
by a unit test); `--no-seccomp` is an explicit opt-out for local
development only. The two integration tests the envelope doc
describes in future tense (`## Test strategy when the profile
pins`) — `tests/seccomp_envelope.rs` and
`tests/seccomp_denies_forbidden.rs` — already exist and pass. This
was discovered while building the A01 fix below: adding
`SO_PEERCRED` support required a new syscall (`getsockopt`), and the
daemon subprocess in `tests/end_to_end_binary.rs` immediately
started dying with `SIGSYS` (`dmesg` showed the kernel killing it for
an un-allowlisted `getuid` call) — which is only possible if a real,
active seccomp filter is enforcing in that test run. A doc that
merely proposed a filter could not have produced that failure.
`docs/v2/daemon-seccomp-envelope.md`'s banner and this audit's own
original A05 entry were both corrected in the same commit that
landed the A01 fix. The narrower, still-genuinely-open question is
whether an operator has reviewed and signed off on the *specific*
41-syscall envelope as final — a policy review, not a "wire it up"
gap — tracked in `TODO.md` with the corrected framing.

---

## A06:2021 — Vulnerable and Outdated Components

**Surface.** Third-party dependency supply chain.

**Mechanism.** `.github/workflows/ci.yml` runs `cargo audit`, `cargo
deny` (`EmbarkStudios/cargo-deny-action`), a CycloneDX SBOM job
(`cargo-cyclonedx`), and `cargo vet`. `.github/dependabot.yml` runs
weekly against both the `cargo` and `github-actions` ecosystems,
with a grouped `crypto-patches` update train covering `ed25519-*`,
`hkdf`, `sha2`, `subtle`, `zeroize`, and related crates so a
security-relevant patch doesn't get lost in a large batched bump.

**Finding — partial; cross-reference plus one open item already
tracked.** The `vet` job runs in `continue-on-error: true` mode
because `supply-chain/audits.toml` / `exemptions.toml` are still
empty pending an operator-run `cargo vet regenerate exemptions`
backfill — this is already tracked in `TODO.md` §"Supply-chain +
build integrity" (the `cargo-vet` `[~]` item). Nothing new to file;
cite the existing item.

---

## A07:2021 — Identification and Authentication Failures

**Surface.** Vault-unlock credential verification.

**Mechanism.** `crates/v2-babbleon-vault/src/backend.rs::KekBackend`
+ `soft_backend.rs` (Argon2id) is the unlock-credential stretch —
every unlock attempt costs real CPU time by design, which is a
partial brute-force mitigant on its own.

**Finding — gap found, closed 2026-07-03.** At audit time, v2 had
**no attempt-rate-limiting or lockout** on repeated unlock attempts.
Note the gap was originally traced to
`crates/v2-babbleon-daemon/src/state.rs::DaemonState::unlock`, which
was a mis-scoping worth recording: that function installs an
*already-unsealed* secret into daemon memory and has no "wrong
guess" concept to rate-limit at all (any bytes handed to it get
installed — there's no independent check to brute-force). The real
gate is the CLIENT-side `Vault::unseal` call in `crates/v2-babbleon/
src/vault_lifecycle.rs::run_unlock`, which is where the Argon2id KDF
actually runs against the operator's passphrase — the same location
v1's `AttemptTracker` lived at
(`crates/babbleon/src/vault/attempts.rs`, not the v1 daemon).

Ported as `crates/v2-babbleon-vault/src/attempts.rs::AttemptTracker`
(same policy: 3 free attempts, then `2^(n-3)`s backoff capped at
60s, lockout at 10 consecutive failures), wired into `run_unlock`
*before* the passphrase prompt and *before* the KDF runs, so a
refused attempt costs nothing. Closes `docs/v2/threat-model.md` row
D1 (now "Shipped") and the `TODO.md` item this finding filed.

---

## A08:2021 — Software and Data Integrity Failures

**Surface.** Release-artifact signing/provenance and the daemon IPC
wire format's trust assumptions.

**Mechanism.** `.github/workflows/release.yml` implements cosign
keyless signing (sigstore/Fulcio OIDC, no long-lived key) and SLSA
L3 provenance (`slsa-framework/slsa-github-generator@v2.0.0`) plus
a CycloneDX SBOM, all pinned to a tag ref. On the wire side,
`crates/v2-babbleon-daemon-protocol/src/protocol.rs`'s module docs
state plainly that the parser "assumes a valid peer" — message-level
integrity is not independently verified; trust is placed entirely
at the socket-permission layer (A01). Epoch state itself is
protected separately: `crates/v2-babbleon-daemon/src/
epoch_journal.rs` provides an HMAC-sealed journal so a tampered
on-disk epoch record is detected at resume, tested in
`state.rs::resume_epoch_from_journal`'s round-trip coverage.

**Finding — genuine gap, filed.** The release `build` job currently
bundles only the v1 binaries (`babbleon`, `babbleon-ns-helper`) —
**v2 binaries are not yet part of the signed, SLSA-attested release
pipeline.** Since v2 is the shipping product (`CLAUDE.md` §1), this
is a real integrity-supply-chain gap, not a documentation nit: an
operator downloading a "signed Babbleon release" today gets
cryptographic assurance over code that isn't the product they're
running. Filed in `TODO.md`.

---

## A09:2021 — Security Logging and Monitoring Failures

**Surface.** Tamper-evident event logging.

**Mechanism.** `crates/v2-babbleon-core/src/events.rs` is a complete
mechanism: an `Event` enum (`Tripwire`, `UnlockFailed`,
`RotationComplete`, `VaultSealed`, ...) with `Severity`
classification, an `EventSink` trait, a `StderrSink` +
`JsonlFileSink` for operator-facing output, and `AuditChainSink` — a
SHA-256 hash-chained log (each entry's hash covers the previous
entry's hash, so a deleted or reordered entry breaks the chain),
optionally Ed25519-signed, with a `audit_chain_detects_tampering`
test proving the tamper-detection property rather than merely
asserting it. `tripwire.rs::TripwireResponsePolicy` (default
`NotifyOnly`) plus `TripwireResponder`/`LogOnlyResponder` complete
the alerting side.

**Finding — no fix; cross-reference.** `docs/v2/threat-model.md`
row T1 already cites `events::AuditChainSink` directly as the
control for this exact STRIDE category. Nothing new to file.

---

## A10:2021 — Server-Side Request Forgery (SSRF)

**Surface.** None — confirmed by absence, not assumed.

**Mechanism.** No `crates/v2-*` package depends on `reqwest`,
`hyper`, `ureq`, or any other HTTP client, and no code constructs a
`TcpStream`. The daemon's only IPC surface is
`std::os::unix::net::UnixListener`
(`crates/v2-babbleon-daemon/src/socket.rs`) — not a TCP listener,
so there is no network-facing service to redirect. The one crate
that plausibly needed network access —
`crates/v2-babbleon-resilience-bench` (LLM-adversary evaluation) —
deliberately shells out to an operator-supplied `curl` command
(`src/evaluator.rs`) instead of embedding an HTTP client, with the
module doc stating the design goal explicitly: "zero-network: no
`reqwest`, no provider SDK, no API-key handling in our address
space."

**Finding — N/A, verified.** No SSRF-shaped surface exists anywhere
in `crates/v2-*`. Re-check this finding if a future crate ever adds
an HTTP client dependency.

---

## Summary

| Category | Verdict | Action |
|---|---|---|
| A01 Broken Access Control | **Closed 2026-07-03** | `SO_PEERCRED` peer-uid check added to `socket.rs::serve_blocking` |
| A02 Cryptographic Failures | No fix | Covered by security-baseline.md rules 3/4/12 |
| A03 Injection | No fix | Ported clean from v1's audited pattern |
| A04 Insecure Design | No fix | Covered by threat-model.md + security-baseline.md |
| A05 Security Misconfiguration | **No fix — original finding was wrong** | Filter is active by default in code; only the envelope-doc banner was stale |
| A06 Vulnerable/Outdated Components | Partial | `cargo vet` exemptions backfill — already tracked |
| A07 Auth Failures | **Closed 2026-07-03** | `AttemptTracker` ported to `v2-babbleon-vault`, wired into `run_unlock` |
| A08 Software/Data Integrity | **Gap** | v2 binaries missing from signed release pipeline — filed |
| A09 Logging/Monitoring Failures | No fix | Covered by threat-model.md T1 + events.rs |
| A10 SSRF | N/A | No network surface exists |

Of the four items this audit originally flagged, three turned out to
be real (A01, A07, A08) and one was a false positive caused by
trusting a stale doc banner instead of running the binary (A05,
corrected in the same session — see that section above). A01 and A07
closed the same day the audit landed; A08 remains open, needing a
small operator decision (which v2 binaries ship) rather than a hard
gate. The corrected A05 entry is the audit's own most useful
finding in a sense: it is a reminder that "the doc says X" and "the
code does X" are different claims, and this audit's own first pass
conflated them exactly once. Filed in `TODO.md` under "v2
security-hygiene gaps (OWASP Top 10 audit)" so the group stays
easy to re-triage as items close.

## Update cadence

Re-run this audit whenever:

- A new v2 crate is added to `crates/v2-*`.
- The daemon socket authentication model changes.
- A new IPC message type is added to `v2-babbleon-daemon-protocol`.
- The release workflow's binary bundle changes.

Last refreshed: 2026-07-03.
