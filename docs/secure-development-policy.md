# Secure development policy

Maps Babbleon's process to NIST SSDF v1.1 (NIST SP 800-218) PO/PS/PW/RV
practice families.  This is the document procurement reviewers ask for;
it's also the contract the project commits to.

Living document — last refreshed 2026-06-15.

---

## PO — Prepare the Organization

**PO.1.1 Define and implement security policies.**  This file.

**PO.1.2 Identify security roles and responsibilities.**

| Role | Owner |
|---|---|
| Repository owner / approver of last resort | @qualified1079 |
| Code owners per path | See `CODEOWNERS` |
| Security disclosure intake | See `SECURITY.md` |
| Release signer | Workflow OIDC identity, `.github/workflows/release.yml` (no human key holder) |

**PO.3.1 Specify tools for each part of the SDLC.**

| Stage | Tool |
|---|---|
| Source control | git + GitHub |
| Dep audit | `cargo audit` + `cargo deny` (`deny.toml`) |
| Static analysis | `cargo clippy -D warnings` |
| Format check | `cargo fmt --check` |
| Unit + property tests | `cargo test` + `proptest` |
| Coverage | `cargo llvm-cov` (CI job; see "PW.8" below) |
| SBOM | `cargo cyclonedx` (per-PR + per-release) |
| Signing | `cosign` keyless (sigstore) |
| Provenance | `slsa-framework/slsa-github-generator@v2.0.0` |
| MAC profile | AppArmor (`policies/apparmor/`) + SELinux (`policies/selinux/`) |
| Scorecard | OpenSSF Scorecard (`.github/workflows/scorecard.yml`) |

**PO.5.1 Vulnerability disclosure.**  `SECURITY.md` +
`.well-known/security.txt` (RFC 9116) declare the disclosure channel,
supported versions, response SLA, and PGP key.

---

## PS — Protect the Software

**PS.1.1 Store source securely.**  Repo on GitHub with branch protection
on `main` (see "Branch protection" below).  Signed commits required.

**PS.2.1 Provide integrity-verification info to consumers.**
`.github/workflows/release.yml` produces:

- cosign keyless signature on the artifact and on the SBOM
- SLSA L3 provenance via the official reusable generator
- SHA-256 digest for the artifact

End-user verification commands documented in `docs/verify-release.md`.

**PS.3.1 Track origin of every component.**  Every Rust dep is
declared with a SemVer constraint in `Cargo.toml`; `Cargo.lock` pins
exact versions and digests.  `deny.toml` refuses git-source deps
(`unknown-git = "deny"`, `allow-git = []`) so a release can only
consume crates.io artifacts.

---

## PW — Produce Well-Secured Software

**PW.1.1 Design with security in mind.**  `docs/threat-model.md`
records the threat model; PRs touching the privilege-bearing surfaces
(`crates/babbleon-ns-helper/`, `crates/babbleon/src/vault/`,
`crates/babbleon/src/crypto.rs`, `crates/babbleon/src/audit.rs`,
`crates/babbleon/src/process_hardening.rs`) require explicit reviewer
sign-off per `CODEOWNERS`.

**PW.4.1 Reuse vetted components.**  Crypto primitives come from
RustCrypto + dalek; KEK from `age`; signature verification from
`ed25519-dalek`.  No hand-rolled primitives — see `docs/cwe-top25-audit.md`
§CWE-798 for the salt-constants discussion.

**PW.5.1 Create source code following secure coding practices.**
- `#![deny(unsafe_code)]` would be ideal but blocks legitimate `libc::*`
  callsites (mkfifo, kill, mlockall, prctl).  Compromise: every `unsafe`
  block carries a `SAFETY:` comment naming the caller invariants.
- Constant-time comparisons via `crate::crypto::ct_eq` for any byte-
  level secret-derived comparison.
- Secrets in `Zeroizing<...>` so they wipe on drop (vault payload,
  host secret, KEK derivation).
- HKDF with explicit salt + info instead of `SHA(secret || label)`
  concatenation.

**PW.6.1 Configure compilation, build, and interpretation tools.**
Release profile in `Cargo.toml`: `lto = "thin"`, `codegen-units = 1`,
`strip = true`, `opt-level = 3`, musl-static target.  CI builds with
`RUSTFLAGS=-D warnings`.

**PW.7.1 Review and analyze human-readable code.**  Every PR runs
`cargo fmt --check`, `cargo clippy -D warnings`, `cargo test`,
`cargo audit`, `cargo deny check`.  No merge without green CI.

**PW.8.1 Test executable code.**

- Unit tests live next to source (`#[cfg(test)] mod tests`).
- Property tests via `proptest` in `crates/babbleon/tests/`.
- Cross-crate integration tests in `crates/babbleon/tests/`.
- Coverage: `cargo llvm-cov` produces line + branch coverage on every
  push; numbers visible in the CI job's log.
- Fuzz harness (`cargo-fuzz`) filed in TODO under "Testing".

**PW.9.1 Configure software to have secure settings by default.**
- Vault unlock rate-limit ON by default (`session::unlock`).
- Ed25519 audit signing is opt-in via `ChainedAuditLog::open_signed`;
  chain-only `open` remains backward compatible.
- Enforcement: default driver is `LinuxNamespaceDriver` on Linux,
  `SimulatedDriver` elsewhere.  No silent fallback to "trusted view
  for everything".

---

## RV — Respond to Vulnerabilities

**RV.1.1 Identify vulnerabilities on an ongoing basis.**
- `cargo audit` runs in CI; `cargo deny` advisory checks run in CI.
- Dependabot weekly: cargo + github-actions ecosystems.
- OpenSSF Scorecard runs weekly via `.github/workflows/scorecard.yml`.

**RV.1.2 Analyze each vulnerability.**  Reporter and reviewers file
a CVE-style triage in the GitHub Advisory tab; severity per CVSS v3.1
with the rationale.

**RV.1.3 Plan a response.**  Per CVSS:

| Severity | Patch SLA |
|---|---|
| Critical (≥ 9.0)  | 7 days |
| High (7.0 – 8.9)   | 30 days |
| Medium (4.0 – 6.9) | 90 days |
| Low (< 4.0)        | next minor release |

**RV.2.1 Implement the response.**  Coordinated disclosure: an
advisory is filed first, fix lands behind a private branch, CVE is
requested, public release ships once the embargo expires (typically
7 days for critical, longer if downstream coordination required).

---

## Branch protection on `main`

Branch protection on `main` should enforce:

- Pull request required (no direct pushes).
- At least one reviewer approval, codeowner approval required where
  CODEOWNERS lists a path.
- All status checks (test, audit, deny, sbom) must pass.
- No force-push, no branch deletion.
- Signed commits required.
- Conversations must be resolved before merge.

This is a remote-side setting (not declared in code).  Until enabled,
the project operates one notch below SSDF expectations on PS.1.1.

---

## Cadence

- Dep updates: weekly via Dependabot.
- Advisory review: at each CI run (`cargo audit`, `cargo deny`,
  Scorecard).
- Threat-model review: every 6 months OR on a class-of-attack change
  (whichever sooner).
- Standards survey: annually; map against the then-current CWE Top 25
  + OWASP ASVS version.

---

## Mapping table — SSDF practice → artifact

| Practice | Where |
|---|---|
| PO.1.1 — security policy | This document |
| PO.1.2 — roles | `CODEOWNERS`, `SECURITY.md` |
| PO.3.1 — tools | This document, "PO.3.1" table |
| PO.5.1 — disclosure | `SECURITY.md`, `.well-known/security.txt` |
| PS.1.1 — source protection | Branch protection (above) |
| PS.2.1 — integrity verification | `docs/verify-release.md`, release.yml |
| PS.3.1 — component origin | `Cargo.lock`, `deny.toml` |
| PW.1.1 — design | `docs/threat-model.md` |
| PW.4.1 — vetted components | `Cargo.toml` deps from RustCrypto + dalek |
| PW.5.1 — secure coding | `SAFETY:` comments, `Zeroizing`, `ct_eq`, HKDF |
| PW.6.1 — build config | `Cargo.toml` `[profile.release]` |
| PW.7.1 — review | `CODEOWNERS` + CI required checks |
| PW.8.1 — testing | `cargo test`, `proptest`, coverage |
| PW.9.1 — secure defaults | Rate-limit, signed-audit opt-in, namespace driver default |
| RV.1.* — vulnerability handling | `cargo audit`, Scorecard, GitHub Advisories |
| RV.2.1 — response | This document, "Cadence" |
