# Standards survey — where Babbleon sits today

Survey of the broad security standards an open-source security
tool is expected to align with.  Each section names the standard,
captures the substantive content from the live documents, gives a
Babbleon gap analysis, and points at the corresponding `TODO.md`
entries.  Performed 2026-06-15 as the input to the overnight
build queue.

The four standards covered:
  - **OWASP ASVS 5.0** (Application Security Verification Standard, May 2025).
  - **NIST SP 800-218 SSDF v1.1** (Secure Software Development Framework, Feb 2022).
  - **OpenSSF Scorecard** (20 active checks as of 2025).
  - **SLSA v1.0** (Supply-chain Levels for Software Artifacts).
  - **CWE Top 25** (2024 ranking from CISA + MITRE).

A separate **NIST SP 800-218A** (Secure Software Development Practices
for Generative AI and Dual-Use Foundation Models) is noted at the
bottom — it's a SSDF community profile for AI systems, NOT directly
applicable to Babbleon's threat model (which defends *against* AI
attackers, not which trains them), but interesting context.

---

## 1. OWASP ASVS 5.0

**Headline.**  ASVS 5.0 was released May 2025 — the largest revision
since the project began in 2008.  Defines ~350 requirements across
17 chapters, modularly composable so a project can apply only the
chapters that fit its surface.  Modernizes ASVS for cloud-native
architectures, automation, and clearer crypto / supply-chain
controls.

**Chapter shape (the 17, abridged):** Architecture, Authentication,
Session Management, Access Control, Validation/Sanitization, Stored
Cryptography, Error Handling and Logging, Data Protection,
Communications, Malicious Code (composition / supply chain), Business
Logic, Files & Resources, API & Web Service, Configuration, Mobile,
WebRTC, IoT.

**Verification levels.** L1 (opportunistic), L2 (standard for most
applications), L3 (high-value).  Babbleon's claim is roughly L2 with
some L3 hardening (mount-namespace + seccomp + Landlock stack).

**Babbleon gap analysis.**

| ASVS chapter | Babbleon stance |
|---|---|
| Architecture | Strong: explicit trust tiers, separation between trusted-view and untrusted-view drivers, kernel-call surface centralized in `syscalls.rs`.  Threat model documented. |
| Authentication | Vault unlock = passphrase / FIDO2 / TPM / USB-keyfile tiers.  **Gap**: rate-limiting on unlock attempts (filed; see TODO). |
| Session Management | n/a — no web sessions. |
| Access Control | Trust tier is the access-control axis; namespace boundary is the enforcement.  Solid. |
| Validation / Sanitization | Honey-FIFO parses untrusted JSON.  **Gap**: no fuzz harness on the parser (filed). |
| Stored Cryptography | Argon2id KEK, age envelope encryption, SHA-256 hash chain in audit log.  **Gap**: hand-rolled domain separation (use HKDF — filed); constant-time compares missing (filed); zeroization (landing now). |
| Error Handling & Logging | `ChainedAuditLog` SHA-256 chain; `StderrSink`/`JsonlFileSink` event bus.  **Gap**: per-entry Ed25519 signing (filed). |
| Data Protection | Credential gate (tmpfs overlay) + env-var scrub (suffix matcher).  Solid. |
| Communications | No network surface in M3.  Future SIEM sinks (M5) will need TLS pinning. |
| Malicious Code | Supply chain weak: `cargo-audit` + `cargo-deny` only.  **Gap**: `cargo-vet`, SBOM, sigstore (all filed). |
| Configuration | musl static release, capability drops, seccomp + Landlock by default. |
| Files & Resources | mount-namespace + Landlock allowlist.  Strong. |
| API / Web Service / Mobile / WebRTC / IoT | n/a for v1. |

**No new TODO items** from this section that aren't already filed in
`TODO.md`.  Recorded the chapter mapping above so future audits can
locate Babbleon's evidence per chapter without re-deriving it.

Source: https://owasp.org/www-project-application-security-verification-standard/
        https://github.com/OWASP/ASVS

---

## 2. NIST SP 800-218 SSDF v1.1

**Headline.**  Federal-procurement-friendly secure-software framework
released Feb 2022.  Organized into four practice families:

- **PO — Prepare the Organization.**  People, processes, technology
  ready to perform secure development before code is written.
  Includes security training, role definitions, toolchain readiness,
  signed builds policy.
- **PS — Protect the Software.**  Protect source and binaries from
  tampering and unauthorised access at rest and in transit.
  Signed releases, dependency integrity, intermediate-build
  protection.
- **PW — Produce Well-Secured Software.**  The "build-time"
  practices: design review, secure coding standards, code review,
  static + dynamic analysis, automated testing of executables, well-
  managed third-party components.
- **RV — Respond to Vulnerabilities.**  The post-release contract:
  identify residual vulnerabilities, root-cause them, ship fixes,
  inform users.

**Babbleon gap analysis.**

| Family | Where we sit |
|---|---|
| PO | Strong: documented threat model, clear roles (this is a one-maintainer project with a forking-friendly public README), Rust toolchain with reproducible-build target.  **Gap**: no published secure-development policy doc; PR_SET_DUMPABLE etc. for the daemon land in this commit's queue. |
| PS | **Gap**: no signed releases (filed — sigstore/cosign).  No SBOM (filed).  `cargo-vet` not deployed (filed). |
| PW | Code review = single-maintainer-with-AI; no formal SAST beyond clippy (CodeQL filed in TODO); some fuzz harnessing filed; test coverage measurable but not measured (add `cargo-llvm-cov` as a follow-up). |
| RV | `SECURITY.md` landed this session covering RV process: triage, CVE, advisory, patch, reporter credit.  90-day disclosure window.  GHSA flow documented. |

**New TODO items from this section:**

- [ ] **`docs/secure-development-policy.md`** — explicit policy doc
      covering: branch protection rules, required reviewers, allowed
      crates, dependency-update cadence, release-signing procedure.
      Maps onto SSDF PO.1–PO.5.  Required for any federal procurement
      pitch.
- [ ] **`cargo-llvm-cov` (or `cargo-tarpaulin`) coverage in CI.**
      Measurable, not just claimed.  Maps onto SSDF PW.8.
- [ ] **`cargo-deny` policy expansion**: ban yanked deps, ban
      non-permissive licenses, ban git-source deps in release
      profile.  Already partially configured (`deny.toml`) but worth
      a sweep against current SSDF guidance.

Source: https://csrc.nist.gov/projects/ssdf

---

## 3. OpenSSF Scorecard (20 checks, 2025)

Each check scores a project 0–10 on one axis.  Composite score is
the project's "Scorecard."  Full check list below with Babbleon's
current status:

| Check | Babbleon today | Status |
|---|---|---|
| Binary-Artifacts | No checked-in binaries (only `tools/ebpf/exec_guard.bpf.c` + Makefile).  Build artifacts in `target/` ignored. | ✅ Likely 10/10 |
| Branch-Protection | Solo-maintainer repo; no enforced protection.  **Gap**: enable on remote. | ❌ Likely low |
| CI-Tests | `cargo test --workspace` runs in CI.  | ✅ Likely 10/10 |
| CII-Best-Practices | Not registered.  Filed (OpenSSF Best Practices Badge). | ❌ 0/10 |
| Code-Review | Solo work; no required-reviewer policy. | ❌ Low |
| Contributors | One contributor org. | ⚠️ Will score low while solo |
| Dangerous-Workflow | No workflows look unsafe; verify against Scorecard's pattern set. | ✅ Probably fine |
| Dependency-Update-Tool | No Dependabot / Renovate configured.  **Gap**: enable Dependabot. | ❌ 0/10 |
| Fuzzing | No fuzz harness yet.  Three surfaces filed for `cargo-fuzz`. | ❌ 0/10 → goal 10/10 |
| License | `LICENSE` is PolyForm Noncommercial 1.0.0; declared in `Cargo.toml`. | ✅ 10/10 |
| Maintained | Active commits; should score 10/10. | ✅ |
| Packaging | Not published to crates.io yet (PolyForm non-commercial license blocks the default registry expectation). | ⚠️ Limited by license model |
| Pinned-Dependencies | `Cargo.lock` committed for the binary crates; workspace deps use semver ranges.  **Gap**: confirm policy. | ⚠️ Partial |
| SAST | clippy + cargo-audit + cargo-deny; no CodeQL.  Filed. | ❌ until CodeQL lands |
| SBOM | None.  Filed. | ❌ → goal |
| Security-Policy | `SECURITY.md` landed this session. | ✅ 10/10 |
| Signed-Releases | No releases yet; sigstore/cosign filed. | ❌ → goal |
| Token-Permissions | CI workflow tokens — verify `permissions:` block in YAML uses least-privilege. | ⚠️ Audit needed |
| Vulnerabilities | `cargo-audit` runs in CI; no current CVEs in deps. | ✅ |
| Webhooks | No webhooks configured. | ✅ n/a |

**New TODO items from this section:**

- [ ] **Enable branch protection on the remote** (Scorecard
      Branch-Protection): require PR review, require status checks
      pass, no force-push to main, signed commits required.
- [ ] **Configure Dependabot** (Scorecard Dependency-Update-Tool).
      Weekly cadence on `cargo` + GitHub-Actions ecosystems.
- [ ] **Audit `.github/workflows/*.yml` for explicit
      `permissions:`** blocks — Scorecard Token-Permissions check
      flags missing-or-write-all defaults.
- [ ] **Run Scorecard against the repo and publish the score** in
      README once the above land.

Source: https://github.com/ossf/scorecard/blob/main/docs/checks.md

---

## 4. SLSA v1.0 Build Levels

**Headline.**  Supply-chain Levels for Software Artifacts.  Build
track has L0–L3; each level constrains how the build runs and what
provenance it produces.

**Levels:**

- **L0** — no provenance produced.  Babbleon today.
- **L1** — provenance exists and is distributed; documents build
  environment, process, inputs.  May be incomplete and unsigned.
- **L2** — *hosted* build (GitHub Actions / Buildkite / similar, not
  a maintainer's workstation); platform signs the provenance with a
  digital signature.
- **L3** — *hardened* hosted build with strong isolation between
  runs (no cross-run leakage) and *unforgeable* provenance (signing
  keys inaccessible to user-defined build steps; nothing the build
  YAML can do can exfiltrate or forge the signing key).

**Babbleon gap analysis.**

- Current: L0.  Releases are tarballs off the maintainer's
  workstation, no provenance, no signatures.
- Realistic v1 target: L2.  GitHub Actions release workflow that
  emits provenance and uses sigstore/cosign for the signing.
- Realistic v2 target: L3.  Either GitHub's reusable workflow that
  is OIDC-bound and runs in an isolated VM (this is the documented
  GHA L3 path), or a custom builder running in a confidential VM.

**New TODO items:**

- [ ] **Release workflow producing SLSA L2 provenance.**  GitHub
      Actions release.yml that produces an `intoto` provenance file
      via `slsa-framework/slsa-github-generator`, signs it via
      sigstore, attaches both to the release.  Closes the gap from
      "no provenance" to L2 in one workflow.
- [ ] **Documentation showing users how to verify L2 provenance.**
      `docs/verify-release.md` with the cosign + slsa-verifier
      commands.
- [ ] **SLSA L3 target as a v2 stretch goal.**  Probably via the
      official `slsa-framework/slsa-github-generator` reusable
      workflow which is documented as L3-conformant on GitHub-hosted
      runners.

Source: https://slsa.dev/spec/v1.0/levels

---

## 5. CWE Top 25 (2024, CISA + MITRE)

**Headline.**  Ranked list of the 25 most dangerous weakness
categories, derived from CVE records June 2023–June 2024 with
emphasis on what shows up in CISA's KEV catalog.  Babbleon should
not exhibit any of the top 25 in its own code; using this list as
an audit checklist is standard practice.

**Per-weakness gap analysis** (Babbleon-relevant only — many are
web-app classes that simply don't apply to a Rust CLI / library):

| # | CWE | Weakness | Babbleon exposure |
|---|---|---|---|
| 1 | CWE-79 | Cross-site Scripting | n/a (no HTTP surface) |
| 2 | CWE-787 | Out-of-bounds Write | Rust safe by default; audit `unsafe` blocks (covered by current SAFETY-comment pass + filed `miri` runs) |
| 3 | CWE-89 | SQL Injection | n/a (no SQL) |
| 4 | CWE-352 | CSRF | n/a |
| 5 | CWE-22 | Path Traversal | **Audit needed**: wrapper paths constructed from scrambled names + real paths; any user-supplied component could traverse.  Filed below. |
| 6 | CWE-125 | Out-of-bounds Read | Same as CWE-787; Rust safe-by-default + `unsafe`-audit. |
| 7 | CWE-78 | OS Command Injection | **Audit needed**: wrapper script generation uses `replace()` over a template; verify nothing in the template can be turned into shell injection by a malicious tracked-tool name or decoy banner.  Filed below. |
| 8 | CWE-416 | Use After Free | Rust safe-by-default. |
| 9 | CWE-862 | Missing Authorization | Trust-tier check via mnt-ns inode comparison; verify the inode-file write is atomic and not readable by untrusted tier. |
| 10 | CWE-434 | Unrestricted File Upload | n/a |
| 11 | CWE-94 | Code Injection | **Audit needed**: wrapper template is shell.  Same fuzz target as CWE-78. |
| 12 | CWE-20 | Improper Input Validation | Honey-FIFO JSON parser; filed for fuzz. |
| 13 | CWE-77 | Command Injection | Same as 78. |
| 14 | CWE-287 | Improper Authentication | Vault unlock = our auth.  Rate-limiting gap filed. |
| 15 | CWE-269 | Improper Privilege Management | ns-helper does setuid + drop caps + NNP.  Audit needed. |
| 16 | CWE-502 | Deserialization | `serde_json::from_slice` over FIFO input + vault payload.  Bounded types; low risk but fuzz target catches misuse. |
| 17 | CWE-200 | Sensitive Info Exposure | `/proc/self/maps` libc leak is documented L3.  Other exposures: env scrubber + credential gate handle. |
| 18 | CWE-863 | Incorrect Authorization | Same as 862. |
| 19 | CWE-918 | SSRF | n/a |
| 20 | CWE-119 | Buffer Bounds | Same as 787/125. |
| 21 | CWE-476 | NULL Pointer Deref | Rust safe-by-default. |
| 22 | CWE-798 | Hard-coded Credentials | **Audit needed**: `SALT` constants in soft.rs and usb.rs are public per-purpose labels (intentional for domain separation), but document this so a fork doesn't read them as a finding. |
| 23 | CWE-190 | Integer Overflow | Rust does panic-on-overflow in debug + wrapping in release; ensure security-relevant arithmetic uses `checked_*` / `saturating_*`. |
| 24 | CWE-400 | Uncontrolled Resource Consumption | Honey-FIFO is unbounded.  Filed below. |
| 25 | CWE-306 | Missing Authentication | Trust-tier boundary is the auth.  ns-inode check in wrappers. |

**New TODO items from this section:**

- [ ] **CWE-22 audit pass on wrapper-path construction.**
      `enforcement/wrapper.rs` builds output paths from scrambled
      names; the scrambled name is a HMAC-output compound that
      cannot contain `/` or `..`, so the audit is documentary
      ("here is why CWE-22 doesn't apply"), not corrective.  But
      record the reasoning explicitly.
- [ ] **CWE-78 / 77 / 94 audit on the wrapper shell template
      renderer.**  `render()` in `wrapper.rs` does `String::replace`
      over placeholders, which is *not* shell-safe escaping.  The
      decoy banner is `replace('\'', "'\\''")`-escaped; verify the
      other fields (scrambled name, real path, ns_inode) cannot be
      attacker-controlled — they aren't today (they all come from
      vault-derived material), but document the chain of trust.
      Fuzz target for this is already filed.
- [ ] **CWE-400 bound on the honey-FIFO reader.**  Add a
      `BufReader::with_capacity` cap + per-line length limit so a
      runaway producer cannot OOM the daemon.  Cheap; closes a
      DoS vector.
- [ ] **CWE-798 documentary note for SALT constants.**  In `soft.rs`
      and `usb.rs`, add a comment explaining the SALT is a public
      domain-separation tag, not a secret; pointing forward to the
      HKDF migration that will make this obvious by the type
      signature.
- [ ] **CWE-269 audit on the ns-helper privilege flow.**  Walk the
      cap-drop / NNP / seccomp sequence; document why no step can
      retain residual privilege if the next step fails.  We do this
      today; just write it down.

Source: https://www.cisa.gov/news-events/alerts/2024/11/20/2024-cwe-top-25-most-dangerous-software-weaknesses

---

## 6. NIST SP 800-218A — GenAI SSDF community profile

Published 2024 as a community profile of SSDF v1.1 specifically for
projects that **produce** generative-AI or dual-use foundation
models.  Babbleon does neither — we defend hosts *against* AI
attackers — so 800-218A is not on our compliance path.

**But it's interesting context.**  The profile names AI-attacker
scenarios as in-scope risks for AI *producers*; Babbleon is the
defender for those same scenarios at the host layer.  If/when
Babbleon publishes its threat model in a form intended for AI-vendor
adoption (e.g. "host-side defense for systems that the producer's
generative model may eventually run on"), 800-218A is the right doc
to map our threat model into.

No TODO items.  Filed here as context.

Source: https://csrc.nist.gov/pubs/sp/800/218/a/final

---

## Summary of new TODO items added by this survey

Added to `TODO.md`:

1. `docs/secure-development-policy.md` (SSDF PO/PS).
2. `cargo-llvm-cov` coverage in CI (SSDF PW.8).
3. `cargo-deny` policy sweep against current SSDF guidance.
4. Enable branch protection on remote (Scorecard).
5. Configure Dependabot (Scorecard).
6. Audit GitHub Actions workflow `permissions:` blocks (Scorecard).
7. Publish Scorecard result in README once landed.
8. SLSA L2 release workflow with provenance + sigstore signing.
9. `docs/verify-release.md` showing users how to verify provenance.
10. SLSA L3 as v2 stretch goal.
11. CWE-22 documentary audit on wrapper-path construction.
12. CWE-78/77/94 wrapper-renderer audit + fuzz target (fuzz target
    already filed; the audit doc is new).
13. CWE-400 length-bounded honey-FIFO reader.
14. CWE-798 documentary note on public SALT constants.
15. CWE-269 documentary audit on ns-helper privilege chain.

The existing items in `TODO.md` (HKDF, zeroize, constant-time,
daemon hardening, fuzz harness, SBOM, cosign signing, AppArmor,
Ed25519 log signing, etc.) all still apply — the survey did not
displace any of them.

---

## What I'd build first, ordered

1. **Now (already mid-flight):** zeroize secrets, SAFETY comments,
   daemon hardening, constant-time compares.  Closes immediate
   cryptographic-hygiene class.
2. **Next:** HKDF replacement of hand-rolled HMAC-of-purpose.
   Pairs with constant-time; auditor-recognizable.
3. **Then:** vault unlock rate-limiting.  Closes CWE-287 angle.
4. **Then:** length-bounded honey-FIFO reader + Cargo.toml audit.
   Closes CWE-400.
5. **Then:** documentary audits — wrapper renderer, ns-helper
   privilege chain, SALT note.  Each is a few-paragraph block in
   the affected module's top doc-comment; closes the CWE Top 25
   sweep without code change.
6. **Then:** GitHub Actions hardening — explicit `permissions:`,
   branch protection, Dependabot, Scorecard workflow itself.
7. **Then:** SBOM generation in CI.
8. **Then:** SLSA L2 release workflow.
9. **Then:** AppArmor / SELinux profile templates.
10. **Then:** Ed25519 audit-log signing.
11. **Eventually:** fuzz harness on the three surfaces.

The 1–5 items are pure-Rust changes in this repo with no external
infra; 6–11 touch CI / packaging / OS profiles and benefit from
review before landing.
