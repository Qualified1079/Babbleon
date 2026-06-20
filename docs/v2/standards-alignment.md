# Standards alignment — v2

v1's standards survey (`docs/standards-survey.md`) covered five
foundational standards.  Honest accounting: the survey was not
exhaustive.  This document records the standards v1 missed,
explains why they matter for v2, and maps Babbleon's v2 design
onto each.

## Standards v1 covered (still apply to v2)

- **OWASP ASVS 5.0** — application security verification.
- **NIST SP 800-218 (SSDF v1.1)** — secure software development.
- **OpenSSF Scorecard** — 20-check repository health metric.
- **SLSA v1.0** — supply-chain build levels.
- **CWE Top 25 (2024)** — most-dangerous weakness ranking.

See `docs/standards-survey.md` for the v1 gap analysis against
each.

## Standards v1 missed — most important first

### MITRE ATT&CK + MITRE D3FEND

**Why it matters:** ATT&CK is the canonical catalogue of attacker
tactics, techniques, and procedures.  D3FEND is the defensive
countermeasure ontology that pairs with it.  For a defensive
tool like Babbleon, ATT&CK mapping is what reviewers expect to
see in the threat model — "this defends against T1059, T1057,
T1083, ..." with a concrete mechanism per ID.

**Babbleon v2 mapping (initial):**

| ATT&CK ID | Technique | v2 defence |
|---|---|---|
| T1059 | Command and Scripting Interpreter | Identifier + operator + whitespace scramble + preprocessor refuses untrusted-tier invocation |
| T1057 | Process Discovery | PID-NS + hidepid=2 + seccomp denies `process_vm_readv`, `kcmp`, `pidfd_*` |
| T1083 | File and Directory Discovery | Mount-NS hides credentials; scrambled `$PATH` returns scrambled names |
| T1552.001 | Credentials in Files | Credential gate (tmpfs overlay) + env-var scrubber |
| T1552.003 | Bash History | `HISTFILE` / `BASH_HISTORY` in scrubber deny-list |
| T1552.004 | Private Keys | `~/.ssh`, `~/.gnupg` in credential gate |
| T1555 | Credentials from Password Stores | Browser cookie dirs in credential gate |
| T1518 | Software Discovery | Scrambled `$PATH`; tripwires on probing scrambled names |
| T1027 | Obfuscated Files or Information | (We're the defender doing this, not the attacker — but documenting the defender side) |
| T1082 | System Information Discovery | NOT defeated; documented as L3 limitation (libc leak via /proc/self/maps) |
| T1574 | Hijack Execution Flow | Stale-mapping tripwire catches cached-mapping attackers |
| T1505.003 | Web Shell | Out of scope (host-side defence) |
| T1003 | OS Credential Dumping | seccomp denies `process_vm_readv`; Landlock denies cred-store read |
| T1078 | Valid Accounts | Out of scope |
| T1011 | Exfiltration Over Other Network Medium | Not defeated; compose with network defence |

**Corresponding D3FEND techniques:**

| D3FEND ID | Defensive technique | Babbleon mechanism |
|---|---|---|
| D3-HCH | Hierarchical Domain Configuration | Trust tiers (trusted/untrusted) |
| D3-MA | Mandatory Access Control | Landlock + (optional) AppArmor/SELinux |
| D3-PSEP | Process Self-Encryption Prevention | seccomp denies ptrace family |
| D3-FAPA | File Access Pattern Analysis | Tripwire FIFO + response policy |
| D3-DSE | Data Service Encryption | Vault (age + Argon2id) |

**Action:** ship a `docs/v2/attack-mapping.md` that's the full
ATT&CK + D3FEND traceability matrix.  Reviewers can grep it.

### NIST SP 800-190 — Application Container Security Guide

**Why it matters:** Babbleon uses mount + PID namespaces.
800-190 is NIST's guidance on doing this safely.  Direct overlap
with the v2 mechanism.

**Babbleon v2 mapping:**

- §4.1 Image-related risks — n/a (we don't ship images).
- §4.2 Registry-related risks — n/a.
- §4.3 Orchestrator-related risks — n/a (no orchestrator).
- §4.4 Container-related risks — **directly applicable.**
  - 4.4.1 Vulnerabilities in runtime software → mount-NS escape
    CVEs.  v2 documents kernel version floor and the CVEs gated
    by it.
  - 4.4.2 Unbounded network access → out of scope, compose with
    firewall.
  - 4.4.3 Insecure container runtime configurations →
    `make_root_private`, `MS_PRIVATE | MS_REC`, `hidepid=2`,
    seccomp, Landlock all directly mapped.
  - 4.4.4 App vulnerabilities → user-side, not Babbleon.
  - 4.4.5 Rogue containers → trust-tier check refuses untrusted
    callers of trusted operations.
- §4.5 Host OS risks — kernel hardening recommendations (KASLR,
  kptr_restrict, dmesg_restrict).  v2 ships an operator doc.

**Action:** map v2's threat model section by section onto 800-190
in `docs/v2/threat-model.md`.

### NIST SP 800-207 — Zero Trust Architecture

**Why it matters:** Babbleon's trusted/untrusted tier model IS a
zero-trust pattern at the host layer.  Procurement reviewers
expect to see the mapping.

**Babbleon v2 mapping:**

- ZTA tenet "Trust is never granted implicitly" → tier
  classification via mnt-NS inode check, not env-var, not
  PID-tree position.
- ZTA tenet "Continuous evaluation of trust" → rotation cadence
  re-derives the trust boundary every epoch.
- ZTA tenet "Minimize implicit trust zones" → scrambled view
  exposes nothing the untrusted tier doesn't need.
- ZTA tenet "Per-request access decisions" → per-process tier
  decision via the wrapper's NS-inode check at exec time.

**Action:** doc-only mapping in `docs/v2/threat-model.md`.

### NIST CSF 2.0 — Cybersecurity Framework

**Why it matters:** higher-level than SSDF; org-side framework.
For Babbleon (a product, not an org), maps to product attributes.

**Babbleon v2 mapping:** out of scope for the product itself;
Babbleon is a tool that fits into a CSF-aligned program's
"Protect" function.  Documentation note only.

### in-toto + TUF (The Update Framework)

**Why it matters:** the substrate SLSA sits on.  SLSA v1.0 cites
these directly.  TUF is the canonical secure software-update
framework; in-toto is the supply-chain attestation format.

**Babbleon v2 stance:** ship attestations in in-toto format from
phase 6 (release engineering).  Sigstore + cosign already produces
in-toto-compatible attestations; we adopt the v1 toolchain.

### CycloneDX vs SPDX — pick one for SBOM

**Why it matters:** v1 punted on this choice ("CycloneDX or SPDX").
v2 picks one and sticks to it.

**v2 decision: CycloneDX 1.6.**  Reasons:
- CycloneDX has better Rust/Cargo tooling (`cargo cyclonedx`).
- CycloneDX has a richer vulnerability section.
- Federal procurement accepts both as of NIST guidance.
- Tooling (Dependency-Track, Trivy) supports CycloneDX as
  primary.

Generated by `cargo cyclonedx` in CI; attached to every GitHub
release.

### GUAC — Graph for Understanding Artifact Composition

**Why it matters:** the query layer over SBOM data.  OpenSSF
project.

**v2 stance:** publish CycloneDX SBOMs in a format GUAC can
ingest.  GUAC integration itself is a downstream concern.

### CSAF 2.0 — Common Security Advisory Framework

**Why it matters:** modern advisory format superseding plain-
text CVE notes.

**v2 stance:** the `SECURITY.md` (in repo) points at GHSA flow.
When we publish advisories, we publish them in CSAF 2.0 JSON
format alongside the human-readable GHSA.  Tooling: most modern
advisory pipelines (GitHub's, GitLab's) can emit CSAF.

### SARIF — Static Analysis Results Interchange Format

**Why it matters:** standard output format for SAST tools.

**v2 stance:** CodeQL and Semgrep (when adopted — filed in v1
TODO) both emit SARIF.  GitHub's Security tab consumes SARIF
natively.  v2 wires CodeQL to upload SARIF as a CI step.

### FIPS 140-3 — Cryptographic Module Validation

**Why it matters:** required for federal procurement.

**v2 stance:** out of scope for v2.0.  Babbleon's crypto stack
(`age` for envelope encryption, `argon2` for KDF, `sha2` for
hashing) is RustCrypto-backed; RustCrypto crates are not FIPS
validated.  For FIPS-mode deployment, v3 would need to substitute
a FIPS-validated module (e.g. AWS-LC, BoringSSL's FIPS module,
RustCrypto FIPS subset when available).  Filed.

### CIS Benchmarks (Ubuntu, RHEL, Fedora)

**Why it matters:** de facto Linux baseline.  Operators of
Babbleon may want "CIS-aligned" deployment documentation.

**v2 stance:** ship `docs/v2/cis-deployment.md` that explains
how Babbleon's settings interact with CIS controls.  Notably,
Babbleon's setuid (v1) violated CIS 4.1; v2's file-cap install
satisfies CIS 4.1.

### DISA STIGs

**Why it matters:** DoD-specific secure-configuration baseline.
Relevant for any setuid (v1) or capability-elevated (v2) binary
in a federal context.

**v2 stance:** STIG-compliant install doc; same shape as the CIS
doc.  Lower priority than CIS.

### OWASP SAMM (Software Assurance Maturity Model)

**Why it matters:** broader than ASVS; org-side maturity model.

**v2 stance:** for the product, NOT directly applicable.  For
the project's development practices, the v2 secure-development
policy doc (filed as TODO under "From the standards survey —
SSDF") maps onto SAMM's Design and Implementation streams.

### BSIMM — Building Security In Maturity Model

**Why it matters:** Synopsys commercial competitor to SAMM.

**v2 stance:** no action — SAMM coverage is sufficient.

### OWASP Top 10 (2021)

**Why it matters:** most-common web-app vulnerabilities.

**v2 stance:** web-app-shaped, so most items don't apply.
Documentary sweep in `docs/v2/owasp-top10-audit.md` confirming
none of the top 10 manifest in Babbleon's code (analogous to
v1's CWE Top 25 audit).

### STRIDE — threat-modeling framework

**Why it matters:** the categorical framework for naming threat
classes.  v1 mentioned STRIDE; the parallel-session work
(commit `6b35b49`) added a STRIDE-formatted threat model doc.
v2 carries it forward.

**v2 stance:** `docs/v2/threat-model-stride.md` carries the
STRIDE matrix forward and extends it with the structure-
scrambling layers' specific threats.

### PASTA, DREAD, OWASP Threat Dragon

**Why it matters:** alternative or complementary threat-modeling
methodologies.

**v2 stance:** STRIDE coverage is sufficient.  DREAD scoring
applied per-issue in advisories.  PASTA and Threat Dragon noted
for completeness; no adoption planned.

## Summary table

| Standard | v1 coverage | v2 plan |
|---|---|---|
| OWASP ASVS 5.0 | Surveyed; gap items filed | Re-evaluate per chapter per phase |
| NIST SSDF v1.1 | Surveyed; gap items filed | Document maps onto PO/PS/PW/RV |
| OpenSSF Scorecard | Surveyed; gap items filed | Target 9+/10 by phase 6 |
| SLSA v1.0 | Surveyed; gap items filed | Target L3 by phase 6 |
| CWE Top 25 (2024) | Surveyed; documentary audits filed | Re-sweep against any new 2025 list |
| **MITRE ATT&CK + D3FEND** | **Missed** | Full traceability matrix |
| **NIST SP 800-190** | **Missed** | Threat-model section-by-section map |
| **NIST SP 800-207** | **Missed** | Zero-trust mapping in threat-model |
| NIST CSF 2.0 | Missed | Documentation note (out of product scope) |
| **in-toto + TUF** | Missed | Adopted via sigstore toolchain |
| **CycloneDX vs SPDX** | Punted | **CycloneDX 1.6** chosen |
| GUAC | Missed | Publish CycloneDX in GUAC-ingestible form |
| CSAF 2.0 | Missed | Advisories emit CSAF JSON |
| SARIF | Missed | CodeQL + Semgrep emit, GitHub consumes |
| FIPS 140-3 | Missed | Out of scope for v2.0 |
| CIS Benchmarks | Missed | Deployment doc |
| DISA STIGs | Missed | Deployment doc (lower priority) |
| OWASP SAMM | Missed | Project-side, not product-side |
| BSIMM | Missed | No action |
| OWASP Top 10 (2021) | Missed | Documentary audit |
| STRIDE | v1 partial | Full STRIDE matrix in v2 threat-model |

## Action items for phase 0 (now)

These are doc-only; no code:

1. Write `docs/v2/attack-mapping.md` — full ATT&CK + D3FEND
   traceability matrix.
2. Extend `docs/v2/threat-model.md` (to be written) with NIST
   800-190 §4.4 mapping and 800-207 zero-trust tenets.
3. Decide CycloneDX (this doc records the decision).
4. Document the FIPS 140-3 deferral.

## Action items for phase 1+ (code phases)

These ship with the corresponding code phase:

5. Phase 1: re-evaluate every code module against ASVS 5.0
   chapter list.
6. Phase 2: code SARIF emission via CodeQL workflow.
7. Phase 3 (structure scrambling): re-evaluate threat model
   under the new attack surface.
8. Phase 6 (release engineering): CycloneDX SBOM, sigstore
   signing, in-toto attestations, SLSA L3 reusable workflow.

## Sources

- MITRE ATT&CK — https://attack.mitre.org/
- MITRE D3FEND — https://d3fend.mitre.org/
- NIST SP 800-190 — https://csrc.nist.gov/publications/detail/sp/800-190/final
- NIST SP 800-207 — https://csrc.nist.gov/publications/detail/sp/800-207/final
- NIST CSF 2.0 — https://www.nist.gov/cyberframework
- in-toto — https://in-toto.io/
- TUF — https://theupdateframework.io/
- CycloneDX 1.6 — https://cyclonedx.org/specification/overview/
- GUAC — https://guac.sh/
- CSAF 2.0 — https://docs.oasis-open.org/csaf/csaf/v2.0/
- SARIF — https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- FIPS 140-3 — https://csrc.nist.gov/projects/cryptographic-module-validation-program
- CIS Benchmarks — https://www.cisecurity.org/cis-benchmarks
- DISA STIGs — https://public.cyber.mil/stigs/
- OWASP SAMM — https://owaspsamm.org/
- BSIMM — https://www.bsimm.com/
- OWASP Top 10 (2021) — https://owasp.org/Top10/
- STRIDE / Threat Modeling Manifesto — https://www.threatmodelingmanifesto.org/
