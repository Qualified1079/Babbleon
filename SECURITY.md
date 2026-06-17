# Security Policy

Babbleon is a security tool.  Vulnerabilities in it directly affect
the security of every host it runs on.  This document is the
disclosure contract.

## Reporting a vulnerability

**Email:** `security@babbleon.dev` (placeholder — replace before first
public release).

**Encrypted:** Please encrypt the report.  See the PGP key at the
bottom of this document or at `https://babbleon.dev/.well-known/security.txt`
(also pending domain registration).

**What to include:**

- A description of the issue and the threat model class it touches
  (see `docs/threat-model.md` for Threat A / Threat B and expressions
  E1–E4).
- The Babbleon version (or commit hash) the issue is reproducible on.
- The kernel version, distro, and any relevant CPU / TPM / FIDO2
  hardware the issue depends on.
- A proof-of-concept if you have one.  PoCs are appreciated but not
  required for an initial report.
- Your preferred attribution name (for the eventual advisory)
  and whether you want to be CC'd on the public disclosure.

**Please do not** open a public GitHub issue, post to a public chat,
or publish a write-up before we have coordinated a release.

## Response timeline

| Stage                        | Target                                |
|------------------------------|---------------------------------------|
| Acknowledgement              | Within 3 business days of report.     |
| First impact assessment      | Within 7 business days of report.     |
| Coordinated disclosure window | 90 days from report, extendable by mutual agreement. |

If a report is exploited in the wild before we ship a fix, we may
shorten the disclosure window unilaterally and publish before the
90-day mark.  We will tell you before we do this.

## Scope

In scope:

- The `babbleon` library crate.
- The `babbleon-cli` binary.
- The `babbleon-ns-helper` setuid binary.
- The `pam_babbleon.so` PAM module.
- The cryptographic constructions in `crates/babbleon/src/mapping/`,
  `crates/babbleon/src/vault/`, and `crates/babbleon/src/audit.rs`.
- The wrapper template in `crates/babbleon/src/enforcement/wrapper.rs`.
- The honey-FIFO / response-policy pipeline in
  `crates/babbleon/src/enforcement/response.rs` and
  `crates/babbleon/src/events.rs`.

Out of scope (see `docs/threat-model.md` for the threat boundaries):

- Compromise of a host that already has unsupervised root.  Babbleon
  assumes root is honest; that's a stated trust boundary, not a bug.
- The three documented limitations (L1 syscall bypass, L2 BYOE,
  L3 libc leak via `/proc/self/maps`).  These are intentional
  out-of-scope items, not vulnerabilities.
- Kernel CVEs that Babbleon's mitigations happen to gate against.
  We don't ship kernel patches; we use kernel features.
- Bugs in third-party dependencies (report those to upstream).  If a
  dep version we pin enables exploitation that wouldn't otherwise
  exist, that IS a Babbleon issue.
- Issues in the `tools/scrambler/` HTML harness, which is an
  adversarial-test playground, not a defended surface.

## Supported versions

This project is pre-1.0.  Security fixes land on `main` and the most
recent tagged release.  Older releases are not patched.

Once a 1.0 ships:

| Version | Patched? |
|---------|----------|
| 1.x latest | Yes |
| 1.x previous-minor | 90 days after the next minor |
| 0.x | No |

## Hall of fame

Reporters who follow this process will be credited in the eventual
advisory and in `docs/reporters.md` (created on first valid report)
unless they ask to remain anonymous.

## Bounty

No bounty program at present.  This will likely change at 1.0.

## PGP key

Pending — replace this section with the actual key fingerprint when
the project key is generated.  Until then, the email channel above
should be treated as "trusted only against a passive attacker."  Do
not send proof-of-concept exploits over plaintext email; coordinate a
secure channel first.

---

## Process for the maintainers

(Internal note, kept here so the contract above is enforceable.)

1. Acknowledge receipt within the stated SLA.
2. File a private security advisory in the GitHub Security tab; do
   not file a public issue.
3. Reproduce on the affected version.
4. Triage: assign a severity using CVSS v3.1 + a Babbleon-specific
   note about which threat-model class is affected.
5. Develop a fix on a private branch.
6. Coordinate disclosure timing with the reporter.
7. Request a CVE through the GitHub Security Advisory flow.
8. Publish the advisory and the patched release simultaneously.
9. Add the reporter to `docs/reporters.md` per their preference.
10. Update `docs/threat-model.md` if the issue revealed a gap in
    what we claim to defend against.
