# DISA STIG deployment notes — v2

Filed per `docs/v2/standards-alignment.md` §"DISA STIGs" — "STIG-
compliant install doc; same shape as the CIS doc. Lower priority than
CIS." This doc is deliberately shorter than `docs/v2/cis-deployment.md`
for that reason: it covers where Babbleon's STIG-relevant surface
DIFFERS from the CIS doc's analysis, and otherwise points back to it
rather than duplicating.

## Why this doc doesn't cite `V-`-number vulnerability IDs

DISA STIG findings use `V-nnnnnn` vulnerability IDs mapped to
`SRG-OS-nnnnnn-GPOS-nnnnnn` Security Requirements Guide IDs, and both
renumber across STIG releases (e.g. the Canonical Ubuntu 20.04 LTS
STIG has gone through multiple release revisions). Same caution as
`cis-deployment.md`'s own rationale, more pronounced here: a bare
`V-`-number pinned to no release is not a verifiable claim. This doc
references requirement CONCEPTS (the underlying SRG family, e.g.
"privileged function execution restricted to authorized accounts")
rather than a specific `V-`-number; an operator running an actual
STIG scan (`Canonical Ubuntu STIG SCAP Benchmark`, or the RHEL/Fedora
equivalent for other target distros) gets the current numbering
directly from the scanner.

## Where STIG and CIS overlap for Babbleon (see `cis-deployment.md`)

The Linux STIG family (DISA's own Ubuntu STIG, and the RHEL/Fedora
STIGs relevant if Babbleon targets those distros) covers almost
exactly the same ground as the CIS Linux Benchmark for the rows that
touch Babbleon: no unauthorized setuid-root binaries, restricted
`ptrace_scope`, Mandatory Access Control enforced, `auditd` capturing
privileged-syscall and access-control events, core dumps disabled for
processes handling sensitive data. Every row in `cis-deployment.md`'s
Section 1/4/5/6 tables applies here with the same Babbleon-side
mechanism (file-cap launcher instead of setuid, the AppArmor/SELinux
policies in `policies/`, `PR_SET_DUMPABLE=0`+`RLIMIT_CORE=0`, the
`nosuid,nodev[,noexec]` flags now set on Babbleon's own internal tmpfs
mounts) — not repeated here.

## Where STIG is stricter or distinct from CIS, for Babbleon's surface

- **Mandatory Access Control is a hard requirement, not a
  recommendation.** DISA STIGs for Linux generally require SELinux
  (RHEL/Fedora targets) or AppArmor (Ubuntu target) to be enabled in
  ENFORCING mode, not merely installed — stricter framing than CIS's
  "enabled and enforcing" recommendation-level control. Babbleon
  ships both `policies/apparmor/usr.local.bin.babbleon` and
  `policies/selinux/babbleon.te`; loading the profile that matches
  the target distro's MAC system in enforcing mode is a prerequisite
  for STIG compliance on a Babbleon-installed host, same as noted in
  `cis-deployment.md`.
- **Privileged function execution restricted to explicitly authorized
  accounts** (the SRG family this maps to covers `sudo`, setuid
  binaries, and capability-holding binaries alike). Babbleon's
  five-capability file-cap launcher
  (`crates/v2-babbleon-launch-untrusted`) is the artifact a STIG
  reviewer would inspect here — same evidence trail as
  `cis-deployment.md`'s Section 5 SUID/SGID row:
  `docs/v2/least-privilege.md`'s audit table names the exact five
  capabilities and the code enforces exactly that set (rooted tests
  in `tests/capability_lifecycle.rs` assert it end-to-end, not just
  by doc claim).
- **Session inactivity / account lockout controls** are a STIG
  concern with no direct CIS analog at the same emphasis. Not
  Babbleon's surface — these govern the HOST's login sessions, and
  Babbleon's own vault-unlock lockout
  (`crates/v2-babbleon-vault/src/attempts.rs::AttemptTracker`) is a
  distinct mechanism protecting a distinct credential (the vault
  passphrase, not the OS login). Worth an operator not conflating the
  two when scoping a STIG assessment that includes a Babbleon
  install.

## What remains genuinely open

- PAM module wiring (`crates/v2-babbleon-pam/`) is still a skeleton —
  see `TODO.md` Phase 2 and `docs/v2/pam-architecture.md`. Not fixed
  here; the same open item `cis-deployment.md` flags, not duplicated
  as a new STIG-specific finding.

The per-tool bind mounts' `nosuid`/`nodev` gap this doc originally
noted here was closed the same night — see `cis-deployment.md`'s
"Update, same night" note and `TODO.md`'s entry for
`bind_mount_entries`.
