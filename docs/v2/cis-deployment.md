# CIS Benchmark deployment notes — v2

Filed per `docs/v2/standards-alignment.md` §"CIS Benchmarks (Ubuntu,
RHEL, Fedora)". This is deployment guidance, not a certification: it
explains how Babbleon v2's own settings interact with the CIS Linux
Benchmark family (Ubuntu/Debian/RHEL/Fedora editions share the same
control shape with minor per-distro differences), and is honest about
which controls Babbleon satisfies by architecture, which remain the
operator's job on the host, and which are still open work tracked
elsewhere.

## Why this doc cites control *titles*, not numbers

CIS renumbers controls between major benchmark revisions. Two
concrete data points from checking this while writing the doc: the
"SUID/SGID executables reviewed" control sits in the benchmark's
final section (titled "System Maintenance" in the 16.04/20.04/22.04
lineage) at IDs `6.1.13`/`6.1.14`, but the same control appears
merged into a single `7.1.13` in the 24.04 edition — a different
number, in a differently-numbered section, for the identical control.
A bare number without a pinned benchmark edition + revision is close
to meaningless and risks reading as a more precise compliance claim
than it is. This doc references controls by their stable title and
the section they live in across the CIS Linux Benchmark family
(section names below match the 16.04/20.04/22.04-era structure:
1 Initial Setup, 2 Services, 3 Network, 4 Logging and Auditing,
5 Access/Authentication/Authorization, 6 System Maintenance).
Operators certifying against a specific benchmark PDF should look up
that edition's exact numbering by title.

## Scope

Babbleon v2 is a per-host obfuscation daemon + CLI + launcher, not a
general-purpose hardening tool. Most of the CIS Linux Benchmark
governs the HOST — filesystem partitioning, network stack sysctls,
service enablement, PAM/password policy for system logins, sudo
configuration — and is the operator's responsibility independent of
whether Babbleon is installed. This doc only covers rows where
Babbleon's own design or code interacts with a CIS control: satisfies
it, needs an operator to complete it, or (rarely) makes a control
harder to satisfy and needs a documented exception.

## Section 1 — Initial Setup

| CIS control (title) | Babbleon v2 interaction |
|---|---|
| Filesystem partitioning: `nodev`/`nosuid`/`noexec` on `/tmp`, `/dev/shm`, `/var/tmp`, etc. | Host-level, independent of Babbleon. Babbleon's OWN internal tmpfs mounts follow the same principle where it doesn't break function — see "Babbleon's internal mounts" below. |
| Mandatory Access Control (AppArmor) enabled and enforcing | Babbleon ships an AppArmor profile at `policies/apparmor/usr.local.bin.babbleon` (and a parallel SELinux policy at `policies/selinux/babbleon.te`) covering the launcher's exact five-capability file-cap set (`cap_sys_admin`, `cap_setuid`, `cap_setgid`, `cap_ipc_lock`, `cap_setpcap` — see `docs/v2/least-privilege.md`'s 2026-07-03 correction). Loading Babbleon's profile is necessary but not sufficient for this control — the operator's host-wide "AppArmor is enabled and in enforce mode" baseline is a separate, host-level setting Babbleon doesn't touch. |
| Warning banners (`/etc/issue`, `/etc/motd`) | N/A — host baseline, unrelated to Babbleon. |
| Bootloader config permissions | N/A — host baseline. |

### Babbleon's internal mounts

Babbleon creates two of its own tmpfs mounts inside the launcher's
private mount namespace (`crates/v2-babbleon-launch-untrusted/src/
mounts.rs` and `credential_gate.rs`). Neither was setting any of the
CIS-recommended restriction flags before 2026-07-03; both now do,
scoped to what doesn't break the mount's actual job:

- **Scrambled-view tmpfs** (`mounts::mount_scrambled_view_tmpfs`,
  `/run/babbleon/scrambled`) — now mounted `nosuid,nodev`. NOT
  `noexec`: the whole point of this tmpfs is that the untrusted-tier
  child execs wrapper scripts out of it, so `noexec` would break
  Babbleon's core function. Nothing legitimately placed here is ever
  a device node or a setuid/setgid binary, so those two restrictions
  cost nothing.
- **Credential-gate overlay tmpfs** (`credential_gate::mount_one`,
  one per discovered `~/.aws`, `~/.kube`, etc.) — now mounted
  `nosuid,nodev,noexec`. This overlay is meant to look like an empty
  directory; it never legitimately holds anything, so all three
  restrictions are free.

Both changes are covered by rooted tests that assert the actual
mount options via `/proc/self/mountinfo`, not just that the mount
call didn't error:
`crates/v2-babbleon-launch-untrusted/tests/rooted_lifecycle.rs`'s
`scrambled_view_tmpfs_sets_nosuid_and_nodev_but_allows_exec` and the
mountinfo assertion added to
`credential_gate_overlays_empty_tmpfs_on_each_discovered_dir`.

**Update, same night:** the per-tool bind mounts in
`mounts::bind_mount_entries` now also carry `nosuid,nodev` (not
`noexec` — the child execs the wrapper). Each bind mount is its own
vfsmount, so `MS_BIND` alone in the call that creates it can't also
set these flags — the fix is a second `mount(2)` call with
`MS_REMOUNT | MS_BIND` plus the desired flags, applied per bind
target after the initial bind. Verified via a mountinfo assertion
added to the existing `bind_mount_entries_succeeds_in_fresh_namespace`
rooted test (checks every bound entry, not just one), not merely
that the mount call didn't error.

## Section 2 — Services

Babbleon opens no network sockets anywhere in `crates/v2-*` (the
daemon's only IPC surface is a Unix domain socket, peer-uid-gated
per `docs/v2/owasp-top10-audit.md` A01) and installs no systemd
service that listens on a port. The "disable unnecessary network
services" control family is unaffected by installing Babbleon — N/A.

## Section 3 — Network

N/A. Babbleon has no network stack of its own (see `docs/v2/
threat-model.md`'s L1/L2/L3 documented-limitation discussion — this
is a deliberate non-goal, not an oversight).

## Section 4 — Logging and Auditing

| CIS control (title) | Babbleon v2 interaction |
|---|---|
| `auditd` installed, enabled, and configured with rules | Independent, host-level control. Babbleon's own audit trail (hash-chained event log, `Ed25519Signed` sink — see `HANDOFF.md`'s wrapper/tripwire sections) is a SUPPLEMENT, not a replacement: it captures Babbleon-specific events (tripwire triggers, epoch rotations) that `auditd` doesn't know exist. Operators should run both. |
| Audit records capture privilege-escalation-relevant syscalls | Babbleon's own seccomp allowlists (launcher, daemon) kill non-allowlisted syscalls with `SECCOMP_RET_KILL_PROCESS`, which the kernel reports as an `AUDIT_SECCOMP` audit record when `auditd` is running — worth an operator enabling `auditd` specifically to catch these, since Babbleon's own stderr/JSONL logging captures the *outcome* (process killed) but not always a structured record of *which* syscall triggered it. |

## Section 5 — Access, Authentication and Authorization

| CIS control (title) | Babbleon v2 interaction |
|---|---|
| PAM password-quality / lockout modules configured | Independent of Babbleon's OWN vault-unlock rate-limiting. Babbleon's `crates/v2-babbleon-vault/src/attempts.rs::AttemptTracker` (3 free attempts, exponential backoff, lockout at 10 — see `TODO.md`'s A07 closure entry) protects the Argon2id-guarded vault passphrase specifically; it is not a substitute for the host's own login-PAM hardening, which remains the operator's job. |
| PAM module for the security tool itself installed and wired into session-open | **Not yet applicable — genuinely open, tracked separately.** `crates/v2-babbleon-pam/` is explicitly a skeleton today (its own module doc says so); the C shim probes the daemon socket but does not invoke `babbleon-launch-untrusted`, pending an operator decision among three candidate architectures in `docs/v2/pam-architecture.md`. See `TODO.md` Phase 2. This doc does not claim otherwise. |
| `ptrace_scope` restricted (`kernel.yama.ptrace_scope`) | Babbleon's own seccomp profiles independently deny `ptrace`/`process_vm_readv`/`kcmp` for the processes they cover (belt-and-suspenders), but the SYSTEM-WIDE `yama.ptrace_scope=2` sysctl is still an open decision recorded in `docs/v2/least-privilege.md`'s "Open audit items carried into v2" — enforce at install time, or just recommend it? Not decided; this doc doesn't pretend it is. |
| No setuid-root binaries beyond a documented allowlist (the SUID/SGID-executables-reviewed control, System Maintenance section) | **Satisfied by v2's architecture.** v1's `babbleon-ns-helper` is exactly what this control flags (`4755 root:root`, full 41-capability grant). v2's `babbleon-launch-untrusted` ships with file capabilities (`cap_sys_admin,cap_setuid,cap_setgid,cap_ipc_lock,cap_setpcap=ep`), not setuid at all — nothing in `crates/v2-*` installs a setuid-root binary. An operator running this control's audit against a v2-only install should find zero Babbleon-owned setuid binaries. |
| Restrict core dumps (`fs.suid_dumpable`, per-process `RLIMIT_CORE`) | Babbleon's own privileged processes (launcher, daemon) set `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` at startup (`process_hardening::apply_secret_hygiene`), independent of and in addition to whatever the host's own `fs.suid_dumpable` sysctl is set to — this is process-level hardening for Babbleon's own secret-holding processes, not a substitute for the system-wide sysctl. |

## Section 6 — System Maintenance

| CIS control (title) | Babbleon v2 interaction |
|---|---|
| SUID/SGID executables reviewed | See Section 5 row above — same control, this benchmark edition files it here instead. |
| File permissions on system files (`/etc/passwd`, `/etc/shadow`, etc.) | N/A — host baseline, unrelated to Babbleon. |
| No unowned files or directories | **Verified 2026-07-03.** `tools/install-v2/install.sh` installs every v2 binary plus `/run/babbleon/`, `/usr/local/libexec/babbleon/wrappers`, and `/etc/babbleon` with explicit `root:root` ownership and asserts it (hard failure, not a warning, on any mismatch); `tools/install-v2/test.sh` exercises this. See `TODO.md`'s matching item for the full closure note. |

## What this doc is NOT

- Not a CIS self-assessment tool output (CIS-CAT, `usg`, OpenSCAP) —
  those audit the HOST, and Babbleon doesn't change most of what they
  check.
- Not a claim of certification. "Satisfied by architecture" rows
  above are traceable to the specific file/function that satisfies
  them, same standard as `docs/v2/owasp-top10-audit.md` and
  `docs/cwe-top25-audit.md` — an auditor should be able to verify
  each row by reading the cited code, not by trusting this doc.

## Related v2 docs

- `docs/v2/least-privilege.md` — the file-capability audit this doc's
  Section 5 SUID/SGID row and Section 1 AppArmor row both depend on.
- `docs/v2/threat-model.md` — the L1/L2/L3 documented limitations
  behind this doc's "Section 3 — Network: N/A" claim.
- `docs/v2/owasp-top10-audit.md` — the daemon-socket peer-uid finding
  this doc's Section 4 auditd row references.
- `docs/v2/pam-architecture.md` — the three candidate PAM
  architectures this doc's Section 5 PAM row defers to.
