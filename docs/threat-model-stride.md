# Threat Model — STRIDE table

Companion to `docs/threat-model.md`.  Same threats, structured into
the STRIDE categories that procurement reviewers expect.  Each row
points back to the code surface or doc artifact that addresses it.

| # | Category | Threat | Asset | Status | Reference |
|---|---|---|---|---|---|
| S1 | **Spoofing** | An untrusted-tier process invokes the real binary by canonical name | Trusted-tier identity | Mitigated | `enforcement/linux_ns.rs` + scrambled-name mapping |
| S2 | **Spoofing** | An attacker on the local network forges the rotation timer / vault unlock prompt | Vault unlock authority | Out of scope (local CLI; no network surface) | — |
| S3 | **Spoofing** | A SIEM consumer accepts a forged audit-log line that an attacker appended after rooting the box | Audit log integrity | Mitigated (signed mode) | `audit.rs::open_signed`, `verify_signed`; `docs/verify-release.md` |
| T1 | **Tampering** | An on-host attacker rewrites the audit JSONL to hide their activity | Audit log | Mitigated | `audit.rs` SHA-256 chain + Ed25519 sig in signed mode |
| T2 | **Tampering** | A man-in-the-middle swaps a release tarball for a Trojan | Release artifact | Mitigated | `release.yml` cosign keyless + SLSA L3 provenance; `docs/verify-release.md` |
| T3 | **Tampering** | A malicious crate in the dep tree (xz-class) lands a backdoor | Build integrity | Partially mitigated | `cargo audit` + `cargo deny` (advisories, sources); `cargo-vet` filed |
| T4 | **Tampering** | An attacker writes a runaway-large line to `/run/babbleon/honey.fifo` to OOM the daemon | Honey FIFO reader | Mitigated | `events.rs::read_bounded_line` + 16 KiB cap (CWE-400) |
| T5 | **Tampering** | The wrapper template gains an injection-friendly substitution field | Wrapper script | Mitigated | `enforcement/wrapper.rs::render` shell escapes; `docs/cwe-top25-audit.md` §CWE-78 |
| R1 | **Repudiation** | A privileged user denies the rotation event they emitted | Audit chain | Mitigated | Hash chain + Ed25519 sig (signed mode) |
| R2 | **Repudiation** | A SIEM forwarder claims it never received an event | Forwarder integrity | Out of scope (SIEM-side problem) | — |
| I1 | **Information Disclosure** | An untrusted-tier process learns the real path of a tracked binary | Tracked-tool inventory | Mitigated | Mount-NS view + per-tier mapping; tier check via `/proc/self/ns/mnt` inode |
| I2 | **Information Disclosure** | The vault file leaks the host secret if exfiltrated | Host secret | Mitigated | `age` passphrase encryption + Argon2id (~250 ms cost) |
| I3 | **Information Disclosure** | A core dump or paged-out memory leaks the host secret or KEK | Host secret in RAM | Mitigated | `process_hardening` (`PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlockall`); `Zeroizing<...>` on heap |
| I4 | **Information Disclosure** | Timing of `is_honey` reveals position of match in honey list | Honey-name layout | Mitigated | `crypto::ct_eq` + full traversal (no short-circuit) |
| I5 | **Information Disclosure** | The wrapper script's size is a fingerprint of "real tool vs honey" | Tier classification | Mitigated | Unified template across honey + real (commit `920e26d`) |
| I6 | **Information Disclosure** | `/proc/self/maps` discloses `libc.so.6` at a canonical path | Library identity | Documented limitation | `TODO.md` §L3 — vetoed obfuscation; reachability is a soundness requirement |
| D1 | **Denial of Service** | Brute-force vault unlock attempts burn CPU on the Argon2id KDF | Vault availability | Mitigated | `vault::attempts` rate limit (3 free → exponential → lockout at 10) |
| D2 | **Denial of Service** | A rapid rotation cadence overwhelms userspace wrapper generation | Daemon CPU | Partially mitigated | `tools/rotation-benchmark/` records the cost curve; pre-build + unified-runtime-table wrapper filed |
| D3 | **Denial of Service** | The FPE permutation cache grows unbounded across rotations | Daemon RAM | Mitigated | `mapping/fpe.rs::Cache` FIFO bound at 32 entries (CWE-770) |
| D4 | **Denial of Service** | A bad sidecar `.attempts` file locks the operator out forever | Vault recoverability | Mitigated | Corrupt sidecar defaults to "no attempts"; `record_failure` failure is logged + skipped |
| E1 | **Elevation of Privilege** | Setuid ns-helper retains residual capability after dropping UID | Local privilege boundary | Mitigated | `babbleon-ns-helper`: ordered `unshare` → `make_root_private` → cap-drop → NNP → seccomp → fork → setuid; `docs/cwe-top25-audit.md` §CWE-269 |
| E2 | **Elevation of Privilege** | An untrusted-tier process re-execs into a tracked tool to escape the mount NS | Tier separation | Mitigated | NNP-locked; mount NS persists across exec; seccomp blocks ptrace/process_vm_* |
| E3 | **Elevation of Privilege** | A scrambled wrapper script is reached at a non-canonical path via path traversal | Filesystem boundary | Mitigated | Scrambled names are lowercase-alpha-only (wordlist filter); `docs/cwe-top25-audit.md` §CWE-22 |
| E4 | **Elevation of Privilege** | A PR adds a new `unsafe` block without invariants documented | Memory safety | Mitigated (process) | `CODEOWNERS` enforces review on every unsafe-touching path; `SAFETY:` comments required (project policy) |

## How to read this

- **Mitigated** — there is a code-level defence and a test that exercises it.
- **Mitigated (process)** — there is a procedural control (review gate, hook, manual audit cadence).  No runtime check.
- **Out of scope** — Babbleon doesn't claim to address this; another layer (network segmentation, SIEM-side controls) does.
- **Documented limitation** — see `TODO.md` §"Documented limitations".

## Update cadence

Refresh whenever the threat model gains a new attacker capability or
Babbleon ships a new mitigation.  Last refreshed alongside
`docs/cwe-top25-audit.md`: 2026-06-15.
