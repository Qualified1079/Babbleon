# ATT&CK + D3FEND traceability matrix — v2

Audit-grade cross-reference.  Companion to `docs/v2/threat-model.md`
(the narrative + standards mapping) and `docs/v2/standards-alignment.md`
(the auditor framework survey).  This document is the grep
surface: every ATT&CK technique Babbleon claims to affect is in
one of the tables below, with a precise mechanism, a D3FEND
control ID where one applies, and a pointer to the v2 code or
doc evidence.

Use this doc to answer reviewer questions of the form:

- *"Show me where Babbleon defends against T1057."*
- *"Which ATT&CK techniques does D3-FAPA cover in your
  deployment?"*
- *"What's your coverage in the Credential Access tactic?"*

Conventions:

- **ID** is the MITRE ATT&CK technique or sub-technique ID
  (v17, April 2025; current as of June 2026).
- **Tactic** is the ATT&CK tactic the technique belongs to.
- **Status** is one of:
  - **Defends** — Babbleon has a concrete mechanism that
    raises the cost of this technique on a Babbleon-protected
    host.
  - **Partial** — Babbleon raises the cost but does not close
    the technique; a complementary control is required.
  - **Out of scope** — Babbleon does not address this; the
    column "Mechanism" names the layer that should.
  - **N/A** — Babbleon is the attacker side of the analogy
    (used for T1027, T1140).
- **Mechanism** is the load-bearing v2 control.
- **D3FEND** is the D3FEND technique ID that classifies the
  control, when one applies.
- **Where** points at a v2 crate, module, or doc.

Phase pointers (see `V2_PLAN.md`):

- **phase 1** — v2 core (mapping, secret, KDF, events,
  tripwire, wrapper) — **shipped**.
- **phase 2** — launcher + PAM (capabilities, mount-NS, PID-NS,
  seccomp, Landlock, credential gate, env scrubber).
- **phase 3** — preprocessor + structural scrambling.
- **phase 4** — multi-language wordlists; additional layers
  6–12.
- **phase 5** — hardware vault backends (FIDO2, TPM).
- **phase 6** — release engineering (SLSA L3, cosign, profiles).

---

## 1. ATT&CK technique coverage (forward direction)

Ordered by Tactic, then by ID.

### Tactic: Initial Access

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Out of scope | Network-perimeter concern; Babbleon is host-side | — | — |
| T1195 | Supply Chain Compromise | Partial | v2 ships SLSA L3 provenance + sigstore + in-toto for Babbleon's own artifacts; downstream supply chain is operator-side | — | `release.yml` (port owed phase 6) |
| T1199 | Trusted Relationship | Out of scope | Identity / network-trust concern | — | — |

### Tactic: Execution

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1059 | Command and Scripting Interpreter | Defends | Identifier scramble + operator scramble + whitespace-as-words; preprocessor required to invoke; untrusted-tier sees scrambled compounds for every interpreter binary | D3-MA, D3-HCH | `docs/v2/structure-scrambling.md` (phase 3) |
| T1059.001 | PowerShell | Out of scope | Linux-only product | — | — |
| T1059.004 | Unix Shell | Defends | Identifier scramble defeats canonical-name path; preprocessor defeats shell-shape fingerprint | D3-MA, D3-HCH | `docs/v2/structure-scrambling.md` (phase 3) |
| T1059.006 | Python | Defends | Layer 2 (operator scramble) targets Python reserved keywords explicitly; layer 3 (whitespace-as-words) defeats indentation fingerprint | D3-MA | `docs/v2/structure-scrambling.md` §"Layer 2" (phase 3) |
| T1059.008 | Network Device CLI | Out of scope | Not a network device | — | — |
| T1106 | Native API | Partial | seccomp deny-list closes process-inspection family; Landlock denies fs-traversal of credentials.  Raw `syscall(2)` against unrelated syscalls is not blocked | D3-PSEP, D3-MA | v1 `enforcement/seccomp.rs`, `enforcement/landlock.rs` (carry-from-v1 port owed phase 2) |
| T1129 | Shared Modules | Documented limitation L3 (libc canonical path required for ELF loader); attacker can read `libc` location but learns nothing about the scramble mapping | — | `docs/threat-model.md` §L3 |
| T1203 | Exploitation for Client Execution | Out of scope | Application-level CVEs; user-side patching | — | — |
| T1559 | Inter-Process Communication | Partial | PID-NS + IPC env-var scrubber (`SSH_AUTH_SOCK`, `gpg-agent`, `DBUS`, `XDG_RUNTIME_DIR`) | D3-PSEP | v1 `credentials.rs` (port owed phase 2) |

### Tactic: Persistence

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1037 | Boot or Logon Initialization Scripts | Out of scope | Babbleon does not manage init scripts; operator-side | — | — |
| T1053 | Scheduled Task/Job | Out of scope | Operator-side | — | — |
| T1543 | Create or Modify System Process | Partial | Untrusted tier cannot write to `/etc/systemd`, `/etc/init.d` via Landlock RO mount; trusted tier is by definition allowed | D3-MA | v1 `enforcement/landlock.rs` (port owed phase 2) |
| T1546 | Event Triggered Execution | Out of scope | Operator-side | — | — |
| T1574 | Hijack Execution Flow | Defends | Stale-mapping tripwire catches cached-mapping attackers that learned the vocabulary in epoch N and used it in epoch N+1+; honey-name tripwire catches probing | D3-RAPA, D3-FAPA | `crates/v2-babbleon-core/src/mapping.rs` (stale list); v1 wrapper template (port owed phase 2) |
| T1574.001 | DLL Search Order Hijacking | Out of scope | Windows-specific | — | — |
| T1574.006 | Dynamic Linker Hijacking | Partial | Mount-NS isolates trusted-tier `$LD_LIBRARY_PATH`; env scrubber drops the var across tier; documented L3 leak via `/proc/self/maps` does NOT reveal scramble mapping | D3-MA | v1 `credentials.rs` env scrubber + v1 `enforcement/linux_ns.rs` (port owed phase 2) |

### Tactic: Privilege Escalation

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1068 | Exploitation for Privilege Escalation | Out of scope | Kernel CVE concern; operator-patched | — | — |
| T1078 | Valid Accounts | Out of scope | Account management is operator-side | — | — |
| T1548 | Abuse Elevation Control Mechanism | Defends (process) | v2 has NO setuid-root binaries; file capabilities only (resolved from v1's `4755 root:root` ns-helper).  Removes the historical category of "setuid binary with capability creep" | D3-MA | `docs/v2/least-privilege.md`; phase 2 |
| T1548.001 | Setuid and Setgid | Defends (architecture) | v2's `babbleon-launch-untrusted` uses file capabilities (`CAP_SYS_ADMIN`, `CAP_SETUID`, `CAP_SETGID`, `CAP_IPC_LOCK`), not setuid | D3-MA | `docs/v2/least-privilege.md`; phase 2 |
| T1611 | Escape to Host | Defends | Tier classification via `/proc/self/ns/mnt` inode is the canonical check; untrusted callers of trusted operations refused; seccomp denies the `unshare`-family escape | D3-HCH, D3-MA | v1 `enforcement/linux_ns.rs` + v1 `enforcement/seccomp.rs` (port owed phase 2) |

### Tactic: Defense Evasion

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1027 | Obfuscated Files or Information | N/A | Babbleon IS the obfuscation (defender side); listed for symmetry | — | `crates/v2-babbleon-core/` |
| T1036 | Masquerading | Defends | Wrapper deception layer (v1 `babbleon-cli/src/deception.rs` → v2 phase 2 port) gives canonical `--help` text in untrusted tier so a process probing `curl --help` does not see the scrambled wrapper's shape | D3-PSEP | v1 `babbleon-cli/src/deception.rs` (port owed phase 2) |
| T1036.005 | Match Legitimate Name or Location | Defends | Wrapper deception emits real-binary banner text; per-host SHA-256 padding defeats binary-fingerprint identification | — | v1 `enforcement/wrapper.rs` (carry-from-v1 — v2-core has unified template) |
| T1070 | Indicator Removal | Partial | Audit chain is append-only with SHA-256 hash + Ed25519 sig in signed mode; rewriting historical entries is detectable | D3-OAM | `crates/v2-babbleon-core/src/events.rs::AuditChainSink` (shipped phase 1) + Ed25519 (port owed phase 1.5) |
| T1070.002 | Clear Linux or Mac System Logs | Out of scope | Syslog is operator-side; Babbleon's audit chain is separate and detects its own gap | — | — |
| T1140 | Deobfuscate/Decode Files or Information | N/A | Babbleon's preprocessor is the *legitimate* deobfuscator running in trusted tier; an attacker doing T1140 against Babbleon's scramble must re-derive the per-host mapping (the threat-model.md adversary's main objective) | — | `docs/v2/structure-scrambling.md` |
| T1480 | Execution Guardrails | Defends | Tier check at every wrapper exec is an execution guardrail; rotation epoch is a guardrail (binary that works in epoch N fails in epoch N+1) | D3-HCH | wrapper tier check; mapping rotation |
| T1497 | Virtualization/Sandbox Evasion | Out of scope | We don't claim to be a sandbox; we are a tier boundary.  Out of scope for evasion detection | — | — |
| T1562 | Impair Defenses | Partial | Audit chain detects post-compromise tampering; tripwires fire on probing; rate-limit + lockout on vault unlock attempts | D3-OAM | shipped (audit chain); v1 (vault rate-limit, port owed phase 1) |

### Tactic: Credential Access

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1003 | OS Credential Dumping | Defends | seccomp denies `ptrace`, `process_vm_readv`, `kcmp`, `pidfd_*`; Landlock denies kernel keyring + `~/.ssh` + `~/.gnupg` + `/etc/shadow` | D3-PSEP, D3-MA | v1 `enforcement/seccomp.rs` + `enforcement/landlock.rs` (port owed phase 2) |
| T1003.007 | Proc Filesystem | Defends | hidepid=2 on `/proc` inside untrusted PID-NS; seccomp denies the proc-inspection syscall family | D3-PSEP | v1 `enforcement/linux_ns.rs` (port owed phase 2) |
| T1003.008 | /etc/passwd and /etc/shadow | Defends | Landlock denies untrusted-tier read of `/etc/shadow` | D3-MA | v1 `enforcement/landlock.rs` (port owed phase 2) |
| T1056 | Input Capture | Partial | PID-NS isolation + seccomp deny on `ptrace` blocks cross-process keystroke capture; in-process input capture (xinput, evdev) is not blocked | D3-PSEP | v1 `enforcement/seccomp.rs` (port owed phase 2) |
| T1539 | Steal Web Session Cookie | Defends | Browser cookie dirs (Chrome, Firefox, Safari) included in credential gate; tmpfs overlay returns empty | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1552 | Unsecured Credentials | Defends | Credential gate covers the documented locations | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1552.001 | Credentials in Files | Defends | `~/.aws`, `~/.netrc`, `~/.docker/config.json`, `~/.kube/config` covered by credential gate | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1552.002 | Credentials in Registry | Out of scope | Windows-specific | — | — |
| T1552.003 | Bash History | Defends | `HISTFILE`, `BASH_HISTORY`, `HISTSIZE`, `HISTCONTROL` in env-var scrubber deny-list | D3-PSEP | v1 `credentials.rs` env scrubber (port owed phase 2) |
| T1552.004 | Private Keys | Defends | `~/.ssh`, `~/.gnupg`, `~/.aws/credentials` included in credential gate; `SSH_AUTH_SOCK`, `GPG_AGENT_INFO` in env scrubber | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1552.005 | Cloud Instance Metadata API | Partial | Babbleon does not block the metadata-API IP; compose with host firewall (network egress policy) | — | — (network-layer) |
| T1552.007 | Container API | Partial | `DOCKER_HOST`, `KUBECONFIG` paths covered by credential gate + env scrubber; raw network access to a Docker socket is not blocked | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1555 | Credentials from Password Stores | Defends | Browser password-store paths + GNOME-keyring / KWallet IPC sockets included in scrubber and credential gate | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1555.001 | Keychain (macOS/Linux) | Defends | GNOME-keyring D-Bus socket in env scrubber | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1555.003 | Credentials from Web Browsers | Defends | Browser profile dirs covered by credential gate | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1556 | Modify Authentication Process | Out of scope | PAM-stack modification is operator-side; Babbleon ships its own PAM module that does NOT modify others | — | `crates/babbleon-pam/` (v1; v2 port owed phase 2) |

### Tactic: Discovery

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1010 | Application Window Discovery | Out of scope | GUI-specific; Babbleon is CLI/headless | — | — |
| T1018 | Remote System Discovery | Out of scope | Network discovery; compose with firewall | — | — |
| T1033 | System Owner/User Discovery | Partial | Untrusted tier sees only its own user; `who`, `w`, `last` see the scrambled wrapper or refuse | D3-HCH | wrapper tier check (port owed phase 2) |
| T1057 | Process Discovery | Defends | PID-NS isolation + hidepid=2; seccomp denies `process_vm_readv`, `kcmp`, `pidfd_*` | D3-PSEP, D3-HCH | v1 `enforcement/linux_ns.rs` + `enforcement/seccomp.rs` (port owed phase 2) |
| T1069 | Permission Groups Discovery | Partial | `getent group` against the per-tier `nsswitch` config returns scrambled or limited group info; full coverage requires NSS plugin (filed for phase 4) | — | — (phase 4 NSS plugin) |
| T1082 | System Information Discovery | Documented limitation | L3 — `/proc/self/maps` discloses libc canonical path; visible from `uname` regardless.  No claim of defense | — | `docs/threat-model.md` §L3 |
| T1083 | File and Directory Discovery | Defends | Mount-NS overlays + credential gate make protected paths return ENOENT; untrusted `$PATH` returns scrambled compounds | D3-HCH, D3-MA | v1 `enforcement/linux_ns.rs` + `credentials.rs` (port owed phase 2) |
| T1087 | Account Discovery | Partial | Untrusted-tier `getent passwd` returns the calling user only; full coverage requires NSS plugin | — | — (phase 4 NSS plugin) |
| T1124 | System Time Discovery | Out of scope | Time leakage is fundamental; v2 rotation cadence is by design synchronised | — | — |
| T1135 | Network Share Discovery | Out of scope | Network share enumeration; compose with firewall + share permissions | — | — |
| T1201 | Password Policy Discovery | Out of scope | `/etc/security` read is operator-side concern | — | — |
| T1217 | Browser Information Discovery | Defends | Browser profile dirs covered by credential gate | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1518 | Software Discovery | Defends | Scrambled `$PATH` returns scrambled compounds; tripwires on probing scrambled names; honey-list catches random-guess probes | D3-HCH, D3-RAPA | v1 wrapper template + `crates/v2-babbleon-core/src/mapping.rs` (honey list shipped phase 1) |
| T1518.001 | Security Software Discovery | Defends | Same mechanism as T1518; specifically, an attacker probing for `clamav`, `falco`, `wazuh` etc. sees scrambled or honey-flagged responses | D3-RAPA | as above |

### Tactic: Lateral Movement

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1021 | Remote Services | Partial | `~/.ssh/known_hosts` is in credential gate; SSH agent socket is scrubbed; outbound network is not blocked | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1021.004 | SSH | Partial | As above | D3-MA | as above |
| T1210 | Exploitation of Remote Services | Out of scope | Network attack surface | — | — |
| T1570 | Lateral Tool Transfer | Partial | Static payload transfer (BYOE limitation L2) is not blocked; what the transferred tool can find on the host IS limited | — | `docs/threat-model.md` §L2 |

### Tactic: Collection

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1005 | Data from Local System | Partial | Credential gate covers documented secret dirs; arbitrary user files are reachable by the user uid | D3-MA | v1 `credentials.rs` (port owed phase 2) |
| T1056 | Input Capture | Partial | See Credential Access | D3-PSEP | as above |
| T1074 | Data Staged | Out of scope | Attacker behavior; detection rather than prevention surface | — | — |
| T1115 | Clipboard Data | Partial | X11 selection is not blocked; Wayland is per-window-isolated by the compositor | — | — |
| T1213 | Data from Information Repositories | Out of scope | Application-side concern | — | — |

### Tactic: Command and Control

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1071 | Application Layer Protocol | Out of scope | Network egress; compose with host firewall | — | — |
| T1090 | Proxy | Out of scope | Network-layer | — | — |
| T1095 | Non-Application Layer Protocol | Out of scope | Raw socket access defended at network layer | — | — |
| T1571 | Non-Standard Port | Out of scope | Network-layer | — | — |
| T1573 | Encrypted Channel | Out of scope | Network-layer | — | — |

### Tactic: Exfiltration

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1041 | Exfiltration Over C2 Channel | Out of scope | Network egress | — | — |
| T1052 | Exfiltration Over Physical Medium | Out of scope | Physical access | — | — |
| T1567 | Exfiltration Over Web Service | Out of scope | Network egress | — | — |

### Tactic: Impact

| ID | Technique | Status | Mechanism | D3FEND | Where |
|---|---|---|---|---|---|
| T1485 | Data Destruction | Out of scope | Filesystem operation defended by OS DAC; Babbleon does not block deletes by the user uid | — | — |
| T1486 | Data Encrypted for Impact | Out of scope | Ransomware impact requires complementary controls (immutable backups) | — | — |
| T1490 | Inhibit System Recovery | Out of scope | OS-level recovery configuration | — | — |
| T1496 | Resource Hijacking | Out of scope | CPU/memory/disk quota concern; cgroups (operator-side) | — | — |

---

## 2. D3FEND coverage (reverse direction)

Each D3FEND technique Babbleon implements, with the ATT&CK
techniques it raises the cost of.

| D3FEND ID | Defensive technique | ATT&CK techniques covered | v2 mechanism (1-line) | Phase / where |
|---|---|---|---|---|
| D3-HCH | Hierarchical Domain Configuration | T1057, T1083, T1518, T1611, T1480, T1033 | Trust tiers (trusted/untrusted) via mount-NS inode classification | phase 2 (`babbleon-launch-untrusted/`) |
| D3-MA | Mandatory Access Control | T1003, T1003.008, T1083, T1059, T1059.004, T1543, T1548, T1548.001, T1552.*, T1555.*, T1574.006, T1217, T1021.004, T1005 | Landlock self-sandbox on untrusted tier; AppArmor + SELinux profile templates | phase 2 (Landlock); phase 6 (profile templates) |
| D3-PSEP | Process Self-Encryption Prevention | T1003, T1003.007, T1057, T1106, T1056, T1559, T1036 | seccomp denies `ptrace`, `process_vm_readv`, `kcmp`, `pidfd_*` | phase 2 (`v2-babbleon-core` declares; launcher applies) |
| D3-FAPA | File Access Pattern Analysis | T1574 | Tripwire FIFO + `TripwireResponsePolicy` (`NotifyOnly`/`KillTrigger`/`KillTriggerTree`) | shipped phase 1 (`crates/v2-babbleon-core/src/events.rs` + `tripwire.rs`) |
| D3-DSE | Data Service Encryption | (Vault — defender-internal, no direct ATT&CK ID) | `age` envelope encryption + Argon2id KDF; FIDO2 / TPM behind hardware gates | phase 1 (soft); phase 5 (hw) |
| D3-RAPA | Resource Access Pattern Analysis | T1518, T1518.001, T1574 | Honey-name + stale-mapping tripwires emit `Tripwire { source }` events | shipped phase 1 (`crates/v2-babbleon-core/src/mapping.rs` honey list + stale list) |
| D3-OAM | Operating System Activity Monitoring | T1070, T1562 | Audit log (SHA-256 chain + Ed25519 sig) emitted to JSONL sink + optional SIEM forwarders | shipped phase 1 (chain); signed mode + SIEM forwarders phase 1.5 + phase 2 |
| D3-NTA | Network Traffic Analysis | (not implemented; out-of-scope) | — | — |

---

## 3. Coverage statistics

Counts are over the ATT&CK techniques and sub-techniques
explicitly listed above (this matrix is not exhaustive over
ATT&CK v17's 222 + 475 = 697 total; it covers the techniques
Babbleon makes a defensive claim about, plus a representative
sample of out-of-scope items for completeness).

| Tactic | Defends | Partial | Out of scope | N/A / Doc-limit |
|---|---|---|---|---|
| Initial Access | 0 | 1 | 2 | 0 |
| Execution | 3 | 2 | 3 | 1 |
| Persistence | 1 | 2 | 3 | 0 |
| Privilege Escalation | 3 | 0 | 2 | 0 |
| Defense Evasion | 3 | 2 | 2 | 2 |
| Credential Access | 11 | 3 | 2 | 0 |
| Discovery | 4 | 3 | 4 | 1 |
| Lateral Movement | 0 | 3 | 1 | 0 |
| Collection | 0 | 3 | 2 | 0 |
| Command and Control | 0 | 0 | 5 | 0 |
| Exfiltration | 0 | 0 | 3 | 0 |
| Impact | 0 | 0 | 4 | 0 |

Babbleon's strongest coverage is in **Credential Access** and
**Discovery** — those are where the AI-attacker classification's
"untrusted process probing the host for canonical names and
canonical credential paths" maps most directly to ATT&CK.

The doc-limit row tracks techniques Babbleon explicitly disclaims
because the threat-model.md L1/L2/L3 limitations apply:

| Doc limit | Technique | Why |
|---|---|---|
| L3 | T1082 | `/proc/self/maps` libc canonical path is required by the ELF loader |
| L3 | T1129 | Same |

---

## 4. Where to grep next

- For the **threat narrative** behind any row: `docs/v2/threat-model.md`.
- For the **standards survey** behind ATT&CK + D3FEND + 800-190
  + 800-207 references: `docs/v2/standards-alignment.md`.
- For the **structural-scrambling mechanism** behind every
  T1059.* and T1059 row in the Execution tactic:
  `docs/v2/structure-scrambling.md`.
- For the **least-privilege mechanism** behind every T1548* and
  T1611 row: `docs/v2/least-privilege.md`.
- For the **security baseline rules** that ship the discipline
  enabling many of the "Defends (process)" rows:
  `docs/v2/security-baseline.md`.

---

## 5. Maintenance

When a v2 phase ships, walk every row whose `Where` cites that
phase and confirm the mechanism landed.  Update the row's status
if anything regressed.

When ATT&CK or D3FEND publish a new version (next expected:
ATT&CK v18 mid-2026), check the diff against the rows above for
renames, deprecations, or new techniques in tactics where
Babbleon claims coverage.  Add rows for the new techniques;
update IDs for any rename.

Last refreshed: 2026-06-18 (filed alongside `threat-model.md`).
