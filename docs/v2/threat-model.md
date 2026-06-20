# Threat model — v2

This document is the v2 threat model.  It supersedes v1's two
threat docs (`docs/threat-model.md` — the AI-attacker
classification — and `docs/threat-model-stride.md` — the
24-row STRIDE matrix), composes them, and adds the standards
mappings v1 missed: MITRE ATT&CK, MITRE D3FEND, NIST SP 800-190
§§4.4–4.5, and NIST SP 800-207's seven Zero Trust tenets.

Companion doc: `docs/v2/attack-mapping.md` (in flight) — the
full ATT&CK + D3FEND traceability matrix.  This document gives
the threat-model commitment; that one gives the auditor-grade
grep surface.

Scope: only the v2 product (`crates/v2-*` + the planned phase
2–5 crates) is described as "Babbleon" below.  v1
(`crates/babbleon*`) is DEPRECATED; see `crates/DEPRECATED-V1.md`.

Sources composed:

- `docs/threat-model.md` — v1 AI-attacker classification
  (carried forward verbatim where unchanged).
- `docs/threat-model-stride.md` — v1 STRIDE matrix (re-evaluated
  for v2).
- `docs/v2/phase0-research-notes.md` §§1–3 — ATT&CK, 800-190,
  800-207 reference material.
- `docs/v2/standards-alignment.md` — initial mapping sketches.
- `V2_PLAN.md` — what v2 adds vs v1.

---

## 1. Adversary classification (carried from v1; still authoritative)

Two underlying threats, several deployment shapes.  v1's
analysis stands — the threat landscape did not change between v1
and v2; the *mechanism* did.

**Underlying threat A — disconnected.**  The attacker has only
what they brought on-host: their own reasoning weights, their own
toolset, no live link to peers.  Once an untrusted process is
running, the model decides what to do from inside it.  Babbleon's
rename + tier + tripwires + credential gate work directly
against this attacker because the attacker's playbook is keyed
on canonical names and canonical paths that no longer resolve.

**Underlying threat B — connected.**  The attacker has a live
link out — to a single larger model, to a peer swarm, to a botnet
controller, to a shared exploit feed.  The on-host model does not
have to crack anything itself; it just relays the current
vocabulary out, receives translated instructions back, and
executes them *within the current rotation window*.  Babbleon's
defense against the connected attacker is **rotation rate ≪ relay
round-trip**.

| Expression | Body | Brain | What defeats it (v2) |
|---|---|---|---|
| **E1.** Solo internal worm. | on-host | on-host | identifier + structural scramble + tier + tripwires |
| **E2.** Solo external attacker. | off-host | off-host | NOT Babbleon — needs network segmentation, service hardening |
| **E3.** Hybrid: small local + large external. | on-host | off-host | rotation < API RTT (typically 1–5 s); preprocessor closes the window faster than v1 |
| **E4.** Adversarial network of LLMs. | many on-host | distributed | per-host randomization + rotation < propagation window; **structural scrambling defeats the per-host shape-fingerprint attack v1 lost to** |

v1's loss on E4 — frontier models defeating the identifier-only
scramble when given the original source side-by-side — is the
load-bearing reason v2 exists.  See `V2_PLAN.md` §"Why v1 is not
the public product" for the full analysis.  v2's answer is the
five-layer structural-scrambling stack from
`docs/v2/structure-scrambling.md`.

---

## 2. Asset model

What v2 defends, ordered by attacker payoff:

1. **The per-host secret** — the only secret on the box.  32
   random bytes.  Reading it recovers every per-epoch mapping,
   every honey list, every tripwire identifier, every wrapper
   padding.  Held in `Zeroizing<[u8; 32]>`; never reaches disk
   uncovered; never copied (no `Clone`/`Copy`/`Debug` derive).
   Threat-model boundary: a kernel-privileged attacker can read
   process memory directly; Babbleon does not defeat that and
   defers to v3 confidential-VM work for that surface.
2. **Tracked-tool inventory** — the set of canonical tools the
   host uses (`curl`, `ssh`, `aws`, `gh`, ...).  Knowing the
   inventory tells an attacker what credentials and service
   integrations to look for.  v2 hides the inventory via the
   mount-NS tier boundary; the untrusted tier sees only
   scrambled compounds.
3. **Credentials** — `~/.aws`, `~/.ssh`, `~/.gnupg`, browser
   cookies, IPC sockets (`SSH_AUTH_SOCK`, `gpg-agent`).  v2's
   credential-gate (carried from v1; re-implemented under v2
   conventions in phase 2) puts a tmpfs overlay over each cred
   dir and scrubs the env-var deny-list at the trust boundary.
4. **Process state of trusted-tier siblings** — process names,
   PIDs, memory, env.  v2 PID-NS + seccomp + Landlock keep them
   invisible to the untrusted tier.
5. **Audit log integrity** — the SHA-256 hash-chained event log
   (with Ed25519 signing in production).  An attacker who can
   rewrite the log past their entry point hides their activity
   from forensics.  v2 carries v1's signed-chain mechanism
   forward and ships it from day one.

Out of scope (Babbleon does not pretend to defend):

- **Network egress.**  Compose with host firewall / outbound
  policy.
- **Kernel CVEs against mount-NS, PID-NS, seccomp, Landlock.**
  We document the kernel-version floor; the operator is
  responsible for patching.
- **Hypervisor / SMM / CPU vulnerabilities.**
- **Physical access to a powered-on machine in trusted state.**
- **Supply-chain compromise of the Babbleon binary itself** —
  defended by SLSA L3 provenance, sigstore signing, in-toto
  attestations (phase 6), but not perfectly.
- **Side channels (Spectre, RowHammer)** against a running vault
  unlock.

---

## 3. What v2 changes vs v1 (threat-model deltas)

| Delta | v1 mechanism | v2 mechanism | Threat closed |
|---|---|---|---|
| Identifier scramble is shape-defeated | Identifier-only rename | Five-layer structural scramble (identifier + operator + whitespace + reorder + decoys) | E4 frontier-model shape fingerprint |
| Domain separation is hand-rolled | `SHA-256(secret \|\| label)` | HKDF-SHA-256 per `(epoch, purpose)` | Cross-purpose key reuse (audit recognizability) |
| Privilege model is over-broad | `4755 root:root` setuid helper | File capabilities, no setuid; per-syscall `CAPABILITY:` annotations | T1574-class hijack via setuid binary; CIS 4.1 violation |
| Secrets are bolted-on zeroize | `Zeroizing` added late, leaves seams (e.g. `host_secret_hex: String`) | `SecretBox`/`Zeroizing` from day one; rule-11 in security-baseline | Core dump / heap reuse / debug-print disclosure |
| Constant-time compare added late | `subtle::ConstantTimeEq` added after audit | Mandated by rule 4 from day one | Timing leak on honey-name match |
| `unsafe` documentation discipline | `SAFETY:` comments retro-applied | Required by rule 9; clippy lint enforces | Memory-safety regressions on PR |
| Multi-language wordlist | English only | EN + ES/FR/DE/JA/ZH/AR/... cycled per epoch | Small-model tokenizer-cost superlinear hypothesis (re-test in phase 4) |
| Preprocessor surface | n/a | New runtime un-scrambler; its own seccomp + hardening profile | Adds attack surface — preprocessor crate carries its own threat model in `docs/v2/structure-scrambling.md` §"Preprocessor topology" |

The structural-scrambling addition is the largest threat-model
shift.  v1 said honestly: "near-frontier models cannot crack the
scramble blind, but DO trivially defeat it when given the
original alongside."  v2's answer is to defeat the shape-
fingerprint vector entirely (wall-of-text + reorder + decoys), so
that having the original alongside no longer translates into
matching line N → line N's purpose.

---

## 4. STRIDE matrix — v2

Carries v1's structure (`docs/threat-model-stride.md`) and
re-evaluates each row for v2.  New rows added for surfaces v1
did not have (preprocessor, mapping-worker).  Status legend:

- **Shipped (v2-core)** — code is in `crates/v2-babbleon-core/`
  today.
- **Carry-from-v1, port owed** — mechanism exists in v1, must be
  reimplemented under v2 conventions in the phase noted.
- **New in v2** — mechanism does not exist in v1; phase noted.

| # | Category | Threat | Asset | Status | Reference |
|---|---|---|---|---|---|
| S1 | **Spoofing** | An untrusted-tier process invokes the real binary by canonical name | Trusted-tier identity | Carry-from-v1, port owed phase 2 | v1 `enforcement/linux_ns.rs`; v2 `babbleon-launch-untrusted/` |
| S2 | **Spoofing** | Local-network attacker forges rotation timer / vault unlock prompt | Vault unlock | Out of scope (local CLI; no network surface) | — |
| S3 | **Spoofing** | A SIEM consumer accepts a forged audit-log line appended after compromise | Audit log integrity | Carry-from-v1, port owed phase 1.5 | v1 `audit.rs::open_signed` + `verify_signed` |
| S4 | **Spoofing** | An attacker substitutes the preprocessor binary with a Trojan that emits scrambled-but-watched source | Preprocessor integrity | New in v2 phase 3 | Preprocessor is a separate binary; SLSA L3 + cosign signature + on-launch self-verify |
| T1 | **Tampering** | On-host attacker rewrites audit JSONL to hide activity | Audit log | Shipped (v2-core: `events::AuditChainSink` + `JsonlFileSink`); Ed25519 sig port owed phase 1.5 | `crates/v2-babbleon-core/src/events.rs` |
| T2 | **Tampering** | MITM swaps a release tarball | Release artifact | Carry-from-v1, port owed phase 6 | v1 `release.yml` (cosign + SLSA L3); v2 inherits |
| T3 | **Tampering** | Malicious dep (xz-class) lands a backdoor | Build integrity | Carry-from-v1, port owed phase 6 | `cargo audit` + `cargo deny` + `cargo vet` |
| T4 | **Tampering** | Runaway-large line on `/run/babbleon/honey.fifo` OOMs daemon | Honey FIFO reader | Carry-from-v1, port owed phase 2 | v1 `events.rs::read_bounded_line` + 16 KiB cap (CWE-400) |
| T5 | **Tampering** | Wrapper template gains injection-friendly substitution field | Wrapper script | Shipped (v2-core: `wrapper::render`); CWE-78 audited | `crates/v2-babbleon-core/src/wrapper.rs` |
| T6 | **Tampering** | Preprocessor's seccomp profile permits a syscall that lets a compromised preprocessor write unscrambled source to disk | Source confidentiality | New in v2 phase 3 | Preprocessor seccomp deny-list designed to refuse `openat(... \|O_CREAT)` against on-disk paths |
| R1 | **Repudiation** | Privileged user denies emitting a rotation event | Audit chain | Carry-from-v1, port owed phase 1.5 | Hash chain + Ed25519 sig |
| R2 | **Repudiation** | SIEM forwarder claims it never received an event | Forwarder integrity | Out of scope (SIEM-side) | — |
| I1 | **Information Disclosure** | Untrusted process learns real path of a tracked binary | Tracked-tool inventory | Carry-from-v1, port owed phase 2 | Mount-NS + per-tier mapping; tier check via `/proc/self/ns/mnt` inode |
| I2 | **Information Disclosure** | Vault file leaks host secret if exfiltrated | Host secret | Carry-from-v1, port owed phase 1 | `age` envelope + Argon2id KDF (~250 ms) |
| I3 | **Information Disclosure** | Core dump or paged-out memory leaks host secret or KEK | Host secret in RAM | Shipped (v2-core: `PerHostSecret` is `Zeroizing<[u8; 32]>`); process hardening port owed phase 2 | `crates/v2-babbleon-core/src/per_host_secret.rs` |
| I4 | **Information Disclosure** | Timing of `is_honey` reveals position of match | Honey-name layout | Shipped (v2-core: `crypto_compare::secret_bytes_equal` + `MappingTable::is_honey` full-traversal) | `crates/v2-babbleon-core/src/crypto_compare.rs` |
| I5 | **Information Disclosure** | Wrapper script size is a fingerprint | Tier classification | Shipped (v2-core: unified wrapper template generator) | `crates/v2-babbleon-core/src/wrapper.rs` |
| I6 | **Information Disclosure** | `/proc/self/maps` discloses `libc.so.6` canonical path | Library identity | Documented limitation (L3) | §"Known limitations" below |
| I7 | **Information Disclosure** | Frontier model defeats identifier-only scramble by structural shape | Tracked-tool inventory (via shape) | New in v2 phase 3 — addressed by structural scrambling | `docs/v2/structure-scrambling.md` |
| I8 | **Information Disclosure** | Mapping-worker memory read recovers next epoch's permutation pre-build | Future mapping | New in v2 phase 3 | Mapping worker runs in separate UID, no shared address space; one-shot pipe transfers activated table at rotation tick |
| D1 | **Denial of Service** | Brute-force vault unlock burns CPU on Argon2id | Vault availability | Carry-from-v1, port owed phase 1 | v1 `vault::attempts` — 3 free → exp backoff → lockout at 10 |
| D2 | **Denial of Service** | Rapid rotation cadence overwhelms wrapper generation | Daemon CPU | Carry-from-v1, port owed phase 2 | Unified runtime-table wrapper + background perm pre-build (v1 mapping-worker design) |
| D3 | **Denial of Service** | FPE permutation cache grows unbounded across rotations | Daemon RAM | Carry-from-v1, port owed phase 2 | v1 `mapping/fpe.rs::Cache` FIFO bound at 32 entries (CWE-770) |
| D4 | **Denial of Service** | Bad sidecar `.attempts` file locks operator out | Vault recoverability | Carry-from-v1, port owed phase 1 | Corrupt sidecar defaults to "no attempts"; failures logged + skipped |
| D5 | **Denial of Service** | Preprocessor parse failure on every invocation makes scripts unrunnable | Trusted-tier scripts | New in v2 phase 3 | Preprocessor reports parse error with line+col against the unscrambled view; CLI ships `babbleon unscramble FILE` for operator debugging |
| E1 | **Elevation of Privilege** | Setuid helper retains residual capability after dropping UID | Local privilege boundary | **Resolved in v2 (no setuid).**  v2 uses file caps on `babbleon-launch-untrusted` | `docs/v2/least-privilege.md`; phase 2 |
| E2 | **Elevation of Privilege** | Untrusted-tier process re-execs into a tracked tool to escape mount NS | Tier separation | Carry-from-v1, port owed phase 2 | NNP-locked; mount NS persists across exec; seccomp denies ptrace family |
| E3 | **Elevation of Privilege** | Scrambled wrapper script reached at non-canonical path via traversal | Filesystem boundary | Shipped (v2-core: scrambled names are lowercase-alpha-only via wordlist filter) | `crates/v2-babbleon-core/src/wordlist.rs` |
| E4 | **Elevation of Privilege** | PR adds `unsafe` block without documented invariants | Memory safety | Shipped (process control via security-baseline rules 1 + 9) | `docs/v2/security-baseline.md` rules 1, 9 |
| E5 | **Elevation of Privilege** | Compromised preprocessor escalates by writing to a path with elevated permissions | Preprocessor blast radius | New in v2 phase 3 | Preprocessor runs as the calling user with its own seccomp + Landlock; cannot write to `/etc`, `/usr`, `/boot` |

**Read this table as:** every "Shipped" row has a code-level
defense and at least one test exercising it.  Every
"Carry-from-v1" row has a v1 defense the port will replicate
under v2 conventions; the phase indicates when.  Every "New in
v2" row identifies a surface that v1 did not have, with the
phase that designs/builds the defense.

---

## 5. MITRE ATT&CK mapping (v17, June 2026)

Per `docs/v2/phase0-research-notes.md` §1, ATT&CK current is v17
(April 2025).  Babbleon v2's defenses keyed by technique ID.
The full traceability matrix is in `docs/v2/attack-mapping.md`
(in flight); this section names the techniques v2 most directly
affects.

| ATT&CK ID | Technique | v2 defence | Where (phase) |
|---|---|---|---|
| T1059 | Command and Scripting Interpreter | Identifier + operator + whitespace scramble; preprocessor refuses untrusted-tier invocation | phase 3 |
| T1057 | Process Discovery | PID-NS + `hidepid=2`; seccomp denies `process_vm_readv`, `kcmp`, `pidfd_*` | phase 2 |
| T1083 | File and Directory Discovery | Mount-NS hides credentials; scrambled `$PATH` returns scrambled names | phase 2 |
| T1552.001 | Credentials in Files | Credential gate (tmpfs overlay) over `~/.aws`, `~/.ssh`, `~/.gnupg`, browser cookies | phase 2 |
| T1552.003 | Bash History | `HISTFILE`, `BASH_HISTORY`, `HISTSIZE` in env-var scrubber deny-list | phase 2 |
| T1552.004 | Private Keys | `~/.ssh`, `~/.gnupg` paths included in credential gate | phase 2 |
| T1555 | Credentials from Password Stores | Browser cookie dirs, `gpg-agent` IPC socket included in gate + env scrubber | phase 2 |
| T1518 | Software Discovery | Scrambled `$PATH`; tripwires on probing scrambled names; honey-list catches random-guess probes | phase 1 (mapping) + phase 2 (PATH wiring) |
| T1574 | Hijack Execution Flow | Stale-mapping tripwire catches cached-mapping attackers across rotation | phase 1 (stale list) + phase 2 (wrapper check) |
| T1003 | OS Credential Dumping | seccomp denies `process_vm_readv`, `ptrace`; Landlock denies `~/.ssh`, kernel keyring read | phase 2 |
| T1027 | Obfuscated Files or Information | (We are the defender doing this against the attacker, not the attacker doing this against us — listed for symmetry) | n/a |
| T1082 | System Information Discovery | NOT defeated; documented as L3 limitation (libc path leak via `/proc/self/maps`) | §"Known limitations" |
| T1505.003 | Web Shell | Out of scope (host-side defence; web-server-side concern) | — |
| T1078 | Valid Accounts | Out of scope (account management) | — |
| T1011 | Exfiltration Over Other Network Medium | Not defeated; compose with network egress policy | — |
| T1059.006 | Python | Layer 2 operator scramble specifically targets Python keywords; layer 3 whitespace-as-words defeats indentation fingerprint | phase 3 |
| T1059.004 | Unix Shell | Identifier scramble defeats canonical-name path; preprocessor defeats shell-shape fingerprint | phase 3 |
| T1071 | Application Layer Protocol | Not defeated (outbound network) | — |
| T1036 | Masquerading | Wrapper deception layer (v1 `babbleon-cli/src/deception.rs`) gives canonical `--help` text in untrusted tier; v2 ports this to `crates/v2-babbleon/` | phase 2 (CLI deception port) |

**Note on T1027:** Babbleon is itself an "obfuscated information"
production tool, used defensively.  The ATT&CK direction is
attacker → defender; the technique appears in our defensive
toolkit because we use the same family of techniques against the
attacker's reasoning layer.  This is normal for MTD-class
defenses.

---

## 6. MITRE D3FEND mapping

D3FEND is the defensive-countermeasure ontology that pairs with
ATT&CK.  v2 implements:

| D3FEND ID | Defensive technique | v2 mechanism | Phase |
|---|---|---|---|
| D3-HCH | Hierarchical Domain Configuration | Trust tiers (trusted/untrusted) via mount-NS inode classification | phase 2 |
| D3-MA | Mandatory Access Control | Landlock LSM self-sandbox on untrusted tier; AppArmor / SELinux profile templates | phase 2 (Landlock); phase 6 (profile templates) |
| D3-PSEP | Process Self-Encryption Prevention | seccomp denies `ptrace`, `process_vm_readv`, `kcmp`, `pidfd_*` | phase 2 |
| D3-FAPA | File Access Pattern Analysis | Tripwire FIFO + TripwireResponsePolicy (NotifyOnly / KillTrigger / KillTriggerTree) | Shipped (v2-core: `events.rs` + `tripwire.rs`) |
| D3-DSE | Data Service Encryption | Vault: `age` envelope encryption + Argon2id KDF for unlock; FIDO2 + TPM backends behind hardware gates | phase 1 (soft backend); phase 5 (hardware) |
| D3-NTA | Network Traffic Analysis | Not implemented (out-of-scope; network-layer concern) | — |
| D3-RAPA | Resource Access Pattern Analysis | Honey-name + stale-mapping tripwires emit `Tripwire { source }` events; audit chain records | Shipped (v2-core); rotation cadence phase 2 |
| D3-OAM | Operating System Activity Monitoring | Audit log (SHA-256 chain + Ed25519 sig) emitted to JSONL sink + optional SIEM forwarders | Shipped (v2-core: chain); signed mode + SIEM forwarders phase 2 |

The full ATT&CK ⇄ D3FEND traceability matrix lives in
`docs/v2/attack-mapping.md` (in flight).  That doc cross-
references which ATT&CK technique each D3FEND control mitigates,
so an auditor can grep "T1057" and find every D3FEND control
Babbleon ships against it.

---

## 7. NIST SP 800-190 mapping (Container Security Guide)

Sections that apply to Babbleon (which uses mount + PID
namespaces) are §4.4 (Container) and §4.5 (Host OS).  §4.1
(Image), §4.2 (Registry), §4.3 (Orchestrator) are not applicable
— Babbleon ships no images, registries, or orchestrators.

### §4.4 — Container-related risks

| §4.4 subsection | v2 mapping |
|---|---|
| 4.4.1 Vulnerabilities in runtime software | v2 documents the kernel-version floor (Landlock requires 5.13+; PID-NS + mount-NS work on every supported kernel) and which CVEs are gated by it.  The operator is responsible for kernel patching. |
| 4.4.2 Unbounded network access from containers | Out of scope.  Compose with host firewall + outbound policy.  Documented limitation L1 in `docs/threat-model.md`. |
| 4.4.3 Insecure container runtime configurations | All applicable controls implemented: `make_root_private`, `MS_PRIVATE \| MS_REC` on the trust-boundary mount, `hidepid=2` on `/proc` inside the untrusted PID NS, seccomp deny-list, Landlock self-sandbox.  All ports to v2 phase 2. |
| 4.4.4 App vulnerabilities | User-side concern, not Babbleon. |
| 4.4.5 Rogue containers | Trust-tier check via `/proc/self/ns/mnt` inode refuses untrusted callers of trusted operations.  Tier classification is the canonical Babbleon control here.  Phase 2. |

### §4.5 — Host OS risks

| §4.5 subsection | v2 mapping |
|---|---|
| Kernel hardening (KASLR, kptr_restrict, dmesg_restrict) | v2 ships `docs/v2/cis-deployment.md` (filed for phase 6) recommending these settings.  Babbleon itself does not configure the kernel; the operator does, and the CIS / STIG profile docs translate that into a checklist. |
| Reduced attack surface | v2 file-cap launcher (replacing v1's setuid) directly satisfies CIS 4.1 (no setuid root binaries except those that must be).  Phase 2. |
| MAC framework (SELinux, AppArmor) | v2 ships SELinux and AppArmor profile templates carried from v1.  Phase 6. |
| Audit framework | v2 audit chain is the application-level analog; auditd integration via JSONL sink ingest is operator-side. |

---

## 8. NIST SP 800-207 zero-trust tenet mapping

Per `docs/v2/phase0-research-notes.md` §3, the seven tenets are:

| # | Tenet | v2 implementation |
|---|---|---|
| 1 | All data sources and computing services are considered resources. | Every tool, credential dir, IPC socket, and process is a resource classified by tier (trusted/untrusted).  Resource catalog lives in the mapping table; classification happens at the mount-NS boundary. |
| 2 | All communication is secured regardless of network location. | Intra-host: tier boundary denies cross-tier IPC (env-var scrubbing, IPC socket deny-list, PID-NS isolation).  Network: out of scope; compose with mTLS / VPN at the network layer. |
| 3 | Access to individual resources is granted on a per-session basis. | Each rotation epoch is a new session.  Mapping changes; previous-epoch scrambled names become stale-list tripwires.  Per-process tier classification at exec time. |
| 4 | Access determined by dynamic policy (identity + state + context). | Trust-tier check via mount-NS inode at every wrapper exec.  Honey tripwires are state-dependent (per-epoch random honey set).  Response policy (`NotifyOnly` / `KillTrigger` / `KillTriggerTree`) is context-dependent (operator config + tripwire source). |
| 5 | Enterprise monitors integrity and security posture of all assets. | Tripwire FIFO + audit chain emit on every tier crossing.  Audit signed mode lets a SIEM verify the chain end-to-end. |
| 6 | Authentication and authorisation are dynamic and strictly enforced. | Per-exec NS-inode check (tier authn); vault unlock per session (operator authn); rate-limit + lockout on unlock attempts. |
| 7 | Enterprise collects as much info as possible to improve posture. | Audit log records every rotation, every tripwire fire, every response policy invocation.  Operator can route to SIEM via the JSONL sink. |

The mapping is documentary — Babbleon's tier model was designed
as zero-trust at the host layer before 800-207 was cited.  This
section makes the alignment explicit for procurement reviewers.

---

## 9. Known limitations (carried from v1, still load-bearing)

Three load-bearing limitations.  All three are real and
acknowledged; designs that pretend otherwise are dishonest.
v2 does not change any of these — the structural-scrambling
additions are orthogonal.

**L1. Built-in / direct syscall bypass.**  If the attacker has
RCE inside a process that already carries its own network and
filesystem libraries — Node.js, Python, PHP, Ruby, Go, Java —
they do not need `/usr/bin/curl`.  The runtime's `socket()` /
`openat()` / `execve()` calls go to the kernel directly,
ignoring Babbleon's userspace namespace renames.  Babbleon's
defenses against this attacker:

- mount-NS keeps credential paths unreachable (Python
  `open('~/.aws/credentials')` returns ENOENT in the untrusted
  view);
- seccomp deny-list blocks peer-inspection syscalls but does NOT
  block raw networking;
- rotation degrades any cached path that the runtime learned
  from its own previous run.

Babbleon does NOT block:

- raw outbound network traffic from an untrusted-tier runtime,
- re-implementations of `curl` written in five lines of Python,
- reading any file the kernel grants the user uid access to.

Compose with host firewall (outbound deny-by-default), Landlock /
AppArmor for syscall-level file gating.

**L2. Bring Your Own Environment (BYOE).**  Statically-linked
self-contained payloads — typically BusyBox-class — run
regardless of what Babbleon renames.  The payload carries its
own shell, networking, grep.

The honest accounting: rename + tier do not stop a static payload
from running.  What they DO stop is the payload from
accomplishing much *with what it finds on the host*:

- the payload still cannot read scrambled-gated credential dirs;
- the payload still cannot enumerate trusted-tier processes
  (PID NS isolation);
- the payload still cannot ptrace or `process_vm_readv` siblings
  (seccomp);
- tripwires still fire if the payload probes wordlist-shaped
  names.

BYOE gives the attacker *primitives* but not *knowledge*.

**L3. Shared-library leak via `/proc/self/maps`.**  Every
dynamically-linked process needs `ld-linux.so` and `libc.so.6`
at canonical paths to start.  We cannot obfuscate those without
breaking the ELF loader.  An untrusted process always sees the
libc path in its own `/proc/self/maps`.

This leak gives the attacker:

- confirmation that the host is glibc-based Linux of
  approximately known version (also visible from `uname` and
  basic syscall behavior; nothing new);
- the canonical path of one library — but NOT the scrambled
  path of any tool.

What it does NOT give: the scramble mapping.  Tools and
credentials are obfuscated independently; the ELF loader path is
a fingerprint surface, not a key-recovery channel.

Designs that try to obfuscate libc itself are vetoed.

---

## 10. Detection signals

- **Honey tripwire** — invocation of any honey-mapped name.
  Very high confidence: legitimate programs have no source of
  the current epoch's randomly-generated honey names.  Not
  literally 100 % — a determined attacker can shotgun random
  compound shapes hoping to land on a tripwire, but the false-
  positive cost is bounded and the alert IS a signal even then.
- **Stale-mapping tripwire** — invocation of a *previous* epoch's
  scrambled name.  Catches cached-mapping attackers that learned
  the vocabulary in epoch N and tried to use it in epoch N+1+.
  Equivalent to T1574 cache invalidation.
- **Argon2 unlock-fail rate spike** — brute-force attempt.
- **Cross-NS bind-mount attempt** — kernel denies + Babbleon
  logs.
- **Audit-log chain gap or signature failure** — JSONL log is
  append-only with a SHA-256 hash chain; signed mode adds
  Ed25519 per entry.  Gap = tampering or process crash;
  signature failure = tampering.

---

## 11. Failure modes we accept

- A user dropping themselves into a root shell sees real names —
  by design (root is trusted).
- A trusted-NS process that hands a scrambled name to an
  untrusted child via env var has leaked the name.  We document
  the boundary; v2 has the env-var scrubber but cannot stop
  arbitrary trusted-tier source code from passing data downward.
- A kernel without mount-NS / PID-NS support degrades the
  enforcement layer to "warn and proceed" (or refuse to start,
  per operator config); the daemon never silently degrades.

---

## 12. Update cadence

This document is refreshed whenever:

- a new threat row is added (STRIDE, ATT&CK, D3FEND);
- a phase ships and moves a row from "carry-from-v1, port
  owed" to "shipped";
- a documented limitation is upgraded to a mitigation (e.g. if
  v3 confidential-VM work closes L3);
- a standards-mapping section's source spec is revised (next
  expected: ATT&CK v18, NIST CSF 2.1).

Each section ends with the source it draws from; refreshing a
section means re-pulling that source.

Last refreshed: 2026-06-18 (filed by the v2 phase-0 doc track).
