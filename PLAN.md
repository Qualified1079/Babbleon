# Babbleon — Design Plan

> Per-host randomized obfuscation of the system namespace to defeat automated
> (LLM-driven) attackers, while remaining invisible to legitimate human users.

## 1. The idea in one line

Rename everything an attacker's priors depend on — binaries, paths, env-var
names, credential locations — to per-host-random, semantically-poisoned tokens.
Legitimate humans operate in a **trusted view** where everything looks normal.
Untrusted/headless processes (where a payload lives) see scrambled garbage.

## 2. Threat model (current)

Not a dumb worm. The realistic adversary, per the agentic-exploitation
literature, is:

- A **small-to-mid LLM** running inside a **good harness** with a
  **well-indexed library of exploits**.
- It **reasons** about which exploit to deploy and **adapts** it to the target.
- It can run shell commands, read permitted files, make raw syscalls, persist a
  process, and run patiently (e.g. while the machine is idle/asleep).
- Reported capability in the literature: autonomous privilege escalation
  succeeding **97.5%** of the time (Fang et al. 2024, one-day CVEs) on
  undefended targets. Automated recon tools (RapidPen) price a full host
  compromise at **~$0.30**. Average exfiltrated credential yield: **87
  secrets/device** (SpyCloud 2024). Babbleon's naming obfuscation raises
  the token cost of a directory-listing recon pass by **2–3×** (BPE
  tokenizer hostility — see §5).

It cannot (assumed): break crypto, sustain long novel reasoning without a
harness, or ship bespoke kernel 0-days.

**Goals (attacker), in priority order:** exfiltrate credentials for lateral
movement → establish persistence → propagate.

### What this threat model forces

1. **Renaming alone is insufficient.** A good harness fingerprints by behavior
   (`--help`, `strings`, `ldd`, magic bytes), not by name. Binary-identity
   obfuscation is therefore **load-bearing**, not a cheap extra.
2. **The attacker will detect scrambling and rebuild its index by probing.**
   This is a race between its probing speed and our **rotation** cadence.
   Probing is loud → high IDS signal.

## 2a. Adversarial assumption: Babbleon is public knowledge

Design discipline: **assume the attacker has read the Babbleon source, knows
the wordlist, knows the rotation cadence, knows the architecture, and knows
it is running on this host.** Kerckhoffs's principle: the algorithm is
public, the **per-host mapping is the only secret**. Concrete consequences:

1. **Binary-identity obfuscation is the actual battlefield, not a nice-to-have.**
   A public-knowledge attacker won't try `curl` blindly — they will
   fingerprint every binary in `$PATH` by `--help`, `strings`, `ldd`, magic
   bytes, behavior. If a scrambled binary returns curl's help verbatim, the
   rename is theater. Architecture (M3 baseline / M3.5 deception):
   - **M3 baseline:** thin **banner-spoofing wrapper** around each scrambled
     binary; heavily stripped; `--help` returns null/empty output; `strings`
     reveals no identifiable symbols; per-host random padding bytes defeat
     hash-based identification (ObserverWard / Wappalyzer / WhatWeb databases).
   - **M3.5 deception:** wrapper returns *plausible-wrong* output — e.g. the
     `curl`-scrambled binary returns `nano`'s help text. Promotes fingerprint
     probing from "learns nothing" to "actively misleads the harness."
   - Adversarial test against ObserverWard/WhatWeb signature DBs before ship.
   Promoted to M3-critical.

2. **The trusted-view boundary becomes the prize.** A public-knowledge
   attacker skips the scrambled view and attacks tier escalation. Defenses:
   namespaces inherited at fork (no `setns()` without `CAP_SYS_ADMIN`);
   seccomp denies `ptrace` to untrusted processes; `yama.ptrace_scope=2`;
   `no_new_privs`; untrusted-view binaries cannot be `exec`'d from the
   trusted view by absolute path without explicit allow-list.

3. **Rotation is load-bearing, not optional.** Public-knowledge means slow
   accumulation attacks (probe-and-exfiltrate over weeks). Default cadence
   drops to **daily**; weekly is the "low-paranoia" setting.

4. **Vault must be unforgeable to an on-host attacker.** Honest tier copy:
   - **Soft:** "raises cost of automated theft; not a defense against
     persistent code execution."
   - **TPM-sealed:** key released only to measured boot states; never leaves
     TPM in usable form except in-memory during use.
   - **FIDO2:** strongest; requires physical key + tap.
   Standard authenticated encryption (libsodium / age). No clever crypto.

5. **Honey-mappings (free IDS).** Seed the mapping with ~50 tripwire names
   that look like plausible scrambled binaries but legitimately map to
   nothing. Any process invoking one of them = 100%-confidence hostile, with
   process attribution. Detection scales with attacker probing.

6. **Side-channel budget.** Public-knowledge attacker may attempt timing
   attacks on resolution, filesystem-metadata leaks (inodes, mtimes),
   `/proc/self/maps`. These must be *named and bounded* in the design even
   if v1 doesn't close all of them.

7. **New explicit threat class: the studious attacker.** Read the source,
   has the wordlist, has hijacked an untrusted user-mode process, willing to
   probe for weeks. Babbleon's answers: (a) rotation outpaces accumulation,
   (b) honey-mappings catch probing, (c) tier boundary prevents escalation,
   (d) vault holds. If any of these fail, Babbleon does not stop this
   attacker — and we say so.

## 2b. Scope vs. the anti-LLM bundle

Babbleon is **one component** of a planned anti-LLM defense suite that will
also include: honeypot files using canonical naming conventions, prompt-
injection bait in `passwords.txt`-style files, and other LLM-specific
deception layers. These are explicitly **out of scope for Babbleon itself**
and must not be pulled into its codebase or threat model. Babbleon does one
thing — per-host randomized namespace obfuscation with trusted-view/untrusted-
view separation and rotation — and ships independently. Bundle integration
is a packaging concern, not an architecture concern.

## 3. Non-goals / honest limits

- Not a replacement for sandboxing, seccomp, least-privilege, or egress control.
  Babbleon is a **complementary layer** that degrades automated attackers.
- The **soft-unlock + LD_PRELOAD** configuration (likely the 99%-home-user
  default) is the realistically weak combination. User-facing copy must say
  "raises the cost of automated credential theft," **not** "stops attackers."
- This is **not** security-through-obscurity in the bad sense. The algorithm is
  open-source; the **per-host mapping is the key** (Kerckhoffs). Cf. ASLR:
  randomization-as-defense is established good practice.

## 4. Core architectural decisions (load-bearing)

### D1 — Scramble the *view*, not the disk
Never `mv` real files. Present different filesystem/namespace **views** per
process trust tier (kernel-enforced). This single decision enables:
- **Usability:** package managers operate on real names; updates don't fight us.
- **Enforcement:** kernel-level resolution can't be bypassed by raw syscalls
  (unlike LD_PRELOAD).
- **Cheap rotation:** re-randomizing is an atomic table swap; nothing moves.
- **TOCTOU safety:** rotation changes *names*, never *inodes*; open FDs and
  cached inode refs are unaffected — only by-name lookups see the new mapping.

### D2 — Rotate the view on a cadence
- Default ~weekly; enterprise dialable to daily; event-triggered (failed
  unlocks, anomalous probing, manual panic-rotate).
- Expires any mapping fragment an attacker exfiltrated; defeats slow/patient
  attacks and index-rebuilding.
- **Rotation cadence scales inversely with unlock-tier strength** — weaker
  unlock rotates faster.
- **Detection bonus:** a process probing for *last rotation's* names is almost
  certainly hostile (no legit program remembers them). Free high-signal IDS.

### D3 — Per-host random mapping is the secret
- Mapping drawn from a per-host CSPRNG seed stored only in the vault.
- No global ordering, no deterministic salt from hostname/MAC, no shipped
  defaults. Two hosts sharing any mapping entry = bug.

## 5. Naming scheme (decided)

- **Pure, unbiased dictionary.** Uniform random draw from a large wordlist.
  **No curation, no weighting, tech terms included.** Rationale: mis-targeting
  is valuable output — if `curl`→a calculator, the harness fires its indexed
  curl exploit at a calculator. Biasing the list throws that benefit away.
  - **Wordlist:** dwyl/english-words (~466k entries, Unlicense); ~370k after
    lowercase a-z filter. No semantic curation.
- **N-word compounds**, N configurable (default 4–5). ~10^20+ combinations from
  a 100k-word list; exhaustion is a non-issue.
- **FPE mapping construction:** 3-round Feistel network over an N×17-bit domain;
  round function = HMAC-SHA-256(host_seed ‖ epoch, "babbleon-fpe-v1‖round‖i").
  Bijective (no collisions), fits in-memory (lookup table), epoch in HMAC gives
  free rotation without re-seeding.
- **All-lowercase, concatenated, no separators**
  (`antiquebifurcatedsableanionmountain`). Humans never read scrambled names
  (they're in the trusted view), so optimize the scrambled side purely to be
  hostile to tokenizers. Ambiguous segmentation (e.g. `cation` → "cat"+"ion"
  vs "cation") is a **feature**: it adds parse-entropy. Measured 2–3× token
  inflation on directory-listing recon (GPT-4o BPE).
- **v2 wordlist filter (post-construction):** reject candidates that score in the
  high-density tail of the BPE token distribution; prefer ambiguous mid-tail
  tokens. Do **not** curate semantically — filter only on tokenization density.
- Uniform format everywhere → attacker can't infer "high-value" vs "long-tail"
  from name shape.

## 6. What gets scrambled (tiered by attacker value)

| Target | Value | Tier |
|---|---|---|
| Credential stores: `~/.aws`, `~/.ssh/id_*`, `~/.netrc`, browser cookie jars, password DBs | 🔥 | must |
| Env-var **names**: `AWS_*`, `GITHUB_TOKEN`, `*_API_KEY`, `*_SECRET` | 🔥 | must |
| Binary **identity**: name + `--help` + `strings` + `ldd` fingerprint | high | must (see §2a-1) |
| `$PATH` binaries (`curl`, `ssh`, `nc`, `python`, `bash`, …) | high | should |
| Standard system paths (`/etc/passwd`, `/proc/*/environ`) | high | v2 |
| IPC sockets: `SSH_AUTH_SOCK`, `gpg-agent`, `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR` | high | M4 |
| Shell builtins | low | skip (very high breakage) |

**M3 credential inventory (14-tool starting set, path-gating sufficient):**

| Tool | Env-var override | Credential path |
|---|---|---|
| AWS CLI | `AWS_SHARED_CREDENTIALS_FILE` | `~/.aws/credentials` |
| GitHub CLI | `GH_CONFIG_DIR` | `~/.config/gh/hosts.yml` |
| git | `GIT_CONFIG_GLOBAL` | `~/.gitconfig` |
| SSH | `SSH_AUTH_SOCK` | `~/.ssh/id_*` |
| Docker | `DOCKER_CONFIG` | `~/.docker/config.json` |
| kubectl | `KUBECONFIG` | `~/.kube/config` |
| npm | `NPM_CONFIG_USERCONFIG` | `~/.npmrc` |
| pip | `PIP_CONFIG_FILE` | `~/.config/pip/pip.conf` |
| Terraform | `TF_CLI_ARGS` | `~/.terraform.d/credentials.tfrc.json` |
| Vault (HashiCorp) | `VAULT_TOKEN` | env only |
| GCP `gcloud` | `CLOUDSDK_CONFIG` | `~/.config/gcloud/` |
| Azure CLI | `AZURE_CONFIG_DIR` | `~/.azure/accessTokens.json` |
| Stripe CLI | `STRIPE_API_KEY` | env only |
| Heroku CLI | `HEROKU_API_KEY` | `~/.netrc` |

**Dominant attacker env-var pattern:** wildcard-suffix scrape —
`*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`, `*_API_KEY`, `*_CREDENTIALS`.
Path-gating alone blocks this without any format parsing.

Credential stores use **path-gating, not format-parsing**: the file lives
encrypted in the vault; only the owning trusted-tier app gets a real view of its
profile dir. This sidesteps Chrome cookie-format churn and generalizes across
all credential types with one mechanism.

## 7. Unlock tiers (pluggable KEK backends → one vault)

| Tier | Unlock source | Audience |
|---|---|---|
| Soft | Argon2id(password) / OS keychain | solo users |
| Soft+ | **TPM-sealed** (no dongle to buy/lose) | default for most laptops |
| Portable | keyfile on any USB stick (± password = 2FA) | prosumer/SMB |
| Hardware | FIDO2 hmac-secret / external token | enterprise/high-value |

**Concrete primitives (decided):**

- **Vault format:** `age` (age-encryption.org); KEK wraps the age identity;
  epoch field in header for rotation tracking. Upgrade tier = re-wrap KEK only;
  payload never re-encrypted.
- **Soft:** Argon2id, m=46 MiB, t=2, p=1; parameters stored in vault header.
  Tradeoff: 46 MiB too large for memory-constrained IoT; acceptable for laptop.
- **Soft+ (TPM2):** tpm2-tss library; seal against PCRs covering kernel cmdline
  + initrd (PCRs 4, 8, 9) **in addition to** PCR7 (Secure Boot). PCR7-only is
  bypassed by the oddlama technique (custom initrd with manipulated PCR7 only).
  Authorized policies enable post-update re-seal without re-enrollment.
- **Hardware (FIDO2):** CTAP2 `hmac-secret` extension via libfido2;
  `HMAC-SHA-256(credential_secret, salt)` where salt is stored on disk; derived
  key never leaves the token. Requires physical tap per unlock.
- **Reference architecture:** mirrors systemd-cryptenroll's pluggable-backend
  pattern for the KEK layer.
- **Rate limiting:** hard limit on unlock attempts; exponential backoff written
  to vault header (tamper-evident).

The vault is built once; tiers are interchangeable KEK sources. Users can
upgrade tiers without re-scrambling.

## 8. Enforcement tiers (match to threat model; always state which is active)

| Tier | Mechanism | Bypass resistance |
|---|---|---|
| Best-effort | LD_PRELOAD shim (`open`/`execve`/`readdir`/`getenv`) | bypassed by raw syscalls / static bins; macOS/cross-platform fallback |
| Strong | mount namespaces (CLONE_NEWNS) + bind mounts + seccomp-bpf | kernel-enforced; raw syscalls resolve to scrambled inode/ENOENT |
| Landlock + eBPF-LSM (v2) | Landlock LSM (per-process self-sandbox) + eBPF-LSM hooks | layered: Landlock contains per-process; eBPF-LSM is host-wide IDS + escape-resistant catch-all |

**M3 enforcement stack (decided):**

1. **Mount namespaces (CLONE_NEWNS)** — kernel-enforced per-process filesystem
   view; bind mounts preserve inode identity (D1 load-bearing). Substrate for
   the scrambled-view/trusted-view split.
2. **PID namespaces** — untrusted tier gets a wholly distinct process view;
   closes `/proc/<pid>/root` escape and `/proc/<pid>/environ` leak. PID-1 init
   required inside the namespace (tini or bespoke). `hidepid=2,gid=proc` on
   the untrusted namespace's `/proc` mount.
3. **Yama `ptrace_scope=2`** — system-wide; combined with seccomp additions:
   `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `pidfd_open`,
   `pidfd_getfd`, `pidfd_send_signal`.
4. **Landlock LSM** (v2, promoted to M3) — unprivileged per-process
   self-sandbox; default-on (no boot flag required); applied to untrusted tier.
5. **eBPF-LSM** (v2, `BPF_PROG_TYPE_LSM`) — `file_open` + `bprm_check_security`
   hooks with deny semantics; host-wide IDS for honey-mapping tripwires and
   escape-resistant catch-all; requires `lsm=...,bpf` kernel cmdline (kernel
   5.7+; confirmed present on 6.4 arm64).
6. **`pam_babbleon.so`** — own PAM module managing mount-namespace lifecycle at
   login (pam_namespace pattern, own config model for per-host mapping tables).

Linux v1 ships **Strong** (layers 1–3). Landlock + eBPF-LSM are v2 targets
promoted to M3 delivery. LD_PRELOAD is the labeled-weak portable fallback.

## 9. Usability surfaces (max usability is a requirement, not a nice-to-have)

- **GUI users:** invisible. Desktop session starts post-unlock in the trusted
  view; they never know Babbleon exists.
- **Terminal users:** a normal bash inside the unlocked namespace — real names,
  full completion/history. Rotation churn never reaches them (they're always
  trusted-view).
- **SSH / power users:** key present (or escrow unlock) → interactive shell in
  trusted view. No key → scrambled view, useless to a payload.
- **Scripts / cron / systemd:** default to scrambled view (safe). Admin tags
  specific units "needs real view" with justification (manifest).
- **Package managers:** run in a transient **maintenance namespace** (private
  outward propagation); hooks are per-ecosystem:
  - apt: `DPkg::Post-Invoke` (or dpkg trigger) — post-install, pre-remove
  - rpm/dnf: `%post`/`%postun` scriptlets
  - Homebrew: no native hook; shim wrapping `brew` binary (upstream issue #2202)
  - cargo/pip/npm: post-install wrapper scripts
  After the transaction commits, an atomic cross-namespace bind rebind makes new
  mappings live simultaneously; new binaries are invisible to untrusted
  namespaces until the rebind completes. This closes the install-window race
  (see §10).
- **EDR / observability agents:** trusted tier with explicit cross-`/proc`
  grant.

## 10. Known-weak / known-open (record before building)

- **Soft-tier + LD_PRELOAD** is the real-world weak config → honest copy.
- **Install-window race:** ~~Design carefully in M3~~ → **Closed.** Maintenance
  namespace with private outward propagation; new binary invisible to untrusted
  namespaces until the post-transaction atomic cross-namespace rebind. See §9.
- **Backup/restore with old mappings** needs a mapping-aware restore path;
  mapping archive must be versioned alongside the backup snapshot.
- **Fingerprint obfuscation** (`--help`/`strings`/`ldd`) is hard and ongoing;
  banner-spoofing wrapper architecture decided (§2a-1); adversarial test against
  ObserverWard/WhatWeb databases required before M3 ship.
- **IPC isolation (M4):** `SSH_AUTH_SOCK`, `gpg-agent` socket,
  `DBUS_SESSION_BUS_ADDRESS`, `XDG_RUNTIME_DIR` must not be inherited in
  untrusted tier. OverlayFS for per-app writable upper layers also M4.
- **macOS:** M5+ via FUSE + Endpoint Security Framework + Keychain/Secure
  Enclave. FUSE is acceptable for the M1 sandbox demo only (3× ext4 perf
  penalty); not in the production path.

## 11. Milestones

1. **M1 — Sandbox demo (1 wk).** Fake root under `./sandbox/`, no system
   changes. Mapping generator + trusted-view shell + scripted attacker-sim that
   demonstrably fails. Passphrase unlock. Demoable.
2. **M2 — Vault + unlock tiers (1 wk).** Encrypted mapping, TPM + FIDO2 + USB +
   password backends, idle timeout, rotation.
3. **M3 — Mount-namespace integration on Linux (2–3 wk).** Real `/usr/bin`, PAM
   hook (`pam_babbleon.so`), install-window handling (maintenance namespace +
   atomic rebind), PID namespace + `hidepid=2` inside untrusted NS, Landlock
   self-sandbox for untrusted tier, banner-spoofing wrapper (M3 baseline).
   Throwaway VM only.
4. **M4 — Credential vault (2 wk).** Path-gated `~/.aws`, `~/.ssh`, browser
   jars; per-app trusted shims.
5. **M5 — Enterprise console + escrow (2 wk).**
6. **M6 — Packaging:** USB installer, MDM integration.

## 12. Open questions

**Closed by T3–T16 research:**
- ~~Prior-art sweep~~ → done; MTD literature confirms novelty of combined
  per-host random + view-layer + rotation approach; no existing system does all
  three.
- ~~v1 target OS~~ → Linux. macOS M5+; Windows v3+ research-only.
- ~~Rotation interaction with snapshots~~ → mapping archive versioned alongside
  backup; mapping-aware restore path required (§10).
- ~~Install-window race design~~ → closed (maintenance namespace architecture).
- ~~Binary-identity solution~~ → banner-spoofing wrapper decided (§2a-1).
- ~~Wordlist source~~ → dwyl/english-words (~466k, Unlicense), ~370k after filter.
- ~~FPE vs lookup table~~ → 3-round Feistel FPE for mapping construction.
- ~~Vault crypto~~ → age format, Argon2id, libfido2 CTAP2, tpm2-tss PCR sealing.
- ~~Landlock vs eBPF-LSM distinction~~ → both; Landlock per-process, eBPF-LSM
  host-wide IDS + escape-resistant deny.
- ~~PID namespace necessity~~ → confirmed; closes /proc environ leak + ptrace
  root escape.

**Open (newly surfaced or still outstanding):**
- **M3.5 deception table scope:** how large should the plausible-wrong banner
  mapping be? Cost vs. attacker confusion benefit. Needs adversarial eval metric.
- **Argon2id parameter scaling:** 46 MiB / t=2 / p=1 tuned for laptops; need
  IoT / headless-server profile (lower m, higher t to preserve time-cost).
- **TPM authorized policy UX:** post-kernel-update re-seal workflow must be
  user-friendly; current tpm2-tools CLI is not. Explore systemd-cryptenroll UX
  as template.
- **OverlayFS per-app upper layers (M4):** architecture TBD; evaluate
  overlayfs vs bind-mount-per-app for credential isolation.
- **Rotation + snapshot interaction:** partial answer (versioned archive);
  need policy for "restore to snapshot with stale mapping" — rollback-safe
  re-seal / re-wrap procedure.
- **Honey-mapping tripwire response:** detection signal alone, or active
  response (kill process, alert, throttle)? Policy design TBD for M3.
- **Windows minifilter research:** deferred to v3; no immediate open questions.
