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
  succeeding a majority of the time (~74% in one cited study) on undefended
  targets.

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
- **N-word compounds**, N configurable (default 4–5). ~10^20+ combinations from
  a 100k-word list; exhaustion is a non-issue.
- **All-lowercase, concatenated, no separators**
  (`antiquebifurcatedsableanionmountain`). Humans never read scrambled names
  (they're in the trusted view), so optimize the scrambled side purely to be
  hostile to tokenizers. Ambiguous segmentation (e.g. `cation` → "cat"+"ion"
  vs "cation") is a **feature**: it adds parse-entropy.
- Uniform format everywhere → attacker can't infer "high-value" vs "long-tail"
  from name shape.

## 6. What gets scrambled (tiered by attacker value)

| Target | Value | Tier |
|---|---|---|
| Credential stores: `~/.aws`, `~/.ssh/id_*`, `~/.netrc`, browser cookie jars, password DBs | 🔥 | must |
| Env-var **names**: `AWS_*`, `GITHUB_TOKEN`, `*_API_KEY`, `*_SECRET` | 🔥 | must |
| Binary **identity**: name + `--help` + `strings` + `ldd` fingerprint | high | must (see D2 threat) |
| `$PATH` binaries (`curl`, `ssh`, `nc`, `python`, `bash`, …) | high | should |
| Standard system paths (`/etc/passwd`, `/proc/*/environ`) | high | v2 |
| Shell builtins | low | skip (very high breakage) |

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

The vault is built once; tiers are interchangeable KEK sources. Users can
upgrade tiers without re-scrambling. Hard rate-limiting on unlock attempts.

## 8. Enforcement tiers (match to threat model; always state which is active)

| Tier | Mechanism | Bypass resistance |
|---|---|---|
| Best-effort | LD_PRELOAD shim (`open`/`execve`/`readdir`/`getenv`) | bypassed by raw syscalls / static bins; macOS/cross-platform fallback |
| Strong | mount + PID namespaces + seccomp-bpf | kernel-enforced; raw syscalls resolve to scrambled inode/ENOENT |
| Hardened (v2) | eBPF-LSM (`file_open`/`bprm_check`) | gates at LSM hook; survives namespace escapes |

Linux v1 ships **Strong**. LD_PRELOAD is the labeled-weak portable fallback.

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
- **Package managers:** run in an audited maintenance namespace on real names;
  a post-install hook assigns mappings to new binaries inside the transaction.
- **EDR / observability agents:** trusted tier with explicit cross-`/proc`
  grant.

## 10. Known-weak / known-open (record before building)

- **Soft-tier + LD_PRELOAD** is the real-world weak config → honest copy.
- **Install-window race:** binary on disk vs mapping assignment. Mitigation:
  hook runs inside the package transaction; new binary invisible to untrusted
  namespaces until commit. Design carefully in M3.
- **Backup/restore with old mappings** needs a mapping-aware restore path.
- **Fingerprint obfuscation** (`--help`/`strings`/`ldd`) is hard and ongoing;
  promoted to must-have by the threat model.

## 11. Milestones

1. **M1 — Sandbox demo (1 wk).** Fake root under `./sandbox/`, no system
   changes. Mapping generator + trusted-view shell + scripted attacker-sim that
   demonstrably fails. Passphrase unlock. Demoable.
2. **M2 — Vault + unlock tiers (1 wk).** Encrypted mapping, TPM + FIDO2 + USB +
   password backends, idle timeout, rotation.
3. **M3 — Mount-namespace integration on Linux (2–3 wk).** Real `/usr/bin`, PAM
   hook, install-window handling. Throwaway VM only.
4. **M4 — Credential vault (2 wk).** Path-gated `~/.aws`, `~/.ssh`, browser
   jars; per-app trusted shims.
5. **M5 — Enterprise console + escrow (2 wk).**
6. **M6 — Packaging:** USB installer, MDM integration.

## 12. Open questions

- Prior-art sweep: **Moving Target Defense** against automated/LLM attackers
  specifically (also n-variant/diversity systems, deception tech). Run as a
  deep-research pass before M1.
- v1 target OS: Linux (enterprise server) vs macOS (endpoint laptop). Mount
  namespaces are Linux; macOS needs Endpoint Security framework; Windows needs
  minifilter drivers.
- Rotation interaction with system snapshots/VM images.
