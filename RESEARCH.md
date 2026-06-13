# Babbleon — Research Log

Living document. Topics from `PLAN.md` §12 + the agreed research slate, worked
through one at a time. Each section records: question, method, findings,
implications for the plan, open follow-ups.

Status legend: ⬜ not started · 🟡 in progress · ✅ done · 🟥 blocked

## Tier 1 — decision-blocking

- ✅ **T1. Moving Target Defense vs LLM/automated attackers** — prior art sweep
- ✅ **T2. Agentic-exploitation capability literature** — what current LLM exploit harnesses actually do
- ✅ **T3. Per-process filesystem view mechanisms on Linux** — mount ns / OverlayFS / FUSE / pam_namespace
- ✅ **T4. eBPF-LSM maturity** for file/exec gating
- ⬜ **T5. Hardware-unlock primitives** — FIDO2 hmac-secret, TPM 2.0 sealing, OS keychains

## Tier 2 — shapes implementation

- ⬜ **T6. LLM/BPE tokenizer behavior** on lowercase concatenated compounds
- ⬜ **T7. Credential-store inventories** across modern dev/cloud tooling
- ⬜ **T8. Env-var vocabulary** attackers actually scrape
- ⬜ **T9. Package manager hook surfaces** (dpkg/rpm/brew/flatpak/snap)
- ⬜ **T10. Binary fingerprinting countermeasures**
- ⬜ **T11. `/proc` and PID-namespace gotchas**

## Tier 3 — confirm assumptions

- ⬜ **T12. CSPRNG + bijective mapping construction**
- ⬜ **T13. Wordlist sources** and licensing
- ⬜ **T14. Backup/snapshot interaction with rotation**
- ⬜ **T15. macOS / Windows feasibility scan**
- ⬜ **T16. Naming / trademark / prior-project collision check**

---

<!-- Findings appended below as each topic completes. -->

## T1 — Moving Target Defense vs LLM/automated attackers

**Question:** What's the prior art for MTD-style defenses? Has anyone done
"rename the userspace"? What's known about MTD effectiveness vs automated/LLM
attackers? How does Babbleon position relative to existing work?

**Method:** 5-angle parallel web search (taxonomy/seminal, commercial
deployments, n-variant/multi-variant, MTD-vs-LLM, critiques), 4 source fetches
of the highest-value hits. Two fetches failed (PDF binary, MDPI 403) and were
worked around with abstract-only fetches and supplementary search.

### Findings

**1. The academic field exists and is mature, but Babbleon's specific angle is not in it.**

MTD as a named field traces to **Jajodia et al., 2011** ("Moving Target
Defense: Creating Asymmetric Uncertainty for Cyber Threats") and the
NIST/NSA-funded research push of the early 2010s. Major taxonomy categories
(per multiple surveys, including Sengupta et al. 2020 in IEEE Comms Surveys &
Tutorials, and the Vanderbilt "Survey of Cyber Moving Targets, 2nd Ed."): (a)
**network MTD** (IP/port hopping, SDN-based shuffling), (b) **host MTD**
(ASLR, KASLR, stack canaries, instruction-set randomization), (c) **software
diversity** (multi-compiler, n-variant), (d) **application/data MTD**.
Farris & Cybenko polled 120 experts on 39 techniques.

The dimension Babbleon operates on — **per-host randomized renaming of the
userspace namespace (binaries, paths, env names, credential paths) with a
trusted-view/untrusted-view split and rotation** — does not appear as a named
category in any of the surveys reviewed. Closest categorical home is "host
MTD / namespace randomization," but the existing literature in that bucket is
overwhelmingly about *memory* (ASLR) and *instruction sets*, not filesystem
namespaces or environment vocabulary.

**2. The closest philosophical ancestor is N-Variant Systems (Cox et al., UVa, ~2006).**

"N-Variant Systems: A Secretless Framework for Security through Diversity."
Runs multiple diversified variants of a program in lockstep on the same
input; an attack must compromise all variants identically without causing
detectable divergence. Specifically varies (i) **address-space partitioning**
— disjoint memory layouts where addresses valid in P₀ are invalid in P₁ — and
(ii) **instruction-set tagging** — prepending variant-specific byte prefixes
so injected code lacking the tag won't execute.

The "secretless" framing is what Babbleon should explicitly adopt and cite.
N-Variant argues that *no secret needs to be kept* — the attacker can know
everything about the construction; the defense rests on the *structural*
impossibility of an exploit working on all variants simultaneously. Babbleon
is the dual: **the attacker can know everything about the construction and
the wordlist; the defense rests on the per-host random *mapping* being the
only secret** (Kerckhoffs again). Same intellectual move.

Acknowledged N-Variant weaknesses: return-to-libc bypasses instruction
tagging; indirect code injection can evade detection; nondeterminism causes
false divergences; some syscalls have to be blocked outright. *Implication for
Babbleon:* the lesson is "diversity alone never closes 100% of the attack
surface; pick what it *does* close and be honest about the rest." Renaming
won't stop return-to-libc analogs (e.g. a payload using raw syscalls); we
already plan namespaces + seccomp for that, and label LD_PRELOAD honestly as
weak.

**3. Polyverse "Polymorphic Linux" is the closest *commercial* implementation, and the public detail is thin.**

Polyverse ships **scrambled binary packages** for the Linux ecosystem — claims
to diversify "the call structure and nomenclature of all resources at compile
and runtime" across 10,000+ open-source projects, covering the stack from
GRUB → kernel → application binaries. The public marketing pitch ("guessing
the location of a single grain of sand on earth") suggests memory/symbol
layout diversification rather than literal binary-name renaming, but the
public sources don't pin down the technical mechanism. Operating in the
market since at least 2018; "significantly increased funding" as of 2020.

*Implication for Babbleon:* commercial validation that diversification at the
binary layer can be sold and deployed; the specific axis Babbleon picks
(**filesystem-namespace and credential-path randomization, not binary
internals**) appears not to be the Polyverse approach. Worth a deeper
technical dive (their GitHub `polyverse-security/*` repos) before M1 to
confirm we're not duplicating them.

**Morphisec** — the other major commercial MTD vendor — does **runtime memory
morphing** of in-memory structures on endpoints (10K+ deployments per their
own figures). Orthogonal to Babbleon: they protect running process memory; we
scramble the *naming* the attacker reaches for.

**4. MTD-vs-LLM literature exists but almost entirely treats the LLM as the *target*, not the attacker.**

Recent (2023–2025) work: "Jailbreaker in Jail: Moving Target Defense for
Large Language Models" (ACM MTD Workshop 2023), "FlexLLM: Exploring LLM
Customization for Moving Target Defense on Black-Box LLMs Against Jailbreak
Attacks" (Dec 2024, arXiv 2412.07672), "Dynamic Moving Target Defense for
Mitigating Targeted LLM Prompt Injection" (TechRxiv). All are about
*defending an LLM service from prompt injection / jailbreak* by varying
decoding parameters, system prompts, or model snapshots.

**MTD-vs-LLM-as-attacker is a near-empty niche.** I found no paper directly
evaluating an MTD against an autonomous LLM exploit harness on a host. This
is a real gap and a real opportunity — also a hint that the academic case
needs to be made from first principles, not by citation.

**5. Autonomous LLM exploit harnesses are real, and they depend on canonical names.**

Surveyed agents/frameworks (PentestAgent at AsiaCCS 2025, CurriculumPT,
AutoPen, METATRON, EniGMA, HackSynth, D-CIPHER, CRAKEN — 39+ open-source AI
pentesting projects as of 2026): they autonomously chain **`nmap`, `nikto`,
`whatweb`, `curl`, `whois`, `dig`, Metasploit modules**. The agent reasons
*about* the target but operationally drives **canonical CLI tools by their
canonical names producing their canonical output**.

This is the empirical validation of Babbleon's bet: **the entire current
generation of agentic exploit harnesses operates one layer above the binary
namespace, treating `nmap` and `curl` as primitives**. Scramble the
primitives and the harness's planning layer is reasoning over symbols that
don't resolve. The harness can recover by re-fingerprinting, but
*re-fingerprinting at scale across rotation cycles is itself the speed-bump
we want to impose*.

**6. The standard critiques of MTD are real and apply to us.**

From the critique literature (Wiley 2018 survey; MDPI 2023 "Intelligently
Affordable" survey; multiple comparison studies):

- **"Attacker just learns the new mapping."** Defeated by per-host
  randomization + rotation. Static MTD is the weak version; rotating MTD with
  high-quality randomness is the answer. *Babbleon: addressed by design.*
- **Randomness quality matters.** Deterministic shuffles get learned.
  *Babbleon: CSPRNG-seeded per-host, mandated in PLAN.md.*
- **Scalability and legacy-compatibility.** Network MTD often breaks
  unmodified clients. *Babbleon's view-not-mutation architecture is the
  answer to this critique on the host side.*
- **Service-availability degradation.** Some MTDs cause downtime on
  reconfiguration. *Babbleon: rotation is an atomic table swap; open FDs
  unaffected; cost near-zero.*
- **Operational cost to defenders.** Real and ongoing. *Babbleon: GUI users
  invisible; power users in the trusted view never see scrambled names; cost
  concentrates in the maintenance-namespace + package-manager hook.*

**7. Has anyone built exactly Babbleon? No, but the building blocks all exist.**

No system in the surveyed literature combines: (a) filesystem-namespace
renaming, (b) per-host randomized mapping, (c) credential-path scrambling,
(d) trusted-view/untrusted-view split per process tier, (e) rotation, (f)
specifically motivated by LLM exploit harnesses. Individually:

- Filesystem namespace separation: standard Linux primitive (mount
  namespaces), used by containers, not as randomization-as-defense.
- Per-host symbol randomization: Polyverse, but at the binary-internals
  layer, not filesystem.
- Credential vaulting: gnome-keyring, macOS Keychain, sealed-storage with
  TPM. None of these scramble *paths* or present a trust-tiered view.
- Trusted-view/untrusted-view: closest analog is **container/sandbox
  isolation** and **deception-tech honeypot environments** (Cymmetria,
  Illusive Networks), but those create *fake* environments for attackers,
  not scrambled *real* ones.
- Rotation: standard MTD principle.

**Deception tech (honeypots, honey-tokens, honey-files) is adjacent but
distinct.** Deception adds *fake* assets to detect attackers; Babbleon
*renames real* assets to disrupt them. The closest hybrid is "honey-mappings"
— a v2 idea: include a small number of bait-only scrambled names that, if
ever invoked by any process, are 100%-signal IDS triggers.

### Implications for the plan

1. **Reposition framing in the README and any future paper.** Babbleon is
   *secretless host-namespace MTD* in the N-Variant tradition; the mapping is
   the key (Kerckhoffs); the motivation is the agentic-harness threat model
   that's emerged 2023–2026. This framing is publishable.
2. **Cite N-Variant explicitly.** It's the intellectual ancestor and
   pre-empts the "but isn't this just security through obscurity?" objection.
3. **Polyverse deeper dive needed before M1.** Confirm we are not duplicating
   their approach. Read their public repos. If we're complementary
   (filesystem namespace vs binary internals), say so; if there's overlap,
   reposition.
4. **Honest acknowledgment of the agentic-pentest gap.** No prior MTD work
   has been evaluated against an LLM exploit harness. We should plan to *be*
   the first such evaluation — running METATRON / PentestAgent against a
   Babbleon'd VM is itself a defensible research contribution.
5. **The "harness depends on canonical names" finding is the lede.** Anchor
   the threat model on it; it's empirical and current.
6. **Honey-mapping bait names** — add as v2 idea, derived from
   deception-tech adjacency.

### Confidence

- **High:** existence and shape of the MTD academic field, N-Variant as
  closest philosophical ancestor, current LLM-pentest agents depending on
  canonical CLI tool names, MTD-vs-LLM-attacker being an unfilled niche.
- **Medium:** Polyverse's exact mechanism (marketing-thin public sources;
  needs code dive).
- **Medium:** whether any unsurveyed industry product (defense-contractor,
  classified, or quiet startup) has built something Babbleon-shaped. Worth
  asking specifically in T16 (naming/prior-project check).

### Open follow-ups

- Read Polyverse's GitHub repos directly (T1-followup).
- Find the Sengupta et al. 2020 IEEE survey full text and map Babbleon
  precisely onto their taxonomy (T1-followup).
- "Survey of Cyber Moving Targets 2nd Ed." (Vanderbilt) — fetch the readable
  version, not the binary PDF, for the canonical taxonomy.

### Sources

- Cox et al., "N-Variant Systems" — https://www.cs.virginia.edu/~evans/pubs/nvariant/html/nvariant.html
- Polyverse Polymorphic Linux (Intellyx coverage) —
  https://intellyx.com/2020/10/13/polyverse-polymorphic-protection-from-bootloader-to-application-binaries/
- "Forewarned is Forearmed: A Survey on LLM-based Agents in Autonomous
  Cyberattacks" (arXiv 2505.12786) — https://arxiv.org/abs/2505.12786
- "Toward Proactive, Adaptive Defense: A Survey on MTD" (arXiv 1909.08092) —
  https://arxiv.org/pdf/1909.08092
- Survey on MTD for Networks: A Practical View (MDPI 2022) —
  https://www.mdpi.com/2079-9292/11/18/2886
- Jailbreaker in Jail: MTD for LLMs (ACM MTD Workshop) —
  https://dl.acm.org/doi/10.1145/3605760.3623764
- FlexLLM (arXiv 2412.07672) — https://arxiv.org/abs/2412.07672
- METATRON / autonomous pentesting tooling overview —
  https://cybersecuritynews.com/metatron-ai-penetration-testing/
- PentestAgent (arXiv 2411.05185) — https://arxiv.org/pdf/2411.05185
- AI Pentesting Agents 2026 landscape —
  https://appsecsanta.com/research/ai-pentesting-agents-2026
- Morphisec product overview — https://www.gartner.com/reviews/product/morphisec
- Polyverse product page — https://info.polyverse.io/free-tier

---

## T2 — Agentic-exploitation capability literature

**Question:** What can current LLM-driven exploit harnesses actually do?
What's the empirical state of capability? What's the cited "74%" number? What
tools do they use, and where does Babbleon hit hardest?

**Method:** 5-angle parallel search across the priv-esc literature, the
named frameworks (HackSynth, METATRON, PentestAgent, RapidPen, Hexstrike-AI),
CTF benchmarks, and 2026 capability surveys.

### Findings

**1. The capability numbers are higher than I had stated, and rising fast.**

- **Happe et al., "LLMs as Hackers: Autonomous Linux Privilege Escalation
  Attacks"** (arXiv 2310.11409, accepted Empirical Software Engineering
  2025). GPT-4-Turbo solves **33–83%** of Linux priv-esc scenarios depending
  on guidance level; comparable to human pentesters at ~75%.
- **Follow-on work (early 2026, arXiv 2603.17673 / 2604.27143)**: RL-tuned
  *local* LLM agents reach **95.8%** on a 12-scenario priv-esc benchmark;
  Claude Opus 4.6 reaches **97.5%** on the same benchmark.
- **"LLM Agents can Autonomously Hack Websites"** (arXiv 2402.06664): top
  agents succeed on **73.3%** of tested web vulnerabilities **with no prior
  knowledge of the vulnerability**. *This is almost certainly the source of
  the "~74%" figure I had in mind.*
- **RapidPen (Feb 2025)**: **IP-to-shell access in 200–400 seconds at
  $0.30–$0.60 per run**. This is the economics number that matters — the
  attack is cheap and fast enough that mass-targeting is viable.
- **CTF leaderboards**: GPT-5.3 Codex at **77.6%** on the public
  cybersecurity-CTFs board; Claude Haiku 4.5 at 46.9%; on NYU CTF Bench
  GPT-4.1 averages 16.94% (the gap reflects benchmark difficulty more than
  model regression).
- **CTFAgent**: 88% autonomous, 94% with a human-in-the-loop.
- **Hadrian.io survey**: **70+ new offensive-security AI tools shipped in
  18 months** (mid-2024 → end-2025). The Cambrian explosion is real.

**2. Real-world deployment is happening, not hypothetical.**
The Hacker News (May 2026) reported attackers using an LLM agent for
**post-exploitation activity following CVE-2026-39987** (Marimo). Commands
were structured for machine consumption, separated by `---` delimiters. This
is the first widely-reported in-the-wild LLM-as-attacker incident I can
confirm. **Check Point's coverage of Hexstrike-AI** describes it driving
real-world zero-day exploitation.

**3. The capability distribution validates Babbleon's targeting precisely.**

From the Hadrian.io 2026 survey, this paragraph is *the* result for us:

> "AI offensive capability is concentrated at the **front end**, degrades
> through the middle, and is effectively absent at the back of the attack
> chain. Reconnaissance is the strongest phase, with some frameworks
> achieving **100% task completion** on vulnerability analysis and
> intelligence gathering, while major frameworks like AutoPentester,
> RapidPen, Excalibur, and xOffense achieve near-ceiling performance on
> scanning and enumeration."

**This is the lede for any future Babbleon write-up.** The strongest phase
of the LLM attacker is the recon phase, and recon is the phase that operates
by invoking canonical tools (`nmap`, `curl`, `whatweb`, `nikto`, `dig`,
`whois`) on canonical targets and parsing their canonical output. Babbleon's
entire mechanism — scramble the names, scramble the help/strings output,
scramble the paths — directly degrades the phase the attacker is best at.

Compounding error rates help us too: top frontier models (GPT-5, Claude
Opus 4.6) hit **60–75% on complex multi-step agentic tasks** (WebArena,
OSWorld), but per-tool-call error rates of **5–15% compound rapidly** across
20-step chains. Every additional fingerprinting step we force on the attacker
multiplies that error tax.

**4. The tools the frameworks chain are exactly the ones Babbleon scrambles.**

Documented in the surveyed frameworks: `nmap`, `nikto`, `whatweb`, `curl`,
`whois`, `dig`, **Metasploit modules**, **ObserverWard** (web-app
fingerprint DB), RAG-augmented recon over public fingerprint databases.
Hexstrike-AI is described as starting with Nmap and "extending to dozens of
other reconnaissance, exploitation, and persistence modules."

Two implications worth recording:

- **The fingerprint databases (ObserverWard et al.) index targets by output
  signatures.** Babbleon's binary-identity obfuscation (M3-critical per
  PLAN.md §2a) must specifically disrupt these signatures — strip them,
  replace them, gate them by trust tier.
- **The agents are RAG-augmented**, so they can pull in the right exploit
  for a recognized signature mid-run. If we let the binary-identity
  fingerprint leak, the RAG attacker re-identifies in one query and runs
  exploits adapted from a knowledge base. Confirms: the rename is theater
  unless the fingerprint is also obfuscated.

**5. Babbleon's failure modes per the capability literature.**

Honest accounting of what these agents *can* do that Babbleon does *not*
stop:

- **Compiled exploits / shellcode** that don't depend on canonical tool
  invocation — they call raw syscalls. Babbleon's namespaces + seccomp tier
  catches some; static binaries calling `int 0x80` slip through LD_PRELOAD
  fully and need eBPF-LSM to gate.
- **Network-side exploits** that never touch the local filesystem (e.g.,
  exploit a service over the wire and pop a remote shell). Babbleon protects
  the *host*; it does nothing for vulnerable services it fronts.
- **Already-trusted-tier compromise:** if the attacker pivots into the
  user's interactive shell, they get the real view. The tier boundary in
  PLAN.md §2a-2 is the answer, but it's the answer to a hard problem.
- **Sandbox escape** (arXiv 2603.02277, "Quantifying Frontier LLM
  Capabilities for Container Sandbox Escape") is improving. If the
  attacker's process can escape its containing namespace into the trusted
  one, Babbleon is bypassed. v2 hardening (eBPF-LSM) is the answer.

**6. Defense-side prior art: prompt-injection-as-defense.**

"Hacking Back the AI-Hacker: Prompt Injection as a Defense Against
LLM-driven Cyberattacks" (arXiv 2410.20911) — files on disk contain
adversarial prompts designed to derail an attacker LLM that ingests them.
**This is exactly the "anti-LLM bundle" companion** to Babbleon that PLAN.md
§2b mentions (prompt-injected `passwords.txt` style files). Worth keeping in
view as a sibling project; it stacks cleanly with Babbleon.

### Implications for the plan

1. **Bull case is empirically grounded.** "Recon is the strongest LLM-attack
   phase (100% on multiple benchmarks); recon is exactly what Babbleon
   degrades." Put this in the README. Cite Hadrian 2026.
2. **Refine PLAN.md §2 (threat model) with real numbers.** Replace the "74%
   in one cited study" prose with: 33–83% (GPT-4-Turbo, Happe), 97.5%
   (Claude Opus 4.6, RL-tuned), 73.3% (autonomous web hacking), real-world
   deployment confirmed (CVE-2026-39987 Marimo post-exploit). Update next
   plan revision.
3. **Binary-identity obfuscation must specifically defeat fingerprint
   databases.** Not just `--help`/`strings` scrubbing — the *response
   patterns* the databases index on. M3 design needs to look at ObserverWard
   schema specifically.
4. **Multi-step error compounding is a defense multiplier.** Adding even
   small additional fingerprinting steps to the attacker's chain
   (rotation-aware probing, honey-mapping confusion) multiplies into large
   end-to-end failure rates. This is mechanistic evidence for honey-mappings
   from PLAN.md §2a-5.
5. **RapidPen economics are the marketing line.** "$0.30 per IP-to-shell"
   is the number that makes mass automated attack viable; Babbleon is the
   defense that raises the per-target cost back up.
6. **Sandbox-escape arms race is a real M5+ concern.** Not a v1 worry, but
   record that as LLM-driven escape research improves, eBPF-LSM moves up
   the priority queue.

### Confidence

- **High:** the capability percentages and the recon-is-strongest finding —
  multiple independent benchmarks agreeing.
- **High:** the tool-chain (nmap, nikto, whatweb, curl, Metasploit) — named
  explicitly across multiple framework papers.
- **Medium:** the Marimo in-the-wild incident — one report; worth a deeper
  read in T2-followup.
- **Medium:** how fast capability is moving. The 33% → 97.5% jump in ~2
  years (priv-esc) suggests the threat surface evolves faster than our
  release cadence; rotation cadence and v2 hardening planning must assume
  that the 2027 attacker is materially stronger than the 2026 one.

### Open follow-ups

- Fetch the CSA whitepaper "Automated Exploit Generation: LLMs Cross the
  Threshold" — likely has the cleanest defender-perspective summary.
- Read the Marimo CVE-2026-39987 incident report end-to-end.
- Examine ObserverWard's fingerprint schema in detail (M3 design input).

### Sources

- Happe et al., "LLMs as Hackers" — https://arxiv.org/abs/2310.11409
- RL priv-esc local LLMs — https://arxiv.org/html/2603.17673v1
- "LLM Agents can Autonomously Hack Websites" — https://arxiv.org/pdf/2402.06664
- HackSynth — https://arxiv.org/abs/2412.01778
- METATRON coverage — https://cybersecuritynews.com/metatron-ai-penetration-testing/
- PentestAgent (AsiaCCS 2025) — https://arxiv.org/pdf/2411.05185
- Hexstrike-AI in real-world zero-days — https://blog.checkpoint.com/executive-insights/hexstrike-ai-when-llms-meet-zero-day-exploitation/
- Marimo CVE-2026-39987 post-exploit incident — https://thehackernews.com/2026/05/attackers-use-llm-agent-for-post.html
- CTF leaderboard — https://llm-stats.com/benchmarks/cybersecurity-ctfs
- CTFAgent — https://www.sciencedirect.com/science/article/abs/pii/S2214212625003424
- Hadrian.io 70-tools survey — https://hadrian.io/blog/the-ai-offensive-security-boom-seventy-tools-in-eighteen-months
- Container sandbox escape (arXiv 2603.02277) — https://arxiv.org/pdf/2603.02277
- Prompt-injection-as-defense — https://arxiv.org/pdf/2410.20911
- CSA whitepaper (LLM exploit automation) — https://labs.cloudsecurityalliance.org/research/csa-whitepaper-llm-exploit-automation-threat-landscape-20260/

---

## T3 — Per-process filesystem view mechanisms on Linux

**Question:** What kernel primitives let us present different filesystem
views to different processes on the same host? Which is the right substrate
for Babbleon's M3 (mount-namespace integration)? What are the bypass paths
and operational costs of each?

**Method:** 5-angle parallel web search across mount namespaces, OverlayFS,
FUSE performance, `pam_namespace` polyinstantiation, and `setns`/escape
semantics. Cross-referenced against PLAN.md D1 (scramble the view, not the
disk) and §8 (enforcement tiers).

### Candidate mechanisms

**1. Mount namespaces (`CLONE_NEWNS`) — the load-bearing primitive.**

Created via `clone(2)` or `unshare(2)` with `CLONE_NEWNS`. Each namespace
holds its own mount-point list; the new namespace is initialized as a
*copy* of the caller's mount list at creation time, and subsequent mounts
are (by default propagation) visible only inside the namespace. `/proc/pid/
mounts`, `/proc/pid/mountinfo`, `/proc/pid/mountstats` reflect the
namespace the named PID lives in.

This is the right substrate for Babbleon. Properties that matter:

- **Kernel-enforced.** Path resolution happens in the kernel against the
  per-namespace mount table; raw syscalls (`openat`, `execve`) cannot
  bypass it the way they bypass LD_PRELOAD.
- **Inherited at fork/exec.** A scrambled-tier process spawning a child
  cannot give the child a different view without `setns()`, which itself
  requires `CAP_SYS_ADMIN` *in the user namespace owning the target mount
  namespace* (post-Lutomirski hardening). That gate is exactly the tier
  boundary PLAN.md §2a-2 prescribes.
- **Propagation modes (shared / private / slave / unbindable)** govern
  whether mount events cross namespace boundaries. Babbleon's mappings
  must mount **private or slave** in the untrusted view so the trusted
  view's real mounts don't leak in, and so untrusted-view mount events
  cannot influence the trusted view.

**2. `pam_namespace` + `namespace.conf` — the polyinstantiation precedent.**

`pam_namespace.so` is the existing, supported PAM module that creates a
per-session mount namespace at login and bind-mounts instance directories
into it. `/etc/security/namespace.conf` syntax: `polydir instance_prefix
method list_of_uids`. RHEL has shipped polyinstantiated `/tmp` and
`/var/tmp` against it for years; SELinux ties an instance to user +
security context.

This is *exactly* the architectural shape Babbleon needs at session-
unlock time: PAM hook → create namespace → populate with trusted-view
binds → execute the user's shell inside it. We can ship a `pam_babbleon.so`
that does the same lifecycle, or piggyback on `pam_namespace` and supply
the polyinstantiation method as an external helper. **Recommendation:
ship our own PAM module.** `pam_namespace`'s config language is too
restricted (path-list with per-uid filter) for the per-host mapping table
Babbleon needs, and reusing it would force us to round-trip the mapping
through a text file at every login.

PAM hook is the right *integration point*, not the right *implementation*.

**3. OverlayFS — the mechanism for materializing the trusted view.**

Layered union mount: `lowerdir` (read-only, possibly many, colon-
separated), `upperdir` (writable), `workdir` (private scratch), `merged`
(the unified result). Copy-on-write on first write into a lower file.
Mature, in-tree, used by every Docker install on Earth.

For Babbleon, OverlayFS is the natural way to build a *trusted view* from
the real system: `lowerdir=/` plus per-app `upperdir`s for credential
profile dirs. The *untrusted view* is the simpler case — it's the
unmodified real filesystem with the scramble layer applied via bind
mounts on top of `/usr/bin`, `/etc`, `$HOME/.aws`, etc.

But — and this is the load-bearing realization — Babbleon does **not** need
OverlayFS to do the renaming. Renaming is just a bag of bind mounts:
`mount --bind /usr/bin/curl /usr/bin/<scrambledname>` inside the untrusted
namespace, then mask `/usr/bin/curl` itself. The bind-mount approach
preserves inode identity (PLAN.md D1 TOCTOU promise) trivially. OverlayFS
enters only when we need *per-app writable upper layers* (M4 credential
vault), not for the namespace renaming itself.

Implication: M3 ships **mount namespace + bind mounts**; M4 adds
**OverlayFS upper layers** for path-gated credential dirs. Cleanly
separable.

**4. FUSE — viable fallback, but the wrong default.**

FUSE lets us implement the scramble lookup in userspace as a filesystem.
Conceptually clean (one path-resolution callback gets to see every
lookup, perfect for honey-mapping IDS). Operationally expensive:

> "FUSE can perform 3× slower than the underlying Ext4 in the worst case;
> for the least friendly workload, FUSE can consume as much as 18× more
> CPU cycles than Ext4." (Vangoor et al., FAST '17; replicated in ACM
> Transactions on Storage 2019.)

Every userspace round-trip costs context switches and data copies.
RFUSE (FAST '24) improves this with a ring-buffer transport, but it is
not the upstream FUSE driver and is not deployed.

Even at best-case parity, FUSE adds a userspace daemon to the trusted
computing base: it has to be running, it has to authenticate to the
vault, and an attacker who kills it crashes the namespace. Mount
namespaces + bind mounts route entirely through the kernel and need no
helper daemon at runtime.

**Verdict:** FUSE is the right substrate for the M1 sandbox demo (fast
iteration, no root) and a candidate for the macOS port (no mount
namespaces there). Not the right substrate for the M3 Linux production
path.

**5. `setns()` and the escape model.**

`setns(2)` moves the calling process into an existing namespace. Post-
Lutomirski (2013 fix), `setns()` requires `CAP_SYS_ADMIN` in the user
namespace *owning* the target namespace, not just the caller's own
capabilities. This is the kernel enforcement behind PLAN.md §2a-2:
"namespaces inherited at fork (no `setns()` without `CAP_SYS_ADMIN`)."

The standard escape patterns are: (a) container has `CAP_SYS_ADMIN`
→ mount host filesystem → pivot; (b) unprivileged user namespaces
abused for kernel exploits (cdk-team CDK wiki documents this class).
Babbleon mitigations track these directly:

- The untrusted namespace must **not** own a user namespace giving its
  processes `CAP_SYS_ADMIN`. Drop `CAP_SYS_ADMIN` from the bounding set
  via `prctl(PR_CAPBSET_DROP)` before exec into the untrusted view; pair
  with `no_new_privs` so `setuid` binaries cannot re-acquire it.
- `yama.ptrace_scope=2` (admin-only ptrace) prevents an untrusted process
  from `ptrace`-ing a trusted-view process and reading its mappings out
  of `/proc/self/maps`. PLAN.md §2a-2 already names this.
- seccomp-bpf filter denies `setns`, `unshare(CLONE_NEWNS)`,
  `pivot_root`, `mount`, `chroot` to untrusted processes. Belt-and-
  suspenders against the capability drop.

The kernel security model lines up exactly with PLAN.md's enforcement
tier. The gaps are operational (correct capability/seccomp wiring at
exec time), not architectural.

### Implications for the plan

1. **M3 substrate decided: mount namespaces + bind mounts, kernel-only,
   no FUSE.** OverlayFS deferred to M4 for credential-dir writable
   upper layers. Update PLAN.md §8 "Strong" row to name these primitives
   explicitly.
2. **Ship `pam_babbleon.so`.** Don't reuse `pam_namespace`; its config
   model is wrong shape for per-host mapping tables. Borrow the lifecycle
   pattern (PAM session open → unshare → bind-mounts → exec user shell)
   verbatim — it's a solved problem at the integration-point level.
3. **Bind mounts preserve inode identity** → the D1 TOCTOU promise holds
   without any extra machinery. Rotation = swap the bind-mount table;
   open FDs unaffected; cached inodes unaffected. Confirmed.
4. **Propagation: mount the untrusted namespace as `slave` of root, not
   `shared`.** Real-system mount events (USB drives, package-manager
   tmpfs) need to propagate *in*; untrusted-namespace events must not
   propagate *out*. `slave` is the textbook mode for this and is what
   `systemd-nspawn` uses.
5. **Capability + seccomp wiring is the bug-prone part.** Drop
   `CAP_SYS_ADMIN` from the bounding set, set `no_new_privs`, install
   seccomp filter denying `setns`/`unshare`/`pivot_root`/`mount`/`chroot`.
   Wire `yama.ptrace_scope=2` system-wide. This belongs in M3 as a
   named sub-deliverable, not as "we'll do it later."
6. **FUSE is the right M1 demo substrate.** Lets the sandbox demo run
   unprivileged in `./sandbox/`, no namespace cap needed. Lift to mount
   namespaces at M3 when we move into VM scope.
7. **macOS portability question opens up.** Mount namespaces are
   Linux-only. macOS has APFS volume firmlinks and per-process
   filesystem views via Endpoint Security, but no direct equivalent of
   `CLONE_NEWNS`. Likely M5+ concern; record now (T15 follow-up).

### Confidence

- **High:** mount namespaces are the right kernel substrate; FUSE is too
  slow for the production path; `pam_namespace` is the right integration-
  point pattern but the wrong implementation; `setns` capability model
  matches the tier boundary we need.
- **High:** bind mounts preserve inode identity → D1 TOCTOU promise.
- **Medium:** propagation-mode choice (`slave`). Right by convention and
  by `systemd-nspawn` precedent, but the exact propagation graph needs
  prototyping against real mount events (USB, snap, flatpak) before M3
  ships.
- **Medium:** capability/seccomp filter completeness. The named list
  (`setns`/`unshare`/`pivot_root`/`mount`/`chroot`) is the obvious one;
  a real audit needs to consider `move_mount`, `open_tree`, `fsmount`,
  `fsopen`, `fspick`, the newer mount API (Linux 5.2+) — easy to miss
  one and leak an escape.

### Open follow-ups

- Confirm propagation behavior against real-world events (USB mount,
  apt/dpkg, snap, flatpak) on a throwaway VM before M3 design freeze.
- New mount API (`fsopen`/`fsmount`/`move_mount`/`open_tree`, Linux 5.2+)
  audit for seccomp filter completeness.
- Idmapped mounts (Linux 5.12+) — possibly useful for per-tier UID
  mapping on shared inodes; not load-bearing for v1 but worth a note.
- Prototype FUSE-based M1 demo to confirm path-resolution callback latency
  is acceptable for an interactive shell.

### Sources

- mount_namespaces(7) — https://man7.org/linux/man-pages/man7/mount_namespaces.7.html
- LWN: Mount namespaces and shared subtrees — https://lwn.net/Articles/689856/
- pam_namespace(8) — https://man7.org/linux/man-pages/man8/pam_namespace.8.html
- namespace.conf(5) — https://man.archlinux.org/man/namespace.conf.5.en
- Red Hat: Configuring polyinstantiated directories — https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/using_selinux/configuring-polyinstantiated-directories_using-selinux
- Kernel docs: Overlay Filesystem — https://docs.kernel.org/filesystems/overlayfs.html
- Docker OverlayFS storage driver — https://docs.docker.com/engine/storage/drivers/overlayfs-driver/
- Vangoor et al., "To FUSE or Not to FUSE" (FAST '17) — https://www.usenix.org/system/files/conference/fast17/fast17-vangoor.pdf
- "Performance and Resource Utilization of FUSE" (ACM TOS 2019) — https://dl.acm.org/doi/10.1145/3310148
- RFUSE (FAST '24) — https://www.usenix.org/system/files/fast24-cho.pdf
- LWN: Namespaces in operation, part 6 (user namespaces) — https://lwn.net/Articles/540087/
- Wiz: Container escape — https://www.wiz.io/academy/container-security/container-escape
- CDK abuse-unpriv-userns — https://github.com/cdk-team/CDK/wiki/Exploit:-abuse-unpriv-userns

---

## T4 — eBPF-LSM maturity for file/exec gating

**Question:** PLAN.md §8 names eBPF-LSM as the v2 "Hardened" enforcement
tier ("gates at LSM hook; survives namespace escapes"). Is the kernel
support real and shippable in 2026? What hooks fire where we need them?
What's the deployment friction (kernel config, distro defaults, kernel
floor)? What does the latency cost look like for an interactive system?
What's the right relationship between eBPF-LSM and the M3 mount-namespace
tier?

**Method:** 5-angle parallel search across BPF LSM hook semantics, kernel
config and distro support, comparison with Landlock and SELinux, the
Tetragon/Falco production stacks, and overhead benchmarks.

### Findings

**1. The hooks fire exactly where Babbleon needs them, with deny semantics.**

`BPF_PROG_TYPE_LSM` programs attach via `SEC("lsm/<hookname>")` and
return an `int`: `0` permits, negative `errno` denies. The two hooks
PLAN.md §8 names — `file_open` (fires before every `open`/`openat`) and
`bprm_check_security` (fires before every `execve`, after the kernel has
resolved the final executable) — are both supported and standard. A BPF
LSM `file_open` program returning `-EPERM` makes `open(2)` fail in
userspace. `bprm_check_security` deny → `execve` returns `-EPERM`.

This is the right surface. It fires *after path resolution and inode
validation*, which means it gates on the **inode the kernel actually
resolved** — not on the path string a process passed in. That sidesteps
TOCTOU between path and inode that any pure-path interposition (including
LD_PRELOAD and any path-string LSM hook) is vulnerable to.

For Babbleon: the natural v2 model is a BPF LSM `file_open`/
`bprm_check_security` pair that consults the per-host mapping table and
denies untrusted-tier processes any inode whose canonical name is
trusted-only. The kernel does the lookup; raw syscalls, static binaries,
and namespace escapes all funnel through the same hook.

**2. Kernel floor: 5.7 (x86), 6.4 (arm64). Real-world floor: 5.13+.**

`BPF_PROG_TYPE_LSM` landed in **Linux 5.7** (May 2020). ARM64 was broken
from 5.7 to 6.3 (missing arch infrastructure); the fix landed in 6.4.
Practical ecosystem floor is **5.13+** based on what production projects
(Tracee's `safeguard`, ebpfguard, lockc) require.

For Babbleon's target window (2026 onward), 5.7 is ancient and 6.4 is
old. Both Ubuntu 24.04 LTS (6.8) and RHEL 9 (5.14 with backports) clear
the bar. Reasonable assumption: v2 ships when we're comfortable
requiring a 6.x kernel.

**3. Distro defaults are the friction point.**

The required kernel-config flags (`CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`,
`CONFIG_BPF_LSM=y`, `CONFIG_BPF_JIT=y`, `CONFIG_DEBUG_INFO_BTF=y`, plus
`CONFIG_LSM` must include `bpf`) are usually compiled in by major
distros, **but BPF LSM is not enabled by default at boot** on most
distros. Enabling it requires editing GRUB:
`GRUB_CMDLINE_LINUX="lsm=lockdown,capability,bpf"` and reboot.

Implications:

- **v2 ships with a `babbleon-enable-bpflsm` helper** that mutates
  `/etc/default/grub`, regenerates grub config, and prompts reboot. Same
  pattern Tracee/ebpfguard ship.
- **Detection-only mode (no enforcement) works without the boot flag**
  via kprobes/tracepoints. v2 should fall back to detection-only on
  hosts where BPF LSM isn't enabled, and surface an "enable to upgrade
  to enforcement" prompt.
- **Distro-shipped BPF LSM packages should be tracked.** Fedora has been
  closest to enabling by default. Worth re-checking before v2 release.

**4. The right comparison is Landlock, not SELinux.**

SELinux is the wrong shape for Babbleon: static policy compiled at boot,
admin-only authorship, complex labeling. It coexists with Babbleon (we
do not conflict with SELinux MAC); it does not replace eBPF LSM as
Babbleon's enforcement substrate.

**Landlock** (Linux 5.13 baseline, dramatically expanded in 6.x) is the
interesting alternative. It's an in-tree LSM that lets *unprivileged*
processes sandbox themselves with path-rule-style policies. Properties
versus eBPF LSM for Babbleon:

| Property | Landlock | eBPF LSM |
|---|---|---|
| Privilege to install policy | unprivileged process self-sandbox | root (CAP_BPF + CAP_SYS_ADMIN) |
| Policy expressiveness | path/inode allow-rules | arbitrary BPF program over hook args |
| Per-process scoping | native (each process installs own ruleset) | global; must inspect `current` to scope |
| Distro default-on | yes (no boot flag) | no (needs `lsm=...,bpf`) |
| Kernel floor for our use | 6.x (path-beneath + truncate scopes) | 5.7 / 6.4 arm64 |

Landlock's per-process self-sandbox model is a better fit for the
*untrusted-tier process* side of Babbleon: at process launch we install
a Landlock ruleset that **denies the untrusted process any access to
canonical-named credential paths and trusted-only binaries**, before
`execve`. No boot flag, no root daemon, no mapping-table lookup in BPF.

eBPF LSM remains the right tool when we need to **see every open across
the system and consult shared state** (honey-mapping IDS in particular —
the LSM program logs every `file_open` that hits a tripwire inode). The
two compose: Landlock for per-process containment, eBPF LSM for
host-wide observation and tripwire detection.

**Implication for PLAN.md §8:** the "Hardened (v2)" tier should be named
as **Landlock + eBPF LSM**, not eBPF LSM alone. Landlock does most of
the enforcement work cheaply; eBPF LSM does the IDS work and the
escape-resistant catch-all.

**5. Production stack: Tetragon is the existence proof.**

Tetragon (Isovalent/Cisco, CNCF Incubating) drives `BPF_PROG_TYPE_LSM`
in production at scale on Kubernetes. Enforcement actions: override
return value, send SIGKILL, signal-based interception. Falco has a
similar event surface but historically focused on detection; Tetragon's
kernel-side filtering is the relevant pattern.

For Babbleon we are **not** building a competitor to Tetragon. We are
building a much smaller, special-purpose LSM that knows one thing: "does
this process see scrambled or real names?" Tetragon's value is that it
proves the operational story is shippable: BTF CO-RE for cross-kernel
portability, BPF skeleton lifecycle, policy reload without reboot.
Borrow the operational pattern; do not pull in the runtime.

**6. Overhead: low but workload-dependent; no published deny-path number.**

I couldn't find a clean published microbenchmark for `file_open` deny
latency, which is mildly surprising and a real research gap for us. The
qualitative picture from the eBPF observability literature: per-hook
overhead is in the low microseconds when programs are simple, the hot
path is well-jitted, and BTF resolution is amortized. arXiv 2101.11611
("Analyzing the Overhead of Filesystem Protection Using LSMs") measures
classical LSMs (SELinux, AppArmor) at single-digit-percent overhead on
representative file workloads; eBPF LSM should be at parity or better.

For Babbleon: the mapping-lookup hot path needs to be a BPF hash map
keyed on `(inode, tier)`, populated at unlock and rotated atomically.
That keeps the deny-decision a single map lookup. Latency cost should
be invisible for interactive shells; the question is whether it costs
us anything noticeable on heavy build workloads (kernel make, npm
install) where `open()` fires millions of times. **Open follow-up: build
a microbenchmark before v2.**

### Implications for the plan

1. **Rename PLAN.md §8 "Hardened (v2)" → "Landlock + eBPF-LSM (v2)."**
   Landlock for per-process untrusted-tier self-sandboxing; eBPF LSM for
   host-wide honey-mapping tripwires and the escape-resistant `file_open`
   /`bprm_check_security` deny path.
2. **Honey-mapping (PLAN.md §2a-5) wants eBPF LSM.** Tripwire-inode
   accesses fire `file_open`; a BPF map records the offending PID + comm
   + uid; userspace daemon escalates. This is exactly the dynamic
   instrumentation eBPF LSM was built for.
3. **v2 kernel floor: Linux 6.4+.** Above the arm64 fix; widely
   deployed by 2026. Document in release notes.
4. **Ship `babbleon-enable-bpflsm` helper** that edits GRUB and prompts
   reboot. Without the boot flag we get detection-only fallback via
   kprobes; with the flag we get enforcement.
5. **v1 can ship a Landlock-only enforcement tier *today*.** Landlock
   doesn't need a boot flag and is on by default in every modern distro.
   This is genuinely interesting: a Landlock-based untrusted-tier
   self-sandbox is achievable in M3 without waiting for v2. **Promotion
   candidate: move Landlock self-sandboxing from "v2" into M3.** The
   mount namespace does the renaming; Landlock seals the untrusted
   process against escaping back to canonical names via any path the
   kernel knows about.
6. **Hot-path data structure decided: BPF hash map keyed on `(inode,
   tier)`.** Populated by userspace at unlock; swapped atomically on
   rotation via `BPF_MAP_TYPE_HASH_OF_MAPS` or two-map flip pattern.
7. **No Tetragon dependency.** Borrow the operational pattern (BTF
   CO-RE, libbpf skeleton, in-tree policy reload); ship our own minimal
   loader.

### Confidence

- **High:** BPF LSM hook semantics, kernel floor, distro friction,
  Landlock as a complementary tool, Tetragon as existence proof.
- **High:** the architectural decision to use Landlock + eBPF LSM
  together rather than eBPF LSM alone.
- **Medium:** the v1 promotion of Landlock self-sandboxing into M3.
  Cheap and high-value on paper; needs a prototype against real shells
  and package managers before commit. The well-known Landlock pitfall
  is that early kernels lacked enough scope axes (no network, limited
  ioctl) — 6.x fills most of these in, but we should verify our
  required scopes (path-beneath read/exec deny, refer scope for renames)
  are all present on the target kernel floor.
- **Low:** the no-published-deny-latency-number gap. We need to
  benchmark this ourselves before v2 enforcement ships.

### Open follow-ups

- Microbenchmark `file_open` deny latency on a 6.x kernel with a
  realistic mapping size (10⁴–10⁵ entries) and heavy `open()` workload
  (linux kernel build, `npm install`).
- Confirm Landlock 6.x scope coverage matches Babbleon's enforcement
  needs (path-beneath read/exec deny for trusted-only inodes; refer
  scope for credential dir bind mounts).
- Re-check Fedora/Ubuntu default-on status for `lsm=...,bpf` before
  v2 release; track which distros remove the GRUB friction.
- Audit Tetragon's BTF CO-RE and libbpf skeleton lifecycle for
  patterns to borrow.

### Sources

- LSM BPF Programs (kernel docs) — https://docs.kernel.org/bpf/prog_lsm.html
- `BPF_PROG_TYPE_LSM` (eBPF docs) — https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_LSM/
- Landlock (kernel docs) — https://docs.kernel.org/admin-guide/LSM/landlock.html
- LWN: Landlock LSM toward unprivileged sandboxing — https://lwn.net/Articles/731478/
- Tracee BPF LSM support requirements — https://aquasecurity.github.io/tracee/dev/docs/install/lsm-support/
- ebpfguard prerequisites — https://github.com/deepfence/ebpfguard/blob/main/docs/gh/prerequisites.md
- Tetragon hook points — https://tetragon.io/docs/concepts/tracing-policy/hooks/
- Tetragon enforcement — https://tetragon.io/docs/concepts/enforcement/
- Cilium: Migrating from Falco to Tetragon — https://cilium.io/blog/2026/01/19/tetragon-falco-migrate/
- Hunting TOCTOU and LD_PRELOAD attacks with eBPF LSM — https://medium.com/@satyam012005/hunting-toctou-and-ld-preload-attacks-with-ebpf-lsm-ea7f4e6c3884
- "Analyzing the Overhead of Filesystem Protection Using LSMs" (arXiv 2101.11611) — https://arxiv.org/pdf/2101.11611

---
