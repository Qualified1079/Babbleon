# Babbleon — Research Log

Living document. Topics from `PLAN.md` §12 + the agreed research slate, worked
through one at a time. Each section records: question, method, findings,
implications for the plan, open follow-ups.

Status legend: ⬜ not started · 🟡 in progress · ✅ done · 🟥 blocked

## Tier 1 — decision-blocking

- ✅ **T1. Moving Target Defense vs LLM/automated attackers** — prior art sweep
- ✅ **T2. Agentic-exploitation capability literature** — what current LLM exploit harnesses actually do
- ⬜ **T3. Per-process filesystem view mechanisms on Linux** — mount ns / OverlayFS / FUSE / pam_namespace
- ⬜ **T4. eBPF-LSM maturity** for file/exec gating
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
