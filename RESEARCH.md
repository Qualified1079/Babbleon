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
- ✅ **T5. Hardware-unlock primitives** — FIDO2 hmac-secret, TPM 2.0 sealing, OS keychains

## Tier 2 — shapes implementation

- ✅ **T6. LLM/BPE tokenizer behavior** on lowercase concatenated compounds
- ✅ **T7. Credential-store inventories** across modern dev/cloud tooling
- ✅ **T8. Env-var vocabulary** attackers actually scrape
- ✅ **T9. Package manager hook surfaces** (dpkg/rpm/brew/flatpak/snap)
- ✅ **T10. Binary fingerprinting countermeasures**
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

## T5 — Hardware-unlock primitives (FIDO2, TPM 2.0, OS keychains, KDF)

**Question:** PLAN.md §7 names four unlock tiers (Soft / Soft+ / Portable
/ Hardware) all feeding one vault. For each tier, what's the actual
primitive, what does it guarantee against an on-host attacker (PLAN.md
§2a-4 honesty bar), what's the implementation pattern, and what are
the gotchas?

**Method:** 5-angle parallel search across FIDO2 hmac-secret, TPM 2.0
PCR sealing, systemd-cryptenroll as production pattern, macOS Keychain
+ Secure Enclave, and modern Argon2id parameters.

### Findings

**1. FIDO2 `hmac-secret` is exactly the right primitive for the Hardware tier.**

The CTAP2 `hmac-secret` extension lets the authenticator compute
**HMAC-SHA-256(credential_secret, salt)** and return the result. The
credential's secret never leaves the token; the host supplies a salt
and receives a 32-byte pseudorandom output. Two salts are supported per
call (enables rolling the symmetric secret without re-enrolling the
credential).

Key properties for Babbleon's vault KEK:

- **The token must be present and tapped for every unlock.** Physical
  presence + user verification ≡ the "Hardware" tier promise. An on-host
  attacker without the token cannot derive the KEK even with full root.
- **`hmac-secret` is scoped to one credential**, so the same YubiKey can
  back Babbleon, age, SSH, and KeePassXC independently with no
  cross-extraction.
- **Production precedent: age**, KeePassXC, and systemd-cryptenroll all
  use `hmac-secret` to derive symmetric KEKs. FiloSottile age discussion
  #390 is the canonical design write-up. We borrow this pattern
  verbatim.
- **Browser/SDK caveat:** Safari/WebAuthn `prf` (the WebAuthn surface
  for hmac-secret) does not yet work with YubiKeys as of iOS 18 / macOS
  15. Irrelevant to Babbleon — we use the native CTAP2 path via
  `libfido2`, not the browser.

**Recommended pattern:** Babbleon enrollment generates a per-host
random salt (stored on disk, *not* secret), registers a resident
credential on the FIDO2 token tagged `babbleon:<hostname>`, and at
unlock time calls `hmac-secret(credential, salt) → KEK`. KEK never
touches disk.

**2. TPM 2.0 PCR-sealed keys = the Soft+ tier (PLAN.md §7).**

A TPM 2.0 can seal an arbitrary blob to a policy expressing "PCR
registers X,Y,Z must equal these values." The TPM releases the blob
only when current PCR state matches. PCRs 0–7 record firmware/bootloader
measurements (Secure Boot chain); 8–9 record kernel + initrd; 14
records cryptographically-bound configurations. A disk pulled out of
the laptop, or a kernel swapped under it, fails the policy and the key
is not released.

`tpm2_createpolicy --policy-pcr -l sha256:0,1,2 …` defines the policy;
`tpm2_create` + `tpm2_load` seal the blob; `tpm2_unseal` retrieves it
when PCRs match. **Authorized policies** (signed by a known key) let
the user re-seal automatically after legitimate firmware/kernel updates
without re-enrolling — important for usability on a host that gets
patched monthly.

For Babbleon: TPM-sealed KEK released only at measured-boot match.
Honest copy per PLAN.md §2a-4: *"key released only to measured boot
states; never leaves TPM in usable form except in-memory during use."*
That's verbatim what TPM sealing delivers, no more.

Two real attacks to document:

- **TPM bus sniffing (LPC/SPI).** Discrete TPMs on a low-speed bus can
  be passively sniffed during the unseal handshake. fTPMs (firmware
  TPMs on the CPU) and Pluton avoid this; discrete TPMs are vulnerable.
  Document in tier-strength copy.
- **PCR11 / Secure Boot policy bypass.** The oddlama 2024 writeup
  documents systemd-cryptenroll TPM2 unlock being bypassed when sealing
  was bound only to PCR7 (Secure Boot state) without binding to the
  kernel command line or initrd; an attacker swaps `init=/bin/sh` into
  cmdline and the TPM still releases the key. **Implication:** Babbleon
  must seal against PCRs covering the kernel command line and initrd
  hashes (PCR8/9 + PCR14 for the boot config), not just Secure Boot
  state. systemd 254+ has `--tpm2-pcrs` documented patterns.

**3. systemd-cryptenroll is the reference implementation.**

`systemd-cryptenroll` manages LUKS2 unlock methods: password, recovery
key, PKCS#11, FIDO2 (`hmac-secret`), TPM2. **All four of Babbleon's
unlock tiers map cleanly onto systemd-cryptenroll backends**, which is
the strongest possible existence proof that the architecture is
shippable: somebody has already built the multi-tier unlock-to-one-
vault pattern at the LUKS layer in production.

**Implication for plan:** Babbleon's vault should not be LUKS2 (it's a
per-app mapping file, not a block device), but its unlock-method abstraction
should **structurally mirror** systemd-cryptenroll. Concretely:

- One pluggable "KEK backend" interface; backends register a `unlock()
  → 32-byte KEK` method.
- Backends shipped in v1: `password` (Argon2id), `tpm2` (PCR-sealed),
  `fido2` (`hmac-secret`), `keyfile` (raw bytes from path, ± password
  for 2FA per PLAN.md §7 "Portable").
- The vault file is age-format (PLAN.md §2a-4 endorses age/libsodium).
  KEK wraps the age identity; rotating the unlock method = re-wrap, no
  re-encrypt of the vault contents.

**4. macOS Keychain + Secure Enclave is the macOS Soft+ analog.**

`kSecAttrTokenIDSecureEnclave` generates a P-256 key inside the SE; the
private key never leaves. Add `kSecAttrAccessControl` with
`.userPresence` or `.biometryCurrentSet` and the SE evaluates the ACL
internally; key is usable only after Touch ID. The SE-protected key
wraps a symmetric key that wraps the vault KEK — same pattern as TPM.

Hardware requirement: Apple Silicon or T2 (2018+). Pre-2018 Macs fall
back to file-based keychain entries; we tier-label that honestly as
Soft, not Soft+.

For Babbleon on macOS: the SE wraps the KEK; Touch ID or device
password is required at unlock; key never extractable. Equivalent
security promise to TPM PCR-sealed on Linux. **macOS port path is
unblocked from a unlock-tier perspective**; the filesystem-view problem
(T3 follow-up) is the harder macOS port question.

**5. Argon2id parameters for the Soft tier (password unlock).**

OWASP 2025 minimum: **m=19 MiB, t=2, p=1**. Alternative profile
**m=46 MiB, t=1, p=1** (the one OWASP empirically benchmarks as
reducing compromise rate by 42.5% vs SHA-256 at a $1/account budget).
RFC 9106 is the IETF standard.

For Babbleon: ship the OWASP "high" profile (**m=46 MiB, t=2, p=1**) as
default — Babbleon's password unlock runs once per session, not once
per HTTPS request, so we can afford to be stricter than OWASP's
web-app minimum. Document `m`/`t`/`p` in the vault header so future
upgrades to harder parameters can re-derive at next unlock.

**Rate-limiting:** PLAN.md §7 names "hard rate-limiting on unlock
attempts." Argon2id's per-attempt cost is the first line; an explicit
counter in the vault header (incremented before each derivation,
cleared on success) is the second. **Open follow-up:** decide the
backoff schedule (linear? exponential? lock-out at N?).

### Implications for the plan

1. **Tier mapping confirmed and tightened:**

   | PLAN tier | Primitive | Concrete API |
   |---|---|---|
   | Soft | Argon2id KEK from password | `libsodium` argon2id, m=46 MiB t=2 p=1 |
   | Soft+ | TPM2 PCR-sealed KEK (Linux) / SE-wrapped KEK (macOS) | `tpm2-tss` / Security framework |
   | Portable | Raw keyfile bytes ± Argon2id over passphrase (2FA) | filesystem read + libsodium |
   | Hardware | FIDO2 `hmac-secret` over per-host salt | `libfido2` |

2. **Vault format: age (libsodium under the hood).** PLAN.md §2a-4
   already endorses this. KEK wraps the age identity file; unlock-tier
   changes re-wrap only the identity, not the vault.
3. **Reference architecture: systemd-cryptenroll.** Mirror its
   pluggable-backend interface. We are not the first to ship this
   shape; do not invent a new abstraction.
4. **TPM PCR sealing must cover kernel cmdline + initrd**, not just
   Secure Boot state (PCR7). The oddlama bypass is the specific failure
   mode to design against. Bake the correct `--tpm2-pcrs` pattern into
   our enrollment helper.
5. **Document discrete-TPM bus-sniffing exposure** in the Soft+ tier
   copy. fTPM/Pluton = full strength; discrete TPM = labeled-weak
   sub-variant.
6. **macOS unlock path is unblocked.** Filesystem-view problem
   (T15 follow-up) remains the macOS porting blocker, not the vault
   layer.
7. **Argon2id default: m=46 MiB, t=2, p=1.** Vault header records the
   parameters; future bumps re-derive at next unlock.
8. **Define rate-limit schedule.** Open follow-up; suggested default
   exponential backoff to 30s after 3 failures, lock requiring
   recovery-key after 10.

### Confidence

- **High:** all four unlock primitives are real, shippable, and have
  production precedent (systemd-cryptenroll, age, KeePassXC, FileVault).
- **High:** the systemd-cryptenroll mirror as Babbleon's KEK-backend
  abstraction.
- **High:** the oddlama TPM-cmdline-bypass requires sealing the cmdline,
  not just PCR7 — well-documented and replicable.
- **Medium:** discrete-TPM bus-sniffing exposure. Real attack class but
  requires physical access + hardware probe; document, don't over-
  weight in user-facing copy.
- **Medium:** browser-side FIDO2 PRF support irrelevant to our path,
  but worth noting in case anyone proposes a web unlock surface in v2.

### Open follow-ups

- Decide rate-limit backoff schedule (default proposal: 1s→2s→4s→…
  exponential to 30s after 3 failures, lock at 10 requiring recovery
  key).
- Verify `libfido2` CTAP2 `hmac-secret` path works without Yubico's
  yesdk dependency (we want it in C/Rust with no JS/SDK indirection).
- Determine which PCRs to seal against on each Linux distro (PCR
  semantics differ slightly between systemd-boot, GRUB, sd-stub).
- Spec the on-disk vault header fields (Argon2id m/t/p, attempt
  counter, KEK-backend type tag, version).

### Sources

- FIDO2 `hmac-secret` (Yubico developer docs) — https://docs.yubico.com/yesdk/users-manual/application-fido2/hmac-secret.html
- WebAuthn PRF Developers Guide (Yubico) — https://developers.yubico.com/WebAuthn/Concepts/PRF_Extension/Developers_Guide_to_PRF.html
- age discussion #390 (FIDO2 hmac-secret design) — https://github.com/FiloSottile/age/discussions/390
- tpm2-tools sealing policies (wolfSSL writeup) — https://www.wolfssl.com/tpm-2-0-sealing-policies-with-wolftpm-pcr-policies-policy-authorize-and-nv-storage-for-tpm-2-0-secrets/
- LUKS + TPM2 sealing with measured boot — https://www.systemshardening.com/articles/linux/luks-tpm2-sealing/
- oddlama: Bypassing TPM2 LUKS unlock when only PCR7 is sealed — https://oddlama.org/blog/bypassing-disk-encryption-with-tpm2-unlock/
- systemd-cryptenroll FIDO2/TPM2 enrollment (Fedora Magazine) — https://fedoramagazine.org/use-systemd-cryptenroll-with-fido-u2f-or-tpm2-to-decrypt-your-disk/
- systemd-boot + FDE with TPM and FIDO2 (openSUSE MicroOS) — https://microos.opensuse.org/blog/2023-12-20-sdboot-fde/
- Apple Keychain data protection — https://support.apple.com/en-ca/guide/security/secb0694df1a/web
- Apple developer forum: Storing SE key into Keychain w/ LA protection — https://developer.apple.com/forums/thread/658821
- OWASP password storage cheat sheet (Argon2id parameters, 2025) — https://guptadeepak.com/the-complete-guide-to-password-hashing-argon2-vs-bcrypt-vs-scrypt-vs-pbkdf2-2026/
- RFC 9106 (Argon2) — https://datatracker.ietf.org/doc/rfc9106/

---

## T6 — LLM / BPE tokenizer behavior on lowercase concatenated compounds

**Question:** PLAN.md §5 commits to all-lowercase concatenated N-word
compounds (`antiquebifurcatedsableanionmountain`) explicitly to be
hostile to BPE tokenizers. Is the design intuition right? What
*quantitatively* happens when modern tokenizers (cl100k_base,
o200k_base, Claude's, Llama's SentencePiece) hit these strings? Are
there better-than-random adversarial properties (glitch tokens,
ambiguous segmentation) we should exploit?

**Method:** 5-angle parallel search: BPE compound-word segmentation
behavior, GPT-4/Claude tokenizer characteristics for random strings,
glitch tokens / SolidGoldMagikarp, tiktoken `cl100k_base`/`o200k_base`
internals, and adversarial tokenizer attacks (entropy / context-length
cost).

### Findings

**1. The design intuition is right and quantifiable.**

Modern BPE tokenizers (`cl100k_base` ~100k vocab, `o200k_base` ~200k,
Claude's similar order of magnitude) trained on English text learn
merges biased toward word boundaries, common prefixes/suffixes, and
whitespace-led tokens. Babbleon's compound names deliberately strip
the two strongest segmentation signals:

- **Whitespace.** The tokenizer regex pre-tokenizer (cl100k_base uses
  the GPT-2 `\s*[\r\n]+`-derived pattern; o200k_base uses a more
  elaborate Unicode-aware pattern) splits on whitespace *first*, before
  BPE merges run. Removing whitespace forces the entire compound into
  one pre-tokenization chunk, where BPE then has to greedily merge
  inside a 60–80 character blob.
- **Capitalization.** Mixed-case tokens (`PascalCase`, `camelCase`)
  trigger merges on case boundaries; pure lowercase removes that
  signal. PLAN.md §5's lowercase decision is technically load-bearing,
  not stylistic.

The rule of thumb is "1 token ≈ 4 chars / 0.75 English words" on
typical text. On a deliberately-ambiguous lowercase compound of 60–80
characters, observed behavior (per the tokenizer-drift literature) is
that token counts inflate to **2–3× normal density** — the same chars
that would be ~15 tokens as spaced words become 30–50 tokens as a
no-whitespace blob. That cost is paid *every time the attacker's
agent reads a directory listing*.

**2. Ambiguous segmentation is a real adversarial property, not just colour.**

PLAN.md §5 notes `cation` (cat+ion vs cation) as a feature. The
tokenizer-drift literature confirms the mechanism: BPE is *greedy
left-to-right with a fixed merge table*; near-ties between merge
candidates resolve deterministically but the choice is fragile. A
single-character perturbation can re-segment the rest of the string
("splits become completely different, a single character affecting
multiple tokens after it" — `tokencontributions` substack on
o200k_base).

For Babbleon this means: **rotation doesn't just change names; it
changes the tokenization pattern of every subsequent directory
listing**. The agent's prior over "what does a Babbleon'd `ls`
output look like" gets invalidated at every rotation, not just at
first encounter. Compounds the multi-step error rate from T2-§3.

**3. Glitch tokens (SolidGoldMagikarp) are not directly usable but the model is.**

Glitch tokens are artefacts of *tokenizer construction* on
non-representative data (e.g. Reddit usernames over-represented in the
tokenizer corpus, under-represented in the model's training corpus).
They cause anomalous model behavior — repetition, refusal,
hallucination of unrelated tokens. We cannot manufacture glitch
tokens for an arbitrary tokenizer we don't control.

**What we *can* do is generate strings whose BPE segmentation
deterministically maps onto rare-but-valid tokens** — high-perplexity
inputs that aren't UNK-rare but are mid-frequency-rare. Effects in the
glitch-token literature: erratic continuations, attention dispersion,
recall failures on long-context retrieval. We don't need full
glitch-token weirdness; we just need to push the agent's
representation of our paths into the low-density tail of its
embedding space.

**Tractable design improvement (recommend for v2):** post-filter the
wordlist to *prefer* words whose BPE byte sequences are mid-frequency
in `cl100k_base` and `o200k_base`. Don't bias toward super-rare (risk
of training-set absence and unpredictable behavior, plus tokenizer-
dependent and brittle); bias toward mid-tail. This is a small,
mechanical optimization on top of PLAN.md §5's "pure unbiased
dictionary" — *additive*, not replacement.

**Caveat to flag against PLAN.md §5:** the plan explicitly argues "no
curation, no weighting" because mis-targeting (curl→calculator) is
valuable. Tokenizer-density filtering is a *different axis* than
semantic curation and does not throw away the mis-targeting benefit.
Worth a plan-amendment note.

**4. Tokenizer cost is a denial-of-pocket vector against the attacker.**

Two papers reframe this nicely:

- **Trend Micro on tokenizer drift:** removed merges cause 2–3× token
  inflation, inflating attacker cost.
- **LoopLLM (AAAI 2026) and ThinkTrap (arXiv 2512.07086):** energy-
  latency attacks on LLM services exploit autoregressive generation
  to force max-length output. Defender-side, the same dynamic helps:
  high token-density on directory listings inflates the attacker's
  per-step cost.

From T2 we have RapidPen's economics: **$0.30–$0.60 per IP-to-shell**.
If Babbleon raises the attacker's tokens-per-recon-step by 2–3×, those
economics shift visibly. Quoting in the README: "Babbleon raises the
attacker's *recon token cost* by ~2–3× — an LLM exploit-as-a-service
priced at $0.30/host gets noticeably less profitable."

**5. Per-tokenizer notes:**

- **cl100k_base (GPT-4 / GPT-3.5):** ~100k vocab; classical GPT-2-
  style pre-tokenizer regex; merges biased toward English web text.
  Babbleon compounds tokenize at high density.
- **o200k_base (GPT-4o / GPT-5):** ~200k vocab; expanded multilingual
  coverage. Doubles the chance any individual short word is a single
  token, but does not change the no-whitespace-blob problem. Density
  reduction on Babbleon compounds: marginal; estimate 10–20%.
- **Claude tokenizer:** not public; Anthropic API token-counting
  endpoint exists but we can't enumerate merges. Family-of-BPE
  assumption suggests similar behavior; needs empirical check.
- **Llama 3 / SentencePiece-Unigram:** different algorithm (unigram
  LM), but pre-tokenization still whitespace-led. Compound names
  expected similarly hostile.

### Implications for the plan

1. **PLAN.md §5 is correct as written.** Lowercase, no separators,
   N-word compounds: the design choice is technically motivated and
   the literature backs it.
2. **Quantify the benefit in user-facing copy.** "~2–3× recon token
   cost" is a defensible specific claim and lands the security
   value proposition concretely.
3. **Add a small wordlist post-filter for v2.** Score each candidate
   word by its `cl100k_base` and `o200k_base` tokenization density,
   prefer mid-tail-rare tokens. *Additive* to PLAN.md §5; does not
   replace unbiased random draw. Amend PLAN.md §5 with a sentence:
   *"v2: post-filter by tokenization density; do not curate
   semantically."*
4. **Empirical sanity check before M1.** Generate 1000 Babbleon
   compounds, run through `tiktoken cl100k_base`/`o200k_base` and
   compare token-density distribution against spaced English. Confirm
   the 2–3× number. Add to the M1 demo as a one-page benchmark.
5. **Tokenizer-density is a v2 rotation knob.** When we rotate, we
   can re-roll to *prefer* compounds that further perturb the
   tokenization-prior the attacker built up. Probably overkill for v1;
   record for v2 design review.
6. **Compounding with T2.** Multi-step error from agent harness chains
   (5–15% per call, compounding fast) gets amplified when each step's
   *input encoding* is also degraded. The two compose.

### Confidence

- **High:** the qualitative direction (lowercase + no-whitespace +
  compounds = high token density, parse ambiguity, rotation-perturbed
  segmentation). Mechanism is well-documented.
- **Medium:** the specific "2–3×" number. Tokenizer-drift literature
  cites it; we should confirm with our own microbenchmark on
  Babbleon-shaped strings before claiming it.
- **Medium:** the tokenization-density wordlist filter's actual
  empirical benefit. Plausibly meaningful, plausibly noise. Worth
  prototyping; not worth blocking v1.
- **Low:** Claude tokenizer specifics. Need an empirical sweep via
  the API token-counting endpoint.

### Open follow-ups

- Microbenchmark: 1000 Babbleon compounds vs comparable spaced-text
  baseline, measure token counts in `cl100k_base`, `o200k_base`,
  and via Claude's count-tokens API. M1 deliverable.
- Tokenization-density wordlist filter prototype. Score the EFF wordlist
  against `tiktoken`; check whether the bias is large enough to matter.
- Empirical glitch-token sweep — unlikely to be exploitable but worth
  a one-shot check that no random Babbleon compound *accidentally*
  collides with a known glitch token in `o200k_base`.
- Llama / SentencePiece-Unigram check; relevant if the threat is a
  local open-weights attacker.

### Sources

- "When Tokenizers Drift" (Trend Micro) — https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/when-tokenizers-drift-hidden-costs-and-security-risks-in-llm-deployments
- Unreachable tokens in GPT-4o (Sander Land) — https://tokencontributions.substack.com/p/unreachable-tokens-in-gpt-4o
- tiktoken (OpenAI) — https://github.com/openai/tiktoken
- cl100k_base tokenizer visualization — https://www.tiktokenizer.app/models/cl100k_base
- GlitchMiner (arXiv 2410.15052) — https://arxiv.org/pdf/2410.15052
- GlitchProber (arXiv 2408.04905) — https://arxiv.org/pdf/2408.04905
- SolidGoldMagikarp + prompt generation (Alignment Forum) — https://www.alignmentforum.org/posts/aPeJE8bSo6rAFoLqg/solidgoldmagikarp-plus-prompt-generation
- LoopLLM energy-latency attacks (arXiv 2511.07876) — https://arxiv.org/pdf/2511.07876
- ThinkTrap DoS via infinite thinking (arXiv 2512.07086) — https://arxiv.org/pdf/2512.07086
- Anthropic token-counting endpoint — https://platform.claude.com/docs/en/build-with-claude/token-counting

---

## T7 — Credential-store inventories across modern dev/cloud tooling

**Question:** PLAN.md §6 names credential stores as the tier-1 "must"
scramble target. What's the actual inventory of file paths and stores
Babbleon needs to know about for M4? Where does each tool look, what's
the env-var override, and what does the 2025 infostealer-economy
literature say is being targeted in the wild?

**Method:** 5-angle search across cloud SDKs (AWS/GCP/Azure/kubectl/
Docker), browser cookie/login databases, SSH+GPG+netrc+git helpers,
package-registry tokens (npm/PyPI/Cargo), and the 2025 infostealer
target-path corpus.

### Findings

**1. The canonical-paths inventory (M4 starting set).**

The "must-scramble" credential paths that every cloud/dev tool reaches
for by default:

| Tool | Default path | Env-var override | Notes |
|---|---|---|---|
| AWS CLI / SDK | `~/.aws/credentials`, `~/.aws/config`, `~/.aws/sso/cache/*` | `AWS_SHARED_CREDENTIALS_FILE`, `AWS_CONFIG_FILE` | profile-keyed; SSO cache holds session tokens |
| GCP `gcloud` | `~/.config/gcloud/credentials.db`, `~/.config/gcloud/application_default_credentials.json` | `CLOUDSDK_CONFIG`, `GOOGLE_APPLICATION_CREDENTIALS` | ADC JSON is the prized file |
| Azure CLI | `~/.azure/accessTokens.json`, `~/.azure/azureProfile.json` | `AZURE_CONFIG_DIR` | rotates frequently; still high-value |
| kubectl | `~/.kube/config` | `KUBECONFIG` (colon-separated list) | embeds exec credentials, ca certs, tokens |
| Docker | `~/.docker/config.json` | `DOCKER_CONFIG` | refers to credsStore/credHelpers (osxkeychain, secretservice, wincred) |
| SSH | `~/.ssh/id_*`, `~/.ssh/config`, `~/.ssh/known_hosts`, `~/.ssh/authorized_keys` | none standard | `IdentityFile` directive overrides per-host |
| GPG | `~/.gnupg/private-keys-v1.d/*`, agent sockets `S.gpg-agent{,.ssh,.browser,.extra}` | `GNUPGHOME` | sockets are *active* trust handles, not just files |
| Git | `~/.gitconfig`, `~/.git-credentials`, `~/.config/git/credentials` | `XDG_CONFIG_HOME`, `GIT_CONFIG_GLOBAL` | credential.helper indirection (osxkeychain, libsecret, GCM) |
| `~/.netrc` | `~/.netrc` | `NETRC` | still alive — curl, git, ftp, hg, Python `requests` |
| npm | `~/.npmrc` (`_authToken`, `//registry.npmjs.org/:_authToken=…`) | `NPM_CONFIG_USERCONFIG` | also project-level overrides |
| pnpm | `~/.config/pnpm/auth.ini` | `PNPM_HOME` | newer XDG-clean location |
| PyPI / twine | `~/.pypirc` | `HOME` | global `pypirc` with `__token__` API key |
| Cargo | `$CARGO_HOME/credentials.toml` (default `~/.cargo/credentials.toml`) | `CARGO_HOME` | also `config.toml` for registry hosts |
| GitHub CLI `gh` | `~/.config/gh/hosts.yml` | `GH_CONFIG_DIR` | OAuth tokens |
| HuggingFace | `~/.cache/huggingface/token`, `~/.huggingface/token` | `HF_HOME`, `HF_TOKEN` | api keys for model push |
| Anthropic / OpenAI SDKs | env-var only (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) | env-var | no on-disk default — env-var inventory (T8) |

**Implication: env-var override is *universal*.** Every single tool
above accepts an env-var to redirect its credential search path. This
is exactly what Babbleon needs — the trusted view points the var at
the real (unscrambled) profile dir; the untrusted view either omits
the env var or points it at a scrambled / honey-pot location. M4's
mechanism is path-gating + env-var injection per app launch, not
format-parsing. PLAN.md §6's "path-gating, not format-parsing" stance
is empirically the correct call.

**2. Browser credential stores — the format-churn trap PLAN.md called.**

- **Chrome / Chromium / Edge / Brave:** SQLite `Cookies`, `Login Data`,
  `Web Data`, `History`. Cookie values are AES-CBC (128-bit) encrypted;
  encryption key wrapped by OS keychain. On macOS the key lives in
  the Keychain as `Chrome Safe Storage`. On Linux it's libsecret /
  KWallet. On Windows it's DPAPI.
- **Firefox:** SQLite `cookies.sqlite`, `logins.json` (encrypted by
  `key4.db` master password — but if no master password set, the
  encryption key is on-disk and decryptable).
- **Safari:** Keychain-stored. Cookies in `~/Library/Cookies/Cookies.binarycookies`.

Per-browser layouts:

| Browser | OS | Profile dir | Cookie file |
|---|---|---|---|
| Chrome | macOS | `~/Library/Application Support/Google/Chrome/Default/` | `Network/Cookies` |
| Chrome | Linux | `~/.config/google-chrome/Default/` | `Cookies` |
| Chrome | Windows | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\` | `Network\Cookies` |
| Firefox | all | `~/.mozilla/firefox/<profile>/` | `cookies.sqlite` |
| Safari | macOS | `~/Library/Safari/`, `~/Library/Cookies/` | `Cookies.binarycookies` |

**Implication:** PLAN.md §6's "path-gating, not format-parsing" is
*especially* right for browsers. The infostealer literature (Recorded
Future 2025) confirms: stealers target the SQLite DB *file* and the
companion `Local State` (which holds the wrapped encryption key). If
the untrusted view cannot reach `Default/Cookies` and `Default/Local
State` *by any path*, decryption is impossible regardless of OS-
keychain access. We do not parse SQLite; we hide the directory.

**3. Active-trust artifacts: sockets and agents.**

Not all credentials are files. Several are live IPC endpoints whose
presence-in-namespace = credential-leak:

- `$SSH_AUTH_SOCK` — ssh-agent UNIX socket. Anyone who can `connect()`
  to it can sign auth challenges with loaded keys. Babbleon's
  untrusted view **must** unset `SSH_AUTH_SOCK` and not bind-mount the
  socket through.
- `~/.gnupg/S.gpg-agent{,.ssh,.browser,.extra}` — gpg-agent sockets,
  similar story.
- `XDG_RUNTIME_DIR` (`/run/user/<uid>/`) — holds keyring sockets
  (`gnome-keyring`, `dbus`), Wayland socket, pulseaudio, etc.
  Selective bind-mount is required; copying the whole dir leaks
  keyring access.
- `$DBUS_SESSION_BUS_ADDRESS` — user dbus. `secret-service` (libsecret)
  rides on dbus; an untrusted-view process talking to user dbus can
  ask `org.freedesktop.secrets` for stored credentials.

**Implication for M4:** the trusted/untrusted boundary needs a
**socket and env-var policy**, not just a file-path policy. Untrusted
view inherits *neither* `SSH_AUTH_SOCK` nor `DBUS_SESSION_BUS_ADDRESS`
nor gpg-agent sockets by default. This is a strict superset of the
file-renaming model and needs a named M4 sub-deliverable: "credential
IPC isolation."

**4. Infostealer telemetry validates the targeting list.**

Recorded Future, Pen Test Partners, and Vectra 2025 reports all
converge on:

- **Browser data** (cookies, saved logins, autofill) — primary target;
  session-cookie theft bypasses MFA. **276M credentials indexed in
  2025**; the average compromised device yielded **87 stolen
  credentials**.
- **Cloud SDK config** — AWS/GCP/Azure dotfiles explicitly enumerated.
- **VPN / SSH** — local-stored keys and configs.
- **Cryptocurrency wallets** — wallet.dat, browser extension storage.
- **Session material > passwords.** The 2025 shift: stealers prize
  *active session tokens* (browser cookies, SSO refresh tokens,
  kubeconfig exec credentials) over passwords because they bypass
  MFA. Babbleon's path-gating defeats both equivalently.

The 87-credentials-per-device average is the human-readable damage
number for the README ("Babbleon collapses the credential-yield of a
host compromise from ~87 to whatever the trusted-tier app footprint
allows — single digits in the typical case").

**5. Env-var inventory (forward reference to T8).**

The cross-tool pattern is consistent enough to record now: each tool
has 1–3 env-vars that redirect its credential search. M4 maintains a
**per-app launch-time env-var injection table**: trusted-view shell
sets the vars to real paths; untrusted-view scripts/cron inherit
neither paths nor vars.

PLAN.md §6 lists "env-var names" as a tier-1 must scramble. T8 will
go deeper, but the pattern is already visible: scramble *the var
name itself* in the untrusted view (`AWS_SHARED_CREDENTIALS_FILE` →
random compound) so even an attacker who knows the canonical SDK code
path can't `getenv()` the right key.

### Implications for the plan

1. **M4 starting set is concrete.** The 14-tool inventory above is
   the bring-up checklist. Each entry has: default path (rename in
   untrusted view), env-var override (redirect in trusted view).
2. **Path-gating is empirically correct.** Every tool surveyed
   accepts an env-var to redirect; no format-parsing is needed for
   any of them.
3. **Add IPC isolation as a named M4 sub-deliverable.** `SSH_AUTH_SOCK`,
   gpg-agent sockets, user dbus, `XDG_RUNTIME_DIR` selective bind.
   Without this, the file-only model leaks live trust handles.
4. **Browser cookies = the Recorded Future smoking gun.** Concrete
   metric for user-facing copy: 87 credentials/host → handful, when
   trusted-view footprint is small.
5. **Profile-dir granularity, not file granularity.** Bind-mount the
   *whole credential profile dir* per trusted app (per PLAN.md §6
   "per-app trusted shims"). Don't try to scramble individual files
   within a profile dir; the apps assume their own dir layout.
6. **GPG agent forwarding is a Babbleon hazard.** A trusted-tier user
   who forwards their gpg-agent socket into an untrusted-tier process
   has handed over credential access regardless of our renaming.
   Document; consider warning.
7. **Update PLAN.md §6 table** to add: browser cookies (already
   present), kubectl `~/.kube/config`, GCP ADC, Azure access tokens,
   Docker config + credentials helpers, GitHub/HuggingFace API
   tokens, package-registry tokens (npm/PyPI/Cargo).

### Confidence

- **High:** the path inventory and env-var overrides. These are
  documented APIs across mature tools.
- **High:** path-gating sufficiency. Every tool surveyed supports
  the env-var redirect pattern.
- **High:** IPC isolation requirement. Sockets are well-known live-
  trust handles.
- **Medium:** the 14-tool list completeness. There will be more in
  practice (1Password CLI, Bitwarden CLI, Vault CLI, OCI/IBM/Heroku
  CLIs, JetBrains IDE keychains). Inventory should be community-
  extensible; M4 ships the top-14 and adds a contrib mechanism.

### Open follow-ups

- Inventory **password-manager CLIs** (1Password `op`, Bitwarden
  `bw`, Vault `vault`, pass) — they have store paths and unlock
  sockets of their own.
- Inventory **IDE keychains** — VSCode token cache, JetBrains
  password store, Cursor.
- Empirical check: does each tool actually respect its env-var on
  current versions? (AWS CLI bug #7956 hints at edge cases when
  vars are partial-set.)
- Define the trusted-shim launch protocol: how does `aws` running in
  the trusted view get `AWS_SHARED_CREDENTIALS_FILE` set
  automatically? PAM session env? Wrapper binary in `$PATH`?

### Sources

- AWS CLI custom credential file locations issue #7956 — https://github.com/aws/aws-cli/issues/7956
- kubectl KUBECONFIG documentation (Microsoft) — https://learn.microsoft.com/en-us/azure/aks/control-kubeconfig-access
- `.npmrc` docs — https://docs.npmjs.com/cli/v11/configuring-npm/npmrc/
- pnpm authentication settings — https://pnpm.io/npmrc
- `.pypirc` specification — https://packaging.python.org/en/latest/specifications/pypirc/
- Cargo Registry Authentication — https://doc.rust-lang.org/cargo/reference/registry-authentication.html
- The current state of browser cookies (CyberArk) — https://www.cyberark.com/resources/threat-research-blog/the-current-state-of-browser-cookies
- Exporting browser cookies on Mac — https://maxchadwick.xyz/blog/exporting-your-browser-cookies-on-a-mac
- gpg-agent sockets / SSH (GnuPG wiki) — https://wiki.gnupg.org/AgentForwarding
- Recorded Future 2025 Identity Threat Landscape — https://www.recordedfuture.com/blog/identity-trend-report-march-blog
- Pen Test Partners: 2025, the year of the Infostealer — https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/
- DeepStrike: Infostealer Malware in 2025 — https://deepstrike.io/blog/infostealer-malware-credential-theft-2025
- Microsoft: Hunting Infostealers — macOS Threats — https://techcommunity.microsoft.com/blog/microsoftsecurityexperts/hunting-infostealers---macos-threats/4494435

---

## T8 — Environment-variable vocabulary attackers scrape

**Question:** PLAN.md §6 names env-var **names** (`AWS_*`,
`GITHUB_TOKEN`, `*_API_KEY`, `*_SECRET`) as tier-1 must-scramble. What
does the attacker actually look for? What's in the gitleaks/trufflehog
detection corpus? How does an attacker read another process's env in
practice? Where does scrambling the *name* help vs scrambling the
*value*?

**Method:** 5-angle search: common secret env-var name patterns,
gitleaks/trufflehog/detect-secrets rule corpora, official cloud SDK
env-var schemas (AWS/Azure/GCP), CI/CD secret patterns
(GITHUB_TOKEN/VAULT_*/DATABASE_URL), and `/proc/<pid>/environ` access
semantics.

### Findings

**1. Env-vars are the dominant credential channel and the easy scrape.**

> "Secrets are mostly stolen from environment variables." — CyberArk
> Developer (2024), confirmed by Recorded Future 2025 telemetry.

Three structural reasons:

- **Designed-to-be-read** by the *owning* process. `getenv()` is one
  call; no parsing, no decryption, no socket dance.
- **Inherited across `fork`/`exec`** unless explicitly stripped. A
  payload launched from a shell inherits everything in the shell's
  env.
- **Exposed via `/proc/<pid>/environ`** on Linux to anyone passing
  `PTRACE_MODE_READ_FSCREDS` (typically: same uid). A sibling process
  running as the same user can `cat /proc/<pid>/environ` of every
  other process the user owns. Babbleon's untrusted tier *running
  under the user's own uid* gets `/proc/<pid>/environ` access by
  default — this is the leak vector PLAN.md §6 promises to address
  via PID-namespace + `hidepid=2`. Confirms T11 priority.

**2. Detection-rule corpora as a proxy for attacker target list.**

Gitleaks (~60 rules) and TruffleHog v3 (~790 detectors, ~800+ secret
types) define empirically what attackers go after. Cross-referenced
patterns:

- **Cloud SDK family:**
  `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
  `AWS_PROFILE`, `AWS_REGION`, `AWS_SHARED_CREDENTIALS_FILE`,
  `AWS_CONFIG_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`.
- **GCP family:**
  `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_PROJECT`,
  `CLOUDSDK_*` (~50 vars in `CLOUDSDK_<section>_<property>` form),
  `GCLOUD_PROJECT`.
- **Azure family:**
  `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`,
  `AZURE_SUBSCRIPTION_ID`, `AZURE_CONFIG_DIR`.
- **VCS / SCM:**
  `GITHUB_TOKEN`, `GH_TOKEN`, `GITLAB_TOKEN`, `BITBUCKET_TOKEN`.
- **CI/CD:**
  `CI_JOB_TOKEN`, `JENKINS_API_TOKEN`, `CIRCLECI_TOKEN`, the entire
  `GITHUB_*` GHA injected-context family.
- **Service tokens:**
  `STRIPE_SECRET_KEY`, `STRIPE_API_KEY`, `SENDGRID_API_KEY`,
  `TWILIO_AUTH_TOKEN`, `SLACK_TOKEN`, `SLACK_BOT_TOKEN`,
  `DISCORD_TOKEN`, `MAILGUN_API_KEY`, `DOCKERHUB_PASSWORD`,
  `NPM_TOKEN`, `PYPI_TOKEN`.
- **AI/LLM tokens (new and rapidly expanding 2024–2026):**
  `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `HF_TOKEN`,
  `HUGGING_FACE_HUB_TOKEN`, `REPLICATE_API_TOKEN`, `COHERE_API_KEY`,
  `MISTRAL_API_KEY`, `GROQ_API_KEY`, `TOGETHER_API_KEY`.
- **Secrets-manager bridge:**
  `VAULT_TOKEN`, `VAULT_ADDR`, `VAULT_NAMESPACE`,
  `DOPPLER_TOKEN`, `1PASSWORD_*`, `OP_SERVICE_ACCOUNT_TOKEN`.
- **Database:**
  `DATABASE_URL`, `POSTGRES_PASSWORD`, `MYSQL_PWD`,
  `MONGO_URI`, `REDIS_URL`.
- **Generic wildcards (the dominant filter):**
  `*_TOKEN`, `*_SECRET`, `*_KEY`, `*_PASSWORD`, `*_PWD`, `*_API_KEY`,
  `*_CREDENTIALS`. Attacker code typically does this filter first,
  then dispatches on prefix.

**Implication for Babbleon:**

a) **The "*_TOKEN / *_SECRET / *_KEY / *_PASSWORD / *_API_KEY" wildcard
filter is the actual primary attack pattern**, not the named-list
match. Babbleon must scramble names so they **do not match these
suffixes** in the untrusted view. Concretely: in the untrusted view,
the canonical-suffix vars are *renamed away* and *removed* from the
environment Block; the values live (if at all) under random compound
names known only to the trusted-tier app that reads them. The
wildcard-filter pattern is unequivocally Babbleon's weak point if we
preserve the canonical suffixes.

b) The named-list match is also relevant; the inventory above (50+
patterns) is the M3 starting list for the scramble table, expandable
via community-maintained rules (mirror the gitleaks/trufflehog
schemas — they're MIT/Apache).

c) **AI-SDK vars are an emerging class.** `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY` etc. are now the highest-leverage tokens on dev
machines (API budget = real money, model access). Recently
expanded; Babbleon's scramble list needs to track this rapidly-
growing family. Add a v1 must.

**3. The leak surfaces are well-understood.**

Three leak channels for env vars, all attacker-tractable:

- `/proc/<pid>/environ` (Linux). Same-uid read on most systems.
  PLAN.md §6 row "Standard system paths (/proc/*/environ)" addresses
  this at v2 with hidepid=2.
- `ps eww` (BSDish; Linux supports via `/proc/<pid>/environ`).
- **Process inheritance from a shell.** If the user `source`s a
  `.env` into their interactive shell, every child inherits. A
  payload spawned in the untrusted tier inherits whatever the
  untrusted shell was started with.

This last channel is the one Babbleon *cleanly* handles: at the
trusted/untrusted boundary, **the env is rewritten by the spawn
machinery**. Untrusted-tier shells start with an env stripped of all
canonical-suffix vars; trusted-tier shells get the real env. The
namespace boundary does the work; we don't need to touch `getenv()`.

**4. Scrambling the *value* is harder and probably unnecessary.**

Renaming `AWS_SECRET_ACCESS_KEY` → `<scrambled>` in the untrusted view
defeats wildcard-suffix filtering. **Renaming the value** (e.g.
encrypting and re-encoding it) would require the trusted-tier app to
know how to decrypt — duplicating the credential-store mechanism.
We don't need value scrambling: the untrusted tier doesn't get the
canonical-name var *at all*, and the value (if present under a
random-named var) is meaningless without knowing what app expects it.

The right model: **names live in the per-host mapping; the
untrusted view has neither the var nor the canonical name; the
trusted view's app-launch shim injects the canonical name pointing
to the real value at exec time**.

**5. CI/CD context is out of scope but informs the design.**

`GITHUB_TOKEN`, `CI_JOB_TOKEN`, `GHA secrets.*` are runtime-injected
by the CI runner. Babbleon doesn't run on GitHub Actions hosted
runners (it's a host-OS layer). But the **patterns** the CI ecosystem
established (env-var injection per build step, short-lived OIDC
tokens, scoped permissions) are exactly the right model for
Babbleon's trusted-app launcher: inject only the env the named
trusted app needs, scoped to its run.

**Implication:** the M4 trusted-shim launcher should mirror GitHub
Actions' `secrets: ${{ secrets.NAME }}` model — declare the env-vars
each trusted app needs in its manifest; the launcher injects them at
exec, strips them from inherited env.

### Implications for the plan

1. **Wildcard-suffix scramble is *the* primary defense, not the
   named-list scramble.** Update PLAN.md §6 prose: "Env-var
   *suffixes* matching `*_TOKEN`/`*_SECRET`/`*_KEY`/`*_PASSWORD`/
   `*_API_KEY`/`*_CREDENTIALS`/`*_PWD` are stripped from the untrusted
   env by name; canonical names are renamed in the per-host mapping;
   values exist only in the trusted view, injected per-app at launch."
2. **M3 starting scramble table = the 50+ patterns above**, with
   gitleaks/trufflehog rule mirrors as the upgrade path.
3. **AI-SDK token family is must-have for v1.** `ANTHROPIC_API_KEY`,
   `OPENAI_API_KEY`, `HF_TOKEN`, etc. These are the *highest-leverage*
   tokens on a 2026 dev machine and the family is growing monthly.
4. **`/proc/<pid>/environ` is the kernel-side leak.** Confirms T11
   priority: untrusted tier needs PID namespace + `hidepid=2`, not
   just mount namespace. Mount namespace alone leaks every other
   process's env to a same-uid attacker.
5. **App-launcher injection model.** M4 trusted-shim spec needs a
   per-app manifest declaring which env-vars to inject. Mirror GHA
   `secrets: NAME` declaration syntax — well-understood pattern.
6. **Value-scrambling is out of scope.** Renaming + IPC-isolation is
   sufficient; don't duplicate the credential-store mechanism.

### Confidence

- **High:** the wildcard-suffix filter is the dominant attacker
  pattern. The detection-rule corpora and incident telemetry agree.
- **High:** `/proc/<pid>/environ` leak semantics; well-documented
  kernel behavior.
- **High:** the AI-SDK token family is the new high-value target.
  Subjective but well-supported by 2025–2026 incident write-ups.
- **Medium:** the 50+ pattern starting list. Definitely incomplete;
  designed to be extended via gitleaks/trufflehog rule import.
- **Medium:** the app-launcher injection model. Right shape; details
  (manifest format, signing, capability scoping) need a design pass
  before M4.

### Open follow-ups

- Mirror gitleaks `.gitleaks.toml` and trufflehog detector schemas;
  pick the env-var-name rules; ship as Babbleon's default mapping
  seed list. License: MIT / Apache 2.0 — clean.
- Track AI-SDK token namespace growth quarterly; the family expands
  with every new model vendor.
- Spec the app-launcher manifest format. Borrow from systemd unit
  files? Bespoke YAML? Compose with Linux capabilities and seccomp.
- Resolve interaction with `.env`-loading tools (`dotenv`,
  `direnv`, `mise`). They load `.env` files into shells; if the
  shell is in the trusted view, the env lives in trusted view.
  Untrusted-view shells should refuse to source `.env` files
  located in trusted-view-only paths.

### Sources

- proc_pid_environ(5) — https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html
- Group-IB: Linux /proc filesystem manipulation — https://www.group-ib.com/blog/linux-pro-manipulation/
- CyberArk: Environment Variables Don't Keep Secrets — https://developer.cyberark.com/blog/environment-variables-dont-keep-secrets-best-practices-for-plugging-application-credential-leaks/
- TruffleHog vs Gitleaks comparison (Jit) — https://www.jit.io/resources/appsec-tools/trufflehog-vs-gitleaks-a-detailed-comparison-of-secret-scanning-tools
- Secrets Patterns DB (Mazin Ahmed) — https://mazinahmed.net/blog/secrets-patterns-db/
- google.auth.environment_vars docs — https://google-auth.readthedocs.io/en/latest/reference/google.auth.environment_vars.html
- gcloud CLI properties / env-var schema — https://cloud.google.com/sdk/docs/properties
- GitHub: Securing CI/CD pipelines with secrets — https://resources.github.com/learn/pathways/automation/advanced/securing-ci-cd-pipelines-with-secrets-and-variables/
- HashiCorp: Secure CI/CD secrets — https://developer.hashicorp.com/well-architected-framework/secure-systems/secure-applications/ci-cd-secrets

---

## T9 — Package manager hook surfaces (dpkg / rpm / brew / flatpak / snap)

**Question:** PLAN.md §9 commits to running package managers in an
"audited maintenance namespace on real names; a post-install hook
assigns mappings to new binaries inside the transaction." §10 names the
install-window race as a known-open. What hook surfaces actually exist
on each package manager? Where do we attach? What's the install-window
race in concrete terms? What changes per ecosystem?

**Method:** 5-angle search across dpkg/APT, rpm/dnf, Homebrew, Flatpak/
Snap, and package-manager TOCTOU literature.

### Findings

**1. APT / dpkg — well-supported, two attach points.**

Two clean hook surfaces:

- **APT hooks** in `/etc/apt/apt.conf.d/`. Configuration-file entries:
  `DPkg::Pre-Invoke { "cmd"; }`, `DPkg::Post-Invoke { "cmd"; }`,
  `APT::Update::Post-Invoke { "cmd"; }`. Fire around the entire APT
  transaction (before/after `dpkg` runs). Multiple hook files execute
  alphabetically; numeric prefixes control order.
- **dpkg triggers** (`/var/lib/dpkg/triggers/`). Lower-level; requires
  ship­ping a Babbleon package that registers a trigger on
  `/usr/bin`. Triggers fire mid-transaction when other packages touch
  the watched path. More precise than APT hooks but tied to dpkg's
  trigger lifecycle.

**Recommended attach point: APT post-invoke hook**, supplemented by a
dpkg trigger on `/usr/bin` (and `/usr/local/bin`, `/usr/sbin`) for
direct-dpkg invocations bypassing APT. Two-layer coverage: APT covers
the common case; the trigger catches `dpkg -i foo.deb`.

Hook script responsibilities: enumerate post-transaction set of new/
removed binaries (`dpkg-query -W -f='${Conffiles}\n'` and diff-against-
mapping); assign random compound names; commit mapping to the vault;
update the bind-mount table; signal active namespaces to re-bind.

**2. RPM / DNF — plugin API + scriptlets + post-transaction-actions plugin.**

Three attach points, increasing in cleanliness:

- **RPM scriptlets** (`%post` in package spec) — ship a Babbleon
  package whose `%post` runs the mapping-assignment for *itself*.
  Doesn't help us cover *other* packages.
- **RPM plugin API** (`scriptlet_pre`/`scriptlet_post`/`tsm_pre`/
  `tsm_post`). Native C plugin, loaded by rpm at transaction start.
  Fine-grained but heavier engineering.
- **DNF plugin API** (`transaction` hook called after successful
  transaction) and the **`dnf-plugins-core` post-transaction-actions
  plugin** (declarative config in
  `/etc/dnf/plugins/post-transaction-actions.d/*.action`, format
  `package_filter:transaction_state:command`).

**Recommended attach point: DNF post-transaction-actions plugin.**
Declarative, easy to ship, covers the common case. Fall back to an
RPM plugin if we need to gate the transaction mid-flight (we
probably don't for v1).

**3. Homebrew — formula post_install, brew bundle, no global hook.**

Homebrew has no global post-install hook. **Open issue #2202** in the
Homebrew repo (still open as of 2026) explicitly tracks a feature
request for pre/post-install hooks at the brew level. Three
workarounds:

- **Per-formula `post_install` block** in formula DSL — only works if
  we ship every formula (we don't).
- **`brew bundle`'s `postinstall:` directive** in `Brewfile` — only
  fires for that bundle, not arbitrary brew invocations.
- **Wrap `brew` itself** — symlink `brew` to a Babbleon shim that
  invokes real brew and then runs the mapping-assignment.

**Recommended attach point on macOS: shim `brew` itself.** Cleanest of
bad options. Document the lack of a native hook surface as an
ecosystem limitation; submit an upstream feature request that aligns
with #2202.

**4. Flatpak / Snap — sandboxed apps, mostly *don't need* scrambling.**

Both Flatpak and Snap install apps into per-app sandboxes:

- **Flatpak** mounts each app under `/app/bin` inside a bubblewrap
  sandbox. Apps see their own restricted PATH; host `/usr/bin` is
  not visible inside the sandbox.
- **Snap** uses `snap-confine` to set up per-app mount namespaces.
  Each snap sees `/home/user/snap/<name>/<rev>/` as its home; host
  PATH is similarly isolated.

**Implication:** the *binaries themselves* installed by Flatpak/Snap
live in sandboxes Babbleon's untrusted-tier attacker can't easily
reach via the canonical-PATH route. **What we still need to scramble**
are the **`flatpak run org.foo.Bar`** and **`snap run foo`** entry-
point commands themselves (which live in host `/usr/bin/flatpak`,
`/usr/bin/snap`), and the **app-IDs** an attacker would invoke. App-IDs
are reverse-DNS strings (`org.mozilla.firefox`) — a different name
space from binary names but the same scramble logic applies.

For v1: scramble the host-side flatpak/snap CLIs (already covered by
the general `/usr/bin` mechanism). Don't try to penetrate the per-app
sandboxes; they're already isolated. v2: optionally scramble app-IDs
in the per-namespace flatpak/snap registry.

**5. The install-window race (PLAN.md §10) is real and has a fix.**

The race: between the moment a new binary `/usr/bin/foo` lands on disk
and the moment Babbleon assigns it a scrambled name and updates the
mount table, an untrusted-tier process can `open()` the canonical
path `/usr/bin/foo` directly. Window is short but exploitable by a
patient attacker spinning on `stat()`.

**Fix: run the package transaction in a dedicated *maintenance
namespace*.**

Concretely:

- Babbleon spawns a transient mount namespace at transaction start.
  The namespace has **the real `/usr/bin`** (i.e. the trusted view).
- The package manager runs *inside* that namespace; `dpkg`/`rpm`
  writes binaries to real names there.
- The new binaries are **not yet visible** in any *other* namespace
  (untrusted views, currently-running scrambled shells) because mount
  propagation is set to `private` outward.
- Post-transaction hook runs, computes the new mapping, atomically
  updates the bind-mount tables in *every* attached namespace via
  a small helper that uses `setns()`+`mount(MS_BIND)` per namespace.
- Only after the atomic update do the new binaries become reachable
  (under scrambled names) from untrusted namespaces.

This closes the race by design: the new binary *never exists under
its canonical name in any untrusted namespace*. The maintenance
namespace is the kernel-enforced quarantine.

Reference: util-linux mount(8) TOCTOU advisory (GHSA-qq4x-vfq4-9h9g)
documents the symmetric attack class — path validated, then re-
canonicalized at use, with a race window between. The mitigation
pattern (use file descriptors not paths between phases, hold
operations open across the entire flow) applies directly.

**6. The "needs real view" manifest for cron / systemd / scripts.**

PLAN.md §9 promises "admin tags specific units 'needs real view' with
justification (manifest)." Concrete shape borrowed from the env-var
injection model in T8:

```
[babbleon-grant]
unit = postgresql.service
needs-real-view = true
allowed-binaries = postgres,psql,pg_ctl
allowed-credentials = ~/.pgpass
justification = "DB needs canonical postgres binary at boot."
signature = <admin-key signature over above fields>
```

Justification + signature is the operational pattern: any persistent
service granted the trusted view is recorded with a reason, signed by
an admin key. Forms the audit log automatically.

### Implications for the plan

1. **Per-ecosystem attach-point table:**

   | Ecosystem | Attach point | v1 effort |
   |---|---|---|
   | APT/dpkg (Debian/Ubuntu) | `/etc/apt/apt.conf.d/99babbleon` + dpkg trigger on `/usr/bin` | low |
   | RPM/DNF (Fedora/RHEL) | DNF `post-transaction-actions` plugin | low |
   | Homebrew (macOS) | shim `brew` binary | medium |
   | Flatpak | scramble host-side `flatpak` CLI only; app IDs v2 | low |
   | Snap | scramble host-side `snap` CLI only | low |
   | snap/flatpak per-app sandboxes | N/A — already isolated | n/a |

2. **Maintenance-namespace pattern is the install-window-race fix.**
   Update PLAN.md §10 from "Mitigation: hook runs inside the package
   transaction; new binary invisible to untrusted namespaces until
   commit. Design carefully in M3." → name the maintenance-namespace
   architecture explicitly: transient mount NS, private propagation
   outward, atomic cross-namespace bind update post-transaction.
3. **Homebrew is a recognized limitation.** No native hook surface;
   shim is the workaround; track upstream issue #2202.
4. **Flatpak/Snap app sandboxes shrink Babbleon's surface helpfully.**
   We don't need to penetrate them; the host-side CLIs are the only
   attack-relevant binaries.
5. **`/usr/local/bin`, `/opt/`, language-package binaries
   (`~/.cargo/bin`, `~/.local/bin`, `node_modules/.bin`)** are not
   covered by system package managers. Need separate hook: a watcher
   on these dirs (inotify) that assigns mappings on add/remove. M3
   sub-deliverable.
6. **Manifest format with signature** for "needs real view" grants.
   Borrow systemd unit syntax; admin key signs the manifest; audit
   trail comes for free.

### Confidence

- **High:** APT and DNF hook surfaces. Documented, mature, widely used.
- **High:** Flatpak/Snap sandbox isolation reducing Babbleon's host-
  side surface.
- **Medium:** the maintenance-namespace install-window fix. Architecturally
  clean; needs prototyping against real `apt upgrade` with mid-flight
  inotify monitoring before M3 ships.
- **Medium:** Homebrew shim approach. Works but fragile to brew
  upstream changes; upstream feature request is the long-term fix.
- **Medium:** `~/.cargo/bin`-style language-PMs. The inotify watcher
  works but is a different mechanism — separate codepath.

### Open follow-ups

- Prototype maintenance-namespace transition: `apt upgrade` inside a
  transient namespace with `mount --make-private` outward, post-
  transaction `setns()`+rebind sweep.
- Inotify watcher for `~/.cargo/bin`, `~/.local/bin`, `~/.npm-global/
  bin`, `pipx`/`uv`/`rye` venvs. Language-PM coverage.
- Submit upstream Homebrew issue: machine-readable post-install hook
  in `brew` itself. Reference issue #2202.
- Investigate Nix/Guix interaction: store-based PMs use content-
  addressed paths, not canonical names — possibly orthogonal or
  possibly a clean integration point. Worth a follow-up.

### Sources

- APT hooks/triggers (oneuptime tutorial) — https://oneuptime.com/blog/post/2026-03-02-how-to-configure-apt-hooks-and-triggers-on-ubuntu/view
- dpkg(1) — https://man7.org/linux/man-pages/man1/dpkg.1.html
- DNF Plugin Interface — https://dnf.readthedocs.io/en/latest/api_plugins.html
- DNF post-transaction-actions plugin — https://dnf-plugins-core.readthedocs.io/en/latest/post-transaction-actions.html
- RPM Plugin Interface (DRAFT) — https://rpm-software-management.github.io/rpm/manual/plugins.html
- Homebrew issue #2202 (pre/post-install hooks feature request) — https://github.com/Homebrew/brew/issues/2202
- Homebrew Brew-Bundle-and-Brewfile docs — https://docs.brew.sh/Brew-Bundle-and-Brewfile
- Flatpak sandbox wiki — https://github.com/flatpak/flatpak/wiki/Sandbox
- Flatpak command reference — https://docs.flatpak.org/en/latest/flatpak-command-reference.html
- util-linux mount(8) TOCTOU advisory — https://github.com/util-linux/util-linux/security/advisories/GHSA-qq4x-vfq4-9h9g

---

## T10 — Binary fingerprinting countermeasures

**Question:** PLAN.md §2a-1 promotes binary-identity obfuscation
(`--help`, `strings`, `ldd`, magic bytes) from "nice-to-have" to
"M3-critical." T2 confirms this via the ObserverWard/Wappalyzer
finding: agentic harnesses index *output signatures*, not just names.
What's the actual menu of fingerprinting techniques an attacker uses
on a host binary? Which are tractable to disrupt? What's the
cost/benefit of each countermeasure?

**Method:** 5-angle search across ELF symbol stripping, web fingerprint
tools (WhatWeb/Nikto/Wappalyzer), YARA rules + obfuscation detection,
ldd security and binary-code fingerprinting taxonomies, ObserverWard
specifically.

### Findings

**1. The fingerprinting taxonomy is well-mapped.**

ACM Computing Surveys ("A Survey of Binary Code Fingerprinting
Approaches," Alrabaee et al. 2022) gives the canonical taxonomy. For
Babbleon, the attacker-relevant categories on an in-tree binary are:

| Category | Mechanism | Babbleon attack surface |
|---|---|---|
| **Name + path** | `which curl`, `/usr/bin/curl` exists | scrambled by mount-NS (T3) |
| **Help text** | `binary --help` / `-h` / `--version` | banner-spoof candidate |
| **String table** | `strings binary \| head` | `strip` removes some; embedded const strings remain |
| **Symbol table** | `nm binary`, `readelf -s` | `strip --strip-all` removes |
| **Dynamic deps** | `ldd binary`, `readelf -d` | hard — depends on linked libs |
| **Magic bytes / file type** | `file binary` | ELF header always identifies as ELF |
| **Section structure** | `readelf -S`, custom sections | mostly stable; can re-section |
| **Hash / VirusTotal** | `sha256sum binary` | per-host random padding bytes |
| **Behavioral / output signature** | `binary --version` parsed output | banner-spoof |
| **YARA-rule matches** | string + byte-pattern rules | adversarial wrt strip + content patching |

**2. Stripping helps but the strings survive.**

`strip --strip-all` removes the symbol table; combined with
`-fvisibility=hidden` and `-s` at link time you can produce a binary
with no debug info, no symbol table, no `.comment` section.

But — per Tavis Ormandy ("Unstripping Stripped Binaries"), and the
Cerbero blog — **the data section's constant strings always survive
stripping** because the program needs them at runtime. `curl --help`
embeds the help text as a constant string in `.rodata`; you cannot
strip it without breaking curl.

This is the load-bearing technical truth for Babbleon: stripping is
*necessary but insufficient*. We also need to **rewrite or gate the
data section** at runtime, or **wrap binaries with thin loaders**
that intercept the canonical output paths.

**3. Three viable countermeasure architectures.**

**a) Strip + content-patch.** Build (or post-build patch) replacement
binaries with `.rodata` strings replaced. Pros: zero-runtime-cost
fingerprint distortion. Cons: enormous engineering surface (every
binary individually patched, breaks on package updates), brittle to
the package-manager hook flow. **Verdict:** rejected for v1.

**b) Banner-spoofing loader wrapper.** Replace `/usr/bin/curl` (in
untrusted view) with a thin wrapper. Wrapper:
- For trust-tier-gated invocations (`--help`, `--version`, identifiable
  fingerprint probes), returns plausible-wrong or scrambled output.
- For real invocations, `execve`s the real curl from the trusted-only
  path.
- Inspects environment + parent process trust tier to decide.

Pros: minimal per-binary engineering — one generic wrapper, parameterized
by binary. Cons: an attacker who `cat`s the binary or runs it through
`ldd`/`strings` sees the *wrapper's* fingerprint, not curl's. That's
fine — the wrapper's fingerprint is also a scrambled-looking blob.
Real curl is reachable only from trusted tier and lives at a scrambled
path. **Verdict: v1 baseline.**

**c) Deception: plausible-wrong banners.** Instead of "command not
found" or random garbage, the wrapper returns *another tool's* help
text. `--help` on `<scrambled-curl>` returns nano's help text;
`<scrambled-ssh>` returns calculator output. Forces the agent to
*believe* it found a different tool and act on that belief, wasting
the recon budget and triggering high-IDS-signal misbehavior.

Pros: actively hostile, not just obstructive. Compounds the
mis-targeting benefit PLAN.md §5 already named for binary *names*
(curl→calculator). Cons: requires a wordlist-style "plausible-wrong
banner library." Worthwhile because the wrapper code is the same;
only the response table changes.
**Verdict: v1 stretch, v2 default.**

**4. Banner-spoofing has the threat-model coverage we need.**

From T2: ObserverWard, Wappalyzer, WhatWeb all work on **response
patterns** — HTTP headers, banner text, version strings. WhatWeb has
**1800+ plugins**, each a regex over response output. Babbleon's
wrapper only needs to ensure that the response *patterns* an
attacker-side fingerprint database has indexed do not match what
Babbleon binaries return when probed by untrusted-tier processes.

This is empirically tractable: the patterns are public (Wappalyzer is
MIT-licensed; WhatWeb plugins on GitHub). We can **adversarially test**
our banner-spoofing against the public fingerprint corpora before
shipping — closing the loop empirically rather than hoping.

**5. `ldd` is a security disaster on the offense side, which works for us.**

`ldd` *executes the binary* with `LD_TRACE_LOADED_OBJECTS=1` to extract
dependencies. **Running ldd on an untrusted binary executes arbitrary
code in the binary's ELF interpreter** (Julio Merino's writeup is the
canonical reference; the Linux man page warns explicitly).

Defensive implications:

- An attacker `ldd`-ing one of our wrapped binaries triggers the
  wrapper's code path → another chance for the wrapper to spoof the
  reported deps, or even to fire a honey-mapping IDS signal ("untrusted
  process invoked `ldd` on a scrambled binary").
- Conversely, the *legitimate* uses of `ldd` in Babbleon's
  maintenance namespace must use `objdump -p` / `readelf -d` instead
  (safe, no execution).

**6. YARA-rule adversarial cost is favorable to us.**

YARA rules match string and byte patterns. With control over the
binary content (we ship the wrapper), we can make the wrapper match
*no useful rule* — pick patterns deliberately not present in
mainstream YARA-rule databases. We can also fire **honey-YARA-
collisions**: make the wrapper match a known benign rule (e.g.,
`Detect_BusyBox`) so the attacker's classifier confidently
mis-identifies it.

The cost asymmetry is real: writing one robust YARA rule takes hours;
generating a binary that evades or mis-classifies takes a generator
script we write once. The literature ("Assessing the Effectiveness of
YARA Rules," arXiv 2111.13910) acknowledges YARA's brittleness
against deliberately-engineered evasion.

**7. What does *not* work: pretending it isn't ELF.**

Magic-byte spoofing (e.g., trying to make the binary look like a
shell script) requires kernel support and breaks `execve`. Don't try.
The attacker can always determine "this is an ELF" from `file binary`;
we accept that and concentrate the deception on *which* ELF.

### Implications for the plan

1. **M3-critical deliverable: the banner-spoofing wrapper.** Generic
   thin loader; per-binary wrapped via a build script that takes
   `real_path` + `name_for_strings` + `banner_table`. Strips heavily,
   no `.comment`, no debug info.
2. **The wrapper is the binary-identity-obfuscation primitive PLAN.md
   §2a-1 named.** Update PLAN.md §10 "Fingerprint obfuscation" row from
   "hard and ongoing" → "banner-spoofing wrapper; M3 ships baseline
   stripped+null-output, M3.5 adds plausible-wrong banner deception."
3. **Adversarial test against public fingerprint corpora.** Before M3
   release: run our wrapped binaries against Wappalyzer, WhatWeb's
   plugins, ObserverWard. Hit count → 0 is the bar.
4. **Deception banner library is a community-extensible asset.**
   Like the wordlist (T13): seed with a couple hundred plausible
   `--help` outputs scraped from real tools (license clean); accept
   community contributions.
5. **`ldd` invocations on untrusted-tier binaries are an IDS
   tripwire.** They're *both* fingerprinting attempts *and*
   arbitrary-code-execution chances we can detect via the wrapper
   itself. Wire to the honey-mapping IDS hook (T4 §3).
6. **Hash-based identification has a low-cost defeat.** Append per-host
   random padding bytes (in a no-op padding section) so two Babbleon
   hosts never share a binary hash. Defeats VirusTotal-style
   identification of our wrappers across hosts. ~16 bytes is enough.
7. **The wrapper must be tier-aware.** Reads its caller's
   `/proc/self/status` or equivalent to determine trust tier; behaves
   differently. The mechanism: untrusted tier sees the wrapper at the
   scrambled path; the wrapper itself is the same binary; behavior
   diverges on detected caller context.

### Confidence

- **High:** the fingerprinting taxonomy and the inadequacy of `strip`
  alone (constant strings survive).
- **High:** banner-spoofing wrapper is the right v1 architecture.
- **High:** WhatWeb / Wappalyzer / ObserverWard are tractable to
  adversarially test against; they're rule-driven and open.
- **High:** `ldd`-as-execution is a documented Linux behavior, real
  attack surface, real IDS opportunity.
- **Medium:** deception banner library quality. The idea is right; the
  curation effort is real and grows with the wrapped-binary set.
- **Medium:** caller-tier detection from inside the wrapper. The
  mount-namespace path the wrapper was reached through is the
  signal; encoding that reliably needs careful design.

### Open follow-ups

- Prototype generic wrapper: `babbleon-wrap <real-bin> <name> <banner-
  table>` → emits stripped null-output binary. Verify against
  WhatWeb/Wappalyzer/ObserverWard corpora.
- Curate v1 banner-spoof table (50 most-fingerprinted dev/recon tools:
  curl, wget, ssh, nmap, nc, python, bash, git, gcc, …). Each gets a
  plausible-wrong response per `--help`/`--version`.
- Decide caller-tier detection mechanism for the wrapper (probe
  `/proc/self/mountinfo`? read a known-named env var injected by the
  trusted-shim launcher? rely purely on which namespace executed
  us?).
- Per-host random padding bytes design: which ELF section? How is the
  per-host value derived (from the vault) and applied at install time?

### Sources

- "Unstripping Stripped Binaries" (Tavis Ormandy) — https://lock.cmpxchg8b.com/symbols.html
- Stripping symbols from an ELF (Cerbero Blog) — https://blog.cerbero.io/stripping-symbols-from-an-elf/
- strip (GNU Binutils) — https://sourceware.org/binutils/docs/binutils/strip.html
- "A Survey of Binary Code Fingerprinting Approaches" (ACM CSUR 2022) — https://dl.acm.org/doi/10.1145/3486860
- ldd(1) — Julio Merino: "ldd and untrusted binaries" — https://jmmv.dev/2023/07/ldd-untrusted-binaries.html
- ldd(1) Linux man page — https://linux.die.net/man/1/ldd
- WhatWeb / Wappalyzer recon overview — https://hackertarget.com/whatweb-scan/
- OWASP: Fingerprint Web Application Framework — https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework
- ObserverWard repo — https://github.com/HLY-TW/ObserverWard
- "Assessing the Effectiveness of YARA Rules" (arXiv 2111.13910) — https://arxiv.org/pdf/2111.13910
- awesome-yara (InQuest curated YARA rule list) — https://github.com/inquest/awesome-yara

---
