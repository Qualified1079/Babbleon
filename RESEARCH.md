# Babbleon — Research Log

Living document. Topics from `PLAN.md` §12 + the agreed research slate, worked
through one at a time. Each section records: question, method, findings,
implications for the plan, open follow-ups.

Status legend: ⬜ not started · 🟡 in progress · ✅ done · 🟥 blocked

## Tier 1 — decision-blocking

- ✅ **T1. Moving Target Defense vs LLM/automated attackers** — prior art sweep
- ⬜ **T2. Agentic-exploitation capability literature** — what current LLM exploit harnesses actually do
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

- Cox et al., "N-Variant Systems: A Secretless Framework for Security through
  Diversity" — https://www.cs.virginia.edu/~evans/pubs/nvariant/html/nvariant.html
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
