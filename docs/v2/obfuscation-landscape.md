# Obfuscation landscape — v2 research

Survey of obfuscation techniques beyond the five layers already in
`docs/v2/structure-scrambling.md`, with an honest assessment of which
ones add value for Babbleon's threat model and which are theatre.

Triggered by operator questions on 2026-06-15:

- Mixed LTR/RTL languages and direction scrambling
- Other obfuscation methods
- Why not just encrypt the source code with normal crypto?

Each section answers the question, files the relevant research, and
maps onto v2 phases.

---

## 1. RTL/LTR / direction tricks

### Display-layer bidi (Unicode bidi controls in source)

**Technically:** Unicode bidirectional algorithm (UAX #9) handles
mixed-direction text at the *rendering* layer.  Source files on disk
are byte-ordered; the runtime reads bytes in storage order; Python /
sh / C readers don't care about bidi.  The display engine reorders
characters for human reading, but the bytes the kernel exec sees
are unchanged.

**For LLM attackers:** zero defence value.  Attacker models work
over byte sequences; whether the renderer shows the bytes
right-to-left or left-to-right is invisible to them.  Only fools
humans and screenshot-OCR pipelines.

**For Trojan Source attacks:** the technique is the basis of
CVE-2021-42574 (Boucher & Anderson, USENIX Security 2023 reprint).
Bidirectional control characters in source code can make malicious
code appear benign by reordering display vs logical order.  Every
modern compiler / linter detects and flags bidi runs:

- Rust: built-in lint via `rust-lang/rust` PR #90462.
- Python: bidichk and similar.
- Red Hat: working with upstream tooling to add diagnostics across
  the ecosystem.

**If Babbleon emitted bidi-mixed source, every linter on the host
would fire.**  Bad UX, bad signal-to-noise vs actual Trojan Source.

**Verdict: skip.**  Display bidi is theatre against LLMs and
collides with anti-Trojan-Source defences.

### Logical direction scramble (segment byte-reversal with markers)

A real obfuscation layer: reverse the byte order of marked
segments in the source.  The preprocessor locates direction
markers, reverses the marked segments before emitting to the
interpreter.

**For LLM attackers:** real (modest) value.  A model scanning the
file naturally has to mentally reverse the marked segments.
Composes with whitespace-as-words (layer 3): the attacker can't
even tell where a segment starts because there are no line
breaks.

**The marker-as-attacker-target objection — resolved.**  Initial
filing flagged that direction markers themselves could be picked
out and inverted-by-rule.  Operator (2026-06-15) corrected this:
**the marker wordlist gets the same defence-in-depth as the
identifier wordlist.**  Specifically: dedicate ~20 000 words per
epoch to "this is a direction marker".  Compounds are wordlist
concatenations as in layer 1.

Example: in compound `CRAIGBLASTFLIP`, if `craig` and `blast` are
junk-decoy tokens (layer 5) and only `flip` is the direction
marker — an attacker who somehow learned that `flip` belongs to
the marker class still doesn't know which sub-token of any given
compound IS the marker.  Three plausible markers per compound and
a 20k-marker-wordlist-per-epoch turns marker extraction into the
same problem as identifier extraction: not solvable without the
per-host secret.

**Costs (revised):**

- Preprocessor complexity — must locate markers without ambiguity
  (token-position rule + wordlist membership check).
- Marker wordlist allocation: ~20k words per epoch from the same
  large pool that feeds layers 1-5.  Disjoint subsets per role
  to prevent cross-class leakage.
- Adds latency to preprocessor (one extra pass).

**Verdict: file as v2 layer 6 (after the existing 5).**  Now
mid-priority, because the marker-as-target objection is closed.
Still ranks below whitespace-as-words because the gain is
smaller per-byte.

Sources:

- [Trojan Source — Boucher & Anderson, USENIX Security 2023](https://www.usenix.org/system/files/sec23fall-prepub-151-boucher.pdf)
- [Rust PR #90462 — bidi lint](https://github.com/rust-lang/rust/pull/90462)
- [Red Hat RHSB-2021-007](https://access.redhat.com/security/vulnerabilities/RHSB-2021-007)

---

## 2. Control-flow obfuscation

The malware-obfuscation literature has decades of techniques here.
Most are evaluated against decompilers and static analysers; the
question for v2 is whether they also work against LLM-based
attackers.

### Control-flow flattening (Obfuscator-LLVM, Tigress)

The classical technique: replace structured control flow (if/else,
loops, nested calls) with a giant state machine — every basic block
becomes a case in one big `switch`, dispatched by a state register.
Used by Obfuscator-LLVM and Tigress for over a decade as defence-
in-depth for malware (and the same defenders' AAA games).

**Against LLM attackers — surprising result:**

[Recent MDPI 2024 work](https://www.mdpi.com/2504-4990/7/4/125)
shows ML classifiers achieve **97–98% accuracy** detecting that
flattening was applied (Tigress switch-flattening, OLLVM
if-nest-flattening).  Detection ≠ defeat — the attacker still has
to *unflatten* — but tools like
[D810](https://www.eshard.com/blog/d810-a-journey-into-control-flow-unflattening)
and
[CaDeCFF](https://dl.acm.org/doi/10.1145/3545258.3545269) automate
the unflattening with high success rates.

**Practical implication:** flattening alone is not enough.
Composed with Babbleon's identifier + operator + whitespace
scrambling, the unflattening pass has to operate on already-
scrambled tokens, which defeats current automated unflatteners
(they pattern-match against switch-case shapes that whitespace-as-
words destroys).

**Verdict: file as v2 layer 7.**  Specifically: flattening AT the
source-code level (not the LLVM-IR level the prior art targets),
producing flattened source that the preprocessor un-flattens
before emission.  The composition with layers 2-5 is the value.

Sources:

- [MDPI: ML classification of LLVM IR obfuscation](https://www.mdpi.com/2504-4990/7/4/125)
- [Tigress: control flow flattening](https://tigress.cs.arizona.edu/transformPage/docs/flatten/index.html)
- [eShard: D810 unflattening tool](https://www.eshard.com/blog/d810-a-journey-into-control-flow-unflattening)
- [Obfuscator-LLVM — Software Protection for the Masses](https://www.researchgate.net/publication/308855157_Obfuscator-LLVM_--_Software_Protection_for_the_Masses)

### Opaque predicates

Insert always-true / always-false predicates the attacker has to
prove are constant.  Example: `if ((x*x + x) % 2 == 0)` is always
true for integer `x`; an analyser must prove this before pruning
the branch.

**For LLM attackers:** moderately effective.  LLMs are
inconsistent at integer-arithmetic reasoning under load; opaque
predicates are exactly the case where the inconsistency shows.

**Cost:** 5-15% runtime overhead per literature.  Cheap.

**Verdict: file as v2 layer 8.**

### Bogus control flow

Branches the runtime never takes but the attacker has to analyse
to know that.  Composes with opaque predicates: the dead branch
contains code that looks plausible — and the predicate is opaque.

**Verdict: file as v2 layer 8 sub-item.**

---

## 3. Data obfuscation

### Constant unfolding

Replace literal constants with expressions that evaluate to the
constant.  `port = 22` becomes `port = some_compound * another -
third`.

**For Babbleon specifically:** composes beautifully with the
wordlist scramble.  The "compound" terms in the expression are
themselves scrambled identifiers from the per-epoch wordlist.

**Cost:** the preprocessor has to evaluate the expressions before
emission, which means it has to run an arithmetic interpreter.
Cheap (sub-millisecond per file).

**Verdict: file as v2 layer 9.**

### String obfuscation

Split, XOR-encode, runtime-reconstruct.  Standard malware
technique.

**For Babbleon:** mostly NOT applicable.  Strings in user code are
user data; obfuscating them changes program semantics from the
user's perspective.

**Exception:** path strings and URL strings that the v2
preprocessor can rewrite at deployment time.  E.g. a hardcoded
`/etc/passwd` could become `read_target_path("etc-passwd-token")`
where the function consults the scrambled-path table.

**Verdict: file as v2 layer 10, NARROWLY scoped to host-path
strings only.**

---

## 4. LLM-specific obfuscation

These are the newest and most directly threat-model-relevant.

### Defensive prompt injection in source code

Embed adversarial prompts as comments or strings that derail
attacker-LLM ingestion.  Original idea: Pasquini et al. 2024
("Hacking Back the AI-Hacker", arXiv 2410.20911).

**State of the art 2024-2025:** very active research.  Key papers:

- [SecAlign: Defending Against Prompt Injection with Preference Optimization (2410.05451)](https://arxiv.org/abs/2410.05451)
- [StruQ: Structured Queries (2402.06363)](https://arxiv.org/pdf/2402.06363)
- [Polymorphic Prompt defence (2506.05739)](https://arxiv.org/pdf/2506.05739)
- [Hidden-Comment Injection in LLM Agents (2602.10498)](https://arxiv.org/html/2602.10498v1) — academic
  documentation of HTML-comment-hidden prompt injection.  Same
  *mechanism* in reverse: the defender hides their own prompts
  where the attacker LLM ingests them but the legitimate
  reviewer doesn't see them.
- **CVE-2025-53773** — GitHub Copilot RCE via prompt injection
  in code comments.  This is the production-attack proof point.
  Defensive flip uses the same channel.

**Caveat:** [Adaptive attacks bypass defences (2510.09023, "The
attacker moves second")](https://arxiv.org/html/2510.09023v1)
shows current defences fall to attacks that know the defence.

**For Babbleon:** the value isn't in stopping every LLM ingestion;
it's in *raising the attacker's cost per rotation window*.  An
attacker model that ingests a Babbleon-protected file has to:
1. Strip whitespace-as-words tokens.
2. Strip junk decoys.
3. Resolve identifier/operator scrambles.
4. **Ignore embedded defensive prompts.**

Each step is per-rotation work.  Sub-second rotation defeats the
chain even if each individual step is solvable.

### Defensive prompt injection — masterlists and value proposition

Operator question (2026-06-15): does defensive prompt injection
add enough value to ship as part of the direct Babbleon
implementation (not just an optional add-on)?  Are there
prompt-injection masterlists analogous to the wordlists?

**Yes to both.**  Multiple open-source corpora exist.  Triaged by
licence:

| Corpus | License | Notes |
|---|---|---|
| **[garak (NVIDIA)](https://github.com/NVIDIA/garak)** | **Apache 2.0** | Generative AI red-teaming kit; stable 0.13.0 (Sept 2025); includes a broad probe library with indirect-injection payloads.  Vendor-able with attribution. |
| [BIPIA (Microsoft)](https://github.com/microsoft/BIPIA) | LICENSE file (verify before vendoring) | Indirect-prompt-injection benchmark; portions sourced from OpenAI Evals, WikiTableQuestions, Stack Exchange (each with own terms). |
| [IPI Arena (Gray Swan)](https://github.com/grayswansecurity/ipi_arena_os) | check repo | 41 behaviours across tool-use, coding, computer-use agents. |
| [LLMail-Inject (arXiv 2506.09956)](https://arxiv.org/pdf/2506.09956) | check paper | Realistic adaptive injection challenge. |
| [PINT (Lakera)](https://github.com/lakeraai/pint-benchmark) | check repo | Detection benchmark; less directly applicable as a payload source. |
| [Purple Llama CyberSecEval (Meta)](https://github.com/facebookresearch/PurpleLlama) | LICENSE in repo | Direct + indirect injection benchmark sets. |
| OWASP LLM Prompt Injection Prevention Cheat Sheet | CC-BY-SA | Defender-oriented; useful for pattern catalogue. |

**Recommended v2 plan: include defensive prompt injection in the
direct Babbleon implementation, opt-in via config flag, default
ON.**  Reasons:

1. **Real-world precedent exists.**  CVE-2025-53773 shows the
   attack channel is exploited in production.  Defensive use of
   the same channel is symmetric.
2. **Open-source corpora are readily available** — at minimum
   `garak` (Apache 2.0, license-clean for vendoring) provides
   thousands of probe payloads.
3. **Composes with rotation.**  Per-epoch random selection from
   a vendored payload pool means the attacker can't pre-train
   against a fixed list — adversarial-prompt rotation comes
   free with mapping rotation.
4. **Composes with layers 3 + 5.**  Defensive prompts are
   hidden among layer-3 wall-of-text and layer-5 junk decoys;
   only an attacker LLM that ingests-then-strips will see them.
   The strip step is per-rotation work.

**Liability concerns documented in `docs/v2/structure-scrambling.md`
phase 4 plan:** operator opt-out via config; surface a clear
disclaimer in the install doc that "your source files now contain
adversarial prompts intended to derail unauthorised LLM
ingestion; some downstream tools (CI lint, AI code review) may
react."

**Vendoring policy proposal:** vendor a subset of garak's
indirect-injection probes (~500 payloads to start) into
`crates/babbleon-core/wordlist/prompt-injection-payloads/` with
Apache 2.0 attribution.  Per-epoch random selection draws from
this subset.  No legal review blocker.

**Verdict: file as v2 layer 11.**  Promoted from "optional
side-loadable" to "direct implementation, opt-in via config,
default ON."

### Tokenizer-hostile patterns (beyond word-compounds)

v1 measured ~7% per-token-cost inflation for English word-compounds.
The smaller-model superlinear hypothesis is still un-tested.
Beyond word-compounds:

- **Mixed-charset codepoints** — Latin + Cyrillic + Greek
  homoglyphs mixed in identifiers.  Tokenizers segment these
  poorly.
- **Unusual unicode normalisations** — NFC / NFD / NFKC mixing.
- **Zero-width joiners (ZWJ) and non-printing characters** —
  bloat token count without affecting execution.

**Cost on attacker:** real (multi-x token-count inflation in
limit cases).  **Cost on us:** zero — the preprocessor strips
non-essential codepoints before emitting to the interpreter.

**Cross-reference:** Trojan Source / CVE-2021-42574 weaponises
exactly some of these.  Babbleon's defensive use is opposite-
direction (we WANT the attacker confused), but it triggers the
same linters.  Mitigation: confine to the scrambled-source
representation; the preprocessor emits cleaned source the
interpreter sees.  Linters running on the *clean* source see
nothing.

**Verdict: file as v2 layer 12.**

### Adversarial code-LLM perturbations (the literature)

[2024 research](https://arxiv.org/pdf/2410.10526) shows
code-LLMs can be derailed by:
- Variable renaming (v1 already does this).
- Dead code insertion (v2 layer 5 already does this).
- Semantic-preserving transforms.

The same techniques attackers use to fool code analysers can be
used by defenders to fool attacker LLMs.  v1 + v2 design is
validated by this literature; no new layer needed.

**Verdict: cite as supporting evidence in `docs/v2/threat-model.md`.**

Sources:

- [Generalized adversarial code-suggestions (2410.10526)](https://arxiv.org/pdf/2410.10526)
- [Trust Me, I Know This Function (2508.17361)](https://arxiv.org/pdf/2508.17361) — LLM bias-hijacking for static analysis defeat
- [ICLR 2024: An LLM can fool itself](https://proceedings.iclr.cc/paper_files/paper/2024/file/0c72285e193ec90dca93258128698cfb-Paper-Conference.pdf)

---

## 5. Anti-analysis techniques (mostly N/A)

### Anti-debugging (detect ptrace, refuse to run)

Babbleon's threat model assumes the attacker is **already running
code**.  Anti-debugging is post-compromise.  **Skip.**

### Self-modifying code

Defeats static analysis but breaks every legitimate tool
(debuggers, profilers, error reporters).  **Skip.**

### Time-bombs / environment checks

Defenders shouldn't ship time-bombs.  **Skip.**

---

## 6. Cryptographic obfuscation (mostly N/A — answer to Q3)

### Whitebox cryptography

The technique: embed a key inside a function such that an attacker
reading the function code cannot extract the key.

**Reality 2024-2025:** every public whitebox AES design has been
broken.  [WhibOx 2017 competition: all 94 submissions broken during
the competition.](https://en.wikipedia.org/wiki/White-box_cryptography)
BGE attack (2004), DCA (2016), grey-box side-channel attacks all
work against current designs.

**Verdict: NOT viable.**  Two decades of academic effort; no
secure construction.

### Indistinguishability obfuscation (iO)

Theoretical: produce an obfuscated program that's
indistinguishable from any equivalent program.  Recent
constructions exist (Jain-Lin-Sahai 2021) but produce gigabyte-
scale outputs per function.  **Not v2-ready.**

### Homomorphic encryption

Compute on encrypted data.  Real and shippable for narrow
primitives (Paillier for additive, BFV for arithmetic).  Not
applicable to general source execution — there's no homomorphic
Python interpreter.

### TEEs (Intel TDX, AMD SEV-SNP, ARM Trustzone)

Hardware confidential computing.  **Real and shippable as of
2025**: Azure, GCP, AWS all offer confidential VM instances; VMware
Cloud Foundation 9.0 supports both TDX and SEV-SNP; QEMU 10.1
mainlined.

**For Babbleon:** the *trusted tier* could run inside a
confidential VM.  The host kernel cannot read enclave memory;
even an attacker with kernel privilege on the host cannot extract
the per-host mapping table.

**Caveats:**

- Doesn't *replace* the namespace + scramble mechanism — covers a
  different surface.  Stacks with it.
- TEEs have their own attack surface (Foreshadow, ZombieLoad,
  SGX deprecation history).
- Operational complexity — confidential VM setup is non-trivial
  for individual operators.

**Verdict: file as v3 hardening direction**, not v2.

Sources:

- [AMD SEV-SNP vs Intel TDX 2025](https://onidel.com/blog/amd-sev-snp-vs-intel-tdx-vps)
- [Empirical analysis of SEV-SNP and TDX (SIGMETRICS 2025)](https://syssec.dpss.inesc-id.pt/papers/misono_sigmetrics25-abstract.pdf)
- [VMware Cloud Foundation 9.0 — Confidential Computing](https://blogs.vmware.com/cloud-foundation/2025/08/06/confidential-computing-vmware-cloud-foundation-9-0/)

---

## 7. Why not just encrypt the source files?

The fundamental answer: **encryption alone does not address
Babbleon's threat model.**

| Threat | Encryption helps? |
|---|---|
| Stolen disk / lost laptop | Yes (LUKS, full-disk encryption) |
| **Attacker with live process running on the host** | **No** |
| Attacker with kernel privilege | Only TEE / confidential VMs help |
| Attacker substituting binaries | Code signing helps |
| Network attacker | Out of scope (firewall) |

The deep problem: **if the runtime can decrypt, the key is
on-host.**  Whatever decrypts before `exec` has the key in
memory.  The attacker — who has live execution — has access to
that same memory.

Specifically:

- **Encrypted source + runtime decryption = same exposure as
  plaintext source.**  Plaintext exists in some buffer between
  disk read and `exec`; attacker reads that buffer.
- **Whole-disk encryption (LUKS) is orthogonal.**  Solves "stolen
  laptop."  Doesn't touch "live process."
- **Code signing helps with a different problem.**  Defeats
  binary substitution.  Doesn't stop a process that's already
  trojaned.

**What encryption-adjacent things DO compose with Babbleon:**

- **Signed binaries + runtime verification** — defeats binary
  substitution.  Filed as v2 phase 6 (release engineering).
- **TEE-protected mapping table** — v3.
- **Confidential VMs for trusted-tier apps** — v3+.
- **Encrypted + signed audit log** — v2 already plans Ed25519
  signing; adding AES-GCM encryption is cheap.  File as v2
  enhancement.

The combined picture: **Babbleon's scramble + tier + tripwires
covers exactly the "live attacker, userspace execution, host-
side" surface that file encryption does not.**  These stack;
neither replaces the other.

---

## Summary — v2 layer roadmap, post-research

The five existing layers from `structure-scrambling.md` plus the
new ones from this research:

| # | Layer | Phase | Notes |
|---|---|---|---|
| 1 | Identifier scramble | v1 already | Carry forward |
| 2 | Operator scramble | v2 phase 3 | Per-language keyword sets |
| 3 | Whitespace-as-words | v2 phase 3 | The big one |
| 4 | Code-order reorder | v2 phase 3 | Top-level blocks |
| 5 | Junk decoys | v2 phase 3 | ~70% noise target |
| 6 | Direction segment reversal | v2 phase 3+ | Lower priority |
| 7 | Source-level control-flow flattening | v2 phase 4 | Composed with 2–5 |
| 8 | Opaque predicates + bogus control flow | v2 phase 4 | |
| 9 | Constant unfolding | v2 phase 4 | Composes with wordlist scramble |
| 10 | Path-string obfuscation | v2 phase 4 | Narrow scope |
| 11 | Defensive prompt injection | v2 phase 4 | Opt-in (operator preference) |
| 12 | Mixed-charset / ZWJ / NFKC tricks | v2 phase 4 | Confined to scrambled representation |
| — | Multi-language wordlists | v2 phase 4 | Already filed |
| — | TEE-protected trusted tier | v3 | Confidential computing direction |
| — | Encrypted + signed audit log | v2 enhancement | Cheap |
| — | Signed-binary verification | v2 phase 6 | Filed |

Layers 1-5 ship in phase 3.  Layers 6-12 ship in phase 4 (or
phase 3.5).  TEE work is v3.

---

## Multi-language wordlist sources — research

Layer 4 / phase-4 multi-language wordlists need actual wordlists.
Searched 2026-06-15 and identified:

**[HermitDave/FrequencyWords](https://github.com/hermitdave/FrequencyWords)
— MIT license, 61 languages from OpenSubtitles 2018.**  Includes
Spanish, French, German, Japanese, Chinese (Simplified +
Traditional), Arabic, Russian, and 53 others.  Frequency-ranked.
Code MIT; underlying OpenSubtitles data is CC-BY-SA (attribution
flows through, but no licence conflict for our use).  **This is
the v2 multilingual wordlist source.**

Considered and rejected:

- **Dict.cc** — proprietary licence post-2018.
- **Multitran** — proprietary.
- **LingoPad** — freeware (unclear redistribution).
- **Refugee Phrasebook** — CC0 but a phrasebook, not a wordlist.

**Action:** vendor frequency-ranked top-N entries per language
into `crates/babbleon-core/wordlist/multilingual/` with the
HermitDave MIT licence preserved.  Decide N per language during
phase 4; provisional 100k per language → 1.6M total across 16
languages.

---

## What this research does NOT close

- The structural-scrambling design (`structure-scrambling.md`)
  still needs an adversarial-LLM measurement once a phase-3
  prototype ships.  Without that measurement, we are stacking
  layers on hope, not data.
- The "smaller-model superlinear" hypothesis on token cost
  (v1 tokenizer-benchmark RESULTS.md) is still untested.
- The TEE direction needs an operator decision: is v2.0 targeting
  individual-developer-laptop deployment (where TEE is not
  available), or enterprise / cloud deployment (where it is)?
  Different priorities.
- The defensive-prompt-injection vendoring legal pass (garak
  Apache 2.0 is clean; BIPIA, IPI Arena, LLMail-Inject, PINT,
  Purple Llama each need per-LICENSE check before we vendor
  from them).

---

## Cross-cutting note

Several of these layers (control-flow flattening, opaque
predicates, constant unfolding) are well-studied in the
software-protection literature for protecting *attacker* code
(malware, DRM).  Using them in reverse — to protect *defender*
code from attacker analysis — is unusual but legitimate.  No
licence conflicts (the techniques are public).  Worth noting in
v2 threat-model documentation that we are inverting the classic
malware-obfuscation toolkit.
