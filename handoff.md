# Handoff — 2026-07-09

## Context found on session start

No `claude.md` or `handoff.md` existed anywhere in this repo's history before
this commit. The only prior content beyond `README.md` was a research note,
"LLM install-time semantic diversification," added 2026-06-14 and **deleted
by the human the same day** (commits `c2000e0`, `32721c3`, `3188d0a`). Per the
standing instructions for an idle session ("no active plan → research
something and write a dated handoff note"), this note picks up that thread:
it does not resurrect the deleted file, but checks its core claims against
the literature before anyone re-proposes that architecture.

The deleted note's thesis: use a local code LLM to rewrite a codebase's
*implementation* (not just symbol names) per install, so that an attacker who
fingerprints one deployment can't reuse that fingerprint against another —
a defense specifically aimed at self-propagating LLM/prompt-injection worms
that need to recognize consistent code shape to spread or target payloads.
It flagged its own open problem before being deleted: **naming-only
diversification is trivially reversible if the attacker holds the original
source** (1:1 dictionary correlation), and it argued structural rewrites are
needed instead. That's the question this note investigates.

## What the literature says

**The threat model is real, not speculative.** "Morris II" (Cohen, Bar-Sinai,
Nassi et al., Technion/Cornell Tech/Intuit, March 2024) is a working,
published zero-click worm against GenAI email assistants: an adversarial
self-replicating prompt that gets an LLM agent to both act on a malicious
payload and re-emit the prompt to propagate to the next agent. It was
demonstrated against GPT-4, Gemini Pro, and LLaVA. The researchers' own
mitigation ("Virtual Donkey") is a runtime guardrail, not a diversification
defense — so Babbleon's angle (make the target non-uniform rather than
detect the payload) is a genuinely different, complementary layer, not
duplicated work.
([Schneier](https://www.schneier.com/blog/archives/2024/03/llm-prompt-injection-worm.html),
[arXiv:2403.02817](https://arxiv.org/abs/2403.02817),
[IBM](https://www.ibm.com/think/insights/morris-ii-self-replicating-malware-genai-email-assistants))

**Structural (not cosmetic) diversity has prior art, and it's older than
expected.** Baudry et al.'s "sosie" work ("Tailored Source Code
Transformations to Synthesize Computationally Diverse Program Variants,"
[arXiv:1401.7635](https://arxiv.org/pdf/1401.7635)) synthesized 30,000+
variants of real programs that preserve expected functionality but diverge
in actual execution — different method-call sequences and data flow in
40%+ of variants, not just renamed identifiers. This is the right *kind* of
diversity target (behavioral, not lexical) — it directly supports the
deleted note's instinct that renaming alone isn't enough.

**Someone already built the LLM-driven version.** "Galapagos: Automated
N-Version Programming with LLMs"
([arXiv:2408.09536](https://arxiv.org/pdf/2408.09536), 2024) uses an LLM to
generate multiple behaviorally-equivalent, structurally-distinct variants of
a program, verified by differential/property testing, evaluated against
real C libraries (OpenSSL, libsodium, FFmpeg, libgcrypt, liboqs). This is
close enough to the deleted note's proposed shape — AST-scoped mutation
menu, property-test-gated retry loop, keep-original fallback — that it
should be read in full before anyone rebuilds that track. Two reasons:
avoid re-deriving a verification harness that already exists, and check
whether Galapagos' variants actually resist correlation attacks (the paper
demonstrates functional diversity across real libraries but its published
abstract doesn't make a correlation-resistance claim — that gap is worth
closing before relying on it).

**Composing diversification techniques can *cancel* their protection, not
stack it.** Galois' analysis of combined MTD techniques
([galois.com](https://www.galois.com/articles/automated-software-diversity-sometimes-more-isnt-merrier))
shows concrete cases where layering defenses opens new holes — e.g., stack
variable shuffling defeats code-layout randomization by giving an attacker a
consistent offset to target across variants; SafeStack + diversity opens a
cross-frame overwrite path neither has alone. This directly undercuts a
specific line in the deleted note, which asserted semantic diversification
"layers cleanly on top of Polyverse-style binary diversification" —
that claim was asserted, not verified, and the literature says composition
safety needs its own analysis, not an assumption.

**Install-time (static) diversity is a weaker point on the MTD spectrum than
runtime-switching diversity.** The MTD literature's core requirement is a
large variant pool *plus the ability to switch between variants during
execution* — that's what makes an attacker's foothold expire. Babbleon's
"one semantic variant baked in per device at install" is closer to a
classic N-variant/N-version fleet (each host gets a different but fixed
build) than to true moving-target defense (one host's build keeps changing).
That's a legitimate and useful property against *worm-scale* attacks (a
fingerprint that works on device A doesn't transfer to device B), but it
does nothing against a sustained attacker who is only ever probing one
specific host. The deleted note didn't distinguish these two threat models;
a rebuilt version should state explicitly which one it's targeting.

## Recommendation (needs a human decision, not autonomous build)

This is a case for manual review, not code: the prior note was deleted by
the repo owner on the same day it was written, which reads as "not
convinced yet" rather than "lost." Building an implementation on top of an
architecture the owner already discarded once would be presumptuous. What
this research changes is the *decision inputs*, not the decision itself:

1. Read Galapagos in full before re-scoping the diversification track — it
   may cover most of the "shape" section of the deleted note already, which
   would turn this from a build into an integration/evaluation task.
2. Decide explicitly which threat model Babbleon is defending: worm-scale
   (fleet-wide fingerprint reuse — served well by install-time diversity) vs.
   single-target persistence (needs true runtime-switching MTD, a materially
   bigger project). The deleted note's own resource math ("Babbleon's
   weekly epoch cadence") suggests fleet-scale was the intent, which lines
   up with install-time diversity being sufficient — but that should be a
   stated decision, not an implicit one.
3. If/when a diversification track is rebuilt, treat "does this survive a
   1:1 correlation attack against the original source" as a testable
   property from day one (e.g., an adversarial harness that's handed both
   variant and original and scored on how fast it re-identifies renamed
   functions), rather than an assumption to fix later.
4. Do not assume composability with other MTD/diversification layers
   (e.g. Polyverse-style binary randomization) without the kind of
   composition analysis Galois describes — that's a distinct research task,
   not a footnote.

No code was written this session — there's no consensus architecture yet to
implement against, and the one that existed was self-retracted. Next
concrete step is (1) above: a close read of Galapagos against the deleted
note's design, done by whoever picks this back up.
