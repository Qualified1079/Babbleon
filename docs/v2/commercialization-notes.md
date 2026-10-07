# Commercialization notes — enterprise licensing posture

Filed 2026-08-08.  Strategy notes, not a spec.  Nothing here
constrains the technical roadmap; it records *why* certain
technical items are commercially load-bearing so a future session
does not deprioritize them as "just polish."

Context: the operator's goal is enterprise licensing out of the
private enterprise repo (PolyForm Noncommercial on the public
side).  These notes assess what stands between the current state
and that outcome.

## 0. Correction (2026-10-07) — what the product is

Filed after an operator correction.  A prior session read §4
("detection is the wedge") as Babbleon's product thesis.  It is
not.  This file is a go-to-market note; the thesis lives in
`V2_PLAN.md` and `docs/v2/structure-scrambling.md`.

**The product is semantic denial.**  The per-host scramble is the
feature.  The assumed adversary is a reasoning model driving a
harness with a large, well-indexed corpus of malware that it
selects from on observed need and adapts to the situation in
front of it.  The defence is to hand that adversary no
semantically legible surface to interface with at all.  The
design does **not** assume the attacker is working from memory,
and does not depend on it being slow, static or unsophisticated —
it assumes the opposite, and expects attackers to become
arbitrarily good and fast.  That is precisely why the mechanism
is denial rather than deception.

**The tripwire is a derived second tier**, not the feature.  It
exists only because a scrambled host makes canonical-name use
anomalous; it is a by-product of the scramble.  It also carries a
false-positive floor the scramble does not: any unscrambled
third-party software that hardcodes a canonical path — installers,
vendor binaries, Makefiles, CI scripts, container images — asks
for a legitimate path and fires it.  Detection is therefore clean
only under **full enclosure**, where everything legitimate has
been through the preprocessor.  Denial has no such dependency:
unenclosed software either got scrambled or it did not.

§4 below stays valid as *sequencing advice for a first sale* —
detection-only mode has no authentication blast radius and lands
on an existing SIEM budget line.  Read it as "what to sell
first," never as "what Babbleon is."

### Scope boundary this memo should have stated

Semantic denial covers an adversary that must **reason about the
system** in order to act.  It does not cover attack paths that
need no semantics at all: parser bugs, memory corruption, and
interoperable-by-necessity network surfaces — a package-registry
proxy must speak real PyPI, an HDF5 loader must parse real HDF5,
a template engine must evaluate real Jinja2.  Those code paths
cannot be scrambled without breaking the product they serve, so
they stay legible by necessity.  The July 2026 Hugging Face
intrusion ran through exactly that layer.  Closing it belongs to
the capability-restriction tier (namespaces / Landlock / seccomp),
not to the scramble.  Do not let a buyer infer coverage there.

### Open technical question, which gates the measurement

Names are one channel; **behaviour** is another.  An agent can run
an unknown binary, observe it speak TLS on 443, and treat it as
curl-equivalent without ever learning its name.  No layer now in
the pipeline (L2-L12) addresses behavioural fingerprinting.
Whether semantic denial is a wall or a speed bump turns on this
question, which is why the empty evidence column in §1 is a
**gate** on ranking any further phase-4 layer work — not a polish
item.

## 1. The evidence column is empty — highest-leverage item

Every published bench run is self-invalidated by
`crates/v2-babbleon-resilience-bench/CORRECTIONS.md`.  Filing that
correction was correct practice, but the consequence is that
Babbleon currently has **no defensible measurement** of scramble
strength.

Enterprise security diligence opens with "what is the
measurement."  The honest present answer is "our harness found our
corpus tautological, and the replacement corpus has not been run."

One credible number closes this.  Requirements, all three
necessary:

- **New corpus** built against `BENCHMARK-DESIGN.md` — recovery
  targets must not be plain literals that no layer scrambles.
- **Non-Claude evaluator** (local Llama/Qwen, or a non-Anthropic
  API).  The 2026-06-22 operator-scramble rerun showed 100%
  usage-policy refusal on L2+L2b+L3 cells; refusal contaminates
  the signal and is *not* a defensive result.
- **Post-normalization** measurement — the adversary is assumed to
  run Unicode normalization (NFKC + confusables) before reasoning.

This outranks building additional layers.  A new layer without a
number does not move the commercial position; a number without a
new layer does.

## 2. Blast radius is inverted against enterprise adoption

The Linux tier's integration surface — PAM module, login-shell
replacement, daemon holding the vault secret, namespaces — sits in
the blast radius of authentication itself.

- Failure mode: nobody logs into production.  Visible, immediate,
  attributable.
- Benefit: invisible and probabilistic.

Enterprises price that asymmetry harshly.  It implies long pilots
and makes the first outage existential for the deal.

Implication: the full enforcement stack should **not** be the
first commercial wedge.

## 3. Category precedent — sell the outcome, not the mechanism

Moving-target defense has commercial history and it is
instructive:

- **Morphisec** built a real business selling "stops ransomware /
  prevents exploits" — the outcome.
- **Polyverse** sold diversity-as-such — the mechanism — and
  stayed small.

The mechanism never sells.  Marketing "per-host randomized
namespace obfuscation" describes how it works, not what the buyer
gets.

## 4. Detection is the wedge; enforcement is the upsell

*Sequencing advice for a first sale only — see §0.  The
scramble is the product; this tier is derived from it.*

The strongest near-term commercial framing is the tripwire, not
the scramble:

> A process reached for a canonical name it should not have been
> able to know.

Why this sells first:

- It is a **SIEM event**, so it lands on an existing budget line
  rather than requiring a new category.
- It **cannot brick production** — detection-only mode has no
  authentication blast radius.
- It **survives a skeptical buyer**.  The prevention pitch
  requires the buyer to believe the crypto is unbreakable.  The
  detection pitch does not: the signal has value even if the
  scramble is eventually broken, because breaking it is itself
  detectable activity.
- The planned enterprise surface (SIEM sinks, console) already
  matches this shape.

Enforcement then becomes the upsell after detection has earned
trust inside the customer's environment.

## 5. What analysis cannot answer

Whether anyone is currently budgeting against LLM-driven
attackers — or whether this is two years early — is a
customer-conversation question.  Five discovery calls would
resolve more than any further internal assessment.

## 6. Structure already correct

PolyForm Noncommercial public + private enterprise repo (escrow,
SIEM sinks, console) is the right licensing shape for this.  No
change recommended.
