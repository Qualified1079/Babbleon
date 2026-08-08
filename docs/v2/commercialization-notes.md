# Commercialization notes — enterprise licensing posture

Filed 2026-08-08.  Strategy notes, not a spec.  Nothing here
constrains the technical roadmap; it records *why* certain
technical items are commercially load-bearing so a future session
does not deprioritize them as "just polish."

Context: the operator's goal is enterprise licensing out of the
private enterprise repo (PolyForm Noncommercial on the public
side).  These notes assess what stands between the current state
and that outcome.

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
