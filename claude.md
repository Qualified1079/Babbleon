# Babbleon — project charter

No `claude.md` existed before this note. This is the first one, written
2026-07-04 by reconstructing intent from `README.md` and the git history
(two commits adding/expanding a research track, one commit deleting it —
see `handoff.md` for the dated log of that reconstruction).

## The one-line thesis

> "An idea to confuse LLM worms and such" — README.md

Read literally, not metaphorically. GenAI ecosystems (RAG-fed email
assistants, tool-using agents, agent-to-agent messaging) are vulnerable to
self-replicating prompt-injection worms — Morris-II (arXiv:2403.02817) was
the first demonstration, and follow-on work (SRPO, cross-platform worm
studies) shows the attack class is actively maturing, not a one-off. These
worms work *at population scale* because deployments are a monoculture:
almost everyone wires up the same agent frameworks, the same tool names
(`send_email`, `search_web`, ...), the same prompt templates, the same
reply conventions. A payload tuned against one instance transfers to
thousands of others for free, the same way one exploit works against
every unpatched copy of the same binary.

Babbleon's bet: break the monoculture. If every deployment presents a
slightly different "dialect" of its own agent surface — different tool
names, different parameter names, different system-prompt phrasing,
different reply/delegation markers — while preserving identical
underlying behavior via a translation layer, then a worm payload authored
against one dialect stops transferring cleanly to the next. Same idea as
biological genetic diversity limiting epidemic spread, or ASLR limiting
memory-corruption exploit portability, applied to the semantic layer
instead of the address space or the genome. The name is the tell: Babel —
confusion of language breaking coordination.

## Scope boundary (read this before adding a new research track)

Three adjacent things already exist in the literature. Babbleon is
specifically the fourth. Do not let the project drift into re-deriving
the first three:

1. **Per-request separator/delimiter randomization** (Polymorphic Prompt
   Assembling, arXiv:2506.05739, and its follow-up arXiv:2605.30534).
   Randomizes the boundary between system instructions and untrusted data
   *within one fixed architecture*, per request, to stop an attacker from
   predicting where instructions end and data begins. This defends
   *instruction/data confusion*. It does not touch tool names, prompt
   wording, or cross-deployment diversity — it's the same dialect
   everywhere, just a shuffled fence within it. Complementary to
   Babbleon, not a substitute.
2. **Out-of-band / information-flow-control enforcement** (Progent,
   CaMeL, FIDES, and the RTW-A / "Temporal Re-Entry Defense" work in
   arXiv:2605.02812). Enforces security with a deterministic policy
   layer outside the model — capability attenuation, typed memory
   promotion, blocking write-before-exposed-read. This defends *what the
   agent is allowed to do after* an injection succeeds. Babbleon defends
   *whether the injection's embedded instructions parse at all* against
   a given install. Different layer, both wanted.
3. **Binary/compiler-level moving-target defense for traditional
   exploits** (Polyverse-style polymorphic recompilation, Shakedown,
   general compiler-MTD literature). This is defense against memory-
   corruption worms in compiled code, not against prompt-injection worms
   in GenAI ecosystems. A research track along these lines
   ("LLM install-time semantic diversification research track") was
   added and then deleted from this repo — it drifted into this
   category. Treat that deletion as a standing decision: Babbleon is
   about the *agent-facing semantic interface* (tool schemas, prompts,
   reply conventions), not source-code AST mutation. If a future
   contributor wants to revive the code-diversification angle, it needs
   to be argued back onto the LLM-worm thesis explicitly, not assumed.

Babbleon is: **install-time diversification of the semantic surface an
LLM agent presents to the world** — tool names, parameter names, system
prompt phrasing, output/reply markers — with a translation shim so
application logic is unaffected, sized to make one worm payload fail to
generalize across a population of differently-dialected installs.

## The honest limitation, front and center

Cross-platform worm research (arXiv:2605.02812, "SRPO") already
demonstrates payload-generation techniques *robust to LLM-mediated
summarization and paraphrasing across multi-hop communication*. That is
a shot across Babbleon's bow: if a payload's effectiveness survives an
LLM rewriting it in its own words, then a *shallow* diversification
(literal string substitution on tool names) may not survive contact with
a sufficiently adaptive attacker or a sufficiently "smart" (semantically
generalizing) target agent that maps the diversified surface back to
intent on its own. Two honest possibilities, not yet resolved:

- Diversification mainly helps against the current, cheaper class of
  worm (payloads that trigger on literal tool-name / marker strings,
  which is what Morris-II-style attacks actually do today), and is a
  defense-in-depth layer, not a silver bullet against a fully adaptive
  semantic attacker.
- Or diversification needs to go structurally deeper than renaming
  (restructuring *how* tools are exposed, not just what they're called)
  to matter against that class of attacker.

Do not oversell this internally or externally until that question has an
experiment behind it. See `handoff.md` for the first attempt at one.

## Working norms for this repo

- No claude.md/handoff.md existed prior to 2026-07-04; this file and
  that one are the first. Whoever picks up next: read `handoff.md`
  first, it's the dated log; this file is the stable charter and should
  only change on a real thesis shift, not every session.
- Prefer small, testable, stdlib-only prototypes over speculative
  markdown-only research tracks — the deleted track was pure prose with
  no code and no experiment; that's a smell to avoid repeating.
- If a session finds no active implementation plan, it should research
  one dated question, write it into `handoff.md`, and — if the research
  surfaces something buildable — actually build a small prototype rather
  than stopping at the write-up.
