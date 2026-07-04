# Handoff / research log

Append-only-ish: newest entry on top. Each entry dated. This is the file
the next session reads first.

---

## 2026-07-04 — session 1, addendum: first experiment on the honest limitation

Same session, continued after the initial commit/push (see the base
2026-07-04 entry below for full context) rather than stopping at "3 next
steps noted." Picked candidate #2 from that list — get an empirical read
on how much diversification degrades once the target agent generalizes
past literal string matching — and actually ran a first, narrow version
of it instead of leaving it as a bullet point.

**What changed in `babbleon/`:**

- `dialect.known_vocabulary()` — new public function exposing the full
  synonym pool `Dialect.generate` draws from. Deliberately public: the
  project's threat model should assume Kerckhoffs's principle (attacker
  knows the algorithm, not the per-install seed), same assumption ASLR
  makes about its own randomization algorithm being public knowledge.
  Hiding the pool and calling that "the defense" would be security
  through obscurity, which isn't a real property to build on.
- `wormlab.FuzzyOverlapAgent` — one rung up from `NaiveTriggerAgent`.
  Fires a tool if every known-vocabulary word in that tool's
  (diversified) description shows up somewhere in the incoming text.
  Deliberately scored *only* against `known_vocabulary()` words, not raw
  text/description overlap — first attempt used raw overlap and produced
  a false positive from two independently-seeded dialects sharing an
  incidental filler word ("memo" showed up in both a tool name and an
  unrelated description by chance); restricting the score to the pool
  actually being tested removes that artifact. Worth remembering as a
  general lesson for future toy-harness work in this repo: bag-of-words
  overlap against arbitrary hand-written English is noisier than it
  looks, small vocab pools collide by chance more than intuition
  suggests.
- `wormlab.craft_informed_payload()` — the Kerckhoffs-aware attacker:
  sprays the entire public vocabulary in one payload instead of naming
  one tool, so whichever synonym a given install happened to land on is
  present regardless of seed.

**Result** (see `tests/test_wormlab.py::TestFuzzyOverlapAgent`, all
passing): the informed payload triggers `FuzzyOverlapAgent` on every
seed tested — synonym-pool substitution alone does not survive an
attacker who knows the pool. The same payload still fails against
`NaiveTriggerAgent`'s literal-name matching on every seed, because it
can't guess the per-name random salt. So the salt — unguessable per-
install entropy — is carrying the actual security weight; the synonym
substitution is decoration on top of it, not a defense by itself. Pushed
this finding up into `claude.md` as a dated update to the honest-
limitation section rather than leaving it buried here, since it changes
what "diversification" should mean going forward for this project (see
that file for the design implication).

**Still open / not touched by this experiment:**

- No real LLM in the loop anywhere — `FuzzyOverlapAgent` is still a
  bag-of-words heuristic, not a semantically-generalizing agent. It's a
  step between `NaiveTriggerAgent` and "a real model," not a stand-in for
  the real model. SRPO-class summary-resilient payloads are still
  untested.
- Structural (not lexical) diversification — varying *how* a tool's
  schema/calling-convention is exposed, not just what it's spelled — is
  still unbuilt and is probably the more important next increment given
  tonight's finding that lexical substitution alone is weak once the
  algorithm is assumed public.
- Marker-token diversification (the hash-derived `X<hash>_FORW`-style
  tokens, `dialect._alias_marker`) doesn't reduce to the same "spray the
  finite public pool" attack the synonym substitution fell to — there's
  no small enumerable pool, it's `sha256(seed:marker:key)` truncated to 6
  hex chars. That's a by-construction argument (preimage resistance),
  not something that needs a wormlab test the way the synonym case did.
  But the truncation width is worth a second look: 6 hex chars is only
  24 bits, i.e. ~16.7M possibilities — small enough that an attacker
  willing to spray a large number of guesses (not fully brute-forceable
  in one realistically-sized payload, but worth being honest that it's
  not astronomically large either) has non-trivial odds over repeated
  attempts. Flagged as a manual-review / hardening item rather than
  something to fix reflexively: widen to 8+ hex chars (32+ bits) if this
  ever moves past prototype, but not worth churning the code for it
  mid-experiment tonight.

---

## 2026-07-04 — session 1: reconstructing the thesis, grounding it in current lit, first prototype

**Starting state.** Repo had no `claude.md` and no `handoff.md` — this is
the first session in whatever loop is driving these. Only content was
`README.md` ("An idea to confuse LLM worms and such") and git history
showing a research track — "LLM install-time semantic diversification" —
added, expanded, then deleted across three commits, with no deletion
rationale in the commit message. No open task/plan was active.

Per standing instructions for a no-active-plan session: researched one
question, wrote it up dated, and built a prototype since the research
turned up something concretely buildable. Full reasoning below; see
`claude.md` for the resulting stable charter (this entry is the log of
*how* that charter was derived — claude.md is the thing to trust going
forward if the two ever disagree).

**Why the deleted track probably got pruned.** Reading it (`git show
32721c3:"LLM install-time semantic diversification"`), it was solid
writing but about the wrong threat model: compiler/AST-level code
mutation to defend compiled binaries against memory-corruption exploits
(citing Polyverse, Shakedown, ACM MTD workshop literature). That's a real
research area, just not "LLM worms" — it's classic binary-exploitation
MTD with an LLM used as the mutation engine. Read literally, the README
is about GenAI-worm confusion (Morris-II-class attacks), not compiled-
binary MTD. I'm treating the deletion as a (silent) correction back onto
thesis and documented it as a standing scope boundary in claude.md so it
doesn't get re-added without an explicit argument for why it's back on
thesis.

**Grounding the actual threat model.** Searched current literature
(current date 2026-07-04) rather than relying on training-data recall,
since this is an actively moving research area:

- Morris-II / "Here Comes the AI Worm" (arXiv:2403.02817, Cohen/Nassi et
  al.) — first GenAI worm. Adversarial self-replicating prompt embedded
  in an email, retrieved via RAG into an email-assistant agent's
  context, carries two payload halves: one malicious action (spam /
  exfiltration), one self-replication instruction that gets the agent to
  forward the same payload onward. Demonstrated black-box and white-box
  against Gemini Pro, GPT-4o, LLaVA. Their own proposed guardrail
  ("Virtual Donkey") reports TPR 1.0 / FPR 0.015 in-paper; I could not
  get mechanism detail past the abstract (fetches kept returning
  abstract-only) — worth a deeper read next time, not urgent for this
  thesis.
- Cross-platform LLM agent worm work (arXiv:2605.02812) — automated,
  cross-framework worm-analysis tooling, and critically: **SRPO**, a
  "summary-resilient payload optimizer" that generates payloads which
  stay effective *after being paraphrased/summarized by an LLM across
  multi-hop communication*. This is the important finding for Babbleon —
  see limitation section below. Same paper proposes **RTW-A**, a formally
  verified ("No Persistent Worm Propagation" theorem) information-flow
  defense: blocks write-before-exposed-read, seals config, does typed
  memory promotion and capability attenuation after untrusted reads.
  This is an out-of-band/IFC defense, architecturally unrelated to
  diversification — complementary layer, not competition.
- Polymorphic Prompt Assembling, PPA (arXiv:2506.05739) + follow-up
  dynamic separator generation (arXiv:2605.30534, keyed on
  timestamp/session/nonce via SHA-256, unique BEGIN/END canary pair per
  assembled prompt). This is the closest prior art to "randomization as
  an LLM defense" and I want it clearly distinguished, not quietly
  duplicated: PPA randomizes the *separator/delimiter structure* between
  system instructions and untrusted input, *per request*, within one
  fixed agent architecture. It defends instruction/data confusion. It
  does not vary tool names, parameter names, prompt wording, or
  anything at the install/deployment level, and it doesn't address
  cross-deployment payload transferability (the monoculture problem) at
  all. Babbleon operates at a different granularity (install-time, whole
  semantic surface) toward a different goal (break population-level
  worm portability, not single-request instruction/data confusion).
  These compose fine together; PPA does not subsume Babbleon.
- No prior art found for the specific idea of population-level /
  install-time diversification of an agent's tool-and-prompt surface as
  an anti-worm-portability measure. That's the gap. (Absence-of-evidence
  caveat: web search, not a systematic lit review — flag if a future
  session finds this already exists somewhere.)

**The honest limitation (do not skip this in any future summary of
Babbleon to anyone).** SRPO shows attackers can already build payloads
that survive LLM-mediated paraphrasing across differently-worded agents.
That's evidence against the strong version of the Babbleon thesis: if a
payload's effect doesn't depend on exact surface tokens, then renaming
`send_email` to `dispatch_msg_x7f` and rewording the system prompt may
not stop a sufficiently adaptive attacker, or a sufficiently
"semantically generalizing" target agent that infers the right tool call
regardless of what it's named. What diversification plausibly *does*
stop, based on how Morris-II itself is actually described (literal
embedded instructions naming specific actions/markers, not an adaptively
optimized payload): the cheaper, more common, currently-dominant worm
class that relies on the target agent recognizing literal trigger
strings or a specific well-known scaffold. That's a real, valuable thing
to stop — it's just not a universal defense, and shouldn't be pitched as
one. Framed as a research question rather than an assumption: **how deep
does diversification need to go (lexical vs. structural) before it stops
mattering whether the attacker also has an LLM to adapt with?** Nobody
has answered this for Babbleon's specific angle yet — the toy experiment
below is a first, deliberately narrow attempt at instrumenting it.

**What I built** (`babbleon/` — stdlib-only Python, no dependencies, in
keeping with the "local-only, no heavy dependency" norm the deleted doc
already argued for on privacy/threat-model grounds, which still applies
here):

- `babbleon/dialect.py` — `Dialect.generate(seed, surface)`: given a
  seed (stand-in for "this install") and an `AgentSurface` (system
  prompt template, list of `ToolSpec(name, description, params)`, and a
  set of reply/control markers), deterministically derives a diversified
  view: tool names and parameter names get seeded synonym-pool
  substitution + salt suffix, control markers get replaced with random
  per-seed tokens, system prompt gets a paraphrase-template swap. Same
  seed always yields the same dialect (reproducible per install, not
  re-rolled per request — that's the intentional difference from PPA's
  per-request granularity).
- `babbleon/runtime.py` — `DialectRuntime`: wraps a canonical tool
  implementation map. Presents the diversified `AgentSurface` outward.
  Translates an incoming (diversified-name, diversified-args) tool call
  back to canonical before dispatch, so application logic never sees the
  diversification — this is the translation-shim property the thesis
  depends on (diversify the interface, not the behavior).
- `babbleon/wormlab.py` — toy demonstration, explicitly scoped and
  commented as modeling *only* the literal-trigger-string worm class
  (not a claim about how real LLMs reason): a `NaiveTriggerAgent` scans
  incoming text for an exact canonical tool-name/marker mention and
  invokes it if found — this models what Morris-II's actual mechanism
  depends on (the target recognizing specific embedded instructions/
  markers). Demonstrates: a payload string built against the canonical
  (undiversified / "common monoculture default") surface propagates
  when replayed against another undiversified instance, and fails to
  trigger against a `DialectRuntime`-wrapped instance with a different
  seed, because the literal strings it depends on don't exist verbatim
  in that install's dialect. The module docstring calls out in plain
  terms that this harness cannot and does not demonstrate anything about
  SRPO-class semantically-adaptive payloads — that would require a real
  LLM in the loop, which is future work, not something to fake with a
  regex and call proven.
- `tests/test_dialect.py`, `tests/test_runtime.py`,
  `tests/test_wormlab.py` — determinism of dialect generation given a
  seed, round-trip correctness of the translation shim (canonical call
  in through the diversified name comes back out as the exact same
  canonical call), and the worm-lab propagate/fail-to-propagate
  behavior described above.

Run with `python3 -m unittest discover -s tests -v` from repo root (no
pip installs needed).

**Next-session candidates, ranked:**

1. Read RTW-A / Virtual Donkey full mechanism (not just abstracts — the
   web fetch tool kept truncating to abstract-only) and check whether
   Babbleon-style diversification composes cleanly with RTW-A's capability
   attenuation, or whether they'd fight each other (e.g. does typed
   memory promotion assume stable tool names across time in a way
   diversification breaks if seeds ever rotate mid-session?).
2. Extend `wormlab.py` with a second agent model that does *some*
   semantic generalization (e.g. fuzzy/embedding-style match on tool
   *description* rather than literal name) to get an empirical read on
   how much diversification degrades once the target agent is smarter
   than pure string-trigger matching — this is the actual test of the
   open question above, the current harness only proves the floor case.
3. Decide whether dialect rotation should ever happen *within* an
   install's lifetime (mid-session reseed) as a second moving-target
   axis on top of the install-time axis, and if so, how that interacts
   with in-flight multi-turn conversations that reference earlier tool
   names.
4. Manual review flag: no real LLM was in the loop anywhere in tonight's
   work (no API calls made) — everything is a structural/string-level
   demonstration. Before citing this prototype as evidence of anything
   to the user, it should be run against an actual agent framework with
   a real model to see if the effect holds up outside the toy harness.
