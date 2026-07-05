# Babbleon — Handoff Notes

## 2026-07-05 — autonomous overnight session

### Starting state

The repo contained only `README.md` ("An ides to confuse LLM worms and
such") and a git history showing a research doc that was added and then
deleted the same day: `LLM install-time semantic diversification`
(added 2026-06-14 18:25, deleted 2026-06-14 18:32, after one edit in
between). No `claude.md` or `handoff.md` existed, so there was no active
implementation plan to pick up. Per standing instructions for a session
with no active plan: researched a relevant direction and wrote it up
here, then built the part of it that was tractable in one unattended
session.

I read the deleted doc via `git show` before doing anything else, so as
not to duplicate that research (summarized under "Prior art" below).

### Research: current threat landscape (as of 2026-07-05)

1. **LLM worms are real and already characterized.** Morris II /
   "ComPromptMized" (Cornell, 2024) demonstrated a zero-click,
   self-replicating prompt-injection worm against GenAI-powered email
   assistants: a malicious prompt embedded in an email or an image gets
   echoed into the assistant's output and re-sent to new contacts,
   propagating without further attacker involvement. Follow-on work
   extends this to broader agent ecosystems and studies re-entry/defense
   (arXiv 2605.24659 "IterInject"; arXiv 2605.02812 "Autonomous LLM Agent
   Worms").
2. **Autonomous LLM exploit agents are the concrete near-term risk for a
   codebase specifically.** XBOW reports 1,060+ vulnerabilities submitted
   through fully autonomous pipelines on HackerOne, 48-step exploit
   chains, and a cryptographic implementation broken in 17 minutes.
   "Shannon Lite" scores 96.15% (100/104) on the hint-free, source-aware
   XBOW benchmark using Claude models as the reasoning engine. This isn't
   speculative — it's benchmarked, productized, and is functionally "an
   LLM worm" aimed at a repo: an agent that reads the tree, reasons over
   it, and tries to exploit what it finds.
3. **AI tarpits are a proven, deployed countermeasure — but aimed at web
   scrapers, not code-recon agents.** Nepenthes (endless fake link
   mazes), Iocaine (garbage generation tuned to poison training data),
   and Cloudflare's AI Labyrinth (bot-gated maze pages) all work the same
   way: waste the crawler's compute/tokens on procedurally generated junk
   rather than trying to block it outright. None of the tools surveyed
   target an agent exploring a *git repository* with tool-calling
   (read-file, run-command) instead of following HTML links.
4. **Honeytokens/canary tokens are the standard way to detect (not just
   waste) an intruder**, and there's now LLM-specific work on this:
   "Identifying AI Web Scrapers Using Canary Tokens" (arXiv 2605.13706)
   serves unique per-visitor tokens and checks whether they resurface in
   a model's output later, as proof that model ingested the content.
   Classic honeytoken practice (Thinkst Canarytokens et al.) plants fake
   credentials/URLs and alerts on any use.

Sources pulled during research (see search results in-session for full
titles): Schneier on Security's Morris II writeup; NeuralTrust "The Dawn
of the AI Worm"; arXiv 2605.24659, 2605.02812, 2403.02817
(ComPromptMized); Cloudflare AI Labyrinth blog; toxsec.com "AI Tar Pits
Are Drowning LLM Scrapers in Infinite Garbage"; XBOW "We Ran 1,060
Autonomous Attacks"; the Shannon Lite Medium writeup; arXiv 2605.13706
("Identifying AI Web Scrapers Using Canary Tokens"); DevSecOps School's
honeytoken guide.

### Prior art considered, not repeated

The deleted `LLM install-time semantic diversification` doc proposed
source-level AST rewriting via a local code LLM, applied per-device at
install time (successor to "runtime name scrambling"). It's a legitimate
but heavyweight direction: 2-3 months for an academic prototype, 12-18
months for production, and it requires a local 30B+-class coder model.
More importantly, it only obscures the *real* codebase from static
analysis — it does nothing to slow down or detect an agent that's
actively probing the live, running system, and an attacker who has
obtained the original source can still diff against the rewritten
version if they have both. It's a moving-target defense against static
analysis, not a countermeasure against an autonomous agent actively
exploring a repo. I didn't resurrect it — it wasn't buildable unattended
in one session, and it addresses a different part of the threat surface
than what follows. Worth a dedicated future session if the human wants
to invest in it; it's complementary to, not a replacement for, the
toolkit below.

### What was built this session: `babbleon/` decoy + honeytoken toolkit

Given the research above, the highest-leverage thing buildable in one
session — and the one that actually matches the project's name and
stated goal — is a **repo-level tarpit for autonomous code-recon/exploit
agents**: plant decoy files that look like real attack surface (leaked
config, a fake legacy-admin backdoor, internal ops notes with a fake
staging URL), each carrying a unique fake secret. An agent that reads and
acts on these wastes tool-calls and time on nothing; if a planted secret
ever resurfaces elsewhere, `babbleon verify <string>` confirms it came
from this repo and which file leaked it.

Modules (stdlib-only, zero third-party dependencies):

- `babbleon/honeytoken.py` — fake-secret generator (`Honeytoken`
  dataclass: id/kind/value/created_at). **Deliberately avoids mimicking
  real provider formats** (e.g. AWS's `AKIA...` access-key prefix) so a
  planted token doesn't trip GitHub's secret-scanning partner program and
  get auto-forwarded to a real cloud provider as a false report. The goal
  is to read as *a* credential to a naive grep or an LLM agent skimming
  the tree, not to pass a specific vendor's format validator.
- `babbleon/wordbank.py` — small randomization word lists (codenames,
  service names, hosts, usernames). This matters specifically *because*
  babbleon is open source: if every deployment produced byte-identical
  decoy text, an attacker who knows the tool could grep for its literal
  template strings and skip every trap. Randomizing the filled-in words
  each `seed` run doesn't make decoys unfingerprintable (the pack
  *structure* is still public — see Limitations) but it raises the cost
  above a single string match.
- `babbleon/decoys.py` — three packs: `leaked_env` (a fake
  `.env.<env>.bak` with an API key + DB URL), `legacy_admin` (a fake
  Python module implementing the classic hardcoded-backdoor-password
  pattern, not wired into any real router), `internal_notes` (a markdown
  doc naming a fake internal staging URL).
- `babbleon/registry.py` — JSON ledger at `<repo>/.babbleon/registry.json`
  recording every planted path + token, with substring/id lookup so a
  partially leaked or reformatted token can still be traced back to its
  source file.
- `babbleon/cli.py` — `babbleon --path <repo> {seed [pack...] | list [-v]
  | verify <string> | clean}`.
- `tests/` — 19 unit tests across all four modules (stdlib `unittest`
  only, no network, `tempfile`-scoped). All passing. Also manually
  smoke-tested the full `seed` → `list -v` → `verify` (hit + miss) →
  `clean` cycle end-to-end on a scratch directory and eyeballed the
  generated decoy content for plausibility.

### Safety/effectiveness note that matters more than it looks like

`.babbleon/registry.json` holds every honeytoken value **in plaintext**
and is the map of exactly which files are fake. It's gitignored by
default (see `.gitignore`) and **must never be committed into the same
repo it's protecting** — if it were, anyone (human or LLM agent) reading
the repo could open it and get the full list of decoys and real secret
values, which defeats the entire mechanism. If you need the registry
past the local clone, copy it somewhere separate from the seeded repo
(password manager, a private repo, wherever) — don't let it ride along
with the thing it's meant to trap.

### Limitations (honest, not hedging on shipping)

- **No live callback yet.** This is a local-only, offline toolkit today:
  `verify` checks a string against the local registry; it does not
  detect *when* an agent reads or exfiltrates a decoy in real time. A
  real deployment needs either (a) a listener behind the fake
  `internal_url`/`admin_override` values that alerts on any hit, or (b)
  periodic external scanning (pastebins, model outputs, bug-bounty
  reports) piped through `babbleon verify`. This is the natural next
  build (see below) — I didn't invent a callback backend unattended
  because *where* it's hosted is an infra decision for whoever deploys
  this, not something to guess at.
- **OSS fingerprintability is a real arms race, not a solved problem.**
  Randomizing filled-in words raises the cost of "grep the tool's GitHub
  repo for template strings" but doesn't eliminate it — a motivated
  attacker (or one specifically targeting known babbleon users) can
  still learn the *structural* tell, e.g. "`legacy_admin.py` always
  defines `authenticate(username, password)` checking one hardcoded env
  var." Mitigation for a real deployment: fork/customize the templates
  in `decoys.py` per-user rather than running the shipped packs verbatim.
- **Doesn't touch the real codebase.** By design this is orthogonal to
  (and much cheaper than) the deleted semantic-diversification track —
  it adds tripwires around the real code, it doesn't obscure the real
  code itself. The two are complementary, not competing; nothing here
  forecloses picking the other one up later.

### Needs manual (human) review before wider use

1. **Scope check**: planting honeytokens in your own repo is
   well-precedented defensive practice (Canarytokens etc.), but this
   should only ever be deployed on repos you own/control — never seeded
   into a shared/third-party repo without consent, since a decoy showing
   up in someone else's PR review would be an unpleasant surprise, not a
   trap that helps anyone.
2. **Decide on a live-callback backend** (webhook/DNS canary behind
   `internal_url` and `admin_override` values) — needs a place to host a
   listener, which is a real infra/cost decision for the human, not
   something to invent unattended.
3. **Decide whether to revisit the semantic-diversification track** from
   the deleted commit. Still a reasonable direction; much bigger scope
   (months of work, needs a local coder-class LLM); didn't fit this
   session and isn't superseded by what got built here.

### Suggested next steps, priority order

1. ~~Add a `check`/pre-commit-hook guard against committing
   `.babbleon/`~~ — **done later in this same session**, see the
   2026-07-05 (continued) entry below.
2. Add a live-callback pack variant (token embeds a URL to a
   user-supplied webhook instead of a fully local placeholder), gated
   behind an explicit `--callback-base-url` flag so nothing calls home
   unless the operator opts in.
3. Expand decoy packs (fake CI/CD secrets, fake package-registry tokens)
   once the above lands, since those are what an autonomous exploit
   agent chasing supply-chain-style objectives would specifically go
   looking for.

---

## 2026-07-05 (continued) — registry safety guard

Picked up next-step #1 from above in the same session rather than
stopping. Added `babbleon/safety.py` plus two new CLI subcommands:

- `babbleon check` — inspects the target repo with `git check-ignore` /
  `git ls-files` / `git diff --cached` and reports (non-zero exit) if
  `.babbleon/` exists but isn't gitignored, or if any registry file is
  tracked or staged.
- `babbleon install-hook` — writes (idempotently, appending rather than
  clobbering an existing hook) a `pre-commit` hook that runs `check` and
  aborts the commit on a real finding.

**Bug found and fixed during manual smoke testing, not just unit tests:**
the first version of the installed hook shelled out to
`python3 -m babbleon.cli ... check` unconditionally. In a target repo
where `babbleon` isn't pip-installed (the common case — most repos this
would protect aren't the babbleon repo itself), that import fails and
the hook printed a `ModuleNotFoundError` and blocked *every* commit, not
just ones touching the registry. That's a strictly worse failure mode
than the mistake the hook exists to prevent. Fixed by probing
`python3 -c "import babbleon"` first: if it fails, the hook now prints a
warning and lets the commit through (fails open); it only fails closed
once the check actually ran and found a problem. Added two integration
tests (`tests/test_safety.py::HookExecutionTests`) that invoke a real
`git commit` subprocess against the installed hook script — one with
`PYTHONPATH` pointing at this repo (import succeeds → commit blocked),
one without (import fails → commit allowed with a warning) — plus
confirmed both paths by hand outside the test suite. This is exactly the
kind of bug that unit tests calling `cli.main()` in-process would never
catch, since they never actually exec the shell script; worth keeping
that pattern (real subprocess + real git repo) for anything that
generates a script meant to run outside this process.

30 unit/integration tests total, all passing. Nothing else changed in
this pass — the limitations, safety note, and remaining "needs manual
review" items from the first entry above still stand unchanged.

---

## 2026-07-05 (continued 2) — opt-in live callback

Picked up next-step #2 (now renumbered #1): a live-callback variant so a
honeytoken can point at a real endpoint the operator controls, instead
of only ever being inert local text.

- `honeytoken.Honeytoken` gained a `live: bool = False` field.
  `make_internal_url(host, callback_base_url=None)` now takes an
  optional http(s) base URL; when given, the token's value becomes
  `<callback_base_url>/babbleon/<fake-host>/<token-id>` and `live=True`.
  With no argument (the default, unchanged from before), behavior is
  identical to the original local-placeholder URL.
- `DecoyPack.build()` across all three packs now accepts
  `callback_base_url=None`; only `InternalNotesPack` acts on it (it's the
  only pack whose planted value is a URL an agent might actually fetch —
  `leaked_env`'s DB connection string and `legacy_admin`'s hardcoded
  password aren't things a generic HTTP client tool-call would hit, so
  wiring them to a callback wouldn't do anything and would be dishonest
  plumbing). The other two packs accept and ignore the parameter so the
  call signature stays uniform across `ALL_PACKS`.
- `babbleon seed --callback-base-url <url>` is the opt-in switch,
  validated to start with `http://`/`https://` or the command fails
  before touching disk. Omitting it (the default) makes zero network
  calls, matching the design constraint from the first entry above.
  `list -v` and `verify` now tag live tokens with `[live]` so an operator
  can tell at a glance which planted values are wired to something real
  versus which are just text.
- Found one polish-level bug via manual smoke test rather than unit
  tests: `InternalNotesPack` built its fake host as
  `f"{service}.internal.{random_tld}"`, and the TLD wordbank includes
  `"internal"` as one of its options — occasionally producing
  `search-svc.internal.internal`, which reads as obviously fake to a
  human (redundant labeling) in a way the rest of the decoy doesn't.
  Fixed by excluding `"internal"` from the TLD choice in that one pack.
  Not security-relevant, but worth noting: **manual smoke-testing the
  actual generated output caught this; the unit tests (which only
  checked structural properties like "token id appears in the URL")
  never would have.** Same lesson as the pre-commit hook bug two entries
  up — generated/templated output needs a human (or an agent) actually
  looking at a sample, not just asserting invariants about it.

Still no live callback *infrastructure* was built or deployed — this is
client-side plumbing only, per the original scoping note ("where it's
hosted is an infra decision for whoever deploys this"). 36 tests total,
all passing.

### Still open (unchanged from the first entry, restated for whoever picks this up next)

- Decide whether to actually stand up a callback receiver, or keep this
  purely opt-in for people who bring their own.
- ~~Expand decoy packs (fake CI/CD secrets, fake package-registry
  tokens)~~ — **done next in this same session**, see below.
- Decide whether to revisit the deleted install-time semantic-diversification
  track (source-level AST rewriting, months of scope, still un-started).

---

## 2026-07-05 (continued 3) — supply-chain-flavored decoy packs

Added two more packs, bringing the total to five (`ALL_PACKS` in
`decoys.py`):

- `npm_registry_token` — a `.npmrc.bak` with a fake
  `//registry.npmjs.org/:_authToken=...` line, framed as a leftover from
  a local `npm publish --dry-run`.
- `ci_deploy_secrets` — `ci/secrets.env.bak` with a fake `DEPLOY_TOKEN`
  and `DOCKER_REGISTRY_PASSWORD`.

Rationale: an autonomous exploit agent chasing supply-chain-style
objectives (publish a malicious package version, push to a container
registry, trigger a CI deploy) is a documented, higher-blast-radius
outcome than reading one repo's own secrets — it's the "worm" framing
in the project name at its most literal, since a compromised publish
credential *does* propagate to every downstream consumer. These packs
target exactly that reconnaissance path.

Added a new `honeytoken.make_registry_token(label)` maker (same shape as
`make_api_key`, distinct `kind="registry_token"` so `list -v`/`verify`
output stays descriptive per pack). Both packs ignore
`callback_base_url` for the same reason `leaked_env`/`legacy_admin` do —
neither planted value is a URL, so there's nothing to point at a
callback.

Updated `test_seed_then_list_then_verify_then_clean` (`tests/test_cli.py`)
to assert against `len(decoys.ALL_PACKS)` instead of a hardcoded `3`,
so it won't silently need editing again next time a pack is added.
Added dedicated shape tests for both new packs plus a
`test_all_pack_names_are_unique` guard. 40 tests total, all passing.
Manually inspected generated `.npmrc.bak` / `ci/secrets.env.bak` output
for plausibility (see this entry's session log) rather than trusting
assertions alone — same practice as the last two entries.

### Still open, unchanged

- Live-callback receiver infrastructure (client-side plumbing only
  exists so far).
- The deleted install-time semantic-diversification track — still
  un-started, still a reasonable multi-month follow-up if the human
  wants it, still orthogonal to everything built in this session.

---

## 2026-07-05 (continued 4) — path/filename randomization, scatter-on-reseed

Closed a gap flagged as a limitation in the very first entry above
("OSS fingerprintability is a real arms race") and, separately, an
awkward property of the original design: every pack always wrote to
one fixed path (`config/.env.<env>.bak`, `internal/legacy_admin.py`,
`docs/INTERNAL_NOTES.md`, `.npmrc.bak`, `ci/secrets.env.bak`). Two
problems with that: (1) an attacker who knows babbleon exists can just
check those five exact paths and skip every decoy without even reading
them, which defeats content-level randomization entirely; (2) running
`seed` a second time silently overwrote the first decoy instead of
adding a second one, so there was no way to scatter more decoys through
a large repo short of inventing new pack types.

Fixed both by giving each pack 3-5 directory and/or filename variants
(new lists in `wordbank.py`: `CONFIG_DIRS`, `NOTES_DIRS`/`NOTES_FILENAMES`,
`ADMIN_DIRS`/`ADMIN_FILENAMES`, `CI_DIRS`/`CI_FILENAMES`, `NPM_DIRS`) and
picking one per build. `write_pack()` now also calls a new
`_avoid_collision()` helper that renames (via a short random suffix)
rather than overwrites if the randomly-chosen path happens to already
have a file there — so `seed leaked_env` run three times in a row now
produces three distinct decoys in three distinct locations (verified by
hand: `deploy/config/.env.prod.bak`, `infra/config/.env.preprod.bak`,
`settings/.env.internal.bak` on one real run), and `clean` still removes
all of them correctly since it already worked off the registry's path
list rather than assuming fixed locations.

Chose plausible-but-boring filenames for the admin-panel decoy
(`legacy_admin.py`, `old_admin_panel.py`, `admin_console_v1.py`,
`deprecated_admin.py`) rather than anything that announces itself (e.g.
avoided naming a file literally `admin_backdoor.py` — a real backdoor is
never self-labeled that obviously, and a name like that would make an
attacker *more* suspicious it's a trap, not less).

Updated tests that had asserted exact literal paths (`test_decoys.py`'s
npm/CI shape tests) to check suffix/membership instead, since paths are
no longer deterministic. Added `test_paths_vary_across_repeated_builds`
(all 5 packs), `test_avoid_collision_renames_on_forced_clash` (forces
the collision deterministically rather than relying on random luck),
and `test_write_pack_twice_scatters_instead_of_overwriting`. 43 tests
total, all passing. Manually verified both the scatter behavior and
that `clean` still fully cleans up afterward.

This is now a reasonably complete v1 for one unattended session: 5
decoy packs, path+content randomization, opt-in live callbacks, and a
registry-leak safety guard, all with tests that were checked against
real generated output by hand, not just structural assertions. The two
items under "still open" above (live-callback hosting, the semantic-
diversification track) are the only things left that genuinely need a
human decision rather than more unattended engineering.

---

## 2026-07-05 (continued 5) — verified packaging, added CI

Two things hadn't actually been exercised despite `pyproject.toml`
existing since the first commit: the editable install and the
`babbleon` console-script entry point. Tested both directly (fresh
venv, `pip install -e .`, then ran `babbleon --path <tmp> seed` via the
installed script rather than `python3 -m babbleon.cli`) — both work.
Also ran the full test suite under Python 3.10 and 3.12 (both present
on this machine) in addition to the 3.11 it had been running under all
session; `pyproject.toml` claims `>=3.9` support and nothing in the
codebase should care (the one place a 3.10+ union-type hint appears,
`honeytoken.make_internal_url`'s `str | None` parameter, is inert on
3.9 because `from __future__ import annotations` defers evaluation —
confirmed by parsing the module's AST, since no 3.9 interpreter was
available locally to run it directly).

Added `.github/workflows/tests.yml`: runs the unittest suite on Python
3.9/3.11/3.12 on every push and PR, plus the same install+console-script
smoke check done by hand above, so packaging regressions get caught
automatically instead of depending on someone remembering to test it
manually like this session just did.

No further code changes planned unattended beyond this point without a
new research thread or explicit next step — the toolkit is at a stable,
tested, documented stopping point. Anyone picking this up next should
start from "Still open" above.

---

## 2026-07-05 (continued 6) — a design gap found by reflection, not a web search

Per the standing instruction (research something new if there's no
active plan, note or build depending on what it turns up), and having
just declared the toolkit "stable" above: rather than another external
search, I re-examined babbleon's own design for gaps, since the tool is
now complete enough to reason about end-to-end. Found a real one.

**The problem:** babbleon's decoys are deliberately built to look like
real attack surface to *any* LLM agent reading the repo tree — that's
the whole mechanism. But "any agent" includes a legitimate coding
assistant the repo's own developer is using for ordinary work in that
same seeded repo. Ask an assistant to "review this repo for security
issues" and it will flag `internal/legacy_admin.py`'s hardcoded
`_OVERRIDE` password comparison as a real finding — correctly, by the
assistant's own lights, since that pattern is a textbook hardcoded
backdoor and most security-review prompts don't reason about
liveness/reachability before flagging it. Same risk for `.env.*.bak`
files and the CI secrets pack: a "grep for leaked credentials" pass
would surface every one of them as if they were real leaks. This
wasn't addressed anywhere in the first five entries above — the threat
model discussion was all about the *adversarial* agent, not the
project's own legitimate tooling running in the same environment.

**Why the obvious fixes don't work:** a marker that's legible to
"friendly" tooling (a comment saying `# BABBLEON DECOY`, a
`.security-ignore` file sitting next to the decoy) is legible to an
adversarial agent's recon step too, for the same reason honeytoken
values can't use real-provider prefixes (see the very first entry) —
anything that helps your own tools recognize a decoy also helps an
attacker who's read babbleon's source recognize it, which defeats the
trap. The registry (`.babbleon/registry.json`) already solves exactly
this class of problem for the *attacker* case (it's the out-of-band,
never-committed list only the operator can see) — the fix here is
making that same mechanism usable by legitimate local tooling without
weakening it against the adversarial case, since a coding assistant
running locally has the same filesystem access as the repo's own
maintainer, not an outside attacker's.

**What was built:** `Registry.is_decoy(path)` (accepts either an
absolute path or one relative to the repo root, resolves both to the
same comparison) and a new `babbleon is-decoy <path>` CLI command
(exit 0 = known decoy, exit 1 = not) for scripting into a security
scanner or an assistant's own pre-flight check. Documented the pattern
in the README: point an AI coding assistant's project instructions
(e.g. its `CLAUDE.md`) at running `is-decoy` before treating a
hardcoded-secret-shaped finding as real. This doesn't fully solve the
problem — it's opt-in, and it only works for a *local* assistant that
has filesystem access to the never-committed registry in the first
place, not a hosted/remote assistant working from a plain clone — but
it's the right mechanism given the constraint above, and it's
consistent with everything else already built (the registry was
already the one place with this specific property).

6 new tests (3 on `Registry.is_decoy`, 1 CLI-level) — relative match,
absolute match, absolute-path-outside-root correctly returns `False`
rather than raising. 47 tests total, all passing. Manually verified
the command with both relative and absolute paths against a real
seeded scratch repo.

### Still open (superseding the shorter list two entries up)

- Live-callback receiver infrastructure — still just client-side
  plumbing, no hosted service exists or should be stood up without the
  human choosing where.
- The deleted install-time semantic-diversification track — still
  un-started, still multi-month scope, still orthogonal to this
  session's work.
- The `is-decoy` mitigation above only covers *local* assistants with
  filesystem access to `.babbleon/`. A hosted/remote assistant working
  from a plain `git clone` of a seeded repo (no registry present) has
  no way to tell a decoy from a real file. Whether that's acceptable,
  or whether it needs a second, more limited mechanism (e.g. a single
  well-known marker file listing *paths only*, no honeytoken values,
  that's still excluded from the adversarial threat model because path
  disclosure alone doesn't hand over working credentials) is a genuine
  open design question, not obviously resolvable without the human's
  judgment call on how much of the trap they're willing to trade away
  for convenience.

---

## 2026-07-05 (continued 7) — independent adversarial review, 4 real bugs found and fixed

Rather than write another entry declaring the toolkit "stable" and stop,
spawned an independent reviewer with no context beyond the code itself
and instructions to actually reproduce anything it flagged, not just
theorize. It read all six modules, all five test files, the CI
workflow, and `pyproject.toml` line-by-line, checked subprocess calls
for injection risk (list-form throughout, no `shell=True`, no
user-controlled string reaches a shell — clean), and found four real
bugs plus several nitpicks, each with a live repro. All fixed here, in
severity order:

1. **`cmd_seed`'s registry was only saved once, after the whole pack
   loop.** If any pack's write throws partway through (repro: pre-create
   plain files blocking every path variant `ci_deploy_secrets` could
   land on — collision reliably hits `FileExistsError` inside
   `full_path.parent.mkdir`), every previously-planted decoy in that run
   was already on disk with a live honeytoken but never reached
   `registry.json`. That's not just an inconvenience — it meant
   `is-decoy` would wrongly report those exact files as *not* known
   decoys, silently defeating the one feature built specifically to
   protect legitimate tooling from false-positiving on them (see the
   previous entry). Fixed with `try/finally: registry.save()` around the
   loop, so partial failure still leaves the registry consistent with
   whatever actually landed on disk. Reproduced the exact failure
   scenario by hand (blocking all four `CI_DIRS` options with plain
   files) both before and after the fix — before: 4 real decoys on disk,
   0 registry entries, `is-decoy` said "no" for all 4; after: same crash
   still propagates (expected — a genuinely broken repo tree should
   fail loud), but all 4 decoys are now correctly registered and
   `is-decoy` says "yes" for each.
2. **`Registry.is_decoy`'s relative-path branch didn't normalize the
   same way the absolute-path branch did.** The absolute branch already
   called `.resolve()`; the relative branch just did `str(p)`. Repro:
   `is_decoy("internal/../internal/legacy_admin.py")` returned `False`
   for a file `is_decoy("internal/legacy_admin.py")` correctly found —
   silently wrong for exactly the kind of non-canonical path a caller's
   own `os.path.relpath()` might hand it. Fixed by resolving both
   branches through the same `(self.root / p).resolve()` path before
   comparing, with the existing `ValueError` catch still handling
   "outside root" for both forms.
3. **`decoys._avoid_collision` only checked once and had a
   check-then-write race.** If the *renamed* candidate also happened to
   exist, it returned that path anyway and the caller silently
   overwrote a second real decoy — the opposite of the function's
   stated purpose. Separately, existence-check-then-write is not atomic,
   so two concurrent `seed` runs could still race onto the same path.
   Replaced with `_candidate_paths()` (an unbounded generator: original
   path, then randomized fallbacks) consumed by `write_pack()` using
   `os.open(..., os.O_CREAT | os.O_EXCL | os.O_WRONLY)`, which makes the
   existence check and the write a single atomic syscall and loops
   (bounded at 1000 attempts, then raises `RuntimeError` rather than
   looping forever or silently overwriting) until it lands on a
   genuinely free path.
4. **`cmd_install_hook` never actually wrote the shebang line for a
   brand-new hook file.** `existing = ... else "#!/bin/sh\n"` only held
   that string in memory to decide whether a leading newline was needed
   before appending — it was never written to disk. Confirmed by
   inspecting the raw bytes of a freshly-installed hook: it started
   directly with `\n# babbleon-registry-guard`, no `#!` line. It still
   worked in this sandbox only because Git's own hook runner falls back
   to `/bin/sh` on `ENOEXEC` for a script missing a shebang — an
   implementation detail of Git internals, not something to depend on.
   Fixed by writing `"#!/bin/sh\n"` to disk first when the hook file
   doesn't exist yet, *then* reading it back before the append/marker
   check. Reproduced before/after with `od -c` on the actual installed
   file.

Also fixed two nitpicks flagged alongside the bugs, since both were
cheap and directly improved correctness of things right next to the
bug fixes above:

5. `safety.check()` could print "exists but is not gitignored -- add it
   to .gitignore" even when the `.gitignore` entry was completely
   correct, because `git check-ignore` reports a path as not-ignored
   once it's already in the git index regardless of `.gitignore`
   content — so the message was actively wrong remediation advice once
   the file was already staged/tracked. Reordered so the
   not-gitignored check only runs when neither the tracked nor the
   staged check already fired.
6. `cmd_seed` with a mix of valid and invalid pack names (e.g.
   `seed legacy_admin totally_bogus_pack`) silently planted the valid
   one and said nothing about the typo. Now validates that every
   requested name is known before planting anything, erroring out with
   the full list of unknown names if not.
7. `Registry.save()` now writes to a `.tmp` file and renames over the
   real one (`Path.replace`, which is atomic on POSIX) instead of
   writing `registry.json` in place, so a crash mid-write can't leave a
   truncated file that the next `_load()` would choke on with a raw,
   uncaught `JSONDecodeError`.

Test changes: replaced the now-nonexistent `_avoid_collision` unit test
with tests on the new `_candidate_paths` generator plus two
`write_pack` tests that force real, deterministic collisions via
`unittest.mock.patch` on `secrets.token_hex` (one that must loop past
two occupied paths to the third, one that must exhaust the retry budget
and raise) rather than relying on random luck. Rewrote
`test_randomization_varies_across_builds`, which the reviewer correctly
flagged as trivially true for the wrong reason (it compared whole
`LeakedEnvPack` build strings, which always differ because every build
also embeds a fresh random honeytoken — the assertion would have passed
even if the wordbank picks never varied at all); it now isolates and
compares only the wordbank-driven DB host substring. Added regression
tests for the `is_decoy` normalization fix (`../` traversal, a `./`
prefix) and for the corrected `safety.check()` messaging (staged +
correctly-gitignored must produce the "staged" message only, not also
the misleading "not gitignored" one).

51 tests total (up from 47), all passing. Every fix above was manually
verified against the real, reproduced failure condition, not just
against the new unit test — the review's whole value was that it
worked from live repros instead of code-reading alone, so the fixes
were held to the same bar.

### One more thing flagged for manual review, not decided here

There is no `LICENSE` file anywhere in this repo. License choice is a
legal/business decision for the repo owner, not something to pick
unilaterally in an unattended session — flagging it here rather than
guessing. Worth resolving before anyone outside this session is
expected to depend on or contribute to `babbleon/`.

### Confidence note for whoever reads this next

This is now a second independent pass over the same code (mine, then a
fresh reviewer's) with real bugs found both times — the pre-commit-hook
fail-open/fail-closed bug during my own manual testing, then these four
during the adversarial review. That's not a reason to trust the current
state less; it's the reason to trust it *more* than a single pass would
warrant, precisely because both passes actually exercised the code
against real inputs and real failure conditions instead of stopping at
"the unit tests pass." Anyone extending this should keep doing that —
manually reproduce the failure mode a change is meant to fix, and
manually reproduce that the fix actually closes it, before considering
it done.

---

## 2026-07-05 (continued 8) — one more robustness gap, found while re-reading the review's own fixes

While re-reading `registry.py` to write the entry above, noticed
`Registry._load()` had no error handling at all around
`json.loads(self.file.read_text())` — a `registry.json` that's
corrupted (partial write from some future non-atomic path, hand-editing,
disk issue) would blow up with a raw, unhandled `JSONDecodeError` on
every single command (`list`, `verify`, `is-decoy`, `clean`, even a
fresh `seed`, since `Registry.__init__` always calls `_load()`).
Silently treating a corrupt file as an empty registry would be worse —
that would make `list`/`verify` quietly forget about decoys that are
still sitting on disk with live honeytoken values — so the fix fails
loud, but with an actual message instead of a traceback: `_load()` now
catches `JSONDecodeError` and re-raises as `RuntimeError` with the file
path, the underlying parse error, and a warning not to delete the file
without first checking whether decoy files are still on disk. Wired a
top-level `try/except RuntimeError` into `cli.main()` so this (and the
existing collision-budget-exhaustion `RuntimeError` from `write_pack`,
finding #3 two entries up) prints as a clean `error: ...` line and exits
1, instead of a Python traceback reaching the terminal.

Verified end-to-end against a real corrupted file (not just the two new
unit tests): `echo "{not valid json" > .babbleon/registry.json` then
`babbleon list` now prints exactly the intended message and exits 1,
where before this fix it would have dumped a full traceback. 53 tests
total (up from 51): one on `Registry` raising directly, one at the CLI
layer confirming `cli.main()` converts it to a clean message rather than
letting it propagate as a traceback.

No other changes this pass. Everything from "Still open" three entries
up is still open and still needs the human's call, not more unattended
engineering.
