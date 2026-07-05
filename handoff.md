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
