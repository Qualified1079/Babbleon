# v1 is DEPRECATED — do not extend

The following crates are **v1 of Babbleon**:

- `crates/babbleon/`           — v1 library
- `crates/babbleon-cli/`       — v1 CLI binary
- `crates/babbleon-ns-helper/` — v1 setuid namespace helper
- `crates/babbleon-pam/`       — v1 PAM module

**v1 is not the public product** and will not ship.  The reasons
are recorded in `V2_PLAN.md` §"Why v1 is not the public product":

1. Identifier-only scramble is structurally fingerprintable.
2. Security conventions were bolted on, not designed in.
3. Privilege model is over-broad (setuid-root for what should
   be three file capabilities).

v2 lives at `crates/v2-*` and is the source of truth.

## Rules for agents

- **Do not extend `crates/babbleon*`.**  No new features, no
  refactors, no back-ports of v2 patterns.
- **Do not back-port v2 fixes to v1.**  v1 stays at its current
  shape as a reference implementation; the operator's plan is
  to rename the branch to `v1-maintenance` and freeze it.
- **You may read v1 as reference.**  v2 explicitly carries forward
  many v1 primitives (HKDF migration, zeroize patterns, tier
  detection, tripwires, response policy).  v1 is the working
  example; v2 is the rewrite.
- **Do not run `cargo test --workspace`.**  It will trip on v1
  drift.  Run `cargo test -p v2-babbleon-core` (and other
  `-p v2-*` crates) instead.

If a v1 crate's behavior is load-bearing for understanding a v2
design choice, link to the specific file from a `docs/v2/*.md`
note explaining what was carried forward and what was
deliberately changed.  Do not assume an agent reading the v2
docs will independently grep v1.

## When v1 actually goes away

The plan in `V2_PLAN.md` §"What stays in `crates/` from v1
unchanged" is *nothing* — v1 source is preserved at a tag
`v1-reference` once v2 takes shape, then removed from `main`.
Until then it lives here, marked deprecated.

See `CLAUDE.md` for the broader entry-point routing.
