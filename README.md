# Babbleon
An ides to confuse LLM worms and such

## What's here

Autonomous LLM agents now clone repos, read source, and chain exploits on
their own (XBOW and similar pipelines have submitted 1,000+ real
vulnerabilities via fully autonomous runs; see `handoff.md` for sourcing).
`babbleon/` is a small, zero-dependency toolkit that plants **decoy files
with embedded honeytokens** in a repository -- fake leaked config, a fake
legacy admin backdoor, fake internal ops notes -- so that:

- an automated recon/exploit agent burns tool-calls and time chasing fake
  attack surface instead of real code, and
- if a planted secret ever resurfaces elsewhere (a scraped dataset, a bug
  bounty report, a pastebin dump), you can prove it came from here and
  which file leaked it.

Each `seed` run randomizes hostnames, codenames, and usernames so
repeated deployments don't share identical decoy text.

### Usage

```sh
python3 -m babbleon.cli --path /path/to/repo seed          # plant all packs
python3 -m babbleon.cli --path /path/to/repo seed leaked_env  # plant one pack
python3 -m babbleon.cli --path /path/to/repo list -v        # see what's planted
python3 -m babbleon.cli --path /path/to/repo verify "<string>"  # trace a leak
python3 -m babbleon.cli --path /path/to/repo clean          # remove decoys
```

Or, after an editable install (`pip install -e .`), just `babbleon ...`.

### Optional: live callbacks

By default every honeytoken is a local, inert placeholder -- babbleon
never makes a network call. If you run your own webhook receiver (or a
canary-token service) and want a real hit when an agent actually fetches
a planted URL, pass `--callback-base-url`:

```sh
python3 -m babbleon.cli --path /path/to/repo seed --callback-base-url https://hooks.example.com/<your-id>
```

Only the `internal_notes` pack embeds a fetchable URL, so it's the only
one affected; it points at `<callback-base-url>/babbleon/<fake-host>/<token-id>`
instead of a placeholder, and `list -v`/`verify` mark that token `[live]`.
This flag is entirely opt-in -- omit it and nothing changes.

### Important: the registry is sensitive

Every `seed` run writes `<repo>/.babbleon/registry.json` with every planted
path and honeytoken **in plaintext**. It's gitignored by default and must
never be committed into the same repo it's protecting -- anyone who can
read it gets the full list of decoys, which defeats the trap. Keep it
local, or copy it somewhere separate from the seeded repo if you need it
later.

Two commands guard against that mistake:

```sh
python3 -m babbleon.cli --path /path/to/repo check         # fail if the registry is un-ignored, tracked, or staged
python3 -m babbleon.cli --path /path/to/repo install-hook  # install a pre-commit hook that runs `check` automatically
```

The installed hook fails *open* (warns, allows the commit) if `babbleon`
isn't importable by whatever `python3` runs in the hook's environment --
e.g. it isn't installed in that repo's virtualenv -- and only fails
*closed* (blocks the commit) once it can actually run the check and finds
a real problem. That split matters: a hook that blocks every commit just
because it couldn't find the module is a worse failure mode than the one
it's trying to prevent.

### Tests

```sh
python3 -m unittest discover -s tests -v
```

See `handoff.md` for the research this was built from, its limitations,
and what still needs a human decision before wider use.
