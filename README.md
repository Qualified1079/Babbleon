# Babbleon
An idea to confuse LLM worms and such.

See `handoff.md` for research notes and status. Current prototype:
`babbleon/diversify.py` — deterministic, seed-keyed renaming of Python
local identifiers, so two installs of the same codebase read differently
to an LLM doing recon while behaving identically.

```
python3 -m babbleon.diversify path/to/file.py --seed <per-install-seed>
```

Tests: `python3 -m unittest discover -s tests`

