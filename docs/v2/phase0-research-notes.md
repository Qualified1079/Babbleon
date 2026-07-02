# Phase 0 — additional research notes

Beyond the obfuscation-landscape research (`docs/v2/obfuscation-landscape.md`),
phase 0 needed five more research threads to inform the operator
decisions and the phase 1+ implementation.  Notes below; the
operator-decision recommendations live in `docs/v2/phase0-decisions.md`.

## 1. MITRE ATT&CK current version

**v17 (April 2025)** was the previous public release.  Current
(June 2026): **15 Tactics, 222 Techniques, 475 Sub-Techniques,
174 Groups, 821 Software, 56 Campaigns, 44 Mitigations,
697 Detection Strategies, 1758 Analytics, 106 Data Components**.

v17 added the ESXi platform and significantly improved Enterprise
Mitigation descriptions; both improvements help Babbleon's
mapping because we can cite ESXi-specific mitigations for any
hypervisor-deployed trusted-tier scenarios.

**For v2 phase-0:**  `docs/v2/threat-model.md` (next-up doc) cites
ATT&CK current version explicitly; uses the v17+ mitigation
language.

Source: [MITRE ATT&CK v17 release](https://medium.com/mitre-attack/attack-v17-dfb59eae2204)

## 2. NIST SP 800-190 structure

Published 2017; not subsequently revised but remains authoritative.
Five-section structure:

| Section | Topic |
|---|---|
| §3.1 / §4.1 | Image risks / countermeasures |
| §3.2 / §4.2 | Registry risks / countermeasures |
| §3.3 / §4.3 | Orchestrator risks / countermeasures |
| §3.4 / §4.4 | Container risks / countermeasures |
| §3.5 / §4.5 | Host OS risks / countermeasures |

**For Babbleon:** sections 3.4 / 4.4 (Container) and 3.5 / 4.5
(Host OS) are the relevant pair.  We don't ship images, registries,
or orchestrators; we use containers (mount + PID namespaces) and
expose host-OS concerns through the launcher's privilege model.

Source: [NIST SP 800-190 PDF](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-190.pdf)

## 3. NIST SP 800-207 seven tenets

The canonical Zero Trust Architecture document.  Seven tenets:

1. All data sources and computing services are considered resources.
2. All communication is secured regardless of network location.
3. Access to individual resources is granted on a per-session basis.
4. Access determined by dynamic policy (identity + state + context).
5. Enterprise monitors integrity and security posture of all assets.
6. Authentication and authorisation are dynamic and strictly enforced.
7. Enterprise collects as much info as possible to improve posture.

**For Babbleon — tenet-by-tenet mapping:**

| # | Tenet | v2 implementation |
|---|---|---|
| 1 | Resources | Tools, credentials, processes all classified as resources |
| 2 | Communication secured | Tier boundary; intra-host communication denied across tier |
| 3 | Per-session access | Each rotation epoch = new session; mapping changes |
| 4 | Dynamic policy | Trust-tier check via mnt-NS inode at every wrapper exec |
| 5 | Posture monitoring | Tripwire FIFO + audit log + response policy |
| 6 | Dynamic auth/authz | Per-exec NS-inode check; vault unlock per session |
| 7 | Info collection | Audit log (Ed25519-signed) + tripwire events |

**For v2 phase-0:** the full map lands in
`docs/v2/threat-model.md`.

Source: [NIST SP 800-207 — Stratix summary](https://stratixsystems.com/seven-tenets-of-zero-trust-architecture/)

## 4. Python keyword stability

Python 3.13 has:
- **35 reserved keywords** (`if`, `def`, `return`, `class`, `import`,
  `for`, `while`, `try`, `except`, `with`, `as`, `from`, `lambda`,
  `yield`, `pass`, `break`, `continue`, `raise`, `global`, `nonlocal`,
  `is`, `in`, `not`, `and`, `or`, `True`, `False`, `None`, `assert`,
  `async`, `await`, `del`, `elif`, `else`, `finally`).
- **4 soft keywords** (`match`, `case`, `type`, `_`) — context-
  sensitive; act as keywords only in specific syntactic positions.

**For Babbleon layer 2 (operator scramble):**

- **Reserved keywords are always-safe to substitute.**  No context
  detection needed.  The preprocessor un-substitutes by lookup.
- **Soft keywords need context-aware handling.**  Easier option:
  leave soft keywords alone in v2.0.  They appear in code less
  frequently than reserved keywords and the obfuscation gain from
  scrambling them is small.
- **Python version compatibility:** the reserved-keyword set has
  grown slowly (`async`/`await` Python 3.7, none since).  Soft
  keywords expand more frequently.  v2 preprocessor reads the
  target Python version from the file's shebang or a `# python:` tag
  and uses the corresponding keyword set.

Source: [Python keyword module docs](https://docs.python.org/3/library/keyword.html)

## 5. Python import hooks (PEP 451)

The mechanism by which v2 can intercept module imports — required
because Python scripts often `import` other Python scripts, and
the wrapper-shebang approach only handles top-level invocation.

**API:**
- Register a `MetaPathFinder` in `sys.meta_path`.
- `find_spec(name, path, target)` returns a `ModuleSpec` for any
  Babbleon-scrambled module (or `None` to defer to the next finder).
- The spec's `loader` provides `exec_module(module)` which runs the
  unscrambled source in the module's namespace.

**For Babbleon v2:** ship a tiny `babbleon_importer` package that
installs the finder.  The user adds one line to their entry-point
(or it's auto-installed by `babbleon-python` shim).  Modules
import normally; the finder transparently unscrambles.

Source: [PEP 451](https://peps.python.org/pep-0451/)

## 6. PEP 657 — fine-grained error locations

Python 3.11+ tracebacks include column offsets.  **For Babbleon
v2 layer 3 (whitespace-as-words):** the preprocessor changes
column positions massively.

**Design constraint, not blocker.**  The Python interpreter sees
the *unscrambled* source via the pipe / importlib loader.  Its
tracebacks point to positions in the unscrambled view, not in
the scrambled file on disk.

**Operator UX implication:**
- Developers debug via `babbleon unscramble FILE` and see clean
  source with traceback-matching positions.
- The editor plugin (VS Code) shows the unscrambled view by
  default; on-disk file remains scrambled.
- Error messages exposed to operators reference the unscrambled
  view, which they can view via `babbleon unscramble`.

Source: [PEP 657](https://peps.python.org/pep-0657/)

## 7. Existing Python obfuscators

**PyArmor** — most production-grade.  Does rename + bytecode
obfuscation + string encryption + selective C compilation.  Does
NOT do whitespace-as-words, operator scramble, or any layer
2-12.  v2 doesn't duplicate PyArmor; v2 extends the obfuscation
toolkit for the LLM-attacker threat model.

**Pyminifier** — light-weight.  Removes whitespace and comments,
renames.  Strictly a subset of v1's identifier scramble; not
competitive.

**Cross-cutting note:** the existing tools' threat models are
"protect proprietary code from human reverse engineers" or "fit
code in a smaller form factor."  Neither is the LLM-attacker
threat.  v2's value is the threat-model fit, not the
obfuscation strength per se.

Sources:
- [PyArmor repo](https://github.com/dashingsoft/pyarmor)
- [Pyminifier discussion](https://benjitrapp.github.io/attacks/2024-02-04-python-code-obfuscation/)

## 8. VS Code editor extension pattern

For v2 layer 3 (whitespace-as-words) the editor must show clean
source while disk holds scrambled bytes.  Standard pattern:

- `contributes.languages` registers a language id for `.py` (or
  `.babbleon`) files associated with Babbleon-scrambled content.
- `contributes.grammars` provides a TextMate grammar for the
  unscrambled view.
- Custom text-document content provider implements
  scramble-on-save / unscramble-on-load via the trusted-tier
  `babbleon unscramble` / `babbleon scramble` CLI calls.

**For v2 phase-3 prototype:** ship a minimal VS Code extension
alongside the preprocessor.  Vim / Emacs / JetBrains
integrations land in phase 6 (release engineering).

Source: [VS Code language extensions](https://code.visualstudio.com/api/language-extensions/overview)

## 9. Confidential VM landscape (TEE)

Confirmed 2025 production status:

| Provider | Offering | Substrate |
|---|---|---|
| AWS | Nitro Enclaves (separate primitive) | EC2 + Nitro hypervisor |
| AWS | EC2 with SEV-SNP (instances) | AMD EPYC |
| Azure | Confidential VMs (DCasv5/DCadsv5) | AMD SEV-SNP |
| Azure | SGX VMs (DCsv5/DCdsv5) | Intel SGX |
| GCP | Confidential VMs | AMD SEV / SEV-SNP / Intel TDX |
| GCP | Confidential Space | Containerised attested workloads |
| VMware | Cloud Foundation 9.0 | TDX + SEV-SNP |

**Developer laptop availability: none.**  TDX requires recent
Xeon (server-class).  SEV-SNP requires EPYC (server-class).  No
consumer CPU ships with either.

**For TEE direction decision** (operator decision #5):  v2.0
cannot assume TEE on developer laptops.  Either v2.0 targets
enterprise/cloud only, or v2.0 ships without TEE and v3 adds it.

Sources:
- [AWS Nitro Enclaves](https://aws.amazon.com/ec2/nitro/nitro-enclaves/)
- [Azure confidential VMs analysis](https://medium.com/cloud-security/azure-confidential-vms-fb820899885a)
- [Confidential computing 2025 review](https://medium.com/blacksecurity/confidential-computing-f4bcf8827963)

## 10. Prompt-injection corpus licenses (round 2)

Round 1 confirmed garak Apache 2.0.  Round 2 checked the remaining:

- **BIPIA (Microsoft)** — repo is MIT.  **Benchmark datasets carry
  separate licenses:** WikiTableQuestions and Stack Exchange
  components are CC-BY-SA 4.0 (share-alike + attribution required).
  Vendor-able but with CC-BY-SA tracking burden.  Babbleon's
  PolyForm Noncommercial license must coexist with CC-BY-SA
  attribution — no conflict, just discipline.
- **Purple Llama Evals (Meta)** — **MIT**, clean.  CyberSecEval
  prompt-injection set is permissive.  **Add to vendoring pool
  alongside garak.**

**Updated layer 11 vendoring plan:**
- garak (Apache 2.0) — primary, ~500 payloads
- Purple Llama Evals (MIT) — secondary, additional payloads
- BIPIA — defer to v2.1 until CC-BY-SA discipline is in place
- IPI Arena, LLMail-Inject, PINT — still need per-LICENSE check

Sources:
- [BIPIA LICENSE](https://github.com/microsoft/BIPIA)
- [Purple Llama repo](https://github.com/facebookresearch/PurpleLlama)
- [garak repo](https://github.com/NVIDIA/garak)

## 11. Wordlist entropy analysis

Provisional pool allocations from `obfuscation-landscape.md` /
`TODO.md`:

| Role | Words per epoch | Compound N | Compound space |
|---|---|---|---|
| Identifier | 370k | 4 | 1.87 × 10²² |
| Decoy | 100k | 1-3 | up to 10¹⁵ |
| Direction marker | 20k | 1-3 | up to 8 × 10¹² |
| Whitespace | 10k | 1-2 | up to 10⁸ |
| Keyword | 5k per language | 1 | 5k each |
| Prompt injection | ~500 payloads | n/a | sample-from-pool |

**Information-theoretic check:** the identifier compound space
(10²²) is so far above the information-theoretic minimum
(~log₂(N_tools) bits) that collisions are negligible even for
N=2000 tools.  Smaller roles still have enough entropy to be
unguessable.

**Cross-role disjointness:** disjoint subsets per role per epoch
prevents leakage between roles.  Subset selection is itself
HKDF-derived from the per-epoch key, so an attacker who learns
"word X is in the identifier pool" gains no information about
which words are in the marker pool for the same epoch.

**No new design constraint** — provisional sizes are
information-theoretically adequate.

**2026-07-02 addendum — density-tuned identifier pool.**  The
identifier role has since been analysed for tokenization density
(see `tools/wordlist-density-analysis/RESULTS.md`).  The peaked
distribution of the baseline (73–76 % of the 369 652 entries sit
at 2–3 BPE tokens under cl100k/o200k) makes a mid-tail filter
meaningful; the leading candidate `intersect [3, 5]` keeps
223 009 words while raising compound token cost by
+15.4 % / +16.1 % (cl100k / o200k, three-seed mean, 2000 samples
at compound-n=4).  Even at 223 009 entries the identifier compound
space at compound-n=4 is 223 009⁴ ≈ 2.47 × 10²¹, well above the
information-theoretic minimum (log₂ N_tools bits) and above the
10²² baseline by only a fraction of a bit per compound.  The
filter therefore trades a negligible fraction of a bit of
theoretical entropy per compound for a measurable increase in
attacker attention cost.  Whether that increase translates into a
crack-rate delta is the adversarial-LLM re-test's job (HANDOFF
2026-06-27 priority 1) — this addendum only settles the entropy
side of the ledger.

**2026-07-02 addendum #2 — role-partitioning formula executable.**
The provisional table above has been formalised as an executable
calculator in `tools/wordlist-role-partitioning/`.  It applies a
per-role entropy target (Birthday bound for compound_n ≥ 2 draws,
Uniqueness bound for the compound_n = 1 and permutation-driven
roles) and reports the derived pool sizes plus fit-in-wordlist
verdict for a chosen (wordlist, attacker) pair.  Under the tool's
`developer_laptop_default` posture (2 000 events/epoch, 1e-6
lifetime collision probability, 8 760-epoch lifetime) the six-role
allocation is 215 387 words — 58 % utilization of the 369 652-word
English baseline, 97 % utilization of the 223 009-word
`intersect[3, 5]` filter output.  The paranoid posture (1e-12
lifetime target) does not fit any English-only corpus; the
mismatch is the tool's explicit signal that phase-4's multi-
language pool is a prerequisite for that posture.  See
`tools/wordlist-role-partitioning/RESULTS.md` for the four preset
scenarios and the sensitivity table.

---

## Cross-cutting findings

1. **The preprocessor pipeline is well-supported by existing
   Python machinery.**  PEP 451 import hooks + PEP 657 column
   offsets + the standard shebang mechanism all align.  No need
   to invent new infrastructure.
2. **Existing source-obfuscation tools (PyArmor, Pyminifier) do
   NOT do layers 2-12.**  v2 is novel territory in that sense.
3. **TEE is enterprise/cloud only as of 2025.**  Developer-laptop
   deployment cannot use it.  Drives the TEE direction decision.
4. **Prompt-injection corpora are vendor-able under permissive
   licenses.**  garak (Apache 2.0) + Purple Llama Evals (MIT)
   together provide a clean v2.0 starting payload set.
5. **NIST 800-207 zero-trust tenets map cleanly onto v2's
   trust-tier model.**  The mapping is documentary, not a
   redesign.

---

Each of the eleven research items above informs one or more
operator decisions or phase-1+ deliverables.  Recommendations
in `docs/v2/phase0-decisions.md`.
