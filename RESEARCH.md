# Babbleon — Research Log

Living document. Topics from `PLAN.md` §12 + the agreed research slate, worked
through one at a time. Each section records: question, method, findings,
implications for the plan, open follow-ups.

Status legend: ⬜ not started · 🟡 in progress · ✅ done · 🟥 blocked

## Tier 1 — decision-blocking

- ⬜ **T1. Moving Target Defense vs LLM/automated attackers** — prior art sweep
- ⬜ **T2. Agentic-exploitation capability literature** — what current LLM exploit harnesses actually do
- ⬜ **T3. Per-process filesystem view mechanisms on Linux** — mount ns / OverlayFS / FUSE / pam_namespace
- ⬜ **T4. eBPF-LSM maturity** for file/exec gating
- ⬜ **T5. Hardware-unlock primitives** — FIDO2 hmac-secret, TPM 2.0 sealing, OS keychains

## Tier 2 — shapes implementation

- ⬜ **T6. LLM/BPE tokenizer behavior** on lowercase concatenated compounds
- ⬜ **T7. Credential-store inventories** across modern dev/cloud tooling
- ⬜ **T8. Env-var vocabulary** attackers actually scrape
- ⬜ **T9. Package manager hook surfaces** (dpkg/rpm/brew/flatpak/snap)
- ⬜ **T10. Binary fingerprinting countermeasures**
- ⬜ **T11. `/proc` and PID-namespace gotchas**

## Tier 3 — confirm assumptions

- ⬜ **T12. CSPRNG + bijective mapping construction**
- ⬜ **T13. Wordlist sources** and licensing
- ⬜ **T14. Backup/snapshot interaction with rotation**
- ⬜ **T15. macOS / Windows feasibility scan**
- ⬜ **T16. Naming / trademark / prior-project collision check**

---

<!-- Findings appended below as each topic completes. -->
