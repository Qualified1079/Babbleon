# Babbleon — Session Handoff

Branch: `claude/magical-turing-mele8c`
Date: 2026-06-14
Last commit: `920e26d` — fix wrapper size fingerprint leak with unified template

---

## What was built this session

### M3 — Linux namespace enforcement (completed)
- `babbleon-ns-helper`: setuid binary, `unshare(NEWNS|NEWPID)`, drops caps, PR_SET_NO_NEW_PRIVS
- `LinuxNamespaceDriver`: bind-mounts trusted/untrusted views
- `/proc` remount with `hidepid=2` inside PID NS
- seccomp-bpf deny-list: ptrace, process_vm_readv/writev, kcmp, pidfd_*, bpf, perf_event_open, userfaultfd
- Landlock LSM filesystem sandbox (kernel 5.13+, graceful degradation)
- Wrapper trust-tier detection via `/proc/self/ns/mnt` inode comparison

### M3.5 — Deception layer (completed)
- Banner deception: scrambled wrappers return wrong `--help` text (curl→less, wget→man, etc.)
- Honey-name tripwires: FIFO pipeline — wrapper writes JSON → HoneyFifoReader → EventBus → HoneyTriggered
- Per-host SHA-256 padding in every wrapper (defeats ObserverWard / WhatWeb fingerprints)
- Adversarial fingerprint test harness: `crates/babbleon/tests/fingerprint.rs` (4 tests)
- eBPF-LSM exec-guard scaffold: `crates/babbleon/src/enforcement/ebpf.rs`, kernel gate MIN_KERNEL=6.1, BPF_LINK_CREATE (never pinned to bpffs)
- BPF C source: `tools/ebpf/exec_guard.bpf.c`, Makefile

### Bug fixes wired in this session
- **Wrapper bypass fix**: `present_untrusted` was bind-mounting real binaries, not wrapper scripts. Fixed with `wrapper_root: Option<PathBuf>` on `LinuxNamespaceDriver` and `with_wrappers()` builder.
- **Unified wrapper template** (last commit): honey and real-tool wrappers now use identical shell code. Runtime split via `/run/babbleon/honey.list`. Eliminates `ls -la` size fingerprint (was ~350B honey vs ~510B+ real-tool).
- **ns-helper seccomp deduplication**: replaced 40-line inline seccomp in ns-helper with `babbleon::enforcement::seccomp::apply_untrusted_filter()`.
- **Integration gap**: seccomp, Landlock, honey wrappers, HoneyFifoReader were all compiled but never called. Now wired into `cmd_apply_ns` in `babbleon-cli/src/main.rs`.

---

## Key invariants — do not break

1. **`NOTES.md` must NEVER be committed** — contains private research (LLM semantic diversification). Lives in `.gitignore`.
2. **Enterprise features** (escrow, SIEM, console) ship via a separate private repo only — never in this public repo.
3. **All Linux kernel calls flow exclusively through `syscalls.rs`** — other enforcement modules must have zero `nix` imports. This is the explicit audit rule in `linux_ns.rs` header.

---

## What's next (from TODO.md)

### Immediate / ready to implement
- **Wrapper-size fingerprint** — DONE this session (unified template). Mark `[x]` in TODO.md.
- **Audit-readability rename pass**: every public fn/type/module gets a name that describes purpose in plain English. Examples in TODO.md (present_untrusted → mount_scrambled_view, etc.). Filed, not yet implemented.
- **Threat-model-first module doc comments**: every file's top doc says what attack it defeats. Filed, not yet implemented.

### Pending testing (needs bare metal, not toolbox/podman)
- `make_root_private()` — is a no-op in unprivileged podman; works on bare metal
- `hidepid=2` on `/proc` — needs real PID namespace from ns-helper setuid path
- PAM session integration (`pam_babbleon.so`)
- Full setuid path for ns-helper
- User is on Fedora Silverblue; dev happens in `toolbox` (rootless podman container)

### HTML scrambler
- File exists at `tools/scrambler/index.html` (417 lines, complete)
- Open with: `file:///home/<user>/path-to-repo/tools/scrambler/index.html` in Firefox
- User wants to run adversarial simulation: paste scrambled Python puzzles, let LLM try to solve them
- Example puzzles directory (`tools/scrambler/example-puzzles/`) is TBD — needs puzzle files added

### M2 — still open
- FIDO2 `get_assertion` flow (skeleton at `vault/fido2.rs`, needs authenticator-rs behind `--features fido2`)
- TPM2 PCR-sealed backend (skeleton at `vault/tpm.rs`, tss-esapi wiring deferred)

### M5 — Enterprise (separate private repo)
- Escrow backend (admin recovery via separate KEK wrap)
- SIEM event sinks (Splunk HEC, syslog RFC5424)
- Enterprise console

---

## Key file map

```
crates/babbleon/src/
  enforcement/
    linux_ns.rs      — mount namespace driver; wrapper_root field; present_untrusted
    wrapper.rs       — unified wrapper template; write_wrapper, write_honey_wrapper, write_honey_list
    seccomp.rs       — BPF deny-list; apply_untrusted_filter()
    landlock.rs      — Landlock LSM; default_config, apply_sandbox
    ebpf.rs          — eBPF-LSM scaffold; probe(), BpfLsmHandle, kernel gate MIN_KERNEL=6.1
    syscalls.rs      — ALL nix/libc kernel calls go here
  events.rs          — EventBus, HoneyFifoReader, StderrSink, HoneyTriggered
  deception.rs       — DEFAULT_TRACKED map; decoy_for, banner_for_decoy
  tests/
    fingerprint.rs   — adversarial fingerprint tests (4 tests)
    enforcement.rs   — namespace enforcement tests

crates/babbleon-cli/src/
  main.rs            — cmd_apply_ns wires everything: wrappers, honey list, FIFO reader, driver

crates/babbleon-ns-helper/src/
  main.rs            — setuid helper; calls seccomp + landlock from babbleon crate

tools/
  scrambler/
    index.html       — standalone HTML adversarial test harness (complete)
    README.md        — workflow docs
  ebpf/
    exec_guard.bpf.c — LSM hook at bprm_check_security
    Makefile         — clang build; outputs to bpf_objects/
    README.md        — hardening guarantees (version gate, no pinning, post-load cap drop)
```

---

## Live test results (confirmed working in toolbox)

- Scrambled view: `ls /run/babbleon/scrambled` shows scrambled names only
- Deception: `<scrambled-curl-name> --help` from unshared namespace → shows `less` banner
- Honey tripwire: executing honey name → logs JSON to FIFO → HoneyFifoReader fires HoneyTriggered event, exits 127
- Seccomp + Landlock: applied in ns-helper before fork
- `/proc hidepid=2`: EPERM in podman (expected); works on bare metal

---

## Context for next session

To continue: start with `git checkout claude/magical-turing-mele8c && cargo build --workspace` to verify clean state. Then pick any item from the "What's next" section above. The HTML scrambler example puzzles are the most immediately useful for the adversarial simulation the user wants to run.
