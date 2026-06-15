# DEFERRED

Technical items identified during development that are not yet implemented.
Prefix meanings:
  REVIEW(manual) — needs human eyes before ship; in-code tag points here
  DEFERRED(Mx)   — explicitly planned for milestone Mx
  DEFERRED(later)— real issue, no milestone assigned yet

Items removed from this list have landed; see `TODO.md` for shipped checkmarks
and `HANDOFF.md` for the most recent session's work.

---

## Vault

**DEFERRED(M2) FIDO2 get_assertion flow**
File: `crates/babbleon/src/vault/fido2.rs`
The CTAP2 hmac-secret assertion call returns `HardwareUnavailable`.
Need: authenticator-rs PublicKeyCredentialRequestOptions wiring behind
`--features fido2`, PIN handling, user-presence prompt, origin/rp_id wiring,
and multi-authenticator testing (YubiKey 5, Solokey, OnlyKey — extension
support varies). Blocked on hardware arrival for the multi-authenticator
test matrix.

**REVIEW(manual) USB keyfile path is unencrypted metadata**
File: `crates/babbleon/src/vault/usb.rs`
The keyfile path is passed at runtime, not stored in vault. If it were stored
(for UX convenience) it would be an unencrypted metadata leak.
Decision: keep path caller-supplied, never store in vault. Documented in
`docs/operator.md`. Listed here so the decision is not silently reversed.

**DEFERRED(M2.5) TPM authorized policy for post-kernel-update re-seal**
File: `crates/babbleon/src/vault/tpm.rs`
After a kernel update, PCR 8/9 values change; the sealed blob becomes
unreadable. Current workaround: manual re-seal via `babbleon tpm-reseal`
(stub exits 2 with instructions). Production path: `tpm2_policyauthorize`
with a signing key that lets the admin issue new PCR policies without
re-sealing the KEK. See tpm2-tools docs. Blocked on TPM hardware arrival.

**DEFERRED(M2.5) tpm2-abrmd vs /dev/tpm0 test matrix**
File: `crates/babbleon/src/vault/tpm.rs`
Resource manager behavior (tpm2-abrmd daemon vs direct /dev/tpm0 access)
differs between distros and kernel versions. Test matrix required before
ship. Blocked on TPM hardware arrival.

---

## Enforcement

**DEFERRED(M3) tini-as-PID-1 pattern**
File: `crates/babbleon-ns-helper/src/main.rs`
The ns-helper currently does its own reaper loop after `unshare(NEWPID)`.
Good enough for M3; revisit if zombie reaping proves fiddly in real
workloads. Switching to `tini` as PID 1 with `babbleon-ns-helper` as a
child is the textbook pattern.

**DEFERRED(M4) O(N) bind cost for large manifests**
File: `crates/babbleon/src/enforcement/linux_ns.rs`
At N=200 tools per mount cycle ≈ 50 ms; at N=2000 (enterprise scale)
this needs revisiting. Options: FUSE overlay; bind a single pre-prepared
directory tree instead of per-binary mounts; OverlayFS lowerdir union.

---

## Credentials (M4)

**DEFERRED(M4+) OverlayFS per-app writable upper layers**
File: `crates/babbleon/src/credentials.rs`
The shipped credential gate uses a tmpfs overlay per cred dir. A per-app
writable upper layer via overlayfs would let untrusted-tier processes
make local edits without contaminating the trusted view. Architecture
TBD: overlayfs vs bind-mount-per-app.

---

## Deception

**DEFERRED(M3.5+) Honey tripwire response policy**
File: `crates/babbleon/src/events.rs`
`HoneyTriggered` events currently only fan out to sinks (stderr / JSONL).
No active response. Planned: a `ResponsePolicy` enum selectable per host:
  - `NotifyOnly` (current behavior; baseline)
  - `KillTrigger` — SIGKILL the process that exec'd the honey wrapper
    (the wrapper's PPID), guarded by `/proc/<ppid>/stat` start-time check
    to defeat PID-reuse races
  - `KillTriggerTree` — `kill -KILL -<pgid>` to take the whole process group
  - `Quarantine` — move the triggering process into a freezer cgroup
  - `SystemAlert` — escalate to PAM / login-blocking state
Permissions: same-uid kills are free; cross-uid needs CAP_KILL via the
ns-helper privilege gate.

**DEFERRED(M3.5+) Background wordlist-permutation pre-build**
File: `crates/babbleon/src/mapping/fpe.rs`
Each fresh epoch costs a ~18 ms Fisher-Yates over the 370k-word
permutation (measured in `tools/rotation-benchmark/RESULTS.md`).
Spawning a thread on epoch advance to build epoch+1's permutation
turns the next rotation tick into a cache hit (~0.2 ms).  Required
for the high-frequency rotation that defeats the Type 3 hybrid
attacker (docs/threat-model.md).

**DEFERRED(M3.5+) Unified runtime-table wrapper**
File: `crates/babbleon/src/enforcement/wrapper.rs`
Today each rotation re-renders one shell script per tracked tool
(~0.4 ms each, dominating rotation cost above N≈100).  A single
wrapper binary that reads its scrambled name from a runtime table
file would collapse rotation to one atomic table write.  Combined
with the perm pre-build above, this enables millisecond-class
rotation.

**DEFERRED(M3.5+) Stale-mapping tripwire**
File: `crates/babbleon/src/mapping/mapper.rs`
The current honey-name set is random compounds derived from
`HMAC(host_secret, "babbleon-honey-v1")`. It catches random guessing
and wordlist scrapes. It does NOT catch an attacker who exfiltrated a
mapping at epoch T and tries to use it at epoch T+1 — those stale
scrambled names just look like unknown commands.
Plan: at rotation, retain the previous K epochs' scrambled→real maps
in a `StaleMappingIndex`. Any exec attempt against a name in that index
becomes a high-confidence tripwire (a legitimate user has no reason to
type a name they last saw before the last rotation). Disjoint from the
random honey set; both fire `HoneyTriggered` with a `source` tag.

---

## General

**DEFERRED(later) Backup/restore with stale mapping archives**
File: `crates/babbleon/src/backup.rs`
`BackupBundle` versions epoch + host_secret + tracked manifest + wordlist
hash. Restoring an old snapshot needs an explicit policy: re-seal under
the current mapping, or honor the snapshot's mapping until next rotation?
No policy yet; current behavior is implicit re-seal on restore.

**DEFERRED(M5+) macOS driver**
Endpoint Security framework + Keychain / Secure Enclave backend.
FUSE for sandbox demo only.

**DEFERRED(v3+) Windows driver**
Minifilter for the namespace-equivalent piece; research-only stage.
