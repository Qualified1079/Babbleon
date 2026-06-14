# DEFERRED

Technical items identified during development that are not yet implemented.
Prefix meanings:
  REVIEW(manual) — needs human eyes before ship; in-code tag points here
  DEFERRED(Mx)   — explicitly planned for milestone Mx
  DEFERRED(later)— real issue, no milestone assigned yet

---

## Vault

**DEFERRED(M2) FIDO2 get_assertion flow**
File: babbleon/vault/fido2.py `_get_hmac_output()`
The CTAP2 hmac-secret assertion call is stubbed with NotImplementedError.
Need: python-fido2 PublicKeyCredentialRequestOptions wiring, PIN handling,
user-presence prompt, origin/rp_id wiring, and multi-authenticator testing
(YubiKey 5, Solokey, OnlyKey — extension support varies).

**REVIEW(manual) Argon2id params for IoT / headless server**
File: babbleon/vault/soft.py
m=46MiB/t=2/p=1 is sized for laptops. A second param profile with lower m
and higher t (same time-cost, less RAM) is needed for embedded/server targets.
Store profile selection in vault header so it's self-describing.

**REVIEW(manual) USB keyfile path is unencrypted metadata**
File: babbleon/vault/usb.py
The keyfile path is passed at runtime, not stored in vault. If it were stored
(for UX convenience) it would be an unencrypted metadata leak.
Decision: keep path caller-supplied, never store in vault. Document this in user docs.

**REVIEW(manual) TPM authorized policy for post-kernel-update re-seal**
File: babbleon/vault/tpm.py
After a kernel update, PCR 8/9 values change; the sealed blob becomes
unreadable. Current workaround: manual re-seal via `babbleon tpm-reseal`.
Production path: tpm2_policyauthorize with a signing key that lets the admin
issue new PCR policies without re-sealing the KEK. See tpm2-tools docs.

**REVIEW(manual) tpm2-abrmd vs /dev/tpm0**
File: babbleon/vault/tpm.py
Resource manager behavior (tpm2-abrmd daemon vs direct /dev/tpm0 access)
differs between distros and kernel versions. Test matrix required before ship.

---

## Enforcement

**REVIEW(manual) Trust-tier detection in banner wrapper**
File: babbleon/enforcement/wrapper.py
The current wrapper returns null output for --help regardless of caller tier.
Production should detect the caller's trust tier (trusted → exec real binary
with real output; untrusted → null/deception). Best mechanism: compare
/proc/self/ns/mnt inode against the known trusted-NS inode at launch time.
Alternatives: session cookie env var (defeated by env scrape), parent PID tree.
Mount NS inode comparison is most robust; needs prototyping.

**REVIEW(manual) CAP_SYS_ADMIN requirement in launcher**
File: babbleon/enforcement/launcher.py, babbleon/enforcement/linux_ns.py
unshare(CLONE_NEWNS | CLONE_NEWPID) requires CAP_SYS_ADMIN or a user
namespace. Production lifecycle: small setuid C helper that does the
unshare, drops privileges, then invokes the Python driver. Do NOT keep
CAP_SYS_ADMIN in the Python process any longer than the two syscalls.

**REVIEW(manual) Python-at-PID-1 signal handling**
File: babbleon/enforcement/launcher.py
Spawning Python as PID 1 in a new PID namespace makes SIGCHLD handling
fiddly (zombie reaping). M3.5: use tini as init, exec babbleon-launcher
as a child.

**DEFERRED(M3) hidepid=2 /proc remount**
File: babbleon/enforcement/linux_ns.py `present_untrusted()`
The /proc remount with hidepid=2 is attempted but silently swallowed on
failure. This only works correctly inside a fresh PID namespace. The setuid
helper must establish the PID NS before invoking LinuxNamespaceDriver.
Status: needs the setuid helper (DEFERRED(M3)).

**DEFERRED(M3) pam_babbleon.so PAM module**
The PAM module that manages mount-namespace lifecycle at login is not yet
written. This is the production lifecycle for LinuxNamespaceDriver.
Pattern: pam_namespace.so for reference.

**DEFERRED(M3) seccomp-bpf filter for untrusted tier**
Per PLAN.md §8: ptrace, process_vm_readv, process_vm_writev, kcmp,
pidfd_open, pidfd_getfd, pidfd_send_signal must be denied to untrusted-tier
processes. No seccomp filter written yet.

**DEFERRED(M3) Landlock self-sandbox**
Per PLAN.md §8: Landlock LSM applied to untrusted tier for per-process
containment (no boot flag required, kernel 5.13+). No implementation yet.

**DEFERRED(M3.5) Banner deception table**
File: babbleon/enforcement/wrapper.py
M3.5: wrapper returns plausible-wrong banner (e.g. curl-scrambled → nano
help text). Deception table mapping real-tool → decoy-tool needs design;
adversarial test against ObserverWard/WhatWeb required before ship.

**DEFERRED(M4) O(N) bind cost for large manifests**
File: babbleon/enforcement/linux_ns.py
At N=200 tools ~50ms; at N=2000 (enterprise) revisit. Options: FUSE overlay
or bind a single pre-prepared directory tree instead of per-binary mounts.

---

## Credentials (M4)

**DEFERRED(M4) IPC socket isolation**
SSH_AUTH_SOCK, gpg-agent socket, DBUS_SESSION_BUS_ADDRESS, XDG_RUNTIME_DIR
must not be inherited in untrusted tier. Not yet implemented.

**DEFERRED(M4) OverlayFS per-app writable upper layers**
Per-app writable credential-dir upper layers via overlayfs.
Architecture TBD: overlayfs vs bind-mount-per-app.

---

## General

**DEFERRED(M3) Rotation cadence scheduler**
No cron / systemd timer for automatic epoch rotation yet.
Plan: ship a systemd service + timer unit; generate via `babbleon install`.

**DEFERRED(later) Honey-mapping tripwire response policy**
Detection signal alone vs active response (kill process, alert, throttle)?
No policy implemented; EventBus emits the signal; consumer decides.

**DEFERRED(later) Backup/restore mapping-aware path**
Mapping archive must be versioned alongside backup snapshots.
Restore to old snapshot needs policy for re-seal / re-wrap with stale mapping.

**DEFERRED(M5+) macOS driver**
Endpoint Security framework + FUSE (sandbox/M1 only) + Keychain/Secure Enclave.
Windows: minifilter, research-only (v3+).
