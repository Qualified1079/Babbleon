# Least-privilege execution — v2 design

Every privileged operation in v1 was audited in the question
"is the caller asking for the minimum necessary capability or is it
asking for more than it needs?"  This document records the
findings and locks in v2's stance: **no setuid-root, file
capabilities only, every syscall site documents the specific
capability it requires.**

## Why this matters

Over-broad capability grants compound attack surface.  A bug in a
function that *needs* `CAP_SYS_ADMIN` for one mount call but runs
with full root authority can be turned into arbitrary file-system
manipulation, kernel module loading, or namespace escape, because
the process already holds every capability.

The rule: each privileged action runs in a short-lived context
that holds only the capability that action requires, dropped
before any child exec.

## v1 audit findings

### `babbleon-ns-helper` is `4755 root:root` (setuid-root)

**What it actually needs:**

| Operation | Capability required |
|---|---|
| `unshare(CLONE_NEWNS | CLONE_NEWPID)` | `CAP_SYS_ADMIN` |
| `mount(... MS_PRIVATE | MS_REC)` on `/` | `CAP_SYS_ADMIN` |
| `mount("proc", ..., "hidepid=2")` | `CAP_SYS_ADMIN` |
| `bind_mount(src, dst)` | `CAP_SYS_ADMIN` |
| `setuid(real_uid)` (drop back to caller) | `CAP_SETUID` |
| `setgid(real_gid)` | `CAP_SETGID` |
| `mlockall(MCL_CURRENT|MCL_FUTURE)` | `CAP_IPC_LOCK` |
| `prctl(PR_CAPBSET_DROP, ...)` | none (bounding-set drop is unprivileged for self) |
| `prctl(PR_SET_NO_NEW_PRIVS)` | none |
| `seccompiler::apply_filter(...)` | none (with NNP set) |
| `landlock::restrict_self(...)` | none |
| `fork()` | none |
| `execvp(...)` | none |

**The total capability set v2 needs:** `CAP_SYS_ADMIN`,
`CAP_SETUID`, `CAP_SETGID`, `CAP_IPC_LOCK`.

**v1 grants:** all 41 capabilities (full root).

**Gap:** 37 unnecessary capabilities, including
`CAP_DAC_OVERRIDE`, `CAP_KILL`, `CAP_NET_RAW`, `CAP_NET_ADMIN`,
`CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_BPF`, etc.  Every one of
these is an escalation vector if any bug in the helper grants
arbitrary syscall execution.

### `babbleon-cli` runs as the invoking user

No privileged operations in the CLI itself.  Hardening calls
(`PR_SET_DUMPABLE`, `RLIMIT_CORE`, `mlockall`) are all
self-targeting; the first two need no capability; `mlockall`
needs `CAP_IPC_LOCK` OR a sufficient `RLIMIT_MEMLOCK` (typical
unprivileged container often grants neither — we accept partial
hardening with a `tracing::warn!`).

**No gap.**  v1 is correct here.

### `pam_babbleon.so` runs in the PAM context

PAM modules execute in whatever context the PAM stack provides.
For `session optional pam_babbleon.so` in `common-session`, that
is usually the user's UID after the session-open.  The module
invokes `babbleon-launch-untrusted` (v2 name); the launcher is
where setuid happens.

**No gap** in the PAM module itself; the gap is in the
launcher's installation mode (setuid vs file caps).

### `LinuxNamespaceDriver::mount_scrambled_view` runs post-unshare

Inside the new mount namespace, the kernel grants `CAP_SYS_ADMIN`
to the caller for operations on that new namespace's mounts.
This is the documented `unshare(CLONE_NEWNS)` behaviour and is
correct — bind-mounts and tmpfs mounts inside the new NS do not
require host-level admin.

**No gap.**

### `credentials::apply_untrusted_gate` mounts tmpfs over credential dirs

Same as above — runs post-unshare; the new-NS capabilities
suffice.

**No gap.**

### `enforcement::response::signal_kill` sends SIGKILL

Same-uid kills are unprivileged.  Cross-uid kills would require
`CAP_KILL` and are not attempted today (the wrapper's PPID is
always same-uid by construction — exec is on the user's
shell).

**No gap** for the current implementation.  When the response
policy is extended to handle cross-uid triggers (e.g. honey
wrapper invoked by a setuid binary), the kill path must run
through the launcher with `CAP_KILL` granted only for that one
signal.

### `babbleon-mapping-worker` (v2 only, planned)

The structure-scrambling design needs a separate-uid worker to
pre-build epoch N+1's wordlist permutation in background (see
v1 measurement: ~18 ms Fisher-Yates per fresh epoch).  This
worker is a v2 component; recording its privilege model here
for completeness:

| Operation | Capability required |
|---|---|
| `read(wordlist file)` | none (file readable by owner) |
| `compute Fisher-Yates over 370k entries` | none |
| `write(activated table)` to pipe | none |
| `mlockall(MCL_CURRENT|MCL_FUTURE)` | `CAP_IPC_LOCK` |

Total: `CAP_IPC_LOCK` only.  Runs as its own UID with no other
capabilities.

## v2 stance

### Install mode for privileged binaries

v2 ships `babbleon-launch-untrusted` with **file capabilities**,
not setuid:

```sh
setcap 'cap_sys_admin,cap_setuid,cap_setgid,cap_ipc_lock=ep' \
    /usr/local/libexec/babbleon-launch-untrusted
chmod 0755 /usr/local/libexec/babbleon-launch-untrusted
```

The four capabilities listed are exactly the ones audited above.
No file-system overhead; no setuid-root.  An attacker exploiting
a bug in the launcher gains only those four caps, not the full
root capability set.

### Interaction with `PR_SET_NO_NEW_PRIVS`

File caps interact with `PR_SET_NO_NEW_PRIVS` differently from
setuid:

- **Setuid:** `PR_SET_NO_NEW_PRIVS = 1` set *after* setuid means
  the inherited euid stays effective but execve cannot regain
  setuid bits.  Standard pattern.
- **File caps with `+ep`:** the `e` and `p` flags mean
  effective and permitted; on exec, the launcher gets the caps.
  Setting `PR_SET_NO_NEW_PRIVS = 1` *before* exec disables the
  cap-elevation; you have to grant caps via the file metadata
  AND inherit, then set NNP after the elevation has happened.

v2 launcher order:
1. Get invoked (caps granted by file metadata).
2. Drop all caps except the four needed (PR_CAPBSET_DROP for
   every cap not in {SYS_ADMIN, SETUID, SETGID, IPC_LOCK}).
3. Apply hardening (PR_SET_DUMPABLE = 0, RLIMIT_CORE = 0,
   mlockall — uses IPC_LOCK).
4. unshare(NEWNS|NEWPID) — uses SYS_ADMIN.
5. make_root_private — uses SYS_ADMIN.
6. bind-mounts, tmpfs — uses SYS_ADMIN (post-unshare, but the
   cap is still needed at this stage).
7. PR_SET_NO_NEW_PRIVS = 1.
8. Apply seccomp (NNP allows unprivileged install).
9. setuid(real_uid), setgid(real_gid) — uses SETUID, SETGID.
10. Drop SYS_ADMIN, SETUID, SETGID, IPC_LOCK from permitted set.
11. fork, exec child.

By step 10 the launcher holds no capabilities and cannot
re-acquire any (NNP guarantee).  The child inherits an empty
capability set.

### Per-syscall capability annotations in code

Every syscall site in v2 carries a comment naming the capability
it consumes:

```rust
// CAPABILITY: CAP_SYS_ADMIN (kernel grants this for unshare(NEWNS)).
// Dropped at step 10 of the launcher lifecycle; this call site is
// expected to run only inside that window.
syscalls::enter_new_mount_namespace(CloneFlags::NEWNS | CloneFlags::NEWPID)?;
```

Reviewers can grep `CAPABILITY:` to enumerate every privileged
operation in the codebase.

### `cap-std` instead of raw libc where possible

Rust's `cap-std` crate exposes a capability-secure file-system
API.  v2 uses it for any file operation that takes an
attacker-influenceable path (e.g. honey-FIFO reads, audit-log
writes), so the call is bound to a capability-pre-validated
handle rather than a path that could be substituted between
check and use (TOCTOU).

### seccomp deny-list for every long-running binary

Every binary that stays alive for more than a single exec
applies a seccomp deny-list at startup:

| Binary | Seccomp profile |
|---|---|
| `babbleon-cli` | deny `bpf`, `mount`, `unshare`, `clone(CLONE_NEWNS)`, raw `ptrace`. |
| `babbleon-launch-untrusted` | post-step-10 deny: everything except `read`, `write`, `wait`, `waitid`, `sigreturn`, `exit*`. |
| `babbleon-mapping-worker` | deny everything except `read`, `write`, `mlockall`, `brk`, `mmap`, `mprotect`, `exit*`. |
| `babbleon-preprocessor` | deny everything except `read`, `write`, `openat`, `close`, `mmap`, `mprotect`, `brk`, `execve`, `pipe2`, `dup3`, signal/exit syscalls. |

Each profile is implemented in the corresponding crate, applied
in `main()` before any work, and asserted to be present via a
self-test (a denied syscall fails with EPERM in a controlled
fashion).

## Open audit items carried into v2

- **AppArmor / SELinux profile templates.**  Belt-and-
  suspenders against the capability set above.  v1 has these
  filed in TODO; v2 ships them.
- **`yama.ptrace_scope = 2` enforcement.**  v1 documents it as a
  recommended host setting; v2 either enforces it at install
  time or refuses to start.  The latter is friendlier to
  developers; the former is friendlier to security.  Decide.
- **No-CAP_BPF-anywhere policy.**  The eBPF-LSM scaffold exists
  in v1 but never loads (kernel gate at 6.1).  When v2 phase 6
  enables it, the BPF load happens in a dedicated short-lived
  process that holds `CAP_BPF` for the load call only.  No
  long-running BPF-capable process.
- **No-CAP_KILL-anywhere policy.**  The response-policy code
  in v1 only does same-uid kills.  v2 keeps that invariant or
  routes cross-uid kills through a dedicated capability-held
  helper.

## Tests

Each privileged operation has a paired test that asserts the
capability set held by the calling process at the moment of the
call.  Implemented via `capng` or by reading `/proc/self/status`
`CapEff` line.  The test asserts the bit set matches the
documented "CAPABILITY:" comment.

Drift detection: if a code change adds a new capability to the
held set without updating the documented set, the test fails.
