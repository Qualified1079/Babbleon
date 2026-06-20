# Daemon syscall envelope — DRAFT for operator confirmation

**Status: draft.**  Filed 2026-06-20.  This is the enumeration of
every syscall the daemon makes today, broken down by lifecycle
stage, so the operator can sign off on the seccomp allowlist
before it lands in code.

The HANDOFF open-items list says, verbatim:

> Daemon seccomp profile.  Allowed-syscall list per
> `docs/v2/least-privilege.md` (daemon's expected envelope).  The
> envelope grew with materialise (openat / write / fchmod /
> unlinkat / read_dir); pin the profile only once the operator
> confirms the envelope.

This document is the envelope.

## Method

The list below was derived by reading every module under
`crates/v2-babbleon-daemon/src/` and `crates/v2-babbleon-core/src/`
(transitive dep) and recording every syscall the corresponding
Rust call could plausibly emit.  Where a single Rust call covers
multiple kernel entry points (`std::fs::write` ≈ `openat` +
`write` + `close`), all are listed.

A second confirmation pass should run the daemon under `strace -f`
on a real workload (start → status × N → rotate × N → emit-table ×
N → SIGTERM) and diff the recorded syscalls against this list.
That belongs in the same PR that pins the profile in code.

## Lifecycle stages

The daemon's lifecycle has three distinct privilege envelopes; the
seccomp profile must be the union but the staged breakdown helps
the operator reason about which calls are really load-bearing.

### Stage A — startup (before `seccomp` installs)

Runs in `main::run_daemon` before any peer can connect.  The
seccomp filter is **not yet installed** during this stage, so
these calls are unfiltered.  Listed for the operator's awareness;
they do NOT need allowing in the filter (the filter installs after
this stage).

| Syscall | Purpose | Source |
|---|---|---|
| `prctl(PR_SET_DUMPABLE, 0)` | refuse core dumps | `daemon/src/hardening.rs::apply_secret_hygiene` |
| `setrlimit(RLIMIT_CORE, 0, 0)` | belt-and-braces no core | same |
| `mlockall(MCL_CURRENT \| MCL_FUTURE)` | pin pages off swap | same |
| `openat(... "wordlist", O_RDONLY)` + `read` + `close` | load wordlist | `core/src/wordlist.rs` (static, but file-load variant exists) |
| `mkdir`/`stat` on `/run/babbleon/` | ensure socket dir exists | future install path (today operator handles externally) |
| `unlink(<socket_path>)` | clear stale socket file | `daemon/src/socket.rs::bind_socket` |
| `socket(AF_UNIX, SOCK_STREAM)` | open the listener | same |
| `bind`, `listen` | bind+listen the socket | same |
| `chmod(socket_path, 0o660)` (via `set_permissions`) | enforce SOCKET_MODE | same |
| `prctl(PR_SET_NO_NEW_PRIVS, 1)` | seal against privilege grants on future exec | future (not present today; FILED) |
| `seccompiler::apply_filter(...)` | install the allowlist itself | future (this PR) |

The two FILED items at the bottom are the missing pieces that
this seccomp work introduces.  They need to be added to the
startup path (after socket bind, before `accept`).

### Stage B — steady state (filter ACTIVE)

Per-connection handling.  Every syscall in this stage MUST be on
the allowlist.

| Syscall | Purpose | Source |
|---|---|---|
| `accept4` / `accept` | dequeue one peer | `socket.rs::serve_blocking` |
| `read` / `recvfrom` | read request bytes | `socket.rs::handle_one_request` |
| `write` / `sendto` | write response bytes | same |
| `close` | end peer connection | same |
| `shutdown` | half-close (occasionally) | implicit via drop |
| `rt_sigaction` | install / restore signal handlers (Rust runtime) | std signals |
| `rt_sigprocmask` | mask / unmask signals across syscalls | std signals |
| `rt_sigreturn` | return from signal handler | kernel |
| `restart_syscall` | resume an interrupted syscall | kernel |
| `futex` | cross-thread sync (Rust std) | std::sync, mpsc |
| `brk` | small heap growth | allocator |
| `mmap` | larger heap growth + thread stacks | allocator |
| `mprotect` | rust runtime stack-guard + JIT-free mmap perms | allocator |
| `munmap` | free large allocations | allocator |
| `madvise` | allocator hints | allocator |
| `getpid` / `gettid` | logging emits pid/tid | tracing |
| `clock_gettime` (`MONOTONIC` / `REALTIME` / `BOOTTIME`) | timestamps for tracing + `SystemTime::now` | tracing, daemon's `last_rotation_unix_secs` |
| `getrandom` | rotation-time secrets — NOT used in steady state (per-host secret is loaded once); listed because Rust's HashMap uses it at construction time | `core/src/mapping.rs` (HashMap re-hash during `MappingBuilder::build`) |
| `epoll_ctl` / `epoll_wait` (or `poll`) | NOT used today (single-threaded accept loop), reserved for v2.1 if we go to a multi-connection event loop | future |
| `sigaltstack` | std signal-stack registration | std |

### Stage B' — rotation (subset of B; same filter)

The `RotateMapping` request triggers materialization:

| Syscall | Purpose | Source |
|---|---|---|
| `openat(O_WRONLY \| O_CREAT, mode=0o755)` | create one wrapper file per tool | `core/src/wrapper.rs::write_wrapper` |
| `write` | write wrapper body | same |
| `fchmod` | set 0o755 (in case umask stripped it) | same |
| `close` | finalize wrapper | same |
| `openat(O_RDONLY)` + `read` + `close` | detect Babbleon signature on stale files | `materialization.rs::is_babbleon_wrapper` |
| `getdents64` (via `read_dir`) | enumerate `wrapper_dir` for cleanup | `materialization.rs::cleanup_stale_wrappers` |
| `unlinkat` (via `remove_file`) | prune stale wrappers | same |
| `newfstatat` (via `metadata`) | stat each entry pre-cleanup | same |
| `statx` (newer kernels) | same as `newfstatat`; glibc may emit either | same |

Same filter; just notes which entries are exercised on a rotation.

### Stage C — shutdown

| Syscall | Purpose | Source |
|---|---|---|
| `close` (× many) | sockets, files, log writers | std::Drop |
| `munmap` | thread-stack and heap teardown | allocator |
| `exit_group` | process exit | kernel |
| `rseq` (older kernels — Rust runtime cleanup) | TLS teardown | std |
| `prctl(PR_SET_NAME, ...)` (NOT today, but Rust runtime may emit on thread spawn) | thread naming | std::thread |

## Proposed allowlist (DRAFT)

Implemented in `seccompiler` as `SeccompAction::Allow` for the
listed syscalls; `SeccompAction::KillProcess` for everything else.

```
// I/O
accept4
read
write
close
shutdown
recvfrom        // some glibc versions translate read on socket
sendto          // some glibc versions translate write on socket

// File system (rotation only)
openat
unlinkat
fchmod
newfstatat
statx
getdents64

// Memory
brk
mmap
mprotect
munmap
madvise
mremap          // realloc paths

// Signals + sync
rt_sigaction
rt_sigprocmask
rt_sigreturn
restart_syscall
sigaltstack
futex

// Time + identity (read-only)
clock_gettime
getpid
gettid

// Randomness (HashMap re-seeding during rotation build)
getrandom

// Exit
exit
exit_group
rseq
```

### What is NOT on the allowlist (explicit deny by absence)

- `execve` / `execveat` — daemon never execs anything; an exec call
  is a strong signal of a compromise attempting to spawn a shell.
- `fork` / `clone` / `clone3` — daemon is single-process.  If we
  ever go multi-threaded the allowlist will need `clone` (the
  Rust runtime spawns at most a small number of background
  threads); for phase 2 the daemon is single-threaded.
- `socket` (except the startup-stage call, which runs before the
  filter installs) — no outbound connections.  The peer-accept
  path uses `accept4` on the bound listener.
- `connect` — no outbound connections.
- `bind` / `listen` — daemon binds its socket at startup; the
  filter installs *after* bind, so the steady-state filter
  rejects re-bind.
- `prctl` — once `PR_SET_NO_NEW_PRIVS=1` is set, the daemon does
  not need to re-prctl.  Denying it closes the late-stage
  privilege manipulation surface.
- `setuid` / `setgid` / `setgroups` — daemon starts under its own
  uid and stays there.
- `mount` / `umount2` — daemon never touches mount namespaces.
- `unshare` / `setns` — same.
- `ptrace` / `process_vm_readv` / `process_vm_writev` — defense in
  depth against a same-uid attacker on the host using ptrace
  introspection.
- `bpf` — daemon never loads eBPF.
- `kcmp` — no PID introspection.
- `pidfd_*` — no PID-fd machinery.
- `perf_event_open` — no perf access.
- `userfaultfd` — no userfault handler.
- `keyctl` / `add_key` / `request_key` — kernel keyring not used.
- `io_uring_*` — daemon uses synchronous I/O.

## Open questions for the operator

1. **Allow `getrandom` in steady state?**  Rust's HashMap uses
   `getrandom` for hash-DoS reseeding at construction time —
   `MappingBuilder::build` constructs HashMaps on every rotation,
   so the call fires on every rotation request.  We could
   pre-seed the HashMap RandomState once at startup and avoid
   the steady-state getrandom (cleaner allowlist) but that's a
   non-trivial Rust refactor.  Decision: **keep `getrandom` on
   the allowlist** unless operator objects.
2. **`statx` vs `newfstatat`.**  glibc emits one or the other
   depending on version + kernel.  Allowing both is the safe
   path; allowing only the newer (`statx`) breaks the daemon on
   older kernels.  Decision: **allow both**.
3. **Multi-threaded future.**  If a phase-3 change makes the
   daemon multi-threaded (e.g. a background mapping-pre-build
   worker thread), the allowlist needs `clone` / `clone3` /
   `set_robust_list` added.  Decision: **single-threaded for
   phase 2; revisit when threads land**.
4. **No `prctl` in steady state.**  This means we cannot use any
   future feature that requires a prctl after startup
   (e.g. `PR_SET_VMA` for memory tagging).  Decision: **OK; cost
   is negligible**.
5. **Argument filtering.**  Some seccomp profiles tighten by
   only allowing certain values of `openat`'s `flags`
   (e.g. forbid `O_CREAT` outside of materialise).  We could
   add per-syscall arg filtering but it doubles the audit
   surface.  Decision: **start with name-only allowlist;
   tighten in v2.1 if a measurable threat appears**.

## Test strategy when the profile pins

A `cargo test -p v2-babbleon-daemon --test seccomp_envelope`
integration test:

1. Spawn the daemon with the profile active (against a tempdir
   socket).
2. Run the full operator sequence (status, rotate, emit-table)
   via the protocol crate's client.
3. Assert every request returns success.
4. SIGTERM and reap.

A separate `tests/seccomp_denies_forbidden.rs` integration test
spawns a child that:

1. Applies the same profile.
2. Attempts `execve("/bin/true")` — must die with `SIGSYS`.
3. Repeats for `fork`, `socket(AF_INET, ...)`, `ptrace`, `bpf`.

That gives mechanical confirmation the deny path actually fires.

## What this profile does NOT defeat

- A bug in the v2-babbleon-core crate (HKDF, mapping, wrapper
  rendering) that produces wrong output.  The profile bounds
  *which syscalls* the daemon can issue, not *what bytes* it
  writes through the allowed syscalls.
- A peer who can already write to `wrapper_dir` out-of-band.
  Wrapper-dir ownership is the operator's responsibility per
  `least-privilege.md`.
- A kernel CVE in any of the allowed syscalls.  Defense in depth
  via the host's kernel-update cadence.

## Cross-refs

- `docs/v2/least-privilege.md` — section "seccomp deny-list for
  every long-running binary" — current table lists CLI, launcher,
  mapping-worker, preprocessor.  **The daemon row is missing**;
  the same PR that pins this profile adds the daemon row there.
- `crates/v2-babbleon-daemon/src/hardening.rs` — three-syscall
  startup hygiene (the stage-A subset).
- `seccompiler` crate docs — the Rust binding the launcher already
  uses for its step-8 profile.
