# Preprocessor syscall envelope

**Status: implemented.**  Filed 2026-06-26.  This documents the
syscall allowlist installed by `crates/v2-babbleon/src/seccomp_profile.rs`
for the `babbleon scramble` / `babbleon unscramble` computation window.

## What this protects

The `scramble` and `unscramble` subcommands process untrusted source
files.  A code-flow bug in the tokenizer, L2 identifier scrambler, L3
whitespace encoder, L4 chunk reorder, or L5 decoy injection could give
an attacker arbitrary syscall execution.  The filter bounds what that
execution can do.

## Install point

The filter installs AFTER the last daemon socket round-trip and BEFORE
the CPU-bound L2/L3/L4/L5 computation.  Specifically:

- `run_scramble`: installs after `fetch_identifier_mapping_at_epoch`
  (the second and final daemon call).
- `run_unscramble`: installs after `fetch_whitespace_wordlist` (the
  second and final daemon call).

Pre-filter window (unfiltered): argument parsing, tracing init,
Unix-socket connect, daemon request/response, input file read, header
parse.  This window is short and involves no untrusted parsing beyond
the scrambled-file header (which is parsed before the filter installs).

## Why `scramble-dir` / `unscramble-dir` are NOT filtered

The corpus-dir paths make one `GetTokenMapping` daemon call per file
inside the walk closure.  Each of those calls creates a new
`UnixStream::connect`, which emits `socket(AF_UNIX)` + `connect()`.
Installing seccomp before the walk would deny those calls.

A v2.1 restructure can batch all `GetTokenMapping` calls before the
walk starts (pre-computing all mappings), then install seccomp before
the actual computation loop.  Until then, the `no_seccomp` field of
`CorpusOptions` is a reserved no-op.

## Allowlist (34 syscalls)

Implemented as `SeccompAction::KillProcess` default,
`SeccompAction::Allow` for the entries below.

### File I/O

| Syscall | Purpose |
|---|---|
| `read` | source file read, daemon socket read (FD already open) |
| `write` | output file write, stdout/stderr |
| `close` | close file descriptors |
| `openat` | open source / output files |
| `writev` | BufWriter flush, some tracing sinks |
| `lseek` | std::io::Seek on file descriptors |
| `ioctl` | tracing-subscriber isatty check via TCGETS on stdout |

### File metadata

| Syscall | Purpose |
|---|---|
| `fstat` | std::fs::metadata on opened FDs |
| `newfstatat` | path-based metadata; glibc may emit on older kernels |
| `statx` | path-based metadata; glibc may emit on newer kernels |
| `fcntl` | F_GETFL / F_SETFL, F_DUPFD_CLOEXEC on tempfile creation |

### Directory ops (scramble-dir / unscramble-dir)

These syscalls appear in the corpus-dir path even though seccomp is
not yet installed there.  Listed for completeness; they will be
needed once the v2.1 batch-prefetch restructure lands.

| Syscall | Purpose |
|---|---|
| `getdents64` | std::fs::read_dir (source tree walk) |
| `mkdir` | std::fs::create_dir_all on output tree |
| `unlinkat` | scramble-dir --force removes stale output files |
| `rmdir` | scramble-dir --force prunes empty output dirs |

### Memory

| Syscall | Purpose |
|---|---|
| `brk` | small heap growth |
| `mmap` | larger heap growth |
| `mprotect` | Rust runtime stack-guard; mmap permission fixup |
| `munmap` | free large allocations |
| `madvise` | allocator hints |
| `mremap` | realloc paths |

### Signals + thread sync

| Syscall | Purpose |
|---|---|
| `rt_sigaction` | Rust runtime signal handler install/restore |
| `rt_sigprocmask` | mask/unmask signals across syscalls |
| `rt_sigreturn` | return from signal handler |
| `restart_syscall` | resume an interrupted syscall |
| `sigaltstack` | std signal-stack registration |
| `futex` | cross-thread sync (Rust std) |

### Time + read-only identity

| Syscall | Purpose |
|---|---|
| `clock_gettime` | tracing timestamps, SystemTime::now |
| `getpid` | tracing emits pid |
| `gettid` | tracing emits tid |

### Randomness

| Syscall | Purpose |
|---|---|
| `getrandom` | HashMap re-seeding during identifier mapping build |

### Exit

| Syscall | Purpose |
|---|---|
| `exit` | process exit |
| `exit_group` | process exit (all threads) |
| `rseq` | Rust runtime TLS/thread teardown |

## Explicit denials

These syscalls are absent from the allowlist and kill the process
if attempted in the computation window.

- `socket` / `connect` / `bind` / `listen` / `accept4` — all daemon
  I/O completes before the filter installs; no outbound connection
  should be needed.
- `execve` / `execveat` — the scrambler never execs.
- `fork` / `vfork` / `clone` / `clone3` — single-threaded.
- `ptrace` / `process_vm_readv` / `process_vm_writev` — no peer
  introspection.
- `mount` / `umount2` — no namespace operations.
- `prctl` — `PR_SET_NO_NEW_PRIVS` is set before the filter installs;
  no further prctl needed.
- `setuid` / `setgid` / `setgroups` — no privilege changes.
- `bpf` — no eBPF.
- `keyctl` / `add_key` / `request_key` — kernel keyring not used.
- `pidfd_*` — no PID-fd machinery.
- `kcmp`, `perf_event_open`, `userfaultfd`, `init_module`,
  `finit_module`, `kexec_load` — never used.

## Cross-refs

- `crates/v2-babbleon/src/seccomp_profile.rs` — implementation.
- `crates/v2-babbleon/src/scramble_lifecycle.rs` — install point
  (`install_seccomp` helper, called in `run_scramble` and
  `run_unscramble`).
- `docs/v2/daemon-seccomp-envelope.md` — analogous doc for the
  daemon's allowlist.
- `docs/v2/least-privilege.md` — the overarching least-privilege
  policy; the preprocessor row was pending this implementation.
