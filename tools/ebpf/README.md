# eBPF exec-guard

Kernel-level enforcement for the untrusted namespace tier.

## What it does

`exec_guard.bpf.c` implements an LSM hook at `bprm_check_security` that fires
before every `execve`.  In the untrusted mount namespace, it denies execution
of any path that does not start with the scrambled wrapper directory
(`/run/babbleon/scrambled/` by default).  This means even if an attacker learns
the real path of a tracked tool, the kernel denies the exec before userspace
sees it.

## Requirements

- Linux 5.7+ with `CONFIG_BPF_LSM=y` in the kernel config
- Boot param: `lsm=lockdown,yama,..,(existing),bpf` (or `lsm=bpf` if only one)
- `CAP_BPF` + `CAP_SYS_ADMIN` at load time (babbleon-ns-helper runs as setuid root, then drops)
- Build tools: `clang`, `llvm-strip`, `libbpf-dev`

Check if your kernel has BPF LSM:

```sh
cat /sys/kernel/security/lsm    # should contain "bpf"
babbleon status                  # reports bpf-lsm: available/unavailable
```

## Build

```sh
# Install deps
apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Build
make -C tools/ebpf

# The compiled object lands at:
# crates/babbleon/src/enforcement/bpf_objects/exec_guard.bpf.o
# Rust embeds it at compile time via include_bytes!()
```

## Current status

The BPF C source is complete.  The Rust embedding (`include_bytes!`) and the
`bpf(BPF_PROG_LOAD)` / `bpf(BPF_LINK_CREATE)` load path in `ebpf.rs` are
scaffolded but stubbed until the build step is wired into CI.  Track at M3.5.

## Hardening guarantees

- **Kernel-version gated.** `ebpf::probe()` refuses to touch BPF below kernel
  6.1, which is the first LTS with the worst pre-6.0 verifier CVEs
  (CVE-2021-3490, -22555, -4204, etc.) patched.  Older kernels degrade to
  mount-NS + seccomp + Landlock only.
- **Link-attached, never pinned.**  We attach via `BPF_LINK_CREATE` and hold
  the link FD in `BpfLsmHandle`.  We do NOT pin to `/sys/fs/bpf/`.  If the
  loader is SIGKILLed mid-life, the kernel closes the link FD on process
  teardown and auto-detaches the program — no "stale deny-all" can outlive
  the babbleon daemon.
- **Caps dropped post-load.**  `babbleon-ns-helper` retains `CAP_BPF` +
  `CAP_SYS_ADMIN` only long enough to call `BPF_PROG_LOAD` +
  `BPF_LINK_CREATE`, then `PR_CAPBSET_DROP`s them.  No userspace process
  on the running system can load additional BPF programs after that.

## Graceful degradation

If BPF LSM is unavailable, babbleon continues to operate with:
- Mount-namespace name scrambling (primary defense)  
- seccomp-bpf syscall filter (blocks ptrace, process_vm_*, etc.)
- Landlock LSM filesystem restriction (kernel 5.13+)

The BPF exec-guard adds a fourth, kernel-enforced layer that survives
namespace escapes.
