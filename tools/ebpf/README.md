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

## Graceful degradation

If BPF LSM is unavailable, babbleon continues to operate with:
- Mount-namespace name scrambling (primary defense)  
- seccomp-bpf syscall filter (blocks ptrace, process_vm_*, etc.)
- Landlock LSM filesystem restriction (kernel 5.13+)

The BPF exec-guard adds a fourth, kernel-enforced layer that survives
namespace escapes.
