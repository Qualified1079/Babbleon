# Design — the Android tier (`v2-babbleon-mobile`)

The scramble-core carve (`docs/v2/scramble-core-carve.md`) split
`v2-babbleon-core` into the OS-agnostic **scramble engine**
(`v2-babbleon-scramble`) and the Linux **detection/response tier**
(`v2-babbleon-linux`).  Its whole purpose was to unblock a mobile fork
that reuses the scramble math and rebuilds enforcement.  This document is
that fork's design, and `crates/v2-babbleon-mobile` is its first
increment.

## What Babbleon must become on Android

Babbleon's invariant is unchanged across platforms: **an untrusted,
LLM-driven agent reasons about the system using cached knowledge of
canonical names, so we rename everything per-device and treat any use of
a canonical (or decoy) name as an intrusion signal.**  What changes is
*what* gets renamed and *how* an "attempt to use the real name" is
detected and answered.

| Concern | Linux tier (`v2-babbleon-linux`) | Android tier (`v2-babbleon-mobile`) |
| --- | --- | --- |
| What is renamed | executables on `$PATH` (`curl`, `ssh`, `aws`) | the capability surface an on-device agent reaches for: **system-service names / binder interfaces, `getprop` keys, package names, intent actions, content-provider authorities** |
| Where the mapping lives | daemon over a Unix socket | an in-process `EpochMapping` (this crate) or an app-scoped service reached over binder — no login daemon |
| Launch model | PAM → login shell → fork-exec wrapper | zygote fork → app process; there is no shell to wrap |
| "Used a real name" tripwire | `/bin/sh` wrapper script + `/proc`-watched FIFO | a **name-resolution hook** the app/system layer calls before it dispatches; a hit returns a policy decision |
| Isolation primitive | composable LSMs (Landlock) + seccomp + mount ns | **mandatory** SELinux app domains + the per-app UID sandbox + the zygote-installed seccomp-bpf filter (all already on) |
| Response | kill the wrapper, log to JSONL, sign an audit chain | deny the resolution, terminate/soft-fail the caller, emit a structured event to logcat / the app's telemetry |

The key structural fact: **on Android, most enforcement is not ours to
implement in Rust.** SELinux policy is `.te` source compiled into the
boot image; the app sandbox and seccomp filter are installed by the OS at
`zygote` fork; binder mediation lives in `system_server`. Our crate does
not — and must not — try to reimplement those. It owns the two things
that *are* portable and *are* ours:

1. the **scramble/reveal/decoy** decision (pure; reused verbatim from
   `v2-babbleon-scramble`), and
2. the **policy + event vocabulary** for a name-resolution tripwire,
   with the actual mechanism (who calls the hook, what "terminate"
   means) supplied by the layer above through a small trait seam.

## Architecture — three layers, one FFI seam

```
  ┌─────────────────────────────────────────────────────────────┐
  │  Android app / system layer  (Kotlin/Java, SELinux, binder)  │
  │   - installs SELinux app domain, relies on zygote seccomp     │
  │   - calls the name-resolution hook before dispatching a       │
  │     service/property/package lookup                           │
  │   - implements the enforcement seam traits (terminate, deny)  │
  └───────────────▲───────────────────────────┬──────────────────┘
                  │  JNI (feature = android-jni)│
  ┌───────────────┴───────────────────────────▼──────────────────┐
  │  v2-babbleon-mobile  (this crate, pure Rust + thin JNI)       │
  │   mapping_handle · response · event · enforcement (traits)    │
  └───────────────────────────┬──────────────────────────────────┘
                              │ depends only on
  ┌───────────────────────────▼──────────────────────────────────┐
  │  v2-babbleon-scramble  (EpochMapping, HKDF, permutations)     │
  └───────────────────────────────────────────────────────────────┘
```

The crate never links the Linux tier, never opens `/proc`, never spawns
`/bin/sh`. That is the carve paying off: the preprocessor already proved
`v2-babbleon-scramble` is consumable standalone; this crate is the second
proof and the first *product* consumer.

### In-crate (pure, host-testable)

- **`mapping_handle`** — `MobileMapping`: owns an `EpochMapping` built
  from a 32-byte per-device secret + the built-in wordlist + an epoch.
  Methods: `scramble(real)`, `reveal(scrambled)`, `is_decoy(name)`. This
  is the whole reusable core, and it is identical math to the Linux tier
  — a device and a server derive the same table from the same
  `(secret, epoch, tool)` triple.
- **`response`** — `ResponsePolicy` (`LogOnly` / `DenyResolution` /
  `TerminateCaller`) and `resolve_name`, which turns a lookup of a
  canonical/decoy/unknown name into a `ResolutionDecision`. No syscalls:
  it decides, it does not act.
- **`event`** — a `MobileEvent` enum (`DecoyNameUsed`, `RealNameUsed`,
  `MappingRotated`, …) and an `EventSink` trait. The default path is a
  callback sink; the app wires it to logcat or its telemetry. No
  filesystem sink, no `/proc` start-time — those are Linux-tier concepts.
- **`enforcement`** — the seam: `trait CallerTerminator`,
  `trait ResolutionGuard`. These are what the Android layer implements to
  give `TerminateCaller` / `DenyResolution` teeth. The crate defines the
  contract and the decision; the app owns the mechanism (e.g. `terminate`
  → `Process.killProcess` / a binder `SecurityException`).

### App/system-provided (documented, not in this crate)

SELinux app-domain policy, the zygote seccomp-bpf filter, binder
interception in `system_server`, Play Integrity / hardware attestation
for the secret's provenance, and Keystore/StrongBox custody of the
per-device secret. The crate's job is to be *called from* a correctly
sandboxed process, not to build the sandbox. Where a piece is genuinely
ours later (e.g. a seccomp-bpf tightening applied from JNI at process
start, mirroring `v2-babbleon-daemon`'s seccompiler use) it will land as
a `#[cfg(target_os = "android")]` module with the Rule-9/Rule-10
`SAFETY:`/`CAPABILITY:` discipline the baseline requires.

## The FFI seam

Default build is **pure Rust, `forbid(unsafe_code)`, no `jni`
dependency** — so `cargo build --workspace` / `cargo test` on a Linux CI
host compiles and exercises the entire decision core without an Android
toolchain. The JNI surface is behind an **opt-in `android-jni` feature**
and built with `cargo-ndk`:

```
cargo ndk -t arm64-v8a -t armeabi-v7a -o app/src/main/jniLibs \
    build --release -p v2-babbleon-mobile --features android-jni
```

`[lib] crate-type = ["cdylib", "rlib"]`: `cdylib` is the `.so` Android
loads; `rlib` keeps the crate usable by host unit tests and any future
Rust consumer. The JNI entry points use `jni` 0.21's **safe** string
path (`JNIEnv::get_string` / `new_string`), so even the FFI module needs
no `unsafe` — the crate keeps `#![forbid(unsafe_code)]` unconditionally.
The mapping handle crosses the boundary as an opaque `jlong` (a
`Box::into_raw` pointer the Kotlin side holds and later frees via
`nativeDestroy`), the standard Rust-JNI handle idiom.

See `crates/v2-babbleon-mobile/examples/BabbleonNative.kt` for the Kotlin
side.

## Threat-model boundaries (Android-specific)

- **Defeats:** an on-device agent that plans using canonical Android
  identifiers (service/property/package names). It cannot name what it
  cannot see, and naming a decoy trips the resolver.
- **Defeats:** a device/server view mismatch — both derive the same
  `EpochMapping`, so a scrambled name minted on the server reveals on the
  device and vice-versa.
- **Does NOT defeat:** an attacker with root / a broken SELinux policy /
  a custom ROM. Same posture as the Linux tier vs. a rewritten
  `/etc/pam.d`. On Android the mitigations are OS-level (verified boot,
  attestation), which this crate consumes but does not provide.
- **Does NOT defeat:** an agent that never resolves a *name* — e.g. one
  holding a raw binder handle it obtained before scrambling. Bounding
  that is the app/system layer's binder-mediation job; the crate gives it
  the name vocabulary to mediate *with*.

## Open question (operator) — carried from the protocol audit

`docs/v2/protocol-transport-split.md` asks which IPC the Android
untrusted tier uses. This crate is deliberately **transport-free**: it is
an in-process library reached by JNI. If a future design puts the mapping
behind an app-scoped *service* (so several processes share one epoch),
that service's wire format is the `v2-babbleon-protocol` question, not
this crate's — this crate would sit inside the service. Nothing here
forecloses either choice.

## Status

Increment 1 (this doc + the pure decision core + the JNI seam + the
Kotlin example) is built. Not yet compiled against a real toolchain (no
Rust/NDK on the authoring host) — verified statically, same caveat as the
carve. Deferred, each its own follow-up: a JNI-side seccomp tightening at
process start; Keystore/StrongBox secret custody; a concrete
name-resolution hook wired into a sample app; and the app-scoped-service
variant if the operator chooses shared-epoch multi-process.
