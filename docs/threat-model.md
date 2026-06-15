# Babbleon Threat Model

Drawn from RESEARCH T1–T16.  This doc names the adversary and the
specific capabilities Babbleon does and doesn't blunt.

## AI-driven attackers: two underlying threats, several expressions

Reducing to first principles, there are **two** underlying AI-driven
threats, and the operational shapes of each are what determine
defense.  Babbleon is built for one of them; we are honest about the
other.

**Underlying threat A — disconnected.**  The attacker has only what
they brought on-host: their own reasoning weights, their own
toolset, no live link to peers.  Once an untrusted process is
running, the model decides what to do from inside it.  Babbleon's
rename + tier + tripwires + credential gate work directly against
this attacker because the attacker's playbook is keyed on canonical
names and canonical paths that no longer resolve.

**Underlying threat B — connected.**  The attacker has a live link
out — to a single larger model, to a peer swarm, to a botnet
controller, to a shared exploit feed.  The on-host model does not
have to crack anything itself; it just relays the current vocabulary
out, receives translated instructions back, and executes them
*within the current rotation window*.  Babbleon's defense against
the connected attacker is **rotation rate ≪ relay round-trip**.  If
the window closes before the translated instruction returns, the
returned instruction is keyed to a vocabulary that no longer exists.

Same underlying axis (offline reasoning vs comm-channel reasoning),
several deployment shapes:

| Expression | Body | Brain | What defeats it |
|---|---|---|---|
| **E1. Solo internal worm.** Compromised dep, post-install script, or browser-RCE payload running a small reasoner on-device. | on-host | on-host | rename + tier + tripwires |
| **E2. Solo external attacker.** Nation-state or red-team with GPU budget probing exposed network services. | off-host | off-host | NOT Babbleon — needs network segmentation, service hardening, your own red-teaming |
| **E3. Hybrid: small local + large external.** On-host agent with an outbound API channel to a frontier model that adapts exploits per host. | on-host | off-host | rotation < API RTT (typically 1–5 s) |
| **E4. Adversarial network of LLMs.** Peer-to-peer swarm, or many small models with a shared exploit feed, possibly carried over Tor or IRC-style chat.  When any peer finds a 0-day, every peer's host gets it within network-propagation time. | many on-host | distributed | per-host randomization + rotation < propagation window |

E1 is what existing static defenses (signature AV, EDR rules) are
shaped against; Babbleon is also strongly oriented toward it.
**E4 is where Babbleon does its most distinctive work**: per-host
random mapping means an exploit that "owns curl" on host A can't be
applied to host B without re-deriving the per-host vocabulary.  The
swarm's speed-of-light coordination advantage is neutralized — the
exploit propagates instantly, but the *adaptation* still pays a
per-host cost.  At sufficiently short rotation, the per-host
adaptation window is shorter than the swarm's per-host work cycle
and the exploit fails to land.

E2 remains explicitly out of scope.  Babbleon is host-side; the
defense against off-host attackers is segmentation, service
hardening, and your own red-teaming.

## What Babbleon does NOT defeat

Three load-bearing limitations.  All three are real and
acknowledged; designs that pretend otherwise are dishonest.

**L1. Built-in / direct syscall bypass.**  If the attacker has RCE
inside a process that already carries its own network and filesystem
libraries — Node.js, Python, PHP, Ruby, Go, Java — they do not need
`/usr/bin/curl`.  The runtime's `socket()` / `openat()` / `execve()`
calls go to the kernel directly, ignoring Babbleon's userspace
namespace renames.  Babbleon's defenses against this attacker:
  - mount-NS keeps credential paths unreachable (Python `open
    ('~/.aws/credentials')` returns ENOENT in the untrusted view);
  - seccomp deny-list blocks peer-inspection syscalls but does NOT
    block raw networking;
  - rotation degrades any cached path that the runtime learned from
    its own previous run.

Babbleon does NOT block:
  - raw outbound network traffic from an untrusted-tier runtime,
  - re-implementations of `curl` written in five lines of Python,
  - reading any file the kernel grants the user uid access to.

The defense against this attacker class composes with Babbleon, it
is not Babbleon: host firewall (outbound deny-by-default),
process-level egress policy, Landlock or AppArmor for syscall-level
file gating.

**L2. Bring Your Own Environment (BYOE).**  The classic MTD
countermeasure: drop a statically-linked, self-contained payload —
typically a customised BusyBox-class binary — and run it.  The
payload carries its own shell, its own networking, its own grep.
The host's scrambled names no longer matter to a tool the attacker
brought along.

The honest accounting: rename + tier do not stop a static payload
from running.  What they DO stop is the payload from accomplishing
much *with what it finds on the host*:
  - the payload still cannot read scrambled-gated credential dirs;
  - the payload still cannot enumerate trusted-tier processes
    (PID NS isolation);
  - the payload still cannot ptrace or `process_vm_readv` siblings
    (seccomp);
  - tripwires still fire if the payload probes wordlist-shaped
    names.

So BYOE gives the attacker *primitives* (a shell, a curl) but not
*knowledge* (where the credentials are, where the trusted shells
live, what services are running).  The attacker has tools pointed
at an empty room.  Useful — not enough on its own — to be combined
with credential-gating and tripwires for the actual defense.

**L3. Shared-library leak via `/proc/self/maps`.**  Every
dynamically-linked process needs to find `ld-linux.so` and
`libc.so.6` at canonical paths or it cannot start.  We cannot
obfuscate those without breaking the ELF loader.  Any untrusted
process that runs at all will have `libc` mapped into its address
space at a path it can read from `/proc/self/maps`.

What that leak does and doesn't give the attacker:
  - Confirms the host is glibc-based Linux of approximately known
    version.  This is also visible from `uname` and basic syscall
    behaviour; nothing new.
  - Reveals the **canonical-path of one library** — but not the
    scrambled-path of any tool.  Tools and credentials are
    obfuscated independently; the ELF loader path is not a key into
    the rest of the namespace.

What it does NOT do is reveal the scramble mapping.  An attacker
who reads `/proc/self/maps` learns `/lib/x86_64-linux-gnu/libc.so.6`
exists; they learn nothing about which scrambled name routes to
`curl`.  The shared-library leak is a fingerprint surface (host
type + glibc version), not a key-recovery channel.

Designs that try to obfuscate libc itself are vetoed as more
brittle than the protection they add.  Document the leak; do not
plug it.

## Primary adversary

**Automated LLM-driven attacker** running a generic playbook inside a
process Babbleon has already classified as untrusted.  Examples:

- `curl | sh` payload pulled by a developer
- Compromised npm/pip dependency executing post-install
- Browser-launched RCE chain
- MCP/agent tool call from an untrusted prompt context

This adversary is **cheap, scalable, and stateless across hosts**.  The
defense is built around that asymmetry.

### What the LLM attacker can do

| Capability                         | Mitigated?  | Mechanism                          |
|------------------------------------|-------------|------------------------------------|
| `which curl` / PATH probe          | Yes         | Mount-NS bind-mount of scrambled names |
| `bash -c "ls /usr/bin"`            | Yes         | Same; binary not present under real name |
| `/proc/<pid>/environ` scrape       | Yes (M3)    | hidepid=2 + env scrub              |
| `/proc/<pid>/cmdline` of others    | Yes (M3)    | PID NS isolates process view       |
| Fingerprint binary via SHA-256     | Yes         | Wrapper padding per host           |
| Fingerprint via `--help` text      | Yes         | Wrapper null-output in untrusted NS |
| `cat ~/.aws/credentials`           | Yes (M4)    | tmpfs-overlay over cred dirs       |
| Inherit SSH_AUTH_SOCK              | Yes (M4)    | env-var scrub list                 |
| `ptrace` a sibling process         | Yes (M3)    | seccomp deny-list                  |
| `process_vm_readv` cross-process   | Yes (M3)    | seccomp deny-list                  |
| Spawn arbitrary syscalls           | Partial     | Landlock (FS) + seccomp (proc)     |
| Read kernel memory via /dev/mem    | Yes         | Untrusted user can't open it       |
| eBPF program load                  | Yes (M3)    | seccomp denies bpf()               |

### What we keep the LLM attacker from doing reliably

Stated as *probable obstacles*, not absolutes.  The attacker has the
public corpus of known exploits behind them (millions of malware
samples, complete CVE databases, leaked offensive tooling) and a
reasoning loop to adapt those primitives.  We do not pretend any of
the items below is closed permanently — we name the mechanism and
the kernel feature that backs it, and leave honest room for novel
bypass.

- Reading the kernel keyring — DAC + no privilege.  Bypass requires
  a kernel privilege escalation, which our threat model assumes is
  itself a separate event Babbleon does not stop.
- Modifying `/boot`, `/etc`, `/usr` from untrusted tier — Landlock
  read-only mounts.  Bypass requires either a Landlock CVE or escape
  to trusted tier.
- Enumerating trusted-tier process names — PID-NS isolation.  Bypass
  requires kernel PID-NS escape (`/proc/<pid>/root` via a leaked
  PID; closed by hidepid + NS).
- Reading another user-process's memory via `process_vm_readv` /
  `ptrace` — seccomp-bpf deny list.  Bypass requires seccomp escape
  or a kernel CVE that doesn't go through the named syscalls.
- Loading eBPF programs to attach LSM hooks — `bpf()` denied.

### What the LLM attacker CAN still do

Be honest:

- **Use built-in runtime libraries** (Python `socket`, Node `http`,
  Ruby `Net::HTTP`, Go std-net).  Babbleon's name-renaming does not
  reach into a runtime that carries its own networking.  Compose
  with a host firewall.
- **Drop a static payload (BYOE).**  Babbleon does not stop the
  payload from executing.  It does keep the payload from finding
  credentials or sibling processes — but the attacker still has a
  shell-equivalent in their hand.
- **Use scrambled binaries it discovers via parent-supplied env or
  files.**  If the parent process leaked a real name, the payload
  can use it.  Mitigation: parent-side wrapper that scrubs argv/env
  at the trust boundary.
- **Read its own files.**  Anything mounted into its view is its to
  read.  Untrusted-tier programs running with user creds against
  user files remain a problem Babbleon does not solve.
- **Make outbound network calls** to anywhere allowed by the host
  firewall.  Babbleon is naming-layer + filesystem; not a network
  firewall.
- **Exfiltrate scrambled names it has access to.**  Per-host mapping
  is the secret, but a payload that *runs* in untrusted tier sees
  the scrambled names it has access to.  Rotate the mapping; old
  discoveries die.
- **Apply known CVE exploits unchanged** against any service Babbleon
  did not put behind the tier boundary.  We are not patching kernels
  or applications; we are renaming and isolating.

## Adversary capabilities OUT of scope

- Persistent local root (we assume root is honest)
- Hypervisor / SMM / CPU vulnerabilities
- Physical access to a powered-on machine in trusted state
- Supply-chain compromise of the Babbleon binary itself
- Side channels (Spectre, RowHammer) against a running vault unlock

## Trust tiers

| Tier        | NS-mnt    | Names visible       | Credentials | Caps |
|-------------|-----------|---------------------|-------------|------|
| Trusted     | trusted   | real (`curl`)       | real        | normal user |
| Untrusted   | untrusted | scrambled compounds | empty tmpfs | bounding set dropped + seccomp + Landlock |

Tier is identified by `/proc/self/ns/mnt` inode comparison against the
value at `/run/babbleon/trusted-ns-inode` (written by the trusted
session at setup).

## Detection signals

- **Honey tripwire** — an invocation of any honey-mapped name.
  Very high confidence: legitimate programs have no source of the
  current epoch's randomly-generated honey names.  Not literally
  100 % — a determined attacker can shotgun random compound shapes
  hoping to land on a tripwire, but the false-positive cost is
  bounded and the alert IS a signal even then.
- **Argon2 unlock-fail rate spike** — brute-force attempt.
- **Cross-NS bind-mount attempt** — kernel denies + we log.
- **Audit-log gap or tamper** — JSONL log is append-only;
  a signed-hash-chain variant lands in M5.

## Failure modes we accept

- A user dropping themselves into a root shell sees real names —
  by design (root is trusted).
- A trusted-NS process that hands a scrambled name to an untrusted
  child via env var has leaked the name.  We document the boundary.
- A kernel without mount/PID NS support degrades to `SimulatedDriver`
  with a clear status message; no silent failure.
