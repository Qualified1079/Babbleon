# Babbleon Threat Model

Drawn from RESEARCH T1–T16.  This doc names the adversary and the
specific capabilities Babbleon does and doesn't blunt.

## Three classes of AI-driven attacker

We currently see three operational shapes for an AI-driven attacker.
Babbleon does not address all three equally and the doc is honest
about that.

**Type 1 — small-model internal worm.**  A compromised dependency,
post-install script, or browser-RCE payload that runs a small
on-device model (or a hardcoded decision tree shaped like one) to
exfil data, drop further malware, join a botnet, or sit dormant
waiting for a buyer.  Its reasoning budget is tiny; it operates by
running canonical tools (`curl`, `aws`, `kubectl`) by their canonical
names against canonical paths.  **Babbleon's primary target.**  The
rename + tier boundary + tripwires directly break this attacker's
playbook because the playbook is encoded in canonical names that no
longer resolve.

**Type 2 — large-model external attacker.**  Threat actor with GPU
budget running a malware-trained or reasoning-tuned frontier model
that probes the host over the network and reasons about exploit
chains from outside.  Could be a profit-motivated red team or a
nation-state stockpiling 0-days against infrastructure.  **Babbleon
does NOT primarily address this.**  An external attacker never sees
the local namespace at all — they're attacking exposed network
services, not enumerating `$PATH`.  The defense against Type 2 is
network segmentation, service hardening, and your own red-teaming;
Babbleon is host-side naming and helps only after the external
attacker has *already* dropped a payload into an untrusted process.

**Type 3 — hybrid: small local + large external, channel between.**
The interesting case and the one Babbleon must be explicit about.
A small on-device agent (Type 1's body) holds an outbound channel to
a large external model (Type 2's brain).  The local agent doesn't
need to crack the scramble itself — it just **exfiltrates the current
scrambled vocabulary to the external model and infiltrates the
external model's adapted commands back into the local namespace.**
As long as both sides agree on what "the current `curl` is named"
within one rotation window, Babbleon's rename is bypassed for the
duration of that window.

**Type 3 defense ⟶ rotation rate is load-bearing.**  The only thing
that closes the Type 3 channel is rotating the mapping faster than
the round-trip-time of the exfil/infil cycle.  If a typical small
model needs N seconds to ask the big model "what should I do next?"
and N exceeds the rotation period, the next instruction comes back
keyed to a vocabulary that no longer exists.  This makes
**maximum-supportable rotation rate** a first-class design question;
see `tools/rotation-benchmark/` for the measurement.

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

### What the LLM attacker CANNOT do, even unmitigated

- Read kernel keyring (DAC + no privilege)
- Modify /boot, /etc, /usr (read-only via Landlock)
- Persist across mount-NS exit
- Side-channel against the vault during sealed-at-rest periods

### What the LLM attacker CAN still do

Be honest:

- **Use scrambled binaries it discovers via parent-supplied env or files.**
  If the parent process leaked a real name, the payload can use it.
  Mitigation: parent-side wrapper that scrubs argv/env at the trust boundary.
- **Read its own files.**  Anything mounted into its view is its to read.
  Untrusted-tier programs running with user creds against user files
  remain a problem we don't solve.
- **Make outbound network calls** to anywhere allowed by the host firewall.
  Babbleon is naming-layer + filesystem; not a network firewall.
- **Exfiltrate the host's randomness.**  Per-host mapping is the secret,
  but a payload that *runs* in untrusted tier sees the scrambled names
  it has access to.  Rotate the mapping; old discoveries die.

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
  100% confidence: no legitimate program knows the honey names.
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
