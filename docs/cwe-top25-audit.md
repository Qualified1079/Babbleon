# CWE Top 25 (2024) audit

Documentary review of Babbleon's source against the CWE Top 25 surfaces
flagged by the standards survey (`docs/standards-survey.md`).  Each
section names the surface, traces the data flow, and records the
finding.  Where a finding is "no fix needed" it explains why so a later
reviewer doesn't re-litigate.

The findings here cover the public package only (`crates/babbleon*/`).
Enterprise additions ship in a separate repo and carry their own audit.

---

## CWE-22 — Path Traversal

**Surface.** Scrambled wrapper-script paths in
`crates/babbleon/src/enforcement/wrapper.rs::write_wrapper`,
`write_tripwire_script`, and `write_all`; vault/state paths in
`crates/babbleon/src/storage.rs` and `session.rs`.

**Data flow.** The "untrusted" half of every wrapper path is the
**scrambled name**.  Scrambled names are produced by `Mapper::compound`
in `mapping/mapper.rs`: they are the concatenation of N (default 4)
indices into the static `wordlist/words.txt` (only `[a-z]+` entries,
filtered at build time).  No path separator (`/`) can appear; no `.`
character can appear; no NUL byte can appear.  An attacker who *forges
the host secret* could control which 4 words are picked but not produce
new bytes — the surface is closed by the wordlist filter, not by run-
time escaping.

**Finding — no fix.** Path traversal requires `/`, `\\`, or `..` in
the rendered file name.  The wordlist guarantees none of these can
appear.  If the wordlist were ever changed to include
non-lowercase-alpha characters, this finding would have to be re-
examined — recorded in `wordlist/README.md` (filed to add).

---

## CWE-78 / CWE-77 / CWE-94 — Command + Code Injection (wrapper renderer)

**Surface.** `crates/babbleon/src/enforcement/wrapper.rs::render`.
The function `String::replace`s six placeholders into a shell-script
template:

| Placeholder      | Source                                                                                  |
|------------------|-----------------------------------------------------------------------------------------|
| `{padding}`      | hex of SHA-256 over (host_secret, scrambled name) — bytes 0..16                          |
| `{self_name}`    | scrambled name (see CWE-22 analysis)                                                    |
| `{real_path}`    | filesystem path of the real binary (e.g. `/usr/bin/curl`)                               |
| `{ns_inode}`     | stringified `u64` mount-NS inode                                                        |
| `{honey_list}`   | constant `/run/babbleon/honey.list` (or test override)                                  |
| `{stale_list}`   | constant `/run/babbleon/stale.list` (or test override)                                  |
| `{honey_fifo}`   | constant `/run/babbleon/honey.fifo` (or test override)                                  |
| `{decoy_banner}` | optional plausible-wrong --help text from `deception.rs`                                |

**Data flow.** Every field except `{decoy_banner}` is either:
  - A hex digest (`padding`, `ns_inode`) — alphanumeric only.
  - A scrambled name (`self_name`) — lowercase alpha only.
  - A real binary path (`real_path`) — supplied by the caller of
    `write_all`, which walks `real_root.join(real_name)` against the
    tracked manifest.  `real_name` is from the manifest (operator-
    controlled, plain identifier); `real_root` is an operator-supplied
    directory (`/usr/bin` by default).
  - A constant test override or a runtime constant.

`{decoy_banner}` is the only field that goes through explicit shell-
escape: `decoy_banner.replace('\'', "'\\''")` in `render()`, then
interpolated inside single quotes (`'%s\n' '{decoy_banner}'`).
That single-quote escape is correct: single quotes inside a shell
single-quoted string cannot be escaped, so the literal sequence
`'\\''` ends the quote, escapes the apostrophe, and reopens the
quote.  No other shell metacharacter can break out of single quotes.

`{real_path}` is the highest-risk field on first reading because it
goes into `exec "$_BL_REAL" "$@"` *unquoted around the variable
expansion*... but wait, the template DOES double-quote it: `exec
"$_BL_REAL"`.  The shell's `exec "$VAR"` performs no word splitting,
no glob, no command substitution — `$VAR`'s value is the entire
argv[0].  So even a path containing spaces, quotes, or `$()` is
passed unmodified.

**Finding — no fix today, but file a fuzz target.**  The four
operator-controlled fields land in a single-quoted echo (decoy) or
behind double-quoted variable expansion (real_path) — both shell-
safe.  The remaining fields are syntactically bounded.  Filed in
TODO under "Testing → fuzz target on the renderer".

---

## CWE-400 — Resource exhaustion (honey FIFO reader)

**Status.** Fixed in commit `7ac15e8`.  `events.rs::HoneyFifoReader::run`
now reads through a `Take` adapter capped at `MAX_HONEY_LINE_BYTES`
(16 KiB) with `discard_to_newline` resync on over-limit.

---

## CWE-269 — Improper Privilege Management (ns-helper chain)

**Surface.** `crates/babbleon-ns-helper/src/main.rs`.  The binary is
installed `root:root 4755` and is the only setuid surface in the
codebase.

**Privilege chain, in order:**

1. **Real-UID guard.**  `geteuid().is_root()` AND
   `getuid().is_root() == false` must both hold — refuses to run as
   real-root (would defeat the user-isolation purpose) and refuses
   to run without setuid (no namespace work possible).
2. **`unshare(CLONE_NEWNS | CLONE_NEWPID)`.**  Requires CAP_SYS_ADMIN
   (held via setuid root).
3. **`make_root_private()`.**  Marks `/` as `MS_PRIVATE | MS_REC` so
   the new mount NS's mount events don't propagate back to the host
   NS.  Failure aborts before any mount work.
4. **Mount placements.**  Performed before `setuid()` — capability
   still held.  Failures abort before privilege drop.
5. **`PR_CAPBSET_DROP` of every capability.**  Removes every
   capability from the bounding set so even an exec'd setuid child
   cannot re-acquire them.
6. **`PR_SET_NO_NEW_PRIVS`.**  Locks NNP across exec.
7. **seccomp-bpf filter.**  Denies `ptrace`, `process_vm_*`, `kcmp`,
   `pidfd_*`.  Applied AFTER NNP so the seccomp install itself
   doesn't need extra privilege.
8. **fork + drop UID.**  Parent stays around as PID-1-reaper for the
   new PID NS.  Child calls `setuid(real_uid)` — the only step that
   would fail if any of the above succeeded out of order (a child
   that retained any cap and got an EPERM here would be a panic-worthy
   bug).  Then `execve` of the user's command.

**Finding — no fix.**  Each privilege step happens only after the
previous step's preconditions are confirmed; capability drop is
total (PR_CAPBSET_DROP, not selective); NNP locks against
re-escalation through subsequent exec.  Any failure path returns
before privilege drop is even attempted.  The one residual concern is
**the ordering check is implicit** — each step's failure aborts via
`?`, but there's no test that confirms the order across refactors.
Filed in TODO under "ns-helper ordering test".

---

## CWE-798 — Hardcoded Credentials (Salt constants)

**Surface.** `crates/babbleon/src/vault/soft.rs` (`SALT`),
`crates/babbleon/src/vault/usb.rs` (`SALT`), and
`crates/babbleon/src/mapping/kdf.rs` (`HKDF_SALT`).  All three are
`const &[u8]` strings baked into the binary.

**Data flow.** A KDF salt is *not* a secret.  It's a public,
domain-separation tag that ensures two systems using the same
ikm-and-info don't collide.  In the soft and USB backends the salt
distinguishes "this is babbleon's KEK derivation" from any other
Argon2id consumer that might run on the same host.  In `kdf.rs`
the salt serves the same role for HKDF.

A SAST tool that flags any constant byte string near `Argon2`,
`Hkdf`, or `hmac` as a credential will fire here.  The docstring on
each constant declares it as a public version tag, not a secret, so
audit reviewers don't have to re-derive that conclusion.

**Finding — no fix.**  Comments in all three modules already state
this; no further action.  Once HKDF is the universal KDF entry
point (post-migration to age 0.11), only `kdf.rs::HKDF_SALT` will
remain and the legacy salts can be deleted.

---

## CWE-352 — CSRF, CWE-79 — XSS, CWE-89 — SQL injection

**Surface.** None.  Babbleon is a local CLI with no web surface,
no HTTP server, and no SQL store.  The HTML scrambler harness
(`tools/scrambler/index.html`) does not send any request and does
not embed any user-supplied data into its DOM beyond the puzzle
input box (which the user controls themselves).

**Finding — N/A.**  Out of scope by design.

---

## CWE-862 — Missing Authorization

**Surface.** Vault unlock (`session.rs::unlock`).  Authorization is
"caller has the passphrase / keyfile / TPM PCR state / FIDO2
authenticator" depending on the configured backend.  No bypass path
exists in the public crate — every code path through `Vault::unseal`
demands the configured credential.

**Finding — no fix.**  Rate-limit (commit `d847283`) closes the
brute-force adjacent class.

---

## CWE-1333 — Inefficient regular expression complexity

**Surface.** None.  The crate has no user-controlled regex.  The
only regex-shaped code is the `proptest` wordlist generator
`"[a-z]{2,8}"` which is fully bounded.

**Finding — N/A.**

---

## CWE-770 — Allocation of resources without limits

**Surface.** Wordlist load (`mapping/mapper.rs::WORDLIST_RAW`) and
mapping table cache (`mapping/fpe.rs::CACHE`).

**Data flow.** Wordlist is `include_str!`'d at compile time — its
size is a build-time property, not a runtime one.  The FPE cache
grows by one (~3 MiB) entry per distinct (host_secret, epoch, n)
combination.  Epochs advance once per rotation interval (default
multi-minute); host_secret per vault; n is fixed.  Cache growth is
O(rotations) — meaningful only for a daemon running across many
rotations without ever clearing.

**Finding — file an eviction policy.**  Filed in TODO under
"FPE cache eviction at N entries".

---

## Update cadence

Re-run this audit whenever:

- A new field is added to the wrapper template.
- The wordlist gains non-alpha characters.
- The ns-helper privilege chain is reordered.
- A new KEK backend ships.

Last refreshed: 2026-06-15.
