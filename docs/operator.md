# Babbleon — Operator Guide

Practical guide for installing, rotating, recovering, and decommissioning
Babbleon on a Linux host.  Companion to PLAN.md (architecture) and
docs/threat-model.md (what's defended).

## Install

### 1. Build

    cargo build --release --workspace

Artifacts:

| Binary                              | Install to                       | Mode      |
|-------------------------------------|----------------------------------|-----------|
| `target/release/babbleon`           | `/usr/local/bin/babbleon`        | `0755`    |
| `target/release/babbleon-ns-helper` | `/usr/local/libexec/babbleon-ns-helper` | `4755 root:root` (SETUID) |
| `target/release/pam_babbleon.so`    | `/lib/security/pam_babbleon.so`  | `0644`    |

The setuid bit on `babbleon-ns-helper` is load-bearing.  Without it,
unprivileged users cannot create the mount + PID namespace.  The helper
drops the capability bounding set and PR_SET_NO_NEW_PRIVS before exec.

### 2. Initialize the vault

As the user who'll be running scrambled workloads:

    babbleon init

You'll be prompted for a passphrase.  Vault lives at
`$XDG_DATA_HOME/babbleon/vault.age` (default `~/.local/share/babbleon/vault.age`).

### 3. Install the rotation timer

    sudo babbleon install --schedule weekly
    sudo systemctl daemon-reload
    sudo systemctl enable --now babbleon-rotate.timer

`--schedule` accepts any systemd `OnCalendar=` expression
(`daily`, `weekly`, `Mon *-*-* 03:00:00`, ...).

### 4. Wire the PAM module

Add to `/etc/pam.d/common-session` (Debian/Ubuntu) or
`/etc/pam.d/system-auth` (RHEL family):

    session optional pam_babbleon.so

`optional`, not `required`: login is never blocked on Babbleon failure.
The trust-tier inode is still written so wrapper scripts behave correctly
even if the helper didn't establish the NS.

## Rotate

The rotation timer handles this automatically.  Manual rotation:

    babbleon rotate

This bumps the epoch, re-derives the mapping, regenerates honey names,
and re-seals the vault with the existing KEK.  Currently-running
scrambled processes keep the old view (their mount NS is unaffected);
new sessions get the new mapping at next PAM session-open.

## Recover

### Lost passphrase, Soft tier

Without the passphrase the vault is unrecoverable — that's the point.
Wipe and re-init:

    rm ~/.local/share/babbleon/vault.age
    rm -f ~/.local/share/babbleon/vault.age.attempts  # rate-limit sidecar
    babbleon init

### Locked out by failed unlock attempts

The vault enforces an exponential backoff after 3 failed attempts
and a hard lockout at 10 (see
`crates/babbleon/src/vault/attempts.rs`).  Locked-out vault rejects
even the correct passphrase until the sidecar is cleared:

    rm ~/.local/share/babbleon/vault.age.attempts

Use this only when you're confident the failures were typos, not an
attacker — clearing the sidecar after a real brute-force attempt
hides the evidence.

### Backup the mapping (against snapshot restore)

A filesystem snapshot captures the *current* epoch's scrambled
binary names.  Pair it with a mapping bundle so a future restore can
re-render the wrapper scripts under whatever epoch the restored
vault is at:

    babbleon backup --out mapping-backup.json

The bundle carries the host_secret, manifest, wordlist hash, and
current epoch.  Store it next to your filesystem snapshot.

### Restore from a backup

Plan first (no filesystem changes yet — currently prints the rename
list only):

    babbleon restore --in mapping-backup.json --policy reject

Policy choices:

  - `reject` (default) — refuse unless epoch + host_secret +
    wordlist match exactly
  - `rewrap` — translate every name through the old mapping back to
    real, then forward through the current mapping (O(N) renames)
  - `honor-snapshot` — keep the bundle's names in place for one
    rotation cycle

### Lost FIDO2 token

If you registered a single token, the vault is unrecoverable.  Always
register at least two tokens, or use Soft tier as a recovery backstop
(community single-tier today; M5 enterprise adds key escrow).

### TPM2-sealed vault, post-kernel-update

PCRs 4/8/9 change on kernel update; the sealed blob becomes unreadable.
Workaround for now:

    babbleon tpm-reseal           # (DEFERRED — M2.5)

Until that ships, keep a Soft-tier backup vault for recovery.

### Suspect compromise

Treat as a fresh-start scenario:

    babbleon rotate                # bumps epoch
    sudo systemctl restart sshd    # forces new PAM sessions

If a honey tripwire fired (`audit.jsonl` shows `HoneyTriggered`), the
host is presumed hostile.  Quarantine, then forensic.

## Decommission

To remove Babbleon cleanly:

    sudo systemctl disable --now babbleon-rotate.timer
    sudo rm /etc/systemd/system/babbleon-rotate.{service,timer}
    sudo rm /lib/security/pam_babbleon.so
    sudo rm /usr/local/libexec/babbleon-ns-helper
    sudo rm /usr/local/bin/babbleon
    rm -rf ~/.local/share/babbleon

Remove the `session optional pam_babbleon.so` line from the PAM stack.

## Verify

Audit-log chain integrity:

    babbleon audit-verify ~/.local/share/babbleon/audit.jsonl

(DEFERRED CLI wrapper; the `audit::ChainedAuditLog::verify` API is in
the library today.)

Status check:

    babbleon status

Per-host scrambling sample:

    babbleon untrusted | head -5

## Common issues

- `unshare(NEWNS|NEWPID) — requires CAP_SYS_ADMIN`:
  setuid bit was lost during install or chmod.  Re-apply `4755`.

- `Landlock not enforced — kernel <5.13`:
  Defense-in-depth layer unavailable; mount-NS boundary still active.
  No action required unless your threat model demands Landlock.

- `/proc hidepid remount failed (PID NS not set up?)`:
  The helper didn't establish the PID NS — usually because it was
  invoked outside the PAM stack.  Confirm `babbleon-ns-helper` is on
  PATH and setuid.
