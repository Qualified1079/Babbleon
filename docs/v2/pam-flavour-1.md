# PAM flavour 1 — shell-wrapper deployment

**Status:** wired.  This is the PAM architecture the project ships
in v2.0.  Code lives in `crates/v2-babbleon-login-shell/` (the
wrapper binary) and `crates/v2-babbleon/src/enroll.rs` (the
operator CLI).  Per-user enrollment via `chsh`.  The PAM module
itself (`crates/v2-babbleon-pam`) is vestigial — its job is the
daemon liveness probe, not the wrap.

See `docs/v2/pam-architecture.md` for the comparison against
flavours 2 and 3, and the security argument for picking F1.

## What it does, end to end

1. Operator installs the launcher at
   `/usr/local/libexec/babbleon-launch-untrusted` (with file
   capabilities — NOT setuid; see `docs/v2/least-privilege.md`).
2. Operator installs the wrapper at
   `/usr/local/bin/babbleon-login-shell` (no special permissions
   required; the wrapper is just an exec shim).
3. Operator runs `babbleon enroll <user>` for every account that
   should run inside the obfuscated environment.  This:
    - Reads the user's current login shell via `getent passwd`.
    - Records `{user, previous_shell}` in
      `/etc/babbleon/enrolled-shells.toml` (mode 0o600).
    - Runs `chsh -s /usr/local/bin/babbleon-login-shell <user>`.
4. From the next login onward, every shell invocation for that
   user goes:
    - `sshd` / `login` / `sudo` / `su` resolves the shell from
      `/etc/passwd` → the wrapper.
    - The wrapper resolves `BABBLEON_LAUNCH_UNTRUSTED_PATH`,
      `BABBLEON_DAEMON_SOCKET_PATH`, `BABBLEON_REAL_SHELL` from
      the environment (defaults documented below).
    - The wrapper `exec`s the launcher:
      `babbleon-launch-untrusted --daemon-socket /run/babbleon/daemon.sock -- /bin/bash --login [args...]`
    - The launcher establishes the untrusted-tier environment
      (mount NS, scrambled view, credential gate, env scrub,
      seccomp, identity drop) and `exec`s `/bin/bash --login` as
      the user's shell.

`babbleon unenroll <user>` reverses step 3: reads the previous
shell from the registry, chshes back, removes the entry.

## Install steps

```sh
# 1. Build + install (operator's build pipeline).
cargo build --release \
    -p v2-babbleon-launch-untrusted \
    -p v2-babbleon-login-shell \
    -p v2-babbleon
sudo install -m 0755 -o root -g root \
    target/release/babbleon-launch-untrusted \
    /usr/local/libexec/babbleon-launch-untrusted
sudo setcap 'cap_sys_admin,cap_setuid,cap_setgid,cap_ipc_lock=ep' \
    /usr/local/libexec/babbleon-launch-untrusted
sudo install -m 0755 -o root -g root \
    target/release/babbleon-login-shell \
    /usr/local/bin/babbleon-login-shell
sudo install -m 0755 -o root -g root \
    target/release/babbleon-v2 \
    /usr/local/bin/babbleon

# 2. Register the wrapper in /etc/shells so chsh accepts it.
echo /usr/local/bin/babbleon-login-shell | sudo tee -a /etc/shells

# 3. Enrol each account.
sudo babbleon enroll alice
sudo babbleon enroll bob
```

To verify:

```sh
getent passwd alice | awk -F: '{print $7}'
# /usr/local/bin/babbleon-login-shell
```

## Closing the non-interactive bypass via sshd

By default, `ssh user@host CMD` runs `$SHELL -c CMD` — which, with
the wrapper as `$SHELL`, still routes through the launcher.  Good.

But `ssh -t user@host` and SFTP / SCP have edge cases:

- **`internal-sftp`**: many distros configure
  `Subsystem sftp internal-sftp` in `sshd_config`.  `internal-sftp`
  is a sshd-internal handler, not a separate program — it bypasses
  the user's shell entirely.  To wrap sftp:
   - Either: leave sftp unwrapped (operator decision — sftp
     transfers are arguably out of scope for an obfuscation
     system that targets interactive exploit attempts).
   - Or: configure `Subsystem sftp /usr/lib/openssh/sftp-server`
     (the external handler) and enrol an `sftp` group via a
     `Match` block.
- **`ssh user@host -- ls`**: runs through `$SHELL -c`, wrapped.
- **`ForceCommand`**: if you set
  `ForceCommand /usr/local/bin/babbleon-login-shell -c "$SSH_ORIGINAL_COMMAND"`
  in a `Match` block, you wrap every connection regardless of
  what's set as `$SHELL`.  Useful as a belt-and-braces for
  servers where you don't trust `/etc/passwd` editability.

Recommended sshd_config addition (single-tenant developer laptop;
adjust the `Match` predicate for multi-tenant):

```sshd_config
# /etc/ssh/sshd_config.d/babbleon.conf
Match User alice,bob
    ForceCommand /usr/local/bin/babbleon-login-shell -c "${SSH_ORIGINAL_COMMAND:-}"
```

Restart sshd to apply.

## Limitations (documented, not silent)

- **Direct invocation of a different shell.**
  `/bin/zsh script.sh` bypasses the wrapper because zsh is not
  invoked via the user's shell-of-record.  This is the standard
  "Linux gives you the keys to your own house" caveat; the
  launcher's per-tool wrappers still catch anything under the
  Babbleon mapping that zsh tries to exec.
- **Operator who edits `/etc/passwd` directly.**  Bypasses the
  registry.  `babbleon enroll` is the supported path; manual
  edits leave the registry stale.
- **sftp via `internal-sftp`** — see the sshd section above.
- **The wrapper itself crashing.**  Login fails loudly (the user
  cannot log in).  By design — silent failure would defeat the
  wrap.  Operator-recovery: log in as root via a non-wrapped
  account and `babbleon unenroll` the broken account.

## Environment overrides

The wrapper reads three env vars at exec time, all optional:

| Variable | Default | Purpose |
|---|---|---|
| `BABBLEON_LAUNCH_UNTRUSTED_PATH` | `/usr/local/libexec/babbleon-launch-untrusted` | Launcher binary path.  Override for non-standard installs. |
| `BABBLEON_DAEMON_SOCKET_PATH` | `/run/babbleon/daemon.sock` | Daemon socket path.  Override for tests or multi-instance setups. |
| `BABBLEON_REAL_SHELL` | `/bin/bash` | The shell the user actually wants to run.  Override per-user via `pam_env.conf` or `~/.pam_environment` for zsh / fish users. |

Per-user override example
(`/etc/security/pam_env.conf`):

```
BABBLEON_REAL_SHELL DEFAULT=/bin/bash OVERRIDE=@{HOME}/.babbleon-shell
```

…with `~/.babbleon-shell` containing `/usr/bin/zsh` (or whatever).
PAM session setup sources this before the user's shell starts,
so the override is visible in the wrapper's environment.

## Testing the enrolment locally

```sh
# Install everything into a tempdir for testing.
DEST=$(mktemp -d)
cp target/debug/babbleon-launch-untrusted "$DEST/launcher"
cp target/debug/babbleon-login-shell "$DEST/login-shell"

# Spawn a daemon (insecure-stub-secret for testing only).
./target/debug/babbleon-daemon \
    --socket "$DEST/d.sock" \
    run --wrapper-dir "$DEST/wrappers" \
        --tracked-tool curl=/usr/bin/curl \
        --insecure-stub-secret &

# Drive the wrapper without actually chshing — set env, exec.
BABBLEON_LAUNCH_UNTRUSTED_PATH="$DEST/launcher" \
BABBLEON_DAEMON_SOCKET_PATH="$DEST/d.sock" \
BABBLEON_REAL_SHELL=/bin/bash \
    "$DEST/login-shell" -c 'which curl; echo $?'
```

Inside the launched shell, `which curl` should return the
per-epoch scrambled path under the daemon's wrapper dir.

## When to escalate to a different flavour

- **F2 (PAM-internal NS):** when an operator demands "every PAM-
  aware session is wrapped, with no per-user enrollment" and is
  willing to absorb the audit-surface cost of `unshare` +
  `mount` inside a PAM module's address space.  Defer to a
  later release.
- **F3 (token + shell rc):** when an operator absolutely cannot
  edit `/etc/passwd` (some compliance regimes) and is willing
  to leave non-interactive sessions unwrapped.  Filed in
  `docs/v2/pam-architecture.md`; not currently implemented.

For v2.0's single-tenant developer-laptop target, F1 is the
shipping choice.  Multi-tenant deployments that need F2 or F3
should file an issue against the `pam-architecture.md` doc with
the use case so we can scope the addition.
