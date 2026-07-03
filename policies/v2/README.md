# OS-level confinement profiles — v2

Conservative starting templates for the two major Linux MAC systems,
covering the five binaries `docs/v2/least-privilege.md`'s A08
release-scope list identifies as the v2 product surface:
`babbleon` (CLI), `babbleon-daemon`, `babbleon-launch-untrusted`,
`babbleon-login-shell`, `babbleon-python`. This directory is the v2
counterpart to `policies/README.md` (v1); see that file for the
shared design philosophy (fail open at the application level, tune
to enforcing after an audit-log review window).

**Do not install both the v1 (`policies/apparmor/`,
`policies/selinux/`) and v2 profiles on the same host.** `babbleon`
(v2 CLI) and v1's `babbleon` share the same install path
(`/usr/local/bin/babbleon`) by design — the two are alternate
generations of the same product, never installed simultaneously.
Install whichever set matches the binaries you actually built; see
`crates/DEPRECATED-V1.md` for why v1 is not the path forward.

| Distro family | Use | Files |
|---|---|---|
| Ubuntu, Debian, SUSE | AppArmor | `apparmor/usr.local.bin.babbleon`, `apparmor/usr.local.libexec.babbleon-daemon`, `apparmor/usr.local.libexec.babbleon-launch-untrusted`, `apparmor/usr.local.bin.babbleon-login-shell`, `apparmor/usr.local.bin.babbleon-python` |
| Fedora, RHEL, Rocky | SELinux | `selinux/babbleon_v2.te`, `babbleon_v2.fc`, `babbleon_v2.if` |

## Why ship profiles at all

Same rationale as v1 (see `policies/README.md`), with one v2-specific
addition: `docs/v2/least-privilege.md`'s own "Open audit items
carried into v2" section flagged this as still open — v1 shipped
profiles, v2 initially didn't. These templates close that gap.

- An attacker who finds an exploit in a v2 binary still has to
  escape MAC as a second, independent barrier.
- `babbleon-launch-untrusted`'s file-capability model (not setuid;
  see `docs/v2/least-privilege.md`) already narrows the blast radius
  of a code bug to five capabilities that are fully dropped before
  step 11's `execve`. MAC is belt-and-suspenders on top of that,
  not the primary control.
- The profiles encode "what each v2 binary legitimately touches" as
  machine-readable policy, cross-checked here against the actual
  source paths (`/run/babbleon/daemon.sock`,
  `/usr/local/libexec/babbleon/wrappers`, the per-user vault path in
  `crates/v2-babbleon-vault/src/file_layout.rs`, etc.) rather than
  guessed.

## AppArmor install

```sh
for f in usr.local.bin.babbleon \
         usr.local.libexec.babbleon-daemon \
         usr.local.libexec.babbleon-launch-untrusted \
         usr.local.bin.babbleon-login-shell \
         usr.local.bin.babbleon-python; do
  sudo cp "policies/v2/apparmor/$f" "/etc/apparmor.d/$f"
  sudo apparmor_parser -r "/etc/apparmor.d/$f"
done

sudo aa-complain /usr/local/bin/babbleon
sudo aa-complain /usr/local/libexec/babbleon-daemon
sudo aa-complain /usr/local/libexec/babbleon-launch-untrusted
sudo aa-complain /usr/local/bin/babbleon-login-shell
sudo aa-complain /usr/local/bin/babbleon-python
```

After a few days of clean `/var/log/audit.log`, `sudo aa-enforce`
each path in turn.

## SELinux install

```sh
cd policies/v2/selinux
make -f /usr/share/selinux/devel/Makefile babbleon_v2.pp
sudo semodule -i babbleon_v2.pp

sudo semanage fcontext -a -t babbleon_v2_cli_exec_t '/usr/local/bin/babbleon'
sudo semanage fcontext -a -t babbleon_v2_daemon_exec_t '/usr/local/libexec/babbleon-daemon'
sudo semanage fcontext -a -t babbleon_v2_launch_exec_t '/usr/local/libexec/babbleon-launch-untrusted'
sudo semanage fcontext -a -t babbleon_v2_login_shell_exec_t '/usr/local/bin/babbleon-login-shell'
sudo semanage fcontext -a -t babbleon_v2_python_exec_t '/usr/local/bin/babbleon-python'
sudo semanage fcontext -a -t babbleon_v2_runtime_t '/run/babbleon(/.*)?'
sudo semanage fcontext -a -t babbleon_v2_wrapper_t '/usr/local/libexec/babbleon/wrappers(/.*)?'

sudo restorecon -Rv /usr/local/bin/babbleon* \
                    /usr/local/libexec/babbleon-daemon \
                    /usr/local/libexec/babbleon-launch-untrusted \
                    /usr/local/libexec/babbleon/wrappers \
                    /run/babbleon \
                    ~/.config/babbleon

for d in babbleon_v2_cli_t babbleon_v2_daemon_t babbleon_v2_launch_t \
         babbleon_v2_login_shell_t babbleon_v2_python_t; do
  sudo semanage permissive -a "$d"
done
```

After clean `ausearch -m AVC -ts recent`, drop each domain from
permissive (`sudo semanage permissive -d <domain>`) to enforce.

## What these templates assume

- The install layout documented in `docs/v2/pam-flavour-1.md`:
  `babbleon` and `babbleon-login-shell` under `/usr/local/bin/`;
  `babbleon-launch-untrusted` under `/usr/local/libexec/`.
- **`babbleon-daemon`'s install path is not yet fixed by any shipped
  systemd unit or packaging** (`TODO.md`'s Phase 6 is still largely
  open). This template assumes `/usr/local/libexec/babbleon-daemon`,
  matching the "internal, not directly user-invoked" convention the
  launcher already uses. If your deployment installs it elsewhere,
  update the profile's confined path (AppArmor) or the `fcontext`
  pattern (SELinux) before loading.
- Runtime state at `/run/babbleon/` (daemon socket, scrambled-view
  tmpfs mount point, activated-table cache).
- Wrapper materialisation at `/usr/local/libexec/babbleon/wrappers`
  (and its atomic-swap staging sibling, `wrappers.next`).
- Per-user vault at `~/.config/babbleon/vault.age`; system-install
  vault and the enrollment registry at `/etc/babbleon/`.

If you install elsewhere, adjust the paths in every file before
loading — same caveat as the v1 templates.

## What's deliberately NOT in the profile

- The 16-syscall seccomp allowlist `babbleon-launch-untrusted`
  installs at step 8 is the load-bearing control on the untrusted
  child, not MAC. Per `TODO.md`'s "post-step-8 seccomp filter" entry,
  that allowlist currently cannot run any real child command at all
  — an operator decision, not something these MAC profiles paper
  over. `untrusted-child` (AppArmor) / the `unconfined_t` transition
  (SELinux) are deliberately permissive because the real containment
  for that step is namespace + seccomp + a fully-dropped capability
  set, not MAC; tightening the child profile without first resolving
  the seccomp gap would just be security theatre layered on a broken
  primary control.
- TPM / FIDO2 device paths — gated until those backends ship for
  real (`TODO.md` Phase 5).
- The enterprise crate's SIEM forwarder socket — out of scope for
  the public templates, same as v1.
- PAM module (`crates/v2-babbleon-pam`) file access is not templated
  separately: it is vestigial today (daemon liveness probe only; see
  `docs/v2/pam-flavour-1.md`) and runs inside whatever domain the
  PAM stack itself already confines the login session to.
