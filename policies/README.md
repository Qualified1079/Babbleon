# OS-level confinement profiles

Conservative starting templates for the two major Linux MAC systems.
Both are written to fail open at the application level (Babbleon will
keep working if the profile isn't loaded) and to be tightened by the
operator after a few days of audit-log review.

| Distro family | Use | Files |
|---|---|---|
| Ubuntu, Debian, SUSE | AppArmor | `apparmor/usr.local.bin.babbleon` |
| Fedora, RHEL, Rocky | SELinux | `selinux/babbleon.te`, `babbleon.fc`, `babbleon.if` |

## Why ship profiles at all

Babbleon's own enforcement layer (mount + PID namespaces, Landlock,
seccomp, capability drop) is already self-contained. The MAC profiles
are **defence-in-depth**:

- An attacker who finds an exploit in babbleon itself (e.g. wrapper
  template injection) still has to escape MAC.
- If the operator's audit pipeline is asleep, MAC blocks the bad call.
- The profile encodes "what babbleon legitimately does" as machine-
  readable policy — easier to review than the code that produces the
  same behaviour.

## AppArmor install

```
sudo cp policies/apparmor/usr.local.bin.babbleon \
        /etc/apparmor.d/usr.local.bin.babbleon
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.babbleon
sudo aa-complain /usr/local/bin/babbleon   # log only for the first run
```

After a few days of clean `/var/log/audit.log`:

```
sudo aa-enforce /usr/local/bin/babbleon
```

## SELinux install

```
cd policies/selinux
make -f /usr/share/selinux/devel/Makefile babbleon.pp
sudo semodule -i babbleon.pp
sudo restorecon -Rv /usr/local/bin/babbleon \
                    /usr/local/libexec/babbleon-ns-helper \
                    /run/babbleon \
                    ~/.config/babbleon \
                    ~/.local/share/babbleon
sudo semanage permissive -a babbleon_t       # log-only for a day
```

After clean `ausearch -m AVC -ts recent`:

```
sudo semanage permissive -d babbleon_t        # enforce
```

## What these templates assume

- Babbleon is at `/usr/local/bin/babbleon`
- The ns-helper is at `/usr/local/libexec/babbleon-ns-helper`
- Runtime state at `/run/babbleon/`
- Per-user state under `~/.config/babbleon/` and
  `~/.local/share/babbleon/`

If you install elsewhere (Homebrew, custom prefix), adjust the paths
in both files before loading.

## What's deliberately NOT in the profile

- TPM / FIDO2 device paths — gated until those backends ship for real
- SIEM forwarder sockets — that lives in the enterprise crate's profile
- Audit-log signing key path — operator-specific; keep that in the
  operator-side wrapper profile, not in the public template
