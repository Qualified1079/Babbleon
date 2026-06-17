# GUI design — v2

The v2 GUI is the operator's control plane for Babbleon.  It is
not required to run Babbleon (everything the GUI does, the CLI
can do), but it is the intended path for operators who are not
comfortable editing config files or running CLI commands.

The single most important GUI flow is **per-app trust grants**:
the operator's way of saying "this tool is legitimate; let it run
in the trusted tier."

## Design principles

1. **Authentication first.**  The GUI is a privileged surface.
   Every action that changes security policy requires the operator
   to authenticate (passphrase, security key, or both per the
   configured credential mode).  The GUI presents a credential
   prompt at open, and re-prompts for any policy-change action.

2. **Plain language everywhere.**  Labels, status messages, and
   error text describe what Babbleon is doing in the same terms
   the naming-conventions doc defines.  No internal codes, no
   jargon below "trusted/untrusted tier."

3. **Destructive actions need confirmation.**  Revoking a trust
   grant, rotating the epoch mapping, or uninstalling the PAM
   module all require a second explicit confirmation after the
   credential prompt.

4. **Audit trail.**  Every GUI action that changes policy is logged
   to the same Ed25519-signed audit chain as CLI actions.  The log
   entry records the action, the authenticated identity, and a
   timestamp.

5. **No state except via the daemon.**  The GUI is a thin client
   that talks to the Babbleon daemon over a local Unix socket.
   It holds no secrets, no epoch keys, no mapping tables.

## Per-app trust grant flow

This is the primary user story the GUI is optimised for.

### Motivating scenario

The operator installs a container runtime (podman, docker, nerdctl).
In the default configuration, container runtimes spawn child
processes in the untrusted tier (they were not launched via a PAM
login that creates the trusted mount namespace).  The runtime's
commands (`podman pull`, `docker build`) fail to find their
dependencies because those dependencies are scrambled in the
untrusted view.

The fix: grant the container runtime a trust exception so that
its process tree runs in the trusted tier.

### Step-by-step UX

1. **Open the Babbleon app.**

   The operator opens the Babbleon GUI (system tray icon, app
   launcher, or `babbleon-gui` in terminal).

2. **Authenticate.**

   The GUI shows a credential prompt: passphrase input field,
   "Use security key" button, or both if multi-factor is
   configured.  On success, the GUI unlocks the policy panel.

3. **Navigate to "Trusted apps".**

   The main panel has tabs: Overview, Trusted apps, Epoch,
   Tripwires, Audit log.  The operator clicks "Trusted apps."

4. **Type the app name.**

   A search/input box at the top of the "Trusted apps" tab,
   labelled "App name or path".  The operator types `podman`.

   As they type, the GUI searches:
   - `/usr/bin`, `/usr/local/bin`, `/opt/*/bin` for executables
     matching the prefix.
   - The current trusted-app list for existing grants.
   
   A dropdown shows matches: `podman`, `podman-remote`, etc.  The
   operator selects `podman`.

5. **Tick "Trusted".**

   The selected row shows a toggle switch labelled "Trusted tier".
   The operator ticks it (or clicks the toggle).  A confirmation
   dialog appears:

   > **Grant trusted tier access to `podman`?**
   >
   > Processes launched by `podman` and its children will run in
   > the trusted tier and see real filesystem names.
   >
   > This grants `podman` access to credentials, SSH keys, and
   > browser cookies that are hidden from untrusted processes.
   > Only grant this to tools you trust completely.
   >
   > [Cancel]  [Grant access]

   The operator clicks "Grant access."

6. **The grant is written.**

   The GUI sends a signed request to the Babbleon daemon.  The
   daemon validates the operator's credential (forwarded as a
   session token from step 2), adds `podman` to the trusted-app
   manifest, and logs the action to the audit chain.

   The "Trusted apps" list refreshes to show `podman` with a green
   "Trusted" badge.

7. **Effect.**

   From this point forward, any process whose executable path
   resolves to the `podman` binary (checked by SHA-256 of the
   binary at grant time, re-verified at exec time) enters the
   trusted mount namespace automatically.  Its children inherit
   the trusted namespace.

### Trusted-app manifest entry

Each grant is stored in the daemon's signed manifest as a TOML
entry:

```toml
[[trusted_app]]
name        = "podman"
path        = "/usr/bin/podman"
binary_hash = "sha256:a1b2c3..."  # SHA-256 of the ELF at grant time
granted_by  = "operator"
granted_at  = "2026-06-17T12:00:00Z"
note        = ""  # optional operator annotation
```

At exec time, the ns-helper checks:
1. Is the executable path in the trusted-app manifest?
2. Does the SHA-256 of the binary match the stored hash?

If both match, the process enters the trusted namespace.
If the binary hash has changed (update, compromise), the ns-helper
refuses and logs a `TrustedAppHashMismatch` event to the tripwire
FIFO.  The operator must re-grant after verifying the update.

### Revocation

The operator ticks "Trusted" off (or clicks "Revoke") in the same
UI row.  Confirmation dialog, same pattern.  The manifest entry
is removed.  Existing processes already running in the trusted
namespace are NOT evicted (eviction would require killing them;
too disruptive).  New processes launched by the app after
revocation enter the untrusted namespace.

## "Trusted apps" tab — full layout

```
┌─────────────────────────────────────────────────────────┐
│ Trusted apps                                            │
│                                                         │
│  Search: [ podman_________________ ] [+ Add manually]  │
│                                                         │
│  ┌──────────────────────┬──────────────┬──────────┐     │
│  │ Name                 │ Path         │ Trusted  │     │
│  ├──────────────────────┼──────────────┼──────────┤     │
│  │ podman               │ /usr/bin/    │ ● ON     │     │
│  │ docker               │ /usr/bin/    │ ○ OFF    │     │
│  │ ssh                  │ /usr/bin/    │ ● ON     │     │
│  │ gpg                  │ /usr/bin/    │ ● ON     │     │
│  └──────────────────────┴──────────────┴──────────┘     │
│                                                         │
│  [Revoke all]                                           │
└─────────────────────────────────────────────────────────┘
```

Clicking a row expands it to show:
- Full binary path
- Binary hash (truncated, copy button)
- Grant date and operator identity
- Optional note field (editable)
- "Re-verify hash" button (checks current binary against stored hash)
- "Revoke" button

## Other GUI panels

### Overview panel

- Current epoch number, time until next rotation, "Rotate now" button.
- Count of trusted-app grants.
- Count of tripwire events in the last 24h.
- Daemon health indicator (green/amber/red).

### Epoch panel

- Current epoch number and seed (non-sensitive; the seed is
  HKDF-derived from the host secret + epoch counter; showing
  it does not expose the host secret).
- "Rotate now" button.  Confirmation required.
- Rotation schedule config (manual, hourly, daily, weekly).
- History: table of past epochs with rotation timestamps.

### Tripwires panel

- List of recent tripwire events (honey name triggered, stale
  name triggered) with timestamp, triggering PID, and the
  scrambled name that was accessed.
- Response policy selector per tripwire type:
  - `notify-only` (log only)
  - `kill-trigger` (SIGKILL the triggering process)
  - `kill-trigger-tree` (SIGKILL the process tree)
  - `quarantine` (move to isolated network namespace)
  - `system-alert` (send to configured SIEM sink)
- "Test tripwire" button: fires a synthetic event to confirm
  the response pipeline is wired up.

### Audit log panel

- Scrollable, filterable view of the Ed25519-signed audit chain.
- Columns: timestamp, action, subject, operator, signature-valid indicator.
- Export to JSONL.
- "Verify chain" button: re-checks every signature and hash link.

## CLI equivalents

Every GUI action maps to a CLI command.  The GUI is a wrapper;
the CLI is the canonical interface.

| GUI action | CLI equivalent |
|---|---|
| Add trusted app | `babbleon trust add podman` |
| Revoke trusted app | `babbleon trust revoke podman` |
| List trusted apps | `babbleon trust list` |
| Rotate epoch now | `babbleon rotate-mapping` (alias: `babbleon rm`) |
| View tripwire events | `babbleon tripwire events` |
| Set response policy | `babbleon tripwire policy set --type honey --response kill-trigger` |
| View audit log | `babbleon audit log` |
| Verify audit chain | `babbleon audit verify` |

## What the GUI does NOT do

- **Mount or unmount the scrambled view.**  That is the ns-helper's
  job, triggered by PAM at login.  The GUI cannot mount it on demand
  for the same reason: mounting requires `CAP_SYS_ADMIN`, which the
  GUI process never holds.
- **Show or export the epoch key or host secret.**  These never
  leave the daemon's mlock'd memory.  The GUI gets a session token
  at authentication; the session token does not embed or derive
  the epoch key.
- **Install or uninstall PAM modules.**  That is a root-level
  operation done once at install time (`babbleon install`).  The
  GUI is not the right surface for it.
- **Operate without authentication.**  Read-only views (audit log,
  tripwire events, trusted-app list) require an authenticated
  session.  There is no guest/read-only mode.

## Open questions (decide before phase 2)

1. **GUI toolkit.**  GTK4 (native Linux) vs a web-based local UI
   (HTML + daemon HTTP-over-Unix-socket) vs a TUI (`ratatui`).
   GTK4 is the most Linux-native but adds a significant dependency.
   Local web UI is portable but ships a mini HTTP server.  TUI is
   the lightest.  Recommendation: TUI for v2.0 (aligns with
   operator persona: Linux sysadmins); GTK4 desktop app for v2.1
   (desktop deployment).

2. **Session token lifetime.**  How long does a GUI authentication
   session stay valid before re-prompting?  Recommendation: 5 minutes
   of inactivity, or until the GUI window closes, whichever is
   first.  Override configurable.

3. **Binary hash re-verification on update.**  When a package
   manager updates `podman`, the binary hash changes and the
   trust grant silently stops working.  Options: (a) the daemon
   auto-detects hash mismatch and shows a notification in the GUI,
   requiring re-grant; (b) the operator installs a package-manager
   hook that calls `babbleon trust re-verify` after every update.
   Recommendation: both (a) and (b); see `docs/v2/` package-manager
   hook design (TBD).
