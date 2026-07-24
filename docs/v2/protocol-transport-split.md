# Audit — is `v2-babbleon-daemon-protocol` shareable with a mobile fork?

Companion to `docs/v2/scramble-core-carve.md`.  That carve unblocked a
mobile Babbleon fork by isolating the OS-agnostic **scramble engine**
(`v2-babbleon-scramble`) from the Linux **detection/response tier**
(`v2-babbleon-linux`).  This document answers the natural follow-on: does
the fork also get to reuse the **daemon protocol** — the vocabulary the
untrusted-tier process uses to ask the daemon for a token mapping — or
must it define its own?

**Short answer: the wire layer is shareable as-is; only the transport is
Linux-welded, and it is already a thin, cleanly separated minority of the
crate.**  A mobile fork keeps the request/response types and the parser,
and swaps `UnixStream` for whatever IPC Android gives it (binder/AIDL, a
bound `LocalSocket`, or a content-provider call).

## Audit — the crate already splits along a transport fault line

`crates/v2-babbleon-daemon-protocol/src/` has five modules.  Grep for OS
surface (`std::os`, `UnixStream`, `std::net`, `std::fs`, `/run`, `/proc`,
`libc`, `nix`) lands entirely in two of them:

```
TRANSPORT-FREE (OS-agnostic, shareable)      LINUX TRANSPORT (welded)
  protocol.rs   Request/Response wire           client.rs      UnixStream::connect,
                types + hand-rolled                             Shutdown::Write, round_trip
                serde_json::Value parser        socket_path.rs  /run/babbleon/daemon.sock
  errors.rs     Error / Result
  unlock_secret.rs  UnlockSecret newtype
```

Confirmed clean: `protocol.rs`, `errors.rs`, and `unlock_secret.rs`
contain **zero** OS/syscall/path references.  (The `last_rotation_unix_secs`
field in the status response is a Unix-*epoch* timestamp — a `u64` field
name, not a syscall or a `/`-path — so it does not weld the types to any
OS.)

The only OS surface is:

- `client.rs` — `std::os::unix::net::UnixStream::connect` + the 70-line
  length-prefixed framing / `Shutdown::Write` half-close.  This is the
  transport, not the protocol.
- `socket_path.rs` — the hard-coded `/run/babbleon/daemon.sock` path.

`lib.rs` already keeps these on separate `pub mod` lines with separate
flat re-exports (`round_trip`, `default_socket_path` are transport;
`Request`, `Response`, `Error`, `UnlockSecret` are wire types), so the
split needs no re-plumbing of the public surface — same property that
made the scramble carve zero-churn.

## Consumer evidence — every transport caller is a Linux binary the fork replaces

Across the workspace, `round_trip` / `default_socket_path` (the Linux
transport) is called by:

| Transport consumer | Why it's Linux-only anyway |
| --- | --- |
| `v2-babbleon` (CLI) | `main.rs`, `scramble_lifecycle.rs`, `vault_lifecycle.rs` — the desktop CLI |
| `v2-babbleon-python-shim` | `pipeline.rs` — the Linux runtime shim |
| `v2-babbleon-launch-untrusted` | `activated_table_input.rs` — the fork-exec launcher |
| `v2-babbleon-daemon` | `main.rs:170` — the daemon binary *also* acts as its own admin client (`babbleon-daemon status`), on top of owning the `UnixListener` in `socket.rs` |

The important observation is not "few callers" — it is that **every
current transport caller is itself a Linux-welded binary or crate that
the mobile fork does not reuse**: the fork has no `/bin/sh` launcher, no
Python shim, and its "daemon" is an Android service reached over a
different IPC.  The fork reuses the request/response *vocabulary* only —
`Request`, `Response`, `UnlockSecret`, `Error` — never `round_trip`.
That is the same shape as the preprocessor reaching only into the
scramble engine, and it is why the wire layer is safe to share while the
transport stays behind.

## Recommended shape (when the mobile fork actually needs it)

Do **not** carve pre-emptively — unlike the scramble carve, nothing is
blocked today (the mobile fork does not exist yet, and the transport is
already a two-module minority).  When the fork lands, the lowest-churn
move that matches the scramble/linux precedent is:

1. Carve `protocol.rs` + `errors.rs` + `unlock_secret.rs` into
   `v2-babbleon-protocol` (`babbleon_protocol_v2`), `forbid(unsafe_code)`,
   no OS deps — just `serde_json` for the `Value` parser.
2. Leave `client.rs` + `socket_path.rs` in
   `v2-babbleon-daemon-protocol`, which becomes the **Linux transport**
   over `v2-babbleon-protocol` (re-exporting the wire types so today's
   `daemon_protocol_v2::Request` call sites keep resolving — zero churn,
   exactly as `v2-babbleon-core` now re-exports scramble + linux).
3. The mobile fork depends on `v2-babbleon-protocol` directly and
   provides its own transport module (binder/AIDL round-trip + its own
   socket/endpoint discovery).

### Alternative: a `transport` cargo feature

If a whole extra crate feels heavy for two modules, gate `client` +
`socket_path` behind a default-on `transport` feature (which pulls the
`std::os::unix` surface) and let the mobile fork depend with
`default-features = false`.  Cheaper to land, but a feature flag is a
weaker boundary than a crate split — a stray `--all-features` build on a
mobile target would still try to compile `UnixStream`.  The crate split
is the cleaner match to what the scramble/linux carve established, so
prefer it unless the fork's timeline demands the quick version.

## Open question for the operator

**What IPC does the Android fork's untrusted tier actually use to reach
the mapping service?**  The answer decides whether the mobile transport
is "a `LocalSocket` with a different path" (in which case even
`socket_path.rs` is nearly reusable behind a path trait) or "binder/AIDL"
(a wholly different `round_trip` with a generated stub).  Until that is
decided, only the audit above is actionable; the carve itself waits on
the fork existing.  Filed rather than executed, per the scramble-carve
precedent of not creating product-shape crates blind.
