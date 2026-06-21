//! `babbleon-python` — phase-3 runtime entry point for layer-3 Python.
//!
//! # What this defeats
//!
//! Phase-3 layer-3 produces scrambled `.py` files where every
//! whitespace marker has been replaced by a per-epoch wordlist
//! compound — no visible newlines, no visible indentation, no block
//! boundaries.  An attacker reading the file by `read()` sees a wall
//! of text and cannot pattern-match structural templates against it.
//!
//! For the operator to actually *run* the scrambled file, the bytes
//! must be unscrambled before the Python interpreter sees them, and
//! the unscrambled bytes must NEVER touch disk (otherwise a snapshot
//! attack between unscramble and exec recovers the plaintext).  This
//! shim is the bridge: it reads a scrambled `.py` file, fetches the
//! daemon's current per-epoch whitespace compounds, unscrambles
//! in-memory, and pipes the result into a child `python3 -` via
//! `pipe(2)`.  No disk write.
//!
//! # Trust placement
//!
//! Per `docs/v2/structure-scrambling.md` §"Trust placement", the
//! preprocessor runs only in the trusted tier — never inside an
//! untrusted-tier process.  The shim runs in the same tier as
//! `babbleon scramble` / `babbleon unscramble`: it holds per-epoch
//! compounds in memory; it does NOT hold the per-host secret.
//!
//! Trust-tier verification (e.g. mount-namespace inode check, peer
//! credential gate on the daemon socket) is the same as the user
//! CLI's; this crate inherits whatever the daemon-side gate enforces
//! on `Request::GetWhitespaceCompounds`.
//!
//! # Mechanism
//!
//! 1. **Process hardening** (`process_hardening::apply`).
//!    `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0`, `mlockall` — same triad
//!    the daemon applies before any secret-derived bytes enter
//!    memory.  Runs FIRST, before any I/O.
//! 2. **Read scrambled bytes** from the script path (argv[1]).  No
//!    daemon traffic yet; if the file does not exist the shim fails
//!    here without bothering the daemon.
//! 3. **Fetch compounds** via `Request::GetWhitespaceCompounds`
//!    round-trip against the daemon's Unix socket.
//! 4. **Unscramble** in-memory via
//!    `babbleon_preprocessor_v2::unscrambler::unscramble`.
//! 5. **Spawn `python3 -`** with stdin piped, stdout/stderr inherited
//!    so script output passes through to the operator's terminal.
//! 6. **Feed the source** to the child's stdin, close stdin so
//!    Python sees EOF.
//! 7. **Wait** and exit with the child's exit status.
//!
//! Steps 4-7 keep the unscrambled source in a `Vec<u8>` on the
//! shim's stack and on the pipe buffer; no `tmpfile`, no `/dev/shm`,
//! no `memfd_create`.
//!
//! # Security baseline
//!
//! Per `docs/v2/security-baseline.md`:
//!
//! - `#![forbid(unsafe_code)]` at the crate root.  The hardening
//!   primitives are wrapped in safe `nix` APIs; the `Command`
//!   plumbing is pure stdlib.
//! - `#![deny(missing_docs)]`.
//! - `#![warn(clippy::pedantic)]`.
//! - No `serde::Deserialize` on operator-influenceable surface
//!   (the protocol crate already enforces this on the wire).
//! - Error messages do not echo compounds.  An error path that
//!   surfaces "wordlist invalid" carries the slot index, not the
//!   compound bytes (delegated to
//!   `WhitespaceWordlist::from_compounds`'s
//!   `InvalidSuppliedCompounds` variant).
//!
//! # Out of scope for MVP (filed for follow-up)
//!
//! - **Argv splitting at `--`**: today every argv beyond the script
//!   path is forwarded to `python3` verbatim.  The dedicated
//!   separator pattern (`babbleon-python script.py -- --py-arg`) is
//!   filed for the next revision when the operator's batch
//!   experience asks for it.
//! - **Trust-tier inode gate**: today the shim trusts that the
//!   operator only installs it where the trusted tier runs.  A
//!   defense-in-depth namespace-inode check (refuse to run if
//!   `readlink(/proc/self/ns/mnt)` matches an
//!   untrusted-tier-inode list) is filed for the same gate the
//!   launcher exposes.
//! - **Child-process reaping on early exit** of the shim.  Today
//!   `child.wait()` is the only collection site; if the shim is
//!   itself signal-killed before reaching wait, the child becomes
//!   an orphan reparented to init.  Filed for a future commit
//!   alongside a teardown helper that `kill`s the child on shim
//!   panic.  SIGINT/SIGTERM/SIGHUP/SIGQUIT forwarding to the
//!   child is wired — see `signal_forwarding`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod exec_python;
pub mod pipeline;
pub mod process_hardening;
pub mod signal_forwarding;
