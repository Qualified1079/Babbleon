//! Babbleon v2 daemon — library surface.
//!
//! # What this defeats
//!
//! The daemon is the only process on the host that holds the
//! per-host secret in memory.  Everything that derives from the
//! secret — per-epoch mappings, wrapper-padding bytes, audit-chain
//! signing keys — happens here.  The launcher, the CLI, and the
//! PAM module each consume **secret-free artefacts** (the activated
//! table, the wrappers, the vault state) so a compromise of any
//! one of them yields no key material.
//!
//! Without this compartmentalization, the cap-holding launcher
//! would need to load the vault and derive keys, and a bug in any
//! single capability-holding binary would expose the host secret.
//!
//! # Mechanism
//!
//! The daemon runs as a dedicated UID (`babbleon-daemon`), with no
//! capabilities, seccomp-confined to the syscall set it needs.
//! It exposes one Unix socket at `/run/babbleon/daemon.sock`:
//!
//! 1. `init` — write a fresh vault.  Called once per host by the
//!    operator via `babbleon init`.
//! 2. `unlock` — load the per-host secret from the sealed vault
//!    into `mlock`'d memory.  Called per session by the operator
//!    via `babbleon unlock`.
//! 3. `request-activated-table` — handed off to a forked-launcher
//!    invocation: the daemon builds a per-epoch `EpochMapping`,
//!    writes the wrappers (if not cached), produces the JSONL
//!    activated-table, writes it to a pipe whose read end is the
//!    launcher's `--activated-table-fd` argument.
//! 4. `rotate-mapping` — bump the epoch and rebuild.
//! 5. `status` — read-only state report (epoch, tracked count,
//!    last-rotation time).
//!
//! # Threat model boundaries
//!
//! - Defeats: secret leakage from the cap-holding launcher,
//!   secret leakage from the user-facing CLI, secret leakage from
//!   the PAM module.
//! - Defeats: blast-radius escalation from a single-binary
//!   compromise (the daemon is the only process with the secret;
//!   the rest cannot derive keys).
//! - Does NOT defeat: a compromise of the daemon itself.
//!   Compensating control: minimal syscall surface (seccomp),
//!   no network, no shell access (no execve into shells; we
//!   `execve` only the launcher binary by absolute path).
//! - Does NOT defeat: an attacker who already has root on the
//!   host.  Out of scope per the threat model.
//!
//! # Phase status
//!
//! Phase 2: this crate ships a CRATE SKELETON.  The CLI surface
//! and the lifecycle docstrings are filed; the actual socket loop,
//! vault load, and request handlers are deliberately stubbed so
//! the operator can review the design before privileged code lands.
//!
//! See `crates/v2-babbleon-daemon/src/cli.rs` for the current CLI
//! surface and `HANDOFF.md` "Phase-2 next steps" for the remaining
//! work.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod cli;
pub mod errors;

pub use cli::Args;
pub use errors::{Error, Result};
