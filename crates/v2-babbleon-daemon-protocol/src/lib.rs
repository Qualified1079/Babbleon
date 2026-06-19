//! Babbleon v2 daemon — wire protocol and operator-side client.
//!
//! # What this defeats
//!
//! The daemon's full crate (`v2-babbleon-daemon`) contains the per-host
//! secret, the materialised wrapper layer, and the serve loop.  Linking
//! that whole surface into every daemon *peer* (the launcher, the user
//! CLI) inflates each peer's audit surface — even if the linker drops
//! the unused symbols, every reviewer has to convince themselves the
//! linker did.  That is the audit-cost tax Phase 2 declared on item 3
//! of the open list.
//!
//! This crate is the carve-out.  It contains only:
//!
//! - the wire format ([`Request`], [`Response`], [`ErrorKind`],
//!   [`MAX_REQUEST_BYTES`]);
//! - the client-side one-shot round-trip ([`round_trip`]);
//! - the daemon's canonical socket path ([`default_socket_path`]).
//!
//! No state.  No secret.  No serve loop.  No materialisation.  No
//! [`v2-babbleon-core`] dependency.  A peer linking this crate adopts
//! only the parser, the wire types, and a 70-line stdlib `UnixStream`
//! wrapper.
//!
//! # Mechanism
//!
//! The wire format is one JSON object per line, hand-parsed via
//! `serde_json::Value` against a documented schema (no
//! `#[derive(Deserialize)]` on operator-influenceable surface; see
//! security-baseline rule 11).  Size-capped at [`MAX_REQUEST_BYTES`]
//! to bound parser allocation under an adversarial peer.
//!
//! # Threat model boundaries
//!
//! - **Defeats**: audit-surface inflation in daemon peers
//!   (launcher, user CLI), untrusted-deserializer gadgets,
//!   oversize-request denial-of-service, schema-mismatch
//!   confused-deputy.
//! - **Does NOT defeat**: a compromise of the daemon itself, or of
//!   a peer that holds the right uid/gid to connect.  Caller
//!   authentication (`SO_PEERCRED`, peer-uid check) lives in
//!   `v2-babbleon-daemon::socket`; this crate assumes a valid peer.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

pub mod client;
pub mod errors;
pub mod protocol;
pub mod socket_path;

pub use client::round_trip;
pub use errors::{Error, Result};
pub use protocol::{ErrorKind, Request, Response, MAX_REQUEST_BYTES};
pub use socket_path::default_socket_path;
