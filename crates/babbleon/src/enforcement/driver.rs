//! The driver contract: how a tier-presenting backend exposes the real and
//! scrambled views of `$PATH`.
//!
//! # What this defeats
//!
//! Every driver method maps to a step in the attacker's discovery loop:
//!
//!   - `mount_real_view` is the trusted-tier entrypoint.  Legitimate
//!     sessions (PAM, root daemons) call it; the view it returns is what
//!     the human or admin script actually executes against.
//!   - `mount_scrambled_view` is the untrusted-tier entrypoint.  Code that
//!     was compromised, or that came in over the network, only ever sees
//!     this view: tools are renamed, honey names are sprinkled in, and
//!     credential dirs are gated.  An attacker enumerating `$PATH` learns
//!     nothing about which real tools are installed.
//!   - `teardown` reverses both — required because mount-NS leakage
//!     between sessions is itself an information-disclosure channel.
//!
//! Implementations: `SimulatedDriver` (no-op for tests / demos) and
//! `LinuxNamespaceDriver` (the production backend).

use crate::mapping::MappingTable;
use crate::Result;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub tier: String,
    pub visible: HashMap<String, PathBuf>,
    pub notes: Vec<String>,
}

pub trait EnforcementDriver: Send + Sync {
    fn name(&self) -> &'static str;

    /// Present the trusted (real-name) view of tracked tools.
    ///
    /// Called from the trusted-tier session; the view it returns lets the
    /// caller invoke tools by their canonical names (`curl`, `ssh`, ...).
    fn mount_real_view(
        &mut self,
        real_root: &std::path::Path,
        tracked: &[String],
    ) -> Result<EnforcementResult>;

    /// Present the untrusted (scrambled-name) view inside a fresh mount NS.
    ///
    /// Called from the untrusted-tier session; the view it returns hides
    /// every canonical tool name behind its scrambled alias, interleaves
    /// honey tripwires, and gates credential directories.
    fn mount_scrambled_view(
        &mut self,
        real_root: &std::path::Path,
        mapping: &MappingTable,
    ) -> Result<EnforcementResult>;

    fn teardown(&mut self) -> Result<()> {
        Ok(())
    }
}
