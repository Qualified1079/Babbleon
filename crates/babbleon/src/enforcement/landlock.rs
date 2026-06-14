//! Landlock LSM self-sandbox for the untrusted tier.
//!
//! Restricts filesystem access to an explicit allowlist.  No boot flag
//! required; requires kernel 5.13+.  If the kernel lacks Landlock support
//! the call succeeds with a warning — the mount-NS boundary is the primary
//! defense; Landlock is defense-in-depth.

#![cfg(target_os = "linux")]

use crate::errors::{BabbleonError, Result};
use landlock::{
    path_beneath_rules, Access, AccessFs, ABI, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};
use std::path::{Path, PathBuf};

pub struct LandlockConfig {
    pub read_only_paths: Vec<PathBuf>,
    pub read_write_paths: Vec<PathBuf>,
}

/// Apply a Landlock sandbox to the current process.  Call from the
/// untrusted-tier child after exec, before payload code runs.
pub fn apply_sandbox(cfg: &LandlockConfig) -> Result<()> {
    let abi = ABI::V3;
    let access_all = AccessFs::from_all(abi);
    let access_ro = AccessFs::from_read(abi);

    let ro_str: Vec<&Path> = cfg.read_only_paths.iter().map(PathBuf::as_path).collect();
    let rw_str: Vec<&Path> = cfg.read_write_paths.iter().map(PathBuf::as_path).collect();

    let status = Ruleset::default()
        .handle_access(access_all)
        .map_err(|e| BabbleonError::Enforcement(format!("landlock handle_access: {e}")))?
        .create()
        .map_err(|e| BabbleonError::Enforcement(format!("landlock create: {e}")))?
        .add_rules(path_beneath_rules(&ro_str, access_ro))
        .map_err(|e| BabbleonError::Enforcement(format!("landlock add_rules(ro): {e}")))?
        .add_rules(path_beneath_rules(&rw_str, access_all))
        .map_err(|e| BabbleonError::Enforcement(format!("landlock add_rules(rw): {e}")))?
        .restrict_self()
        .map_err(|e| BabbleonError::Enforcement(format!("landlock restrict_self: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("Landlock sandbox fully enforced (ABI V3)");
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::warn!("Landlock partially enforced (kernel older than 5.19)");
        }
        RulesetStatus::NotEnforced => {
            tracing::warn!("Landlock not enforced — kernel <5.13; mount-NS boundary active");
        }
    }
    Ok(())
}

/// Minimal default sandbox: RO access to scrambled view, /usr, /lib*, /etc;
/// RW only to /tmp and device nodes.
pub fn default_config(scrambled_root: &Path) -> LandlockConfig {
    LandlockConfig {
        read_only_paths: vec![
            scrambled_root.to_path_buf(),
            PathBuf::from("/usr"),
            PathBuf::from("/lib"),
            PathBuf::from("/lib64"),
            PathBuf::from("/etc"),
        ],
        read_write_paths: vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/dev/null"),
            PathBuf::from("/dev/urandom"),
            PathBuf::from("/dev/random"),
        ],
    }
}
