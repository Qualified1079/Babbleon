//! Mapping-aware backup / restore.
//!
//! A backup snapshot of the host filesystem captures the *current* epoch's
//! scrambled binary names — but the mapping is the only thing that makes
//! those names mean anything.  A restore against a different vault epoch
//! would resurrect dead names with no inverse table.
//!
//! `BackupBundle` versions the mapping alongside the snapshot:
//!   - `epoch` — vault epoch at backup time
//!   - `host_secret_hex` — needed to rebuild the mapping deterministically
//!   - `tracked` — manifest at backup time (manifest can drift over time)
//!   - `wordlist_sha256` — pin to the wordlist that produced the names
//!
//! ## Restore policy (`RestorePolicy`)
//!
//! Restoring an old snapshot is always against the CURRENT vault.  The
//! caller picks one of:
//!
//! - `RejectMismatch` (default) — refuse unless the bundle's
//!   `epoch + host_secret + wordlist` triple exactly matches the
//!   current vault.  Safest; demands the operator restore an aligned
//!   pair.
//! - `RewrapToCurrent` — translate every scrambled name through the
//!   OLD mapping back to real names, then forward through the CURRENT
//!   mapping.  Cost: O(N) renames on disk.  Requires the old
//!   host_secret in the bundle (which we have).
//! - `HonorSnapshotUntilNextRotation` — leave the snapshot's scrambled
//!   names in place; the daemon honours them by also activating the
//!   bundle's mapping for one rotation cycle.  Operator chooses this
//!   when they're restoring a snapshot temporarily (forensics, audit)
//!   and don't want to disturb the host filesystem.  Risky because
//!   the audit log will see both mappings active simultaneously —
//!   explicit operator confirmation required.
//!
//! `BackupBundle::resolve_against` returns a `ResolvedRestore` value
//! that names which of these the caller intends and which O(N)
//! renames are required.  Wiring this through the CLI's `restore`
//! command is filed in `TODO.md` (the bundle structure is ready; the
//! CLI command is not yet).

use crate::errors::{BabbleonError, Result};
use crate::mapping::Mapper;
use crate::session::Session;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version for the bundle header.  Bump only on breaking changes.
pub const BUNDLE_SCHEMA: u32 = 1;

/// Caller's explicit choice for what to do when bundle and vault
/// disagree on epoch / host_secret.  See module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RestorePolicy {
    /// Refuse the restore unless bundle and vault align exactly.
    #[default]
    RejectMismatch,
    /// Translate every name through the bundle's mapping back to the
    /// real name, then forward through the current vault's mapping.
    /// Cost is O(N) renames on the filesystem.
    RewrapToCurrent,
    /// Keep the bundle's scrambled names in place; daemon honours
    /// both mappings for one rotation cycle.  Risky; operator must
    /// confirm.
    HonorSnapshotUntilNextRotation,
}

/// What `resolve_against` decided.  Renames is `Vec<(from, to)>`
/// where `from` is a scrambled name on disk and `to` is the new
/// scrambled name to land at.  Empty when no rename is required.
#[derive(Debug, Clone)]
pub struct ResolvedRestore {
    pub policy: RestorePolicy,
    pub renames: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupBundle {
    pub schema: u32,
    pub epoch: u64,
    pub host_secret_hex: String,
    pub tracked: Vec<String>,
    pub wordlist_sha256: String,
    pub created_at: String,
}

impl BackupBundle {
    /// Construct a bundle from an unlocked session.
    pub fn from_session(session: &Session, wordlist_bytes: &[u8]) -> Self {
        Self {
            schema: BUNDLE_SCHEMA,
            epoch: session.payload.epoch,
            host_secret_hex: session.payload.host_secret_hex.clone(),
            tracked: session.tracked.clone(),
            wordlist_sha256: sha256_hex(wordlist_bytes),
            created_at: current_ts(),
        }
    }

    /// Verify this bundle can be restored against the given session +
    /// wordlist.  Returns Ok(()) if compatible, error otherwise.
    pub fn check_compatible(&self, session: &Session, wordlist_bytes: &[u8]) -> Result<()> {
        if self.schema != BUNDLE_SCHEMA {
            return Err(BabbleonError::Vault(format!(
                "bundle schema {} != supported {BUNDLE_SCHEMA}",
                self.schema
            )));
        }
        if self.epoch != session.payload.epoch {
            return Err(BabbleonError::Vault(format!(
                "epoch mismatch: bundle={}, vault={}; use --rewrap to translate",
                self.epoch, session.payload.epoch
            )));
        }
        if self.host_secret_hex != session.payload.host_secret_hex {
            return Err(BabbleonError::Vault(
                "host_secret mismatch: bundle was made on a different host".into(),
            ));
        }
        let current_hash = sha256_hex(wordlist_bytes);
        if self.wordlist_sha256 != current_hash {
            return Err(BabbleonError::Vault(format!(
                "wordlist hash mismatch: bundle={}, current={}",
                &self.wordlist_sha256[..16],
                &current_hash[..16]
            )));
        }
        Ok(())
    }

    /// Rebuild the mapping the bundle was created with, using the embedded
    /// wordlist (assumed to match `wordlist_sha256`).  Used by `--rewrap`
    /// to translate names from old epoch to new epoch.
    pub fn rebuild_mapping(&self) -> Result<crate::mapping::MappingTable> {
        let secret = hex::decode(&self.host_secret_hex)
            .map_err(|e| BabbleonError::Vault(format!("host_secret_hex decode: {e}")))?;
        let mapper = Mapper::new(&secret);
        Ok(mapper.build_table(&self.tracked, self.epoch))
    }

    /// Apply `policy` to decide what restoring `self` against `current`
    /// means.  Returns the rename plan; the caller is responsible for
    /// executing the renames on disk and updating the audit log.
    pub fn resolve_against(
        &self,
        current: &Session,
        wordlist_bytes: &[u8],
        policy: RestorePolicy,
    ) -> Result<ResolvedRestore> {
        if policy == RestorePolicy::RejectMismatch {
            self.check_compatible(current, wordlist_bytes)?;
            return Ok(ResolvedRestore {
                policy,
                renames: Vec::new(),
            });
        }

        // For both rewrap-mode and honor-snapshot-mode we need the
        // bundle to have come from the same host (same host_secret +
        // same wordlist).  Only the epoch is allowed to drift.
        if self.schema != BUNDLE_SCHEMA {
            return Err(BabbleonError::Vault(format!(
                "bundle schema {} != supported {BUNDLE_SCHEMA}",
                self.schema
            )));
        }
        if self.host_secret_hex != current.payload.host_secret_hex {
            return Err(BabbleonError::Vault(
                "host_secret mismatch: cross-host restore is not supported".into(),
            ));
        }
        let current_hash = sha256_hex(wordlist_bytes);
        if self.wordlist_sha256 != current_hash {
            return Err(BabbleonError::Vault(format!(
                "wordlist hash mismatch: bundle={}, current={}",
                &self.wordlist_sha256[..16],
                &current_hash[..16]
            )));
        }

        match policy {
            RestorePolicy::RejectMismatch => unreachable!("handled above"),
            RestorePolicy::HonorSnapshotUntilNextRotation => {
                // No filesystem renames; the daemon side activates the
                // bundle's mapping table for one rotation cycle.
                Ok(ResolvedRestore {
                    policy,
                    renames: Vec::new(),
                })
            }
            RestorePolicy::RewrapToCurrent => {
                let old_table = self.rebuild_mapping()?;
                let mut renames = Vec::with_capacity(self.tracked.len());
                for real in &self.tracked {
                    let from = match old_table.scramble(real) {
                        Some(s) => s.to_string(),
                        None => continue,
                    };
                    let to = match current.mapping.scramble(real) {
                        Some(s) => s.to_string(),
                        None => continue,
                    };
                    if from != to {
                        renames.push((from, to));
                    }
                }
                Ok(ResolvedRestore { policy, renames })
            }
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn current_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("epoch:{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(tmp: &std::path::Path) -> Session {
        Session::initialize("pw", None, Some(tmp.join("vault.age"))).unwrap()
    }

    #[test]
    fn bundle_roundtrips_through_json() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        let wordlist = b"alpha\nbeta\ngamma\n";
        let bundle = BackupBundle::from_session(&session, wordlist);
        let json = serde_json::to_string(&bundle).unwrap();
        let back: BackupBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(back.epoch, bundle.epoch);
        assert_eq!(back.host_secret_hex, bundle.host_secret_hex);
    }

    #[test]
    fn same_epoch_is_compatible() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        let wordlist = b"alpha\nbeta\n";
        let bundle = BackupBundle::from_session(&session, wordlist);
        bundle.check_compatible(&session, wordlist).unwrap();
    }

    #[test]
    fn wordlist_drift_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let session = make_session(tmp.path());
        let bundle = BackupBundle::from_session(&session, b"alpha\nbeta\n");
        let r = bundle.check_compatible(&session, b"alpha\nbeta\ngamma\n");
        assert!(r.is_err());
        let msg = format!("{:?}", r.unwrap_err());
        assert!(msg.contains("wordlist hash mismatch"));
    }

    #[test]
    fn reject_mismatch_policy_refuses_epoch_drift() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = make_session(tmp.path());
        let wordlist = b"alpha\nbeta\n";
        let bundle = BackupBundle::from_session(&session, wordlist);
        // Rotate the vault so the current session is at epoch 1.
        session.rotate("pw").unwrap();
        let r = bundle.resolve_against(&session, wordlist, RestorePolicy::RejectMismatch);
        assert!(r.is_err(), "RejectMismatch must refuse epoch drift");
    }

    #[test]
    fn rewrap_policy_produces_renames_for_drifted_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = make_session(tmp.path());
        let wordlist =
            include_bytes!("../wordlist/words.txt").as_slice();
        let bundle = BackupBundle::from_session(&session, wordlist);
        session.rotate("pw").unwrap();
        let r = bundle
            .resolve_against(&session, wordlist, RestorePolicy::RewrapToCurrent)
            .unwrap();
        assert_eq!(r.policy, RestorePolicy::RewrapToCurrent);
        // The default tracked list moves every name across the epoch
        // (proptest already proved this; we just need at least one
        // rename here).
        assert!(
            !r.renames.is_empty(),
            "rewrap across rotation must produce renames"
        );
        // No identity-rename ever lands in the list (would be a bug).
        for (from, to) in &r.renames {
            assert_ne!(from, to);
        }
    }

    #[test]
    fn honor_snapshot_policy_does_no_renames() {
        let tmp = tempfile::tempdir().unwrap();
        let mut session = make_session(tmp.path());
        let wordlist = include_bytes!("../wordlist/words.txt").as_slice();
        let bundle = BackupBundle::from_session(&session, wordlist);
        session.rotate("pw").unwrap();
        let r = bundle
            .resolve_against(
                &session,
                wordlist,
                RestorePolicy::HonorSnapshotUntilNextRotation,
            )
            .unwrap();
        assert!(r.renames.is_empty());
        assert_eq!(r.policy, RestorePolicy::HonorSnapshotUntilNextRotation);
    }

    #[test]
    fn cross_host_restore_is_refused_even_in_rewrap() {
        // Two vaults at different host_secrets — bundle from one
        // cannot rewrap into the other.
        let tmp = tempfile::tempdir().unwrap();
        let s_origin = Session::initialize(
            "pw",
            Some(vec!["curl".into()]),
            Some(tmp.path().join("origin.vault")),
        )
        .unwrap();
        let s_target = Session::initialize(
            "pw",
            Some(vec!["curl".into()]),
            Some(tmp.path().join("target.vault")),
        )
        .unwrap();
        let wordlist = include_bytes!("../wordlist/words.txt").as_slice();
        let bundle = BackupBundle::from_session(&s_origin, wordlist);
        let r = bundle.resolve_against(&s_target, wordlist, RestorePolicy::RewrapToCurrent);
        assert!(r.is_err(), "cross-host rewrap must be refused");
    }
}
