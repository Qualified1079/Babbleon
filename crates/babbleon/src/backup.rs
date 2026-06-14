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
//! Restoring is allowed only when:
//!   - the current vault's epoch + host_secret + wordlist match, OR
//!   - the operator passes `--rewrap` and provides the new vault, in which
//!     case backup names are translated back through the OLD mapping and
//!     forward through the NEW mapping (cost: O(N) renames).

use crate::errors::{BabbleonError, Result};
use crate::mapping::Mapper;
use crate::session::Session;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version for the bundle header.  Bump only on breaking changes.
pub const BUNDLE_SCHEMA: u32 = 1;

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
}
