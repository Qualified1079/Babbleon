//! High-level orchestration: init / unlock / rotate.

use crate::errors::{BabbleonError, Result};
use crate::events::{Event, EventBus};
use crate::manifest::DEFAULT_TRACKED;
use crate::mapping::{Mapper, MappingTable};
use crate::storage::{ensure_dirs, vault_path};
use crate::vault::attempts::{now_secs, AttemptTracker};
use crate::vault::{SoftBackend, Vault, VaultPayload};
use std::path::{Path, PathBuf};

pub struct Session {
    pub payload: VaultPayload,
    pub mapping: MappingTable,
    pub tracked: Vec<String>,
    pub bus: EventBus,
    vault_file: PathBuf,
}

impl Session {
    pub fn initialize(
        password: &str,
        tracked: Option<Vec<String>>,
        vault_file: Option<PathBuf>,
    ) -> Result<Self> {
        ensure_dirs()?;
        let tracked = tracked.unwrap_or_else(default_tracked);
        let path = vault_file.unwrap_or_else(vault_path);
        if path.exists() {
            return Err(BabbleonError::Vault(format!(
                "vault already exists at {}",
                path.display()
            )));
        }

        let payload = VaultPayload::new(0, vec![]);
        let secret = payload.host_secret()?;
        let table = Mapper::new(&secret).build_table(&tracked, 0);
        let payload = payload.with_honey(table.honey_names.clone());

        let vault = Vault::new(SoftBackend::default());
        let sealed = vault.seal(&payload, Some(password))?;
        std::fs::write(&path, &sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        // Fresh vault — drop any leftover attempt counter from a prior
        // vault at the same path.  (Cheap; no-op when none exists.)
        let _ = AttemptTracker::for_vault(&path).record_success();

        let bus = EventBus::new();
        bus.emit(Event::VaultSealed {
            epoch: 0,
            backend: "soft".into(),
        });

        Ok(Self {
            payload,
            mapping: table,
            tracked,
            bus,
            vault_file: path,
        })
    }

    pub fn unlock(
        password: &str,
        tracked: Option<Vec<String>>,
        vault_file: Option<PathBuf>,
    ) -> Result<Self> {
        let tracked = tracked.unwrap_or_else(default_tracked);
        let path = vault_file.unwrap_or_else(vault_path);
        if !path.exists() {
            return Err(BabbleonError::VaultNotFound(path.display().to_string()));
        }

        let bus = EventBus::new();

        // Rate-limit check happens *before* the (expensive, Argon2id)
        // KDF call — a brute-force attacker shouldn't get to burn CPU
        // on attempts the policy already refused.
        let mut tracker = AttemptTracker::for_vault(&path);
        tracker.check_allowed(now_secs())?;

        let vault = Vault::new(SoftBackend::default());
        let data = std::fs::read(&path)?;
        let payload = match vault.unseal(&data, Some(password)) {
            Ok(p) => p,
            Err(e) => {
                bus.emit(Event::UnlockFailed {
                    epoch: 0,
                    backend: "soft".into(),
                });
                let _ = tracker.record_failure(now_secs());
                return Err(e);
            }
        };
        // Success — reset the counter so a legitimate-typo'd run doesn't
        // accumulate failures forever.
        let _ = tracker.record_success();
        let secret = payload.host_secret()?;
        let table = Mapper::new(&secret).build_table(&tracked, payload.epoch);

        Ok(Self {
            payload,
            mapping: table,
            tracked,
            bus,
            vault_file: path,
        })
    }

    pub fn rotate(&mut self, password: &str) -> Result<u64> {
        let old = self.payload.epoch;
        let new = old + 1;
        let secret = self.payload.host_secret()?;
        let table = Mapper::new(&secret).build_table(&self.tracked, new);
        let payload = self
            .payload
            .clone()
            .with_epoch(new)
            .with_honey(table.honey_names.clone());

        let vault = Vault::new(SoftBackend::default());
        let sealed = vault.seal(&payload, Some(password))?;
        std::fs::write(&self.vault_file, &sealed)?;

        self.payload = payload;
        self.mapping = table;
        self.bus.emit(Event::RotationComplete {
            old_epoch: old,
            new_epoch: new,
        });
        Ok(new)
    }

    pub fn vault_file(&self) -> &Path {
        &self.vault_file
    }
}

fn default_tracked() -> Vec<String> {
    DEFAULT_TRACKED.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_then_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let tracked: Vec<String> = ["curl", "ssh"].iter().map(|s| s.to_string()).collect();
        let s1 = Session::initialize("pw", Some(tracked.clone()), Some(vault.clone())).unwrap();
        let s2 = Session::unlock("pw", Some(tracked), Some(vault)).unwrap();
        assert_eq!(s1.mapping.scramble("curl"), s2.mapping.scramble("curl"));
        assert_eq!(s1.payload.epoch, 0);
        assert_eq!(s2.payload.epoch, 0);
    }

    #[test]
    fn locked_out_vault_refuses_correct_password() {
        // The full "burn through the backoff schedule with wrong
        // passwords" path needs the wall clock to advance through each
        // window, which a unit test should not depend on.  Instead,
        // seed the tracker directly at the lockout threshold and verify
        // Session::unlock refuses even the right password.
        use crate::vault::attempts::{AttemptTracker, LOCKOUT_AT};
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let tracked: Vec<String> = vec!["curl".into()];
        Session::initialize("right-pw", Some(tracked.clone()), Some(vault.clone())).unwrap();

        // Push the tracker to LOCKOUT_AT failures.
        let mut tracker = AttemptTracker::for_vault(&vault);
        for i in 0..LOCKOUT_AT {
            tracker.record_failure(i as u64).unwrap();
        }
        assert_eq!(tracker.failed_attempts(), LOCKOUT_AT);

        match Session::unlock("right-pw", Some(tracked.clone()), Some(vault.clone())) {
            Err(BabbleonError::UnlockLockedOut { attempts }) => {
                assert!(attempts >= LOCKOUT_AT);
            }
            Err(other) => panic!("expected UnlockLockedOut, got {other:?}"),
            Ok(_) => panic!("locked-out vault accepted a password"),
        }
    }

    #[test]
    fn backoff_window_refuses_unlock_even_with_right_password() {
        // After INSTA_RETRIES + 1 failures the tracker enforces a
        // backoff window; the unlock path must refuse with
        // `UnlockBackoff` before invoking the (expensive) Argon2id KDF.
        use crate::vault::attempts::{now_secs, AttemptTracker, INSTA_RETRIES};
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let tracked: Vec<String> = vec!["curl".into()];
        Session::initialize("right-pw", Some(tracked.clone()), Some(vault.clone())).unwrap();

        let mut tracker = AttemptTracker::for_vault(&vault);
        for _ in 0..=INSTA_RETRIES {
            tracker.record_failure(now_secs()).unwrap();
        }

        match Session::unlock("right-pw", Some(tracked), Some(vault)) {
            Err(BabbleonError::UnlockBackoff { remaining_secs }) => {
                assert!(remaining_secs > 0);
            }
            Err(other) => panic!("expected UnlockBackoff, got {other:?}"),
            Ok(_) => panic!("backoff window let an unlock through"),
        }
    }

    #[test]
    fn wrong_password_increments_attempt_counter() {
        use crate::vault::attempts::AttemptTracker;
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let tracked: Vec<String> = vec!["curl".into()];
        Session::initialize("right-pw", Some(tracked.clone()), Some(vault.clone())).unwrap();

        // One wrong-password unlock bumps the counter from 0 to 1.
        let r = Session::unlock("WRONG", Some(tracked.clone()), Some(vault.clone()));
        assert!(matches!(r, Err(BabbleonError::WrongPassphrase)));
        assert_eq!(AttemptTracker::for_vault(&vault).failed_attempts(), 1);
    }

    #[test]
    fn successful_unlock_clears_failure_count() {
        use crate::vault::attempts::AttemptTracker;
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let tracked: Vec<String> = vec!["curl".into()];
        Session::initialize("right-pw", Some(tracked.clone()), Some(vault.clone())).unwrap();

        // Seed the tracker at 2 failures with old timestamps so the
        // backoff window has fully elapsed and the next attempt can
        // actually call the KDF.
        let mut tracker = AttemptTracker::for_vault(&vault);
        tracker.record_failure(1).unwrap();
        tracker.record_failure(2).unwrap();
        assert_eq!(tracker.failed_attempts(), 2);

        Session::unlock("right-pw", Some(tracked.clone()), Some(vault.clone()))
            .expect("right password must succeed");
        assert_eq!(AttemptTracker::for_vault(&vault).failed_attempts(), 0);
    }

    #[test]
    fn rotate_bumps_epoch_and_remaps() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.age");
        let tracked: Vec<String> = vec!["curl".to_string()];
        let mut s = Session::initialize("pw", Some(tracked.clone()), Some(vault.clone())).unwrap();
        let old = s.mapping.scramble("curl").unwrap().to_string();
        s.rotate("pw").unwrap();
        let new = s.mapping.scramble("curl").unwrap();
        assert_eq!(s.payload.epoch, 1);
        assert_ne!(old, new);

        // persisted
        let s2 = Session::unlock("pw", Some(tracked), Some(vault)).unwrap();
        assert_eq!(s2.payload.epoch, 1);
    }
}
