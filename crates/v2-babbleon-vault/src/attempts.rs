//! Per-vault unlock attempt counter with exponential backoff.
//!
//! # What this defeats
//!
//! Unrestricted offline-guessing pressure against the vault's
//! Argon2id-derived passphrase.  Without a rate limit, an attacker
//! who can invoke `babbleon unlock` repeatedly (locally, or via any
//! future remote-unlock surface) pays only the Argon2id KDF's fixed
//! per-guess cost — real, but bounded and parallelisable across
//! cores. This tracker adds a *sequential*, disk-persisted cost on
//! top: the first few mistypes are free (typo budget), then each
//! further failure doubles the wait before the next guess is even
//! attempted, and ten consecutive failures lock the vault out
//! entirely until an operator clears the sidecar file.
//!
//! Ported from v1's `crates/babbleon/src/vault/attempts.rs`
//! (unchanged policy constants and backoff shape) into the v2
//! error-type and module-doc conventions. v2 had no equivalent
//! control — filed in `docs/v2/threat-model.md` row D1 as "port
//! owed phase 1" and confirmed still missing by
//! `docs/v2/owasp-top10-audit.md` A07 — this module closes that gap.
//!
//! # Mechanism
//!
//! Sidecar file at `<vault_path>.attempts` carries two numbers:
//!
//! - `failed_attempts` (`u32`) — consecutive failures since the last
//!   success.
//! - `last_failure_ts` (`u64`) — seconds since `UNIX_EPOCH` of the
//!   last failure.
//!
//! Policy (constants below):
//!
//! - The first [`INSTA_RETRIES`] failures trigger no wait —
//!   legitimate operators mistype.
//! - After that, each failure adds an exponentially-growing window
//!   before the next attempt is accepted:
//!   `2^(n - INSTA_RETRIES)` seconds, capped at [`BACKOFF_CAP_SECS`].
//! - At [`LOCKOUT_AT`] consecutive failures the vault refuses
//!   further attempts entirely until an operator clears the sidecar
//!   file (or a future recovery flow does).
//!
//! # Threat model boundaries
//!
//! - **Defeats:** unattended repeated-guess automation against the
//!   local `babbleon unlock` entry point.
//! - **Does NOT defeat:** an attacker who can also delete or edit
//!   the sidecar file — they can also rewrite the vault ciphertext
//!   itself, so this is defence-in-depth against a *weaker* attacker
//!   than the one the vault's own encryption defends against, not a
//!   hard containment boundary.  Sidecar read/parse failures
//!   therefore default to "no attempts on record" rather than
//!   refusing outright — a corrupted sidecar must never be able to
//!   lock a legitimate operator out of their own vault.

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Failures before any backoff window kicks in.  Three accommodates
/// a reasonable typo budget (caps-lock, keyboard layout) without
/// giving a brute-force attacker free attempts forever.
pub const INSTA_RETRIES: u32 = 3;

/// Hard ceiling on consecutive failures; beyond this the vault
/// refuses further attempts until the sidecar is cleared.
pub const LOCKOUT_AT: u32 = 10;

/// Maximum backoff window between attempts.  At `LOCKOUT_AT - 1 = 9`
/// failures the raw window would be `2^(9-3) = 64s`; clamp to 60.
pub const BACKOFF_CAP_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct AttemptState {
    #[serde(default)]
    failed_attempts: u32,
    #[serde(default)]
    last_failure_ts: u64,
}

/// Wraps a sidecar attempt-counter file for a specific vault.
pub struct AttemptTracker {
    path: PathBuf,
    state: AttemptState,
}

impl AttemptTracker {
    /// Open (or create) the tracker for `vault_path`.  Sidecar file
    /// path is `<vault_path>.attempts`.
    #[must_use]
    pub fn for_vault(vault_path: &Path) -> Self {
        let path = sidecar_path(vault_path);
        let state = load(&path).unwrap_or_default();
        Self { path, state }
    }

    /// Read-only count of consecutive failures recorded on disk.
    #[must_use]
    pub fn failed_attempts(&self) -> u32 {
        self.state.failed_attempts
    }

    /// Refuse the unlock attempt if the vault is either locked out
    /// or still inside an exponential-backoff window.  Otherwise
    /// returns `Ok(())`.
    ///
    /// # Errors
    ///
    /// - [`Error::UnlockLockedOut`] at or beyond [`LOCKOUT_AT`]
    ///   consecutive failures.
    /// - [`Error::UnlockBackoff`] inside the current backoff window.
    pub fn check_allowed(&self, now: u64) -> Result<()> {
        if self.state.failed_attempts >= LOCKOUT_AT {
            return Err(Error::UnlockLockedOut {
                attempts: self.state.failed_attempts,
            });
        }
        let window = backoff_window_secs(self.state.failed_attempts);
        if window == 0 {
            return Ok(());
        }
        // Time-going-backwards (clock skew, NTP step) must not
        // extend the window past sane bounds: cap `elapsed` at 0
        // via saturating_sub so we never refuse forever on a bad
        // clock.
        let elapsed = now.saturating_sub(self.state.last_failure_ts);
        if elapsed >= window {
            return Ok(());
        }
        Err(Error::UnlockBackoff {
            remaining_secs: window - elapsed,
        })
    }

    /// Mark this attempt as failed.  Increments the counter and
    /// writes the sidecar file.  Sidecar write failures are
    /// downgraded to a warning trace — refusing the attempt because
    /// the rate-limit file itself couldn't be written would lock the
    /// operator out over an unrelated filesystem problem.
    pub fn record_failure(&mut self, now: u64) {
        self.state.failed_attempts = self.state.failed_attempts.saturating_add(1);
        self.state.last_failure_ts = now;
        if let Err(e) = save(&self.path, &self.state) {
            tracing::warn!(
                "attempt tracker: failed to persist failure count: {e} \
                 (path={})",
                self.path.display()
            );
        }
    }

    /// Mark this attempt as successful.  Resets the counter and
    /// removes the sidecar file (or, if removal fails, writes a
    /// zeroed state so the next attempt still sees a clean counter).
    pub fn record_success(&mut self) {
        self.state = AttemptState::default();
        if self.path.exists() && std::fs::remove_file(&self.path).is_err() {
            let _ = save(&self.path, &self.state);
        }
    }
}

fn sidecar_path(vault_path: &Path) -> PathBuf {
    let mut name = vault_path.file_name().unwrap_or_default().to_os_string();
    name.push(".attempts");
    vault_path.with_file_name(name)
}

fn backoff_window_secs(failed_attempts: u32) -> u64 {
    if failed_attempts <= INSTA_RETRIES {
        return 0;
    }
    let shift = u64::from(failed_attempts - INSTA_RETRIES);
    // 2^shift seconds, with a guard against overflow at large shifts
    // (already capped below, but keep the intermediate safe too).
    let raw = 1u64
        .checked_shl(u32::try_from(shift.min(32)).unwrap_or(32))
        .unwrap_or(u64::MAX);
    raw.min(BACKOFF_CAP_SECS)
}

fn load(path: &Path) -> std::result::Result<AttemptState, ()> {
    let bytes = std::fs::read(path).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn save(path: &Path, state: &AttemptState) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(state).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Current wall-clock seconds since `UNIX_EPOCH`, or 0 if the clock
/// is before the epoch (only possible on a machine with a grossly
/// broken RTC).
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        sidecar_path, AttemptTracker, BACKOFF_CAP_SECS, INSTA_RETRIES, LOCKOUT_AT,
    };
    use crate::errors::Error;
    use std::path::{Path, PathBuf};

    fn vault_in(dir: &Path) -> PathBuf {
        dir.join("vault.age")
    }

    #[test]
    fn fresh_vault_allows_attempt() {
        let dir = tempfile::tempdir().unwrap();
        let t = AttemptTracker::for_vault(&vault_in(dir.path()));
        assert_eq!(t.failed_attempts(), 0);
        t.check_allowed(100).unwrap();
    }

    #[test]
    fn first_three_failures_skip_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        for i in 1..=INSTA_RETRIES {
            t.record_failure(1000 + u64::from(i));
            let again = AttemptTracker::for_vault(&path);
            assert_eq!(again.failed_attempts(), i);
            again
                .check_allowed(1000 + u64::from(i))
                .expect("inside INSTA_RETRIES must skip backoff");
        }
    }

    #[test]
    fn fourth_failure_enforces_backoff_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        for i in 1..=INSTA_RETRIES + 1 {
            t.record_failure(1000 + u64::from(i));
        }
        // 4 failures -> window 2^(4-3) = 2s.
        let last_ts = 1000 + u64::from(INSTA_RETRIES + 1);
        let err = AttemptTracker::for_vault(&path)
            .check_allowed(last_ts + 1)
            .expect_err("must refuse within window");
        match err {
            Error::UnlockBackoff { remaining_secs } => {
                assert!(remaining_secs > 0, "expected positive remaining");
                assert!(remaining_secs <= 2, "expected window <= 2s");
            }
            other => panic!("expected UnlockBackoff, got {other:?}"),
        }
        AttemptTracker::for_vault(&path)
            .check_allowed(last_ts + 10)
            .expect("after window must allow");
    }

    #[test]
    fn lockout_at_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        for i in 1..=LOCKOUT_AT {
            t.record_failure(1000 + u64::from(i));
        }
        let err = AttemptTracker::for_vault(&path)
            .check_allowed(u64::MAX)
            .expect_err("must lock out");
        assert!(matches!(err, Error::UnlockLockedOut { .. }));
    }

    #[test]
    fn success_clears_counter_and_removes_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        t.record_failure(1000);
        t.record_failure(1001);
        assert_eq!(t.failed_attempts(), 2);

        t.record_success();
        assert_eq!(t.failed_attempts(), 0);
        let reloaded = AttemptTracker::for_vault(&path);
        assert_eq!(reloaded.failed_attempts(), 0);

        let sidecar = sidecar_path(&path);
        assert!(
            !sidecar.exists(),
            "success should remove the sidecar (got {})",
            sidecar.display()
        );
    }

    #[test]
    fn backoff_window_shape() {
        for n in 0..=INSTA_RETRIES {
            assert_eq!(super::backoff_window_secs(n), 0);
        }
        assert_eq!(super::backoff_window_secs(INSTA_RETRIES + 1), 2);
        assert_eq!(super::backoff_window_secs(INSTA_RETRIES + 2), 4);
        assert_eq!(super::backoff_window_secs(INSTA_RETRIES + 3), 8);
        assert!(super::backoff_window_secs(LOCKOUT_AT) <= BACKOFF_CAP_SECS);
    }

    #[test]
    fn clock_skew_does_not_brick_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        for i in 1..=INSTA_RETRIES + 1 {
            t.record_failure(1_000_000 + u64::from(i));
        }
        let err = AttemptTracker::for_vault(&path)
            .check_allowed(0)
            .expect_err("must still refuse");
        match err {
            Error::UnlockBackoff { remaining_secs } => {
                assert!(remaining_secs > 0);
                assert!(remaining_secs <= BACKOFF_CAP_SECS);
            }
            other => panic!("expected backoff, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        t.record_failure(0);

        let sidecar = sidecar_path(&path);
        let perms = std::fs::metadata(&sidecar).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "sidecar permissions should be 0o600, got {:o}",
            perms.mode() & 0o777
        );
    }

    #[test]
    fn corrupted_sidecar_defaults_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        std::fs::write(sidecar_path(&path), b"not-json-at-all").unwrap();
        let t = AttemptTracker::for_vault(&path);
        assert_eq!(t.failed_attempts(), 0, "corrupt sidecar -> fresh state");
        t.check_allowed(100).unwrap();
    }

    #[test]
    fn now_secs_is_plausible() {
        // Sanity check only -- not asserting an exact value, just
        // that it's a real, recent-ish Unix timestamp (after 2024-01-01).
        assert!(super::now_secs() > 1_700_000_000);
    }
}
