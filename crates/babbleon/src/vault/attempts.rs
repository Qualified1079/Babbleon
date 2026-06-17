//! Per-vault unlock attempt counter with exponential backoff.
//!
//! Sidecar file at `<vault_path>.attempts` carries two numbers:
//!   - `failed_attempts`  (u32) — consecutive failures since last success
//!   - `last_failure_ts`  (u64) — seconds since UNIX_EPOCH of last failure
//!
//! Policy (constants below):
//!
//!   * The first `INSTA_RETRIES` failures don't trigger any wait —
//!     legitimate users mistype.
//!   * After that, each failure adds an exponentially-growing window
//!     before the next attempt is accepted (`2^(n - INSTA_RETRIES)`
//!     seconds, capped at `BACKOFF_CAP_SECS`).
//!   * At `LOCKOUT_AT` consecutive failures the vault refuses further
//!     attempts entirely until an operator clears the file (or runs a
//!     recovery flow).
//!
//! Sidecar file failures (missing, unreadable, corrupted) default to
//! "no attempts on record" — the rate limit is best-effort against an
//! attacker, not a hard correctness boundary against ourselves.  An
//! attacker who can delete the sidecar can also rewrite the vault, so
//! this is a defence-in-depth measure rather than a containment.

use crate::errors::{BabbleonError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Failures before any backoff window kicks in.  Three accommodates a
/// reasonable typo budget (caps-lock, layout, keyfile insertion timing)
/// without giving a brute-force attacker free attempts forever.
pub const INSTA_RETRIES: u32 = 3;

/// Hard ceiling on consecutive failures; beyond this the vault refuses
/// further attempts until cleared.
pub const LOCKOUT_AT: u32 = 10;

/// Maximum backoff window between attempts.  At LOCKOUT_AT − 1 = 9
/// failures the raw window would be `2^(9-3)` = 64 s; clamp to 60.
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
    /// Open (or create) the tracker for `vault_path`.  Sidecar file path
    /// is `<vault_path>.attempts`.
    pub fn for_vault(vault_path: &Path) -> Self {
        let path = sidecar_path(vault_path);
        let state = load(&path).unwrap_or_default();
        Self { path, state }
    }

    /// Read-only count of consecutive failures recorded on disk.
    pub fn failed_attempts(&self) -> u32 {
        self.state.failed_attempts
    }

    /// Refuse the unlock attempt if the vault is either locked out or
    /// still inside an exponential-backoff window.  Otherwise return Ok.
    pub fn check_allowed(&self, now: u64) -> Result<()> {
        if self.state.failed_attempts >= LOCKOUT_AT {
            return Err(BabbleonError::UnlockLockedOut {
                attempts: self.state.failed_attempts,
            });
        }
        let window = backoff_window_secs(self.state.failed_attempts);
        if window == 0 {
            return Ok(());
        }
        // Time-going-backwards (clock skew, NTP step) shouldn't extend the
        // window past sane bounds: cap `elapsed` at `window` so we never
        // refuse forever on a bad clock.
        let elapsed = now.saturating_sub(self.state.last_failure_ts);
        if elapsed >= window {
            return Ok(());
        }
        Err(BabbleonError::UnlockBackoff {
            remaining_secs: window - elapsed,
        })
    }

    /// Mark this attempt as failed.  Increments the counter and writes
    /// the sidecar file.  Errors from the sidecar write are downgraded
    /// to a warning trace — refusing the attempt because we can't write
    /// our own rate-limit file would lock the operator out.
    pub fn record_failure(&mut self, now: u64) -> Result<()> {
        self.state.failed_attempts = self.state.failed_attempts.saturating_add(1);
        self.state.last_failure_ts = now;
        if let Err(e) = save(&self.path, &self.state) {
            tracing::warn!(
                "attempt tracker: failed to persist failure count: {e} (path={})",
                self.path.display()
            );
        }
        Ok(())
    }

    /// Mark this attempt as successful.  Resets the counter and writes
    /// the sidecar file (or removes it for a clean filesystem).
    pub fn record_success(&mut self) -> Result<()> {
        self.state = AttemptState::default();
        if self.path.exists() {
            // Best-effort delete; if it fails we fall back to writing
            // a zeroed state so the next attempt still sees a clean
            // counter.
            if std::fs::remove_file(&self.path).is_err() {
                let _ = save(&self.path, &self.state);
            }
        }
        Ok(())
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
    let shift = (failed_attempts - INSTA_RETRIES) as u64;
    // 2^shift seconds, with a guard against overflow at large shifts
    // (we already cap below, but make the intermediate safe too).
    let raw = 1u64.checked_shl(shift.min(32) as u32).unwrap_or(u64::MAX);
    raw.min(BACKOFF_CAP_SECS)
}

fn load(path: &Path) -> Result<AttemptState> {
    let bytes = std::fs::read(path)?;
    let state: AttemptState = serde_json::from_slice(&bytes)?;
    Ok(state)
}

fn save(path: &Path, state: &AttemptState) -> Result<()> {
    let bytes = serde_json::to_vec(state)?;
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Current wall-clock seconds since UNIX_EPOCH, or 0 if the clock is
/// before the epoch (which only happens on machines with grossly broken
/// RTCs).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            t.record_failure(1000 + i as u64).unwrap();
            // Reloading from disk gives the same state.
            let again = AttemptTracker::for_vault(&path);
            assert_eq!(again.failed_attempts(), i);
            again
                .check_allowed(1000 + i as u64)
                .expect("inside INSTA_RETRIES must skip backoff");
        }
    }

    #[test]
    fn fourth_failure_enforces_backoff_window() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        for i in 1..=INSTA_RETRIES + 1 {
            t.record_failure(1000 + i as u64).unwrap();
        }
        // 4 failures → window 2^(4-3) = 2 s
        let last_ts = 1000 + (INSTA_RETRIES + 1) as u64;
        let err = AttemptTracker::for_vault(&path)
            .check_allowed(last_ts + 1)
            .expect_err("must refuse within window");
        match err {
            BabbleonError::UnlockBackoff { remaining_secs } => {
                assert!(remaining_secs > 0, "expected positive remaining");
                assert!(remaining_secs <= 2, "expected window ≤ 2s");
            }
            other => panic!("expected UnlockBackoff, got {other:?}"),
        }
        // After the window passes, allowed again.
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
            t.record_failure(1000 + i as u64).unwrap();
        }
        let err = AttemptTracker::for_vault(&path)
            .check_allowed(u64::MAX)
            .expect_err("must lock out");
        assert!(matches!(err, BabbleonError::UnlockLockedOut { .. }));
    }

    #[test]
    fn success_clears_counter_and_removes_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        t.record_failure(1000).unwrap();
        t.record_failure(1001).unwrap();
        assert_eq!(t.failed_attempts(), 2);

        t.record_success().unwrap();
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
        // No backoff for the first INSTA_RETRIES.
        for n in 0..=INSTA_RETRIES {
            assert_eq!(backoff_window_secs(n), 0);
        }
        // Doubles past that.
        assert_eq!(backoff_window_secs(INSTA_RETRIES + 1), 2);
        assert_eq!(backoff_window_secs(INSTA_RETRIES + 2), 4);
        assert_eq!(backoff_window_secs(INSTA_RETRIES + 3), 8);
        // Capped at BACKOFF_CAP_SECS.
        assert!(backoff_window_secs(LOCKOUT_AT) <= BACKOFF_CAP_SECS);
    }

    #[test]
    fn clock_skew_does_not_brick_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        let mut t = AttemptTracker::for_vault(&path);
        for i in 1..=INSTA_RETRIES + 1 {
            t.record_failure(1_000_000 + i as u64).unwrap();
        }
        // Clock walked backwards — "now" is BEFORE the recorded failure.
        // Implementation caps elapsed at 0 (saturating_sub), so the
        // refusal is "wait `window` seconds", which is the recoverable
        // outcome we want — not "wait forever".
        let err = AttemptTracker::for_vault(&path)
            .check_allowed(0)
            .expect_err("must still refuse");
        match err {
            BabbleonError::UnlockBackoff { remaining_secs } => {
                assert!(remaining_secs > 0);
                assert!(remaining_secs <= BACKOFF_CAP_SECS);
            }
            other => panic!("expected backoff, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_sidecar_defaults_to_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = vault_in(dir.path());
        // Write garbage to the sidecar.
        std::fs::write(sidecar_path(&path), b"not-json-at-all").unwrap();
        let t = AttemptTracker::for_vault(&path);
        assert_eq!(t.failed_attempts(), 0, "corrupt sidecar -> fresh state");
        t.check_allowed(100).unwrap();
    }
}
