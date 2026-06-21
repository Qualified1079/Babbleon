//! HMAC-sealed epoch journal — persist the daemon's rotation
//! counter across restarts without re-sealing the vault.
//!
//! # What this defeats
//!
//! Without persistence, every daemon restart resets the rotation
//! counter to 0.  An attacker who can kill the daemon (signal,
//! systemd restart, OOM kill) shortens the stale-list window
//! every time: previous-epoch scrambled names that would have
//! tripped a "stale" tripwire silently become unknown-name
//! lookups instead, weakening the cached-intel detection signal.
//!
//! Without HMAC, a plaintext epoch file would let an attacker
//! shift the counter forward or backward.  Backward shifts let
//! the attacker reuse a cached epoch's mapping; forward shifts
//! waste the stale-list window prematurely.
//!
//! `epoch_journal` is the middle ground: a 40-byte file containing
//! the epoch (8 bytes, little-endian u64) plus a 32-byte HMAC over
//! those 8 bytes keyed by an HKDF subkey of the per-host secret.
//! Tamper → HMAC fails → daemon refuses to use the journal and
//! resumes at epoch 0 with a tracing `warn`.  Missing file →
//! `read` returns `None` and the daemon resumes at 0 (genesis
//! case).  All failure modes are safe.
//!
//! # Why not re-seal the vault on every rotate?
//!
//! Re-sealing requires either holding the KEK in memory (security
//! regression) or re-prompting for the passphrase (terrible UX).
//! The HMAC journal sidesteps both: the HKDF key is derived from
//! the already-unlocked secret, so no additional key material lives
//! in process memory beyond what's already there.
//!
//! # Wire format
//!
//! ```text
//! 0      8                            40   (bytes)
//! +------+----------------------------+
//! |epoch | HMAC-SHA256(epoch_bytes)   |
//! +------+----------------------------+
//!  u64-LE                32-byte tag
//! ```
//!
//! Atomic write: emit to `<path>.tmp` then `rename(2)` into place.
//! A crash mid-write leaves the previous journal intact.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** plaintext-file tampering (HMAC); restart-loses-
//!   rotation-history (persistence); attacker-controlled epoch
//!   replacement on disk (HMAC verification + safe-fail).
//! - **Does NOT defeat:** attacker who reads the per-host secret
//!   from daemon memory; they can forge a valid HMAC for any
//!   epoch.  Compensating control: the daemon's seccomp filter
//!   blocks `process_vm_readv` and the OS's `yama.ptrace_scope=2`
//!   blocks same-uid ptrace.
//! - **Does NOT defeat:** journal file deletion as a denial-of-
//!   service.  An attacker who can delete the file forces a reset
//!   to epoch 0.  Compensating control: the journal file should
//!   live under a daemon-owned directory (mode 0o700) on a
//!   filesystem the user does not have write access to.

use std::path::{Path, PathBuf};

use babbleon_core_v2::{key_derivation::derive_subkey, PerHostSecret};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::errors::{Error, Result};

/// HKDF info label for the journal's HMAC key.  Independent of the
/// mapping / wrapper / tripwire purpose strings so a key reuse
/// across subsystems is structurally impossible.
const JOURNAL_KEY_PURPOSE: &[u8] = b"v2-epoch-journal";

/// Total bytes the journal serialises to.  Exact (not min); a
/// shorter or longer file is rejected at read time.
pub const JOURNAL_BYTES: usize = 8 + 32;

type HmacSha256 = Hmac<Sha256>;

/// Write the epoch journal atomically.
///
/// Computes the HMAC tag, serialises `epoch || tag`, writes to a
/// sibling `.tmp` path, then `rename(2)`s into place.  A crash
/// between write and rename leaves the previous journal intact.
///
/// `secret` is borrowed; no secret bytes are retained beyond the
/// stack frame.
///
/// # Errors
///
/// - [`Error::Vault`] on HKDF derivation failure (cannot happen
///   in practice — included for completeness).
/// - [`Error::Vault`] on any I/O failure (`open`, `write`, `rename`).
pub fn write_journal(
    epoch: u64,
    secret: &PerHostSecret,
    path: &Path,
) -> Result<()> {
    let key = derive_subkey(secret, 0, JOURNAL_KEY_PURPOSE, 32)
        .map_err(|e| Error::Vault(format!("epoch-journal HKDF: {e}")))?;

    let mut mac = HmacSha256::new_from_slice(key.as_slice())
        .map_err(|e| Error::Vault(format!("epoch-journal HMAC init: {e}")))?;
    let epoch_bytes = epoch.to_le_bytes();
    mac.update(&epoch_bytes);
    let tag = mac.finalize().into_bytes();

    let mut buf = Vec::with_capacity(JOURNAL_BYTES);
    buf.extend_from_slice(&epoch_bytes);
    buf.extend_from_slice(tag.as_slice());
    debug_assert_eq!(buf.len(), JOURNAL_BYTES);

    let tmp_path = tmp_sibling(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Vault(format!(
                    "epoch-journal parent {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    write_with_mode(&tmp_path, &buf, 0o600).map_err(|e| {
        Error::Vault(format!(
            "epoch-journal tmp write {}: {e}",
            tmp_path.display()
        ))
    })?;
    std::fs::rename(&tmp_path, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp_path);
        Error::Vault(format!(
            "epoch-journal rename {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        ))
    })?;
    Ok(())
}

/// Read the epoch journal, verifying the HMAC tag in constant
/// time against a freshly derived key.
///
/// Returns `Ok(Some(epoch))` on a valid journal,
/// `Ok(None)` when the file is missing, and `Err(Error::Vault)`
/// when the file exists but fails any validation step (wrong
/// length, HMAC mismatch, I/O error).  The caller is responsible
/// for the warn-and-fall-back-to-0 policy — this module does not
/// silently swallow tamper signals.
///
/// `secret` is borrowed; no secret bytes are retained.
///
/// # Errors
///
/// - [`Error::Vault`] on I/O failure, wrong file length, or HMAC
///   mismatch.  The error message names the failure mode so an
///   operator log triage tells tamper from corruption.
pub fn read_journal(
    secret: &PerHostSecret,
    path: &Path,
) -> Result<Option<u64>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(e) => {
            return Err(Error::Vault(format!(
                "epoch-journal read {}: {e}",
                path.display()
            )));
        }
    };
    if bytes.len() != JOURNAL_BYTES {
        return Err(Error::Vault(format!(
            "epoch-journal {} length {} != expected {}",
            path.display(),
            bytes.len(),
            JOURNAL_BYTES
        )));
    }

    let (epoch_bytes, tag_bytes) = bytes.split_at(8);
    let key = derive_subkey(secret, 0, JOURNAL_KEY_PURPOSE, 32)
        .map_err(|e| Error::Vault(format!("epoch-journal HKDF: {e}")))?;
    let mut mac = HmacSha256::new_from_slice(key.as_slice())
        .map_err(|e| Error::Vault(format!("epoch-journal HMAC init: {e}")))?;
    mac.update(epoch_bytes);
    mac.verify_slice(tag_bytes).map_err(|_| {
        Error::Vault(format!(
            "epoch-journal {}: HMAC mismatch (tamper or wrong secret)",
            path.display()
        ))
    })?;

    let mut epoch_arr = [0u8; 8];
    epoch_arr.copy_from_slice(epoch_bytes);
    Ok(Some(u64::from_le_bytes(epoch_arr)))
}

fn tmp_sibling(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

#[cfg(target_os = "linux")]
fn write_with_mode(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

#[cfg(not(target_os = "linux"))]
fn write_with_mode(path: &Path, bytes: &[u8], _mode: u32) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::{read_journal, write_journal, JOURNAL_BYTES};
    use babbleon_core_v2::PerHostSecret;

    fn secret_a() -> PerHostSecret {
        PerHostSecret::from_bytes(&[7u8; 32]).unwrap()
    }
    fn secret_b() -> PerHostSecret {
        PerHostSecret::from_bytes(&[13u8; 32]).unwrap()
    }

    #[test]
    fn roundtrip_preserves_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        let s = secret_a();
        write_journal(42, &s, &p).unwrap();
        let got = read_journal(&s, &p).unwrap();
        assert_eq!(got, Some(42));
    }

    #[test]
    fn read_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nonexistent.bin");
        let s = secret_a();
        assert_eq!(read_journal(&s, &p).unwrap(), None);
    }

    #[test]
    fn wrong_secret_fails_hmac_verification() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        write_journal(99, &secret_a(), &p).unwrap();
        let err = read_journal(&secret_b(), &p).unwrap_err();
        assert!(format!("{err}").contains("HMAC mismatch"));
    }

    #[test]
    fn tampered_epoch_bytes_fail_verification() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        let s = secret_a();
        write_journal(100, &s, &p).unwrap();
        let mut bytes = std::fs::read(&p).unwrap();
        bytes[0] ^= 1; // flip a bit in the epoch
        std::fs::write(&p, &bytes).unwrap();
        let err = read_journal(&s, &p).unwrap_err();
        assert!(format!("{err}").contains("HMAC mismatch"));
    }

    #[test]
    fn tampered_hmac_tag_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        let s = secret_a();
        write_journal(7, &s, &p).unwrap();
        let mut bytes = std::fs::read(&p).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&p, &bytes).unwrap();
        let err = read_journal(&s, &p).unwrap_err();
        assert!(format!("{err}").contains("HMAC mismatch"));
    }

    #[test]
    fn truncated_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        let s = secret_a();
        write_journal(7, &s, &p).unwrap();
        let bytes = std::fs::read(&p).unwrap();
        std::fs::write(&p, &bytes[..bytes.len() - 1]).unwrap();
        let err = read_journal(&s, &p).unwrap_err();
        assert!(format!("{err}").contains("length"));
    }

    #[test]
    fn oversize_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        let s = secret_a();
        write_journal(7, &s, &p).unwrap();
        let mut bytes = std::fs::read(&p).unwrap();
        bytes.push(0);
        std::fs::write(&p, &bytes).unwrap();
        let err = read_journal(&s, &p).unwrap_err();
        assert!(format!("{err}").contains("length"));
    }

    #[test]
    fn overwrite_replaces_previous_journal_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        let s = secret_a();
        write_journal(1, &s, &p).unwrap();
        write_journal(2, &s, &p).unwrap();
        write_journal(3, &s, &p).unwrap();
        assert_eq!(read_journal(&s, &p).unwrap(), Some(3));
        // Tmp sibling should not linger.
        let tmp = dir.path().join("epoch.bin.tmp");
        assert!(!tmp.exists(), "tmp sibling should be cleaned up by rename");
    }

    #[test]
    fn journal_file_size_matches_constant() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        write_journal(0, &secret_a(), &p).unwrap();
        let len = std::fs::metadata(&p).unwrap().len();
        assert_eq!(usize::try_from(len).unwrap(), JOURNAL_BYTES);
    }

    #[test]
    fn distinct_secrets_produce_distinct_tags_for_same_epoch() {
        // Sanity: the HMAC key depends on the secret, so the tag
        // for epoch=N under secret_a differs from the tag for
        // epoch=N under secret_b.
        let dir = tempfile::tempdir().unwrap();
        let p_a = dir.path().join("a.bin");
        let p_b = dir.path().join("b.bin");
        write_journal(5, &secret_a(), &p_a).unwrap();
        write_journal(5, &secret_b(), &p_b).unwrap();
        let bytes_a = std::fs::read(&p_a).unwrap();
        let bytes_b = std::fs::read(&p_b).unwrap();
        assert_eq!(&bytes_a[..8], &bytes_b[..8], "epoch bytes identical");
        assert_ne!(&bytes_a[8..], &bytes_b[8..], "HMAC tags must differ");
    }

    #[test]
    fn epoch_max_value_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("epoch.bin");
        let s = secret_a();
        write_journal(u64::MAX, &s, &p).unwrap();
        assert_eq!(read_journal(&s, &p).unwrap(), Some(u64::MAX));
    }
}
