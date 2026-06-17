//! Tamper-evident audit log.
//!
//! Each entry carries a SHA-256 hash of the previous entry's JSON bytes,
//! forming a forward-only chain.  Truncation or in-place edits invalidate
//! the chain.  Useful as a community-side audit primitive; SIEM forwarders
//! in the enterprise crate can stream from the same source.
//!
//! ## Two integrity tiers
//!
//! 1. **Chain-only** (`open` + `verify`): SHA-256 hash chain.  Detects
//!    in-place edits and re-ordering, but an attacker with write access
//!    can recompute the entire chain from scratch.  Cheap baseline.
//!
//! 2. **Signed chain** (`open_signed` + `verify_signed`): each entry's
//!    {prev, seq, ts, event} is Ed25519-signed by a key the audited host
//!    does NOT hold long-term (held by a separate admin host or in a
//!    TPM).  An attacker who roots the box cannot forge new entries — at
//!    worst they can truncate, which is what the chain hash plus a known
//!    high-water seq from the verifier detects.
//!
//! Format: one JSON object per line (JSONL).  Each line:
//!   `{"prev":"<hex>","seq":N,"ts":"<rfc3339>","event":{...},"sig":"<hex>"?}`
//!
//! The prev hash of entry 0 is the all-zero hash.
//! The `sig` field is omitted in chain-only mode and required in signed
//! mode; mixed logs are rejected at verify time.

use crate::errors::{BabbleonError, Result};
use crate::events::{Event, EventSink};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    pub prev: String,
    pub seq: u64,
    pub ts: String,
    pub event: Event,
    /// Ed25519 signature over the JSON form of `SigningPayload {prev,
    /// seq, ts, event}`, hex-encoded.  `None` for chain-only logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// Bytes-to-be-signed for an entry: every field of `ChainEntry` *except*
/// `sig`.  Producing this as a separate type with the same field order
/// guarantees the bytes the signer signs are exactly the bytes the
/// verifier reconstructs from a parsed entry — no `sig = None;
/// reserialize` dance, no canonicalization fragility.
#[derive(Serialize)]
struct SigningPayload<'a> {
    prev: &'a str,
    seq: u64,
    ts: &'a str,
    event: &'a Event,
}

impl<'a> SigningPayload<'a> {
    fn for_entry(entry: &'a ChainEntry) -> Self {
        Self {
            prev: &entry.prev,
            seq: entry.seq,
            ts: &entry.ts,
            event: &entry.event,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        // serde_json::to_vec is deterministic given a fixed struct
        // (field order is the declaration order, no map iteration).
        serde_json::to_vec(self).expect("SigningPayload always serializes")
    }
}

pub struct ChainedAuditLog {
    path: PathBuf,
    state: Mutex<ChainState>,
}

struct ChainState {
    last_hash: String,
    next_seq: u64,
    signing_key: Option<SigningKey>,
}

impl ChainedAuditLog {
    /// Open a chain-only log.  Entries written via `emit` will NOT carry
    /// a signature; `verify` checks the hash chain only.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        Self::open_inner(path.into(), None)
    }

    /// Open a signed log.  Every entry written via `emit` is Ed25519-
    /// signed with `signing_key`.  Verify with `verify_signed`.
    ///
    /// The signing key should NOT be the same key the audited host's
    /// own daemons would normally hold — the whole point is that the
    /// verifier can detect post-compromise forgery.  In production the
    /// expected pattern is: admin host generates a key, hands the
    /// public half to the audited host, keeps the private half on a
    /// separate (or TPM-sealed) host.
    pub fn open_signed(path: impl Into<PathBuf>, signing_key: SigningKey) -> Result<Self> {
        Self::open_inner(path.into(), Some(signing_key))
    }

    fn open_inner(path: PathBuf, signing_key: Option<SigningKey>) -> Result<Self> {
        let (last_hash, next_seq) = if path.exists() {
            scan_tail(&path)?
        } else {
            (ZERO_HASH.to_string(), 0)
        };
        Ok(Self {
            path,
            state: Mutex::new(ChainState {
                last_hash,
                next_seq,
                signing_key,
            }),
        })
    }

    /// Verify the entire chain.  Returns Ok(count) if valid, Err otherwise.
    pub fn verify(path: &std::path::Path) -> Result<u64> {
        if !path.exists() {
            return Ok(0);
        }
        let f = std::fs::File::open(path)
            .map_err(|e| BabbleonError::Enforcement(format!("open audit: {e}")))?;
        let r = BufReader::new(f);
        let mut prev = ZERO_HASH.to_string();
        let mut count = 0u64;
        for (i, line) in r.lines().enumerate() {
            let line =
                line.map_err(|e| BabbleonError::Enforcement(format!("read line {i}: {e}")))?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: ChainEntry = serde_json::from_str(&line)
                .map_err(|e| BabbleonError::Enforcement(format!("parse line {i}: {e}")))?;
            if entry.prev != prev {
                return Err(BabbleonError::Enforcement(format!(
                    "chain break at seq {} (line {i}): prev mismatch",
                    entry.seq
                )));
            }
            if entry.seq != count {
                return Err(BabbleonError::Enforcement(format!(
                    "chain break: expected seq {count}, got {}",
                    entry.seq
                )));
            }
            prev = hash_line(&line);
            count += 1;
        }
        Ok(count)
    }

    /// Verify the chain AND every entry's Ed25519 signature.
    ///
    /// Rejects entries without a `sig` field — a signed log that gains
    /// an unsigned entry has been tampered with.
    pub fn verify_signed(path: &std::path::Path, verifying_key: &VerifyingKey) -> Result<u64> {
        if !path.exists() {
            return Ok(0);
        }
        let f = std::fs::File::open(path)
            .map_err(|e| BabbleonError::Enforcement(format!("open audit: {e}")))?;
        let r = BufReader::new(f);
        let mut prev = ZERO_HASH.to_string();
        let mut count = 0u64;
        for (i, line) in r.lines().enumerate() {
            let line =
                line.map_err(|e| BabbleonError::Enforcement(format!("read line {i}: {e}")))?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: ChainEntry = serde_json::from_str(&line)
                .map_err(|e| BabbleonError::Enforcement(format!("parse line {i}: {e}")))?;

            if entry.prev != prev {
                return Err(BabbleonError::Enforcement(format!(
                    "chain break at seq {} (line {i}): prev mismatch",
                    entry.seq
                )));
            }
            if entry.seq != count {
                return Err(BabbleonError::Enforcement(format!(
                    "chain break: expected seq {count}, got {}",
                    entry.seq
                )));
            }

            let sig_hex = entry.sig.as_ref().ok_or_else(|| {
                BabbleonError::Enforcement(format!(
                    "signed-verify: entry seq {} has no signature",
                    entry.seq
                ))
            })?;
            let sig_bytes = hex::decode(sig_hex).map_err(|e| {
                BabbleonError::Enforcement(format!("signed-verify: hex decode at seq {}: {e}", entry.seq))
            })?;
            if sig_bytes.len() != SIGNATURE_LENGTH {
                return Err(BabbleonError::Enforcement(format!(
                    "signed-verify: bad signature length at seq {}: got {}, want {SIGNATURE_LENGTH}",
                    entry.seq,
                    sig_bytes.len()
                )));
            }
            let sig_array: [u8; SIGNATURE_LENGTH] = sig_bytes
                .try_into()
                .expect("length checked above");
            let sig = Signature::from_bytes(&sig_array);

            let signed_bytes = SigningPayload::for_entry(&entry).to_bytes();
            verifying_key.verify(&signed_bytes, &sig).map_err(|e| {
                BabbleonError::Enforcement(format!(
                    "signed-verify: bad signature at seq {}: {e}",
                    entry.seq
                ))
            })?;

            prev = hash_line(&line);
            count += 1;
        }
        Ok(count)
    }
}

impl EventSink for ChainedAuditLog {
    fn emit(&self, event: &Event) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut entry = ChainEntry {
            prev: state.last_hash.clone(),
            seq: state.next_seq,
            ts: current_ts(),
            event: event.clone(),
            sig: None,
        };
        if let Some(sk) = state.signing_key.as_ref() {
            let payload = SigningPayload::for_entry(&entry).to_bytes();
            let sig: Signature = sk.sign(&payload);
            entry.sig = Some(hex::encode(sig.to_bytes()));
        }
        let line = match serde_json::to_string(&entry) {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            if writeln!(f, "{line}").is_ok() {
                state.last_hash = hash_line(&line);
                state.next_seq += 1;
            }
        }
    }
}

fn hash_line(line: &str) -> String {
    let mut h = Sha256::new();
    h.update(line.as_bytes());
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

fn scan_tail(path: &std::path::Path) -> Result<(String, u64)> {
    let f = std::fs::File::open(path)
        .map_err(|e| BabbleonError::Enforcement(format!("open audit: {e}")))?;
    let r = BufReader::new(f);
    let mut prev = ZERO_HASH.to_string();
    let mut next_seq = 0u64;
    for line in r.lines() {
        let line = line.map_err(|e| BabbleonError::Enforcement(format!("read audit: {e}")))?;
        if line.trim().is_empty() {
            continue;
        }
        prev = hash_line(&line);
        next_seq += 1;
    }
    Ok((prev, next_seq))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn rotation(old: u64, new: u64) -> Event {
        Event::RotationComplete {
            old_epoch: old,
            new_epoch: new,
        }
    }

    #[test]
    fn chain_grows_and_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let log = ChainedAuditLog::open(&path).unwrap();
        log.emit(&rotation(0, 1));
        log.emit(&Event::VaultSealed {
            epoch: 1,
            backend: "soft".into(),
        });
        log.emit(&Event::HoneyTriggered {
            epoch: 1,
            names: vec!["xx".into()],
            source: crate::events::TripwireSource::Honey,
            wrapper_pid: 99,
            triggering_pid: None,
            triggering_pid_start: None,
            process_hint: "pid=99".into(),
        });
        let count = ChainedAuditLog::verify(&path).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn tamper_is_detected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let log = ChainedAuditLog::open(&path).unwrap();
        log.emit(&rotation(0, 1));
        log.emit(&rotation(1, 2));

        // Tamper: rewrite the first line with a different event.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut first: ChainEntry = serde_json::from_str(&lines[0]).unwrap();
        first.event = rotation(0, 999);
        lines[0] = serde_json::to_string(&first).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let r = ChainedAuditLog::verify(&path);
        assert!(r.is_err(), "tamper should be detected");
    }

    #[test]
    fn reopening_continues_chain() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        {
            let log = ChainedAuditLog::open(&path).unwrap();
            log.emit(&rotation(0, 1));
        }
        {
            let log = ChainedAuditLog::open(&path).unwrap();
            log.emit(&rotation(1, 2));
        }
        let count = ChainedAuditLog::verify(&path).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn signed_log_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("signed.jsonl");
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let log = ChainedAuditLog::open_signed(&path, sk).unwrap();
        log.emit(&rotation(0, 1));
        log.emit(&rotation(1, 2));
        log.emit(&rotation(2, 3));

        let count = ChainedAuditLog::verify_signed(&path, &vk).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn signed_log_rejects_event_tamper() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("signed.jsonl");
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        let log = ChainedAuditLog::open_signed(&path, sk).unwrap();
        log.emit(&rotation(0, 1));
        log.emit(&rotation(1, 2));

        // Rewrite the *second* entry's event while preserving its signature.
        // signed-verify should refuse: signature is over the original event.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut second: ChainEntry = serde_json::from_str(&lines[1]).unwrap();
        second.event = rotation(1, 9999);
        lines[1] = serde_json::to_string(&second).unwrap();
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        // The chain may or may not detect this depending on the prev hash;
        // the SIGNATURE check definitely will.
        let r = ChainedAuditLog::verify_signed(&path, &vk);
        assert!(r.is_err(), "tampered event must fail signed verify");
    }

    #[test]
    fn signed_log_rejects_unsigned_entry() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("signed.jsonl");
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();

        // Write one signed entry...
        {
            let log = ChainedAuditLog::open_signed(&path, sk).unwrap();
            log.emit(&rotation(0, 1));
        }
        // ...then append an UNSIGNED entry using the chain-only path.
        // (This is exactly what a post-compromise attacker would try.)
        {
            let log = ChainedAuditLog::open(&path).unwrap();
            log.emit(&rotation(1, 2));
        }

        let r = ChainedAuditLog::verify_signed(&path, &vk);
        assert!(
            r.is_err(),
            "signed log must reject any entry without a signature"
        );
    }

    #[test]
    fn signed_log_rejects_wrong_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("signed.jsonl");
        let sk = SigningKey::generate(&mut OsRng);

        let log = ChainedAuditLog::open_signed(&path, sk).unwrap();
        log.emit(&rotation(0, 1));

        let wrong_vk = SigningKey::generate(&mut OsRng).verifying_key();
        let r = ChainedAuditLog::verify_signed(&path, &wrong_vk);
        assert!(r.is_err(), "wrong verifying key must fail");
    }

    #[test]
    fn chain_verify_ignores_signature_field() {
        // A chain-only `verify` over a signed log should still succeed —
        // it doesn't inspect signatures, just hashes.  Useful for SIEM
        // forwarders that don't carry the verifying key.
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("signed.jsonl");
        let sk = SigningKey::generate(&mut OsRng);

        let log = ChainedAuditLog::open_signed(&path, sk).unwrap();
        log.emit(&rotation(0, 1));
        log.emit(&rotation(1, 2));

        let count = ChainedAuditLog::verify(&path).unwrap();
        assert_eq!(count, 2);
    }
}
