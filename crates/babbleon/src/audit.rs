//! Tamper-evident audit log.
//!
//! Each entry carries a SHA-256 hash of the previous entry's JSON bytes,
//! forming a forward-only chain.  Truncation or in-place edits invalidate
//! the chain.  Useful as a community-side audit primitive; SIEM forwarders
//! in the enterprise crate can stream from the same source.
//!
//! Format: one JSON object per line (JSONL).  Each line:
//!   {"prev":"<hex>","seq":N,"ts":"<rfc3339>","event":{...}}
//!
//! The prev hash of entry 0 is the all-zero hash.

use crate::errors::{BabbleonError, Result};
use crate::events::{Event, EventSink};
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
}

pub struct ChainedAuditLog {
    path: PathBuf,
    state: Mutex<ChainState>,
}

struct ChainState {
    last_hash: String,
    next_seq: u64,
}

impl ChainedAuditLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
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
}

impl EventSink for ChainedAuditLog {
    fn emit(&self, event: &Event) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let entry = ChainEntry {
            prev: state.last_hash.clone(),
            seq: state.next_seq,
            ts: current_ts(),
            event: event.clone(),
        };
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

    #[test]
    fn chain_grows_and_verifies() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let log = ChainedAuditLog::open(&path).unwrap();
        log.emit(&Event::RotationComplete {
            old_epoch: 0,
            new_epoch: 1,
        });
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
        log.emit(&Event::RotationComplete {
            old_epoch: 0,
            new_epoch: 1,
        });
        log.emit(&Event::RotationComplete {
            old_epoch: 1,
            new_epoch: 2,
        });

        // Tamper: rewrite the first line with a different event.
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(String::from).collect();
        let mut first: ChainEntry = serde_json::from_str(&lines[0]).unwrap();
        first.event = Event::RotationComplete {
            old_epoch: 0,
            new_epoch: 999,
        };
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
            log.emit(&Event::RotationComplete {
                old_epoch: 0,
                new_epoch: 1,
            });
        }
        {
            let log = ChainedAuditLog::open(&path).unwrap();
            log.emit(&Event::RotationComplete {
                old_epoch: 1,
                new_epoch: 2,
            });
        }
        let count = ChainedAuditLog::verify(&path).unwrap();
        assert_eq!(count, 2);
    }
}
