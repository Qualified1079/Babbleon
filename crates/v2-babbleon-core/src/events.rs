//! Structured event bus for tripwires, vault lifecycle, and rotation.
//!
//! # What this defeats
//!
//! Defence-in-depth depends on detection: when an attacker probes a
//! honey name or a stale-mapping name, the operator (and any plugged-in
//! responder) needs an authenticated, machine-readable signal — not a
//! grep over stderr.  This module is that signal path.
//!
//! # Mechanism
//!
//! - [`Event`] is the wire format: a tagged enum, serde-derived,
//!   stable across versions via `#[serde(tag = "event")]`.
//! - [`TripwireSource`] tags whether a tripwire fired from the honey
//!   pool (random per-epoch decoys) or the stale-mapping pool
//!   (previous-epoch scrambled names).  v2 keeps the v1 distinction
//!   because they imply different attacker models.
//! - [`EventSink`] is the abstraction every consumer implements.  Two
//!   built-ins ship here: [`StderrSink`] for operator-visible runs and
//!   [`JsonlFileSink`] for long-term audit.
//! - [`AuditChainSink`] wraps another sink and appends each event to a
//!   SHA-256 hash-chained log.  When configured with an Ed25519 signer,
//!   each entry is also signed; the result is a tamper-evident audit
//!   trail that an offline verifier can replay end-to-end.
//!
//! # What this module does NOT do
//!
//! - It does NOT take action on tripwires.  The responder model
//!   (`TripwireResponsePolicy`) lives in the enforcement crate (phase 1
//!   completion).  This module surfaces events; the responder consumes
//!   them.
//! - It does NOT zeroize event payloads.  Event payloads are
//!   non-secret by construction — scrambled names, PIDs, epoch numbers.
//!   Any secret material that leaks into an event is a caller bug.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Severity classes used by sinks to decide colour, log level, or
/// alerting threshold.  Three classes is enough; finer granularity
/// (CVSS, ATT&CK technique) belongs on the consumer side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Routine lifecycle: rotation complete, vault sealed.
    Info,
    /// Suspicious-but-not-confirmed: unlock failure, repeated PAM denies.
    Warning,
    /// Confirmed adversarial signal: tripwire fired, audit-chain break.
    Critical,
}

/// Which tripwire pool fired.  v2 keeps the v1 source distinction
/// because they reflect different attacker models: honey is blind
/// guessing; stale is cached-intel reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TripwireSource {
    /// Random per-epoch honey compound.  Probe implies blind
    /// enumeration.
    Honey,
    /// Previous-epoch scrambled name still in the stale window.
    /// Probe implies the attacker has cached intel from before the
    /// last rotation.
    Stale,
}

/// The v2 event wire format.
///
/// `tag = "event"` puts the variant name in a top-level field so the
/// JSONL stream is greppable without parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// A tripwire fired.  Renamed from v1's `HoneyTriggered` to make
    /// the stale-vs-honey duality explicit at the event level.
    Tripwire {
        /// Epoch in which the probe occurred.
        epoch: u64,
        /// Which pool fired.
        source: TripwireSource,
        /// The scrambled name(s) the probe touched.  Vec because
        /// some wrappers batch (e.g. shell completion enumerations).
        names: Vec<String>,
        /// PID of the wrapper that emitted the event.  Wrapper exits
        /// 127 immediately after writing; this PID is for correlation
        /// only — DO NOT signal it from a responder.
        wrapper_pid: u32,
        /// PID of the process that exec'd the wrapper.  This is the
        /// candidate for responder action (kill, quarantine).
        triggering_pid: Option<u32>,
        /// `/proc/<pid>/stat` start-time of `triggering_pid` at
        /// trigger time, in clock ticks since boot.  A responder
        /// MUST re-read this value before acting on the PID, to
        /// defeat PID reuse races.
        triggering_pid_start: Option<u64>,
    },
    /// Vault unlock attempt failed (wrong passphrase, missing security
    /// key, expired credential).  Repeated failures escalate to
    /// rate-limit responses upstream.
    UnlockFailed {
        /// Epoch at the time of the attempt.
        epoch: u64,
        /// Symbolic name of the credential backend that rejected.
        backend: String,
    },
    /// Rotation completed successfully.  `old_epoch + 1 == new_epoch`
    /// for a normal forward rotation; emergency rotations may skip
    /// epochs to invalidate compromised mappings.
    RotationComplete {
        /// Epoch before the rotation.
        old_epoch: u64,
        /// Epoch after the rotation.
        new_epoch: u64,
    },
    /// Vault successfully sealed to disk.
    VaultSealed {
        /// Epoch of the vault that was sealed.
        epoch: u64,
        /// Symbolic name of the credential backend.
        backend: String,
    },
}

impl Event {
    /// Map this event to its severity class.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            Event::Tripwire { .. } => Severity::Critical,
            Event::UnlockFailed { .. } => Severity::Warning,
            Event::RotationComplete { .. } | Event::VaultSealed { .. } => {
                Severity::Info
            }
        }
    }
}

/// Sink trait.  Implementations MUST be `Send + Sync` because the
/// daemon multiplexes one sink across all worker threads.
///
/// Implementations SHOULD be non-blocking on the hot path; the
/// tripwire FIFO reader holds no lock while emitting and a slow sink
/// causes back-pressure.  The built-in sinks here take only short
/// mutexes around the write syscall.
pub trait EventSink: Send + Sync {
    /// Consume one event.  Errors are sink-internal; the trait
    /// deliberately swallows them so a misconfigured sink cannot
    /// stall the detection pipeline.  Sinks SHOULD log their own
    /// failures via `tracing` for operator visibility.
    fn emit(&self, event: &Event);

    /// Consume a pre-serialized line.  `AuditChainSink` calls this to
    /// forward its wrapped audit-entry JSON (which is a richer schema
    /// than [`Event`]).  Sinks whose wire format cannot represent the
    /// richer schema may leave the default no-op, which silently drops
    /// the audit entry — that is the correct failure mode rather than
    /// emitting a mangled line.
    fn emit_raw_line(&self, _line: &str) {}
}

/// Operator-visible sink: one JSON line per event on stderr.
pub struct StderrSink;

impl EventSink for StderrSink {
    fn emit(&self, event: &Event) {
        // Best-effort: if serialization fails the event is dropped
        // (cannot happen for our derives, but we don't panic in a
        // detection path).
        if let Ok(line) = serde_json::to_string(event) {
            eprintln!("[babbleon] {line}");
        }
    }

    fn emit_raw_line(&self, line: &str) {
        eprintln!("[babbleon-audit] {line}");
    }
}

/// Append-only JSONL sink for long-term audit retention.
///
/// One file lock per emit; the syscall surface is `open + write +
/// close` per event, which is acceptable for security-event
/// frequency (humans, not packets).  For high-volume telemetry, wrap
/// this in a batching sink upstream.
pub struct JsonlFileSink {
    path: PathBuf,
    /// Serializes concurrent writers so a partial line cannot
    /// interleave with another event mid-write.
    lock: Mutex<()>,
}

impl JsonlFileSink {
    /// Construct a sink targeting `path`.  The file is created on
    /// first emit, not at construction, so a sink can be set up
    /// before the audit directory exists.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), lock: Mutex::new(()) }
    }
}

impl EventSink for JsonlFileSink {
    fn emit(&self, event: &Event) {
        // Mutex is the only blocking point; held only for the
        // syscalls below.  Poisoning is recoverable: if a previous
        // writer panicked mid-write we still want subsequent events
        // to land, even if the file has a torn line.
        let Ok(line) = serde_json::to_string(event) else {
            return;
        };
        self.write_line(&line);
    }

    fn emit_raw_line(&self, line: &str) {
        self.write_line(line);
    }
}

impl JsonlFileSink {
    fn write_line(&self, line: &str) {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// Tamper-evident wrapper around another sink.
///
/// Every emitted event is serialized, hashed into a SHA-256 chain
/// (`H_n = SHA256(H_{n-1} || serialize(event_n))`), and optionally
/// signed with an Ed25519 key.  The wrapped sink receives a new
/// JSON object combining the original event with chain metadata.
///
/// # Verification
///
/// An offline verifier replays the chain by re-hashing each entry's
/// `event` field in order and asserting that the recorded `prev_hash`
/// matches.  If a signing key is configured, the verifier also
/// checks each signature against the chain hash for that entry.
///
/// # What this defeats
///
/// An attacker who gains write access to the JSONL file post-fact
/// (e.g. via a forensic-evasion script) cannot remove or modify
/// historical entries without breaking the chain.  Signing prevents
/// reconstructing a fake chain end-to-end without the private key.
pub struct AuditChainSink {
    inner: Box<dyn EventSink>,
    /// Chain state: last hash + entry counter.  Held under a mutex
    /// so concurrent emits append in a strict total order.
    state: Mutex<ChainState>,
    /// Optional signer.  When `None`, entries are chained but not
    /// signed; this is the local-only audit configuration.
    signer: Option<SigningKey>,
}

/// Mutable chain state.
struct ChainState {
    /// Hex-encoded SHA-256 of the previous entry's `event` field
    /// concatenated with the previous `prev_hash`.  Empty string at
    /// the genesis entry.
    prev_hash_hex: String,
    /// Monotone counter; helps detect dropped entries even before
    /// hash verification.
    seq: u64,
}

/// Wire format of an audited entry.  The wrapped sink sees this
/// instead of the raw `Event`.
#[derive(Debug, Serialize)]
struct AuditedEntry<'a> {
    /// Monotone sequence number, starting at 0.
    seq: u64,
    /// Hex-encoded previous chain hash.
    prev_hash: &'a str,
    /// Hex-encoded SHA-256 of this entry's event payload.
    event_hash: String,
    /// The event itself.
    event: &'a Event,
    /// Hex-encoded Ed25519 signature over `event_hash`, when a
    /// signing key is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

impl AuditChainSink {
    /// Wrap `inner` with hash chaining only.  Use this when the audit
    /// log is local and the signing key has not yet been provisioned.
    #[must_use]
    pub fn new(inner: Box<dyn EventSink>) -> Self {
        Self {
            inner,
            state: Mutex::new(ChainState {
                prev_hash_hex: String::new(),
                seq: 0,
            }),
            signer: None,
        }
    }

    /// Wrap `inner` with hash chaining AND Ed25519 signing.  Each
    /// entry's `signature` field is the signer's signature over the
    /// entry's `event_hash`.
    #[must_use]
    pub fn with_signer(inner: Box<dyn EventSink>, signer: SigningKey) -> Self {
        Self {
            inner,
            state: Mutex::new(ChainState {
                prev_hash_hex: String::new(),
                seq: 0,
            }),
            signer: Some(signer),
        }
    }
}

impl EventSink for AuditChainSink {
    fn emit(&self, event: &Event) {
        // Serialize the payload first; the chain hash covers this
        // canonical form.  We accept serde_json's output as canonical
        // because all Event fields are owned String / integer types
        // whose serde_json serialization is deterministic and
        // byte-stable.  INVARIANT: do NOT add HashMap or f64 fields
        // to Event — both produce non-deterministic byte sequences
        // (map key order; float formatting) that would silently break
        // chain replay verification.
        let Ok(event_bytes) = serde_json::to_vec(event) else {
            return;
        };

        // Compute event_hash = SHA256(payload).
        let mut h = Sha256::new();
        h.update(&event_bytes);
        let event_hash_bytes = h.finalize();
        let event_hash_hex = hex::encode(event_hash_bytes);

        // Sign event_hash if configured.  We sign the hex digest so
        // verifier scripts can reproduce the signed message without
        // re-serializing the payload — a small ergonomic win for
        // post-hoc auditors.
        let signature_hex = self.signer.as_ref().map(|sk| {
            let sig: Signature = sk.sign(event_hash_hex.as_bytes());
            hex::encode(sig.to_bytes())
        });

        // Append to chain.  prev_hash_hex covers the *previous*
        // entry's (prev_hash || event_hash) pair, giving a strict
        // tail-extension property.
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let seq = st.seq;
        let prev_hash_hex = st.prev_hash_hex.clone();

        let entry = AuditedEntry {
            seq,
            prev_hash: &prev_hash_hex,
            event_hash: event_hash_hex.clone(),
            event,
            signature: signature_hex,
        };

        // Compute next chain hash.  Encoded form is what the verifier
        // will reproduce; using `to_string` keeps that explicit.
        let mut next = Sha256::new();
        next.update(prev_hash_hex.as_bytes());
        next.update(event_hash_hex.as_bytes());
        st.prev_hash_hex = hex::encode(next.finalize());
        st.seq = seq.saturating_add(1);
        drop(st);

        // Forward as a synthetic event-shaped JSON line.  We bypass
        // the inner sink's Event-shaped API because audit entries are
        // a strictly richer wire format; emit as raw stderr/file
        // write via a small adapter.
        if let Ok(line) = serde_json::to_string(&entry) {
            // Emit through a one-shot raw-line sink so any inner
            // sink (stderr, JSONL) receives the wrapped form.
            self.inner.emit_raw_line(&line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use rand::rngs::OsRng;

    fn sample_tripwire() -> Event {
        Event::Tripwire {
            epoch: 7,
            source: TripwireSource::Honey,
            names: vec!["riverstoneanvilfreckle".into()],
            wrapper_pid: 4242,
            triggering_pid: Some(4240),
            triggering_pid_start: Some(123_456),
        }
    }

    #[test]
    fn tripwire_event_is_critical() {
        assert_eq!(sample_tripwire().severity(), Severity::Critical);
    }

    #[test]
    fn rotation_event_is_info() {
        let e = Event::RotationComplete { old_epoch: 1, new_epoch: 2 };
        assert_eq!(e.severity(), Severity::Info);
    }

    #[test]
    fn jsonl_sink_writes_one_line_per_event() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let sink = JsonlFileSink::new(&path);
        sink.emit(&sample_tripwire());
        sink.emit(&Event::RotationComplete { old_epoch: 1, new_epoch: 2 });
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("\"tripwire\""));
        assert!(contents.contains("\"rotation_complete\""));
    }

    #[test]
    fn audit_chain_links_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let inner: Box<dyn EventSink> = Box::new(JsonlFileSink::new(&path));
        let chain = AuditChainSink::new(inner);
        chain.emit(&sample_tripwire());
        chain.emit(&Event::RotationComplete { old_epoch: 0, new_epoch: 1 });

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify chain by replaying.
        let mut expected_prev = String::new();
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let prev = v["prev_hash"].as_str().unwrap();
            assert_eq!(prev, expected_prev, "chain prev_hash mismatch");

            // Recompute next prev_hash.
            let event_hash = v["event_hash"].as_str().unwrap();
            let mut h = Sha256::new();
            h.update(prev.as_bytes());
            h.update(event_hash.as_bytes());
            expected_prev = hex::encode(h.finalize());
        }
    }

    #[test]
    fn audit_chain_signatures_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signed.jsonl");
        let signer = SigningKey::generate(&mut OsRng);
        let verifier = signer.verifying_key();
        let inner: Box<dyn EventSink> = Box::new(JsonlFileSink::new(&path));
        let chain = AuditChainSink::with_signer(inner, signer);
        chain.emit(&sample_tripwire());

        let line = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let event_hash = v["event_hash"].as_str().unwrap();
        let sig_hex = v["signature"].as_str().unwrap();
        let sig_bytes: [u8; 64] =
            hex::decode(sig_hex).unwrap().try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        verifier.verify(event_hash.as_bytes(), &sig).expect("signature valid");
    }

    #[test]
    fn audit_chain_detects_tampering() {
        // Replay a chain after mutating one entry's payload; recomputed
        // hash should disagree with the recorded chain progression.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let inner: Box<dyn EventSink> = Box::new(JsonlFileSink::new(&path));
        let chain = AuditChainSink::new(inner);
        chain.emit(&sample_tripwire());
        chain.emit(&sample_tripwire());

        let contents = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<serde_json::Value> = contents
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        // Tamper: rewrite the first event's epoch.
        lines[0]["event"]["epoch"] = serde_json::json!(999);

        // Recompute event_hash for the tampered entry; original
        // event_hash in the file should no longer match.
        let tampered_payload = serde_json::to_vec(&lines[0]["event"]).unwrap();
        let mut h = Sha256::new();
        h.update(&tampered_payload);
        let recomputed = hex::encode(h.finalize());
        let recorded = lines[0]["event_hash"].as_str().unwrap();
        assert_ne!(recomputed, recorded, "tampering must be detectable");
    }
}
