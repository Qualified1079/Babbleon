//! Detection + audit event bus.
//!
//! The public package emits structured events; sinks consume them.
//! Enterprise additions: SIEM forwarder, central escrow alert, webhook.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    HoneyTriggered {
        epoch: u64,
        names: Vec<String>,
        process_hint: String,
    },
    UnlockFailed {
        epoch: u64,
        backend: String,
    },
    RotationComplete {
        old_epoch: u64,
        new_epoch: u64,
    },
    VaultSealed {
        epoch: u64,
        backend: String,
    },
}

impl Event {
    pub fn severity(&self) -> Severity {
        match self {
            Event::HoneyTriggered { .. } => Severity::Critical,
            Event::UnlockFailed { .. } => Severity::Warning,
            _ => Severity::Info,
        }
    }
}

pub trait EventSink: Send + Sync {
    fn emit(&self, event: &Event);
}

pub struct StderrSink;

impl EventSink for StderrSink {
    fn emit(&self, event: &Event) {
        eprintln!("[babbleon] {}", serde_json::to_string(event).unwrap_or_default());
    }
}

/// Append-only JSONL sink for local audit logs.  Each emit takes the
/// write lock briefly; suitable for low-frequency security events.
pub struct JsonlFileSink {
    path: std::path::PathBuf,
    lock: std::sync::Mutex<()>,
}

impl JsonlFileSink {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: std::sync::Mutex::new(()),
        }
    }
}

impl EventSink for JsonlFileSink {
    fn emit(&self, event: &Event) {
        use std::io::Write;
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let line = match serde_json::to_string(event) {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

pub struct EventBus {
    sinks: Vec<Box<dyn EventSink>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self {
            sinks: vec![Box::new(StderrSink)],
        }
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self { sinks: Vec::new() }
    }

    pub fn add_sink(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    pub fn emit(&self, event: Event) {
        for sink in &self.sinks {
            // A panicking sink must not break others.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.emit(&event)));
            let _ = result;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Capture(Arc<Mutex<Vec<Event>>>);
    impl EventSink for Capture {
        fn emit(&self, e: &Event) {
            self.0.lock().unwrap().push(e.clone());
        }
    }

    #[test]
    fn jsonl_sink_writes_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("audit.jsonl");
        let sink = JsonlFileSink::new(&path);
        sink.emit(&Event::RotationComplete { old_epoch: 1, new_epoch: 2 });
        sink.emit(&Event::VaultSealed { epoch: 2, backend: "soft".into() });
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Event = serde_json::from_str(lines[0]).unwrap();
        assert!(matches!(first, Event::RotationComplete { old_epoch: 1, new_epoch: 2 }));
    }

    #[test]
    fn fanout_and_severity() {
        let store = Arc::new(Mutex::new(vec![]));
        let mut bus = EventBus::new();
        bus.add_sink(Box::new(Capture(store.clone())));
        bus.emit(Event::HoneyTriggered {
            epoch: 1,
            names: vec!["x".into()],
            process_hint: "pid=42".into(),
        });
        bus.emit(Event::RotationComplete { old_epoch: 0, new_epoch: 1 });
        let s = store.lock().unwrap();
        assert_eq!(s.len(), 2);
        assert!(matches!(s[0].severity(), Severity::Critical));
        assert!(matches!(s[1].severity(), Severity::Info));
    }
}
