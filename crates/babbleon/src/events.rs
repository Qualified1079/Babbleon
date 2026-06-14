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
        eprintln!(
            "[babbleon] {}",
            serde_json::to_string(event).unwrap_or_default()
        );
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

/// Reads honey-tripwire access events from the named FIFO and forwards them
/// to an `EventBus`.
///
/// The honey wrapper scripts write a minimal JSON line to `HONEY_FIFO`.
/// This reader opens the FIFO (blocking until a writer appears), parses each
/// line, and emits `Event::HoneyTriggered` to the bus.
///
/// Call `spawn(bus, epoch, fifo_path)` from the trusted-tier daemon.  The
/// returned `JoinHandle` runs until the FIFO is removed or an error occurs.
pub struct HoneyFifoReader;

#[derive(serde::Deserialize)]
struct HoneyLine {
    ts: Option<u64>,
    pid: Option<u64>,
    honey: String,
    args: Option<String>,
}

impl HoneyFifoReader {
    /// Spawn a background thread that reads from `fifo_path` and emits events.
    ///
    /// The thread exits cleanly when the FIFO is deleted or read returns EOF.
    pub fn spawn(
        bus: std::sync::Arc<EventBus>,
        epoch: u64,
        fifo_path: impl AsRef<std::path::Path> + Send + 'static,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            Self::run(bus, epoch, fifo_path.as_ref());
        })
    }

    fn run(bus: std::sync::Arc<EventBus>, epoch: u64, fifo_path: &std::path::Path) {
        use std::io::{BufRead, BufReader};

        // Create the FIFO if it doesn't exist.
        #[cfg(unix)]
        {
            if !fifo_path.exists() {
                unsafe {
                    let path_cstr = std::ffi::CString::new(fifo_path.to_string_lossy().as_bytes())
                        .unwrap_or_default();
                    libc::mkfifo(path_cstr.as_ptr(), 0o600);
                }
            }
        }

        let f = match std::fs::OpenOptions::new().read(true).open(fifo_path) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("honey fifo open failed: {e}");
                return;
            }
        };

        let reader = BufReader::new(f);
        for line in reader.lines() {
            let line = match line {
                Ok(l) if !l.is_empty() => l,
                _ => break,
            };
            if let Ok(entry) = serde_json::from_str::<HoneyLine>(&line) {
                let hint = format!(
                    "pid={} ts={} args={}",
                    entry.pid.unwrap_or(0),
                    entry.ts.unwrap_or(0),
                    entry.args.as_deref().unwrap_or("")
                );
                bus.emit(Event::HoneyTriggered {
                    epoch,
                    names: vec![entry.honey],
                    process_hint: hint,
                });
            }
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
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sink.emit(&event)));
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
        sink.emit(&Event::RotationComplete {
            old_epoch: 1,
            new_epoch: 2,
        });
        sink.emit(&Event::VaultSealed {
            epoch: 2,
            backend: "soft".into(),
        });
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Event = serde_json::from_str(lines[0]).unwrap();
        assert!(matches!(
            first,
            Event::RotationComplete {
                old_epoch: 1,
                new_epoch: 2
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn honey_fifo_reader_fires_event() {
        use std::io::Write;
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let fifo_path = tmp.path().join("honey.fifo");

        // Create FIFO
        unsafe {
            let cstr =
                std::ffi::CString::new(fifo_path.to_string_lossy().as_bytes()).unwrap();
            libc::mkfifo(cstr.as_ptr(), 0o600);
        }

        let store = Arc::new(Mutex::new(vec![]));
        let mut bus = EventBus::new();
        bus.add_sink(Box::new(Capture(store.clone())));
        let bus = Arc::new(bus);

        let fp = fifo_path.clone();
        let handle = HoneyFifoReader::spawn(bus.clone(), 7, fp);

        // Give the reader thread time to open the FIFO.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Write a honey line as if a honey wrapper did it.
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&fifo_path)
                .unwrap();
            writeln!(
                f,
                r#"{{"ts":1234,"pid":9999,"honey":"xq-marble-fern","args":"--list"}}"#
            )
            .unwrap();
        }
        // Close the FIFO so the reader sees EOF.
        std::fs::remove_file(&fifo_path).ok();

        handle.join().ok();

        let s = store.lock().unwrap();
        assert_eq!(s.len(), 1, "expected exactly one HoneyTriggered event");
        match &s[0] {
            Event::HoneyTriggered { epoch, names, process_hint } => {
                assert_eq!(*epoch, 7);
                assert_eq!(names[0], "xq-marble-fern");
                assert!(process_hint.contains("9999"), "pid should appear in hint");
            }
            other => panic!("unexpected event: {other:?}"),
        }
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
        bus.emit(Event::RotationComplete {
            old_epoch: 0,
            new_epoch: 1,
        });
        let s = store.lock().unwrap();
        assert_eq!(s.len(), 2);
        assert!(matches!(s[0].severity(), Severity::Critical));
        assert!(matches!(s[1].severity(), Severity::Info));
    }
}
