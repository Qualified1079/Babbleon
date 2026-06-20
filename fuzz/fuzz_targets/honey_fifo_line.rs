//! Fuzz the honey-FIFO line parser.
//!
//! The wrapper script writes JSON lines like
//!   `{"ts":N,"pid":N,"ppid":N,"ppid_start":N,"source":"honey","honey":"...","args":"..."}`
//! into `/run/babbleon/honey.fifo`.  `HoneyFifoReader::run` parses
//! these via `serde_json::from_str::<HoneyLine>`.  The CWE-400
//! length-bound on the *reader* is already enforced; this fuzzer
//! targets the *parser*: malformed JSON, oversized strings, Unicode
//! surrogates, integer-overflow values, etc.
//!
//! We can't reach the private `HoneyLine` type from here, so we
//! exercise the public path: write the input into a real FIFO, spin
//! up the reader, and confirm it doesn't panic or block.  Skipped on
//! non-Linux.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(unix)]
    {
        use babbleon::events::{EventBus, HoneyFifoReader};
        use std::io::Write;
        use std::sync::Arc;
        use std::time::Duration;

        let tmp = match tempfile::tempdir() {
            Ok(t) => t,
            Err(_) => return,
        };
        let fifo = tmp.path().join("f");
        let cstr = match std::ffi::CString::new(fifo.to_string_lossy().as_bytes()) {
            Ok(c) => c,
            Err(_) => return,
        };
        // SAFETY: cstr lives until end of function; mode is a plain
        // scalar; return ignored because EEXIST/EPERM surfaces at open.
        unsafe {
            libc::mkfifo(cstr.as_ptr(), 0o600);
        }

        let bus = Arc::new(EventBus::new());
        let handle = HoneyFifoReader::spawn(bus.clone(), 0, fifo.clone());

        std::thread::sleep(Duration::from_millis(10));

        // Write whatever the fuzzer produced, followed by a newline so
        // the reader has a complete record to consume.
        if let Ok(mut w) = std::fs::OpenOptions::new().write(true).open(&fifo) {
            let _ = w.write_all(data);
            let _ = w.write_all(b"\n");
        }
        // Close the FIFO to signal EOF.
        let _ = std::fs::remove_file(&fifo);
        let _ = handle.join();
    }

    // Non-Unix: don't exercise the FIFO path.  Reading bytes is enough
    // to silence "unused" lint.
    let _ = data.len();
});
