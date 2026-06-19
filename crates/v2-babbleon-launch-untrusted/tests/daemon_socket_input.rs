//! End-to-end: launcher reads its activated table from a running
//! `babbleon-daemon` over the Unix socket.
//!
//! Spawns the daemon binary, asks it for the per-epoch table over
//! the wire, asserts the launcher-side reader returns the same
//! parsed shape as the daemon-side build path.  Catches drift
//! between the daemon's emit path and the launcher's
//! `--daemon-socket` consumer.
//!
//! No root required: we don't bind-mount, we just exercise the
//! protocol → parse → ActivatedTable conversion.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use v2_babbleon_launch_untrusted::activated_table_input;

/// Locate the built `babbleon-daemon` binary that cargo built for
/// the v2-babbleon-daemon crate's tests.  `CARGO_BIN_EXE_*` is
/// guaranteed for binaries in dependency crates as of Rust 1.79+ in
/// integration-test builds.
fn daemon_binary() -> PathBuf {
    // The launcher's Cargo.toml depends on v2-babbleon-daemon, so
    // cargo builds the daemon's bin target alongside.  The env var
    // for a dep-crate's bin is `CARGO_BIN_EXE_<bin-name>` if the
    // dep declares `[[bin]]` with that name and that bin is reachable
    // — which it is, since daemon's Cargo.toml has
    // `[[bin]] name = "babbleon-daemon"`.
    //
    // Fall back to `target/debug/babbleon-daemon` relative to the
    // workspace root if the env-var path is not available (older
    // toolchain or alternate build profile).
    if let Some(p) = option_env!("CARGO_BIN_EXE_babbleon-daemon") {
        return PathBuf::from(p);
    }
    let mut candidate = std::env::current_exe()
        .expect("current_exe")
        .parent()
        .unwrap()
        .to_path_buf();
    // current_exe is target/debug/deps/<test-binary>; ../babbleon-daemon
    // resolves to the daemon binary if cargo built it.
    candidate.pop();
    candidate.push("babbleon-daemon");
    candidate
}

#[allow(clippy::zombie_processes)]
fn spawn_daemon(socket_path: &std::path::Path) -> Child {
    let bin = daemon_binary();
    let mut child = Command::new(&bin)
        .arg("--socket")
        .arg(socket_path)
        .arg("run")
        .arg("--wrapper-dir")
        .arg("/usr/local/libexec/babbleon/wrappers")
        .arg("--tracked-tool")
        .arg("curl")
        .arg("--tracked-tool")
        .arg("ssh")
        .arg("--tracked-tool")
        .arg("git")
        .arg("--insecure-stub-secret")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "spawn {}: {e} (does the daemon bin exist?)",
                bin.display()
            )
        });

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if socket_path.exists() {
            return child;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let _ = child.kill();
            panic!("daemon exited before binding: {status}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("daemon did not create socket within 5 s");
}

fn shutdown(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn launcher_reads_activated_table_from_daemon_socket() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let child = spawn_daemon(&sock);

    let parsed = activated_table_input::read_if_present(
        None,
        None,
        Some(sock.as_path()),
    );
    let table = match parsed {
        Ok(Some(t)) => t,
        Ok(None) => {
            shutdown(child);
            panic!("expected Some(table), got None");
        }
        Err(e) => {
            shutdown(child);
            panic!("read failed: {e}");
        }
    };

    assert_eq!(table.epoch, 0);
    assert_eq!(table.entries.len(), 3, "three --tracked-tool args");
    for e in &table.entries {
        assert!(
            e.wrapper_path
                .starts_with("/usr/local/libexec/babbleon/wrappers"),
            "wrapper_path {:?} should start with the daemon's --wrapper-dir",
            e.wrapper_path,
        );
    }
    assert!(
        !table.honey_names.is_empty(),
        "daemon emits honey names per epoch",
    );

    shutdown(child);
}

#[test]
fn launcher_surfaces_clean_error_when_daemon_socket_missing() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("not-a-daemon.sock");
    let parsed = activated_table_input::read_if_present(
        None,
        None,
        Some(sock.as_path()),
    );
    match parsed {
        Err(e) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("daemon-socket") && msg.contains("round-trip"),
                "expected daemon-socket round-trip error, got: {msg}",
            );
        }
        Ok(other) => panic!("expected Err, got Ok({other:?})"),
    }
}
