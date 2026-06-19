//! End-to-end test: spawn the real `babbleon-daemon` binary, hit
//! every operator subcommand via the socket, observe the responses.
//!
//! This catches regressions in the CLI surface and the main-loop
//! wiring that the in-process unit tests cannot see (clap parsing,
//! exit-code mapping, socket-bind timing, tracing init).
//!
//! The test is unconditional — it runs on any UNIX target — because
//! we use `tempfile` for the socket path and don't require root.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use babbleon_daemon_v2::{round_trip, Request, Response};

/// Spawn the daemon under test against `socket_path`.
///
/// Polls the socket file for up to 5 s before returning, so the
/// caller doesn't race the bind.
///
/// Returns a `Child` that the caller MUST pass to [`shutdown`]
/// before dropping; otherwise the daemon zombifies.  Clippy's
/// `zombie_processes` lint flags this contract explicitly.
#[allow(clippy::zombie_processes)]
fn spawn_daemon(socket_path: &std::path::Path) -> Child {
    let bin = daemon_binary();
    let mut child = Command::new(&bin)
        .arg("--socket")
        .arg(socket_path)
        .arg("run")
        .arg("--wrapper-dir")
        .arg("/wrappers")
        .arg("--tracked-tool")
        .arg("curl")
        .arg("--tracked-tool")
        .arg("ssh")
        .arg("--insecure-stub-secret")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn babbleon-daemon");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if socket_path.exists() {
            return child;
        }
        if let Ok(Some(status)) = child.try_wait() {
            // Daemon exited before binding the socket.  Capture
            // stderr for the failure message.
            let mut stderr = String::new();
            if let Some(s) = child.stderr.as_mut() {
                let _ = BufReader::new(s).read_line(&mut stderr);
            }
            panic!(
                "daemon exited before binding ({status}); stderr: {stderr}"
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Last-ditch: try to kill so we don't leak.
    let _ = child.kill();
    panic!(
        "daemon did not create socket at {} within 5 s",
        socket_path.display()
    );
}

/// Locate the built `babbleon-daemon` binary.  Cargo guarantees
/// `CARGO_BIN_EXE_babbleon-daemon` for binaries declared in the
/// same crate.
fn daemon_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_babbleon-daemon"))
}

fn shutdown(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn binary_serves_status_emit_rotate_in_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");

    let child = spawn_daemon(&sock);

    // status — expect epoch 0, tracked_count 2.
    let resp = round_trip(&sock, &Request::Status).expect("status");
    match resp {
        Response::Status {
            epoch,
            tracked_count,
            vault_locked,
            ..
        } => {
            assert_eq!(epoch, 0);
            assert_eq!(tracked_count, 2);
            assert!(!vault_locked, "phase 2 stub leaves vault unlocked");
        }
        other => {
            shutdown(child);
            panic!("expected Status response, got {other:?}");
        }
    }

    // emit-activated-table — expect epoch 0 and 2 entries.
    let resp = round_trip(&sock, &Request::EmitActivatedTable).expect("emit");
    match resp {
        Response::ActivatedTable { epoch, jsonl } => {
            assert_eq!(epoch, 0);
            let table = babbleon_core_v2::ActivatedTable::read_jsonl(
                std::io::Cursor::new(&jsonl),
            )
            .expect("parse activated table");
            assert_eq!(table.entries.len(), 2);
            for entry in &table.entries {
                assert!(
                    entry.wrapper_path.starts_with("/wrappers"),
                    "wrapper_path {:?} should start with /wrappers",
                    entry.wrapper_path,
                );
            }
        }
        other => {
            shutdown(child);
            panic!("expected ActivatedTable response, got {other:?}");
        }
    }

    // rotate-mapping — epoch advances to 1.
    let resp = round_trip(&sock, &Request::RotateMapping).expect("rotate");
    match resp {
        Response::Rotated { new_epoch } => assert_eq!(new_epoch, 1),
        other => {
            shutdown(child);
            panic!("expected Rotated response, got {other:?}");
        }
    }

    // status — should now report epoch 1.
    let resp =
        round_trip(&sock, &Request::Status).expect("status post-rotate");
    match resp {
        Response::Status { epoch, .. } => assert_eq!(epoch, 1),
        other => {
            shutdown(child);
            panic!("expected Status post-rotate, got {other:?}");
        }
    }

    // emit-activated-table again — epoch 1, different scrambled names.
    let resp = round_trip(&sock, &Request::EmitActivatedTable)
        .expect("emit post-rotate");
    match resp {
        Response::ActivatedTable { epoch, jsonl } => {
            assert_eq!(epoch, 1);
            let table = babbleon_core_v2::ActivatedTable::read_jsonl(
                std::io::Cursor::new(&jsonl),
            )
            .expect("parse activated table post-rotate");
            assert_eq!(table.entries.len(), 2);
        }
        other => {
            shutdown(child);
            panic!("expected ActivatedTable post-rotate, got {other:?}");
        }
    }

    shutdown(child);
}

#[test]
fn binary_refuses_to_run_without_insecure_stub_secret_flag() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");

    let output = Command::new(daemon_binary())
        .arg("--socket")
        .arg(&sock)
        .arg("run")
        .arg("--wrapper-dir")
        .arg("/wrappers")
        // NOTE: no --insecure-stub-secret.
        .output()
        .expect("run babbleon-daemon");

    assert!(
        !output.status.success(),
        "daemon should refuse to start without --insecure-stub-secret"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--insecure-stub-secret"),
        "stderr should explain the required flag.  Got: {stderr}",
    );
}

#[test]
fn binary_one_shots_fail_cleanly_when_daemon_absent() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("missing.sock");

    for subcmd in ["status", "rotate-mapping", "emit-activated-table"] {
        let output = Command::new(daemon_binary())
            .arg("--socket")
            .arg(&sock)
            .arg(subcmd)
            .output()
            .expect("run babbleon-daemon");
        assert!(
            !output.status.success(),
            "one-shot {subcmd} should fail when daemon is absent",
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("connect")
                || stderr.contains("No such file"),
            "stderr should explain the connect failure.  Got: {stderr}",
        );
    }
}
