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
/// `wrapper_dir` is where the daemon will materialise wrappers;
/// `tools` is the `(name, real_path)` set the daemon tracks.
///
/// Returns a `Child` that the caller MUST pass to [`shutdown`]
/// before dropping; otherwise the daemon zombifies.  Clippy's
/// `zombie_processes` lint flags this contract explicitly.
#[allow(clippy::zombie_processes)]
fn spawn_daemon(
    socket_path: &std::path::Path,
    wrapper_dir: &std::path::Path,
    tools: &[(&str, &std::path::Path)],
) -> Child {
    let bin = daemon_binary();
    let mut cmd = Command::new(&bin);
    cmd.arg("--socket")
        .arg(socket_path)
        .arg("run")
        .arg("--wrapper-dir")
        .arg(wrapper_dir);
    for (name, path) in tools {
        cmd.arg("--tracked-tool")
            .arg(format!("{name}={}", path.display()));
    }
    cmd.arg("--insecure-stub-secret")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn babbleon-daemon");

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

/// Create a placeholder real-binary the daemon can wrap.  Returns
/// the absolute path; the file is left in `dir`.
fn fake_real_binary(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(format!("real-{name}"));
    std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            &p,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    p
}

#[test]
fn binary_serves_status_emit_rotate_in_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");
    let ssh = fake_real_binary(dir.path(), "ssh");

    let child = spawn_daemon(
        &sock,
        &wrapper_dir,
        &[("curl", &curl), ("ssh", &ssh)],
    );

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
                    entry.wrapper_path.starts_with(&wrapper_dir),
                    "wrapper_path {:?} should start with {:?}",
                    entry.wrapper_path,
                    wrapper_dir,
                );
                // The daemon must have actually written each wrapper
                // to disk — this is the materialisation invariant.
                assert!(
                    entry.wrapper_path.exists(),
                    "wrapper file missing on disk: {:?}",
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
fn binary_starts_locked_without_insecure_stub_secret_flag() {
    // Default behaviour as of HANDOFF item 2 closure: the daemon
    // starts in the Locked state without the `--insecure-stub-secret`
    // flag.  `Status` works; `EmitActivatedTable` and `RotateMapping`
    // return `Vault` errors until an operator sends `Request::Unlock`.
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();

    // Spawn the daemon WITHOUT --insecure-stub-secret.
    let bin = daemon_binary();
    let mut child = Command::new(&bin)
        .arg("--socket")
        .arg(&sock)
        .arg("run")
        .arg("--wrapper-dir")
        .arg(&wrapper_dir)
        // NOTE: no --insecure-stub-secret.
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn babbleon-daemon");

    // Wait for the socket to appear (it always does, regardless of
    // lock state — the listener binds before the serve loop starts).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if sock.exists() {
            break;
        }
        if let Ok(Some(status)) = child.try_wait() {
            let _ = child.kill();
            let mut stderr = String::new();
            if let Some(s) = child.stderr.as_mut() {
                use std::io::BufRead;
                let _ = std::io::BufReader::new(s).read_line(&mut stderr);
            }
            panic!("daemon exited before binding ({status}); stderr: {stderr}");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(sock.exists(), "daemon never bound socket");

    // Status works in Locked mode: vault_locked = true.
    let resp = round_trip(&sock, &Request::Status).expect("status");
    match resp {
        Response::Status {
            vault_locked,
            tracked_count,
            ..
        } => {
            assert!(vault_locked, "daemon should start Locked");
            assert_eq!(tracked_count, 0);
        }
        other => {
            shutdown(child);
            panic!("expected Status, got {other:?}");
        }
    }

    // Emit-activated-table refuses with a Vault error in Locked.
    let resp = round_trip(&sock, &Request::EmitActivatedTable)
        .expect("emit round-trip");
    match resp {
        Response::Error { kind, message } => {
            use babbleon_daemon_protocol_v2::ErrorKind;
            assert_eq!(kind, ErrorKind::Vault);
            assert!(message.contains("locked"), "{message}");
        }
        other => {
            shutdown(child);
            panic!("expected Error, got {other:?}");
        }
    }

    shutdown(child);
}

#[test]
fn binary_writes_real_and_honey_wrappers_to_wrapper_dir() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");

    let child = spawn_daemon(&sock, &wrapper_dir, &[("curl", &curl)]);

    let resp = round_trip(&sock, &Request::EmitActivatedTable).expect("emit");
    let table = match resp {
        Response::ActivatedTable { jsonl, .. } => {
            babbleon_core_v2::ActivatedTable::read_jsonl(
                std::io::Cursor::new(&jsonl),
            )
            .expect("parse table")
        }
        other => {
            shutdown(child);
            panic!("expected ActivatedTable, got {other:?}");
        }
    };

    // Every entry must have a wrapper file on disk.
    for entry in &table.entries {
        assert!(entry.wrapper_path.exists(), "missing {:?}", entry.wrapper_path);
    }
    // Honey wrappers must also exist on disk.
    for honey in &table.honey_names {
        let p = wrapper_dir.join(honey);
        assert!(p.exists(), "honey wrapper missing: {p:?}");
    }
    shutdown(child);
}

#[test]
fn binary_rotation_updates_wrappers_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");

    let child = spawn_daemon(&sock, &wrapper_dir, &[("curl", &curl)]);

    let pre = round_trip(&sock, &Request::EmitActivatedTable).expect("pre-emit");
    let pre_table = match pre {
        Response::ActivatedTable { jsonl, .. } => {
            babbleon_core_v2::ActivatedTable::read_jsonl(
                std::io::Cursor::new(&jsonl),
            )
            .unwrap()
        }
        other => {
            shutdown(child);
            panic!("expected ActivatedTable, got {other:?}");
        }
    };

    let _ = round_trip(&sock, &Request::RotateMapping).expect("rotate");

    let post = round_trip(&sock, &Request::EmitActivatedTable).expect("post-emit");
    let post_table = match post {
        Response::ActivatedTable { jsonl, .. } => {
            babbleon_core_v2::ActivatedTable::read_jsonl(
                std::io::Cursor::new(&jsonl),
            )
            .unwrap()
        }
        other => {
            shutdown(child);
            panic!("expected ActivatedTable post-rotate, got {other:?}");
        }
    };

    // Post-rotation scrambled names must differ from pre-rotation.
    let pre_names: std::collections::HashSet<_> =
        pre_table.entries.iter().map(|e| &e.scrambled).collect();
    let post_names: std::collections::HashSet<_> =
        post_table.entries.iter().map(|e| &e.scrambled).collect();
    assert!(
        pre_names.is_disjoint(&post_names),
        "scrambled names persisted across rotation",
    );
    // New wrappers must exist on disk.
    for entry in &post_table.entries {
        assert!(
            entry.wrapper_path.exists(),
            "post-rotation wrapper missing: {:?}",
            entry.wrapper_path,
        );
    }
    shutdown(child);
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
