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

/// Locate `babbleon-daemon` for this test.
///
/// Cargo only sets `CARGO_BIN_EXE_<name>` for binaries in **this**
/// package — not for cross-package binaries reached via a dev-dep
/// edge.  (The earlier comment claiming otherwise was inaccurate;
/// the prior version of this helper silently fell through to a
/// non-existent fallback path and the test failed with a
/// `daemon exited before binding` panic on a clean target dir.)
///
/// Strategy:
///
/// 1. **target-dir lookup** — `target/<profile>/babbleon-daemon`
///    relative to the test binary.  Cheap and works if anything else
///    built the daemon recently.
/// 2. **self-bootstrap** — synchronous `cargo build -p
///    v2-babbleon-daemon --bin babbleon-daemon`.  Cargo's lockfile
///    serialises concurrent invocations so this is parallel-safe.
fn daemon_binary() -> PathBuf {
    let target_path = target_dir_binary("babbleon-daemon");
    if target_path.exists() {
        return target_path;
    }
    bootstrap_via_cargo_build("v2-babbleon-daemon", "babbleon-daemon");
    let after = target_dir_binary("babbleon-daemon");
    assert!(
        after.exists(),
        "after cargo build the daemon binary still does not exist at {}",
        after.display(),
    );
    after
}

/// Compute `target/<profile>/<name>` from the test binary's location.
fn target_dir_binary(name: &str) -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop(); // deps/
    p.pop(); // <profile>/
    p.push(name);
    p
}

/// Synchronously invoke `cargo build -p <pkg> --bin <bin>` to
/// produce a sibling-package binary into the workspace target dir.
fn bootstrap_via_cargo_build(pkg: &str, bin: &str) {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(&cargo)
        .args(["build", "-p", pkg, "--bin", bin])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("spawn cargo build for sibling binary");
    assert!(
        status.success(),
        "cargo build -p {pkg} --bin {bin} failed with {status}",
    );
}

/// Drop a placeholder real-binary in `dir` so the daemon has
/// something to wrap.  The daemon writes wrappers that `exec` this
/// path; the launcher test doesn't actually invoke the wrappers so
/// the placeholder body is irrelevant.
fn fake_real(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
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
    let mut child = cmd.spawn().unwrap_or_else(|e| {
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
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real(dir.path(), "curl");
    let ssh = fake_real(dir.path(), "ssh");
    let git = fake_real(dir.path(), "git");
    let child = spawn_daemon(
        &sock,
        &wrapper_dir,
        &[("curl", &curl), ("ssh", &ssh), ("git", &git)],
    );

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
            e.wrapper_path.starts_with(&wrapper_dir),
            "wrapper_path {:?} should start with the daemon's --wrapper-dir {:?}",
            e.wrapper_path,
            wrapper_dir,
        );
        // The daemon-side materialisation invariant: every
        // advertised wrapper_path actually exists on disk.
        assert!(
            e.wrapper_path.exists(),
            "wrapper file missing on disk: {:?}",
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
