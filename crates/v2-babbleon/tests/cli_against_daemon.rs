//! End-to-end: spawn the real `babbleon-daemon` binary against a
//! tempdir socket, then drive `babbleon` (the user-facing CLI) at
//! the same socket and assert the output.
//!
//! This catches drift between the user CLI's expected protocol and
//! the daemon's actual responses without requiring the full PAM /
//! launcher lifecycle.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Locate a sibling binary in the same target directory as the test
/// binary.  Works regardless of whether the test was launched via
/// `cargo test` or directly.
fn sibling_binary(name: &str) -> PathBuf {
    // The test binary lives at target/<profile>/deps/<test-name>-<hash>.
    // The crate binaries live at target/<profile>/<name>.
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop(); // deps/
    p.pop(); // <profile>/
    p.push(name);
    assert!(
        p.exists(),
        "expected binary at {} — run `cargo build --workspace` first",
        p.display(),
    );
    p
}

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

#[allow(clippy::zombie_processes)]
fn spawn_daemon(
    socket_path: &std::path::Path,
    wrapper_dir: &std::path::Path,
    tool: (&str, &std::path::Path),
) -> Child {
    let bin = sibling_binary("babbleon-daemon");
    let mut child = Command::new(&bin)
        .arg("--socket")
        .arg(socket_path)
        .arg("run")
        .arg("--wrapper-dir")
        .arg(wrapper_dir)
        .arg("--tracked-tool")
        .arg(format!("{}={}", tool.0, tool.1.display()))
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
            let mut stderr = String::new();
            if let Some(s) = child.stderr.as_mut() {
                let _ = BufReader::new(s).read_line(&mut stderr);
            }
            panic!("daemon exited before binding ({status}); stderr: {stderr}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("daemon never bound socket {}", socket_path.display());
}

fn shutdown(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn cli_status_prints_daemon_state() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");
    let child = spawn_daemon(&sock, &wrapper_dir, ("curl", &curl));

    let cli = sibling_binary("babbleon-v2");
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("status")
        .output()
        .expect("run babbleon-v2");

    shutdown(child);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "CLI failed: status={:?}, stderr={stderr}",
        out.status,
    );
    assert!(stdout.contains("epoch: 0"), "stdout: {stdout}");
    assert!(stdout.contains("tracked_count: 1"), "stdout: {stdout}");
    assert!(stdout.contains("vault_locked: false"), "stdout: {stdout}");
}

#[test]
fn cli_rotate_mapping_advances_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");
    let child = spawn_daemon(&sock, &wrapper_dir, ("curl", &curl));

    let cli = sibling_binary("babbleon-v2");
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("rotate-mapping")
        .output()
        .expect("run babbleon-v2 rotate-mapping");
    assert!(out.status.success(), "rotate-mapping failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("rotated to epoch: 1"),
        "stdout: {stdout}",
    );

    // Subsequent status should now show epoch 1.
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("status")
        .output()
        .expect("status post-rotate");
    shutdown(child);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("epoch: 1"), "stdout post-rotate: {stdout}");
}

#[test]
fn cli_status_against_missing_daemon_returns_actionable_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("does-not-exist.sock");

    let cli = sibling_binary("babbleon-v2");
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("status")
        .output()
        .expect("run babbleon-v2");
    assert!(!out.status.success(), "should fail with no daemon");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("round-trip") || stderr.contains("No such file"),
        "stderr should mention the connect failure: {stderr}",
    );
}

#[test]
fn cli_init_still_returns_not_yet_implemented() {
    // Regression guard: phase-3 stubs must keep failing loudly until
    // their daemon-side wiring lands.  This test prevents accidentally
    // wiring `init` before the vault-unlock protocol exists.
    let cli = sibling_binary("babbleon-v2");
    let out = Command::new(&cli).arg("init").output().expect("run init");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not yet implemented"), "stderr: {stderr}");
}
