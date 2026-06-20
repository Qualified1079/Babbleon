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

/// Drive `babbleon init --passphrase-stdin` against a tempdir vault
/// path with a known passphrase, confirm the on-disk vault file
/// exists with mode 0o600.
#[test]
fn cli_init_creates_vault_file_at_specified_path() {
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault.age");

    let cli = sibling_binary("babbleon-v2");
    let mut child = Command::new(&cli)
        .arg("--vault-path")
        .arg(&vault)
        .arg("--passphrase-stdin")
        .arg("init")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn babbleon-v2 init");
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"correct horse battery staple\n").unwrap();
    }
    let out = child.wait_with_output().expect("wait init");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "init failed: status={:?}, stderr={stderr}, stdout={stdout}",
        out.status,
    );
    assert!(vault.exists(), "vault file should exist post-init");
    assert!(
        stdout.contains("initialized at"),
        "stdout should announce vault path: {stdout}",
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&vault)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "vault file mode should be 0o600");
    }
}

/// Drive `babbleon init` twice without `--force`; second call must
/// fail and the file from the first call must remain intact.
#[test]
fn cli_init_refuses_overwrite_without_force() {
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault.age");

    let cli = sibling_binary("babbleon-v2");

    // First init succeeds.
    let mut child = Command::new(&cli)
        .arg("--vault-path")
        .arg(&vault)
        .arg("--passphrase-stdin")
        .arg("init")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn init #1");
    child.stdin.as_mut().unwrap().write_all(b"first-pass\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "first init must succeed");
    let original_bytes = std::fs::read(&vault).unwrap();

    // Second init without --force fails.
    let mut child = Command::new(&cli)
        .arg("--vault-path")
        .arg(&vault)
        .arg("--passphrase-stdin")
        .arg("init")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn init #2");
    child.stdin.as_mut().unwrap().write_all(b"second-pass\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success(), "second init must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("already exists"),
        "stderr should mention overwrite: {stderr}",
    );

    // The original vault is intact.
    let after = std::fs::read(&vault).unwrap();
    assert_eq!(original_bytes, after, "vault must NOT be overwritten");
}

/// Full end-to-end: spawn the daemon in Locked mode (no
/// `--insecure-stub-secret`), run `babbleon init` to create a
/// vault, run `babbleon unlock` to install the per-host secret,
/// then run `babbleon status` and confirm `vault_locked: false`.
///
/// The daemon binary today still requires `--insecure-stub-secret`
/// (the flip to "starts Locked by default" lands in HANDOFF item 2's
/// final commit).  For this test we route through that flag —
/// `--insecure-stub-secret` puts the daemon in Unlocked at start,
/// so `babbleon unlock` is exercised AFTER a fresh rotate / lock
/// path... actually no, we can't easily re-lock.  This test instead
/// confirms `babbleon init` works end-to-end and the `babbleon
/// unlock` flow against a daemon that ALREADY has a stub secret
/// returns the right "already unlocked" error (an honest negative
/// path).
#[test]
fn cli_init_then_unlock_against_already_unlocked_daemon_reports_already() {
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let sock = tmp.path().join("daemon.sock");
    let wrapper_dir = tmp.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let vault = tmp.path().join("vault.age");
    let curl = fake_real_binary(tmp.path(), "curl");

    // Spawn daemon in stub-unlocked mode.
    let child = spawn_daemon(&sock, &wrapper_dir, ("curl", &curl));

    let cli = sibling_binary("babbleon-v2");

    // Init the vault first.
    let mut init = Command::new(&cli)
        .arg("--vault-path")
        .arg(&vault)
        .arg("--passphrase-stdin")
        .arg("init")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn init");
    init.stdin.as_mut().unwrap().write_all(b"test-pass\n").unwrap();
    let init_out = init.wait_with_output().unwrap();
    assert!(init_out.status.success(), "init must succeed");

    // Now `babbleon unlock` against a daemon that is already
    // Unlocked (the stub-secret startup path).  Expect a clean
    // daemon-error response.
    let mut unlock = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("--vault-path")
        .arg(&vault)
        .arg("--passphrase-stdin")
        .arg("unlock")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn unlock");
    unlock.stdin.as_mut().unwrap().write_all(b"test-pass\n").unwrap();
    let unlock_out = unlock.wait_with_output().unwrap();
    shutdown(child);
    assert!(!unlock_out.status.success(), "unlock must fail (already unlocked)");
    let stderr = String::from_utf8_lossy(&unlock_out.stderr);
    assert!(
        stderr.contains("already") || stderr.contains("Vault"),
        "stderr should mention already-unlocked: {stderr}",
    );
}

/// Verify the wrong-passphrase path: init with one passphrase, then
/// `unlock` with a different one.  The unseal MUST fail before any
/// daemon round-trip happens; the daemon does not see any traffic.
#[test]
fn cli_unlock_with_wrong_passphrase_fails_without_daemon_traffic() {
    use std::io::Write;
    let tmp = tempfile::tempdir().unwrap();
    let vault = tmp.path().join("vault.age");
    let sock = tmp.path().join("does-not-exist.sock");

    let cli = sibling_binary("babbleon-v2");

    // Init.
    let mut init = Command::new(&cli)
        .arg("--vault-path")
        .arg(&vault)
        .arg("--passphrase-stdin")
        .arg("init")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    init.stdin.as_mut().unwrap().write_all(b"the-right-one\n").unwrap();
    assert!(init.wait_with_output().unwrap().status.success());

    // Unlock with the wrong passphrase against a non-existent
    // daemon socket: if the unseal fails first (correct order), the
    // daemon-connect error doesn't fire.
    let mut unlock = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("--vault-path")
        .arg(&vault)
        .arg("--passphrase-stdin")
        .arg("unlock")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    unlock.stdin.as_mut().unwrap().write_all(b"WRONG\n").unwrap();
    let out = unlock.wait_with_output().unwrap();
    assert!(!out.status.success(), "wrong passphrase must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("wrong passphrase") || stderr.contains("unsealing"),
        "stderr should reflect unseal failure, not connect failure: {stderr}",
    );
}
