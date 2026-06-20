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
    // The "refuse overwrite" path may exit before the parent
    // finishes feeding stdin — that produces an EPIPE on write_all.
    // The child already gave up; that's the behaviour under test,
    // so swallow the write error rather than racing the child.
    let _ = child.stdin.as_mut().unwrap().write_all(b"second-pass\n");
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

/// End-to-end: `babbleon scramble FILE.py | babbleon unscramble`
/// against a running daemon round-trips a Python source file.
///
/// Pipeline:
///
/// 1. Spawn the daemon with `--insecure-stub-secret` so it starts
///    Unlocked and serves the per-epoch whitespace compounds.
/// 2. Write a small Python source to a tempfile.
/// 3. Run `babbleon scramble -i src.py -o out.scr` against the
///    daemon's socket.
/// 4. Assert the scrambled file is non-empty and contains no
///    visible newline characters (the layer-3 promise).
/// 5. Run `babbleon unscramble -i out.scr -o reconstructed.py`
///    against the same socket.
/// 6. Assert the reconstructed source is byte-identical to the
///    original modulo trailing newline / canonical indent
///    normalisation.
#[test]
fn cli_scramble_then_unscramble_round_trips_python_source() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");
    let child = spawn_daemon(&sock, &wrapper_dir, ("curl", &curl));

    let cli = sibling_binary("babbleon-v2");

    // Original Python source — uses one level of indent, internal
    // spaces in a string, and a comment.  Matches the MVP
    // tokenizer's supported subset.
    let src_path = dir.path().join("src.py");
    let scr_path = dir.path().join("out.scr");
    let recon_path = dir.path().join("reconstructed.py");
    let original = "def greet(name):\n    print(\"hello \" + name)\n";
    std::fs::write(&src_path, original).unwrap();

    // Scramble.
    let scramble_out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("scramble")
        .arg("-i")
        .arg(&src_path)
        .arg("-o")
        .arg(&scr_path)
        .output()
        .unwrap();
    if !scramble_out.status.success() {
        shutdown(child);
        panic!(
            "scramble failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&scramble_out.stdout),
            String::from_utf8_lossy(&scramble_out.stderr),
        );
    }

    let scrambled = std::fs::read(&scr_path).unwrap();
    assert!(!scrambled.is_empty(), "scrambled file is empty");
    // Layer-3 promise: no visible '\n' in the scrambled body.
    assert!(
        !scrambled.contains(&b'\n'),
        "scrambled output contains visible '\\n' byte",
    );

    // Unscramble.
    let unscramble_out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("unscramble")
        .arg("-i")
        .arg(&scr_path)
        .arg("-o")
        .arg(&recon_path)
        .output()
        .unwrap();
    if !unscramble_out.status.success() {
        shutdown(child);
        panic!(
            "unscramble failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&unscramble_out.stdout),
            String::from_utf8_lossy(&unscramble_out.stderr),
        );
    }

    let reconstructed = std::fs::read_to_string(&recon_path).unwrap();
    // Round-trip: byte-identical to the original modulo the trailing
    // newline normalisation the MVP tokenizer documents.  The
    // original ends in '\n', so the reconstructed must too.
    assert_eq!(
        reconstructed, original,
        "reconstructed source mismatch — original={original:?}, \
         reconstructed={reconstructed:?}",
    );

    shutdown(child);
}

/// Scramble against a daemon that is locked must surface the
/// daemon's Vault-error cleanly (not panic, not hang).
#[test]
fn cli_scramble_against_locked_daemon_reports_vault_error() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = dir.path().join("real-curl");
    std::fs::write(&curl, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(
        &curl,
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    // Start the daemon Locked: omit --insecure-stub-secret.
    let daemon_bin = sibling_binary("babbleon-daemon");
    #[allow(clippy::zombie_processes)]
    let mut child = Command::new(&daemon_bin)
        .arg("--socket")
        .arg(&sock)
        .arg("run")
        .arg("--wrapper-dir")
        .arg(&wrapper_dir)
        .arg("--tracked-tool")
        .arg(format!("curl={}", curl.display()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Wait for socket bind.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() && Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            let mut stderr = String::new();
            if let Some(s) = child.stderr.as_mut() {
                let _ = BufReader::new(s).read_line(&mut stderr);
            }
            panic!(
                "locked daemon exited early ({status}); stderr: {stderr}",
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(sock.exists(), "daemon socket not bound");

    let cli = sibling_binary("babbleon-v2");
    let src_path = dir.path().join("src.py");
    std::fs::write(&src_path, "x = 1\n").unwrap();

    let out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("scramble")
        .arg("-i")
        .arg(&src_path)
        .output()
        .unwrap();
    shutdown(child);

    assert!(
        !out.status.success(),
        "scramble must fail when daemon is locked",
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Vault") || stderr.contains("locked"),
        "stderr should mention vault locked, got: {stderr}",
    );
}

/// End-to-end: `babbleon scramble-dir` + `babbleon unscramble-dir`
/// round-trip a small Python corpus through the daemon.
///
/// Demonstrates the install-time use case: one daemon round-trip
/// covers the whole tree.  Output structure mirrors input layout
/// (including subdirectories); non-`.py` files are skipped.
#[test]
fn cli_scramble_dir_then_unscramble_dir_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");
    let child = spawn_daemon(&sock, &wrapper_dir, ("curl", &curl));

    let inp = dir.path().join("inp");
    let scr = dir.path().join("scr");
    let recon = dir.path().join("recon");
    std::fs::create_dir_all(inp.join("sub")).unwrap();
    let a_body = "x = 1\nif x:\n    print(\"a\")\n";
    let b_body = "def f():\n    return 2\n";
    let readme = "this is a non-py file\n";
    std::fs::write(inp.join("a.py"), a_body).unwrap();
    std::fs::write(inp.join("sub").join("b.py"), b_body).unwrap();
    std::fs::write(inp.join("README"), readme).unwrap();

    let cli = sibling_binary("babbleon-v2");

    // scramble-dir
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("scramble-dir")
        .arg("--input-dir")
        .arg(&inp)
        .arg("--output-dir")
        .arg(&scr)
        .output()
        .unwrap();
    if !out.status.success() {
        shutdown(child);
        panic!(
            "scramble-dir failed: stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("files_transformed: 2"),
        "stdout should report 2 files: {stdout}",
    );

    // Scrambled tree mirrors the input layout; non-.py files are
    // skipped.
    assert!(scr.join("a.py").exists());
    assert!(scr.join("sub").join("b.py").exists());
    assert!(!scr.join("README").exists(), "README must be skipped");

    // Layer-3 promise: no visible '\n' in any scrambled output.
    let scrambled_a = std::fs::read(scr.join("a.py")).unwrap();
    assert!(!scrambled_a.contains(&b'\n'));

    // unscramble-dir
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("unscramble-dir")
        .arg("--input-dir")
        .arg(&scr)
        .arg("--output-dir")
        .arg(&recon)
        .output()
        .unwrap();
    shutdown(child);
    assert!(
        out.status.success(),
        "unscramble-dir failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // Reconstructed sources are byte-identical to originals modulo
    // the MVP normalisations (trailing newline; canonical indent).
    let recon_a = std::fs::read_to_string(recon.join("a.py")).unwrap();
    assert_eq!(recon_a, a_body);
    let recon_b =
        std::fs::read_to_string(recon.join("sub").join("b.py")).unwrap();
    assert_eq!(recon_b, b_body);
}

/// `scramble` against a missing daemon socket must fail cleanly
/// with an actionable error pointing at the socket path.  Catches
/// regression where the CLI swallows the connect error or
/// segfaults.
#[test]
fn cli_scramble_against_missing_daemon_returns_actionable_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("does-not-exist.sock");
    let src_path = dir.path().join("src.py");
    std::fs::write(&src_path, "x = 1\n").unwrap();

    let cli = sibling_binary("babbleon-v2");
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(&sock)
        .arg("scramble")
        .arg("-i")
        .arg(&src_path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&sock.display().to_string())
            || stderr.contains("daemon")
            || stderr.contains("round-trip"),
        "stderr should reference the daemon / socket: {stderr}",
    );
}
