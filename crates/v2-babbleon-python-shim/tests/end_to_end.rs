//! End-to-end: spawn the real `babbleon-daemon`, scramble a Python
//! source via the daemon's compounds, then invoke
//! `babbleon-python` against the scrambled file and assert the
//! script ran (correct exit status, expected stdout).
//!
//! This is the closest the test suite gets to the production
//! invocation path: the only piece not exercised here is the
//! operator's actual install (PAM session, mount-namespace gate).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Find a sibling binary built by `cargo build` in the same target
/// directory as the test binary.
fn sibling_binary(name: &str) -> PathBuf {
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

fn find_python() -> Option<PathBuf> {
    for p in [
        "/usr/bin/python3",
        "/usr/local/bin/python3",
        "/opt/homebrew/bin/python3",
    ] {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }
    None
}

fn fake_real_binary(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(format!("real-{name}"));
    std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
        .unwrap();
    p
}

#[allow(clippy::zombie_processes)]
fn spawn_daemon(
    socket_path: &Path,
    wrapper_dir: &Path,
    tool: (&str, &Path),
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

/// Scramble `src.py` against the daemon by running `babbleon-v2
/// scramble`.  Writes the scrambled bytes to `out_path`.
fn scramble_with_daemon_cli(
    socket: &Path,
    src_path: &Path,
    out_path: &Path,
) {
    let cli = sibling_binary("babbleon-v2");
    let out = Command::new(&cli)
        .arg("--socket")
        .arg(socket)
        .arg("scramble")
        .arg("-i")
        .arg(src_path)
        .arg("-o")
        .arg(out_path)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scramble failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn shim_runs_scrambled_python_against_real_daemon() {
    let Some(python) = find_python() else {
        eprintln!("skipping: no python3 binary on conventional paths");
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");
    let daemon = spawn_daemon(&sock, &wrapper_dir, ("curl", &curl));

    let src_path = dir.path().join("src.py");
    let scr_path = dir.path().join("src.scr");
    // Use a script that exits non-zero so we can assert the shim
    // propagated the exit status (more robust than asserting on
    // stdout text, which depends on the python build's locale).
    let original =
        "import sys\nx = 1\nfor i in range(3):\n    x = x + i\nsys.exit(x)\n";
    std::fs::write(&src_path, original).unwrap();

    scramble_with_daemon_cli(&sock, &src_path, &scr_path);

    let shim = sibling_binary("babbleon-python");
    let out = Command::new(&shim)
        .arg("--socket")
        .arg(&sock)
        .arg("--python")
        .arg(&python)
        .arg(&scr_path)
        .output()
        .unwrap();
    shutdown(daemon);

    // x = 1 + 0 + 1 + 2 = 4
    assert_eq!(
        out.status.code(),
        Some(4),
        "shim exit code mismatch.  stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn shim_forwards_python_args_to_script_sys_argv() {
    let Some(python) = find_python() else {
        return;
    };

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");
    let daemon = spawn_daemon(&sock, &wrapper_dir, ("curl", &curl));

    let src_path = dir.path().join("src.py");
    let scr_path = dir.path().join("src.scr");
    // Exit 0 iff --flag-i-passed is in argv.
    let original = "import sys\nsys.exit(0 if \"--flag-i-passed\" in sys.argv else 33)\n";
    std::fs::write(&src_path, original).unwrap();

    scramble_with_daemon_cli(&sock, &src_path, &scr_path);

    let shim = sibling_binary("babbleon-python");
    let out = Command::new(&shim)
        .arg("--socket")
        .arg(&sock)
        .arg("--python")
        .arg(&python)
        .arg(&scr_path)
        .arg("--flag-i-passed")
        .output()
        .unwrap();
    shutdown(daemon);

    assert_eq!(
        out.status.code(),
        Some(0),
        "shim did not forward argv.  stderr={:?}",
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn shim_surfaces_daemon_locked_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = dir.path().join("real-curl");
    std::fs::write(&curl, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755))
        .unwrap();

    // Daemon Locked: no --insecure-stub-secret.
    let bin = sibling_binary("babbleon-daemon");
    #[allow(clippy::zombie_processes)]
    let mut daemon = Command::new(&bin)
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
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() && Instant::now() < deadline {
        if let Ok(Some(_)) = daemon.try_wait() {
            panic!("locked daemon exited early");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(sock.exists());

    // Write some dummy scrambled file (content doesn't matter; we
    // fail at the daemon round-trip).
    let scr_path = dir.path().join("dummy.scr");
    std::fs::write(&scr_path, "irrelevant").unwrap();

    let shim = sibling_binary("babbleon-python");
    let out = Command::new(&shim)
        .arg("--socket")
        .arg(&sock)
        .arg(&scr_path)
        .output()
        .unwrap();
    shutdown(daemon);

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("locked") || stderr.contains("Vault"),
        "stderr should mention daemon lock: {stderr}",
    );
}

#[test]
fn shim_fails_cleanly_on_missing_script() {
    let dir = tempfile::tempdir().unwrap();
    let nope = dir.path().join("does-not-exist.scr");

    let shim = sibling_binary("babbleon-python");
    let out = Command::new(&shim)
        .arg("--socket")
        .arg(dir.path().join("does-not-exist.sock"))
        .arg(&nope)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains(&nope.display().to_string())
            || stderr.contains("read"),
        "stderr should reference the missing path: {stderr}",
    );
    // Note: we don't `write!` to suppress unused; just rely on the
    // assertion above.
    let _ = std::io::stderr().write_all(b"");
}
