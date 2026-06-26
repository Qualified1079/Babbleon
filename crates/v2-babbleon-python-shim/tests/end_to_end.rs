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

/// Locate a sibling binary cargo built for this test harness.
///
/// Strategy:
///
/// 1. **`CARGO_BIN_EXE_<name>`** — set by cargo automatically for
///    every `[[bin]]` target in **this** package.  Covers
///    `babbleon-python`.
/// 2. **target-dir lookup** — `target/<profile>/<name>` relative to
///    the test binary.  Covers sibling-workspace binaries
///    (`babbleon-v2`, `babbleon-daemon`) once they have been built.
/// 3. **self-bootstrap** — if step 2 misses, invoke
///    `cargo build -p <package> --bin <name>` synchronously.  Avoids
///    the `cargo build --workspace` recommendation CLAUDE.md forbids
///    (it would compile the deprecated v1 lineage).
///
/// Adding a new binary: extend `cargo_package_for` so the bootstrap
/// fallback knows which `-p` to pass.
fn sibling_binary(name: &str) -> PathBuf {
    if let Some(p) = env_bin_exe(name) {
        return PathBuf::from(p);
    }
    let target_path = target_dir_binary(name);
    if target_path.exists() {
        return target_path;
    }
    bootstrap_via_cargo_build(name);
    let after = target_dir_binary(name);
    assert!(
        after.exists(),
        "after cargo build the binary still does not exist at {} — \
         cargo did not produce the expected `target/<profile>/<name>` artefact",
        after.display(),
    );
    after
}

/// Resolve `CARGO_BIN_EXE_<name>` at compile time.  Cargo only sets
/// this for binaries in **this** package.
fn env_bin_exe(name: &str) -> Option<&'static str> {
    match name {
        "babbleon-python" => option_env!("CARGO_BIN_EXE_babbleon-python"),
        _ => None,
    }
}

/// Compute `target/<profile>/<name>` from the test binary's location.
fn target_dir_binary(name: &str) -> PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    p.pop(); // deps/
    p.pop(); // <profile>/
    p.push(name);
    p
}

/// Synchronously invoke `cargo build -p <package> --bin <name>` to
/// produce a sibling-package binary into the workspace target dir.
/// Cargo's lockfile serialises concurrent invocations so this is
/// safe to call from parallel tests.
fn bootstrap_via_cargo_build(name: &str) {
    let pkg = cargo_package_for(name).unwrap_or_else(|| {
        panic!(
            "no cargo package registered for binary `{name}` — \
             extend cargo_package_for() in this test file to add the mapping",
        )
    });
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(&cargo)
        .args(["build", "-p", pkg, "--bin", name])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("spawn cargo build for sibling binary");
    assert!(
        status.success(),
        "cargo build -p {pkg} --bin {name} failed with {status}",
    );
}

/// Map a binary `name` to its producing cargo package name.  Add an
/// entry when a new sibling-workspace binary is exercised.
fn cargo_package_for(name: &str) -> Option<&'static str> {
    match name {
        "babbleon-v2" => Some("v2-babbleon"),
        "babbleon-daemon" => Some("v2-babbleon-daemon"),
        _ => None,
    }
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

/// End-to-end signal forwarding: `kill -TERM <shim_pid>` should reach
/// the child python.  Discriminator: a script that traps SIGTERM and
/// exits with a known code (42).  Without forwarding, SIGTERM kills
/// the shim via its default disposition (exit code 143 = 128 + 15)
/// and the python child is orphaned to init.  With forwarding, the
/// shim blocks SIGTERM, the forwarder thread sigwaits it and re-
/// delivers to the child PID, python's handler fires, python exits
/// 42, the shim's `wait()` returns that status, and the shim's own
/// exit code is 42.
#[test]
fn shim_forwards_sigterm_to_child_python() {
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

    let src_path = dir.path().join("trap.py");
    let scr_path = dir.path().join("trap.scr");
    // Trap SIGTERM, exit 42 on receipt.  Print a "ready" marker
    // (flushed) before sleeping so the test thread can wait for the
    // child to be in its handler-installed loop before firing.
    let original = "\
import sys, signal, time
def handler(signum, frame):
    sys.exit(42)
signal.signal(signal.SIGTERM, handler)
print('ready', flush=True)
time.sleep(30)
sys.exit(99)
";
    std::fs::write(&src_path, original).unwrap();
    scramble_with_daemon_cli(&sock, &src_path, &scr_path);

    let shim = sibling_binary("babbleon-python");
    let mut child = Command::new(&shim)
        .arg("--socket")
        .arg(&sock)
        .arg("--python")
        .arg(&python)
        .arg(&scr_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn babbleon-python");

    // Wait for python's "ready" line, which tells us the trap
    // handler is installed and the script is in the sleep loop.
    let stdout = child.stdout.take().expect("piped stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let read_deadline = Instant::now() + Duration::from_secs(10);
    while line.trim() != "ready" {
        line.clear();
        let read = reader
            .read_line(&mut line)
            .expect("read shim stdout");
        if read == 0 {
            // EOF before ready: shim or child died early.
            let mut stderr = String::new();
            if let Some(mut s) = child.stderr.take() {
                use std::io::Read;
                let _ = s.read_to_string(&mut stderr);
            }
            shutdown(daemon);
            panic!(
                "shim never printed 'ready' (child died early?). stderr: {stderr}",
            );
        }
        if Instant::now() > read_deadline {
            let _ = child.kill();
            shutdown(daemon);
            panic!("timed out waiting for python ready line");
        }
    }

    // Python is in `time.sleep(30)` with the SIGTERM trap armed.
    // Send SIGTERM to the SHIM.  If forwarding is correctly wired,
    // the shim's main thread blocks it, the forwarder thread
    // sigwaits + re-delivers to python's pid, python's handler
    // fires, python exits 42, shim's wait returns 42, shim exits
    // with code 42.
    let shim_pid = i32::try_from(child.id()).unwrap();
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(shim_pid),
        nix::sys::signal::Signal::SIGTERM,
    )
    .expect("deliver SIGTERM to shim");

    let status = wait_with_timeout(&mut child, Duration::from_secs(10))
        .expect("shim hung after SIGTERM forward");
    shutdown(daemon);

    assert_eq!(
        status.code(),
        Some(42),
        "shim exit code mismatch — forwarder did not reach child python.  \
         status: {status:?}",
    );
}

/// Wait on `child` with a wall-clock timeout.
///
/// Polls `try_wait` every 25 ms up to `dur`.  Returns the child's
/// status on exit, or `None` on timeout (caller responsible for
/// killing the child in that case).
fn wait_with_timeout(
    child: &mut Child,
    dur: Duration,
) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + dur;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(_) => return None,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    None
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
