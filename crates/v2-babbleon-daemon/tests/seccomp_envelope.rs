//! End-to-end test: spawn the daemon with `--enable-seccomp` and
//! verify it serves the full operator sequence (status → emit →
//! rotate → emit) without tripping the filter.
//!
//! This is the **positive** test for the seccomp profile.  The
//! negative test (forbidden syscalls actually die) lives in
//! `seccomp_denies_forbidden.rs`.
//!
//! Why a separate integration test instead of extending
//! `end_to_end_binary.rs`:
//!
//! - The seccomp test spawns the daemon under a stricter envelope
//!   that one regression in the materialise / rotate path can
//!   immediately kill.  Keeping it isolated means a failure here
//!   stays attributable to seccomp drift.
//! - Future operator profiles may want to compare envelopes by
//!   running the same test against different `--enable-*` flags.
//!
//! The test is unconditional on Linux — `--enable-seccomp` is
//! always safe to pass; if the envelope is correct, the daemon
//! runs.  We skip on non-Linux because seccomp is a Linux primitive.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use babbleon_daemon_v2::{round_trip, Request, Response};

fn daemon_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_babbleon-daemon"))
}

fn fake_real_binary(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(format!("real-{name}"));
    std::fs::write(&p, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755))
        .unwrap();
    p
}

#[allow(clippy::zombie_processes)]
fn spawn_daemon_with_seccomp(
    socket_path: &Path,
    wrapper_dir: &Path,
    tools: &[(&str, &Path)],
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
        .arg("--enable-seccomp")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn babbleon-daemon");

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
            panic!(
                "daemon exited before binding (status={status}, \
                 enable-seccomp=true); stderr: {stderr}",
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!(
        "daemon (--enable-seccomp) did not create socket at {} within 5 s",
        socket_path.display(),
    );
}

fn shutdown(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn daemon_serves_full_operator_sequence_under_seccomp() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("daemon.sock");
    let wrapper_dir = dir.path().join("wrappers");
    std::fs::create_dir_all(&wrapper_dir).unwrap();
    let curl = fake_real_binary(dir.path(), "curl");
    let ssh = fake_real_binary(dir.path(), "ssh");

    let child = spawn_daemon_with_seccomp(
        &sock,
        &wrapper_dir,
        &[("curl", &curl), ("ssh", &ssh)],
    );

    // The daemon is now serving under the seccomp filter.  Every
    // syscall it issues from here on must be on the allowlist —
    // otherwise the kernel sends SIGSYS and the connect below
    // hangs.  We use the standard operator sequence: each request
    // exercises a different code path on the daemon side.

    // status — exercises accept4 / read / write / close / time +
    // identity calls (clock_gettime, getpid).
    match round_trip(&sock, &Request::Status) {
        Ok(Response::Status {
            epoch,
            tracked_count,
            ..
        }) => {
            assert_eq!(epoch, 0);
            assert_eq!(tracked_count, 2);
        }
        other => {
            shutdown(child);
            panic!("status under seccomp: expected Ok(Status), got {other:?}");
        }
    }

    // rotate-mapping — exercises the full materialise path: openat,
    // write, fchmod, close, getdents64, unlinkat, newfstatat/statx.
    // This is where the seccomp envelope is most load-bearing.
    match round_trip(&sock, &Request::RotateMapping) {
        Ok(Response::Rotated { new_epoch }) => assert_eq!(new_epoch, 1),
        other => {
            shutdown(child);
            panic!(
                "rotate under seccomp: expected Ok(Rotated), got {other:?}.  \
                 If this fails with a transport error, the daemon was killed \
                 by SIGSYS — diff strace against the envelope in \
                 docs/v2/daemon-seccomp-envelope.md",
            );
        }
    }

    // emit-activated-table — exercises the encoder path; also
    // confirms the daemon is still alive after the rotate (i.e. no
    // delayed SIGSYS from rotation).
    match round_trip(&sock, &Request::EmitActivatedTable) {
        Ok(Response::ActivatedTable { epoch, jsonl }) => {
            assert_eq!(epoch, 1);
            assert!(!jsonl.is_empty(), "activated table jsonl is empty");
        }
        other => {
            shutdown(child);
            panic!("emit under seccomp: expected ActivatedTable, got {other:?}");
        }
    }

    // get-whitespace-compounds — exercises HKDF + Permutation + string
    // concatenation for the whitespace mapping; pure compute, no new
    // syscalls beyond the read/write/close envelope already covered.
    // If this fails with a transport error, the daemon was killed by
    // SIGSYS — diff strace against the envelope in
    // docs/v2/daemon-seccomp-envelope.md.
    match round_trip(&sock, &Request::GetWhitespaceCompounds) {
        Ok(Response::WhitespaceCompounds { epoch, compounds }) => {
            assert_eq!(epoch, 1);
            assert_eq!(compounds.len(), 5);
            for c in &compounds {
                assert!(!c.is_empty(), "whitespace compound is empty");
                assert!(
                    c.bytes().all(|b| b.is_ascii_lowercase()),
                    "whitespace compound contains non-lowercase byte: {c:?}",
                );
            }
        }
        other => {
            shutdown(child);
            panic!(
                "get-whitespace-compounds under seccomp: expected \
                 Ok(WhitespaceCompounds), got {other:?}",
            );
        }
    }

    // Final liveness check.
    match round_trip(&sock, &Request::Status) {
        Ok(Response::Status { epoch, .. }) => assert_eq!(epoch, 1),
        other => {
            shutdown(child);
            panic!("post-rotate status under seccomp: {other:?}");
        }
    }

    shutdown(child);
}
