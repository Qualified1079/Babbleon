//! Rooted lifecycle tests.
//!
//! These tests exercise the launcher's privileged syscalls
//! (`unshare(NEWNS)`, `mount(2)` with `MS_BIND` and tmpfs,
//! `PR_CAPBSET_DROP`).  Each test:
//!
//! 1. Skips itself if `geteuid() != 0` so the unprivileged CI suite
//!    stays green.
//! 2. Runs inside a forked child so the parent test process keeps
//!    its original mount namespace.  This is mandatory: if the
//!    parent enters a new mount NS, every subsequent test inherits
//!    the new NS and may see unexpected state.
//!
//! Invocation:
//!
//! ```sh
//! sudo cargo test --test rooted_lifecycle -- --ignored
//! ```
//!
//! Or, more typically, the developer runs the harness inside a
//! disposable VM / nested-namespace container where they already
//! hold root and the host is not at risk.
//!
//! # Why each test is `#[ignore]`
//!
//! `cargo test` defaults to running every test in the file.  The
//! rooted tests require capabilities the default test runner does
//! not hold, so they would fail spuriously in unprivileged CI.
//! Marking them `#[ignore]` flips that default — they run only
//! when explicitly requested via `--ignored`.
//!
//! Within a `#[ignore]` test we also guard at runtime with
//! [`require_root`] so a developer running `--ignored` on an
//! unprivileged shell gets a clean SKIP rather than a confusing
//! `mount(2)` EPERM.

#![cfg(target_os = "linux")]

use std::path::PathBuf;

use babbleon_core_v2::{
    build_activated_table_from_mapping, MappingBuilder, PerHostSecret,
    Wordlist,
};

/// Test-harness exit code marking a deliberate skip (unprivileged
/// run).  Distinct from `0` (success) so a parent test runner that
/// wants to be strict can refuse to count skips as passes.
const SKIP_EXIT_CODE: u8 = 77;

/// Run `body` inside a forked child that enters a fresh mount
/// namespace before executing.  Propagates child exit status to
/// the parent test result.
///
/// The child should call `std::process::exit(0)` on success and a
/// non-zero code on failure.  Any panic aborts the child with
/// exit code 101 (Rust's default panic exit) which the parent
/// surfaces as a test failure.
fn run_in_forked_mount_ns<F: FnOnce() -> u8>(body: F) {
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};

    // SAFETY-equivalent reasoning: we are in a test harness, no
    // unsafe code is invoked here directly — nix's `fork` wraps
    // the unsafe libc::fork.  After fork the child has its own
    // process state; we restrict the child to one operation.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Enter the new mount NS *only* in the child.
            if let Err(e) = nix::sched::unshare(
                nix::sched::CloneFlags::CLONE_NEWNS,
            ) {
                eprintln!("rooted-test child: unshare(NEWNS): {e}");
                std::process::exit(2);
            }
            // Mark / private so our tmpfs mounts don't propagate
            // back to the test host.
            if let Err(e) = nix::mount::mount(
                None::<&str>,
                "/",
                None::<&str>,
                nix::mount::MsFlags::MS_PRIVATE | nix::mount::MsFlags::MS_REC,
                None::<&str>,
            ) {
                eprintln!("rooted-test child: mount(MS_PRIVATE,REC): {e}");
                std::process::exit(3);
            }
            let code = body();
            std::process::exit(i32::from(code));
        }
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => {}
                WaitStatus::Exited(_, code) => {
                    panic!("rooted-test child exited with code {code}");
                }
                other => panic!("rooted-test child status: {other:?}"),
            }
        }
        Err(e) => panic!("fork failed: {e}"),
    }
}

/// Returns `true` iff the current process is running as effective
/// UID 0.  When `false` the rooted tests print a SKIP message and
/// exit 0.
fn require_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Look up the mount-options field for the mount whose mount point
/// is exactly `path`, by reading `/proc/self/mountinfo`.  Returns the
/// LAST matching line's options (mountinfo lists mounts in the order
/// they were established, so the last match is the currently active
/// mount at that path — relevant when a path is mounted over more
/// than once, which doesn't happen in these tests but is cheap to
/// get right).
///
/// Field layout (see `proc_pid_mountinfo(5)`): mount ID, parent ID,
/// major:minor, root, mount point, mount options, then optional
/// fields, a literal `-` separator, filesystem type, mount source,
/// super options. Mount point is field index 4; mount options is
/// field index 5 (both 0-indexed, both before the optional fields so
/// their position is fixed regardless of how many optional fields a
/// given line has).
fn mount_options_for(path: &std::path::Path) -> Option<String> {
    let info = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let mut found = None;
    for line in info.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 6 {
            continue;
        }
        if std::path::Path::new(fields[4]) == path {
            found = Some(fields[5].to_string());
        }
    }
    found
}

#[test]
#[ignore = "requires root + Linux; runs only under `cargo test -- --ignored`"]
fn bind_mount_entries_succeeds_in_fresh_namespace() {
    if !require_root() {
        eprintln!("SKIP: rooted-test requires effective UID 0");
        return;
    }

    run_in_forked_mount_ns(|| {
        use v2_babbleon_launch_untrusted::mounts;

        // Build a small activated table pointing at /bin/sh as the
        // wrapper binary — we just want to verify the bind-mount
        // syscall succeeds and produces the expected metadata.
        let secret = PerHostSecret::from_bytes(&[1u8; 32]).unwrap();
        let wl = Wordlist::english_baseline();
        let tracked = vec!["curl".to_string(), "ssh".to_string()];
        let mapping = MappingBuilder::new(&secret, wl)
            .build(&tracked, 0)
            .unwrap();

        // Set up a scrambled-view tmpfs at a tempdir.
        let scrambled_root_holder = match tempfile::tempdir() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("tempdir: {e}");
                return 4;
            }
        };
        let scrambled_root: PathBuf = scrambled_root_holder.path().to_owned();
        if let Err(e) = nix::mount::mount(
            Some("tmpfs"),
            scrambled_root.as_path(),
            Some("tmpfs"),
            nix::mount::MsFlags::empty(),
            Some("mode=0555"),
        ) {
            eprintln!("tmpfs mount: {e}");
            return 5;
        }

        let table = match build_activated_table_from_mapping(
            &mapping,
            std::path::Path::new("/bin"),
        ) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("build_activated_table: {e}");
                return 6;
            }
        };
        // Rewrite every wrapper_path to /bin/sh — /bin/<scrambled>
        // does not exist; we just want a real file to bind.
        let mut table = table;
        for e in &mut table.entries {
            e.wrapper_path = PathBuf::from("/bin/sh");
        }

        if let Err(e) = mounts::bind_mount_entries(&scrambled_root, &table) {
            eprintln!("bind_mount_entries: {e}");
            return 7;
        }

        // Validate every scrambled name is a bound file with size
        // matching /bin/sh.
        let sh_size = std::fs::metadata("/bin/sh").unwrap().len();
        for entry in &table.entries {
            let target = scrambled_root.join(&entry.scrambled);
            let m = match std::fs::metadata(&target) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("metadata {}: {e}", target.display());
                    return 8;
                }
            };
            if m.len() != sh_size {
                eprintln!(
                    "size mismatch at {}: {} vs /bin/sh {}",
                    target.display(),
                    m.len(),
                    sh_size,
                );
                return 9;
            }
        }

        0
    });
}

#[test]
#[ignore = "requires root + Linux; runs only under `cargo test -- --ignored`"]
fn credential_gate_overlays_empty_tmpfs_on_each_discovered_dir() {
    if !require_root() {
        eprintln!("SKIP: rooted-test requires effective UID 0");
        return;
    }

    run_in_forked_mount_ns(|| {
        use babbleon_core_v2::discover_credential_dirs;
        use v2_babbleon_launch_untrusted::credential_gate;

        // Synthesise a "home" with two of the canonical cred dirs
        // populated.  The discovery walk should pick exactly those
        // two; the gate should overlay an empty tmpfs over each.
        let home_holder = match tempfile::tempdir() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("tempdir: {e}");
                return 4;
            }
        };
        let home = home_holder.path();
        let aws_dir = home.join(".aws");
        let kube_dir = home.join(".kube");
        std::fs::create_dir_all(&aws_dir).unwrap();
        std::fs::create_dir_all(&kube_dir).unwrap();
        // Drop a sentinel file in each; after the overlay it
        // should be invisible.
        std::fs::write(aws_dir.join("credentials"), b"REAL-SECRET").unwrap();
        std::fs::write(kube_dir.join("config"), b"REAL-KUBECONFIG").unwrap();

        let dirs = discover_credential_dirs(home);
        if dirs.len() != 2 {
            eprintln!("discover returned {} dirs; expected 2", dirs.len());
            return 5;
        }

        if let Err(e) =
            credential_gate::hide_credential_dirs_with_tmpfs(&dirs)
        {
            eprintln!("hide_credential_dirs_with_tmpfs: {e}");
            return 6;
        }

        // CIS-style hardening check: this decoy tmpfs never
        // legitimately needs devices, setuid execution, or exec at
        // all — confirm the mount actually carries all three
        // restrictions (see `credential_gate::mount_one`).
        for dir in &dirs {
            let opts = match mount_options_for(dir) {
                Some(o) => o,
                None => {
                    eprintln!("no mountinfo entry found for {}", dir.display());
                    return 10;
                }
            };
            for want in ["nosuid", "nodev", "noexec"] {
                if !opts.split(',').any(|o| o == want) {
                    eprintln!(
                        "credential-gate tmpfs at {} missing '{want}' (opts: {opts})",
                        dir.display()
                    );
                    return 11;
                }
            }
        }

        // Post-overlay: each dir exists but is empty.  The
        // sentinel file must be inaccessible (overlay shadows it).
        for dir in &dirs {
            let entries: Vec<_> =
                std::fs::read_dir(dir).unwrap().collect();
            if !entries.is_empty() {
                eprintln!(
                    "{} should be empty after overlay; has {} entries",
                    dir.display(),
                    entries.len(),
                );
                return 7;
            }
        }

        // Final assertion: the sentinel files cannot be opened.
        // open(2) returns ENOENT because the overlay shadows them.
        if std::fs::read(aws_dir.join("credentials")).is_ok() {
            eprintln!(".aws/credentials should be unreadable after overlay");
            return 8;
        }
        if std::fs::read(kube_dir.join("config")).is_ok() {
            eprintln!(".kube/config should be unreadable after overlay");
            return 9;
        }

        0
    });
}

#[test]
#[ignore = "requires root + Linux; runs only under `cargo test -- --ignored`"]
fn scrambled_view_tmpfs_sets_nosuid_and_nodev_but_allows_exec() {
    if !require_root() {
        eprintln!("SKIP: rooted-test requires effective UID 0");
        return;
    }

    run_in_forked_mount_ns(|| {
        use v2_babbleon_launch_untrusted::mounts;

        // `mount_scrambled_view_tmpfs` hard-codes `SCRAMBLED_ROOT`
        // ("/run/babbleon/scrambled"); a real install pre-creates it.
        // Creating it here is safe: we're inside a forked child that
        // already entered a private mount namespace, so the mount
        // this test performs never becomes visible outside this
        // child. The directory creation itself (not the mount) does
        // land on the real filesystem, matching what a real
        // installer does.
        if let Err(e) = std::fs::create_dir_all(mounts::SCRAMBLED_ROOT) {
            eprintln!("create_dir_all({}): {e}", mounts::SCRAMBLED_ROOT);
            return 4;
        }

        if let Err(e) = mounts::mount_scrambled_view_tmpfs() {
            eprintln!("mount_scrambled_view_tmpfs: {e}");
            return 5;
        }

        let opts = match mount_options_for(std::path::Path::new(mounts::SCRAMBLED_ROOT)) {
            Some(o) => o,
            None => {
                eprintln!("no mountinfo entry found for {}", mounts::SCRAMBLED_ROOT);
                return 6;
            }
        };
        for want in ["nosuid", "nodev"] {
            if !opts.split(',').any(|o| o == want) {
                eprintln!("scrambled-view tmpfs missing '{want}' (opts: {opts})");
                return 7;
            }
        }
        // The one flag that must NOT be set: the child execs wrapper
        // scripts out of this tmpfs, so noexec would break Babbleon.
        if opts.split(',').any(|o| o == "noexec") {
            eprintln!("scrambled-view tmpfs must stay executable (opts: {opts})");
            return 8;
        }

        0
    });
}

#[test]
#[ignore = "requires root + Linux"]
fn unprivileged_skip_returns_quickly() {
    // Sanity check: when the test runs without root the SKIP path
    // is taken and the test exits without doing anything dangerous.
    if !require_root() {
        eprintln!("SKIP: rooted-test requires effective UID 0");
        std::process::exit(i32::from(SKIP_EXIT_CODE));
    }
    // If we got here we ARE root — the test is a no-op success.
}
