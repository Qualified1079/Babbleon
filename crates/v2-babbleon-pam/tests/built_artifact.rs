//! Integration test: the `.so` artifact is produced.
//!
//! `build.rs` compiles `src/pam_babbleon.c` into `pam_babbleon.so`
//! at `target/<profile>/`.  This test asserts the artifact exists
//! and is non-empty.  If the build host lacks `libpam0g-dev`, the
//! `build.rs` skips compilation and prints `cargo:warning=...`; in
//! that case this test is skipped (with a clear message), not
//! failed — refusing to test on a developer box without libpam-dev
//! would block iteration on the v2 crates that don't need PAM at
//! all.
//!
//! The `.so` itself is intentionally NOT load-tested here: PAM
//! loads modules under `pam_handle_t` machinery that only a real
//! PAM stack provides.  Loading the `.so` standalone via `dlopen(3)`
//! is possible but introduces a runtime dep on libpam at test time,
//! again hurting workspace-wide iteration.  Load-testing lives in
//! the rooted-test harness (filed for follow-up).

use std::path::PathBuf;

fn target_so_path() -> Option<PathBuf> {
    // CARGO_TARGET_TMPDIR points at `target/<profile>/tmp/<crate>`;
    // we walk up to `target/<profile>/`.
    let tmpdir = std::env::var_os("CARGO_TARGET_TMPDIR")?;
    let target_profile = std::path::Path::new(&tmpdir)
        .ancestors()
        .nth(2)?
        .to_path_buf();
    Some(target_profile.join("pam_babbleon.so"))
}

#[test]
fn so_artifact_exists_when_libpam_dev_present() {
    let Some(path) = target_so_path() else {
        // CARGO_TARGET_TMPDIR is set by cargo for integration tests
        // since 1.54; absence indicates a deeply non-standard
        // invocation we can't reason about.
        eprintln!(
            "test skipped: CARGO_TARGET_TMPDIR not set; cannot locate \
             target/<profile>/pam_babbleon.so",
        );
        return;
    };

    if !path.exists() {
        // build.rs printed a cargo:warning explaining why; do not
        // fail the test (libpam-dev is an optional toolchain dep).
        eprintln!(
            "test skipped: {} not built — see build.rs cargo:warning \
             output (likely libpam-dev / cc absent on this host)",
            path.display(),
        );
        return;
    }

    let meta = std::fs::metadata(&path).expect("stat on built .so");
    assert!(
        meta.is_file(),
        "{} should be a regular file, got {meta:?}",
        path.display()
    );
    assert!(
        meta.len() > 0,
        "{} should be non-empty, got {} bytes",
        path.display(),
        meta.len()
    );
}

#[test]
fn so_artifact_starts_with_elf_magic_when_present() {
    let Some(path) = target_so_path() else { return };
    if !path.exists() {
        return;
    }
    let bytes = std::fs::read(&path).expect("read built .so");
    // ELF magic: 0x7F 'E' 'L' 'F'.  A correctly-built PAM module on
    // Linux is an ELF shared object.
    assert!(
        bytes.len() >= 4,
        "{} too short to be an ELF file",
        path.display()
    );
    assert_eq!(
        &bytes[..4],
        b"\x7FELF",
        "{} does not start with ELF magic; build pipeline produced a \
         non-ELF file",
        path.display(),
    );
}

#[test]
fn so_artifact_carries_bind_now_when_present() {
    // Regression guard: -Wl,-z,now in build.rs produces a `DT_FLAGS`
    // dynamic entry with `BIND_NOW` set.  Without it the PAM module's
    // GOT is writable until first symbol resolution; a future shim
    // function pointer overwrite gadget would survive.
    //
    // We test by spawning `readelf -d` and grepping for `BIND_NOW`.
    // The test skips when readelf is unavailable rather than failing
    // — CI hosts without binutils should still be able to run cargo
    // test against this crate.
    let Some(path) = target_so_path() else { return };
    if !path.exists() {
        return;
    }
    let output = match std::process::Command::new("readelf")
        .args(["-d"])
        .arg(&path)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "test skipped: readelf not on PATH ({e}); cannot verify BIND_NOW"
            );
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("BIND_NOW"),
        "pam_babbleon.so does not carry BIND_NOW — build.rs hardening regressed.\n\
         readelf -d output:\n{stdout}",
    );
}

#[test]
fn so_artifact_has_noexec_stack_when_present() {
    // Regression guard: -Wl,-z,noexecstack produces `RW` (no `E`) on
    // the GNU_STACK program header.
    let Some(path) = target_so_path() else { return };
    if !path.exists() {
        return;
    }
    let output = match std::process::Command::new("readelf")
        .args(["-l"])
        .arg(&path)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!(
                "test skipped: readelf not on PATH ({e}); cannot verify GNU_STACK"
            );
            return;
        }
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The GNU_STACK line is followed by a flags line; presence of
    // `GNU_STACK` indicates the segment was emitted.  We then scan
    // the dump for a flag line that's `RW` (no `E`) appearing after
    // GNU_STACK.  This is approximate but catches the regression
    // mode we care about (someone deletes the noexecstack flag and
    // ld produces an executable stack).
    assert!(
        stdout.contains("GNU_STACK"),
        "pam_babbleon.so is missing GNU_STACK segment entirely (very old binutils?)",
    );
    let after_gnu_stack = stdout
        .split("GNU_STACK")
        .nth(1)
        .expect("GNU_STACK segment present");
    // Look at the flags column on the first few lines after GNU_STACK
    // for an `E`.  Walk only the bytes through the next blank line so
    // we don't accidentally pick up an `E` from a later segment's
    // flags.
    let next_segment_start =
        after_gnu_stack.find("\n\n").unwrap_or(after_gnu_stack.len());
    let segment = &after_gnu_stack[..next_segment_start];
    let executable = segment
        .lines()
        .filter_map(|line| line.split_whitespace().find(|tok| *tok == "RWE"));
    assert!(
        executable.count() == 0,
        "pam_babbleon.so has an executable stack — build.rs hardening regressed.\n\
         GNU_STACK segment:\n{segment}",
    );
}
