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
