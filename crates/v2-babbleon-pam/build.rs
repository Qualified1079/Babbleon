//! Builds `pam_babbleon.so` from the C source.
//!
//! Output: `target/<profile>/pam_babbleon.so`.  Install with:
//!
//! ```text
//! install -m 0644 pam_babbleon.so /lib/security/
//! ```
//!
//! then add to a PAM stack (for example, `/etc/pam.d/common-session`):
//!
//! ```text
//! session optional pam_babbleon.so
//! ```
//!
//! `optional` (not `required`) is deliberate: a Babbleon failure must
//! NOT lock a user out of their own host.  The C shim returns
//! `PAM_SUCCESS` even when the launcher exec fails (and writes the
//! failure to syslog) so a regression cannot brick a login.
//!
//! # Configurable paths
//!
//! `build.rs` reads two environment variables at build time and
//! bakes them into the C source via `-D` macros:
//!
//! - `BABBLEON_LAUNCH_UNTRUSTED_PATH` — absolute path to the
//!   `babbleon-launch-untrusted` binary.  Default
//!   `/usr/local/libexec/babbleon-launch-untrusted`.
//! - `BABBLEON_DAEMON_SOCKET_PATH` — absolute path to the daemon's
//!   Unix socket.  Default `/run/babbleon/daemon.sock`.  Must match
//!   the `default_socket_path()` constant in
//!   `v2-babbleon-daemon-protocol/src/socket_path.rs`.
//!
//! # Skip behaviour
//!
//! - **Non-Linux host:** PAM is Linux-only; build emits a `cargo:warning`
//!   and skips compilation.
//! - **`cc` not on `$PATH`:** ditto.
//! - **`libpam-dev` headers missing:** ditto.  The Rust stub library
//!   still builds, so `cargo check -p v2-babbleon-pam` succeeds on a
//!   developer box without libpam-dev — only the `.so` is missing.
//!
//! Failure paths log a `cargo:warning` instead of failing the build,
//! because every other v2 crate in the workspace must build on any
//! host where the maintainer is working — locking the whole workspace
//! to libpam-dev would burn iteration speed.

#[cfg(target_os = "linux")]
fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set by cargo");
    // OUT_DIR is e.g. `target/<profile>/build/<crate-hash>/out`.  We
    // walk three ancestors up to `target/<profile>/` so the installed
    // location is alongside the other binaries.
    let target_dir = std::path::Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .expect("target dir derivable from OUT_DIR")
        .to_path_buf();

    let src = "src/pam_babbleon.c";
    println!("cargo:rerun-if-changed={src}");
    println!("cargo:rerun-if-env-changed=BABBLEON_LAUNCH_UNTRUSTED_PATH");
    println!("cargo:rerun-if-env-changed=BABBLEON_DAEMON_SOCKET_PATH");

    let launch_path = std::env::var("BABBLEON_LAUNCH_UNTRUSTED_PATH")
        .unwrap_or_else(|_| {
            "/usr/local/libexec/babbleon-launch-untrusted".into()
        });
    let socket_path = std::env::var("BABBLEON_DAEMON_SOCKET_PATH")
        .unwrap_or_else(|_| "/run/babbleon/daemon.sock".into());

    if launch_path.contains('"') || socket_path.contains('"') {
        println!(
            "cargo:warning=babbleon-pam: configured path contains a double-quote \
             (unsafe to embed in the C source); skipping pam_babbleon build"
        );
        return;
    }

    let out_so = target_dir.join("pam_babbleon.so");
    let status = std::process::Command::new("cc")
        .args(["-fPIC", "-shared", "-Wall", "-Wextra", "-Werror", "-O2"])
        .arg(format!(
            "-DBABBLEON_LAUNCH_UNTRUSTED_PATH=\"{launch_path}\""
        ))
        .arg(format!(
            "-DBABBLEON_DAEMON_SOCKET_PATH=\"{socket_path}\""
        ))
        .args(["-o"])
        .arg(&out_so)
        .arg(src)
        .args(["-lpam"])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!(
                "cargo:warning=babbleon-pam: built {} \
                 (launch={launch_path}, socket={socket_path})",
                out_so.display(),
            );
        }
        Ok(s) => {
            println!(
                "cargo:warning=babbleon-pam: pam_babbleon build failed (exit {s}); \
                 install libpam0g-dev (Debian/Ubuntu) or libpam-devel (RHEL) to enable"
            );
        }
        Err(e) => {
            println!(
                "cargo:warning=babbleon-pam: `cc` not available ({e}); \
                 skipping pam_babbleon build"
            );
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!(
        "cargo:warning=babbleon-pam: PAM is Linux-only; skipped on this platform"
    );
}
