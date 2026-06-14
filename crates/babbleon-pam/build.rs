//! Compiles `pam_babbleon.so` from the C source.
//!
//! Output: `target/<profile>/pam_babbleon.so`.  Install with:
//!   install -m 0644 pam_babbleon.so /lib/security/
//! then add to a PAM stack (e.g. /etc/pam.d/common-session):
//!   session optional pam_babbleon.so

#[cfg(target_os = "linux")]
fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let target_dir = std::path::Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .expect("target dir from OUT_DIR")
        .to_path_buf();

    let src = "src/pam_babbleon.c";
    println!("cargo:rerun-if-changed={src}");

    let status = std::process::Command::new("cc")
        .args([
            "-fPIC",
            "-shared",
            "-Wall",
            "-Wextra",
            "-O2",
            "-o",
        ])
        .arg(target_dir.join("pam_babbleon.so"))
        .arg(src)
        .args(["-lpam"])
        .status();

    match status {
        Ok(s) if s.success() => {
            println!("cargo:warning=built {}/pam_babbleon.so", target_dir.display());
        }
        Ok(s) => {
            println!("cargo:warning=pam_babbleon build failed (exit {s}); install libpam-dev to enable");
        }
        Err(e) => {
            println!("cargo:warning=cc not available ({e}); skipping pam_babbleon");
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("cargo:warning=babbleon-pam: skipped on non-Linux");
}
