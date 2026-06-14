//! Banner-spoofing wrapper generator.
//!
//! Generates a tiny shell script per scrambled name that:
//!   - Returns empty output for --help / -V / --version when called from
//!     the untrusted namespace (tier check via /proc/self/ns/mnt inode).
//!   - Passes through to the real binary with original output in the trusted NS.
//!   - Embeds per-host SHA-256 padding to defeat hash-based fingerprinting
//!     (ObserverWard, WhatWeb, Wappalyzer signature DBs).
//!
//! M3.5 upgrade path: replace the shell template with a stripped static Rust
//! binary so the wrapper body itself leaks no identifiable content.

use crate::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Shell template with banner deception.
///
/// Fields:
/// {padding}      — per-host 16-byte hex; changes per scrambled name
/// {real_path}    — absolute path to the real binary
/// {ns_inode}     — trusted mount-NS inode; 0 = no tier check (always-null)
/// {decoy_banner} — plausible wrong help text; empty = silent
const TEMPLATE: &str = r#"#!/bin/sh
# babbleon wrapper (host-pad:{padding})
_BL_REAL="{real_path}"
_BL_NS_INODE="{ns_inode}"
_in_trusted_ns() {
    _cur=$(stat -Lc '%i' /proc/self/ns/mnt 2>/dev/null) || return 1
    [ "$_cur" = "$_BL_NS_INODE" ]
}
case "$1" in
    --help|--version|-h|-V|-help|-version)
        if ! _in_trusted_ns; then
            printf '%s\n' '{decoy_banner}'
            exit 0
        fi
        ;;
esac
exec "$_BL_REAL" "$@"
"#;

fn padding(scrambled: &str, host_secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(host_secret);
    h.update(scrambled.as_bytes());
    hex::encode(&h.finalize()[..16])
}

pub fn write_wrapper(
    real_name: &str,
    scrambled: &str,
    real_path: &Path,
    output_dir: &Path,
    host_secret: &[u8],
    trusted_ns_inode: Option<u64>,
    decoy_banner: Option<&str>,
) -> Result<PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    let wp = output_dir.join(scrambled);
    let inode_str = trusted_ns_inode
        .map(|i| i.to_string())
        .unwrap_or_else(|| "0".to_string());
    // Escape single quotes in decoy banner for sh printf.
    let decoy = decoy_banner.unwrap_or("").replace('\'', "'\\''");
    let _ = real_name; // may be used by caller to look up deception table
    let contents = TEMPLATE
        .replace("{padding}", &padding(scrambled, host_secret))
        .replace("{real_path}", &real_path.display().to_string())
        .replace("{ns_inode}", &inode_str)
        .replace("{decoy_banner}", &decoy);
    std::fs::write(&wp, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wp, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(wp)
}

/// FIFO path where honey-name wrappers report access events.
pub const HONEY_FIFO: &str = "/run/babbleon/honey.fifo";

/// Shell template for a honey-name wrapper.
///
/// When executed (from any tier), it:
///   1. Writes a minimal JSON event to HONEY_FIFO (non-blocking; fails silently if no reader).
///   2. Exits 127 — "command not found" — so the caller sees a plausible missing-binary error.
///
/// The trusted-tier daemon reads from HONEY_FIFO and emits `Event::HoneyTriggered`.
const HONEY_TEMPLATE: &str = r#"#!/bin/sh
# babbleon honey-wrapper (host-pad:{padding})
_BL_HONEY="{honey_name}"
_BL_FIFO="{fifo}"
_ts=$(date -u +%s 2>/dev/null || echo 0)
_pid=$$
printf '{"ts":%s,"pid":%s,"honey":"%s","args":"%s"}\n' \
    "$_ts" "$_pid" "$_BL_HONEY" "$*" \
    >> "$_BL_FIFO" 2>/dev/null || true
exit 127
"#;

/// Write a honey-name wrapper script.
///
/// The wrapper does not exec any real binary — the scrambled name maps to
/// nothing real.  On execution it appends a JSON line to `HONEY_FIFO` and
/// returns exit code 127.
pub fn write_honey_wrapper(
    honey_name: &str,
    output_dir: &Path,
    host_secret: &[u8],
    fifo: Option<&str>,
) -> Result<PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    let wp = output_dir.join(honey_name);
    let fifo_path = fifo.unwrap_or(HONEY_FIFO);
    let contents = HONEY_TEMPLATE
        .replace("{padding}", &padding(honey_name, host_secret))
        .replace("{honey_name}", honey_name)
        .replace("{fifo}", fifo_path);
    std::fs::write(&wp, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wp, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(wp)
}

/// Write honey-name wrapper scripts for every name in `honey_names`.
pub fn write_honey_wrappers<'a, I>(
    honey_names: I,
    output_dir: &Path,
    host_secret: &[u8],
) -> Result<Vec<PathBuf>>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut out = Vec::new();
    for name in honey_names {
        let p = write_honey_wrapper(name, output_dir, host_secret, None)?;
        out.push(p);
    }
    Ok(out)
}

/// Write wrapper scripts for all entries in the mapping.
///
/// `deception_fn` — optional lookup: given the real tool name, returns
/// a banner string to emit in the untrusted namespace.  Pass `|_| None`
/// to use silent mode (empty output for --help).
pub fn write_all<I, S, F>(
    mapping_iter: I,
    real_root: &Path,
    output_dir: &Path,
    host_secret: &[u8],
    trusted_ns_inode: Option<u64>,
    deception_fn: F,
) -> Result<std::collections::HashMap<String, PathBuf>>
where
    I: IntoIterator<Item = (S, S)>,
    S: AsRef<str>,
    F: Fn(&str) -> Option<&'static str>,
{
    let mut out = std::collections::HashMap::new();
    for (real, scrambled) in mapping_iter {
        let real_s = real.as_ref();
        let scrambled_s = scrambled.as_ref();
        let src = real_root.join(real_s);
        if !src.exists() {
            continue;
        }
        let decoy = deception_fn(real_s);
        let p = write_wrapper(
            real_s,
            scrambled_s,
            &src,
            output_dir,
            host_secret,
            trusted_ns_inode,
            decoy,
        )?;
        out.insert(scrambled_s.to_string(), p);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_host_padding_differs() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("curl");
        std::fs::write(&real, "#!/bin/sh\n").unwrap();
        let a = write_wrapper(
            "curl",
            "name",
            &real,
            &dir.path().join("a"),
            &[1u8; 32],
            None,
            None,
        )
        .unwrap();
        let b = write_wrapper(
            "curl",
            "name",
            &real,
            &dir.path().join("b"),
            &[2u8; 32],
            None,
            None,
        )
        .unwrap();
        assert_ne!(
            std::fs::read_to_string(a).unwrap(),
            std::fs::read_to_string(b).unwrap()
        );
    }

    #[test]
    fn trusted_ns_inode_embedded() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("curl");
        std::fs::write(&real, "#!/bin/sh\n").unwrap();
        let wp = write_wrapper(
            "curl",
            "testname",
            &real,
            dir.path(),
            b"secret",
            Some(12345),
            None,
        )
        .unwrap();
        let contents = std::fs::read_to_string(wp).unwrap();
        assert!(contents.contains("12345"));
    }

    #[test]
    fn honey_wrapper_exits_127() {
        let dir = tempfile::tempdir().unwrap();
        let tmp_fifo = dir.path().join("honey.fifo");
        let wp = write_honey_wrapper(
            "xq-marble-fern",
            dir.path(),
            b"secret",
            Some(tmp_fifo.to_str().unwrap()),
        )
        .unwrap();
        let status = std::process::Command::new("sh")
            .arg(&wp)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status()
            .unwrap();
        assert_eq!(
            status.code(),
            Some(127),
            "honey wrapper must exit 127 (command not found)"
        );
    }

    #[test]
    fn honey_wrapper_writes_to_fifo_file() {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        // Use a regular file instead of a real FIFO so we can read it after exec
        let log_file = dir.path().join("honey.log");
        let wp = write_honey_wrapper(
            "xq-marble-fern",
            dir.path(),
            b"secret",
            Some(log_file.to_str().unwrap()),
        )
        .unwrap();
        std::process::Command::new("sh")
            .arg(&wp)
            .arg("--list")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status()
            .unwrap();
        let mut content = String::new();
        std::fs::File::open(&log_file)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(
            content.contains("xq-marble-fern"),
            "honey name must appear in log: {content:?}"
        );
        // Should be valid JSON
        let _: serde_json::Value =
            serde_json::from_str(content.trim()).expect("honey log must be valid JSON");
    }

    #[test]
    fn decoy_banner_embedded_in_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("curl");
        std::fs::write(&real, "#!/bin/sh\n").unwrap();
        let wp = write_wrapper(
            "curl",
            "scrambled-name",
            &real,
            dir.path(),
            b"s",
            None,
            Some("less [OPTION]... [FILE]...\n"),
        )
        .unwrap();
        let contents = std::fs::read_to_string(wp).unwrap();
        assert!(
            contents.contains("less"),
            "decoy banner not in wrapper: {contents}"
        );
    }
}
