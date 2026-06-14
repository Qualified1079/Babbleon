//! Banner-spoofing wrapper generator.
//!
//! Generates a tiny shell script per scrambled name that:
//!   - Returns empty output for --help / -V / --version when called from
//!     the untrusted namespace (tier check via /proc/self/ns/mnt inode).
//!   - Passes through to the real binary with original output in the trusted NS.
//!   - Embeds per-host SHA-256 padding to defeat hash-based fingerprinting
//!     (ObserverWard, WhatWeb, Wappalyzer signature DBs).
//!
//! # Uniform-size guarantee
//!
//! Both honey-name wrappers and real-tool wrappers use the SAME shell template.
//! The distinction is made at runtime via `/run/babbleon/honey.list` — if the
//! wrapper's own name appears there it logs to the FIFO and exits 127; otherwise
//! it performs the normal trusted-NS check and execs the real binary.  This
//! eliminates the size-class fingerprint that `ls -la` would otherwise expose
//! (honey ~350 B vs real-tool ~510 B+).
//!
//! M3.5 upgrade path: replace the shell template with a stripped static Rust
//! binary so the wrapper body itself leaks no identifiable content.

use crate::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// FIFO path where honey-name wrappers report access events.
pub const HONEY_FIFO: &str = "/run/babbleon/honey.fifo";

/// File listing one honey name per line; written by `write_honey_list`.
pub const HONEY_LIST: &str = "/run/babbleon/honey.list";

/// Unified shell template used for BOTH honey and real-tool wrappers.
///
/// Fields:
/// {padding}      — per-host 16-byte hex; unique per name × secret
/// {self_name}    — the scrambled (or honey) name of this wrapper
/// {real_path}    — absolute path to the real binary (empty for honey)
/// {ns_inode}     — trusted mount-NS inode; 0 = no tier check
/// {honey_list}   — path to honey.list file
/// {honey_fifo}   — path to honey.fifo
/// {decoy_banner} — plausible wrong help text; empty = silent
const TEMPLATE: &str = r#"#!/bin/sh
# babbleon wrapper (host-pad:{padding})
_BL_NAME="{self_name}"
_BL_REAL="{real_path}"
_BL_NS_INODE="{ns_inode}"
_BL_HONEY_LIST="{honey_list}"
_BL_FIFO="{honey_fifo}"
_in_trusted_ns() {
    _cur=$(stat -Lc '%i' /proc/self/ns/mnt 2>/dev/null) || return 1
    [ "$_cur" = "$_BL_NS_INODE" ]
}
_is_honey() {
    grep -qxF "$_BL_NAME" "$_BL_HONEY_LIST" 2>/dev/null
}
if _is_honey; then
    _ts=$(date -u +%s 2>/dev/null || echo 0)
    printf '{"ts":%s,"pid":%s,"honey":"%s","args":"%s"}\n' \
        "$_ts" "$$" "$_BL_NAME" "$*" >> "$_BL_FIFO" 2>/dev/null || true
    exit 127
fi
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

fn wrapper_padding(name: &str, host_secret: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(host_secret);
    h.update(name.as_bytes());
    hex::encode(&h.finalize()[..16])
}

fn render(
    name: &str,
    real_path: &str,
    ns_inode: &str,
    honey_list: &str,
    honey_fifo: &str,
    decoy_banner: &str,
    host_secret: &[u8],
) -> String {
    let decoy = decoy_banner.replace('\'', "'\\''");
    TEMPLATE
        .replace("{padding}", &wrapper_padding(name, host_secret))
        .replace("{self_name}", name)
        .replace("{real_path}", real_path)
        .replace("{ns_inode}", ns_inode)
        .replace("{honey_list}", honey_list)
        .replace("{honey_fifo}", honey_fifo)
        .replace("{decoy_banner}", &decoy)
}

fn write_script(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

pub fn write_wrapper(
    _real_name: &str,
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
    let contents = render(
        scrambled,
        &real_path.display().to_string(),
        &inode_str,
        HONEY_LIST,
        HONEY_FIFO,
        decoy_banner.unwrap_or(""),
        host_secret,
    );
    write_script(&wp, &contents)?;
    Ok(wp)
}

/// Write a honey-name wrapper using the unified template.
///
/// The wrapper is byte-for-byte the same shape as a real-tool wrapper.
/// The honey list (`/run/babbleon/honey.list`) is what makes execution
/// different at runtime — not the wrapper's contents.
pub fn write_honey_wrapper(
    honey_name: &str,
    output_dir: &Path,
    host_secret: &[u8],
    fifo: Option<&str>,
) -> Result<PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    let wp = output_dir.join(honey_name);
    let fifo_path = fifo.unwrap_or(HONEY_FIFO);
    // real_path is unused for honey (exits before exec), but we fill it
    // with /dev/null so the template renders to the same structure.
    let contents = render(
        honey_name,
        "/dev/null",
        "0",
        HONEY_LIST,
        fifo_path,
        "",
        host_secret,
    );
    write_script(&wp, &contents)?;
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

/// Write `/run/babbleon/honey.list` (or `path`) with one honey name per line.
///
/// The unified wrapper template reads this file at exec time to decide
/// whether it is a honey wrapper or a real-tool wrapper.  Writing this
/// list is separate from writing the wrapper scripts so the list can be
/// regenerated (e.g. after a rotation) without rewriting every wrapper.
pub fn write_honey_list<'a, I>(honey_names: I, path: Option<&Path>) -> Result<()>
where
    I: IntoIterator<Item = &'a str>,
{
    let p = path.unwrap_or_else(|| Path::new(HONEY_LIST));
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content: String = honey_names
        .into_iter()
        .flat_map(|n| [n, "\n"])
        .collect();
    std::fs::write(p, content)?;
    Ok(())
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
    fn honey_and_real_wrapper_same_structure() {
        // The unified template means honey and real-tool wrappers differ only
        // in {padding} (name-keyed) and {real_path}. Line count must be equal.
        let dir = tempfile::tempdir().unwrap();
        let real_bin = dir.path().join("curl");
        std::fs::write(&real_bin, "#!/bin/sh\n").unwrap();

        let honey_wp =
            write_honey_wrapper("honey-name", dir.path(), b"secret", None).unwrap();
        let real_wp =
            write_wrapper("curl", "real-name", &real_bin, dir.path(), b"secret", None, None)
                .unwrap();

        let honey_lines = std::fs::read_to_string(&honey_wp)
            .unwrap()
            .lines()
            .count();
        let real_lines = std::fs::read_to_string(&real_wp)
            .unwrap()
            .lines()
            .count();
        assert_eq!(
            honey_lines, real_lines,
            "honey ({honey_lines}) and real-tool ({real_lines}) wrappers must have the same line count"
        );
    }

    #[test]
    fn honey_wrapper_exits_127() {
        let dir = tempfile::tempdir().unwrap();
        let list_file = dir.path().join("honey.list");
        std::fs::write(&list_file, "xq-marble-fern\n").unwrap();
        let fifo_file = dir.path().join("honey.fifo");

        // Render with custom honey_list/fifo paths pointing into our temp dir.
        let honey_name = "xq-marble-fern";
        let contents = render(
            honey_name,
            "/dev/null",
            "0",
            list_file.to_str().unwrap(),
            fifo_file.to_str().unwrap(),
            "",
            b"secret",
        );
        let wp = dir.path().join(honey_name);
        write_script(&wp, &contents).unwrap();

        let status = std::process::Command::new("sh")
            .arg(&wp)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin")
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
        let list_file = dir.path().join("honey.list");
        std::fs::write(&list_file, "xq-marble-fern\n").unwrap();
        let log_file = dir.path().join("honey.log");

        let honey_name = "xq-marble-fern";
        let contents = render(
            honey_name,
            "/dev/null",
            "0",
            list_file.to_str().unwrap(),
            log_file.to_str().unwrap(),
            "",
            b"secret",
        );
        let wp = dir.path().join(honey_name);
        write_script(&wp, &contents).unwrap();

        std::process::Command::new("sh")
            .arg(&wp)
            .arg("--list")
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/local/bin")
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

    #[test]
    fn honey_list_written_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("honey.list");
        write_honey_list(["alpha", "beta", "gamma"], Some(&list)).unwrap();
        let content = std::fs::read_to_string(&list).unwrap();
        assert!(content.contains("alpha\n"));
        assert!(content.contains("beta\n"));
        assert!(content.contains("gamma\n"));
    }
}
