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

/// Shell template.
/// {padding}     — per-host 16-byte hex; changes per scrambled name
/// {scrambled}   — the scrambled binary name (for comments only)
/// {real_path}   — absolute path to the real binary
/// {ns_inode}    — inode of the trusted mount namespace; 0 means always-null
const TEMPLATE: &str = r#"#!/bin/sh
# babbleon wrapper
# host-pad: {padding}
_BL_REAL="{real_path}"
_BL_NS_INODE="{ns_inode}"
_in_trusted_ns() {
    _cur=$(stat -Lc '%i' /proc/self/ns/mnt 2>/dev/null) || return 1
    [ "$_cur" = "$_BL_NS_INODE" ]
}
case "$1" in
    --help|--version|-h|-V|-help|-version)
        if ! _in_trusted_ns; then
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
    scrambled: &str,
    real_path: &Path,
    output_dir: &Path,
    host_secret: &[u8],
    trusted_ns_inode: Option<u64>,
) -> Result<PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    let wp = output_dir.join(scrambled);
    let inode_str = trusted_ns_inode
        .map(|i| i.to_string())
        .unwrap_or_else(|| "0".to_string());
    let contents = TEMPLATE
        .replace("{padding}", &padding(scrambled, host_secret))
        .replace("{scrambled}", scrambled)
        .replace("{real_path}", &real_path.display().to_string())
        .replace("{ns_inode}", &inode_str);
    std::fs::write(&wp, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wp, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(wp)
}

pub fn write_all<I, S>(
    mapping_iter: I,
    real_root: &Path,
    output_dir: &Path,
    host_secret: &[u8],
    trusted_ns_inode: Option<u64>,
) -> Result<std::collections::HashMap<String, PathBuf>>
where
    I: IntoIterator<Item = (S, S)>,
    S: AsRef<str>,
{
    let mut out = std::collections::HashMap::new();
    for (real, scrambled) in mapping_iter {
        let src = real_root.join(real.as_ref());
        if !src.exists() {
            continue;
        }
        let p = write_wrapper(scrambled.as_ref(), &src, output_dir, host_secret, trusted_ns_inode)?;
        out.insert(scrambled.as_ref().to_string(), p);
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
        let a = write_wrapper("name", &real, &dir.path().join("a"), &[1u8; 32], None).unwrap();
        let b = write_wrapper("name", &real, &dir.path().join("b"), &[2u8; 32], None).unwrap();
        assert_ne!(std::fs::read_to_string(a).unwrap(), std::fs::read_to_string(b).unwrap());
    }

    #[test]
    fn trusted_ns_inode_embedded() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("curl");
        std::fs::write(&real, "#!/bin/sh\n").unwrap();
        let wp = write_wrapper("testname", &real, dir.path(), b"secret", Some(12345)).unwrap();
        let contents = std::fs::read_to_string(wp).unwrap();
        assert!(contents.contains("12345"));
    }
}
