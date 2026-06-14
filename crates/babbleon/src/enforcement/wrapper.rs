//! Banner-spoofing wrapper generator (M3 baseline).
//!
//! Generates a tiny shell script per scrambled name. The script:
//!   - returns empty output for --help / -V / --version (M3 baseline)
//!   - exec's the real binary for everything else (caller-tier detection DEFERRED)
//!   - embeds per-host random padding bytes to defeat hash fingerprinting
//!     (ObserverWard / WhatWeb / Wappalyzer signature DBs)
//!
//! DEFERRED M3.5: rewrite as a stripped Rust binary (no shell-script content
//! leakage) with caller-tier detection via /proc/self/ns/mnt inode comparison.

use crate::Result;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const TEMPLATE: &str = r#"#!/bin/sh
# babbleon scrambled-binary wrapper (M3 baseline)
# padding: {padding}
# scrambled: {scrambled}
case "$1" in
    --help|--version|-h|-V|-help|-version)
        exit 0
        ;;
esac
exec {real_path} "$@"
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
) -> Result<PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    let wp = output_dir.join(scrambled);
    let contents = TEMPLATE
        .replace("{padding}", &padding(scrambled, host_secret))
        .replace("{scrambled}", scrambled)
        .replace("{real_path}", &real_path.display().to_string());
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
        let p = write_wrapper(scrambled.as_ref(), &src, output_dir, host_secret)?;
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
        let a = write_wrapper("name", &real, &dir.path().join("a"), &[1u8; 32]).unwrap();
        let b = write_wrapper("name", &real, &dir.path().join("b"), &[2u8; 32]).unwrap();
        assert_ne!(std::fs::read_to_string(a).unwrap(), std::fs::read_to_string(b).unwrap());
    }
}
