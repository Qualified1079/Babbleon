//! Default vault file path and parent-dir setup helpers.
//!
//! # Infrastructure module
//!
//! Centralises the "where on disk does the vault live" question so
//! the CLI does not hard-code it and the operator can override it
//! per call.  No specific attack is defeated here; the security
//! properties live in the [`crate::vault`] cipher layer.
//!
//! Policy:
//!
//! - `$XDG_CONFIG_HOME/babbleon/vault.age` for per-user installs.
//! - `/etc/babbleon/vault.age` for system installs (root only).
//!
//! In v2.0 the per-user path is the default; system installs pass
//! `--vault-path /etc/babbleon/vault.age` explicitly.  The
//! [`default_vault_path`] function returns the per-user path when
//! `$HOME` (or `$XDG_CONFIG_HOME`) is set, falling back to the
//! system path otherwise.

use std::path::{Path, PathBuf};

use crate::errors::{Error, Result};

/// Vault file name under the parent directory.  Public so operator
/// CLI tooling can compose its own parent paths without recomputing
/// the suffix.
pub const VAULT_FILE_NAME: &str = "vault.age";

/// System-install vault path used when no per-user config dir is
/// resolvable.  Always absolute.
pub const SYSTEM_VAULT_PATH: &str = "/etc/babbleon/vault.age";

/// Compute the default vault path for this process.
///
/// Resolution order:
///
/// 1. `$XDG_CONFIG_HOME/babbleon/vault.age` if `$XDG_CONFIG_HOME` is
///    set to an absolute path.
/// 2. `$HOME/.config/babbleon/vault.age` if `$HOME` resolves through
///    `dirs::config_dir()`.
/// 3. [`SYSTEM_VAULT_PATH`].
#[must_use]
pub fn default_vault_path() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            return p.join("babbleon").join(VAULT_FILE_NAME);
        }
    }
    if let Some(cfg) = dirs::config_dir() {
        return cfg.join("babbleon").join(VAULT_FILE_NAME);
    }
    PathBuf::from(SYSTEM_VAULT_PATH)
}

/// Create the vault file's parent directory if missing.  Mode 0o700
/// on Unix so a per-user vault stays per-user-readable.
///
/// # Errors
///
/// - [`Error::Io`] with `op = "create-parent"` and the underlying
///   `ErrorKind` Debug-name if the directory cannot be created.
pub fn ensure_parent_dir(vault_path: &Path) -> Result<()> {
    let parent = vault_path.parent().ok_or_else(|| Error::Io {
        op: "create-parent",
        kind: "vault path has no parent".into(),
    })?;
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    if parent.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|e| Error::Io {
        op: "create-parent",
        kind: format!("{:?}", e.kind()),
    })?;
    set_user_only_mode(parent)?;
    Ok(())
}

#[cfg(unix)]
fn set_user_only_mode(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(dir)
        .map_err(|e| Error::Io {
            op: "stat-parent",
            kind: format!("{:?}", e.kind()),
        })?
        .permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(dir, perms).map_err(|e| Error::Io {
        op: "chmod-parent",
        kind: format!("{:?}", e.kind()),
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn set_user_only_mode(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_under_xdg_config_home_when_set() {
        let saved_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let saved_home = std::env::var_os("HOME");
        // SAFETY-ish: tests are single-threaded by default; assume so.
        std::env::set_var("XDG_CONFIG_HOME", "/tmp/test-xdg");
        let p = default_vault_path();
        assert_eq!(p, PathBuf::from("/tmp/test-xdg/babbleon/vault.age"));
        // Restore environment.
        match saved_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn default_path_ignores_relative_xdg() {
        let saved_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let saved_home = std::env::var_os("HOME");
        std::env::set_var("XDG_CONFIG_HOME", "relative/xdg");
        std::env::set_var("HOME", "/home/test");
        let p = default_vault_path();
        // Relative XDG must not be honoured.
        assert!(p.is_absolute());
        assert!(!p.starts_with("relative"));
        match saved_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match saved_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn vault_file_name_is_stable() {
        // Sanity test — refactors should not silently change the
        // on-disk artifact name.
        assert_eq!(VAULT_FILE_NAME, "vault.age");
    }

    #[test]
    fn ensure_parent_dir_creates_missing_parent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("deep").join("vault.age");
        ensure_parent_dir(&path).unwrap();
        assert!(path.parent().unwrap().exists());
    }

    #[test]
    fn ensure_parent_dir_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested").join("vault.age");
        ensure_parent_dir(&path).unwrap();
        ensure_parent_dir(&path).unwrap();
        assert!(path.parent().unwrap().exists());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_parent_dir_sets_700_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("secrets").join("vault.age");
        ensure_parent_dir(&path).unwrap();
        let meta = std::fs::metadata(path.parent().unwrap()).unwrap();
        // Lower 9 bits — drop the type bits, keep the perm bits.
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn system_vault_path_is_absolute() {
        assert!(PathBuf::from(SYSTEM_VAULT_PATH).is_absolute());
    }
}
