//! XDG-aware storage paths.

use std::path::PathBuf;

pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("babbleon")
}

pub fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("babbleon")
}

pub fn vault_path() -> PathBuf {
    config_dir().join("vault.age")
}

pub fn state_path() -> PathBuf {
    config_dir().join("state.json")
}

pub fn ensure_dirs() -> std::io::Result<()> {
    std::fs::create_dir_all(config_dir())?;
    std::fs::create_dir_all(data_dir())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(config_dir(), std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}
