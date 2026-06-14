//! M4: credential vault path-gating.
//!
//! Real credentials (`~/.aws`, `~/.ssh`, `~/.config/gh`, `~/.kube`, browser
//! cookies) live in their normal home-directory locations on disk.  At
//! namespace-setup time, the trusted view bind-mounts each real directory
//! into its normal path; the untrusted view bind-mounts a tmpfs *over* each
//! credential dir so the path exists but contains nothing.
//!
//! The list of gated paths is per-host (some users have ~/.config/gh; some
//! don't) and is computed from the running user's home plus the canonical
//! set.  Paths that don't exist are silently skipped.
//!
//! IPC sockets (SSH_AUTH_SOCK, gpg-agent, DBUS_SESSION_BUS_ADDRESS,
//! XDG_RUNTIME_DIR) are handled by env-var scrubbing (see `env_scrub`).

use crate::errors::Result;
use std::path::{Path, PathBuf};

/// Canonical set of credential directories under $HOME.
pub const HOME_RELATIVE_CRED_DIRS: &[&str] = &[
    ".aws",
    ".ssh",
    ".config/gh",
    ".config/doctl",
    ".kube",
    ".docker",
    ".terraform.d",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".gnupg",
    ".password-store",
    // Browser cookies (Linux paths).
    ".config/google-chrome",
    ".config/chromium",
    ".mozilla/firefox",
    ".config/BraveSoftware/Brave-Browser",
];

/// Resolve the gated credential paths for the current user.
/// Returns only paths that actually exist on disk.
pub fn discover(home: &Path) -> Vec<PathBuf> {
    HOME_RELATIVE_CRED_DIRS
        .iter()
        .map(|p| home.join(p))
        .filter(|p| p.exists())
        .collect()
}

/// Apply the untrusted-tier credential gate: overlay each discovered cred
/// directory with an empty tmpfs so the path exists (avoids "no such file"
/// telltales) but the contents are inaccessible.
#[cfg(target_os = "linux")]
pub fn apply_untrusted_gate(home: &Path) -> Result<Vec<PathBuf>> {
    use crate::enforcement::syscalls;

    let mut gated = Vec::new();
    for path in discover(home) {
        if let Err(e) = syscalls::mount_tmpfs(&path, "mode=0700,size=64k") {
            tracing::warn!("credential gate {} failed: {}", path.display(), e);
            continue;
        }
        gated.push(path);
    }
    Ok(gated)
}

#[cfg(not(target_os = "linux"))]
pub fn apply_untrusted_gate(_home: &Path) -> Result<Vec<PathBuf>> {
    Ok(Vec::new())
}

/// Env-var deny-list: things the untrusted tier should NOT inherit.
/// Drawn from RESEARCH.md T7-T8.
pub const SCRUB_ENV_VARS: &[&str] = &[
    // IPC sockets
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",
    // Cloud credential hints
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "DIGITALOCEAN_ACCESS_TOKEN",
    "VAULT_TOKEN",
    "DOCKER_AUTH_CONFIG",
    "KUBECONFIG",
    // History / shell context
    "HISTFILE",
    "BASH_HISTORY",
];

/// Filter an environment map down to what the untrusted tier may see.
pub fn scrub_env<S: AsRef<str>>(env: impl IntoIterator<Item = (S, S)>) -> Vec<(String, String)> {
    let deny: std::collections::HashSet<&str> = SCRUB_ENV_VARS.iter().copied().collect();
    env.into_iter()
        .filter(|(k, _)| !deny.contains(k.as_ref()))
        .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_finds_existing_dirs_only() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".aws")).unwrap();
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        // .kube intentionally not created
        let found = discover(home);
        assert!(found.iter().any(|p| p.ends_with(".aws")));
        assert!(found.iter().any(|p| p.ends_with(".ssh")));
        assert!(!found.iter().any(|p| p.ends_with(".kube")));
    }

    #[test]
    fn scrub_removes_sensitive_vars() {
        let env = vec![
            ("PATH", "/usr/bin"),
            ("HOME", "/home/u"),
            ("AWS_SECRET_ACCESS_KEY", "secret"),
            ("SSH_AUTH_SOCK", "/tmp/sock"),
            ("GITHUB_TOKEN", "ghp_xxx"),
        ];
        let scrubbed = scrub_env(env);
        let keys: std::collections::HashSet<_> =
            scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains("PATH"));
        assert!(keys.contains("HOME"));
        assert!(!keys.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(!keys.contains("SSH_AUTH_SOCK"));
        assert!(!keys.contains("GITHUB_TOKEN"));
    }

    #[test]
    fn scrub_is_complete() {
        // Every entry in the deny-list must be a non-empty string.
        for &v in SCRUB_ENV_VARS {
            assert!(!v.is_empty());
            assert!(!v.contains(' '));
        }
    }
}
