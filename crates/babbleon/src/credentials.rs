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

/// Env-var deny-list: exact names the untrusted tier must NOT inherit.
///
/// The deny mechanism has two layers:
///
///   1. This exact-name list — covers IPC sockets and named credentials
///      whose tokens carry no recognizable suffix (e.g. `AWS_PROFILE`,
///      `KUBECONFIG`, `DATABASE_URL`).
///   2. `SCRUB_ENV_SUFFIXES` — wildcard-suffix match against the var name.
///      Per RESEARCH.md T8, the wildcard filter is the *primary* attacker
///      pattern (gitleaks/trufflehog corpora overwhelmingly index by
///      `*_TOKEN`/`*_SECRET`/`*_KEY` suffix, not by named list).  Names
///      not in the exact list still get scrubbed if their suffix matches.
///
/// Drawn from RESEARCH.md T7-T8 and the gitleaks/trufflehog detector schemas.
pub const SCRUB_ENV_VARS: &[&str] = &[
    // IPC sockets — live trust handles, not just credential text.
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GPG_AGENT_INFO",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_RUNTIME_DIR",

    // Cloud / orchestration config (not always suffix-matched).
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_PROJECT",
    "CLOUDSDK_CONFIG",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_TENANT_ID",
    "AZURE_SUBSCRIPTION_ID",
    "AZURE_CONFIG_DIR",
    "KUBECONFIG",
    "DOCKER_AUTH_CONFIG",
    "DOCKER_CONFIG",

    // VCS / SCM
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITLAB_TOKEN",
    "BITBUCKET_TOKEN",

    // Secrets brokers
    "VAULT_TOKEN",
    "VAULT_ADDR",
    "VAULT_NAMESPACE",
    "DOPPLER_TOKEN",
    "OP_SERVICE_ACCOUNT_TOKEN",

    // AI / LLM SDK tokens — the highest-leverage credentials on a 2026
    // developer machine (RESEARCH.md T8).  Family expands monthly;
    // suffix-match below catches new vendors automatically as long as
    // they follow the `*_API_KEY` / `*_TOKEN` convention.
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "REPLICATE_API_TOKEN",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "GROQ_API_KEY",
    "TOGETHER_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "PERPLEXITY_API_KEY",

    // Database connection strings — credential material inline.
    "DATABASE_URL",
    "POSTGRES_PASSWORD",
    "MYSQL_PWD",
    "MONGO_URI",
    "REDIS_URL",

    // History / shell context
    "HISTFILE",
    "BASH_HISTORY",

    // Less-suffixed cloud and registry tokens.
    "DIGITALOCEAN_ACCESS_TOKEN",
    "HEROKU_API_KEY",
];

/// Suffix patterns the untrusted tier must NOT inherit.  Matched
/// case-sensitive against the env-var *name*.  Per RESEARCH.md T8, this is
/// the dominant attacker scrape pattern — adversaries grep `getenv` results
/// for these suffixes before looking at exact names.
///
/// Suffixes are matched as `key.ends_with(suffix)`, so e.g.
/// `MY_CUSTOM_API_KEY` is filtered without being in the exact list.
pub const SCRUB_ENV_SUFFIXES: &[&str] = &[
    "_TOKEN",
    "_SECRET",
    "_KEY",
    "_PASSWORD",
    "_PWD",
    "_API_KEY",
    "_CREDENTIALS",
    "_PRIVATE_KEY",
];

/// Returns true if `name` should be scrubbed from the untrusted env.
///
/// Matches if the name is in the exact deny-list OR ends with any
/// suffix in `SCRUB_ENV_SUFFIXES`.
pub fn is_scrubbed_var(name: &str) -> bool {
    if SCRUB_ENV_VARS.contains(&name) {
        return true;
    }
    SCRUB_ENV_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Filter an environment map down to what the untrusted tier may see.
pub fn scrub_env<S: AsRef<str>>(env: impl IntoIterator<Item = (S, S)>) -> Vec<(String, String)> {
    env.into_iter()
        .filter(|(k, _)| !is_scrubbed_var(k.as_ref()))
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
        let keys: std::collections::HashSet<_> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains("PATH"));
        assert!(keys.contains("HOME"));
        assert!(!keys.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(!keys.contains("SSH_AUTH_SOCK"));
        assert!(!keys.contains("GITHUB_TOKEN"));
    }

    #[test]
    fn scrub_catches_ai_sdk_tokens() {
        let env = vec![
            ("ANTHROPIC_API_KEY", "sk-ant-xxx"),
            ("OPENAI_API_KEY", "sk-xxx"),
            ("HF_TOKEN", "hf_xxx"),
            ("MISTRAL_API_KEY", "xxx"),
            ("COHERE_API_KEY", "xxx"),
            ("PATH", "/usr/bin"),
        ];
        let scrubbed = scrub_env(env);
        let keys: std::collections::HashSet<_> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains("PATH"));
        for k in ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "HF_TOKEN",
                  "MISTRAL_API_KEY", "COHERE_API_KEY"] {
            assert!(!keys.contains(k), "{k} leaked through");
        }
    }

    #[test]
    fn scrub_catches_unknown_vars_by_suffix() {
        // The whole point of the suffix matcher: catch vendor-specific
        // names we never enumerated.
        let env = vec![
            ("MYSERVICE_API_KEY", "leak"),
            ("CUSTOMER_INTERNAL_TOKEN", "leak"),
            ("ACME_DB_PASSWORD", "leak"),
            ("APP_CLIENT_SECRET", "leak"),
            ("RSA_PRIVATE_KEY", "leak"),
            ("LEGITIMATE_PATH", "ok"),
        ];
        let scrubbed = scrub_env(env);
        let keys: std::collections::HashSet<_> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains("LEGITIMATE_PATH"));
        for leaked in ["MYSERVICE_API_KEY", "CUSTOMER_INTERNAL_TOKEN",
                       "ACME_DB_PASSWORD", "APP_CLIENT_SECRET", "RSA_PRIVATE_KEY"] {
            assert!(!keys.contains(leaked), "{leaked} should have been scrubbed by suffix");
        }
    }

    #[test]
    fn scrub_does_not_overmatch_non_secret_keys() {
        // Negative test: env var names that happen to contain "KEY" or "TOKEN"
        // as substrings (not suffix) should NOT be scrubbed.  Avoids breaking
        // PATH-like variables.
        let env = vec![
            ("KEYBOARD_LAYOUT", "us"),
            ("TOKENIZER_PATH", "/opt/tok"),
            ("SECRETARY_NAME", "ada"),
            ("PATH", "/usr/bin"),
        ];
        let scrubbed = scrub_env(env);
        let keys: std::collections::HashSet<_> = scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        for k in ["KEYBOARD_LAYOUT", "TOKENIZER_PATH", "SECRETARY_NAME", "PATH"] {
            assert!(keys.contains(k), "{k} should NOT have been scrubbed");
        }
    }

    #[test]
    fn scrub_is_complete() {
        // Every entry in the deny-list must be a non-empty string.
        for &v in SCRUB_ENV_VARS {
            assert!(!v.is_empty());
            assert!(!v.contains(' '));
        }
        for &s in SCRUB_ENV_SUFFIXES {
            assert!(s.starts_with('_'), "suffix {s} must start with _ to avoid mid-word matches");
            assert_eq!(s, s.to_uppercase(), "suffix {s} must be uppercase");
        }
    }
}
