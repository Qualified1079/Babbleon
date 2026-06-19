//! Credential-bearing paths and environment variables that the
//! untrusted tier must not see.
//!
//! # What this defeats
//!
//! Real credentials (`~/.aws`, `~/.ssh`, `~/.config/gh`, `~/.kube`,
//! browser cookies) live in their normal home-directory locations
//! on disk.  An untrusted-tier process inheriting the user's home
//! directly would see every one of them.  This module enumerates
//! the canonical locations so the launcher (`v2-babbleon-launch-untrusted`)
//! can overlay each with an empty tmpfs in the new mount namespace.
//!
//! Live trust handles (`SSH_AUTH_SOCK`, `KUBECONFIG`,
//! `ANTHROPIC_API_KEY`, etc.) leak through the environment rather
//! than the filesystem.  This module also enumerates the names and
//! suffix patterns the launcher must scrub from the child's
//! environment before exec.  See RESEARCH.md T7-T8 for the
//! adversary scraping patterns we modelled.
//!
//! # Compartmentalization
//!
//! This module is **policy** (which paths, which env-var names),
//! not **mechanism** (mount syscalls, exec environment).  Mounts
//! happen in
//! `v2-babbleon-launch-untrusted::credential_gate`; env scrubbing
//! happens in the launcher's exec wrapper.  Splitting policy from
//! mechanism lets the policy lists be unit-tested without root.
//!
//! # Threat model boundaries
//!
//! - Defeats: untrusted-tier processes reading `~/.aws/credentials`,
//!   `~/.ssh/id_*`, browser cookie databases, `$ANTHROPIC_API_KEY`.
//! - Defeats: suffix-pattern attacker scraping
//!   (`*_TOKEN`, `*_SECRET`, `*_KEY`).
//! - Does NOT defeat: credentials the user types interactively at
//!   the untrusted-tier prompt — out of scope; user discipline.
//! - Does NOT defeat: credentials embedded inside non-credential
//!   files (e.g. a Python script with an inline API key).  The
//!   identifier-scramble + structural-scramble layers compensate
//!   by hiding the script's discoverability, not its contents.

use std::path::{Path, PathBuf};

/// Canonical set of credential directories under `$HOME`, expressed
/// as relative paths.
///
/// Each entry is joined onto the per-user home directory at runtime
/// by [`discover_credential_dirs`].  Entries that do not exist on
/// disk are silently skipped — different users have different
/// subsets installed.
///
/// Ordering is not security-relevant but is stable across builds
/// so audit logs and bind-mount traces are reproducible.
pub const CREDENTIAL_DIRS_RELATIVE_TO_HOME: &[&str] = &[
    // Cloud + orchestration
    ".aws",
    ".ssh",
    ".config/gh",
    ".config/doctl",
    ".kube",
    ".docker",
    ".terraform.d",
    // Package-manager credentials
    ".npmrc",
    ".pypirc",
    ".netrc",
    // PGP / password store
    ".gnupg",
    ".password-store",
    // Browser cookies (Linux paths)
    ".config/google-chrome",
    ".config/chromium",
    ".mozilla/firefox",
    ".config/BraveSoftware/Brave-Browser",
];

/// Resolve the credential-bearing directories that exist on disk
/// for the user whose home is `home`.
///
/// Returns absolute paths.  Skips entries that do not currently
/// exist.  Pure function (filesystem `metadata` lookups only — no
/// syscalls that require capabilities).
#[must_use]
pub fn discover_credential_dirs(home: &Path) -> Vec<PathBuf> {
    CREDENTIAL_DIRS_RELATIVE_TO_HOME
        .iter()
        .map(|p| home.join(p))
        .filter(|p| p.exists())
        .collect()
}

/// Exact environment-variable names that the untrusted tier must
/// not inherit.
///
/// Covers IPC sockets (live trust handles, not just credential
/// text) and named tokens whose names do not match any of the
/// suffix patterns in [`SCRUB_ENV_SUFFIXES`].
///
/// Drawn from RESEARCH.md T7-T8 and the gitleaks/trufflehog
/// detector schemas.  Names are matched case-sensitive.
pub const SCRUB_ENV_VAR_NAMES: &[&str] = &[
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
    // AI / LLM SDK tokens — the highest-leverage credentials on a
    // 2026 developer machine (RESEARCH.md T8).  Family expands
    // monthly; the suffix patterns below catch new vendors
    // automatically as long as they follow the `*_API_KEY`
    // convention.
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

/// Suffix patterns the untrusted tier must not inherit.
///
/// Matched case-sensitive against each environment variable's
/// **name** (not value).  Per RESEARCH.md T8 the suffix scan is
/// the dominant adversary scrape pattern.
///
/// Suffixes are matched as `name.ends_with(suffix)`; e.g.
/// `MY_CUSTOM_API_KEY` is filtered without being in
/// [`SCRUB_ENV_VAR_NAMES`].
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

/// True iff `name` should be scrubbed from the untrusted-tier
/// environment.
///
/// Matches if the name is in [`SCRUB_ENV_VAR_NAMES`] OR ends with
/// any suffix in [`SCRUB_ENV_SUFFIXES`].
#[must_use]
pub fn is_credential_env_var(name: &str) -> bool {
    if SCRUB_ENV_VAR_NAMES.contains(&name) {
        return true;
    }
    SCRUB_ENV_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Filter an environment iterator down to what the untrusted tier
/// may see.
///
/// Allocates a new `Vec<(String, String)>` and drops any
/// `(name, value)` pair whose name matches
/// [`is_credential_env_var`].  Caller-owned strings so the
/// scrubber can run inside a daemon process that does not share
/// the launcher's address space.
#[must_use]
pub fn scrub_credential_env_vars<S>(
    env: impl IntoIterator<Item = (S, S)>,
) -> Vec<(String, String)>
where
    S: AsRef<str>,
{
    env.into_iter()
        .filter(|(k, _)| !is_credential_env_var(k.as_ref()))
        .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        discover_credential_dirs, is_credential_env_var,
        scrub_credential_env_vars, CREDENTIAL_DIRS_RELATIVE_TO_HOME,
        SCRUB_ENV_SUFFIXES, SCRUB_ENV_VAR_NAMES,
    };

    #[test]
    fn discover_returns_existing_dirs_only() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        std::fs::create_dir_all(home.join(".aws")).unwrap();
        std::fs::create_dir_all(home.join(".kube")).unwrap();
        // .ssh deliberately not created — should be skipped.
        let found = discover_credential_dirs(home);
        assert!(found.contains(&home.join(".aws")));
        assert!(found.contains(&home.join(".kube")));
        assert!(!found.contains(&home.join(".ssh")));
    }

    #[test]
    fn discover_handles_missing_home() {
        let p = std::path::Path::new("/nonexistent-babbleon-home-xyzzy");
        let found = discover_credential_dirs(p);
        assert!(found.is_empty(), "no entries exist under a missing home");
    }

    #[test]
    fn canonical_credential_dir_list_is_relative_and_nonempty() {
        assert!(!CREDENTIAL_DIRS_RELATIVE_TO_HOME.is_empty());
        for entry in CREDENTIAL_DIRS_RELATIVE_TO_HOME {
            assert!(!entry.is_empty(), "blank entry");
            assert!(
                !entry.starts_with('/'),
                "{entry} must be relative to $HOME, not absolute"
            );
            assert!(
                !entry.contains(".."),
                "{entry} must not contain '..' (path traversal)"
            );
        }
    }

    #[test]
    fn is_credential_env_var_matches_exact_names() {
        assert!(is_credential_env_var("ANTHROPIC_API_KEY"));
        assert!(is_credential_env_var("SSH_AUTH_SOCK"));
        assert!(is_credential_env_var("KUBECONFIG"));
        assert!(is_credential_env_var("DATABASE_URL"));
    }

    #[test]
    fn is_credential_env_var_matches_suffix_patterns() {
        assert!(is_credential_env_var("MY_CUSTOM_API_KEY"));
        assert!(is_credential_env_var("RANDOM_NAME_TOKEN"));
        assert!(is_credential_env_var("SOMETHING_SECRET"));
        assert!(is_credential_env_var("FOO_PRIVATE_KEY"));
    }

    #[test]
    fn is_credential_env_var_lets_safe_vars_through() {
        assert!(!is_credential_env_var("PATH"));
        assert!(!is_credential_env_var("HOME"));
        assert!(!is_credential_env_var("TERM"));
        assert!(!is_credential_env_var("LANG"));
        assert!(!is_credential_env_var(""));
    }

    #[test]
    fn is_credential_env_var_is_case_sensitive() {
        // Lowercase variants must NOT match — Linux env-vars are
        // canonically uppercase; lowercase forms are usually noise
        // (path completion vars etc.) and scrubbing them would
        // mangle user shells.
        assert!(!is_credential_env_var("aws_access_key_id"));
        assert!(!is_credential_env_var("anthropic_api_key"));
        assert!(!is_credential_env_var("ssh_auth_sock"));
    }

    #[test]
    fn scrub_credential_env_vars_drops_matches_and_keeps_safe_pairs() {
        let env = vec![
            ("PATH", "/usr/bin:/bin"),
            ("HOME", "/home/u"),
            ("ANTHROPIC_API_KEY", "sk-shouldnotleak"),
            ("MY_TOKEN", "shouldnotleak"),
            ("LANG", "en_US.UTF-8"),
        ];
        let scrubbed = scrub_credential_env_vars(env);
        let names: Vec<&str> =
            scrubbed.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"PATH"));
        assert!(names.contains(&"HOME"));
        assert!(names.contains(&"LANG"));
        assert!(!names.contains(&"ANTHROPIC_API_KEY"));
        assert!(!names.contains(&"MY_TOKEN"));
    }

    #[test]
    fn scrub_credential_env_vars_does_not_leak_values_of_safe_keys() {
        // Property: every kept (k, v) pair preserves its original
        // value exactly.  Filtering is by NAME, never by VALUE.
        let env = vec![
            ("PATH", "/usr/bin:/bin"),
            ("ARBITRARY", "anthropic-api-key-value-shape"),
        ];
        let scrubbed = scrub_credential_env_vars(env);
        let arbitrary = scrubbed
            .iter()
            .find(|(k, _)| k == "ARBITRARY")
            .unwrap();
        assert_eq!(arbitrary.1, "anthropic-api-key-value-shape");
    }

    #[test]
    fn suffix_patterns_are_uppercase_and_underscore_only() {
        // Sanity check on the suffix list — typos here have caused
        // silent under-filtering historically.
        for s in SCRUB_ENV_SUFFIXES {
            assert!(s.starts_with('_'), "{s} must begin with _");
            assert!(
                s.bytes()
                    .all(|b| b == b'_' || b.is_ascii_uppercase()),
                "{s} must be uppercase + underscore only",
            );
        }
    }

    #[test]
    fn exact_var_list_is_uppercase_and_nonempty() {
        for n in SCRUB_ENV_VAR_NAMES {
            assert!(!n.is_empty());
            assert!(
                n.bytes()
                    .all(|b| b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit()),
                "{n} must be uppercase + underscore + digit only",
            );
        }
    }
}
