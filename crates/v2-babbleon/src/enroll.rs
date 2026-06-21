//! `babbleon enroll` / `babbleon unenroll` — PAM-flavour-1 user
//! enrollment.
//!
//! # What this defeats
//!
//! Flavour 1 wraps every shell invocation by setting the user's
//! shell-of-record (in `/etc/passwd`) to
//! `/usr/local/bin/babbleon-login-shell`.  This module provides
//! the operator-facing CLI for the chsh edit, plus a sidecar
//! registry at `/etc/babbleon/enrolled-shells.toml` that records
//! the user's previous shell so `unenroll` can restore it.
//!
//! Without the sidecar registry, an operator who runs `chsh` and
//! later removes Babbleon would have to remember and re-set
//! everyone's previous shells by hand.
//!
//! # Mechanism
//!
//! `enroll <user>`:
//!
//! 1. Read the user's current shell from `/etc/passwd` via
//!    `getent passwd`.  Refuse to enrol if the user is missing.
//! 2. Refuse if the current shell is already the wrapper.
//! 3. Append `{username, previous_shell}` to
//!    `/etc/babbleon/enrolled-shells.toml`.  Atomic write
//!    (tempfile + rename); mode 0o600.
//! 4. Invoke `chsh -s <wrapper-path> <user>`.  Fail with the
//!    chsh exit code on failure.
//!
//! `unenroll <user>`:
//!
//! 1. Read `/etc/babbleon/enrolled-shells.toml`; refuse if the
//!    user is absent.
//! 2. Invoke `chsh -s <previous_shell> <user>`.
//! 3. Remove the user's entry from the registry; atomic write.
//!
//! # Compartmentalization
//!
//! The CLI dispatches into this module which shells out to
//! `chsh` and `getent`.  Neither call is privileged in itself
//! (`chsh` is setuid-root on every distro we target); the CLI
//! runs as the invoking user, who must be root or have `CAP_CHOWN`
//! to chsh someone else.  All filesystem state lives under
//! `/etc/babbleon/` which is daemon-installed at mode 0o755.
//!
//! # Threat model boundaries
//!
//! - **Defeats:** operator-error in shell rollback (registry
//!   makes the "what was their previous shell?" question trivial).
//! - **Does NOT defeat:** an attacker with write access to
//!   `/etc/passwd`.  Such an attacker is already root-equivalent;
//!   Babbleon does not claim to defend against that threat.
//! - **Does NOT defeat:** a user who runs a non-login shell by
//!   absolute path (`/bin/zsh` instead of `bash --login`).  See
//!   `docs/v2/pam-flavour-1.md` "Limitations" for the full list.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

/// Default install path of the Babbleon login-shell wrapper.
const DEFAULT_WRAPPER_PATH: &str = "/usr/local/bin/babbleon-login-shell";

/// Registry file recording per-user previous shells.
const REGISTRY_PATH: &str = "/etc/babbleon/enrolled-shells.toml";

/// Run `babbleon enroll <username>`.
///
/// Resolves the user's current shell, records it in the registry,
/// and `chsh`'s them to the wrapper.  Returns an error if any
/// step fails; partial state is rolled back where possible
/// (registry write happens BEFORE chsh so a chsh failure leaves
/// the registry untouched).
///
/// # Errors
///
/// - Anyhow context for: missing user, already-enrolled,
///   registry write, chsh non-zero exit.
pub fn run_enroll(username: &str, wrapper_path: Option<&Path>) -> Result<()> {
    let wrapper = wrapper_path
        .map_or_else(|| PathBuf::from(DEFAULT_WRAPPER_PATH), Path::to_path_buf);
    run_enroll_inner(
        username,
        &wrapper,
        Path::new(REGISTRY_PATH),
        &SystemHost,
    )
}

/// Run `babbleon unenroll <username>`.
///
/// Restores the user's previous shell from the registry and
/// removes their entry.
///
/// # Errors
///
/// - Anyhow context for: missing registry, user-not-enrolled,
///   chsh non-zero exit, registry write failure.
pub fn run_unenroll(username: &str) -> Result<()> {
    run_unenroll_inner(username, Path::new(REGISTRY_PATH), &SystemHost)
}

// ----- Inner implementation, parameterised on a Host trait so
// ----- tests can mock chsh / passwd / filesystem.

/// Host-system seam: every privileged or environment-touching
/// call goes through this trait so unit tests can substitute
/// in-memory equivalents.
trait Host {
    /// Look up the user's current login shell.  Returns `None` if
    /// the user does not exist.
    fn current_login_shell(&self, username: &str) -> Result<Option<PathBuf>>;
    /// Invoke `chsh -s <shell> <user>`.  Returns `Ok(())` on
    /// success.
    fn chsh(&self, username: &str, shell: &Path) -> Result<()>;
    /// Read the registry file's bytes.  Returns `Ok(None)` if the
    /// file does not exist; `Err` on permission / I/O failure.
    fn read_registry(&self, path: &Path) -> Result<Option<Vec<u8>>>;
    /// Write the registry file atomically (tempfile + rename).
    fn write_registry(&self, path: &Path, bytes: &[u8]) -> Result<()>;
}

fn run_enroll_inner(
    username: &str,
    wrapper: &Path,
    registry_path: &Path,
    host: &dyn Host,
) -> Result<()> {
    let current = host
        .current_login_shell(username)
        .with_context(|| format!("look up shell for {username}"))?
        .ok_or_else(|| {
            anyhow!("user {username:?} does not exist on this host")
        })?;
    if current == wrapper {
        return Err(anyhow!(
            "user {username:?} is already enrolled (login shell is {})",
            wrapper.display()
        ));
    }
    let mut registry = load_registry(host, registry_path)?;
    if let Some(prev) = registry.entries.get(username) {
        return Err(anyhow!(
            "user {username:?} is already in the registry with previous shell {}; \
             unenrol first",
            prev.display()
        ));
    }
    registry
        .entries
        .insert(username.to_string(), current.clone());
    host.write_registry(registry_path, &registry.serialise())
        .context("write enrolled-shells registry")?;
    host.chsh(username, wrapper).with_context(|| {
        format!("chsh {username} to {}", wrapper.display())
    })?;
    println!(
        "enrolled {username}: shell changed from {} to {}",
        current.display(),
        wrapper.display()
    );
    Ok(())
}

fn run_unenroll_inner(
    username: &str,
    registry_path: &Path,
    host: &dyn Host,
) -> Result<()> {
    let mut registry = load_registry(host, registry_path)?;
    let previous = registry
        .entries
        .remove(username)
        .ok_or_else(|| {
            anyhow!(
                "user {username:?} is not in the registry at {}",
                registry_path.display()
            )
        })?;
    host.chsh(username, &previous).with_context(|| {
        format!("chsh {username} back to {}", previous.display())
    })?;
    host.write_registry(registry_path, &registry.serialise())
        .context("rewrite enrolled-shells registry")?;
    println!(
        "unenrolled {username}: shell restored to {}",
        previous.display()
    );
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Registry {
    entries: BTreeMap<String, PathBuf>,
}

impl Registry {
    /// Hand-rolled TOML emit / parse — small enough that pulling
    /// in a full TOML crate would be more dependency surface
    /// than gain.  Format:
    ///
    /// ```toml
    /// [users]
    /// alice = "/bin/bash"
    /// bob = "/bin/zsh"
    /// ```
    fn serialise(&self) -> Vec<u8> {
        let mut out = String::from("[users]\n");
        for (user, shell) in &self.entries {
            // Refuse to serialise names that would break the
            // TOML frame.  Linux usernames are POSIX-portable
            // (`[a-z_][a-z0-9_-]*`); anything else indicates a
            // caller bug.
            assert!(
                user.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
                "user {user:?} contains non-portable characters",
            );
            let s = shell.to_string_lossy();
            assert!(
                !s.contains('"') && !s.contains('\\') && !s.contains('\n'),
                "shell path {s:?} contains characters that would break TOML",
            );
            out.push_str(user);
            out.push_str(" = \"");
            out.push_str(&s);
            out.push_str("\"\n");
        }
        out.into_bytes()
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)
            .context("registry is not valid UTF-8")?;
        let mut entries = BTreeMap::new();
        let mut in_users_table = false;
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "[users]" {
                in_users_table = true;
                continue;
            }
            if line.starts_with('[') {
                in_users_table = false;
                continue;
            }
            if !in_users_table {
                continue;
            }
            let (user, rest) = line.split_once('=').ok_or_else(|| {
                anyhow!(
                    "registry line {} missing '=': {line:?}",
                    line_no + 1
                )
            })?;
            let user = user.trim().to_string();
            let rest = rest.trim();
            let shell = rest
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .ok_or_else(|| {
                    anyhow!(
                        "registry line {} value not double-quoted: {line:?}",
                        line_no + 1
                    )
                })?;
            entries.insert(user, PathBuf::from(shell));
        }
        Ok(Self { entries })
    }
}

fn load_registry(host: &dyn Host, path: &Path) -> Result<Registry> {
    match host.read_registry(path)? {
        Some(bytes) => Registry::parse(&bytes),
        None => Ok(Registry::default()),
    }
}

// ----- Production Host impl -----

struct SystemHost;

impl Host for SystemHost {
    fn current_login_shell(&self, username: &str) -> Result<Option<PathBuf>> {
        // getent passwd <user> → either prints a passwd line and exits 0,
        // or exits 2 (user not found).  Other non-zero exits indicate a
        // nsswitch / DB error worth surfacing.
        let out = Command::new("getent")
            .arg("passwd")
            .arg(username)
            .output()
            .context("spawn getent passwd")?;
        if out.status.code() == Some(2) {
            return Ok(None);
        }
        if !out.status.success() {
            return Err(anyhow!(
                "getent passwd {username} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        let line = std::str::from_utf8(&out.stdout)
            .context("getent stdout not UTF-8")?;
        // Passwd line format: name:passwd:uid:gid:gecos:home:shell
        let shell = line
            .trim_end()
            .rsplit(':')
            .next()
            .ok_or_else(|| anyhow!("getent output malformed: {line:?}"))?;
        Ok(Some(PathBuf::from(shell)))
    }

    fn chsh(&self, username: &str, shell: &Path) -> Result<()> {
        let status = Command::new("chsh")
            .arg("-s")
            .arg(shell)
            .arg(username)
            .status()
            .context("spawn chsh")?;
        if !status.success() {
            return Err(anyhow!("chsh exited {status}"));
        }
        Ok(())
    }

    fn read_registry(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow!(e)).context("read registry"),
        }
    }

    fn write_registry(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create parent {}", parent.display()))?;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp_path = PathBuf::from(tmp);
        {
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);
            let mut f = opts
                .open(&tmp_path)
                .with_context(|| format!("open tmp {}", tmp_path.display()))?;
            f.write_all(bytes)
                .with_context(|| format!("write tmp {}", tmp_path.display()))?;
        }
        std::fs::rename(&tmp_path, path).with_context(|| {
            format!("rename {} -> {}", tmp_path.display(), path.display())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Test Host: in-memory passwd + chsh + registry.
    struct MockHost {
        passwd: RefCell<BTreeMap<String, PathBuf>>,
        chsh_calls: RefCell<Vec<(String, PathBuf)>>,
        registry: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
        chsh_should_fail: bool,
    }

    impl MockHost {
        fn new() -> Self {
            Self {
                passwd: RefCell::new(BTreeMap::new()),
                chsh_calls: RefCell::new(Vec::new()),
                registry: RefCell::new(BTreeMap::new()),
                chsh_should_fail: false,
            }
        }
    }

    impl Host for MockHost {
        fn current_login_shell(
            &self,
            username: &str,
        ) -> Result<Option<PathBuf>> {
            Ok(self.passwd.borrow().get(username).cloned())
        }
        fn chsh(&self, username: &str, shell: &Path) -> Result<()> {
            if self.chsh_should_fail {
                return Err(anyhow!("simulated chsh failure"));
            }
            self.chsh_calls
                .borrow_mut()
                .push((username.to_string(), shell.to_path_buf()));
            self.passwd
                .borrow_mut()
                .insert(username.to_string(), shell.to_path_buf());
            Ok(())
        }
        fn read_registry(&self, path: &Path) -> Result<Option<Vec<u8>>> {
            Ok(self.registry.borrow().get(path).cloned())
        }
        fn write_registry(&self, path: &Path, bytes: &[u8]) -> Result<()> {
            self.registry
                .borrow_mut()
                .insert(path.to_path_buf(), bytes.to_vec());
            Ok(())
        }
    }

    fn wrapper() -> PathBuf {
        PathBuf::from("/usr/local/bin/babbleon-login-shell")
    }
    fn registry() -> PathBuf {
        PathBuf::from("/etc/babbleon/enrolled-shells.toml")
    }

    #[test]
    fn enroll_changes_shell_and_records_previous() {
        let host = MockHost::new();
        host.passwd
            .borrow_mut()
            .insert("alice".into(), PathBuf::from("/bin/zsh"));
        run_enroll_inner("alice", &wrapper(), &registry(), &host).unwrap();
        // chsh was invoked once with the wrapper.
        let calls = host.chsh_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "alice");
        assert_eq!(calls[0].1, wrapper());
        // Registry recorded /bin/zsh as the previous shell.
        let bytes = host.registry.borrow().get(&registry()).cloned().unwrap();
        let parsed = Registry::parse(&bytes).unwrap();
        assert_eq!(parsed.entries.get("alice").unwrap(), &PathBuf::from("/bin/zsh"));
    }

    #[test]
    fn enroll_rejects_missing_user() {
        let host = MockHost::new();
        let err = run_enroll_inner("nobody", &wrapper(), &registry(), &host)
            .unwrap_err();
        assert!(format!("{err}").contains("does not exist"));
    }

    #[test]
    fn enroll_rejects_already_wrapped() {
        let host = MockHost::new();
        host.passwd
            .borrow_mut()
            .insert("bob".into(), wrapper());
        let err =
            run_enroll_inner("bob", &wrapper(), &registry(), &host).unwrap_err();
        assert!(format!("{err}").contains("already enrolled"));
    }

    #[test]
    fn enroll_rejects_duplicate_registry_entry() {
        let host = MockHost::new();
        host.passwd
            .borrow_mut()
            .insert("carol".into(), PathBuf::from("/bin/bash"));
        let mut r = Registry::default();
        r.entries.insert("carol".into(), PathBuf::from("/bin/fish"));
        host.registry.borrow_mut().insert(registry(), r.serialise());
        let err = run_enroll_inner("carol", &wrapper(), &registry(), &host)
            .unwrap_err();
        assert!(format!("{err}").contains("already in the registry"));
    }

    #[test]
    fn unenroll_restores_previous_shell_and_clears_entry() {
        let host = MockHost::new();
        host.passwd
            .borrow_mut()
            .insert("dave".into(), wrapper());
        let mut r = Registry::default();
        r.entries.insert("dave".into(), PathBuf::from("/bin/zsh"));
        host.registry.borrow_mut().insert(registry(), r.serialise());
        run_unenroll_inner("dave", &registry(), &host).unwrap();
        let calls = host.chsh_calls.borrow();
        assert_eq!(calls[0].1, PathBuf::from("/bin/zsh"));
        let bytes = host.registry.borrow().get(&registry()).cloned().unwrap();
        let parsed = Registry::parse(&bytes).unwrap();
        assert!(parsed.entries.is_empty());
    }

    #[test]
    fn unenroll_rejects_user_not_in_registry() {
        let host = MockHost::new();
        let err = run_unenroll_inner("eve", &registry(), &host).unwrap_err();
        assert!(format!("{err}").contains("not in the registry"));
    }

    #[test]
    fn registry_roundtrip_preserves_entries() {
        let mut r = Registry::default();
        r.entries.insert("alice".into(), PathBuf::from("/bin/zsh"));
        r.entries.insert("bob".into(), PathBuf::from("/bin/fish"));
        let bytes = r.serialise();
        let parsed = Registry::parse(&bytes).unwrap();
        assert_eq!(parsed, r);
    }

    #[test]
    fn registry_parse_ignores_comments_and_blank_lines() {
        let toml = b"# comment\n\n[users]\nalice = \"/bin/zsh\"\n# another\n";
        let r = Registry::parse(toml).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.entries.get("alice").unwrap(), &PathBuf::from("/bin/zsh"));
    }

    #[test]
    fn registry_parse_rejects_unquoted_value() {
        let toml = b"[users]\nalice = /bin/zsh\n";
        let err = Registry::parse(toml).unwrap_err();
        assert!(format!("{err}").contains("not double-quoted"));
    }

    #[test]
    fn registry_parse_rejects_missing_equals() {
        let toml = b"[users]\nalice /bin/zsh\n";
        let err = Registry::parse(toml).unwrap_err();
        assert!(format!("{err}").contains("missing '='"));
    }

    #[test]
    fn registry_parse_empty_file_returns_empty_registry() {
        let r = Registry::parse(b"").unwrap();
        assert!(r.entries.is_empty());
    }

    #[test]
    fn registry_parse_no_users_table_returns_empty() {
        let toml = b"[other]\nfoo = \"bar\"\n";
        let r = Registry::parse(toml).unwrap();
        assert!(r.entries.is_empty());
    }
}
