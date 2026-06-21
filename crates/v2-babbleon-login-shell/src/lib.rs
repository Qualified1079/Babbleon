//! Babbleon v2 login-shell wrapper (PAM flavour 1) — library
//! surface.
//!
//! # What this defeats
//!
//! The PAM session module cannot itself arrange for the user's
//! shell to run inside `babbleon-launch-untrusted` — PAM session
//! modules return before PAM's caller (sshd, login, gdm)
//! `exec`s the shell.  Flavour 1 sidesteps the limitation by
//! making the launcher invocation BE the login shell: `chsh -s
//! /usr/local/bin/babbleon-login-shell` sets this binary as the
//! user's shell-of-record.  When sshd / login / sudo / su run
//! the user's shell, they run this wrapper, which exec's the
//! launcher with the user's real shell as the child.
//!
//! Compared with flavour 2 (PAM-internal namespace) and flavour
//! 3 (token + shell rc), this approach has the broadest bypass
//! coverage: every shell invocation goes through the wrapper,
//! including `ssh user@host CMD` (which runs `$SHELL -c CMD`).
//! The cost is per-user enrollment via `chsh`.
//!
//! See `docs/v2/pam-architecture.md` for the trade-off matrix and
//! `docs/v2/pam-flavour-1.md` for the operator install steps.
//!
//! # Mechanism
//!
//! 1. The wrapper is invoked as the user's shell.  Per POSIX
//!    convention, `argv[0]` may begin with `-` to signal a login
//!    shell.  We preserve that signal by forwarding the rest of
//!    `argv` unmodified.
//! 2. We `exec` the launcher:
//!    `babbleon-launch-untrusted --daemon-socket <PATH> -- <REAL-SHELL> --login <argv[1..]>`
//!    where `<REAL-SHELL>` defaults to `/bin/bash` and can be
//!    overridden per-user via the `BABBLEON_REAL_SHELL` env var
//!    (set in `pam_env.conf` or `~/.pam_environment`).
//! 3. The launcher establishes the untrusted-tier environment
//!    (mount namespace, scrambled view, credential gate, env
//!    scrub, seccomp, identity drop) and then exec's the real
//!    shell.  The user sees no perceptible difference except
//!    that the scrambled view is now in place.
//!
//! # Compartmentalization
//!
//! The wrapper does NOT itself perform any privileged operation.
//! It only `exec`s.  All security-relevant logic lives in the
//! launcher.  This crate exists separately so its dependency
//! graph stays minimal and its audit footprint is bounded to
//! "find the exec target and exec it."
//!
//! # Threat model boundaries
//!
//! - **Defeats:** shell invocations that bypass `/etc/profile.d/`
//!   (flavour 3's failure mode).  Non-interactive `ssh user@host
//!   CMD` still goes through this wrapper because `CMD` runs in
//!   `$SHELL -c CMD`.
//! - **Defeats:** sftp's `internal-sftp` only if the operator
//!   also chsh's sftp-only accounts to this wrapper (most don't;
//!   sftp-only accounts use `/usr/lib/openssh/sftp-server` as
//!   shell).  Documented limitation.
//! - **Does NOT defeat:** an operator who invokes a different
//!   shell directly (`/bin/zsh script.sh`).  That call bypasses
//!   the wrapper because zsh is invoked by absolute path, not
//!   via the user's shell-of-record.  Compensating control: the
//!   launcher's per-tool wrappers (real binaries replaced by
//!   per-host scrambled names) still apply to anything under the
//!   mapping.
//! - **Does NOT defeat:** a compromised launcher itself.  The
//!   wrapper hands control to the launcher and exits; if the
//!   launcher has a bug, the bug fires.  Compensating control:
//!   the launcher's audit-surface tightening
//!   (`v2-babbleon-launch-artefacts` carve-out) keeps the
//!   launcher's linked code minimal.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

use std::ffi::OsString;
use std::path::PathBuf;

/// Default install path of the launcher binary.  Overridable via
/// `BABBLEON_LAUNCH_UNTRUSTED_PATH`.
pub const DEFAULT_LAUNCHER_PATH: &str =
    "/usr/local/libexec/babbleon-launch-untrusted";

/// Default Unix-socket path the launcher uses to talk to the
/// daemon.  Overridable via `BABBLEON_DAEMON_SOCKET_PATH`.
pub const DEFAULT_DAEMON_SOCKET_PATH: &str = "/run/babbleon/daemon.sock";

/// Default real shell the wrapper exec's inside the launcher.
/// Overridable per-user via `BABBLEON_REAL_SHELL` (set via PAM
/// environment).  `/bin/bash` is chosen because it is on every
/// Linux distribution we target and accepts the `--login` flag we
/// pass through.
pub const DEFAULT_REAL_SHELL: &str = "/bin/bash";

/// Resolved invocation parameters for the wrapper.  Pure data —
/// no I/O, no env reads beyond the resolution helpers below.  Used
/// by the binary and by tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Absolute path to the launcher binary.
    pub launcher_path: PathBuf,
    /// Unix-socket path the launcher will read the activated
    /// table from.
    pub daemon_socket_path: PathBuf,
    /// Absolute path to the real shell to run inside the launcher.
    pub real_shell: PathBuf,
    /// Original `argv` as received, MINUS `argv[0]`.  Forwarded to
    /// the real shell after the `--login` flag.
    pub forwarded_args: Vec<OsString>,
}

/// Read environment overrides and assemble an [`Invocation`].
///
/// The function takes the `argv` slice (caller passes
/// `std::env::args_os().collect()`) so unit tests can exercise it
/// without touching the real process environment for argv.  Env
/// reads use `std::env::var_os` directly because tests inject via
/// a mutex-guarded `set_var` pattern.
///
/// `argv[0]` is consumed but not used: POSIX convention says it
/// may be `-bash` (login) or `bash` (non-login); the launcher's
/// `--login` flag preserves login semantics regardless.
#[must_use]
pub fn resolve(argv: &[OsString]) -> Invocation {
    let launcher_path = env_or_default(
        "BABBLEON_LAUNCH_UNTRUSTED_PATH",
        DEFAULT_LAUNCHER_PATH,
    );
    let daemon_socket_path =
        env_or_default("BABBLEON_DAEMON_SOCKET_PATH", DEFAULT_DAEMON_SOCKET_PATH);
    let real_shell = env_or_default("BABBLEON_REAL_SHELL", DEFAULT_REAL_SHELL);
    let forwarded_args = if argv.is_empty() {
        Vec::new()
    } else {
        argv[1..].to_vec()
    };
    Invocation {
        launcher_path,
        daemon_socket_path,
        real_shell,
        forwarded_args,
    }
}

/// Build the full launcher argv from an [`Invocation`].
///
/// Wire format:
///
/// ```text
/// <launcher_path> --daemon-socket <socket_path> -- <real_shell> --login <forwarded_args...>
/// ```
///
/// The `--` separator is required by the launcher's CLI to mark
/// the start of the child command (`trailing_var_arg = true`).
#[must_use]
pub fn build_argv(inv: &Invocation) -> Vec<OsString> {
    let mut argv: Vec<OsString> =
        Vec::with_capacity(6 + inv.forwarded_args.len());
    argv.push(inv.launcher_path.as_os_str().to_os_string());
    argv.push("--daemon-socket".into());
    argv.push(inv.daemon_socket_path.as_os_str().to_os_string());
    argv.push("--".into());
    argv.push(inv.real_shell.as_os_str().to_os_string());
    argv.push("--login".into());
    argv.extend(inv.forwarded_args.iter().cloned());
    argv
}

fn env_or_default(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var)
        .map_or_else(|| PathBuf::from(default), PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_with_no_overrides_uses_defaults() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("BABBLEON_LAUNCH_UNTRUSTED_PATH");
        std::env::remove_var("BABBLEON_DAEMON_SOCKET_PATH");
        std::env::remove_var("BABBLEON_REAL_SHELL");
        let inv = resolve(&[OsString::from("-bash")]);
        assert_eq!(inv.launcher_path, PathBuf::from(DEFAULT_LAUNCHER_PATH));
        assert_eq!(
            inv.daemon_socket_path,
            PathBuf::from(DEFAULT_DAEMON_SOCKET_PATH)
        );
        assert_eq!(inv.real_shell, PathBuf::from(DEFAULT_REAL_SHELL));
        assert!(inv.forwarded_args.is_empty());
    }

    #[test]
    fn resolve_honours_launcher_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("BABBLEON_LAUNCH_UNTRUSTED_PATH", "/opt/launcher");
        std::env::remove_var("BABBLEON_DAEMON_SOCKET_PATH");
        std::env::remove_var("BABBLEON_REAL_SHELL");
        let inv = resolve(&[OsString::from("bash")]);
        assert_eq!(inv.launcher_path, PathBuf::from("/opt/launcher"));
        std::env::remove_var("BABBLEON_LAUNCH_UNTRUSTED_PATH");
    }

    #[test]
    fn resolve_honours_socket_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("BABBLEON_LAUNCH_UNTRUSTED_PATH");
        std::env::set_var("BABBLEON_DAEMON_SOCKET_PATH", "/tmp/d.sock");
        std::env::remove_var("BABBLEON_REAL_SHELL");
        let inv = resolve(&[OsString::from("bash")]);
        assert_eq!(inv.daemon_socket_path, PathBuf::from("/tmp/d.sock"));
        std::env::remove_var("BABBLEON_DAEMON_SOCKET_PATH");
    }

    #[test]
    fn resolve_honours_real_shell_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("BABBLEON_LAUNCH_UNTRUSTED_PATH");
        std::env::remove_var("BABBLEON_DAEMON_SOCKET_PATH");
        std::env::set_var("BABBLEON_REAL_SHELL", "/usr/bin/zsh");
        let inv = resolve(&[OsString::from("bash")]);
        assert_eq!(inv.real_shell, PathBuf::from("/usr/bin/zsh"));
        std::env::remove_var("BABBLEON_REAL_SHELL");
    }

    #[test]
    fn resolve_forwards_args_minus_argv0() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("BABBLEON_LAUNCH_UNTRUSTED_PATH");
        std::env::remove_var("BABBLEON_DAEMON_SOCKET_PATH");
        std::env::remove_var("BABBLEON_REAL_SHELL");
        let argv: Vec<OsString> = ["-bash", "-c", "echo hi"]
            .iter()
            .map(|s| (*s).into())
            .collect();
        let inv = resolve(&argv);
        assert_eq!(inv.forwarded_args.len(), 2);
        assert_eq!(inv.forwarded_args[0], OsString::from("-c"));
        assert_eq!(inv.forwarded_args[1], OsString::from("echo hi"));
    }

    #[test]
    fn build_argv_shapes_the_launcher_invocation() {
        let inv = Invocation {
            launcher_path: PathBuf::from("/usr/local/libexec/launcher"),
            daemon_socket_path: PathBuf::from("/run/babbleon/d.sock"),
            real_shell: PathBuf::from("/bin/bash"),
            forwarded_args: vec!["-c".into(), "ls -la".into()],
        };
        let argv = build_argv(&inv);
        let as_strs: Vec<&str> =
            argv.iter().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(
            as_strs,
            vec![
                "/usr/local/libexec/launcher",
                "--daemon-socket",
                "/run/babbleon/d.sock",
                "--",
                "/bin/bash",
                "--login",
                "-c",
                "ls -la",
            ]
        );
    }

    #[test]
    fn build_argv_handles_empty_forwarded_args() {
        let inv = Invocation {
            launcher_path: PathBuf::from("/l"),
            daemon_socket_path: PathBuf::from("/s"),
            real_shell: PathBuf::from("/b"),
            forwarded_args: vec![],
        };
        let argv = build_argv(&inv);
        assert_eq!(argv.len(), 6);
        assert_eq!(argv.last().unwrap(), &OsString::from("--login"));
    }

    #[test]
    fn resolve_with_empty_argv_is_safe() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("BABBLEON_LAUNCH_UNTRUSTED_PATH");
        std::env::remove_var("BABBLEON_DAEMON_SOCKET_PATH");
        std::env::remove_var("BABBLEON_REAL_SHELL");
        let inv = resolve(&[]);
        assert!(inv.forwarded_args.is_empty());
    }
}
