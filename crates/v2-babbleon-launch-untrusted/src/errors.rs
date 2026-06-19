//! Launcher error type.
//!
//! # Infrastructure module
//!
//! Every step of the lifecycle returns one of these errors tagged
//! with the [`Step`] it came from.  The orchestrator in `main.rs`
//! exits with a step-specific code so an operator looking at exit
//! status alone can localize the failure without parsing stderr.
//!
//! Errors do NOT carry secret material (security-baseline rule 13).
//! Underlying syscall errors are stringified via their `Display`
//! impl, which for `nix::Errno` and `std::io::Error` is the kernel's
//! human-readable name (e.g. `"EPERM: operation not permitted"`).

use thiserror::Error;

/// Identifier for the lifecycle step that raised an error.
///
/// Matches the table in [`crate`] documentation 1:1.  Used as the
/// process exit code offset so `echo $?` distinguishes steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Pre-flight check — caller is non-root, args parsed, target
    /// command exists in `PATH`.
    Preflight,
    /// Step 2 — drop the Linux capability bounding set down to the
    /// four caps the launcher actually needs.
    BoundingSetTrim,
    /// Step 3 — process-wide hardening: `PR_SET_DUMPABLE = 0`,
    /// `RLIMIT_CORE = 0`, `mlockall`.
    ProcessHardening,
    /// Step 4 — `unshare(NEWNS | NEWPID)`.
    EnterNamespaces,
    /// Step 5 — `mount("/", MS_PRIVATE | MS_REC)`.
    MakeRootPrivate,
    /// Step 6 — bind / tmpfs mounts that materialize the scrambled
    /// view inside the new namespace.
    MountScrambledView,
    /// Step 7 — `PR_SET_NO_NEW_PRIVS = 1`.
    SetNoNewPrivs,
    /// Step 8 — apply the post-NNP seccomp allowlist.
    ApplySeccomp,
    /// Step 9 — `setuid` / `setgid` back to the invoking real
    /// user/group.
    DropIdentity,
    /// Step 10 — drop every remaining capability from permitted set.
    DropAllPermitted,
    /// Step 11 — `fork` + `execve` the child command.
    ExecChild,
}

impl Step {
    /// The numeric step identifier used as the process exit code
    /// offset.  Values are stable across versions; never reordered.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Preflight => 1,
            Self::BoundingSetTrim => 2,
            Self::ProcessHardening => 3,
            Self::EnterNamespaces => 4,
            Self::MakeRootPrivate => 5,
            Self::MountScrambledView => 6,
            Self::SetNoNewPrivs => 7,
            Self::ApplySeccomp => 8,
            Self::DropIdentity => 9,
            Self::DropAllPermitted => 10,
            Self::ExecChild => 11,
        }
    }

    /// Human-readable name for log/error output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::BoundingSetTrim => "bounding-set-trim",
            Self::ProcessHardening => "process-hardening",
            Self::EnterNamespaces => "enter-namespaces",
            Self::MakeRootPrivate => "make-root-private",
            Self::MountScrambledView => "mount-scrambled-view",
            Self::SetNoNewPrivs => "set-no-new-privs",
            Self::ApplySeccomp => "apply-seccomp",
            Self::DropIdentity => "drop-identity",
            Self::DropAllPermitted => "drop-all-permitted",
            Self::ExecChild => "exec-child",
        }
    }
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The launcher error.
#[derive(Debug, Error)]
pub enum Error {
    /// Pre-flight check rejected the invocation (bad arguments,
    /// root-uid caller, missing target command, etc.).
    #[error("preflight rejected: {0}")]
    Preflight(String),

    /// `PR_CAPBSET_DROP` failed for a non-EINVAL reason (EINVAL is
    /// silently ignored — capability slot doesn't exist on this
    /// kernel — see [`crate::bounding_set`]).
    #[error("capability bounding-set drop failed: {0}")]
    BoundingSet(String),

    /// `prctl` / `setrlimit` / `mlockall` failed.  The launcher does
    /// NOT degrade gracefully on `mlockall` failure when the caller
    /// has `CAP_IPC_LOCK` — that indicates a kernel anomaly worth
    /// surfacing.  Without `CAP_IPC_LOCK` (e.g. running outside
    /// production install mode) `mlockall` may legitimately EPERM
    /// and the launcher logs+continues.
    #[error("process-hardening step failed: {0}")]
    Hardening(String),

    /// `unshare(2)` rejected — usually `EPERM` (caller lacks
    /// `CAP_SYS_ADMIN`) or `ENOSPC` (per-user namespace limit).
    #[error("unshare(NEWNS|NEWPID) failed: {0}")]
    Unshare(String),

    /// `mount(2)` failed.  Wraps the kernel error verbatim so the
    /// operator can disambiguate (EPERM = caps wrong; EBUSY = path
    /// already mounted; ENOENT = source missing; etc.).
    #[error("mount step failed: {0}")]
    Mount(String),

    /// `seccomp` filter compile / install failed.  Always a code
    /// bug — the profile is fixed at build time.
    #[error("seccomp install failed: {0}")]
    Seccomp(String),

    /// `setuid` / `setgid` rejected by the kernel.  Indicates the
    /// caller's real-UID / real-GID are bogus or the `CAP_SETUID`
    /// / `CAP_SETGID` bit was dropped too eagerly.
    #[error("identity-drop step failed: {0}")]
    Identity(String),

    /// `fork(2)` or `execve(2)` failed.  Wraps the kernel error.
    #[error("exec child {command:?} failed: {kernel_message}")]
    Exec {
        /// The command we tried to execute.
        command: String,
        /// The kernel error message (e.g. `"ENOENT: No such file
        /// or directory"`).  Carries no secret material.
        kernel_message: String,
    },

    /// Reading or parsing the per-epoch activated table failed.
    /// Wraps the source identifier (fd N or path P) and the
    /// underlying error.  Carries no secret material — the
    /// activated table itself contains none.
    #[error("activated-table input failed: {0}")]
    ActivatedTable(String),
}

/// Result alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
