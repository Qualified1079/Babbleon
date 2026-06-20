//! **DEPRECATED v1 — see `crates/DEPRECATED-V1.md`.  v2 replaces this
//! with `crates/v2-babbleon-launch-untrusted` (file capabilities, NOT
//! setuid).  Do not extend this binary; v2 is the source of truth for
//! new work.**
//!
//! `babbleon-ns-helper`: setuid helper that establishes the untrusted-tier
//! mount + PID namespace, drops all capabilities, then execs the child.
//!
//! # Privilege model
//!
//! The binary is installed `root:root 4755`.  It:
//!   1. Verifies it was invoked by a non-root real UID (real users only).
//!   2. Calls `unshare(CLONE_NEWNS | CLONE_NEWPID)`.
//!   3. Calls `make_root_private()` so host mounts don't propagate.
//!   4. Drops the entire Linux capability bounding set (PR_CAPBSET_DROP).
//!   5. Sets PR_SET_NO_NEW_PRIVS so the child can never re-escalate.
//!   6. Applies a seccomp-bpf filter denying dangerous process-inspection
//!      syscalls (ptrace, process_vm_*, kcmp, pidfd_*).
//!   7. Forks: parent becomes the init-reaper for the new PID NS;
//!      child drops back to real UID and execs the requested command.

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("babbleon-ns-helper: Linux only");
        std::process::exit(2);
    }

    #[cfg(target_os = "linux")]
    run()
}

#[cfg(target_os = "linux")]
fn run() -> Result<()> {
    use nix::sched::{unshare, CloneFlags};
    use nix::sys::prctl;
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult, Pid};
    use std::os::unix::process::CommandExt;

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: babbleon-ns-helper <command> [args...]");
        std::process::exit(2);
    }
    let cmd_args = &args[1..];

    // Verify setuid is in effect and caller is a real user.
    let euid = nix::unistd::geteuid();
    if !euid.is_root() {
        bail!("babbleon-ns-helper must be installed setuid root");
    }
    let real_uid = nix::unistd::getuid();
    if real_uid.is_root() {
        bail!("babbleon-ns-helper must be invoked by a non-root user");
    }
    let real_gid = nix::unistd::getgid();

    // Apply secret-process hardening early.  The ns-helper does NOT
    // hold the host_secret in memory (the CLI does, and the helper is
    // a fork/exec staging post), but defence-in-depth wants
    // PR_SET_DUMPABLE off for the helper too — if the helper crashes
    // mid-setup the core file should not capture the parent's address
    // space metadata.  As root (euid=0) the helper can also actually
    // succeed at mlockall, which the unprivileged CLI often cannot.
    let _ = babbleon::process_hardening::harden_for_secrets();

    // Establish mount + PID namespaces.
    unshare(CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID)
        .context("unshare(NEWNS|NEWPID) — requires CAP_SYS_ADMIN")?;

    // Prevent our bind-mounts from propagating to the host.
    make_root_private().context("make_root_private")?;

    // Drop the entire capability bounding set via PR_CAPBSET_DROP.
    drop_bounding_set().context("drop capability bounding set")?;

    // No new privileges ever.
    prctl::set_no_new_privs().context("PR_SET_NO_NEW_PRIVS")?;

    // Seccomp deny-list: process-inspection syscalls (single source of truth
    // in the babbleon crate).
    babbleon::enforcement::seccomp::block_process_inspection_syscalls()
        .map_err(|e| anyhow::anyhow!("seccomp: {e}"))?;

    // Landlock LSM self-sandbox: restrict filesystem access to an allowlist.
    // Best-effort — gracefully degrades if kernel < 5.13.
    let landlock_cfg = babbleon::enforcement::landlock::default_config(std::path::Path::new(
        "/run/babbleon/scrambled",
    ));
    if let Err(e) = babbleon::enforcement::landlock::apply_sandbox(&landlock_cfg) {
        tracing::warn!("landlock not applied: {e}");
    }

    // Fork: we (parent) become PID 1 init-reaper; child execs the command.
    // SAFETY: `fork(2)` itself is async-signal-safe and takes no arguments;
    // the unsafety here is purely Rust's "fork can leave the child in a
    // surprising state" hazard.  At this point in the helper we have NOT
    // yet started any threads (we run single-threaded by construction —
    // see the crate's tokio-free dependency tree) and we hold no locks,
    // so the child inherits exactly the same address space and is safe
    // to either `execve` immediately (the child branch below does this
    // via `nix::unistd::execvp`) or to call only async-signal-safe libc
    // (the reaper branch).
    match unsafe { fork() }.context("fork")? {
        ForkResult::Parent { child } => {
            // Drop back to real UID in the parent reaper.
            nix::unistd::setgroups(&[]).ok();
            nix::unistd::setgid(real_gid).ok();
            nix::unistd::setuid(real_uid).ok();
            loop {
                match waitpid(Pid::from_raw(-1), None) {
                    Ok(WaitStatus::Exited(pid, code)) if pid == child => {
                        std::process::exit(code);
                    }
                    Ok(WaitStatus::Signaled(pid, sig, _)) if pid == child => {
                        std::process::exit(128 + sig as i32);
                    }
                    Ok(_) => continue,
                    Err(nix::errno::Errno::ECHILD) => std::process::exit(0),
                    Err(e) => {
                        eprintln!("waitpid: {e}");
                        std::process::exit(1);
                    }
                }
            }
        }
        ForkResult::Child => {
            // Drop back to real UID/GID before exec.
            nix::unistd::setgroups(&[]).context("setgroups")?;
            nix::unistd::setgid(real_gid).context("setgid")?;
            nix::unistd::setuid(real_uid).context("setuid")?;

            let err = std::process::Command::new(&cmd_args[0])
                .args(&cmd_args[1..])
                .exec();
            Err(anyhow::anyhow!("exec {}: {err}", cmd_args[0]))
        }
    }
}

#[cfg(target_os = "linux")]
fn make_root_private() -> Result<()> {
    use nix::mount::{mount, MsFlags};
    use std::path::Path;
    mount(
        Some("none"),
        "/",
        None::<&Path>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&Path>,
    )
    .map_err(|e| anyhow::anyhow!("MS_PRIVATE|MS_REC: {e}"))
}

#[cfg(target_os = "linux")]
fn drop_bounding_set() -> Result<()> {
    // Linux has 41 capability slots (0..=40).  We drop each from the bounding
    // set via PR_CAPBSET_DROP; the child inherits an empty bounding set and
    // can never gain new caps even via file capabilities.
    for cap in 0i32..=40 {
        // SAFETY: `prctl(2)` with `PR_CAPBSET_DROP` and a capability
        // number is a documented kernel ABI taking five scalar args.
        // We pass the cap number as an unsigned long and zero for the
        // unused trailing args.  No pointers, no aliasing, no lifetime
        // concern; the only way this can "fail" is EINVAL when the cap
        // number is not allocated on this kernel, which we handle below.
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // EINVAL means the cap doesn't exist; harmless.
            if err.raw_os_error() != Some(libc::EINVAL) {
                tracing::warn!("PR_CAPBSET_DROP {cap}: {err}");
            }
        }
    }
    Ok(())
}
