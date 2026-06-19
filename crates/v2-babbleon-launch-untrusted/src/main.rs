//! `babbleon-launch-untrusted` — entry point.
//!
//! Orchestrates the 11-step lifecycle from `docs/v2/least-privilege.md`.
//! All substantive logic lives in [`v2_babbleon_launch_untrusted`]
//! crate modules; this binary is purely a sequencer with exit-code
//! mapping.

#![cfg_attr(target_os = "linux", deny(unsafe_code))]
#![cfg_attr(not(target_os = "linux"), forbid(unsafe_code))]
#![deny(missing_docs)]
#![warn(clippy::pedantic)]

use clap::Parser;

use v2_babbleon_launch_untrusted::cli::Args;
use v2_babbleon_launch_untrusted::errors::Step;

fn main() {
    // tracing init — INFO by default; honour RUST_LOG override so
    // CI / debugging can crank verbosity without a rebuild.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();

    let args = Args::parse();
    let exit_code = run(&args);
    std::process::exit(exit_code);
}

// `real_uid` / `real_gid` are kernel terminology preserved across the
// entire 11-step lifecycle; see preflight::check for the rationale.
#[cfg(target_os = "linux")]
#[allow(clippy::similar_names)]
fn run(args: &Args) -> i32 {
    use v2_babbleon_launch_untrusted::{
        activated_table_input, bounding_set, identity_drop, mounts,
        namespaces, preflight, process_hardening, seccomp_profile,
    };

    macro_rules! step {
        ($step:expr, $expr:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => return exit_for_step($step, &e.to_string()),
            }
        };
    }

    // ---- Step 1 — pre-flight ------------------------------------
    let real_uid = nix::unistd::getuid().as_raw();
    let real_gid = nix::unistd::getgid().as_raw();
    let outcome = step!(Step::Preflight, preflight::check(args, real_uid, real_gid));

    tracing::info!(
        step = %Step::Preflight,
        real_uid,
        real_gid,
        cmd_argc = outcome.child_command.len(),
        "preflight ok"
    );

    // Read the per-epoch activated table BEFORE any privileged step,
    // so a malformed table never leaves the process in a half-set-up
    // namespace.  The table contains no secret material; the launcher
    // never derives keys.  Failure is attributed to Preflight because
    // it precedes the first capability-consuming step.
    let activated_table = step!(
        Step::Preflight,
        activated_table_input::read_if_present(
            args.activated_table_fd,
            args.activated_table_path.as_deref(),
            args.daemon_socket.as_deref(),
        )
    );
    if let Some(ref t) = activated_table {
        tracing::info!(
            epoch = t.epoch,
            entries = t.entries.len(),
            honey = t.honey_names.len(),
            "activated-table loaded"
        );
    } else {
        tracing::warn!(
            "no activated table supplied; scrambled view will be empty \
             (smoke-test mode only)"
        );
    }

    // ---- Step 2 — trim bounding set to 4-cap working set --------
    step!(Step::BoundingSetTrim, bounding_set::trim_to_working_set());
    tracing::info!(step = %Step::BoundingSetTrim, "bounding set trimmed");

    // ---- Step 3 — process hardening -----------------------------
    step!(Step::ProcessHardening, process_hardening::apply_secret_hygiene());
    tracing::info!(step = %Step::ProcessHardening, "hardening applied");

    // ---- Step 4 — enter NEWNS|NEWPID ----------------------------
    step!(Step::EnterNamespaces, namespaces::enter_fresh_namespaces());
    tracing::info!(step = %Step::EnterNamespaces, "namespaces entered");

    // ---- Step 5 — make root mount tree private ------------------
    step!(Step::MakeRootPrivate, namespaces::make_root_private());
    tracing::info!(step = %Step::MakeRootPrivate, "/ marked MS_PRIVATE|MS_REC");

    // ---- Step 6 — mount scrambled view --------------------------
    step!(Step::MountScrambledView, mounts::mount_scrambled_view_tmpfs());
    tracing::info!(step = %Step::MountScrambledView, "scrambled-view tmpfs mounted");
    if let Some(ref table) = activated_table {
        step!(
            Step::MountScrambledView,
            mounts::bind_mount_entries(
                std::path::Path::new(mounts::SCRAMBLED_ROOT),
                table,
            )
        );
        tracing::info!(
            step = %Step::MountScrambledView,
            count = table.entries.len(),
            "bind-mounted activated-table entries",
        );
    }

    // ---- Step 6 (continued) — credential-dir tmpfs overlays ----
    step!(
        Step::MountScrambledView,
        run_credential_gate(outcome.real_uid)
    );

    // ---- Step 7 — PR_SET_NO_NEW_PRIVS ---------------------------
    step!(Step::SetNoNewPrivs, process_hardening::set_no_new_privs());
    tracing::info!(step = %Step::SetNoNewPrivs, "NO_NEW_PRIVS=1");

    // ---- Step 9 — drop identity ---------------------------------
    // NOTE: identity drop happens BEFORE seccomp install in this
    // ordering because the v2 baseline requires seccomp to allow
    // execve and the post-step-10 surface to be minimal — we want
    // setuid/setgid to NOT be in the post-seccomp allowlist, so
    // they must run first.  Document this divergence from the
    // strict 1..=11 ordering in least-privilege.md: step 9 runs
    // before step 8 by design.  Step 8 (seccomp) closes the window
    // on every cap-requiring syscall before step 11 fires.
    step!(
        Step::DropIdentity,
        identity_drop::drop_to_real_user(outcome.real_uid, outcome.real_gid)
    );
    tracing::info!(step = %Step::DropIdentity, uid = outcome.real_uid, "identity dropped");

    // ---- Step 10 — drop remaining permitted caps ----------------
    // After setuid with KEEPCAPS=0 the effective set is already
    // cleared by the kernel; tightening the bounding set here
    // prevents file-cap regain across step-11 execve.
    step!(Step::DropAllPermitted, bounding_set::drop_all_bounding());
    tracing::info!(step = %Step::DropAllPermitted, "bounding set fully cleared");

    // ---- Step 8 (deferred to here) — seccomp ---------------------
    step!(Step::ApplySeccomp, seccomp_profile::apply());
    tracing::info!(step = %Step::ApplySeccomp, "seccomp filter installed");

    // ---- Step 11 — execve child ---------------------------------
    exec_child(&outcome.child_command)
}

#[cfg(not(target_os = "linux"))]
fn run(_args: &Args) -> i32 {
    eprintln!(
        "babbleon-launch-untrusted: Linux-only.  This binary uses \
         capabilities, mount namespaces, and seccomp; none have a \
         meaningful cross-platform analog."
    );
    Step::Preflight.code()
}

/// Look up the caller's home via getpwuid (NOT via `HOME`, which an
/// attacker can spoof), discover the per-user credential-dir set,
/// and overlay an empty tmpfs over each.
///
/// Returns `Ok(())` if the gate ran cleanly OR if home lookup failed
/// gracefully (no `/etc/passwd` entry).  Returns `Err(_)` only on a
/// `mount(2)` failure, which is a real configuration / capability
/// problem worth aborting on.
#[cfg(target_os = "linux")]
fn run_credential_gate(real_uid: u32) -> v2_babbleon_launch_untrusted::Result<()> {
    use v2_babbleon_launch_untrusted::credential_gate;

    let user_result =
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(real_uid));
    let user = match user_result {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!(
                uid = real_uid,
                "no passwd entry for caller uid; skipping credential gate",
            );
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(
                uid = real_uid,
                error = %e,
                "passwd lookup failed; skipping credential gate",
            );
            return Ok(());
        }
    };
    let cred_dirs = babbleon_core_v2::discover_credential_dirs(&user.dir);
    if cred_dirs.is_empty() {
        tracing::info!(
            home = %user.dir.display(),
            "no credential dirs to overlay",
        );
        return Ok(());
    }
    let count = cred_dirs.len();
    credential_gate::hide_credential_dirs_with_tmpfs(&cred_dirs)?;
    tracing::info!(count, "credential dirs overlaid with empty tmpfs");
    Ok(())
}

#[cfg(target_os = "linux")]
fn exec_child(cmd: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;
    let program = &cmd[0];
    let mut command = std::process::Command::new(program);
    command.args(&cmd[1..]);

    // Scrub credential-bearing env vars before exec.  Policy lives
    // in v2-babbleon-core::credentials; this binary just enforces.
    //
    // `env_clear` + `envs(scrubbed)` is the only safe shape:
    // Command::env_remove would leak any name we forgot to list,
    // whereas env_clear forces a positive whitelist by construction.
    let scrubbed_env = babbleon_core_v2::scrub_credential_env_vars(std::env::vars());
    let scrubbed_count = std::env::vars().count() - scrubbed_env.len();
    command.env_clear().envs(scrubbed_env);
    if scrubbed_count > 0 {
        tracing::info!(
            scrubbed = scrubbed_count,
            "stripped credential env vars before exec",
        );
    }

    let err = command.exec();
    eprintln!(
        "babbleon-launch-untrusted: step {} exec {}: {err}",
        Step::ExecChild.name(),
        program,
    );
    // exec(2) only returns on failure; use the step code so an
    // operator looking at $? alone can attribute the failure.
    Step::ExecChild.code()
}

/// Map a step error to a stable exit code.  Codes match
/// [`Step::code`]; values are part of the operator contract.
fn exit_for_step(step: Step, message: &str) -> i32 {
    eprintln!("babbleon-launch-untrusted: step {}: {message}", step.name());
    step.code()
}
