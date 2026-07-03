//! Capability-lifecycle tests — `docs/v2/least-privilege.md` "Tests"
//! section, closing the TODO.md Phase-2 item "Capability-set test
//! that asserts CapEff at each lifecycle stage matches the
//! documented `CAPABILITY:` comments".
//!
//! # Why this reads `/proc/self/status` instead of only `capget(2)`
//!
//! [`v2_babbleon_launch_untrusted::syscall::capget_effective_bitmask`]
//! only returns the *effective* set.  The two invariants this file
//! checks live in different sets:
//!
//! - Step 2 ([`bounding_set::trim_to_working_set`]) narrows the
//!   **bounding** set (`CapBnd`).  Dropping a bit from the bounding
//!   set does NOT retroactively strip a capability the process
//!   already holds in its permitted/effective sets — bounding only
//!   constrains what can be *(re)acquired* later (e.g. across a
//!   file-capability `execve`).  A test that asserted `CapEff`
//!   narrowed at step 2 would be correct in the intended production
//!   deployment (file-cap install, non-root invoking user, so
//!   `CapPrm`/`CapEff` start equal to exactly the five granted caps)
//!   but WRONG in this rooted-test harness, where the test process
//!   starts as literal root with the full capability set already
//!   effective. Asserting `CapBnd` is the invariant that holds
//!   either way, and it's what `bounding_set::trim_to_working_set`
//!   actually changes.
//! - Steps 10+9 ([`bounding_set::drop_all_bounding`] then
//!   [`identity_drop::drop_to_real_user`] — deliberately in that
//!   order, see below) are where `CapPrm`/`CapEff` actually clear —
//!   `setuid(2)` away from uid 0 with `PR_SET_KEEPCAPS=0` is a
//!   genuine kernel-level cap-clearing side effect regardless of how
//!   the process arrived at uid 0, so this part of the invariant IS
//!   testable from a root harness.
//!
//! # Why step 10 runs before step 9 in this test (and in `main.rs`)
//!
//! `PR_CAPBSET_DROP` (what [`bounding_set::drop_all_bounding`] calls)
//! requires `CAP_SETPCAP` in the calling thread's *effective* set
//! for every invocation. `setuid(2)` away from uid 0 clears the
//! effective/permitted sets as a kernel side effect
//! (`PR_SET_KEEPCAPS=0`) — including `CAP_SETPCAP`. So calling
//! `drop_all_bounding` AFTER `drop_to_real_user` fails with `EPERM`
//! on the very first capability it tries to drop: there is no
//! `CAP_SETPCAP` left to authorize the call. This is exactly the gap
//! that motivated adding `CAP_SETPCAP` to `WORKING_CAPS` (previously
//! four caps, missing the one `PR_CAPBSET_DROP` itself needs) and
//! reordering the orchestrator; see `bounding_set`'s module doc and
//! `docs/v2/least-privilege.md`'s "why steps transpose" section.
//!
//! Each test forks (see [`run_in_forked_child`]) before touching
//! process-wide capability/identity state: `setuid(2)` and
//! `prctl(PR_CAPBSET_DROP)` affect the whole thread group under
//! glibc's NPTL synchronization, so running them un-forked would
//! corrupt every other test sharing this test binary's process.

#![cfg(target_os = "linux")]

use v2_babbleon_launch_untrusted::bounding_set::{self, WORKING_CAPS};
use v2_babbleon_launch_untrusted::{identity_drop, process_hardening};

/// Bit mask covering every currently-defined Linux capability slot
/// (0 through `CAP_LAST_CAP` == 40, `CAP_CHECKPOINT_RESTORE`).
/// Matches `bounding_set::HIGHEST_KNOWN_CAP`, duplicated here because
/// that constant is private to the module under test.
const KNOWN_CAP_MASK: u64 = (1u64 << 41) - 1;

/// A UID/GID pair the test drops into.  `65534` is the conventional
/// `nobody`/`nogroup` id; `setuid`/`setgid` don't require a `passwd`
/// entry to exist, so this works even on minimal containers.
const DROP_UID: u32 = 65534;
const DROP_GID: u32 = 65534;

fn require_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Read the four `Cap*` lines of `/proc/self/status` as `u64`
/// bitmasks: `(CapInh, CapPrm, CapEff, CapBnd)`.
fn read_self_caps() -> (u64, u64, u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("read /proc/self/status");
    let mut inh = 0u64;
    let mut prm = 0u64;
    let mut eff = 0u64;
    let mut bnd = 0u64;
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapInh:") {
            inh = u64::from_str_radix(hex.trim(), 16).expect("CapInh hex");
        } else if let Some(hex) = line.strip_prefix("CapPrm:") {
            prm = u64::from_str_radix(hex.trim(), 16).expect("CapPrm hex");
        } else if let Some(hex) = line.strip_prefix("CapEff:") {
            eff = u64::from_str_radix(hex.trim(), 16).expect("CapEff hex");
        } else if let Some(hex) = line.strip_prefix("CapBnd:") {
            bnd = u64::from_str_radix(hex.trim(), 16).expect("CapBnd hex");
        }
    }
    (inh, prm, eff, bnd)
}

/// Bitmask of exactly [`WORKING_CAPS`].
fn working_caps_mask() -> u64 {
    WORKING_CAPS.iter().fold(0u64, |acc, &c| acc | (1u64 << c))
}

/// Run `body` inside a forked child; propagate its exit code to the
/// parent test result.  No mount-namespace entry — these tests never
/// touch mounts, only capability/identity state, which is why this
/// helper is deliberately smaller than
/// `rooted_lifecycle::run_in_forked_mount_ns`.
fn run_in_forked_child<F: FnOnce() -> u8>(body: F) {
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult};

    // SAFETY-equivalent reasoning: test harness only; `nix::fork`
    // wraps the unsafe `libc::fork`. The child runs exactly one
    // self-contained operation below and calls `process::exit`
    // without returning, so no double-drop / partial-init hazards
    // cross the fork boundary.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let code = body();
            std::process::exit(i32::from(code));
        }
        Ok(ForkResult::Parent { child }) => {
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => {}
                WaitStatus::Exited(_, code) => {
                    panic!("capability-lifecycle child exited with code {code}");
                }
                other => panic!("capability-lifecycle child status: {other:?}"),
            }
        }
        Err(e) => panic!("fork failed: {e}"),
    }
}

#[test]
#[ignore = "requires root + Linux; runs only under `cargo test -- --ignored`"]
fn step2_trim_narrows_capbnd_to_exactly_working_caps() {
    if !require_root() {
        eprintln!("SKIP: rooted-test requires effective UID 0");
        return;
    }

    run_in_forked_child(|| {
        let (_, _, _, bnd_before) = read_self_caps();
        let expected = working_caps_mask();
        if bnd_before & KNOWN_CAP_MASK == expected {
            eprintln!(
                "harness already holds only the working-cap bounding \
                 set before trim; the assertion below would pass \
                 vacuously — this container is more restricted than \
                 the test expects"
            );
            return 10;
        }

        if let Err(e) = bounding_set::trim_to_working_set() {
            eprintln!("trim_to_working_set: {e}");
            return 2;
        }

        let (_, _, _, bnd_after) = read_self_caps();
        if bnd_after & KNOWN_CAP_MASK != expected {
            eprintln!(
                "CapBnd after step 2 = {:#x}, expected exactly WORKING_CAPS = {:#x}",
                bnd_after & KNOWN_CAP_MASK,
                expected
            );
            return 3;
        }

        0
    });
}

#[test]
#[ignore = "requires root + Linux; runs only under `cargo test -- --ignored`"]
fn steps_10_and_9_clear_capeff_and_capprm_before_exec() {
    if !require_root() {
        eprintln!("SKIP: rooted-test requires effective UID 0");
        return;
    }

    run_in_forked_child(|| {
        // Step 3 first, mirroring the real orchestrator's ordering
        // (hardening happens before identity drop). Failure here is
        // reported but not fatal to the invariant under test —
        // `mlockall` legitimately degrades in constrained containers
        // (see `process_hardening::apply_secret_hygiene` doc
        // comment), so we only hard-fail on the two calls whose
        // success the capability invariant actually depends on.
        if let Err(e) = process_hardening::apply_secret_hygiene() {
            eprintln!("apply_secret_hygiene: {e}");
            return 3;
        }

        // Step 10 — clear the bounding set FIRST, while CAP_SETPCAP
        // is still effective. Calling this after the identity drop
        // fails with EPERM (see the module doc's "why step 10 runs
        // before step 9" section) — this ordering is deliberate and
        // matches the corrected `main.rs` orchestrator.
        if let Err(e) = bounding_set::drop_all_bounding() {
            eprintln!("drop_all_bounding: {e}");
            return 10;
        }

        // Step 9 — drop to a non-zero UID/GID. This is the call that
        // actually clears CapPrm/CapEff as a kernel side effect
        // (KEEPCAPS=0 was set inside apply_secret_hygiene above).
        // Bounding-set removal above does not strip CAP_SETUID/
        // CAP_SETGID from the still-intact effective set, so this
        // still succeeds even though step 10 ran first.
        if let Err(e) = identity_drop::drop_to_real_user(DROP_UID, DROP_GID) {
            eprintln!("drop_to_real_user: {e}");
            return 9;
        }

        let (_, prm, eff, bnd) = read_self_caps();
        if eff != 0 {
            eprintln!("CapEff after steps 10+9 = {eff:#x}, expected 0");
            return 4;
        }
        if prm != 0 {
            eprintln!("CapPrm after steps 10+9 = {prm:#x}, expected 0");
            return 5;
        }
        if bnd & KNOWN_CAP_MASK != 0 {
            eprintln!(
                "CapBnd after steps 10+9 = {:#x}, expected 0 in the known range",
                bnd & KNOWN_CAP_MASK
            );
            return 6;
        }

        // Belt-and-suspenders: confirm the identity actually moved,
        // otherwise a no-op setuid could vacuously pass the cap
        // assertions above.
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        if uid != DROP_UID || gid != DROP_GID {
            eprintln!(
                "identity did not move as expected: uid={uid} \
                 (want {DROP_UID}), gid={gid} (want {DROP_GID})"
            );
            return 7;
        }

        0
    });
}
