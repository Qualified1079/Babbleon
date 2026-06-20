/*
 * pam_babbleon.so — PAM session module for Babbleon v2.
 *
 * # What this defeats
 *
 * Without a PAM module, the Babbleon untrusted-tier environment is
 * established only when a user explicitly invokes the launcher.
 * That makes the obfuscation opt-in per command, defeating the
 * point: an LLM-driven worm spawning a child via the user's shell
 * inherits the user's unscrambled view because the shell never ran
 * inside the launcher.
 *
 * This PAM module is the entry point that arranges, at session
 * open, for the user's interactive shell to run inside the launcher
 * — every subsequent process the shell spawns inherits the
 * scrambled namespace by descent.
 *
 * # Mechanism — current state (SKELETON)
 *
 * This is a v2 phase-2 *skeleton*.  It compiles, loads as a PAM
 * module, and answers `pam_sm_open_session` with a daemon-liveness
 * probe — but it does NOT yet hand the user session into the
 * untrusted-tier launcher.  The architectural question of how a
 * PAM session module wraps the eventual login shell does NOT have
 * a single right answer; the three candidates are documented in
 * `docs/v2/pam-architecture.md` and the operator picks one before
 * this module ships in a release.
 *
 * What the skeleton DOES do today:
 *
 *   1. `pam_sm_open_session` is called by PAM at session open.
 *   2. Root sessions are exempt — `sysadmin@host` needs an
 *      unscrambled view for diagnostics.  We early-return
 *      `PAM_SUCCESS` for them.
 *   3. For every other user, we probe the daemon's Unix socket
 *      at `BABBLEON_DAEMON_SOCKET_PATH` (compile-time constant,
 *      defaulting to `/run/babbleon/daemon.sock`).  Probe ==
 *      `connect(2)` succeeds.  Probe failure is non-fatal and is
 *      logged at LOG_WARNING.
 *   4. We log a one-line breadcrumb at LOG_INFO with the user name
 *      so an operator who installs this module can confirm at a
 *      glance that PAM is reaching it.
 *   5. Return `PAM_SUCCESS` unconditionally.  The PAM stack
 *      example in `build.rs` is `session optional pam_babbleon.so`
 *      — `optional` keeps a Babbleon regression from blocking
 *      logins.
 *
 * What the skeleton does NOT do — load-bearing follow-up work:
 *
 *   - Establish the namespace for the user's eventual login shell.
 *     The session module runs at the PAM-stack stage where PAM
 *     decides what to do at session creation; it does NOT itself
 *     `exec` the user's shell (that happens *after* the stack
 *     returns, in PAM's caller — login/sshd/sudo).  Wrapping the
 *     user's shell is a design choice with three flavours
 *     documented in `docs/v2/pam-architecture.md`.
 *   - Pass a daemon-socket FD to the launcher via `SCM_RIGHTS`.
 *     The launcher already supports `--daemon-socket PATH`; the
 *     FD-passing optimisation removes the post-PAM dependency on
 *     the path being mountable in the user's view.
 *   - Read pam_get_item(PAM_USER) under the right credentials.
 *     PAM session modules run as root (PAM is loaded by sshd /
 *     login / etc., which run as root before they drop).  The
 *     launcher invocation will need to preserve the caller's
 *     intended UID through one of the three architectures.
 *
 * # Threat model boundaries
 *
 *   - Defeats: the "user forgot to type `babbleon`" failure mode.
 *     Once wired (post-skeleton), every user login is automatically
 *     under the launcher.
 *   - Does NOT defeat: root sessions (intentionally exempt).
 *   - Does NOT defeat: a hostile PAM stack reorder.  Operator
 *     responsibility per `/etc/pam.d/` review.
 *
 * # Why C (and not Rust)
 *
 * PAM's ABI is C.  Linux-PAM looks up `pam_sm_open_session` and
 * `pam_sm_close_session` as symbols in the loaded `.so` via
 * `dlsym(3)`.  A pure-Rust PAM module is theoretically possible via
 * `#[no_mangle]` + `extern "C"`, but:
 *
 *   - The C ABI surface is tiny (two entry points) and stable; no
 *     ergonomic gain from Rust.
 *   - The PAM headers' opaque types and macros translate awkwardly
 *     into Rust FFI bindings.
 *   - C+`Werror` plus the bounded entry-point shape keeps the
 *     auditor's reading surface small.  Rule 1 of the security
 *     baseline (`#![forbid(unsafe_code)]`) does not apply here
 *     because there is no Rust code in the runtime artifact — the
 *     `src/lib.rs` stub is build-time scaffolding only.
 *
 * Future Rust port is filed as a follow-up; the immediate priority
 * is choosing the session-architecture (the architectural problem,
 * not the language).
 */

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/_pam_types.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#ifndef BABBLEON_LAUNCH_UNTRUSTED_PATH
#define BABBLEON_LAUNCH_UNTRUSTED_PATH "/usr/local/libexec/babbleon-launch-untrusted"
#endif

#ifndef BABBLEON_DAEMON_SOCKET_PATH
#define BABBLEON_DAEMON_SOCKET_PATH "/run/babbleon/daemon.sock"
#endif

/*
 * Probe the daemon's Unix socket.  Returns 0 on success, -1 on any
 * failure (with errno propagated from the failing syscall).  Used
 * by `pam_sm_open_session` for a non-fatal liveness check.
 *
 * Side effects:
 *   - Opens and immediately closes one Unix-stream FD.  No bytes
 *     are written to the daemon — the connect itself is the probe.
 *
 * Safety:
 *   - Treats `BABBLEON_DAEMON_SOCKET_PATH` as a NUL-terminated C
 *     string of length less than `sizeof(addr.sun_path)`.  Compile
 *     fails (via the static_assert below) if that invariant is
 *     violated.
 */
static int babbleon_probe_daemon_socket(void)
{
    struct sockaddr_un addr;
    int fd;
    int rc;

    /* Path length is a compile-time constant; we check it once. */
    _Static_assert(
        sizeof(BABBLEON_DAEMON_SOCKET_PATH) <= sizeof(addr.sun_path),
        "BABBLEON_DAEMON_SOCKET_PATH does not fit in sun_path"
    );

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* The static_assert above guarantees this fits. */
    memcpy(addr.sun_path, BABBLEON_DAEMON_SOCKET_PATH,
           sizeof(BABBLEON_DAEMON_SOCKET_PATH));

    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    /* Preserve errno across close(). */
    if (rc < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    close(fd);
    return 0;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                   int flags __attribute__((unused)),
                                   int argc __attribute__((unused)),
                                   const char **argv __attribute__((unused)))
{
    const char *user = NULL;
    int probe_rc;

    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        pam_syslog(pamh, LOG_ERR,
                   "pam_babbleon: pam_get_user failed; passing session through");
        /* Optional module: do not block login on PAM-internal failure. */
        return PAM_SUCCESS;
    }

    /* Root sessions are exempt — operators need an unscrambled
     * view for diagnostics.  See module-level "What this defeats"
     * comment. */
    if (strcmp(user, "root") == 0) {
        return PAM_SUCCESS;
    }

    probe_rc = babbleon_probe_daemon_socket();
    if (probe_rc != 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "pam_babbleon: daemon socket %s not reachable (errno=%d, %s); "
                   "session continuing un-scrambled",
                   BABBLEON_DAEMON_SOCKET_PATH, errno, strerror(errno));
        /* Skeleton behaviour: log and continue.  Once the
         * session-architecture is chosen (docs/v2/pam-architecture.md),
         * the launcher invocation goes here. */
        return PAM_SUCCESS;
    }

    pam_syslog(pamh, LOG_INFO,
               "pam_babbleon: session opened for user %s (daemon reachable; "
               "launcher invocation pending phase-2 follow-up)",
               user);

    /* Compile-time advertisement of where the launcher lives.  When
     * the architecture lands, the exec is added here; until then we
     * intentionally do not invoke it. */
    (void)BABBLEON_LAUNCH_UNTRUSTED_PATH;

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh __attribute__((unused)),
                                    int flags __attribute__((unused)),
                                    int argc __attribute__((unused)),
                                    const char **argv __attribute__((unused)))
{
    /* Namespace teardown is automatic on process exit; nothing to
     * do here.  Stub for ABI completeness. */
    return PAM_SUCCESS;
}
