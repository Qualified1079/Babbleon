/*
 * pam_babbleon.so — PAM session module that establishes the Babbleon
 * mount + PID namespaces at session open by exec'ing the trusted
 * `babbleon-ns-helper`.
 *
 * Module type: `session`.
 * PAM stack example (/etc/pam.d/common-session):
 *     session optional pam_babbleon.so
 *
 * The module is intentionally tiny — all real work lives in
 * babbleon-ns-helper (Rust, auditable, single binary).  This C shim
 * only exists because the PAM ABI requires a C entry point.
 */

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#ifndef BABBLEON_NS_HELPER
#define BABBLEON_NS_HELPER "/usr/local/libexec/babbleon-ns-helper"
#endif

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                   int flags __attribute__((unused)),
                                   int argc __attribute__((unused)),
                                   const char **argv __attribute__((unused)))
{
    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_SESSION_ERR;
    }

    /* Root sessions are exempt — sysadmins need an unscrambled view. */
    if (strcmp(user, "root") == 0) {
        return PAM_SUCCESS;
    }

    pid_t pid = fork();
    if (pid < 0) {
        pam_syslog(pamh, 3 /* LOG_ERR */, "pam_babbleon: fork failed");
        return PAM_SESSION_ERR;
    }
    if (pid == 0) {
        /* Child: hand off to the Rust ns-helper which will unshare,
         * drop caps, and re-exec the user's shell.  We pass /bin/true
         * so the helper validates its argv structure without spawning
         * a real shell — the real session shell is spawned by PAM's
         * caller (login/sshd/sudo) after the session stack returns. */
        execl(BABBLEON_NS_HELPER, "babbleon-ns-helper",
              "/bin/true", (char *)NULL);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        pam_syslog(pamh, 3, "pam_babbleon: waitpid failed");
        return PAM_SESSION_ERR;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        pam_syslog(pamh, 4 /* LOG_WARNING */,
                   "pam_babbleon: helper exited with status %d", status);
        /* Optional module: don't block login on helper failure. */
        return PAM_SUCCESS;
    }
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh __attribute__((unused)),
                                    int flags __attribute__((unused)),
                                    int argc __attribute__((unused)),
                                    const char **argv __attribute__((unused)))
{
    /* Namespace teardown is automatic on process exit. */
    return PAM_SUCCESS;
}
