# PAM session architecture — three candidate flavours

**Status: open.** Drafted 2026-06-20 alongside the
`crates/v2-babbleon-pam/` skeleton.  The skeleton compiles, loads,
and probes the daemon socket; but it does NOT yet arrange the
user's login shell to run inside `babbleon-launch-untrusted`.
That wrapping is the architectural problem; this document
enumerates the three viable architectures so the operator can
pick before the module ships in a release.

Cross-refs:

- `crates/v2-babbleon-pam/src/pam_babbleon.c` — the C shim,
  referencing this doc in its module-level comment.
- `crates/v2-babbleon-pam/src/lib.rs` — the Rust scaffolding and
  the `Readiness::SkeletonOnly` constant that flips to `Wired`
  when one of these architectures lands.
- `docs/v2/least-privilege.md` — the launcher's privilege
  envelope, which any of the three architectures must preserve.

## The problem in one paragraph

PAM session modules run during the **session-stack phase** of a
PAM-aware program (sshd, login, gdm, su, sudo).  They are loaded,
have `pam_sm_open_session` called, and return — *they do not
themselves `exec` the user's shell*.  The actual exec happens in
PAM's caller, *after* the session stack returns: sshd forks the
user's shell process; login does `execve(shell_path, ...)`; gdm
spawns the desktop session.  A PAM session module that wants the
user's shell to run inside a particular environment must therefore
either (a) cause PAM's caller to exec a wrapper instead of the
real shell, or (b) change the process state in a way that survives
the caller's exec, or (c) re-architect the chain so PAM itself
sits behind the launcher.

The three flavours below correspond to (a), (b), and (c).

---

## Flavour 1 — Shell wrapper (the `chsh` path)

**Mechanism.**  Install `/usr/local/bin/babbleon-login-shell` as
a thin wrapper that `exec`s
`babbleon-launch-untrusted --daemon-socket /run/babbleon/daemon.sock
   -- /bin/bash --login "$@"`.  Set this as the user's login shell
in `/etc/passwd` (via `chsh -s` at user enrollment).  PAM session
module is then **vestigial** — it logs and exits; the user's shell
is the launcher.

**Pros.**

- Trivial to reason about.  One config change per user, visible
  in `/etc/passwd`.
- Independent of the PAM stack — sudo, su, sshd all converge on
  the same login-shell path.
- Reversal is a one-line `chsh` per user.

**Cons.**

- Touches every user account.  Operator must script enrollment
  + de-enrollment.  An ops-team with 200 users in IPA / LDAP needs
  a directory-level hook.
- `/etc/passwd` shell column is `chmod 644` — readable by every
  process.  An attacker recon step trivially reads "this host
  runs babbleon" off the shell column.  Defeats one obfuscation
  goal (visibility-of-deployment).
- `su` and `sudo` may not honour the shell column in every
  configuration; cross-tool consistency requires the operator to
  audit each entry point.
- Doesn't compose with users who already have a non-default
  shell (`fish`, `zsh`).  Wrapper must accept and forward the
  user's preferred shell-of-record, kept somewhere else
  (`/etc/babbleon/users.toml`?).

**Resource cost.**  One extra fork+exec per login.  Negligible.

**Recommendation.**  Fine for single-tenant developer laptops
(v2.0's target market per phase-0 decision 5).  Awkward for
multi-tenant servers — defer until v2.x adds the directory-level
hook.

## Flavour 2 — Namespace-survival via setns / pam_namespace style

**Mechanism.**  The PAM session module itself calls
`unshare(CLONE_NEWNS | CLONE_NEWPID)` + bind-mounts inside that
namespace + `setns(2)` to keep PAM's caller in the new namespace.
PAM's caller then `exec`s the user's shell *inside* the namespace
the module established.  This is morally the same trick
`pam_namespace.so` plays.

**Pros.**

- No per-user enrollment.  Drop the module into
  `/etc/pam.d/common-session` and every login is wrapped.
- No visibility-of-deployment leak through `/etc/passwd`.
- Architecturally clean — there is exactly one namespace and the
  user's shell runs in it.

**Cons.**

- PAM session modules run with whatever credentials the caller
  has — usually root before the credential drop.  We'd be doing
  namespace work in PAM's address space, which is shared with
  any other PAM modules in the stack.  A misbehaving sibling
  module that, say, `chdir`s after `pam_babbleon` runs ends up
  in our namespace — surprising and likely buggy.
- The launcher's 11-step lifecycle assumes a fresh process.
  Calling it inside PAM's address space breaks that assumption;
  we'd have to factor the launcher's step machinery into a
  library and re-invoke it from PAM.  That's a meaningful chunk
  of work and a non-trivial audit surface (PAM modules cannot
  do `forbid(unsafe_code)`; they're shared between C and Rust
  address space).
- `setns` of the *current* process to a *new* namespace is exactly
  what `pam_namespace` does — fine — but our launcher does more
  (seccomp, capability drop, identity drop).  Doing all of that
  inside PAM's address space is risky: PAM's caller may have
  state we don't know about (file handles, signal handlers, env
  vars).  An undetected leak is a security regression.

**Resource cost.**  No fork+exec; namespace work happens in-line.
Cheap but invasive.

**Recommendation.**  Tempting but premature.  Defer until v2.x
when the launcher has been factored into a library API; even then,
the audit cost of "PAM module that owns the namespace machinery"
is high.

## Flavour 3 — Authorized-session daemon ("sudo-style splice")

**Mechanism.**  The PAM session module talks to the daemon over
the existing Unix socket and requests an **authorized session
token**.  The daemon writes the token + the activated table to a
per-session directory it owns
(`/run/babbleon/sessions/<sid>/`).  PAM's caller continues
unmodified — it execs the user's shell as usual.  The user's
shell, the moment it starts an interactive job, looks for the
session token and re-execs itself inside
`babbleon-launch-untrusted --activated-table-path ...` if found.

This is essentially the `tmux`-attaches-on-login pattern, but
done by the shell rc files instead of by PAM.  PAM's role is to
*authorize* the wrap (write the token); the wrap itself happens
in `/etc/profile.d/babbleon-attach.sh`.

**Pros.**

- PAM's job is small and bounded.  It writes one token file and
  returns.
- The exec-of-launcher happens in the user's process, not in
  PAM's — clean lifecycle separation.
- Works across login mechanisms with no per-user state in
  `/etc/passwd`.
- Lock-in of "this user's interactive shell must launch under
  babbleon" is testable as an integration test in the rooted-test
  harness.

**Cons.**

- Two failure modes: PAM didn't write the token, OR the shell rc
  didn't read it.  Diagnosing which is the problem requires
  reading two logs.
- Adds `/etc/profile.d/babbleon-attach.sh` as packaging surface.
  We already ship one binary (the launcher) and one .so (the PAM
  module); now we also ship a shell script.  Auditable but more
  pieces.
- Non-interactive logins (sftp, scp via sshd's
  `internal-sftp`) don't run `/etc/profile.d/*` — those sessions
  skip the wrap.  Operator must decide whether that's a feature
  (sftp transfers are unaffected) or a defect (sftp can be used
  to ship live exploit code into the user's home dir).

**Resource cost.**  One extra fork+exec per interactive shell
launch.  Same as flavour 1.

**Recommendation.**  Likely the best v2.0 architecture.  Smallest
PAM-module surface, no per-user enrollment, no `/etc/passwd`
visibility leak, no risk to PAM's address space.  Pay the cost
of one extra script and one extra failure mode for those wins.

---

## Decision criteria

The operator picks based on:

| Criterion | F1 (shell wrapper) | F2 (PAM-internal) | F3 (token+rc) |
|---|---|---|---|
| Per-user enrollment | ❌ required | ✅ none | ✅ none |
| Visibility-of-deployment leak | ❌ `/etc/passwd` | ✅ none | ⚠️ rc files |
| Audit surface in PAM | ✅ tiny | ❌ huge | ✅ small |
| Affects non-interactive sessions | ✅ yes | ✅ yes | ❌ no |
| Reversibility | per-user chsh | unload module | unload + remove rc |
| Composes with `fish`, `zsh` | ❌ wrapper-aware | ✅ transparent | ✅ transparent |
| Composes with sudo/su | ⚠️ config-dep | ✅ yes | ⚠️ rc-dep |
| Single-tenant fit (v2.0) | ✅ fine | ⚠️ overkill | ✅ fine |
| Multi-tenant fit (v2.x) | ❌ scripting | ✅ clean | ✅ clean |

## What lands when the operator picks

For each flavour, the PAM crate's lib.rs constant flips from
`Readiness::SkeletonOnly` → `Readiness::Wired` in the same PR
that adds:

- **Flavour 1:** a new `babbleon-login-shell` binary + the
  enrollment CLI (`babbleon enroll <user>`).
- **Flavour 2:** the launcher's step machinery factored into a
  library API + `pam_babbleon.c` invoking it via `setns`.
- **Flavour 3:** the token-write protocol added to
  `v2-babbleon-daemon-protocol` (a new
  `Request::AuthorizeSession`) + the `/etc/profile.d/*` script.

All three options leave the `babbleon-launch-untrusted` binary
unchanged.  This is by design: the launcher is the load-bearing
piece, and we don't want PAM architecture decisions to ripple
into its lifecycle.

## Default-recommendation block (for the next session)

If the operator does not pick before phase 3 starts, the default
recommendation is **flavour 3**.  It minimises PAM-module audit
surface, doesn't require per-user enrollment, and decouples the
PAM contract from the launcher's lifecycle.  The sftp gap is a
documented limitation, not a silent bypass.
