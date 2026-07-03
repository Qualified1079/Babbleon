#!/usr/bin/env bash
# Babbleon v2 installer.
#
# Consolidates the manual `install`/`setcap` sequence documented in
# docs/v2/pam-flavour-1.md into one reviewable, idempotent script,
# and closes TODO.md's "Explicit root:root ownership on installed
# Babbleon artifacts" item by asserting ownership explicitly after
# every install instead of relying on an operator's ambient umask.
#
# This is deliberately NOT a packaging solution (no .deb/.rpm) --
# TODO.md's Phase 6 packaging decision is still open. It is exactly
# what that item asked for: "a real installer script asserting
# [ownership] explicitly ... rather than relying on operators
# copying the doc's example commands correctly."
#
# Usage:
#   sudo ./install.sh [--source-dir DIR] [--prefix DIR] [--no-setcap]
#
#   --source-dir DIR   Where the release binaries live. Default:
#                       target/x86_64-unknown-linux-musl/release if
#                       present, else target/release.
#   --prefix DIR        Root to install under (for testing without
#                       touching a real system). Default: "" (installs
#                       to the real /usr/local, /run, /etc paths).
#   --no-setcap         Skip the `setcap` call on the launcher (CI /
#                       containers without CAP_SETFCAP on the
#                       filesystem; the binary is still installed).
#
# Exit codes: 0 success. 1 a required source binary is missing.
# 2 an ownership/mode assertion failed after install (should be
# unreachable if `install`/`chown` themselves succeeded, but this
# script checks explicitly rather than trusting them silently, per
# the TODO item's own framing).

set -euo pipefail

SOURCE_DIR=""
PREFIX=""
DO_SETCAP=1

while [ $# -gt 0 ]; do
  case "$1" in
    --source-dir) SOURCE_DIR="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    --no-setcap) DO_SETCAP=0; shift ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)
      echo "install.sh: unrecognized argument: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "$SOURCE_DIR" ]; then
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  if [ -d "$repo_root/target/x86_64-unknown-linux-musl/release" ]; then
    SOURCE_DIR="$repo_root/target/x86_64-unknown-linux-musl/release"
  else
    SOURCE_DIR="$repo_root/target/release"
  fi
fi

# Five binaries this installer places, and where each one goes.
# Source name (as cargo builds it) -> installed name -> install dir.
# See each crate's Cargo.toml [[bin]] section for the source names;
# babbleon-v2 -> babbleon is the one rename (matches
# docs/v2/pam-flavour-1.md's install step exactly).
BIN_SPECS=(
  "babbleon-v2:babbleon:${PREFIX}/usr/local/bin"
  "babbleon-login-shell:babbleon-login-shell:${PREFIX}/usr/local/bin"
  "babbleon-python:babbleon-python:${PREFIX}/usr/local/bin"
  "babbleon-launch-untrusted:babbleon-launch-untrusted:${PREFIX}/usr/local/libexec"
  "babbleon-daemon:babbleon-daemon:${PREFIX}/usr/local/libexec"
)

assert_owned_by_root() {
  local path="$1"
  local uid gid
  uid=$(stat -c '%u' "$path")
  gid=$(stat -c '%g' "$path")
  if [ "$uid" != "0" ] || [ "$gid" != "0" ]; then
    echo "install.sh: FATAL: $path is owned by uid=$uid gid=$gid, not root:root" >&2
    exit 2
  fi
}

echo "install.sh: source dir: $SOURCE_DIR"

for spec in "${BIN_SPECS[@]}"; do
  src_name="${spec%%:*}"
  rest="${spec#*:}"
  dst_name="${rest%%:*}"
  dst_dir="${rest#*:}"
  src_path="$SOURCE_DIR/$src_name"
  dst_path="$dst_dir/$dst_name"

  if [ ! -f "$src_path" ]; then
    echo "install.sh: FATAL: missing built binary $src_path (did you run" \
         "'cargo build --release -p v2-babbleon -p v2-babbleon-daemon" \
         "-p v2-babbleon-launch-untrusted -p v2-babbleon-login-shell" \
         "-p v2-babbleon-python-shim'?)" >&2
    exit 1
  fi

  install -d -m 0755 -o root -g root "$dst_dir"
  install -m 0755 -o root -g root "$src_path" "$dst_path"
  assert_owned_by_root "$dst_path"
  echo "install.sh: installed $dst_path (root:root, 0755)"
done

# Runtime + wrapper-materialisation directories. The daemon and
# launcher create these themselves at first run if absent, but an
# installer that pre-creates them with explicit ownership removes
# the "whatever the invoking process's umask happens to produce"
# variable TODO.md's item was concerned about.
for d in "${PREFIX}/run/babbleon" "${PREFIX}/usr/local/libexec/babbleon/wrappers" "${PREFIX}/etc/babbleon"; do
  install -d -m 0755 -o root -g root "$d"
  assert_owned_by_root "$d"
  echo "install.sh: installed $d (root:root, 0755)"
done

launcher_path="${PREFIX}/usr/local/libexec/babbleon-launch-untrusted"
if [ "$DO_SETCAP" = "1" ]; then
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_sys_admin,cap_setuid,cap_setgid,cap_ipc_lock,cap_setpcap=ep' "$launcher_path"
    echo "install.sh: setcap'd $launcher_path (5 caps; see docs/v2/least-privilege.md)"
  else
    echo "install.sh: WARNING: setcap not found; skipping capability grant on" \
         "$launcher_path -- the launcher will fail at its first privileged" \
         "call until you setcap it manually. See docs/v2/least-privilege.md." >&2
  fi
else
  echo "install.sh: --no-setcap given; skipping capability grant on $launcher_path"
fi

echo "install.sh: done. Register /usr/local/bin/babbleon-login-shell in" \
     "/etc/shells and run 'babbleon enroll <user>' next -- see" \
     "docs/v2/pam-flavour-1.md."
