#!/usr/bin/env bash
# Smoke test for install.sh. Does NOT build the real binaries (that's
# a multi-minute cargo build); instead fabricates stand-in
# executables of the five expected source names in a scratch source
# dir, installs into a scratch --prefix, and asserts every installed
# path ends up root:root 0755 in the right place with the right
# rename applied (babbleon-v2 -> babbleon). Also asserts install.sh
# refuses to proceed (exit 1) when a source binary is missing.
#
# Run as root (this repo's CI/dev containers run as root; install.sh
# itself requires root to chown, so this test does too).

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ "$(id -u)" != "0" ]; then
  echo "test.sh: must run as root (install.sh chowns to root:root)" >&2
  exit 1
fi

src="$work/src"
prefix="$work/prefix"
mkdir -p "$src"

for name in babbleon-v2 babbleon-login-shell babbleon-python \
            babbleon-launch-untrusted babbleon-daemon; do
  printf '#!/bin/sh\necho stand-in %s\n' "$name" > "$src/$name"
  chmod +x "$src/$name"
done

echo "test.sh: case 1 -- full install into scratch prefix"
"$here/install.sh" --source-dir "$src" --prefix "$prefix" --no-setcap

declare -A expect=(
  ["$prefix/usr/local/bin/babbleon"]=1
  ["$prefix/usr/local/bin/babbleon-login-shell"]=1
  ["$prefix/usr/local/bin/babbleon-python"]=1
  ["$prefix/usr/local/libexec/babbleon-launch-untrusted"]=1
  ["$prefix/usr/local/libexec/babbleon-daemon"]=1
  ["$prefix/run/babbleon"]=1
  ["$prefix/usr/local/libexec/babbleon/wrappers"]=1
  ["$prefix/etc/babbleon"]=1
)

fail=0
for path in "${!expect[@]}"; do
  if [ ! -e "$path" ]; then
    echo "test.sh: FAIL: expected path missing: $path" >&2
    fail=1
    continue
  fi
  uid=$(stat -c '%u' "$path")
  gid=$(stat -c '%g' "$path")
  mode=$(stat -c '%a' "$path")
  if [ "$uid" != "0" ] || [ "$gid" != "0" ]; then
    echo "test.sh: FAIL: $path is uid=$uid gid=$gid, want 0:0" >&2
    fail=1
  fi
  if [ "$mode" != "755" ]; then
    echo "test.sh: FAIL: $path is mode $mode, want 755" >&2
    fail=1
  fi
done

if [ -e "$prefix/usr/local/bin/babbleon-v2" ]; then
  echo "test.sh: FAIL: babbleon-v2 should have been installed as 'babbleon', not left under its cargo source name" >&2
  fail=1
fi

if [ "$fail" != "0" ]; then
  echo "test.sh: case 1 FAILED"
  exit 1
fi
echo "test.sh: case 1 OK -- all 5 binaries + 3 runtime dirs are root:root 0755, rename applied"

echo "test.sh: case 2 -- missing source binary is a hard failure, not a silent skip"
rm "$src/babbleon-daemon"
if "$here/install.sh" --source-dir "$src" --prefix "$work/prefix2" --no-setcap 2>/tmp/install-v2-test-case2.log; then
  echo "test.sh: FAIL: install.sh should have exited non-zero with babbleon-daemon missing" >&2
  exit 1
fi
if ! grep -q "missing built binary" /tmp/install-v2-test-case2.log; then
  echo "test.sh: FAIL: expected a 'missing built binary' message, got:" >&2
  cat /tmp/install-v2-test-case2.log >&2
  exit 1
fi
rm -f /tmp/install-v2-test-case2.log
echo "test.sh: case 2 OK -- missing binary correctly refused with exit 1"

echo "test.sh: all cases passed"
