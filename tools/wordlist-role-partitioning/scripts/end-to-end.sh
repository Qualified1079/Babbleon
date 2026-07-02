#!/usr/bin/env bash
# End-to-end wordlist pipeline:
#   1. score + filter each input wordlist (density-analysis)
#   2. compute per-role allocation (role-partitioning)
#   3. extract disjoint per-role subsets from the unioned filter output
#   4. re-verify the extracted directory
#
# Intended for a phase-4 operator who wants to go from
# "here are my raw wordlist file(s)" to "here are the checked-in
# per-role artefacts" in one command.
#
# Usage:
#   scripts/end-to-end.sh <output-dir> <secret-file> <domain-label> <wordlist1> [wordlist2 ...]
#
# Assumes both tools' `cargo build --release` has run.  Bounces
# out early with a clear message otherwise.
#
# Design notes:
#   * Determinism: HKDF(secret, label) → seed → ChaCha20 →
#     Fisher-Yates.  Same inputs → byte-identical outputs.
#   * Zero temp-file collision: intermediate files live under
#     `<output-dir>/tmp/`, cleaned on success.
#   * Uses `intersect[3, 5]` as the density filter (session-1's
#     leading recommendation).  Edit the `MIN_TOKENS` /
#     `MAX_TOKENS` env vars to override.
#   * ASCII-only mode by default (matches the runtime `[a-z]+`
#     invariant).  Set `NORMALISE_DIACRITICS=1` to enable the
#     shim for multi-lang wordlists.

set -euo pipefail

if [[ $# -lt 4 ]]; then
  echo "usage: $0 <output-dir> <secret-file> <domain-label> <wordlist1> [wordlist2 ...]" >&2
  exit 2
fi

OUT_DIR="$1"; shift
SECRET_FILE="$1"; shift
LABEL="$1"; shift

# Filter knobs.
MIN_TOKENS="${MIN_TOKENS:-3}"
MAX_TOKENS="${MAX_TOKENS:-5}"
NORMALISE_DIACRITICS="${NORMALISE_DIACRITICS:-0}"

# Locate the two tools.  This script lives at
# tools/wordlist-role-partitioning/scripts/end-to-end.sh, so
# `../..` is the repo root's `tools/` dir.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DENSITY_BIN="${TOOLS_DIR}/wordlist-density-analysis/target/release/wordlist-density-analysis"
ROLE_BIN="${TOOLS_DIR}/wordlist-role-partitioning/target/release/wordlist-role-partitioning"

for bin in "$DENSITY_BIN" "$ROLE_BIN"; do
  if [[ ! -x "$bin" ]]; then
    echo "missing binary: $bin" >&2
    echo "run 'cargo build --release' in each tool directory first." >&2
    exit 1
  fi
done

if [[ ! -r "$SECRET_FILE" ]]; then
  echo "cannot read secret file: $SECRET_FILE" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
TMP="$OUT_DIR/tmp"
rm -rf "$TMP"
mkdir -p "$TMP"

# 1. Density-analysis + filter, one filtered wordlist per source.
FILTERED_ARGS=()
i=0
for src in "$@"; do
  if [[ ! -r "$src" ]]; then
    echo "cannot read wordlist: $src" >&2
    exit 1
  fi
  i=$((i + 1))
  base="$(basename "$src")"
  filtered="$TMP/filtered-${i}-${base}"
  manifest="$TMP/filtered-${i}-${base}.manifest"

  DA_FLAGS=(
    --wordlist "$src"
    --filter cl100k
    --min-tokens "$MIN_TOKENS"
    --max-tokens "$MAX_TOKENS"
    --intersect-tokenizers
    --filtered-out "$filtered"
    --manifest-out "$manifest"
    --quiet
  )
  if [[ "$NORMALISE_DIACRITICS" -eq 1 ]]; then
    DA_FLAGS+=( --normalise-diacritics )
  fi

  echo "[1/4] filtering $src -> $filtered" >&2
  "$DENSITY_BIN" "${DA_FLAGS[@]}"
  FILTERED_ARGS+=( --wordlist-path "$filtered" )
done

# 2. Role-partitioning report (for audit trail).
REPORT="$OUT_DIR/allocation.md"
echo "[2/4] writing allocation report to $REPORT" >&2
"$ROLE_BIN" --quiet --report-out "$REPORT"

# 3. Extraction over the union.
echo "[3/4] extracting disjoint per-role subsets into $OUT_DIR/roles/" >&2
mkdir -p "$OUT_DIR/roles"
"$ROLE_BIN" --quiet \
  --extract-to "$OUT_DIR/roles" \
  --extract-seed-file "$SECRET_FILE" \
  --extract-domain-label "$LABEL" \
  "${FILTERED_ARGS[@]}"

# 4. Verification pass.
echo "[4/4] verifying $OUT_DIR/roles" >&2
"$ROLE_BIN" --quiet --verify-extracted "$OUT_DIR/roles"

# Cleanup temp files on success.
rm -rf "$TMP"

echo "done." >&2
echo "outputs:" >&2
echo "  allocation report: $REPORT" >&2
echo "  role subsets:     $OUT_DIR/roles/*.txt" >&2
echo "  manifest:         $OUT_DIR/roles/MANIFEST.txt" >&2
