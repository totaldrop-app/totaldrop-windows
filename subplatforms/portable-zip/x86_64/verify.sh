#!/bin/sh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Isolated sub-platform artifact & provenance verifier for `windows-portable-zip-x86_64` (ADR 0020).

set -eu

UNIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$UNIT_DIR/../../.." && pwd)
RECIPE="$UNIT_DIR/RECIPE.toml"
WORKFLOW="$REPO_ROOT/.github/workflows/pkg-portable-zip-x86_64.yml"

if [ "${1:-}" = "--check-recipe" ]; then
  [ -f "$RECIPE" ] || { echo "missing $RECIPE" >&2; exit 1; }
  [ -f "$WORKFLOW" ] || { echo "missing workflow $WORKFLOW" >&2; exit 1; }
  sh -n "$UNIT_DIR/build.sh"
  sh -n "$UNIT_DIR/verify.sh"
  grep -q 'windows-portable-zip-x86_64-v\*' "$WORKFLOW"
  echo "verify check ok: windows-portable-zip-x86_64"
  exit 0
fi

ART_DIR="${1:?usage: verify.sh [--check-recipe | <artifact-dir>]}"
[ -f "$ART_DIR/TotalDrop-0.1.0-beta.1-portable-x64.zip" ] || { echo "missing artifact $ART_DIR/TotalDrop-0.1.0-beta.1-portable-x64.zip" >&2; exit 1; }
[ -s "$ART_DIR/TotalDrop-0.1.0-beta.1-portable-x64.zip" ] || { echo "empty artifact $ART_DIR/TotalDrop-0.1.0-beta.1-portable-x64.zip" >&2; exit 1; }
[ -f "$ART_DIR/SHA256SUMS" ] || { echo "missing $ART_DIR/SHA256SUMS" >&2; exit 1; }
(cd "$ART_DIR" && sha256sum -c SHA256SUMS)
resolve_python() {
  for py_cand in python3 python py; do
    rest_path="${PATH:-}"
    while [ -n "$rest_path" ]; do
      case "$rest_path" in
        *:*)
          dir=${rest_path%%:*}
          rest_path=${rest_path#*:}
          ;;
        *)
          dir=$rest_path
          rest_path=""
          ;;
      esac
      [ -n "$dir" ] || continue
      dir=${dir%/}
      [ -n "$dir" ] || dir="/"
      case "$dir" in
        *[Mm]icrosoft/[Ww]indows[Aa]pps|*[Mm]icrosoft/[Ww]indows[Aa]pps/*|*[Mm]icrosoft\\[Ww]indows[Aa]pps|*[Mm]icrosoft\\[Ww]indows[Aa]pps\\*)
          continue
          ;;
      esac
      for ext in "" ".exe"; do
        if [ "$dir" = "/" ]; then
          py_path="/${py_cand}${ext}"
        else
          py_path="${dir}/${py_cand}${ext}"
        fi
        [ -f "$py_path" ] && [ -x "$py_path" ] && [ ! -d "$py_path" ] || continue
        if [ "$py_cand" = "py" ]; then
          if "$py_path" -3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 2)' >/dev/null 2>&1; then
            PY_BIN="$py_path"
            PY_ARG="-3"
            return 0
          fi
        else
          if "$py_path" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 2)' >/dev/null 2>&1; then
            PY_BIN="$py_path"
            PY_ARG=""
            return 0
          fi
        fi
      done
    done
  done
  echo "error: Python >= 3.10 is required (checked python3, python, and py -3 across PATH, skipping WindowsApps stubs)" >&2
  return 1
}

run_python() {
  if [ -n "$PY_ARG" ]; then
    "$PY_BIN" "$PY_ARG" "$@"
  else
    "$PY_BIN" "$@"
  fi
}

resolve_python
WIN_ARCHIVE="$ART_DIR/TotalDrop-0.1.0-beta.1-portable-x64.zip"
if command -v cygpath >/dev/null 2>&1; then
  WIN_ARCHIVE=$(cygpath -w "$WIN_ARCHIVE")
fi
run_python - "$WIN_ARCHIVE" <<'PY'
import sys, zipfile
from pathlib import Path

archive = Path(sys.argv[1])
magic = archive.read_bytes()[:4]
if magic != b"PK\x03\x04":
    raise SystemExit(f"error: {archive.name} is not a real ZIP archive (magic={magic!r})")
with zipfile.ZipFile(archive, "r") as zf:
    bad = zf.testzip()
    if bad is not None:
        raise SystemExit(f"error: corrupt ZIP entry {bad}")
    names = zf.namelist()
    if not names or "BUILD_METADATA.txt" not in names:
        raise SystemExit(f"error: ZIP archive missing BUILD_METADATA.txt (entries={names})")
PY
echo "artifact verified: $ART_DIR/TotalDrop-0.1.0-beta.1-portable-x64.zip"
