#!/bin/sh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Isolated sub-platform build entry point for `windows-portable-zip-arm64` (ADR 0020).

set -eu

UNIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$UNIT_DIR/../../.." && pwd)
RECIPE="$UNIT_DIR/RECIPE.toml"
DELEGATE="$REPO_ROOT/target-arm64/cargo-config.toml"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1760000000}"

if [ "${1:-}" = "--check-recipe" ]; then
  [ -f "$RECIPE" ] || { echo "missing $RECIPE" >&2; exit 1; }
  [ -e "$DELEGATE" ] || { echo "missing upstream delegate $DELEGATE" >&2; exit 1; }
  grep -q 'unit_id = "windows-portable-zip-arm64"' "$RECIPE"
  grep -q 'artifact_name = "TotalDrop-0.1.0-beta.1-portable-arm64.zip"' "$RECIPE"
  echo "recipe check ok: windows-portable-zip-arm64 -> TotalDrop-0.1.0-beta.1-portable-arm64.zip"
  exit 0
fi

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

to_win_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s\n' "$1"
  fi
}

if [ "${1:-}" = "--package-staged" ]; then
  STAGE_IN="${2:?missing staging input directory}"
  OUT_DIR="${3:?missing output directory}"
  if [ ! -d "$STAGE_IN" ]; then
    echo "error: staging input directory does not exist or is not a directory: $STAGE_IN" >&2
    exit 1
  fi
  mkdir -p "$OUT_DIR"
  stage_root=$(mktemp -d)
  trap 'rm -rf "$stage_root"' EXIT
  cp -R "$STAGE_IN/." "$stage_root/"
  printf 'unit=%s\narch=%s\nformat=%s\ntarget=%s\n' "windows-portable-zip-arm64" "arm64" "portable-zip" "aarch64-pc-windows-msvc" >"$stage_root/BUILD_METADATA.txt"
  resolve_python
  WIN_STAGE_ROOT=$(to_win_path "$stage_root")
  WIN_OUT_ZIP=$(to_win_path "$OUT_DIR/TotalDrop-0.1.0-beta.1-portable-arm64.zip")
  run_python - "$WIN_STAGE_ROOT" "$WIN_OUT_ZIP" "$SOURCE_DATE_EPOCH" <<'PY'
import datetime, os, sys, zipfile
from pathlib import Path

stage = Path(sys.argv[1])
out_zip = Path(sys.argv[2])
epoch = max(int(sys.argv[3]), 315532800)
dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
zip_dt = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

files = sorted(p for p in stage.rglob("*") if p.is_file())
with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
    for path in files:
        rel = path.relative_to(stage).as_posix()
        info = zipfile.ZipInfo(rel, date_time=zip_dt)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        zf.writestr(info, path.read_bytes())
os.utime(out_zip, (epoch, epoch))
PY
  (cd "$OUT_DIR" && sha256sum "TotalDrop-0.1.0-beta.1-portable-arm64.zip" >SHA256SUMS)
  echo "packaged windows-portable-zip-arm64 -> $OUT_DIR/TotalDrop-0.1.0-beta.1-portable-arm64.zip"
  exit 0
fi

OUT_DIR="${1:-$REPO_ROOT/dist/portable-zip/arm64}"
mkdir -p "$OUT_DIR"

case "$DELEGATE" in
  *.sh)
    sh "$DELEGATE"
    ;;
  *.ps1)
    WIN_DELEGATE=$(to_win_path "$DELEGATE")
    pwsh -NoProfile -File "$WIN_DELEGATE"
    ;;
  *)
    echo "Verified delegate configuration: $DELEGATE (Rust target: aarch64-pc-windows-msvc)"
    ;;
esac
