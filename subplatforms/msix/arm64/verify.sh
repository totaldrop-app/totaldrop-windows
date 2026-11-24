#!/bin/sh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Isolated sub-platform artifact & provenance verifier for `windows-msix-arm64` (ADR 0020).

set -eu

UNIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$UNIT_DIR/../../.." && pwd)
RECIPE="$UNIT_DIR/RECIPE.toml"
WORKFLOW="$REPO_ROOT/.github/workflows/pkg-msix-arm64.yml"
ARTIFACT_NAME="TotalDrop_0.1.1.0_arm64.msix"

if [ "${1:-}" = "--check-recipe" ]; then
  [ -f "$RECIPE" ] || { echo "missing $RECIPE" >&2; exit 1; }
  [ -f "$WORKFLOW" ] || { echo "missing workflow $WORKFLOW" >&2; exit 1; }
  sh -n "$UNIT_DIR/build.sh"
  sh -n "$UNIT_DIR/verify.sh"
  grep -q 'windows-msix-arm64-v\*' "$WORKFLOW"
  echo "verify check ok: windows-msix-arm64"
  exit 0
fi

ART_DIR="${1:?usage: verify.sh [--check-recipe | <artifact-dir>]}"
MSIX_PATH="$ART_DIR/$ARTIFACT_NAME"
[ -f "$MSIX_PATH" ] || { echo "missing artifact $MSIX_PATH" >&2; exit 1; }
[ -s "$MSIX_PATH" ] || { echo "empty artifact $MSIX_PATH" >&2; exit 1; }
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
WIN_MSIX_PATH="$MSIX_PATH"
if command -v cygpath >/dev/null 2>&1; then
  WIN_MSIX_PATH=$(cygpath -w "$MSIX_PATH")
fi

run_python - "$WIN_MSIX_PATH" <<'PY'
import sys, zipfile, xml.etree.ElementTree as ET
from pathlib import Path

msix = Path(sys.argv[1])
magic = msix.read_bytes()[:4]
if magic != b"PK\x03\x04":
    raise SystemExit(f"error: {msix.name} is not a real OPC/ZIP MSIX (magic={magic!r})")
with zipfile.ZipFile(msix, "r") as zf:
    bad = zf.testzip()
    if bad is not None:
        raise SystemExit(f"error: corrupt ZIP entry {bad}")
    names = set(zf.namelist())
    required = {
        "AppxManifest.xml",
        "AppxBlockMap.xml",
        "[Content_Types].xml",
        "resources.pri",
        "totaldrop-winui.exe",
        "totaldrop_windows_ffi.dll",
    }
    missing = sorted(required - names)
    if missing:
        raise SystemExit(f"error: MSIX missing entries: {missing}")
    root = ET.fromstring(zf.read("AppxManifest.xml"))
    ident = root.find("{http://schemas.microsoft.com/appx/manifest/foundation/windows10}Identity")
    if ident is None:
        raise SystemExit("error: AppxManifest.xml missing Identity")
    if ident.attrib.get("ProcessorArchitecture") != "arm64":
        raise SystemExit(f"error: expected ProcessorArchitecture=arm64, got {ident.attrib.get('ProcessorArchitecture')!r}")
    if ident.attrib.get("Version") != "0.1.1.0":
        raise SystemExit(f"error: expected Version=0.1.1.0, got {ident.attrib.get('Version')!r}")
    com_ns = "{http://schemas.microsoft.com/appx/manifest/com/windows10}"
    for com_cls in root.iter(f"{com_ns}Class"):
        dll_path = com_cls.attrib.get("Path")
        if dll_path:
            normalized = dll_path.replace("\\", "/").lstrip("/")
            if normalized not in names:
                raise SystemExit(f"error: MSIX missing COM server binary declared in manifest: {normalized}")
PY

echo "artifact verified: $MSIX_PATH"
