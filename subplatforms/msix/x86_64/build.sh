#!/bin/sh
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Isolated sub-platform build entry point for `windows-msix-x86_64` (ADR 0020).

set -eu

UNIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$UNIT_DIR/../../.." && pwd)
RECIPE="$UNIT_DIR/RECIPE.toml"
DELEGATE="$REPO_ROOT/target-x86_64/build-x64.ps1"
MSIX_VERSION="0.1.1.0"
ARTIFACT_NAME="TotalDrop_0.1.1.0_x64.msix"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1760000000}"

if [ "${1:-}" = "--check-recipe" ]; then
  [ -f "$RECIPE" ] || { echo "missing $RECIPE" >&2; exit 1; }
  [ -e "$DELEGATE" ] || { echo "missing upstream delegate $DELEGATE" >&2; exit 1; }
  grep -q 'unit_id = "windows-msix-x86_64"' "$RECIPE"
  grep -q 'version = "0.1.0-beta.1"' "$RECIPE"
  grep -q "artifact_name = \"$ARTIFACT_NAME\"" "$RECIPE"
  echo "recipe check ok: windows-msix-x86_64 -> $ARTIFACT_NAME"
  exit 0
fi

if [ "${1:-}" = "--package-staged" ]; then
  STAGE_IN="${2:?missing staging input directory}"
  OUT_DIR="${3:?missing output directory}"
  if [ ! -f "$STAGE_IN/AppxManifest.xml" ]; then
    echo "error: refusing to create a non-MSIX archive; missing $STAGE_IN/AppxManifest.xml" >&2
    exit 1
  fi
  MAKEAPPX_BIN="${MAKEAPPX_EXE:-}"
  if [ -z "$MAKEAPPX_BIN" ]; then
    if command -v makeappx.exe >/dev/null 2>&1; then
      MAKEAPPX_BIN="makeappx.exe"
    elif command -v makeappx >/dev/null 2>&1; then
      MAKEAPPX_BIN="makeappx"
    else
      echo "error: makeappx.exe is required to pack a real MSIX package (refusing tar.gz fallback)" >&2
      exit 1
    fi
  fi
  mkdir -p "$OUT_DIR"
  WIN_STAGE_IN="$STAGE_IN"
  WIN_OUT_MSIX="$OUT_DIR/$ARTIFACT_NAME"
  if command -v cygpath >/dev/null 2>&1; then
    WIN_STAGE_IN=$(cygpath -w "$STAGE_IN")
    WIN_OUT_MSIX=$(cygpath -w "$OUT_DIR/$ARTIFACT_NAME")
  fi
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' "$MAKEAPPX_BIN" pack /o /h SHA256 /d "$WIN_STAGE_IN" /p "$WIN_OUT_MSIX"
  (cd "$OUT_DIR" && sha256sum "$ARTIFACT_NAME" >SHA256SUMS)
  echo "packaged windows-msix-x86_64 -> $OUT_DIR/$ARTIFACT_NAME"
  exit 0
fi

OUT_DIR="${1:-$REPO_ROOT/dist/msix/x86_64}"
mkdir -p "$OUT_DIR"

WIN_DELEGATE="$DELEGATE"
WIN_OUT_DIR="$OUT_DIR"
if command -v cygpath >/dev/null 2>&1; then
  WIN_DELEGATE=$(cygpath -w "$DELEGATE")
  WIN_OUT_DIR=$(cygpath -w "$OUT_DIR")
fi

if [ "${TOTALDROP_SELF_SIGN_EPHEMERAL:-0}" = "1" ]; then
  pwsh -NoProfile -File "$WIN_DELEGATE" -Version "$MSIX_VERSION" -OutputDir "$WIN_OUT_DIR" -SelfSignEphemeral
else
  pwsh -NoProfile -File "$WIN_DELEGATE" -Version "$MSIX_VERSION" -OutputDir "$WIN_OUT_DIR"
fi
