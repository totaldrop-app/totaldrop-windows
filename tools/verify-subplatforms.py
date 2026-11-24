#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""CI verifier for isolated `subplatforms/<format>/<arch>/` units in `totaldrop-windows` (ADR 0020)."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_REPO = "totaldrop-windows"
EXPECTED_PLATFORM = "windows"
EXPECTED_UNITS = 6


def main() -> int:
    sub_root = REPO_ROOT / "subplatforms"
    if not sub_root.is_dir():
        print(f"error: missing {sub_root}", file=sys.stderr)
        return 1

    recipes = sorted(sub_root.glob("*/*/RECIPE.toml"))
    if len(recipes) != EXPECTED_UNITS:
        print(
            f"error: expected {EXPECTED_UNITS} subplatform units in {EXPECTED_REPO}, found {len(recipes)}",
            file=sys.stderr,
        )
        return 1

    has_dash = sys.platform != "win32" and shutil.which("dash") is not None
    portable_tested = 0

    for recipe_path in recipes:
        unit_dir = recipe_path.parent
        fmt = unit_dir.parent.name
        arch = unit_dir.name
        data = tomllib.loads(recipe_path.read_text(encoding="utf-8"))

        expected_unit_id = f"{EXPECTED_PLATFORM}-{fmt}-{arch}"
        assert data["unit_id"] == expected_unit_id, f"unit_id mismatch in {recipe_path}"
        assert data["repository"] == EXPECTED_REPO, f"repository mismatch in {recipe_path}"
        assert data["platform"] == EXPECTED_PLATFORM
        assert data["format"] == fmt
        assert data["arch"] == arch
        assert data["reproducible"] is True
        assert data["provenance"] == "sigstore-oidc"
        assert data["checksums_file"] == "SHA256SUMS"
        assert data["l10n_locales"] == 35

        workflow = REPO_ROOT / data["workflow"]
        if not workflow.is_file():
            print(f"error: missing workflow {workflow}", file=sys.stderr)
            return 1

        build_rel = (unit_dir / "build.sh").relative_to(REPO_ROOT).as_posix()
        verify_rel = (unit_dir / "verify.sh").relative_to(REPO_ROOT).as_posix()
        for rel_script in (build_rel, verify_rel):
            subprocess.run(["sh", "-n", rel_script], cwd=REPO_ROOT, check=True)
            if has_dash:
                subprocess.run(["dash", "-n", rel_script], cwd=REPO_ROOT, check=True)

        subprocess.run(["sh", build_rel, "--check-recipe"], cwd=REPO_ROOT, check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["sh", verify_rel, "--check-recipe"], cwd=REPO_ROOT, check=True, stdout=subprocess.DEVNULL)

        # End-to-end staged archive build + SHA256SUMS verification on portable archive units
        can_smoke = (
            (fmt in ("tar-gz", "static-tar-gz", "wasm32-simd128", "wasm32-baseline") and shutil.which("tar") is not None)
            or fmt in ("portable-zip", "winget")
        )
        if can_smoke and shutil.which("sha256sum"):
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                stage_in = tmp_path / "stage"
                out_dir = tmp_path / "out"
                stage_in.mkdir()
                (stage_in / "totaldrop").write_bytes(b"#!/bin/sh\necho totaldrop\n")
                (stage_in / "totaldrop.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00")
                subprocess.run(
                    ["sh", build_rel, "--package-staged", stage_in.as_posix(), out_dir.as_posix()],
                    cwd=REPO_ROOT,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                subprocess.run(
                    ["sh", verify_rel, out_dir.as_posix()],
                    cwd=REPO_ROOT,
                    check=True,
                    stdout=subprocess.DEVNULL,
                )
                portable_tested += 1

    print(
        f"subplatforms OK ({EXPECTED_REPO}): {len(recipes)}/{EXPECTED_UNITS} isolated units verified "
        f"(portable archive smoke tests={portable_tested})."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
