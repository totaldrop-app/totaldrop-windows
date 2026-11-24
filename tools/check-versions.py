#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Enforce version alignment and CLSID invariants across totaldrop-windows."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CORE_VERSION = "0.2.0-beta.5"
APP_VERSION = "0.1.0-beta.1"
MSIX_VERSION = "0.1.1.0"
CANONICAL_CLSID = "8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0"

# Split forbidden literals so this script never matches itself if scanned naively.
FORBIDDEN_LITERALS: tuple[tuple[str, str], ...] = (
    ("0.3.0-" + "beta.6", "stale pre-alignment subplatform version"),
    ("0.2." + "0.0", "stale 4-part MSIX/PE version"),
    ("8E6D76B4-" + "54A9-4D92-9A57-2F7D25F8B216", "bogus Explorer COM CLSID"),
)


def expect_eq(errors: list[str], label: str, actual: object, expected: object) -> None:
    if actual != expected:
        errors.append(f"{label}: expected {expected!r}, got {actual!r}")


def check_core_bucket(errors: list[str]) -> None:
    root_toml = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    expect_eq(
        errors,
        "Cargo.toml [workspace.package].version",
        root_toml.get("workspace", {}).get("package", {}).get("version"),
        CORE_VERSION,
    )

    for crate in (
        "totaldrop-crypto",
        "totaldrop-proto",
        "totaldrop-core",
        "totaldrop-l10n",
        "totaldrop-windows-bridge",
    ):
        manifest = tomllib.loads(
            (REPO_ROOT / "crates" / crate / "Cargo.toml").read_text(encoding="utf-8")
        )
        ver = manifest.get("package", {}).get("version")
        expect_eq(
            errors,
            f"crates/{crate}/Cargo.toml [package].version",
            ver,
            {"workspace": True},
        )


def check_ffi_and_csproj(errors: list[str]) -> None:
    ffi_toml = tomllib.loads(
        (REPO_ROOT / "crates" / "totaldrop-windows-ffi" / "Cargo.toml").read_text(
            encoding="utf-8"
        )
    )
    expect_eq(
        errors,
        "crates/totaldrop-windows-ffi/Cargo.toml [package].version",
        ffi_toml.get("package", {}).get("version"),
        APP_VERSION,
    )

    ffi_src = (REPO_ROOT / "crates" / "totaldrop-windows-ffi" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    m_core = re.search(r'pub const CORE_VERSION:\s*&str\s*=\s*"([^"]+)"', ffi_src)
    expect_eq(
        errors,
        "crates/totaldrop-windows-ffi/src/lib.rs CORE_VERSION",
        m_core.group(1) if m_core else None,
        CORE_VERSION,
    )
    m_msix = re.search(r'pub const MSIX_VERSION:\s*&str\s*=\s*"([^"]+)"', ffi_src)
    expect_eq(
        errors,
        "crates/totaldrop-windows-ffi/src/lib.rs MSIX_VERSION",
        m_msix.group(1) if m_msix else None,
        MSIX_VERSION,
    )

    csproj_root = ET.fromstring(
        (REPO_ROOT / "ui-winui3-fluent2" / "TotalDrop.WinUI.csproj").read_text(encoding="utf-8")
    )
    for tag, expected in (
        ("Version", APP_VERSION),
        ("InformationalVersion", APP_VERSION),
        ("AssemblyVersion", MSIX_VERSION),
        ("FileVersion", MSIX_VERSION),
    ):
        elem = csproj_root.find(f"./PropertyGroup/{tag}")
        expect_eq(
            errors,
            f"ui-winui3-fluent2/TotalDrop.WinUI.csproj <{tag}>",
            elem.text.strip() if elem is not None and elem.text else None,
            expected,
        )

    main_win = (REPO_ROOT / "ui-winui3-fluent2" / "MainWindow.xaml.cs").read_text(
        encoding="utf-8"
    )
    m_fb = re.search(r'FallbackAppVersion\s*=\s*"([^"]+)"', main_win)
    expect_eq(
        errors,
        "ui-winui3-fluent2/MainWindow.xaml.cs FallbackAppVersion",
        m_fb.group(1) if m_fb else None,
        APP_VERSION,
    )


def check_manifests_and_scripts(errors: list[str]) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+\.0", MSIX_VERSION):
        errors.append(
            f"MSIX_VERSION {MSIX_VERSION!r} must be 4-part with Revision == 0 for Microsoft Store"
        )

    app_manifest = ET.fromstring(
        (REPO_ROOT / "ui-winui3-fluent2" / "app.manifest").read_text(encoding="utf-8")
    )
    asm_id = app_manifest.find("{urn:schemas-microsoft-com:asm.v1}assemblyIdentity")
    expect_eq(
        errors,
        "ui-winui3-fluent2/app.manifest assemblyIdentity/@version",
        asm_id.attrib.get("version") if asm_id is not None else None,
        MSIX_VERSION,
    )

    appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
    for rel, expected_arch in (
        ("target-x86_64/Package.x64.appxmanifest", "x64"),
        ("target-arm64/Package.arm64.appxmanifest", "arm64"),
    ):
        root = ET.fromstring((REPO_ROOT / rel).read_text(encoding="utf-8"))
        ident = root.find(f"{appx_ns}Identity")
        expect_eq(
            errors,
            f"{rel} Identity/@Version",
            ident.attrib.get("Version") if ident is not None else None,
            MSIX_VERSION,
        )
        expect_eq(
            errors,
            f"{rel} Identity/@ProcessorArchitecture",
            ident.attrib.get("ProcessorArchitecture") if ident is not None else None,
            expected_arch,
        )

    for rel in ("target-x86_64/build-x64.ps1", "target-arm64/build-arm64.ps1"):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        m_ver = re.search(r'\[string\]\$Version\s*=\s*"([^"]+)"', text)
        expect_eq(
            errors,
            f"{rel} default $Version",
            m_ver.group(1) if m_ver else None,
            MSIX_VERSION,
        )

    for rel, arch_tag in (
        ("target-x86_64/winget/app.totaldrop.TotalDrop.x64.yaml", "x64"),
        ("target-arm64/winget/app.totaldrop.TotalDrop.arm64.yaml", "arm64"),
    ):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        m_pkg = re.search(r"^PackageVersion:\s*(\S+)\s*$", text, re.MULTILINE)
        expect_eq(
            errors,
            f"{rel} PackageVersion",
            m_pkg.group(1) if m_pkg else None,
            APP_VERSION,
        )
        expected_msix = f"TotalDrop_{MSIX_VERSION}_{arch_tag}.msix"
        if expected_msix not in text:
            errors.append(f"{rel}: InstallerUrl does not reference {expected_msix}")


def check_subplatforms_and_workflows(errors: list[str]) -> None:
    expected_artifacts: dict[tuple[str, str], str] = {
        ("msix", "x86_64"): f"TotalDrop_{MSIX_VERSION}_x64.msix",
        ("msix", "arm64"): f"TotalDrop_{MSIX_VERSION}_arm64.msix",
        ("portable-zip", "x86_64"): f"TotalDrop-{APP_VERSION}-portable-x64.zip",
        ("portable-zip", "arm64"): f"TotalDrop-{APP_VERSION}-portable-arm64.zip",
        ("winget", "x86_64"): f"TotalDrop-{APP_VERSION}-winget-x64.zip",
        ("winget", "arm64"): f"TotalDrop-{APP_VERSION}-winget-arm64.zip",
    }

    for (fmt, arch), expected_artifact in sorted(expected_artifacts.items()):
        unit_dir = REPO_ROOT / "subplatforms" / fmt / arch
        recipe_path = unit_dir / "RECIPE.toml"
        data = tomllib.loads(recipe_path.read_text(encoding="utf-8"))
        expect_eq(errors, f"{recipe_path.relative_to(REPO_ROOT)} version", data.get("version"), APP_VERSION)
        expect_eq(
            errors,
            f"{recipe_path.relative_to(REPO_ROOT)} artifact_name",
            data.get("artifact_name"),
            expected_artifact,
        )
        for script_name in ("build.sh", "verify.sh"):
            script_path = unit_dir / script_name
            if expected_artifact not in script_path.read_text(encoding="utf-8"):
                errors.append(
                    f"{script_path.relative_to(REPO_ROOT)}: missing expected artifact {expected_artifact}"
                )
        workflow_path = REPO_ROOT / data["workflow"]
        if expected_artifact not in workflow_path.read_text(encoding="utf-8"):
            errors.append(
                f"{workflow_path.relative_to(REPO_ROOT)}: missing expected artifact {expected_artifact}"
            )

    ci_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    expected_ci_msix = f"TotalDrop_{MSIX_VERSION}_x64.msix"
    if expected_ci_msix not in ci_text:
        errors.append(f".github/workflows/ci.yml: missing expected x64 MSIX filename {expected_ci_msix}")
    expected_ci_flag = f"--expected-version {MSIX_VERSION}"
    if expected_ci_flag not in ci_text:
        errors.append(f".github/workflows/ci.yml: missing `{expected_ci_flag}`")

    verifier_text = (REPO_ROOT / "tools" / "verify-msix-artifact.py").read_text(encoding="utf-8")
    for const_name, expected_val in (
        ("EXPECTED_APP_VERSION", APP_VERSION),
        ("EXPECTED_CORE_VERSION", CORE_VERSION),
        ("EXPECTED_MSIX_VERSION", MSIX_VERSION),
    ):
        m_const = re.search(rf'^{const_name}\s*=\s*"([^"]+)"', verifier_text, re.MULTILINE)
        expect_eq(
            errors,
            f"tools/verify-msix-artifact.py {const_name}",
            m_const.group(1) if m_const else None,
            expected_val,
        )


def check_readme_and_forbidden_literals(errors: list[str]) -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    if CANONICAL_CLSID not in readme:
        errors.append(f"README.md: missing canonical Explorer COM CLSID {{{CANONICAL_CLSID}}}")

    ls_proc = subprocess.run(
        ["git", "ls-files"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    for rel in ls_proc.stdout.splitlines():
        if not rel or rel in ("Cargo.lock", "tools/check-versions.py"):
            continue
        path = REPO_ROOT / rel
        if not path.is_file() or path.suffix.lower() in (".png", ".ico", ".pri", ".msix"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for literal, reason in FORBIDDEN_LITERALS:
            if re.search(re.escape(literal), text, re.IGNORECASE):
                errors.append(f"{rel}: contains forbidden {reason} ({literal!r})")


def main() -> int:
    errors: list[str] = []
    check_core_bucket(errors)
    check_ffi_and_csproj(errors)
    check_manifests_and_scripts(errors)
    check_subplatforms_and_workflows(errors)
    check_readme_and_forbidden_literals(errors)

    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return 1

    print(
        f"versions check OK: core={CORE_VERSION}, app={APP_VERSION}, "
        f"msix={MSIX_VERSION}, clsid={{{CANONICAL_CLSID}}}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
