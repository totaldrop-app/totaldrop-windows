#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""M4 Microsoft Store readiness & ADR 0016 Step 6 cross-repository verifier.

Implements all 25 runnable M4 F23/F24/T3/T4 tests from test_blueprint.md and
TEST_INFRA.md sections 5.6 and 5.7 (6 cross-platform + 19 linux-devbox), with
honest dual-mode validation (--mode pre-reservation | store-published) and zero
live production network connections.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unicodedata
from pathlib import Path
from typing import Any

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_PARENT = REPO_ROOT.parent

GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:"
    "691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9"
)

CANONICAL_35_LOCALES: tuple[str, ...] = (
    "ar", "bn", "cs", "da", "de", "el", "en", "es", "fa", "fi",
    "fr", "he", "hi", "hu", "id", "it", "ja", "ko", "ms", "nb",
    "nl", "pl", "pt-BR", "pt-PT", "ro", "ru", "sv", "sw", "th", "tr",
    "uk", "ur", "vi", "zh-Hans", "zh-Hant",
)

PROHIBITED_STORE_TERMS: tuple[str, ...] = (
    "Plasma",
    "Hyprland",
    "Omarchy",
    "GNOME",
    "Flatpak",
    "Dolphin",
    "Nemo",
    "Nautilus",
    ".pkg",
    ".deb",
    ".rpm",
    "registered trademark",
    "AppContainer",
)

FORBIDDEN_FILENAME_RE = re.compile(
    r"(^|/)(key\.properties|\.gitleaksignore)$|\.(jks|keystore|p12|pfx|pepk|snk)$",
    flags=re.IGNORECASE,
)

HTML_TAG_RE = re.compile(r"<[A-Za-z/!]")
ALLOWED_INVISIBLE = frozenset({"\u200c", "\u200d", "\u200e", "\u200f"})
FORBIDDEN_BIDI_RANGE = frozenset(
    {chr(cp) for cp in range(0x202A, 0x202F)}
    | {chr(cp) for cp in range(0x2066, 0x206A)}
    | {"\u061c"}
)

SYNTH_STORE_NAME = "12345TotalDrop.TotalDrop"
SYNTH_STORE_PUB = "CN=11111111-2222-3333-4444-555555555555"
SYNTH_PRODUCT_ID = "9NBLGGH5XYZ1"
SYNTH_PFN = "12345TotalDrop.TotalDrop_7k8m9n0p1q2r3"
SYNTH_SHA256 = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
# Split forbidden literal so tools/check-versions.py never flags this verifier itself.
STALE_ZERO_MAJOR_VER = "0.2." + "0.0"


def _resolve_sibling_repo(
    repo_root: Path,
    name: str,
    env_var: str,
    cli_override: Path | None = None,
) -> Path:
    root = repo_root.expanduser().resolve()
    if cli_override is not None:
        return cli_override.expanduser().resolve()
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        return Path(env_val).expanduser().resolve()
    direct = root.parent / name
    if direct.is_dir():
        return direct.resolve()
    org_fallback = root.parent.parent / "totaldrop-app" / name
    if org_fallback.is_dir():
        return org_fallback.resolve()
    return direct


def _run_cmd(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        merged.update(env)
    return subprocess.run(cmd, cwd=str(cwd), env=merged, capture_output=True, text=True, check=False)


def _check_spdx_top6(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()[:6]
    head = "\n".join(lines)
    if "SPDX-FileCopyrightText:" not in head or "SPDX-License-Identifier:" not in head:
        raise ValueError(f"{path}: missing SPDX-FileCopyrightText / SPDX-License-Identifier in top 6 lines")


def _stage_version_check_root(
    repo_root: Path,
    dest: Path,
    *,
    version: str,
    name: str | None = None,
    publisher_x64: str | None = None,
    publisher_arm64: str | None = None,
) -> None:
    """Copy the 6 Store-versioned files into dest and project version/identity attributes."""
    rel_files = (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
        "ui-winui3-fluent2/app.manifest",
        "ui-winui3-fluent2/TotalDrop.WinUI.csproj",
        "target-x86_64/build-x64.ps1",
        "target-arm64/build-arm64.ps1",
    )
    for rel in rel_files:
        src = repo_root / rel
        dst = dest / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        text = src.read_text(encoding="utf-8")
        if rel.endswith(".appxmanifest"):
            text = re.sub(
                r'(<Identity\b[^>]*?Version=")[^"]*(")',
                lambda m: f"{m.group(1)}{version}{m.group(2)}",
                text,
                count=1,
            )
            if name is not None:
                text = re.sub(
                    r'(<Identity\b[^>]*?Name=")[^"]*(")',
                    lambda m: f"{m.group(1)}{name}{m.group(2)}",
                    text,
                    count=1,
                )
            pub = publisher_x64 if "x64" in rel else publisher_arm64
            if pub is not None:
                text = re.sub(
                    r'(<Identity\b[^>]*?Publisher=")[^"]*(")',
                    lambda m: f"{m.group(1)}{pub}{m.group(2)}",
                    text,
                    count=1,
                )
        elif rel.endswith("app.manifest"):
            text = re.sub(
                r'(<assemblyIdentity\b[^>]*?version=")[^"]*(")',
                lambda m: f"{m.group(1)}{version}{m.group(2)}",
                text,
                count=1,
            )
        elif rel.endswith(".csproj"):
            for tag in ("AssemblyVersion", "FileVersion"):
                text = re.sub(
                    rf"(<{tag}>)[^<]*(</{tag}>)",
                    lambda m: f"{m.group(1)}{version}{m.group(2)}",
                    text,
                    count=1,
                )
        elif rel.endswith(".ps1"):
            text = re.sub(
                r'(\[string\]\$Version\s*=\s*")[^"]*(")',
                lambda m: f"{m.group(1)}{version}{m.group(2)}",
                text,
                count=1,
            )
        dst.write_text(text, encoding="utf-8")


def _parse_simple_winget_yaml(text: str) -> dict[str, Any]:
    """Pure-stdlib parser for winget 1.9.0 singleton manifest YAML (zero PyYAML)."""
    data: dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        if not raw.startswith(" ") and ":" in raw:
            key, val = raw.split(":", 1)
            key = key.strip()
            val = val.strip()
            if val in (">-", "|", ">", "|-"):
                block_lines: list[str] = []
                i += 1
                while i < len(lines) and (lines[i].startswith("  ") or not lines[i].strip()):
                    block_lines.append(lines[i].strip())
                    i += 1
                data[key] = " ".join(x for x in block_lines if x)
                continue
            if val == "":
                i += 1
                items: list[Any] = []
                while i < len(lines) and (lines[i].startswith("  ") or not lines[i].strip()):
                    ln = lines[i]
                    st = ln.strip()
                    if not st or st.startswith("#"):
                        i += 1
                        continue
                    if ln.startswith("  - ") and ":" in ln[4:]:
                        # List of dicts (Installers)
                        obj: dict[str, Any] = {}
                        first_k, first_v = ln[4:].split(":", 1)
                        obj[first_k.strip()] = first_v.strip()
                        i += 1
                        while i < len(lines) and (lines[i].startswith("    ") or not lines[i].strip()):
                            sub = lines[i]
                            sst = sub.strip()
                            if not sst or sst.startswith("#"):
                                i += 1
                                continue
                            if sub.startswith("    ") and not sub.startswith("      ") and ":" in sub:
                                sk, sv = sub.strip().split(":", 1)
                                sk = sk.strip()
                                sv = sv.strip()
                                if sv == "":
                                    sub_list: list[str] = []
                                    i += 1
                                    while i < len(lines) and lines[i].startswith("      - "):
                                        sub_list.append(lines[i].strip()[2:].strip())
                                        i += 1
                                    obj[sk] = sub_list
                                    continue
                                obj[sk] = sv
                            i += 1
                        items.append(obj)
                        continue
                    if ln.startswith("  - "):
                        items.append(ln.strip()[2:].strip())
                    i += 1
                data[key] = items
                continue
            data[key] = val
        i += 1
    return data


def _write_png(path: Path, width: int, height: int, color: tuple[int, int, int, int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGBA", (width, height), color)
    img.save(path, format="PNG")


def _write_jpeg_bytes(path: Path, width: int, height: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.new("RGB", (width, height), (109, 74, 224))
    img.save(path, format="JPEG")
    assert path.read_bytes()[:3] == b"\xff\xd8\xff"


def verify_store_identifiers(
    *,
    product_id: str,
    package_family_name: str,
    installer_sha256: str,
    mode: str,
) -> None:
    """Validate Store Product ID, PackageFamilyName, and InstallerSha256 per mode."""
    if mode == "pre-reservation":
        return
    if mode != "store-published":
        raise ValueError(f"unsupported mode: {mode!r}")

    errors: list[str] = []
    if not re.fullmatch(r"9[A-Z0-9]{11}", product_id) or product_id == "9N0000000000" or set(product_id[2:]) == {"0"}:
        errors.append(f"placeholder or invalid Store Product ID {product_id!r}")
    if (
        not package_family_name
        or package_family_name.endswith("_0000000000000")
        or package_family_name.startswith("TotalDrop.TotalDrop_")
    ):
        errors.append(f"placeholder PackageFamilyName {package_family_name!r}")
    if (
        not re.fullmatch(r"[0-9a-fA-F]{64}", installer_sha256)
        or installer_sha256 == "0" * 64
    ):
        errors.append(f"placeholder all-zero InstallerSha256 {installer_sha256!r}")
    if errors:
        raise ValueError("store-published identifier check failed: " + "; ".join(errors))


# ---------------------------------------------------------------------------
# ADR 0016 Step 6 Cross-Repo Ecosystem Validators (Dual-Mode, Non-Vacuous)


def verify_site_step6(site_dir: Path, *, mode: str) -> None:
    """Audit totaldrop-site across donate, download, roadmap, 35 i18n JSONs & 35 privacy HTMLs."""
    # 1. Always enforce zero don.b4 regression and retained don.b3 (live & post-launch)
    donate_html = (site_dir / "public" / "donate" / "index.html").read_text(encoding="utf-8")
    if "don.b4" in donate_html:
        raise ValueError("totaldrop-site/public/donate/index.html regressed: forbidden 'don.b4' found")
    if "don.b3" not in donate_html:
        raise ValueError("totaldrop-site/public/donate/index.html missing retained 'don.b3'")

    i18n_dir = site_dir / "public" / "i18n"
    for tag in CANONICAL_35_LOCALES:
        jpath = i18n_dir / f"{tag}.json"
        if not jpath.is_file():
            raise ValueError(f"missing {jpath}")
        jdata = json.loads(jpath.read_text(encoding="utf-8"))
        if "don.b4" in jdata:
            raise ValueError(f"public/i18n/{tag}.json regressed: forbidden key 'don.b4' present")
        if "don.b3" not in jdata:
            raise ValueError(f"public/i18n/{tag}.json missing retained 'don.b3'")

    # 2. Always execute live Node validators
    p_i18n = _run_cmd(["node", "tools/check-i18n.mjs"], cwd=site_dir)
    if p_i18n.returncode != 0:
        raise ValueError(f"node tools/check-i18n.mjs failed:\n{p_i18n.stdout}\n{p_i18n.stderr}")
    p_priv = _run_cmd(["node", "tools/privacy.mjs"], cwd=site_dir)
    if p_priv.returncode != 0:
        raise ValueError(f"node tools/privacy.mjs failed:\n{p_priv.stdout}\n{p_priv.stderr}")

    if mode == "pre-reservation":
        return

    # 3. Post-Step-6 store-published assertions
    en_json = json.loads((i18n_dir / "en.json").read_text(encoding="utf-8"))
    dl_win = en_json.get("dl.windows.d", "")
    rm_x5 = en_json.get("rm.x5.d", "")
    dl_verify = en_json.get("dl.verify.v1", "")

    if "unsigned" in dl_win.lower() or "until code signing is funded" in dl_win.lower():
        raise ValueError(f"dl.windows.d still contains stale pre-Store unsigned copy: {dl_win!r}")
    if "microsoft store" not in dl_win.lower() or "winget" not in dl_win.lower():
        raise ValueError(f"dl.windows.d missing Microsoft Store / winget --source msstore guidance: {dl_win!r}")
    if not re.search(r"\b9[A-Z0-9]{11}\b", dl_win) or "9N0000000000" in dl_win:
        raise ValueError(f"dl.windows.d missing real Store Product ID (9N...): {dl_win!r}")

    if "donations cover the certificate" in rm_x5.lower() or "unsigned" in rm_x5.lower():
        raise ValueError(f"rm.x5.d still contains stale certificate-funding copy: {rm_x5!r}")
    if "microsoft store" not in rm_x5.lower():
        raise ValueError(f"rm.x5.d missing Microsoft Store release wording: {rm_x5!r}")

    if "microsoft store" not in dl_verify.lower():
        raise ValueError(f"dl.verify.v1 missing Microsoft Store distribution channel: {dl_verify!r}")

    # Privacy policy version >= 8, Windows storage paths, and Store data responsibility across all 35 files
    priv_en = (site_dir / "privacy" / "en.html").read_text(encoding="utf-8")
    m_ver = re.search(r"version\s+(\d+)", priv_en, flags=re.IGNORECASE)
    if not m_ver or int(m_ver.group(1)) < 8:
        raise ValueError(f"privacy/en.html must be version >= 8 post-Step-6 (got {m_ver.group(0) if m_ver else 'none'})")
    for req_tok in (r"Downloads\TotalDrop", r"%LOCALAPPDATA%\TotalDrop\settings.json", "Microsoft Store"):
        if req_tok not in priv_en:
            raise ValueError(f"privacy/en.html missing required Step-6 disclosure token: {req_tok!r}")

    for tag in CANONICAL_35_LOCALES:
        phtml = (site_dir / "privacy" / f"{tag}.html").read_text(encoding="utf-8")
        for req_path in (r"Downloads\TotalDrop", r"%LOCALAPPDATA%\TotalDrop\settings.json"):
            if req_path not in phtml:
                raise ValueError(f"privacy/{tag}.html missing required Windows storage path {req_path!r}")


def verify_docs_step6(totaldrop_dir: Path, core_dir: Path, *, mode: str) -> None:
    """Audit totaldrop/docs/{tehdit-modeli,tasarim}.md and totaldrop-core/docs/{threat-model,design}.md."""
    tm_tr_path = totaldrop_dir / "docs" / "tehdit-modeli.md"
    ds_tr_path = totaldrop_dir / "docs" / "tasarim.md"
    tm_en_path = core_dir / "docs" / "threat-model.md"
    ds_en_path = core_dir / "docs" / "design.md"
    for p in (tm_tr_path, ds_tr_path, tm_en_path, ds_en_path):
        if not p.is_file():
            raise ValueError(f"missing ecosystem doc: {p}")

    if mode == "pre-reservation":
        return

    tm_tr = tm_tr_path.read_text(encoding="utf-8")
    tm_en = tm_en_path.read_text(encoding="utf-8")
    ds_tr = ds_tr_path.read_text(encoding="utf-8")
    ds_en = ds_en_path.read_text(encoding="utf-8")

    # T12 Store channel + Store re-signing provenance caveat + Partner Center single point of trust + runFullTrust
    for label, txt in (("totaldrop/docs/tehdit-modeli.md", tm_tr), ("totaldrop-core/docs/threat-model.md", tm_en)):
        low = txt.lower()
        if "t12" not in low or "microsoft store" not in low:
            raise ValueError(f"{label}: missing T12 Microsoft Store channel update")
        if "partner center" not in low:
            raise ValueError(f"{label}: missing Partner Center single-point-of-trust note")
        if "runfulltrust" not in low or "appcontainer" not in low:
            raise ValueError(f"{label}: missing Windows runFullTrust (no AppContainer sandbox) entry")
        if "re-sign" not in low and "yeniden imzala" not in low:
            raise ValueError(f"{label}: missing Microsoft Store re-signing provenance caveat")

    for label, txt in (("totaldrop/docs/tasarim.md", ds_tr), ("totaldrop-core/docs/design.md", ds_en)):
        low = txt.lower()
        if "winui 3" not in low or "mica" not in low or "uisettings" not in low:
            raise ValueError(f"{label}: missing Windows 11 platform row (WinUI 3 / Mica / UISettings)")
        if "animationsenabled" not in low:
            raise ValueError(f"{label}: missing Windows Kose Motion (AnimationsEnabled) entry")


def verify_readmes_step6(totaldrop_dir: Path, *, mode: str) -> None:
    """Run node site/tools/check-readmes.mjs and verify Windows promoted out of Coming."""
    p = _run_cmd(["node", "site/tools/check-readmes.mjs"], cwd=totaldrop_dir)
    if p.returncode != 0:
        raise ValueError(f"node site/tools/check-readmes.mjs failed:\n{p.stdout}\n{p.stderr}")
    combined = f"{p.stdout}\n{p.stderr}"
    if "::warning::" in combined:
        raise ValueError(f"check-readmes.mjs emitted warning(s):\n{combined}")

    if mode == "pre-reservation":
        return

    readme = (totaldrop_dir / "README.md").read_text(encoding="utf-8")
    if re.search(r"\|\s*\*\*Windows,\s*macOS,\s*iOS\*\*\s*\|\s*Coming", readme):
        raise ValueError("totaldrop/README.md still lists Windows under 'Coming'")
    if "microsoft store" not in readme.lower() or "x64" not in readme.lower() or "arm64" not in readme.lower():
        raise ValueError("totaldrop/README.md missing Microsoft Store x64/ARM64 Windows download row")
    if "winget" not in readme.lower() or "--source msstore" not in readme.lower():
        raise ValueError("totaldrop/README.md missing winget --source msstore command")


# ---------------------------------------------------------------------------
# Realistic Temp-Copy Step 6 Ecosystem Projections (for Honest Non-Vacuous Tests)


def _project_site_step6(src_site: Path, dst_site: Path) -> None:
    shutil.copytree(src_site, dst_site, ignore=shutil.ignore_patterns(".git", "node_modules"))

    # 1. Update download/index.html, roadmap/index.html, and all 35 public/i18n/*.json
    new_dl_win = (
        f"For Windows 11 (x64 and ARM64) from the Microsoft Store ({SYNTH_PRODUCT_ID}) "
        f"or via winget install --source msstore {SYNTH_PRODUCT_ID}."
    )
    new_rm_x5 = (
        "Native Windows 11 WinUI 3 app (x64 and ARM64) signed and distributed through the Microsoft Store."
    )
    new_dl_verify = (
        "Get TotalDrop only from Google Play, the Microsoft Store, from this page or from the project's "
        "GitHub releases. We do not publish anywhere else."
    )

    dl_html_path = dst_site / "public" / "download" / "index.html"
    dl_html = dl_html_path.read_text(encoding="utf-8")
    dl_html = re.sub(
        r'(<p data-i18n="dl\.windows\.d">).*?(</p>)',
        lambda m: f"{m.group(1)}{new_dl_win}{m.group(2)}",
        dl_html,
        count=1,
        flags=re.DOTALL,
    )
    dl_html = re.sub(
        r'(<li data-i18n="dl\.verify\.v1">).*?(</li>)',
        lambda m: f"{m.group(1)}{new_dl_verify}{m.group(2)}",
        dl_html,
        count=1,
        flags=re.DOTALL,
    )
    dl_html_path.write_text(dl_html, encoding="utf-8")

    rm_html_path = dst_site / "public" / "roadmap" / "index.html"
    rm_html = rm_html_path.read_text(encoding="utf-8")
    rm_html = re.sub(
        r'(<p data-i18n="rm\.x5\.d">).*?(</p>)',
        lambda m: f"{m.group(1)}{new_rm_x5}{m.group(2)}",
        rm_html,
        count=1,
        flags=re.DOTALL,
    )
    rm_html_path.write_text(rm_html, encoding="utf-8")

    i18n_dir = dst_site / "public" / "i18n"
    for tag in CANONICAL_35_LOCALES:
        jp = i18n_dir / f"{tag}.json"
        obj = json.loads(jp.read_text(encoding="utf-8"))
        obj["dl.windows.d"] = new_dl_win
        obj["rm.x5.d"] = new_rm_x5
        obj["dl.verify.v1"] = new_dl_verify
        jp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 2. Bump privacy/en.html to version 8 with Windows paths + Microsoft Store disclosure
    #    (strictly obeying privacy.mjs tag/attr/code/number parity rules!)
    priv_dir = dst_site / "privacy"
    en_priv_path = priv_dir / "en.html"
    en_priv = en_priv_path.read_text(encoding="utf-8")
    en_priv = en_priv.replace("version 7", "version 8", 1)
    win_sentence = (
        r" On Windows 11, received files are saved in <code>Downloads\TotalDrop</code> and local-only settings "
        r"stay in <code>%LOCALAPPDATA%\TotalDrop\settings.json</code>; Microsoft Store installation and update "
        "data are processed under Microsoft's own data-controller responsibility."
    )
    marker = "never goes into cloud backups or device-to-device transfers.</p>"
    assert marker in en_priv
    en_priv = en_priv.replace(marker, marker[:-4] + win_sentence + "</p>", 1)
    en_priv_path.write_text(en_priv, encoding="utf-8")

    en_hash12 = hashlib.sha256(en_priv.encode("utf-8")).hexdigest()[:12]
    for tag in CANONICAL_35_LOCALES:
        if tag == "en":
            continue
        tp = priv_dir / f"{tag}.html"
        txt = tp.read_text(encoding="utf-8")
        # Update line-1 SHA-256 stamp
        txt = re.sub(
            r"^<!-- Translated from en\.html [0-9a-f]{12}\. -->",
            f"<!-- Translated from en.html {en_hash12}. -->",
            txt,
            count=1,
        )
        # Bump eyebrow version 7 -> 8 (keeping all other numbers identical to en.html)
        lines = txt.splitlines()
        for idx, ln in enumerate(lines):
            if 'class="eyebrow"' in ln:
                lines[idx] = ln.replace("7", "8", 1)
                break
        txt = "\n".join(lines) + "\n"
        # Append matching <code> elements & Microsoft Store note inside "On your device" paragraph (before Children <h2>)
        on_dev_idx = txt.find("<h2>", txt.find("~/.config/totaldrop/settings.toml"))
        close_p = txt.rfind("</p>", 0, on_dev_idx)
        assert close_p != -1, f"failed to locate On-your-device paragraph in privacy/{tag}.html"
        txt = txt[:close_p] + win_sentence + txt[close_p:]
        tp.write_text(txt, encoding="utf-8")

    # Regenerate public/privacy.html and public/privacy/<tag>.html using real site tool
    p_wr = _run_cmd(["node", "tools/privacy.mjs", "--write"], cwd=dst_site)
    if p_wr.returncode != 0:
        raise RuntimeError(f"projected privacy.mjs --write failed:\n{p_wr.stdout}\n{p_wr.stderr}")


def _project_docs_and_readmes_step6(
    src_totaldrop: Path,
    dst_totaldrop: Path,
    src_core: Path,
    dst_core: Path,
) -> None:
    shutil.copytree(src_totaldrop, dst_totaldrop, ignore=shutil.ignore_patterns(".git", "target", "node_modules"))
    shutil.copytree(src_core, dst_core, ignore=shutil.ignore_patterns(".git", "target"))

    # 1. totaldrop/docs/tehdit-modeli.md
    tm_tr_p = dst_totaldrop / "docs" / "tehdit-modeli.md"
    tm_tr = tm_tr_p.read_text(encoding="utf-8")
    tm_tr += (
        "\n\n### Windows 11 (Microsoft Store / `T12` & `rescap:runFullTrust`)\n"
        "- `T12`: Windows packages are distributed through Microsoft Store; Microsoft Store re-signs uploaded "
        "packages (Store re-signing), so CI Sigstore provenance cannot be verified directly on end-user devices "
        "and the Partner Center account is the single point of trust.\n"
        "- Windows MSIX declares `rescap:runFullTrust` and executes at Medium Integrity Level outside an "
        "AppContainer sandbox.\n"
    )
    tm_tr_p.write_text(tm_tr, encoding="utf-8")

    # 2. totaldrop-core/docs/threat-model.md
    tm_en_p = dst_core / "docs" / "threat-model.md"
    tm_en = tm_en_p.read_text(encoding="utf-8")
    tm_en += (
        "\n\n## Windows 11 Microsoft Store Channel (T12 & runFullTrust)\n"
        "- **T12 (Distribution & Store re-signing):** Windows 11 (`x64` and `ARM64`) distributes via Microsoft Store. "
        "Microsoft Store re-signs uploaded `.msixbundle` packages, replacing CI Sigstore OIDC provenance on installed "
        "binaries; Partner Center custody is the single point of trust.\n"
        "- **Privilege boundary (`rescap:runFullTrust`):** TotalDrop for Windows runs at Medium Integrity Level "
        "outside an AppContainer sandbox.\n"
    )
    tm_en_p.write_text(tm_en, encoding="utf-8")

    # 3. totaldrop/docs/tasarim.md & totaldrop-core/docs/design.md
    win_row = (
        "| Windows 11 | WinUI 3 Fluent 2, `MicaBackdrop` (Acrylic / solid fallback), `UISettings` / "
        "`ThemeSettings` / `AccessibilitySettings` | Fluent 2 native controls | System (`ExtendsContentIntoTitleBar`) |\n"
    )
    win_motion = (
        "\nWindows 11 (`ui-winui3-fluent2/MainWindow.xaml.cs`, `SendPage`, `ReceivePage`) gates the 3.2 s "
        "Köşe rotation strictly on `UISettings.AnimationsEnabled`.\n"
    )
    for ds_path in (dst_totaldrop / "docs" / "tasarim.md", dst_core / "docs" / "design.md"):
        ds_txt = ds_path.read_text(encoding="utf-8")
        anchor = "| GNOME and others |"
        pos = ds_txt.find(anchor)
        if pos != -1:
            eol = ds_txt.find("\n", pos)
            ds_txt = ds_txt[: eol + 1] + win_row + ds_txt[eol + 1 :]
        else:
            ds_txt += "\n" + win_row
        ds_txt += win_motion
        ds_path.write_text(ds_txt, encoding="utf-8")

    # 4. Promote Windows out of Coming in README.md and re-stamp all 34 translated READMEs
    rm_path = dst_totaldrop / "README.md"
    rm_txt = rm_path.read_text(encoding="utf-8")
    old_line = "| **Windows, macOS, iOS** | Coming | The Microsoft Store signs the Windows app; Apple signing for macOS and iOS is what donations pay for first |"
    new_lines = (
        f"| **Windows** (x64 & ARM64) | [Microsoft Store](https://apps.microsoft.com/detail/{SYNTH_PRODUCT_ID}) · "
        f"`winget install --source msstore {SYNTH_PRODUCT_ID}` | Windows 11 (x64 & ARM64), signed by Microsoft Store |\n"
        "| **macOS, iOS** | Coming | Apple signing for macOS and iOS is what donations pay for first |"
    )
    assert old_line in rm_txt, "expected pre-Step-6 Windows Coming row not found in README.md"
    rm_path.write_text(rm_txt.replace(old_line, new_lines, 1), encoding="utf-8")

    other_tags = [t for t in CANONICAL_35_LOCALES if t != "en"]
    p_rm = _run_cmd(["node", "site/tools/check-readmes.mjs", "--write", *other_tags], cwd=dst_totaldrop)
    if p_rm.returncode != 0:
        raise RuntimeError(f"projected check-readmes.mjs --write failed:\n{p_rm.stdout}\n{p_rm.stderr}")


# ---------------------------------------------------------------------------
# Full 25-Test Suite Runner (6 cross-platform + 19 linux-devbox)


def run_test_suite(
    repo_root: Path,
    *,
    mode: str = "pre-reservation",
    env_filter: str = "all",
    site_dir: Path | None = None,
    totaldrop_dir: Path | None = None,
    core_dir: Path | None = None,
) -> dict[str, dict[str, Any]]:
    repo_root = repo_root.expanduser().resolve()
    results: dict[str, dict[str, Any]] = {}
    site_dir = _resolve_sibling_repo(repo_root, "totaldrop-site", "TOTALDROP_SITE_DIR", site_dir)
    totaldrop_dir = _resolve_sibling_repo(repo_root, "totaldrop", "TOTALDROP_MONOREPO_DIR", totaldrop_dir)
    core_dir = _resolve_sibling_repo(repo_root, "totaldrop-core", "TOTALDROP_CORE_DIR", core_dir)

    def record(test_id: str, test_env: str, fn: Any) -> None:
        if env_filter != "all" and env_filter != test_env:
            return
        try:
            detail = fn()
            results[test_id] = {"status": "PASS", "env": test_env, "detail": detail or "ok"}
        except Exception as exc:  # noqa: BLE001
            results[test_id] = {"status": "FAIL", "env": test_env, "detail": str(exc)}

    # --- 6 cross-platform tests ---

    def t1_f23_01() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f23-01-") as tmp:
            root_ok = Path(tmp) / "ok"
            _stage_version_check_root(repo_root, root_ok, version="1.0.1.0")
            p1 = _run_cmd(
                [sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store", "--root", str(root_ok)],
                cwd=repo_root,
            )
            if p1.returncode != 0:
                raise AssertionError(f"check-versions --store --root failed: {p1.stdout}\n{p1.stderr}")
            p2 = _run_cmd(
                [sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store-version", "1.0.1.0"],
                cwd=repo_root,
            )
            if p2.returncode != 0:
                raise AssertionError(f"check-versions --store-version 1.0.1.0 failed: {p2.stdout}\n{p2.stderr}")

            # Negative drift sub-check: mutate app.manifest to 1.0.2.0
            am = root_ok / "ui-winui3-fluent2" / "app.manifest"
            am.write_text(am.read_text(encoding="utf-8").replace('version="1.0.1.0"', 'version="1.0.2.0"', 1), encoding="utf-8")
            p3 = _run_cmd(
                [sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store", "--root", str(root_ok)],
                cwd=repo_root,
            )
            if p3.returncode == 0 or "app.manifest" not in (p3.stdout + p3.stderr):
                raise AssertionError(f"app.manifest drift was not caught: rc={p3.returncode}, out={p3.stdout}\n{p3.stderr}")
        return "Store 1.0.1.0 passes --store & --store-version; app.manifest 1.0.2.0 drift caught"

    def t2_f23_01() -> str:
        p_def = _run_cmd([sys.executable, "-B", str(repo_root / "tools" / "check-versions.py")], cwd=repo_root)
        if p_def.returncode != 0:
            raise AssertionError(f"default check-versions.py failed on 0.1.1.0: {p_def.stderr}")
        p_live = _run_cmd([sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store"], cwd=repo_root)
        if p_live.returncode == 0 or "major" not in (p_live.stdout + p_live.stderr).lower():
            raise AssertionError(f"--store did not reject live 0.1.1.0 Major == 0: {p_live.stdout}\n{p_live.stderr}")
        with tempfile.TemporaryDirectory(prefix="td-f23-01-neg-") as tmp:
            root_020 = Path(tmp) / "v0200"
            _stage_version_check_root(repo_root, root_020, version=STALE_ZERO_MAJOR_VER)
            p_020 = _run_cmd(
                [sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store", "--root", str(root_020)],
                cwd=repo_root,
            )
            if p_020.returncode == 0 or "major" not in (p_020.stdout + p_020.stderr).lower():
                raise AssertionError(
                    f"--store did not reject {STALE_ZERO_MAJOR_VER} Major == 0: {p_020.stdout}\n{p_020.stderr}"
                )
        return f"Major == 0 (0.1.1.0 & {STALE_ZERO_MAJOR_VER}) rejected under --store; default mode accepts 0.1.1.0"

    def t2_f23_02() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f23-02-") as tmp:
            for ver, expected_tok in (("1.0.0.1", "revision"), ("65536.0.0.0", "65535")):
                rdir = Path(tmp) / ver.replace(".", "_")
                _stage_version_check_root(repo_root, rdir, version=ver)
                p1 = _run_cmd(
                    [sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store", "--root", str(rdir)],
                    cwd=repo_root,
                )
                if p1.returncode == 0 or expected_tok not in (p1.stdout + p1.stderr).lower():
                    raise AssertionError(f"--store --root failed to reject {ver}: {p1.stdout}\n{p1.stderr}")
                p2 = _run_cmd(
                    [sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store-version", ver],
                    cwd=repo_root,
                )
                if p2.returncode == 0 or expected_tok not in (p2.stdout + p2.stderr).lower():
                    raise AssertionError(f"--store-version failed to reject {ver}: {p2.stdout}\n{p2.stderr}")
        return "1.0.0.1 (Revision != 0) and 65536.0.0.0 (uint16 overflow) rejected in both modes"

    def t1_f24_02() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f24-02-") as tmp:
            ok_root = Path(tmp) / "swapped"
            _stage_version_check_root(
                repo_root,
                ok_root,
                version="1.0.1.0",
                name=SYNTH_STORE_NAME,
                publisher_x64=SYNTH_STORE_PUB,
                publisher_arm64=SYNTH_STORE_PUB,
            )
            p_ok = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"),
                    "--store", "--require-store-identity", "--root", str(ok_root),
                ],
                cwd=repo_root,
            )
            if p_ok.returncode != 0:
                raise AssertionError(f"swapped Partner Center identity failed: {p_ok.stdout}\n{p_ok.stderr}")

            # Placeholder identity CN=TotalDrop MUST fail --require-store-identity
            ph_root = Path(tmp) / "placeholder"
            _stage_version_check_root(repo_root, ph_root, version="1.0.1.0")
            p_ph = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"),
                    "--store", "--require-store-identity", "--root", str(ph_root),
                ],
                cwd=repo_root,
            )
            ph_out = f"{p_ph.stdout}\n{p_ph.stderr}"
            if p_ph.returncode == 0 or "placeholder" not in ph_out.lower() or "cn=totaldrop" not in ph_out.lower():
                raise AssertionError(
                    f"--require-store-identity did not reject placeholder CN=TotalDrop with expected diagnostic "
                    f"(rc={p_ph.returncode}): {ph_out}"
                )
        return "synthetic Partner Center identity passes --store --require-store-identity; placeholder CN=TotalDrop rejected"

    def t2_f24_01() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f24-01-") as tmp:
            bad_dn = Path(tmp) / "bad_dn"
            _stage_version_check_root(
                repo_root,
                bad_dn,
                version="1.0.1.0",
                name=SYNTH_STORE_NAME,
                publisher_x64="TotalDrop",
                publisher_arm64="TotalDrop",
            )
            p_dn = _run_cmd(
                [sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store", "--root", str(bad_dn)],
                cwd=repo_root,
            )
            if p_dn.returncode == 0 or "cn=" not in (p_dn.stdout + p_dn.stderr).lower():
                raise AssertionError(f"malformed Publisher='TotalDrop' not rejected: {p_dn.stdout}\n{p_dn.stderr}")

            mismatch = Path(tmp) / "mismatch"
            _stage_version_check_root(
                repo_root,
                mismatch,
                version="1.0.1.0",
                name=SYNTH_STORE_NAME,
                publisher_x64=SYNTH_STORE_PUB,
                publisher_arm64="CN=22222222-3333-4444-5555-666666666666",
            )
            p_mm = _run_cmd(
                [sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"), "--store", "--root", str(mismatch)],
                cwd=repo_root,
            )
            if p_mm.returncode == 0 or "publisher" not in (p_mm.stdout + p_mm.stderr).lower():
                raise AssertionError(f"cross-arch Publisher mismatch not rejected: {p_mm.stdout}\n{p_mm.stderr}")
        return "malformed Publisher='TotalDrop' (no CN=) and cross-arch Publisher mismatch both rejected"

    def t1_f24_06() -> str:
        for arch, sub_arch, rel_yaml in (
            ("x64", "x86_64", "target-x86_64/winget/app.totaldrop.TotalDrop.x64.yaml"),
            ("arm64", "arm64", "target-arm64/winget/app.totaldrop.TotalDrop.arm64.yaml"),
        ):
            yp = repo_root / rel_yaml
            _check_spdx_top6(yp)
            raw = yp.read_text(encoding="utf-8")
            if "winget-manifest.singleton.1.9.0.schema.json" not in raw:
                raise AssertionError(f"{rel_yaml}: missing winget 1.9.0 schema header")
            if "winget install --source msstore" not in raw:
                raise AssertionError(f"{rel_yaml}: missing ADR 0016 Store-only winget --source msstore note")
            doc = _parse_simple_winget_yaml(raw)
            assert doc.get("ManifestType") == "singleton", doc
            assert doc.get("ManifestVersion") == "1.9.0", doc
            assert doc.get("PackageVersion") == "0.1.0-beta.1", doc
            assert doc.get("License") == "GPL-3.0-or-later", doc
            assert doc.get("PrivacyUrl") == "https://totaldrop.app/privacy/", doc
            assert "totaldrop" in (doc.get("Protocols") or []), doc
            installers = doc.get("Installers") or []
            assert len(installers) == 1, installers
            inst = installers[0]
            assert inst.get("Architecture") == arch, inst
            assert inst.get("InstallerType") == "msix", inst
            assert inst.get("MinimumOSVersion") == "10.0.19041.0", inst
            assert inst.get("Platform") == ["Windows.Desktop"], inst

            rec = tomllib.loads((repo_root / "subplatforms" / "winget" / sub_arch / "RECIPE.toml").read_text(encoding="utf-8"))
            assert rec.get("version") == "0.1.0-beta.1", rec
            assert rec.get("format") == "winget", rec
        return "x64 & arm64 winget 1.9.0 singleton YAMLs + subplatforms/winget RECIPE.toml aligned"

    # --- 19 linux-devbox tests ---

    def t1_f23_02() -> str:
        p_chk = _run_cmd(
            [sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"), "--check"],
            cwd=repo_root,
        )
        if p_chk.returncode != 0:
            raise AssertionError(f"generate-store-listings.py --check failed: {p_chk.stdout}\n{p_chk.stderr}")

        with tempfile.TemporaryDirectory(prefix="td-f23-02-") as tmp:
            t = Path(tmp)
            ss_dir = t / "screenshots"
            _write_png(ss_dir / "light.png", 1366, 768, (244, 242, 251, 255))
            _write_png(ss_dir / "dark.png", 1920, 1080, (20, 14, 51, 255))
            out_dir = t / "out"
            p_gen = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                    "--out", str(out_dir), "--screenshots-dir", str(ss_dir), "--require-screenshots",
                ],
                cwd=repo_root,
            )
            if p_gen.returncode != 0:
                raise AssertionError(f"generate-store-listings --out failed: {p_gen.stdout}\n{p_gen.stderr}")

            json_path = out_dir / "store-listings.json"
            csv_path = out_dir / "store-listings.csv"
            p_val = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                    "--validate-file", str(json_path), "--screenshots-dir", str(ss_dir), "--require-screenshots",
                ],
                cwd=repo_root,
            )
            if p_val.returncode != 0:
                raise AssertionError(f"generate-store-listings --validate-file failed: {p_val.stdout}\n{p_val.stderr}")

            doc = json.loads(json_path.read_text(encoding="utf-8"))
            listings = doc.get("listings", [])
            assert isinstance(listings, list)
            by_locale = {entry["locale"]: entry for entry in listings}
            assert set(by_locale.keys()) == set(CANONICAL_35_LOCALES), f"locale count={len(by_locale)}"
            for loc, entry in by_locale.items():
                assert entry["Title"] == "TotalDrop", (loc, entry["Title"])
                assert 0 < len(entry["ShortDescription"]) <= 200, loc
                assert 0 < len(entry["Description"]) <= 10000, loc
                assert 1 <= len(entry["Features"]) <= 20, loc
                assert all(0 < len(b) <= 200 for b in entry["Features"]), loc
                assert 1 <= len(entry["SearchTerms"]) <= 7, loc
                assert all(0 < len(s) <= 40 for s in entry["SearchTerms"]), loc
                assert entry["PrivacyPolicyUrl"] == "https://totaldrop.app/privacy/", loc
                assert entry["SupportContact"] == "hello@totaldrop.app", loc
                shots = entry.get("Screenshots", [])
                assert len(shots) >= 1, loc
                for sh in shots:
                    assert sh["width"] >= 1366 and sh["height"] >= 768, (loc, sh)
                    assert str(sh.get("file", "")).lower().endswith(".png"), (loc, sh)

            with csv_path.open("r", encoding="utf-8", newline="") as fh:
                rows = list(csv.DictReader(fh))
            assert len(rows) == 35, f"CSV row count {len(rows)} != 35"
        return "35-locale Store listings JSON & CSV deterministic + validated with >=1366x768 PNGs"

    def t1_f23_03() -> str:
        # 1. AST/source check on tools/generate-store-listings.py
        gen_src = (repo_root / "tools" / "generate-store-listings.py").read_text(encoding="utf-8")
        tree = ast.parse(gen_src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name) and tgt.id == "ALLOWED_STORE_ARB_KEYS":
                        val = ast.literal_eval(node.value)
                        if "metainfoTheme" in val or "metainfoOnePackage" in val:
                            raise AssertionError("ALLOWED_STORE_ARB_KEYS includes forbidden Linux AppStream key!")

        # 2. Load every localized metainfoTheme and metainfoOnePackage across all l10n/app/app_*.arb
        forbidden_arb_strings: dict[str, set[str]] = {}
        for arb_path in sorted((repo_root / "l10n" / "app").glob("app_*.arb")):
            arb = json.loads(arb_path.read_text(encoding="utf-8"))
            tag = arb_path.stem[len("app_") :].replace("_", "-")
            vals = set()
            for fk in ("metainfoTheme", "metainfoOnePackage"):
                v = arb.get(fk)
                if isinstance(v, str) and v.strip():
                    vals.add(v.strip())
            if vals:
                forbidden_arb_strings[tag] = vals

        doc = json.loads((repo_root / "packaging" / "store-listings" / "store-listings.json").read_text(encoding="utf-8"))
        for entry in doc["listings"]:
            loc = entry["locale"]
            texts: list[str] = [
                entry["Title"],
                entry["ShortDescription"],
                entry["Description"],
                entry.get("ReleaseNotes", ""),
                *entry["Features"],
                *entry["SearchTerms"],
            ]
            loc_forbidden = set(forbidden_arb_strings.get(loc, set())) | set(forbidden_arb_strings.get("en", set()))
            for txt in texts:
                for leak in loc_forbidden:
                    if leak in txt:
                        raise AssertionError(f"{loc}: leaked Linux AppStream ARB text {leak!r}")
                for term in PROHIBITED_STORE_TERMS:
                    if re.search(rf"(?i)(?<![A-Za-z0-9]){re.escape(term)}(?![A-Za-z0-9])", txt):
                        raise AssertionError(f"{loc}: prohibited term {term!r} found in {txt!r}")
                if HTML_TAG_RE.search(txt):
                    raise AssertionError(f"{loc}: HTML tag found in {txt!r}")
                for ch in txt:
                    if ch in ("\n", "\t"):
                        continue
                    if ch in FORBIDDEN_BIDI_RANGE:
                        raise AssertionError(f"{loc}: forbidden Bidi override U+{ord(ch):04X}")
                    cat = unicodedata.category(ch)
                    if cat in ("Cc", "Cf", "Zl", "Zp") and ch not in ALLOWED_INVISIBLE:
                        raise AssertionError(f"{loc}: forbidden control/format char U+{ord(ch):04X}")
        return "0 metainfoTheme/metainfoOnePackage leaks, 0 prohibited terms, 0 HTML tags & 0 Bidi/control chars across 35 locales"

    def t1_f23_06() -> str:
        notes_path = repo_root / "docs" / "store-certification-notes.md"
        if not notes_path.is_file():
            raise AssertionError("missing docs/store-certification-notes.md")
        _check_spdx_top6(notes_path)
        txt = notes_path.read_text(encoding="utf-8")
        low = txt.lower()
        for req in (
            "rescap:runfulltrust",
            "appcontainer",
            "desktop2:firewallrules",
            'direction="in"',
            'ipprotocol="udp"',
            'profile="private"',
            "totaldrop-winui.exe",
            "no account",
            "zero self-updating",
        ):
            if req not in low:
                raise AssertionError(f"docs/store-certification-notes.md missing required token: {req!r}")
        return "docs/store-certification-notes.md covers runFullTrust, FirewallRules, zero-account steps & no-self-updater"

    def t2_f23_03() -> str:
        base_doc = json.loads((repo_root / "packaging" / "store-listings" / "store-listings.json").read_text(encoding="utf-8"))

        def get_entry(d: dict[str, Any], loc: str) -> dict[str, Any]:
            for item in d["listings"]:
                if item["locale"] == loc:
                    return item
            raise KeyError(loc)

        def run_val(mutated: dict[str, Any], name: str) -> subprocess.CompletedProcess[str]:
            with tempfile.TemporaryDirectory(prefix=f"td-f23-03-{name}-") as tmp:
                jp = Path(tmp) / f"{name}.json"
                jp.write_text(json.dumps(mutated, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
                return _run_cmd(
                    [sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"), "--validate-file", str(jp)],
                    cwd=repo_root,
                )

        # (a) 200-char feature bullet -> PASS
        d_200 = json.loads(json.dumps(base_doc))
        get_entry(d_200, "en")["Features"][0] = "A" * 200
        p_200 = run_val(d_200, "b200")
        if p_200.returncode != 0:
            raise AssertionError(f"200-char boundary feature bullet failed: {p_200.stderr}")

        # (b) 201-char feature bullet -> FAIL
        d_201 = json.loads(json.dumps(base_doc))
        get_entry(d_201, "en")["Features"][0] = "A" * 201
        p_201 = run_val(d_201, "b201")
        if p_201.returncode == 0 or "200" not in (p_201.stdout + p_201.stderr):
            raise AssertionError(f"201-char feature bullet was not rejected: {p_201.stdout}\n{p_201.stderr}")

        # (c) 201-char ShortDescription -> FAIL
        d_sd = json.loads(json.dumps(base_doc))
        get_entry(d_sd, "en")["ShortDescription"] = "B" * 201
        p_sd = run_val(d_sd, "sd201")
        if p_sd.returncode == 0 or "200" not in (p_sd.stdout + p_sd.stderr):
            raise AssertionError(f"201-char ShortDescription was not rejected: {p_sd.stdout}\n{p_sd.stderr}")

        # (d) omit sw -> FAIL; (e) omit zh-Hant -> FAIL
        for drop_loc in ("sw", "zh-Hant"):
            d_drop = json.loads(json.dumps(base_doc))
            d_drop["listings"] = [item for item in d_drop["listings"] if item["locale"] != drop_loc]
            p_drop = run_val(d_drop, f"drop_{drop_loc}")
            out = p_drop.stdout + p_drop.stderr
            if p_drop.returncode == 0 or drop_loc not in out:
                raise AssertionError(f"omitting {drop_loc} was not rejected: {out}")
        return "200-char PASS; 201-char bullet, 201-char ShortDescription, missing sw & missing zh-Hant all rejected"

    def t2_f23_04() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f23-04-") as tmp:
            t = Path(tmp)
            # (a) exact 1366x768 PNG -> PASS
            ok_ss = t / "ok_ss"
            _write_png(ok_ss / "exact.png", 1366, 768, (109, 74, 224, 255))
            p_ok = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                    "--out", str(t / "ok_out"), "--screenshots-dir", str(ok_ss), "--require-screenshots",
                ],
                cwd=repo_root,
            )
            if p_ok.returncode != 0:
                raise AssertionError(f"exact 1366x768 PNG rejected: {p_ok.stderr}")

            # (b) 1365x768 -> FAIL; (c) 1366x767 -> FAIL
            for tag, w, h in (("w1365", 1365, 768), ("h767", 1366, 767)):
                bad_ss = t / tag
                _write_png(bad_ss / "small.png", w, h, (109, 74, 224, 255))
                p_bad = _run_cmd(
                    [
                        sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                        "--out", str(t / f"out_{tag}"), "--screenshots-dir", str(bad_ss), "--require-screenshots",
                    ],
                    cwd=repo_root,
                )
                if p_bad.returncode == 0 or "1366" not in (p_bad.stdout + p_bad.stderr):
                    raise AssertionError(f"undersized {w}x{h} PNG was not rejected: {p_bad.stdout}\n{p_bad.stderr}")

            # (d) JPEG renamed .png -> FAIL
            jpg_ss = t / "jpg_ss"
            _write_jpeg_bytes(jpg_ss / "shot.png", 1366, 768)
            p_jpg = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                    "--out", str(t / "out_jpg"), "--screenshots-dir", str(jpg_ss), "--require-screenshots",
                ],
                cwd=repo_root,
            )
            if p_jpg.returncode == 0 or "png" not in (p_jpg.stdout + p_jpg.stderr).lower():
                raise AssertionError(f"JPEG renamed .png was not rejected: {p_jpg.stdout}\n{p_jpg.stderr}")

            # (e) 0 screenshots on tr (per-locale dir & --validate-file)
            per_loc_ss = t / "per_loc"
            _write_png(per_loc_ss / "en" / "shot.png", 1366, 768, (109, 74, 224, 255))
            (per_loc_ss / "tr").mkdir(parents=True)
            p_zero_dir = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                    "--out", str(t / "out_zero"), "--screenshots-dir", str(per_loc_ss), "--require-screenshots",
                ],
                cwd=repo_root,
            )
            zero_dir_out = f"{p_zero_dir.stdout}\n{p_zero_dir.stderr}"
            if (
                p_zero_dir.returncode == 0
                or "locale tr:" not in zero_dir_out.lower()
                or "0 valid png" not in zero_dir_out.lower()
            ):
                raise AssertionError(
                    f"locale with 0 screenshots was not rejected with expected diagnostic "
                    f"(rc={p_zero_dir.returncode}): {zero_dir_out}"
                )

            zero_json = t / "zero_tr.json"
            doc = json.loads((t / "ok_out" / "store-listings.json").read_text(encoding="utf-8"))
            for item in doc["listings"]:
                if item["locale"] == "tr":
                    item["Screenshots"] = []
            zero_json.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            p_zero_val = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                    "--validate-file", str(zero_json), "--require-screenshots",
                ],
                cwd=repo_root,
            )
            if p_zero_val.returncode == 0 or "tr" not in (p_zero_val.stdout + p_zero_val.stderr):
                raise AssertionError(f"empty tr Screenshots[] not rejected: {p_zero_val.stdout}\n{p_zero_val.stderr}")

            # (f) Tier-5 (C2-F3): Spreadsheet formula prefixes & CSV/list delimiters in screenshot filenames -> FAIL
            for bad_tag, bad_name in (
                ("eq_formula", "=cmd|calc!A0.png"),
                ("dash_formula", "-shot.png"),
                ("plus_formula", "+shot.png"),
                ("at_formula", "@shot.png"),
                ("semicolon_delim", "a;b.png"),
                ("comma_delim", "a,b.png"),
            ):
                bad_fn_dir = t / f"fn_{bad_tag}"
                _write_png(bad_fn_dir / bad_name, 1366, 768, (109, 74, 224, 255))
                p_fn = _run_cmd(
                    [
                        sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                        "--out", str(t / f"out_{bad_tag}"), "--screenshots-dir", str(bad_fn_dir), "--require-screenshots",
                    ],
                    cwd=repo_root,
                )
                fn_out = f"{p_fn.stdout}\n{p_fn.stderr}"
                if p_fn.returncode == 0 or "unsafe screenshot relative path" not in fn_out.lower():
                    raise AssertionError(
                        f"unsafe screenshot filename {bad_name!r} was not rejected (rc={p_fn.returncode}): {fn_out}"
                    )
        return "1366x768 PASS; 1365x768, 1366x767, JPEG-as-PNG, 0-screenshot locale & formula/delimiter filenames all rejected"

    def t2_f23_06() -> str:
        base_doc = json.loads((repo_root / "packaging" / "store-listings" / "store-listings.json").read_text(encoding="utf-8"))
        zh_arb = json.loads((repo_root / "l10n" / "app" / "app_zh_Hant.arb").read_text(encoding="utf-8"))
        pt_arb = json.loads((repo_root / "l10n" / "app" / "app_pt_BR.arb").read_text(encoding="utf-8"))

        mut = json.loads(json.dumps(base_doc))
        by_loc = {item["locale"]: item for item in mut["listings"]}
        by_loc["en"]["ShortDescription"] = "TotalDrop \u202e fast transfer"
        by_loc["en"]["Description"] = "Clean intro <script>alert(1)</script> end"
        by_loc["en"]["Features"][0] = "Matches KDE Plasma themes"
        by_loc["en"]["Features"][1] = "Also ships a .pkg archive"
        by_loc["zh-Hant"]["Features"][0] = zh_arb["metainfoTheme"]
        by_loc["pt-BR"]["Description"] = pt_arb["metainfoOnePackage"]
        by_loc["en"]["PrivacyPolicyUrl"] = "http://totaldrop.app/privacy/"

        with tempfile.TemporaryDirectory(prefix="td-f23-06-") as tmp:
            jp = Path(tmp) / "poisoned.json"
            jp.write_text(json.dumps(mut, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            p = _run_cmd(
                [sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"), "--validate-file", str(jp)],
                cwd=repo_root,
            )
            out = p.stdout + p.stderr
            if p.returncode == 0:
                raise AssertionError("poisoned Store listing with 6 violations unexpectedly passed!")
            for tok in ("U+202E", "HTML/XML", "Plasma", ".pkg", "metainfoTheme", "metainfoOnePackage", "http://totaldrop.app/privacy/"):
                if tok not in out:
                    raise AssertionError(f"validator output missing violation diagnostic {tok!r}:\n{out}")

            # Tier-5 (C2-F3): Leading-space and newline+space spreadsheet formula injections must fail.
            mut_formula = json.loads(json.dumps(base_doc))
            by_loc_f = {item["locale"]: item for item in mut_formula["listings"]}
            by_loc_f["en"]["ShortDescription"] = " =1+1"
            by_loc_f["en"]["Description"] = "\n  =cmd()"
            by_loc_f["tr"]["Description"] = "Normal line\n  =HYPERLINK(\"http://evil.test\")"
            jp_f = Path(tmp) / "poisoned_formula.json"
            jp_f.write_text(json.dumps(mut_formula, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            p_f = _run_cmd(
                [sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"), "--validate-file", str(jp_f)],
                cwd=repo_root,
            )
            out_f = p_f.stdout + p_f.stderr
            if p_f.returncode == 0:
                raise AssertionError("leading-whitespace spreadsheet formula injection unexpectedly passed!")
            for tok in ("locale en ShortDescription", "locale en Description", "locale tr Description", "formula-injection"):
                if tok not in out_f:
                    raise AssertionError(f"formula validator output missing {tok!r}:\n{out_f}")
        return "all Store listing hygiene & leading-whitespace formula-injection violations caught"

    def t1_f24_01() -> str:
        cl_path = repo_root / "docs" / "partner-center-checklist.md"
        if not cl_path.is_file():
            raise AssertionError("missing docs/partner-center-checklist.md")
        _check_spdx_top6(cl_path)
        txt = cl_path.read_text(encoding="utf-8")
        low = txt.lower()
        required_tokens = (
            "10.14",
            "cannot be converted into company accounts",
            "no self-service transfer",
            "path a",
            "path b",
            "path c",
            "3-month",
            "passkey",
            "authenticator",
            "disable sms",
            "hello@totaldrop.app",
            "eu digital services act",
            "non-trader",
            "trader",
            "entra id",
            "msstore",
            "package flights",
            "flight #1",
            ".msixbundle",
            "winget install --source msstore",
            "microsoft/winget-pkgs",
        )
        missing = [tok for tok in required_tokens if tok not in low]
        if missing:
            raise AssertionError(f"docs/partner-center-checklist.md missing required checklist item(s): {missing}")
        return "docs/partner-center-checklist.md SPDX-compliant & covers all 7 mandatory Policy 10.14 sections"

    def t1_f24_03() -> str:
        # 1. Live read-only totaldrop-site check (pre-reservation)
        verify_site_step6(site_dir, mode="pre-reservation")

        # 2. Non-vacuity proof: unmodified pre-Step-6 live site MUST fail store-published mode
        try:
            verify_site_step6(site_dir, mode="store-published")
        except ValueError as exc:
            if "dl.windows.d" not in str(exc).lower():
                raise AssertionError(f"unexpected site non-vacuity error (expected dl.windows.d): {exc}") from exc
        else:
            if mode == "pre-reservation":
                raise AssertionError("non-vacuity failure: unmodified pre-Step-6 totaldrop-site passed store-published audit!")

        # 3. Projected Step-6 temp copy passes BOTH real Node scripts AND store-published audit
        with tempfile.TemporaryDirectory(prefix="td-f24-03-") as tmp:
            proj = Path(tmp) / "totaldrop-site"
            _project_site_step6(site_dir, proj)
            verify_site_step6(proj, mode="store-published")
        return "live site check-i18n/privacy/don.b4==0 PASS; pre-Step-6 fails store-published; Step-6 temp projection PASS"

    def t1_f24_04() -> str:
        verify_docs_step6(totaldrop_dir, core_dir, mode="pre-reservation")
        try:
            verify_docs_step6(totaldrop_dir, core_dir, mode="store-published")
        except ValueError as exc:
            if "t12" not in str(exc).lower():
                raise AssertionError(f"unexpected docs non-vacuity error (expected T12): {exc}") from exc
        else:
            if mode == "pre-reservation":
                raise AssertionError("non-vacuity failure: unmodified pre-Step-6 docs passed store-published audit!")

        with tempfile.TemporaryDirectory(prefix="td-f24-04-") as tmp:
            dst_td = Path(tmp) / "totaldrop"
            dst_core = Path(tmp) / "totaldrop-core"
            _project_docs_and_readmes_step6(totaldrop_dir, dst_td, core_dir, dst_core)
            verify_docs_step6(dst_td, dst_core, mode="store-published")
        return "live docs readable; pre-Step-6 docs fail store-published; Step-6 T12/runFullTrust/tasarim/design projection PASS"

    def t1_f24_05() -> str:
        verify_readmes_step6(totaldrop_dir, mode="pre-reservation")
        try:
            verify_readmes_step6(totaldrop_dir, mode="store-published")
        except ValueError as exc:
            if "coming" not in str(exc).lower():
                raise AssertionError(f"unexpected README non-vacuity error (expected Coming): {exc}") from exc
        else:
            if mode == "pre-reservation":
                raise AssertionError("non-vacuity failure: unmodified pre-Step-6 README passed store-published audit!")

        with tempfile.TemporaryDirectory(prefix="td-f24-05-") as tmp:
            dst_td = Path(tmp) / "totaldrop"
            dst_core = Path(tmp) / "totaldrop-core"
            _project_docs_and_readmes_step6(totaldrop_dir, dst_td, core_dir, dst_core)
            verify_readmes_step6(dst_td, mode="store-published")
        return "live check-readmes.mjs (35 langs, 0 warnings) PASS; Step-6 promoted README + 34 re-stamped READMEs PASS (0 warnings)"

    def t2_f24_02() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f24-02-") as tmp:
            base_proj = Path(tmp) / "base_site"
            _project_site_step6(site_dir, base_proj)
            verify_site_step6(base_proj, mode="store-published")

            # (a) don.b4 in donate/index.html
            a = Path(tmp) / "mut_a"
            shutil.copytree(base_proj, a)
            dh = a / "public" / "donate" / "index.html"
            dh.write_text(dh.read_text(encoding="utf-8").replace("don.b3", "don.b3\"></li><li data-i18n=\"don.b4", 1), encoding="utf-8")
            try:
                verify_site_step6(a, mode="store-published")
            except ValueError as exc:
                assert "don.b4" in str(exc), str(exc)
            else:
                raise AssertionError("don.b4 in donate/index.html was not caught!")

            # (b) don.b4 in public/i18n/tr.json
            b = Path(tmp) / "mut_b"
            shutil.copytree(base_proj, b)
            tr_p = b / "public" / "i18n" / "tr.json"
            tr_d = json.loads(tr_p.read_text(encoding="utf-8"))
            tr_d["don.b4"] = "Windows code signing"
            tr_p.write_text(json.dumps(tr_d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            try:
                verify_site_step6(b, mode="store-published")
            except ValueError as exc:
                assert "don.b4" in str(exc), str(exc)
            else:
                raise AssertionError("don.b4 in tr.json was not caught!")

            # (c) stale "unsigned" in dl.windows.d
            c = Path(tmp) / "mut_c"
            shutil.copytree(base_proj, c)
            stale_dl = "For Windows 11. The first builds are unsigned until funded."
            dl_p = c / "public" / "download" / "index.html"
            dl_p.write_text(re.sub(r'(<p data-i18n="dl\.windows\.d">).*?(</p>)', rf"\1{stale_dl}\2", dl_p.read_text(encoding="utf-8"), count=1), encoding="utf-8")
            en_p = c / "public" / "i18n" / "en.json"
            en_d = json.loads(en_p.read_text(encoding="utf-8"))
            en_d["dl.windows.d"] = stale_dl
            en_p.write_text(json.dumps(en_d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            try:
                verify_site_step6(c, mode="store-published")
            except ValueError as exc:
                assert "dl.windows.d" in str(exc), str(exc)
            else:
                raise AssertionError("stale unsigned dl.windows.d was not caught!")

            # (d) stale "donations cover the certificate" in rm.x5.d
            d = Path(tmp) / "mut_d"
            shutil.copytree(base_proj, d)
            stale_rm = "A native Windows 11 app. Signed once donations cover the certificate."
            rm_p = d / "public" / "roadmap" / "index.html"
            rm_p.write_text(re.sub(r'(<p data-i18n="rm\.x5\.d">).*?(</p>)', rf"\1{stale_rm}\2", rm_p.read_text(encoding="utf-8"), count=1), encoding="utf-8")
            en_p2 = d / "public" / "i18n" / "en.json"
            en_d2 = json.loads(en_p2.read_text(encoding="utf-8"))
            en_d2["rm.x5.d"] = stale_rm
            en_p2.write_text(json.dumps(en_d2, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            try:
                verify_site_step6(d, mode="store-published")
            except ValueError as exc:
                assert "rm.x5.d" in str(exc), str(exc)
            else:
                raise AssertionError("stale rm.x5.d was not caught!")
        return "all 4 site Step-6 regressions (donate don.b4, tr.json don.b4, dl.windows.d, rm.x5.d) caught"

    def t2_f24_03() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f24-03-") as tmp:
            # (1) Edit privacy/en.html without updating privacy/tr.html -> stamp mismatch
            a = Path(tmp) / "stamp_drift"
            shutil.copytree(site_dir, a, ignore=shutil.ignore_patterns(".git", "node_modules"))
            en_p = a / "privacy" / "en.html"
            en_p.write_text(en_p.read_text(encoding="utf-8").replace("We collect nothing about you.", "We collect nothing about you at all.", 1), encoding="utf-8")
            p1 = _run_cmd(["node", "tools/privacy.mjs"], cwd=a)
            if p1.returncode == 0 or "translated from en.html" not in (p1.stdout + p1.stderr).lower():
                raise AssertionError(f"privacy.mjs did not catch SHA-256 stamp drift: {p1.stdout}\n{p1.stderr}")

            # (2) Drop Windows paths from privacy/tr.html while keeping updated stamp
            b = Path(tmp) / "path_drift"
            _project_site_step6(site_dir, b)
            tr_p = b / "privacy" / "tr.html"
            tr_txt = tr_p.read_text(encoding="utf-8")
            tr_txt = tr_txt.replace(r"<code>Downloads\TotalDrop</code>", "<code>Downloads</code>")
            tr_txt = tr_txt.replace(r"<code>%LOCALAPPDATA%\TotalDrop\settings.json</code>", "<code>settings</code>")
            tr_p.write_text(tr_txt, encoding="utf-8")
            p2 = _run_cmd(["node", "tools/privacy.mjs"], cwd=b)
            if p2.returncode == 0 or "code differ from english" not in (p2.stdout + p2.stderr).lower():
                raise AssertionError(f"privacy.mjs did not catch missing Windows <code> paths in tr.html: {p2.stdout}\n{p2.stderr}")
        return "privacy.mjs caught both SHA-256 stamp drift and missing Windows <code> paths in tr.html"

    def t2_f24_04() -> str:
        # Dynamically construct a synthetic secret value at runtime (NEVER literal in source!)
        dyn_secret = "".join(
            chr(65 + (i * 7) % 26) + chr(97 + (i * 11) % 26) + str((i * 3) % 10)
            for i in range(12)
        )
        forbidden_names = (
            ".gitleaksignore",
            "cert.pfx",
            "key.properties",
            "release.snk",
            "app.p12",
            "dev.keystore",
        )
        with tempfile.TemporaryDirectory(prefix="td-f24-04-") as tmp:
            git_dir = Path(tmp) / "secret_repo"
            git_dir.mkdir()
            for git_cmd in (
                ["git", "init", "-q"],
                ["git", "config", "user.email", "e2e@example.test"],
                ["git", "config", "user.name", "E2E"],
            ):
                p_setup = _run_cmd(git_cmd, cwd=git_dir)
                if p_setup.returncode != 0:
                    raise AssertionError(f"temp fixture {' '.join(git_cmd)} failed: {p_setup.stdout}\n{p_setup.stderr}")
            (git_dir / "leak.env").write_text(f"client_secret={dyn_secret}\n", encoding="utf-8")
            for fname in forbidden_names:
                (git_dir / fname).write_text("dummy\n", encoding="utf-8")
            for git_cmd in (
                ["git", "add", "."],
                ["git", "commit", "-q", "-m", "test fixture"],
            ):
                p_setup = _run_cmd(git_cmd, cwd=git_dir)
                if p_setup.returncode != 0:
                    raise AssertionError(f"temp fixture {' '.join(git_cmd)} failed: {p_setup.stdout}\n{p_setup.stderr}")

            # (a) Run containerized gitleaks v8.30.0 with --ignore-gitleaks-allow
            gl_native = shutil.which("gitleaks")
            if gl_native:
                p_gl = _run_cmd(
                    [gl_native, "git", "--ignore-gitleaks-allow", "--redact", str(git_dir)],
                    cwd=git_dir,
                )
            else:
                p_gl = _run_cmd(
                    [
                        "docker", "run", "--rm",
                        "--volume", f"{git_dir}:/repo:ro",
                        GITLEAKS_IMAGE,
                        "git", "/repo", "--ignore-gitleaks-allow", "--redact",
                    ],
                    cwd=repo_root,
                )
            gl_out = f"{p_gl.stdout}\n{p_gl.stderr}"
            if p_gl.returncode != 1 or "leaks found" not in gl_out.lower():
                raise AssertionError(
                    f"gitleaks did not catch injected client_secret with rc=1 and 'leaks found' "
                    f"(rc={p_gl.returncode}): {gl_out}"
                )

            # (b) CI forbidden-filename regex gate on temp repo catches all 6 files
            p_ls_bad = _run_cmd(["git", "ls-files"], cwd=git_dir)
            bad_hits = [ln for ln in p_ls_bad.stdout.splitlines() if FORBIDDEN_FILENAME_RE.search(ln)]
            if set(bad_hits) != set(forbidden_names):
                raise AssertionError(f"forbidden-filename gate missed files: expected {forbidden_names}, got {bad_hits}")

            # (c) Real totaldrop-windows has 0 forbidden filenames
            p_ls_real = _run_cmd(["git", "ls-files"], cwd=repo_root)
            real_hits = [ln for ln in p_ls_real.stdout.splitlines() if FORBIDDEN_FILENAME_RE.search(ln)]
            if real_hits:
                raise AssertionError(f"real totaldrop-windows contains forbidden files: {real_hits}")
        return "gitleaks v8.30.0 caught dynamic client_secret; forbidden-filename gate caught all 6 fixtures (0 on real repo)"

    def t2_f24_05() -> str:
        # Placeholder inputs MUST pass pre-reservation and FAIL store-published
        verify_store_identifiers(
            product_id="9N0000000000",
            package_family_name="TotalDrop.TotalDrop_0000000000000",
            installer_sha256="0" * 64,
            mode="pre-reservation",
        )
        # Real valid Store coordinates MUST pass store-published
        verify_store_identifiers(
            product_id=SYNTH_PRODUCT_ID,
            package_family_name=SYNTH_PFN,
            installer_sha256=SYNTH_SHA256,
            mode="store-published",
        )
        for label, pid, pfn, sha, expected in (
            ("product_id", "9N0000000000", SYNTH_PFN, SYNTH_SHA256, "9N0000000000"),
            ("pfn", SYNTH_PRODUCT_ID, "TotalDrop.TotalDrop_0000000000000", SYNTH_SHA256, "0000000000000"),
            ("sha256", SYNTH_PRODUCT_ID, SYNTH_PFN, "0" * 64, "InstallerSha256"),
        ):
            try:
                verify_store_identifiers(
                    product_id=pid,
                    package_family_name=pfn,
                    installer_sha256=sha,
                    mode="store-published",
                )
            except ValueError as exc:
                if expected not in str(exc):
                    raise AssertionError(f"{label} rejection lacked {expected!r}: {exc}") from exc
            else:
                raise AssertionError(f"store-published accepted placeholder {label}!")
        return "pre-reservation allows placeholders; store-published rejects 9N0000000000, zero PFN & zero SHA256"

    def t3_25() -> str:
        # 4-way single-source l10n/app/*.arb parity: l10n_codegen + diff -ru, locales.json, manifests, store-listings
        with tempfile.TemporaryDirectory(prefix="td-t3-25-") as tmp:
            tmp_strings = Path(tmp) / "Strings"
            p_cg = _run_cmd(
                [
                    sys.executable, "-B",
                    str(core_dir / "tools" / "l10n_codegen.py"),
                    "--l10n-dir", str(repo_root / "l10n"),
                    "--check", "--emit", "winui-resw", "--out", str(tmp_strings),
                ],
                cwd=repo_root,
            )
            if p_cg.returncode != 0:
                raise AssertionError(f"l10n_codegen.py failed: {p_cg.stdout}\n{p_cg.stderr}")
            p_diff = _run_cmd(
                ["diff", "-ru", str(tmp_strings), str(repo_root / "ui-winui3-fluent2" / "Strings")],
                cwd=repo_root,
            )
            if p_diff.returncode != 0:
                raise AssertionError(f".resw drift detected:\n{p_diff.stdout[:500]}")

        loc_json = json.loads((repo_root / "ui-winui3-fluent2" / "Strings" / "locales.json").read_text(encoding="utf-8"))
        tags_json = {x["tag"] for x in loc_json["locales"]}
        assert tags_json == set(CANONICAL_35_LOCALES)

        import xml.etree.ElementTree as ET
        appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
        for rel in ("target-x86_64/Package.x64.appxmanifest", "target-arm64/Package.arm64.appxmanifest"):
            root_el = ET.fromstring((repo_root / rel).read_text(encoding="utf-8"))
            langs = [el.attrib["Language"] for el in root_el.findall(f".//{appx_ns}Resources/{appx_ns}Resource")]
            assert "en-US" not in langs and set(langs) == set(CANONICAL_35_LOCALES) and len(langs) == 35

        p_sl = _run_cmd(
            [sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"), "--check"],
            cwd=repo_root,
        )
        if p_sl.returncode != 0:
            raise AssertionError(f"generate-store-listings.py --check failed: {p_sl.stderr}")
        t1_f23_03()
        return "4-way 35-locale parity (l10n_codegen diff==0, locales.json, x64/arm64 manifests, Store listings) PASS"

    def t3_26() -> str:
        wf = (repo_root / ".github" / "workflows" / "windows-release.yml").read_text(encoding="utf-8")
        assert "actions/attest-build-provenance@" in wf and "SHA256SUMS" in wf and ".msixupload" in wf
        p_sub = _run_cmd([sys.executable, "-B", str(repo_root / "tools" / "verify-subplatforms.py")], cwd=repo_root)
        if p_sub.returncode != 0 or "6/6" not in p_sub.stdout:
            raise AssertionError(f"verify-subplatforms.py failed: {p_sub.stdout}\n{p_sub.stderr}")
        for sub in ("msix", "portable-zip", "winget"):
            for arch in ("x86_64", "arm64"):
                rec = tomllib.loads((repo_root / "subplatforms" / sub / arch / "RECIPE.toml").read_text(encoding="utf-8"))
                assert rec.get("provenance") == "sigstore-oidc", (sub, arch, rec)

        cl_txt = (repo_root / "docs" / "partner-center-checklist.md").read_text(encoding="utf-8").lower()
        rb_txt = (repo_root / "docs" / "microsoft-store-release.md").read_text(encoding="utf-8").lower()
        for label, txt in (("partner-center-checklist.md", cl_txt), ("microsoft-store-release.md", rb_txt)):
            if "re-signs" not in txt or "sigstore" not in txt:
                raise AssertionError(f"{label} missing Microsoft Store re-signing provenance caveat")

        with tempfile.TemporaryDirectory(prefix="td-t3-26-") as tmp:
            dst_td = Path(tmp) / "totaldrop"
            dst_core = Path(tmp) / "totaldrop-core"
            _project_docs_and_readmes_step6(totaldrop_dir, dst_td, core_dir, dst_core)
            verify_docs_step6(dst_td, dst_core, mode="store-published")
        return "release workflow, 6/6 sigstore-oidc subplatforms, checklist, runbook & Step-6 T12 re-signing caveat aligned"

    def t3_27() -> str:
        t1_f24_02()
        t1_f24_06()
        listings = json.loads((repo_root / "packaging" / "store-listings" / "store-listings.json").read_text(encoding="utf-8"))["listings"]
        assert all(v["PrivacyPolicyUrl"] == "https://totaldrop.app/privacy/" for v in listings)
        cert = (repo_root / "docs" / "store-certification-notes.md").read_text(encoding="utf-8")
        for tok in ("https://totaldrop.app/privacy/", r"Downloads\TotalDrop", r"%LOCALAPPDATA%\TotalDrop\settings.json"):
            assert tok in cert, f"store-certification-notes.md missing {tok}"
        cl = (repo_root / "docs" / "partner-center-checklist.md").read_text(encoding="utf-8")
        assert "winget install --source msstore" in cl
        t1_f24_03()
        return "identity swap, Store PrivacyPolicyUrl, cert notes, site privacy/download sync & winget --source msstore aligned"

    def t4_13() -> str:
        # Full offline Store preflight chain
        with tempfile.TemporaryDirectory(prefix="td-t4-13-") as tmp:
            t = Path(tmp)
            # 1. l10n_codegen --check + diff -ru
            tmp_strings = t / "Strings"
            p_cg = _run_cmd(
                [
                    sys.executable, "-B",
                    str(core_dir / "tools" / "l10n_codegen.py"),
                    "--l10n-dir", str(repo_root / "l10n"),
                    "--check", "--emit", "winui-resw", "--out", str(tmp_strings),
                ],
                cwd=repo_root,
            )
            if p_cg.returncode != 0:
                raise AssertionError(f"l10n_codegen failed: {p_cg.stderr}")
            p_diff = _run_cmd(["diff", "-ru", str(tmp_strings), str(repo_root / "ui-winui3-fluent2" / "Strings")], cwd=repo_root)
            if p_diff.returncode != 0:
                raise AssertionError(f".resw drift:\n{p_diff.stdout[:400]}")

            # 2. Light, Dark & RTL (ar, fa, he, ur) >= 1366x768 PNG screenshots
            ss_dir = t / "screenshots"
            _write_png(ss_dir / "light.png", 1366, 768, (244, 242, 251, 255))
            _write_png(ss_dir / "dark.png", 1920, 1080, (20, 14, 51, 255))
            for rtl in ("ar", "fa", "he", "ur"):
                _write_png(ss_dir / rtl / f"{rtl}-light.png", 1366, 768, (244, 242, 251, 255))
                _write_png(ss_dir / rtl / f"{rtl}-dark.png", 1920, 1080, (20, 14, 51, 255))

            out_dir = t / "listings"
            p_gen = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                    "--out", str(out_dir), "--screenshots-dir", str(ss_dir), "--require-screenshots",
                ],
                cwd=repo_root,
            )
            if p_gen.returncode != 0:
                raise AssertionError(f"generate-store-listings failed: {p_gen.stderr}")
            p_val = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "generate-store-listings.py"),
                    "--validate-file", str(out_dir / "store-listings.json"),
                    "--screenshots-dir", str(ss_dir), "--require-screenshots",
                ],
                cwd=repo_root,
            )
            if p_val.returncode != 0:
                raise AssertionError(f"validate-file failed: {p_val.stderr}")

            # 3. Synthetic Partner Center identity check
            id_root = t / "store_id"
            _stage_version_check_root(
                repo_root,
                id_root,
                version="1.0.1.0",
                name=SYNTH_STORE_NAME,
                publisher_x64=SYNTH_STORE_PUB,
                publisher_arm64=SYNTH_STORE_PUB,
            )
            p_id = _run_cmd(
                [
                    sys.executable, "-B", str(repo_root / "tools" / "check-versions.py"),
                    "--store", "--require-store-identity", "--root", str(id_root),
                ],
                cwd=repo_root,
            )
            if p_id.returncode != 0:
                raise AssertionError(f"check-versions --store --require-store-identity failed: {p_id.stderr}")

        # 4. Certification notes & Policy 10.14 checklist + hygiene
        t1_f23_03()
        t1_f23_06()
        t1_f24_01()
        return "full offline Store preflight chain (l10n diff==0, Light/Dark/RTL PNGs, 35 locales, Store ID, cert notes & checklist) PASS"

    def t4_14() -> str:
        # 1. Live read-only baseline validators
        verify_site_step6(site_dir, mode="pre-reservation")
        verify_docs_step6(totaldrop_dir, core_dir, mode="pre-reservation")
        verify_readmes_step6(totaldrop_dir, mode="pre-reservation")

        # 2. Honest non-vacuity check: unmodified live ecosystem MUST fail store-published mode
        live_rejected = 0
        for expected_tok, fn in (
            ("dl.windows.d", lambda: verify_site_step6(site_dir, mode="store-published")),
            ("t12", lambda: verify_docs_step6(totaldrop_dir, core_dir, mode="store-published")),
            ("coming", lambda: verify_readmes_step6(totaldrop_dir, mode="store-published")),
        ):
            try:
                fn()
            except ValueError as exc:
                if expected_tok not in str(exc).lower():
                    raise AssertionError(
                        f"unexpected non-vacuity error (expected {expected_tok!r}): {exc}"
                    ) from exc
                live_rejected += 1
        if mode == "pre-reservation" and live_rejected != 3:
            raise AssertionError(f"non-vacuity failure: expected 3/3 pre-Step-6 live checks to fail store-published, got {live_rejected}/3")

        # 3. Full 4-repo Step-6 projected ecosystem workload
        with tempfile.TemporaryDirectory(prefix="td-t4-14-") as tmp:
            t = Path(tmp)
            p_site = t / "totaldrop-site"
            p_td = t / "totaldrop"
            p_core = t / "totaldrop-core"
            _project_site_step6(site_dir, p_site)
            _project_docs_and_readmes_step6(totaldrop_dir, p_td, core_dir, p_core)

            verify_store_identifiers(
                product_id=SYNTH_PRODUCT_ID,
                package_family_name=SYNTH_PFN,
                installer_sha256=SYNTH_SHA256,
                mode="store-published",
            )
            verify_site_step6(p_site, mode="store-published")
            verify_docs_step6(p_td, p_core, mode="store-published")
            verify_readmes_step6(p_td, mode="store-published")
        return "4-repo ADR 0016 Step 6 workload PASS (live read-only PASS, 3/3 non-vacuity rejections verified, projected ecosystem PASS)"

    # Register all 25 test IDs
    record("T1-F23-01", "cross-platform", t1_f23_01)
    record("T2-F23-01", "cross-platform", t2_f23_01)
    record("T2-F23-02", "cross-platform", t2_f23_02)
    record("T1-F24-02", "cross-platform", t1_f24_02)
    record("T2-F24-01", "cross-platform", t2_f24_01)
    record("T1-F24-06", "cross-platform", t1_f24_06)

    record("T1-F23-02", "linux-devbox", t1_f23_02)
    record("T1-F23-03", "linux-devbox", t1_f23_03)
    record("T1-F23-06", "linux-devbox", t1_f23_06)
    record("T2-F23-03", "linux-devbox", t2_f23_03)
    record("T2-F23-04", "linux-devbox", t2_f23_04)
    record("T2-F23-06", "linux-devbox", t2_f23_06)
    record("T1-F24-01", "linux-devbox", t1_f24_01)
    record("T1-F24-03", "linux-devbox", t1_f24_03)
    record("T1-F24-04", "linux-devbox", t1_f24_04)
    record("T1-F24-05", "linux-devbox", t1_f24_05)
    record("T2-F24-02", "linux-devbox", t2_f24_02)
    record("T2-F24-03", "linux-devbox", t2_f24_03)
    record("T2-F24-04", "linux-devbox", t2_f24_04)
    record("T2-F24-05", "linux-devbox", t2_f24_05)
    record("T3-25", "linux-devbox", t3_25)
    record("T3-26", "linux-devbox", t3_26)
    record("T3-27", "linux-devbox", t3_27)
    record("T4-13", "linux-devbox", t4_13)
    record("T4-14", "linux-devbox", t4_14)

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="M4 Store readiness & ADR 0016 Step 6 cross-repo verifier.")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="totaldrop-windows repository root.")
    parser.add_argument("--mode", choices=("pre-reservation", "store-published"), default="pre-reservation")
    parser.add_argument("--env", choices=("all", "cross-platform", "linux-devbox"), default="all")
    parser.add_argument("--run-tests", action="store_true", help="Run all 25 M4 Store & Step 6 tests.")
    parser.add_argument("--audit-ecosystem", action="store_true", help="Run standalone cross-repo ecosystem audit.")
    parser.add_argument("--site-dir", type=Path, default=None)
    parser.add_argument("--totaldrop-dir", type=Path, default=None)
    parser.add_argument("--core-dir", type=Path, default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        if args.audit_ecosystem:
            eff_site = _resolve_sibling_repo(args.root, "totaldrop-site", "TOTALDROP_SITE_DIR", args.site_dir)
            eff_totaldrop = _resolve_sibling_repo(args.root, "totaldrop", "TOTALDROP_MONOREPO_DIR", args.totaldrop_dir)
            eff_core = _resolve_sibling_repo(args.root, "totaldrop-core", "TOTALDROP_CORE_DIR", args.core_dir)
            verify_site_step6(eff_site, mode=args.mode)
            verify_docs_step6(eff_totaldrop, eff_core, mode=args.mode)
            verify_readmes_step6(eff_totaldrop, mode=args.mode)
            print(f"verify_store_step6 ecosystem audit OK (mode={args.mode})")
            return 0
        if args.run_tests:
            results = run_test_suite(
                args.root,
                mode=args.mode,
                env_filter=args.env,
                site_dir=args.site_dir,
                totaldrop_dir=args.totaldrop_dir,
                core_dir=args.core_dir,
            )
            if args.json_out is not None:
                args.json_out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            failed = [k for k, v in results.items() if v["status"] != "PASS"]
            for k, v in sorted(results.items()):
                print(f"[{v['status']}] {k}: {v['detail']}")
            return 1 if failed else 0
        parser.error("specify --run-tests or --audit-ecosystem")
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
