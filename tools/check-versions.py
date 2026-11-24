#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Enforce version alignment, CLSID invariants, and Microsoft Store MSIX rules across totaldrop-windows."""

from __future__ import annotations

import argparse
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
TOAST_ACTIVATOR_CLSID = "7DF2CCED-0448-4849-A140-41CD106EAA9B"
UNSIGNED_PACKAGE_OID = "2.25.311729368913984317654407730594956997722"
BARE_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
IDENTITY_NAME_RE = re.compile(r"^[A-Za-z0-9.-]{3,50}$")
RDN_KEY_RE = re.compile(r"\A(?:[A-Za-z][A-Za-z0-9-]*|(?:OID\.)?[0-9]+(?:\.[0-9]+)+)\Z", re.ASCII)
RFC2253_ESCAPABLE_CHARS: frozenset[str] = frozenset({",", "+", '"', "\\", "<", ">", ";", "#", "=", " "})
ASCII_HEX_DIGITS: frozenset[str] = frozenset("0123456789ABCDEFabcdef")
FORBIDDEN_UNQUOTED_RDN_CHARS: frozenset[str] = frozenset({'"', ";", "<", ">", "+", "`", "$", "|", "&"})
PLACEHOLDER_CN_VALUES: frozenset[str] = frozenset({"totaldrop", "00000000-0000-0000-0000-000000000000"})
QUAD_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$", re.ASCII)

# Split forbidden literals so this script never matches itself if scanned naively.
FORBIDDEN_LITERALS: tuple[tuple[str, str], ...] = (
    ("0.3.0-" + "beta.6", "stale pre-alignment subplatform version"),
    ("0.2." + "0.0", "stale 4-part MSIX/PE version"),
    ("8E6D76B4-" + "54A9-4D92-9A57-2F7D25F8B216", "bogus Explorer COM CLSID"),
)

SKIP_WALK_DIRS: frozenset[str] = frozenset({".git", "target", "dist", "bin", "obj", "__pycache__"})


def expect_eq(errors: list[str], label: str, actual: object, expected: object) -> None:
    if actual != expected:
        errors.append(f"{label}: expected {expected!r}, got {actual!r}")


def validate_msix_version_quad(
    version: str,
    label: str,
    errors: list[str],
    *,
    require_store_rules: bool,
) -> bool:
    if not isinstance(version, str) or not QUAD_RE.fullmatch(version):
        errors.append(
            f"{label}: invalid MSIX version {version!r} (expected 4-part numeric Major.Minor.Build.Revision)"
        )
        return False

    parts = version.split(".")
    nums: list[int] = []
    for part in parts:
        if len(part) > 1 and part.startswith("0"):
            errors.append(
                f"{label}: invalid MSIX version {version!r} (leading zeros not allowed in {part!r})"
            )
            return False
        val = int(part)
        if val < 0 or val > 65535:
            errors.append(
                f"{label}: invalid MSIX version {version!r} "
                f"(component {val} outside 0..=65535 uint16 quad bounds)"
            )
            return False
        nums.append(val)

    major, _minor, _build, revision = nums
    ok = True
    if require_store_rules:
        if major < 1:
            errors.append(
                f"{label}: Store MSIX version {version!r} violates Microsoft Store Major >= 1 requirement"
            )
            ok = False
        if revision != 0:
            errors.append(
                f"{label}: Store MSIX version {version!r} violates Microsoft Store Revision == 0 requirement"
            )
            ok = False
    return ok


def validate_store_msix_version(version: str, label: str, errors: list[str]) -> bool:
    return validate_msix_version_quad(version, label, errors, require_store_rules=True)


def _check_no_control_or_bidi(text: str, label: str) -> None:
    for ch in text:
        cp = ord(ch)
        if (
            cp < 0x20
            or cp == 0x7F
            or 0x80 <= cp <= 0x9F
            or 0x202A <= cp <= 0x202E
            or 0x2066 <= cp <= 0x2069
            or cp == 0x061C
        ):
            raise ValueError(
                f"{label}: contains forbidden control or Bidi override character U+{cp:04X}"
            )


def strip_unescaped_x500_whitespace(text: str) -> str:
    """Strip unescaped leading/trailing whitespace while preserving RFC 2253 escaped trailing spaces."""
    n = len(text)
    start = 0
    while start < n and text[start].isspace():
        start += 1
    last_sig_end = start
    escaped = False
    for idx in range(start, n):
        ch = text[idx]
        if escaped:
            escaped = False
            last_sig_end = idx + 1
            continue
        if ch == "\\":
            escaped = True
            last_sig_end = idx + 1
            continue
        if not ch.isspace():
            last_sig_end = idx + 1
    return text[start:last_sig_end]


def _decode_rfc2253_rdn_value(raw_text: str, *, quoted: bool, label: str, rdn: str) -> str:
    """Decode RFC 2253/4514 escapes (escapable punctuation/space and UTF-8 \\XX hexpairs)."""
    chars: list[str] = []
    i = 0
    n = len(raw_text)
    while i < n:
        c = raw_text[i]
        if c == "\\":
            if i + 1 >= n:
                raise ValueError(f"{label}: trailing escape in X.500 Publisher RDN {rdn!r}")
            nxt = raw_text[i + 1]
            if nxt in RFC2253_ESCAPABLE_CHARS:
                chars.append(nxt)
                i += 2
            elif i + 2 < n and nxt in ASCII_HEX_DIGITS and raw_text[i + 2] in ASCII_HEX_DIGITS:
                hex_bytes = bytearray()
                while (
                    i + 2 < n
                    and raw_text[i] == "\\"
                    and raw_text[i + 1] in ASCII_HEX_DIGITS
                    and raw_text[i + 2] in ASCII_HEX_DIGITS
                ):
                    hex_bytes.append(int(raw_text[i + 1 : i + 3], 16))
                    i += 3
                try:
                    chars.append(hex_bytes.decode("utf-8", errors="strict"))
                except UnicodeDecodeError as exc:
                    raise ValueError(
                        f"{label}: invalid UTF-8 byte sequence in RFC 2253 hex escape in RDN {rdn!r}: {exc}"
                    ) from exc
            else:
                raise ValueError(
                    f"{label}: invalid RFC 2253 escape sequence '\\{nxt}' in X.500 Publisher RDN {rdn!r}"
                )
        else:
            if not quoted and c in FORBIDDEN_UNQUOTED_RDN_CHARS:
                raise ValueError(
                    f"{label}: forbidden unescaped character {c!r} in unquoted X.500 RDN {rdn!r}"
                )
            chars.append(c)
            i += 1
    return "".join(chars)


def parse_x500_publisher(publisher: str, label: str) -> list[tuple[str, str]]:
    """Parse and strictly validate an RFC 2253/4514 X.500 Publisher DN, returning (KEY_UPPER, decoded_value) pairs."""
    if not isinstance(publisher, str) or not strip_unescaped_x500_whitespace(publisher):
        raise ValueError(f"{label}: Publisher must be a non-empty X.500 CN=... distinguished name")
    if len(publisher) > 8192:
        raise ValueError(f"{label}: Publisher exceeds 8192 characters")

    _check_no_control_or_bidi(publisher, f"{label} Publisher")

    if UNSIGNED_PACKAGE_OID in publisher.lower():
        raise ValueError(
            f"{label}: Publisher contains forbidden unsigned-package OID {UNSIGNED_PACKAGE_OID}"
        )

    rdns: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escaped = False
    for ch in publisher:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
            continue
        if ch == "," and not in_quotes:
            rdns.append(strip_unescaped_x500_whitespace("".join(buf)))
            buf.clear()
            continue
        buf.append(ch)

    if in_quotes or escaped:
        raise ValueError(
            f"{label}: malformed X.500 Publisher {publisher!r} (unterminated quote or escape)"
        )
    rdns.append(strip_unescaped_x500_whitespace("".join(buf)))

    parsed: list[tuple[str, str]] = []
    has_cn = False
    for rdn in rdns:
        if not rdn or "=" not in rdn:
            raise ValueError(
                f"{label}: malformed X.500 Publisher RDN {rdn!r} in {publisher!r} (expected e.g. 'CN=...')"
            )
        raw_key, raw_val = rdn.split("=", 1)
        key = raw_key.strip()
        val = strip_unescaped_x500_whitespace(raw_val)
        if not RDN_KEY_RE.fullmatch(key) or not val:
            raise ValueError(
                f"{label}: malformed X.500 Publisher RDN {rdn!r} in {publisher!r} (expected e.g. 'CN=...')"
            )

        if val.startswith("#"):
            raise ValueError(
                f"{label}: ASN.1 BER #hex RDN values are not permitted in MSIX Identity/@Publisher ({rdn!r})"
            )
        if val.startswith('"'):
            if len(val) < 2:
                raise ValueError(
                    f"{label}: malformed quoted X.500 Publisher RDN {rdn!r} in {publisher!r}"
                )
            q_escaped = False
            closed = False
            for idx in range(1, len(val)):
                c = val[idx]
                if q_escaped:
                    q_escaped = False
                    continue
                if c == "\\":
                    q_escaped = True
                    continue
                if c == '"':
                    if idx != len(val) - 1:
                        raise ValueError(
                            f"{label}: unexpected trailing characters after closing quote in RDN {rdn!r}"
                        )
                    closed = True
                    break
            if not closed or q_escaped:
                raise ValueError(
                    f"{label}: unterminated quoted X.500 Publisher RDN {rdn!r} in {publisher!r}"
                )
            decoded_val = _decode_rfc2253_rdn_value(val[1:-1], quoted=True, label=label, rdn=rdn)
        else:
            decoded_val = _decode_rfc2253_rdn_value(val, quoted=False, label=label, rdn=rdn)

        _check_no_control_or_bidi(decoded_val, f"{label} decoded RDN {rdn!r}")
        if UNSIGNED_PACKAGE_OID in decoded_val.lower():
            raise ValueError(
                f"{label}: decoded Publisher RDN contains forbidden unsigned-package OID {UNSIGNED_PACKAGE_OID}"
            )
        if not decoded_val.strip():
            raise ValueError(f"{label}: empty X.500 Publisher RDN value in {rdn!r}")

        key_upper = key.upper()
        if key_upper == "CN" and decoded_val.strip():
            has_cn = True
        parsed.append((key_upper, decoded_val))

    if not has_cn:
        raise ValueError(
            f"{label}: X.500 Publisher {publisher!r} must include a non-empty 'CN=' attribute"
        )
    return parsed


def validate_x500_publisher(publisher: str, label: str, errors: list[str]) -> bool:
    try:
        parse_x500_publisher(publisher, label)
    except ValueError as exc:
        errors.append(str(exc))
        return False
    return True


def is_placeholder_test_identity(name: str, publisher: str) -> bool:
    """Return True if Name or Publisher matches a placeholder/all-zero test identity."""
    if isinstance(name, str) and name.strip().lower() == "totaldrop.totaldrop":
        return True
    try:
        parsed_rdns = parse_x500_publisher(publisher, "Publisher")
    except ValueError:
        return False
    for key, val in parsed_rdns:
        if key == "CN" and val.strip().lower() in PLACEHOLDER_CN_VALUES:
            return True
    return False



def check_core_bucket(repo_root: Path, errors: list[str]) -> None:
    root_toml = tomllib.loads((repo_root / "Cargo.toml").read_text(encoding="utf-8"))
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
            (repo_root / "crates" / crate / "Cargo.toml").read_text(encoding="utf-8")
        )
        ver = manifest.get("package", {}).get("version")
        expect_eq(
            errors,
            f"crates/{crate}/Cargo.toml [package].version",
            ver,
            {"workspace": True},
        )


def check_ffi_and_csproj(repo_root: Path, errors: list[str]) -> None:
    ffi_toml = tomllib.loads(
        (repo_root / "crates" / "totaldrop-windows-ffi" / "Cargo.toml").read_text(
            encoding="utf-8"
        )
    )
    expect_eq(
        errors,
        "crates/totaldrop-windows-ffi/Cargo.toml [package].version",
        ffi_toml.get("package", {}).get("version"),
        APP_VERSION,
    )

    ext_toml = tomllib.loads(
        (repo_root / "crates" / "totaldrop-explorer-ext" / "Cargo.toml").read_text(
            encoding="utf-8"
        )
    )
    expect_eq(
        errors,
        "crates/totaldrop-explorer-ext/Cargo.toml [package].version",
        ext_toml.get("package", {}).get("version"),
        APP_VERSION,
    )

    ext_src = (repo_root / "crates" / "totaldrop-explorer-ext" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    if CANONICAL_CLSID not in ext_src:
        errors.append(
            f"crates/totaldrop-explorer-ext/src/lib.rs: missing canonical Explorer CLSID {CANONICAL_CLSID}"
        )

    ffi_src = (repo_root / "crates" / "totaldrop-windows-ffi" / "src" / "lib.rs").read_text(
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
        (repo_root / "ui-winui3-fluent2" / "TotalDrop.WinUI.csproj").read_text(encoding="utf-8")
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

    main_win = (repo_root / "ui-winui3-fluent2" / "MainWindow.xaml.cs").read_text(
        encoding="utf-8"
    )
    m_fb = re.search(r'FallbackAppVersion\s*=\s*"([^"]+)"', main_win)
    expect_eq(
        errors,
        "ui-winui3-fluent2/MainWindow.xaml.cs FallbackAppVersion",
        m_fb.group(1) if m_fb else None,
        APP_VERSION,
    )


def _check_manifest_extensions(rel: str, root: ET.Element, errors: list[str]) -> None:
    appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
    uap_ns = "{http://schemas.microsoft.com/appx/manifest/uap/windows10}"
    com_ns = "{http://schemas.microsoft.com/appx/manifest/com/windows10}"
    desktop_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10}"
    desktop2_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/2}"
    desktop4_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/4}"
    desktop5_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/5}"
    rescap_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities}"

    if root.tag != f"{appx_ns}Package":
        errors.append(f"{rel}: root must be <Package>, got {root.tag!r}")
        return

    # 1. Single <Applications>/<Application> and single Application/Package <Extensions> containers.
    doc_applications = root.findall(f".//{appx_ns}Applications")
    direct_applications = root.findall(f"{appx_ns}Applications")
    if len(doc_applications) != 1 or len(direct_applications) != 1:
        errors.append(
            f"{rel}: must contain exactly 1 top-level <Applications> element "
            f"(doc={len(doc_applications)}, direct={len(direct_applications)})"
        )

    doc_apps = root.findall(f".//{appx_ns}Application")
    direct_apps = root.findall(f"{appx_ns}Applications/{appx_ns}Application")
    if len(doc_apps) != 1 or len(direct_apps) != 1:
        errors.append(
            f"{rel}: must contain exactly 1 <Application> under <Applications> "
            f"(doc={len(doc_apps)}, direct={len(direct_apps)})"
        )
        return
    app = direct_apps[0]
    expect_eq(errors, f"{rel} <Application> Executable", app.attrib.get("Executable"), "totaldrop-winui.exe")

    app_exts = app.findall(f"{appx_ns}Extensions")
    if len(app_exts) != 1:
        errors.append(f"{rel}: <Application> must contain exactly 1 <Extensions>, found {len(app_exts)}")
    pkg_exts = root.findall(f"{appx_ns}Extensions")
    if len(pkg_exts) != 1:
        errors.append(f"{rel}: <Package> must contain exactly 1 <Extensions>, found {len(pkg_exts)}")
    doc_exts = root.findall(f".//{appx_ns}Extensions")
    if len(doc_exts) != 2:
        errors.append(f"{rel}: must contain exactly 2 <Extensions> containers total, found {len(doc_exts)}")

    toast_cls_id: str | None = None
    if len(app_exts) == 1:
        app_ext = app_exts[0]
        allowed_app_ext_tags = {
            f"{uap_ns}Extension",
            f"{com_ns}Extension",
            f"{desktop4_ns}Extension",
            f"{desktop_ns}Extension",
        }
        unexpected_app_exts = [child.tag for child in app_ext if child.tag not in allowed_app_ext_tags]
        if unexpected_app_exts:
            errors.append(
                f"{rel}: Applications/Application/Extensions contains unexpected extension(s): "
                f"{unexpected_app_exts!r}"
            )

        # 2. com:Extension (windows.comServer): exact 1 SurrogateServer (1 Class) + 1 ExeServer (1 Class).
        doc_com_exts = root.findall(f".//{com_ns}Extension")
        app_com_exts = app_ext.findall(f"{com_ns}Extension")
        if len(doc_com_exts) != 1 or len(app_com_exts) != 1:
            errors.append(
                f"{rel}: must declare exactly 1 <com:Extension> directly under "
                f"Applications/Application/Extensions (doc={len(doc_com_exts)}, app={len(app_com_exts)})"
            )
        else:
            com_ext = app_com_exts[0]
            expect_eq(errors, f"{rel} <com:Extension> Category", com_ext.attrib.get("Category"), "windows.comServer")
            doc_com_servers = root.findall(f".//{com_ns}ComServer")
            child_com_servers = com_ext.findall(f"{com_ns}ComServer")
            if len(doc_com_servers) != 1 or len(child_com_servers) != 1 or len(list(com_ext)) != 1:
                errors.append(
                    f"{rel}: <com:Extension> must contain exactly 1 <com:ComServer> as its sole child "
                    f"(doc={len(doc_com_servers)}, direct={len(child_com_servers)}, children={len(list(com_ext))})"
                )
            else:
                com_server = child_com_servers[0]
                com_children = list(com_server)
                if len(com_children) != 2:
                    errors.append(
                        f"{rel}: <com:ComServer> must contain exactly 2 children "
                        f"(1 ExeServer + 1 SurrogateServer), found {len(com_children)}"
                    )
                elif [child.tag for child in com_children] != [
                    f"{com_ns}ExeServer",
                    f"{com_ns}SurrogateServer",
                ]:
                    errors.append(
                        f"{rel}: <com:ComServer> must declare <com:ExeServer> before "
                        "<com:SurrogateServer> per ComManifestSchema.xsd CT_ComServer sequence"
                    )

                doc_surrogates = root.findall(f".//{com_ns}SurrogateServer")
                child_surrogates = com_server.findall(f"{com_ns}SurrogateServer")
                if len(doc_surrogates) != 1 or len(child_surrogates) != 1:
                    errors.append(
                        f"{rel}: must declare exactly 1 <com:SurrogateServer> directly under <com:ComServer> "
                        f"(doc={len(doc_surrogates)}, direct={len(child_surrogates)})"
                    )
                else:
                    surrogate = child_surrogates[0]
                    surrogate_classes = surrogate.findall(f"{com_ns}Class")
                    if len(list(surrogate)) != 1 or len(surrogate_classes) != 1:
                        errors.append(
                            f"{rel}: <com:SurrogateServer> must contain exactly 1 <com:Class> as its sole child "
                            f"(children={len(list(surrogate))}, classes={len(surrogate_classes)})"
                        )
                    else:
                        explorer_cls = surrogate_classes[0]
                        if len(list(explorer_cls)) != 0:
                            errors.append(f"{rel}: Explorer <com:Class> must not contain child elements")
                        raw_id = explorer_cls.attrib.get("Id", "")
                        if not BARE_GUID_RE.fullmatch(raw_id):
                            errors.append(
                                f"{rel}: Explorer COM Class Id must be bare GUID without braces, got {raw_id!r}"
                            )
                        expect_eq(errors, f"{rel} Explorer COM Class Id", raw_id.upper(), CANONICAL_CLSID)
                        expect_eq(
                            errors,
                            f"{rel} Explorer COM Path",
                            explorer_cls.attrib.get("Path"),
                            "totaldrop_explorer_ext.dll",
                        )
                        expect_eq(
                            errors,
                            f"{rel} Explorer COM ThreadingModel",
                            explorer_cls.attrib.get("ThreadingModel"),
                            "STA",
                        )

                doc_exe_servers = root.findall(f".//{com_ns}ExeServer")
                child_exe_servers = com_server.findall(f"{com_ns}ExeServer")
                if len(doc_exe_servers) != 1 or len(child_exe_servers) != 1:
                    errors.append(
                        f"{rel}: must declare exactly 1 <com:ExeServer> directly under <com:ComServer> "
                        f"(doc={len(doc_exe_servers)}, direct={len(child_exe_servers)})"
                    )
                else:
                    exe_server = child_exe_servers[0]
                    expect_eq(
                        errors,
                        f"{rel} Toast ExeServer Executable",
                        exe_server.attrib.get("Executable"),
                        "totaldrop-winui.exe",
                    )
                    expect_eq(
                        errors,
                        f"{rel} Toast ExeServer Arguments",
                        exe_server.attrib.get("Arguments"),
                        "----AppNotificationActivated:",
                    )
                    exe_classes = exe_server.findall(f"{com_ns}Class")
                    if len(list(exe_server)) != 1 or len(exe_classes) != 1:
                        errors.append(
                            f"{rel}: <com:ExeServer> must contain exactly 1 <com:Class> as its sole child "
                            f"(children={len(list(exe_server))}, classes={len(exe_classes)})"
                        )
                    else:
                        toast_cls = exe_classes[0]
                        if len(list(toast_cls)) != 0:
                            errors.append(f"{rel}: Toast ExeServer <com:Class> must not contain child elements")
                        toast_cls_id = toast_cls.attrib.get("Id", "")
                        if not BARE_GUID_RE.fullmatch(toast_cls_id):
                            errors.append(
                                f"{rel}: Toast ExeServer Class Id must be bare GUID without braces, got {toast_cls_id!r}"
                            )
                        expect_eq(
                            errors,
                            f"{rel} Toast ExeServer Class Id",
                            toast_cls_id.upper(),
                            TOAST_ACTIVATOR_CLSID,
                        )

        doc_com_classes = root.findall(f".//{com_ns}Class")
        if len(doc_com_classes) != 2:
            errors.append(
                f"{rel}: must declare exactly 2 <com:Class> elements total, found {len(doc_com_classes)}"
            )
        doc_com_all = [el for el in root.iter() if el.tag.startswith(com_ns)]
        if len(doc_com_all) != 6:
            errors.append(
                f"{rel}: contains unexpected com:* elements (expected 6 total, found {len(doc_com_all)})"
            )

        # 3. desktop4:Extension (windows.fileExplorerContextMenus): exact 2 ItemTypes (* and Directory), 1 Verb each.
        doc_d4_exts = root.findall(f".//{desktop4_ns}Extension")
        app_d4_exts = app_ext.findall(f"{desktop4_ns}Extension")
        if len(doc_d4_exts) != 1 or len(app_d4_exts) != 1:
            errors.append(
                f"{rel}: must declare exactly 1 <desktop4:Extension> directly under "
                f"Applications/Application/Extensions (doc={len(doc_d4_exts)}, app={len(app_d4_exts)})"
            )
        else:
            d4_ext = app_d4_exts[0]
            expect_eq(
                errors,
                f"{rel} <desktop4:Extension> Category",
                d4_ext.attrib.get("Category"),
                "windows.fileExplorerContextMenus",
            )
            doc_ctx_menus = root.findall(f".//{desktop4_ns}FileExplorerContextMenus")
            child_ctx_menus = d4_ext.findall(f"{desktop4_ns}FileExplorerContextMenus")
            if len(doc_ctx_menus) != 1 or len(child_ctx_menus) != 1 or len(list(d4_ext)) != 1:
                errors.append(
                    f"{rel}: <desktop4:Extension> must contain exactly 1 <desktop4:FileExplorerContextMenus> "
                    f"as its sole child (doc={len(doc_ctx_menus)}, direct={len(child_ctx_menus)}, "
                    f"children={len(list(d4_ext))})"
                )
            else:
                ctx_menus = child_ctx_menus[0]
                doc_item_types = root.findall(f".//{desktop5_ns}ItemType")
                child_item_types = ctx_menus.findall(f"{desktop5_ns}ItemType")
                if len(list(ctx_menus)) != 2 or len(doc_item_types) != 2 or len(child_item_types) != 2:
                    errors.append(
                        f"{rel}: <desktop4:FileExplorerContextMenus> must contain exactly 2 <desktop5:ItemType> "
                        f"children total (children={len(list(ctx_menus))}, doc={len(doc_item_types)}, "
                        f"direct={len(child_item_types)})"
                    )
                else:
                    seen_types: list[str | None] = [it.attrib.get("Type") for it in child_item_types]
                    if set(seen_types) != {"*", "Directory"}:
                        errors.append(
                            f"{rel}: <desktop5:ItemType> Type set must be exactly {{'*', 'Directory'}}, "
                            f"got {seen_types!r}"
                        )
                    verb_ids: set[str] = set()
                    for item_type in child_item_types:
                        verbs = item_type.findall(f"{desktop5_ns}Verb")
                        if len(list(item_type)) != 1 or len(verbs) != 1:
                            errors.append(
                                f"{rel}: <desktop5:ItemType Type={item_type.attrib.get('Type')!r}> must contain "
                                f"exactly 1 <desktop5:Verb> as its sole child "
                                f"(children={len(list(item_type))}, verbs={len(verbs)})"
                            )
                            continue
                        verb = verbs[0]
                        if len(list(verb)) != 0:
                            errors.append(f"{rel}: <desktop5:Verb> must not contain child elements")
                        verb_id = verb.attrib.get("Id", "")
                        if not verb_id.strip():
                            errors.append(
                                f"{rel}: <desktop5:Verb> under Type={item_type.attrib.get('Type')!r} "
                                "must have a non-empty Id"
                            )
                        elif verb_id in verb_ids:
                            errors.append(f"{rel}: duplicate <desktop5:Verb> Id {verb_id!r}")
                        else:
                            verb_ids.add(verb_id)
                        verb_clsid = verb.attrib.get("Clsid", "")
                        if not BARE_GUID_RE.fullmatch(verb_clsid):
                            errors.append(
                                f"{rel}: <desktop5:Verb> Clsid must be bare GUID without braces, got {verb_clsid!r}"
                            )
                        expect_eq(
                            errors,
                            f"{rel} <desktop5:Verb> Clsid (Type={item_type.attrib.get('Type')!r})",
                            verb_clsid.upper(),
                            CANONICAL_CLSID,
                        )

        doc_verbs = root.findall(f".//{desktop5_ns}Verb")
        if len(doc_verbs) != 2:
            errors.append(
                f"{rel}: must declare exactly 2 <desktop5:Verb> elements total, found {len(doc_verbs)}"
            )
        doc_d4_all = [el for el in root.iter() if el.tag.startswith(desktop4_ns)]
        if len(doc_d4_all) != 2:
            errors.append(
                f"{rel}: contains unexpected desktop4:* elements (expected 2 total, found {len(doc_d4_all)})"
            )
        doc_d5_all = [el for el in root.iter() if el.tag.startswith(desktop5_ns)]
        if len(doc_d5_all) != 4:
            errors.append(
                f"{rel}: contains unexpected desktop5:* elements (expected 4 total, found {len(doc_d5_all)})"
            )

        # 4. desktop:Extension (windows.toastNotificationActivation) matching com:ExeServer Class Id.
        doc_d_exts = root.findall(f".//{desktop_ns}Extension")
        app_d_exts = app_ext.findall(f"{desktop_ns}Extension")
        if len(doc_d_exts) != 1 or len(app_d_exts) != 1:
            errors.append(
                f"{rel}: must declare exactly 1 <desktop:Extension> directly under "
                f"Applications/Application/Extensions (doc={len(doc_d_exts)}, app={len(app_d_exts)})"
            )
        else:
            d_ext = app_d_exts[0]
            expect_eq(
                errors,
                f"{rel} <desktop:Extension> Category",
                d_ext.attrib.get("Category"),
                "windows.toastNotificationActivation",
            )
            doc_toasts = root.findall(f".//{desktop_ns}ToastNotificationActivation")
            child_toasts = d_ext.findall(f"{desktop_ns}ToastNotificationActivation")
            if len(doc_toasts) != 1 or len(child_toasts) != 1 or len(list(d_ext)) != 1:
                errors.append(
                    f"{rel}: <desktop:Extension> must contain exactly 1 <desktop:ToastNotificationActivation> "
                    f"as its sole child (doc={len(doc_toasts)}, direct={len(child_toasts)}, "
                    f"children={len(list(d_ext))})"
                )
            else:
                toast_elem = child_toasts[0]
                if len(list(toast_elem)) != 0:
                    errors.append(f"{rel}: <desktop:ToastNotificationActivation> must not contain child elements")
                toast_guid = toast_elem.attrib.get("ToastActivatorCLSID", "")
                if not BARE_GUID_RE.fullmatch(toast_guid):
                    errors.append(
                        f"{rel}: ToastActivatorCLSID must be bare GUID without braces, got {toast_guid!r}"
                    )
                expect_eq(errors, f"{rel} ToastActivatorCLSID", toast_guid.upper(), TOAST_ACTIVATOR_CLSID)
                if toast_guid.upper() == CANONICAL_CLSID:
                    errors.append(f"{rel}: ToastActivatorCLSID must be distinct from Explorer CLSID")
                if toast_cls_id is not None and toast_guid.upper() != toast_cls_id.upper():
                    errors.append(
                        f"{rel}: ToastActivatorCLSID ({toast_guid!r}) must match ExeServer/Class/@Id ({toast_cls_id!r})"
                    )
        doc_d_all = [el for el in root.iter() if el.tag.startswith(desktop_ns)]
        if len(doc_d_all) != 2:
            errors.append(
                f"{rel}: contains unexpected desktop:* elements (expected 2 total, found {len(doc_d_all)})"
            )

    # 5. Package-level desktop2:Extension (windows.firewallRules): exact 1 FirewallRules + 1 scoped Rule.
    if len(pkg_exts) == 1:
        pkg_ext = pkg_exts[0]
        doc_d2_exts = root.findall(f".//{desktop2_ns}Extension")
        pkg_d2_exts = pkg_ext.findall(f"{desktop2_ns}Extension")
        if len(doc_d2_exts) != 1 or len(pkg_d2_exts) != 1 or len(list(pkg_ext)) != 1:
            errors.append(
                f"{rel}: must declare exactly 1 <desktop2:Extension> as the sole child of "
                f"Package/Extensions (doc={len(doc_d2_exts)}, pkg={len(pkg_d2_exts)}, "
                f"pkg_children={len(list(pkg_ext))})"
            )
        else:
            d2_ext = pkg_d2_exts[0]
            expect_eq(
                errors,
                f"{rel} <desktop2:Extension> Category",
                d2_ext.attrib.get("Category"),
                "windows.firewallRules",
            )
            doc_fw_rules = root.findall(f".//{desktop2_ns}FirewallRules")
            child_fw_rules = d2_ext.findall(f"{desktop2_ns}FirewallRules")
            if len(doc_fw_rules) != 1 or len(child_fw_rules) != 1 or len(list(d2_ext)) != 1:
                errors.append(
                    f"{rel}: <desktop2:Extension> must contain exactly 1 <desktop2:FirewallRules> "
                    f"as its sole child (doc={len(doc_fw_rules)}, direct={len(child_fw_rules)}, "
                    f"children={len(list(d2_ext))})"
                )
            else:
                fw_rules = child_fw_rules[0]
                expect_eq(
                    errors,
                    f"{rel} FirewallRules Executable",
                    fw_rules.attrib.get("Executable"),
                    "totaldrop-winui.exe",
                )
                doc_rules = root.findall(f".//{desktop2_ns}Rule")
                child_rules = fw_rules.findall(f"{desktop2_ns}Rule")
                if len(doc_rules) != 1 or len(child_rules) != 1 or len(list(fw_rules)) != 1:
                    errors.append(
                        f"{rel}: <desktop2:FirewallRules> must contain exactly 1 <desktop2:Rule> "
                        f"as its sole child (doc={len(doc_rules)}, direct={len(child_rules)}, "
                        f"children={len(list(fw_rules))})"
                    )
                else:
                    rule = child_rules[0]
                    if len(list(rule)) != 0:
                        errors.append(f"{rel}: <desktop2:Rule> must not contain child elements")
                    expect_eq(errors, f"{rel} Firewall Rule Direction", rule.attrib.get("Direction"), "in")
                    expect_eq(errors, f"{rel} Firewall Rule IPProtocol", rule.attrib.get("IPProtocol"), "UDP")
                    expect_eq(errors, f"{rel} Firewall Rule Profile", rule.attrib.get("Profile"), "private")
        doc_d2_all = [el for el in root.iter() if el.tag.startswith(desktop2_ns)]
        if len(doc_d2_all) != 3:
            errors.append(
                f"{rel}: contains unexpected desktop2:* elements (expected 3 total, found {len(doc_d2_all)})"
            )

    # 6. Restricted capability runFullTrust (sole rescap:Capability under Package/Capabilities).
    doc_caps = root.findall(f".//{appx_ns}Capabilities")
    direct_caps = root.findall(f"{appx_ns}Capabilities")
    if len(doc_caps) != 1 or len(direct_caps) != 1:
        errors.append(
            f"{rel}: must contain exactly 1 top-level <Capabilities> element "
            f"(doc={len(doc_caps)}, direct={len(direct_caps)})"
        )
    else:
        caps = direct_caps[0]
        doc_rescaps = root.findall(f".//{rescap_ns}Capability")
        direct_rescaps = caps.findall(f"{rescap_ns}Capability")
        if (
            len(doc_rescaps) != 1
            or len(direct_rescaps) != 1
            or direct_rescaps[0].attrib.get("Name") != "runFullTrust"
        ):
            errors.append(
                f'{rel}: must declare exactly 1 <rescap:Capability Name="runFullTrust" /> '
                "under Package/Capabilities"
            )


def check_cross_arch_identity_parity(
    x64_label: str,
    x64_root: ET.Element,
    x64_raw: str,
    arm64_label: str,
    arm64_root: ET.Element,
    arm64_raw: str,
    errors: list[str],
    *,
    require_store_rules: bool,
    require_store_identity: bool = False,
    allow_test_identity: bool = False,
    notes: list[str] | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Validate x64 & arm64 Identity, X.500 Publisher, unsigned OID ban, Properties parity, and extensions."""
    appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"

    extracted: dict[str, dict[str, str]] = {}
    for arch, label, root, raw_text in (
        ("x64", x64_label, x64_root, x64_raw),
        ("arm64", arm64_label, arm64_root, arm64_raw),
    ):
        if UNSIGNED_PACKAGE_OID in raw_text.lower():
            errors.append(
                f"{label}: contains forbidden unsigned-package OID {UNSIGNED_PACKAGE_OID}"
            )

        doc_idents = root.findall(f".//{appx_ns}Identity")
        direct_idents = root.findall(f"{appx_ns}Identity")
        if len(doc_idents) != 1 or len(direct_idents) != 1:
            errors.append(
                f"{label}: must declare exactly 1 top-level <Identity> "
                f"(doc={len(doc_idents)}, direct={len(direct_idents)})"
            )
            continue
        ident = direct_idents[0]
        name = ident.attrib.get("Name", "")
        publisher = ident.attrib.get("Publisher", "")
        version = ident.attrib.get("Version", "")
        proc_arch = ident.attrib.get("ProcessorArchitecture", "")

        expect_eq(errors, f"{label} Identity/@ProcessorArchitecture", proc_arch, arch)
        if not IDENTITY_NAME_RE.fullmatch(name):
            errors.append(
                f"{label}: Identity/@Name {name!r} must match {IDENTITY_NAME_RE.pattern}"
            )
        validate_x500_publisher(publisher, f"{label} Identity/@Publisher", errors)
        validate_msix_version_quad(
            version,
            f"{label} Identity/@Version",
            errors,
            require_store_rules=require_store_rules,
        )

        doc_props = root.findall(f".//{appx_ns}Properties")
        direct_props = root.findall(f"{appx_ns}Properties")
        disp_name = ""
        pub_disp = ""
        if len(doc_props) != 1 or len(direct_props) != 1:
            errors.append(
                f"{label}: AppxManifest.xml must declare exactly 1 top-level <Properties> "
                f"(doc={len(doc_props)}, direct={len(direct_props)})"
            )
        else:
            props = direct_props[0]
            doc_dns = root.findall(f".//{appx_ns}DisplayName")
            direct_dns = props.findall(f"{appx_ns}DisplayName")
            if len(doc_dns) != 1 or len(direct_dns) != 1:
                errors.append(
                    f"{label}: Properties must declare exactly 1 <DisplayName> "
                    f"(doc={len(doc_dns)}, direct={len(direct_dns)})"
                )
            else:
                disp_name = (direct_dns[0].text or "").strip()
                if not disp_name:
                    errors.append(f"{label}: Properties/DisplayName must be non-empty")

            doc_pds = root.findall(f".//{appx_ns}PublisherDisplayName")
            direct_pds = props.findall(f"{appx_ns}PublisherDisplayName")
            if len(doc_pds) != 1 or len(direct_pds) != 1:
                errors.append(
                    f"{label}: Properties must declare exactly 1 <PublisherDisplayName> "
                    f"(doc={len(doc_pds)}, direct={len(direct_pds)})"
                )
            else:
                pub_disp = (direct_pds[0].text or "").strip()
                if not pub_disp:
                    errors.append(f"{label}: Properties/PublisherDisplayName must be non-empty")

        _check_manifest_extensions(label, root, errors)
        extracted[arch] = {
            "name": name,
            "publisher": publisher,
            "version": version,
            "display_name": disp_name,
            "publisher_display_name": pub_disp,
        }

    if "x64" not in extracted or "arm64" not in extracted:
        return (None, None, None)

    x64_info = extracted["x64"]
    arm64_info = extracted["arm64"]
    for field, field_label in (
        ("name", "Identity/@Name"),
        ("publisher", "Identity/@Publisher"),
        ("version", "Identity/@Version"),
        ("display_name", "Properties/DisplayName"),
        ("publisher_display_name", "Properties/PublisherDisplayName"),
    ):
        if x64_info[field] != arm64_info[field]:
            errors.append(
                f"cross-arch parity mismatch on {field_label}: "
                f"x64={x64_info[field]!r} vs arm64={arm64_info[field]!r}"
            )

    if require_store_rules:
        is_placeholder = is_placeholder_test_identity(x64_info["name"], x64_info["publisher"])
        if is_placeholder:
            if require_store_identity:
                errors.append(
                    "Store identity required (--require-store-identity): refusing placeholder "
                    f"Name={x64_info['name']!r}, Publisher={x64_info['publisher']!r}"
                )
            elif not allow_test_identity and notes is not None:
                notes.append(
                    f"note: manifests still use temporary test identity "
                    f"(Name={x64_info['name']!r}, Publisher={x64_info['publisher']!r}); "
                    "pass --require-store-identity to reject placeholders before Partner Center submission."
                )

    return (x64_info["version"], x64_info["name"], x64_info["publisher"])


def check_manifests_and_scripts(repo_root: Path, errors: list[str]) -> None:
    if not re.fullmatch(r"\d+\.\d+\.\d+\.0", MSIX_VERSION):
        errors.append(
            f"MSIX_VERSION {MSIX_VERSION!r} must be 4-part with Revision == 0 for Microsoft Store"
        )

    app_manifest = ET.fromstring(
        (repo_root / "ui-winui3-fluent2" / "app.manifest").read_text(encoding="utf-8")
    )
    asm_id = app_manifest.find("{urn:schemas-microsoft-com:asm.v1}assemblyIdentity")
    expect_eq(
        errors,
        "ui-winui3-fluent2/app.manifest assemblyIdentity/@version",
        asm_id.attrib.get("version") if asm_id is not None else None,
        MSIX_VERSION,
    )

    x64_rel = "target-x86_64/Package.x64.appxmanifest"
    arm64_rel = "target-arm64/Package.arm64.appxmanifest"
    x64_raw = (repo_root / x64_rel).read_text(encoding="utf-8")
    arm64_raw = (repo_root / arm64_rel).read_text(encoding="utf-8")
    x64_root = ET.fromstring(x64_raw)
    arm64_root = ET.fromstring(arm64_raw)

    appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
    for rel, root in ((x64_rel, x64_root), (arm64_rel, arm64_root)):
        ident = root.find(f"{appx_ns}Identity")
        expect_eq(
            errors,
            f"{rel} Identity/@Version",
            ident.attrib.get("Version") if ident is not None else None,
            MSIX_VERSION,
        )

    check_cross_arch_identity_parity(
        x64_rel,
        x64_root,
        x64_raw,
        arm64_rel,
        arm64_root,
        arm64_raw,
        errors,
        require_store_rules=False,
    )

    for rel in ("target-x86_64/build-x64.ps1", "target-arm64/build-arm64.ps1"):
        text = (repo_root / rel).read_text(encoding="utf-8")
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
        text = (repo_root / rel).read_text(encoding="utf-8")
        if not re.search(
            r"^#[ \t]*yaml-language-server:[ \t]*\$schema=https://aka\.ms/winget-manifest\.singleton\.1\.9\.0\.schema\.json[ \t]*$",
            text,
            re.MULTILINE,
        ):
            errors.append(
                f"{rel}: missing https://aka.ms/winget-manifest.singleton.1.9.0.schema.json schema header"
            )
        for key_name, expected_val in (("ManifestVersion", "1.9.0"), ("PackageVersion", APP_VERSION)):
            key_lines = [
                line for line in text.splitlines() if re.match(rf"^[ \t]*{key_name}:", line)
            ]
            if len(key_lines) != 1:
                errors.append(
                    f"{rel}: expected exactly 1 {key_name} entry, found {len(key_lines)}"
                )
            else:
                m_key = re.fullmatch(rf"{key_name}:[ \t]*(\S+)[ \t]*(?:#.*)?", key_lines[0])
                expect_eq(
                    errors,
                    f"{rel} {key_name}",
                    m_key.group(1) if m_key else None,
                    expected_val,
                )
        expected_msix = f"TotalDrop_{MSIX_VERSION}_{arch_tag}.msix"
        installer_urls = [
            m.group(1).split("#", 1)[0].strip().strip("'\"")
            for m in re.finditer(r"^[ \t]*(?:-[ \t]+)?InstallerUrl:[ \t]*(.*)$", text, re.MULTILINE)
        ]
        if len(installer_urls) != 1:
            errors.append(
                f"{rel}: expected exactly 1 non-comment InstallerUrl entry, found {len(installer_urls)}"
            )
        elif not installer_urls[0].endswith(f"/{expected_msix}"):
            errors.append(
                f"{rel}: InstallerUrl ({installer_urls[0]!r}) does not reference {expected_msix}"
            )


def check_subplatforms_and_workflows(repo_root: Path, errors: list[str]) -> None:
    expected_artifacts: dict[tuple[str, str], str] = {
        ("msix", "x86_64"): f"TotalDrop_{MSIX_VERSION}_x64.msix",
        ("msix", "arm64"): f"TotalDrop_{MSIX_VERSION}_arm64.msix",
        ("portable-zip", "x86_64"): f"TotalDrop-{APP_VERSION}-portable-x64.zip",
        ("portable-zip", "arm64"): f"TotalDrop-{APP_VERSION}-portable-arm64.zip",
        ("winget", "x86_64"): f"TotalDrop-{APP_VERSION}-winget-x64.zip",
        ("winget", "arm64"): f"TotalDrop-{APP_VERSION}-winget-arm64.zip",
    }

    for (fmt, arch), expected_artifact in sorted(expected_artifacts.items()):
        unit_dir = repo_root / "subplatforms" / fmt / arch
        recipe_path = unit_dir / "RECIPE.toml"
        data = tomllib.loads(recipe_path.read_text(encoding="utf-8"))
        expect_eq(errors, f"{recipe_path.relative_to(repo_root)} version", data.get("version"), APP_VERSION)
        expect_eq(
            errors,
            f"{recipe_path.relative_to(repo_root)} artifact_name",
            data.get("artifact_name"),
            expected_artifact,
        )
        for script_name in ("build.sh", "verify.sh"):
            script_path = unit_dir / script_name
            if expected_artifact not in script_path.read_text(encoding="utf-8"):
                errors.append(
                    f"{script_path.relative_to(repo_root)}: missing expected artifact {expected_artifact}"
                )
        workflow_path = repo_root / data["workflow"]
        if expected_artifact not in workflow_path.read_text(encoding="utf-8"):
            errors.append(
                f"{workflow_path.relative_to(repo_root)}: missing expected artifact {expected_artifact}"
            )

    ci_text = (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for arch_tag in ("x64", "arm64"):
        expected_ci_msix = f"TotalDrop_{MSIX_VERSION}_{arch_tag}.msix"
        if expected_ci_msix not in ci_text:
            errors.append(
                f".github/workflows/ci.yml: missing expected {arch_tag} MSIX filename {expected_ci_msix}"
            )
    expected_ci_flag = f"--expected-version {MSIX_VERSION}"
    if expected_ci_flag not in ci_text:
        errors.append(f".github/workflows/ci.yml: missing `{expected_ci_flag}`")

    verifier_text = (repo_root / "tools" / "verify-msix-artifact.py").read_text(encoding="utf-8")
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


def _iter_repo_text_files(repo_root: Path) -> list[str]:
    if (repo_root / ".git").exists():
        ls_proc = subprocess.run(
            ["git", "ls-files"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        return [rel for rel in ls_proc.stdout.splitlines() if rel]

    rel_paths: list[str] = []
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root)
        if any(part in SKIP_WALK_DIRS for part in rel.parts):
            continue
        rel_paths.append(rel.as_posix())
    return rel_paths


def check_readme_and_forbidden_literals(repo_root: Path, errors: list[str]) -> None:
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    if CANONICAL_CLSID not in readme:
        errors.append(f"README.md: missing canonical Explorer COM CLSID {{{CANONICAL_CLSID}}}")

    for rel in _iter_repo_text_files(repo_root):
        if not rel or rel in ("Cargo.lock", "tools/check-versions.py"):
            continue
        path = repo_root / rel
        if not path.is_file() or path.suffix.lower() in (".png", ".ico", ".pri", ".msix", ".msixbundle", ".msixupload", ".appxsym"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for literal, reason in FORBIDDEN_LITERALS:
            if re.search(re.escape(literal), text, re.IGNORECASE):
                errors.append(f"{rel}: contains forbidden {reason} ({literal!r})")


def _resolve_manifest_pair(repo_root: Path) -> tuple[Path | None, Path | None]:
    x64_candidates = (
        repo_root / "target-x86_64" / "Package.x64.appxmanifest",
        repo_root / "Package.x64.appxmanifest",
    )
    arm64_candidates = (
        repo_root / "target-arm64" / "Package.arm64.appxmanifest",
        repo_root / "Package.arm64.appxmanifest",
    )
    x64_path = next((p for p in x64_candidates if p.is_file()), None)
    arm64_path = next((p for p in arm64_candidates if p.is_file()), None)
    return (x64_path, arm64_path)


def check_store_mode(
    repo_root: Path,
    store_version: str | None,
    require_store_identity: bool,
    allow_test_identity: bool,
    errors: list[str],
    notes: list[str],
) -> tuple[str | None, str | None, str | None]:
    if store_version is not None:
        validate_store_msix_version(store_version, "--store-version", errors)

    x64_path, arm64_path = _resolve_manifest_pair(repo_root)
    if x64_path is None:
        errors.append(
            f"{repo_root}: missing Package.x64.appxmanifest (checked target-x86_64/ and root)"
        )
    if arm64_path is None:
        errors.append(
            f"{repo_root}: missing Package.arm64.appxmanifest (checked target-arm64/ and root)"
        )
    if x64_path is None or arm64_path is None:
        return (None, None, None)

    x64_label = x64_path.relative_to(repo_root).as_posix()
    arm64_label = arm64_path.relative_to(repo_root).as_posix()
    try:
        x64_raw = x64_path.read_text(encoding="utf-8")
        x64_root = ET.fromstring(x64_raw)
    except (OSError, ET.ParseError) as exc:
        errors.append(f"{x64_label}: failed to parse XML: {exc}")
        return (None, None, None)
    try:
        arm64_raw = arm64_path.read_text(encoding="utf-8")
        arm64_root = ET.fromstring(arm64_raw)
    except (OSError, ET.ParseError) as exc:
        errors.append(f"{arm64_label}: failed to parse XML: {exc}")
        return (None, None, None)

    manifest_ver, ident_name, publisher = check_cross_arch_identity_parity(
        x64_label,
        x64_root,
        x64_raw,
        arm64_label,
        arm64_root,
        arm64_raw,
        errors,
        require_store_rules=True,
        require_store_identity=require_store_identity,
        allow_test_identity=allow_test_identity,
        notes=notes,
    )

    effective_ver = store_version if store_version is not None else manifest_ver
    if store_version is not None and manifest_ver is not None and manifest_ver != store_version:
        errors.append(
            f"manifest Identity/@Version ({manifest_ver!r}) does not match --store-version ({store_version!r})"
        )

    # Validate companion app.manifest and build-{x64,arm64}.ps1 when present under repo_root.
    if effective_ver is not None:
        app_manifest_path = repo_root / "ui-winui3-fluent2" / "app.manifest"
        if app_manifest_path.is_file():
            try:
                app_manifest = ET.fromstring(app_manifest_path.read_text(encoding="utf-8"))
                asm_id = app_manifest.find("{urn:schemas-microsoft-com:asm.v1}assemblyIdentity")
                expect_eq(
                    errors,
                    "ui-winui3-fluent2/app.manifest assemblyIdentity/@version",
                    asm_id.attrib.get("version") if asm_id is not None else None,
                    effective_ver,
                )
            except ET.ParseError as exc:
                errors.append(f"ui-winui3-fluent2/app.manifest: invalid XML: {exc}")

        for rel in ("target-x86_64/build-x64.ps1", "target-arm64/build-arm64.ps1"):
            script_path = repo_root / rel
            if script_path.is_file():
                text = script_path.read_text(encoding="utf-8")
                m_ver = re.search(r'\[string\]\$Version\s*=\s*"([^"]+)"', text)
                expect_eq(
                    errors,
                    f"{rel} default $Version",
                    m_ver.group(1) if m_ver else None,
                    effective_ver,
                )

        csproj_path = repo_root / "ui-winui3-fluent2" / "TotalDrop.WinUI.csproj"
        if csproj_path.is_file():
            try:
                csproj_root = ET.fromstring(csproj_path.read_text(encoding="utf-8"))
                for tag in ("AssemblyVersion", "FileVersion"):
                    elems = csproj_root.findall(f".//{tag}")
                    val = (elems[0].text or "").strip() if len(elems) == 1 else None
                    expect_eq(
                        errors,
                        f"ui-winui3-fluent2/TotalDrop.WinUI.csproj <{tag}>",
                        val,
                        effective_ver,
                    )
            except ET.ParseError as exc:
                errors.append(f"ui-winui3-fluent2/TotalDrop.WinUI.csproj: invalid XML: {exc}")

    return (effective_ver, ident_name, publisher)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify version alignment, CLSID invariants, and Microsoft Store MSIX rules."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="Repository or fixture root directory (default: repo root).",
    )
    parser.add_argument(
        "--store",
        action="store_true",
        help="Validate Package.{x64,arm64}.appxmanifest (and companion files when present) under Microsoft Store rules.",
    )
    parser.add_argument(
        "--store-version",
        default=None,
        help="Validate an explicit 4-part Microsoft Store MSIX version (Major >= 1, Revision == 0).",
    )
    parser.add_argument(
        "--require-store-identity",
        action="store_true",
        help="With --store, reject temporary CN=TotalDrop / TotalDrop.TotalDrop test identity.",
    )
    parser.add_argument(
        "--allow-test-identity",
        action="store_true",
        help="With --store, explicitly permit temporary CN=TotalDrop / TotalDrop.TotalDrop dry-run identity.",
    )
    args = parser.parse_args(argv)

    if args.require_store_identity and args.allow_test_identity:
        parser.error("--require-store-identity and --allow-test-identity are mutually exclusive.")
    if (args.require_store_identity or args.allow_test_identity) and not args.store:
        parser.error("--require-store-identity and --allow-test-identity require --store.")

    errors: list[str] = []
    notes: list[str] = []
    repo_root = args.root.resolve()

    if args.store_version is not None and not args.store:
        validate_store_msix_version(args.store_version, "--store-version", errors)
        if errors:
            for err in errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        print(f"store version check OK: msix={args.store_version} (Major >= 1, Revision == 0, uint16 quad).")
        return 0

    if args.store:
        ver, ident_name, publisher = check_store_mode(
            repo_root,
            args.store_version,
            args.require_store_identity,
            args.allow_test_identity,
            errors,
            notes,
        )
        if errors:
            for err in errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        for note in notes:
            print(note)
        print(
            f"store versions check OK: msix={ver}, identity={ident_name}, "
            f"publisher={publisher}, cross-arch parity verified."
        )
        return 0

    check_core_bucket(repo_root, errors)
    check_ffi_and_csproj(repo_root, errors)
    check_manifests_and_scripts(repo_root, errors)
    check_subplatforms_and_workflows(repo_root, errors)
    check_readme_and_forbidden_literals(repo_root, errors)

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
