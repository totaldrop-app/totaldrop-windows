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
TOAST_ACTIVATOR_CLSID = "7DF2CCED-0448-4849-A140-41CD106EAA9B"
BARE_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

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

    ext_toml = tomllib.loads(
        (REPO_ROOT / "crates" / "totaldrop-explorer-ext" / "Cargo.toml").read_text(
            encoding="utf-8"
        )
    )
    expect_eq(
        errors,
        "crates/totaldrop-explorer-ext/Cargo.toml [package].version",
        ext_toml.get("package", {}).get("version"),
        APP_VERSION,
    )

    ext_src = (REPO_ROOT / "crates" / "totaldrop-explorer-ext" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    if CANONICAL_CLSID not in ext_src:
        errors.append(
            f"crates/totaldrop-explorer-ext/src/lib.rs: missing canonical Explorer CLSID {CANONICAL_CLSID}"
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
        _check_manifest_extensions(rel, root, errors)

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
