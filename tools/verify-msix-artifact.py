#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Deep structural, PRI, PE32+ hardening, CRT, and live C ABI verifier for TotalDrop MSIX packages.

Uses only the Python standard library so it runs cleanly on GitHub Actions
`windows-latest` and `windows-11-arm` runners without extra dependencies.
"""

from __future__ import annotations

import argparse
import re
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

EXPECTED_APP_VERSION = "0.1.0-beta.1"
EXPECTED_CORE_VERSION = "0.2.0-beta.5"
EXPECTED_MSIX_VERSION = "0.1.1.0"

REQUIRED_FFI_EXPORTS: tuple[str, ...] = (
    "totaldrop_win_string_free",
    "totaldrop_win_version_json",
    "totaldrop_win_validate_uri_json",
    "totaldrop_win_validate_input_json",
    "totaldrop_win_format_percent_json",
    "totaldrop_win_ui_bundle_json",
)

FORBIDDEN_CRT_DLLS: tuple[str, ...] = (
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "msvcp140.dll",
)


def _build_expected_assets() -> frozenset[str]:
    """Return the exact 46 canonical Kose asset filenames matching tools/render-windows-assets.py."""
    names: list[str] = ["TotalDrop.ico"]
    for prefix in (
        "StoreLogo",
        "Square44x44Logo",
        "Square71x71Logo",
        "Square150x150Logo",
        "Wide310x150Logo",
        "Square310x310Logo",
    ):
        for scale in (100, 125, 150, 200, 400):
            names.append(f"{prefix}.scale-{scale}.png")
    for size in (16, 24, 32, 48, 256):
        names.append(f"Square44x44Logo.targetsize-{size}.png")
        names.append(f"Square44x44Logo.targetsize-{size}_altform-unplated.png")
        names.append(f"Square44x44Logo.targetsize-{size}_altform-lightunplated.png")
    return frozenset(names)


EXPECTED_ASSETS: frozenset[str] = _build_expected_assets()

IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20
IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x0001
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x0800

_SMOKE_TEST_CHILD_SCRIPT = r"""
import ctypes
import json
import sys

dll_path, expected_app, expected_core, expected_msix = sys.argv[1:5]
lib = ctypes.CDLL(dll_path)

lib.totaldrop_win_string_free.argtypes = [ctypes.c_void_p]
lib.totaldrop_win_string_free.restype = None

lib.totaldrop_win_version_json.argtypes = []
lib.totaldrop_win_version_json.restype = ctypes.c_void_p

lib.totaldrop_win_validate_uri_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_validate_uri_json.restype = ctypes.c_void_p

lib.totaldrop_win_validate_input_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_validate_input_json.restype = ctypes.c_void_p

lib.totaldrop_win_format_percent_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_char_p,
]
lib.totaldrop_win_format_percent_json.restype = ctypes.c_void_p

lib.totaldrop_win_ui_bundle_json.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_ui_bundle_json.restype = ctypes.c_void_p


def take_json(ptr):
    if not ptr:
        raise ValueError("FFI returned null pointer during live smoke test")
    try:
        raw = ctypes.cast(ptr, ctypes.c_char_p).value
        if raw is None:
            raise ValueError("FFI returned empty C string")
        return json.loads(raw.decode("utf-8"))
    finally:
        lib.totaldrop_win_string_free(ptr)


# Null free must be safe.
lib.totaldrop_win_string_free(None)

ver = take_json(lib.totaldrop_win_version_json())
assert ver == {
    "app_version": expected_app,
    "core_version": expected_core,
    "msix_version": expected_msix,
}, f"unexpected version JSON: {ver}"

uri_ok = take_json(lib.totaldrop_win_validate_uri_json(b"totaldrop://r/7-harbor-rocket"))
assert uri_ok.get("display_english") == "7-harbor-rocket", f"unexpected uri ok: {uri_ok}"

uri_bad = take_json(lib.totaldrop_win_validate_uri_json(b"https://evil.example/r#7-harbor-rocket"))
assert uri_bad.get("ok") is False, f"expected error envelope for evil URI: {uri_bad}"

input_ok = take_json(lib.totaldrop_win_validate_input_json(b"7 harbor rocket"))
assert input_ok.get("canonical") == "7-840-1499", f"unexpected input ok: {input_ok}"

pct = take_json(lib.totaldrop_win_format_percent_json(999_999, 1_000_000, b"tr-TR"))
assert pct == {"whole": 99, "formatted": "%99"}, f"unexpected #483 percent JSON: {pct}"

ar_bundle = take_json(lib.totaldrop_win_ui_bundle_json(b"ar-SA,en-US", b"ar-EG", None))
assert ar_bundle.get("language_tag") == "ar", f"unexpected ar bundle: {ar_bundle}"
assert ar_bundle.get("flow_direction") == "RightToLeft"
assert ar_bundle.get("verification_title") == "Verification words"
"""


def parse_pe64(path: Path) -> dict[str, object]:
    """Parse PE32+ headers, security flags, Debug Dir CET_COMPAT, Load Config, imports, and exports."""
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path.name}: missing MZ header")

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError(f"{path.name}: missing PE signature")

        coff_off = e_lfanew + 4
        machine, num_sections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff_off)
        opt_off = coff_off + 20
        if opt_off + 2 > len(data):
            raise ValueError(f"{path.name}: truncated PE optional header")
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            raise ValueError(f"{path.name}: expected PE32+ (0x20B), got {magic:#x}")
        if opt_size < 112 or opt_off + opt_size > len(data):
            raise ValueError(f"{path.name}: truncated PE32+ optional header")

        dll_chars = struct.unpack_from("<H", data, opt_off + 70)[0]
        num_rvas = struct.unpack_from("<I", data, opt_off + 108)[0]
        data_dirs_off = opt_off + 112

        def data_dir(index: int) -> tuple[int, int]:
            off = data_dirs_off + index * 8
            if index >= num_rvas or off + 8 > opt_off + opt_size or off + 8 > len(data):
                return (0, 0)
            return struct.unpack_from("<II", data, off)

        sections: list[tuple[int, int, int, int]] = []
        sec_off = opt_off + opt_size
        if sec_off + num_sections * 40 > len(data):
            raise ValueError(f"{path.name}: truncated PE32+ section table")
        for i in range(num_sections):
            entry_off = sec_off + i * 40
            _, v_size, v_addr, raw_size, raw_ptr, _, _, _, _, _ = struct.unpack_from(
                "<8sIIIIIIHHI", data, entry_off
            )
            sections.append((v_addr, max(v_size, raw_size), raw_ptr, raw_size))

        def rva_to_off(rva: int) -> int | None:
            if rva == 0:
                return None
            for v_addr, span, raw_ptr, raw_size in sections:
                if v_addr <= rva < v_addr + span:
                    delta = rva - v_addr
                    if delta < raw_size and raw_ptr + delta < len(data):
                        return raw_ptr + delta
            return None

        def read_cstr(off: int | None) -> str:
            if off is None or off >= len(data):
                return ""
            end = data.find(b"\x00", off)
            if end == -1:
                return ""
            return data[off:end].decode("ascii", errors="replace")

        # Extended DllCharacteristics (CET_COMPAT) in Debug Directory Type == 20.
        ex_dll_chars = 0
        dbg_rva, dbg_size = data_dir(6)
        dbg_off = rva_to_off(dbg_rva)
        if dbg_off is not None and dbg_size >= 28:
            for i in range(dbg_size // 28):
                eoff = dbg_off + i * 28
                if eoff + 28 > len(data):
                    break
                _, _, _, _, dtype, size_of_data, addr_raw, ptr_raw = struct.unpack_from(
                    "<IIHHIIII", data, eoff
                )
                if dtype == IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS and size_of_data >= 4:
                    val_off = ptr_raw if ptr_raw != 0 else rva_to_off(addr_raw)
                    if val_off is not None and val_off + 4 <= len(data):
                        ex_dll_chars |= struct.unpack_from("<I", data, val_off)[0]

        # Load Config DependentLoadFlags (offset 0x4E in IMAGE_LOAD_CONFIG_DIRECTORY64;
        # minimum struct size 0x50 = 80 bytes per Microsoft PE32+ specification).
        # Note: MSVC link.exe historically sets DataDirectory[10].Size = 0x40 while
        # the struct's own Size header field holds the full >= 0x50 length, whereas
        # DataDirectory[10].Size == 0 disables Load Config in the Windows PE loader.
        dependent_load_flags: int | None = None
        lc_rva, lc_dir_size = data_dir(10)
        lc_off = rva_to_off(lc_rva)
        if lc_dir_size > 0 and lc_off is not None and lc_off + 4 <= len(data):
            lc_struct_size = struct.unpack_from("<I", data, lc_off)[0]
            if lc_struct_size >= 0x50 and lc_off + 0x50 <= len(data):
                dependent_load_flags = struct.unpack_from("<H", data, lc_off + 0x4E)[0]

        # Standard Import Directory (DataDirectory[1]).
        imports: list[str] = []
        imp_rva, _ = data_dir(1)
        imp_off = rva_to_off(imp_rva)
        if imp_off is not None:
            pos = imp_off
            while pos + 20 <= len(data):
                oft, ts, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, pos)
                if (oft, ts, fwd, name_rva, ft) == (0, 0, 0, 0, 0):
                    break
                dll_name = read_cstr(rva_to_off(name_rva)).lower()
                if dll_name:
                    imports.append(dll_name)
                pos += 20

        # Delay-Import Directory (DataDirectory[13]).
        delay_imports: list[str] = []
        dimp_rva, _ = data_dir(13)
        dimp_off = rva_to_off(dimp_rva)
        if dimp_off is not None:
            pos = dimp_off
            while pos + 32 <= len(data):
                attrs, dll_name_rva, _, _, _, _, _, _ = struct.unpack_from("<IIIIIIII", data, pos)
                if attrs == 0 and dll_name_rva == 0:
                    break
                dll_name = read_cstr(rva_to_off(dll_name_rva)).lower()
                if dll_name:
                    delay_imports.append(dll_name)
                pos += 32

        # Export Directory (DataDirectory[0]).
        exports: list[str] = []
        exp_rva, _ = data_dir(0)
        exp_off = rva_to_off(exp_rva)
        if exp_off is not None and exp_off + 40 <= len(data):
            num_names = struct.unpack_from("<I", data, exp_off + 24)[0]
            names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
            names_off = rva_to_off(names_rva)
            if names_off is not None:
                for i in range(num_names):
                    if names_off + i * 4 + 4 > len(data):
                        break
                    sym_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
                    sym = read_cstr(rva_to_off(sym_rva))
                    if sym:
                        exports.append(sym)

        clr_rva, clr_size = data_dir(14)
    except struct.error as exc:
        raise ValueError(f"{path.name}: truncated or malformed PE32+ binary: {exc}") from exc

    return {
        "machine": machine,
        "dll_chars": dll_chars,
        "ex_dll_chars": ex_dll_chars,
        "dependent_load_flags": dependent_load_flags,
        "imports": imports,
        "delay_imports": delay_imports,
        "exports": exports,
        "clr_header": (clr_rva, clr_size),
    }


def verify_pri_dump(pri_dump_path: Path) -> None:
    raw = pri_dump_path.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    upper_text = text.upper()
    required_tokens = (
        "StoreLogo.png",
        "Square44x44Logo.png",
        "Square150x150Logo.png",
        "Wide310x150Logo.png",
        "Square71x71Logo.png",
        "Square310x310Logo.png",
        "App.xbf",
        "MainWindow.xbf",
        "SendPage.xbf",
        "ReceivePage.xbf",
    )
    missing = [tok for tok in required_tokens if tok not in text]
    for qualifier in ("UNPLATED", "LIGHTUNPLATED"):
        if not re.search(rf"(?<![A-Z0-9]){qualifier}(?![A-Z0-9])", upper_text):
            missing.append(qualifier)
    if missing:
        raise ValueError(f"resources.pri dump missing expected entries: {missing}")

    # Verify multi-locale string candidates compiled from the 35 .resw files.
    for lang_marker in ('"EN"', '"TR"', '"AR"', '"JA"', '"ZH-HANS"', '"ZH-HANT"'):
        if lang_marker not in upper_text:
            raise ValueError(f"resources.pri dump missing locale candidate {lang_marker}")


def smoke_test_ffi_dll(dll_path: Path) -> None:
    """Invoke live C ABI exports in a short-lived child subprocess.

    Running ctypes.CDLL in a child process guarantees Windows releases the DLL
    file mapping on child exit before TemporaryDirectory cleanup deletes it.
    """
    subprocess.run(
        [
            sys.executable,
            "-c",
            _SMOKE_TEST_CHILD_SCRIPT,
            str(dll_path),
            EXPECTED_APP_VERSION,
            EXPECTED_CORE_VERSION,
            EXPECTED_MSIX_VERSION,
        ],
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify packed TotalDrop MSIX archive, PRI dump, PE32+ hardening, and FFI ABI."
    )
    parser.add_argument("--msix", type=Path, required=True, help="Path to built .msix archive.")
    parser.add_argument("--arch", choices=("x64", "arm64"), default="x64")
    parser.add_argument("--expected-version", default=EXPECTED_MSIX_VERSION)
    parser.add_argument(
        "--expect-signed",
        action="store_true",
        help="Require AppxSignature.p7x inside the MSIX package.",
    )
    parser.add_argument(
        "--pri-dump",
        type=Path,
        default=None,
        help="Optional MakePri.exe detailed XML dump to inspect.",
    )
    args = parser.parse_args(argv)

    msix_path = args.msix
    if not msix_path.is_file():
        print(f"error: MSIX not found: {msix_path}", file=sys.stderr)
        return 1

    magic = msix_path.read_bytes()[:4]
    if magic != b"PK\x03\x04":
        print(f"error: {msix_path} is not a ZIP/OPC archive (magic={magic!r})", file=sys.stderr)
        return 1

    expected_machine = IMAGE_FILE_MACHINE_AMD64 if args.arch == "x64" else IMAGE_FILE_MACHINE_ARM64

    with zipfile.ZipFile(msix_path, "r") as zf:
        bad_member = zf.testzip()
        if bad_member is not None:
            print(f"error: corrupted ZIP member in MSIX: {bad_member}", file=sys.stderr)
            return 1

        names = set(zf.namelist())
        required = {
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "resources.pri",
            "totaldrop-winui.exe",
            "totaldrop_windows_ffi.dll",
            "App.xbf",
            "MainWindow.xbf",
            "Views/SendPage.xbf",
            "Views/ReceivePage.xbf",
        }
        if args.expect_signed:
            required.add("AppxSignature.p7x")

        missing = sorted(required - names)
        if missing:
            print(f"error: MSIX missing required entries: {missing}", file=sys.stderr)
            return 1

        if args.expect_signed and zf.getinfo("AppxSignature.p7x").file_size <= 0:
            print("error: AppxSignature.p7x is empty", file=sys.stderr)
            return 1

        asset_entries = {n for n in names if n.startswith("Assets/") and not n.endswith("/")}
        expected_asset_entries = {f"Assets/{name}" for name in EXPECTED_ASSETS}
        if asset_entries != expected_asset_entries:
            missing_assets = sorted(expected_asset_entries - asset_entries)
            extra_assets = sorted(asset_entries - expected_asset_entries)
            print(
                f"error: MSIX Assets/ mismatch (expected {len(expected_asset_entries)} canonical Kose assets; "
                f"missing={missing_assets[:8]}, unexpected={extra_assets[:8]})",
                file=sys.stderr,
            )
            return 1

        forbidden_entries = [
            n
            for n in names
            if n.lower().endswith(".pdb")
            or n.lower().endswith(".resw")
            or (
                Path(n.replace("\\", "/")).name.lower().startswith("resources.")
                and n.lower().endswith(".pri")
                and n.lower() != "resources.pri"
            )
        ]
        if forbidden_entries:
            print(f"error: forbidden staging artifacts packed in MSIX: {forbidden_entries}", file=sys.stderr)
            return 1

        # Verify AppxManifest Identity attributes.
        manifest_root = ET.fromstring(zf.read("AppxManifest.xml"))
        appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
        ident = manifest_root.find(f"{appx_ns}Identity")
        if ident is None:
            print("error: AppxManifest.xml missing <Identity>", file=sys.stderr)
            return 1
        if ident.attrib.get("ProcessorArchitecture") != args.arch:
            print(
                f"error: AppxManifest arch mismatch: {ident.attrib.get('ProcessorArchitecture')!r} != {args.arch!r}",
                file=sys.stderr,
            )
            return 1
        if ident.attrib.get("Version") != args.expected_version:
            print(
                f"error: AppxManifest version mismatch: {ident.attrib.get('Version')!r} != {args.expected_version!r}",
                file=sys.stderr,
            )
            return 1

        with tempfile.TemporaryDirectory(prefix="totaldrop-msix-verify-") as tmp:
            tmp_dir = Path(tmp)
            zf.extract("totaldrop_windows_ffi.dll", tmp_dir)
            zf.extract("totaldrop-winui.exe", tmp_dir)

            ffi_path = tmp_dir / "totaldrop_windows_ffi.dll"
            exe_path = tmp_dir / "totaldrop-winui.exe"

            ffi_pe = parse_pe64(ffi_path)
            exe_pe = parse_pe64(exe_path)

            for label, pe in (("totaldrop_windows_ffi.dll", ffi_pe), ("totaldrop-winui.exe", exe_pe)):
                if pe["machine"] != expected_machine:
                    raise ValueError(
                        f"{label}: expected machine {expected_machine:#x}, got {pe['machine']:#x}"
                    )
                dc = int(pe["dll_chars"])  # type: ignore[arg-type]
                for flag_name, flag_bit in (
                    ("HIGH_ENTROPY_VA", IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
                    ("DYNAMIC_BASE", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
                    ("NX_COMPAT", IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
                ):
                    if (dc & flag_bit) == 0:
                        raise ValueError(f"{label}: missing PE hardening flag {flag_name} (DllCharacteristics={dc:#x})")
                if args.arch == "x64":
                    ex_dc = int(pe["ex_dll_chars"])  # type: ignore[arg-type]
                    if (ex_dc & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT) == 0:
                        raise ValueError(
                            f"{label}: missing CET_COMPAT in Debug Directory Type=20 (ex_dll_chars={ex_dc:#x})"
                        )

            # Verify /DEPENDENTLOADFLAG:0x800 on totaldrop_windows_ffi.dll.
            dep_flags = ffi_pe["dependent_load_flags"]
            if not isinstance(dep_flags, int) or (dep_flags & LOAD_LIBRARY_SEARCH_SYSTEM32) == 0:
                raise ValueError(
                    f"totaldrop_windows_ffi.dll: missing DependentLoadFlags 0x800 (got {dep_flags!r})"
                )

            # Verify +crt-static: zero VCRUNTIME140 / MSVCP140 imports.
            all_imports = set(ffi_pe["imports"]) | set(ffi_pe["delay_imports"])  # type: ignore[arg-type]
            bad_crt = sorted(
                imp for imp in all_imports if any(imp.startswith(f.replace(".dll", "")) for f in FORBIDDEN_CRT_DLLS)
            )
            if bad_crt:
                raise ValueError(
                    f"totaldrop_windows_ffi.dll links dynamic MSVC CRT DLL(s): {bad_crt}"
                )

            # Verify all 6 Phase 1 C ABI exports exist.
            exports = set(ffi_pe["exports"])  # type: ignore[arg-type]
            missing_exports = [sym for sym in REQUIRED_FFI_EXPORTS if sym not in exports]
            if missing_exports:
                raise ValueError(
                    f"totaldrop_windows_ffi.dll missing C ABI exports: {missing_exports}"
                )

            # Verify totaldrop-winui.exe is genuinely Native AOT (zero CLR runtime header).
            if exe_pe["clr_header"] != (0, 0):
                raise ValueError(
                    f"totaldrop-winui.exe has non-zero CLR header {exe_pe['clr_header']} (not Native AOT)"
                )

            # Live ctypes C ABI smoke test when running natively on Windows.
            if sys.platform == "win32":
                smoke_test_ffi_dll(ffi_path)

    if args.pri_dump is not None:
        verify_pri_dump(args.pri_dump)

    print(
        f"msix-artifact verify OK: {msix_path.name} ({msix_path.stat().st_size} bytes, "
        f"arch={args.arch}, version={args.expected_version}, 46 canonical Assets, "
        f"PE hardening + CET_COMPAT + DependentLoadFlags=0x800 + zero VCRUNTIME140 + "
        f"6 C ABI exports + Native AOT verified)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
