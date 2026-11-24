#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Pure-Python stdlib PE32+ hardening, static CRT, AOT purity, export & icon oracle.

Implements TEST_INFRA.md section 5.1 for T1-F02-04, T1-F02-05, T1-F05-04,
T1-F16-01, T1-F22-01, T2-F02-04, T2-F05-03, T2-F22-03, T2-F22-06, T3-14,
T3-23, and T4-06, plus --unit-test-synthetic so the parser and negative-mutation
checks can be self-verified on Linux devbox for both x64 and arm64.
"""

from __future__ import annotations

import argparse
import shutil
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_ARM64 = 0xAA64
IMAGE_FILE_DLL = 0x2000
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B

IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100

IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20
IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT = 0x0001
LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x0800

RT_ICON = 3
RT_GROUP_ICON = 14

M1_FFI_EXPORTS: tuple[str, ...] = (
    "totaldrop_win_string_free",
    "totaldrop_win_version_json",
    "totaldrop_win_validate_uri_json",
    "totaldrop_win_validate_input_json",
    "totaldrop_win_format_percent_json",
    "totaldrop_win_ui_bundle_json",
)

M2_EXTRA_FFI_EXPORTS: tuple[str, ...] = (
    "totaldrop_win_extract_clipboard_code_json",
    "totaldrop_win_code_completions_json",
    "totaldrop_win_format_bytes_json",
    "totaldrop_win_format_message_json",
    "totaldrop_win_sanitize_filename_json",
    "totaldrop_win_sanitize_text_json",
    "totaldrop_win_validate_server_url_json",
    "totaldrop_win_validate_paths_json",
    "totaldrop_win_send_files_start",
    "totaldrop_win_send_text_start",
    "totaldrop_win_receive_connect_start",
    "totaldrop_win_receive_accept_files",
    "totaldrop_win_receive_accept_text",
    "totaldrop_win_receive_decline",
    "totaldrop_win_session_poll_events_ndjson",
    "totaldrop_win_session_cancel",
    "totaldrop_win_session_destroy",
    "totaldrop_win_shutdown",
)

M3_EXTRA_FFI_EXPORTS: tuple[str, ...] = (
    "totaldrop_win_router_create",
    "totaldrop_win_router_ingest_ipc_bytes_json",
    "totaldrop_win_router_update_locale_json",
    "totaldrop_win_router_set_animations_json",
    "totaldrop_win_router_set_activity_json",
    "totaldrop_win_router_drain_ndjson",
    "totaldrop_win_router_destroy",
)

EXPLORER_EXT_EXPORTS: tuple[str, ...] = (
    "DllGetClassObject",
    "DllCanUnloadNow",
)

EXPLORER_ICON_RESOURCE_ID = 101

FORBIDDEN_CRT_PREFIXES: tuple[str, ...] = (
    "vcruntime140",
    "msvcp140",
    "concrt140",
    "vcomp140",
    "ucrtbased",
)

FORBIDDEN_CLR_IMPORTS: tuple[str, ...] = (
    "hostfxr.dll",
    "coreclr.dll",
    "clrjit.dll",
    "mscoree.dll",
)


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def parse_pe32_plus(path: Path) -> dict[str, Any]:
    """Parse PE32+ headers, hardening flags, CRT/CLR imports, exports, and resources."""
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{path.name}: missing DOS MZ header")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError(f"{path.name}: missing PE\\0\\0 signature")

    coff_off = e_lfanew + 4
    machine, num_sections, _, _, _, opt_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff_off
    )
    opt_off = coff_off + 20
    if opt_off + 2 > len(data):
        raise ValueError(f"{path.name}: truncated Optional Header")
    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        raise ValueError(f"{path.name}: expected PE32+ magic 0x020B, got {magic:#x}")
    if opt_size < 112 or opt_off + opt_size > len(data):
        raise ValueError(f"{path.name}: truncated PE32+ Optional Header")

    section_alignment = struct.unpack_from("<I", data, opt_off + 32)[0]
    file_alignment = struct.unpack_from("<I", data, opt_off + 36)[0]
    size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
    dll_chars_off = opt_off + 70
    dll_chars = struct.unpack_from("<H", data, dll_chars_off)[0]
    num_rvas = struct.unpack_from("<I", data, opt_off + 108)[0]
    data_dirs_off = opt_off + 112

    def data_dir(index: int) -> tuple[int, int]:
        off = data_dirs_off + index * 8
        if index >= num_rvas or off + 8 > opt_off + opt_size or off + 8 > len(data):
            return (0, 0)
        return struct.unpack_from("<II", data, off)

    sections: list[tuple[int, int, int, int]] = []
    sections_meta: list[dict[str, int]] = []
    sec_off = opt_off + opt_size
    if sec_off + num_sections * 40 > len(data):
        raise ValueError(f"{path.name}: truncated section table")
    for i in range(num_sections):
        eoff = sec_off + i * 40
        _, v_size, v_addr, raw_size, raw_ptr, _, _, _, _, _ = struct.unpack_from(
            "<8sIIIIIIHHI", data, eoff
        )
        sections.append((v_addr, max(v_size, raw_size), raw_ptr, raw_size))
        sections_meta.append(
            {
                "hdr_off": eoff,
                "v_size": v_size,
                "v_addr": v_addr,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
            }
        )

    def rva_to_off(rva: int) -> int | None:
        if rva == 0:
            return None
        for v_addr, span, raw_ptr, raw_size in sections:
            if v_addr <= rva < v_addr + span:
                delta = rva - v_addr
                if delta < raw_size and raw_ptr + delta < len(data):
                    return raw_ptr + delta
        return None

    def read_cstr(off: int | None) -> tuple[str, int | None]:
        if off is None or off >= len(data):
            return ("", None)
        end = data.find(b"\x00", off)
        if end == -1:
            return ("", None)
        return (data[off:end].decode("ascii", errors="replace"), off)

    # Debug Directory (DataDirectory[6]) -> CET_COMPAT (Type 20)
    ex_dll_chars = 0
    ex_dll_chars_off: int | None = None
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
                    ex_dll_chars = struct.unpack_from("<I", data, val_off)[0]
                    ex_dll_chars_off = val_off

    # Load Config Directory (DataDirectory[10]) -> DependentLoadFlags @ +0x4E.
    # Windows PE loader ignores LoadConfig unless DataDirectory[10].Size > 0.
    dependent_load_flags: int | None = None
    dependent_load_flags_off: int | None = None
    lc_rva, lc_size = data_dir(10)
    lc_off = rva_to_off(lc_rva) if lc_size > 0 else None
    if lc_off is not None and lc_off + 4 <= len(data):
        lc_struct_size = struct.unpack_from("<I", data, lc_off)[0]
        if lc_struct_size >= 0x50 and lc_off + 0x50 <= len(data):
            dependent_load_flags = struct.unpack_from("<H", data, lc_off + 0x4E)[0]
            dependent_load_flags_off = lc_off + 0x4E

    # Import Directory (DataDirectory[1])
    imports: list[str] = []
    import_name_offsets: list[tuple[str, int]] = []
    import_name_rva_offsets: list[int] = []
    imp_rva, _ = data_dir(1)
    imp_off = rva_to_off(imp_rva)
    if imp_off is not None:
        pos = imp_off
        while pos + 20 <= len(data):
            oft, ts, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, pos)
            if (oft, ts, fwd, name_rva, ft) == (0, 0, 0, 0, 0):
                break
            dll_name, noff = read_cstr(rva_to_off(name_rva))
            if dll_name:
                imports.append(dll_name.lower())
                if noff is not None:
                    import_name_offsets.append((dll_name.lower(), noff))
                import_name_rva_offsets.append(pos + 12)
            pos += 20

    # Delay-Import Directory (DataDirectory[13])
    delay_imports: list[str] = []
    dimp_rva, _ = data_dir(13)
    dimp_off = rva_to_off(dimp_rva)
    if dimp_off is not None:
        pos = dimp_off
        while pos + 32 <= len(data):
            attrs, dll_name_rva, _, _, _, _, _, _ = struct.unpack_from("<IIIIIIII", data, pos)
            if attrs == 0 and dll_name_rva == 0:
                break
            dll_name, _ = read_cstr(rva_to_off(dll_name_rva))
            if dll_name:
                delay_imports.append(dll_name.lower())
            pos += 32

    # Export Directory (DataDirectory[0])
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
                sym, _ = read_cstr(rva_to_off(sym_rva))
                if sym:
                    exports.append(sym)

    # Resource Directory (DataDirectory[2]) -> 3-level walk collecting type ID -> data entries & level-1 IDs
    resources: dict[int, list[tuple[int, int]]] = {}
    resource_ids: dict[int, set[int]] = {}
    rsrc_rva, rsrc_size = data_dir(2)
    rsrc_base = rva_to_off(rsrc_rva)
    if rsrc_base is not None and rsrc_size >= 16:
        def _walk_rsrc(dir_rel: int, depth: int, type_id: int | None, res_id: int | None) -> None:
            dir_off = rsrc_base + dir_rel
            if dir_off + 16 > len(data):
                return
            _, _, _, _, num_named, num_id = struct.unpack_from("<IIHHHH", data, dir_off)
            total = num_named + num_id
            for idx in range(total):
                eoff = dir_off + 16 + idx * 8
                if eoff + 8 > len(data):
                    break
                name_or_id, offset_to_data = struct.unpack_from("<II", data, eoff)
                is_subdir = (offset_to_data & 0x8000_0000) != 0
                rel = offset_to_data & 0x7FFF_FFFF
                cur_type = type_id
                cur_res = res_id
                if depth == 0 and (name_or_id & 0x8000_0000) == 0:
                    cur_type = name_or_id
                elif depth == 1 and (name_or_id & 0x8000_0000) == 0:
                    cur_res = name_or_id
                if is_subdir and depth < 2:
                    _walk_rsrc(rel, depth + 1, cur_type, cur_res)
                elif not is_subdir and cur_type is not None:
                    leaf_off = rsrc_base + rel
                    if leaf_off + 16 <= len(data):
                        leaf_rva, leaf_size, _, _ = struct.unpack_from("<IIII", data, leaf_off)
                        if leaf_size > 0:
                            resources.setdefault(cur_type, []).append((leaf_rva, leaf_size))
                            if cur_res is not None:
                                resource_ids.setdefault(cur_type, set()).add(cur_res)

        _walk_rsrc(0, 0, None, None)

    clr_rva, clr_size = data_dir(14)

    return {
        "name": path.name,
        "machine": machine,
        "characteristics": characteristics,
        "is_dll": (characteristics & IMAGE_FILE_DLL) != 0,
        "dll_chars": dll_chars,
        "dll_chars_off": dll_chars_off,
        "ex_dll_chars": ex_dll_chars,
        "ex_dll_chars_off": ex_dll_chars_off,
        "dependent_load_flags": dependent_load_flags,
        "dependent_load_flags_off": dependent_load_flags_off,
        "imports": imports,
        "import_name_offsets": import_name_offsets,
        "import_name_rva_offsets": import_name_rva_offsets,
        "delay_imports": delay_imports,
        "exports": exports,
        "resources": resources,
        "resource_ids": resource_ids,
        "clr_header": (clr_rva, clr_size),
        "opt_off": opt_off,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "size_of_image": size_of_image,
        "sections_meta": sections_meta,
    }


def _check_common_hardening(pe: dict[str, Any], arch: str, expect_dll: bool, require_load_config: bool) -> None:
    label = pe["name"]
    expected_machine = IMAGE_FILE_MACHINE_AMD64 if arch == "x64" else IMAGE_FILE_MACHINE_ARM64
    if pe["machine"] != expected_machine:
        raise ValueError(f"{label}: Machine mismatch expected {expected_machine:#06x}, got {pe['machine']:#06x}")
    if pe["is_dll"] != expect_dll:
        raise ValueError(f"{label}: IMAGE_FILE_DLL expected {expect_dll}, got {pe['is_dll']}")

    dll_chars = pe["dll_chars"]
    for bit, flag_name in (
        (IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, "HIGHENTROPYVA"),
        (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "DYNAMICBASE"),
        (IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "NXCOMPAT"),
    ):
        if (dll_chars & bit) == 0:
            raise ValueError(f"{label}: missing DllCharacteristics flag {flag_name}")

    if arch == "x64" and (pe["ex_dll_chars"] & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT) == 0:
        raise ValueError(f"{label}: missing x64 Debug Directory CETCOMPAT (0x0001)")

    if require_load_config:
        dlf = pe["dependent_load_flags"]
        if dlf is None or (dlf & LOAD_LIBRARY_SEARCH_SYSTEM32) != LOAD_LIBRARY_SEARCH_SYSTEM32:
            raise ValueError(f"{label}: missing LoadConfig DependentLoadFlags=0x800 (got {dlf})")

    all_imports = set(pe["imports"]) | set(pe["delay_imports"])
    bad_crt = sorted(
        imp
        for imp in all_imports
        if any(imp.startswith(prefix) for prefix in FORBIDDEN_CRT_PREFIXES)
    )
    if bad_crt:
        raise ValueError(f"{label}: forbidden dynamic/debug CRT import(s) found: {bad_crt}")


def verify_unpacked_dir(unpacked: Path, arch: str, milestone: str) -> dict[str, Any]:
    exe_path = unpacked / "totaldrop-winui.exe"
    ffi_path = unpacked / "totaldrop_windows_ffi.dll"
    if not exe_path.is_file():
        raise ValueError(f"missing executable: {exe_path}")
    if not ffi_path.is_file():
        raise ValueError(f"missing native FFI DLL: {ffi_path}")

    # Native AOT purity: reject managed apphost sidecars
    for forbidden_sidecar in (
        "totaldrop-winui.dll",
        "totaldrop-winui.deps.json",
        "totaldrop-winui.runtimeconfig.json",
    ):
        if (unpacked / forbidden_sidecar).exists():
            raise ValueError(f"forbidden managed apphost artifact present: {forbidden_sidecar}")

    exe_pe = parse_pe32_plus(exe_path)
    ffi_pe = parse_pe32_plus(ffi_path)

    _check_common_hardening(exe_pe, arch=arch, expect_dll=False, require_load_config=False)
    _check_common_hardening(ffi_pe, arch=arch, expect_dll=True, require_load_config=True)

    # Native AOT purity on exe: zero CLR header and zero CLR/JIT DLL imports
    if exe_pe["clr_header"] != (0, 0):
        raise ValueError(f"totaldrop-winui.exe: non-zero CLR header {exe_pe['clr_header']}")
    exe_imports = set(exe_pe["imports"]) | set(exe_pe["delay_imports"])
    bad_clr = sorted(d for d in FORBIDDEN_CLR_IMPORTS if d in exe_imports)
    if bad_clr:
        raise ValueError(f"totaldrop-winui.exe: forbidden CLR/JIT import(s): {bad_clr}")

    # Embedded Win32 icon resource (T1-F02-05)
    if RT_GROUP_ICON not in exe_pe["resources"] or not exe_pe["resources"][RT_GROUP_ICON]:
        raise ValueError("totaldrop-winui.exe: missing RT_GROUP_ICON (14) resource")
    if RT_ICON not in exe_pe["resources"] or not exe_pe["resources"][RT_ICON]:
        raise ValueError("totaldrop-winui.exe: missing RT_ICON (3) resource")

    # Export verification by milestone
    required_exports = list(M1_FFI_EXPORTS)
    if milestone in ("M2", "M3", "M4"):
        required_exports.extend(M2_EXTRA_FFI_EXPORTS)
    if milestone in ("M3", "M4"):
        required_exports.extend(M3_EXTRA_FFI_EXPORTS)
    actual_exports = set(ffi_pe["exports"])
    missing_exports = [sym for sym in required_exports if sym not in actual_exports]
    if missing_exports:
        raise ValueError(
            f"totaldrop_windows_ffi.dll ({milestone}): missing required C ABI export(s): {missing_exports}"
        )

    result: dict[str, Any] = {"exe": exe_pe, "ffi": ffi_pe}

    if milestone in ("M3", "M4"):
        ext_path = unpacked / "totaldrop_explorer_ext.dll"
        if not ext_path.is_file():
            raise ValueError(f"missing Explorer COM shell extension DLL ({milestone}): {ext_path}")
        ext_pe = parse_pe32_plus(ext_path)
        _check_common_hardening(ext_pe, arch=arch, expect_dll=True, require_load_config=True)
        ext_exports = set(ext_pe["exports"])
        missing_ext_exports = [sym for sym in EXPLORER_EXT_EXPORTS if sym not in ext_exports]
        if missing_ext_exports:
            raise ValueError(
                f"totaldrop_explorer_ext.dll ({milestone}): missing required COM export(s): {missing_ext_exports}"
            )
        if RT_GROUP_ICON not in ext_pe["resources"] or not ext_pe["resources"][RT_GROUP_ICON]:
            raise ValueError("totaldrop_explorer_ext.dll: missing RT_GROUP_ICON (14) resource")
        if EXPLORER_ICON_RESOURCE_ID not in ext_pe["resource_ids"].get(RT_GROUP_ICON, set()):
            raise ValueError(
                f"totaldrop_explorer_ext.dll: missing RT_GROUP_ICON integer resource ID {EXPLORER_ICON_RESOURCE_ID} "
                f"(found={sorted(ext_pe['resource_ids'].get(RT_GROUP_ICON, set()))})"
            )
        if RT_ICON not in ext_pe["resources"] or not ext_pe["resources"][RT_ICON]:
            raise ValueError("totaldrop_explorer_ext.dll: missing RT_ICON (3) resource")
        result["explorer_ext"] = ext_pe

    return result


def _patch_import_name(pe_path: Path, new_dll_name: str) -> None:
    pe = parse_pe32_plus(pe_path)
    raw = bytearray(pe_path.read_bytes())
    target_bytes = new_dll_name.encode("ascii") + b"\x00"
    for existing, off in pe["import_name_offsets"]:
        avail = len(existing) + 1
        if avail >= len(target_bytes):
            raw[off : off + len(target_bytes)] = target_bytes
            pe_path.write_bytes(bytes(raw))
            return

    rva_offsets: list[int] = pe["import_name_rva_offsets"]
    sections_meta: list[dict[str, int]] = pe["sections_meta"]
    if not rva_offsets or not sections_meta:
        raise ValueError(f"{pe_path.name}: no import descriptor available to patch {new_dll_name!r}")

    # Append the new ASCII DLL name into the tail of the last file-backed section
    # and repoint the first IMAGE_IMPORT_DESCRIPTOR.Name RVA to it so short-import
    # binaries (e.g. KERNEL32.dll / ole32.dll / ntdll.dll) mutate cleanly.
    last_sec = max(sections_meta, key=lambda s: s["raw_ptr"] + s["raw_size"])
    file_align = pe["file_alignment"] or 0x200
    sec_align = pe["section_alignment"] or 0x1000
    append_delta = max(last_sec["v_size"], last_sec["raw_size"], max(0, len(raw) - last_sec["raw_ptr"]))
    write_off = last_sec["raw_ptr"] + append_delta
    if len(raw) < write_off:
        raw.extend(b"\x00" * (write_off - len(raw)))
    raw.extend(target_bytes)

    new_v_size = append_delta + len(target_bytes)
    new_raw_size = _align_up(new_v_size, file_align)
    target_file_end = last_sec["raw_ptr"] + new_raw_size
    if len(raw) < target_file_end:
        raw.extend(b"\x00" * (target_file_end - len(raw)))

    new_name_rva = last_sec["v_addr"] + append_delta
    struct.pack_into("<I", raw, last_sec["hdr_off"] + 8, new_v_size)
    struct.pack_into("<I", raw, last_sec["hdr_off"] + 16, new_raw_size)
    new_size_of_image = max(
        pe["size_of_image"],
        _align_up(last_sec["v_addr"] + new_v_size, sec_align),
    )
    struct.pack_into("<I", raw, pe["opt_off"] + 56, new_size_of_image)
    struct.pack_into("<I", raw, rva_offsets[0], new_name_rva)
    pe_path.write_bytes(bytes(raw))


def run_self_test_mutations(unpacked: Path, arch: str, milestone: str) -> None:
    """Execute T2-F02-04 (3 CLR/apphost mutations) and T2-F05-03 (4 PE32+ mutations) on temp copies."""
    # Baseline must pass first
    verify_unpacked_dir(unpacked, arch=arch, milestone=milestone)

    def expect_fail(mutated_dir: Path, label: str, required_token: str) -> None:
        try:
            verify_unpacked_dir(mutated_dir, arch=arch, milestone=milestone)
        except ValueError as exc:
            msg = str(exc)
            if required_token.lower() not in msg.lower():
                raise AssertionError(
                    f"mutation {label} failed with unexpected error (expected {required_token!r}): {msg}"
                ) from exc
            return
        raise AssertionError(f"mutation {label} unexpectedly PASSED verification!")

    with tempfile.TemporaryDirectory(prefix="td-pe-mut-") as tmp:
        root = Path(tmp)

        # T2-F02-04 (a): patch exe import to hostfxr.dll / coreclr.dll / clrjit.dll
        for clr_dll in ("hostfxr.dll", "coreclr.dll", "clrjit.dll"):
            d = root / f"clr-{clr_dll}"
            shutil.copytree(unpacked, d)
            _patch_import_name(d / "totaldrop-winui.exe", clr_dll)
            expect_fail(d, f"T2-F02-04a({clr_dll})", clr_dll)

        # T2-F02-04 (b): add managed totaldrop-winui.dll sidecar
        d_dll = root / "sidecar-dll"
        shutil.copytree(unpacked, d_dll)
        (d_dll / "totaldrop-winui.dll").write_bytes(b"managed-il-stub")
        expect_fail(d_dll, "T2-F02-04b(managed-dll)", "totaldrop-winui.dll")

        # T2-F02-04 (c): add .deps.json & .runtimeconfig.json
        for sidecar in ("totaldrop-winui.deps.json", "totaldrop-winui.runtimeconfig.json"):
            d_sc = root / f"sidecar-{sidecar}"
            shutil.copytree(unpacked, d_sc)
            (d_sc / sidecar).write_text("{}", encoding="utf-8")
            expect_fail(d_sc, f"T2-F02-04c({sidecar})", sidecar)

        # T2-F05-03 / T2-F22-06: mutate every Rust cdylib DLL present for this milestone
        cdylib_names = ["totaldrop_windows_ffi.dll"]
        if milestone in ("M3", "M4"):
            cdylib_names.append("totaldrop_explorer_ext.dll")

        for dll_name in cdylib_names:
            # (a): patch DLL import to VCRUNTIME140.dll and ucrtbased.dll
            for bad_crt in ("VCRUNTIME140.dll", "ucrtbased.dll"):
                d_crt = root / f"crt-{dll_name}-{bad_crt}"
                shutil.copytree(unpacked, d_crt)
                _patch_import_name(d_crt / dll_name, bad_crt)
                expect_fail(d_crt, f"T2-F05-03a/{dll_name}({bad_crt})", bad_crt.lower())

            # (b): clear CET_COMPAT in Debug Directory Type 20 (x64)
            if arch == "x64":
                d_cet = root / f"no-cet-{dll_name}"
                shutil.copytree(unpacked, d_cet)
                dll = d_cet / dll_name
                pe = parse_pe32_plus(dll)
                cet_off = pe["ex_dll_chars_off"]
                assert cet_off is not None
                raw = bytearray(dll.read_bytes())
                val = struct.unpack_from("<I", raw, cet_off)[0] & ~IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
                struct.pack_into("<I", raw, cet_off, val)
                dll.write_bytes(bytes(raw))
                expect_fail(d_cet, f"T2-F05-03b/{dll_name}(CETCOMPAT)", "CETCOMPAT")

            # (c): clear DependentLoadFlags 0x0800 in LoadConfig
            d_dlf = root / f"no-dlf-{dll_name}"
            shutil.copytree(unpacked, d_dlf)
            dll = d_dlf / dll_name
            pe = parse_pe32_plus(dll)
            dlf_off = pe["dependent_load_flags_off"]
            assert dlf_off is not None
            raw = bytearray(dll.read_bytes())
            val = struct.unpack_from("<H", raw, dlf_off)[0] & ~LOAD_LIBRARY_SEARCH_SYSTEM32
            struct.pack_into("<H", raw, dlf_off, val)
            dll.write_bytes(bytes(raw))
            expect_fail(d_dlf, f"T2-F05-03c/{dll_name}(DependentLoadFlags)", "DependentLoadFlags")

            # (d): clear NXCOMPAT & HIGHENTROPYVA in DllCharacteristics
            d_nx = root / f"no-nx-heva-{dll_name}"
            shutil.copytree(unpacked, d_nx)
            dll = d_nx / dll_name
            pe = parse_pe32_plus(dll)
            dc_off = pe["dll_chars_off"]
            raw = bytearray(dll.read_bytes())
            val = struct.unpack_from("<H", raw, dc_off)[0] & ~(
                IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            )
            struct.pack_into("<H", raw, dc_off, val)
            dll.write_bytes(bytes(raw))
            expect_fail(d_nx, f"T2-F05-03d/{dll_name}(NXCOMPAT/HIGHENTROPYVA)", "HIGHENTROPYVA")


def _build_synthetic_pe32_plus(
    *,
    machine: int,
    is_dll: bool,
    imports: list[str],
    exports: list[str],
    include_icons: bool,
    include_load_config: bool,
    include_cet: bool,
    icon_group_id: int = EXPLORER_ICON_RESOURCE_ID,
) -> bytes:
    """Build a genuine minimal PE32+ binary for parser self-testing on Linux."""
    sec_rva = 0x1000
    sec_raw = 0x0400
    rdata = bytearray()

    def alloc(size: int, align: int = 4) -> int:
        rem = len(rdata) % align
        if rem:
            rdata.extend(b"\x00" * (align - rem))
        rel = len(rdata)
        rdata.extend(b"\x00" * size)
        return rel

    def write_cstr(text: str) -> int:
        b = text.encode("ascii") + b"\x00"
        rel = alloc(len(b), 1)
        rdata[rel : rel + len(b)] = b
        return sec_rva + rel

    # 1. Export Directory
    exp_rva, exp_size = 0, 0
    if exports:
        name_rvas = [write_cstr(sym) for sym in exports]
        names_tbl_rel = alloc(4 * len(exports), 4)
        for idx, nrva in enumerate(name_rvas):
            struct.pack_into("<I", rdata, names_tbl_rel + idx * 4, nrva)
        exp_rel = alloc(40, 4)
        struct.pack_into("<I", rdata, exp_rel + 24, len(exports))
        struct.pack_into("<I", rdata, exp_rel + 32, sec_rva + names_tbl_rel)
        exp_rva = sec_rva + exp_rel
        exp_size = 40

    # 2. Import Directory
    imp_rva, imp_size = 0, 0
    if imports:
        dll_rvas = [write_cstr(d) for d in imports]
        imp_rel = alloc(20 * (len(imports) + 1), 4)
        for idx, drva in enumerate(dll_rvas):
            struct.pack_into("<IIIII", rdata, imp_rel + idx * 20, 0, 0, 0, drva, 0)
        imp_rva = sec_rva + imp_rel
        imp_size = 20 * (len(imports) + 1)

    # 3. Resource Directory (3 levels: Type -> ID 1 -> Lang 1033 -> DataEntry)
    rsrc_rva, rsrc_size = 0, 0
    if include_icons:
        rsrc_start = alloc(0, 4)
        # Level 0 dir: 16 header + 2 entries (RT_ICON=3, RT_GROUP_ICON=14) = 32 bytes
        l0 = alloc(16 + 2 * 8, 4) - rsrc_start
        # Level 1 dirs (1 entry each): 24 bytes each
        l1_icon = alloc(16 + 8, 4) - rsrc_start
        l1_grp = alloc(16 + 8, 4) - rsrc_start
        # Level 2 dirs (1 entry each): 24 bytes each
        l2_icon = alloc(16 + 8, 4) - rsrc_start
        l2_grp = alloc(16 + 8, 4) - rsrc_start
        # Leaf DataEntries (16 bytes each)
        leaf_icon = alloc(16, 4) - rsrc_start
        leaf_grp = alloc(16, 4) - rsrc_start
        # Dummy icon payload bytes
        pay_icon_rel = alloc(16, 4)
        pay_grp_rel = alloc(16, 4)
        rdata[pay_icon_rel : pay_icon_rel + 4] = b"\x89PNG"
        rdata[pay_grp_rel : pay_grp_rel + 6] = struct.pack("<HHH", 0, 1, 1)

        struct.pack_into("<IIHHHH", rdata, rsrc_start + l0, 0, 0, 0, 0, 0, 2)
        struct.pack_into("<II", rdata, rsrc_start + l0 + 16, RT_ICON, 0x8000_0000 | l1_icon)
        struct.pack_into("<II", rdata, rsrc_start + l0 + 24, RT_GROUP_ICON, 0x8000_0000 | l1_grp)

        for l1, l2, leaf, pay_rel, rid in (
            (l1_icon, l2_icon, leaf_icon, pay_icon_rel, 1),
            (l1_grp, l2_grp, leaf_grp, pay_grp_rel, icon_group_id),
        ):
            struct.pack_into("<IIHHHH", rdata, rsrc_start + l1, 0, 0, 0, 0, 0, 1)
            struct.pack_into("<II", rdata, rsrc_start + l1 + 16, rid, 0x8000_0000 | l2)
            struct.pack_into("<IIHHHH", rdata, rsrc_start + l2, 0, 0, 0, 0, 0, 1)
            struct.pack_into("<II", rdata, rsrc_start + l2 + 16, 0x0409, leaf)
            struct.pack_into("<IIII", rdata, rsrc_start + leaf, sec_rva + pay_rel, 16, 0, 0)

        rsrc_rva = sec_rva + rsrc_start
        rsrc_size = len(rdata) - rsrc_start

    # 4. Debug Directory (Type 20 CET_COMPAT)
    dbg_rva, dbg_size = 0, 0
    if include_cet:
        val_rel = alloc(4, 4)
        struct.pack_into("<I", rdata, val_rel, IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT)
        dbg_rel = alloc(28, 4)
        struct.pack_into(
            "<IIHHIIII",
            rdata,
            dbg_rel,
            0,
            0,
            0,
            0,
            IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
            4,
            sec_rva + val_rel,
            sec_raw + val_rel,
        )
        dbg_rva = sec_rva + dbg_rel
        dbg_size = 28

    # 5. Load Config Directory (Size 0x60, DependentLoadFlags = 0x0800 @ +0x4E)
    lc_rva, lc_size = 0, 0
    if include_load_config:
        lc_rel = alloc(0x60, 8)
        struct.pack_into("<I", rdata, lc_rel, 0x60)
        struct.pack_into("<H", rdata, lc_rel + 0x4E, LOAD_LIBRARY_SEARCH_SYSTEM32)
        lc_rva = sec_rva + lc_rel
        lc_size = 0x60

    # Assemble DOS + PE32+ headers into first 0x400 bytes
    headers = bytearray(sec_raw)
    headers[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", headers, 0x3C, e_lfanew)
    headers[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"

    opt_size = 240  # 112 + 16*8
    chars = 0x0022 | (IMAGE_FILE_DLL if is_dll else 0)
    struct.pack_into("<HHIIIHH", headers, e_lfanew + 4, machine, 1, 0, 0, 0, opt_size, chars)

    opt_off = e_lfanew + 24
    struct.pack_into("<H", headers, opt_off, IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    dll_chars = (
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    )
    struct.pack_into("<H", headers, opt_off + 70, dll_chars)
    struct.pack_into("<I", headers, opt_off + 108, 16)

    dirs = {
        0: (exp_rva, exp_size),
        1: (imp_rva, imp_size),
        2: (rsrc_rva, rsrc_size),
        6: (dbg_rva, dbg_size),
        10: (lc_rva, lc_size),
    }
    for idx, (rva, sz) in dirs.items():
        struct.pack_into("<II", headers, opt_off + 112 + idx * 8, rva, sz)

    sec_off = opt_off + opt_size
    raw_padded = ((len(rdata) + 0x1FF) // 0x200) * 0x200
    rdata.extend(b"\x00" * (raw_padded - len(rdata)))
    struct.pack_into(
        "<8sIIIIIIHHI",
        headers,
        sec_off,
        b".rdata\x00\x00",
        len(rdata),
        sec_rva,
        len(rdata),
        sec_raw,
        0,
        0,
        0,
        0,
        0x4000_0040,
    )
    return bytes(headers) + bytes(rdata)


def run_synthetic_unit_tests() -> None:
    """Self-test the PE32+ parser and all M1-M4 positive/negative mutations without Windows binaries."""
    with tempfile.TemporaryDirectory(prefix="td-pe-synth-") as tmp:
        d = Path(tmp) / "x64-ok"
        d.mkdir()
        all_ffi_exports = list(M1_FFI_EXPORTS) + list(M2_EXTRA_FFI_EXPORTS) + list(M3_EXTRA_FFI_EXPORTS)
        assert len(all_ffi_exports) == 31
        (d / "totaldrop-winui.exe").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_AMD64,
                is_dll=False,
                imports=["kernel32_long_placeholder.dll", "user32.dll"],
                exports=[],
                include_icons=True,
                include_load_config=False,
                include_cet=True,
            )
        )
        (d / "totaldrop_windows_ffi.dll").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_AMD64,
                is_dll=True,
                imports=["kernel32_long_placeholder.dll", "bcrypt.dll"],
                exports=all_ffi_exports,
                include_icons=False,
                include_load_config=True,
                include_cet=True,
            )
        )
        (d / "totaldrop_explorer_ext.dll").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_AMD64,
                is_dll=True,
                imports=["kernel32_long_placeholder.dll", "ole32.dll"],
                exports=list(EXPLORER_EXT_EXPORTS),
                include_icons=True,
                include_load_config=True,
                include_cet=True,
                icon_group_id=EXPLORER_ICON_RESOURCE_ID,
            )
        )

        # Clean M1, M2, M3 & M4 checks + all T2-F02-04 & T2-F05-03 mutations across both DLLs
        for ms in ("M1", "M2", "M3", "M4"):
            verify_unpacked_dir(d, arch="x64", milestone=ms)
        run_self_test_mutations(d, arch="x64", milestone="M4")

        # Negative check: missing icon on exe
        d_no_icon = Path(tmp) / "no-icon"
        shutil.copytree(d, d_no_icon)
        (d_no_icon / "totaldrop-winui.exe").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_AMD64,
                is_dll=False,
                imports=["kernel32.dll"],
                exports=[],
                include_icons=False,
                include_load_config=False,
                include_cet=True,
            )
        )
        try:
            verify_unpacked_dir(d_no_icon, arch="x64", milestone="M4")
        except ValueError as exc:
            assert "RT_GROUP_ICON" in str(exc)
        else:
            raise AssertionError("missing icon on exe was not caught")

        # Negative check: explorer_ext with wrong RT_GROUP_ICON ID (1 != 101)
        d_wrong_icon = Path(tmp) / "ext-wrong-icon"
        shutil.copytree(d, d_wrong_icon)
        (d_wrong_icon / "totaldrop_explorer_ext.dll").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_AMD64,
                is_dll=True,
                imports=["kernel32_long_placeholder.dll"],
                exports=list(EXPLORER_EXT_EXPORTS),
                include_icons=True,
                include_load_config=True,
                include_cet=True,
                icon_group_id=1,
            )
        )
        try:
            verify_unpacked_dir(d_wrong_icon, arch="x64", milestone="M3")
        except ValueError as exc:
            assert "101" in str(exc)
        else:
            raise AssertionError("wrong RT_GROUP_ICON ID on explorer_ext was not caught")

        # Negative check: explorer_ext missing DllCanUnloadNow
        d_no_com = Path(tmp) / "ext-no-com"
        shutil.copytree(d, d_no_com)
        (d_no_com / "totaldrop_explorer_ext.dll").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_AMD64,
                is_dll=True,
                imports=["kernel32_long_placeholder.dll"],
                exports=["DllGetClassObject"],
                include_icons=True,
                include_load_config=True,
                include_cet=True,
                icon_group_id=EXPLORER_ICON_RESOURCE_ID,
            )
        )
        try:
            verify_unpacked_dir(d_no_com, arch="x64", milestone="M3")
        except ValueError as exc:
            assert "DllCanUnloadNow" in str(exc)
        else:
            raise AssertionError("missing DllCanUnloadNow on explorer_ext was not caught")

        # Negative check: missing M3 router export when checking M3/M4
        d_no_router = Path(tmp) / "ffi-no-router"
        shutil.copytree(d, d_no_router)
        (d_no_router / "totaldrop_windows_ffi.dll").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_AMD64,
                is_dll=True,
                imports=["kernel32_long_placeholder.dll"],
                exports=list(M1_FFI_EXPORTS) + list(M2_EXTRA_FFI_EXPORTS),
                include_icons=False,
                include_load_config=True,
                include_cet=True,
            )
        )
        verify_unpacked_dir(d_no_router, arch="x64", milestone="M2")
        try:
            verify_unpacked_dir(d_no_router, arch="x64", milestone="M3")
        except ValueError as exc:
            assert "totaldrop_win_router_create" in str(exc)
        else:
            raise AssertionError("missing M3 router exports were not caught")

        # Negative check: x86 machine mismatch
        d_x86 = Path(tmp) / "x86-bad"
        shutil.copytree(d, d_x86)
        (d_x86 / "totaldrop_windows_ffi.dll").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_I386,
                is_dll=True,
                imports=["kernel32.dll"],
                exports=all_ffi_exports,
                include_icons=False,
                include_load_config=True,
                include_cet=True,
            )
        )
        try:
            verify_unpacked_dir(d_x86, arch="x64", milestone="M4")
        except ValueError as exc:
            assert "0x014c" in str(exc).lower()
        else:
            raise AssertionError("x86 machine mismatch was not caught")

        # ARM64 clean check (M1-M4) + T2-F22-06 mutations across both ARM64 cdylibs
        d_arm = Path(tmp) / "arm64-ok"
        d_arm.mkdir()
        (d_arm / "totaldrop-winui.exe").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_ARM64,
                is_dll=False,
                imports=["kernel32_long_placeholder.dll"],
                exports=[],
                include_icons=True,
                include_load_config=False,
                include_cet=False,
            )
        )
        (d_arm / "totaldrop_windows_ffi.dll").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_ARM64,
                is_dll=True,
                imports=["kernel32_long_placeholder.dll"],
                exports=all_ffi_exports,
                include_icons=False,
                include_load_config=True,
                include_cet=False,
            )
        )
        (d_arm / "totaldrop_explorer_ext.dll").write_bytes(
            _build_synthetic_pe32_plus(
                machine=IMAGE_FILE_MACHINE_ARM64,
                is_dll=True,
                imports=["kernel32_long_placeholder.dll"],
                exports=list(EXPLORER_EXT_EXPORTS),
                include_icons=True,
                include_load_config=True,
                include_cet=False,
                icon_group_id=EXPLORER_ICON_RESOURCE_ID,
            )
        )
        for ms in ("M1", "M2", "M3", "M4"):
            verify_unpacked_dir(d_arm, arch="arm64", milestone=ms)
        run_self_test_mutations(d_arm, arch="arm64", milestone="M4")

        # T2-F22-03 cross-arch contamination: x64 explorer_ext inside arm64 unpacked dir
        d_arm_contam = Path(tmp) / "arm64-contam"
        shutil.copytree(d_arm, d_arm_contam)
        shutil.copy2(d / "totaldrop_explorer_ext.dll", d_arm_contam / "totaldrop_explorer_ext.dll")
        try:
            verify_unpacked_dir(d_arm_contam, arch="arm64", milestone="M4")
        except ValueError as exc:
            low = str(exc).lower()
            assert "0xaa64" in low and "0x8664" in low, f"unexpected error: {exc}"
        else:
            raise AssertionError("x64-in-arm64 cross-architecture contamination was not caught")

        # Tier-5 (C2-F1a): Realistic short-import x64 & ARM64 binaries (NO kernel32_long_placeholder.dll)
        # must pass verification AND run_self_test_mutations via append-to-last-section fallback.
        for arch_tag, machine_id, want_cet in (
            ("x64", IMAGE_FILE_MACHINE_AMD64, True),
            ("arm64", IMAGE_FILE_MACHINE_ARM64, False),
        ):
            d_short = Path(tmp) / f"short-imports-{arch_tag}"
            d_short.mkdir()
            (d_short / "totaldrop-winui.exe").write_bytes(
                _build_synthetic_pe32_plus(
                    machine=machine_id,
                    is_dll=False,
                    imports=["KERNEL32.dll", "user32.dll", "ntdll.dll"],
                    exports=[],
                    include_icons=True,
                    include_load_config=False,
                    include_cet=want_cet,
                )
            )
            (d_short / "totaldrop_windows_ffi.dll").write_bytes(
                _build_synthetic_pe32_plus(
                    machine=machine_id,
                    is_dll=True,
                    imports=["KERNEL32.dll", "bcrypt.dll", "WS2_32.dll", "ntdll.dll"],
                    exports=all_ffi_exports,
                    include_icons=False,
                    include_load_config=True,
                    include_cet=want_cet,
                )
            )
            (d_short / "totaldrop_explorer_ext.dll").write_bytes(
                _build_synthetic_pe32_plus(
                    machine=machine_id,
                    is_dll=True,
                    imports=["KERNEL32.dll", "ole32.dll", "ntdll.dll"],
                    exports=list(EXPLORER_EXT_EXPORTS),
                    include_icons=True,
                    include_load_config=True,
                    include_cet=want_cet,
                    icon_group_id=EXPLORER_ICON_RESOURCE_ID,
                )
            )
            verify_unpacked_dir(d_short, arch=arch_tag, milestone="M4")
            run_self_test_mutations(d_short, arch=arch_tag, milestone="M4")

        # Tier-5 (C2-F1b): DataDirectory[10].Size == 0 (LoadConfig disabled by PE loader) must fail.
        d_lc_zero = Path(tmp) / "lc-size-zero"
        shutil.copytree(d, d_lc_zero)
        ffi_lc_zero = d_lc_zero / "totaldrop_windows_ffi.dll"
        raw_lc = bytearray(ffi_lc_zero.read_bytes())
        e_lfanew = struct.unpack_from("<I", raw_lc, 0x3C)[0]
        lc_size_off = e_lfanew + 24 + 112 + 10 * 8 + 4
        struct.pack_into("<I", raw_lc, lc_size_off, 0)
        ffi_lc_zero.write_bytes(bytes(raw_lc))
        try:
            verify_unpacked_dir(d_lc_zero, arch="x64", milestone="M4")
        except ValueError as exc:
            assert "DependentLoadFlags" in str(exc), f"unexpected error: {exc}"
        else:
            raise AssertionError("DataDirectory[10].Size == 0 LoadConfig bypass was not caught")

        # Tier-5 (C2-F1c): Debug & auxiliary MSVC CRT stems caught by prefix matching.
        for aux_crt in (
            "msvcp140d.dll",
            "vcruntime140_1d.dll",
            "vcruntime140_threads.dll",
            "concrt140d.dll",
            "vcomp140d.dll",
        ):
            d_aux = Path(tmp) / f"aux-{aux_crt}"
            shutil.copytree(d, d_aux)
            (d_aux / "totaldrop_windows_ffi.dll").write_bytes(
                _build_synthetic_pe32_plus(
                    machine=IMAGE_FILE_MACHINE_AMD64,
                    is_dll=True,
                    imports=["KERNEL32.dll", aux_crt],
                    exports=all_ffi_exports,
                    include_icons=False,
                    include_load_config=True,
                    include_cet=True,
                )
            )
            try:
                verify_unpacked_dir(d_aux, arch="x64", milestone="M4")
            except ValueError as exc:
                assert aux_crt in str(exc).lower(), f"unexpected error for {aux_crt}: {exc}"
            else:
                raise AssertionError(f"forbidden debug/auxiliary CRT {aux_crt!r} was not caught")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PE32+ hardening, static CRT, AOT, export & icon verifier.")
    parser.add_argument("--unpacked", type=Path, default=None, help="Directory with totaldrop-winui.exe and DLLs.")
    parser.add_argument("--arch", choices=("x64", "arm64"), default="x64")
    parser.add_argument("--milestone", choices=("M1", "M2", "M3", "M4"), default="M4")
    parser.add_argument("--self-test-mutations", action="store_true", help="Run T2-F02-04, T2-F05-03 & T2-F22-06 negative mutations on temp copies.")
    parser.add_argument("--unit-test-synthetic", action="store_true", help="Run full synthetic PE32+ self-test suite.")
    args = parser.parse_args(argv)

    try:
        if args.unit_test_synthetic:
            run_synthetic_unit_tests()
            print("verify_pe_hardening synthetic unit tests OK (x64 + arm64 + M1-M4 + COM icon 101 + all mutations)")
            return 0
        if args.unpacked is None:
            parser.error("--unpacked is required unless --unit-test-synthetic is specified")
        verify_unpacked_dir(args.unpacked, arch=args.arch, milestone=args.milestone)
        if args.self_test_mutations:
            run_self_test_mutations(args.unpacked, arch=args.arch, milestone=args.milestone)
            print(f"verify_pe_hardening OK (+ self-test mutations): {args.unpacked} ({args.arch}, {args.milestone})")
        else:
            print(f"verify_pe_hardening OK: {args.unpacked} ({args.arch}, {args.milestone})")
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
