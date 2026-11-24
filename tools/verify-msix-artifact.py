#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Deep structural, PRI, PE32+ hardening, CRT, COM, manifest, bundle, upload, and live C ABI verifier for TotalDrop MSIX packages.

Uses only the Python standard library so it runs cleanly on GitHub Actions
`ubuntu-latest`, `windows-latest`, and `windows-11-arm` runners without extra dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import platform
import re
import struct
import subprocess
import sys
import sysconfig
import tempfile
import warnings
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path

EXPECTED_APP_VERSION = "0.1.0-beta.1"
EXPECTED_CORE_VERSION = "0.2.0-beta.5"
EXPECTED_MSIX_VERSION = "0.1.1.0"
EXPECTED_EXPLORER_CLSID = "8f6e3d72-4b9a-4e1c-9d3a-7c2f5a81e4b0"
EXPECTED_TOAST_CLSID = "7df2cced-0448-4849-a140-41cd106eaa9b"
UNSIGNED_PACKAGE_OID = "2.25.311729368913984317654407730594956997722"

BARE_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
QUAD_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$", re.ASCII)
IDENTITY_NAME_RE = re.compile(r"^[A-Za-z0-9.-]{3,50}$")
RDN_KEY_RE = re.compile(r"\A(?:[A-Za-z][A-Za-z0-9-]*|(?:OID\.)?[0-9]+(?:\.[0-9]+)+)\Z", re.ASCII)
RFC2253_ESCAPABLE_CHARS: frozenset[str] = frozenset({",", "+", '"', "\\", "<", ">", ";", "#", "=", " "})
ASCII_HEX_DIGITS: frozenset[str] = frozenset("0123456789ABCDEFabcdef")
FORBIDDEN_UNQUOTED_RDN_CHARS: frozenset[str] = frozenset({'"', ";", "<", ">", "+", "`", "$", "|", "&"})
PLACEHOLDER_CN_VALUES: frozenset[str] = frozenset({"totaldrop", "00000000-0000-0000-0000-000000000000"})
PDB_MSF7_MAGIC: bytes = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
EXPECTED_MANIFEST_LANGUAGES: frozenset[str] = frozenset(
    {
        "ar",
        "bn",
        "cs",
        "da",
        "de",
        "el",
        "en",
        "es",
        "fa",
        "fi",
        "fr",
        "he",
        "hi",
        "hu",
        "id",
        "it",
        "ja",
        "ko",
        "ms",
        "nb",
        "nl",
        "pl",
        "pt-BR",
        "pt-PT",
        "ro",
        "ru",
        "sv",
        "sw",
        "th",
        "tr",
        "uk",
        "ur",
        "vi",
        "zh-Hans",
        "zh-Hant",
    }
)

APPX_NS = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
BUNDLE_NS = "{http://schemas.microsoft.com/appx/2013/bundle}"

REQUIRED_FFI_EXPORTS: tuple[str, ...] = (
    # Phase 1 (6 exports)
    "totaldrop_win_string_free",
    "totaldrop_win_version_json",
    "totaldrop_win_validate_uri_json",
    "totaldrop_win_validate_input_json",
    "totaldrop_win_format_percent_json",
    "totaldrop_win_ui_bundle_json",
    # Phase 2 Group A (8 exports)
    "totaldrop_win_extract_clipboard_code_json",
    "totaldrop_win_code_completions_json",
    "totaldrop_win_format_bytes_json",
    "totaldrop_win_format_message_json",
    "totaldrop_win_sanitize_filename_json",
    "totaldrop_win_sanitize_text_json",
    "totaldrop_win_validate_server_url_json",
    "totaldrop_win_validate_paths_json",
    # Phase 2 Group B (10 exports)
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
    # Phase 3 Router (7 exports -> 31 cumulative)
    "totaldrop_win_router_create",
    "totaldrop_win_router_ingest_ipc_bytes_json",
    "totaldrop_win_router_update_locale_json",
    "totaldrop_win_router_set_animations_json",
    "totaldrop_win_router_set_activity_json",
    "totaldrop_win_router_drain_ndjson",
    "totaldrop_win_router_destroy",
)

REQUIRED_EXPLORER_EXT_EXPORTS: tuple[str, ...] = (
    "DllGetClassObject",
    "DllCanUnloadNow",
)

REQUIRED_SYMBOL_PDBS: frozenset[str] = frozenset(
    {
        "totaldrop-winui.pdb",
        "totaldrop_windows_ffi.pdb",
        "totaldrop_explorer_ext.pdb",
    }
)

FORBIDDEN_KEY_EXTS: tuple[str, ...] = (
    ".pfx",
    ".p12",
    ".cer",
    ".snk",
    ".key",
    ".pem",
    ".pvk",
    ".pepk",
    ".jks",
    ".keystore",
)

FORBIDDEN_CRT_DLLS: tuple[str, ...] = (
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "vcruntime140d.dll",
    "msvcp140.dll",
    "msvcp140_1.dll",
    "msvcp140_2.dll",
    "concrt140.dll",
    "vcomp140.dll",
    "ucrtbased.dll",
)

FORBIDDEN_CLR_HOST_DLLS: tuple[str, ...] = (
    "hostfxr.dll",
    "coreclr.dll",
    "clrjit.dll",
    "mscoree.dll",
)

RT_ICON = 3
RT_GROUP_ICON = 14
EXPLORER_ICON_RESOURCE_ID = 101

ALLOWED_OPC_COMPRESS_TYPES: tuple[int, ...] = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
# Forbidden PKWARE APPNOTE 4.4.4 general-purpose bit flags:
# 0x0001 = encrypted, 0x0020 = compressed patched data,
# 0x0040 = strong encryption, 0x2000 = masked local header values.
FORBIDDEN_ZIP_FLAGS: int = 0x0001 | 0x0020 | 0x0040 | 0x2000
_STREAM_READ_CHUNK_BYTES = 65536
_STREAM_DECOMPRESS_STEP_BYTES = 1 << 20


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
IMAGE_FILE_DLL = 0x2000
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
import struct
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

lib.totaldrop_win_extract_clipboard_code_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_extract_clipboard_code_json.restype = ctypes.c_void_p

lib.totaldrop_win_code_completions_json.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
lib.totaldrop_win_code_completions_json.restype = ctypes.c_void_p

lib.totaldrop_win_format_bytes_json.argtypes = [ctypes.c_uint64, ctypes.c_char_p, ctypes.c_char_p]
lib.totaldrop_win_format_bytes_json.restype = ctypes.c_void_p

lib.totaldrop_win_format_message_json.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_format_message_json.restype = ctypes.c_void_p

lib.totaldrop_win_sanitize_filename_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_sanitize_filename_json.restype = ctypes.c_void_p

lib.totaldrop_win_sanitize_text_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_sanitize_text_json.restype = ctypes.c_void_p

lib.totaldrop_win_validate_server_url_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_validate_server_url_json.restype = ctypes.c_void_p

lib.totaldrop_win_validate_paths_json.argtypes = [ctypes.c_char_p]
lib.totaldrop_win_validate_paths_json.restype = ctypes.c_void_p

lib.totaldrop_win_send_files_start.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_send_files_start.restype = ctypes.c_uint64

lib.totaldrop_win_send_text_start.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_send_text_start.restype = ctypes.c_uint64

lib.totaldrop_win_receive_connect_start.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_receive_connect_start.restype = ctypes.c_uint64

lib.totaldrop_win_receive_accept_files.argtypes = [ctypes.c_uint64, ctypes.c_char_p]
lib.totaldrop_win_receive_accept_files.restype = ctypes.c_int32

lib.totaldrop_win_receive_accept_text.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_receive_accept_text.restype = ctypes.c_int32

lib.totaldrop_win_receive_decline.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_receive_decline.restype = ctypes.c_int32

lib.totaldrop_win_session_poll_events_ndjson.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_session_poll_events_ndjson.restype = ctypes.c_void_p

lib.totaldrop_win_session_cancel.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_session_cancel.restype = ctypes.c_int32

lib.totaldrop_win_session_destroy.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_session_destroy.restype = ctypes.c_int32

lib.totaldrop_win_shutdown.argtypes = [ctypes.c_uint32]
lib.totaldrop_win_shutdown.restype = ctypes.c_int32

# Phase 3 router C ABI exports
lib.totaldrop_win_router_create.argtypes = [
    ctypes.c_uint32,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_bool,
]
lib.totaldrop_win_router_create.restype = ctypes.c_uint64

lib.totaldrop_win_router_ingest_ipc_bytes_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
lib.totaldrop_win_router_ingest_ipc_bytes_json.restype = ctypes.c_void_p

lib.totaldrop_win_router_update_locale_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
lib.totaldrop_win_router_update_locale_json.restype = ctypes.c_void_p

lib.totaldrop_win_router_set_animations_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_bool,
]
lib.totaldrop_win_router_set_animations_json.restype = ctypes.c_void_p

lib.totaldrop_win_router_set_activity_json.argtypes = [
    ctypes.c_uint64,
    ctypes.c_char_p,
]
lib.totaldrop_win_router_set_activity_json.restype = ctypes.c_void_p

lib.totaldrop_win_router_drain_ndjson.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_router_drain_ndjson.restype = ctypes.c_void_p

lib.totaldrop_win_router_destroy.argtypes = [ctypes.c_uint64]
lib.totaldrop_win_router_destroy.restype = ctypes.c_int32


def take_str(ptr):
    if not ptr:
        raise ValueError("FFI returned null pointer during live smoke test")
    try:
        raw = ctypes.cast(ptr, ctypes.c_char_p).value
        if raw is None:
            raise ValueError("FFI returned empty C string")
        return raw.decode("utf-8")
    finally:
        lib.totaldrop_win_string_free(ptr)


def take_json(ptr):
    return json.loads(take_str(ptr))


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

clip_ok = take_json(lib.totaldrop_win_extract_clipboard_code_json(b"Code: 7-harbor-rocket"))
assert clip_ok.get("display_english") == "7-harbor-rocket", f"unexpected clipboard ok: {clip_ok}"

comp_ok = take_json(lib.totaldrop_win_code_completions_json(b"harb", 4))
assert comp_ok == ["harbor"], f"unexpected completions: {comp_ok}"

bytes_de = take_json(lib.totaldrop_win_format_bytes_json(1_500_000, b"en-US", b"de-DE"))
assert bytes_de == {"bytes": 1_500_000, "formatted": "1,5 MB"}, f"unexpected bytes JSON: {bytes_de}"

msg_ok = take_json(
    lib.totaldrop_win_format_message_json(
        b"sendDoneBody", b'{"count":3}', b"en-US", b"en-US"
    )
)
assert msg_ok.get("formatted") == "All 3 files arrived intact.", f"unexpected message JSON: {msg_ok}"

fn_ok = take_json(lib.totaldrop_win_sanitize_filename_json("invoice\u202efdp.exe".encode("utf-8")))
assert fn_ok.get("has_hidden_controls") is True and "<U+202E>" in fn_ok.get("sanitized", "")

txt_ok = take_json(lib.totaldrop_win_sanitize_text_json(b"hello\r\nworld"))
assert txt_ok == {"display_text": "hello\nworld", "shortened": False, "has_hidden_controls": False}

srv_ok = take_json(lib.totaldrop_win_validate_server_url_json(b"wss://rendezvous.totaldrop.app"))
assert srv_ok == {"ok": True}, f"unexpected server url ok: {srv_ok}"

srv_bad = take_json(lib.totaldrop_win_validate_server_url_json(b"wss://user@host"))
assert srv_bad.get("ok") is False and srv_bad.get("error", {}).get("l10n_key") == "errorBadServer"

paths_ok = take_json(
    lib.totaldrop_win_validate_paths_json(b'["\\\\\\\\nas01\\\\team\\\\spec.docx"]')
)
assert len(paths_ok) == 1 and paths_ok[0].get("extended_path") == r"\\?\UNC\nas01\team\spec.docx"

assert lib.totaldrop_win_send_files_start(None, None, None, None) == 0
assert lib.totaldrop_win_send_text_start(None, None, None, None) == 0
assert lib.totaldrop_win_receive_connect_start(None, None, None, None) == 0
assert lib.totaldrop_win_receive_accept_files(0, None) == -1
assert lib.totaldrop_win_receive_accept_files(0, b"C:\\Downloads") == -3
assert lib.totaldrop_win_receive_accept_text(0) == -3
assert lib.totaldrop_win_receive_decline(0) == -3
poll_bad = take_json(lib.totaldrop_win_session_poll_events_ndjson(0))
assert poll_bad.get("ok") is False and poll_bad.get("error", {}).get("kind") == "invalid_handle", (
    f"unexpected poll invalid_handle JSON: {poll_bad}"
)
assert lib.totaldrop_win_session_cancel(0) == -3
assert lib.totaldrop_win_session_destroy(0) == -3

# Phase 3 router live C ABI smoke test
router_id = lib.totaldrop_win_router_create(1, b"en-US", b"en-US", None, True)
assert router_id > 0, f"expected non-zero router handle, got {router_id}"

initial_ndjson = take_str(lib.totaldrop_win_router_drain_ndjson(router_id))
assert len(initial_ndjson.splitlines()) == 2

loc_msg = take_json(lib.totaldrop_win_router_update_locale_json(router_id, b"tr-TR", b"tr-TR"))
assert loc_msg.get("kind") == "ui_bundle_ready"
assert loc_msg.get("data", {}).get("language_tag") == "tr"

act_msg = take_json(
    lib.totaldrop_win_router_set_activity_json(
        router_id, b'{"state":"transferring","done_bytes":512,"total_bytes":4096}'
    )
)
assert act_msg.get("kind") == "mark_animation_state"
assert act_msg.get("data", {}).get("animate") is True

anim_off = take_json(lib.totaldrop_win_router_set_animations_json(router_id, False))
assert anim_off.get("data", {}).get("animate") is False

idle_msg = take_json(lib.totaldrop_win_router_set_activity_json(router_id, b'{"state":"idle"}'))
assert idle_msg.get("data", {}).get("animate") is False

payload = b'{"version":1,"payload":{"kind":"share_target","paths":["\\\\\\\\nas01\\\\share\\\\a.txt"],"text":null}}'
frame = struct.pack("<I", len(payload)) + payload
buf = ctypes.create_string_buffer(frame)
decs = take_json(lib.totaldrop_win_router_ingest_ipc_bytes_json(router_id, ctypes.byref(buf), len(frame)))
assert isinstance(decs, list) and len(decs) == 1
assert decs[0].get("decision") == "navigate_send_files"
assert decs[0].get("paths") == [r"\\?\UNC\nas01\share\a.txt"]

# 0-byte EOF flush with null pointer must succeed cleanly.
eof_ok = take_json(lib.totaldrop_win_router_ingest_ipc_bytes_json(router_id, None, 0))
assert eof_ok == []

assert lib.totaldrop_win_router_destroy(router_id) == 0
assert lib.totaldrop_win_router_destroy(router_id) == -3
assert lib.totaldrop_win_shutdown(100) == 0
"""

_COM_SMOKE_TEST_CHILD_SCRIPT = r"""
import ctypes
import sys
import uuid


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_str(cls, text: str) -> "GUID":
        raw = uuid.UUID(text).bytes_le
        return cls.from_buffer_copy(raw)

    def to_str(self) -> str:
        return str(uuid.UUID(bytes_le=bytes(self)))


dll_path, expected_clsid = sys.argv[1:3]
mod = ctypes.WinDLL(dll_path)
ole32 = ctypes.WinDLL("ole32.dll")
shell32 = ctypes.WinDLL("shell32.dll")
user32 = ctypes.WinDLL("user32.dll")

ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
ole32.CoTaskMemFree.restype = None

shell32.ExtractIconExW.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_int,
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_uint,
]
shell32.ExtractIconExW.restype = ctypes.c_uint

user32.DestroyIcon.argtypes = [ctypes.c_void_p]
user32.DestroyIcon.restype = ctypes.c_int

mod.DllCanUnloadNow.argtypes = []
mod.DllCanUnloadNow.restype = ctypes.c_int32

mod.DllGetClassObject.argtypes = [
    ctypes.POINTER(GUID),
    ctypes.POINTER(GUID),
    ctypes.POINTER(ctypes.c_void_p),
]
mod.DllGetClassObject.restype = ctypes.c_int32

assert mod.DllCanUnloadNow() == 0, "expected S_OK before instantiating COM objects"

clsid = GUID.from_str(expected_clsid)
iid_factory = GUID.from_str("00000001-0000-0000-c000-000000000046")
iid_cmd = GUID.from_str("a08ce4d0-fa25-44ab-b57c-c7b1c323e0b9")

factory_ptr = ctypes.c_void_p()
hr = mod.DllGetClassObject(ctypes.byref(clsid), ctypes.byref(iid_factory), ctypes.byref(factory_ptr))
assert hr == 0 and factory_ptr.value, f"DllGetClassObject failed: hr={hr:#x}"
assert mod.DllCanUnloadNow() == 1, "expected S_FALSE while factory is alive"

factory_vtbl = ctypes.cast(
    ctypes.cast(factory_ptr, ctypes.POINTER(ctypes.c_void_p)).contents.value,
    ctypes.POINTER(ctypes.c_void_p),
)
ReleaseFn = ctypes.WINFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p)
CreateInstanceFn = ctypes.WINFUNCTYPE(
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.POINTER(GUID),
    ctypes.POINTER(ctypes.c_void_p),
)

cmd_ptr = ctypes.c_void_p()
create_inst = CreateInstanceFn(factory_vtbl[3])
hr = create_inst(factory_ptr, None, ctypes.byref(iid_cmd), ctypes.byref(cmd_ptr))
assert hr == 0 and cmd_ptr.value, f"IClassFactory::CreateInstance failed: hr={hr:#x}"

cmd_vtbl = ctypes.cast(
    ctypes.cast(cmd_ptr, ctypes.POINTER(ctypes.c_void_p)).contents.value,
    ctypes.POINTER(ctypes.c_void_p),
)
GetTitleFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
GetIconFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
GetCanonicalFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(GUID))
GetStateFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int32, ctypes.POINTER(ctypes.c_int32))
GetFlagsFn = ctypes.WINFUNCTYPE(ctypes.c_int32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int32))

out_guid = GUID()
assert GetCanonicalFn(cmd_vtbl[6])(cmd_ptr, ctypes.byref(out_guid)) == 0
assert out_guid.to_str().lower() == expected_clsid.lower(), f"canonical CLSID mismatch: {out_guid.to_str()}"

title_ptr = ctypes.c_void_p()
assert GetTitleFn(cmd_vtbl[3])(cmd_ptr, None, ctypes.byref(title_ptr)) == 0
assert title_ptr.value
title = ctypes.wstring_at(title_ptr.value)
ole32.CoTaskMemFree(title_ptr)
assert title.strip(), "GetTitle returned empty string"

icon_ptr = ctypes.c_void_p()
assert GetIconFn(cmd_vtbl[4])(cmd_ptr, None, ctypes.byref(icon_ptr)) == 0
assert icon_ptr.value
icon_spec = ctypes.wstring_at(icon_ptr.value)
ole32.CoTaskMemFree(icon_ptr)
assert icon_spec.endswith(",-101"), f"unexpected GetIcon spec: {icon_spec}"

large_ico = ctypes.c_void_p()
small_ico = ctypes.c_void_p()
extracted = shell32.ExtractIconExW(dll_path, -101, ctypes.byref(large_ico), ctypes.byref(small_ico), 1)
assert extracted >= 1, f"ExtractIconExW(dll, -101) failed: {extracted}"
if large_ico.value:
    user32.DestroyIcon(large_ico)
if small_ico.value:
    user32.DestroyIcon(small_ico)

state = ctypes.c_int32(-1)
assert GetStateFn(cmd_vtbl[7])(cmd_ptr, None, 0, ctypes.byref(state)) == 0
assert state.value == 2, f"expected ECS_HIDDEN (2) for null array, got {state.value}"

flags = ctypes.c_int32(-1)
assert GetFlagsFn(cmd_vtbl[9])(cmd_ptr, ctypes.byref(flags)) == 0
assert flags.value == 0, f"expected ECF_DEFAULT (0), got {flags.value}"

ReleaseFn(cmd_vtbl[2])(cmd_ptr)
ReleaseFn(factory_vtbl[2])(factory_ptr)
assert mod.DllCanUnloadNow() == 0, "expected S_OK after releasing all COM instances"
"""


def _pe_machine_to_arch(pe_bytes: bytes) -> str | None:
    """Return 'x64' or 'arm64' for a PE32+ executable, or None for PE32 (32-bit) / non-PE bytes."""
    try:
        pe = parse_pe64_bytes(pe_bytes, "<python>")
    except ValueError:
        return None
    machine = pe.get("machine")
    if machine == IMAGE_FILE_MACHINE_AMD64:
        return "x64"
    if machine == IMAGE_FILE_MACHINE_ARM64:
        return "arm64"
    return None


def _python_host_arch() -> str | None:
    if sys.platform == "win32":
        exe = Path(sys.executable) if sys.executable else None
        if exe is not None and exe.is_file():
            try:
                exe_bytes = exe.read_bytes()
                if len(exe_bytes) >= 0x40 and exe_bytes[:2] == b"MZ":
                    return _pe_machine_to_arch(exe_bytes)
            except OSError:
                pass
        plat = sysconfig.get_platform().lower()
        if plat == "win-amd64":
            return "x64"
        if plat == "win-arm64":
            return "arm64"
        return None
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        return "x64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    return None


def _validate_msix_version_quad(version: str, label: str, *, store_mode: bool) -> None:
    if not isinstance(version, str) or not QUAD_RE.fullmatch(version):
        raise ValueError(
            f"{label}: invalid MSIX version {version!r} (expected Major.Minor.Build.Revision)"
        )
    parts = version.split(".")
    nums: list[int] = []
    for part in parts:
        if len(part) > 1 and part.startswith("0"):
            raise ValueError(f"{label}: leading zero not permitted in version component {part!r}")
        val = int(part)
        if val < 0 or val > 65535:
            raise ValueError(
                f"{label}: version component {val} outside 0..=65535 uint16 quad bounds"
            )
        nums.append(val)
    if store_mode:
        if nums[0] < 1:
            raise ValueError(
                f"{label}: Store MSIX version {version!r} violates Microsoft Store Major >= 1 requirement"
            )
        if nums[3] != 0:
            raise ValueError(
                f"{label}: Store MSIX version {version!r} violates Microsoft Store Revision == 0 requirement"
            )


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
            raise ValueError(f"{label}: contains forbidden control/Bidi char U+{cp:04X}")


def _strip_unescaped_x500_whitespace(text: str) -> str:
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


def _parse_x500_publisher(publisher: str, label: str) -> list[tuple[str, str]]:
    """Parse and strictly validate an RFC 2253/4514 X.500 Publisher DN, returning (KEY_UPPER, decoded_value) pairs."""
    if not isinstance(publisher, str) or not _strip_unescaped_x500_whitespace(publisher):
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
            rdns.append(_strip_unescaped_x500_whitespace("".join(buf)))
            buf.clear()
            continue
        buf.append(ch)
    if in_quotes or escaped:
        raise ValueError(f"{label}: malformed X.500 Publisher {publisher!r} (unterminated quote/escape)")
    rdns.append(_strip_unescaped_x500_whitespace("".join(buf)))

    parsed: list[tuple[str, str]] = []
    has_cn = False
    for rdn in rdns:
        if not rdn or "=" not in rdn:
            raise ValueError(
                f"{label}: malformed X.500 Publisher RDN {rdn!r} in {publisher!r} (expected e.g. 'CN=...')"
            )
        raw_key, raw_val = rdn.split("=", 1)
        key = raw_key.strip()
        val = _strip_unescaped_x500_whitespace(raw_val)
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
        raise ValueError(f"{label}: X.500 Publisher {publisher!r} must include a non-empty 'CN=' attribute")
    return parsed


def _validate_x500_publisher(publisher: str, label: str) -> None:
    _parse_x500_publisher(publisher, label)


def is_placeholder_test_identity(name: str, publisher: str) -> bool:
    """Return True if Name or Publisher matches a placeholder/all-zero test identity."""
    if isinstance(name, str) and name.strip().lower() == "totaldrop.totaldrop":
        return True
    try:
        parsed_rdns = _parse_x500_publisher(publisher, "Publisher")
    except ValueError:
        return False
    for key, val in parsed_rdns:
        if key == "CN" and val.strip().lower() in PLACEHOLDER_CN_VALUES:
            return True
    return False


def _validate_identity_store_policy(
    name: str,
    publisher: str,
    version: str,
    label: str,
    *,
    expected_version: str | None,
    store_mode: bool,
    allow_test_identity: bool,
) -> None:
    if not IDENTITY_NAME_RE.fullmatch(name):
        raise ValueError(f"{label}: invalid Identity/@Name {name!r}")
    _validate_x500_publisher(publisher, f"{label} Identity/@Publisher")
    _validate_msix_version_quad(version, f"{label} Identity/@Version", store_mode=store_mode)
    if expected_version is not None and version != expected_version:
        raise ValueError(
            f"{label}: Identity/@Version mismatch: {version!r} != {expected_version!r}"
        )
    if store_mode and not allow_test_identity:
        if is_placeholder_test_identity(name, publisher):
            raise ValueError(
                f"{label}: Store-mode build refuses placeholder test identity "
                f"(Name={name!r}, Publisher={publisher!r}); supply Partner Center identity or pass --allow-test-identity"
            )


def _read_zip_member(zf: zipfile.ZipFile, member: str | zipfile.ZipInfo, label: str) -> bytes:
    member_name = member.filename if isinstance(member, zipfile.ZipInfo) else member
    try:
        return zf.read(member)
    except (zlib.error, zipfile.BadZipFile, RuntimeError, EOFError, struct.error, OverflowError) as exc:
        raise ValueError(f"{label}: corrupted ZIP member {member_name!r}: {exc}") from exc


def _check_zip_extra_fields(extra: bytes, label: str, entry_name: str, location: str) -> None:
    off = 0
    extra_len = len(extra)
    seen_zip64 = False
    while off < extra_len:
        if off + 4 > extra_len:
            raise ValueError(
                f"{label}: ZIP entry {entry_name!r} has truncated {location} extra field header"
            )
        header_id, data_size = struct.unpack_from("<HH", extra, off)
        off += 4
        if off + data_size > extra_len:
            raise ValueError(
                f"{label}: ZIP entry {entry_name!r} has truncated {location} extra field 0x{header_id:04x}"
            )
        if header_id == 0x7075:
            raise ValueError(
                f"{label}: ZIP entry {entry_name!r} uses forbidden Info-ZIP 0x7075 Unicode Path "
                f"extra field ({location})"
            )
        if header_id == 0x0001:
            if seen_zip64:
                raise ValueError(
                    f"{label}: ZIP entry {entry_name!r} has duplicate {location} 0x0001 Zip64 extra field"
                )
            seen_zip64 = True
        off += data_size


def _extract_zip64_lfh_sizes(extra: bytes, label: str, entry_name: str) -> tuple[int, int] | None:
    """Return (uncomp_size, comp_size) from LFH 0x0001 Zip64 extra field, rejecting malformed/duplicate 0x0001."""
    found: tuple[int, int] | None = None
    off = 0
    extra_len = len(extra)
    while off < extra_len:
        if off + 4 > extra_len:
            raise ValueError(
                f"{label}: ZIP entry {entry_name!r} has truncated local-header extra field header"
            )
        header_id, data_size = struct.unpack_from("<HH", extra, off)
        off += 4
        if off + data_size > extra_len:
            raise ValueError(
                f"{label}: ZIP entry {entry_name!r} has truncated local-header extra field 0x{header_id:04x}"
            )
        if header_id == 0x0001:
            if found is not None:
                raise ValueError(
                    f"{label}: ZIP entry {entry_name!r} has duplicate local-header 0x0001 Zip64 extra field"
                )
            if data_size != 16:
                raise ValueError(
                    f"{label}: ZIP entry {entry_name!r} local-header 0x0001 Zip64 extra field "
                    f"must be exactly 16 bytes (got {data_size})"
                )
            found = struct.unpack_from("<QQ", extra, off)
        off += data_size
    return found


def _verify_data_descriptor(dd: bytes, info: zipfile.ZipInfo, label: str) -> None:
    """Validate a PKWARE APPNOTE 4.3.9 streaming Data Descriptor against CD metadata."""
    gap = len(dd)
    if gap == 12:
        dd_crc, dd_csz, dd_usz = struct.unpack("<III", dd)
    elif gap == 16:
        dd_sig, dd_crc, dd_csz, dd_usz = struct.unpack("<4sIII", dd)
        if dd_sig != b"PK\x07\x08":
            raise ValueError(
                f"{label}: ZIP entry {info.orig_filename!r} has invalid 16-byte data descriptor signature {dd_sig!r}"
            )
    elif gap == 20:
        dd_crc, dd_csz, dd_usz = struct.unpack("<IQQ", dd)
    elif gap == 24:
        dd_sig, dd_crc, dd_csz, dd_usz = struct.unpack("<4sIQQ", dd)
        if dd_sig != b"PK\x07\x08":
            raise ValueError(
                f"{label}: ZIP entry {info.orig_filename!r} has invalid 24-byte data descriptor signature {dd_sig!r}"
            )
    else:
        raise ValueError(
            f"{label}: ZIP entry {info.orig_filename!r} has unexpected streaming data descriptor size "
            f"{gap} bytes (expected 12, 16, 20, or 24)"
        )
    if (dd_crc, dd_csz, dd_usz) != (info.CRC, info.compress_size, info.file_size):
        raise ValueError(
            f"{label}: ZIP entry {info.orig_filename!r} data descriptor mismatch "
            f"(dd={(dd_crc, dd_csz, dd_usz)!r} != cd={(info.CRC, info.compress_size, info.file_size)!r})"
        )


def _verify_entry_stream_exact(
    fp: object,
    comp_start: int,
    info: zipfile.ZipInfo,
    label: str,
) -> None:
    """Verify exact raw payload byte count, DEFLATE EOF/zero-slack, uncompressed length, and CRC-32 in O(1) RAM."""
    if info.compress_size < 0 or info.file_size < 0:
        raise ValueError(
            f"{label}: ZIP entry {info.orig_filename!r} has negative size "
            f"(compress_size={info.compress_size}, file_size={info.file_size})"
        )

    if info.compress_type == zipfile.ZIP_STORED:
        if info.compress_size != info.file_size:
            raise ValueError(
                f"{label}: ZIP_STORED entry {info.orig_filename!r} has mismatched sizes "
                f"(compress_size={info.compress_size} != file_size={info.file_size})"
            )
        fp.seek(comp_start)  # type: ignore[attr-defined]
        remaining = info.compress_size
        total_read = 0
        running_crc = 0
        while remaining > 0:
            chunk = fp.read(min(_STREAM_READ_CHUNK_BYTES, remaining))  # type: ignore[attr-defined]
            if not chunk:
                raise ValueError(
                    f"{label}: ZIP_STORED entry {info.orig_filename!r} truncated "
                    f"(read {total_read} of {info.compress_size} bytes)"
                )
            total_read += len(chunk)
            remaining -= len(chunk)
            running_crc = zlib.crc32(chunk, running_crc)
        if total_read != info.compress_size:
            raise ValueError(
                f"{label}: ZIP_STORED entry {info.orig_filename!r} byte count mismatch "
                f"({total_read} != {info.compress_size})"
            )
        if (running_crc & 0xFFFFFFFF) != info.CRC:
            raise ValueError(
                f"{label}: ZIP_STORED entry {info.orig_filename!r} raw stream CRC-32 mismatch "
                f"({running_crc & 0xFFFFFFFF:#010x} != {info.CRC:#010x})"
            )
        return

    if info.compress_type == zipfile.ZIP_DEFLATED:
        fp.seek(comp_start)  # type: ignore[attr-defined]
        dec = zlib.decompressobj(-15)
        remaining = info.compress_size
        total_out = 0
        running_crc = 0
        try:
            while remaining > 0:
                if dec.eof:
                    raise ValueError(
                        f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} has trailing unconsumed bytes "
                        f"after DEFLATE end-of-stream ({remaining} unread compressed bytes)"
                    )
                chunk = fp.read(min(_STREAM_READ_CHUNK_BYTES, remaining))  # type: ignore[attr-defined]
                if not chunk:
                    raise ValueError(
                        f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} compressed stream truncated "
                        f"({remaining} bytes remaining)"
                    )
                remaining -= len(chunk)
                pending = chunk
                while True:
                    max_step = min(_STREAM_DECOMPRESS_STEP_BYTES, (info.file_size - total_out) + 1)
                    out = dec.decompress(pending, max_step)
                    total_out += len(out)
                    if out:
                        running_crc = zlib.crc32(out, running_crc)
                    if total_out > info.file_size:
                        raise ValueError(
                            f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} uncompressed stream exceeds "
                            f"declared file_size ({total_out} > {info.file_size})"
                        )
                    pending = dec.unconsumed_tail
                    if dec.eof:
                        if pending or dec.unused_data or remaining > 0:
                            raise ValueError(
                                f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} has trailing unconsumed bytes "
                                f"after DEFLATE end-of-stream "
                                f"(unused={len(dec.unused_data)}, pending={len(pending)}, remaining={remaining})"
                            )
                        break
                    if not pending and len(out) < max_step:
                        break

            if not dec.eof:
                raise ValueError(
                    f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} ended without DEFLATE end-of-stream marker"
                )
            if dec.unconsumed_tail or dec.unused_data:
                raise ValueError(
                    f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} has trailing unconsumed bytes "
                    f"after DEFLATE end-of-stream (unused={len(dec.unused_data)}, tail={len(dec.unconsumed_tail)})"
                )
            tail = dec.flush(min(_STREAM_DECOMPRESS_STEP_BYTES, (info.file_size - total_out) + 1))
            if tail:
                total_out += len(tail)
                running_crc = zlib.crc32(tail, running_crc)
                if total_out > info.file_size:
                    raise ValueError(
                        f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} uncompressed stream exceeds "
                        f"declared file_size ({total_out} > {info.file_size})"
                    )
        except zlib.error as exc:
            raise ValueError(
                f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} has corrupted DEFLATE stream: {exc}"
            ) from exc

        if not dec.eof or dec.unconsumed_tail or dec.unused_data:
            raise ValueError(
                f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} failed final DEFLATE EOF/zero-slack check"
            )
        if total_out != info.file_size:
            raise ValueError(
                f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} uncompressed stream length mismatch "
                f"({total_out} != {info.file_size})"
            )
        if (running_crc & 0xFFFFFFFF) != info.CRC:
            raise ValueError(
                f"{label}: ZIP_DEFLATED entry {info.orig_filename!r} raw stream CRC-32 mismatch "
                f"({running_crc & 0xFFFFFFFF:#010x} != {info.CRC:#010x})"
            )
        return

    raise ValueError(
        f"{label}: ZIP entry {info.orig_filename!r} uses unsupported OPC/MSIX compression method "
        f"{info.compress_type} (only ZIP_STORED=0 and ZIP_DEFLATED=8 are permitted)"
    )


def _check_zip_container_structure(
    zf: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
    label: str,
) -> None:
    """Strictly verify ZIP EOCD/Zip64-EOCD parity, concat == 0, EOF anchoring, CD contiguity, and LFH layout."""
    fp = zf.fp
    if fp is None:
        return
    saved_pos = fp.tell()
    try:
        fp.seek(0, os.SEEK_END)
        file_size = fp.tell()
        if file_size < 22:
            raise ValueError(f"{label}: ZIP archive truncated ({file_size} bytes < 22-byte EOCD)")

        comment = zf.comment or b""
        if b"PK\x05\x06" in comment:
            raise ValueError(f"{label}: ZIP archive comment contains forbidden nested EOCD signature PK\\x05\\x06")

        eocd_pos = file_size - 22 - len(comment)
        if eocd_pos < 0:
            raise ValueError(f"{label}: ZIP EOCD offset {eocd_pos} precedes start of archive")

        fp.seek(eocd_pos)
        eocd_raw = fp.read(22)
        if len(eocd_raw) != 22:
            raise ValueError(f"{label}: truncated 32-bit ZIP EOCD record at offset {eocd_pos}")
        (
            eocd_sig,
            disk_num,
            cd_disk,
            entries_disk,
            entries_total,
            cd_size32,
            cd_offset32,
            comment_len,
        ) = struct.unpack("<4sHHHHIIH", eocd_raw)
        if eocd_sig != b"PK\x05\x06":
            raise ValueError(
                f"{label}: 32-bit ZIP EOCD not anchored to EOF (trailing bytes after EOCD or malformed comment)"
            )
        if comment_len != len(comment):
            raise ValueError(
                f"{label}: ZIP EOCD comment_len ({comment_len}) does not match remaining EOF bytes ({len(comment)})"
            )
        actual_comment = fp.read(comment_len) if comment_len else b""
        if actual_comment != comment:
            raise ValueError(f"{label}: ZIP EOCD comment bytes mismatch at EOF")

        z64_loc_pos = eocd_pos - 20
        has_z64_locator = False
        if z64_loc_pos >= 0:
            fp.seek(z64_loc_pos)
            has_z64_locator = fp.read(4) == b"PK\x06\x07"

        if has_z64_locator:
            fp.seek(z64_loc_pos)
            loc_raw = fp.read(20)
            if len(loc_raw) != 20:
                raise ValueError(f"{label}: truncated Zip64 EOCD Locator at offset {z64_loc_pos}")
            loc_sig, z64_disk, z64_eocd_off, total_disks = struct.unpack("<4sIQI", loc_raw)
            if loc_sig != b"PK\x06\x07":
                raise ValueError(f"{label}: invalid Zip64 EOCD Locator signature {loc_sig!r}")
            if z64_disk != 0 or total_disks != 1:
                raise ValueError(
                    f"{label}: multi-disk Zip64 archive is forbidden (disk={z64_disk}, total_disks={total_disks})"
                )
            if z64_eocd_off < 0 or z64_eocd_off + 56 > z64_loc_pos:
                raise ValueError(
                    f"{label}: Zip64 EOCD offset {z64_eocd_off} out of bounds before Locator {z64_loc_pos}"
                )

            fp.seek(z64_eocd_off)
            z64_raw = fp.read(56)
            if len(z64_raw) != 56:
                raise ValueError(f"{label}: truncated Zip64 EOCD record at offset {z64_eocd_off}")
            (
                z64_sig,
                z64_rec_size,
                _vm,
                _vn,
                z64_disk_num,
                z64_cd_disk,
                z64_entries_disk,
                z64_entries_total,
                z64_cd_size,
                z64_cd_off,
            ) = struct.unpack("<4sQHHIIQQQQ", z64_raw)
            if z64_sig != b"PK\x06\x06":
                raise ValueError(f"{label}: invalid Zip64 EOCD signature {z64_sig!r} at offset {z64_eocd_off}")
            if z64_rec_size < 44 or z64_eocd_off + 12 + z64_rec_size != z64_loc_pos:
                raise ValueError(
                    f"{label}: Zip64 EOCD size/alignment mismatch "
                    f"(off={z64_eocd_off}, rec_size={z64_rec_size}, loc={z64_loc_pos})"
                )
            if z64_disk_num != 0 or z64_cd_disk != 0:
                raise ValueError(
                    f"{label}: multi-disk Zip64 EOCD is forbidden (disk={z64_disk_num}, cd_disk={z64_cd_disk})"
                )
            if z64_entries_disk != len(infos) or z64_entries_total != len(infos):
                raise ValueError(
                    f"{label}: Zip64 EOCD entry count mismatch "
                    f"(disk={z64_entries_disk}, total={z64_entries_total}, parsed={len(infos)})"
                )
            if z64_cd_off + z64_cd_size != z64_eocd_off:
                raise ValueError(
                    f"{label}: Zip64 non-zero concat/offset mismatch "
                    f"(cd_off={z64_cd_off}, cd_size={z64_cd_size}, z64_eocd={z64_eocd_off})"
                )
            if zf.start_dir != z64_cd_off:
                raise ValueError(
                    f"{label}: parsed central directory offset ({zf.start_dir}) != Zip64 EOCD ({z64_cd_off})"
                )

            # Strict 32-bit vs Zip64 EOCD parity kills both full and partial-sentinel Zip64 split attacks.
            if disk_num not in (0, 0xFFFF) or cd_disk not in (0, 0xFFFF):
                raise ValueError(
                    f"{label}: 32-bit EOCD disk fields ({disk_num}, {cd_disk}) conflict with Zip64 EOCD (0, 0)"
                )
            if entries_disk not in (z64_entries_disk, 0xFFFF) or entries_total not in (z64_entries_total, 0xFFFF):
                raise ValueError(
                    f"{label}: 32-bit EOCD entry counts ({entries_disk}, {entries_total}) conflict with "
                    f"Zip64 EOCD ({z64_entries_disk}, {z64_entries_total})"
                )
            if cd_size32 not in (z64_cd_size, 0xFFFFFFFF) or cd_offset32 not in (z64_cd_off, 0xFFFFFFFF):
                raise ValueError(
                    f"{label}: 32-bit EOCD central directory ({cd_offset32}, {cd_size32}) conflicts with "
                    f"Zip64 EOCD ({z64_cd_off}, {z64_cd_size}) (Zip64 EOCD shadowing/split is forbidden)"
                )

            cd_off = z64_cd_off
            cd_size = z64_cd_size
        else:
            if disk_num != 0 or cd_disk != 0:
                raise ValueError(
                    f"{label}: multi-disk 32-bit ZIP archive is forbidden (disk={disk_num}, cd_disk={cd_disk})"
                )
            if (
                entries_disk == 0xFFFF
                or entries_total == 0xFFFF
                or cd_size32 == 0xFFFFFFFF
                or cd_offset32 == 0xFFFFFFFF
            ):
                raise ValueError(
                    f"{label}: 32-bit ZIP EOCD contains Zip64 sentinel without a Zip64 EOCD Locator"
                )
            if entries_disk != len(infos) or entries_total != len(infos):
                raise ValueError(
                    f"{label}: 32-bit ZIP EOCD entry count mismatch "
                    f"(disk={entries_disk}, total={entries_total}, parsed={len(infos)})"
                )
            if cd_offset32 + cd_size32 != eocd_pos:
                raise ValueError(
                    f"{label}: ZIP archive has non-zero concat/prepended offset "
                    f"(cd_off={cd_offset32}, cd_size={cd_size32}, eocd={eocd_pos})"
                )
            if zf.start_dir != cd_offset32:
                raise ValueError(
                    f"{label}: parsed central directory offset ({zf.start_dir}) != 32-bit EOCD ({cd_offset32})"
                )
            cd_off = cd_offset32
            cd_size = cd_size32

        # Walk Central Directory records to prove exact contiguity over [cd_off, cd_off + cd_size).
        cd_end = cd_off + cd_size
        pos = cd_off
        cd_records = 0
        while pos < cd_end:
            if pos + 46 > cd_end:
                raise ValueError(f"{label}: truncated central directory record header at offset {pos}")
            fp.seek(pos)
            hdr = fp.read(46)
            if len(hdr) != 46 or hdr[:4] != b"PK\x01\x02":
                raise ValueError(f"{label}: invalid central directory signature at offset {pos}")
            fname_len, extra_len, cmt_len, cd_disk_start = struct.unpack_from("<HHHH", hdr, 28)
            if cd_disk_start != 0:
                raise ValueError(
                    f"{label}: multi-disk central directory record (disk_start={cd_disk_start}) at offset {pos}"
                )
            pos += 46 + fname_len + extra_len + cmt_len
            if pos > cd_end:
                raise ValueError(f"{label}: central directory record overflows central directory end {cd_end}")
            cd_records += 1
        if cd_records != len(infos) or pos != cd_end:
            raise ValueError(
                f"{label}: central directory contiguity mismatch "
                f"(records={cd_records}, parsed={len(infos)}, end={pos}, cd_end={cd_end})"
            )

        # Verify Local File Header layout starts at byte 0 with strictly increasing, non-overlapping spans.
        if not infos:
            if cd_off != 0:
                raise ValueError(f"{label}: empty ZIP archive contains {cd_off} unreferenced leading bytes")
            return

        sorted_infos = sorted(infos, key=lambda item: item.header_offset)
        if sorted_infos[0].header_offset != 0:
            raise ValueError(
                f"{label}: first ZIP local file header starts at offset {sorted_infos[0].header_offset} != 0 "
                "(unreferenced prepended data is forbidden)"
            )
        for idx, info in enumerate(sorted_infos):
            hdr_off = info.header_offset
            next_off = sorted_infos[idx + 1].header_offset if idx + 1 < len(sorted_infos) else cd_off
            if idx + 1 < len(sorted_infos) and next_off <= hdr_off:
                raise ValueError(
                    f"{label}: overlapping/duplicate ZIP local file header offset {hdr_off} for {info.orig_filename!r}"
                )
            if hdr_off < 0 or next_off > cd_off or hdr_off + 30 > next_off:
                raise ValueError(
                    f"{label}: ZIP entry {info.orig_filename!r} has invalid local file header bounds "
                    f"(offset={hdr_off}, next={next_off}, cd_off={cd_off})"
                )
            fp.seek(hdr_off)
            lfh = fp.read(30)
            if len(lfh) != 30 or lfh[:4] != b"PK\x03\x04":
                raise ValueError(f"{label}: ZIP entry {info.orig_filename!r} has invalid local file header")
            lfh_flags = struct.unpack_from("<H", lfh, 6)[0]
            lfh_name_len, lfh_extra_len = struct.unpack_from("<HH", lfh, 26)
            comp_end = hdr_off + 30 + lfh_name_len + lfh_extra_len + info.compress_size
            if comp_end > next_off or comp_end > cd_off:
                raise ValueError(
                    f"{label}: ZIP entry {info.orig_filename!r} compressed data span ({hdr_off}..{comp_end}) "
                    f"exceeds next boundary ({min(next_off, cd_off)})"
                )
            has_dd_cd = (info.flag_bits & 0x0008) != 0
            has_dd_lfh = (lfh_flags & 0x0008) != 0
            if has_dd_cd != has_dd_lfh:
                raise ValueError(
                    f"{label}: ZIP entry {info.orig_filename!r} data-descriptor flag mismatch "
                    f"(lfh={lfh_flags:#x}, cd={info.flag_bits:#x})"
                )
            gap = next_off - comp_end
            if has_dd_cd:
                if gap not in (12, 16, 20, 24):
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} has unexpected streaming data descriptor size "
                        f"{gap} bytes (expected 12, 16, 20, or 24)"
                    )
                fp.seek(comp_end)
                dd = fp.read(gap)
                _verify_data_descriptor(dd, info, label)
            elif gap != 0:
                raise ValueError(
                    f"{label}: ZIP entry {info.orig_filename!r} has {gap} unreferenced trailing gap bytes "
                    f"before offset {next_off}"
                )
    finally:
        fp.seek(saved_pos)


def _check_opc_zip_entries(
    zf: zipfile.ZipFile,
    label: str,
    *,
    flat_root_only: bool = False,
    case_sensitive_unique_paths: tuple[str, ...] = (),
) -> list[str]:
    infos = zf.infolist()
    if zf.fp is not None:
        _check_zip_container_structure(zf, infos, label)

    # Enforce strict OPC/MSIX compression allowlist and forbidden flag bits BEFORE zf.testzip()
    # so unsupported codecs (e.g., ZIP_LZMA=14, ZIP_BZIP2=12) can never invoke lzma/bz2 decompressors.
    for info in infos:
        if info.compress_type not in ALLOWED_OPC_COMPRESS_TYPES:
            raise ValueError(
                f"{label}: ZIP entry {info.orig_filename!r} uses unsupported OPC/MSIX compression method "
                f"{info.compress_type} (only ZIP_STORED=0 and ZIP_DEFLATED=8 are permitted)"
            )
        if (info.flag_bits & FORBIDDEN_ZIP_FLAGS) != 0:
            raise ValueError(
                f"{label}: ZIP entry {info.orig_filename!r} has forbidden general-purpose flag bits "
                f"{info.flag_bits:#06x} (forbidden mask {FORBIDDEN_ZIP_FLAGS:#06x})"
            )

    try:
        bad_member = zf.testzip()
    except (zlib.error, zipfile.BadZipFile, RuntimeError, EOFError, struct.error, OverflowError) as exc:
        raise ValueError(f"{label}: corrupted ZIP archive: {exc}") from exc
    if bad_member is not None:
        raise ValueError(f"{label}: corrupted ZIP member {bad_member!r}")

    raw_names = [info.filename for info in infos]
    seen_exact: set[str] = set()
    seen_lower: dict[str, str] = {}
    seen_files: dict[str, str] = {}
    seen_dirs: dict[str, str] = {}
    seen_dir_case: dict[str, str] = {}
    for info in infos:
        if info.orig_filename != info.filename:
            raise ValueError(
                f"{label}: raw ZIP entry name {info.orig_filename!r} differs from normalized name "
                f"{info.filename!r} (NUL truncation, backslash separator, or 0x7075 extra-field spoofing is forbidden)"
            )
        unix_type = (info.external_attr >> 16) & 0o170000
        if info.create_system in (3, 19) or unix_type != 0:
            if unix_type == 0o120000:
                raise ValueError(
                    f"{label}: symbolic link ZIP entry is forbidden: {info.orig_filename!r}"
                )
            if unix_type not in (0, 0o100000, 0o040000):
                raise ValueError(
                    f"{label}: non-regular Unix ZIP entry mode {unix_type:#o} is forbidden: {info.orig_filename!r}"
                )
            if unix_type == 0o040000 and not info.filename.endswith("/"):
                raise ValueError(
                    f"{label}: directory-mode ZIP entry missing trailing slash: {info.orig_filename!r}"
                )
            if unix_type == 0o100000 and info.filename.endswith("/"):
                raise ValueError(
                    f"{label}: regular-file-mode ZIP entry has trailing slash: {info.orig_filename!r}"
                )
        _check_zip_extra_fields(info.extra or b"", label, info.orig_filename, "central-directory")
        if zf.fp is not None:
            saved_pos = zf.fp.tell()
            try:
                zf.fp.seek(info.header_offset)
                lfh = zf.fp.read(30)
                if len(lfh) != 30 or lfh[:4] != b"PK\x03\x04":
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} has invalid local file header"
                    )
                lfh_flags, lfh_method = struct.unpack_from("<HH", lfh, 6)
                lfh_crc, lfh_comp_size, lfh_uncomp_size = struct.unpack_from("<III", lfh, 14)
                lfh_name_len, lfh_extra_len = struct.unpack_from("<HH", lfh, 26)
                if lfh_method != info.compress_type:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} local-header compression method "
                        f"({lfh_method}) differs from central-directory method ({info.compress_type})"
                    )
                if (lfh_flags & FORBIDDEN_ZIP_FLAGS) != 0 or (info.flag_bits & FORBIDDEN_ZIP_FLAGS) != 0:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} has forbidden general-purpose flag bits "
                        f"(lfh={lfh_flags:#06x}, cd={info.flag_bits:#06x}, forbidden mask {FORBIDDEN_ZIP_FLAGS:#06x})"
                    )
                if (lfh_flags & 0x0008) != (info.flag_bits & 0x0008):
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} local-header data-descriptor flag "
                        f"({lfh_flags:#x}) differs from central-directory flag ({info.flag_bits:#x})"
                    )
                lfh_name_bytes = zf.fp.read(lfh_name_len)
                if len(lfh_name_bytes) != lfh_name_len:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} has truncated local-header filename"
                    )
                cd_encoding = "utf-8" if (info.flag_bits & 0x0800) else "cp437"
                try:
                    expected_name_bytes = info.orig_filename.encode(cd_encoding)
                except UnicodeEncodeError as exc:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} cannot be encoded as {cd_encoding}: {exc}"
                    ) from exc
                if lfh_name_bytes != expected_name_bytes:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} local-header filename "
                        f"{lfh_name_bytes!r} differs from central-directory filename {expected_name_bytes!r}"
                    )
                lfh_extra = zf.fp.read(lfh_extra_len) if lfh_extra_len else b""
                if len(lfh_extra) != lfh_extra_len:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} has truncated local-header extra field"
                    )
                if lfh_extra:
                    _check_zip_extra_fields(lfh_extra, label, info.orig_filename, "local-header")
                z64_sizes = _extract_zip64_lfh_sizes(lfh_extra, label, info.orig_filename) if lfh_extra else None
                if (lfh_flags & 0x0008) == 0:
                    if lfh_crc != info.CRC:
                        raise ValueError(
                            f"{label}: ZIP entry {info.orig_filename!r} local-header CRC-32 "
                            f"({lfh_crc:#010x}) differs from central-directory CRC-32 ({info.CRC:#010x})"
                        )
                    if lfh_comp_size not in (info.compress_size, 0xFFFFFFFF):
                        raise ValueError(
                            f"{label}: ZIP entry {info.orig_filename!r} local-header compressed size "
                            f"({lfh_comp_size}) differs from central-directory ({info.compress_size})"
                        )
                    if lfh_uncomp_size not in (info.file_size, 0xFFFFFFFF):
                        raise ValueError(
                            f"{label}: ZIP entry {info.orig_filename!r} local-header uncompressed size "
                            f"({lfh_uncomp_size}) differs from central-directory ({info.file_size})"
                        )
                    if lfh_comp_size == 0xFFFFFFFF or lfh_uncomp_size == 0xFFFFFFFF or z64_sizes is not None:
                        if z64_sizes != (info.file_size, info.compress_size):
                            raise ValueError(
                                f"{label}: ZIP entry {info.orig_filename!r} local-header 0x0001 Zip64 sizes "
                                f"{z64_sizes!r} differ from central-directory ({info.file_size}, {info.compress_size})"
                            )
                else:
                    if lfh_crc not in (0, info.CRC):
                        raise ValueError(
                            f"{label}: ZIP entry {info.orig_filename!r} streaming local-header CRC-32 "
                            f"({lfh_crc:#010x}) must be 0 or match central-directory ({info.CRC:#010x})"
                        )
                    if lfh_comp_size not in (0, info.compress_size, 0xFFFFFFFF):
                        raise ValueError(
                            f"{label}: ZIP entry {info.orig_filename!r} streaming local-header compressed size "
                            f"({lfh_comp_size}) must be 0, sentinel, or match central-directory ({info.compress_size})"
                        )
                    if lfh_uncomp_size not in (0, info.file_size, 0xFFFFFFFF):
                        raise ValueError(
                            f"{label}: ZIP entry {info.orig_filename!r} streaming local-header uncompressed size "
                            f"({lfh_uncomp_size}) must be 0, sentinel, or match central-directory ({info.file_size})"
                        )
                    if lfh_comp_size == 0xFFFFFFFF or lfh_uncomp_size == 0xFFFFFFFF:
                        if z64_sizes is None:
                            raise ValueError(
                                f"{label}: ZIP entry {info.orig_filename!r} streaming local-header uses 0xFFFFFFFF "
                                "sentinel without a 0x0001 Zip64 extra field"
                            )
                        if z64_sizes not in ((0, 0), (info.file_size, info.compress_size)):
                            raise ValueError(
                                f"{label}: ZIP entry {info.orig_filename!r} streaming local-header 0x0001 Zip64 "
                                f"sizes {z64_sizes!r} must be (0, 0) or match central-directory "
                                f"({info.file_size}, {info.compress_size})"
                            )
                    elif z64_sizes is not None:
                        if z64_sizes not in ((0, 0), (info.file_size, info.compress_size)):
                            raise ValueError(
                                f"{label}: ZIP entry {info.orig_filename!r} streaming local-header 0x0001 Zip64 "
                                f"sizes {z64_sizes!r} must be (0, 0) or match central-directory "
                                f"({info.file_size}, {info.compress_size})"
                            )

                comp_start = info.header_offset + 30 + lfh_name_len + lfh_extra_len
                _verify_entry_stream_exact(zf.fp, comp_start, info, label)
            finally:
                zf.fp.seek(saved_pos)
        elif info.compress_type == zipfile.ZIP_STORED and info.compress_size != info.file_size:
            raise ValueError(
                f"{label}: ZIP_STORED entry {info.orig_filename!r} has mismatched sizes "
                f"(compress_size={info.compress_size} != file_size={info.file_size})"
            )

        name = info.filename
        if name in seen_exact:
            raise ValueError(f"{label}: duplicate ZIP entry {name!r}")
        seen_exact.add(name)

        if not name or name.startswith("/") or "\\" in name or ":" in name:
            raise ValueError(f"{label}: unsafe OPC/ZIP entry path {name!r}")
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in name):
            raise ValueError(f"{label}: non-ASCII or control char in ZIP entry name {name!r}")

        is_dir = name.endswith("/")
        parts = name.split("/")
        check_parts = parts[:-1] if is_dir else parts
        if not check_parts:
            raise ValueError(f"{label}: empty OPC/ZIP entry path {name!r}")
        if ".." in check_parts or "." in check_parts:
            raise ValueError(f"{label}: unsafe relative/traversal path component in ZIP entry {name!r}")
        if "" in check_parts:
            raise ValueError(f"{label}: empty path segment in ZIP entry {name!r}")
        if any(part.endswith((".", " ")) for part in check_parts):
            raise ValueError(
                f"{label}: OPC/ZIP path segment with trailing dot or space is forbidden "
                f"(ECMA-376 M1.9 / Windows NTFS collision): {name!r}"
            )

        if is_dir:
            if info.file_size != 0 or len(_read_zip_member(zf, info, label)) != 0:
                raise ValueError(f"{label}: directory ZIP entry {name!r} carries non-zero payload")
            if name.rstrip("/").lower().endswith(FORBIDDEN_KEY_EXTS) or any(
                part.lower().endswith(FORBIDDEN_KEY_EXTS) for part in check_parts
            ):
                raise ValueError(f"{label}: forbidden signing/key directory entry {name!r}")

        if flat_root_only and ("/" in name):
            raise ValueError(f"{label}: nested directory entry {name!r} not permitted (flat root files only)")

        lower_name = name.lower()
        if lower_name in seen_lower:
            raise ValueError(
                f"{label}: case-insensitive duplicate OPC/ZIP entry {name!r} "
                f"(conflicts with {seen_lower[lower_name]!r})"
            )
        seen_lower[lower_name] = name

        lower_parts = [p.lower() for p in check_parts]
        for depth in range(1, len(lower_parts)):
            parent_dir = "/".join(lower_parts[:depth])
            parent_exact = "/".join(check_parts[:depth])
            if parent_dir in seen_files:
                raise ValueError(
                    f"{label}: colliding OPC/ZIP file/directory entry {name!r} "
                    f"(conflicts with file {seen_files[parent_dir]!r})"
                )
            prev_exact = seen_dir_case.get(parent_dir)
            if prev_exact is not None and prev_exact != parent_exact:
                raise ValueError(
                    f"{label}: case-colliding directory prefix {parent_exact!r} vs {prev_exact!r}"
                )
            seen_dir_case[parent_dir] = parent_exact
            seen_dirs.setdefault(parent_dir, name)

        norm_key = "/".join(lower_parts)
        exact_key = "/".join(check_parts)
        if is_dir:
            if norm_key in seen_files:
                raise ValueError(
                    f"{label}: colliding OPC/ZIP file/directory entry {name!r} "
                    f"(conflicts with file {seen_files[norm_key]!r})"
                )
            prev_exact = seen_dir_case.get(norm_key)
            if prev_exact is not None and prev_exact != exact_key:
                raise ValueError(
                    f"{label}: case-colliding directory prefix {exact_key!r} vs {prev_exact!r}"
                )
            seen_dir_case[norm_key] = exact_key
            seen_dirs.setdefault(norm_key, name)
        else:
            if norm_key in seen_dirs:
                raise ValueError(
                    f"{label}: colliding OPC/ZIP file/directory entry {name!r} "
                    f"(conflicts with directory prefix from {seen_dirs[norm_key]!r})"
                )
            seen_files[norm_key] = name

    for critical_path in case_sensitive_unique_paths:
        matches = [n for n in raw_names if n.lower() == critical_path.lower()]
        if len(matches) > 1:
            raise ValueError(
                f"{label}: case-insensitive duplicate critical manifest entry {critical_path!r}"
            )
    return raw_names


def _canonicalize_manifest_for_parity(elem: ET.Element) -> tuple[object, ...]:
    """Return a canonical tree representation ignoring comments/whitespace and ONLY Identity/@ProcessorArchitecture."""
    attrs: list[tuple[str, str]] = []
    for k, v in sorted(elem.attrib.items()):
        if elem.tag == f"{APPX_NS}Identity" and k == "ProcessorArchitecture":
            continue
        attrs.append((k, v))
    text = (elem.text or "").strip()
    tail = (elem.tail or "").strip()
    children = tuple(_canonicalize_manifest_for_parity(child) for child in elem)
    return (elem.tag, tuple(attrs), text, tail, children)


def _parse_resource_directory(
    data: bytes, rsrc_off: int, rsrc_size: int
) -> tuple[set[int], set[tuple[int, int]]]:
    """Parse 2 levels of PE DataDirectory[2] Resource Directory (Type ID -> Name ID)."""
    resource_types: set[int] = set()
    resource_ids: set[tuple[int, int]] = set()
    if rsrc_size < 16 or rsrc_off + 16 > len(data):
        return resource_types, resource_ids

    def read_dir_entries(dir_off: int) -> list[tuple[int, int]]:
        if dir_off + 16 > len(data):
            return []
        _, _, _, _, n_named, n_id = struct.unpack_from("<IIHHHH", data, dir_off)
        total = n_named + n_id
        entries: list[tuple[int, int]] = []
        pos = dir_off + 16
        for _ in range(total):
            if pos + 8 > len(data):
                break
            name_or_id, offset_to_data = struct.unpack_from("<II", data, pos)
            entries.append((name_or_id, offset_to_data))
            pos += 8
        return entries

    for type_raw, type_sub in read_dir_entries(rsrc_off):
        if (type_raw & 0x8000_0000) != 0:
            continue
        type_id = type_raw & 0xFFFF
        resource_types.add(type_id)
        if (type_sub & 0x8000_0000) == 0:
            continue
        lvl2_off = rsrc_off + (type_sub & 0x7FFF_FFFF)
        for name_raw, _ in read_dir_entries(lvl2_off):
            if (name_raw & 0x8000_0000) != 0:
                continue
            resource_ids.add((type_id, name_raw & 0xFFFF))

    return resource_types, resource_ids


def parse_pe64_bytes(data: bytes, label: str) -> dict[str, object]:
    """Parse PE32+ headers, security flags, Debug Dir CET_COMPAT, Load Config, imports, exports, and resources."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError(f"{label}: missing MZ header")

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError(f"{label}: missing PE signature")

        coff_off = e_lfanew + 4
        machine, num_sections, _, _, _, opt_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, coff_off
        )
        opt_off = coff_off + 20
        if opt_off + 2 > len(data):
            raise ValueError(f"{label}: truncated PE optional header")
        magic = struct.unpack_from("<H", data, opt_off)[0]
        if magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            raise ValueError(f"{label}: expected PE32+ (0x20B), got {magic:#x}")
        if opt_size < 112 or opt_off + opt_size > len(data):
            raise ValueError(f"{label}: truncated PE32+ optional header")

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
            raise ValueError(f"{label}: truncated PE32+ section table")
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

        # Resource Directory (DataDirectory[2]).
        rsrc_rva, rsrc_size = data_dir(2)
        rsrc_off = rva_to_off(rsrc_rva)
        resource_types: set[int] = set()
        resource_ids: set[tuple[int, int]] = set()
        if rsrc_off is not None and rsrc_size >= 16:
            resource_types, resource_ids = _parse_resource_directory(data, rsrc_off, rsrc_size)

        clr_rva, clr_size = data_dir(14)
    except struct.error as exc:
        raise ValueError(f"{label}: truncated or malformed PE32+ binary: {exc}") from exc

    return {
        "machine": machine,
        "characteristics": characteristics,
        "dll_chars": dll_chars,
        "ex_dll_chars": ex_dll_chars,
        "dependent_load_flags": dependent_load_flags,
        "imports": imports,
        "delay_imports": delay_imports,
        "exports": exports,
        "resource_types": resource_types,
        "resource_ids": resource_ids,
        "clr_header": (clr_rva, clr_size),
    }


def parse_pe64(path: Path) -> dict[str, object]:
    return parse_pe64_bytes(path.read_bytes(), path.name)


def verify_manifest_extensions(manifest_root: ET.Element) -> None:
    """Validate Explorer COM, FileExplorerContextMenus, Toast Activation, runFullTrust, and scoped FirewallRules."""
    appx_ns = APPX_NS
    uap_ns = "{http://schemas.microsoft.com/appx/manifest/uap/windows10}"
    com_ns = "{http://schemas.microsoft.com/appx/manifest/com/windows10}"
    desktop_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10}"
    desktop2_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/2}"
    desktop4_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/4}"
    desktop5_ns = "{http://schemas.microsoft.com/appx/manifest/desktop/windows10/5}"
    rescap_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities}"

    if manifest_root.tag != f"{appx_ns}Package":
        raise ValueError(f"AppxManifest.xml root must be <Package>, got {manifest_root.tag!r}")

    # 0a. <Properties> exact cardinality + non-empty DisplayName & PublisherDisplayName.
    doc_props = manifest_root.findall(f".//{appx_ns}Properties")
    direct_props = manifest_root.findall(f"{appx_ns}Properties")
    if len(doc_props) != 1 or len(direct_props) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 top-level <Properties> element "
            f"(doc={len(doc_props)}, direct={len(direct_props)})"
        )
    props_el = direct_props[0]
    for prop_tag in ("DisplayName", "PublisherDisplayName"):
        doc_tags = manifest_root.findall(f".//{appx_ns}{prop_tag}")
        direct_tags = props_el.findall(f"{appx_ns}{prop_tag}")
        if len(doc_tags) != 1 or len(direct_tags) != 1:
            raise ValueError(
                f"AppxManifest.xml <Properties> must contain exactly 1 <{prop_tag}> "
                f"(doc={len(doc_tags)}, direct={len(direct_tags)})"
            )
        if not (direct_tags[0].text or "").strip():
            raise ValueError(f"AppxManifest.xml <Properties>/<{prop_tag}> must be non-empty")

    # 0b. <Dependencies> exact Windows.Desktop >= 10.0.19041.0 and Microsoft.WindowsAppRuntime.1.8.
    doc_deps = manifest_root.findall(f".//{appx_ns}Dependencies")
    direct_deps = manifest_root.findall(f"{appx_ns}Dependencies")
    if len(doc_deps) != 1 or len(direct_deps) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 top-level <Dependencies> element "
            f"(doc={len(doc_deps)}, direct={len(direct_deps)})"
        )
    deps_el = direct_deps[0]
    doc_tdfs = manifest_root.findall(f".//{appx_ns}TargetDeviceFamily")
    direct_tdfs = deps_el.findall(f"{appx_ns}TargetDeviceFamily")
    if len(doc_tdfs) != 1 or len(direct_tdfs) != 1:
        raise ValueError(
            "AppxManifest.xml <Dependencies> must contain exactly 1 <TargetDeviceFamily> "
            f"(doc={len(doc_tdfs)}, direct={len(direct_tdfs)})"
        )
    tdf = direct_tdfs[0]
    if tdf.attrib.get("Name") != "Windows.Desktop" or tdf.attrib.get("MinVersion") != "10.0.19041.0":
        raise ValueError(
            "AppxManifest.xml <TargetDeviceFamily> must specify Name='Windows.Desktop' "
            f"MinVersion='10.0.19041.0', got {tdf.attrib!r}"
        )
    doc_pkg_deps = manifest_root.findall(f".//{appx_ns}PackageDependency")
    direct_pkg_deps = deps_el.findall(f"{appx_ns}PackageDependency")
    if len(doc_pkg_deps) != len(direct_pkg_deps):
        raise ValueError(
            "AppxManifest.xml contains <PackageDependency> outside top-level <Dependencies>"
        )
    winappsdk_deps = [
        dep for dep in direct_pkg_deps if dep.attrib.get("Name") == "Microsoft.WindowsAppRuntime.1.8"
    ]
    if (
        len(winappsdk_deps) != 1
        or not winappsdk_deps[0].attrib.get("MinVersion", "").strip()
        or not winappsdk_deps[0].attrib.get("Publisher", "").strip()
    ):
        raise ValueError(
            "AppxManifest.xml <Dependencies> must declare exactly 1 valid "
            "<PackageDependency Name='Microsoft.WindowsAppRuntime.1.8' ...>"
        )

    # 0c. <Resources> exact 35 canonical languages (no duplicates, missing, or extras).
    doc_res = manifest_root.findall(f".//{appx_ns}Resources")
    direct_res = manifest_root.findall(f"{appx_ns}Resources")
    if len(doc_res) != 1 or len(direct_res) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 top-level <Resources> element "
            f"(doc={len(doc_res)}, direct={len(direct_res)})"
        )
    res_el = direct_res[0]
    res_children = list(res_el)
    if any(child.tag != f"{appx_ns}Resource" for child in res_children):
        raise ValueError("AppxManifest.xml <Resources> contains unexpected child element(s)")
    res_langs = [child.attrib.get("Language", "") for child in res_children]
    if len(res_langs) != len(EXPECTED_MANIFEST_LANGUAGES) or set(res_langs) != EXPECTED_MANIFEST_LANGUAGES:
        missing_langs = sorted(EXPECTED_MANIFEST_LANGUAGES - set(res_langs))
        extra_langs = sorted(set(res_langs) - EXPECTED_MANIFEST_LANGUAGES)
        raise ValueError(
            "AppxManifest.xml <Resources> must declare the exact 35 canonical TotalDrop languages "
            f"(count={len(res_langs)}, missing={missing_langs[:8]}, extra={extra_langs[:8]})"
        )

    doc_applications = manifest_root.findall(f".//{appx_ns}Applications")
    direct_applications = manifest_root.findall(f"{appx_ns}Applications")
    if len(doc_applications) != 1 or len(direct_applications) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 top-level <Applications> element "
            f"(doc={len(doc_applications)}, direct={len(direct_applications)})"
        )

    doc_apps = manifest_root.findall(f".//{appx_ns}Application")
    direct_apps = manifest_root.findall(f"{appx_ns}Applications/{appx_ns}Application")
    if len(doc_apps) != 1 or len(direct_apps) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 <Application> under <Applications> "
            f"(doc={len(doc_apps)}, direct={len(direct_apps)})"
        )
    app = direct_apps[0]
    if app.attrib.get("Executable") != "totaldrop-winui.exe":
        raise ValueError(
            f"AppxManifest.xml <Application> Executable mismatch: {app.attrib.get('Executable')!r}"
        )

    app_exts = app.findall(f"{appx_ns}Extensions")
    if len(app_exts) != 1:
        raise ValueError(
            f"AppxManifest.xml <Application> must contain exactly 1 <Extensions>, found {len(app_exts)}"
        )
    pkg_exts = manifest_root.findall(f"{appx_ns}Extensions")
    if len(pkg_exts) != 1:
        raise ValueError(
            f"AppxManifest.xml <Package> must contain exactly 1 <Extensions>, found {len(pkg_exts)}"
        )
    doc_exts = manifest_root.findall(f".//{appx_ns}Extensions")
    if len(doc_exts) != 2:
        raise ValueError(
            f"AppxManifest.xml must contain exactly 2 <Extensions> containers total, found {len(doc_exts)}"
        )
    app_ext = app_exts[0]
    pkg_ext = pkg_exts[0]

    allowed_app_ext_tags = {
        f"{uap_ns}Extension",
        f"{com_ns}Extension",
        f"{desktop4_ns}Extension",
        f"{desktop_ns}Extension",
    }
    unexpected_app_exts = [child.tag for child in app_ext if child.tag not in allowed_app_ext_tags]
    if unexpected_app_exts:
        raise ValueError(
            "AppxManifest.xml Applications/Application/Extensions contains unexpected extension(s): "
            f"{unexpected_app_exts!r}"
        )

    # 2. com:Extension (windows.comServer): exact 1 SurrogateServer (1 Class) + 1 ExeServer (1 Class).
    doc_com_exts = manifest_root.findall(f".//{com_ns}Extension")
    app_com_exts = app_ext.findall(f"{com_ns}Extension")
    if len(doc_com_exts) != 1 or len(app_com_exts) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <com:Extension> directly under "
            f"Applications/Application/Extensions (doc={len(doc_com_exts)}, app={len(app_com_exts)})"
        )
    com_ext = app_com_exts[0]
    if com_ext.attrib.get("Category") != "windows.comServer":
        raise ValueError(
            f"<com:Extension> Category must be 'windows.comServer', got {com_ext.attrib.get('Category')!r}"
        )

    doc_com_servers = manifest_root.findall(f".//{com_ns}ComServer")
    child_com_servers = com_ext.findall(f"{com_ns}ComServer")
    if len(doc_com_servers) != 1 or len(child_com_servers) != 1 or len(list(com_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml <com:Extension> must contain exactly 1 <com:ComServer> as its sole child "
            f"(doc={len(doc_com_servers)}, direct={len(child_com_servers)}, children={len(list(com_ext))})"
        )
    com_server = child_com_servers[0]
    com_children = list(com_server)
    if len(com_children) != 2:
        raise ValueError(
            "AppxManifest.xml <com:ComServer> must contain exactly 2 children "
            f"(1 ExeServer + 1 SurrogateServer), found {len(com_children)}"
        )
    if [child.tag for child in com_children] != [
        f"{com_ns}ExeServer",
        f"{com_ns}SurrogateServer",
    ]:
        raise ValueError(
            "AppxManifest.xml <com:ComServer> must declare <com:ExeServer> before "
            "<com:SurrogateServer> per ComManifestSchema.xsd CT_ComServer sequence"
        )

    doc_surrogates = manifest_root.findall(f".//{com_ns}SurrogateServer")
    child_surrogates = com_server.findall(f"{com_ns}SurrogateServer")
    if len(doc_surrogates) != 1 or len(child_surrogates) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <com:SurrogateServer> directly under <com:ComServer> "
            f"(doc={len(doc_surrogates)}, direct={len(child_surrogates)})"
        )
    surrogate = child_surrogates[0]
    surrogate_classes = surrogate.findall(f"{com_ns}Class")
    if len(list(surrogate)) != 1 or len(surrogate_classes) != 1:
        raise ValueError(
            "AppxManifest.xml <com:SurrogateServer> must contain exactly 1 <com:Class> as its sole child "
            f"(children={len(list(surrogate))}, classes={len(surrogate_classes)})"
        )
    explorer_cls = surrogate_classes[0]
    if len(list(explorer_cls)) != 0:
        raise ValueError("Explorer <com:Class> must not contain child elements")
    explorer_id = explorer_cls.attrib.get("Id", "")
    if not BARE_GUID_RE.fullmatch(explorer_id):
        raise ValueError(f"Explorer COM Class Id must be a bare GUID without braces, got {explorer_id!r}")
    if explorer_id.lower() != EXPECTED_EXPLORER_CLSID:
        raise ValueError(
            f"Explorer COM Class Id mismatch: {explorer_id!r} != {EXPECTED_EXPLORER_CLSID!r}"
        )
    if explorer_cls.attrib.get("Path") != "totaldrop_explorer_ext.dll":
        raise ValueError(f"Explorer COM Path mismatch: {explorer_cls.attrib.get('Path')!r}")
    if explorer_cls.attrib.get("ThreadingModel") != "STA":
        raise ValueError(
            f"Explorer COM ThreadingModel must be 'STA', got {explorer_cls.attrib.get('ThreadingModel')!r}"
        )

    doc_exe_servers = manifest_root.findall(f".//{com_ns}ExeServer")
    child_exe_servers = com_server.findall(f"{com_ns}ExeServer")
    if len(doc_exe_servers) != 1 or len(child_exe_servers) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <com:ExeServer> directly under <com:ComServer> "
            f"(doc={len(doc_exe_servers)}, direct={len(child_exe_servers)})"
        )
    exe_server = child_exe_servers[0]
    if exe_server.attrib.get("Executable") != "totaldrop-winui.exe":
        raise ValueError(f"Toast ExeServer Executable mismatch: {exe_server.attrib.get('Executable')!r}")
    if exe_server.attrib.get("Arguments") != "----AppNotificationActivated:":
        raise ValueError(f"Toast ExeServer Arguments mismatch: {exe_server.attrib.get('Arguments')!r}")
    exe_classes = exe_server.findall(f"{com_ns}Class")
    if len(list(exe_server)) != 1 or len(exe_classes) != 1:
        raise ValueError(
            "AppxManifest.xml <com:ExeServer> must contain exactly 1 <com:Class> as its sole child "
            f"(children={len(list(exe_server))}, classes={len(exe_classes)})"
        )
    toast_cls = exe_classes[0]
    if len(list(toast_cls)) != 0:
        raise ValueError("Toast ExeServer <com:Class> must not contain child elements")
    toast_cls_id = toast_cls.attrib.get("Id", "")
    if not BARE_GUID_RE.fullmatch(toast_cls_id):
        raise ValueError(f"Toast ExeServer Class Id must be a bare GUID without braces, got {toast_cls_id!r}")
    if toast_cls_id.lower() != EXPECTED_TOAST_CLSID:
        raise ValueError(
            f"Toast ExeServer Class Id mismatch: {toast_cls_id!r} != {EXPECTED_TOAST_CLSID!r}"
        )

    doc_com_classes = manifest_root.findall(f".//{com_ns}Class")
    if len(doc_com_classes) != 2:
        raise ValueError(
            f"AppxManifest.xml must declare exactly 2 <com:Class> elements total, found {len(doc_com_classes)}"
        )
    doc_com_all = [el for el in manifest_root.iter() if el.tag.startswith(com_ns)]
    if len(doc_com_all) != 6:
        raise ValueError(
            f"AppxManifest.xml contains unexpected com:* elements (expected 6 total, found {len(doc_com_all)})"
        )

    # 3. desktop4:Extension (windows.fileExplorerContextMenus): exact 2 ItemTypes (* and Directory), 1 Verb each.
    doc_d4_exts = manifest_root.findall(f".//{desktop4_ns}Extension")
    app_d4_exts = app_ext.findall(f"{desktop4_ns}Extension")
    if len(doc_d4_exts) != 1 or len(app_d4_exts) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <desktop4:Extension> directly under "
            f"Applications/Application/Extensions (doc={len(doc_d4_exts)}, app={len(app_d4_exts)})"
        )
    d4_ext = app_d4_exts[0]
    if d4_ext.attrib.get("Category") != "windows.fileExplorerContextMenus":
        raise ValueError(
            "<desktop4:Extension> Category must be 'windows.fileExplorerContextMenus', "
            f"got {d4_ext.attrib.get('Category')!r}"
        )
    doc_ctx_menus = manifest_root.findall(f".//{desktop4_ns}FileExplorerContextMenus")
    child_ctx_menus = d4_ext.findall(f"{desktop4_ns}FileExplorerContextMenus")
    if len(doc_ctx_menus) != 1 or len(child_ctx_menus) != 1 or len(list(d4_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml <desktop4:Extension> must contain exactly 1 <desktop4:FileExplorerContextMenus> "
            f"as its sole child (doc={len(doc_ctx_menus)}, direct={len(child_ctx_menus)}, children={len(list(d4_ext))})"
        )
    ctx_menus = child_ctx_menus[0]
    doc_item_types = manifest_root.findall(f".//{desktop5_ns}ItemType")
    child_item_types = ctx_menus.findall(f"{desktop5_ns}ItemType")
    if len(list(ctx_menus)) != 2 or len(doc_item_types) != 2 or len(child_item_types) != 2:
        raise ValueError(
            "AppxManifest.xml <desktop4:FileExplorerContextMenus> must contain exactly 2 <desktop5:ItemType> "
            f"children total (children={len(list(ctx_menus))}, doc={len(doc_item_types)}, direct={len(child_item_types)})"
        )
    seen_types: list[str | None] = [it.attrib.get("Type") for it in child_item_types]
    if set(seen_types) != {"*", "Directory"}:
        raise ValueError(
            f"<desktop5:ItemType> Type set must be exactly {{'*', 'Directory'}}, got {seen_types!r}"
        )
    verb_ids: set[str] = set()
    for item_type in child_item_types:
        verbs = item_type.findall(f"{desktop5_ns}Verb")
        if len(list(item_type)) != 1 or len(verbs) != 1:
            raise ValueError(
                f"<desktop5:ItemType Type={item_type.attrib.get('Type')!r}> must contain exactly 1 "
                f"<desktop5:Verb> as its sole child (children={len(list(item_type))}, verbs={len(verbs)})"
            )
        verb = verbs[0]
        if len(list(verb)) != 0:
            raise ValueError("<desktop5:Verb> must not contain child elements")
        verb_id = verb.attrib.get("Id", "")
        if not verb_id.strip():
            raise ValueError(
                f"<desktop5:Verb> under Type={item_type.attrib.get('Type')!r} must have a non-empty Id"
            )
        if verb_id in verb_ids:
            raise ValueError(f"Duplicate <desktop5:Verb> Id {verb_id!r}")
        verb_ids.add(verb_id)
        verb_clsid = verb.attrib.get("Clsid", "")
        if not BARE_GUID_RE.fullmatch(verb_clsid):
            raise ValueError(
                f"<desktop5:Verb> Clsid must be a bare GUID without braces, got {verb_clsid!r}"
            )
        if verb_clsid.lower() != EXPECTED_EXPLORER_CLSID:
            raise ValueError(
                f"<desktop5:Verb> Clsid mismatch: {verb_clsid!r} != {EXPECTED_EXPLORER_CLSID!r}"
            )

    doc_verbs = manifest_root.findall(f".//{desktop5_ns}Verb")
    if len(doc_verbs) != 2:
        raise ValueError(
            f"AppxManifest.xml must declare exactly 2 <desktop5:Verb> elements total, found {len(doc_verbs)}"
        )
    doc_d4_all = [el for el in manifest_root.iter() if el.tag.startswith(desktop4_ns)]
    if len(doc_d4_all) != 2:
        raise ValueError(
            f"AppxManifest.xml contains unexpected desktop4:* elements (expected 2 total, found {len(doc_d4_all)})"
        )
    doc_d5_all = [el for el in manifest_root.iter() if el.tag.startswith(desktop5_ns)]
    if len(doc_d5_all) != 4:
        raise ValueError(
            f"AppxManifest.xml contains unexpected desktop5:* elements (expected 4 total, found {len(doc_d5_all)})"
        )

    # 4. desktop:Extension (windows.toastNotificationActivation) matching com:ExeServer Class Id.
    doc_d_exts = manifest_root.findall(f".//{desktop_ns}Extension")
    app_d_exts = app_ext.findall(f"{desktop_ns}Extension")
    if len(doc_d_exts) != 1 or len(app_d_exts) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <desktop:Extension> directly under "
            f"Applications/Application/Extensions (doc={len(doc_d_exts)}, app={len(app_d_exts)})"
        )
    d_ext = app_d_exts[0]
    if d_ext.attrib.get("Category") != "windows.toastNotificationActivation":
        raise ValueError(
            "<desktop:Extension> Category must be 'windows.toastNotificationActivation', "
            f"got {d_ext.attrib.get('Category')!r}"
        )
    doc_toasts = manifest_root.findall(f".//{desktop_ns}ToastNotificationActivation")
    child_toasts = d_ext.findall(f"{desktop_ns}ToastNotificationActivation")
    if len(doc_toasts) != 1 or len(child_toasts) != 1 or len(list(d_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml <desktop:Extension> must contain exactly 1 <desktop:ToastNotificationActivation> "
            f"as its sole child (doc={len(doc_toasts)}, direct={len(child_toasts)}, children={len(list(d_ext))})"
        )
    toast_elem = child_toasts[0]
    if len(list(toast_elem)) != 0:
        raise ValueError("<desktop:ToastNotificationActivation> must not contain child elements")
    toast_guid = toast_elem.attrib.get("ToastActivatorCLSID", "")
    if not BARE_GUID_RE.fullmatch(toast_guid):
        raise ValueError(f"ToastActivatorCLSID must be a bare GUID without braces, got {toast_guid!r}")
    if toast_guid.lower() != EXPECTED_TOAST_CLSID:
        raise ValueError(f"ToastActivatorCLSID mismatch: {toast_guid!r} != {EXPECTED_TOAST_CLSID!r}")
    if toast_guid.lower() == EXPECTED_EXPLORER_CLSID:
        raise ValueError("ToastActivatorCLSID must be distinct from Explorer COM CLSID")
    if toast_guid.lower() != toast_cls_id.lower():
        raise ValueError(
            f"ToastActivatorCLSID ({toast_guid!r}) must match ExeServer/Class/@Id ({toast_cls_id!r})"
        )
    doc_d_all = [el for el in manifest_root.iter() if el.tag.startswith(desktop_ns)]
    if len(doc_d_all) != 2:
        raise ValueError(
            f"AppxManifest.xml contains unexpected desktop:* elements (expected 2 total, found {len(doc_d_all)})"
        )

    # 5. Package-level desktop2:Extension (windows.firewallRules): exact 1 FirewallRules + 1 scoped Rule.
    doc_d2_exts = manifest_root.findall(f".//{desktop2_ns}Extension")
    pkg_d2_exts = pkg_ext.findall(f"{desktop2_ns}Extension")
    if len(doc_d2_exts) != 1 or len(pkg_d2_exts) != 1 or len(list(pkg_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml must declare exactly 1 <desktop2:Extension> as the sole child of "
            f"Package/Extensions (doc={len(doc_d2_exts)}, pkg={len(pkg_d2_exts)}, pkg_children={len(list(pkg_ext))})"
        )
    d2_ext = pkg_d2_exts[0]
    if d2_ext.attrib.get("Category") != "windows.firewallRules":
        raise ValueError(
            "<desktop2:Extension> Category must be 'windows.firewallRules', "
            f"got {d2_ext.attrib.get('Category')!r}"
        )
    doc_fw_rules = manifest_root.findall(f".//{desktop2_ns}FirewallRules")
    child_fw_rules = d2_ext.findall(f"{desktop2_ns}FirewallRules")
    if len(doc_fw_rules) != 1 or len(child_fw_rules) != 1 or len(list(d2_ext)) != 1:
        raise ValueError(
            "AppxManifest.xml <desktop2:Extension> must contain exactly 1 <desktop2:FirewallRules> "
            f"as its sole child (doc={len(doc_fw_rules)}, direct={len(child_fw_rules)}, children={len(list(d2_ext))})"
        )
    fw_rules = child_fw_rules[0]
    if fw_rules.attrib.get("Executable") != "totaldrop-winui.exe":
        raise ValueError(f"FirewallRules Executable mismatch: {fw_rules.attrib.get('Executable')!r}")
    doc_rules = manifest_root.findall(f".//{desktop2_ns}Rule")
    child_rules = fw_rules.findall(f"{desktop2_ns}Rule")
    if len(doc_rules) != 1 or len(child_rules) != 1 or len(list(fw_rules)) != 1:
        raise ValueError(
            "AppxManifest.xml <desktop2:FirewallRules> must contain exactly 1 <desktop2:Rule> "
            f"as its sole child (doc={len(doc_rules)}, direct={len(child_rules)}, children={len(list(fw_rules))})"
        )
    rule = child_rules[0]
    if len(list(rule)) != 0:
        raise ValueError("<desktop2:Rule> must not contain child elements")
    if (
        rule.attrib.get("Direction") != "in"
        or rule.attrib.get("IPProtocol") != "UDP"
        or rule.attrib.get("Profile") != "private"
    ):
        raise ValueError(
            "FirewallRule must be strictly Direction='in', IPProtocol='UDP', Profile='private'; "
            f"got {rule.attrib!r}"
        )
    doc_d2_all = [el for el in manifest_root.iter() if el.tag.startswith(desktop2_ns)]
    if len(doc_d2_all) != 3:
        raise ValueError(
            f"AppxManifest.xml contains unexpected desktop2:* elements (expected 3 total, found {len(doc_d2_all)})"
        )

    # 6. Restricted capability runFullTrust (sole rescap:Capability under Package/Capabilities).
    doc_caps = manifest_root.findall(f".//{appx_ns}Capabilities")
    direct_caps = manifest_root.findall(f"{appx_ns}Capabilities")
    if len(doc_caps) != 1 or len(direct_caps) != 1:
        raise ValueError(
            "AppxManifest.xml must contain exactly 1 top-level <Capabilities> element "
            f"(doc={len(doc_caps)}, direct={len(direct_caps)})"
        )
    caps = direct_caps[0]
    doc_rescaps = manifest_root.findall(f".//{rescap_ns}Capability")
    direct_rescaps = caps.findall(f"{rescap_ns}Capability")
    if (
        len(doc_rescaps) != 1
        or len(direct_rescaps) != 1
        or direct_rescaps[0].attrib.get("Name") != "runFullTrust"
    ):
        raise ValueError(
            'AppxManifest.xml must declare exactly 1 <rescap:Capability Name="runFullTrust" /> '
            "under Package/Capabilities"
        )


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
        "SettingsPage.xbf",
    )
    missing = [tok for tok in required_tokens if tok not in text]
    for qualifier in ("UNPLATED", "LIGHTUNPLATED"):
        if not re.search(rf"(?<![A-Z0-9]){qualifier}(?![A-Z0-9])", upper_text):
            missing.append(qualifier)
    if missing:
        raise ValueError(f"resources.pri dump missing expected entries: {missing}")

    for lang_marker in ('"EN"', '"TR"', '"AR"', '"JA"', '"ZH-HANS"', '"ZH-HANT"'):
        if lang_marker not in upper_text:
            raise ValueError(f"resources.pri dump missing locale candidate {lang_marker}")


def smoke_test_ffi_dll(dll_path: Path) -> None:
    """Invoke live C ABI exports in a short-lived child subprocess."""
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


def smoke_test_explorer_ext_dll(dll_path: Path) -> None:
    """Invoke live Win32 COM exports and ExtractIconExW(-101) in a short-lived child subprocess."""
    subprocess.run(
        [
            sys.executable,
            "-c",
            _COM_SMOKE_TEST_CHILD_SCRIPT,
            str(dll_path),
            EXPECTED_EXPLORER_CLSID,
        ],
        check=True,
    )


def _check_pe_common(label: str, pe: dict[str, object], expected_machine: int, arch: str, expect_dll: bool) -> None:
    if pe["machine"] != expected_machine:
        raise ValueError(f"{label}: expected machine {expected_machine:#x}, got {pe['machine']:#x}")
    chars = int(pe["characteristics"])  # type: ignore[arg-type]
    is_dll = (chars & IMAGE_FILE_DLL) != 0
    if is_dll != expect_dll:
        raise ValueError(f"{label}: IMAGE_FILE_DLL={is_dll}, expected {expect_dll}")
    dc = int(pe["dll_chars"])  # type: ignore[arg-type]
    for flag_name, flag_bit in (
        ("HIGH_ENTROPY_VA", IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA),
        ("DYNAMIC_BASE", IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE),
        ("NX_COMPAT", IMAGE_DLLCHARACTERISTICS_NX_COMPAT),
    ):
        if (dc & flag_bit) == 0:
            raise ValueError(f"{label}: missing PE hardening flag {flag_name} (DllCharacteristics={dc:#x})")
    if arch == "x64":
        ex_dc = int(pe["ex_dll_chars"])  # type: ignore[arg-type]
        if (ex_dc & IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT) == 0:
            raise ValueError(
                f"{label}: missing CET_COMPAT in Debug Directory Type=20 (ex_dll_chars={ex_dc:#x})"
            )


def _check_no_forbidden_crt(label: str, pe: dict[str, object]) -> None:
    all_imports = set(pe["imports"]) | set(pe["delay_imports"])  # type: ignore[arg-type]
    bad_crt = sorted(
        imp for imp in all_imports if any(imp.startswith(f.replace(".dll", "")) for f in FORBIDDEN_CRT_DLLS)
    )
    if bad_crt:
        raise ValueError(f"{label} links dynamic MSVC CRT DLL(s): {bad_crt}")


def verify_msix_archive(
    source: Path | bytes,
    label: str,
    *,
    arch: str,
    expected_version: str | None,
    expect_signed: bool,
    store_mode: bool,
    allow_test_identity: bool,
    pri_dump: Path | None = None,
    run_live_smoke: bool = True,
    require_live_smoke: bool = False,
) -> dict[str, object]:
    """Deep-verify a single-architecture .msix package (from disk Path or in-memory bytes)."""
    if isinstance(source, Path):
        if not source.is_file():
            raise ValueError(f"MSIX not found: {source}")
        raw_bytes = source.read_bytes()
    else:
        raw_bytes = source

    if len(raw_bytes) < 4 or raw_bytes[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a ZIP/OPC archive (magic={raw_bytes[:4]!r})")

    expected_machine = IMAGE_FILE_MACHINE_AMD64 if arch == "x64" else IMAGE_FILE_MACHINE_ARM64

    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
        raw_names = _check_opc_zip_entries(
            zf,
            label,
            flat_root_only=False,
            case_sensitive_unique_paths=("AppxManifest.xml",),
        )
        names = set(raw_names)
        required = {
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "resources.pri",
            "totaldrop-winui.exe",
            "totaldrop_windows_ffi.dll",
            "totaldrop_explorer_ext.dll",
            "App.xbf",
            "MainWindow.xbf",
            "Views/SendPage.xbf",
            "Views/ReceivePage.xbf",
            "Views/SettingsPage.xbf",
        }
        if expect_signed:
            required.add("AppxSignature.p7x")

        missing = sorted(required - names)
        if missing:
            raise ValueError(f"{label}: MSIX missing required entries: {missing}")

        if expect_signed and zf.getinfo("AppxSignature.p7x").file_size <= 0:
            raise ValueError(f"{label}: AppxSignature.p7x is empty")

        asset_entries = {n for n in names if n.lower().startswith("assets/") and not n.endswith("/")}
        expected_asset_entries = {f"Assets/{name}" for name in EXPECTED_ASSETS}
        if asset_entries != expected_asset_entries:
            missing_assets = sorted(expected_asset_entries - asset_entries)
            extra_assets = sorted(asset_entries - expected_asset_entries)
            raise ValueError(
                f"{label}: MSIX Assets/ mismatch (expected {len(expected_asset_entries)} canonical Kose assets; "
                f"missing={missing_assets[:8]}, unexpected={extra_assets[:8]})"
            )

        forbidden_entries = [
            n
            for n in raw_names
            if n.lower().endswith(".pdb")
            or n.lower().endswith(".resw")
            or n.lower().endswith(FORBIDDEN_KEY_EXTS)
            or (
                Path(n.replace("\\", "/")).name.lower().startswith("resources.")
                and n.lower().endswith(".pri")
                and n.lower() != "resources.pri"
            )
        ]
        if forbidden_entries:
            raise ValueError(f"{label}: forbidden staging/key artifacts packed in MSIX: {forbidden_entries}")

        for opc_xml_name in ("AppxBlockMap.xml", "[Content_Types].xml"):
            try:
                opc_xml_raw = _read_zip_member(zf, opc_xml_name, label).decode("utf-8", errors="strict")
                ET.fromstring(opc_xml_raw)
            except (UnicodeDecodeError, ET.ParseError) as exc:
                raise ValueError(f"{label}: invalid XML in {opc_xml_name}: {exc}") from exc

        manifest_raw = _read_zip_member(zf, "AppxManifest.xml", label).decode("utf-8", errors="strict")
        if UNSIGNED_PACKAGE_OID in manifest_raw.lower():
            raise ValueError(
                f"{label}: AppxManifest.xml contains forbidden unsigned-package OID {UNSIGNED_PACKAGE_OID}"
            )
        manifest_root = ET.fromstring(manifest_raw)

        doc_idents = manifest_root.findall(f".//{APPX_NS}Identity")
        direct_idents = manifest_root.findall(f"{APPX_NS}Identity")
        if len(doc_idents) != 1 or len(direct_idents) != 1:
            raise ValueError(
                f"{label}: AppxManifest.xml must declare exactly 1 top-level <Identity> "
                f"(doc={len(doc_idents)}, direct={len(direct_idents)})"
            )
        ident = direct_idents[0]
        actual_arch = ident.attrib.get("ProcessorArchitecture", "")
        if actual_arch != arch:
            raise ValueError(f"{label}: AppxManifest arch mismatch: {actual_arch!r} != {arch!r}")

        ident_name = ident.attrib.get("Name", "")
        ident_pub = ident.attrib.get("Publisher", "")
        ident_ver = ident.attrib.get("Version", "")
        _validate_identity_store_policy(
            ident_name,
            ident_pub,
            ident_ver,
            f"{label} AppxManifest.xml",
            expected_version=expected_version,
            store_mode=store_mode,
            allow_test_identity=allow_test_identity,
        )
        verify_manifest_extensions(manifest_root)

        ffi_bytes = _read_zip_member(zf, "totaldrop_windows_ffi.dll", label)
        ext_bytes = _read_zip_member(zf, "totaldrop_explorer_ext.dll", label)
        exe_bytes = _read_zip_member(zf, "totaldrop-winui.exe", label)

        ffi_pe = parse_pe64_bytes(ffi_bytes, f"{label}:totaldrop_windows_ffi.dll")
        ext_pe = parse_pe64_bytes(ext_bytes, f"{label}:totaldrop_explorer_ext.dll")
        exe_pe = parse_pe64_bytes(exe_bytes, f"{label}:totaldrop-winui.exe")

        _check_pe_common(f"{label}:totaldrop_windows_ffi.dll", ffi_pe, expected_machine, arch, expect_dll=True)
        _check_pe_common(f"{label}:totaldrop_explorer_ext.dll", ext_pe, expected_machine, arch, expect_dll=True)
        _check_pe_common(f"{label}:totaldrop-winui.exe", exe_pe, expected_machine, arch, expect_dll=False)

        for dll_label, dll_pe in (
            (f"{label}:totaldrop_windows_ffi.dll", ffi_pe),
            (f"{label}:totaldrop_explorer_ext.dll", ext_pe),
        ):
            dep_flags = dll_pe["dependent_load_flags"]
            if not isinstance(dep_flags, int) or (dep_flags & LOAD_LIBRARY_SEARCH_SYSTEM32) == 0:
                raise ValueError(f"{dll_label}: missing DependentLoadFlags 0x800 (got {dep_flags!r})")
            _check_no_forbidden_crt(dll_label, dll_pe)

        _check_no_forbidden_crt(f"{label}:totaldrop-winui.exe", exe_pe)

        ffi_exports = set(ffi_pe["exports"])  # type: ignore[arg-type]
        missing_exports = [sym for sym in REQUIRED_FFI_EXPORTS if sym not in ffi_exports]
        if missing_exports:
            raise ValueError(f"{label}: totaldrop_windows_ffi.dll missing C ABI exports: {missing_exports}")

        ext_exports = set(ext_pe["exports"])  # type: ignore[arg-type]
        missing_ext_exports = [sym for sym in REQUIRED_EXPLORER_EXT_EXPORTS if sym not in ext_exports]
        if missing_ext_exports:
            raise ValueError(
                f"{label}: totaldrop_explorer_ext.dll missing COM exports: {missing_ext_exports}"
            )
        ext_rsrc_types = set(ext_pe["resource_types"])  # type: ignore[arg-type]
        ext_rsrc_ids = set(ext_pe["resource_ids"])  # type: ignore[arg-type]
        if (RT_GROUP_ICON, EXPLORER_ICON_RESOURCE_ID) not in ext_rsrc_ids or RT_ICON not in ext_rsrc_types:
            raise ValueError(
                f"{label}: totaldrop_explorer_ext.dll missing embedded Win32 icon resource ID 101 "
                f"(types={sorted(ext_rsrc_types)}, ids={sorted(ext_rsrc_ids)})"
            )

        if exe_pe["clr_header"] != (0, 0):
            raise ValueError(
                f"{label}: totaldrop-winui.exe has non-zero CLR header {exe_pe['clr_header']} (not Native AOT)"
            )
        exe_imports = set(exe_pe["imports"]) | set(exe_pe["delay_imports"])  # type: ignore[arg-type]
        bad_clr = sorted(imp for imp in exe_imports if imp in FORBIDDEN_CLR_HOST_DLLS)
        if bad_clr:
            raise ValueError(f"{label}: totaldrop-winui.exe imports CLR host DLL(s): {bad_clr}")
        exe_rsrc_types = set(exe_pe["resource_types"])  # type: ignore[arg-type]
        if RT_GROUP_ICON not in exe_rsrc_types or RT_ICON not in exe_rsrc_types:
            raise ValueError(
                f"{label}: totaldrop-winui.exe missing embedded application icon resources "
                f"(types={sorted(exe_rsrc_types)})"
            )

        # Scan every .dll and .exe entry in the MSIX for packed CRT/CLR binaries and cross-arch PE contamination.
        core_pe_entries = {"totaldrop-winui.exe", "totaldrop_windows_ffi.dll", "totaldrop_explorer_ext.dll"}
        for entry_name in raw_names:
            if entry_name.endswith("/"):
                continue
            if not entry_name.lower().endswith((".dll", ".exe")):
                continue
            base_lower = Path(entry_name).name.lower()
            if base_lower in FORBIDDEN_CLR_HOST_DLLS:
                raise ValueError(f"{label}: forbidden CLR host binary packed in MSIX: {entry_name!r}")
            if any(base_lower.startswith(f.replace(".dll", "")) for f in FORBIDDEN_CRT_DLLS):
                raise ValueError(f"{label}: forbidden dynamic MSVC CRT binary packed in MSIX: {entry_name!r}")
            if entry_name not in core_pe_entries:
                extra_pe = parse_pe64_bytes(_read_zip_member(zf, entry_name, label), f"{label}:{entry_name}")
                if extra_pe["machine"] != expected_machine:
                    raise ValueError(
                        f"{label}:{entry_name}: expected machine {expected_machine:#x}, got {extra_pe['machine']:#x}"
                    )

        if run_live_smoke:
            if sys.platform == "win32":
                host_arch = _python_host_arch()
                if host_arch == arch:
                    with tempfile.TemporaryDirectory(prefix="totaldrop-msix-smoke-") as tmp:
                        tmp_dir = Path(tmp)
                        ffi_path = tmp_dir / "totaldrop_windows_ffi.dll"
                        ext_path = tmp_dir / "totaldrop_explorer_ext.dll"
                        ffi_path.write_bytes(ffi_bytes)
                        ext_path.write_bytes(ext_bytes)
                        smoke_test_ffi_dll(ffi_path)
                        smoke_test_explorer_ext_dll(ext_path)
                elif require_live_smoke:
                    raise ValueError(
                        f"{label}: --require-live-smoke failed because host Python arch={host_arch!r} "
                        f"does not match package arch={arch!r}"
                    )
                else:
                    print(
                        f"note: skipping live ctypes smoke test for {label} (arch={arch}) on host Python arch={host_arch}; "
                        "all static PE32+, export, resource, and manifest checks passed."
                    )
            elif require_live_smoke:
                raise ValueError(
                    f"{label}: --require-live-smoke requires native Windows execution "
                    f"(current platform={sys.platform!r})"
                )

    if pri_dump is not None:
        verify_pri_dump(pri_dump)

    return {
        "arch": arch,
        "name": ident_name,
        "publisher": ident_pub,
        "version": ident_ver,
        "manifest_root": manifest_root,
        "size_bytes": len(raw_bytes),
    }


def verify_msixbundle_archive(
    source: Path | bytes,
    label: str,
    *,
    expected_version: str | None,
    expect_signed: bool,
    store_mode: bool,
    allow_test_identity: bool,
    run_live_smoke: bool = True,
    require_live_smoke: bool = False,
) -> dict[str, object]:
    """Deep-verify a unified dual-arch (x64 + arm64) .msixbundle archive."""
    if isinstance(source, Path):
        if not source.is_file():
            raise ValueError(f"MSIX bundle not found: {source}")
        raw_bytes = source.read_bytes()
    else:
        raw_bytes = source

    if len(raw_bytes) < 4 or raw_bytes[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a ZIP/OPC .msixbundle archive (magic={raw_bytes[:4]!r})")

    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
        raw_names = _check_opc_zip_entries(
            zf,
            label,
            flat_root_only=False,
            case_sensitive_unique_paths=("AppxMetadata/AppxBundleManifest.xml",),
        )
        names = set(raw_names)
        required = {
            "AppxMetadata/AppxBundleManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
        }
        if expect_signed:
            required.add("AppxSignature.p7x")
        missing = sorted(required - names)
        if missing:
            raise ValueError(f"{label}: .msixbundle missing required OPC entries: {missing}")
        if expect_signed and zf.getinfo("AppxSignature.p7x").file_size <= 0:
            raise ValueError(f"{label}: AppxSignature.p7x is empty")

        forbidden_bundle_exts = FORBIDDEN_KEY_EXTS + (".pdb", ".resw")
        bad_entries = [n for n in raw_names if n.lower().endswith(forbidden_bundle_exts)]
        if bad_entries:
            raise ValueError(f"{label}: forbidden key/symbol/staging files inside .msixbundle: {bad_entries}")

        for opc_xml_name in ("AppxBlockMap.xml", "[Content_Types].xml"):
            try:
                opc_xml_raw = _read_zip_member(zf, opc_xml_name, label).decode("utf-8", errors="strict")
                ET.fromstring(opc_xml_raw)
            except (UnicodeDecodeError, ET.ParseError) as exc:
                raise ValueError(f"{label}: invalid XML in {opc_xml_name}: {exc}") from exc

        manifest_raw = _read_zip_member(zf, "AppxMetadata/AppxBundleManifest.xml", label).decode(
            "utf-8", errors="strict"
        )
        if UNSIGNED_PACKAGE_OID in manifest_raw.lower():
            raise ValueError(
                f"{label}: AppxBundleManifest.xml contains forbidden unsigned-package OID {UNSIGNED_PACKAGE_OID}"
            )
        bundle_root = ET.fromstring(manifest_raw)
        if bundle_root.tag != f"{BUNDLE_NS}Bundle":
            raise ValueError(
                f"{label}: AppxBundleManifest.xml root must be <Bundle>, got {bundle_root.tag!r}"
            )

        doc_idents = bundle_root.findall(f".//{BUNDLE_NS}Identity")
        direct_idents = bundle_root.findall(f"{BUNDLE_NS}Identity")
        if len(doc_idents) != 1 or len(direct_idents) != 1:
            raise ValueError(
                f"{label}: AppxBundleManifest.xml must declare exactly 1 top-level <Identity> "
                f"(doc={len(doc_idents)}, direct={len(direct_idents)})"
            )
        b_ident = direct_idents[0]
        b_name = b_ident.attrib.get("Name", "")
        b_pub = b_ident.attrib.get("Publisher", "")
        b_ver = b_ident.attrib.get("Version", "")
        _validate_identity_store_policy(
            b_name,
            b_pub,
            b_ver,
            f"{label} AppxBundleManifest.xml",
            expected_version=expected_version,
            store_mode=store_mode,
            allow_test_identity=allow_test_identity,
        )

        doc_pkgs_containers = bundle_root.findall(f".//{BUNDLE_NS}Packages")
        direct_pkgs_containers = bundle_root.findall(f"{BUNDLE_NS}Packages")
        if len(doc_pkgs_containers) != 1 or len(direct_pkgs_containers) != 1:
            raise ValueError(
                f"{label}: AppxBundleManifest.xml must declare exactly 1 top-level <Packages> "
                f"(doc={len(doc_pkgs_containers)}, direct={len(direct_pkgs_containers)})"
            )
        pkgs_container = direct_pkgs_containers[0]
        pkg_children = list(pkgs_container)
        unexpected_children = [el.tag for el in pkg_children if el.tag != f"{BUNDLE_NS}Package"]
        if unexpected_children:
            raise ValueError(
                f"{label}: <Packages> contains unexpected child elements: {unexpected_children!r}"
            )

        app_packages_by_arch: dict[str, tuple[str, str]] = {}
        referenced_files: set[str] = set()
        for pkg in pkg_children:
            pkg_type = pkg.attrib.get("Type", "")
            pkg_arch = pkg.attrib.get("Architecture", "")
            pkg_ver = pkg.attrib.get("Version", "")
            pkg_file = pkg.attrib.get("FileName", "")

            if pkg_arch.lower() == "x86":
                raise ValueError(
                    f"{label}: forbidden 32-bit 'x86' architecture slice found in AppxBundleManifest.xml (ADR 0016)"
                )
            if pkg_type != "application":
                raise ValueError(
                    f"{label}: unexpected bundle <Package Type={pkg_type!r}> (expected 'application' slices only)"
                )
            if pkg_arch not in ("x64", "arm64"):
                raise ValueError(
                    f"{label}: unsupported bundle <Package Architecture={pkg_arch!r}> (expected 'x64' or 'arm64')"
                )
            if pkg_arch in app_packages_by_arch:
                raise ValueError(f"{label}: duplicate bundle <Package> slice for Architecture={pkg_arch!r}")
            if pkg_ver != b_ver:
                raise ValueError(
                    f"{label}: <Package Architecture={pkg_arch!r}> Version={pkg_ver!r} != bundle Version={b_ver!r}"
                )
            if (
                not pkg_file
                or "/" in pkg_file
                or "\\" in pkg_file
                or not pkg_file.lower().endswith(".msix")
                or pkg_file not in names
            ):
                raise ValueError(
                    f"{label}: <Package Architecture={pkg_arch!r}> FileName={pkg_file!r} "
                    "must be a flat root .msix entry present in bundle"
                )
            app_packages_by_arch[pkg_arch] = (pkg_file, pkg_ver)
            referenced_files.add(pkg_file)

        missing_arches = sorted({"x64", "arm64"} - set(app_packages_by_arch))
        if missing_arches:
            raise ValueError(
                f"{label}: .msixbundle missing required architecture slice(s): {missing_arches} "
                f"(present={sorted(app_packages_by_arch)})"
            )

        unreferenced_msix = sorted(
            n for n in raw_names if n.lower().endswith((".msix", ".appx")) and n not in referenced_files
        )
        if unreferenced_msix:
            raise ValueError(
                f"{label}: unreferenced .msix/.appx entries inside .msixbundle: {unreferenced_msix}"
            )

        allowed_bundle_files = referenced_files | {
            "AppxMetadata/AppxBundleManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "AppxSignature.p7x",
            "AppxMetadata/CodeIntegrity.cat",
        }
        unexpected_bundle_entries = sorted(
            n
            for n in raw_names
            if (n.endswith("/") and n != "AppxMetadata/")
            or (not n.endswith("/") and n not in allowed_bundle_files)
        )
        if unexpected_bundle_entries:
            raise ValueError(
                f"{label}: unexpected/unreferenced entries inside .msixbundle: {unexpected_bundle_entries}"
            )

        inner_results: dict[str, dict[str, object]] = {}
        for arch in ("x64", "arm64"):
            pkg_file, _ = app_packages_by_arch[arch]
            inner_bytes = _read_zip_member(zf, pkg_file, label)
            res = verify_msix_archive(
                inner_bytes,
                f"{label}/{pkg_file}",
                arch=arch,
                expected_version=b_ver,
                expect_signed=False,
                store_mode=store_mode,
                allow_test_identity=allow_test_identity,
                run_live_smoke=run_live_smoke,
                require_live_smoke=require_live_smoke,
            )
            if res["name"] != b_name:
                raise ValueError(
                    f"{label}/{pkg_file}: inner Identity/@Name {res['name']!r} != bundle {b_name!r}"
                )
            if res["publisher"] != b_pub:
                raise ValueError(
                    f"{label}/{pkg_file}: inner Identity/@Publisher {res['publisher']!r} != bundle {b_pub!r}"
                )
            if res["version"] != b_ver:
                raise ValueError(
                    f"{label}/{pkg_file}: inner Identity/@Version {res['version']!r} != bundle {b_ver!r}"
                )
            inner_results[arch] = res

        # Cross-arch canonical XML parity across Properties, Dependencies, 35 Resources, Extensions, Capabilities.
        x64_canon = _canonicalize_manifest_for_parity(inner_results["x64"]["manifest_root"])  # type: ignore[arg-type]
        arm64_canon = _canonicalize_manifest_for_parity(inner_results["arm64"]["manifest_root"])  # type: ignore[arg-type]
        if x64_canon != arm64_canon:
            raise ValueError(
                f"{label}: x64 and arm64 inner AppxManifest.xml files diverge beyond Identity/@ProcessorArchitecture"
            )

    return {
        "name": b_name,
        "publisher": b_pub,
        "version": b_ver,
        "arches": ("x64", "arm64"),
        "package_files": {arch: pkg_file for arch, (pkg_file, _) in app_packages_by_arch.items()},
        "size_bytes": len(raw_bytes),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }


def _verify_appxsym_bytes(data: bytes, label: str) -> set[str]:
    if len(data) < 4 or data[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a valid ZIP .appxsym archive (magic={data[:4]!r})")
    pdb_basenames: set[str] = set()
    forbidden_sym_exts = FORBIDDEN_KEY_EXTS + (".exe", ".dll", ".msix", ".appx", ".msixbundle")
    with zipfile.ZipFile(io.BytesIO(data), "r") as sym_zf:
        names = _check_opc_zip_entries(sym_zf, label, flat_root_only=True)
        for name in names:
            lower = name.lower()
            if lower.endswith(forbidden_sym_exts):
                raise ValueError(f"{label}: forbidden file inside .appxsym archive: {name!r}")
            if not lower.endswith(".pdb"):
                raise ValueError(f"{label}: unexpected non-PDB file inside .appxsym archive: {name!r}")
            if sym_zf.getinfo(name).file_size <= 0:
                raise ValueError(f"{label}: empty PDB entry inside .appxsym archive: {name!r}")
            pdb_bytes = _read_zip_member(sym_zf, name, label)
            if len(pdb_bytes) < len(PDB_MSF7_MAGIC) or not pdb_bytes.startswith(PDB_MSF7_MAGIC):
                raise ValueError(
                    f"{label}: PDB entry {name!r} does not start with Microsoft MSF 7.00 magic header"
                )
            pdb_basenames.add(lower)
    if not pdb_basenames:
        raise ValueError(f"{label}: .appxsym archive contains zero .pdb entries")
    return pdb_basenames


def verify_msixupload_archive(
    upload_path: Path,
    *,
    expected_version: str | None,
    expect_signed: bool,
    store_mode: bool,
    allow_test_identity: bool,
    expected_bundle_path: Path | None = None,
    run_live_smoke: bool = True,
    require_live_smoke: bool = False,
) -> dict[str, object]:
    """Deep-verify a Microsoft Store Partner Center .msixupload archive."""
    if not upload_path.is_file():
        raise ValueError(f"MSIX upload package not found: {upload_path}")
    raw_bytes = upload_path.read_bytes()
    label = upload_path.name
    if len(raw_bytes) < 4 or raw_bytes[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a ZIP .msixupload archive (magic={raw_bytes[:4]!r})")

    with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
        names = _check_opc_zip_entries(zf, label, flat_root_only=True)
        bundles: list[str] = []
        appxsyms: list[str] = []

        for name in names:
            lower = name.lower()
            if lower.endswith((".msix", ".appx")):
                raise ValueError(
                    f"{label}: bare standalone package {name!r} is forbidden inside .msixupload "
                    "(Microsoft Store enforces irreversible standalone .msix <-> .msixbundle format lock-in; "
                    "always wrap a dual-arch .msixbundle from Flight #1)"
                )
            if lower.endswith(FORBIDDEN_KEY_EXTS):
                raise ValueError(f"{label}: forbidden signing key/certificate file inside .msixupload: {name!r}")
            if lower.endswith(".msixbundle"):
                bundles.append(name)
            elif lower.endswith(".appxsym"):
                appxsyms.append(name)
            else:
                raise ValueError(
                    f"{label}: unexpected entry {name!r} inside .msixupload (expected only .msixbundle and .appxsym)"
                )

        if len(bundles) != 1:
            raise ValueError(
                f"{label}: .msixupload must contain exactly 1 .msixbundle entry, found {len(bundles)} ({bundles!r})"
            )
        if len(appxsyms) < 1:
            raise ValueError(
                f"{label}: .msixupload must contain at least 1 .appxsym PDB symbol archive"
            )

        bundle_name = bundles[0]
        bundle_bytes = _read_zip_member(zf, bundle_name, label)
        bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
        if expected_bundle_path is not None:
            disk_bytes = expected_bundle_path.read_bytes()
            disk_sha = hashlib.sha256(disk_bytes).hexdigest()
            if bundle_name != expected_bundle_path.name:
                raise ValueError(
                    f"{label}: embedded bundle name {bundle_name!r} != --bundle {expected_bundle_path.name!r}"
                )
            if bundle_sha != disk_sha:
                raise ValueError(
                    f"{label}: embedded {bundle_name} SHA-256 ({bundle_sha}) != --bundle ({disk_sha})"
                )

        bundle_info = verify_msixbundle_archive(
            bundle_bytes,
            f"{label}/{bundle_name}",
            expected_version=expected_version,
            expect_signed=expect_signed,
            store_mode=store_mode,
            allow_test_identity=allow_test_identity,
            run_live_smoke=run_live_smoke,
            require_live_smoke=require_live_smoke,
        )

        package_files: dict[str, str] = bundle_info["package_files"]  # type: ignore[assignment]
        expected_appxsyms = {f"{Path(pf).stem}.appxsym" for pf in package_files.values()}
        actual_appxsyms = set(appxsyms)
        if actual_appxsyms != expected_appxsyms:
            missing_syms = sorted(expected_appxsyms - actual_appxsyms)
            extra_syms = sorted(actual_appxsyms - expected_appxsyms)
            raise ValueError(
                f"{label}: .msixupload .appxsym archive set must match bundle slices exactly "
                f"(expected={sorted(expected_appxsyms)}, missing={missing_syms}, unexpected={extra_syms})"
            )

        combined_pdbs: set[str] = set()
        for sym_name in sorted(appxsyms):
            sym_bytes = _read_zip_member(zf, sym_name, label)
            sym_pdbs = _verify_appxsym_bytes(sym_bytes, f"{label}/{sym_name}")
            missing_pdbs = sorted(REQUIRED_SYMBOL_PDBS - sym_pdbs)
            if missing_pdbs:
                raise ValueError(
                    f"{label}/{sym_name}: .appxsym archive missing required PDB symbol(s): {missing_pdbs} "
                    f"(present={sorted(sym_pdbs)})"
                )
            combined_pdbs |= sym_pdbs

    return {
        "bundle_name": bundle_name,
        "bundle_info": bundle_info,
        "appxsym_count": len(appxsyms),
        "pdb_names": sorted(combined_pdbs),
        "size_bytes": len(raw_bytes),
    }


def _build_synthetic_pe64(
    *,
    machine: int,
    is_dll: bool,
    exports: tuple[str, ...] = (),
    cet_compat: bool = False,
    dependent_load_flags: int | None = None,
    include_icon_101: bool = False,
) -> bytes:
    """Build a minimal valid PE32+ image for pure-Python verifier self-tests (zero external tools)."""
    v_addr = 0x1000
    raw_ptr = 0x200
    sec = bytearray()

    def align4() -> None:
        while len(sec) % 4 != 0:
            sec.append(0)

    def cur_rva() -> int:
        return v_addr + len(sec)

    # 1. Export directory (DataDirectory[0])
    exp_rva, exp_size = 0, 0
    if exports:
        align4()
        exp_off = len(sec)
        exp_rva = v_addr + exp_off
        sec.extend(b"\x00" * 40)
        names_table_off = len(sec)
        names_table_rva = v_addr + names_table_off
        sec.extend(b"\x00" * (4 * len(exports)))
        name_rvas: list[int] = []
        for sym in exports:
            name_rvas.append(cur_rva())
            sec.extend(sym.encode("ascii") + b"\x00")
        struct.pack_into("<I", sec, exp_off + 24, len(exports))
        struct.pack_into("<I", sec, exp_off + 32, names_table_rva)
        for i, nrva in enumerate(name_rvas):
            struct.pack_into("<I", sec, names_table_off + i * 4, nrva)
        exp_size = len(sec) - exp_off

    # 2. Resource directory (DataDirectory[2]) — 2-level RT_ICON(3) & RT_GROUP_ICON(14) ID 101
    rsrc_rva, rsrc_size = 0, 0
    if include_icon_101:
        align4()
        rsrc_off = len(sec)
        rsrc_rva = v_addr + rsrc_off
        # Root dir: 16-byte header + 2*8=16-byte entries = 32 bytes.
        # Lvl2 RT_ICON at rel 32 (24 bytes), Lvl2 RT_GROUP_ICON at rel 56 (24 bytes).
        lvl2_icon_rel = 32
        lvl2_group_rel = 56
        sec.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 2))
        sec.extend(struct.pack("<II", RT_ICON, 0x8000_0000 | lvl2_icon_rel))
        sec.extend(struct.pack("<II", RT_GROUP_ICON, 0x8000_0000 | lvl2_group_rel))
        # Lvl2 RT_ICON
        sec.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
        sec.extend(struct.pack("<II", 1, 0))
        # Lvl2 RT_GROUP_ICON
        sec.extend(struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1))
        sec.extend(struct.pack("<II", EXPLORER_ICON_RESOURCE_ID, 0))
        rsrc_size = len(sec) - rsrc_off

    # 3. Debug directory (DataDirectory[6]) — Type 20 CET_COMPAT
    dbg_rva, dbg_size = 0, 0
    if cet_compat:
        align4()
        dbg_off = len(sec)
        dbg_rva = v_addr + dbg_off
        sec.extend(b"\x00" * 28)
        val_off = len(sec)
        val_rva = v_addr + val_off
        val_raw_ptr = raw_ptr + val_off
        sec.extend(struct.pack("<I", IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT))
        struct.pack_into(
            "<IIHHIIII",
            sec,
            dbg_off,
            0,
            0,
            0,
            0,
            IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS,
            4,
            val_rva,
            val_raw_ptr,
        )
        dbg_size = 28

    # 4. Load Config directory (DataDirectory[10]) — DependentLoadFlags at offset 0x4E
    lc_rva, lc_size = 0, 0
    if dependent_load_flags is not None:
        align4()
        lc_off = len(sec)
        lc_rva = v_addr + lc_off
        lc_buf = bytearray(0x50)
        struct.pack_into("<I", lc_buf, 0, 0x50)
        struct.pack_into("<H", lc_buf, 0x4E, dependent_load_flags)
        sec.extend(lc_buf)
        lc_size = 0x50

    if not sec:
        sec.extend(b"\x00" * 16)
    v_size = len(sec)
    while len(sec) % 0x200 != 0:
        sec.append(0)
    raw_size = len(sec)

    hdr = bytearray(raw_ptr)
    hdr[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    hdr[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"

    coff_off = e_lfanew + 4
    opt_size = 240
    characteristics = IMAGE_FILE_DLL if is_dll else 0x0002
    struct.pack_into("<HHIIIHH", hdr, coff_off, machine, 1, 0, 0, 0, opt_size, characteristics)

    opt_off = coff_off + 20
    struct.pack_into("<H", hdr, opt_off, IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    dll_chars = (
        IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        | IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        | IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    )
    struct.pack_into("<H", hdr, opt_off + 70, dll_chars)
    struct.pack_into("<I", hdr, opt_off + 108, 16)

    data_dirs_off = opt_off + 112
    for idx, (rva, size) in (
        (0, (exp_rva, exp_size)),
        (2, (rsrc_rva, rsrc_size)),
        (6, (dbg_rva, dbg_size)),
        (10, (lc_rva, lc_size)),
    ):
        struct.pack_into("<II", hdr, data_dirs_off + idx * 8, rva, size)

    sec_tbl_off = opt_off + opt_size
    struct.pack_into(
        "<8sIIIIIIHHI",
        hdr,
        sec_tbl_off,
        b".rdata\x00\x00",
        v_size,
        v_addr,
        raw_size,
        raw_ptr,
        0,
        0,
        0,
        0,
        0x4000_0040,
    )
    return bytes(hdr) + bytes(sec)


def _xml_attr_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _build_synthetic_pe32(machine: int = 0x014C) -> bytes:
    """Build a minimal 32-bit PE32 (0x010B) header for host-architecture guard self-tests."""
    hdr = bytearray(0x200)
    hdr[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    hdr[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    coff_off = e_lfanew + 4
    struct.pack_into("<HHIIIHH", hdr, coff_off, machine, 0, 0, 0, 0, 224, 0x0102)
    opt_off = coff_off + 20
    struct.pack_into("<H", hdr, opt_off, 0x010B)
    return bytes(hdr)


def _patch_manifest_xml(
    template_xml: str,
    *,
    name: str,
    publisher: str,
    version: str,
    arch: str,
    publisher_display_name: str = "TotalDrop",
    drop_run_full_trust: bool = False,
) -> bytes:
    xml = template_xml
    xml = re.sub(r'Name="TotalDrop\.TotalDrop"', lambda _: f'Name="{_xml_attr_escape(name)}"', xml, count=1)
    xml = re.sub(
        r'Publisher="CN=TotalDrop"', lambda _: f'Publisher="{_xml_attr_escape(publisher)}"', xml, count=1
    )
    xml = re.sub(r'Version="[^"]+"', lambda _: f'Version="{_xml_attr_escape(version)}"', xml, count=1)
    xml = re.sub(
        r'ProcessorArchitecture="[^"]+"',
        lambda _: f'ProcessorArchitecture="{_xml_attr_escape(arch)}"',
        xml,
        count=1,
    )
    xml = re.sub(
        r"<PublisherDisplayName>[^<]*</PublisherDisplayName>",
        lambda _: f"<PublisherDisplayName>{_xml_attr_escape(publisher_display_name)}</PublisherDisplayName>",
        xml,
        count=1,
    )
    if drop_run_full_trust:
        xml = xml.replace('<rescap:Capability Name="runFullTrust" />', "")
    return xml.encode("utf-8")


def _make_synthetic_msix(
    template_xml: str,
    *,
    arch: str,
    name: str,
    publisher: str,
    version: str,
    publisher_display_name: str = "TotalDrop",
    ext_machine_override: int | None = None,
    drop_run_full_trust: bool = False,
    extra_entries: list[tuple[str, bytes]] | None = None,
) -> bytes:
    machine = IMAGE_FILE_MACHINE_AMD64 if arch == "x64" else IMAGE_FILE_MACHINE_ARM64
    is_x64 = arch == "x64"
    manifest_bytes = _patch_manifest_xml(
        template_xml,
        name=name,
        publisher=publisher,
        version=version,
        arch=arch,
        publisher_display_name=publisher_display_name,
        drop_run_full_trust=drop_run_full_trust,
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AppxManifest.xml", manifest_bytes)
        zf.writestr("AppxBlockMap.xml", b"<BlockMap />")
        zf.writestr("[Content_Types].xml", b"<Types />")
        zf.writestr("resources.pri", b"mrm_pri2\x00\x00\x00\x00")
        zf.writestr("App.xbf", b"XBF\x00")
        zf.writestr("MainWindow.xbf", b"XBF\x00")
        zf.writestr("Views/SendPage.xbf", b"XBF\x00")
        zf.writestr("Views/ReceivePage.xbf", b"XBF\x00")
        zf.writestr("Views/SettingsPage.xbf", b"XBF\x00")
        for asset in sorted(EXPECTED_ASSETS):
            zf.writestr(f"Assets/{asset}", b"\x89PNG\r\n\x1a\n" if asset.endswith(".png") else b"\x00\x00\x01\x00")
        zf.writestr(
            "totaldrop-winui.exe",
            _build_synthetic_pe64(machine=machine, is_dll=False, cet_compat=is_x64, include_icon_101=True),
        )
        zf.writestr(
            "totaldrop_windows_ffi.dll",
            _build_synthetic_pe64(
                machine=machine,
                is_dll=True,
                exports=REQUIRED_FFI_EXPORTS,
                cet_compat=is_x64,
                dependent_load_flags=LOAD_LIBRARY_SEARCH_SYSTEM32,
            ),
        )
        zf.writestr(
            "totaldrop_explorer_ext.dll",
            _build_synthetic_pe64(
                machine=ext_machine_override if ext_machine_override is not None else machine,
                is_dll=True,
                exports=REQUIRED_EXPLORER_EXT_EXPORTS,
                cet_compat=(ext_machine_override == IMAGE_FILE_MACHINE_AMD64) if ext_machine_override else is_x64,
                dependent_load_flags=LOAD_LIBRARY_SEARCH_SYSTEM32,
                include_icon_101=True,
            ),
        )
        if extra_entries:
            for extra_name, extra_bytes in extra_entries:
                zf.writestr(extra_name, extra_bytes)
    return buf.getvalue()


def _make_synthetic_bundle(
    *,
    name: str,
    publisher: str,
    version: str,
    packages: list[tuple[str, str, str, bytes]],
    duplicate_identity: bool = False,
    duplicate_manifest_entry: bool = False,
    extra_entries: list[tuple[str, bytes]] | None = None,
) -> bytes:
    esc_name = _xml_attr_escape(name)
    esc_pub = _xml_attr_escape(publisher)
    esc_ver = _xml_attr_escape(version)
    pkg_xml = "\n".join(
        f'    <Package Type="application" Version="{_xml_attr_escape(p_ver)}" Architecture="{_xml_attr_escape(p_arch)}" FileName="{_xml_attr_escape(p_file)}" />'
        for p_arch, p_ver, p_file, _ in packages
    )
    extra_id = f'\n  <Identity Name="{esc_name}" Publisher="{esc_pub}" Version="{esc_ver}" />' if duplicate_identity else ""
    bundle_manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Bundle SchemaVersion="5.0" xmlns="http://schemas.microsoft.com/appx/2013/bundle">\n'
        f'  <Identity Name="{esc_name}" Publisher="{esc_pub}" Version="{esc_ver}" />{extra_id}\n'
        "  <Packages>\n"
        f"{pkg_xml}\n"
        "  </Packages>\n"
        "</Bundle>\n"
    ).encode("utf-8")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AppxMetadata/AppxBundleManifest.xml", bundle_manifest)
        if duplicate_manifest_entry:
            zf.writestr("appxmetadata/appxbundlemanifest.xml", bundle_manifest)
        zf.writestr("AppxBlockMap.xml", b"<BlockMap />")
        zf.writestr("[Content_Types].xml", b"<Types />")
        for _, _, p_file, p_bytes in packages:
            zf.writestr(p_file, p_bytes)
        if extra_entries:
            for extra_name, extra_bytes in extra_entries:
                zf.writestr(extra_name, extra_bytes)
    return buf.getvalue()


def _make_synthetic_appxsym(
    pdb_names: tuple[str, ...],
    extra_entries: list[tuple[str, bytes]] | None = None,
) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for pdb in pdb_names:
            zf.writestr(pdb, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")
        if extra_entries:
            for extra_name, extra_bytes in extra_entries:
                zf.writestr(extra_name, extra_bytes)
    return buf.getvalue()


def _make_synthetic_upload(entries: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buf.getvalue()


def run_self_test_bundle() -> int:
    """Run 38 positive and negative pure-Python synthetic self-tests against the real verifier."""
    repo_root = Path(__file__).resolve().parent.parent
    x64_tpl = (repo_root / "target-x86_64" / "Package.x64.appxmanifest").read_text(encoding="utf-8")
    arm64_tpl = (repo_root / "target-arm64" / "Package.arm64.appxmanifest").read_text(encoding="utf-8")

    store_name = "12345TotalDrop.TotalDrop"
    store_pub = "CN=11111111-2222-3333-4444-555555555555"
    store_ver = "1.0.1.0"
    all_pdbs = tuple(sorted(REQUIRED_SYMBOL_PDBS))

    def expect_fail(case_name: str, fn: object, expected_substr: str = "") -> None:
        try:
            fn()  # type: ignore[operator]
        except ValueError as exc:
            if expected_substr and expected_substr.lower() not in str(exc).lower():
                raise AssertionError(
                    f"self-test {case_name}: failed with unexpected error {exc!r} (expected {expected_substr!r})"
                ) from exc
            return
        raise AssertionError(f"self-test {case_name}: expected ValueError, but verification passed")

    with tempfile.TemporaryDirectory(prefix="totaldrop-bundle-selftest-") as tmp:
        tmp_dir = Path(tmp)
        x64_ok = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=store_pub, version=store_ver)
        arm64_ok = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=store_ver)
        bundle_ok_bytes = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
        )
        sym_ok = _make_synthetic_appxsym(all_pdbs)
        bundle_ok_path = tmp_dir / f"TotalDrop-{store_ver}.msixbundle"
        bundle_ok_path.write_bytes(bundle_ok_bytes)
        upload_ok_path = tmp_dir / f"TotalDrop-{store_ver}.msixupload"
        upload_ok_path.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                ]
            )
        )

        # Case 1: Positive valid dual-arch Store .msixbundle + .msixupload passes --store-mode.
        verify_msixbundle_archive(
            bundle_ok_path,
            bundle_ok_path.name,
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            run_live_smoke=False,
        )
        verify_msixupload_archive(
            upload_ok_path,
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            expected_bundle_path=bundle_ok_path,
            run_live_smoke=False,
        )

        # Case 2: Dry-run CN=TotalDrop bundle fails strict --store-mode, passes --store-mode --allow-test-identity.
        x64_dry = _make_synthetic_msix(x64_tpl, arch="x64", name="TotalDrop.TotalDrop", publisher="CN=TotalDrop", version=store_ver)
        arm64_dry = _make_synthetic_msix(arm64_tpl, arch="arm64", name="TotalDrop.TotalDrop", publisher="CN=TotalDrop", version=store_ver)
        bundle_dry = _make_synthetic_bundle(
            name="TotalDrop.TotalDrop",
            publisher="CN=TotalDrop",
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_dry),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_dry),
            ],
        )
        expect_fail(
            "case-2-dryrun-strict",
            lambda: verify_msixbundle_archive(
                bundle_dry, "dry.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "placeholder",
        )
        verify_msixbundle_archive(
            bundle_dry, "dry.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=True, run_live_smoke=False
        )

        # Case 3: Missing arm64 slice (x64 only).
        bundle_no_arm64 = _make_synthetic_bundle(
            name=store_name, publisher=store_pub, version=store_ver, packages=[("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok)]
        )
        expect_fail(
            "case-3-missing-arm64",
            lambda: verify_msixbundle_archive(
                bundle_no_arm64, "no-arm64.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "arm64",
        )

        # Case 4: Forbidden x86 slice.
        bundle_x86 = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
                ("x86", store_ver, f"TotalDrop_{store_ver}_x86.msix", x64_ok),
            ],
        )
        expect_fail(
            "case-4-forbidden-x86",
            lambda: verify_msixbundle_archive(
                bundle_x86, "x86.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "x86",
        )

        # Case 5: Bare .msix at root of .msixupload -> cites Store format lock-in rule.
        bad_upload_bare = tmp_dir / "bare.msixupload"
        bad_upload_bare.write_bytes(
            _make_synthetic_upload([(f"TotalDrop_{store_ver}_x64.msix", x64_ok), (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok)])
        )
        expect_fail(
            "case-5-bare-msix-upload",
            lambda: verify_msixupload_archive(
                bad_upload_bare, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "lock-in",
        )

        # Case 6: Cross-arch PE contamination (x64 0x8664 totaldrop_explorer_ext.dll inside arm64.msix).
        arm64_contaminated = _make_synthetic_msix(
            arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=store_ver, ext_machine_override=IMAGE_FILE_MACHINE_AMD64
        )
        bundle_contam = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_contaminated),
            ],
        )
        expect_fail(
            "case-6-pe-arch-contamination",
            lambda: verify_msixbundle_archive(
                bundle_contam, "contam.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "expected machine",
        )

        # Case 7: Outer bundle version 1.0.2.0 vs inner arm64 version 1.0.1.0.
        x64_v2 = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=store_pub, version="1.0.2.0")
        bundle_ver_drift = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version="1.0.2.0",
            packages=[
                ("x64", "1.0.2.0", "TotalDrop_1.0.2.0_x64.msix", x64_v2),
                ("arm64", "1.0.2.0", "TotalDrop_1.0.2.0_arm64.msix", arm64_ok),
            ],
        )
        expect_fail(
            "case-7-version-drift",
            lambda: verify_msixbundle_archive(
                bundle_ver_drift, "ver-drift.msixbundle", expected_version=None, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "Version mismatch",
        )

        # Case 8: Cross-arch Identity/@Publisher mismatch.
        arm64_diff_pub = _make_synthetic_msix(
            arm64_tpl, arch="arm64", name=store_name, publisher="CN=99999999-2222-3333-4444-555555555555", version=store_ver
        )
        bundle_pub_drift = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_diff_pub),
            ],
        )
        expect_fail(
            "case-8-publisher-drift",
            lambda: verify_msixbundle_archive(
                bundle_pub_drift, "pub-drift.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "Publisher",
        )

        # Case 9: Major == 0 (0.1.1.0) under --store-mode.
        x64_zero = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=store_pub, version="0.1.1.0")
        arm64_zero = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version="0.1.1.0")
        bundle_zero = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version="0.1.1.0",
            packages=[
                ("x64", "0.1.1.0", "TotalDrop_0.1.1.0_x64.msix", x64_zero),
                ("arm64", "0.1.1.0", "TotalDrop_0.1.1.0_arm64.msix", arm64_zero),
            ],
        )
        expect_fail(
            "case-9-major-zero",
            lambda: verify_msixbundle_archive(
                bundle_zero, "major0.msixbundle", expected_version=None, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "Major >= 1",
        )

        # Case 10: Revision != 0 (1.0.0.1) and uint16 overflow (65536.0.0.0).
        for bad_ver, expected_msg in (("1.0.0.1", "Revision == 0"), ("65536.0.0.0", "0..=65535")):
            bx = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=store_pub, version=bad_ver)
            ba = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=bad_ver)
            bb = _make_synthetic_bundle(
                name=store_name,
                publisher=store_pub,
                version=bad_ver,
                packages=[
                    ("x64", bad_ver, f"TotalDrop_{bad_ver}_x64.msix", bx),
                    ("arm64", bad_ver, f"TotalDrop_{bad_ver}_arm64.msix", ba),
                ],
            )
            expect_fail(
                f"case-10-{bad_ver}",
                lambda bb=bb: verify_msixbundle_archive(
                    bb, "badver.msixbundle", expected_version=None, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                expected_msg,
            )

        # Case 11: Unsigned-package OID in Publisher.
        oid_pub = f"CN=TotalDrop, OID.{UNSIGNED_PACKAGE_OID}=1"
        x64_oid = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher=oid_pub, version=store_ver)
        arm64_oid = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher=oid_pub, version=store_ver)
        bundle_oid = _make_synthetic_bundle(
            name=store_name,
            publisher=oid_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_oid),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_oid),
            ],
        )
        expect_fail(
            "case-11-unsigned-oid",
            lambda: verify_msixbundle_archive(
                bundle_oid, "oid.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=True, run_live_smoke=False
            ),
            UNSIGNED_PACKAGE_OID,
        )

        # Case 12: Malformed Publisher without CN=.
        x64_badpub = _make_synthetic_msix(x64_tpl, arch="x64", name=store_name, publisher="TotalDrop", version=store_ver)
        arm64_badpub = _make_synthetic_msix(arm64_tpl, arch="arm64", name=store_name, publisher="TotalDrop", version=store_ver)
        bundle_badpub = _make_synthetic_bundle(
            name=store_name,
            publisher="TotalDrop",
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_badpub),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_badpub),
            ],
        )
        expect_fail(
            "case-12-bad-publisher",
            lambda: verify_msixbundle_archive(
                bundle_badpub, "badpub.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "X.500",
        )

        # Case 13: Leaked .pfx and .snk inside .msixupload.
        for leak_name in ("signing.pfx", "strongname.snk"):
            bad_leak = tmp_dir / f"leak-{leak_name}.msixupload"
            bad_leak.write_bytes(
                _make_synthetic_upload(
                    [
                        (bundle_ok_path.name, bundle_ok_bytes),
                        (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok),
                        (leak_name, b"SECRET"),
                    ]
                )
            )
            expect_fail(
                f"case-13-leak-{leak_name}",
                lambda p=bad_leak: verify_msixupload_archive(
                    p, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                "signing key",
            )

        # Case 14: Duplicate <Identity> and case-insensitive duplicate AppxBundleManifest.xml ZIP entry.
        bundle_dup_id = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
            duplicate_identity=True,
        )
        expect_fail(
            "case-14a-dup-identity",
            lambda: verify_msixbundle_archive(
                bundle_dup_id, "dupid.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "exactly 1 top-level <Identity>",
        )
        bundle_dup_zip = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
            duplicate_manifest_entry=True,
        )
        expect_fail(
            "case-14b-dup-manifest-zip",
            lambda: verify_msixbundle_archive(
                bundle_dup_zip, "dupzip.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "duplicate",
        )

        # Case 15: Missing PDB in .appxsym AND SHA-256 mismatch between --bundle and embedded bundle.
        sym_incomplete = _make_synthetic_appxsym(("totaldrop-winui.pdb", "totaldrop_windows_ffi.pdb"))
        bad_sym_upload = tmp_dir / "missing-pdb.msixupload"
        bad_sym_upload.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_incomplete),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                ]
            )
        )
        expect_fail(
            "case-15a-missing-pdb",
            lambda: verify_msixupload_archive(
                bad_sym_upload, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "totaldrop_explorer_ext.pdb",
        )
        mismatch_dir = tmp_dir / "other"
        mismatch_dir.mkdir()
        other_bundle_path = mismatch_dir / bundle_ok_path.name
        other_bundle_path.write_bytes(bundle_dry)
        expect_fail(
            "case-15b-sha256-mismatch",
            lambda: verify_msixupload_archive(
                upload_ok_path,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                expected_bundle_path=other_bundle_path,
                run_live_smoke=False,
            ),
            "SHA-256",
        )

        # Case 16: Cross-arch manifest divergence (PublisherDisplayName mismatch & missing runFullTrust in arm64).
        arm64_diff_disp = _make_synthetic_msix(
            arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=store_ver, publisher_display_name="Other Publisher"
        )
        bundle_disp_drift = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_diff_disp),
            ],
        )
        expect_fail(
            "case-16a-manifest-divergence",
            lambda: verify_msixbundle_archive(
                bundle_disp_drift, "disp-drift.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "diverge",
        )
        arm64_no_rft = _make_synthetic_msix(
            arm64_tpl, arch="arm64", name=store_name, publisher=store_pub, version=store_ver, drop_run_full_trust=True
        )
        bundle_no_rft = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_no_rft),
            ],
        )
        expect_fail(
            "case-16b-missing-runfulltrust",
            lambda: verify_msixbundle_archive(
                bundle_no_rft, "no-rft.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "runFullTrust",
        )

        # Case 17: PE binary host architecture detection (AMD64 -> x64, ARM64 -> arm64, PE32 0x010B -> None).
        pe_x64 = _build_synthetic_pe64(machine=IMAGE_FILE_MACHINE_AMD64, is_dll=False)
        pe_arm64 = _build_synthetic_pe64(machine=IMAGE_FILE_MACHINE_ARM64, is_dll=False)
        pe_x86 = _build_synthetic_pe32(machine=0x014C)
        assert _pe_machine_to_arch(pe_x64) == "x64", "expected AMD64 PE32+ -> 'x64'"
        assert _pe_machine_to_arch(pe_arm64) == "arm64", "expected ARM64 PE32+ -> 'arm64'"
        assert _pe_machine_to_arch(pe_x86) is None, "expected 32-bit PE32 (0x010B) -> None"
        assert _pe_machine_to_arch(b"not-a-pe") is None, "expected non-PE bytes -> None"

        # Case 18: OPC archive-wide case-shadowing DLL & dot-segment / empty-segment / colon path bypasses.
        arm64_case_shadow = _make_synthetic_msix(
            arm64_tpl,
            arch="arm64",
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            extra_entries=[("TOTALDROP_EXPLORER_EXT.DLL", pe_x64)],
        )
        bundle_case_shadow = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_case_shadow),
            ],
        )
        expect_fail(
            "case-18a-opc-case-shadow-dll",
            lambda: verify_msixbundle_archive(
                bundle_case_shadow, "case-shadow.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "case-insensitive duplicate",
        )
        for sub_id, bad_entry, expected_err in (
            ("18b-dot-segment", "./AppxManifest.xml", "relative/traversal"),
            ("18c-empty-segment", "Assets//extra.png", "empty path segment"),
            ("18d-colon-path", "C:evil.dll", "unsafe OPC/ZIP"),
        ):
            arm64_bad_path = _make_synthetic_msix(
                arm64_tpl,
                arch="arm64",
                name=store_name,
                publisher=store_pub,
                version=store_ver,
                extra_entries=[(bad_entry, b"<Package/>")],
            )
            bundle_bad_path = _make_synthetic_bundle(
                name=store_name,
                publisher=store_pub,
                version=store_ver,
                packages=[
                    ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                    ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_bad_path),
                ],
            )
            expect_fail(
                f"case-{sub_id}",
                lambda b=bundle_bad_path: verify_msixbundle_archive(
                    b, f"{sub_id}.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                expected_err,
            )

        # Case 19: Per-archive .appxsym PDB completeness (complete x64.appxsym + incomplete arm64.appxsym).
        asym_sym_upload = tmp_dir / "asym-pdb.msixupload"
        asym_sym_upload.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_incomplete),
                ]
            )
        )
        expect_fail(
            "case-19-per-appxsym-pdb-completeness",
            lambda: verify_msixupload_archive(
                asym_sym_upload, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "arm64.appxsym",
        )

        # Case 20: Corrupted deflate stream (invalid deflate block) produces clean ValueError, never raw zlib.error.
        corrupt_buf = bytearray(bundle_ok_bytes)
        with zipfile.ZipFile(io.BytesIO(bundle_ok_bytes), "r") as zf_inspect:
            info = zf_inspect.getinfo("AppxMetadata/AppxBundleManifest.xml")
            l_name_len, l_extra_len = struct.unpack_from("<HH", bundle_ok_bytes, info.header_offset + 26)
            data_off = info.header_offset + 30 + l_name_len + l_extra_len
            # Overwrite first deflate bytes with 0xFF (invalid block type 11 in RFC 1951 -> guaranteed zlib.error).
            for i in range(min(8, info.compress_size)):
                corrupt_buf[data_off + i] = 0xFF
        expect_fail(
            "case-20-corrupt-deflate",
            lambda: verify_msixbundle_archive(
                bytes(corrupt_buf), "corrupt-deflate.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "corrupted ZIP",
        )

        # Case 21: Normalized placeholder identity variants (incl. RFC 2253 hexpair escapes) rejected under strict --store-mode.
        for variant_id, v_name, v_pub in (
            ("21a-space-cn", store_name, "CN = TotalDrop"),
            ("21b-lower-cn", store_name, "cn=totaldrop"),
            ("21c-quoted-cn", store_name, 'CN="TotalDrop"'),
            ("21d-lower-name", "totaldrop.totaldrop", store_pub),
            ("21e-hexpair-cn", store_name, r"CN=\54otalDrop"),
            ("21f-quoted-hexpair-cn", store_name, r'CN="\54otalDrop"'),
            ("21g-full-hexpair-cn", store_name, r"CN=\54\6f\74\61\6c\44\72\6f\70"),
            ("21h-trailing-hexspace-cn", store_name, r"CN=TotalDrop\20"),
            ("21i-quoted-padded-cn", store_name, 'CN=" TotalDrop "'),
        ):
            vx = _make_synthetic_msix(x64_tpl, arch="x64", name=v_name, publisher=v_pub, version=store_ver)
            va = _make_synthetic_msix(arm64_tpl, arch="arm64", name=v_name, publisher=v_pub, version=store_ver)
            vb = _make_synthetic_bundle(
                name=v_name,
                publisher=v_pub,
                version=store_ver,
                packages=[
                    ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", vx),
                    ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", va),
                ],
            )
            expect_fail(
                f"case-{variant_id}",
                lambda b=vb: verify_msixbundle_archive(
                    b, f"{variant_id}.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                "placeholder",
            )

        # Case 22: Strict RFC 2253/4514 X.500 publisher hardening (BER #hex, hex-smuggled control/Bidi, invalid escapes rejected; escaped trailing space & UTF-8 hexpairs accepted).
        _validate_x500_publisher('CN=Ozan Özdil, O="TotalDrop, Inc.", C=TR', "selftest-valid-x500")
        _validate_x500_publisher("CN=11111111-2222-3333-4444-555555555555", "selftest-valid-guid")
        assert _parse_x500_publisher(r"CN=Acme\ ", "selftest-escaped-space") == [("CN", "Acme ")], (
            "expected RFC 2253 trailing escaped space to parse cleanly as 'Acme '"
        )
        assert _parse_x500_publisher(r"CN=Ozan \c3\96zdil", "selftest-utf8-hexpair") == [("CN", "Ozan Özdil")], (
            "expected RFC 2253 UTF-8 hexpair sequence to decode cleanly"
        )
        for bad_pub in (
            'CN=Foo"; rm -rf / #',
            'CN="Foo"; rm -rf /',
            "CN=Foo; rm -rf /",
            "CN=Foo, NotAnRdn",
            "CN=Foo\u202eBar",
            "CN=Foo$(id)",
            "CN=Foo`id`",
            "CN=#nothex",
            "CN=#0C09546F74616C44726F70",
            "CN=#1309546F74616C44726F70",
            r"CN=Foo\0aBar",
            r"CN=Foo\00Bar",
            r"CN=Foo\e2\80\aeBar",
            r"CN=Foo\c2\85Bar",
            r"CN=Total\Drop",
            r"CN=\5otalDrop",
            r"CN=Bad\ffUtf8",
            "CN=Acme, 1.\u0662.3=Val",
        ):
            expect_fail(
                f"case-22-bad-x500-{bad_pub!r}",
                lambda p=bad_pub: _validate_x500_publisher(p, "selftest-bad-x500"),
            )

        # Case 23: Non-empty trailing-slash directory ZIP entries & forbidden key directory entries rejected in .msix, .msixbundle, and .appxsym.
        for sub_id, dir_name, dir_payload, expected_err in (
            ("23a-msix-nonempty-evil-dll-dir", "evil.dll/", pe_x64, "non-zero payload"),
            ("23b-msix-nonempty-assets-dir", "Assets/", b"NON_EMPTY_DIR_DATA", "non-zero payload"),
            ("23c-msix-nonempty-pfx-dir", "signing.pfx/", b"SECRET_KEY", "non-zero payload"),
            ("23d-msix-empty-pfx-dir", "signing.pfx/", b"", "forbidden signing/key directory"),
        ):
            arm64_dir_smuggle = _make_synthetic_msix(
                arm64_tpl,
                arch="arm64",
                name=store_name,
                publisher=store_pub,
                version=store_ver,
                extra_entries=[(dir_name, dir_payload)],
            )
            expect_fail(
                f"case-{sub_id}",
                lambda m=arm64_dir_smuggle: verify_msix_archive(
                    m, f"{sub_id}.msix", arch="arm64", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                expected_err,
            )
        bundle_dir_smuggle = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
            extra_entries=[("signing.pfx/", b"SECRET_KEY")],
        )
        expect_fail(
            "case-23e-bundle-nonempty-pfx-dir",
            lambda: verify_msixbundle_archive(
                bundle_dir_smuggle, "dir-smuggle.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "non-zero payload",
        )
        for sub_id, sym_extra, expected_err in (
            ("23f-appxsym-nonempty-evil-dll-dir", ("evil.dll/", pe_x64), "non-zero payload"),
            ("23g-appxsym-nonempty-pfx-dir", ("signing.pfx/", b"SECRET"), "non-zero payload"),
        ):
            sym_bad = _make_synthetic_appxsym(all_pdbs, extra_entries=[sym_extra])
            bad_upload = tmp_dir / f"{sub_id}.msixupload"
            bad_upload.write_bytes(
                _make_synthetic_upload(
                    [
                        (bundle_ok_path.name, bundle_ok_bytes),
                        (f"TotalDrop_{store_ver}_x64.appxsym", sym_bad),
                        (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                    ]
                )
            )
            expect_fail(
                f"case-{sub_id}",
                lambda p=bad_upload: verify_msixupload_archive(
                    p, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                expected_err,
            )

        # Case 24: Case-mismatched directory prefix collisions rejected while matching-case empty directory entries pass.
        for sub_id, bad_entry, bad_payload in (
            ("24a-msix-lowercase-assets-dir", "assets/", b""),
            ("24b-msix-lowercase-assets-evil-dll", "assets/evil.dll", pe_x64),
            ("24c-msix-lowercase-assets-extra-png", "assets/extra.png", b"\x89PNG\r\n\x1a\n"),
        ):
            arm64_dir_case = _make_synthetic_msix(
                arm64_tpl,
                arch="arm64",
                name=store_name,
                publisher=store_pub,
                version=store_ver,
                extra_entries=[(bad_entry, bad_payload)],
            )
            expect_fail(
                f"case-{sub_id}",
                lambda m=arm64_dir_case: verify_msix_archive(
                    m, f"{sub_id}.msix", arch="arm64", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                "case-colliding directory prefix",
            )
        bundle_dir_case = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
            extra_entries=[("appxmetadata/", b"")],
        )
        expect_fail(
            "case-24d-bundle-lowercase-appxmetadata-dir",
            lambda: verify_msixbundle_archive(
                bundle_dir_case, "dir-case.msixbundle", expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
            ),
            "case-colliding directory prefix",
        )
        arm64_matching_dirs = _make_synthetic_msix(
            arm64_tpl,
            arch="arm64",
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            extra_entries=[("Assets/", b""), ("Views/", b"")],
        )
        bundle_matching_dirs = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_matching_dirs),
            ],
            extra_entries=[("AppxMetadata/", b"")],
        )
        verify_msixbundle_archive(
            bundle_matching_dirs,
            "matching-dirs.msixbundle",
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            run_live_smoke=False,
        )

        # Case 25: Flat-root .appxsym enforcement (nested subdirectories & duplicate-basename PDB trees rejected).
        for sub_id, bad_pdb_tuple in (
            ("25a-nested-pdbs", tuple(f"nested/{p}" for p in all_pdbs)),
            (
                "25b-duplicate-basename-pdbs",
                ("a/totaldrop-winui.pdb", "b/totaldrop-winui.pdb", "totaldrop_windows_ffi.pdb", "totaldrop_explorer_ext.pdb"),
            ),
        ):
            sym_nested = _make_synthetic_appxsym(bad_pdb_tuple)
            nested_upload = tmp_dir / f"{sub_id}.msixupload"
            nested_upload.write_bytes(
                _make_synthetic_upload(
                    [
                        (bundle_ok_path.name, bundle_ok_bytes),
                        (f"TotalDrop_{store_ver}_x64.appxsym", sym_nested),
                        (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                    ]
                )
            )
            expect_fail(
                f"case-{sub_id}",
                lambda p=nested_upload: verify_msixupload_archive(
                    p, expected_version=store_ver, expect_signed=False, store_mode=True, allow_test_identity=False, run_live_smoke=False
                ),
                "flat root",
            )

        # Case 26: ECMA-376 M1.9/M1.10 & Windows NTFS trailing-dot / trailing-space OPC/ZIP path segments rejected.
        for sub_id, bad_entry, bad_payload in (
            ("26a-msix-pfx-trailing-dot", "signing.pfx.", b"PRIVATE_KEY_MATERIAL"),
            ("26b-msix-pfx-trailing-space", "signing.pfx ", b"PRIVATE_KEY_MATERIAL"),
            ("26c-msix-dll-trailing-dot", "totaldrop_explorer_ext.dll.", pe_x64),
            ("26d-msix-manifest-trailing-dot", "AppxManifest.xml.", b"<Package/>"),
            ("26e-msix-assets-dot-evil-dll", "Assets./evil.dll", pe_x64),
            ("26f-msix-assets-space-extra-png", "Assets /extra.png", b"\x89PNG\r\n\x1a\n"),
            ("26g-msix-pdb-trailing-dot", "totaldrop-winui.pdb.", b"FAKE_PDB"),
            ("26h-msix-dot-only-segment", ".../evil.dll", pe_x64),
            ("26i-msix-pfx-dot-dir", "signing.pfx./", b""),
            ("26j-msix-assets-dot-dir", "Assets./", b""),
        ):
            arm64_ntfs_bad = _make_synthetic_msix(
                arm64_tpl,
                arch="arm64",
                name=store_name,
                publisher=store_pub,
                version=store_ver,
                extra_entries=[(bad_entry, bad_payload)],
            )
            expect_fail(
                f"case-{sub_id}",
                lambda m=arm64_ntfs_bad: verify_msix_archive(
                    m,
                    f"{sub_id}.msix",
                    arch="arm64",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                "trailing dot or space",
            )
        for sub_id, bad_entry, bad_payload in (
            ("26k-bundle-appxmetadata-dot-manifest", "AppxMetadata./AppxBundleManifest.xml", b"<Bundle/>"),
            ("26l-bundle-rogue-x86-msix-dot", "rogue_x86.msix.", b"PK\x03\x04"),
            ("26m-bundle-pfx-trailing-dot", "signing.pfx.", b"PRIVATE_KEY_MATERIAL"),
        ):
            bundle_ntfs_bad = _make_synthetic_bundle(
                name=store_name,
                publisher=store_pub,
                version=store_ver,
                packages=[
                    ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                    ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
                ],
                extra_entries=[(bad_entry, bad_payload)],
            )
            expect_fail(
                f"case-{sub_id}",
                lambda b=bundle_ntfs_bad: verify_msixbundle_archive(
                    b,
                    f"{sub_id}.msixbundle",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                "trailing dot or space",
            )

        # Case 27: NUL-byte filename truncation and Info-ZIP 0x7075 Unicode Path extra-field polyglot shadowing rejected.
        def _make_unicode_path_extra(raw_name: str, unicode_name: str) -> bytes:
            crc = zlib.crc32(raw_name.encode("utf-8")) & 0xFFFF_FFFF
            payload = struct.pack("<BL", 1, crc) + unicode_name.encode("utf-8")
            return struct.pack("<HH", 0x7075, len(payload)) + payload

        def _patch_zip_raw_entries(
            base_zip: bytes,
            raw_entries: list[tuple[str, bytes, bytes]],
            *,
            drop_names: frozenset[str] = frozenset(),
        ) -> bytes:
            out = io.BytesIO()
            with (
                zipfile.ZipFile(io.BytesIO(base_zip), "r") as zin,
                zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zout,
            ):
                for item in zin.infolist():
                    if item.filename in drop_names:
                        continue
                    zout.writestr(item.filename, zin.read(item))
                for raw_name, payload, extra in raw_entries:
                    zi = zipfile.ZipInfo("placeholder")
                    zi.filename = raw_name
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.extra = extra
                    zout.writestr(zi, payload)
            return out.getvalue()

        # 27a: NUL-truncated benign\x00signing.pfx inside .msix.
        arm64_nul_pfx = _patch_zip_raw_entries(
            arm64_ok,
            [("benign\x00signing.pfx", b"PRIVATE_KEY_MATERIAL", b"")],
        )
        expect_fail(
            "case-27a-msix-nul-truncation",
            lambda: verify_msix_archive(
                arm64_nul_pfx,
                "27a-nul.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "differs from normalized name",
        )

        # 27b: NUL-truncated totaldrop-winui.pdb\x00signing.pfx inside .appxsym inside .msixupload.
        sym_nul_pfx = _patch_zip_raw_entries(
            sym_ok,
            [("totaldrop-winui.pdb\x00signing.pfx", b"PRIVATE_KEY_MATERIAL", b"")],
            drop_names=frozenset({"totaldrop-winui.pdb"}),
        )
        upload_nul_sym = tmp_dir / "27b-appxsym-nul.msixupload"
        upload_nul_sym.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_nul_pfx),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                ]
            )
        )
        expect_fail(
            "case-27b-appxsym-nul-truncation",
            lambda: verify_msixupload_archive(
                upload_nul_sym,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "differs from normalized name",
        )

        # 27c: Info-ZIP 0x7075 full AppxManifest.xml polyglot shadowing (evil x86 / unsigned-OID / CN=TotalDrop).
        with zipfile.ZipFile(io.BytesIO(arm64_ok), "r") as zf_arm64_good:
            good_arm64_manifest = zf_arm64_good.read("AppxManifest.xml")
        evil_manifest = _patch_manifest_xml(
            arm64_tpl,
            name="TotalDrop.TotalDrop",
            publisher=f"OID.{UNSIGNED_PACKAGE_OID}=1, CN=TotalDrop",
            version="0.0.0.1",
            arch="x86",
        )
        arm64_manifest_shadow = _patch_zip_raw_entries(
            arm64_ok,
            [
                (
                    "good_manifest.dat",
                    good_arm64_manifest,
                    _make_unicode_path_extra("good_manifest.dat", "AppxManifest.xml"),
                ),
                (
                    "AppxManifest.xml",
                    evil_manifest,
                    _make_unicode_path_extra("AppxManifest.xml", "harmless_note.txt"),
                ),
            ],
            drop_names=frozenset({"AppxManifest.xml"}),
        )
        bundle_manifest_shadow = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_manifest_shadow),
            ],
        )
        expect_fail(
            "case-27c-0x7075-manifest-polyglot",
            lambda: verify_msixbundle_archive(
                bundle_manifest_shadow,
                "27c-manifest-shadow.msixbundle",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "0x7075",
        )

        # 27d: Info-ZIP 0x7075 hidden signing.pfx in .msix.
        arm64_0x7075_pfx = _patch_zip_raw_entries(
            arm64_ok,
            [
                (
                    "signing.pfx",
                    b"PRIVATE_KEY_MATERIAL",
                    _make_unicode_path_extra("signing.pfx", "harmless.txt"),
                ),
            ],
        )
        expect_fail(
            "case-27d-0x7075-msix-pfx",
            lambda: verify_msix_archive(
                arm64_0x7075_pfx,
                "27d-0x7075-pfx.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "0x7075",
        )

        # 27e: Info-ZIP 0x7075 hidden signing.pfx in .appxsym inside .msixupload.
        sym_0x7075_pfx = _patch_zip_raw_entries(
            sym_ok,
            [
                (
                    "signing.pfx",
                    b"PRIVATE_KEY_MATERIAL",
                    _make_unicode_path_extra("signing.pfx", "totaldrop-winui.pdb"),
                ),
            ],
            drop_names=frozenset({"totaldrop-winui.pdb"}),
        )
        upload_0x7075_sym = tmp_dir / "27e-0x7075-appxsym.msixupload"
        upload_0x7075_sym.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_0x7075_pfx),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                ]
            )
        )
        expect_fail(
            "case-27e-0x7075-appxsym-pfx",
            lambda: verify_msixupload_archive(
                upload_0x7075_sym,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "0x7075",
        )

        # 27f: Info-ZIP 0x7075 poisoned NUL suffix matching orig_filename (orig="benign" + 0x7075="benign\x00evil").
        arm64_0x7075_nul_match = _patch_zip_raw_entries(
            arm64_ok,
            [
                (
                    "benign",
                    b"POISONED_EXTRA",
                    _make_unicode_path_extra("benign", "benign\x00evil"),
                ),
            ],
        )
        expect_fail(
            "case-27f-0x7075-nul-matching-orig",
            lambda: verify_msix_archive(
                arm64_0x7075_nul_match,
                "27f-0x7075-nul.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "0x7075",
        )

        # Positive control: standard Extended Timestamp (0x5455) extra field passes cleanly.
        ext_ts_extra = struct.pack("<HHBI", 0x5455, 5, 1, 1760000000)
        arm64_valid_extra = _patch_zip_raw_entries(
            arm64_ok,
            [("benign_meta.txt", b"OK", ext_ts_extra)],
        )
        verify_msix_archive(
            arm64_valid_extra,
            "27-pos-0x5455.msix",
            arch="arm64",
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            run_live_smoke=False,
        )

        # Case 28: ZIP container binary structure hardening (concat == 0, Zip64 vs 32-bit EOCD parity,
        # EOF anchoring, CD entry count/contiguity, LFH-vs-CD header parity, nested EOCD comment, inter-entry slack)
        # plus positive controls (consistent Zip64 EOCD sentinel/non-sentinel & streaming bit-3 Data Descriptor).
        def _split_zip_parts(zip_bytes: bytes) -> tuple[bytes, bytes, int]:
            eocd_off = zip_bytes.rfind(b"PK\x05\x06")
            assert eocd_off >= 0 and eocd_off + 22 == len(zip_bytes)
            _, _, _, n_disk, n_tot, cd_sz, cd_off, cmt_len = struct.unpack_from("<4sHHHHIIH", zip_bytes, eocd_off)
            assert n_disk == n_tot and cmt_len == 0 and cd_off + cd_sz == eocd_off
            return zip_bytes[:cd_off], zip_bytes[cd_off:eocd_off], n_tot

        def _shift_cd_offsets(cd_bytes: bytes, delta: int) -> bytes:
            out = bytearray(cd_bytes)
            p = 0
            while p < len(out):
                assert out[p : p + 4] == b"PK\x01\x02"
                nlen, elen, clen = struct.unpack_from("<HHH", out, p + 28)
                old_off = struct.unpack_from("<I", out, p + 42)[0]
                struct.pack_into("<I", out, p + 42, old_off + delta)
                p += 46 + nlen + elen + clen
            assert p == len(out)
            return bytes(out)

        def _make_evil_zip_matching_lfh_len(target_lfh_len: int, entries: list[tuple[str, bytes]]) -> bytes:
            base_buf = io.BytesIO()
            with zipfile.ZipFile(base_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf_e:
                for ename, edata in entries:
                    zf_e.writestr(ename, edata)
            base_lfh, _, _ = _split_zip_parts(base_buf.getvalue())
            pad_name = "pad.bin"
            hdr_overhead = 30 + len(pad_name)
            assert target_lfh_len >= len(base_lfh) + hdr_overhead
            pad_len = target_lfh_len - len(base_lfh) - hdr_overhead
            padded_buf = io.BytesIO()
            with zipfile.ZipFile(padded_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf_e:
                for ename, edata in entries:
                    zf_e.writestr(ename, edata)
                zf_e.writestr(pad_name, b"\x00" * pad_len, compress_type=zipfile.ZIP_STORED)
            return padded_buf.getvalue()

        def _make_aligned_concat_polyglot(good_zip: bytes, evil_entries: list[tuple[str, bytes]]) -> bytes:
            good_lfh, good_cd, good_n = _split_zip_parts(good_zip)
            evil_zip = _make_evil_zip_matching_lfh_len(len(good_lfh), evil_entries)
            evil_lfh, evil_cd, _ = _split_zip_parts(evil_zip)
            assert len(evil_lfh) == len(good_lfh)
            eocd = struct.pack(
                "<4sHHHHIIH",
                b"PK\x05\x06",
                0,
                0,
                good_n,
                good_n,
                len(good_cd),
                len(evil_lfh),
                0,
            )
            return evil_lfh + evil_cd + good_lfh + good_cd + eocd

        def _make_zip64_split_archive(
            good_zip: bytes,
            evil_entries: list[tuple[str, bytes]],
            *,
            partial_size_sentinel: bool = False,
        ) -> bytes:
            evil_buf = io.BytesIO()
            with zipfile.ZipFile(evil_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf_e:
                for ename, edata in evil_entries:
                    zf_e.writestr(ename, edata)
            evil_lfh, evil_cd, evil_n = _split_zip_parts(evil_buf.getvalue())
            good_lfh, good_cd, good_n = _split_zip_parts(good_zip)
            good_cd_shifted = _shift_cd_offsets(good_cd, len(evil_lfh))
            evil_cd_off = len(evil_lfh) + len(good_lfh)
            stop_sep = b"STOP"
            good_cd_off = evil_cd_off + len(evil_cd) + len(stop_sep)
            z64_eocd_off = good_cd_off + len(good_cd_shifted)
            z64_eocd = struct.pack(
                "<4sQHHIIQQQQ",
                b"PK\x06\x06",
                44,
                45,
                45,
                0,
                0,
                good_n,
                good_n,
                len(good_cd_shifted),
                good_cd_off,
            )
            z64_loc = struct.pack("<4sIQI", b"PK\x06\x07", 0, z64_eocd_off, 1)
            eocd32 = struct.pack(
                "<4sHHHHIIH",
                b"PK\x05\x06",
                0,
                0,
                evil_n,
                evil_n,
                0xFFFFFFFF if partial_size_sentinel else len(evil_cd),
                evil_cd_off,
                0,
            )
            return evil_lfh + good_lfh + evil_cd + stop_sep + good_cd_shifted + z64_eocd + z64_loc + eocd32

        def _wrap_consistent_zip64(good_zip: bytes, *, use_sentinels: bool) -> bytes:
            good_lfh, good_cd, good_n = _split_zip_parts(good_zip)
            cd_off = len(good_lfh)
            cd_sz = len(good_cd)
            z64_eocd_off = cd_off + cd_sz
            z64_eocd = struct.pack(
                "<4sQHHIIQQQQ",
                b"PK\x06\x06",
                44,
                45,
                45,
                0,
                0,
                good_n,
                good_n,
                cd_sz,
                cd_off,
            )
            z64_loc = struct.pack("<4sIQI", b"PK\x06\x07", 0, z64_eocd_off, 1)
            eocd32 = struct.pack(
                "<4sHHHHIIH",
                b"PK\x05\x06",
                0xFFFF if use_sentinels else 0,
                0xFFFF if use_sentinels else 0,
                0xFFFF if use_sentinels else good_n,
                0xFFFF if use_sentinels else good_n,
                0xFFFFFFFF if use_sentinels else cd_sz,
                0xFFFFFFFF if use_sentinels else cd_off,
                0,
            )
            return good_lfh + good_cd + z64_eocd + z64_loc + eocd32

        class _NonSeekableStream(io.RawIOBase):
            def __init__(self, target: io.BytesIO) -> None:
                self._target = target

            def writable(self) -> bool:
                return True

            def seekable(self) -> bool:
                return False

            def write(self, b: bytes | bytearray | memoryview) -> int:
                return self._target.write(b)

        def _repack_streaming_bit3(good_zip: bytes, *, force_zip64: bool = False) -> bytes:
            out_buf = io.BytesIO()
            with (
                zipfile.ZipFile(io.BytesIO(good_zip), "r") as zin,
                zipfile.ZipFile(_NonSeekableStream(out_buf), "w", compression=zipfile.ZIP_DEFLATED) as zout,
            ):
                for item in zin.infolist():
                    data = zin.read(item)
                    with zout.open(item.filename, "w", force_zip64=force_zip64) as member_out:
                        member_out.write(data)
            return out_buf.getvalue()

        evil_msix_payloads = [
            ("AppxManifest.xml", evil_manifest),
            ("signing.pfx", b"PRIVATE_KEY_MATERIAL"),
        ]
        evil_upload_payloads = [
            ("bare_rogue_x86.msix", b"PK\x03\x04EVIL"),
            ("signing.pfx", b"OUTER_UPLOAD_SECRET_PFX"),
        ]
        evil_bundle_payloads = [
            ("TotalDrop_0.0.0.1_x86.msix", b"PK\x03\x04EVIL"),
            ("signing.pfx", b"OUTER_BUNDLE_SECRET_PFX"),
        ]
        evil_sym_payloads = [("signing.pfx", b"SYM_SECRET_PFX")]

        # 28a: Aligned concat > 0 polyglot inside arm64.msix in .msixbundle AND on outer .msixupload.
        arm64_concat_poly = _make_aligned_concat_polyglot(arm64_ok, evil_msix_payloads)
        bundle_concat_poly = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_concat_poly),
            ],
        )
        expect_fail(
            "case-28a-concat-polyglot-msix-in-bundle",
            lambda: verify_msixbundle_archive(
                bundle_concat_poly,
                "28a-concat.msixbundle",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "concat",
        )
        upload_ok_raw = upload_ok_path.read_bytes()
        upload_concat_poly_path = tmp_dir / "28a-outer-concat.msixupload"
        upload_concat_poly_path.write_bytes(_make_aligned_concat_polyglot(upload_ok_raw, evil_upload_payloads))
        expect_fail(
            "case-28a-concat-polyglot-outer-msixupload",
            lambda: verify_msixupload_archive(
                upload_concat_poly_path,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "concat",
        )

        # 28b: Naive prepended evil.zip + arm64.msix (concat > 0).
        naive_evil_buf = io.BytesIO()
        with zipfile.ZipFile(naive_evil_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf_ne:
            zf_ne.writestr("signing.pfx", b"NAIVE_PREPENDED_KEY")
        arm64_naive_prepended = naive_evil_buf.getvalue() + arm64_ok
        expect_fail(
            "case-28b-naive-prepended-zip",
            lambda: verify_msix_archive(
                arm64_naive_prepended,
                "28b-prepended.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "concat",
        )

        # 28c: Zip64 EOCD vs 32-bit EOCD split across .msix, .msixbundle, .appxsym in .msixupload, and outer .msixupload.
        arm64_z64_split = _make_zip64_split_archive(arm64_ok, evil_msix_payloads, partial_size_sentinel=False)
        expect_fail(
            "case-28c-z64-split-msix",
            lambda: verify_msix_archive(
                arm64_z64_split,
                "28c-z64-split.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "Zip64 EOCD",
        )
        bundle_z64_split = _make_zip64_split_archive(bundle_ok_bytes, evil_bundle_payloads, partial_size_sentinel=False)
        expect_fail(
            "case-28c-z64-split-bundle",
            lambda: verify_msixbundle_archive(
                bundle_z64_split,
                "28c-z64-split.msixbundle",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "Zip64 EOCD",
        )
        sym_z64_split = _make_zip64_split_archive(sym_ok, evil_sym_payloads, partial_size_sentinel=False)
        upload_sym_z64_path = tmp_dir / "28c-z64-split-appxsym.msixupload"
        upload_sym_z64_path.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_z64_split),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                ]
            )
        )
        expect_fail(
            "case-28c-z64-split-appxsym-in-upload",
            lambda: verify_msixupload_archive(
                upload_sym_z64_path,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "Zip64 EOCD",
        )
        upload_outer_z64_path = tmp_dir / "28c-z64-split-outer.msixupload"
        upload_outer_z64_path.write_bytes(
            _make_zip64_split_archive(upload_ok_raw, evil_upload_payloads, partial_size_sentinel=False)
        )
        expect_fail(
            "case-28c-z64-split-outer-upload",
            lambda: verify_msixupload_archive(
                upload_outer_z64_path,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "Zip64 EOCD",
        )

        # 28d: Partial-sentinel Zip64 EOCD split (size_cd == 0xFFFFFFFF only, offset_cd == off_evil).
        arm64_z64_partial = _make_zip64_split_archive(arm64_ok, evil_msix_payloads, partial_size_sentinel=True)
        expect_fail(
            "case-28d-z64-partial-sentinel-split",
            lambda: verify_msix_archive(
                arm64_z64_partial,
                "28d-z64-partial.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "Zip64 EOCD",
        )

        # 28e: Trailing garbage bytes appended after EOCD AND bogus comment_len exceeding EOF.
        arm64_trailing = arm64_ok + b"TRAILING_SMUGGLED_KEY_BYTES_0123456789"
        expect_fail(
            "case-28e-trailing-garbage-after-eocd",
            lambda: verify_msix_archive(
                arm64_trailing,
                "28e-trailing.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "anchored to EOF",
        )
        arm64_bogus_cmt = bytearray(arm64_ok)
        struct.pack_into("<H", arm64_bogus_cmt, len(arm64_bogus_cmt) - 2, 12345)
        expect_fail(
            "case-28e-bogus-comment-len",
            lambda: verify_msix_archive(
                bytes(arm64_bogus_cmt),
                "28e-bogus-cmt.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "comment_len",
        )

        # 28f: EOCD entries_total / entries_disk mismatch (0 != len(infos)).
        arm64_zero_entries = bytearray(arm64_ok)
        eocd_idx = len(arm64_zero_entries) - 22
        struct.pack_into("<HH", arm64_zero_entries, eocd_idx + 8, 0, 0)
        expect_fail(
            "case-28f-eocd-entries-mismatch",
            lambda: verify_msix_archive(
                bytes(arm64_zero_entries),
                "28f-entries.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "entry count mismatch",
        )

        # 28g: LFH vs CD compression method, CRC-32, and compressed/uncompressed size mismatches.
        with zipfile.ZipFile(io.BytesIO(arm64_ok), "r") as zf_m:
            manifest_off = zf_m.getinfo("AppxManifest.xml").header_offset
        for sub_id, patch_off, patch_fmt, patch_val, expected_err in (
            ("28g-lfh-method", manifest_off + 8, "<H", zipfile.ZIP_STORED, "compression method"),
            ("28g-lfh-crc", manifest_off + 14, "<I", 0xDEADBEEF, "CRC-32"),
            ("28g-lfh-comp-size", manifest_off + 18, "<I", 12345, "compressed size"),
            ("28g-lfh-uncomp-size", manifest_off + 22, "<I", 67890, "uncompressed size"),
        ):
            mut = bytearray(arm64_ok)
            struct.pack_into(patch_fmt, mut, patch_off, patch_val)
            expect_fail(
                f"case-{sub_id}",
                lambda m=bytes(mut), s=sub_id: verify_msix_archive(
                    m,
                    f"{s}.msix",
                    arch="arm64",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                expected_err,
            )

        # 28h: Nested PK\x05\x06 in archive comment, unreferenced inter-entry slack, overlapping LFH, & LFH flag/name parity.
        arm64_nested_cmt = bytearray(arm64_ok)
        nested_cmt = b" benign PK\x05\x06 end"
        struct.pack_into("<H", arm64_nested_cmt, len(arm64_nested_cmt) - 2, len(nested_cmt))
        arm64_nested_cmt.extend(nested_cmt)
        try:
            verify_msix_archive(
                bytes(arm64_nested_cmt),
                "28h-nested-cmt.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            )
            raise AssertionError("self-test case-28h-nested-eocd-comment: expected rejection, but verification passed")
        except (ValueError, zipfile.BadZipFile):
            pass

        lfh_part, cd_part, n_part = _split_zip_parts(arm64_ok)
        slack = b"SMUGGLED_INTER_ENTRY_SLACK"
        cd_off_slack = len(lfh_part) + len(slack)
        eocd_slack = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, n_part, n_part, len(cd_part), cd_off_slack, 0)
        arm64_slack = lfh_part + slack + cd_part + eocd_slack
        expect_fail(
            "case-28h-unreferenced-slack-gap",
            lambda: verify_msix_archive(
                arm64_slack,
                "28h-slack.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "trailing gap",
        )

        # LFH bit-3 flag mismatch (LFH has 0x0008, CD does not) & LFH filename mismatch & overlapping LFH offsets.
        mut_flag = bytearray(arm64_ok)
        cur_lfh_flag = struct.unpack_from("<H", mut_flag, manifest_off + 6)[0]
        struct.pack_into("<H", mut_flag, manifest_off + 6, cur_lfh_flag | 0x0008)
        expect_fail(
            "case-28h-lfh-bit3-flag-mismatch",
            lambda: verify_msix_archive(
                bytes(mut_flag),
                "28h-lfh-flag.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "data-descriptor flag",
        )

        mut_name = bytearray(arm64_ok)
        mut_name[manifest_off + 30 + len("AppxManifest.xm")] = ord("x")
        expect_fail(
            "case-28h-lfh-name-mismatch",
            lambda: verify_msix_archive(
                bytes(mut_name),
                "28h-lfh-name.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "corrupted ZIP",
        )
        # Shadowed duplicate where Entry 1 has mismatched LFH name (skipped by zf.testzip()) and Entry 2 is valid.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            arm64_shadow_lfh = _patch_zip_raw_entries(
                arm64_ok,
                [("AppxManifest.xml", good_arm64_manifest, b"")],
            )
        mut_shadow = bytearray(arm64_shadow_lfh)
        mut_shadow[manifest_off + 30 + len("AppxManifest.xm")] = ord("x")
        expect_fail(
            "case-28h-shadowed-lfh-name-mismatch",
            lambda: verify_msix_archive(
                bytes(mut_shadow),
                "28h-shadow-lfh-name.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "local-header filename",
        )

        cd_overlap = bytearray(cd_part)
        nlen0, elen0, clen0 = struct.unpack_from("<HHH", cd_overlap, 28)
        rec1_pos = 46 + nlen0 + elen0 + clen0
        struct.pack_into("<I", cd_overlap, rec1_pos + 42, 0)
        eocd_base = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, n_part, n_part, len(cd_overlap), len(lfh_part), 0)
        expect_fail(
            "case-28h-overlapping-lfh-offset",
            lambda: verify_msix_archive(
                lfh_part + bytes(cd_overlap) + eocd_base,
                "28h-overlap.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "overlapping/duplicate",
        )

        # Positive controls for Case 28:
        # (1) Legitimate consistent Zip64 EOCD + Locator (both sentinel 0xFFFF/0xFFFFFFFF and matching non-sentinel).
        for pos_id, use_sentinels in (("28-pos-z64-sentinels", True), ("28-pos-z64-matching", False)):
            arm64_z64_ok = _wrap_consistent_zip64(arm64_ok, use_sentinels=use_sentinels)
            verify_msix_archive(
                arm64_z64_ok,
                f"{pos_id}.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            )
        # (2) Streaming bit-3 Data Descriptor (flag_bits & 0x0008, LFH CRC/sizes == 0, both 16-byte & Zip64 24-byte).
        for pos_id, fz64 in (("28-pos-stream-bit3", False), ("28-pos-stream-bit3-z64", True)):
            arm64_stream_ok = _repack_streaming_bit3(arm64_ok, force_zip64=fz64)
            verify_msix_archive(
                arm64_stream_ok,
                f"{pos_id}.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            )
        # (3) Benign archive comment anchored cleanly to EOF passes.
        arm64_benign_cmt = bytearray(arm64_ok)
        benign_cmt = b"TotalDrop Store build metadata"
        struct.pack_into("<H", arm64_benign_cmt, len(arm64_benign_cmt) - 2, len(benign_cmt))
        arm64_benign_cmt.extend(benign_cmt)
        verify_msix_archive(
            bytes(arm64_benign_cmt),
            "28-pos-benign-comment.msix",
            arch="arm64",
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            run_live_smoke=False,
        )

        # Case 29: Exact raw stream verification (ZIP_STORED size parity + ZIP_DEFLATED overflow/underflow/slack),
        # strict OPC compression method allowlist (STORED/DEFLATED only), forbidden flag bits, & LFH 0x0001 Zip64 parity.
        def _crc32_forge_suffix(prefix: bytes, target_crc: int) -> bytes:
            cur_state = (zlib.crc32(prefix) ^ 0xFFFFFFFF) & 0xFFFFFFFF
            state = (target_crc ^ 0xFFFFFFFF) & 0xFFFFFFFF
            for _ in range(32):
                if state & 0x80000000:
                    state = (((state ^ 0xEDB88320) << 1) | 1) & 0xFFFFFFFF
                else:
                    state = (state << 1) & 0xFFFFFFFF
            return struct.pack("<I", state ^ cur_state)

        def _make_crc_colliding_evil_zip(good_prefix: bytes, entries: list[tuple[str, bytes]]) -> bytes:
            ebuf = io.BytesIO()
            with zipfile.ZipFile(ebuf, "w", compression=zipfile.ZIP_DEFLATED) as zfe:
                for ename, edata in entries:
                    zfe.writestr(ename, edata)
            e_lfh, e_cd, e_n = _split_zip_parts(ebuf.getvalue())
            e_cd_shifted = _shift_cd_offsets(e_cd, len(good_prefix))
            e_cd_off = len(good_prefix) + len(e_lfh)
            e_eocd = struct.pack(
                "<4sHHHHIIH",
                b"PK\x05\x06",
                0,
                0,
                e_n,
                e_n,
                len(e_cd_shifted),
                e_cd_off,
                4,
            )
            target_crc = zlib.crc32(good_prefix) & 0xFFFFFFFF
            body = e_lfh + e_cd_shifted + e_eocd
            crc_fix = _crc32_forge_suffix(good_prefix + body, target_crc)
            out = body + crc_fix
            assert (zlib.crc32(good_prefix + out) & 0xFFFFFFFF) == target_crc
            return out

        def _rebuild_zip_with_raw_entry(
            base_zip: bytes,
            target_name: str,
            *,
            method: int,
            raw_payload: bytes,
            declared_uncomp_size: int,
            declared_crc: int,
            append_if_missing: bool = False,
            lfh_extra_override: bytes | None = None,
            lfh_flags_or: int = 0,
            cd_flags_or: int = 0,
        ) -> bytes:
            lfh_parts: list[bytes] = []
            cd_parts: list[bytes] = []
            cur_off = 0
            replaced = False

            def _emit_entry(
                name_bytes: bytes,
                emethod: int,
                e_lfh_flags: int,
                e_cd_flags: int,
                ecrc: int,
                ecsz: int,
                eusz: int,
                e_lfh_extra: bytes,
                e_cd_extra: bytes,
                epayload: bytes,
            ) -> None:
                nonlocal cur_off
                lfh_hdr = struct.pack(
                    "<4sHHHHHIIIHH",
                    b"PK\x03\x04",
                    20,
                    e_lfh_flags,
                    emethod,
                    0,
                    0,
                    ecrc,
                    ecsz,
                    eusz,
                    len(name_bytes),
                    len(e_lfh_extra),
                )
                cd_hdr = struct.pack(
                    "<4sHHHHHHIIIHHHHHII",
                    b"PK\x01\x02",
                    20,
                    20,
                    e_cd_flags,
                    emethod,
                    0,
                    0,
                    ecrc,
                    ecsz,
                    eusz,
                    len(name_bytes),
                    len(e_cd_extra),
                    0,
                    0,
                    0,
                    0,
                    cur_off,
                )
                lfh_parts.append(lfh_hdr + name_bytes + e_lfh_extra + epayload)
                cd_parts.append(cd_hdr + name_bytes + e_cd_extra)
                cur_off += len(lfh_hdr) + len(name_bytes) + len(e_lfh_extra) + len(epayload)

            with zipfile.ZipFile(io.BytesIO(base_zip), "r") as zin:
                for info in zin.infolist():
                    nb = info.orig_filename.encode("utf-8" if (info.flag_bits & 0x0800) else "cp437")
                    if info.orig_filename == target_name:
                        replaced = True
                        lextra = lfh_extra_override if lfh_extra_override is not None else b""
                        _emit_entry(
                            nb,
                            method,
                            (info.flag_bits & ~0x0008) | lfh_flags_or,
                            (info.flag_bits & ~0x0008) | cd_flags_or,
                            declared_crc,
                            len(raw_payload),
                            declared_uncomp_size,
                            lextra,
                            b"",
                            raw_payload,
                        )
                    else:
                        data = zin.read(info)
                        cobj = zlib.compressobj(6, zlib.DEFLATED, -15)
                        cdata = cobj.compress(data) + cobj.flush()
                        _emit_entry(
                            nb,
                            zipfile.ZIP_DEFLATED,
                            info.flag_bits & ~0x0008,
                            info.flag_bits & ~0x0008,
                            zlib.crc32(data) & 0xFFFFFFFF,
                            len(cdata),
                            len(data),
                            b"",
                            b"",
                            cdata,
                        )
            if not replaced:
                assert append_if_missing, f"entry {target_name!r} not found"
                nb = target_name.encode("ascii")
                lextra = lfh_extra_override if lfh_extra_override is not None else b""
                _emit_entry(
                    nb,
                    method,
                    lfh_flags_or,
                    cd_flags_or,
                    declared_crc,
                    len(raw_payload),
                    declared_uncomp_size,
                    lextra,
                    b"",
                    raw_payload,
                )
            lfh_blob = b"".join(lfh_parts)
            cd_blob = b"".join(cd_parts)
            eocd = struct.pack(
                "<4sHHHHIIH",
                b"PK\x05\x06",
                0,
                0,
                len(cd_parts),
                len(cd_parts),
                len(cd_blob),
                len(lfh_blob),
                0,
            )
            return lfh_blob + cd_blob + eocd

        # 29a: ZIP_STORED compress_size != file_size + GF(2) CRC-32 collision across all 4 archive layers,
        # PE overlay smuggling, directory payload smuggling, and compress_size < file_size.
        evil_bundle_tail = _make_crc_colliding_evil_zip(bundle_ok_bytes, evil_bundle_payloads)
        upload_stored_smuggle_path = tmp_dir / "29a-stored-bundle-smuggle.msixupload"
        upload_stored_smuggle_path.write_bytes(
            _rebuild_zip_with_raw_entry(
                upload_ok_raw,
                bundle_ok_path.name,
                method=zipfile.ZIP_STORED,
                raw_payload=bundle_ok_bytes + evil_bundle_tail,
                declared_uncomp_size=len(bundle_ok_bytes),
                declared_crc=zlib.crc32(bundle_ok_bytes) & 0xFFFFFFFF,
            )
        )
        expect_fail(
            "case-29a-stored-bundle-in-upload-with-sha256",
            lambda: verify_msixupload_archive(
                upload_stored_smuggle_path,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                expected_bundle_path=bundle_ok_path,
                run_live_smoke=False,
            ),
            "ZIP_STORED",
        )

        evil_msix_tail = _make_crc_colliding_evil_zip(arm64_ok, evil_msix_payloads)
        bundle_stored_msix = _rebuild_zip_with_raw_entry(
            bundle_ok_bytes,
            f"TotalDrop_{store_ver}_arm64.msix",
            method=zipfile.ZIP_STORED,
            raw_payload=arm64_ok + evil_msix_tail,
            declared_uncomp_size=len(arm64_ok),
            declared_crc=zlib.crc32(arm64_ok) & 0xFFFFFFFF,
        )
        expect_fail(
            "case-29a-stored-msix-in-bundle",
            lambda: verify_msixbundle_archive(
                bundle_stored_msix,
                "29a-stored-msix.msixbundle",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "ZIP_STORED",
        )

        evil_sym_tail = _make_crc_colliding_evil_zip(sym_ok, evil_sym_payloads)
        upload_stored_sym_path = tmp_dir / "29a-stored-appxsym.msixupload"
        upload_stored_sym_path.write_bytes(
            _rebuild_zip_with_raw_entry(
                upload_ok_raw,
                f"TotalDrop_{store_ver}_x64.appxsym",
                method=zipfile.ZIP_STORED,
                raw_payload=sym_ok + evil_sym_tail,
                declared_uncomp_size=len(sym_ok),
                declared_crc=zlib.crc32(sym_ok) & 0xFFFFFFFF,
            )
        )
        expect_fail(
            "case-29a-stored-appxsym-in-upload",
            lambda: verify_msixupload_archive(
                upload_stored_sym_path,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "ZIP_STORED",
        )

        with zipfile.ZipFile(io.BytesIO(arm64_ok), "r") as zf_pe:
            exe_good_bytes = zf_pe.read("totaldrop-winui.exe")
        exe_crc = zlib.crc32(exe_good_bytes) & 0xFFFFFFFF
        pe_overlay = b"SMUGGLED_UNVERIFIED_PE_OVERLAY_PAYLOAD_DATA"
        pe_overlay_fix = _crc32_forge_suffix(exe_good_bytes + pe_overlay, exe_crc)
        arm64_pe_overlay = _rebuild_zip_with_raw_entry(
            arm64_ok,
            "totaldrop-winui.exe",
            method=zipfile.ZIP_STORED,
            raw_payload=exe_good_bytes + pe_overlay + pe_overlay_fix,
            declared_uncomp_size=len(exe_good_bytes),
            declared_crc=exe_crc,
        )
        expect_fail(
            "case-29a-stored-pe-overlay-msix",
            lambda: verify_msix_archive(
                arm64_pe_overlay,
                "29a-pe-overlay.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "ZIP_STORED",
        )

        arm64_dir_stored = _rebuild_zip_with_raw_entry(
            arm64_ok,
            "Assets/",
            method=zipfile.ZIP_STORED,
            raw_payload=b"SMUGGLED_DIR_PAYLOAD_32_BYTES_00",
            declared_uncomp_size=0,
            declared_crc=0,
            append_if_missing=True,
        )
        expect_fail(
            "case-29a-stored-dir-csz-gt-0",
            lambda: verify_msix_archive(
                arm64_dir_stored,
                "29a-dir-stored.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "ZIP_STORED",
        )

        arm64_stored_short = _rebuild_zip_with_raw_entry(
            arm64_ok,
            "AppxBlockMap.xml",
            method=zipfile.ZIP_STORED,
            raw_payload=b"<BlockMap />",
            declared_uncomp_size=64,
            declared_crc=zlib.crc32(b"<BlockMap />") & 0xFFFFFFFF,
        )
        expect_fail(
            "case-29a-stored-compress-lt-file-size",
            lambda: verify_msix_archive(
                arm64_stored_short,
                "29a-stored-short.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "ZIP_STORED",
        )

        # 29b: ZIP_DEFLATED uncompressed-stream overflow + GF(2) CRC-32 collision, underflow, and trailing slack.
        c_ovf = zlib.compressobj(6, zlib.DEFLATED, -15)
        deflated_bundle_ovf = c_ovf.compress(bundle_ok_bytes + evil_bundle_tail) + c_ovf.flush()
        upload_deflate_ovf_path = tmp_dir / "29b-deflate-overflow.msixupload"
        upload_deflate_ovf_path.write_bytes(
            _rebuild_zip_with_raw_entry(
                upload_ok_raw,
                bundle_ok_path.name,
                method=zipfile.ZIP_DEFLATED,
                raw_payload=deflated_bundle_ovf,
                declared_uncomp_size=len(bundle_ok_bytes),
                declared_crc=zlib.crc32(bundle_ok_bytes) & 0xFFFFFFFF,
            )
        )
        expect_fail(
            "case-29b-deflate-overflow-crc-collision",
            lambda: verify_msixupload_archive(
                upload_deflate_ovf_path,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                expected_bundle_path=bundle_ok_path,
                run_live_smoke=False,
            ),
            "exceeds declared file_size",
        )

        c_short = zlib.compressobj(6, zlib.DEFLATED, -15)
        deflated_short = c_short.compress(b"<BlockMap />") + c_short.flush()
        arm64_deflate_underflow = _rebuild_zip_with_raw_entry(
            arm64_ok,
            "AppxBlockMap.xml",
            method=zipfile.ZIP_DEFLATED,
            raw_payload=deflated_short,
            declared_uncomp_size=512,
            declared_crc=zlib.crc32(b"<BlockMap />") & 0xFFFFFFFF,
        )
        expect_fail(
            "case-29b-deflate-underflow",
            lambda: verify_msix_archive(
                arm64_deflate_underflow,
                "29b-deflate-underflow.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "length mismatch",
        )

        c_slack = zlib.compressobj(6, zlib.DEFLATED, -15)
        deflated_with_slack = (
            c_slack.compress(good_arm64_manifest)
            + c_slack.flush()
            + b"TRAILING_UNVERIFIED_SLACK_AFTER_BFINAL"
        )
        arm64_deflate_slack = _rebuild_zip_with_raw_entry(
            arm64_ok,
            "AppxManifest.xml",
            method=zipfile.ZIP_DEFLATED,
            raw_payload=deflated_with_slack,
            declared_uncomp_size=len(good_arm64_manifest),
            declared_crc=zlib.crc32(good_arm64_manifest) & 0xFFFFFFFF,
        )
        expect_fail(
            "case-29b-deflate-trailing-slack-after-bfinal",
            lambda: verify_msix_archive(
                arm64_deflate_slack,
                "29b-deflate-slack.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "trailing unconsumed bytes",
        )

        # 29c: Unsupported OPC/MSIX compression methods (ZIP_BZIP2=12, valid ZIP_LZMA=14, corrupt ZIP_LZMA=14).
        for sub_id, cmethod in (
            ("29c-bzip2", zipfile.ZIP_BZIP2),
            ("29c-lzma-valid", zipfile.ZIP_LZMA),
        ):
            repack_buf = io.BytesIO()
            with (
                zipfile.ZipFile(io.BytesIO(arm64_ok), "r") as zin,
                zipfile.ZipFile(repack_buf, "w", compression=zipfile.ZIP_DEFLATED) as zout,
            ):
                for item in zin.infolist():
                    data = zin.read(item)
                    if item.filename == "AppxBlockMap.xml":
                        zout.writestr(item.filename, data, compress_type=cmethod)
                    else:
                        zout.writestr(item.filename, data, compress_type=zipfile.ZIP_DEFLATED)
            repacked_bytes = repack_buf.getvalue()
            expect_fail(
                f"case-{sub_id}",
                lambda b=repacked_bytes, s=sub_id: verify_msix_archive(
                    b,
                    f"{s}.msix",
                    arch="arm64",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                "unsupported OPC/MSIX compression method",
            )
            if cmethod == zipfile.ZIP_LZMA:
                # Corrupt LZMA payload must raise clean ValueError (never uncaught _lzma.LZMAError).
                arm64_lzma_corrupt = _rebuild_zip_with_raw_entry(
                    arm64_ok,
                    "AppxBlockMap.xml",
                    method=zipfile.ZIP_LZMA,
                    raw_payload=b"\x09\x14\x05\x00\x5d\x00\x00\x80\x00\xff\xff\xfe\xfa\x01\x02",
                    declared_uncomp_size=12,
                    declared_crc=zlib.crc32(b"<BlockMap />") & 0xFFFFFFFF,
                )
                try:
                    verify_msix_archive(
                        arm64_lzma_corrupt,
                        "29c-lzma-corrupt.msix",
                        arch="arm64",
                        expected_version=store_ver,
                        expect_signed=False,
                        store_mode=True,
                        allow_test_identity=False,
                        run_live_smoke=False,
                    )
                    raise AssertionError("self-test case-29c-lzma-corrupt: expected rejection, but verification passed")
                except ValueError as exc:
                    assert "unsupported OPC/MSIX compression method" in str(exc), str(exc)

        # 29d: Forbidden flag bits (LFH-only 0x0020/0x0040/0x2000 & CD+LFH 0x2000) and LFH 0x0001 Zip64 consistency.
        for sub_id, lfh_f, cd_f in (
            ("29d-lfh-flag-0x0020", 0x0020, 0),
            ("29d-lfh-flag-0x0040", 0x0040, 0),
            ("29d-lfh-flag-0x2000", 0x2000, 0),
            ("29d-cd-lfh-flag-0x2000", 0x2000, 0x2000),
        ):
            c_m = zlib.compressobj(6, zlib.DEFLATED, -15)
            d_m = c_m.compress(b"<BlockMap />") + c_m.flush()
            arm64_bad_flag = _rebuild_zip_with_raw_entry(
                arm64_ok,
                "AppxBlockMap.xml",
                method=zipfile.ZIP_DEFLATED,
                raw_payload=d_m,
                declared_uncomp_size=len(b"<BlockMap />"),
                declared_crc=zlib.crc32(b"<BlockMap />") & 0xFFFFFFFF,
                lfh_flags_or=lfh_f,
                cd_flags_or=cd_f,
            )
            expect_fail(
                f"case-{sub_id}",
                lambda b=arm64_bad_flag, s=sub_id: verify_msix_archive(
                    b,
                    f"{s}.msix",
                    arch="arm64",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                "forbidden general-purpose flag bits",
            )

        # Non-streaming bogus 0x0001 Zip64 extra field with non-sentinel 32-bit LFH sizes.
        c_bm = zlib.compressobj(6, zlib.DEFLATED, -15)
        d_bm = c_bm.compress(b"<BlockMap />") + c_bm.flush()
        bogus_z64_extra = struct.pack("<HHQQ", 0x0001, 16, 123456789, 987654321)
        arm64_bogus_z64 = _rebuild_zip_with_raw_entry(
            arm64_ok,
            "AppxBlockMap.xml",
            method=zipfile.ZIP_DEFLATED,
            raw_payload=d_bm,
            declared_uncomp_size=len(b"<BlockMap />"),
            declared_crc=zlib.crc32(b"<BlockMap />") & 0xFFFFFFFF,
            lfh_extra_override=bogus_z64_extra,
        )
        expect_fail(
            "case-29d-nonstream-bogus-0001",
            lambda: verify_msix_archive(
                arm64_bogus_z64,
                "29d-nonstream-bogus-0001.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "0x0001 Zip64",
        )

        # Streaming bit-3 with 0xFFFFFFFF sentinel and NO 0x0001 extra field.
        arm64_stream_base = bytearray(_repack_streaming_bit3(arm64_ok, force_zip64=False))
        with zipfile.ZipFile(io.BytesIO(bytes(arm64_stream_base)), "r") as zf_sb:
            s_off = zf_sb.getinfo("AppxManifest.xml").header_offset
        struct.pack_into("<II", arm64_stream_base, s_off + 18, 0xFFFFFFFF, 0xFFFFFFFF)
        expect_fail(
            "case-29d-stream-sentinel-no-0001",
            lambda: verify_msix_archive(
                bytes(arm64_stream_base),
                "29d-stream-sentinel-no-0001.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "0x0001 Zip64",
        )

        # Streaming bit-3 with forged 0x0001 Zip64 extra field sizes (both sentinel and zero 32-bit LFH sizes).
        arm64_stream_z64_base = bytearray(_repack_streaming_bit3(arm64_ok, force_zip64=True))
        with zipfile.ZipFile(io.BytesIO(bytes(arm64_stream_z64_base)), "r") as zf_sz:
            sz_info = zf_sz.getinfo("AppxManifest.xml")
            sz_off = sz_info.header_offset
        sz_nlen, sz_elen = struct.unpack_from("<HH", arm64_stream_z64_base, sz_off + 26)
        assert sz_elen >= 20
        struct.pack_into("<QQ", arm64_stream_z64_base, sz_off + 30 + sz_nlen + 4, 999999, 888888)
        expect_fail(
            "case-29d-stream-forged-0001-sentinel",
            lambda: verify_msix_archive(
                bytes(arm64_stream_z64_base),
                "29d-stream-forged-0001.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "0x0001 Zip64",
        )
        struct.pack_into("<II", arm64_stream_z64_base, sz_off + 18, 0, 0)
        expect_fail(
            "case-29d-stream-forged-0001-zero-lfh",
            lambda: verify_msix_archive(
                bytes(arm64_stream_z64_base),
                "29d-stream-forged-0001-zero.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "0x0001 Zip64",
        )

        # Positive controls for Case 29:
        # (1) Pure ZIP_STORED archive (including empty ZIP_STORED Assets/ directory) passes cleanly.
        stored_ok_buf = io.BytesIO()
        with (
            zipfile.ZipFile(io.BytesIO(arm64_ok), "r") as zin,
            zipfile.ZipFile(stored_ok_buf, "w", compression=zipfile.ZIP_STORED) as zout,
        ):
            zout.writestr("Assets/", b"", compress_type=zipfile.ZIP_STORED)
            for item in zin.infolist():
                zout.writestr(item.filename, zin.read(item), compress_type=zipfile.ZIP_STORED)
        verify_msix_archive(
            stored_ok_buf.getvalue(),
            "29-pos-stored-valid.msix",
            arch="arm64",
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            run_live_smoke=False,
        )
        # (2) Multi-step >1 MiB exact boundary ZIP_DEFLATED entry passes cleanly.
        arm64_large_deflate = _make_synthetic_msix(
            arm64_tpl,
            arch="arm64",
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            extra_entries=[("large_boundary.bin", b"A" * _STREAM_DECOMPRESS_STEP_BYTES)],
        )
        verify_msix_archive(
            arm64_large_deflate,
            "29-pos-large-deflate-boundary.msix",
            arch="arm64",
            expected_version=store_ver,
            expect_signed=False,
            store_mode=True,
            allow_test_identity=False,
            run_live_smoke=False,
        )

        # Case 30: .msixupload dual-arch .appxsym stem correlation & MSF 7.00 PDB header checks.
        missing_arm64_sym_upload = tmp_dir / "missing-arm64-sym.msixupload"
        missing_arm64_sym_upload.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok),
                ]
            )
        )
        expect_fail(
            "case-30a-missing-arm64-appxsym",
            lambda: verify_msixupload_archive(
                missing_arm64_sym_upload,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "arm64.appxsym",
        )
        unmatched_sym_upload = tmp_dir / "unmatched-sym.msixupload"
        unmatched_sym_upload.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    ("unrelated_foo.appxsym", sym_ok),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                ]
            )
        )
        expect_fail(
            "case-30b-unmatched-appxsym-stem",
            lambda: verify_msixupload_archive(
                unmatched_sym_upload,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "unrelated_foo.appxsym",
        )
        fake_pdb_buf = io.BytesIO()
        with zipfile.ZipFile(fake_pdb_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf_fake:
            for pdb_n in all_pdbs:
                zf_fake.writestr(pdb_n, b"X")
        fake_pdb_upload = tmp_dir / "fake-pdb.msixupload"
        fake_pdb_upload.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", fake_pdb_buf.getvalue()),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                ]
            )
        )
        expect_fail(
            "case-30c-non-msf7-pdb",
            lambda: verify_msixupload_archive(
                fake_pdb_upload,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "MSF 7.00",
        )

        # Case 31: Extra .dll/.exe cross-arch contamination and packed CRT/CLR binaries inside .msix.
        extra_x64_dll = _build_synthetic_pe64(machine=IMAGE_FILE_MACHINE_AMD64, is_dll=True, cet_compat=True)
        arm64_extra_x64 = _make_synthetic_msix(
            arm64_tpl,
            arch="arm64",
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            extra_entries=[("extra_helper.dll", extra_x64_dll)],
        )
        expect_fail(
            "case-31a-extra-cross-arch-dll",
            lambda: verify_msix_archive(
                arm64_extra_x64,
                "31a-extra-x64.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "expected machine",
        )
        for packed_bad_dll, expect_msg in (
            ("vcruntime140.dll", "MSVC CRT"),
            ("sub/coreclr.dll", "CLR host"),
        ):
            arm64_packed_bad = _make_synthetic_msix(
                arm64_tpl,
                arch="arm64",
                name=store_name,
                publisher=store_pub,
                version=store_ver,
                extra_entries=[(packed_bad_dll, extra_x64_dll)],
            )
            expect_fail(
                f"case-31b-packed-{Path(packed_bad_dll).name}",
                lambda b=arm64_packed_bad: verify_msix_archive(
                    b,
                    "31b-packed.msix",
                    arch="arm64",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                expect_msg,
            )

        # Case 32: .pvk / .pepk forbidden key extensions + M1 Fix #4 subdirectory split-PRI regression.
        for bad_entry, expect_msg in (
            ("signing.pvk", "forbidden staging/key"),
            ("sub/resources.scale-200.pri", "forbidden staging/key"),
        ):
            arm64_bad_art = _make_synthetic_msix(
                arm64_tpl,
                arch="arm64",
                name=store_name,
                publisher=store_pub,
                version=store_ver,
                extra_entries=[(bad_entry, b"SECRET")],
            )
            expect_fail(
                f"case-32a-{Path(bad_entry).name}",
                lambda b=arm64_bad_art: verify_msix_archive(
                    b,
                    "32a-bad.msix",
                    arch="arm64",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                expect_msg,
            )
        bundle_pvk = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
            extra_entries=[("signing.pvk", b"PVK")],
        )
        expect_fail(
            "case-32b-bundle-pvk",
            lambda: verify_msixbundle_archive(
                bundle_pvk,
                "32b-pvk.msixbundle",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "signing.pvk",
        )
        pepk_upload = tmp_dir / "leak-pepk.msixupload"
        pepk_upload.write_bytes(
            _make_synthetic_upload(
                [
                    (bundle_ok_path.name, bundle_ok_bytes),
                    (f"TotalDrop_{store_ver}_x64.appxsym", sym_ok),
                    (f"TotalDrop_{store_ver}_arm64.appxsym", sym_ok),
                    ("upload.pepk", b"PEPK"),
                ]
            )
        )
        expect_fail(
            "case-32c-upload-pepk",
            lambda: verify_msixupload_archive(
                pepk_upload,
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "signing key",
        )

        # Case 33: Unix symlink and non-regular mode ZIP entries rejected by _check_opc_zip_entries.
        sym_zip_buf = io.BytesIO()
        with (
            zipfile.ZipFile(io.BytesIO(arm64_ok), "r") as zin,
            zipfile.ZipFile(sym_zip_buf, "w", compression=zipfile.ZIP_DEFLATED) as zout,
        ):
            for item in zin.infolist():
                zout.writestr(item.filename, zin.read(item))
            link_info = zipfile.ZipInfo("evil_link.txt")
            link_info.create_system = 3
            link_info.external_attr = (0o120777 << 16)
            zout.writestr(link_info, b"../../etc/passwd")
        expect_fail(
            "case-33-unix-symlink",
            lambda: verify_msix_archive(
                sym_zip_buf.getvalue(),
                "33-symlink.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "symbolic link",
        )

        # Case 34: Multi-RDN placeholder, RFC 2253 multi-valued RDN '+', and all-zero GUID bypasses.
        for bad_pub, expect_msg in (
            ("CN=TotalDrop, O=TotalDrop", "placeholder"),
            ("CN=TotalDrop+O=Evil", "forbidden unescaped"),
            ("CN=00000000-0000-0000-0000-000000000000", "placeholder"),
        ):
            arm64_bad_id = _make_synthetic_msix(
                arm64_tpl, arch="arm64", name=store_name, publisher=bad_pub, version=store_ver
            )
            expect_fail(
                f"case-34-pub-{bad_pub[:12]}",
                lambda b=arm64_bad_id: verify_msix_archive(
                    b,
                    "34-bad-pub.msix",
                    arch="arm64",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                expect_msg,
            )

        # Case 35: Unreferenced arbitrary file and nested slice FileName inside .msixbundle.
        bundle_rogue = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
            extra_entries=[("rogue.exe", b"MZ\x00\x00")],
        )
        expect_fail(
            "case-35a-bundle-rogue-entry",
            lambda: verify_msixbundle_archive(
                bundle_rogue,
                "35a-rogue.msixbundle",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "rogue.exe",
        )
        bundle_nested_pkg = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"sub/TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_ok),
            ],
        )
        expect_fail(
            "case-35b-bundle-nested-filename",
            lambda: verify_msixbundle_archive(
                bundle_nested_pkg,
                "35b-nested.msixbundle",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "flat root",
        )

        # Case 36: Manifest Properties/Resources/Dependencies, OPC XML well-formedness, and elem.tail parity.
        arm64_no_res = _make_synthetic_msix(
            arm64_tpl.replace('<Resource Language="tr" />', ""),
            arch="arm64",
            name=store_name,
            publisher=store_pub,
            version=store_ver,
        )
        expect_fail(
            "case-36a-missing-resource-lang",
            lambda: verify_msix_archive(
                arm64_no_res,
                "36a-no-res.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "35 canonical",
        )
        arm64_empty_pubdisp = _make_synthetic_msix(
            arm64_tpl,
            arch="arm64",
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            publisher_display_name="",
        )
        expect_fail(
            "case-36b-empty-pubdisp",
            lambda: verify_msix_archive(
                arm64_empty_pubdisp,
                "36b-empty-pubdisp.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "PublisherDisplayName",
        )
        arm64_bad_xml_buf = io.BytesIO()
        with (
            zipfile.ZipFile(io.BytesIO(arm64_ok), "r") as zin,
            zipfile.ZipFile(arm64_bad_xml_buf, "w", compression=zipfile.ZIP_DEFLATED) as zout,
        ):
            for item in zin.infolist():
                payload = b"NOT VALID XML <<<" if item.filename == "AppxBlockMap.xml" else zin.read(item)
                zout.writestr(item.filename, payload)
        expect_fail(
            "case-36c-corrupt-blockmap-xml",
            lambda: verify_msix_archive(
                arm64_bad_xml_buf.getvalue(),
                "36c-bad-blockmap.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "AppxBlockMap.xml",
        )
        arm64_tail_div = _make_synthetic_msix(
            arm64_tpl.replace("</DisplayName>", "</DisplayName>ROGUE_TAIL"),
            arch="arm64",
            name=store_name,
            publisher=store_pub,
            version=store_ver,
        )
        bundle_tail_div = _make_synthetic_bundle(
            name=store_name,
            publisher=store_pub,
            version=store_ver,
            packages=[
                ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_ok),
                ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_tail_div),
            ],
        )
        expect_fail(
            "case-36d-tail-parity",
            lambda: verify_msixbundle_archive(
                bundle_tail_div,
                "36d-tail.msixbundle",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "diverge",
        )

        # Case 37: LFH 0x0001 Zip64 extra field with trailing slack (data_size == 24 != 16).
        c_slack = zlib.compressobj(6, zlib.DEFLATED, -15)
        d_slack = c_slack.compress(b"<BlockMap />") + c_slack.flush()
        slack_z64_extra = struct.pack("<HHQQQ", 0x0001, 24, len(b"<BlockMap />"), len(d_slack), 0xDEADBEEFCAFECAFE)
        arm64_slack_z64 = _rebuild_zip_with_raw_entry(
            arm64_ok,
            "AppxBlockMap.xml",
            method=zipfile.ZIP_DEFLATED,
            raw_payload=d_slack,
            declared_uncomp_size=len(b"<BlockMap />"),
            declared_crc=zlib.crc32(b"<BlockMap />") & 0xFFFFFFFF,
            lfh_extra_override=slack_z64_extra,
        )
        expect_fail(
            "case-37-lfh-z64-slack",
            lambda: verify_msix_archive(
                arm64_slack_z64,
                "37-z64-slack.msix",
                arch="arm64",
                expected_version=store_ver,
                expect_signed=False,
                store_mode=True,
                allow_test_identity=False,
                run_live_smoke=False,
            ),
            "exactly 16 bytes",
        )

        # Case 38: macOS/Darwin (create_system=19) and DOS (create_system=0) upper-16-bit S_IFLNK symlinks rejected.
        for case_tag, create_sys in (("case-38a-darwin-symlink", 19), ("case-38b-dos-upper-symlink", 0)):
            spoof_sym_buf = io.BytesIO()
            with (
                zipfile.ZipFile(io.BytesIO(arm64_ok), "r") as zin,
                zipfile.ZipFile(spoof_sym_buf, "w", compression=zipfile.ZIP_DEFLATED) as zout,
            ):
                for item in zin.infolist():
                    zout.writestr(item.filename, zin.read(item))
                spoof_info = zipfile.ZipInfo(f"{case_tag}.txt")
                spoof_info.create_system = create_sys
                spoof_info.external_attr = 0o120777 << 16
                zout.writestr(spoof_info, b"../../etc/passwd")
            expect_fail(
                case_tag,
                lambda b=spoof_sym_buf.getvalue(), tag=case_tag: verify_msix_archive(
                    b,
                    f"{tag}.msix",
                    arch="arm64",
                    expected_version=store_ver,
                    expect_signed=False,
                    store_mode=True,
                    allow_test_identity=False,
                    run_live_smoke=False,
                ),
                "symbolic link",
            )

    print(
        "self-test-bundle OK: 38/38 checks passed "
        "(29/29 baseline + 9/9 hardened positive & negative bundle/msixupload/store-mode checks)."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify packed TotalDrop .msix, .msixbundle, and .msixupload archives."
    )
    parser.add_argument("--msix", type=Path, default=None, help="Path to built single-arch .msix archive.")
    parser.add_argument("--bundle", type=Path, default=None, help="Path to unified dual-arch .msixbundle archive.")
    parser.add_argument("--msixupload", type=Path, default=None, help="Path to Partner Center .msixupload archive.")
    parser.add_argument(
        "--self-test-bundle",
        action="store_true",
        help="Run built-in pure-Python positive & negative bundle/msixupload/Store-mode self-tests.",
    )
    parser.add_argument("--arch", choices=("x64", "arm64"), default="x64")
    parser.add_argument("--expected-version", default=None)
    parser.add_argument(
        "--expect-signed",
        action="store_true",
        help="Require non-empty AppxSignature.p7x inside the package/bundle.",
    )
    parser.add_argument(
        "--pri-dump",
        type=Path,
        default=None,
        help="Optional MakePri.exe detailed XML dump to inspect (with --msix).",
    )
    parser.add_argument(
        "--store-mode",
        action="store_true",
        help="Enforce Microsoft Store MSIX rules (Major >= 1, Revision == 0, X.500 CN=, non-placeholder identity).",
    )
    parser.add_argument(
        "--allow-test-identity",
        action="store_true",
        help="Permit temporary CN=TotalDrop / TotalDrop.TotalDrop identity during --store-mode dry-runs.",
    )
    parser.add_argument(
        "--require-live-smoke",
        action="store_true",
        help="Fail instead of skipping if live ctypes FFI/COM smoke cannot run (e.g. wrong host Python arch).",
    )
    args = parser.parse_args(argv)

    if not any((args.msix, args.bundle, args.msixupload, args.self_test_bundle)):
        parser.error("Provide at least one of --msix, --bundle, --msixupload, or --self-test-bundle.")

    try:
        if args.self_test_bundle:
            run_self_test_bundle()

        if args.msix is not None:
            eff_ver = args.expected_version
            if eff_ver is None and not args.store_mode:
                eff_ver = EXPECTED_MSIX_VERSION
            res = verify_msix_archive(
                args.msix,
                args.msix.name,
                arch=args.arch,
                expected_version=eff_ver,
                expect_signed=args.expect_signed,
                store_mode=args.store_mode,
                allow_test_identity=args.allow_test_identity,
                pri_dump=args.pri_dump,
                require_live_smoke=args.require_live_smoke,
            )
            cet_note = " + CET_COMPAT" if args.arch == "x64" else ""
            print(
                f"msix-artifact verify OK: {args.msix.name} ({res['size_bytes']} bytes, "
                f"arch={args.arch}, version={res['version']}, 46 canonical Assets, "
                f"PE hardening{cet_note} + DependentLoadFlags=0x800 + zero VCRUNTIME140 + "
                f"{len(REQUIRED_FFI_EXPORTS)} C ABI exports + Explorer COM DLL (icon 101) + "
                f"COM/Toast/Firewall manifest + Native AOT verified)."
            )

        if args.bundle is not None:
            b_res = verify_msixbundle_archive(
                args.bundle,
                args.bundle.name,
                expected_version=args.expected_version,
                expect_signed=args.expect_signed,
                store_mode=args.store_mode,
                allow_test_identity=args.allow_test_identity,
                require_live_smoke=args.require_live_smoke,
            )
            print(
                f"msixbundle verify OK: {args.bundle.name} ({b_res['size_bytes']} bytes, "
                f"version={b_res['version']}, identity={b_res['name']}, arches=x64+arm64, "
                f"cross-arch manifest parity & PE32+ hardening verified)."
            )

        if args.msixupload is not None:
            u_res = verify_msixupload_archive(
                args.msixupload,
                expected_version=args.expected_version,
                expect_signed=args.expect_signed,
                store_mode=args.store_mode,
                allow_test_identity=args.allow_test_identity,
                expected_bundle_path=args.bundle,
                require_live_smoke=args.require_live_smoke,
            )
            b_info = u_res["bundle_info"]
            print(
                f"msixupload verify OK: {args.msixupload.name} ({u_res['size_bytes']} bytes, "
                f"bundle={u_res['bundle_name']}, version={b_info['version']}, "  # type: ignore[index]
                f"appxsym={u_res['appxsym_count']}, pdbs={len(u_res['pdb_names'])}, "  # type: ignore[arg-type]
                "zero bare .msix & zero signing keys verified)."
            )
    except (
        ValueError,
        ET.ParseError,
        zipfile.BadZipFile,
        zlib.error,
        RuntimeError,
        EOFError,
        struct.error,
        OverflowError,
        subprocess.CalledProcessError,
        OSError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
