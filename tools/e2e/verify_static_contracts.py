#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Pure-Python stdlib static contract, negative-mutation & anti-prod-probe verifier.

Implements M1, M2, M3, and M4 static & mutation tests from test_blueprint.md and
TEST_INFRA.md sections 3.3, 5.4, and 5.5 with zero third-party dependencies.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tokenize
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Construct forbidden version/CLSID literals dynamically so tools/check-versions.py
# never flags this verifier script itself.
STALE_SUBPLATFORM_VER = "0.3.0-" + "beta.6"
STALE_MSIX_VER = "0.2." + "0.0"
DRIFTED_CLSID = "8E6D76B4-" + "54A9-4D92-9A57-2F7D25F8B216"
CANONICAL_CLSID = "8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0"
TOAST_ACTIVATOR_CLSID = "7DF2CCED-0448-4849-A140-41CD106EAA9B"
BARE_UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")

FORBID_UNSAFE_CRATES: tuple[str, ...] = (
    "totaldrop-crypto",
    "totaldrop-proto",
    "totaldrop-core",
    "totaldrop-l10n",
    "totaldrop-windows-bridge",
)

APP_CRITICAL_KEYS: tuple[str, ...] = (
    "verificationTitle",
    "verificationHint",
    "errorWrongCode",
    "errorInvalidOffer",
    "receiveAccept",
    "receiveDecline",
)

ALLOWLISTED_XAML_LITERALS: frozenset[str] = frozenset({
    "",
    "TotalDrop",
    "7-harbor-rocket",
    "totaldrop.app",
})

INTERACTIVE_XAML_TAGS: frozenset[str] = frozenset({
    "Button",
    "HyperlinkButton",
    "TextBox",
    "AutoSuggestBox",
    "ToggleSwitch",
    "NavigationView",
    "NavigationViewItem",
    "ProgressBar",
})

USER_VISIBLE_XAML_ATTRS: tuple[str, ...] = (
    "Text",
    "Content",
    "Header",
    "PlaceholderText",
    "Title",
    "Message",
    "OffContent",
    "OnContent",
)

A11Y_AND_TOOLTIP_XAML_ATTRS: tuple[str, ...] = (
    "AutomationProperties.Name",
    "AutomationProperties.HelpText",
    "AutomationProperties.FullDescription",
    "AutomationProperties.LocalizedLandmarkType",
    "ToolTipService.ToolTip",
)

XAML_STRING_TAG = "{http://schemas.microsoft.com/winfx/2006/xaml}String"

FORBIDDEN_SIGNING_EXTS: frozenset[str] = frozenset({
    ".pfx", ".p12", ".snk", ".cer", ".jks", ".keystore", ".pepk", ".key", ".pem", ".pvk",
})
FORBIDDEN_SIGNING_NAMES: frozenset[str] = frozenset({
    "key.properties", ".gitleaksignore",
})

APPX_NS = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"


# ---------------------------------------------------------------------------
# Lexers & File Helpers


def _is_excluded_app_path(path: Path) -> bool:
    parts = set(path.parts)
    return bool(parts & {"TotalDrop.WinUI.Tests", "bin", "obj", ".git"})


def iter_app_files(root: Path, pattern: str) -> list[Path]:
    ui_dir = root / "ui-winui3-fluent2"
    if not ui_dir.is_dir():
        return []
    return sorted(p for p in ui_dir.rglob(pattern) if p.is_file() and not _is_excluded_app_path(p))


def _resolve_sh() -> str:
    """Resolve POSIX sh on PATH or Git for Windows fallbacks."""
    found = shutil.which("sh")
    if found:
        return found
    if os.name == "nt":
        for candidate in (
            r"C:\Program Files\Git\bin\sh.exe",
            r"C:\Program Files\Git\usr\bin\sh.exe",
        ):
            if Path(candidate).is_file():
                return candidate
    raise ValueError("POSIX sh executable not found on PATH or Git for Windows")


def _resolve_posix_shells() -> list[tuple[str, str]]:
    """Resolve available POSIX shells (sh and optional dash) cross-platform."""
    shells: list[tuple[str, str]] = []
    sh_path = shutil.which("sh")
    if not sh_path and os.name == "nt":
        for candidate in (
            r"C:\Program Files\Git\bin\sh.exe",
            r"C:\Program Files\Git\usr\bin\sh.exe",
        ):
            if Path(candidate).is_file():
                sh_path = candidate
                break
    if sh_path:
        shells.append(("sh", sh_path))
    dash_path = shutil.which("dash")
    if dash_path:
        shells.append(("dash", dash_path))
    if not shells:
        raise ValueError("no POSIX shell (sh or dash) found on PATH or Git for Windows")
    return shells


def _match_rust_char_literal(src: str, i: int) -> int:
    """If src[i:] starts a Rust char or byte-char literal ('x', b'x', '\\'', '\\u{...}'), return end index; else -1."""
    n = len(src)
    q = i
    if src[i] == "b" and i + 1 < n and src[i + 1] == "'":
        if i > 0 and (src[i - 1].isalnum() or src[i - 1] == "_"):
            return -1
        q = i + 1
    elif src[i] != "'":
        return -1

    if q + 2 >= n:
        return -1
    if src[q + 1] == "\\":
        # Escape sequence: \', \\, \n, \xHH, \u{...}
        j = q + 2
        if j >= n:
            return -1
        if src[j] == "u" and j + 1 < n and src[j + 1] == "{":
            close_brace = src.find("}", j + 2)
            if close_brace != -1 and close_brace + 1 < n and src[close_brace + 1] == "'" and close_brace - j <= 10:
                return close_brace + 2
            return -1
        if src[j] == "x":
            if j + 3 < n and src[j + 3] == "'":
                return j + 4
            return -1
        if j + 1 < n and src[j + 1] == "'":
            return j + 2
        return -1
    if src[q + 1] not in ("'", "\\", "\n", "\r") and src[q + 2] == "'":
        return q + 3
    return -1


def _mask_rust_comments_and_strings(src: str) -> str:
    """Return a same-length copy of Rust source with comments, strings, and char literals replaced by spaces (preserving \\n)."""
    out: list[str] = []
    i = 0
    n = len(src)

    def _emit_masked(seg: str) -> None:
        out.append("".join("\n" if c == "\n" else " " for c in seg))

    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        # Line comment
        if ch == "/" and nxt == "/":
            start = i
            i += 2
            while i < n and src[i] != "\n":
                i += 1
            _emit_masked(src[start:i])
            continue
        # Nested block comment
        if ch == "/" and nxt == "*":
            start = i
            depth = 1
            i += 2
            while i < n and depth > 0:
                if src[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    i += 1
            _emit_masked(src[start:i])
            continue
        # Raw string r#"..."#, br#"..."#, cr#"..."#
        if (ch == "r" or (ch in ("b", "c") and nxt == "r")) and (
            i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")
        ):
            j = i + 2 if ch in ("b", "c") else i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                end_marker = '"' + ("#" * hashes)
                end_pos = src.find(end_marker, j + 1)
                end_idx = n if end_pos == -1 else end_pos + len(end_marker)
                _emit_masked(src[i:end_idx])
                i = end_idx
                continue
        # Regular / byte / C string "...", b"...", c"..."
        if ch == '"' or (
            ch in ("b", "c")
            and nxt == '"'
            and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))
        ):
            start = i
            i = (i + 2) if ch in ("b", "c") else (i + 1)
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            _emit_masked(src[start:i])
            continue
        # Character / byte-character literal (not lifetime 'a)
        if ch in ("'", "b"):
            char_end = _match_rust_char_literal(src, i)
            if char_end != -1:
                _emit_masked(src[i:char_end])
                i = char_end
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def strip_rust_comments_and_strings(src: str) -> str:
    """Strip Rust // comments, nested /* */ comments, raw strings, strings, and char/byte-char literals."""
    out: list[str] = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        # Line comment
        if ch == "/" and nxt == "/":
            i += 2
            while i < n and src[i] != "\n":
                i += 1
            continue
        # Nested block comment
        if ch == "/" and nxt == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if src[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    if src[i] == "\n":
                        out.append("\n")
                    i += 1
            out.append(" ")
            continue
        # Raw string r#"..."#, br#"..."#, cr#"..."#
        if (ch == "r" or (ch in ("b", "c") and nxt == "r")) and (
            i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")
        ):
            start = i + 2 if ch in ("b", "c") else i + 1
            hashes = 0
            j = start
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                j += 1
                end_marker = '"' + ("#" * hashes)
                end_pos = src.find(end_marker, j)
                if end_pos == -1:
                    out.append("\n" * src[i:].count("\n"))
                    break
                nl_count = src[i : end_pos + len(end_marker)].count("\n")
                i = end_pos + len(end_marker)
                out.append('""' + ("\n" * nl_count))
                continue
        # Regular / byte / C string "..."
        if ch == '"' or (
            ch in ("b", "c")
            and nxt == '"'
            and (i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_"))
        ):
            start = i
            i = (i + 2) if ch in ("b", "c") else (i + 1)
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            out.append('""' + ("\n" * src[start:i].count("\n")))
            continue
        # Character / byte-character literal (not lifetime 'a)
        if ch in ("'", "b"):
            char_end = _match_rust_char_literal(src, i)
            if char_end != -1:
                i = char_end
                out.append("''")
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _lex_csharp(src: str, *, mask_literals: bool) -> str:
    """Lex C# source handling comments, char literals, verbatim/raw strings, and recursive interpolated strings.

    When `mask_literals=False`, removes `//` and `/* */` comments (including inside `{...}` interpolation holes)
    while preserving string/char contents and exact 1:1 line counts.
    When `mask_literals=True`, returns a same-length string (preserving `\\n`) with comments, string literal bodies
    outside interpolation holes, format clauses, and char literals masked to spaces while keeping code tokens and
    expressions inside `{...}` interpolation holes intact.
    """
    out: list[str] = []
    i = 0
    n = len(src)
    # Stack frame formats:
    #   ["code", close_braces, brace_depth, paren_depth, bracket_depth, in_format]
    #   ["interp_reg"]
    #   ["interp_verb"]
    #   ["interp_raw", dollar_count, quote_count]
    stack: list[list[Any]] = [["code", 0, 0, 0, 0, False]]

    def emit_code(seg: str) -> None:
        out.append(seg)

    def emit_lit(seg: str) -> None:
        if mask_literals:
            out.append("".join("\n" if c == "\n" else " " for c in seg))
        else:
            out.append(seg)

    while i < n:
        frame = stack[-1]
        kind = frame[0]
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if kind == "interp_reg":
            if ch == "\\" and i + 1 < n:
                emit_lit(src[i : i + 2])
                i += 2
                continue
            if ch == '"':
                emit_lit('"')
                i += 1
                stack.pop()
                continue
            if ch == "{" and nxt == "{":
                emit_lit("{{")
                i += 2
                continue
            if ch == "}" and nxt == "}":
                emit_lit("}}")
                i += 2
                continue
            if ch == "{":
                emit_lit("{")
                i += 1
                stack.append(["code", 1, 0, 0, 0, False])
                continue
            emit_lit(ch)
            i += 1
            continue

        if kind == "interp_verb":
            if ch == '"' and nxt == '"':
                emit_lit('""')
                i += 2
                continue
            if ch == '"':
                emit_lit('"')
                i += 1
                stack.pop()
                continue
            if ch == "{" and nxt == "{":
                emit_lit("{{")
                i += 2
                continue
            if ch == "}" and nxt == "}":
                emit_lit("}}")
                i += 2
                continue
            if ch == "{":
                emit_lit("{")
                i += 1
                stack.append(["code", 1, 0, 0, 0, False])
                continue
            emit_lit(ch)
            i += 1
            continue

        if kind == "interp_raw":
            dollar_count: int = frame[1]
            quote_count: int = frame[2]
            if ch == '"':
                r_end = i
                while r_end < n and src[r_end] == '"':
                    r_end += 1
                emit_lit(src[i:r_end])
                run_len = r_end - i
                i = r_end
                if run_len >= quote_count:
                    stack.pop()
                continue
            if ch == "{":
                r_end = i
                while r_end < n and src[r_end] == "{":
                    r_end += 1
                emit_lit(src[i:r_end])
                run_len = r_end - i
                i = r_end
                if run_len >= dollar_count:
                    stack.append(["code", dollar_count, 0, 0, 0, False])
                continue
            emit_lit(ch)
            i += 1
            continue

        # kind == "code"
        close_braces: int = frame[1]
        if close_braces > 0 and frame[5]:
            # Inside interpolation format clause `:...`
            if src[i : i + close_braces] == "}" * close_braces:
                emit_lit(src[i : i + close_braces])
                i += close_braces
                stack.pop()
                continue
            parent_kind = stack[-2][0] if len(stack) >= 2 else ""
            if parent_kind == "interp_reg" and ch == "\\" and i + 1 < n:
                emit_lit(src[i : i + 2])
                i += 2
                continue
            if parent_kind == "interp_verb" and ch == '"' and nxt == '"':
                emit_lit('""')
                i += 2
                continue
            emit_lit(ch)
            i += 1
            continue

        if close_braces > 0 and frame[2] == 0 and src[i : i + close_braces] == "}" * close_braces:
            emit_lit(src[i : i + close_braces])
            i += close_braces
            stack.pop()
            continue

        if close_braces > 0 and frame[2] == 0 and frame[3] == 0 and frame[4] == 0 and ch == ":":
            if nxt == ":":
                emit_code("::")
                i += 2
                continue
            frame[5] = True
            emit_lit(":")
            i += 1
            continue

        if ch == "/" and nxt == "/":
            start = i
            i += 2
            while i < n and src[i] != "\n":
                i += 1
            if mask_literals:
                out.append(" " * (i - start))
            continue

        if ch == "/" and nxt == "*":
            start = i
            i += 2
            while i < n:
                if i + 1 < n and src[i] == "*" and src[i + 1] == "/":
                    i += 2
                    break
                i += 1
            seg = src[start:i]
            if mask_literals:
                out.append("".join("\n" if c == "\n" else " " for c in seg))
            else:
                out.append(("\n" * seg.count("\n")) + " ")
            continue

        # C# raw string literal / interpolated raw string literal: optional $+ followed by >= 3 `"`
        if ch in ('"', "$"):
            k_end = i
            while k_end < n and src[k_end] == "$":
                k_end += 1
            dollars = k_end - i
            q_end = k_end
            while q_end < n and src[q_end] == '"':
                q_end += 1
            quotes = q_end - k_end
            if quotes >= 3:
                emit_lit(src[i:q_end])
                i = q_end
                if dollars > 0:
                    stack.append(["interp_raw", dollars, quotes])
                else:
                    while i < n:
                        if src[i] == '"':
                            r_end = i
                            while r_end < n and src[r_end] == '"':
                                r_end += 1
                            emit_lit(src[i:r_end])
                            run_len = r_end - i
                            i = r_end
                            if run_len >= quotes:
                                break
                            continue
                        emit_lit(src[i])
                        i += 1
                continue

        # C# interpolated verbatim string literal: $@"..." or @$"..."
        if ((ch == "$" and nxt == "@") or (ch == "@" and nxt == "$")) and i + 2 < n and src[i + 2] == '"':
            emit_lit(src[i : i + 3])
            i += 3
            stack.append(["interp_verb"])
            continue

        # C# non-interpolated verbatim string literal: @"..."
        if ch == "@" and nxt == '"':
            emit_lit('@"')
            i += 2
            while i < n:
                if src[i] == '"':
                    if i + 1 < n and src[i + 1] == '"':
                        emit_lit('""')
                        i += 2
                        continue
                    emit_lit('"')
                    i += 1
                    break
                emit_lit(src[i])
                i += 1
            continue

        # C# regular interpolated string literal: $"..."
        if ch == "$" and nxt == '"':
            emit_lit('$"')
            i += 2
            stack.append(["interp_reg"])
            continue

        # C# character literal: 'x', '\'', '\\', '\"', '"'
        if ch == "'":
            emit_lit("'")
            i += 1
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    emit_lit(src[i : i + 2])
                    i += 2
                    continue
                emit_lit(src[i])
                if src[i] in ("'", "\n"):
                    i += 1
                    break
                i += 1
            continue

        # Regular string literal: "..."
        if ch == '"':
            emit_lit('"')
            i += 1
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    emit_lit(src[i : i + 2])
                    i += 2
                    continue
                emit_lit(src[i])
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue

        if ch == "{":
            frame[2] += 1
        elif ch == "}":
            frame[2] = max(0, frame[2] - 1)
        elif ch == "(":
            frame[3] += 1
        elif ch == ")":
            frame[3] = max(0, frame[3] - 1)
        elif ch == "[":
            frame[4] += 1
        elif ch == "]":
            frame[4] = max(0, frame[4] - 1)
        emit_code(ch)
        i += 1

    return "".join(out)


def strip_csharp_comments(src: str) -> str:
    """Strip C# // and /* */ comments while lexing char literals, verbatim/raw strings, and recursive interpolated strings."""
    return _lex_csharp(src, mask_literals=False)


def mask_csharp_comments_and_strings(src: str) -> str:
    """Return a same-length C# source string with comments, char literals, and string text outside interpolation holes masked to spaces."""
    return _lex_csharp(src, mask_literals=True)


def strip_cfg_test_modules(src: str) -> str:
    """Blank out actual `#[cfg(test)] mod ... { ... }` blocks (ignoring comments/strings and preserving line numbers)."""
    masked = _mask_rust_comments_and_strings(src)
    n = len(masked)
    spans: list[tuple[int, int]] = []
    cfg_re = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]")

    pos = 0
    while True:
        m = cfg_re.search(masked, pos)
        if not m:
            break
        cur = m.end()
        # Skip whitespace and any sibling attributes `#[...]` before `mod <ident> {`.
        while cur < n:
            while cur < n and masked[cur].isspace():
                cur += 1
            if cur + 1 < n and masked[cur] == "#" and masked[cur + 1] == "[":
                depth = 1
                cur += 2
                while cur < n and depth > 0:
                    if masked[cur] == "[":
                        depth += 1
                    elif masked[cur] == "]":
                        depth -= 1
                    cur += 1
                continue
            break

        # Optional visibility (`pub`, `pub(crate)`, etc.) followed by `mod <ident> {`.
        vis_m = re.match(r"pub(?:\s*\([^)]*\))?\s+", masked[cur:])
        if vis_m:
            cur += vis_m.end()
        mod_m = re.match(r"mod\s+[A-Za-z_]\w*\s*\{", masked[cur:])
        if not mod_m:
            pos = m.end()
            continue

        brace_pos = cur + mod_m.end()
        depth = 1
        while brace_pos < n and depth > 0:
            if masked[brace_pos] == "{":
                depth += 1
            elif masked[brace_pos] == "}":
                depth -= 1
            brace_pos += 1
        spans.append((m.start(), brace_pos))
        pos = brace_pos

    if not spans:
        return src

    chars = list(src)
    for start, end in spans:
        for k in range(start, end):
            if chars[k] != "\n":
                chars[k] = " "
    return "".join(chars)


# ---------------------------------------------------------------------------
# M1 Invariant Checks


def check_rust_safety_isolation(root: Path) -> None:
    root_toml = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    ws_rust_lints = root_toml.get("workspace", {}).get("lints", {}).get("rust", {})
    if ws_rust_lints.get("unsafe_code") != "forbid":
        raise ValueError("Cargo.toml missing [workspace.lints.rust] unsafe_code = 'forbid'")

    for crate in FORBID_UNSAFE_CRATES:
        crate_dir = root / "crates" / crate
        ctoml = tomllib.loads((crate_dir / "Cargo.toml").read_text(encoding="utf-8"))
        if ctoml.get("lints", {}).get("workspace") is not True:
            raise ValueError(f"crates/{crate}/Cargo.toml does not inherit [lints] workspace = true")
        for rs in sorted((crate_dir / "src").rglob("*.rs")):
            text = rs.read_text(encoding="utf-8")
            stripped = strip_rust_comments_and_strings(text)
            if re.search(r"\bunsafe\b", stripped):
                raise ValueError(f"forbidden unsafe token found in {rs.relative_to(root)}")
            if re.search(r"#!?\[allow\([^]]*unsafe_code", stripped):
                raise ValueError(f"forbidden allow(unsafe_code) in {rs.relative_to(root)}")

    # Audit both unsafe-isolating cdylib crates: totaldrop-windows-ffi (M1+) and totaldrop-explorer-ext (M3+)
    isolated_cdylib_crates: list[str] = ["totaldrop-windows-ffi"]
    if (root / "crates" / "totaldrop-explorer-ext" / "Cargo.toml").is_file():
        isolated_cdylib_crates.append("totaldrop-explorer-ext")

    for crate_name in isolated_cdylib_crates:
        c_dir = root / "crates" / crate_name
        c_toml = tomllib.loads((c_dir / "Cargo.toml").read_text(encoding="utf-8"))
        crate_types = c_toml.get("lib", {}).get("crate-type", [])
        if set(crate_types) != {"cdylib", "rlib"}:
            raise ValueError(f"{crate_name} crate-type must be ['cdylib', 'rlib'], got {crate_types}")
        if c_toml.get("package", {}).get("license") != "MIT OR Apache-2.0":
            raise ValueError(f"{crate_name} license must be MIT OR Apache-2.0")
        if c_toml.get("lints", {}).get("rust", {}).get("unsafe_op_in_unsafe_fn") != "deny":
            raise ValueError(f"{crate_name} missing unsafe_op_in_unsafe_fn = 'deny'")
        if c_toml.get("lints", {}).get("clippy", {}).get("undocumented_unsafe_blocks") != "deny":
            raise ValueError(f"{crate_name} missing clippy::undocumented_unsafe_blocks = 'deny'")

        sources = sorted((c_dir / "src").rglob("*.rs"))
        guard_has_catch_unwind = False
        for rs in sources:
            raw = strip_cfg_test_modules(rs.read_text(encoding="utf-8"))
            if ("fn guard_ffi_" in raw or "fn guard_hresult" in raw) and "catch_unwind" in raw:
                guard_has_catch_unwind = True

        for rs in sources:
            raw = strip_cfg_test_modules(rs.read_text(encoding="utf-8"))
            masked_raw = _mask_rust_comments_and_strings(raw)
            lines = raw.splitlines()
            masked_lines = masked_raw.splitlines()
            # Check every `unsafe {` block across the full masked Rust source (not line-by-line)
            # so multi-line `unsafe // note\n{ ... }` and URL strings containing `//` before `unsafe {`
            # can never evade `// SAFETY:` verification.
            for u_match in re.finditer(r"(?<!#\[)\bunsafe\s*\{", masked_raw):
                idx = masked_raw.count("\n", 0, u_match.start())
                masked_line = masked_lines[idx] if idx < len(masked_lines) else ""
                # Look backward over contiguous comments/blank lines for `// SAFETY:`.
                # Also permit a single immediately preceding rustfmt statement-header line
                # ending in `=` (e.g. `let hr =\n    unsafe { ... };`) when the unsafe block
                # starts the continuation line (still rejecting `fn bad() {\n    unsafe {}\n}`).
                found_safety = False
                j = idx - 1
                if j >= 0 and re.match(r"unsafe(?:\s*\{|\s*$)", masked_line.lstrip()):
                    prev_code = masked_lines[j].strip()
                    if prev_code.endswith("="):
                        j -= 1
                while j >= 0:
                    prev = lines[j].strip()
                    if prev.startswith("// SAFETY:"):
                        found_safety = True
                        break
                    if prev.startswith("//") or prev == "":
                        j -= 1
                        continue
                    break
                if not found_safety:
                    raise ValueError(
                        f"{rs.relative_to(root)}:{idx + 1}: undocumented unsafe block missing preceding '// SAFETY:' comment"
                    )

            # Check every `pub (unsafe )?extern ("...")? fn <name>` (including implicit C ABI `pub extern fn`)
            # has unwind protection (strip_rust_comments_and_strings replaces string literals with `""`).
            stripped = strip_rust_comments_and_strings(raw)
            for match in re.finditer(
                r'\bpub\s+(?:unsafe\s+)?extern(?:\s+"[^"]*")?\s+fn\s+([A-Za-z0-9_]+)',
                stripped,
            ):
                fn_name = match.group(1)
                brace_open = stripped.find("{", match.end())
                if brace_open == -1:
                    continue
                depth = 1
                pos = brace_open + 1
                while pos < len(stripped) and depth > 0:
                    if stripped[pos] == "{":
                        depth += 1
                    elif stripped[pos] == "}":
                        depth -= 1
                    pos += 1
                body = stripped[brace_open:pos]
                uses_guard = ("guard_ffi_" in body or "guard_hresult" in body) and guard_has_catch_unwind
                if "catch_unwind" not in body and not uses_guard:
                    raise ValueError(
                        f"{rs.relative_to(root)}: extern export {fn_name!r} is missing catch_unwind / guard unwind protection"
                    )


def check_csproj_and_aot_contracts(root: Path, milestone: str = "M1") -> None:
    csproj_path = root / "ui-winui3-fluent2" / "TotalDrop.WinUI.csproj"
    csproj_text = csproj_path.read_text(encoding="utf-8")
    tree = ET.fromstring(csproj_text)

    def get_prop(name: str) -> str:
        el = tree.find(f".//{name}")
        return (el.text or "").strip() if el is not None else ""

    tf = get_prop("TargetFramework")
    if tf != "net10.0-windows10.0.26100.0":
        raise ValueError(f"TotalDrop.WinUI.csproj TargetFramework={tf!r} != 'net10.0-windows10.0.26100.0'")
    required_props = [
        ("PublishAot", "true"),
        ("TreatWarningsAsErrors", "true"),
        ("CsWinRTAotOptimizerEnabled", "true"),
        ("EnableTypeInfoReflection", "false"),
        ("InvariantGlobalization", "false"),
        ("WindowsAppSDKSelfContained", "false"),
        ("ApplicationIcon", r"Assets\TotalDrop.ico"),
    ]
    if milestone in ("M3", "M4"):
        required_props.append(("JsonSerializerIsReflectionEnabledByDefault", "false"))
    for prop, expected in required_props:
        actual = get_prop(prop)
        if actual.lower() != expected.lower():
            raise ValueError(f"TotalDrop.WinUI.csproj <{prop}>={actual!r} != {expected!r}")

    wasdk_ver = ""
    for pkg in tree.findall(".//PackageReference"):
        if pkg.attrib.get("Include") == "Microsoft.WindowsAppSDK":
            wasdk_ver = pkg.attrib.get("Version", "")
    if not re.match(r"^1\.8\.", wasdk_ver):
        raise ValueError(f"TotalDrop.WinUI.csproj Microsoft.WindowsAppSDK Version={wasdk_ver!r} does not match ^1.8.")

    # Check manifest dependency on Microsoft.WindowsAppRuntime.1.8
    x64_manifest = root / "target-x86_64" / "Package.x64.appxmanifest"
    m_root = ET.fromstring(x64_manifest.read_text(encoding="utf-8"))
    deps = [
        el.attrib.get("Name", "")
        for el in m_root.findall(f".//{{{APPX_NS}}}PackageDependency")
    ]
    if "Microsoft.WindowsAppRuntime.1.8" not in deps:
        raise ValueError(f"Package.x64.appxmanifest missing Microsoft.WindowsAppRuntime.1.8 dependency (got {deps})")

    # Scan C# & XAML app files (excluding TotalDrop.WinUI.Tests)
    cs_files = iter_app_files(root, "*.cs")
    xaml_files = iter_app_files(root, "*.xaml")
    has_disable_marshalling = False
    bridge_imports_found = 0
    allowed_sys_dlls = {"kernel32.dll", "shell32.dll", "ole32.dll"}

    for cs in cs_files:
        rel = cs.relative_to(root)
        raw_cs = cs.read_text(encoding="utf-8")
        cleaned = strip_csharp_comments(raw_cs)
        masked_cs = mask_csharp_comments_and_strings(raw_cs)
        if re.search(r"\[assembly:\s*DisableRuntimeMarshalling\s*\]", cleaned):
            has_disable_marshalling = True
        for forbidden_pat, token_label in (
            (r"\[\s*ComImport\b", "[ComImport]"),
            (r"\[\s*DllImport\b", "[DllImport]"),
            (r"\bActivator\.CreateInstance\b", "Activator.CreateInstance"),
            (r"\bSystem\.Security\.Cryptography\b", "System.Security.Cryptography"),
        ):
            if re.search(forbidden_pat, cleaned):
                raise ValueError(f"{rel}: forbidden construct {token_label} found")

        # Resolve local const string definitions (e.g., BridgeDll = "totaldrop_windows_ffi")
        consts = dict(re.findall(r'\bconst\s+string\s+(\w+)\s*=\s*"([^"]+)"\s*;', cleaned))
        for m in re.finditer(r'\[LibraryImport\(\s*(?:"([^"]+)"|(\w+))([^]]*)\)\]', cleaned):
            dll_lit, dll_const, rest = m.group(1), m.group(2), m.group(3)
            dll_val = dll_lit if dll_lit is not None else consts.get(dll_const or "", "")
            if "totaldrop_win_" in rest or dll_val == "totaldrop_windows_ffi":
                if dll_val != "totaldrop_windows_ffi":
                    raise ValueError(f"{rel}: totaldrop_win_* LibraryImport targets {dll_val!r} instead of 'totaldrop_windows_ffi'")
                bridge_imports_found += 1
            elif dll_val.lower() not in allowed_sys_dlls:
                raise ValueError(f"{rel}: unexpected LibraryImport target {dll_val!r}")

        # Verify every JsonSerializer.Serialize* / Deserialize* (incl. E12 DeserializeAsyncEnumerable
        # and arbitrarily nested generic type arguments like Dictionary<string, List<int>>)
        # passes TotalDropJsonContext.Default.* as real code (not inside strings or bled across parens-in-strings).
        masked_len = len(masked_cs)
        for jm in re.finditer(
            r"\bJsonSerializer\s*\.\s*(?:De)?[Ss]erialize(?:AsyncEnumerable|Async|ToUtf8Bytes|ToDocument|ToNode|ToElement)?\b",
            masked_cs,
        ):
            pos = jm.end()
            while pos < masked_len and masked_cs[pos].isspace():
                pos += 1
            if pos < masked_len and masked_cs[pos] == "<":
                angle_depth = 1
                pos += 1
                while pos < masked_len and angle_depth > 0:
                    if masked_cs[pos] == "<":
                        angle_depth += 1
                    elif masked_cs[pos] == ">":
                        angle_depth -= 1
                    pos += 1
                while pos < masked_len and masked_cs[pos].isspace():
                    pos += 1
            if pos >= masked_len or masked_cs[pos] != "(":
                continue
            depth = 1
            pos += 1
            while pos < masked_len and depth > 0:
                if masked_cs[pos] == "(":
                    depth += 1
                elif masked_cs[pos] == ")":
                    depth -= 1
                pos += 1
            masked_call = masked_cs[jm.start() : pos]
            if "TotalDropJsonContext.Default." not in masked_call:
                raw_call = raw_cs[jm.start() : pos].strip()
                raise ValueError(
                    f"{rel}: reflection-based JsonSerializer call without TotalDropJsonContext.Default: {raw_call!r}"
                )

    if not has_disable_marshalling:
        raise ValueError("ui-winui3-fluent2: missing [assembly: DisableRuntimeMarshalling]")
    if bridge_imports_found < 6:
        raise ValueError(f"ui-winui3-fluent2: expected >= 6 totaldrop_windows_ffi [LibraryImport] declarations, found {bridge_imports_found}")

    for xaml in xaml_files:
        rel = xaml.relative_to(root)
        # Strip XML comments before scanning for reflection {Binding ...}
        text = re.sub(r"<!--.*?-->", "", xaml.read_text(encoding="utf-8"), flags=re.DOTALL)
        if "{Binding " in text or "{Binding}" in text:
            raise ValueError(f"{rel}: forbidden reflection '{{Binding ' expression found (must use {{x:Bind}})")


def check_4way_35_locale_parity(root: Path) -> None:
    l10n_dir = root / "l10n"
    neg_data = json.loads((l10n_dir / "tests" / "negotiation.json").read_text(encoding="utf-8"))
    neg_avail = set(neg_data["available"])

    status_data = json.loads((l10n_dir / "status.json").read_text(encoding="utf-8"))
    status_set = (set(status_data["languages"].keys()) | {"en"}) - {"pt", "zh"}

    arb_files = sorted((l10n_dir / "app").glob("app_*.arb"))
    arb_stems = {p.stem[len("app_") :].replace("_", "-") for p in arb_files} - {"pt", "zh"}

    if len(neg_avail) != 35 or neg_avail != status_set or neg_avail != arb_stems:
        raise ValueError(
            f"canonical 35-locale mismatch inside l10n/: neg={len(neg_avail)}, status={len(status_set)}, arb={len(arb_stems)}"
        )

    en_arb = json.loads((l10n_dir / "app" / "app_en.arb").read_text(encoding="utf-8"))
    expected_keys = {k for k in en_arb if not k.startswith("@")}
    if len(expected_keys) < 176:
        raise ValueError(f"l10n/app/app_en.arb key count {len(expected_keys)} < 176")

    # 1. Manifests Package.{x64,arm64}.appxmanifest
    for rel_manifest in (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    ):
        m_path = root / rel_manifest
        m_root = ET.fromstring(m_path.read_text(encoding="utf-8"))
        langs = [
            el.attrib.get("Language", "")
            for el in m_root.findall(f".//{{{APPX_NS}}}Resources/{{{APPX_NS}}}Resource")
        ]
        if "en-US" in langs:
            raise ValueError(f"{rel_manifest}: forbidden <Resource Language=\"en-US\" /> mismatch against Strings/en/Resources.resw")
        if "en" not in langs:
            raise ValueError(f"{rel_manifest}: missing <Resource Language=\"en\" />")
        if len(langs) != len(set(langs)):
            dups = sorted({t for t in langs if langs.count(t) > 1})
            raise ValueError(f"{rel_manifest}: duplicate <Resource Language> entries ({len(langs)} != 35): {dups}")
        if set(langs) != neg_avail:
            missing = sorted(neg_avail - set(langs))
            extra = sorted(set(langs) - neg_avail)
            raise ValueError(
                f"{rel_manifest}: locale set mismatch ({len(langs)} != 35); missing={missing}, extra={extra}"
            )

    # 2. Strings/locales.json
    strings_dir = root / "ui-winui3-fluent2" / "Strings"
    locales_json = json.loads((strings_dir / "locales.json").read_text(encoding="utf-8"))
    if locales_json.get("defaultLocale") != "en" or locales_json.get("localeCount") != 35:
        raise ValueError(f"Strings/locales.json invalid header: {locales_json.get('defaultLocale')}, {locales_json.get('localeCount')}")
    json_tags = {item["tag"] for item in locales_json.get("locales", [])}
    if json_tags != neg_avail:
        raise ValueError(f"Strings/locales.json tag mismatch: diff={sorted(json_tags ^ neg_avail)}")

    # 3. Strings/<tag>/Resources.resw directories and key completeness
    resw_dirs = {p.name for p in strings_dir.iterdir() if p.is_dir()}
    for forbidden_base in ("pt", "zh"):
        if forbidden_base in resw_dirs:
            raise ValueError(f"Strings/{forbidden_base}: forbidden base fallback directory leaked into WinUI Strings/")
    if resw_dirs != neg_avail:
        missing = sorted(neg_avail - resw_dirs)
        extra = sorted(resw_dirs - neg_avail)
        raise ValueError(
            f"Strings/ locale directory mismatch ({len(resw_dirs)} != 35); missing={missing}, extra={extra}"
        )

    for tag in sorted(neg_avail):
        resw_path = strings_dir / tag / "Resources.resw"
        if not resw_path.is_file():
            raise ValueError(f"missing {resw_path.relative_to(root)}")
        resw_root = ET.fromstring(resw_path.read_text(encoding="utf-8"))
        keys = {el.attrib.get("name", "") for el in resw_root.findall("data")}
        if keys != expected_keys:
            missing_k = sorted(expected_keys - keys)
            extra_k = sorted(keys - expected_keys)
            raise ValueError(
                f"Strings/{tag}/Resources.resw key count mismatch ({len(keys)} != {len(expected_keys)}); "
                f"missing={missing_k[:5]}, extra={extra_k[:5]}"
            )


def _lex_ps1(src: str) -> list[tuple[str, str, int]]:
    """Single quote/here-string/backtick/subexpression-aware PowerShell tokenizer (R2-C2-F2).

    Emits `(kind, text, start_line)` tokens where `kind` is one of:
    `CODE`, `STRING`, `COMMENT`, `NEWLINE`, `CONT`, `SEP`, `LBRACE`, `RBRACE`,
    `SUBEXPR_OPEN`, `SUBEXPR_CLOSE`.
    """
    tokens: list[tuple[str, str, int]] = []
    # Stack frame formats:
    #   ["code", paren_depth, is_subexpr]
    #   ["dq"]
    #   ["here_dq", at_line_start]
    stack: list[list[Any]] = [["code", 0, False]]
    code_buf: list[str] = []
    code_line = 1
    str_buf: list[str] = []
    str_line = 1
    line_no = 1
    i = 0
    n = len(src)

    def flush_code() -> None:
        if code_buf:
            tokens.append(("CODE", "".join(code_buf), code_line))
            code_buf.clear()

    def flush_str() -> None:
        if str_buf:
            tokens.append(("STRING", "".join(str_buf), str_line))
            str_buf.clear()

    while i < n:
        frame = stack[-1]
        kind = frame[0]
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""

        if kind == "dq":
            if not str_buf:
                str_line = line_no
            if ch == "`" and i + 1 < n:
                str_buf.append(src[i : i + 2])
                if src[i + 1] == "\n":
                    line_no += 1
                i += 2
                continue
            if ch == "$" and nxt == "(":
                flush_str()
                tokens.append(("SUBEXPR_OPEN", "$(", line_no))
                i += 2
                stack.append(["code", 1, True])
                continue
            if ch == '"' and nxt == '"':
                str_buf.append('""')
                i += 2
                continue
            if ch == '"':
                str_buf.append('"')
                flush_str()
                i += 1
                stack.pop()
                continue
            if ch == "\n":
                line_no += 1
            str_buf.append(ch)
            i += 1
            continue

        if kind == "here_dq":
            at_line_start: bool = frame[1]
            if not str_buf:
                str_line = line_no
            if at_line_start and ch == '"' and nxt == "@":
                str_buf.append('"@')
                flush_str()
                i += 2
                stack.pop()
                continue
            if ch == "`" and i + 1 < n:
                str_buf.append(src[i : i + 2])
                if src[i + 1] == "\n":
                    line_no += 1
                    frame[1] = True
                else:
                    frame[1] = False
                i += 2
                continue
            if ch == "$" and nxt == "(":
                flush_str()
                tokens.append(("SUBEXPR_OPEN", "$(", line_no))
                frame[1] = False
                i += 2
                stack.append(["code", 1, True])
                continue
            if ch == "\n":
                line_no += 1
                frame[1] = True
            else:
                frame[1] = False
            str_buf.append(ch)
            i += 1
            continue

        # kind == "code"
        is_subexpr: bool = frame[2]

        if ch == "`":
            if nxt == "\n":
                flush_code()
                tokens.append(("CONT", "`\n", line_no))
                line_no += 1
                i += 2
                continue
            if nxt == "\r" and i + 2 < n and src[i + 2] == "\n":
                flush_code()
                tokens.append(("CONT", "`\r\n", line_no))
                line_no += 1
                i += 3
                continue
            if i + 1 < n:
                if not code_buf:
                    code_line = line_no
                code_buf.append(src[i : i + 2])
                i += 2
                continue

        if ch == "<" and nxt == "#":
            flush_code()
            start_ln = line_no
            end_pos = src.find("#>", i + 2)
            end_idx = n if end_pos == -1 else end_pos + 2
            seg = src[i:end_idx]
            tokens.append(("COMMENT", seg, start_ln))
            line_no += seg.count("\n")
            i = end_idx
            continue

        if ch == "#":
            flush_code()
            start = i
            while i < n and src[i] != "\n":
                i += 1
            tokens.append(("COMMENT", src[start:i], line_no))
            continue

        # Here-string @"...\n"@ or @'...\n'@
        if ch == "@" and nxt in ('"', "'"):
            j = i + 2
            while j < n and src[j] in (" ", "\t", "\r"):
                j += 1
            if j < n and src[j] == "\n":
                flush_code()
                start_ln = line_no
                hdr = src[i : j + 1]
                line_no += 1
                i = j + 1
                if nxt == "'":
                    parts = [hdr]
                    at_start = True
                    while i < n:
                        if at_start and src[i : i + 2] == "'@":
                            parts.append("'@")
                            i += 2
                            break
                        c = src[i]
                        parts.append(c)
                        if c == "\n":
                            line_no += 1
                            at_start = True
                        else:
                            at_start = False
                        i += 1
                    tokens.append(("STRING", "".join(parts), start_ln))
                else:
                    str_line = start_ln
                    str_buf.append(hdr)
                    stack.append(["here_dq", True])
                continue

        # Verbatim single-quoted string '...' (only '' escapes ')
        if ch == "'":
            flush_code()
            start_ln = line_no
            parts = ["'"]
            i += 1
            while i < n:
                if src[i] == "'" and i + 1 < n and src[i + 1] == "'":
                    parts.append("''")
                    i += 2
                    continue
                c = src[i]
                parts.append(c)
                i += 1
                if c == "'":
                    break
                if c == "\n":
                    line_no += 1
            tokens.append(("STRING", "".join(parts), start_ln))
            continue

        # Expandable double-quoted string "..."
        if ch == '"':
            flush_code()
            str_line = line_no
            str_buf.append('"')
            i += 1
            stack.append(["dq"])
            continue

        if ch == "(":
            frame[1] += 1
            if not code_buf:
                code_line = line_no
            code_buf.append("(")
            i += 1
            continue

        if ch == ")":
            if is_subexpr and frame[1] == 1:
                flush_code()
                tokens.append(("SUBEXPR_CLOSE", ")", line_no))
                i += 1
                stack.pop()
                continue
            frame[1] = max(0, frame[1] - 1)
            if not code_buf:
                code_line = line_no
            code_buf.append(")")
            i += 1
            continue

        if ch == "{":
            flush_code()
            tokens.append(("LBRACE", "{", line_no))
            i += 1
            continue

        if ch == "}":
            flush_code()
            tokens.append(("RBRACE", "}", line_no))
            i += 1
            continue

        if (ch == "&" and nxt == "&") or (ch == "|" and nxt == "|"):
            flush_code()
            tokens.append(("SEP", src[i : i + 2], line_no))
            i += 2
            continue

        if ch in (";", "|"):
            flush_code()
            tokens.append(("SEP", ch, line_no))
            i += 1
            continue

        if ch == "\n":
            flush_code()
            tokens.append(("NEWLINE", "\n", line_no))
            line_no += 1
            i += 1
            continue

        if not code_buf:
            code_line = line_no
        code_buf.append(ch)
        i += 1

    flush_code()
    flush_str()
    return tokens


def _strip_ps1_comments_preserve_lines(src: str) -> str:
    """Strip unquoted PowerShell `#` and `<# ... #>` comments while preserving strings and exact 1:1 line numbers."""
    out: list[str] = []
    for kind, text, _line in _lex_ps1(src):
        if kind == "COMMENT":
            nl = text.count("\n")
            if nl:
                out.append("\n" * nl)
            elif text.startswith("<#"):
                out.append(" ")
        else:
            out.append(text)
    return "".join(out)


def _analyze_ps1_hardening(ps1_path: Path, rel_label: str, *, require_rustflags_clear: bool = True) -> None:
    raw = ps1_path.read_text(encoding="utf-8")
    tokens = _lex_ps1(raw)

    brace_depth = 0
    finally_entry_depths: list[int] = []
    pending_finally = False
    cleared_rustflags = False
    cleared_encoded = False
    saw_cargo_build = False

    # Statement stack allows `$(...)` subexpressions inside strings to be analyzed independently
    # rather than being masked by an outer `Write-Host` command.
    stmt_stack: list[list[tuple[str, str, int]]] = [[]]

    def analyze_statement(stmt: list[tuple[str, str, int]]) -> None:
        nonlocal pending_finally, cleared_rustflags, cleared_encoded, saw_cargo_build
        if not stmt:
            return
        line_no = stmt[0][2]
        code_parts: list[str] = []
        full_parts: list[str] = []
        for tkind, ttext, _tln in stmt:
            if tkind == "CODE":
                code_parts.append(ttext)
                full_parts.append(ttext)
            elif tkind == "STRING":
                code_parts.append(" ")
                full_parts.append(ttext)
        code_only = "".join(code_parts)
        full_stmt = "".join(full_parts)
        if not code_only.strip() and not full_stmt.strip():
            return

        # `finally` keyword must appear strictly in unquoted code at the end of the statement before `{`.
        if re.search(r"(?:^|[\s}])finally\s*$", code_only, flags=re.IGNORECASE):
            pending_finally = True
        else:
            pending_finally = False

        in_finally = bool(finally_entry_depths)

        # Evaluate statement actions in execution order; because unquoted `;`, `|`, `&&`, `||`
        # split statements before calling analyze_statement, post-cargo clears on the same line
        # see `saw_cargo_build == True` and cannot satisfy the pre-cargo clearing contract.
        if re.search(r"\bRemove-Item\s+Env:RUSTFLAGS\b", code_only, flags=re.IGNORECASE) and not saw_cargo_build:
            cleared_rustflags = True
        if (
            re.search(r"\bRemove-Item\s+Env:CARGO_ENCODED_RUSTFLAGS\b", code_only, flags=re.IGNORECASE)
            and not saw_cargo_build
        ):
            cleared_encoded = True
        if (
            re.search(r"\bcargo\s+build\b", code_only, flags=re.IGNORECASE)
            or re.search(r"(?:^|[\s(&])&\s*cargo\s+@", code_only, flags=re.IGNORECASE)
        ):
            saw_cargo_build = True

        # Active $env:RUSTFLAGS = ... or $env:CARGO_ENCODED_RUSTFLAGS = ... outside finally (unquoted code only)
        if not in_finally:
            m_rf = re.search(r"\$\{?env:(RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS)\}?\s*=", code_only, flags=re.IGNORECASE)
            if m_rf:
                raise ValueError(
                    f"{rel_label}:{line_no}: active $env:{m_rf.group(1)} assignment outside finally block"
                )

        # Check makeappx invocations per statement (log/throw statements do not exempt subsequent `;`-chained commands)
        is_log_stmt = bool(
            re.match(
                r"^\s*(?:Write-Host|Write-Output|Write-Verbose|Write-Warning|Write-Information|throw)\b",
                code_only,
                flags=re.IGNORECASE,
            )
        )
        if not is_log_stmt:
            if re.search(r"makeappx", full_stmt, flags=re.IGNORECASE):
                if re.search(r'(?:^|[\s,(])["\']?[/-]nv["\']?(?:[\s,)]|$)', full_stmt, flags=re.IGNORECASE):
                    raise ValueError(
                        f"{rel_label}:{line_no}: forbidden makeappx '/nv' flag found on command invocation"
                    )

    for kind, text, line_no in tokens:
        if kind in ("CONT", "COMMENT"):
            # Preserve token separation across line continuations and inline `<# ... #>` comments.
            if stmt_stack[-1]:
                stmt_stack[-1].append(("CODE", " ", line_no))
            continue
        if kind in ("NEWLINE", "SEP"):
            analyze_statement(stmt_stack[-1])
            stmt_stack[-1] = []
            continue
        if kind == "SUBEXPR_OPEN":
            stmt_stack.append([])
            continue
        if kind == "SUBEXPR_CLOSE":
            analyze_statement(stmt_stack[-1])
            stmt_stack.pop()
            if stmt_stack:
                stmt_stack[-1].append(("CODE", " ", line_no))
            else:
                stmt_stack.append([])
            continue
        if kind == "LBRACE":
            analyze_statement(stmt_stack[-1])
            stmt_stack[-1] = []
            brace_depth += 1
            if pending_finally:
                finally_entry_depths.append(brace_depth)
                pending_finally = False
            continue
        if kind == "RBRACE":
            analyze_statement(stmt_stack[-1])
            stmt_stack[-1] = []
            if finally_entry_depths and finally_entry_depths[-1] == brace_depth:
                finally_entry_depths.pop()
            brace_depth = max(0, brace_depth - 1)
            continue
        if kind in ("CODE", "STRING"):
            if kind == "CODE" and not text.strip() and not stmt_stack[-1]:
                continue
            stmt_stack[-1].append((kind, text, line_no))

    while stmt_stack:
        analyze_statement(stmt_stack.pop())

    if require_rustflags_clear and (not cleared_rustflags or not cleared_encoded):
        raise ValueError(
            f"{rel_label}: must clear both Env:RUSTFLAGS and Env:CARGO_ENCODED_RUSTFLAGS before cargo build"
        )


def check_cargo_hardening_and_ps1(root: Path, milestone: str = "M1") -> None:
    x64_cfg = (root / "target-x86_64" / "cargo-config.toml").read_text(encoding="utf-8")
    x64_parsed = tomllib.loads(x64_cfg)
    x64_flags = " ".join(x64_parsed.get("target", {}).get("x86_64-pc-windows-msvc", {}).get("rustflags", []))
    for req in ("+crt-static", "/DEPENDENTLOADFLAG:0x800", "/CETCOMPAT", "/DYNAMICBASE", "/HIGHENTROPYVA", "/NXCOMPAT"):
        if req not in x64_flags:
            raise ValueError(f"target-x86_64/cargo-config.toml missing required hardening flag {req}")

    arm_cfg = (root / "target-arm64" / "cargo-config.toml").read_text(encoding="utf-8")
    arm_parsed = tomllib.loads(arm_cfg)
    arm_flags = " ".join(arm_parsed.get("target", {}).get("aarch64-pc-windows-msvc", {}).get("rustflags", []))
    for req in ("+crt-static", "/DEPENDENTLOADFLAG:0x800", "/DYNAMICBASE", "/HIGHENTROPYVA", "/NXCOMPAT"):
        if req not in arm_flags:
            raise ValueError(f"target-arm64/cargo-config.toml missing required hardening flag {req}")

    _analyze_ps1_hardening(root / "target-x86_64" / "build-x64.ps1", "target-x86_64/build-x64.ps1")
    _analyze_ps1_hardening(root / "target-arm64" / "build-arm64.ps1", "target-arm64/build-arm64.ps1")
    bundle_ps1 = root / "tools" / "build-msixbundle.ps1"
    if milestone == "M4" and bundle_ps1.is_file():
        _analyze_ps1_hardening(bundle_ps1, "tools/build-msixbundle.ps1", require_rustflags_clear=False)

    # Signing-material / secret-extension scan (T2-F05-05b)
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in {".git", "target"} for part in p.parts):
            continue
        if p.name in FORBIDDEN_SIGNING_NAMES or p.suffix.lower() in FORBIDDEN_SIGNING_EXTS:
            raise ValueError(f"forbidden signing/secret material found in repository tree: {p.relative_to(root)}")


def _parse_ci_jobs(ci_text: str) -> dict[str, str]:
    """Extract top-level `jobs:` blocks by 2-space YAML indentation (pure stdlib)."""
    jobs: dict[str, list[str]] = {}
    in_jobs = False
    cur_job: str | None = None
    for line in ci_text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs and line and not line.startswith(" ") and not line.startswith("#"):
            break
        if not in_jobs:
            continue
        m = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if m:
            cur_job = m.group(1)
            jobs[cur_job] = []
        elif cur_job is not None:
            jobs[cur_job].append(line)
    return {k: "\n".join(v) for k, v in jobs.items()}


def check_workflows_and_subplatform_scripts(root: Path) -> None:
    wf_dir = root / ".github" / "workflows"
    workflows = sorted(wf_dir.glob("*.yml"))
    if not workflows:
        raise ValueError("no .github/workflows/*.yml found")

    for wf in workflows:
        rel = wf.relative_to(root)
        for line_no, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.split("#", 1)[0].strip()
            m = re.match(r"^(?:-\s*)?uses:\s*([^\s]+)$", stripped)
            if not m:
                continue
            ref = m.group(1).strip("'\"")
            if ref.startswith("./"):
                continue
            if not re.search(r"@[0-9a-f]{40}$", ref):
                raise ValueError(f"{rel}:{line_no}: unpinned mutable action ref {ref!r} (must pin 40-hex commit SHA)")

    ci_text = (wf_dir / "ci.yml").read_text(encoding="utf-8")
    jobs = _parse_ci_jobs(ci_text)
    if "windows-x64-msix" not in jobs:
        raise ValueError(".github/workflows/ci.yml missing job 'windows-x64-msix'")
    win_job = jobs["windows-x64-msix"]
    if not re.search(r"runs-on:\s*(windows-latest|windows-2025)\b", win_job):
        raise ValueError("ci.yml windows-x64-msix must run on windows-latest or windows-2025")
    if not re.search(r'dotnet-version:\s*["\']?10\.0\.x["\']?', win_job):
        raise ValueError("ci.yml windows-x64-msix must pin .NET 10 (dotnet-version: 10.0.x)")
    if "rustup" not in win_job:
        raise ValueError("ci.yml windows-x64-msix must verify Rust toolchain via rustup")
    rt_toml = tomllib.loads((root / "rust-toolchain.toml").read_text(encoding="utf-8"))
    if rt_toml.get("toolchain", {}).get("channel") != "1.99.1":
        raise ValueError("rust-toolchain.toml must pin channel = '1.99.1'")
    if "if-no-files-found: error" not in win_job:
        raise ValueError("ci.yml windows-x64-msix upload must set if-no-files-found: error")
    if ".msix" not in win_job or "SHA256SUMS" not in win_job:
        raise ValueError("ci.yml windows-x64-msix must upload .msix and SHA256SUMS")

    gate_job = jobs.get("gate", "")
    if "windows-x64-msix" not in gate_job:
        raise ValueError("ci.yml jobs.gate.needs is missing required 'windows-x64-msix' dependency")

    # Verify check-versions.py is invoked in a job required by gate (T1-F07-05)
    version_jobs = [name for name, body in jobs.items() if "tools/check-versions.py" in body]
    if not any(name in gate_job for name in version_jobs):
        raise ValueError("ci.yml does not enforce tools/check-versions.py in any job feeding jobs.gate.needs")

    # Verify subplatform POSIX shell scripts (T1-F06-02)
    build_sh = root / "subplatforms" / "msix" / "x86_64" / "build.sh"
    verify_sh = root / "subplatforms" / "msix" / "x86_64" / "verify.sh"
    posix_shells = _resolve_posix_shells()
    for sh_path in (build_sh, verify_sh):
        for label, shell_exe in posix_shells:
            p = subprocess.run([shell_exe, "-n", str(sh_path)], capture_output=True, text=True, check=False)
            if p.returncode != 0:
                raise ValueError(f"{label} -n failed on {sh_path.relative_to(root)}: {p.stderr}")
    build_text = build_sh.read_text(encoding="utf-8")
    if re.search(r"\btar\b[^|\n]*\|\s*gzip\b", build_text):
        raise ValueError("subplatforms/msix/x86_64/build.sh still contains forbidden tar | gzip stub")
    verify_text = verify_sh.read_text(encoding="utf-8")
    if "sha256sum" not in verify_text or "AppxManifest.xml" not in verify_text:
        raise ValueError("subplatforms/msix/x86_64/verify.sh must validate both SHA256SUMS and OPC/ZIP AppxManifest.xml")


_ASCII_MSIX_QUAD_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$", re.ASCII)


def _validate_msix_quad(version: str, source_label: str) -> None:
    if not _ASCII_MSIX_QUAD_RE.fullmatch(version):
        raise ValueError(
            f"{source_label}: invalid 4-part quad MSIX version {version!r} (must have 4 ASCII numeric parts)"
        )
    parts = version.split(".")
    if any(len(p) > 1 and p.startswith("0") for p in parts):
        raise ValueError(
            f"{source_label}: MSIX quad {version!r} must not contain leading zeros"
        )
    nums = [int(p) for p in parts]
    for idx, val in enumerate(nums):
        if not (0 <= val <= 65535):
            raise ValueError(
                f"{source_label}: MSIX quad component {idx} ({val}) exceeds uint16 bounds 0..=65535"
            )
    if nums[3] != 0:
        raise ValueError(
            f"{source_label}: MSIX version {version!r} violates Microsoft Store Revision == 0 rule"
        )


def check_versions_quad_and_clsid(root: Path) -> None:
    # Check 4-part MSIX quad rules across manifests & scripts
    versions_found: dict[str, str] = {}
    for rel in (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    ):
        m_root = ET.fromstring((root / rel).read_text(encoding="utf-8"))
        ident = m_root.find(f"{{{APPX_NS}}}Identity")
        if ident is None:
            raise ValueError(f"{rel}: missing <Identity>")
        ver = ident.attrib.get("Version", "")
        _validate_msix_quad(ver, f"{rel} Identity/@Version")
        versions_found[rel] = ver

    app_manifest_root = ET.fromstring((root / "ui-winui3-fluent2" / "app.manifest").read_text(encoding="utf-8"))
    asm_ident = app_manifest_root.find("{urn:schemas-microsoft-com:asm.v1}assemblyIdentity")
    if asm_ident is None:
        raise ValueError("ui-winui3-fluent2/app.manifest missing <assemblyIdentity>")
    app_ver = asm_ident.attrib.get("version", "")
    _validate_msix_quad(app_ver, "ui-winui3-fluent2/app.manifest")
    versions_found["ui-winui3-fluent2/app.manifest"] = app_ver

    for rel in ("target-x86_64/build-x64.ps1", "target-arm64/build-arm64.ps1"):
        m = re.search(r'\[string\]\$Version\s*=\s*"([^"]+)"', (root / rel).read_text(encoding="utf-8"))
        if not m:
            raise ValueError(f"{rel}: missing default $Version parameter")
        _validate_msix_quad(m.group(1), rel)
        versions_found[rel] = m.group(1)

    ffi_lib_rel = "crates/totaldrop-windows-ffi/src/lib.rs"
    ffi_lib_text = (root / ffi_lib_rel).read_text(encoding="utf-8")
    m_ffi_ver = re.search(r'\bpub\s+const\s+MSIX_VERSION\s*:\s*&str\s*=\s*"([^"]+)"\s*;', ffi_lib_text)
    if not m_ffi_ver:
        raise ValueError(f"{ffi_lib_rel}: missing pub const MSIX_VERSION")
    _validate_msix_quad(m_ffi_ver.group(1), f"{ffi_lib_rel} MSIX_VERSION")
    versions_found[ffi_lib_rel] = m_ffi_ver.group(1)

    unique_msix_versions = set(versions_found.values())
    if len(unique_msix_versions) != 1:
        raise ValueError(f"MSIX version mismatch across manifests/scripts/FFI: {versions_found}")
    unified_msix_ver = next(iter(unique_msix_versions))
    if unified_msix_ver != "0.1.1.0":
        raise ValueError(
            f"unified MSIX quad version {unified_msix_ver!r} != expected '0.1.1.0': {versions_found}"
        )

    # Core crate version isolation (0.2.0-beta.5) vs Windows FFI app SemVer (0.1.0-beta.1)
    root_toml = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    ws_ver = root_toml.get("workspace", {}).get("package", {}).get("version")
    if ws_ver != "0.2.0-beta.5":
        raise ValueError(f"workspace core version {ws_ver!r} != '0.2.0-beta.5'")
    for crate in FORBID_UNSAFE_CRATES:
        ct = tomllib.loads((root / "crates" / crate / "Cargo.toml").read_text(encoding="utf-8"))
        if ct.get("package", {}).get("version", {}).get("workspace") is not True:
            raise ValueError(f"crates/{crate}/Cargo.toml must inherit version.workspace = true")
    ffi_toml = tomllib.loads((root / "crates" / "totaldrop-windows-ffi" / "Cargo.toml").read_text(encoding="utf-8"))
    if ffi_toml.get("package", {}).get("version") != "0.1.0-beta.1":
        raise ValueError("crates/totaldrop-windows-ffi/Cargo.toml version != '0.1.0-beta.1'")

    ext_cargo_path = root / "crates" / "totaldrop-explorer-ext" / "Cargo.toml"
    if ext_cargo_path.is_file():
        ext_toml = tomllib.loads(ext_cargo_path.read_text(encoding="utf-8"))
        if ext_toml.get("package", {}).get("version") != "0.1.0-beta.1":
            raise ValueError("crates/totaldrop-explorer-ext/Cargo.toml version != '0.1.0-beta.1'")

    # Validate canonical Explorer COM CLSID in crates/totaldrop-explorer-ext/src/lib.rs
    # (retired C++/MIDL ExplorerCommand.idl replaced by pure-Rust COM server in M3).
    ext_lib_rel = "crates/totaldrop-explorer-ext/src/lib.rs"
    ext_lib_text = (root / ext_lib_rel).read_text(encoding="utf-8")
    m_clsid_str = re.search(
        r'\bpub\s+const\s+CLSID_TOTALDROP_EXPLORER_COMMAND_STR\s*:\s*&str\s*=\s*"([^"]+)"\s*;',
        ext_lib_text,
    )
    if not m_clsid_str:
        raise ValueError(f"{ext_lib_rel}: missing pub const CLSID_TOTALDROP_EXPLORER_COMMAND_STR")
    ext_guid = m_clsid_str.group(1).strip()
    if not BARE_UUID_RE.fullmatch(ext_guid):
        raise ValueError(f"{ext_lib_rel}: malformed CLSID GUID {ext_guid!r} in CLSID_TOTALDROP_EXPLORER_COMMAND_STR")
    if ext_guid.upper() != CANONICAL_CLSID:
        raise ValueError(f"{ext_lib_rel}: mismatched CLSID {ext_guid!r} != {CANONICAL_CLSID}")

    m_clsid_u128 = re.search(
        r"\bpub\s+const\s+CLSID_TOTALDROP_EXPLORER_COMMAND_U128\s*:\s*u128\s*=\s*0x([0-9A-Fa-f_]+)\s*;",
        ext_lib_text,
    )
    if not m_clsid_u128:
        raise ValueError(f"{ext_lib_rel}: missing pub const CLSID_TOTALDROP_EXPLORER_COMMAND_U128")
    expected_hex = CANONICAL_CLSID.replace("-", "").lower()
    actual_hex = m_clsid_u128.group(1).replace("_", "").lower()
    if actual_hex != expected_hex:
        raise ValueError(f"{ext_lib_rel}: CLSID_TOTALDROP_EXPLORER_COMMAND_U128 {actual_hex!r} != {expected_hex!r}")

    # CLSID consistency across README, ExplorerExtension README, pure-Rust COM crate, and manifests
    clsid_files = (
        "README.md",
        "ui-winui3-fluent2/ExplorerExtension/README.md",
        ext_lib_rel,
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    )
    for rel in clsid_files:
        text = (root / rel).read_text(encoding="utf-8")
        if DRIFTED_CLSID.lower() in text.lower():
            raise ValueError(f"{rel}: drifted CLSID {DRIFTED_CLSID} found!")
        if CANONICAL_CLSID.lower() not in text.lower():
            raise ValueError(f"{rel}: canonical CLSID {CANONICAL_CLSID} missing!")


# ---------------------------------------------------------------------------
# M2 Invariant Checks


def check_no_cloud_roaming(root: Path) -> None:
    store_path = root / "ui-winui3-fluent2" / "Services" / "SettingsStore.cs"
    store_text = store_path.read_text(encoding="utf-8")
    if "LocalApplicationData" not in store_text or "settings.json" not in store_text:
        raise ValueError("Services/SettingsStore.cs must persist to LocalApplicationData/TotalDrop/settings.json")

    for cs in iter_app_files(root, "*.cs"):
        cleaned = strip_csharp_comments(cs.read_text(encoding="utf-8"))
        for forbidden in ("RoamingFolder", "RoamingSettings"):
            if re.search(rf"\b{forbidden}\b", cleaned):
                raise ValueError(f"{cs.relative_to(root)}: forbidden cloud-sync API '{forbidden}' found")


def check_resw_critical_security_keys(root: Path) -> None:
    status_data = json.loads((root / "l10n" / "status.json").read_text(encoding="utf-8"))
    en_arb = json.loads((root / "l10n" / "app" / "app_en.arb").read_text(encoding="utf-8"))
    strings_dir = root / "ui-winui3-fluent2" / "Strings"

    for tag, meta in sorted(status_data["languages"].items()):
        if tag in ("pt", "zh") or meta.get("reviewed") is True:
            continue
        resw_path = strings_dir / tag / "Resources.resw"
        if not resw_path.is_file():
            raise ValueError(f"missing {resw_path.relative_to(root)}")
        resw_root = ET.fromstring(resw_path.read_text(encoding="utf-8"))
        values = {
            el.attrib.get("name", ""): (el.findtext("value") or "")
            for el in resw_root.findall("data")
        }
        for key in APP_CRITICAL_KEYS:
            expected = en_arb[key]
            actual = values.get(key)
            if actual != expected:
                raise ValueError(
                    f"unauthorized unreviewed critical-key translation in {tag}:{key} "
                    f"(got {actual!r}, expected English {expected!r})"
                )


def _is_allowed_xaml_value(val: str) -> bool:
    if val.startswith(("{x:Bind ", "{StaticResource ", "{ThemeResource ")):
        return True
    return val in ALLOWLISTED_XAML_LITERALS


def check_zero_hardcoded_english_xaml(root: Path) -> None:
    checked_attrs = set(USER_VISIBLE_XAML_ATTRS) | set(A11Y_AND_TOOLTIP_XAML_ATTRS)
    for xaml in iter_app_files(root, "*.xaml"):
        rel = xaml.relative_to(root)
        el_root = ET.fromstring(xaml.read_text(encoding="utf-8"))
        for el in el_root.iter():
            tag = el.tag.split("}", 1)[-1]
            for attr_k, attr_v in el.attrib.items():
                local_attr = attr_k.split("}", 1)[-1]
                if local_attr not in checked_attrs:
                    continue
                val = attr_v.strip()
                if _is_allowed_xaml_value(val):
                    continue
                raise ValueError(
                    f"{rel}: hardcoded user-visible literal {local_attr}=\"{attr_v}\" (must bind via {{x:Bind}})"
                )

            # Check non-whitespace inner element text (excluding <x:String> path geometry constants)
            if el.tag != XAML_STRING_TAG:
                inner_txt = (el.text or "").strip()
                if inner_txt and not _is_allowed_xaml_value(inner_txt):
                    raise ValueError(
                        f"{rel}: hardcoded user-visible element text <{tag}>{inner_txt}</{tag}> (must bind via {{x:Bind}})"
                    )
                tail_txt = (el.tail or "").strip()
                if tail_txt and not _is_allowed_xaml_value(tail_txt):
                    raise ValueError(
                        f"{rel}: hardcoded user-visible inline text after <{tag}>: {tail_txt!r} (must bind via {{x:Bind}})"
                    )


def check_kose_motion_rtl_hc_a11y(root: Path) -> None:
    app_xaml_path = root / "ui-winui3-fluent2" / "App.xaml"
    app_xaml = app_xaml_path.read_text(encoding="utf-8")
    for token in (
        "#6D4AE0",
        "#F4F2FB",
        "#A68BFF",
        "#22184F",
        "M55 15H97V57A42 42 0 1 1 55 15Z",
        "M37 58 L50 71 L74 45",
        "HighContrast",
        "SystemColorHighlightColor",
        "SystemColorWindowColor",
        "SystemColorWindowTextColor",
    ):
        if token not in app_xaml:
            raise ValueError(f"ui-winui3-fluent2/App.xaml missing required Kose/HighContrast token {token!r}")

    # Check Kose Viewbox FlowDirection="LeftToRight", pivot (55, 57), 3.2s storyboard, Done StrokeThickness=9
    kose_pages = (
        "ui-winui3-fluent2/MainWindow.xaml",
        "ui-winui3-fluent2/Views/SendPage.xaml",
        "ui-winui3-fluent2/Views/ReceivePage.xaml",
    )
    for rel in kose_pages:
        raw = (root / rel).read_text(encoding="utf-8")
        tree = ET.fromstring(raw)
        parent_map = {child: parent for parent in tree.iter() for child in parent}

        kose_paths = 0
        done_checks = 0
        for el in tree.iter():
            tag = el.tag.split("}", 1)[-1]
            if tag == "Path":
                data_attr = el.attrib.get("Data", "")
                if data_attr == "M55 15H97V57A42 42 0 1 1 55 15Z":
                    kose_paths += 1
                    # Must have ancestor Viewbox with FlowDirection="LeftToRight"
                    cur = parent_map.get(el)
                    found_ltr_vb = False
                    while cur is not None:
                        ctag = cur.tag.split("}", 1)[-1]
                        if ctag == "Viewbox" and cur.attrib.get("FlowDirection") == "LeftToRight":
                            found_ltr_vb = True
                            break
                        cur = parent_map.get(cur)
                    if not found_ltr_vb:
                        raise ValueError(f"{rel}: Kose mark <Path> is missing ancestor <Viewbox FlowDirection=\"LeftToRight\">")
                elif data_attr == "M37 58 L50 71 L74 45":
                    done_checks += 1
                    if el.attrib.get("StrokeThickness") != "9":
                        raise ValueError(f"{rel}: Done checkmark StrokeThickness != '9'")
            elif tag == "RotateTransform":
                if el.attrib.get("CenterX") != "55" or el.attrib.get("CenterY") != "57":
                    raise ValueError(f"{rel}: RotateTransform pivot must be (55, 57), got ({el.attrib.get('CenterX')}, {el.attrib.get('CenterY')})")

        if kose_paths == 0:
            raise ValueError(f"{rel}: missing Kose mark <Path Data='M55 15H97V57A42 42 0 1 1 55 15Z'>")
        if done_checks == 0:
            raise ValueError(f"{rel}: missing Done checkmark <Path Data='M37 58 L50 71 L74 45'>")
        if "0:0:3.2" not in raw or (
            'ControlPoint1="0.65,0"' not in raw or 'ControlPoint2="0.35,1"' not in raw
        ):
            raise ValueError(
                f"{rel}: missing 3.2s Kose Storyboard with KeySpline ControlPoint1='0.65,0' ControlPoint2='0.35,1'"
            )

    # Reduced-motion UISettings.AnimationsEnabled & HighContrast SystemBackdrop = null in C#
    for rel in (
        "ui-winui3-fluent2/MainWindow.xaml.cs",
        "ui-winui3-fluent2/Views/SendPage.xaml.cs",
        "ui-winui3-fluent2/Views/ReceivePage.xaml.cs",
    ):
        text = (root / rel).read_text(encoding="utf-8")
        if "AnimationsEnabled" not in text:
            raise ValueError(f"{rel}: missing UISettings.AnimationsEnabled reduced-motion gate")
    mw_cs = strip_csharp_comments((root / "ui-winui3-fluent2" / "MainWindow.xaml.cs").read_text(encoding="utf-8"))
    if not re.search(r"if\s*\([^)]*HighContrast[^)]*\)\s*\{[^}]*SystemBackdrop\s*=\s*null\s*;", mw_cs, flags=re.DOTALL):
        raise ValueError("MainWindow.xaml.cs: missing HighContrast SystemBackdrop = null handling")

    # TransferCode & VerificationWords LTR + Language="en-US"
    send_tree = ET.fromstring((root / "ui-winui3-fluent2" / "Views" / "SendPage.xaml").read_text(encoding="utf-8"))
    recv_tree = ET.fromstring((root / "ui-winui3-fluent2" / "Views" / "ReceivePage.xaml").read_text(encoding="utf-8"))

    def _find_control(tree: ET.Element, target_xname: str, target_bind: str) -> ET.Element | None:
        for el in tree.iter():
            for k, v in el.attrib.items():
                if k.endswith("}Name") and v == target_xname:
                    return el
            text_attr = el.attrib.get("Text", "")
            if target_bind and target_bind in text_attr:
                return el
        return None

    for tree, page_name, ctrl_name, bind_hint in (
        (send_tree, "Views/SendPage.xaml", "TransferCodeTextBlock", "ViewModel.TransferCode"),
        (send_tree, "Views/SendPage.xaml", "VerificationWords", "ViewModel.VerificationWords"),
        (recv_tree, "Views/ReceivePage.xaml", "CodeInputBox", ""),
        (recv_tree, "Views/ReceivePage.xaml", "VerificationWords", "ViewModel.VerificationWords"),
    ):
        el = _find_control(tree, ctrl_name, bind_hint)
        if el is None:
            raise ValueError(f"{page_name}: missing expected control matching {ctrl_name}")
        if el.attrib.get("FlowDirection") != "LeftToRight":
            raise ValueError(f"{page_name}: {ctrl_name} missing FlowDirection='LeftToRight'")
        if el.attrib.get("Language") != "en-US":
            raise ValueError(f"{page_name}: {ctrl_name} missing Language='en-US'")

    # T1-F14-03: All interactive controls have non-empty AutomationProperties.Name,
    # and all TextBlocks enable TextWrapping="Wrap" and IsTextScaleFactorEnabled="True".
    for xaml in iter_app_files(root, "*.xaml"):
        rel = xaml.relative_to(root)
        el_root = ET.fromstring(xaml.read_text(encoding="utf-8"))
        for el in el_root.iter():
            tag = el.tag.split("}", 1)[-1]
            if tag in INTERACTIVE_XAML_TAGS:
                a11y_name = el.attrib.get("AutomationProperties.Name", "").strip()
                if not a11y_name:
                    xname = next((v for k, v in el.attrib.items() if k.endswith("}Name")), "<unnamed>")
                    raise ValueError(f"{rel}: interactive <{tag} x:Name='{xname}'> missing AutomationProperties.Name")
            elif tag == "TextBlock":
                if el.attrib.get("TextWrapping") != "Wrap":
                    raise ValueError(f"{rel}: <TextBlock> missing TextWrapping='Wrap'")
                if el.attrib.get("IsTextScaleFactorEnabled") != "True":
                    raise ValueError(f"{rel}: <TextBlock> missing IsTextScaleFactorEnabled='True'")


def check_m2_ui_page_audits(root: Path) -> None:
    """Static UI page contract audits used by T1-F10-05, T1-F11-05, and T1-F12-05."""
    send_cs = (root / "ui-winui3-fluent2" / "Views" / "SendPage.xaml.cs").read_text(encoding="utf-8")
    if r'"\\\\?\\"' in send_cs or r'@"\\?\"' in send_cs:
        raise ValueError("SendPage.xaml.cs contains forbidden naive '\\\\?\\' path concatenation")
    if "TryAddRawPaths" not in send_cs or "CancelTransferTitle" not in send_cs or "CancelTransferBody" not in send_cs:
        raise ValueError("SendPage.xaml.cs missing TryAddRawPaths or localized cancel confirmation dialog bindings")

    recv_xaml = (root / "ui-winui3-fluent2" / "Views" / "ReceivePage.xaml").read_text(encoding="utf-8")
    recv_cs = (root / "ui-winui3-fluent2" / "Views" / "ReceivePage.xaml.cs").read_text(encoding="utf-8")
    vm_cs = (root / "ui-winui3-fluent2" / "ViewModels" / "TransferViewModels.cs").read_text(encoding="utf-8")
    if "ReceiveCodeHint" not in recv_xaml or '"7-harbor-rocket"' not in vm_cs:
        raise ValueError("ReceivePage.xaml missing ReceiveCodeHint -> '7-harbor-rocket' binding chain")
    if "IsReceivedTextVisible" not in recv_cs or "VirtualKey.Escape" not in recv_cs:
        raise ValueError("ReceivePage.xaml.cs missing Escape suppression while IsReceivedTextVisible")
    if "ResolveDefaultDownloadsFolder" not in vm_cs:
        raise ValueError("TransferViewModels.cs missing ResolveDefaultDownloadsFolder (Downloads\\TotalDrop)")

    mw_cs = (root / "ui-winui3-fluent2" / "MainWindow.xaml.cs").read_text(encoding="utf-8")
    settings_xaml = (root / "ui-winui3-fluent2" / "Views" / "SettingsPage.xaml").read_text(encoding="utf-8")
    settings_cs = (root / "ui-winui3-fluent2" / "Views" / "SettingsPage.xaml.cs").read_text(encoding="utf-8")
    if "typeof(SettingsPage)" not in mw_cs or "IsSettingsSelected" not in mw_cs:
        raise ValueError("MainWindow.xaml.cs does not navigate NavigationView Settings to SettingsPage")
    for token in ("DraftTranslation", "SettingsWordsEnglish", "VersionLabel", "https://totaldrop.app"):
        if token not in settings_xaml:
            raise ValueError(f"SettingsPage.xaml missing required binding/link {token!r}")
    if "CanSaveServer" not in vm_cs or "HasUnsavedServerEdit" not in settings_cs:
        raise ValueError("SettingsPage missing CanSaveServer trim check or Escape revert on HasUnsavedServerEdit")


def _strip_py_comments_preserve_lines(src: str) -> str:
    """Strip Python `#` comments via stdlib tokenize (supporting PEP 701 f-strings) preserving exact line positions."""
    raw_lines = io.StringIO(src).readlines()
    if not raw_lines:
        return src
    comment_spans: dict[int, list[tuple[int, int]]] = {}
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.COMMENT:
                row, start_col = tok.start
                _end_row, end_col = tok.end
                comment_spans.setdefault(row, []).append((start_col, end_col))
    except (tokenize.TokenError, IndentationError):
        # Safe line-preserving fallback only when Python source fails tokenization.
        out: list[str] = []
        i = 0
        n = len(src)
        while i < n:
            ch = src[i]
            if ch in ("'", '"'):
                quote = src[i : i + 3] if src[i : i + 3] in ('"""', "'''") else ch
                out.append(quote)
                i += len(quote)
                while i < n:
                    if src[i] == "\\" and i + 1 < n:
                        out.append(src[i : i + 2])
                        i += 2
                        continue
                    if src[i : i + len(quote)] == quote:
                        out.append(quote)
                        i += len(quote)
                        break
                    out.append(src[i])
                    i += 1
                continue
            if ch == "#":
                while i < n and src[i] != "\n":
                    i += 1
                continue
            out.append(ch)
            i += 1
        return "".join(out)

    for row, spans in comment_spans.items():
        if 1 <= row <= len(raw_lines):
            line = raw_lines[row - 1]
            for start_col, end_col in sorted(spans, reverse=True):
                line = line[:start_col] + line[end_col:]
            raw_lines[row - 1] = line
    return "".join(raw_lines)


def _strip_comments_preserve_lines(src: str, suffix: str) -> str:
    """Strip comments while preserving string literals and exact 1:1 line numbering."""
    if suffix == ".ps1":
        return _strip_ps1_comments_preserve_lines(src)

    if suffix == ".py":
        return _strip_py_comments_preserve_lines(src)

    if suffix == ".cs":
        return strip_csharp_comments(src)

    # Rust (.rs): preserve string & char/byte-char literals (incl. raw strings) and 1:1 line numbering.
    out = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            i += 2
            while i < n and src[i] != "\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            depth = 1
            i += 2
            while i < n and depth > 0:
                if src[i : i + 2] == "/*":
                    depth += 1
                    i += 2
                elif src[i : i + 2] == "*/":
                    depth -= 1
                    i += 2
                else:
                    if src[i] == "\n":
                        out.append("\n")
                    i += 1
            out.append(" ")
            continue
        if (ch == "r" or (ch in ("b", "c") and nxt == "r")) and (
            i == 0 or not (src[i - 1].isalnum() or src[i - 1] == "_")
        ):
            start = i + 2 if ch in ("b", "c") else i + 1
            j = start
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                end_marker = '"' + ("#" * hashes)
                end_pos = src.find(end_marker, j + 1)
                if end_pos == -1:
                    out.append(src[i:])
                    break
                out.append(src[i : end_pos + len(end_marker)])
                i = end_pos + len(end_marker)
                continue
        if ch in ("'", "b"):
            char_end = _match_rust_char_literal(src, i)
            if char_end != -1:
                out.append(src[i:char_end])
                i = char_end
                continue
        if ch == '"':
            out.append('"')
            i += 1
            while i < n:
                if src[i] == "\\" and i + 1 < n:
                    out.append(src[i : i + 2])
                    i += 2
                    continue
                out.append(src[i])
                if src[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _compute_function_blocks(lines: list[str], suffix: str) -> list[tuple[int, int]]:
    """Return 1-indexed (start_line, end_line) spans approximating enclosing functions/tests."""
    if suffix == ".rs":
        hdr = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+[A-Za-z_]\w*\b")
    elif suffix == ".py":
        hdr = re.compile(r"^\s*(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(")
    elif suffix == ".cs":
        hdr = re.compile(
            r"^\s*(?:public|private|internal|protected)\s+(?:static\s+)?(?:async\s+)?[A-Za-z_][\w<>?\[\],\s]*\s+[A-Za-z_]\w*\s*\("
        )
    elif suffix == ".ps1":
        hdr = re.compile(r"^\s*function\s+[A-Za-z_][\w-]*\b", flags=re.IGNORECASE)
    else:
        return []

    starts: list[int] = [i for i, line in enumerate(lines, start=1) if hdr.search(line)]
    if not starts:
        return []
    blocks: list[tuple[int, int]] = []
    for idx, st in enumerate(starts):
        end = (starts[idx + 1] - 1) if idx + 1 < len(starts) else len(lines)
        blocks.append((st, end))
    return blocks


def _extract_balanced_spans(text: str, open_pattern: str) -> list[tuple[int, str]]:
    """Extract multi-line balanced (...) or {...} spans matching open_pattern."""
    spans: list[tuple[int, str]] = []
    for m in re.finditer(open_pattern, text):
        open_ch = text[m.end() - 1]
        close_ch = ")" if open_ch == "(" else "}"
        depth = 1
        pos = m.end()
        in_sq = False
        in_dq = False
        while pos < len(text) and depth > 0:
            c = text[pos]
            if (in_sq or in_dq) and c == "\\" and pos + 1 < len(text):
                pos += 2
                continue
            if c == "'" and not in_dq:
                in_sq = not in_sq
            elif c == '"' and not in_sq:
                in_dq = not in_dq
            elif not in_sq and not in_dq:
                if c == open_ch:
                    depth += 1
                elif c == close_ch:
                    depth -= 1
            pos += 1
        line_no = text.count("\n", 0, m.start()) + 1
        spans.append((line_no, text[m.start() : pos]))
    return spans


def scan_no_live_production_probing(root: Path) -> list[str]:
    """Static anti-production-probing scanner (TEST_INFRA.md section 3.3)."""
    forbidden_hosts = (
        "rendezvous.totaldrop.app",
        "relay.totaldrop.app",
        "stun.cloudflare.com",
        "totaldrop.app",
    )
    raw_network_api_patterns = (
        r"\bTcpStream::connect(?:_timeout)?\s*\(",
        r"\bUdpSocket::connect\s*\(",
        r"\bconnect_async\s*\(",
        r"\bsocket\.create_connection\s*\(",
        r"\.[Cc]onnect(?:Async)?\s*\((?!\s*\d*\s*\))",
        r"\bHTTPS?Connection\s*\(",
        r"\burlopen\s*\(",
        r"\brequests\.(?:get|post|put|head|request)\s*\(",
        r"\bhttpx\.",
        r"\bwebsockets\.connect\s*\(",
        r"\breqwest::",
        r"\bHttpClient\b",
        r"\bClientWebSocket\b",
        r"\bTcpClient\b",
        r"\bInvoke-WebRequest\b",
        r"\bInvoke-RestMethod\b",
        r"\bcurl\b",
    )
    session_start_api_patterns = (
        r"\btotaldrop_win_(?:send_files|send_text|receive_connect)_start\b",
        r"\bStart(?:SendFiles|SendText|ReceiveConnect)\b",
        r"\bstart_(?:send_files|send_text|receive_connect)\s*\(",
    )
    raw_net_re = re.compile("|".join(raw_network_api_patterns))
    all_live_re = re.compile("|".join(raw_network_api_patterns + session_start_api_patterns))
    offline_context_re = re.compile(
        r"\b(?:(?:totaldrop_win_)?(?:validate_server_url|validate_uri|validate_input|extract_clipboard_code)(?:_json)?|"
        r"TryValidateServerUrl|TrySaveServerUrl|"
        r"DefaultRendezvousServer|DefaultRelayServer|DefaultStunServer)\b|Assert\.Equal\s*\("
    )
    userinfo_spoof_re = re.compile(r"wss?://[^\s\"']*@[^\s\"']*totaldrop\.app", flags=re.IGNORECASE)
    invalid_space_url_re = re.compile(r"wss?://[^\s\"']*totaldrop\.app\s+/bad", flags=re.IGNORECASE)
    config_kv_re = re.compile(
        r'(?:\\?["\']?(?:rendezvous_server|relay_server|stun_server|'
        r'RendezvousServer|RelayServer|StunServer)\\?["\']?\s*[:=]\s*)'
        r'(?:r#*)?\\?["\']([^"\'\\]+)\\?["\']'
    )

    def _first_forbidden_host(snippet: str) -> str | None:
        low = snippet.lower()
        for h in forbidden_hosts:
            if h in low:
                return h
        return None

    def _is_share_or_privacy_only(line: str) -> bool:
        low = line.lower()
        if any(h in low for h in ("rendezvous.totaldrop.app", "relay.totaldrop.app", "stun.cloudflare.com")):
            return False
        stripped = re.sub(r"https://totaldrop\.app/(?:r#|privacy/)", "", low)
        return "totaldrop.app" not in stripped

    scan_dirs: list[Path] = [
        root / "tests",
        root / "tools" / "e2e",
        root / "ui-winui3-fluent2" / "TotalDrop.WinUI.Tests",
    ]
    crates_dir = root / "crates"
    if crates_dir.is_dir():
        for tdir in sorted(crates_dir.glob("*/tests")):
            if tdir.is_dir():
                scan_dirs.append(tdir)

    seen_paths: set[Path] = set()
    scan_paths: list[Path] = []
    for base in scan_dirs:
        if base.is_dir():
            for p in sorted(base.rglob("*")):
                if (
                    p.is_file()
                    and p.suffix in {".rs", ".py", ".ps1", ".cs"}
                    and not _is_excluded_scan_path(p)
                    and p not in seen_paths
                ):
                    seen_paths.add(p)
                    scan_paths.append(p)

    violations: list[str] = []
    seen_violations: set[str] = set()

    def _add_violation(msg: str) -> None:
        if msg not in seen_violations:
            seen_violations.add(msg)
            violations.append(msg)

    for p in scan_paths:
        rel = p.relative_to(root)
        # Skip this scanner's own pattern table
        if rel == Path("tools/e2e/verify_static_contracts.py"):
            continue
        raw_text = p.read_text(encoding="utf-8", errors="replace")
        code_text = _strip_comments_preserve_lines(raw_text, p.suffix)
        lines = code_text.splitlines()
        blocks = _compute_function_blocks(lines, p.suffix)

        def _enclosing_range(line_no: int) -> tuple[int, int]:
            lo = max(1, line_no - 20)
            hi = min(len(lines), line_no + 20)
            for b_start, b_end in blocks:
                if b_start <= line_no <= b_end:
                    lo = min(lo, b_start)
                    hi = max(hi, b_end)
                    break
            return lo, hi

        def _enclosing_block_only(line_no: int) -> tuple[int, int]:
            for b_start, b_end in blocks:
                if b_start <= line_no <= b_end:
                    return b_start, b_end
            # E9: top-level declarations outside any function block must never bleed into
            # an adjacent offline decoy function's context window.
            return line_no, line_no

        file_has_live_api = any(all_live_re.search(ln) for ln in lines)

        # Rule 2a: Multi-line BridgeNetworkConfig / BridgeNetworkConfigDto / make_cfg_json literals
        for cfg_pat in (
            r"\bBridgeNetworkConfig(?:Dto)?\s*[\(\{]",
            r"\bBridgeNetworkConfig(?:Dto)?\s+\w+\s*=\s*new\s*\(",
            r"\bmake_cfg_json\s*\(",
        ):
            for span_line, span_text in _extract_balanced_spans(code_text, cfg_pat):
                if userinfo_spoof_re.search(span_text) or invalid_space_url_re.search(span_text):
                    continue
                host = _first_forbidden_host(span_text)
                if host is not None and not _is_share_or_privacy_only(span_text):
                    _add_violation(
                        f"{rel}:{span_line}: forbidden production host {host!r} inside network config literal"
                    )

        # Rule 2b: JSON / dict / struct / named-arg assignments to rendezvous_server / relay_server / stun_server
        for m_kv in config_kv_re.finditer(code_text):
            val = m_kv.group(1)
            if userinfo_spoof_re.search(val) or invalid_space_url_re.search(val):
                continue
            host = _first_forbidden_host(val)
            if host is None:
                continue
            kv_line = code_text.count("\n", 0, m_kv.start()) + 1
            b_lo, b_hi = _enclosing_block_only(kv_line)
            block_text = "\n".join(lines[b_lo - 1 : b_hi])
            block_has_live = bool(all_live_re.search(block_text))
            is_strict_offline_settings = (
                rel.name == "SettingsStoreTests.cs"
                or bool(offline_context_re.search(lines[kv_line - 1]))
            ) and not block_has_live and not file_has_live_api
            if not is_strict_offline_settings:
                _add_violation(
                    f"{rel}:{kv_line}: forbidden production host {host!r} assigned in network config field: "
                    f"{lines[kv_line - 1].strip()}"
                )

        # Rule 3: Line-by-line, +-20 line window, and enclosing function-block API correlation
        for line_no, line in enumerate(lines, start=1):
            host = _first_forbidden_host(line)
            if host is None:
                continue

            lo, hi = _enclosing_range(line_no)
            b_lo, b_hi = _enclosing_block_only(line_no)
            block_text = "\n".join(lines[b_lo - 1 : b_hi])

            # Check unconditional Cloudflare STUN prohibition
            if host == "stun.cloudflare.com":
                block_has_live = bool(all_live_re.search(block_text))
                if (
                    ("DefaultStunServer" not in line and "Assert.Equal" not in line)
                    or block_has_live
                ):
                    _add_violation(
                        f"{rel}:{line_no}: forbidden live STUN host 'stun.cloudflare.com': {line.strip()}"
                    )
                    continue

            is_share_only = _is_share_or_privacy_only(line)
            is_malformed_test = bool(userinfo_spoof_re.search(line) or invalid_space_url_re.search(line))

            # Even share-link or malformed URL lines must never sit next to raw HTTP/socket connect APIs
            if is_share_only or is_malformed_test:
                for api_line in range(lo, hi + 1):
                    m_api = raw_net_re.search(lines[api_line - 1])
                    if m_api:
                        _add_violation(
                            f"{rel}:{line_no}: forbidden live network API {m_api.group(0)!r} (line {api_line}) "
                            f"near production host {host!r}: {line.strip()}"
                        )
                        break
                continue

            # Regular production host literal: forbid ANY network or session-start API in window or block
            matched_api: tuple[int, str] | None = None
            for api_line in range(lo, hi + 1):
                m_api = all_live_re.search(lines[api_line - 1])
                if m_api:
                    matched_api = (api_line, m_api.group(0))
                    break
            if matched_api is not None:
                api_ln, api_tok = matched_api
                _add_violation(
                    f"{rel}:{line_no}: forbidden live network/session API {api_tok!r} (line {api_ln}) "
                    f"targeting production host {host!r}: {line.strip()}"
                )
                continue

            # Also flag file-level indirection (e.g. top-level constant used by live API elsewhere in file)
            # unless the host appears strictly inside an explicit offline validation/assertion context.
            if file_has_live_api and not offline_context_re.search(block_text):
                _add_violation(
                    f"{rel}:{line_no}: production host {host!r} in file containing live network/session APIs "
                    f"outside explicit offline validation: {line.strip()}"
                )

    return violations


def _is_excluded_scan_path(p: Path) -> bool:
    return bool(set(p.parts) & {"bin", "obj", "__pycache__", ".git", "target"})


# ---------------------------------------------------------------------------
# M3 & M4 Invariant Checks


def _local_tag(el: ET.Element) -> str:
    return el.tag.split("}", 1)[-1]


def check_m3_explorer_com_manifest(root: Path) -> None:
    """T1-F16-03 part-b: COM SurrogateServer (STA, bare GUIDs) & Explorer context menus (*, Directory)."""
    for rel in (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    ):
        m_root = ET.fromstring((root / rel).read_text(encoding="utf-8"))
        surrogates = [el for el in m_root.iter() if _local_tag(el) == "SurrogateServer"]
        if len(surrogates) != 1:
            raise ValueError(f"{rel}: expected exactly 1 <com:SurrogateServer>, found {len(surrogates)}")
        surr_classes = [el for el in surrogates[0] if _local_tag(el) == "Class"]
        if len(surr_classes) != 1:
            raise ValueError(f"{rel}: expected exactly 1 <com:Class> under SurrogateServer, found {len(surr_classes)}")
        cls = surr_classes[0]
        cls_id = cls.attrib.get("Id", "")
        if not BARE_UUID_RE.fullmatch(cls_id) or cls_id.upper() != CANONICAL_CLSID:
            raise ValueError(f"{rel}: SurrogateServer com:Class Id={cls_id!r} != bare {CANONICAL_CLSID}")
        if cls.attrib.get("Path") != "totaldrop_explorer_ext.dll":
            raise ValueError(f"{rel}: SurrogateServer com:Class Path={cls.attrib.get('Path')!r} != 'totaldrop_explorer_ext.dll'")
        if cls.attrib.get("ThreadingModel") != "STA":
            raise ValueError(
                f"{rel}: SurrogateServer com:Class ThreadingModel={cls.attrib.get('ThreadingModel')!r} != 'STA' (MSIX XSD)"
            )

        menus = [el for el in m_root.iter() if _local_tag(el) == "FileExplorerContextMenus"]
        if len(menus) != 1:
            raise ValueError(f"{rel}: expected exactly 1 <desktop4:FileExplorerContextMenus>, found {len(menus)}")
        item_types: dict[str, list[tuple[str, str]]] = {}
        for item in menus[0]:
            if _local_tag(item) == "ItemType":
                t = item.attrib.get("Type", "")
                verbs = [
                    (v.attrib.get("Id", ""), v.attrib.get("Clsid", ""))
                    for v in item
                    if _local_tag(v) == "Verb"
                ]
                item_types[t] = verbs
        for req_type, req_verb in (("*", "TotalDropSendFiles"), ("Directory", "TotalDropSendFolder")):
            if req_type not in item_types:
                raise ValueError(f"{rel}: FileExplorerContextMenus missing ItemType={req_type!r}")
            matched = [
                clsid for vid, clsid in item_types[req_type]
                if vid == req_verb and BARE_UUID_RE.fullmatch(clsid) and clsid.upper() == CANONICAL_CLSID
            ]
            if len(matched) != 1:
                raise ValueError(
                    f"{rel}: ItemType={req_type!r} missing expected Verb Id={req_verb!r} bare Clsid={CANONICAL_CLSID}"
                )


def check_m3_named_pipe_ipc_app(root: Path) -> None:
    """T1-F17-03: Zero C# JSON parsing of Named Pipe frames in App.xaml.cs; PipeOptions.CurrentUserOnly."""
    app_cs_path = root / "ui-winui3-fluent2" / "App.xaml.cs"
    cleaned = strip_csharp_comments(app_cs_path.read_text(encoding="utf-8"))
    for forbidden_pat, tok in (
        (r"\bSystem\.Text\.Json\b", "System.Text.Json"),
        (r"\bJsonSerializer\b", "JsonSerializer"),
        (r"\bActivationEnvelopeDto\b", "ActivationEnvelopeDto"),
    ):
        if re.search(forbidden_pat, cleaned):
            raise ValueError(f"ui-winui3-fluent2/App.xaml.cs: forbidden C# IPC JSON construct {tok} found")
    if "PipeOptions.CurrentUserOnly" not in cleaned:
        raise ValueError("ui-winui3-fluent2/App.xaml.cs: missing PipeOptions.CurrentUserOnly on NamedPipeServerStream")
    if r"LOCAL\app.totaldrop.TotalDrop.v1." not in cleaned:
        raise ValueError("ui-winui3-fluent2/App.xaml.cs: missing LOCAL\\app.totaldrop.TotalDrop.v1.<SessionId> pipe prefix")
    if "TryIngestNamedPipeChunk" not in cleaned:
        raise ValueError("ui-winui3-fluent2/App.xaml.cs: Named Pipe listener does not delegate raw bytes to Rust router")

    mw_cs = strip_csharp_comments((root / "ui-winui3-fluent2" / "MainWindow.xaml.cs").read_text(encoding="utf-8"))
    if "TryIngestRouterIpcBytes" not in mw_cs:
        raise ValueError("ui-winui3-fluent2/MainWindow.xaml.cs: missing NativeBridge.TryIngestRouterIpcBytes delegation")


def check_m3_protocol_and_share_manifest(root: Path) -> None:
    """T1-F18-01 part-b & T2-F18-03 part-b: protocol/shareTarget XML & ReportCompleted() in finally."""
    for rel in (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    ):
        m_root = ET.fromstring((root / rel).read_text(encoding="utf-8"))
        protocols = [el.attrib.get("Name", "") for el in m_root.iter() if _local_tag(el) == "Protocol"]
        if "totaldrop" not in protocols:
            raise ValueError(f"{rel}: missing <uap:Protocol Name='totaldrop'>")
        share_targets = [el for el in m_root.iter() if _local_tag(el) == "ShareTarget"]
        if len(share_targets) != 1:
            raise ValueError(f"{rel}: expected exactly 1 <uap:ShareTarget>, found {len(share_targets)}")
        st = share_targets[0]
        if not any(_local_tag(el) == "SupportsAnyFileType" for el in st.iter()):
            raise ValueError(f"{rel}: <uap:ShareTarget> missing <uap:SupportsAnyFileType />")
        formats = {(el.text or "").strip() for el in st.iter() if _local_tag(el) == "DataFormat"}
        missing_fmts = sorted({"Text", "WebLink", "StorageItems"} - formats)
        if missing_fmts:
            raise ValueError(f"{rel}: <uap:ShareTarget> missing DataFormat(s): {missing_fmts}")

    router_cs = strip_csharp_comments((root / "ui-winui3-fluent2" / "Services" / "ShareTargetRouter.cs").read_text(encoding="utf-8"))
    if not re.search(r"finally\s*\{\s*FinishLifecycle\s*\(", router_cs, flags=re.DOTALL):
        raise ValueError("Services/ShareTargetRouter.cs: missing guaranteed finally { FinishLifecycle(...) }")
    if "lifecycle.ReportCompleted();" not in router_cs:
        raise ValueError("Services/ShareTargetRouter.cs: FinishLifecycle does not invoke lifecycle.ReportCompleted()")
    app_cs = strip_csharp_comments((root / "ui-winui3-fluent2" / "App.xaml.cs").read_text(encoding="utf-8"))
    if "shareOperation.ReportCompleted()" not in app_cs:
        raise ValueError("App.xaml.cs: missing shareOperation.ReportCompleted() adapter")


def check_m3_toast_activation(root: Path) -> None:
    """T1-F19-01, T1-F19-04 part-b, T2-F19-05, T3-12 part-b: Toast CLSID, ExeServer & foreground switch."""
    for rel in (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    ):
        m_root = ET.fromstring((root / rel).read_text(encoding="utf-8"))
        toasts = [el for el in m_root.iter() if _local_tag(el) == "ToastNotificationActivation"]
        if len(toasts) != 1:
            raise ValueError(f"{rel}: expected exactly 1 <desktop:ToastNotificationActivation>, found {len(toasts)}")
        toast_clsid = toasts[0].attrib.get("ToastActivatorCLSID", "")
        if not BARE_UUID_RE.fullmatch(toast_clsid):
            raise ValueError(f"{rel}: malformed ToastActivatorCLSID {toast_clsid!r} (expected bare GUID)")
        if toast_clsid.upper() == CANONICAL_CLSID:
            raise ValueError(
                f"{rel}: ToastActivatorCLSID collision with Explorer COM CLSID ({CANONICAL_CLSID})"
            )

        exe_servers = [el for el in m_root.iter() if _local_tag(el) == "ExeServer"]
        matched_servers = [
            es for es in exe_servers
            if es.attrib.get("Executable") == "totaldrop-winui.exe"
            and es.attrib.get("Arguments") == "----AppNotificationActivated:"
        ]
        if len(matched_servers) != 1:
            raise ValueError(
                f"{rel}: missing <com:ExeServer Executable='totaldrop-winui.exe' Arguments='----AppNotificationActivated:'>"
            )
        exe_class_ids = [
            c.attrib.get("Id", "") for c in matched_servers[0] if _local_tag(c) == "Class"
        ]
        if len(exe_class_ids) != 1 or not BARE_UUID_RE.fullmatch(exe_class_ids[0]):
            raise ValueError(f"{rel}: com:ExeServer missing single bare GUID <com:Class Id=...>")
        if exe_class_ids[0].upper() != toast_clsid.upper():
            raise ValueError(
                f"{rel}: ToastActivatorCLSID ({toast_clsid}) != com:ExeServer/com:Class/@Id ({exe_class_ids[0]}) mismatch"
            )

    app_cs = strip_csharp_comments((root / "ui-winui3-fluent2" / "App.xaml.cs").read_text(encoding="utf-8"))
    if "ExtendedActivationKind.AppNotification" not in app_cs:
        raise ValueError("App.xaml.cs: missing ExtendedActivationKind.AppNotification foreground handler")
    if not re.search(
        r'"----AppNotificationActivated:".*?BringToForeground\s*\(\s*\)\s*;\s*return\s*;',
        app_cs,
        flags=re.DOTALL,
    ):
        raise ValueError(
            "App.xaml.cs: ----AppNotificationActivated: switch must call BringToForeground() and return before file validation"
        )
    mw_cs = strip_csharp_comments((root / "ui-winui3-fluent2" / "MainWindow.xaml.cs").read_text(encoding="utf-8"))
    if "----AppNotificationActivated:" not in mw_cs:
        raise ValueError("MainWindow.xaml.cs: missing ----AppNotificationActivated: foreground-only guard")


def check_m3_firewall_and_app_manifest(root: Path) -> None:
    """T1-F21-01, T1-F21-02, T2-F21-04: Scoped Private inbound UDP FirewallRules, runFullTrust & app.manifest."""
    for rel in (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    ):
        m_root = ET.fromstring((root / rel).read_text(encoding="utf-8"))
        # Must declare <rescap:Capability Name="runFullTrust" />
        has_rft = any(
            _local_tag(el) == "Capability" and el.attrib.get("Name") == "runFullTrust"
            for el in m_root.iter()
        )
        if not has_rft:
            raise ValueError(f"{rel}: missing <rescap:Capability Name='runFullTrust' />")

        apps = [el for el in m_root.iter() if _local_tag(el) == "Application"]
        app_exes = {a.attrib.get("Executable", "") for a in apps}
        if "totaldrop-winui.exe" not in app_exes:
            raise ValueError(f"{rel}: missing <Application Executable='totaldrop-winui.exe'>")

        # Package-level <Extensions>/<desktop2:Extension Category="windows.firewallRules">
        pkg_exts = [el for el in m_root if _local_tag(el) == "Extensions"]
        fw_containers = [
            el for ext_blk in pkg_exts for el in ext_blk.iter() if _local_tag(el) == "FirewallRules"
        ]
        if len(fw_containers) != 1:
            raise ValueError(f"{rel}: expected exactly 1 Package-level <desktop2:FirewallRules>, found {len(fw_containers)}")
        fw = fw_containers[0]
        fw_exe = fw.attrib.get("Executable", "")
        if fw_exe != "totaldrop-winui.exe" or fw_exe not in app_exes:
            raise ValueError(
                f"{rel}: over-scoped or mismatched FirewallRules Executable={fw_exe!r} (expected 'totaldrop-winui.exe')"
            )
        rules = [el for el in fw if _local_tag(el) == "Rule"]
        if len(rules) != 1:
            raise ValueError(f"{rel}: expected exactly 1 <desktop2:Rule>, found {len(rules)}")
        rule = rules[0]
        direction = rule.attrib.get("Direction", "")
        proto = rule.attrib.get("IPProtocol", "")
        profile = rule.attrib.get("Profile", "")
        if direction != "in":
            raise ValueError(f"{rel}: over-scoped FirewallRules Direction={direction!r} (expected 'in')")
        if proto != "UDP":
            raise ValueError(f"{rel}: over-scoped FirewallRules IPProtocol={proto!r} (expected 'UDP')")
        if profile != "private":
            raise ValueError(f"{rel}: over-scoped FirewallRules Profile={profile!r} (expected 'private')")

    # T1-F21-02: ui-winui3-fluent2/app.manifest Win32 assembly settings
    am_path = root / "ui-winui3-fluent2" / "app.manifest"
    am_root = ET.fromstring(am_path.read_text(encoding="utf-8"))
    lpa = next(((el.text or "").strip() for el in am_root.iter() if _local_tag(el) == "longPathAware"), "")
    dpia = next(((el.text or "").strip() for el in am_root.iter() if _local_tag(el) == "dpiAwareness"), "")
    dpia_legacy = next(((el.text or "").strip() for el in am_root.iter() if _local_tag(el) == "dpiAware"), "")
    supported_os = {el.attrib.get("Id", "").lower() for el in am_root.iter() if _local_tag(el) == "supportedOS"}
    if lpa != "true":
        raise ValueError(f"ui-winui3-fluent2/app.manifest: <longPathAware>={lpa!r} != 'true'")
    if dpia != "PerMonitorV2":
        raise ValueError(f"ui-winui3-fluent2/app.manifest: <dpiAwareness>={dpia!r} != 'PerMonitorV2'")
    if dpia_legacy != "true/PM":
        raise ValueError(f"ui-winui3-fluent2/app.manifest: <dpiAware>={dpia_legacy!r} != 'true/PM'")
    if "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" not in supported_os:
        raise ValueError("ui-winui3-fluent2/app.manifest: missing Windows 10/11 supportedOS GUID")


def _extract_yaml_top_block(text: str, key: str) -> str:
    """Extract a top-level YAML block (0-indent key) using pure stdlib."""
    lines = text.splitlines()
    out: list[str] = []
    in_blk = False
    for line in lines:
        if not in_blk:
            if re.match(rf"^{re.escape(key)}:\s*(?:#.*)?$", line) or re.match(rf"^{re.escape(key)}:\s+\S", line):
                in_blk = True
                out.append(line)
            continue
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        out.append(line)
    return "\n".join(out)


def _check_no_raw_inputs_in_yaml_run(text: str, rel_label: str) -> None:
    """Verify zero raw ${{ inputs.* }} interpolation inside YAML run: blocks."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r"^(\s*)(?:-\s*)?run:\s*(.*)$", line)
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        rest = m.group(2).strip()
        if rest and not rest.startswith(("|", ">")):
            if re.search(r"\$\{\{\s*inputs\.", rest):
                raise ValueError(f"{rel_label}:{i + 1}: unsafe raw ${{{{ inputs.* }}}} inside run:")
            i += 1
            continue
        i += 1
        while i < len(lines):
            sub = lines[i]
            if sub.strip() and (len(sub) - len(sub.lstrip(" "))) <= indent:
                break
            if re.search(r"\$\{\{\s*inputs\.", sub):
                raise ValueError(f"{rel_label}:{i + 1}: unsafe raw ${{{{ inputs.* }}}} inside run: block")
            i += 1


def check_m4_release_and_arm64_workflows(root: Path) -> None:
    """T1-F22-04 & M4 CI gates: windows-release.yml, ci.yml ARM64 gate, pkg-msix-arm64.yml."""
    wf_dir = root / ".github" / "workflows"

    # 1. ci.yml ARM64 job wired into aggregate gate
    ci_text = (wf_dir / "ci.yml").read_text(encoding="utf-8")
    ci_jobs = _parse_ci_jobs(ci_text)
    if "windows-arm64-msix" not in ci_jobs:
        raise ValueError(".github/workflows/ci.yml missing job 'windows-arm64-msix'")
    arm_job = ci_jobs["windows-arm64-msix"]
    if not re.search(r"runs-on:\s*windows-11-arm\b", arm_job):
        raise ValueError("ci.yml windows-arm64-msix must run on windows-11-arm")
    if not re.search(r'dotnet-version:\s*["\']?10\.0\.x["\']?', arm_job):
        raise ValueError("ci.yml windows-arm64-msix must pin .NET 10 (dotnet-version: 10.0.x)")
    if "rustup" not in arm_job or "if-no-files-found: error" not in arm_job:
        raise ValueError("ci.yml windows-arm64-msix must verify rustup and set if-no-files-found: error")
    if "windows-arm64-msix" not in ci_jobs.get("gate", ""):
        raise ValueError("ci.yml jobs.gate.needs is missing 'windows-arm64-msix'")

    # 2. pkg-msix-arm64.yml has zero PR skip guards
    pkg_arm_text = (wf_dir / "pkg-msix-arm64.yml").read_text(encoding="utf-8")
    if re.search(r"github\.event_name\s*!=\s*['\"]pull_request['\"]", pkg_arm_text):
        raise ValueError("pkg-msix-arm64.yml contains forbidden pull_request skip guard")

    # 3. windows-release.yml contract (T1-F22-04)
    rel_wf_path = wf_dir / "windows-release.yml"
    if not rel_wf_path.is_file():
        raise ValueError("missing .github/workflows/windows-release.yml")
    rel_text = rel_wf_path.read_text(encoding="utf-8")

    # 40-hex SHA pinning on every uses:
    for line_no, line in enumerate(rel_text.splitlines(), start=1):
        stripped = line.split("#", 1)[0].strip()
        m = re.match(r"^(?:-\s*)?uses:\s*([^\s]+)$", stripped)
        if m:
            ref = m.group(1).strip("'\"")
            if not ref.startswith("./") and not re.search(r"@[0-9a-f]{40}$", ref):
                raise ValueError(
                    f".github/workflows/windows-release.yml:{line_no}: unpinned mutable action ref {ref!r}"
                )

    on_blk = _extract_yaml_top_block(rel_text, "on")
    if "windows-v*" not in on_blk or "workflow_dispatch" not in on_blk:
        raise ValueError("windows-release.yml must trigger on push tags 'windows-v*' and 'workflow_dispatch'")
    if re.search(r"^\s+branches:", on_blk, flags=re.MULTILINE):
        raise ValueError("windows-release.yml must trigger only on 'windows-v*' tags (not push branches)")

    perm_blk = _extract_yaml_top_block(rel_text, "permissions")
    if re.search(r"\b(write-all|contents:\s*write|id-token:\s*write|attestations:\s*write)\b", perm_blk):
        raise ValueError(f"windows-release.yml top-level permissions overly broad: {perm_blk!r}")
    if not perm_blk or "contents: read" not in perm_blk:
        raise ValueError("windows-release.yml missing least-privilege top-level 'permissions: contents: read'")

    env_blk = _extract_yaml_top_block(rel_text, "env")
    if "SOURCE_DATE_EPOCH" not in env_blk:
        raise ValueError("windows-release.yml missing top-level SOURCE_DATE_EPOCH")

    _check_no_raw_inputs_in_yaml_run(rel_text, ".github/workflows/windows-release.yml")

    rel_jobs = _parse_ci_jobs(rel_text)
    for req_job in ("preflight", "build-x64", "build-arm64", "bundle-and-attest"):
        if req_job not in rel_jobs:
            raise ValueError(f"windows-release.yml missing required job {req_job!r}")

    preflight = rel_jobs["preflight"]
    if "git merge-base --is-ancestor" not in preflight or "origin/main" not in preflight:
        raise ValueError("windows-release.yml preflight missing 'git merge-base --is-ancestor ... origin/main' guard")
    if "tools/check-versions.py --store --require-store-identity" not in preflight:
        raise ValueError("windows-release.yml preflight missing Store identity/version check")

    if not re.search(r"runs-on:\s*(windows-latest|windows-2025)\b", rel_jobs["build-x64"]):
        raise ValueError("windows-release.yml build-x64 must run on windows-latest or windows-2025")
    if not re.search(r"runs-on:\s*windows-11-arm\b", rel_jobs["build-arm64"]):
        raise ValueError("windows-release.yml build-arm64 must run on windows-11-arm")

    bundle_job = rel_jobs["bundle-and-attest"]
    if "id-token: write" not in bundle_job or "attestations: write" not in bundle_job:
        raise ValueError("windows-release.yml bundle-and-attest missing job-scoped id-token: write & attestations: write")
    if not re.search(r"actions/attest-build-provenance@[0-9a-f]{40}", bundle_job):
        raise ValueError("windows-release.yml bundle-and-attest missing SHA-pinned actions/attest-build-provenance")
    if "SHA256SUMS" not in bundle_job or ".msixupload" not in bundle_job or "dist/store/" not in bundle_job:
        raise ValueError("windows-release.yml bundle-and-attest missing SHA256SUMS / .msixupload / dist/store/ upload")
    if "if-no-files-found: error" not in bundle_job:
        raise ValueError("windows-release.yml bundle-and-attest upload missing if-no-files-found: error")


def self_test_prod_scanner() -> None:
    """Self-test E9, E10a, and E10b anti-production-probing hardening on isolated temp fixtures."""
    with tempfile.TemporaryDirectory(prefix="td-e9-e10-selftest-") as tmp:
        root = Path(tmp)
        tests_dir = root / "tests"
        tests_dir.mkdir()

        # E9: top-level const outside any function block next to offline decoy fn + live call 30 lines below
        filler = "\n".join(f"    let _pad_{i} = {i};" for i in range(30))
        (tests_dir / "e9_evasion.rs").write_text(
            'const PROD_RELAY: &str = "wss://relay.totaldrop.app/v0/relay";\n'
            "\n"
            "fn decoy_offline() {\n"
            '    let _ = totaldrop_win_validate_server_url_json("wss://example.test");\n'
            "}\n"
            "\n"
            "fn live_caller() {\n"
            f"{filler}\n"
            "    let _ = totaldrop_win_receive_connect_start(PROD_RELAY);\n"
            "}\n",
            encoding="utf-8",
        )
        v_e9 = scan_no_live_production_probing(root)
        if not any("e9_evasion.rs" in v for v in v_e9):
            raise AssertionError(f"E9 top-level const evasion was NOT caught: {v_e9}")
        (tests_dir / "e9_evasion.rs").unlink()

        # E10a: Rust TcpStream::connect_timeout
        (tests_dir / "e10a_evasion.rs").write_text(
            "fn bad_timeout() {\n"
            '    let host = "https://totaldrop.app/r#7-harbor-rocket";\n'
            "    let _ = TcpStream::connect_timeout(&addr, dur);\n"
            "}\n",
            encoding="utf-8",
        )
        v_e10a = scan_no_live_production_probing(root)
        if not any("e10a_evasion.rs" in v for v in v_e10a):
            raise AssertionError(f"E10a TcpStream::connect_timeout evasion was NOT caught: {v_e10a}")
        (tests_dir / "e10a_evasion.rs").unlink()

        # E10b: C# Socket.Connect("rendezvous.totaldrop.app", 443) caught, while pipe.Connect(5000) is clean
        (tests_dir / "e10b_evasion.cs").write_text(
            "class Bad {\n"
            "    void Run() {\n"
            '        new Socket(0, 0, 0).Connect("rendezvous.totaldrop.app", 443);\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        v_e10b = scan_no_live_production_probing(root)
        if not any("e10b_evasion.cs" in v for v in v_e10b):
            raise AssertionError(f"E10b C# Socket.Connect evasion was NOT caught: {v_e10b}")
        (tests_dir / "e10b_evasion.cs").unlink()

        (tests_dir / "e10b_pipe_ok.cs").write_text(
            "class PipeTest {\n"
            "    void Run(NamedPipeClientStream pipe) {\n"
            '        const string share = "https://totaldrop.app/r#7-harbor-rocket";\n'
            "        pipe.Connect(5000);\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        v_pipe = scan_no_live_production_probing(root)
        if v_pipe:
            raise AssertionError(f"E10b false-positived on local NamedPipeClientStream.Connect(5000): {v_pipe}")
        (tests_dir / "e10b_pipe_ok.cs").unlink()

        # Tier-5 (C2-F2): C# char literal '"' and verbatim @"\\?\" must NOT desync comment stripping
        (tests_dir / "t5_cs_desync.cs").write_text(
            "class BadProbe {\n"
            "    bool IsQuote(char c) => c == '\"';\n"
            '    string Prefix => @"\\\\?\\";\n'
            '    string Marker => "/*";\n'
            '    void Attack() => new HttpClient().GetAsync("https://rendezvous.totaldrop.app/health");\n'
            "    // */\n"
            "}\n",
            encoding="utf-8",
        )
        v_cs = scan_no_live_production_probing(root)
        if not v_cs:
            raise AssertionError("Tier-5 C2-F2 C# char-literal/verbatim desync bypassed anti-production-probing scanner")
        (tests_dir / "t5_cs_desync.cs").unlink()

        # Tier-5 (C2-F2): Rust char literal '"' and byte-char b'"' must NOT desync comment stripping
        (tests_dir / "t5_rs_desync.rs").write_text(
            "fn attack(c: char, b: u8) {\n"
            "    let _ = c == '\"' && b == b'\"';\n"
            '    let _m = "/*";\n'
            '    let _ = TcpStream::connect("rendezvous.totaldrop.app:443");\n'
            "    // */\n"
            "}\n",
            encoding="utf-8",
        )
        v_rs = scan_no_live_production_probing(root)
        if not v_rs:
            raise AssertionError("Tier-5 C2-F2 Rust char-literal desync bypassed anti-production-probing scanner")
        (tests_dir / "t5_rs_desync.rs").unlink()

        # Tier-5 (R2-C2-F1): C# interpolated verbatim $@"..." and interpolated raw $$"""...""" must NOT desync
        (tests_dir / "t5_r2_cs_interp_verb.cs").write_text(
            "class BadInterp {\n"
            '    string Desync => $@"hello {"\\""} /*";\n'
            '    void Attack() => new HttpClient().GetAsync("https://rendezvous.totaldrop.app/health");\n'
            "    // */\n"
            "}\n",
            encoding="utf-8",
        )
        if not scan_no_live_production_probing(root):
            raise AssertionError("Tier-5 R2-C2-F1 C# $@\"...\" interp-verbatim bypassed anti-production-probing scanner")
        (tests_dir / "t5_r2_cs_interp_verb.cs").unlink()

        (tests_dir / "t5_r2_cs_interp_raw.cs").write_text(
            "class BadInterpRaw {\n"
            '    string Desync => $$"""hello {{"\\""}} /*""";\n'
            '    void Attack() => new HttpClient().GetAsync("https://rendezvous.totaldrop.app/health");\n'
            "    // */\n"
            "}\n",
            encoding="utf-8",
        )
        if not scan_no_live_production_probing(root):
            raise AssertionError("Tier-5 R2-C2-F1 C# $$ raw interpolated string bypassed anti-production-probing scanner")
        (tests_dir / "t5_r2_cs_interp_raw.cs").unlink()

        # Tier-5 (R2-C2-F2): PowerShell "<#" string literal must NOT start a block comment
        (tests_dir / "t5_r2_ps1_block_str.ps1").write_text(
            '$marker = "<#"\n'
            'Invoke-WebRequest "https://rendezvous.totaldrop.app/health"\n'
            "# #>\n",
            encoding="utf-8",
        )
        if not scan_no_live_production_probing(root):
            raise AssertionError("Tier-5 R2-C2-F2 PowerShell \"<#\" string bypassed anti-production-probing scanner")
        (tests_dir / "t5_r2_ps1_block_str.ps1").unlink()

        # Tier-5 (R2-C2-F3): Python 3.12 PEP 701 f-string quote reuse f"{"#"}" must NOT treat `#` as comment
        (tests_dir / "t5_r2_py_pep701.py").write_text(
            'x = f"{"#"}"; requests.get("https://rendezvous.totaldrop.app/health")\n',
            encoding="utf-8",
        )
        if not scan_no_live_production_probing(root):
            raise AssertionError("Tier-5 R2-C2-F3 Python 3.12 PEP 701 f-string bypassed anti-production-probing scanner")
        (tests_dir / "t5_r2_py_pep701.py").unlink()


def verify_all_static(root: Path, milestone: str) -> None:
    check_rust_safety_isolation(root)
    check_csproj_and_aot_contracts(root, milestone=milestone)
    check_4way_35_locale_parity(root)
    check_cargo_hardening_and_ps1(root, milestone=milestone)
    check_workflows_and_subplatform_scripts(root)
    check_versions_quad_and_clsid(root)
    if milestone in ("M2", "M3", "M4"):
        check_no_cloud_roaming(root)
        check_resw_critical_security_keys(root)
        check_zero_hardcoded_english_xaml(root)
        check_kose_motion_rtl_hc_a11y(root)
        check_m2_ui_page_audits(root)
    if milestone in ("M3", "M4"):
        check_m3_explorer_com_manifest(root)
        check_m3_named_pipe_ipc_app(root)
        check_m3_protocol_and_share_manifest(root)
        check_m3_toast_activation(root)
        check_m3_firewall_and_app_manifest(root)
    if milestone == "M4":
        check_m4_release_and_arm64_workflows(root)


# ---------------------------------------------------------------------------
# Mutation Test Helpers & Runner


def _clone_temp_git_repo(root: Path, dest: Path) -> None:
    p = subprocess.run(
        ["git", "clone", "--local", "--no-hardlinks", "-q", str(root), str(dest)],
        capture_output=True,
        text=True,
        check=False,
    )
    if p.returncode != 0:
        raise AssertionError(f"git clone --local failed: {p.stderr}")


def _copy_lightweight_tree(root: Path, dest: Path, rel_paths: list[str]) -> None:
    for rel in rel_paths:
        src = root / rel
        dst = dest / rel
        if src.is_dir():
            shutil.copytree(
                src,
                dst,
                ignore=shutil.ignore_patterns("bin", "obj", "TotalDrop.WinUI.Tests", "__pycache__"),
            )
        elif src.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def _run_self_on(tmp_root: Path, milestone: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", str(Path(__file__).resolve()), "--milestone", milestone, "--root", str(tmp_root)],
        capture_output=True,
        text=True,
        check=False,
    )


def _run_check_versions(repo_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", str(repo_dir / "tools" / "check-versions.py")],
        cwd=str(repo_dir),
        capture_output=True,
        text=True,
        check=False,
    )


def _expect_fail_proc(proc: subprocess.CompletedProcess[str], label: str, must_contain: tuple[str, ...]) -> None:
    combined = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode == 0:
        raise AssertionError(f"{label}: expected non-zero exit, got 0 (out={combined})")
    for tok in must_contain:
        if tok.lower() not in combined.lower():
            raise AssertionError(f"{label}: expected {tok!r} in failure output, got: {combined}")


def run_test_suite(root: Path, milestone: str) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}

    def record(test_id: str, fn: Any) -> None:
        try:
            detail = fn()
            results[test_id] = {"status": "PASS", "detail": detail or "ok"}
        except Exception as exc:  # noqa: BLE001
            results[test_id] = {"status": "FAIL", "detail": str(exc)}

    m1_light_paths = [
        "Cargo.toml",
        "rust-toolchain.toml",
        "README.md",
        "crates",
        "l10n",
        "ui-winui3-fluent2",
        "target-x86_64",
        "target-arm64",
        "subplatforms",
        ".github/workflows",
    ]

    # --- M1 Tests (28 static + mutation tests) ---
    def t1_f01_01() -> str:
        check_rust_safety_isolation(root)
        p = subprocess.run(
            ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if p.returncode != 0:
            raise AssertionError(f"cargo clippy failed:\n{p.stderr}")
        return "unsafe_code=forbid on 5 crates, FFI cdylib+rlib MIT/Apache-2.0, clippy -D warnings exit 0"

    def t2_f01_05() -> str:
        check_rust_safety_isolation(root)
        with tempfile.TemporaryDirectory(prefix="td-f01-05-") as tmp:
            t = Path(tmp)
            # (a) inject unsafe {} into totaldrop-windows-bridge
            a = t / "a"
            _copy_lightweight_tree(root, a, m1_light_paths)
            p_a = a / "crates" / "totaldrop-windows-bridge" / "src" / "uri.rs"
            p_a.write_text(p_a.read_text(encoding="utf-8") + "\nfn bad() { unsafe {} }\n", encoding="utf-8")
            _expect_fail_proc(_run_self_on(a, "M1"), "T2-F01-05(a)", ("unsafe", "totaldrop-windows-bridge"))

            # (b) inject undocumented unsafe {} into totaldrop-windows-ffi
            b = t / "b"
            _copy_lightweight_tree(root, b, m1_light_paths)
            p_b = b / "crates" / "totaldrop-windows-ffi" / "src" / "lib.rs"
            raw_b = p_b.read_text(encoding="utf-8")
            idx_test = raw_b.find("#[cfg(test)]")
            ins = "\nfn bad_undoc() {\n    unsafe {}\n}\n"
            p_b.write_text((raw_b[:idx_test] + ins + raw_b[idx_test:]) if idx_test != -1 else (raw_b + ins), encoding="utf-8")
            _expect_fail_proc(_run_self_on(b, "M1"), "T2-F01-05(b)", ("SAFETY:",))

            # (c) inject unguarded extern "C" export into totaldrop-windows-ffi
            c = t / "c"
            _copy_lightweight_tree(root, c, m1_light_paths)
            p_c = c / "crates" / "totaldrop-windows-ffi" / "src" / "lib.rs"
            raw_c = p_c.read_text(encoding="utf-8")
            idx_test = raw_c.find("#[cfg(test)]")
            ins_c = '\n#[unsafe(no_mangle)]\npub extern "C" fn totaldrop_win_unguarded() -> i32 { 0 }\n'
            p_c.write_text((raw_c[:idx_test] + ins_c + raw_c[idx_test:]) if idx_test != -1 else (raw_c + ins_c), encoding="utf-8")
            _expect_fail_proc(_run_self_on(c, "M1"), "T2-F01-05(c)", ("totaldrop_win_unguarded", "catch_unwind"))

            # (d) Tier-5 (C2-F2): comment containing `#[cfg(test)]` must NOT hide production unsafe / unguarded exports
            d_cmt = t / "d_cmt"
            _copy_lightweight_tree(root, d_cmt, m1_light_paths)
            p_d = d_cmt / "crates" / "totaldrop-windows-ffi" / "src" / "lib.rs"
            p_d.write_text(
                "// Note: #[cfg(test)] helpers live at the bottom\n"
                "fn sneaky_undoc() -> i32 { unsafe { 42 } }\n"
                + p_d.read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            _expect_fail_proc(_run_self_on(d_cmt, "M1"), "T2-F01-05(d-cfg-comment)", ("SAFETY:",))

            # (e) Tier-5 (C2-F2): URL string with `//` before `unsafe {` on the same line must NOT hide it
            e_url = t / "e_url"
            _copy_lightweight_tree(root, e_url, m1_light_paths)
            p_e = e_url / "crates" / "totaldrop-windows-ffi" / "src" / "lib.rs"
            raw_e = p_e.read_text(encoding="utf-8")
            idx_test_e = raw_e.find("#[cfg(test)]")
            ins_e = '\nfn sneaky_url_unsafe() -> i32 { let _u = "https://example.test"; unsafe { 1 } }\n'
            p_e.write_text((raw_e[:idx_test_e] + ins_e + raw_e[idx_test_e:]) if idx_test_e != -1 else (raw_e + ins_e), encoding="utf-8")
            _expect_fail_proc(_run_self_on(e_url, "M1"), "T2-F01-05(e-url-unsafe)", ("SAFETY:",))

            # (f) Tier-5 (R2-C2-F3): Multi-line `unsafe // note\n{` must NOT evade `// SAFETY:` enforcement
            f_ml = t / "f_ml"
            _copy_lightweight_tree(root, f_ml, m1_light_paths)
            p_f = f_ml / "crates" / "totaldrop-windows-ffi" / "src" / "lib.rs"
            raw_f = p_f.read_text(encoding="utf-8")
            idx_test_f = raw_f.find("#[cfg(test)]")
            ins_f = "\nfn sneaky_multiline_unsafe() -> i32 {\n    unsafe // rustfmt keeps this line break\n    {\n        1\n    }\n}\n"
            p_f.write_text((raw_f[:idx_test_f] + ins_f + raw_f[idx_test_f:]) if idx_test_f != -1 else (raw_f + ins_f), encoding="utf-8")
            _expect_fail_proc(_run_self_on(f_ml, "M1"), "T2-F01-05(f-multiline-unsafe)", ("SAFETY:",))

            # (g) Tier-5 (R2-C2-F3): Implicit C-ABI `pub extern fn` must NOT evade unwind-guard verification
            g_ext = t / "g_ext"
            _copy_lightweight_tree(root, g_ext, m1_light_paths)
            p_g = g_ext / "crates" / "totaldrop-windows-ffi" / "src" / "lib.rs"
            raw_g = p_g.read_text(encoding="utf-8")
            idx_test_g = raw_g.find("#[cfg(test)]")
            ins_g = "\n#[unsafe(no_mangle)]\npub extern fn totaldrop_win_unguarded_default_abi() -> i32 { 0 }\n"
            p_g.write_text((raw_g[:idx_test_g] + ins_g + raw_g[idx_test_g:]) if idx_test_g != -1 else (raw_g + ins_g), encoding="utf-8")
            _expect_fail_proc(_run_self_on(g_ext, "M1"), "T2-F01-05(g-implicit-extern)", ("totaldrop_win_unguarded_default_abi", "catch_unwind"))
        return "clean PASS; all 7 safety & lexer-bypass mutations caught"

    def t1_f02_01() -> str:
        check_csproj_and_aot_contracts(root)
        return ".NET 10 LTS + WinAppSDK 1.8 + AOT/WAE/Icon + Microsoft.WindowsAppRuntime.1.8 verified"

    def t1_f02_02() -> str:
        check_csproj_and_aot_contracts(root)
        return "DisableRuntimeMarshalling + LibraryImport(totaldrop_windows_ffi) + 0 ComImport/DllImport/Binding"

    def t2_f02_02() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f02-02-") as tmp:
            t = Path(tmp)
            cases = (
                ("a", "ui-winui3-fluent2/TotalDrop.WinUI.csproj", "net10.0-windows10.0.26100.0", "net9.0-windows10.0.26100.0", ("net9.0",)),
                ("b", "ui-winui3-fluent2/TotalDrop.WinUI.csproj", "1.8.", "1.7.", ("1.7",)),
                ("c", "ui-winui3-fluent2/TotalDrop.WinUI.csproj", "<InvariantGlobalization>false</InvariantGlobalization>", "<InvariantGlobalization>true</InvariantGlobalization>", ("InvariantGlobalization",)),
                ("d", "ui-winui3-fluent2/TotalDrop.WinUI.csproj", "<PublishAot>true</PublishAot>", "<PublishAot>false</PublishAot>", ("PublishAot",)),
            )
            for tag, rel, old, new, toks in cases:
                d = t / tag
                _copy_lightweight_tree(root, d, m1_light_paths)
                f = d / rel
                txt = f.read_text(encoding="utf-8")
                assert old in txt, f"{old} not found in {rel}"
                f.write_text(txt.replace(old, new, 1), encoding="utf-8")
                _expect_fail_proc(_run_self_on(d, "M1"), f"T2-F02-02({tag})", toks)
        return "all 4 csproj/manifest AOT & SDK regressions caught"

    def t2_f02_03() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f02-03-") as tmp:
            t = Path(tmp)
            cs_cases = (
                ("a", "[ComImport]\ninterface IFoo {}", ("[ComImport]",)),
                ("b", '[DllImport("totaldrop_windows_ffi")] static extern void Bad();', ("[DllImport]",)),
                ("c", "class Bad { object X() => Activator.CreateInstance(typeof(object))!; }", ("Activator.CreateInstance",)),
                ("d", "using System.Security.Cryptography;", ("System.Security.Cryptography",)),
            )
            for tag, snippet, toks in cs_cases:
                d = t / tag
                _copy_lightweight_tree(root, d, m1_light_paths)
                (d / "ui-winui3-fluent2" / "BadInjected.cs").write_text(snippet + "\n", encoding="utf-8")
                _expect_fail_proc(_run_self_on(d, "M1"), f"T2-F02-03({tag})", toks)
            e = t / "e"
            _copy_lightweight_tree(root, e, m1_light_paths)
            (e / "ui-winui3-fluent2" / "BadBinding.xaml").write_text('<Page><TextBlock Text="{Binding Text}" /></Page>\n', encoding="utf-8")
            _expect_fail_proc(_run_self_on(e, "M1"), "T2-F02-03(e)", ("{Binding ",))

            # (f) Tier-5 (C2-F2 & R2-C2-F1): C# char literal `'"'`, verbatim `@"\\?\"`, interpolated verbatim `$@"..."`,
            # interpolated char `$"{(c == '"')}"`, and interpolated raw `$$"""..."""` must NOT mask [DllImport]
            for tag, leader in (
                ("f_char", "bool Q(char c) => c == '\"';"),
                ("f_verb", 'string P => @"\\\\?\\";'),
                ("f_interp_verb", 'string Desync => $@"hello {"\\""} /*";'),
                ("f_interp_char", 'string Desync(char c) => $"{(c == \'"\' ? 1 : 0)} \' /*";'),
                ("f_interp_raw", 'string DesyncRaw => $$"""hello {{"\\""}} /*""";'),
            ):
                f_dir = t / tag
                _copy_lightweight_tree(root, f_dir, m1_light_paths)
                (f_dir / "ui-winui3-fluent2" / "BadDesync.cs").write_text(
                    f"class BadDesync {{\n"
                    f"    {leader}\n"
                    f'    string Marker => "/*";\n'
                    f'    [DllImport("evil.dll")] static extern void Boom();\n'
                    f"    // */\n"
                    f"}}\n",
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(f_dir, "M1"), f"T2-F02-03({tag})", ("[DllImport]",))
        return "all 10 forbidden AOT/Rule-2 & C# lexer-desync constructs caught"

    def t2_f02_05() -> str:
        check_csproj_and_aot_contracts(root, milestone=milestone)
        with tempfile.TemporaryDirectory(prefix="td-f02-05-") as tmp:
            t = Path(tmp)
            for tag, snippet, expected in (
                ("sync", "object? Parse(string raw) => JsonSerializer.Deserialize<object>(raw);", "JsonSerializer.Deserialize<object>"),
                ("async", "System.Threading.Tasks.ValueTask<string?> ParseAsync(System.IO.Stream s) => JsonSerializer.DeserializeAsync<string>(s);", "JsonSerializer.DeserializeAsync<string>"),
                ("async_enum", "System.Collections.Generic.IAsyncEnumerable<string?> ParseStream(System.IO.Stream s) => JsonSerializer.DeserializeAsyncEnumerable<string>(s);", "JsonSerializer.DeserializeAsyncEnumerable<string>"),
                ("nested_list", "object? ParseList(string raw) => JsonSerializer.Deserialize<System.Collections.Generic.List<string>>(raw);", "JsonSerializer.Deserialize<System.Collections.Generic.List<string>>"),
                ("nested_dict", "string SerDict(System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<int>> m) => JsonSerializer.Serialize<System.Collections.Generic.Dictionary<string, System.Collections.Generic.List<int>>>(m);", "JsonSerializer.Serialize<"),
                (
                    "paren_in_str",
                    'void Bleed(object x) { _ = JsonSerializer.Deserialize<object>("("); _ = JsonSerializer.Serialize(x, TotalDropJsonContext.Default.SettingsDto); }',
                    'JsonSerializer.Deserialize<object>("(")',
                ),
                (
                    "str_spoof_ctx",
                    'object? Spoof() => JsonSerializer.Deserialize<object>("TotalDropJsonContext.Default.Fake");',
                    "JsonSerializer.Deserialize<object>",
                ),
            ):
                d = t / tag
                _copy_lightweight_tree(root, d, m1_light_paths)
                (d / "ui-winui3-fluent2" / "Interop" / "BadJson.cs").write_text(
                    f"using System.Text.Json;\nclass Bad {{ {snippet} }}\n",
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(d, "M1"), f"T2-F02-05({tag})", (expected,))
        return "clean source-gen JSON passes; reflection, nested-generic, paren-in-string, and string-spoofed JsonSerializer mutations caught"

    def t1_f04_01() -> str:
        check_4way_35_locale_parity(root)
        return "both x64 and arm64 manifests declare <Resource Language='en'/> and exact 35-locale parity"

    def t2_f04_01() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f04-01-") as tmp:
            t = Path(tmp)
            for tag, rel in (
                ("x64", "target-x86_64/Package.x64.appxmanifest"),
                ("arm64", "target-arm64/Package.arm64.appxmanifest"),
            ):
                d = t / tag
                _copy_lightweight_tree(root, d, m1_light_paths)
                f = d / rel
                f.write_text(f.read_text(encoding="utf-8").replace('Language="en"', 'Language="en-US"', 1), encoding="utf-8")
                _expect_fail_proc(_run_self_on(d, "M1"), f"T2-F04-01({tag})", ("en-US",))
        return "mutated <Resource Language='en-US'/> rejected on both x64 and arm64 manifests"

    def t2_f04_02() -> str:
        check_4way_35_locale_parity(root)
        with tempfile.TemporaryDirectory(prefix="td-f04-02-") as tmp:
            t = Path(tmp)
            # (a) stray pt and zh directories
            for base_tag in ("pt", "zh"):
                d = t / f"stray-{base_tag}"
                _copy_lightweight_tree(root, d, m1_light_paths)
                (d / "ui-winui3-fluent2" / "Strings" / base_tag).mkdir()
                shutil.copy2(
                    d / "ui-winui3-fluent2" / "Strings" / "en" / "Resources.resw",
                    d / "ui-winui3-fluent2" / "Strings" / base_tag / "Resources.resw",
                )
                _expect_fail_proc(_run_self_on(d, "M1"), f"T2-F04-02a({base_tag})", (base_tag,))

            # (b) remove Strings/sw and <Resource Language="sw" />
            b = t / "drop-sw"
            _copy_lightweight_tree(root, b, m1_light_paths)
            shutil.rmtree(b / "ui-winui3-fluent2" / "Strings" / "sw")
            for rel in ("target-x86_64/Package.x64.appxmanifest", "target-arm64/Package.arm64.appxmanifest"):
                f = b / rel
                f.write_text(re.sub(r'\s*<Resource Language="sw"\s*/>\s*', "\n", f.read_text(encoding="utf-8")), encoding="utf-8")
            _expect_fail_proc(_run_self_on(b, "M1"), "T2-F04-02b", ("sw", "34 != 35"))

            # (c) remove <Resource Language="zh-Hant" /> while keeping Strings/zh-Hant/
            c = t / "drop-zh-hant"
            _copy_lightweight_tree(root, c, m1_light_paths)
            f = c / "target-x86_64" / "Package.x64.appxmanifest"
            f.write_text(re.sub(r'\s*<Resource Language="zh-Hant"\s*/>\s*', "\n", f.read_text(encoding="utf-8")), encoding="utf-8")
            _expect_fail_proc(_run_self_on(c, "M1"), "T2-F04-02c", ("zh-Hant",))
        return "clean 35==35 PASS; stray pt/zh, dropped sw, and orphan zh-Hant all caught"

    def t2_f04_03() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f04-03-") as tmp:
            d = Path(tmp) / "m"
            _copy_lightweight_tree(root, d, m1_light_paths)
            tr_resw = d / "ui-winui3-fluent2" / "Strings" / "tr" / "Resources.resw"
            txt = tr_resw.read_text(encoding="utf-8")
            mutated = re.sub(r'<data name="verificationTitle".*?</data>', "", txt, count=1, flags=re.DOTALL)
            assert mutated != txt
            tr_resw.write_text(mutated, encoding="utf-8")
            _expect_fail_proc(_run_self_on(d, "M1"), "T2-F04-03", ("verificationTitle", "tr"))
        return "missing verificationTitle key in tr/Resources.resw caught"

    def t1_f05_01() -> str:
        check_cargo_hardening_and_ps1(root)
        return "x64+arm64 cargo-config.toml hardening & PS1 RUSTFLAGS/no-/nv checks pass"

    def t2_f05_01() -> str:
        check_cargo_hardening_and_ps1(root)
        with tempfile.TemporaryDirectory(prefix="td-f05-01-") as tmp:
            t = Path(tmp)
            # (a) inject $env:RUSTFLAGS = "-D warnings" before `& cargo @cargoArgs`
            a = t / "a"
            _copy_lightweight_tree(root, a, m1_light_paths)
            ps_a = a / "target-x86_64" / "build-x64.ps1"
            ps_a.write_text(
                ps_a.read_text(encoding="utf-8").replace(
                    "& cargo @cargoArgs",
                    '$env:RUSTFLAGS = "-D warnings"\n    & cargo @cargoArgs',
                    1,
                ),
                encoding="utf-8",
            )
            _expect_fail_proc(_run_self_on(a, "M1"), "T2-F05-01(a)", ("RUSTFLAGS",))

            # (b) inject $env:CARGO_ENCODED_RUSTFLAGS before `& cargo @cargoArgs`
            b = t / "b"
            _copy_lightweight_tree(root, b, m1_light_paths)
            ps_b = b / "target-arm64" / "build-arm64.ps1"
            ps_b.write_text(
                ps_b.read_text(encoding="utf-8").replace(
                    "& cargo @cargoArgs",
                    '$env:CARGO_ENCODED_RUSTFLAGS = "-D"\n    & cargo @cargoArgs',
                    1,
                ),
                encoding="utf-8",
            )
            _expect_fail_proc(_run_self_on(b, "M1"), "T2-F05-01(b)", ("CARGO_ENCODED_RUSTFLAGS",))

            # (c) append /nv to makeappx pack (single-line, multi-line backtick, and quoted "/nv")
            c = t / "c"
            _copy_lightweight_tree(root, c, m1_light_paths)
            ps_c = c / "target-x86_64" / "build-x64.ps1"
            ps_c.write_text(ps_c.read_text(encoding="utf-8").replace("& $MakeAppxExe pack ", "& $MakeAppxExe pack /nv ", 1), encoding="utf-8")
            _expect_fail_proc(_run_self_on(c, "M1"), "T2-F05-01(c)", ("/nv",))

            c2 = t / "c2"
            _copy_lightweight_tree(root, c2, m1_light_paths)
            ps_c2 = c2 / "target-x86_64" / "build-x64.ps1"
            ps_c2.write_text(ps_c2.read_text(encoding="utf-8").replace("& $MakeAppxExe pack ", '& $MakeAppxExe pack `\n    "/nv" ', 1), encoding="utf-8")
            _expect_fail_proc(_run_self_on(c2, "M1"), "T2-F05-01(c2)", ("/nv",))

            # (c3) E11 inline multi-line <# ... #> comment splitting makeappx pack and "/nv"
            c3 = t / "c3"
            _copy_lightweight_tree(root, c3, m1_light_paths)
            ps_c3 = c3 / "target-x86_64" / "build-x64.ps1"
            ps_c3.write_text(
                ps_c3.read_text(encoding="utf-8").replace(
                    "& $MakeAppxExe pack ",
                    '& $MakeAppxExe pack <#\n  bypass\n#> "/nv" ',
                    1,
                ),
                encoding="utf-8",
            )
            _expect_fail_proc(_run_self_on(c3, "M1"), "T2-F05-01(c3-E11)", ("/nv",))

            # (d) Tier-5 (C2-F2): Move Remove-Item Env:RUSTFLAGS AFTER `& cargo @cargoArgs`
            d_ord = t / "d_ord"
            _copy_lightweight_tree(root, d_ord, m1_light_paths)
            ps_d = d_ord / "target-x86_64" / "build-x64.ps1"
            raw_d = ps_d.read_text(encoding="utf-8")
            raw_d = raw_d.replace("Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue", "", 1)
            raw_d = raw_d.replace(
                "& cargo @cargoArgs",
                "& cargo @cargoArgs\n    Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue",
                1,
            )
            ps_d.write_text(raw_d, encoding="utf-8")
            _expect_fail_proc(_run_self_on(d_ord, "M1"), "T2-F05-01(d-order)", ("RUSTFLAGS",))

            # (e) Tier-5 (R2-C2-F2): Same-line post-cargo `& cargo @cargoArgs; Remove-Item Env:RUSTFLAGS; ...`
            e_same = t / "e_same"
            _copy_lightweight_tree(root, e_same, m1_light_paths)
            ps_e = e_same / "target-x86_64" / "build-x64.ps1"
            raw_e = ps_e.read_text(encoding="utf-8")
            raw_e = raw_e.replace("Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue", "", 1)
            raw_e = raw_e.replace("Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue", "", 1)
            raw_e = raw_e.replace(
                "& cargo @cargoArgs",
                "& cargo @cargoArgs; Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue; Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue",
                1,
            )
            ps_e.write_text(raw_e, encoding="utf-8")
            _expect_fail_proc(_run_self_on(e_same, "M1"), "T2-F05-01(e-sameline-clear)", ("RUSTFLAGS",))

            # (f) Tier-5 (R2-C2-F2): Backtick-escaped quote string spoofing Remove-Item Env:RUSTFLAGS
            f_bt = t / "f_bt"
            _copy_lightweight_tree(root, f_bt, m1_light_paths)
            ps_f = f_bt / "target-x86_64" / "build-x64.ps1"
            raw_f = ps_f.read_text(encoding="utf-8")
            raw_f = raw_f.replace(
                "Remove-Item Env:RUSTFLAGS -ErrorAction SilentlyContinue",
                'Write-Host "note `" Remove-Item Env:RUSTFLAGS `""',
                1,
            )
            raw_f = raw_f.replace(
                "Remove-Item Env:CARGO_ENCODED_RUSTFLAGS -ErrorAction SilentlyContinue",
                'Write-Host "note `" Remove-Item Env:CARGO_ENCODED_RUSTFLAGS `""',
                1,
            )
            ps_f.write_text(raw_f, encoding="utf-8")
            _expect_fail_proc(_run_self_on(f_bt, "M1"), "T2-F05-01(f-backtick-quote)", ("RUSTFLAGS",))

            # (g) Tier-5 (R2-C2-F2): "finally" inside string unlocking active $env:RUSTFLAGS = ...
            g_fin = t / "g_fin"
            _copy_lightweight_tree(root, g_fin, m1_light_paths)
            ps_g = g_fin / "target-x86_64" / "build-x64.ps1"
            ps_g.write_text(
                ps_g.read_text(encoding="utf-8").replace(
                    "& cargo @cargoArgs",
                    'Write-Host "finally"\n    if ($true) { $env:RUSTFLAGS = "-C target-feature=-crt-static" }\n    & cargo @cargoArgs',
                    1,
                ),
                encoding="utf-8",
            )
            _expect_fail_proc(_run_self_on(g_fin, "M1"), "T2-F05-01(g-finally-in-str)", ("RUSTFLAGS",))

            # (h) Tier-5 (R2-C2-F2): Same-line Write-Host followed by `; & $MakeAppxExe pack /nv`
            h_wh = t / "h_wh"
            _copy_lightweight_tree(root, h_wh, m1_light_paths)
            ps_h = h_wh / "target-x86_64" / "build-x64.ps1"
            ps_h.write_text(
                ps_h.read_text(encoding="utf-8").replace(
                    "& $MakeAppxExe pack ",
                    'Write-Host "packing"; & $MakeAppxExe pack /nv ',
                    1,
                ),
                encoding="utf-8",
            )
            _expect_fail_proc(_run_self_on(h_wh, "M1"), "T2-F05-01(h-writehost-nv)", ("/nv",))
        return "clean PS1 passes; all 10 RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS/finally/Write-Host/backtick/E11/R2-C2-F2 /nv mutations caught"

    def t1_f06_01() -> str:
        check_workflows_and_subplatform_scripts(root)
        return "ci.yml windows-x64-msix job, SHA pinning, .NET 10, Rust 1.99.1, and gate.needs verified"

    def t1_f06_02() -> str:
        check_workflows_and_subplatform_scripts(root)
        return "subplatforms/msix/x86_64/{build.sh,verify.sh} POSIX syntax & non-stub checks verified"

    def t1_f06_03() -> str:
        p = subprocess.run(
            [sys.executable, "-B", str(root / "tools" / "verify-subplatforms.py")],
            cwd=str(root),
            capture_output=True,
            text=True,
            check=False,
        )
        if p.returncode != 0 or "6/6" not in p.stdout:
            raise AssertionError(f"verify-subplatforms.py failed: rc={p.returncode}, out={p.stdout}\n{p.stderr}")
        return p.stdout.strip()

    def t2_f06_05() -> str:
        check_workflows_and_subplatform_scripts(root)
        with tempfile.TemporaryDirectory(prefix="td-f06-05-") as tmp:
            t = Path(tmp)
            # (a) mutable @v4 in ci.yml
            a = t / "a"
            _copy_lightweight_tree(root, a, m1_light_paths)
            ci_a = a / ".github" / "workflows" / "ci.yml"
            ci_a.write_text(re.sub(r"actions/checkout@[0-9a-f]{40}", "actions/checkout@v4", ci_a.read_text(encoding="utf-8"), count=1), encoding="utf-8")
            _expect_fail_proc(_run_self_on(a, "M1"), "T2-F06-05(a)", ("@v4",))

            # (b) mutable @main in pkg-msix-x86_64.yml
            b = t / "b"
            _copy_lightweight_tree(root, b, m1_light_paths)
            pkg_b = b / ".github" / "workflows" / "pkg-msix-x86_64.yml"
            pkg_b.write_text(re.sub(r"actions/checkout@[0-9a-f]{40}", "actions/checkout@main", pkg_b.read_text(encoding="utf-8"), count=1), encoding="utf-8")
            _expect_fail_proc(_run_self_on(b, "M1"), "T2-F06-05(b)", ("@main",))

            # (c) drop windows-x64-msix from jobs.gate.needs
            c = t / "c"
            _copy_lightweight_tree(root, c, m1_light_paths)
            ci_c = c / ".github" / "workflows" / "ci.yml"
            txt_c = ci_c.read_text(encoding="utf-8")
            gate_pos = txt_c.find("\n  gate:\n")
            assert gate_pos != -1
            patched = txt_c[:gate_pos] + txt_c[gate_pos:].replace("windows-x64-msix", "other-job", 1)
            ci_c.write_text(patched, encoding="utf-8")
            _expect_fail_proc(_run_self_on(c, "M1"), "T2-F06-05(c)", ("windows-x64-msix",))
        return "clean workflows PASS; @v4, @main, and dropped windows-x64-msix gate all caught"

    def t1_f07_01() -> str:
        p = _run_check_versions(root)
        if p.returncode != 0:
            raise AssertionError(f"check-versions.py failed: {p.stdout}\n{p.stderr}")
        return p.stdout.strip()

    def t1_f07_02() -> str:
        check_versions_quad_and_clsid(root)
        return "all 5 manifest/script sources + FFI version aligned at 0.1.1.0 (Revision == 0)"

    def t1_f07_03() -> str:
        check_versions_quad_and_clsid(root)
        p = _run_check_versions(root)
        if p.returncode != 0:
            raise AssertionError(p.stderr)
        return "core crates isolated at 0.2.0-beta.5 vs Windows app 0.1.0-beta.1"

    def t1_f07_04() -> str:
        check_versions_quad_and_clsid(root)
        return f"canonical CLSID {{{CANONICAL_CLSID}}} consistent; zero drifted CLSID references"

    def t1_f07_05() -> str:
        check_workflows_and_subplatform_scripts(root)
        return "ci.yml enforces tools/check-versions.py in required job(s) feeding gate"

    def t2_f07_01() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f07-01-") as tmp:
            clone = Path(tmp) / "repo"
            _clone_temp_git_repo(root, clone)
            recipe = clone / "subplatforms" / "msix" / "x86_64" / "RECIPE.toml"
            recipe.write_text(recipe.read_text(encoding="utf-8").replace('version = "0.1.0-beta.1"', f'version = "{STALE_SUBPLATFORM_VER}"', 1), encoding="utf-8")
            _expect_fail_proc(_run_check_versions(clone), "T2-F07-01", ("RECIPE.toml", STALE_SUBPLATFORM_VER))

            # Tier-5 (C2-F5): Multi-line broken WinGet schema header must be rejected by tools/check-versions.py
            clone_wg = Path(tmp) / "repo_wg"
            _clone_temp_git_repo(root, clone_wg)
            wg_yaml = clone_wg / "target-x86_64" / "winget" / "app.totaldrop.TotalDrop.x64.yaml"
            wg_txt = wg_yaml.read_text(encoding="utf-8")
            broken_hdr = "#\nyaml-language-server:\n$schema=https://aka.ms/winget-manifest.singleton.1.9.0.schema.json"
            mut_wg = re.sub(
                r"^#[ \t]*yaml-language-server:[ \t]*\$schema=https://aka\.ms/winget-manifest\.singleton\.1\.9\.0\.schema\.json[ \t]*$",
                broken_hdr,
                wg_txt,
                count=1,
                flags=re.MULTILINE,
            )
            assert mut_wg != wg_txt
            wg_yaml.write_text(mut_wg, encoding="utf-8")
            p_wg = subprocess.run(
                [sys.executable, "-B", str(root / "tools" / "check-versions.py"), "--root", str(clone_wg)],
                cwd=str(root),
                capture_output=True,
                text=True,
                check=False,
            )
            _expect_fail_proc(p_wg, "T2-F07-01(winget-multiline-schema)", ("winget-manifest.singleton.1.9.0.schema.json",))

            # Tier-5 (R2-C2-F6): Duplicate WinGet ManifestVersion/PackageVersion & commented-out InstallerUrl rejected
            wg_cases = (
                ("dup-manifest-ver", lambda s: s + "\nManifestVersion: 1.0.0\n", ("ManifestVersion",)),
                ("dup-pkg-ver", lambda s: s + "\nPackageVersion: 9.9.9\n", ("PackageVersion",)),
                (
                    "commented-installer-url",
                    lambda s: re.sub(r"^([ \t]*InstallerUrl:)", r"# \1", s, count=1, flags=re.MULTILINE),
                    ("InstallerUrl",),
                ),
            )
            for tag, mutate_fn, expect_toks in wg_cases:
                c_dir = Path(tmp) / f"repo_wg_{tag}"
                _clone_temp_git_repo(root, c_dir)
                y_path = c_dir / "target-x86_64" / "winget" / "app.totaldrop.TotalDrop.x64.yaml"
                orig_y = y_path.read_text(encoding="utf-8")
                mut_y = mutate_fn(orig_y)
                assert mut_y != orig_y, f"{tag} mutation was a no-op"
                y_path.write_text(mut_y, encoding="utf-8")
                p_mut = subprocess.run(
                    [sys.executable, "-B", str(root / "tools" / "check-versions.py"), "--root", str(c_dir)],
                    cwd=str(root),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                _expect_fail_proc(p_mut, f"T2-F07-01(winget-{tag})", expect_toks)
        return "mutated RECIPE.toml stale version, multi-line WinGet schema, duplicate WinGet keys & commented InstallerUrl all caught"

    def t2_f07_02() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f07-02-") as tmp:
            clone = Path(tmp) / "repo"
            _clone_temp_git_repo(root, clone)
            man = clone / "target-x86_64" / "Package.x64.appxmanifest"
            man.write_text(man.read_text(encoding="utf-8").replace('Version="0.1.1.0"', 'Version="0.1.1.1"', 1), encoding="utf-8")
            _expect_fail_proc(_run_check_versions(clone), "T2-F07-02(check-versions)", ("Package.x64.appxmanifest", "0.1.1.1"))
            _expect_fail_proc(_run_self_on(clone, "M1"), "T2-F07-02(static)", ("Revision == 0",))
        return "non-zero Revision 0.1.1.1 caught by both check-versions.py and Revision == 0 oracle"

    def t2_f07_03() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f07-03-") as tmp:
            t = Path(tmp)
            for tag, bad_ver, token in (
                ("overflow", "0.1.65536.0", "65535"),
                ("threepart", "0.1.1", "4-part"),
                ("leadingzero", "01.0.1.0", "leading zero"),
                ("nonascii", "١.٠.١.٠", "4-part"),
            ):
                clone = t / tag
                _clone_temp_git_repo(root, clone)
                man = clone / "target-x86_64" / "Package.x64.appxmanifest"
                man.write_text(man.read_text(encoding="utf-8").replace('Version="0.1.1.0"', f'Version="{bad_ver}"', 1), encoding="utf-8")
                _expect_fail_proc(_run_check_versions(clone), f"T2-F07-03({tag},cv)", ("Package.x64.appxmanifest",))
                _expect_fail_proc(_run_self_on(clone, "M1"), f"T2-F07-03({tag},static)", (token,))
        return "uint16 overflow, 3-part, leading-zero (01.0.1.0), and non-ASCII digit quads caught by both tools"

    def t2_f07_04() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f07-04-") as tmp:
            clone = Path(tmp) / "repo"
            _clone_temp_git_repo(root, clone)
            man = clone / "target-arm64" / "Package.arm64.appxmanifest"
            man.write_text(man.read_text(encoding="utf-8").replace('Version="0.1.1.0"', 'Version="0.1.2.0"', 1), encoding="utf-8")
            _expect_fail_proc(_run_check_versions(clone), "T2-F07-04", ("Package.arm64.appxmanifest", "0.1.2.0"))
        return "cross-arch x64!=arm64 manifest version drift caught"

    def t2_f07_05() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f07-05-") as tmp:
            t = Path(tmp)
            # (a) Re-introduce drifted CLSID in README.md
            a = t / "a"
            _clone_temp_git_repo(root, a)
            readme = a / "README.md"
            readme.write_text(readme.read_text(encoding="utf-8").replace(CANONICAL_CLSID, DRIFTED_CLSID, 1), encoding="utf-8")
            _expect_fail_proc(_run_check_versions(a), "T2-F07-05a(cv)", ("README.md", DRIFTED_CLSID))
            _expect_fail_proc(_run_self_on(a, "M1"), "T2-F07-05a(static)", ("README.md", DRIFTED_CLSID))

            # (b) Malformed GUID in crates/totaldrop-explorer-ext/src/lib.rs (replaced retired ExplorerCommand.idl in M3)
            b = t / "b"
            _clone_temp_git_repo(root, b)
            ext_lib = b / "crates" / "totaldrop-explorer-ext" / "src" / "lib.rs"
            ext_lib.write_text(
                ext_lib.read_text(encoding="utf-8").replace(CANONICAL_CLSID, "8F6E3D72-BAD"),
                encoding="utf-8",
            )
            _expect_fail_proc(_run_check_versions(b), "T2-F07-05b(cv)", ("crates/totaldrop-explorer-ext/src/lib.rs",))
            _expect_fail_proc(_run_self_on(b, "M1"), "T2-F07-05b(static)", ("crates/totaldrop-explorer-ext/src/lib.rs", "8F6E3D72-BAD"))
        return "drifted README.md CLSID and malformed totaldrop-explorer-ext/src/lib.rs GUID both caught"

    def t3_16() -> str:
        # Clean repo passes both check-versions.py and verify-subplatforms.py
        if _run_check_versions(root).returncode != 0:
            raise AssertionError("clean check-versions.py failed")
        p_sub = subprocess.run([sys.executable, "-B", str(root / "tools" / "verify-subplatforms.py")], cwd=str(root), capture_output=True, text=True, check=False)
        if p_sub.returncode != 0:
            raise AssertionError(f"clean verify-subplatforms.py failed: {p_sub.stderr}")

        with tempfile.TemporaryDirectory(prefix="td-t3-16-") as tmp:
            t = Path(tmp)
            clone = t / "repo"
            _clone_temp_git_repo(root, clone)
            recipe = clone / "subplatforms" / "msix" / "x86_64" / "RECIPE.toml"
            recipe.write_text(recipe.read_text(encoding="utf-8").replace('version = "0.1.0-beta.1"', 'version = "9.9.9"', 1), encoding="utf-8")
            _expect_fail_proc(_run_check_versions(clone), "T3-16(version)", ("RECIPE.toml",))

            # Gzip fake .msix fails verify.sh
            art = t / "art"
            art.mkdir()
            rec_data = tomllib.loads((root / "subplatforms" / "msix" / "x86_64" / "RECIPE.toml").read_text(encoding="utf-8"))
            art_name = rec_data["artifact_name"]
            import gzip as _gz
            fake = art / art_name
            fake.write_bytes(_gz.compress(b"not-an-msix"))
            import hashlib as _hl
            (art / "SHA256SUMS").write_text(f"{_hl.sha256(fake.read_bytes()).hexdigest()}  {art_name}\n", encoding="utf-8")
            p_ver = subprocess.run([_resolve_sh(), str(root / "subplatforms" / "msix" / "x86_64" / "verify.sh"), str(art)], cwd=str(root), capture_output=True, text=True, check=False)
            _expect_fail_proc(p_ver, "T3-16(gzip-msix)", ("not a real opc/zip msix",))

            # Tier-5 (R2-C2-F6): All 4 portable-zip/winget build.sh scripts must fail non-zero on missing STAGE_IN
            sh_bin = _resolve_sh()
            missing_stage = t / "does_not_exist"
            for fmt in ("portable-zip", "winget"):
                for arch in ("x86_64", "arm64"):
                    out_missing = t / f"out_missing_{fmt}_{arch}"
                    bsh = root / "subplatforms" / fmt / arch / "build.sh"
                    p_miss = subprocess.run(
                        [sh_bin, str(bsh), "--package-staged", str(missing_stage), str(out_missing)],
                        cwd=str(root),
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    _expect_fail_proc(p_miss, f"T3-16(missing-stage-{fmt}-{arch})", ("staging input directory",))
                    if out_missing.exists() and list(out_missing.glob("*.zip")):
                        raise AssertionError(f"R2-C2-F6: {bsh} unexpectedly emitted ZIP on nonexistent STAGE_IN")
        return "clean check-versions + verify-subplatforms PASS; version drift, gzip fake .msix & 4x missing-STAGE_IN build.sh caught"

    record("T1-F01-01", t1_f01_01)
    record("T2-F01-05", t2_f01_05)
    record("T1-F02-01", t1_f02_01)
    record("T1-F02-02", t1_f02_02)
    record("T2-F02-02", t2_f02_02)
    record("T2-F02-03", t2_f02_03)
    record("T2-F02-05", t2_f02_05)
    record("T1-F04-01", t1_f04_01)
    record("T2-F04-01", t2_f04_01)
    record("T2-F04-02", t2_f04_02)
    record("T2-F04-03", t2_f04_03)
    record("T1-F05-01", t1_f05_01)
    record("T2-F05-01", t2_f05_01)
    record("T1-F06-01", t1_f06_01)
    record("T1-F06-02", t1_f06_02)
    record("T1-F06-03", t1_f06_03)
    record("T2-F06-05", t2_f06_05)
    record("T1-F07-01", t1_f07_01)
    record("T1-F07-02", t1_f07_02)
    record("T1-F07-03", t1_f07_03)
    record("T1-F07-04", t1_f07_04)
    record("T1-F07-05", t1_f07_05)
    record("T2-F07-01", t2_f07_01)
    record("T2-F07-02", t2_f07_02)
    record("T2-F07-03", t2_f07_03)
    record("T2-F07-04", t2_f07_04)
    record("T2-F07-05", t2_f07_05)
    record("T3-16", t3_16)

    if milestone in ("M2", "M3", "M4"):
        def t2_f12_05() -> str:
            check_no_cloud_roaming(root)
            with tempfile.TemporaryDirectory(prefix="td-f12-05-") as tmp:
                t = Path(tmp)
                for tag, token in (("a", "RoamingFolder"), ("b", "RoamingSettings")):
                    d = t / tag
                    _copy_lightweight_tree(root, d, m1_light_paths)
                    (d / "ui-winui3-fluent2" / "Services" / "BadSync.cs").write_text(
                        f"class BadSync {{ object X() => ApplicationData.Current.{token}; }}\n",
                        encoding="utf-8",
                    )
                    _expect_fail_proc(_run_self_on(d, "M2"), f"T2-F12-05({tag})", (token,))
                # Tier-5 (R2-C2-F1): $@"hello {"\""} /*" must NOT hide RoamingFolder
                c = t / "c_interp"
                _copy_lightweight_tree(root, c, m1_light_paths)
                (c / "ui-winui3-fluent2" / "Services" / "BadSyncInterp.cs").write_text(
                    'class BadSyncInterp {\n'
                    '    string Desync => $@"hello {"\\""} /*";\n'
                    '    object Roam() => ApplicationData.Current.RoamingFolder;\n'
                    '    // */\n'
                    '}\n',
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(c, "M2"), "T2-F12-05(c-interp)", ("RoamingFolder",))
            return "clean local settings.json PASS; RoamingFolder, RoamingSettings & $@\"...\"-masked RoamingFolder mutations caught"

        def t2_f13_01_part_b() -> str:
            check_resw_critical_security_keys(root)
            with tempfile.TemporaryDirectory(prefix="td-f13-01b-") as tmp:
                d = Path(tmp) / "m"
                _copy_lightweight_tree(root, d, m1_light_paths)
                de_resw = d / "ui-winui3-fluent2" / "Strings" / "de" / "Resources.resw"
                de_resw.write_text(
                    de_resw.read_text(encoding="utf-8").replace(
                        '<data name="verificationTitle" xml:space="preserve">\n    <value>Verification words</value>',
                        '<data name="verificationTitle" xml:space="preserve">\n    <value>Pr\u00fcfw\u00f6rter</value>',
                        1,
                    ),
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(d, "M2"), "T2-F13-01b(de)", ("de:verificationTitle",))

                d2 = Path(tmp) / "m2"
                _copy_lightweight_tree(root, d2, m1_light_paths)
                ar_resw = d2 / "ui-winui3-fluent2" / "Strings" / "ar" / "Resources.resw"
                ar_resw.write_text(
                    ar_resw.read_text(encoding="utf-8").replace(
                        '<data name="receiveAccept" xml:space="preserve">\n    <value>Accept</value>',
                        '<data name="receiveAccept" xml:space="preserve">\n    <value>\u0642\u0628\u0648\u0644</value>',
                        1,
                    ),
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(d2, "M2"), "T2-F13-01b(ar)", ("ar:receiveAccept",))
            return "clean 33 unreviewed .resw critical keys PASS; de:verificationTitle & ar:receiveAccept tampering caught"

        def t2_f13_06() -> str:
            check_zero_hardcoded_english_xaml(root)
            with tempfile.TemporaryDirectory(prefix="td-f13-06-") as tmp:
                t = Path(tmp)
                for tag, snippet, expected in (
                    ("a", '<TextBlock Text="Send files" TextWrapping="Wrap" IsTextScaleFactorEnabled="True" />', 'Text="Send files"'),
                    ("b", '<Button Content="Connect" AutomationProperties.Name="TotalDrop" />', 'Content="Connect"'),
                    ("c", '<TextBox Header="Server" AutomationProperties.Name="TotalDrop" />', 'Header="Server"'),
                    ("d", '<TextBlock TextWrapping="Wrap" IsTextScaleFactorEnabled="True">Connecting...</TextBlock>', "Connecting..."),
                    ("e", '<TextBox AutomationProperties.Name="TotalDrop" AutomationProperties.HelpText="Enter your server address" />', 'AutomationProperties.HelpText="Enter your server address"'),
                    ("f", '<Button AutomationProperties.Name="TotalDrop" ToolTipService.ToolTip="Copy transfer code" />', 'ToolTipService.ToolTip="Copy transfer code"'),
                    ("g", '<InfoBar Title="TotalDrop" Message="Hardcoded warning" />', 'Message="Hardcoded warning"'),
                ):
                    d = t / tag
                    _copy_lightweight_tree(root, d, m1_light_paths)
                    (d / "ui-winui3-fluent2" / "Views" / "InjectedHardcoded.xaml").write_text(
                        f'<Page xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation">{snippet}</Page>\n',
                        encoding="utf-8",
                    )
                    _expect_fail_proc(_run_self_on(d, "M2"), f"T2-F13-06({tag})", (expected,))
            return "zero hardcoded English XAML literals PASS; attributes, Message, inner text, HelpText & ToolTip caught"

        def t1_f14_01() -> str:
            check_kose_motion_rtl_hc_a11y(root)
            return "Kose path, pivot (55,57), palette, 3.2s spline storyboard, Done check, AnimationsEnabled verified"

        def t1_f14_02() -> str:
            check_kose_motion_rtl_hc_a11y(root)
            return "Kose/TransferCode/VerificationWords LTR + en-US and HighContrast SystemColor dictionary verified"

        def t1_f14_03() -> str:
            check_kose_motion_rtl_hc_a11y(root)
            return "100% interactive controls have AutomationProperties.Name & TextBlocks wrap+scale"

        def t2_f14_01() -> str:
            check_kose_motion_rtl_hc_a11y(root)
            with tempfile.TemporaryDirectory(prefix="td-f14-01-") as tmp:
                t = Path(tmp)
                a = t / "a"
                _copy_lightweight_tree(root, a, m1_light_paths)
                mw_a = a / "ui-winui3-fluent2" / "MainWindow.xaml"
                mw_a.write_text(mw_a.read_text(encoding="utf-8").replace('FlowDirection="LeftToRight"', 'FlowDirection="RightToLeft"', 1), encoding="utf-8")
                _expect_fail_proc(_run_self_on(a, "M2"), "T2-F14-01(a)", ("LeftToRight",))

                b = t / "b"
                _copy_lightweight_tree(root, b, m1_light_paths)
                sp_b = b / "ui-winui3-fluent2" / "Views" / "SendPage.xaml"
                sp_b.write_text(sp_b.read_text(encoding="utf-8").replace('Language="en-US"', "", 2), encoding="utf-8")
                _expect_fail_proc(_run_self_on(b, "M2"), "T2-F14-01(b)", ("en-US",))

                c = t / "c"
                _copy_lightweight_tree(root, c, m1_light_paths)
                mw_c = c / "ui-winui3-fluent2" / "MainWindow.xaml"
                mw_c.write_text(mw_c.read_text(encoding="utf-8").replace('CenterX="55"', 'CenterX="50"', 1), encoding="utf-8")
                _expect_fail_proc(_run_self_on(c, "M2"), "T2-F14-01(c1)", ("(55, 57)",))

                c2 = t / "c2"
                _copy_lightweight_tree(root, c2, m1_light_paths)
                mw_cs = c2 / "ui-winui3-fluent2" / "MainWindow.xaml.cs"
                mw_cs.write_text(mw_cs.read_text(encoding="utf-8").replace("SystemBackdrop = null", "// removed", 1), encoding="utf-8")
                _expect_fail_proc(_run_self_on(c2, "M2"), "T2-F14-01(c2)", ("SystemBackdrop = null",))

                d = t / "d"
                _copy_lightweight_tree(root, d, m1_light_paths)
                sp_d = d / "ui-winui3-fluent2" / "Views" / "SendPage.xaml"
                sp_d.write_text(re.sub(r'(<Button\b[^>]*?)\s+AutomationProperties\.Name="[^"]*"', r"\1", sp_d.read_text(encoding="utf-8"), count=1), encoding="utf-8")
                _expect_fail_proc(_run_self_on(d, "M2"), "T2-F14-01(d)", ("AutomationProperties.Name",))
            return "all 4 F14 brand/RTL/reduced-motion/HC/a11y regressions caught"

        record("T2-F12-05", t2_f12_05)
        record("T2-F13-01-part-b", t2_f13_01_part_b)
        record("T2-F13-06", t2_f13_06)
        record("T1-F14-01", t1_f14_01)
        record("T1-F14-02", t1_f14_02)
        record("T1-F14-03", t1_f14_03)
        record("T2-F14-01", t2_f14_01)

    if milestone in ("M3", "M4"):
        def t1_f16_03_part_b() -> str:
            check_m3_explorer_com_manifest(root)
            return "SurrogateServer (STA, bare GUID) + FileExplorerContextMenus (* & Directory) verified on x64 & arm64"

        def t1_f17_03() -> str:
            check_m3_named_pipe_ipc_app(root)
            with tempfile.TemporaryDirectory(prefix="td-f17-03-") as tmp:
                d = Path(tmp) / "m"
                _copy_lightweight_tree(root, d, m1_light_paths)
                app_cs = d / "ui-winui3-fluent2" / "App.xaml.cs"
                app_cs.write_text(
                    app_cs.read_text(encoding="utf-8")
                    + "\n// test mutation\nclass BadIpc { object? Parse(string s) => System.Text.Json.JsonSerializer.Deserialize<object>(s); }\n",
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(d, "M3"), "T1-F17-03(mut)", ("JsonSerializer",))
            return "App.xaml.cs uses PipeOptions.CurrentUserOnly + Rust IPC router (0 C# JSON); mutation caught"

        def t1_f18_01_part_b() -> str:
            check_m3_protocol_and_share_manifest(root)
            return "<uap:Protocol Name='totaldrop'> + <uap:ShareTarget> (SupportsAnyFileType, Text/WebLink/StorageItems) verified"

        def t2_f18_03_part_b() -> str:
            check_m3_protocol_and_share_manifest(root)
            return "ShareOperation.ReportCompleted() guaranteed in finally block (ShareTargetRouter + App.xaml.cs)"

        def t1_f19_01() -> str:
            check_m3_toast_activation(root)
            return f"ToastActivatorCLSID ({TOAST_ACTIVATOR_CLSID}) distinct from Explorer CLSID & matched to ExeServer"

        def t1_f19_04_part_b() -> str:
            check_m3_toast_activation(root)
            return "App.xaml.cs & MainWindow.xaml.cs handle ----AppNotificationActivated: foreground-only before file validation"

        def t2_f19_05() -> str:
            check_m3_toast_activation(root)
            with tempfile.TemporaryDirectory(prefix="td-f19-05-") as tmp:
                t = Path(tmp)
                # (a) ToastActivatorCLSID collides with Explorer COM CLSID
                a = t / "collide"
                _copy_lightweight_tree(root, a, m1_light_paths)
                man_a = a / "target-x86_64" / "Package.x64.appxmanifest"
                man_a.write_text(
                    man_a.read_text(encoding="utf-8").replace(
                        f'ToastActivatorCLSID="{TOAST_ACTIVATOR_CLSID.lower()}"',
                        f'ToastActivatorCLSID="{CANONICAL_CLSID.lower()}"',
                        1,
                    ),
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(a, "M3"), "T2-F19-05(collision)", ("collision",))

                # (b) ToastActivatorCLSID mismatches ExeServer/Class/@Id
                b = t / "mismatch"
                _copy_lightweight_tree(root, b, m1_light_paths)
                man_b = b / "target-x86_64" / "Package.x64.appxmanifest"
                man_b.write_text(
                    man_b.read_text(encoding="utf-8").replace(
                        f'ToastActivatorCLSID="{TOAST_ACTIVATOR_CLSID.lower()}"',
                        'ToastActivatorCLSID="11111111-2222-3333-4444-555555555555"',
                        1,
                    ),
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(b, "M3"), "T2-F19-05(mismatch)", ("mismatch",))
            return "Toast CLSID Explorer-collision and ExeServer/@Id mismatch mutations both caught"

        def t1_f21_01() -> str:
            check_m3_firewall_and_app_manifest(root)
            return "runFullTrust + Package-level FirewallRules (in/UDP/private/totaldrop-winui.exe) verified on x64 & arm64"

        def t1_f21_02() -> str:
            check_m3_firewall_and_app_manifest(root)
            return "app.manifest longPathAware=true, PerMonitorV2, true/PM & Win10/11 supportedOS verified"

        def t2_f21_04() -> str:
            check_m3_firewall_and_app_manifest(root)
            with tempfile.TemporaryDirectory(prefix="td-f21-04-") as tmp:
                t = Path(tmp)
                mutations = (
                    ("public", 'Profile="private"', 'Profile="public"', "public"),
                    ("all", 'Profile="private"', 'Profile="all"', "all"),
                    ("out", 'Direction="in"', 'Direction="out"', "out"),
                    ("tcp", 'IPProtocol="UDP"', 'IPProtocol="TCP"', "TCP"),
                    ("cmd", '<desktop2:FirewallRules Executable="totaldrop-winui.exe">', '<desktop2:FirewallRules Executable="cmd.exe">', "cmd.exe"),
                )
                for tag, old, new, tok in mutations:
                    d = t / tag
                    _copy_lightweight_tree(root, d, m1_light_paths)
                    man = d / "target-x86_64" / "Package.x64.appxmanifest"
                    txt = man.read_text(encoding="utf-8")
                    assert old in txt, f"{old} not found in Package.x64.appxmanifest"
                    man.write_text(txt.replace(old, new, 1), encoding="utf-8")
                    _expect_fail_proc(_run_self_on(d, "M3"), f"T2-F21-04({tag})", (tok,))
            return "all 5 over-scoped firewall rule mutations (public, all, out, TCP, cmd.exe) caught"

        def t3_12_part_b() -> str:
            check_m3_toast_activation(root)
            return "----AppNotificationActivated: manifest ExeServer + App/MainWindow foreground wiring verified"

        record("T1-F16-03-part-b", t1_f16_03_part_b)
        record("T1-F17-03", t1_f17_03)
        record("T1-F18-01-part-b", t1_f18_01_part_b)
        record("T2-F18-03-part-b", t2_f18_03_part_b)
        record("T1-F19-01", t1_f19_01)
        record("T1-F19-04-part-b", t1_f19_04_part_b)
        record("T2-F19-05", t2_f19_05)
        record("T1-F21-01", t1_f21_01)
        record("T1-F21-02", t1_f21_02)
        record("T2-F21-04", t2_f21_04)
        record("T3-12-part-b", t3_12_part_b)

    if milestone == "M4":
        m4_light_paths = m1_light_paths + ["tools/build-msixbundle.ps1"]

        def t1_f22_04() -> str:
            check_m4_release_and_arm64_workflows(root)
            with tempfile.TemporaryDirectory(prefix="td-f22-04-") as tmp:
                t = Path(tmp)
                # (a) mutable @v4 action pin
                a = t / "tag"
                _copy_lightweight_tree(root, a, m4_light_paths)
                wf_a = a / ".github" / "workflows" / "windows-release.yml"
                wf_a.write_text(
                    re.sub(r"actions/checkout@[0-9a-f]{40}", "actions/checkout@v4", wf_a.read_text(encoding="utf-8"), count=1),
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(a, "M4"), "T1-F22-04(a-pin)", ("@v4",))

                # (b) remove origin/main ancestry check
                b = t / "ancestry"
                _copy_lightweight_tree(root, b, m4_light_paths)
                wf_b = b / ".github" / "workflows" / "windows-release.yml"
                wf_b.write_text(
                    wf_b.read_text(encoding="utf-8").replace("git merge-base --is-ancestor", "# removed-ancestry-check"),
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(b, "M4"), "T1-F22-04(b-ancestry)", ("origin/main",))

                # (c) elevate top-level permissions to write-all & drop attest-build-provenance
                c = t / "perms"
                _copy_lightweight_tree(root, c, m4_light_paths)
                wf_c = c / ".github" / "workflows" / "windows-release.yml"
                wf_c.write_text(
                    wf_c.read_text(encoding="utf-8").replace("permissions:\n  contents: read", "permissions: write-all", 1),
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(c, "M4"), "T1-F22-04(c-perms)", ("write-all",))

                d = t / "attest"
                _copy_lightweight_tree(root, d, m4_light_paths)
                wf_d = d / ".github" / "workflows" / "windows-release.yml"
                wf_d.write_text(
                    re.sub(r"actions/attest-build-provenance@[0-9a-f]{40}", "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", wf_d.read_text(encoding="utf-8")),
                    encoding="utf-8",
                )
                _expect_fail_proc(_run_self_on(d, "M4"), "T1-F22-04(d-attest)", ("attest-build-provenance",))
            return "windows-release.yml, ci.yml ARM64 gate & pkg-msix-arm64.yml PASS; 4 workflow mutations caught"

        record("T1-F22-04", t1_f22_04)

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static contract, negative-mutation & anti-prod-probing verifier.")
    parser.add_argument("--milestone", choices=("M1", "M2", "M3", "M4"), default="M4")
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--run-tests", action="store_true", help="Run all static + negative-mutation test IDs.")
    parser.add_argument("--check-m2-ui-audit", action="store_true", help="Run M2 Send/Receive/Settings UI static audits.")
    parser.add_argument("--scan-no-prod-probing", action="store_true", help="Run TEST_INFRA.md section 3.3 scanner (+ E9/E10 self-test).")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.scan_no_prod_probing:
        try:
            self_test_prod_scanner()
        except Exception as exc:  # noqa: BLE001
            print(f"error: anti-production-probing self-test failed: {exc}", file=sys.stderr)
            return 1
        violations = scan_no_live_production_probing(args.root)
        if violations:
            for v in violations:
                print(f"error: {v}", file=sys.stderr)
            return 1
        print("anti-production-probing scanner OK: 0 live production probes found (E9/E10 self-test PASS)")
        return 0

    if args.check_m2_ui_audit:
        try:
            check_m2_ui_page_audits(args.root)
            print("M2 SendPage/ReceivePage/SettingsPage static audit OK")
            return 0
        except Exception as exc:  # noqa: BLE001
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.run_tests:
        results = run_test_suite(args.root, args.milestone)
        if args.json_out is not None:
            args.json_out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        failed = [k for k, v in results.items() if v["status"] != "PASS"]
        for k, v in sorted(results.items()):
            print(f"[{v['status']}] {k}: {v['detail']}")
        return 1 if failed else 0

    try:
        verify_all_static(args.root, args.milestone)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"verify_static_contracts OK ({args.milestone}): {args.root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
