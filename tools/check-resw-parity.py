#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Standalone 35-language .resw and manifest parity verifier for totaldrop-windows (ADR 0008).

Self-contained in totaldrop-windows so GitHub Actions CI can verify:
  1. All 35 canonical ARB catalogs + pt/zh fallbacks + l10n/status.json invariants
     (matching totaldrop-core/tools/l10n_codegen.py).
  2. Exact 36-file inventory and byte-for-byte parity between l10n/ and
     ui-winui3-fluent2/Strings/ (35 <tag>/Resources.resw + locales.json).
  3. Exact 35-language <Resource Language="..." /> parity (with "en" first)
     in Package.x64.appxmanifest and Package.arm64.appxmanifest.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import unicodedata
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_LOCALE = "en"

CANONICAL_LOCALES: tuple[tuple[str, str], ...] = (
    ("ar", "العربية"),
    ("bn", "বাংলা"),
    ("cs", "Čeština"),
    ("da", "Dansk"),
    ("de", "Deutsch"),
    ("el", "Ελληνικά"),
    ("en", "English"),
    ("es", "Español"),
    ("fa", "فارسی"),
    ("fi", "Suomi"),
    ("fr", "Français"),
    ("he", "עברית"),
    ("hi", "हिन्दी"),
    ("hu", "Magyar"),
    ("id", "Bahasa Indonesia"),
    ("it", "Italiano"),
    ("ja", "日本語"),
    ("ko", "한국어"),
    ("ms", "Bahasa Melayu"),
    ("nb", "Norsk bokmål"),
    ("nl", "Nederlands"),
    ("pl", "Polski"),
    ("pt-BR", "Português (Brasil)"),
    ("pt-PT", "Português (Portugal)"),
    ("ro", "Română"),
    ("ru", "Русский"),
    ("sv", "Svenska"),
    ("sw", "Kiswahili"),
    ("th", "ไทย"),
    ("tr", "Türkçe"),
    ("uk", "Українська"),
    ("ur", "اردو"),
    ("vi", "Tiếng Việt"),
    ("zh-Hans", "简体中文"),
    ("zh-Hant", "繁體中文"),
)

CANONICAL_TAGS: tuple[str, ...] = tuple(tag for tag, _ in CANONICAL_LOCALES)
RTL_LOCALES: frozenset[str] = frozenset({"ar", "fa", "he", "ur"})
BASE_FALLBACK_LOCALES: tuple[str, ...] = ("pt", "zh")
ENGLISH_NO_WORDS: frozenset[str] = frozenset({"n", "no", "not"})
CRITICAL_PLACEHOLDERS: frozenset[str] = frozenset({"code", "words", "folder", "name"})
MARKUP_RE = re.compile(r"<[A-Za-z/!]")


def is_forbidden_char(ch: str) -> bool:
    if ch in ("\n", "\u200C", "\u200D", "\u200E", "\u200F"):
        return False
    cp = ord(ch)
    if 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE:
        return True
    return unicodedata.category(ch) in ("Cc", "Cf", "Zl", "Zp")


def _find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def extract_placeholders(message: str) -> set[str]:
    found: set[str] = set()
    n = len(message)
    i = 0
    while i < n:
        if message[i] == "{":
            close_idx = _find_matching_brace(message, i)
            if close_idx == -1:
                break
            inner = message[i + 1 : close_idx]
            parts = inner.split(",", 2)
            ident = parts[0].strip()
            if ident and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ident):
                found.add(ident)
            if len(parts) == 3 and parts[1].strip() in ("plural", "select", "selectordinal"):
                body = parts[2]
                bi = 0
                bn = len(body)
                while bi < bn:
                    sub_open = body.find("{", bi)
                    if sub_open == -1:
                        break
                    sub_close = _find_matching_brace(body, sub_open)
                    if sub_close == -1:
                        break
                    found |= extract_placeholders(body[sub_open + 1 : sub_close])
                    bi = sub_close + 1
            i = close_idx + 1
            continue
        i += 1
    return found


def parse_json_no_duplicates(raw_text: str, label: str) -> dict[str, Any]:
    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in pairs:
            if k in out:
                raise ValueError(f"{label}: duplicate JSON key `{k}`")
            out[k] = v
        return out

    parsed = json.loads(raw_text, object_pairs_hook=hook)
    if not isinstance(parsed, dict):
        raise ValueError(f"{label}: top-level JSON value must be an object")
    return parsed


def arb_filename_for_locale(domain: str, tag: str) -> str:
    return f"{domain}_{tag.replace('-', '_')}.arb"


class CatalogBundle:
    def __init__(
        self,
        status: dict[str, Any],
        app_catalogs: dict[str, dict[str, str]],
        app_meta: dict[str, dict[str, Any]],
        cli_catalogs: dict[str, dict[str, str]],
    ) -> None:
        self.status = status
        self.app_catalogs = app_catalogs
        self.app_meta = app_meta
        self.cli_catalogs = cli_catalogs
        self.critical_keys: set[str] = set(status.get("critical", []))
        self.languages_meta: dict[str, dict[str, Any]] = status.get("languages", {})

    def is_reviewed(self, tag: str) -> bool:
        if tag == TEMPLATE_LOCALE:
            return True
        return bool(self.languages_meta.get(tag, {}).get("reviewed", False))

    def draft_keys(self, tag: str) -> set[str]:
        if tag == TEMPLATE_LOCALE:
            return set()
        return set(self.languages_meta.get(tag, {}).get("draft", []))

    def direction(self, tag: str) -> str:
        return "rtl" if tag in RTL_LOCALES else "ltr"

    def effective_app_strings(self, tag: str) -> dict[str, str]:
        en_map = self.app_catalogs[TEMPLATE_LOCALE]
        if tag == TEMPLATE_LOCALE:
            return dict(sorted(en_map.items()))
        loc_map = self.app_catalogs[tag]
        base_tag = tag.split("-", 1)[0] if "-" in tag else None
        base_map = self.app_catalogs.get(base_tag, {}) if base_tag else {}
        reviewed = self.is_reviewed(tag)
        drafts = self.draft_keys(tag)

        resolved: dict[str, str] = {}
        for key in sorted(en_map):
            if key in self.critical_keys and (not reviewed or key in drafts):
                resolved[key] = en_map[key]
            elif key in loc_map:
                resolved[key] = loc_map[key]
            elif key in base_map:
                resolved[key] = base_map[key]
            else:
                resolved[key] = en_map[key]
        return resolved


def load_and_validate(l10n_dir: Path) -> tuple[CatalogBundle | None, list[str]]:
    errors: list[str] = []
    status_path = l10n_dir / "status.json"
    if not status_path.is_file():
        return None, [f"missing status file: {status_path}"]

    try:
        status = parse_json_no_duplicates(
            status_path.read_text(encoding="utf-8"), "status.json"
        )
    except Exception as exc:  # noqa: BLE001
        return None, [f"invalid status.json: {exc}"]

    critical_list = status.get("critical")
    languages_meta = status.get("languages")
    if (
        not isinstance(critical_list, list)
        or not critical_list
        or not all(isinstance(k, str) and k.strip() for k in critical_list)
    ):
        errors.append("status.json: `critical` must be a non-empty list of strings")
        critical_list = []
    if not isinstance(languages_meta, dict):
        errors.append("status.json: `languages` must be a JSON object")
        languages_meta = {}

    expected_all_locales = list(CANONICAL_TAGS) + list(BASE_FALLBACK_LOCALES)
    domain_maps: dict[str, dict[str, dict[str, str]]] = {"app": {}, "cli": {}}
    app_template_meta: dict[str, dict[str, Any]] = {}

    for domain in ("app", "cli"):
        domain_dir = l10n_dir / domain
        if not domain_dir.is_dir():
            errors.append(f"missing domain directory: {domain_dir}")
            continue
        for tag in expected_all_locales:
            arb_path = domain_dir / arb_filename_for_locale(domain, tag)
            if not arb_path.is_file():
                errors.append(f"missing ARB catalog: {arb_path}")
                continue
            try:
                obj = parse_json_no_duplicates(
                    arb_path.read_text(encoding="utf-8"), f"{domain}/{arb_path.name}"
                )
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))
                continue

            declared_locale = str(obj.get("@@locale", "")).replace("_", "-")
            if declared_locale != tag:
                errors.append(
                    f"{domain}/{arb_path.name}: @@locale `{declared_locale}` != `{tag}`"
                )

            messages: dict[str, str] = {}
            for key, val in obj.items():
                if key.startswith("@"):
                    if (
                        domain == "app"
                        and tag == TEMPLATE_LOCALE
                        and key != "@@locale"
                        and isinstance(val, dict)
                    ):
                        app_template_meta[key[1:]] = val
                    continue
                if not isinstance(val, str):
                    errors.append(
                        f"{domain}/{tag} `{key}`: value must be string, got {type(val).__name__}"
                    )
                    continue
                messages[key] = val
            domain_maps[domain][tag] = messages

    for tag in expected_all_locales:
        if tag == TEMPLATE_LOCALE:
            continue
        if tag not in languages_meta:
            errors.append(f"status.json: missing language entry `{tag}`")
            continue
        entry = languages_meta[tag]
        if not isinstance(entry.get("reviewed"), bool):
            errors.append(f"status.json `{tag}`: `reviewed` must be a boolean")
        if not isinstance(entry.get("draft"), list):
            errors.append(f"status.json `{tag}`: `draft` must be a list")
        no_words_raw = entry.get("noWords", "")
        if not isinstance(no_words_raw, str) or not no_words_raw.strip():
            errors.append(f"status.json `{tag}`: `noWords` must be a non-empty string")
        else:
            no_tokens = {
                w.strip().casefold() for w in no_words_raw.split("|") if w.strip()
            } | ENGLISH_NO_WORDS
            cli_yes_raw = domain_maps["cli"].get(tag, {}).get("cliYes", "")
            yes_tokens = {
                w.strip().casefold() for w in cli_yes_raw.split("|") if w.strip()
            }
            overlap = sorted(no_tokens & yes_tokens)
            if overlap:
                errors.append(
                    f"cli/{tag} `cliYes`: overlaps with `noWords`: {', '.join(overlap)}"
                )

    for domain in ("app", "cli"):
        template = domain_maps[domain].get(TEMPLATE_LOCALE)
        if not template:
            errors.append(f"{domain}: missing `{TEMPLATE_LOCALE}` template catalog")
            continue
        template_placeholders = {k: extract_placeholders(v) for k, v in template.items()}
        for tag, msg_map in sorted(domain_maps[domain].items()):
            for key, text in sorted(msg_map.items()):
                if key not in template:
                    errors.append(f"{domain}/{tag} `{key}`: unknown key not in template")
                    continue
                for ch in text:
                    if is_forbidden_char(ch):
                        errors.append(
                            f"{domain}/{tag} `{key}`: forbidden control/bidi char U+{ord(ch):04X}"
                        )
                        break
                if MARKUP_RE.search(text) and not MARKUP_RE.search(template[key]):
                    errors.append(f"{domain}/{tag} `{key}`: unexpected HTML/XML markup tag")
                expected_ph = template_placeholders[key]
                actual_ph = extract_placeholders(text)
                if actual_ph != expected_ph:
                    errors.append(
                        f"{domain}/{tag} `{key}`: placeholder mismatch "
                        f"(expected {sorted(expected_ph)}, got {sorted(actual_ph)})"
                    )
                for crit_ph in CRITICAL_PLACEHOLDERS & expected_ph:
                    if f"{{{crit_ph}}}" not in text:
                        errors.append(
                            f"{domain}/{tag} `{key}`: missing literal critical placeholder `{{{crit_ph}}}`"
                        )

    all_en_keys = set(domain_maps["app"].get(TEMPLATE_LOCALE, {})) | set(
        domain_maps["cli"].get(TEMPLATE_LOCALE, {})
    )
    for crit_key in critical_list:
        if crit_key not in all_en_keys:
            errors.append(f"status.json: critical key `{crit_key}` missing from English templates")

    if errors:
        return None, errors
    return (
        CatalogBundle(
            status=status,
            app_catalogs=domain_maps["app"],
            app_meta=app_template_meta,
            cli_catalogs=domain_maps["cli"],
        ),
        [],
    )


def render_winui_resw(strings: dict[str, str], descriptions: dict[str, dict[str, Any]]) -> str:
    """Render deterministic MRT Core `.resw` XML matching totaldrop-core/tools/l10n_codegen.py."""
    # Split SPDX template tokens so fsfe/reuse lint does not attribute MIT OR Apache-2.0 to this GPL script.
    spdx_copy = "SPDX-File" + "CopyrightText: 2026 The TotalDrop Contributors"
    spdx_lic = "SPDX-License-" + "Identifier: MIT OR Apache-2.0"
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        f"<!-- {spdx_copy} -->",
        f"<!-- {spdx_lic} -->",
        "<root>",
        '  <resheader name="resmimetype">',
        "    <value>text/microsoft-resx</value>",
        "  </resheader>",
        '  <resheader name="version">',
        "    <value>2.0</value>",
        "  </resheader>",
        '  <resheader name="reader">',
        "    <value>System.Resources.ResXResourceReader, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>",
        "  </resheader>",
        '  <resheader name="writer">',
        "    <value>System.Resources.ResXResourceWriter, System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089</value>",
        "  </resheader>",
    ]
    for key in sorted(strings):
        val = xml_escape(strings[key])
        desc = descriptions.get(key, {}).get("description")
        lines.append(f'  <data name="{xml_escape(key)}" xml:space="preserve">')
        lines.append(f"    <value>{val}</value>")
        if isinstance(desc, str) and desc.strip():
            lines.append(f"    <comment>{xml_escape(desc.strip())}</comment>")
        lines.append("  </data>")
    lines.append("</root>")
    return "\n".join(lines) + "\n"


def render_expected_strings_tree(bundle: CatalogBundle) -> dict[str, bytes]:
    expected: dict[str, bytes] = {}
    manifest_locales = []
    for tag, autonym in CANONICAL_LOCALES:
        effective = bundle.effective_app_strings(tag)
        xml_text = render_winui_resw(effective, bundle.app_meta)
        ET.fromstring(xml_text)
        expected[f"{tag}/Resources.resw"] = xml_text.encode("utf-8")
        manifest_locales.append(
            {
                "tag": tag,
                "autonym": autonym,
                "dir": bundle.direction(tag),
                "reviewed": bundle.is_reviewed(tag),
                "keyCount": len(effective),
            }
        )
    manifest = {
        "defaultLocale": TEMPLATE_LOCALE,
        "localeCount": len(CANONICAL_LOCALES),
        "locales": manifest_locales,
    }
    expected["locales.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(
        "utf-8"
    )
    return expected


def check_manifest_resources(errors: list[str]) -> None:
    appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
    expected_set = set(CANONICAL_TAGS)
    for rel in (
        "target-x86_64/Package.x64.appxmanifest",
        "target-arm64/Package.arm64.appxmanifest",
    ):
        root = ET.fromstring((REPO_ROOT / rel).read_text(encoding="utf-8"))
        res_nodes = root.findall(f"{appx_ns}Resources/{appx_ns}Resource")
        langs = [node.attrib.get("Language", "") for node in res_nodes]
        if not langs:
            errors.append(f"{rel}: <Resources> declares zero <Resource Language> entries")
            continue
        if langs[0] != TEMPLATE_LOCALE:
            errors.append(
                f"{rel}: first <Resource Language> must be {TEMPLATE_LOCALE!r} (matching Strings/en), got {langs[0]!r}"
            )
        if len(langs) != len(set(langs)):
            errors.append(f"{rel}: duplicate <Resource Language> entries")
        if set(langs) != expected_set:
            missing = sorted(expected_set - set(langs))
            extra = sorted(set(langs) - expected_set)
            errors.append(
                f"{rel}: <Resources> mismatch (missing={missing}, extra={extra})"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify 35-language l10n ARB -> WinUI .resw and AppxManifest parity."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        default=True,
        help="Validate l10n/, Strings/ byte-for-byte parity, and Package.*.appxmanifest Resources.",
    )
    parser.add_argument(
        "--l10n-dir",
        type=Path,
        default=REPO_ROOT / "l10n",
        help="Path to l10n directory.",
    )
    parser.add_argument(
        "--strings-dir",
        type=Path,
        default=REPO_ROOT / "ui-winui3-fluent2" / "Strings",
        help="Path to WinUI Strings directory.",
    )
    args = parser.parse_args(argv)

    bundle, errors = load_and_validate(args.l10n_dir)
    if errors or bundle is None:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return 1

    expected = render_expected_strings_tree(bundle)
    if not args.strings_dir.is_dir():
        print(f"error: missing Strings directory: {args.strings_dir}", file=sys.stderr)
        return 1

    actual_paths = {
        p.relative_to(args.strings_dir).as_posix()
        for p in args.strings_dir.rglob("*")
        if p.is_file()
    }
    parity_errors: list[str] = []
    missing = sorted(set(expected) - actual_paths)
    extra = sorted(actual_paths - set(expected))
    if missing:
        parity_errors.append(f"Strings/ missing files: {missing}")
    if extra:
        parity_errors.append(f"Strings/ unexpected extra files: {extra}")

    for rel, expected_bytes in sorted(expected.items()):
        actual_path = args.strings_dir / rel
        if not actual_path.is_file():
            continue
        actual_bytes = actual_path.read_bytes()
        if actual_bytes != expected_bytes:
            parity_errors.append(f"Strings/{rel}: content drifted from l10n/ source catalog")

    check_manifest_resources(parity_errors)

    if parity_errors:
        for err in parity_errors:
            print(f"error: {err}", file=sys.stderr)
        return 1

    print(
        f"resw-parity check OK: {len(CANONICAL_TAGS)} locales + locales.json ({len(expected)} files) "
        f"byte-exact with l10n/ and matched in Package.{{x64,arm64}}.appxmanifest."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
