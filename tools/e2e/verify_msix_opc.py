#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Pure-Python stdlib OPC/ZIP MSIX, bundle, upload, resources.pri & subplatform oracle.

Implements TEST_INFRA.md section 5.2 and cross-platform/windows-ci checks for
T1-F04-03..05, T2-F04-04..05, T1-F06-04..05, T2-F06-01..04,
T1-F22-03, T1-F22-05, T2-F22-01, T2-F22-02, T2-F22-04, and T2-F22-05.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import warnings
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CANONICAL_35_LOCALES: tuple[str, ...] = (
    "ar", "bn", "cs", "da", "de", "el", "en", "es", "fa", "fi",
    "fr", "he", "hi", "hu", "id", "it", "ja", "ko", "ms", "nb",
    "nl", "pl", "pt-BR", "pt-PT", "ro", "ru", "sv", "sw", "th", "tr",
    "uk", "ur", "vi", "zh-Hans", "zh-Hant",
)

REQUIRED_PRI_RESOURCE_KEYS: tuple[str, ...] = (
    "appTagline",
    "sendTitle",
    "receiveTitle",
    "desktopSendWith",
    "keepAwakeReason",
)


def resolve_recipe_artifact_name(repo_root: Path, arch: str = "x86_64") -> tuple[str, str]:
    """Read artifact_name and expected MSIX version from subplatforms/msix/<arch>/RECIPE.toml."""
    recipe_arch = "x86_64" if arch in ("x64", "x86_64") else "arm64"
    recipe_path = repo_root / "subplatforms" / "msix" / recipe_arch / "RECIPE.toml"
    data = tomllib.loads(recipe_path.read_text(encoding="utf-8"))
    artifact_name = data.get("artifact_name")
    if not isinstance(artifact_name, str) or not artifact_name.endswith(".msix"):
        raise ValueError(f"{recipe_path}: invalid or missing artifact_name: {artifact_name!r}")
    parts = artifact_name.split("_")
    msix_version = parts[1] if len(parts) >= 3 else "0.1.1.0"
    return artifact_name, msix_version


def verify_pri_bytes(pri_data: bytes, label: str = "resources.pri") -> None:
    if len(pri_data) <= 4096:
        raise ValueError(f"{label}: undersized PRI ({len(pri_data)} bytes <= 4096)")
    if pri_data[:8] != b"mrm_pri2":
        raise ValueError(f"{label}: invalid PRI magic {pri_data[:8]!r} (expected b'mrm_pri2')")


def verify_pri_file(pri_path: Path) -> None:
    if not pri_path.is_file():
        raise ValueError(f"missing PRI file: {pri_path}")
    verify_pri_bytes(pri_path.read_bytes(), label=pri_path.name)


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
    raise RuntimeError("POSIX sh executable not found on PATH or Git for Windows")


def _local_tag(el: ET.Element) -> str:
    return el.tag.split("}", 1)[-1]


def _extract_candidate_qualifiers(
    cand: ET.Element,
    qualifier_sets: dict[str, list[tuple[str, str]]],
) -> list[tuple[str, str]]:
    """Parse qualifier (name, value) pairs from inline qualifiers=, child <Qualifier>, and qualifierSet=."""
    pairs: list[tuple[str, str]] = []
    quals_raw = cand.attrib.get("qualifiers", "").strip()
    if quals_raw:
        for part in re.split(r"[;,]", quals_raw):
            token = part.strip()
            if not token:
                continue
            kv = re.split(r"[=-]", token, maxsplit=1)
            if len(kv) != 2:
                continue
            k, v = kv[0].strip(), kv[1].strip()
            if k and v:
                pairs.append((k, v))
    for child in cand:
        child_tag = _local_tag(child)
        if child_tag == "Qualifier":
            qname = child.attrib.get("name", "").strip()
            qval = child.attrib.get("value", "").strip()
            if qname and qval:
                pairs.append((qname, qval))
        elif child_tag == "QualifierSet":
            found_inline_q = False
            for q in child:
                if _local_tag(q) == "Qualifier":
                    qname = q.attrib.get("name", "").strip()
                    qval = q.attrib.get("value", "").strip()
                    if qname and qval:
                        pairs.append((qname, qval))
                        found_inline_q = True
            if not found_inline_q:
                qidx = child.attrib.get("index", "").strip()
                if qidx and qidx in qualifier_sets:
                    pairs.extend(qualifier_sets[qidx])
    qset_ref = cand.attrib.get("qualifierSet", "").strip()
    if qset_ref and qset_ref in qualifier_sets:
        pairs.extend(qualifier_sets[qset_ref])
    return pairs


def verify_pri_dump(pri_xml_path: Path) -> None:
    """Verify MakePri.exe XML dump contains all 35 BCP-47 languages and Kose asset qualifiers."""
    if not pri_xml_path.is_file():
        raise ValueError(f"missing pri.xml dump: {pri_xml_path}")
    tree = ET.parse(pri_xml_path)
    root = tree.getroot()

    # Index /dt detailed <QualifierSet index="..."><Qualifier name="..." value="..."/></QualifierSet>
    qualifier_sets: dict[str, list[tuple[str, str]]] = {}
    for el in root.iter():
        if _local_tag(el) != "QualifierSet":
            continue
        qidx = el.attrib.get("index", "").strip()
        if not qidx:
            continue
        qpairs: list[tuple[str, str]] = []
        for child in el:
            if _local_tag(child) == "Qualifier":
                qname = child.attrib.get("name", "").strip()
                qval = child.attrib.get("value", "").strip()
                if qname and qval:
                    qpairs.append((qname, qval))
        if qpairs:
            qualifier_sets[qidx] = qpairs

    # Collect language qualifiers per (subtree_full_path, raw_normalized_name) and globally.
    lang_by_resource_path: dict[tuple[str, str], set[str]] = {}
    all_langs: set[str] = set()
    square44_quals: set[str] = set()
    square44_sizes_by_altform: dict[str, set[str]] = {"UNPLATED": set(), "LIGHTUNPLATED": set()}
    asset_scales: set[str] = set()
    asset_targetsizes: set[str] = set()

    def _walk_pri(elem: ET.Element, subtree_prefix: str) -> None:
        tag = _local_tag(elem)
        if tag == "ResourceMapSubtree":
            sub_name = elem.attrib.get("name", "").strip().replace("\\", "/").strip("/")
            next_prefix = f"{subtree_prefix}/{sub_name}" if (subtree_prefix and sub_name) else (sub_name or subtree_prefix)
            for child in elem:
                _walk_pri(child, next_prefix)
            return
        if tag == "NamedResource":
            name = elem.attrib.get("name", "").strip()
            if not name:
                return
            norm_name = name.replace("\\", "/")
            full_path = f"{subtree_prefix}/{norm_name}" if subtree_prefix else norm_name
            leaf = norm_name.rsplit("/", 1)[-1]
            is_square44 = leaf.lower() == "square44x44logo.png"
            langs: set[str] = set()
            for cand in elem:
                if _local_tag(cand) != "Candidate":
                    continue
                cand_ts: set[str] = set()
                cand_alts: set[str] = set()
                for k, v_clean in _extract_candidate_qualifiers(cand, qualifier_sets):
                    k_up = k.upper()
                    if k_up == "LANGUAGE":
                        langs.add(v_clean.lower())
                        all_langs.add(v_clean.lower())
                    elif k_up == "SCALE":
                        asset_scales.add(v_clean)
                    elif k_up == "TARGETSIZE":
                        asset_targetsizes.add(v_clean)
                        cand_ts.add(v_clean)
                    elif k_up in ("ALTERNATEFORM", "ALTFORM"):
                        if is_square44:
                            v_up = v_clean.upper()
                            if v_up in ("UNPLATED", "LIGHTUNPLATED"):
                                square44_quals.add(v_up)
                                cand_alts.add(v_up)
                if is_square44 and cand_ts and cand_alts:
                    for alt in cand_alts:
                        square44_sizes_by_altform[alt].update(cand_ts)
            lang_by_resource_path.setdefault((full_path, norm_name), set()).update(langs)
            return
        for child in elem:
            _walk_pri(child, subtree_prefix)

    _walk_pri(root, "")

    expected_lower = {tag.lower(): tag for tag in CANONICAL_35_LOCALES}
    expected_set = set(expected_lower)
    missing_global = [orig for low, orig in sorted(expected_lower.items()) if low not in all_langs]
    if missing_global:
        present_count = len(expected_lower) - len(missing_global)
        raise ValueError(
            f"pri.xml language count mismatch ({present_count} != 35); missing: {missing_global}"
        )

    for key in REQUIRED_PRI_RESOURCE_KEYS:
        key_candidates: list[tuple[int, int, set[str]]] = []
        for (full_path, raw_norm), r_langs in lang_by_resource_path.items():
            if raw_norm != key and not raw_norm.endswith(f"/{key}"):
                continue
            low_raw = raw_norm.lower()
            low_full = full_path.lower()
            is_resources_scope = (
                low_raw == f"resources/{key.lower()}"
                or low_full == f"resources/{key.lower()}"
                or low_full.endswith(f"/resources/{key.lower()}")
                or low_raw == key.lower()
            )
            priority = 2 if is_resources_scope else 1
            coverage = len(r_langs & expected_set)
            key_candidates.append((priority, coverage, r_langs))
        if not key_candidates:
            raise ValueError(f"pri.xml missing expected NamedResource key: {key}")
        key_candidates.sort(key=lambda item: (item[1] == len(expected_set), item[0], item[1]), reverse=True)
        key_langs = key_candidates[0][2]
        missing_key = [orig for low, orig in sorted(expected_lower.items()) if low not in key_langs]
        if missing_key:
            raise ValueError(
                f"pri.xml key {key!r} missing languages ({35 - len(missing_key)} != 35): {missing_key}"
            )

    missing_scales = [s for s in ("100", "125", "150", "200", "400") if s not in asset_scales]
    if missing_scales:
        raise ValueError(f"pri.xml missing Scale asset candidates: {missing_scales}")
    required_ts = ("16", "24", "32", "48", "256")
    missing_ts = [s for s in required_ts if s not in asset_targetsizes]
    if missing_ts:
        raise ValueError(f"pri.xml missing TargetSize asset candidates: {missing_ts}")
    for alt in ("UNPLATED", "LIGHTUNPLATED"):
        if alt not in square44_quals:
            raise ValueError(f"pri.xml Square44x44Logo.png missing AlternateForm={alt}")
        missing_alt_ts = [s for s in required_ts if s not in square44_sizes_by_altform[alt]]
        if missing_alt_ts:
            raise ValueError(
                f"pri.xml Square44x44Logo.png AlternateForm={alt} missing TargetSize candidates: {missing_alt_ts}"
            )


def _build_realistic_makepri_xml(
    locales: tuple[str, ...],
    *,
    include_unplated: bool = True,
    include_lightunplated: bool = True,
    unplated_sizes: tuple[str, ...] = ("16", "24", "32", "48", "256"),
    lightunplated_sizes: tuple[str, ...] = ("16", "24", "32", "48", "256"),
    use_qualifier_sets_only: bool = False,
) -> str:
    """Construct realistic Windows SDK MakePri.exe dump XML (hyphen + comma qualifiers)."""
    qset_lines: list[str] = []
    res_lines: list[str] = []
    next_qset = 1

    if use_qualifier_sets_only:
        lang_qset_ids: dict[str, int] = {}
        for loc in locales:
            qidx = next_qset
            next_qset += 1
            lang_qset_ids[loc] = qidx
            qset_lines.append(
                f'      <QualifierSet index="{qidx}">'
                f'<Qualifier name="Language" value="{loc.upper()}"/>'
                f"</QualifierSet>"
            )
        scale_qset_ids: dict[str, int] = {}
        for sc in ("100", "125", "150", "200", "400"):
            qidx = next_qset
            next_qset += 1
            scale_qset_ids[sc] = qidx
            qset_lines.append(
                f'      <QualifierSet index="{qidx}">'
                f'<Qualifier name="Scale" value="{sc}"/>'
                f"</QualifierSet>"
            )
        ts_qset_ids: list[tuple[str, int]] = []
        for ts in ("16", "24", "32", "48", "256"):
            if include_unplated:
                qidx = next_qset
                next_qset += 1
                ts_qset_ids.append((f"unplated-{ts}", qidx))
                qset_lines.append(
                    f'      <QualifierSet index="{qidx}">'
                    f'<Qualifier name="TargetSize" value="{ts}"/>'
                    f'<Qualifier name="AlternateForm" value="UNPLATED"/>'
                    f"</QualifierSet>"
                )
            if include_lightunplated:
                qidx = next_qset
                next_qset += 1
                ts_qset_ids.append((f"light-{ts}", qidx))
                qset_lines.append(
                    f'      <QualifierSet index="{qidx}">'
                    f'<Qualifier name="TargetSize" value="{ts}"/>'
                    f'<Qualifier name="AlternateForm" value="LIGHTUNPLATED"/>'
                    f"</QualifierSet>"
                )
        for key in REQUIRED_PRI_RESOURCE_KEYS:
            cands = "".join(
                f'<Candidate qualifierSet="{lang_qset_ids[loc]}" type="String"><Value>{key}-{loc}</Value></Candidate>'
                for loc in locales
            )
            res_lines.append(f'      <NamedResource name="{key}">{cands}</NamedResource>')
        sq_cands = [
            f'<Candidate qualifierSet="{scale_qset_ids[sc]}" type="Path"><Value>Assets\\Square44x44Logo.scale-{sc}.png</Value></Candidate>'
            for sc in ("100", "125", "150", "200", "400")
        ]
        sq_cands.extend(
            f'<Candidate qualifierSet="{qidx}" type="Path"><Value>Assets\\Square44x44Logo.{label}.png</Value></Candidate>'
            for label, qidx in ts_qset_ids
        )
        res_lines.append(f'      <NamedResource name="Assets\\Square44x44Logo.png">{"".join(sq_cands)}</NamedResource>')
        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            "<PriInfo>\n"
            "  <ResourceMap name=\"TotalDrop.TotalDrop\">\n"
            "    <DecisionInfo>\n"
            + "\n".join(qset_lines)
            + "\n    </DecisionInfo>\n"
            "    <ResourceMapSubtree name=\"Resources\">\n"
            + "\n".join(res_lines)
            + "\n    </ResourceMapSubtree>\n"
            "  </ResourceMap>\n"
            "</PriInfo>\n"
        )

    for key in REQUIRED_PRI_RESOURCE_KEYS:
        cands = "".join(
            f'<Candidate qualifiers="Language-{loc.upper()}" type="String"><Value>{key}-{loc}</Value></Candidate>'
            for loc in locales
        )
        res_lines.append(f'      <NamedResource name="{key}">{cands}</NamedResource>')

    sq_cands = [
        f'<Candidate qualifiers="Scale-{sc}" type="Path"><Value>Assets\\Square44x44Logo.scale-{sc}.png</Value></Candidate>'
        for sc in ("100", "125", "150", "200", "400")
    ]
    if include_unplated:
        for ts in unplated_sizes:
            sq_cands.append(
                f'<Candidate qualifiers="TargetSize-{ts}, AlternateForm-UNPLATED" type="Path">'
                f"<Value>Assets\\Square44x44Logo.targetsize-{ts}_altform-unplated.png</Value></Candidate>"
            )
    if include_lightunplated:
        for ts in lightunplated_sizes:
            sq_cands.append(
                f'<Candidate qualifiers="TargetSize-{ts}, AlternateForm-LIGHTUNPLATED" type="Path">'
                f"<Value>Assets\\Square44x44Logo.targetsize-{ts}_altform-lightunplated.png</Value></Candidate>"
            )
    res_lines.append(f'      <NamedResource name="Assets\\Square44x44Logo.png">{"".join(sq_cands)}</NamedResource>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        "<PriInfo>\n"
        "  <ResourceMap name=\"TotalDrop.TotalDrop\">\n"
        "    <ResourceMapSubtree name=\"Resources\">\n"
        + "\n".join(res_lines)
        + "\n    </ResourceMapSubtree>\n"
        "  </ResourceMap>\n"
        "</PriInfo>\n"
    )


def self_test_pri_dump() -> str:
    """Self-test verify_pri_dump() against realistic Windows SDK MakePri.exe dump formats."""
    with tempfile.TemporaryDirectory(prefix="td-pri-selftest-") as tmp:
        tmp_dir = Path(tmp)

        # (a) 35-locale realistic MakePri dump (Language-EN, Language-ZH-HANT, Scale-100,
        #     TargetSize-16, AlternateForm-UNPLATED / LIGHTUNPLATED) -> PASS
        p_ok = tmp_dir / "pri_35_ok.xml"
        p_ok.write_text(_build_realistic_makepri_xml(CANONICAL_35_LOCALES), encoding="utf-8")
        verify_pri_dump(p_ok)

        # (b) Missing zh-Hant (34 != 35) -> FAIL naming BOTH '34 != 35' and 'zh-Hant'
        locales_34 = tuple(loc for loc in CANONICAL_35_LOCALES if loc != "zh-Hant")
        p_34 = tmp_dir / "pri_34_missing_zhhant.xml"
        p_34.write_text(_build_realistic_makepri_xml(locales_34), encoding="utf-8")
        try:
            verify_pri_dump(p_34)
        except ValueError as exc:
            msg = str(exc)
            if "34 != 35" not in msg or "zh-Hant" not in msg:
                raise AssertionError(f"missing zh-Hant error lacked '34 != 35' or 'zh-Hant': {msg}") from exc
        else:
            raise AssertionError("34-locale MakePri dump missing zh-Hant unexpectedly passed!")

        # (c) Missing dark AlternateForm-UNPLATED (only AlternateForm-LIGHTUNPLATED present) -> FAIL
        p_no_unplated = tmp_dir / "pri_missing_unplated.xml"
        p_no_unplated.write_text(
            _build_realistic_makepri_xml(
                CANONICAL_35_LOCALES,
                include_unplated=False,
                include_lightunplated=True,
            ),
            encoding="utf-8",
        )
        try:
            verify_pri_dump(p_no_unplated)
        except ValueError as exc:
            msg = str(exc)
            if "AlternateForm=UNPLATED" not in msg:
                raise AssertionError(f"missing UNPLATED error lacked 'AlternateForm=UNPLATED': {msg}") from exc
        else:
            raise AssertionError("MakePri dump with LIGHTUNPLATED only (no UNPLATED) unexpectedly passed!")

        # (d) /dt detailed <QualifierSet> references without inline qualifiers= -> PASS
        p_qset = tmp_dir / "pri_qset_detailed.xml"
        p_qset.write_text(
            _build_realistic_makepri_xml(CANONICAL_35_LOCALES, use_qualifier_sets_only=True),
            encoding="utf-8",
        )
        verify_pri_dump(p_qset)

        # (e) E13 regression guard: UNPLATED has only TargetSize-256 while LIGHTUNPLATED has all 5 -> FAIL
        p_e13 = tmp_dir / "pri_e13_partial_unplated.xml"
        p_e13.write_text(
            _build_realistic_makepri_xml(
                CANONICAL_35_LOCALES,
                unplated_sizes=("256",),
                lightunplated_sizes=("16", "24", "32", "48", "256"),
            ),
            encoding="utf-8",
        )
        try:
            verify_pri_dump(p_e13)
        except ValueError as exc:
            msg = str(exc)
            if "AlternateForm=UNPLATED" not in msg or "['16', '24', '32', '48']" not in msg:
                raise AssertionError(
                    f"E13 partial UNPLATED error lacked AlternateForm=UNPLATED or missing sizes: {msg}"
                ) from exc
        else:
            raise AssertionError("E13 partial UNPLATED (256 only while LIGHTUNPLATED has all 5) unexpectedly passed!")

        # (f) Tier-5 (R2-C2-F5): FakeSquare44x44LogoJunk.txt substring spoof must NOT satisfy Square44x44Logo.png -> FAIL
        p_spoof = tmp_dir / "pri_r2_sq44_spoof.xml"
        base_no_unplated = _build_realistic_makepri_xml(
            CANONICAL_35_LOCALES,
            include_unplated=False,
            include_lightunplated=False,
        )
        fake_cands = "".join(
            f'<Candidate qualifiers="TargetSize-{ts}, AlternateForm-{alt}" type="Path"><Value>junk.txt</Value></Candidate>'
            for alt in ("UNPLATED", "LIGHTUNPLATED")
            for ts in ("16", "24", "32", "48", "256")
        )
        spoof_xml = base_no_unplated.replace(
            "</ResourceMapSubtree>",
            f'      <NamedResource name="FakeSquare44x44LogoJunk.txt">{fake_cands}</NamedResource>\n    </ResourceMapSubtree>',
            1,
        )
        p_spoof.write_text(spoof_xml, encoding="utf-8")
        try:
            verify_pri_dump(p_spoof)
        except ValueError as exc:
            if "AlternateForm=UNPLATED" not in str(exc):
                raise AssertionError(f"FakeSquare44x44LogoJunk spoof error lacked AlternateForm=UNPLATED: {exc}") from exc
        else:
            raise AssertionError("FakeSquare44x44LogoJunk.txt substring spoof unexpectedly passed!")

        # (g) Tier-5 (R2-C2-F5): Child <Qualifier> elements AND combined inline qualifiers= + qualifierSet= -> PASS
        p_child = tmp_dir / "pri_r2_child_qual.xml"
        child_lines: list[str] = []
        for key in REQUIRED_PRI_RESOURCE_KEYS:
            cands = "".join(
                f'<Candidate type="String"><Qualifier name="Language" value="{loc.upper()}" /><Value>{key}-{loc}</Value></Candidate>'
                for loc in CANONICAL_35_LOCALES
            )
            child_lines.append(f'      <NamedResource name="{key}">{cands}</NamedResource>')
        child_sq = [
            f'<Candidate type="Path"><Qualifier name="Scale" value="{sc}" /><Value>Assets\\sq.png</Value></Candidate>'
            for sc in ("100", "125", "150", "200", "400")
        ]
        for alt in ("UNPLATED", "LIGHTUNPLATED"):
            for ts in ("16", "24", "32", "48", "256"):
                child_sq.append(
                    f'<Candidate type="Path"><Qualifier name="TargetSize" value="{ts}" />'
                    f'<Qualifier name="AlternateForm" value="{alt}" /><Value>Assets\\sq.png</Value></Candidate>'
                )
        child_lines.append(f'      <NamedResource name="Assets\\Square44x44Logo.png">{"".join(child_sq)}</NamedResource>')
        p_child.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<PriInfo><ResourceMap name="TotalDrop.TotalDrop"><ResourceMapSubtree name="Resources">\n'
            + "\n".join(child_lines)
            + "\n</ResourceMapSubtree></ResourceMap></PriInfo>\n",
            encoding="utf-8",
        )
        verify_pri_dump(p_child)

        p_split_q = tmp_dir / "pri_r2_split_inline_qset.xml"
        split_lines: list[str] = []
        for key in REQUIRED_PRI_RESOURCE_KEYS:
            cands = "".join(
                f'<Candidate qualifiers="Language-{loc.upper()}" type="String"><Value>{key}-{loc}</Value></Candidate>'
                for loc in CANONICAL_35_LOCALES
            )
            split_lines.append(f'      <NamedResource name="{key}">{cands}</NamedResource>')
        split_sq = [
            f'<Candidate qualifiers="Scale-{sc}" type="Path"><Value>Assets\\sq.png</Value></Candidate>'
            for sc in ("100", "125", "150", "200", "400")
        ]
        for qidx in ("90", "91"):
            for ts in ("16", "24", "32", "48", "256"):
                split_sq.append(
                    f'<Candidate qualifiers="TargetSize-{ts}" qualifierSet="{qidx}" type="Path"><Value>Assets\\sq.png</Value></Candidate>'
                )
        split_lines.append(f'      <NamedResource name="Assets\\Square44x44Logo.png">{"".join(split_sq)}</NamedResource>')
        p_split_q.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<PriInfo><ResourceMap name="TotalDrop.TotalDrop"><DecisionInfo>'
            '<QualifierSet index="90"><Qualifier name="AlternateForm" value="UNPLATED" /></QualifierSet>'
            '<QualifierSet index="91"><Qualifier name="AlternateForm" value="LIGHTUNPLATED" /></QualifierSet>'
            '</DecisionInfo><ResourceMapSubtree name="Resources">\n'
            + "\n".join(split_lines)
            + "\n</ResourceMapSubtree></ResourceMap></PriInfo>\n",
            encoding="utf-8",
        )
        verify_pri_dump(p_split_q)

        # (h) Tier-5 (R2-C2-F5): Other/appTagline (1 lang) before Resources/appTagline (35 langs) -> PASS;
        # splitting 17+18 languages across unrelated subtrees (neither complete) -> FAIL.
        p_multi = tmp_dir / "pri_r2_multi_subtree.xml"
        p_multi.write_text(
            _build_realistic_makepri_xml(CANONICAL_35_LOCALES).replace(
                '<NamedResource name="appTagline">',
                '<NamedResource name="Other/appTagline"><Candidate qualifiers="Language-EN" type="String"><Value>x</Value></Candidate></NamedResource>\n'
                '      <NamedResource name="Resources/appTagline">',
                1,
            ),
            encoding="utf-8",
        )
        verify_pri_dump(p_multi)

        p_multi_split = tmp_dir / "pri_r2_multi_split_incomplete.xml"
        h1 = "".join(
            f'<Candidate qualifiers="Language-{loc.upper()}" type="String"><Value>a-{loc}</Value></Candidate>'
            for loc in CANONICAL_35_LOCALES[:17]
        )
        h2 = "".join(
            f'<Candidate qualifiers="Language-{loc.upper()}" type="String"><Value>b-{loc}</Value></Candidate>'
            for loc in CANONICAL_35_LOCALES[17:]
        )
        base_multi = _build_realistic_makepri_xml(CANONICAL_35_LOCALES)
        mut_multi = re.sub(
            r'<NamedResource name="appTagline">.*?</NamedResource>',
            f'<NamedResource name="Other/appTagline">{h1}</NamedResource>\n'
            f'      <NamedResource name="Resources/appTagline">{h2}</NamedResource>',
            base_multi,
            count=1,
            flags=re.DOTALL,
        )
        assert mut_multi != base_multi
        p_multi_split.write_text(mut_multi, encoding="utf-8")
        try:
            verify_pri_dump(p_multi_split)
        except ValueError as exc:
            if "18 != 35" not in str(exc):
                raise AssertionError(f"split multi-subtree error lacked '18 != 35': {exc}") from exc
        else:
            raise AssertionError("split 17+18 languages across Other/ and Resources/ unexpectedly passed!")

        # (i) Real MakePri.exe /dt detailed format: <Candidate><QualifierSet><Qualifier .../></QualifierSet></Candidate>
        p_detailed = tmp_dir / "pri_detailed_nested_qset.xml"
        det_res: list[str] = []
        for key in REQUIRED_PRI_RESOURCE_KEYS:
            cands = "".join(
                f'<Candidate type="String"><QualifierSet index="{idx + 1}">'
                f'<Qualifier name="Language" value="{loc.upper()}" priority="900" scoreAsDefault="1.0" index="1"/>'
                f"</QualifierSet><Value>{key}-{loc}</Value></Candidate>"
                for idx, loc in enumerate(CANONICAL_35_LOCALES)
            )
            det_res.append(f'      <NamedResource name="{key}">{cands}</NamedResource>')
        det_sq = [
            f'<Candidate type="Path"><QualifierSet index="100"><Qualifier name="Scale" value="{sc}" priority="500" scoreAsDefault="0.0" index="1"/></QualifierSet>'
            f"<Value>Assets\\Square44x44Logo.scale-{sc}.png</Value></Candidate>"
            for sc in ("100", "125", "150", "200", "400")
        ]
        for alt in ("UNPLATED", "LIGHTUNPLATED"):
            for ts in ("16", "24", "32", "48", "256"):
                det_sq.append(
                    f'<Candidate type="Path"><QualifierSet index="200">'
                    f'<Qualifier name="TargetSize" value="{ts}" priority="500" scoreAsDefault="0.0" index="1"/>'
                    f'<Qualifier name="AlternateForm" value="{alt}" priority="500" scoreAsDefault="0.0" index="2"/>'
                    f"</QualifierSet><Value>Assets\\Square44x44Logo.targetsize-{ts}_altform-{alt.lower()}.png</Value></Candidate>"
                )
        det_xml = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<PriInfo><ResourceMap name="TotalDrop.TotalDrop">'
            '<ResourceMapSubtree name="Files"><ResourceMapSubtree name="Assets">'
            f'<NamedResource name="Square44x44Logo.png">{"".join(det_sq)}</NamedResource>'
            '</ResourceMapSubtree></ResourceMapSubtree>'
            '<ResourceMapSubtree name="Resources">\n'
            + "\n".join(det_res)
            + "\n</ResourceMapSubtree></ResourceMap></PriInfo>\n"
        )
        p_detailed.write_text(det_xml, encoding="utf-8")
        verify_pri_dump(p_detailed)

        p_detailed_bad = tmp_dir / "pri_detailed_missing_unplated.xml"
        p_detailed_bad.write_text(det_xml.replace('value="UNPLATED"', 'value="PLATED"'), encoding="utf-8")
        try:
            verify_pri_dump(p_detailed_bad)
        except ValueError as exc:
            if "AlternateForm=UNPLATED" not in str(exc):
                raise AssertionError(f"/dt detailed missing UNPLATED error lacked AlternateForm=UNPLATED: {exc}") from exc
        else:
            raise AssertionError("/dt detailed missing UNPLATED unexpectedly passed!")

    # Tier-5 (C2-F5): Leading-zero and non-ASCII digit MSIX version quads must be rejected.
    for bad_quad in ("01.0.1.0", "1.00.1.0", "00.1.1.0", "١.٠.١.٠", "٠.١.١.٠"):
        try:
            _validate_quad(bad_quad, store_mode=False, label="tier5-quad")
        except ValueError:
            pass
        else:
            raise AssertionError(f"_validate_quad unexpectedly accepted invalid MSIX quad {bad_quad!r}")

    return (
        "realistic MakePri dump (35-locale, missing zh-Hant 34!=35, LIGHTUNPLATED-only, "
        "QualifierSet, /dt detailed nested QualifierSet, E13 per-altform 5-size matrix, "
        "R2-C2-F5 exact Square44 leaf/child/split-qset/multi-subtree, Tier-5 ASCII quad guard) verified"
    )


FORBIDDEN_PACKAGE_KEY_EXTS: tuple[str, ...] = (
    ".pfx", ".p12", ".snk", ".cer", ".jks", ".keystore", ".pepk", ".key", ".pem", ".pvk",
)
REQUIRED_UPLOAD_PDBS: frozenset[str] = frozenset(
    {
        "totaldrop-winui.pdb",
        "totaldrop_windows_ffi.pdb",
        "totaldrop_explorer_ext.pdb",
    }
)
PDB_MSF7_MAGIC: bytes = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
ALLOWED_OPC_COMPRESS_TYPES: tuple[int, ...] = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
FORBIDDEN_ZIP_FLAGS: int = 0x0001 | 0x0020 | 0x0040 | 0x2000


def _check_opc_zip_entries(
    zf: zipfile.ZipFile,
    label: str,
    *,
    flat_root_only: bool = False,
    case_sensitive_unique_paths: tuple[str, ...] = (),
) -> list[str]:
    """Enforce hardened OPC/ZIP structural & security invariants matching tools/verify-msix-artifact.py."""
    infos = zf.infolist()

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
        bad = zf.testzip()
    except (zlib.error, zipfile.BadZipFile, RuntimeError, EOFError, struct.error, OverflowError) as exc:
        raise ValueError(f"{label}: corrupt ZIP archive: {exc}") from exc
    if bad is not None:
        raise ValueError(f"{label}: corrupt ZIP member {bad!r}")

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
                lfh_name_len = struct.unpack_from("<H", lfh, 26)[0]
                if lfh_method != info.compress_type:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} local-header compression method "
                        f"({lfh_method}) differs from central-directory method ({info.compress_type})"
                    )
                if (lfh_flags & FORBIDDEN_ZIP_FLAGS) != 0:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} local-header has forbidden flags {lfh_flags:#06x}"
                    )
                if (lfh_flags & 0x0008) != (info.flag_bits & 0x0008):
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} local-header data-descriptor flag mismatch"
                    )
                lfh_name_bytes = zf.fp.read(lfh_name_len)
                cd_encoding = "utf-8" if (info.flag_bits & 0x0800) else "cp437"
                try:
                    expected_name_bytes = info.orig_filename.encode(cd_encoding)
                except UnicodeEncodeError as exc:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} cannot be encoded as {cd_encoding}: {exc}"
                    ) from exc
                if lfh_name_bytes != expected_name_bytes:
                    raise ValueError(
                        f"{label}: ZIP entry {info.orig_filename!r} local-header filename differs from central directory"
                    )
            finally:
                zf.fp.seek(saved_pos)

        name = info.filename
        if name in seen_exact:
            raise ValueError(f"{label}: duplicate ZIP entry {name!r}")
        seen_exact.add(name)

        if not name or name.startswith("/") or "\\" in name or ":" in name:
            raise ValueError(f"{label}: unsafe OPC/ZIP entry path {name!r}")
        # Store ANSI-only path invariant (0x20..=0x7E) — T2-F06-04
        if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in name):
            raise ValueError(
                f"{label}: non-ASCII ZIP entry violates Store ANSI-only path rule: {name!r}"
            )

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
                f"{label}: OPC/ZIP path segment with trailing dot or space is forbidden: {name!r}"
            )

        if is_dir:
            if info.file_size != 0 or len(zf.read(info)) != 0:
                raise ValueError(f"{label}: directory ZIP entry {name!r} carries non-zero payload")
            if name.rstrip("/").lower().endswith(FORBIDDEN_PACKAGE_KEY_EXTS) or any(
                part.lower().endswith(FORBIDDEN_PACKAGE_KEY_EXTS) for part in check_parts
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


def _verify_appxsym_bytes(data: bytes, label: str) -> set[str]:
    """Validate nested .appxsym archive: flat-root non-empty MSF-7.00 PDBs only, zero forbidden artifacts."""
    if len(data) < 4 or data[:4] != b"PK\x03\x04":
        raise ValueError(f"{label}: not a valid ZIP .appxsym archive (magic={data[:4]!r})")
    pdb_basenames: set[str] = set()
    forbidden_sym_exts = FORBIDDEN_PACKAGE_KEY_EXTS + (".exe", ".dll", ".msix", ".appx", ".msixbundle")
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
            pdb_bytes = sym_zf.read(name)
            if len(pdb_bytes) < len(PDB_MSF7_MAGIC) or not pdb_bytes.startswith(PDB_MSF7_MAGIC):
                raise ValueError(
                    f"{label}: PDB entry {name!r} does not start with Microsoft MSF 7.00 magic header"
                )
            pdb_basenames.add(lower)
    if not pdb_basenames:
        raise ValueError(f"{label}: .appxsym archive contains zero .pdb entries")
    return pdb_basenames


def verify_msix_archive(
    msix_path: Path,
    arch: str = "x64",
    milestone: str = "M1",
    expect_signed: bool = False,
    pri_dump: Path | None = None,
) -> None:
    if not msix_path.is_file():
        raise ValueError(f"MSIX file not found: {msix_path}")
    raw_head = msix_path.read_bytes()[:4]
    if raw_head != b"PK\x03\x04":
        raise ValueError(
            f"{msix_path.name}: not a valid OPC/ZIP MSIX (magic={raw_head!r}, expected b'PK\\x03\\x04')"
        )

    expected_arch = "x64" if arch in ("x64", "x86_64") else "arm64"
    with zipfile.ZipFile(msix_path, "r") as zf:
        names = _check_opc_zip_entries(
            zf,
            msix_path.name,
            flat_root_only=False,
            case_sensitive_unique_paths=("AppxManifest.xml",),
        )
        name_set = set(names)
        required = {
            "AppxManifest.xml",
            "AppxBlockMap.xml",
            "[Content_Types].xml",
            "resources.pri",
            "totaldrop-winui.exe",
            "totaldrop_windows_ffi.dll",
        }
        if milestone in ("M3", "M4"):
            required.add("totaldrop_explorer_ext.dll")
        if expect_signed:
            required.add("AppxSignature.p7x")
        missing = sorted(required - name_set)
        if missing:
            raise ValueError(f"{msix_path.name}: missing required OPC/MSIX entries: {missing}")

        if expect_signed and zf.getinfo("AppxSignature.p7x").file_size <= 0:
            raise ValueError(f"{msix_path.name}: AppxSignature.p7x is empty")

        forbidden_entries = [
            n
            for n in names
            if n.lower().endswith(".pdb")
            or n.lower().endswith(".resw")
            or n.lower().endswith(FORBIDDEN_PACKAGE_KEY_EXTS)
            or (
                Path(n.replace("\\", "/")).name.lower().startswith("resources.")
                and n.lower().endswith(".pri")
                and n.lower() != "resources.pri"
            )
        ]
        if forbidden_entries:
            raise ValueError(f"{msix_path.name}: forbidden staging/key/split-PRI artifacts packed in MSIX: {forbidden_entries}")

        asset_pngs = [n for n in names if n.startswith("Assets/") and n.lower().endswith(".png")]
        if not asset_pngs:
            raise ValueError(f"{msix_path.name}: missing Assets/*.png entries")

        # Validate AppxBlockMap.xml and [Content_Types].xml parse as XML, and BlockMap uses SHA-256
        for opc_xml_name in ("AppxBlockMap.xml", "[Content_Types].xml"):
            try:
                opc_xml_raw = zf.read(opc_xml_name).decode("utf-8", errors="strict")
                ET.fromstring(opc_xml_raw)
            except (UnicodeDecodeError, ET.ParseError) as exc:
                raise ValueError(f"{msix_path.name}: invalid XML in {opc_xml_name}: {exc}") from exc
        blockmap_xml = zf.read("AppxBlockMap.xml").decode("utf-8", errors="strict")
        if "sha256" not in blockmap_xml.lower():
            raise ValueError(f"{msix_path.name}: AppxBlockMap.xml does not declare SHA-256 hash method")

        # Validate resources.pri magic and size
        verify_pri_bytes(zf.read("resources.pri"), label=f"{msix_path.name}:resources.pri")

        # Validate AppxManifest.xml identity, processor architecture & COM DLL references
        root = ET.fromstring(zf.read("AppxManifest.xml"))
        appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
        ident = root.find(f"{appx_ns}Identity")
        if ident is None:
            raise ValueError(f"{msix_path.name}: AppxManifest.xml missing <Identity>")
        if ident.attrib.get("ProcessorArchitecture") != expected_arch:
            raise ValueError(
                f"{msix_path.name}: ProcessorArchitecture={ident.attrib.get('ProcessorArchitecture')!r} "
                f"!= expected {expected_arch!r}"
            )
        if milestone in ("M3", "M4"):
            for el in root.iter():
                if _local_tag(el) == "Class" and "Path" in el.attrib:
                    dll_rel = el.attrib["Path"].replace("\\", "/").lstrip("./")
                    if dll_rel not in name_set:
                        raise ValueError(
                            f"{msix_path.name}: AppxManifest.xml <com:Class Path={dll_rel!r}> missing from archive"
                        )

    if pri_dump is not None:
        verify_pri_dump(pri_dump)


_ASCII_MSIX_QUAD_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+$", re.ASCII)


def _validate_quad(version: str, *, store_mode: bool, label: str) -> tuple[int, int, int, int]:
    if not _ASCII_MSIX_QUAD_RE.fullmatch(version):
        raise ValueError(f"{label}: invalid 4-part ASCII MSIX version {version!r}")
    parts = version.split(".")
    if any(len(p) > 1 and p.startswith("0") for p in parts):
        raise ValueError(f"{label}: MSIX version quad must not contain leading zeros: {version!r}")
    quad = tuple(int(p) for p in parts)
    if any(n < 0 or n > 65535 for n in quad):
        raise ValueError(f"{label}: MSIX version quad out of 0..=65535 uint16 bounds: {version!r}")
    if quad[3] != 0:
        raise ValueError(f"{label}: MSIX Revision (4th part) must be 0, got {version!r}")
    if store_mode and quad[0] < 1:
        raise ValueError(f"{label}: Microsoft Store requires Major >= 1, got {version!r}")
    return quad  # type: ignore[return-value]


def verify_msixbundle_archive(
    bundle_path: Path,
    *,
    milestone: str = "M4",
    expect_signed: bool = False,
    expected_version: str | None = None,
    store_mode: bool = False,
) -> dict[str, Any]:
    """Independent opaque-box verifier for dual-arch (x64 + arm64) .msixbundle containers."""
    if not bundle_path.is_file():
        raise ValueError(f"MSIX bundle not found: {bundle_path}")
    raw_head = bundle_path.read_bytes()[:4]
    if raw_head != b"PK\x03\x04":
        raise ValueError(
            f"{bundle_path.name}: not a valid OPC/ZIP .msixbundle (magic={raw_head!r}, expected b'PK\\x03\\x04')"
        )

    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = _check_opc_zip_entries(
            zf,
            bundle_path.name,
            flat_root_only=False,
            case_sensitive_unique_paths=("AppxMetadata/AppxBundleManifest.xml",),
        )
        forbidden_bundle_exts = FORBIDDEN_PACKAGE_KEY_EXTS + (".pdb", ".resw")
        for member in names:
            if member.lower().endswith(forbidden_bundle_exts):
                raise ValueError(f"{bundle_path.name}: forbidden key/symbol/staging file inside bundle: {member!r}")

        name_set = set(names)
        required = {"AppxMetadata/AppxBundleManifest.xml", "AppxBlockMap.xml", "[Content_Types].xml"}
        if expect_signed:
            required.add("AppxSignature.p7x")
        missing = sorted(required - name_set)
        if missing:
            raise ValueError(f"{bundle_path.name}: missing required OPC bundle entries: {missing}")
        if expect_signed and zf.getinfo("AppxSignature.p7x").file_size <= 0:
            raise ValueError(f"{bundle_path.name}: AppxSignature.p7x is empty")

        for opc_xml_name in ("AppxBlockMap.xml", "[Content_Types].xml"):
            try:
                opc_xml_raw = zf.read(opc_xml_name).decode("utf-8", errors="strict")
                ET.fromstring(opc_xml_raw)
            except (UnicodeDecodeError, ET.ParseError) as exc:
                raise ValueError(f"{bundle_path.name}: invalid XML in {opc_xml_name}: {exc}") from exc

        bundle_root = ET.fromstring(zf.read("AppxMetadata/AppxBundleManifest.xml"))
        if _local_tag(bundle_root) != "Bundle":
            raise ValueError(f"{bundle_path.name}: AppxBundleManifest.xml root is not <Bundle>")

        bundle_ns = "{http://schemas.microsoft.com/appx/2013/bundle}"
        ident = bundle_root.find(f"{bundle_ns}Identity")
        if ident is None:
            raise ValueError(f"{bundle_path.name}: AppxBundleManifest.xml missing <Identity>")

        b_name = ident.attrib.get("Name", "")
        b_pub = ident.attrib.get("Publisher", "")
        b_ver = ident.attrib.get("Version", "")
        if not b_name or not b_pub or not b_ver:
            raise ValueError(f"{bundle_path.name}: incomplete bundle <Identity> attributes")
        _validate_quad(b_ver, store_mode=store_mode, label=f"{bundle_path.name} Identity/@Version")
        if expected_version is not None and b_ver != expected_version:
            raise ValueError(
                f"{bundle_path.name}: bundle Version {b_ver!r} != expected {expected_version!r}"
            )

        app_pkgs = [
            p for p in bundle_root.findall(f".//{bundle_ns}Package")
            if p.attrib.get("Type") == "application"
        ]
        arches_seen: dict[str, str] = {}
        inner_identities: dict[str, dict[str, str]] = {}
        referenced_files: set[str] = set()

        with tempfile.TemporaryDirectory(prefix="td-bundle-check-") as tmp:
            tmp_dir = Path(tmp)
            for pkg in app_pkgs:
                p_arch = pkg.attrib.get("Architecture", "").lower()
                p_ver = pkg.attrib.get("Version", "")
                p_file = pkg.attrib.get("FileName", "")
                if p_arch == "x86":
                    raise ValueError(
                        f"{bundle_path.name}: forbidden 32-bit x86 architecture slice found ({p_file!r})"
                    )
                if p_arch not in ("x64", "arm64"):
                    raise ValueError(
                        f"{bundle_path.name}: unsupported package Architecture={p_arch!r} ({p_file!r})"
                    )
                if p_arch in arches_seen:
                    raise ValueError(f"{bundle_path.name}: duplicate architecture slice {p_arch!r}")
                if p_ver != b_ver:
                    raise ValueError(
                        f"{bundle_path.name}: package {p_file!r} Version={p_ver!r} != bundle Version={b_ver!r}"
                    )
                if (
                    not p_file
                    or "/" in p_file
                    or "\\" in p_file
                    or not p_file.lower().endswith(".msix")
                    or p_file not in name_set
                ):
                    raise ValueError(
                        f"{bundle_path.name}: referenced slice {p_file!r} must be a flat root .msix present in bundle ZIP"
                    )
                referenced_files.add(p_file)

                slice_path = tmp_dir / Path(p_file).name
                slice_path.write_bytes(zf.read(p_file))
                verify_msix_archive(slice_path, arch=p_arch, milestone=milestone, expect_signed=False)

                with zipfile.ZipFile(slice_path, "r") as inner_zf:
                    inner_root = ET.fromstring(inner_zf.read("AppxManifest.xml"))
                    appx_ns = "{http://schemas.microsoft.com/appx/manifest/foundation/windows10}"
                    inner_id = inner_root.find(f"{appx_ns}Identity")
                    assert inner_id is not None
                    i_name = inner_id.attrib.get("Name", "")
                    i_pub = inner_id.attrib.get("Publisher", "")
                    i_ver = inner_id.attrib.get("Version", "")
                    if i_ver != b_ver:
                        raise ValueError(
                            f"{bundle_path.name}: inner {p_arch} slice Version={i_ver!r} != bundle Version={b_ver!r}"
                        )
                    if i_name != b_name:
                        raise ValueError(
                            f"{bundle_path.name}: inner {p_arch} slice Identity/@Name={i_name!r} != bundle {b_name!r}"
                        )
                    if i_pub != b_pub:
                        raise ValueError(
                            f"{bundle_path.name}: inner {p_arch} slice Identity/@Publisher={i_pub!r} != bundle {b_pub!r}"
                        )
                    arches_seen[p_arch] = p_file
                    inner_identities[p_arch] = {"name": i_name, "publisher": i_pub, "version": i_ver}

        missing_arches = sorted({"x64", "arm64"} - set(arches_seen))
        if missing_arches:
            raise ValueError(
                f"{bundle_path.name}: dual-arch .msixbundle missing required architecture slice(s): {missing_arches}"
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
            for n in names
            if (n.endswith("/") and n != "AppxMetadata/")
            or (not n.endswith("/") and n not in allowed_bundle_files)
        )
        if unexpected_bundle_entries:
            raise ValueError(
                f"{bundle_path.name}: unexpected/unreferenced entries inside .msixbundle: {unexpected_bundle_entries}"
            )

        if inner_identities["x64"]["publisher"] != inner_identities["arm64"]["publisher"]:
            raise ValueError(
                f"{bundle_path.name}: Publisher mismatch between x64 ({inner_identities['x64']['publisher']!r}) "
                f"and arm64 ({inner_identities['arm64']['publisher']!r})"
            )

    return {
        "name": b_name,
        "publisher": b_pub,
        "version": b_ver,
        "architectures": sorted(arches_seen),
        "slices": arches_seen,
    }


def verify_msixupload_archive(
    upload_path: Path,
    *,
    milestone: str = "M4",
    expected_bundle_path: Path | None = None,
    expected_version: str | None = None,
    store_mode: bool = False,
) -> dict[str, Any]:
    """Independent opaque-box verifier for Partner Center .msixupload containers."""
    if not upload_path.is_file():
        raise ValueError(f"MSIX upload archive not found: {upload_path}")
    raw_head = upload_path.read_bytes()[:4]
    if raw_head != b"PK\x03\x04":
        raise ValueError(
            f"{upload_path.name}: not a valid ZIP .msixupload (magic={raw_head!r}, expected b'PK\\x03\\x04')"
        )

    with zipfile.ZipFile(upload_path, "r") as zf:
        names = _check_opc_zip_entries(zf, upload_path.name, flat_root_only=True)
        bundles: list[str] = []
        appxsyms: list[str] = []

        for member in names:
            low = member.lower()
            if low.endswith((".msix", ".appx")):
                raise ValueError(
                    f"{upload_path.name}: bare standalone package {member!r} is forbidden inside .msixupload "
                    "(Microsoft Store enforces irreversible standalone .msix <-> .msixbundle format lock-in; "
                    "always wrap a dual-arch .msixbundle from Flight #1)"
                )
            if low.endswith(FORBIDDEN_PACKAGE_KEY_EXTS):
                raise ValueError(f"{upload_path.name}: forbidden key/certificate file inside .msixupload: {member!r}")
            if low.endswith(".msixbundle"):
                bundles.append(member)
            elif low.endswith(".appxsym"):
                appxsyms.append(member)
            else:
                raise ValueError(f"{upload_path.name}: unexpected .msixupload entry: {member!r}")

        if len(bundles) != 1:
            raise ValueError(
                f"{upload_path.name}: expected exactly 1 .msixbundle inside .msixupload, found {len(bundles)}"
            )
        if len(appxsyms) < 1:
            raise ValueError(f"{upload_path.name}: expected at least 1 .appxsym symbol archive inside .msixupload")

        bundle_bytes = zf.read(bundles[0])
        bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
        if expected_bundle_path is not None:
            disk_sha = hashlib.sha256(expected_bundle_path.read_bytes()).hexdigest()
            if bundle_sha != disk_sha:
                raise ValueError(
                    f"{upload_path.name}: embedded bundle SHA-256 ({bundle_sha}) != standalone bundle ({disk_sha})"
                )

        with tempfile.TemporaryDirectory(prefix="td-upload-check-") as tmp:
            tmp_bundle = Path(tmp) / Path(bundles[0]).name
            tmp_bundle.write_bytes(bundle_bytes)
            bundle_info = verify_msixbundle_archive(
                tmp_bundle,
                milestone=milestone,
                expect_signed=False,
                expected_version=expected_version,
                store_mode=store_mode,
            )

        expected_appxsyms = {f"{Path(pf).stem}.appxsym" for pf in bundle_info["slices"].values()}
        actual_appxsyms = set(appxsyms)
        if actual_appxsyms != expected_appxsyms:
            missing_syms = sorted(expected_appxsyms - actual_appxsyms)
            extra_syms = sorted(actual_appxsyms - expected_appxsyms)
            raise ValueError(
                f"{upload_path.name}: .msixupload .appxsym archive set must match bundle slices exactly "
                f"(expected={sorted(expected_appxsyms)}, missing={missing_syms}, unexpected={extra_syms})"
            )

        all_pdbs: set[str] = set()
        for sym_name in sorted(appxsyms):
            sym_bytes = zf.read(sym_name)
            sym_pdbs = _verify_appxsym_bytes(sym_bytes, f"{upload_path.name}/{sym_name}")
            missing_pdbs = sorted(REQUIRED_UPLOAD_PDBS - sym_pdbs)
            if missing_pdbs:
                raise ValueError(
                    f"{upload_path.name}/{sym_name}: .appxsym missing required PDB(s): {missing_pdbs}"
                )
            all_pdbs.update(sym_pdbs)

    return {
        "bundle": bundles[0],
        "bundle_sha256": bundle_sha,
        "bundle_info": bundle_info,
        "appxsym_count": len(appxsyms),
        "pdbs": sorted(all_pdbs),
    }


def _create_valid_fixture_msix(
    target_path: Path,
    version: str,
    arch: str = "x64",
    *,
    include_explorer_ext: bool = False,
) -> None:
    manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">\n'
        f'  <Identity Name="TotalDrop.TotalDrop" Publisher="CN=TotalDrop" Version="{version}" '
        f'ProcessorArchitecture="{arch}" />\n'
        "</Package>\n"
    ).encode("utf-8")
    blockmap = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
        'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"></BlockMap>\n'
    ).encode("utf-8")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>\n'
    ).encode("utf-8")
    pri = b"mrm_pri2" + (b"\x00" * 4100)
    with zipfile.ZipFile(target_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AppxManifest.xml", manifest)
        zf.writestr("AppxBlockMap.xml", blockmap)
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("resources.pri", pri)
        zf.writestr("totaldrop-winui.exe", b"MZ" + b"\x00" * 64)
        zf.writestr("totaldrop_windows_ffi.dll", b"MZ" + b"\x00" * 64)
        if include_explorer_ext:
            zf.writestr("totaldrop_explorer_ext.dll", b"MZ" + b"\x00" * 64)
        zf.writestr("Assets/StoreLogo.scale-100.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)


def _load_sibling_module(path: Path, name: str) -> Any:
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module spec: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build_full_store_synthetic_msix(
    repo_root: Path,
    *,
    arch: str,
    name: str,
    publisher: str,
    version: str,
) -> bytes:
    """Build a synthetic MSIX compatible with BOTH verify_msix_opc.py and tools/verify-msix-artifact.py."""
    pe_mod = _load_sibling_module(Path(__file__).resolve().parent / "verify_pe_hardening.py", "_td_pe_mod")
    tpl_rel = (
        Path("target-x86_64") / "Package.x64.appxmanifest"
        if arch in ("x64", "x86")
        else Path("target-arm64") / "Package.arm64.appxmanifest"
    )
    xml = (repo_root / tpl_rel).read_text(encoding="utf-8")
    xml = re.sub(
        r'(<Identity\b[^>]*?Name=")[^"]*(")',
        lambda m: f"{m.group(1)}{name}{m.group(2)}",
        xml,
        count=1,
    )
    xml = re.sub(
        r'(<Identity\b[^>]*?Publisher=")[^"]*(")',
        lambda m: f"{m.group(1)}{publisher}{m.group(2)}",
        xml,
        count=1,
    )
    xml = re.sub(
        r'(<Identity\b[^>]*?Version=")[^"]*(")',
        lambda m: f"{m.group(1)}{version}{m.group(2)}",
        xml,
        count=1,
    )
    xml = re.sub(
        r'(<Identity\b[^>]*?ProcessorArchitecture=")[^"]*(")',
        lambda m: f"{m.group(1)}{arch}{m.group(2)}",
        xml,
        count=1,
    )

    if arch == "x64":
        machine = pe_mod.IMAGE_FILE_MACHINE_AMD64
        include_cet = True
    elif arch == "arm64":
        machine = pe_mod.IMAGE_FILE_MACHINE_ARM64
        include_cet = False
    else:
        machine = pe_mod.IMAGE_FILE_MACHINE_I386
        include_cet = False

    all_ffi_exports = (
        list(pe_mod.M1_FFI_EXPORTS) + list(pe_mod.M2_EXTRA_FFI_EXPORTS) + list(pe_mod.M3_EXTRA_FFI_EXPORTS)
    )
    exe_bytes = pe_mod._build_synthetic_pe32_plus(
        machine=machine,
        is_dll=False,
        imports=["kernel32.dll", "user32.dll"],
        exports=[],
        include_icons=True,
        include_load_config=False,
        include_cet=include_cet,
    )
    ffi_bytes = pe_mod._build_synthetic_pe32_plus(
        machine=machine,
        is_dll=True,
        imports=["kernel32.dll", "bcrypt.dll"],
        exports=all_ffi_exports,
        include_icons=False,
        include_load_config=True,
        include_cet=include_cet,
    )
    ext_bytes = pe_mod._build_synthetic_pe32_plus(
        machine=machine,
        is_dll=True,
        imports=["kernel32.dll", "ole32.dll"],
        exports=list(pe_mod.EXPLORER_EXT_EXPORTS),
        include_icons=True,
        include_load_config=True,
        include_cet=include_cet,
        icon_group_id=pe_mod.EXPLORER_ICON_RESOURCE_ID,
    )
    blockmap = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
        'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"></BlockMap>\n'
    ).encode("utf-8")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>\n'
    ).encode("utf-8")
    pri = b"mrm_pri2" + (b"\x00" * 4100)

    assets_dir = repo_root / "ui-winui3-fluent2" / "Assets"
    asset_files = sorted(p.name for p in assets_dir.iterdir() if p.is_file() and p.suffix.lower() in (".png", ".ico"))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AppxManifest.xml", xml.encode("utf-8"))
        zf.writestr("AppxBlockMap.xml", blockmap)
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("resources.pri", pri)
        zf.writestr("App.xbf", b"XBF\x00")
        zf.writestr("MainWindow.xbf", b"XBF\x00")
        zf.writestr("Views/SendPage.xbf", b"XBF\x00")
        zf.writestr("Views/ReceivePage.xbf", b"XBF\x00")
        zf.writestr("Views/SettingsPage.xbf", b"XBF\x00")
        for asset_name in asset_files:
            zf.writestr(
                f"Assets/{asset_name}",
                b"\x89PNG\r\n\x1a\n" if asset_name.endswith(".png") else b"\x00\x00\x01\x00",
            )
        zf.writestr("totaldrop-winui.exe", exe_bytes)
        zf.writestr("totaldrop_windows_ffi.dll", ffi_bytes)
        zf.writestr("totaldrop_explorer_ext.dll", ext_bytes)
    return buf.getvalue()


def _build_synthetic_bundle_bytes(
    *,
    name: str,
    publisher: str,
    version: str,
    packages: list[tuple[str, str, str, bytes]],
) -> bytes:
    pkg_xml = "\n".join(
        f'    <Package Type="application" Version="{p_ver}" Architecture="{p_arch}" FileName="{p_file}" />'
        for p_arch, p_ver, p_file, _ in packages
    )
    bundle_manifest = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Bundle SchemaVersion="5.0" xmlns="http://schemas.microsoft.com/appx/2013/bundle">\n'
        f'  <Identity Name="{name}" Publisher="{publisher}" Version="{version}" />\n'
        "  <Packages>\n"
        f"{pkg_xml}\n"
        "  </Packages>\n"
        "</Bundle>\n"
    ).encode("utf-8")
    blockmap = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap" '
        'HashMethod="http://www.w3.org/2001/04/xmlenc#sha256"></BlockMap>\n'
    ).encode("utf-8")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>\n'
    ).encode("utf-8")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AppxMetadata/AppxBundleManifest.xml", bundle_manifest)
        zf.writestr("AppxBlockMap.xml", blockmap)
        zf.writestr("[Content_Types].xml", content_types)
        for _, _, p_file, p_bytes in packages:
            zf.writestr(p_file, p_bytes)
    return buf.getvalue()


def _build_synthetic_appxsym_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for pdb in sorted(REQUIRED_UPLOAD_PDBS):
            zf.writestr(pdb, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")
    return buf.getvalue()


def _cross_verify_repo_msix_tool(
    repo_root: Path,
    *,
    bundle_path: Path | None = None,
    upload_path: Path | None = None,
    expected_version: str | None = None,
    store_mode: bool = True,
) -> tuple[bool, str]:
    """Cross-verify synthetic bundle/upload against tools/verify-msix-artifact.py safely on all OSes."""
    tool_path = repo_root / "tools" / "verify-msix-artifact.py"
    if sys.platform != "win32":
        cmd = [sys.executable, "-B", str(tool_path)]
        if bundle_path is not None:
            cmd.extend(["--bundle", str(bundle_path)])
        if upload_path is not None:
            cmd.extend(["--msixupload", str(upload_path)])
        if expected_version is not None:
            cmd.extend(["--expected-version", expected_version])
        if store_mode:
            cmd.append("--store-mode")
        proc = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, check=False)
        return (proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}".strip())

    # On Windows, invoke the verifier function with run_live_smoke=False so ctypes.CDLL
    # does not attempt LoadLibrary on synthetic PE64 stubs.
    mod = _load_sibling_module(tool_path, "_td_repo_msix_artifact")
    try:
        if upload_path is not None:
            mod.verify_msixupload_archive(
                upload_path,
                expected_version=expected_version,
                expect_signed=False,
                store_mode=store_mode,
                allow_test_identity=False,
                expected_bundle_path=bundle_path,
                run_live_smoke=False,
            )
        elif bundle_path is not None:
            mod.verify_msixbundle_archive(
                bundle_path,
                bundle_path.name,
                expected_version=expected_version,
                expect_signed=False,
                store_mode=store_mode,
                allow_test_identity=False,
                run_live_smoke=False,
            )
        return (True, "ok")
    except Exception as exc:  # noqa: BLE001
        return (False, str(exc))


def _write_sha256sums(art_dir: Path, filename: str) -> None:
    digest = hashlib.sha256((art_dir / filename).read_bytes()).hexdigest()
    (art_dir / "SHA256SUMS").write_text(f"{digest}  {filename}\n", encoding="utf-8")


def run_cross_platform_tests(repo_root: Path, milestone: str = "M4") -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    sh_exe = _resolve_sh()
    artifact_name, msix_version = resolve_recipe_artifact_name(repo_root, "x86_64")
    build_sh = repo_root / "subplatforms" / "msix" / "x86_64" / "build.sh"
    verify_sh = repo_root / "subplatforms" / "msix" / "x86_64" / "verify.sh"

    def record(test_id: str, fn: Any) -> None:
        try:
            detail = fn()
            results[test_id] = {"status": "PASS", "detail": detail or "ok"}
        except Exception as exc:  # noqa: BLE001
            results[test_id] = {"status": "FAIL", "detail": str(exc)}

    def t1_f06_05() -> str:
        pri_note = self_test_pri_dump()
        p_check = subprocess.run(
            [sh_exe, str(build_sh), "--check-recipe"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if p_check.returncode != 0:
            raise AssertionError(f"build.sh --check-recipe failed: {p_check.stdout}\n{p_check.stderr}")

        with tempfile.TemporaryDirectory(prefix="td-f06-05-") as tmp:
            tmp_root = Path(tmp)
            art_dir = tmp_root / "art"
            art_dir.mkdir()
            msix_path = art_dir / artifact_name
            _create_valid_fixture_msix(msix_path, msix_version, arch="x64")
            _write_sha256sums(art_dir, artifact_name)
            verify_msix_archive(msix_path, arch="x64", milestone="M1", expect_signed=False)

            p_ver = subprocess.run(
                [sh_exe, str(verify_sh), str(art_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if p_ver.returncode != 0:
                raise AssertionError(f"verify.sh failed on valid OPC fixture: {p_ver.stdout}\n{p_ver.stderr}")

            empty_stage = tmp_root / "empty_stage"
            empty_stage.mkdir()
            out_dir = tmp_root / "out"
            p_empty = subprocess.run(
                [sh_exe, str(build_sh), "--package-staged", str(empty_stage), str(out_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            empty_out = f"{p_empty.stdout}\n{p_empty.stderr}"
            if p_empty.returncode == 0 or "AppxManifest.xml" not in empty_out:
                raise AssertionError(
                    f"build.sh --package-staged did not refuse empty staging dir with AppxManifest.xml diagnostic "
                    f"(rc={p_empty.returncode}): {empty_out}"
                )
        return f"verified recipe ({artifact_name}), verify.sh PASS on OPC fixture, build.sh refuses empty stage; {pri_note}"

    def t2_f06_01() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f06-01-") as tmp:
            art_dir = Path(tmp)
            fake_msix = art_dir / artifact_name
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w") as tf:
                    info = tarfile.TarInfo("AppxManifest.xml")
                    payload = b"<Package/>"
                    info.size = len(payload)
                    tf.addfile(info, io.BytesIO(payload))
            data = buf.getvalue()
            assert data[:2] == b"\x1f\x8b"
            fake_msix.write_bytes(data)
            _write_sha256sums(art_dir, artifact_name)

            p = subprocess.run(
                [sh_exe, str(verify_sh), str(art_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            out = f"{p.stdout}\n{p.stderr}"
            if p.returncode == 0 or "not a real opc/zip msix" not in out.lower():
                raise AssertionError(
                    f"verify.sh did not reject gzip tarball with expected OPC/ZIP diagnostic "
                    f"(rc={p.returncode}): {out}"
                )

            try:
                verify_msix_archive(fake_msix, arch="x64", milestone="M1")
            except ValueError as exc:
                if "not a valid opc/zip msix" not in str(exc).lower():
                    raise AssertionError(f"unexpected gzip rejection reason: {exc}") from exc
            else:
                raise AssertionError("verify_msix_archive accepted gzip tarball!")
        return "gzipped tarball (1F 8B) rejected by both verify.sh and verify_msix_archive"

    def t2_f06_02() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f06-02-") as tmp:
            art_dir = Path(tmp)
            empty_zip = art_dir / artifact_name
            with zipfile.ZipFile(empty_zip, "w"):
                pass
            assert empty_zip.read_bytes()[:4] == b"PK\x05\x06"
            _write_sha256sums(art_dir, artifact_name)

            p = subprocess.run(
                [sh_exe, str(verify_sh), str(art_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            out = f"{p.stdout}\n{p.stderr}"
            if p.returncode == 0 or "not a real opc/zip msix" not in out.lower():
                raise AssertionError(
                    f"verify.sh did not reject empty non-OPC ZIP (PK\\x05\\x06) with expected diagnostic "
                    f"(rc={p.returncode}): {out}"
                )

            try:
                verify_msix_archive(empty_zip, arch="x64", milestone="M1")
            except ValueError as exc:
                if "not a valid opc/zip msix" not in str(exc).lower():
                    raise AssertionError(f"unexpected empty-ZIP rejection reason: {exc}") from exc
            else:
                raise AssertionError("verify_msix_archive accepted empty ZIP!")
        return "empty ZIP (50 4B 05 06) rejected by both verify.sh and verify_msix_archive"

    def t2_f06_03() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f06-03-") as tmp:
            art_dir = Path(tmp)
            msix_path = art_dir / artifact_name
            _create_valid_fixture_msix(msix_path, msix_version, arch="x64")
            _write_sha256sums(art_dir, artifact_name)
            raw = bytearray(msix_path.read_bytes())
            raw[-1] ^= 0x01
            msix_path.write_bytes(bytes(raw))

            p = subprocess.run(
                [sh_exe, str(verify_sh), str(art_dir)],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            out = f"{p.stdout}\n{p.stderr}"
            if p.returncode == 0 or (f"{artifact_name}: FAILED" not in out and "did not match" not in out.lower()):
                raise AssertionError(
                    f"verify.sh did not reject 1-byte tampered MSIX with SHA256SUMS mismatch "
                    f"(rc={p.returncode}): {out}"
                )
        return "1-byte MSIX tampering caught by SHA256SUMS verification"

    def t2_f06_04() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f06-04-") as tmp:
            tmp_dir = Path(tmp)
            msix_path = tmp_dir / artifact_name
            _create_valid_fixture_msix(msix_path, msix_version, arch="x64")
            with zipfile.ZipFile(msix_path, "a") as zf:
                zf.writestr("Assets/k\u00f6\u015fe.png", b"\x89PNG\r\n\x1a\n")
            try:
                verify_msix_archive(msix_path, arch="x64", milestone="M1")
            except ValueError as exc:
                if "non-ascii" not in str(exc).lower() and "ansi" not in str(exc).lower():
                    raise AssertionError(f"unexpected rejection reason: {exc}") from exc
            else:
                raise AssertionError("non-ASCII ZIP entry Assets/kose-utf8.png was NOT rejected!")

            # Tier-5 (R2-C2-F4): Hardened OPC/ZIP smuggling negative tests on verify_msix_archive
            def _expect_msix_fail(case_name: str, path: Path, expected_tok: str) -> None:
                try:
                    verify_msix_archive(path, arch="x64", milestone="M1")
                except ValueError as exc:
                    if expected_tok.lower() not in str(exc).lower():
                        raise AssertionError(
                            f"R2-C2-F4({case_name}): expected {expected_tok!r} in error, got: {exc}"
                        ) from exc
                else:
                    raise AssertionError(f"R2-C2-F4({case_name}): tampered MSIX unexpectedly passed!")

            # (a) Duplicate AppxManifest.xml
            p_dup = tmp_dir / "dup_manifest.msix"
            _create_valid_fixture_msix(p_dup, msix_version, arch="x64")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(p_dup, "a") as zf:
                    zf.writestr("AppxManifest.xml", b"<Package/>")
            _expect_msix_fail("dup-manifest", p_dup, "duplicate")

            # (b) Unix symlinks across create_system 0, 3, 10, 14, 19
            for cs in (0, 3, 10, 14, 19):
                p_sym = tmp_dir / f"symlink_cs{cs}.msix"
                _create_valid_fixture_msix(p_sym, msix_version, arch="x64")
                with zipfile.ZipFile(p_sym, "a") as zf:
                    zi = zipfile.ZipInfo("evil_link.txt")
                    zi.create_system = cs
                    zi.external_attr = 0o120777 << 16
                    zf.writestr(zi, b"target.txt")
                _expect_msix_fail(f"symlink-cs{cs}", p_sym, "symbolic link")

            # (c) Non-regular Unix mode FIFO (0o010644) with create_system=0
            p_fifo = tmp_dir / "fifo.msix"
            _create_valid_fixture_msix(p_fifo, msix_version, arch="x64")
            with zipfile.ZipFile(p_fifo, "a") as zf:
                zi = zipfile.ZipInfo("evil_fifo")
                zi.create_system = 0
                zi.external_attr = 0o010644 << 16
                zf.writestr(zi, b"")
            _expect_msix_fail("fifo-cs0", p_fifo, "non-regular unix")

            # (d) Path traversal, backslash, drive colon, embedded key (.pfx), and split PRI
            for tag, entry_name, payload, expect_tok in (
                ("traversal", "../evil.txt", b"x", "traversal"),
                ("backslash", "sub\\evil.txt", b"x", "unsafe"),
                ("drive-colon", "C:evil.txt", b"x", "unsafe"),
                ("embedded-pfx", "cert.pfx", b"KEY", "cert.pfx"),
                ("split-pri", "sub/resources.scale-200.pri", b"mrm_pri2", "resources.scale-200.pri"),
            ):
                p_bad = tmp_dir / f"bad_{tag}.msix"
                _create_valid_fixture_msix(p_bad, msix_version, arch="x64")
                with zipfile.ZipFile(p_bad, "a") as zf:
                    zf.writestr(entry_name, payload)
                _expect_msix_fail(tag, p_bad, expect_tok)
        return "non-ASCII entry + R2-C2-F4 OPC/ZIP smuggling (dup manifest, symlinks, FIFO, traversal, backslash, drive colon, .pfx, split PRI) all rejected"

    record("T1-F06-05", t1_f06_05)
    record("T2-F06-01", t2_f06_01)
    record("T2-F06-02", t2_f06_02)
    record("T2-F06-03", t2_f06_03)
    record("T2-F06-04", t2_f06_04)

    if milestone == "M4":
        store_name = "12345TotalDrop.TotalDrop"
        store_pub = "CN=11111111-2222-3333-4444-555555555555"
        store_ver = "1.0.1.0"

        def t1_f22_03() -> str:
            # Self-test repo's bundle verifier CLI first (47/47 total, 29/29 baseline)
            p_st = subprocess.run(
                [sys.executable, "-B", "-W", "error", str(repo_root / "tools" / "verify-msix-artifact.py"), "--self-test-bundle"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                check=False,
            )
            if p_st.returncode != 0 or "47/47" not in p_st.stdout or "29/29" not in p_st.stdout:
                raise AssertionError(
                    f"tools/verify-msix-artifact.py --self-test-bundle failed: {p_st.stdout}\n{p_st.stderr}"
                )

            with tempfile.TemporaryDirectory(prefix="td-f22-03-") as tmp:
                tmp_dir = Path(tmp)
                x64_bytes = _build_full_store_synthetic_msix(
                    repo_root, arch="x64", name=store_name, publisher=store_pub, version=store_ver
                )
                arm64_bytes = _build_full_store_synthetic_msix(
                    repo_root, arch="arm64", name=store_name, publisher=store_pub, version=store_ver
                )
                bundle_bytes = _build_synthetic_bundle_bytes(
                    name=store_name,
                    publisher=store_pub,
                    version=store_ver,
                    packages=[
                        ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_bytes),
                        ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_bytes),
                    ],
                )
                sym_bytes = _build_synthetic_appxsym_bytes()
                bundle_path = tmp_dir / f"TotalDrop-{store_ver}.msixbundle"
                bundle_path.write_bytes(bundle_bytes)
                upload_path = tmp_dir / f"TotalDrop-{store_ver}.msixupload"
                with zipfile.ZipFile(upload_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr(bundle_path.name, bundle_bytes)
                    zf.writestr(f"TotalDrop_{store_ver}_x64.appxsym", sym_bytes)
                    zf.writestr(f"TotalDrop_{store_ver}_arm64.appxsym", sym_bytes)

                info = verify_msixupload_archive(
                    upload_path,
                    milestone="M4",
                    expected_bundle_path=bundle_path,
                    expected_version=store_ver,
                    store_mode=True,
                )
                assert info["appxsym_count"] == 2
                assert set(info["pdbs"]) == REQUIRED_UPLOAD_PDBS

                ok, msg = _cross_verify_repo_msix_tool(
                    repo_root,
                    bundle_path=bundle_path,
                    upload_path=upload_path,
                    expected_version=store_ver,
                    store_mode=True,
                )
                if not ok:
                    raise AssertionError(f"tools/verify-msix-artifact.py rejected valid .msixupload: {msg}")
            return "dual-arch .msixbundle + .msixupload (2 .appxsym, 3 PDBs, SHA-256 parity) & 47/47 (29/29 baseline) self-test PASS"

        def t1_f22_05() -> str:
            arm64_artifact_name, arm64_ver = resolve_recipe_artifact_name(repo_root, "arm64")
            for sub in ("msix", "portable-zip", "winget"):
                sub_dir = repo_root / "subplatforms" / sub / "arm64"
                recipe = tomllib.loads((sub_dir / "RECIPE.toml").read_text(encoding="utf-8"))
                for field, expected in (
                    ("arch", "arm64"),
                    ("rust_target", "aarch64-pc-windows-msvc"),
                    ("runner", "windows-11-arm"),
                    ("reproducible", True),
                    ("provenance", "sigstore-oidc"),
                    ("checksums_file", "SHA256SUMS"),
                    ("l10n_locales", 35),
                ):
                    if recipe.get(field) != expected:
                        raise AssertionError(
                            f"{sub_dir / 'RECIPE.toml'}: {field}={recipe.get(field)!r} != {expected!r}"
                        )
                for script_name in ("build.sh", "verify.sh"):
                    sp = sub_dir / script_name
                    p_syn = subprocess.run([sh_exe, "-n", str(sp)], cwd=str(repo_root), capture_output=True, text=True, check=False)
                    if p_syn.returncode != 0:
                        raise AssertionError(f"sh -n failed on {sp}: {p_syn.stderr}")
                    p_rec = subprocess.run(
                        [sh_exe, str(sp), "--check-recipe"], cwd=str(repo_root), capture_output=True, text=True, check=False
                    )
                    if p_rec.returncode != 0:
                        raise AssertionError(f"--check-recipe failed on {sp}: {p_rec.stdout}\n{p_rec.stderr}")

            arm64_build_sh = repo_root / "subplatforms" / "msix" / "arm64" / "build.sh"
            arm64_verify_sh = repo_root / "subplatforms" / "msix" / "arm64" / "verify.sh"
            build_text = arm64_build_sh.read_text(encoding="utf-8")
            if re.search(r"\btar\b[^\n]*\|\s*gzip\b", build_text):
                raise AssertionError("subplatforms/msix/arm64/build.sh contains forbidden tar|gzip stub pipeline")

            with tempfile.TemporaryDirectory(prefix="td-f22-05-") as tmp:
                tmp_root = Path(tmp)
                art_dir = tmp_root / "art"
                art_dir.mkdir()
                msix_path = art_dir / arm64_artifact_name
                _create_valid_fixture_msix(msix_path, arm64_ver, arch="arm64", include_explorer_ext=True)
                _write_sha256sums(art_dir, arm64_artifact_name)
                verify_msix_archive(msix_path, arch="arm64", milestone="M4", expect_signed=False)

                p_ver = subprocess.run(
                    [sh_exe, str(arm64_verify_sh), str(art_dir)],
                    cwd=str(repo_root),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if p_ver.returncode != 0:
                    raise AssertionError(f"arm64 verify.sh failed on valid OPC fixture: {p_ver.stdout}\n{p_ver.stderr}")

                empty_stage = tmp_root / "empty_stage"
                empty_stage.mkdir()
                out_dir = tmp_root / "out"
                p_empty = subprocess.run(
                    [sh_exe, str(arm64_build_sh), "--package-staged", str(empty_stage), str(out_dir)],
                    cwd=str(repo_root),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if p_empty.returncode == 0:
                    raise AssertionError("arm64 build.sh --package-staged succeeded on empty staging dir")
                if "AppxManifest.xml" not in (p_empty.stdout + p_empty.stderr):
                    raise AssertionError(
                        f"arm64 build.sh empty stage failure did not cite AppxManifest.xml: {p_empty.stderr}"
                    )
            return f"6/6 ARM64 scripts & 3/3 RECIPE.toml verified, {arm64_artifact_name} verify.sh PASS, empty stage rejected"

        def t2_f22_01() -> str:
            with tempfile.TemporaryDirectory(prefix="td-f22-01-") as tmp:
                tmp_dir = Path(tmp)
                x64_bytes = _build_full_store_synthetic_msix(
                    repo_root, arch="x64", name=store_name, publisher=store_pub, version=store_ver
                )
                arm64_bytes = _build_full_store_synthetic_msix(
                    repo_root, arch="arm64", name=store_name, publisher=store_pub, version=store_ver
                )
                x86_bytes = _build_full_store_synthetic_msix(
                    repo_root, arch="x86", name=store_name, publisher=store_pub, version=store_ver
                )

                # (a) x64-only bundle (missing arm64)
                no_arm_path = tmp_dir / "x64-only.msixbundle"
                no_arm_path.write_bytes(
                    _build_synthetic_bundle_bytes(
                        name=store_name,
                        publisher=store_pub,
                        version=store_ver,
                        packages=[("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_bytes)],
                    )
                )
                try:
                    verify_msixbundle_archive(no_arm_path, milestone="M4", expected_version=store_ver, store_mode=True)
                except ValueError as exc:
                    if "arm64" not in str(exc).lower():
                        raise AssertionError(f"missing-arm64 error lacked 'arm64': {exc}") from exc
                else:
                    raise AssertionError("verify_msixbundle_archive accepted x64-only bundle!")

                ok_a, msg_a = _cross_verify_repo_msix_tool(
                    repo_root, bundle_path=no_arm_path, expected_version=store_ver, store_mode=True
                )
                if ok_a or "arm64" not in msg_a.lower():
                    raise AssertionError(f"tools/verify-msix-artifact.py did not reject missing arm64: ok={ok_a}, msg={msg_a}")

                # (b) bundle containing forbidden x86 slice
                x86_bundle_path = tmp_dir / "with-x86.msixbundle"
                x86_bundle_path.write_bytes(
                    _build_synthetic_bundle_bytes(
                        name=store_name,
                        publisher=store_pub,
                        version=store_ver,
                        packages=[
                            ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_bytes),
                            ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_bytes),
                            ("x86", store_ver, f"TotalDrop_{store_ver}_x86.msix", x86_bytes),
                        ],
                    )
                )
                try:
                    verify_msixbundle_archive(x86_bundle_path, milestone="M4", expected_version=store_ver, store_mode=True)
                except ValueError as exc:
                    if "x86" not in str(exc).lower():
                        raise AssertionError(f"forbidden-x86 error lacked 'x86': {exc}") from exc
                else:
                    raise AssertionError("verify_msixbundle_archive accepted bundle with x86 slice!")

                ok_b, msg_b = _cross_verify_repo_msix_tool(
                    repo_root, bundle_path=x86_bundle_path, expected_version=store_ver, store_mode=True
                )
                if ok_b or "x86" not in msg_b.lower():
                    raise AssertionError(f"tools/verify-msix-artifact.py did not reject x86 slice: ok={ok_b}, msg={msg_b}")
            return "both verifiers rejected missing arm64 slice and forbidden x86 slice"

        def t2_f22_02() -> str:
            with tempfile.TemporaryDirectory(prefix="td-f22-02-") as tmp:
                tmp_dir = Path(tmp)
                x64_bytes = _build_full_store_synthetic_msix(
                    repo_root, arch="x64", name=store_name, publisher=store_pub, version=store_ver
                )
                arm64_bytes = _build_full_store_synthetic_msix(
                    repo_root, arch="arm64", name=store_name, publisher=store_pub, version=store_ver
                )
                sym_bytes = _build_synthetic_appxsym_bytes()
                bad_upload = tmp_dir / f"TotalDrop-{store_ver}-bare.msixupload"
                with zipfile.ZipFile(bad_upload, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr(f"TotalDrop_{store_ver}_x64.msix", x64_bytes)
                    zf.writestr(f"TotalDrop_{store_ver}_x64.appxsym", sym_bytes)

                try:
                    verify_msixupload_archive(bad_upload, milestone="M4", expected_version=store_ver, store_mode=True)
                except ValueError as exc:
                    low = str(exc).lower()
                    if "lock-in" not in low and "msixbundle" not in low:
                        raise AssertionError(f"bare .msix rejection lacked Store lock-in explanation: {exc}") from exc
                else:
                    raise AssertionError("verify_msixupload_archive accepted bare .msix inside .msixupload!")

                ok, msg = _cross_verify_repo_msix_tool(
                    repo_root, upload_path=bad_upload, expected_version=store_ver, store_mode=True
                )
                if ok or ("lock-in" not in msg.lower() and "msixbundle" not in msg.lower()):
                    raise AssertionError(
                        f"tools/verify-msix-artifact.py did not reject bare .msix in .msixupload: ok={ok}, msg={msg}"
                    )

                # Tier-5 (R2-C2-F4): Hardened .msixbundle & .msixupload/.appxsym smuggling negative checks
                good_bundle_bytes = _build_synthetic_bundle_bytes(
                    name=store_name,
                    publisher=store_pub,
                    version=store_ver,
                    packages=[
                        ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_bytes),
                        ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_bytes),
                    ],
                )
                # (a) Duplicate AppxBundleManifest.xml + symlink in .msixbundle
                bad_bundle_dup = tmp_dir / "dup_bundle.msixbundle"
                bad_bundle_dup.write_bytes(good_bundle_bytes)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    with zipfile.ZipFile(bad_bundle_dup, "a") as zf:
                        zf.writestr("AppxMetadata/AppxBundleManifest.xml", b"<Bundle/>")
                try:
                    verify_msixbundle_archive(bad_bundle_dup, milestone="M4", expected_version=store_ver, store_mode=True)
                except ValueError as exc:
                    if "duplicate" not in str(exc).lower():
                        raise AssertionError(f"bundle dup-manifest error lacked 'duplicate': {exc}") from exc
                else:
                    raise AssertionError("verify_msixbundle_archive accepted duplicate AppxBundleManifest.xml!")

                bad_bundle_sym = tmp_dir / "sym_bundle.msixbundle"
                bad_bundle_sym.write_bytes(good_bundle_bytes)
                with zipfile.ZipFile(bad_bundle_sym, "a") as zf:
                    zi = zipfile.ZipInfo("evil_link.txt")
                    zi.create_system = 3
                    zi.external_attr = 0o120777 << 16
                    zf.writestr(zi, b"target")
                try:
                    verify_msixbundle_archive(bad_bundle_sym, milestone="M4", expected_version=store_ver, store_mode=True)
                except ValueError as exc:
                    if "symbolic link" not in str(exc).lower():
                        raise AssertionError(f"bundle symlink error lacked 'symbolic link': {exc}") from exc
                else:
                    raise AssertionError("verify_msixbundle_archive accepted symlink entry!")

                # (b) .appxsym containing traversal, embedded cert.pfx, and fake non-MSF-7.00 PDBs
                def _make_bad_sym(entries: list[tuple[str, bytes]]) -> bytes:
                    b = io.BytesIO()
                    with zipfile.ZipFile(b, "w", compression=zipfile.ZIP_DEFLATED) as szf:
                        for n, data in entries:
                            szf.writestr(n, data)
                    return b.getvalue()

                msf_ok = PDB_MSF7_MAGIC + b"\x00" * 16
                base_pdb_entries = [(pdb, msf_ok) for pdb in sorted(REQUIRED_UPLOAD_PDBS)]
                bad_sym_cases = (
                    ("appxsym-traversal", base_pdb_entries + [("../evil.pdb", msf_ok)], "traversal"),
                    ("appxsym-pfx", base_pdb_entries + [("cert.pfx", b"KEY")], "cert.pfx"),
                    ("appxsym-fake-pdb", [(pdb, b"FAKE_NOT_MSF7") for pdb in sorted(REQUIRED_UPLOAD_PDBS)], "msf 7.00"),
                    ("appxsym-portable-pdb", [(pdb, b"BSJB\x01\x00\x00\x00") for pdb in sorted(REQUIRED_UPLOAD_PDBS)], "msf 7.00"),
                )
                for tag, sym_entries, expect_tok in bad_sym_cases:
                    up = tmp_dir / f"{tag}.msixupload"
                    with zipfile.ZipFile(up, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                        zf.writestr(f"TotalDrop-{store_ver}.msixbundle", good_bundle_bytes)
                        zf.writestr(f"TotalDrop_{store_ver}_x64.appxsym", sym_bytes)
                        zf.writestr(f"TotalDrop_{store_ver}_arm64.appxsym", _make_bad_sym(sym_entries))
                    try:
                        verify_msixupload_archive(up, milestone="M4", expected_version=store_ver, store_mode=True)
                    except ValueError as exc:
                        if expect_tok not in str(exc).lower():
                            raise AssertionError(f"R2-C2-F4({tag}): expected {expect_tok!r}, got: {exc}") from exc
                    else:
                        raise AssertionError(f"R2-C2-F4({tag}): tampered .msixupload unexpectedly passed!")
            return "both verifiers rejected bare standalone .msix + R2-C2-F4 bundle/.appxsym smuggling (dup manifest, symlink, traversal, .pfx, non-MSF-7.00 PDB)"

        def t2_f22_04() -> str:
            with tempfile.TemporaryDirectory(prefix="td-f22-04-") as tmp:
                tmp_dir = Path(tmp)
                x64_102 = _build_full_store_synthetic_msix(
                    repo_root, arch="x64", name=store_name, publisher=store_pub, version="1.0.2.0"
                )
                arm64_101 = _build_full_store_synthetic_msix(
                    repo_root, arch="arm64", name=store_name, publisher=store_pub, version="1.0.1.0"
                )
                # (a) outer bundle Version=1.0.2.0 vs inner arm64 Version=1.0.1.0
                ver_drift = tmp_dir / "ver-drift.msixbundle"
                ver_drift.write_bytes(
                    _build_synthetic_bundle_bytes(
                        name=store_name,
                        publisher=store_pub,
                        version="1.0.2.0",
                        packages=[
                            ("x64", "1.0.2.0", "TotalDrop_1.0.2.0_x64.msix", x64_102),
                            ("arm64", "1.0.2.0", "TotalDrop_1.0.1.0_arm64.msix", arm64_101),
                        ],
                    )
                )
                try:
                    verify_msixbundle_archive(ver_drift, milestone="M4", store_mode=True)
                except ValueError as exc:
                    msg = str(exc)
                    if "1.0.1.0" not in msg or "1.0.2.0" not in msg:
                        raise AssertionError(f"version mismatch error lacked both versions: {msg}") from exc
                else:
                    raise AssertionError("verify_msixbundle_archive accepted outer/inner version mismatch!")

                ok_v, msg_v = _cross_verify_repo_msix_tool(repo_root, bundle_path=ver_drift, store_mode=True)
                if ok_v or ("1.0.1.0" not in msg_v and "version" not in msg_v.lower()):
                    raise AssertionError(f"tools/verify-msix-artifact.py did not reject version drift: ok={ok_v}, msg={msg_v}")

                # (b) x64 Publisher != arm64 Publisher
                pub_other = "CN=22222222-3333-4444-5555-666666666666"
                x64_101 = _build_full_store_synthetic_msix(
                    repo_root, arch="x64", name=store_name, publisher=store_pub, version=store_ver
                )
                arm64_badpub = _build_full_store_synthetic_msix(
                    repo_root, arch="arm64", name=store_name, publisher=pub_other, version=store_ver
                )
                pub_drift = tmp_dir / "pub-drift.msixbundle"
                pub_drift.write_bytes(
                    _build_synthetic_bundle_bytes(
                        name=store_name,
                        publisher=store_pub,
                        version=store_ver,
                        packages=[
                            ("x64", store_ver, f"TotalDrop_{store_ver}_x64.msix", x64_101),
                            ("arm64", store_ver, f"TotalDrop_{store_ver}_arm64.msix", arm64_badpub),
                        ],
                    )
                )
                try:
                    verify_msixbundle_archive(pub_drift, milestone="M4", expected_version=store_ver, store_mode=True)
                except ValueError as exc:
                    msg = str(exc)
                    if "22222222" not in msg or "11111111" not in msg:
                        raise AssertionError(f"publisher mismatch error lacked both publishers: {msg}") from exc
                else:
                    raise AssertionError("verify_msixbundle_archive accepted cross-arch Publisher mismatch!")

                ok_p, msg_p = _cross_verify_repo_msix_tool(
                    repo_root, bundle_path=pub_drift, expected_version=store_ver, store_mode=True
                )
                if ok_p or "publisher" not in msg_p.lower():
                    raise AssertionError(f"tools/verify-msix-artifact.py did not reject publisher drift: ok={ok_p}, msg={msg_p}")
            return "both verifiers rejected outer/inner version divergence (1.0.2.0 vs 1.0.1.0) and publisher mismatch"

        def t2_f22_05() -> str:
            arm64_artifact_name, _arm64_ver = resolve_recipe_artifact_name(repo_root, "arm64")
            arm64_verify_sh = repo_root / "subplatforms" / "msix" / "arm64" / "verify.sh"
            with tempfile.TemporaryDirectory(prefix="td-f22-05-") as tmp:
                art_dir = Path(tmp)
                fake_msix = art_dir / arm64_artifact_name
                buf = io.BytesIO()
                with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
                    with tarfile.open(fileobj=gz, mode="w") as tf:
                        info = tarfile.TarInfo("AppxManifest.xml")
                        payload = b"<Package/>"
                        info.size = len(payload)
                        tf.addfile(info, io.BytesIO(payload))
                data = buf.getvalue()
                assert data[:2] == b"\x1f\x8b"
                fake_msix.write_bytes(data)
                _write_sha256sums(art_dir, arm64_artifact_name)

                p = subprocess.run(
                    [sh_exe, str(arm64_verify_sh), str(art_dir)],
                    cwd=str(repo_root),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                out = f"{p.stdout}\n{p.stderr}"
                if p.returncode == 0 or "not a real opc/zip msix" not in out.lower():
                    raise AssertionError(
                        f"arm64 verify.sh did not reject gzip tarball with expected OPC/ZIP diagnostic "
                        f"(rc={p.returncode}): {out}"
                    )

                try:
                    verify_msix_archive(fake_msix, arch="arm64", milestone="M4")
                except ValueError as exc:
                    if "not a valid opc/zip msix" not in str(exc).lower():
                        raise AssertionError(f"unexpected ARM64 gzip rejection reason: {exc}") from exc
                else:
                    raise AssertionError("verify_msix_archive accepted ARM64 gzip tarball!")
            return f"ARM64 gzipped tarball (1F 8B) named {arm64_artifact_name} rejected by both verify.sh and verify_msix_archive"

        record("T1-F22-03", t1_f22_03)
        record("T1-F22-05", t1_f22_05)
        record("T2-F22-01", t2_f22_01)
        record("T2-F22-02", t2_f22_02)
        record("T2-F22-04", t2_f22_04)
        record("T2-F22-05", t2_f22_05)

    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OPC/ZIP MSIX, bundle, upload, resources.pri, and subplatform verifier.")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="Repository root.")
    parser.add_argument("--msix", type=Path, default=None, help="Path to .msix archive to verify.")
    parser.add_argument("--bundle", type=Path, default=None, help="Path to .msixbundle archive to verify.")
    parser.add_argument("--msixupload", type=Path, default=None, help="Path to .msixupload archive to verify.")
    parser.add_argument("--expected-version", type=str, default=None, help="Expected 4-part version quad.")
    parser.add_argument("--store-mode", action="store_true", help="Enforce Microsoft Store Major >= 1, Revision == 0.")
    parser.add_argument("--arch", choices=("x64", "x86_64", "arm64"), default="x64")
    parser.add_argument("--milestone", choices=("M1", "M2", "M3", "M4"), default="M4")
    parser.add_argument("--expect-signed", action="store_true")
    parser.add_argument("--pri-dump", type=Path, default=None, help="Path to MakePri.exe XML dump.")
    parser.add_argument("--check-pri-file", type=Path, default=None, help="Verify standalone resources.pri file.")
    parser.add_argument("--resolve-recipe", action="store_true", help="Print artifact_name from RECIPE.toml.")
    parser.add_argument("--self-test-pri", action="store_true", help="Run realistic MakePri.exe XML dump self-tests.")
    parser.add_argument("--run-tests", action="store_true", help="Run cross-platform F06 and (M4) F22 tests.")
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)

    try:
        if args.resolve_recipe:
            name, _ver = resolve_recipe_artifact_name(args.root, args.arch)
            print(name)
            return 0
        if args.self_test_pri:
            note = self_test_pri_dump()
            print(f"verify_msix_opc PRI self-test OK: {note}")
            return 0
        if args.run_tests:
            results = run_cross_platform_tests(args.root, milestone=args.milestone)
            if args.json_out is not None:
                args.json_out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            failed = [k for k, v in results.items() if v["status"] != "PASS"]
            for k, v in sorted(results.items()):
                print(f"[{v['status']}] {k}: {v['detail']}")
            return 1 if failed else 0
        if args.check_pri_file is not None:
            verify_pri_file(args.check_pri_file)
            print(f"verify_msix_opc PRI OK: {args.check_pri_file}")
            return 0
        if args.msixupload is not None:
            info = verify_msixupload_archive(
                args.msixupload,
                milestone=args.milestone,
                expected_bundle_path=args.bundle,
                expected_version=args.expected_version,
                store_mode=args.store_mode,
            )
            print(f"verify_msix_opc MSIXUPLOAD OK: {args.msixupload} ({info['bundle']})")
            return 0
        if args.bundle is not None:
            info = verify_msixbundle_archive(
                args.bundle,
                milestone=args.milestone,
                expect_signed=args.expect_signed,
                expected_version=args.expected_version,
                store_mode=args.store_mode,
            )
            print(f"verify_msix_opc MSIXBUNDLE OK: {args.bundle} ({info['architectures']})")
            return 0
        if args.msix is not None:
            verify_msix_archive(
                args.msix,
                arch=args.arch,
                milestone=args.milestone,
                expect_signed=args.expect_signed,
                pri_dump=args.pri_dump,
            )
            print(f"verify_msix_opc MSIX OK: {args.msix}")
            return 0
        if args.pri_dump is not None:
            verify_pri_dump(args.pri_dump)
            print(f"verify_msix_opc PRI dump OK: {args.pri_dump}")
            return 0
        parser.error(
            "specify one of --msix, --bundle, --msixupload, --check-pri-file, --pri-dump, "
            "--resolve-recipe, --self-test-pri, or --run-tests"
        )
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
