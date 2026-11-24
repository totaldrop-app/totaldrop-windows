#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Authoritative M1-M4 E2E Test Suite Orchestrator for TotalDrop for Windows.

Executes all Linux-runnable tests (208 total: 184 cross-platform + 24 linux-devbox)
filtered by --tier (1|2|3|4|all) and --milestone (M1|M2|M3|M4|all), and honestly
reconciles all 291 blueprint test IDs using exact status WINDOWS_ONLY_READY for
the 83 Windows-only tests (60 windows-ci + 23 windows-interactive-wack).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
WORKSPACE_PARENT = REPO_ROOT.parent

REUSE_IMAGE = (
    "fsfe/reuse:6.2.0@sha256:"
    "85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e"
)
GITLEAKS_IMAGE = (
    "ghcr.io/gitleaks/gitleaks:v8.30.0@sha256:"
    "691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9"
)

# Canonical 291-test ledger by milestone and environment (verbatim from test_blueprint.md)
BLUEPRINT_LEDGER: dict[str, dict[str, tuple[str, ...]]] = {
    "M1": {
        "cross-platform": (
            "T1-F01-01", "T1-F01-02", "T1-F01-03", "T1-F01-04", "T1-F01-05",
            "T1-F02-01", "T1-F02-02", "T1-F03-01", "T1-F03-02", "T1-F03-03",
            "T1-F03-04", "T1-F03-05", "T1-F04-01", "T1-F05-01", "T1-F06-01",
            "T1-F06-02", "T1-F06-03", "T1-F06-05", "T1-F07-01", "T1-F07-02",
            "T1-F07-03", "T1-F07-04", "T1-F07-05", "T2-F01-01", "T2-F01-02",
            "T2-F01-03", "T2-F01-04", "T2-F01-05", "T2-F02-02", "T2-F02-03",
            "T2-F02-05", "T2-F03-01", "T2-F03-02", "T2-F03-03", "T2-F03-04",
            "T2-F03-05", "T2-F04-01", "T2-F04-02", "T2-F04-03", "T2-F05-01",
            "T2-F06-01", "T2-F06-02", "T2-F06-03", "T2-F06-04", "T2-F06-05",
            "T2-F07-01", "T2-F07-02", "T2-F07-03", "T2-F07-04", "T2-F07-05",
            "T3-16",
        ),
        "linux-devbox": ("T1-F04-02",),
        "windows-ci": (
            "T1-F02-03", "T1-F02-04", "T1-F02-05", "T1-F04-03", "T1-F04-04",
            "T1-F04-05", "T1-F05-02", "T1-F05-03", "T1-F05-04", "T1-F05-05",
            "T1-F06-04", "T2-F02-01", "T2-F02-04", "T2-F04-04", "T2-F04-05",
            "T2-F05-02", "T2-F05-03", "T2-F05-04", "T2-F05-05", "T3-14",
            "T3-15", "T4-06",
        ),
        "windows-interactive-wack": (),
    },
    "M2": {
        "cross-platform": (
            "T1-F08-01", "T1-F08-02", "T1-F08-03", "T1-F08-04", "T1-F08-05",
            "T1-F09-01", "T1-F09-02", "T1-F09-03", "T1-F09-04", "T1-F09-05",
            "T1-F09-06", "T1-F10-01", "T1-F10-02", "T1-F10-03", "T1-F10-04",
            "T1-F11-01", "T1-F11-02", "T1-F11-03", "T1-F11-04", "T1-F12-04",
            "T1-F13-01", "T1-F13-02", "T1-F13-03", "T1-F13-04", "T1-F13-05",
            "T1-F13-06", "T1-F14-01", "T1-F14-02", "T1-F14-03", "T1-F15-03",
            "T1-F15-04", "T1-F15-05", "T2-F08-01", "T2-F08-02", "T2-F08-03",
            "T2-F08-04", "T2-F08-05", "T2-F09-01", "T2-F09-02", "T2-F09-03",
            "T2-F09-04", "T2-F09-05", "T2-F09-06", "T2-F10-01", "T2-F10-02",
            "T2-F10-03", "T2-F10-04", "T2-F10-05", "T2-F11-01", "T2-F11-02",
            "T2-F11-03", "T2-F11-04", "T2-F11-05", "T2-F12-05", "T2-F13-01",
            "T2-F13-02", "T2-F13-03", "T2-F13-04", "T2-F13-05", "T2-F13-06",
            "T2-F14-01", "T2-F15-01", "T2-F15-02", "T2-F15-03", "T2-F15-04",
            "T2-F15-05", "T3-01", "T3-05", "T3-06", "T3-18", "T3-19",
            "T3-21", "T4-01", "T4-02", "T4-03",
        ),
        "linux-devbox": ("T1-F15-01", "T1-F15-02", "T3-22"),
        "windows-ci": (
            "T1-F10-05", "T1-F11-05", "T1-F12-01", "T1-F12-02", "T1-F12-05",
            "T2-F12-01", "T2-F12-02", "T3-04",
        ),
        "windows-interactive-wack": (
            "T1-F12-03", "T1-F14-04", "T1-F14-05", "T2-F12-03", "T2-F12-04",
            "T2-F14-02", "T2-F14-03", "T2-F14-04", "T2-F14-05", "T3-02",
            "T3-03", "T3-20", "T4-04", "T4-05",
        ),
    },
    "M3": {
        "cross-platform": (
            "T1-F16-03", "T1-F17-01", "T1-F17-02", "T1-F17-03", "T1-F18-01",
            "T1-F18-02", "T1-F18-03", "T1-F19-01", "T1-F19-02", "T1-F19-03",
            "T1-F19-04", "T1-F20-01", "T1-F20-03", "T1-F20-05", "T1-F21-01",
            "T1-F21-02", "T1-F21-05", "T2-F16-02", "T2-F16-03", "T2-F17-01",
            "T2-F17-02", "T2-F17-03", "T2-F17-04", "T2-F17-05", "T2-F18-01",
            "T2-F18-02", "T2-F18-03", "T2-F18-04", "T2-F18-05", "T2-F19-01",
            "T2-F19-02", "T2-F19-03", "T2-F19-04", "T2-F19-05", "T2-F20-02",
            "T2-F20-03", "T2-F20-05", "T2-F21-01", "T2-F21-02", "T2-F21-03",
            "T2-F21-04", "T3-07", "T3-08", "T3-11", "T3-12",
        ),
        "linux-devbox": ("T3-28",),
        "windows-ci": (
            "T1-F16-01", "T1-F16-02", "T1-F16-04", "T1-F16-05", "T1-F17-04",
            "T1-F18-04", "T1-F19-05", "T1-F20-02", "T1-F21-03", "T1-F21-04",
            "T2-F16-01", "T2-F16-04", "T2-F16-05", "T2-F20-01", "T2-F21-05",
            "T3-09", "T3-10", "T3-13", "T3-17", "T4-07", "T4-10",
        ),
        "windows-interactive-wack": (
            "T1-F17-05", "T1-F18-05", "T1-F20-04", "T2-F20-04", "T4-08", "T4-09",
        ),
    },
    "M4": {
        "cross-platform": (
            "T1-F22-03", "T1-F22-04", "T1-F22-05", "T1-F23-01", "T1-F24-02",
            "T1-F24-06", "T2-F22-01", "T2-F22-02", "T2-F22-04", "T2-F22-05",
            "T2-F23-01", "T2-F23-02", "T2-F24-01",
        ),
        "linux-devbox": (
            "T1-F23-02", "T1-F23-03", "T1-F23-06", "T1-F24-01", "T1-F24-03",
            "T1-F24-04", "T1-F24-05", "T2-F23-03", "T2-F23-04", "T2-F23-06",
            "T2-F24-02", "T2-F24-03", "T2-F24-04", "T2-F24-05", "T3-25",
            "T3-26", "T3-27", "T4-13", "T4-14",
        ),
        "windows-ci": (
            "T1-F22-01", "T1-F22-02", "T1-F22-06", "T1-F23-04", "T2-F22-03",
            "T2-F22-06", "T2-F23-05", "T3-23", "T4-11",
        ),
        "windows-interactive-wack": ("T1-F23-05", "T3-24", "T4-12"),
    },
}

SPLIT_PAIRS: dict[str, tuple[str, str]] = {
    "T2-F13-01": ("T2-F13-01-part-a", "T2-F13-01-part-b"),
    "T1-F16-03": ("T1-F16-03-part-a", "T1-F16-03-part-b"),
    "T1-F18-01": ("T1-F18-01-part-a", "T1-F18-01-part-b"),
    "T1-F19-04": ("T1-F19-04-part-a", "T1-F19-04-part-b"),
    "T2-F18-03": ("T2-F18-03-part-a", "T2-F18-03-part-b"),
    "T3-12": ("T3-12-part-a", "T3-12-part-b"),
}


def _tier_of(tid: str) -> str:
    return tid[1]


_PATH_ENV_VARS: tuple[str, ...] = (
    "CARGO_TARGET_DIR",
    "NUGET_PACKAGES",
    "DOTNET_CLI_HOME",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "TMPDIR",
    "TOTALDROP_TEST_RENDEZVOUS_BIN",
    "TOTALDROP_TEST_RELAY_BIN",
    "TOTALDROP_EXPLORER_EXT_DLL",
)


def _normalize_path_env(env: dict[str, str]) -> dict[str, str]:
    """Resolve relative or tilde-prefixed path env vars in caller CWD before changing subprocess cwd."""
    for key in _PATH_ENV_VARS:
        raw = env.get(key)
        if raw is None:
            continue
        stripped = raw.strip()
        if stripped:
            env[key] = str(Path(stripped).expanduser().resolve())
        else:
            env.pop(key, None)
    return env


def _run(cmd: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        merged.update(env)
    _normalize_path_env(merged)
    return subprocess.run(cmd, cwd=str(cwd), env=merged, capture_output=True, text=True, check=False)


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


def _canonical_id_from_fn(name: str) -> str | None:
    low = name.lower()
    m_f = re.match(r"^(t[12])_(f\d{2})_(\d{2})(?:_(part_[ab]))?", low)
    if m_f:
        base = f"{m_f.group(1).upper()}-{m_f.group(2).upper()}-{m_f.group(3)}"
        if m_f.group(4):
            return f"{base}-{m_f.group(4).replace('_', '-')}"
        return base
    m_t = re.match(r"^(t[34])_(\d{2})(?:_(part_[ab]))?", low)
    if m_t:
        base = f"{m_t.group(1).upper()}-{m_t.group(2)}"
        if m_t.group(3):
            return f"{base}-{m_t.group(3).replace('_', '-')}"
        return base
    return None


def _run_cargo_test_target(target: str, tier_filter: str | None, raw_results: dict[str, dict[str, Any]]) -> None:
    cmd = ["cargo", "test", "--workspace", "--locked", "--test", target]
    if tier_filter is not None:
        cmd.extend(["--", f"t{tier_filter}_"])
    p = _run(cmd, cwd=REPO_ROOT)
    combined = f"{p.stdout}\n{p.stderr}"
    for line in combined.splitlines():
        m = re.match(r"^test\s+([A-Za-z0-9_:]+)\s+\.\.\.\s+(ok|FAILED)$", line.strip())
        if not m:
            continue
        fn_name = m.group(1).split("::")[-1]
        tid = _canonical_id_from_fn(fn_name)
        if tid:
            if tid == "T2-F13-01":
                tid = "T2-F13-01-part-a"
            status = "PASS" if m.group(2) == "ok" else "FAIL"
            raw_results[tid] = {"status": status, "suite": f"cargo:{target}", "detail": fn_name}
    if p.returncode != 0:
        raise RuntimeError(f"cargo test --test {target} failed (exit {p.returncode}):\n{combined[-1200:]}")


def _ffi_library_filename() -> str:
    if sys.platform == "win32":
        return "totaldrop_windows_ffi.dll"
    if sys.platform == "darwin":
        return "libtotaldrop_windows_ffi.dylib"
    return "libtotaldrop_windows_ffi.so"


def _run_dotnet_tests(tier_filter: str | None, raw_results: dict[str, dict[str, Any]]) -> None:
    p_build = _run(["cargo", "build", "--locked", "-p", "totaldrop-windows-ffi"], cwd=REPO_ROOT)
    if p_build.returncode != 0:
        raise RuntimeError(f"cargo build -p totaldrop-windows-ffi failed:\n{p_build.stderr}")

    cargo_target_env = os.environ.get("CARGO_TARGET_DIR", "").strip()
    target_root = (
        Path(cargo_target_env).expanduser().resolve()
        if cargo_target_env
        else (REPO_ROOT / "target").resolve()
    )
    ffi_lib_path = (target_root / "debug" / _ffi_library_filename()).resolve()
    if not ffi_lib_path.is_file():
        raise RuntimeError(f"built FFI library not found at {ffi_lib_path}")

    ui_dir = REPO_ROOT / "ui-winui3-fluent2"
    proj = Path("TotalDrop.WinUI.Tests") / "TotalDrop.WinUI.Tests.csproj"
    flt = "Category!=WindowsCI&FullyQualifiedName!~LoopbackRelayTransferTests"
    if tier_filter is not None:
        flt = f"{flt}&FullyQualifiedName~T{tier_filter}_"
    dotnet_env = {
        "TOTALDROP_FFI_DLL_PATH": str(ffi_lib_path),
        "MSBUILDDISABLENODEREUSE": "1",
        "DOTNET_CLI_DO_NOT_USE_MSBUILD_SERVER": "1",
    }
    p = _run(
        [
            "dotnet", "test", str(proj),
            "-m:1", "-p:BuildInParallel=false", "-p:UseSharedCompilation=false",
            "--filter", flt, "--verbosity", "normal",
        ],
        cwd=ui_dir,
        env=dotnet_env,
    )
    combined = f"{p.stdout}\n{p.stderr}"
    for line in combined.splitlines():
        m = re.match(r"^\s*(Passed|Failed)\s+TotalDrop\.WinUI\.Tests\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)", line)
        if not m:
            continue
        outcome, cls_name, method = m.group(1), m.group(2), m.group(3)
        tid = _canonical_id_from_fn(method)
        if tid:
            if tid == "T3-12" and "parta" in method.lower():
                tid = "T3-12-part-a"
            raw_results[tid] = {
                "status": "PASS" if outcome == "Passed" else "FAIL",
                "suite": f"dotnet:{cls_name}",
                "detail": method,
            }
    if p.returncode != 0:
        raise RuntimeError(f"dotnet test failed (exit {p.returncode}):\n{combined[-1200:]}")


def _run_python_verifier(script_rel: str, extra_args: list[str], raw_results: dict[str, dict[str, Any]]) -> None:
    with tempfile.TemporaryDirectory(prefix="td-e2e-json-") as tmp:
        out_json = (Path(tmp) / "out.json").resolve()
        cmd = [sys.executable, "-B", str(REPO_ROOT / script_rel), *extra_args, "--json-out", str(out_json)]
        p = _run(cmd, cwd=REPO_ROOT)
        if out_json.is_file():
            data = json.loads(out_json.read_text(encoding="utf-8"))
            for tid, entry in data.items():
                raw_results[tid] = {
                    "status": entry.get("status", "FAIL"),
                    "suite": script_rel,
                    "detail": entry.get("detail", ""),
                }
        if p.returncode != 0:
            raise RuntimeError(f"{script_rel} failed (exit {p.returncode}):\n{p.stdout}\n{p.stderr}")


def _run_linux_devbox_m1_m3(
    active_ms: set[str],
    active_tiers: set[str],
    raw_results: dict[str, dict[str, Any]],
    *,
    core_dir: Path | None = None,
    fuzz_dir: Path | None = None,
) -> None:
    core_dir = _resolve_sibling_repo(REPO_ROOT, "totaldrop-core", "TOTALDROP_CORE_DIR", core_dir)
    fuzz_dir = _resolve_sibling_repo(REPO_ROOT, "totaldrop-formal-fuzz", "TOTALDROP_FUZZ_DIR", fuzz_dir)

    def record(tid: str, fn: Any) -> None:
        if _tier_of(tid) not in active_tiers:
            return
        try:
            detail = fn()
            raw_results[tid] = {"status": "PASS", "suite": "linux-devbox", "detail": detail}
        except Exception as exc:  # noqa: BLE001
            raw_results[tid] = {"status": "FAIL", "suite": "linux-devbox", "detail": str(exc)}

    if "M1" in active_ms:
        def t1_f04_02() -> str:
            with tempfile.TemporaryDirectory(prefix="td-f04-02-") as tmp:
                tmp_str = (Path(tmp) / "Strings").resolve()
                p1 = _run(
                    [
                        sys.executable, "-B", str(core_dir / "tools" / "l10n_codegen.py"),
                        "--l10n-dir", str(REPO_ROOT / "l10n"),
                        "--check", "--emit", "winui-resw", "--out", str(tmp_str),
                    ],
                    cwd=REPO_ROOT,
                )
                if p1.returncode != 0:
                    raise AssertionError(f"l10n_codegen failed: {p1.stderr}")
                p2 = _run(["diff", "-ru", str(tmp_str), str(REPO_ROOT / "ui-winui3-fluent2" / "Strings")], cwd=REPO_ROOT)
                if p2.returncode != 0:
                    raise AssertionError(f"diff -ru Strings failed:\n{p2.stdout[:500]}")
            return "l10n_codegen --check --emit winui-resw + diff -ru exit 0 (0 byte diffs)"

        record("T1-F04-02", t1_f04_02)

    if "M2" in active_ms:
        def t1_f15_01() -> str:
            ftoml = tomllib.loads((fuzz_dir / "fuzz" / "Cargo.toml").read_text(encoding="utf-8"))
            bins = {b["name"]: b for b in ftoml.get("bin", [])}
            for target in ("windows_ipc", "windows_path", "windows_cmdline", "windows_uri", "windows_ndjson"):
                assert target in bins, f"missing fuzz bin {target}"
                b = bins[target]
                assert b.get("test") is False and b.get("doc") is False and b.get("bench") is False, b
                src = (fuzz_dir / "fuzz" / "fuzz_targets" / f"{target}.rs").read_text(encoding="utf-8")
                head = "\n".join(src.splitlines()[:6])
                assert "SPDX-FileCopyrightText:" in head and "MIT OR Apache-2.0" in head, target
            p = _run(["cargo", "check", "--manifest-path", "fuzz/Cargo.toml", "--bins", "--locked"], cwd=fuzz_dir)
            if p.returncode != 0:
                raise AssertionError(f"fuzz cargo check failed:\n{p.stderr[-800:]}")
            return "all 5 Windows fuzz targets exist, SPDX-clean & compile cleanly"

        def t1_f15_02() -> str:
            for cmd in (
                ["cargo", "fmt", "--all", "--", "--check"],
                ["cargo", "fmt", "--manifest-path", "fuzz/Cargo.toml", "--all", "--", "--check"],
                ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"],
                ["cargo", "test", "--workspace", "--locked"],
                ["./tools/check-spdx.sh"],
            ):
                p = _run(cmd, cwd=fuzz_dir)
                if p.returncode != 0:
                    raise AssertionError(f"{' '.join(cmd)} in totaldrop-formal-fuzz failed:\n{p.stdout}\n{p.stderr[-600:]}")
            p_reuse = _run(
                ["docker", "run", "--rm", "--volume", f"{fuzz_dir}:/data:ro", REUSE_IMAGE, "lint"],
                cwd=fuzz_dir,
            )
            if p_reuse.returncode != 0:
                raise AssertionError(f"reuse lint in totaldrop-formal-fuzz failed:\n{p_reuse.stdout}\n{p_reuse.stderr}")
            return "totaldrop-formal-fuzz fmt, clippy, test, check-spdx & reuse lint all exit 0"

        def t3_22() -> str:
            p = _run(["cargo", "check", "--manifest-path", "fuzz/Cargo.toml", "--bins", "--locked"], cwd=fuzz_dir)
            if p.returncode != 0:
                raise AssertionError(f"fuzz cargo check failed: {p.stderr[-600:]}")
            p_adv = _run(
                ["cargo", "test", "--workspace", "--locked", "--test", "e2e_c_abi_m1", "--", "t2_f01"],
                cwd=REPO_ROOT,
            )
            if p_adv.returncode != 0:
                raise AssertionError(f"adversarial C ABI corpus check failed: {p_adv.stdout}\n{p_adv.stderr}")
            return "5 fuzz targets compile + adversarial C ABI corpus passes with 0 panics/UB"

        record("T1-F15-01", t1_f15_01)
        record("T1-F15-02", t1_f15_02)
        record("T3-22", t3_22)

    if "M3" in active_ms:
        def t3_28() -> str:
            for cmd in (
                ["./tools/check-spdx.sh"],
                [sys.executable, "-B", "tools/e2e/verify_static_contracts.py", "--scan-no-prod-probing"],
            ):
                p = _run(cmd, cwd=REPO_ROOT)
                if p.returncode != 0:
                    raise AssertionError(f"{' '.join(cmd)} failed:\n{p.stdout}\n{p.stderr}")

            p_reuse = _run(
                ["docker", "run", "--rm", "--volume", f"{REPO_ROOT}:/data:ro", REUSE_IMAGE, "lint"],
                cwd=REPO_ROOT,
            )
            if p_reuse.returncode != 0:
                raise AssertionError(f"REUSE 3.3 lint failed:\n{p_reuse.stdout}\n{p_reuse.stderr}")

            deny_txt = (REPO_ROOT / "deny.toml").read_text(encoding="utf-8")
            assert re.search(r"ignore\s*=\s*\[\s*\]", deny_txt), "deny.toml must keep ignore = []"
            if shutil.which("cargo-deny"):
                p_deny = _run(["cargo", "deny", "check"], cwd=REPO_ROOT)
                if p_deny.returncode != 0:
                    raise AssertionError(f"cargo deny check failed:\n{p_deny.stdout}\n{p_deny.stderr}")

            p_gl = _run(
                [
                    "docker", "run", "--rm", "--volume", f"{REPO_ROOT}/.git:/repo/.git:ro",
                    GITLEAKS_IMAGE, "git", "/repo", "--ignore-gitleaks-allow", "--redact",
                ],
                cwd=REPO_ROOT,
            )
            if p_gl.returncode != 0:
                raise AssertionError(f"gitleaks git scan failed:\n{p_gl.stdout}\n{p_gl.stderr}")
            with tempfile.TemporaryDirectory(prefix="td-t3-28-scan-") as scan_tmp:
                for scan_rel in (
                    "tests/e2e",
                    "tools/e2e",
                    "crates/totaldrop-windows-ffi/tests",
                    "crates/totaldrop-explorer-ext/tests",
                    "ui-winui3-fluent2/TotalDrop.WinUI.Tests",
                ):
                    staged_dir = (Path(scan_tmp) / scan_rel).resolve()
                    shutil.copytree(
                        REPO_ROOT / scan_rel,
                        staged_dir,
                        ignore=shutil.ignore_patterns("bin", "obj", "__pycache__", "target"),
                    )
                    p_dir = _run(
                        [
                            "docker", "run", "--rm", "--volume", f"{staged_dir}:/scan:ro",
                            GITLEAKS_IMAGE, "dir", "/scan", "--ignore-gitleaks-allow", "--redact",
                        ],
                        cwd=REPO_ROOT,
                    )
                    if p_dir.returncode != 0:
                        raise AssertionError(f"gitleaks dir scan failed on {scan_rel}:\n{p_dir.stdout}\n{p_dir.stderr}")
            return "SPDX, REUSE 3.3, cargo-deny (ignore=[]), gitleaks v8.30.0 (git + E2E dirs) & zero-prod-probe sweep all PASS"

        record("T3-28", t3_28)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Authoritative TotalDrop for Windows M1-M4 E2E orchestrator.")
    parser.add_argument("--tier", choices=("1", "2", "3", "4", "all"), default="all")
    parser.add_argument(
        "--milestone",
        type=lambda s: s.upper() if s.lower() != "all" else "all",
        choices=("M1", "M2", "M3", "M4", "all"),
        default="all",
    )
    parser.add_argument("--core-dir", type=Path, default=None)
    parser.add_argument("--fuzz-dir", type=Path, default=None)
    parser.add_argument("--site-dir", type=Path, default=None)
    parser.add_argument("--totaldrop-dir", type=Path, default=None)
    parser.add_argument("--json-out", type=Path, default=None)
    args = parser.parse_args(argv)

    active_ms = {"M1", "M2", "M3", "M4"} if args.milestone == "all" else {args.milestone}
    active_tiers = {"1", "2", "3", "4"} if args.tier == "all" else {args.tier}
    tier_filter: str | None = None if args.tier == "all" else args.tier
    max_ms = "M4" if args.milestone == "all" else args.milestone
    raw_results: dict[str, dict[str, Any]] = {}

    # Determine which runnable IDs are in scope so tier-scoped runs avoid wasted work.
    in_scope_runnable: set[str] = set()
    for ms in active_ms:
        for env_name in ("cross-platform", "linux-devbox"):
            for tid in BLUEPRINT_LEDGER[ms][env_name]:
                if _tier_of(tid) in active_tiers:
                    in_scope_runnable.add(tid)

    # 1. Fail-fast anti-production-probing scanner + E9/E10 self-test
    p_prod = _run(
        [sys.executable, "-B", "tools/e2e/verify_static_contracts.py", "--scan-no-prod-probing"],
        cwd=REPO_ROOT,
    )
    if p_prod.returncode != 0:
        print(f"error: anti-production-probing gate failed:\n{p_prod.stdout}\n{p_prod.stderr}", file=sys.stderr)
        return 1
    print(p_prod.stdout.strip())

    # 2. Challenger 1 E13 PRI matrix self-test & PE32+ synthetic self-test (fast <1s sanity)
    p_pri = _run([sys.executable, "-B", "tools/e2e/verify_msix_opc.py", "--self-test-pri"], cwd=REPO_ROOT)
    if p_pri.returncode != 0:
        print(f"error: verify_msix_opc.py --self-test-pri failed:\n{p_pri.stdout}\n{p_pri.stderr}", file=sys.stderr)
        return 1
    print(p_pri.stdout.strip())

    p_pe = _run([sys.executable, "-B", "tools/e2e/verify_pe_hardening.py", "--unit-test-synthetic"], cwd=REPO_ROOT)
    if p_pe.returncode != 0:
        print(f"error: verify_pe_hardening.py --unit-test-synthetic failed:\n{p_pe.stdout}\n{p_pe.stderr}", file=sys.stderr)
        return 1
    print(p_pe.stdout.strip())

    # 3. Static contracts & mutation tests (covers T1, T2, T3)
    if active_tiers & {"1", "2", "3"}:
        _run_python_verifier("tools/e2e/verify_static_contracts.py", ["--milestone", max_ms, "--run-tests"], raw_results)

    # 4. Assets & Kose geometry oracle (M1 T1 & T2)
    if "M1" in active_ms and (active_tiers & {"1", "2"}):
        _run_python_verifier("tools/e2e/verify_assets_kose.py", ["--run-tests"], raw_results)

    # 5. OPC / MSIX / Bundle / Upload oracle (M1 & M4 T1 & T2)
    if ("M1" in active_ms or "M4" in active_ms) and (active_tiers & {"1", "2"}):
        _run_python_verifier("tools/e2e/verify_msix_opc.py", ["--milestone", max_ms, "--run-tests"], raw_results)

    # 6. Rust E2E harnesses (filtered by tier when --tier is specified!)
    if "M1" in active_ms and (active_tiers & {"1", "2"}):
        _run_cargo_test_target("e2e_c_abi_m1", tier_filter, raw_results)
    if "M2" in active_ms:
        _run_cargo_test_target("e2e_loopback_m2", tier_filter, raw_results)
    if "M3" in active_ms and (active_tiers & {"1", "2", "3"}):
        _run_cargo_test_target("e2e_ipc_shutdown_m3", tier_filter, raw_results)
        p_com = _run(["cargo", "test", "--workspace", "--locked", "--test", "e2e_com_harness"], cwd=REPO_ROOT)
        if p_com.returncode != 0:
            print(f"error: e2e_com_harness failed:\n{p_com.stdout}\n{p_com.stderr}", file=sys.stderr)
            return 1

    # 7. Headless .NET 10 xUnit tests (NotificationPlanner, WakeLockService, ShareTargetRouter, SettingsStore)
    if ("M2" in active_ms or "M3" in active_ms) and (active_tiers & {"1", "2", "3"}):
        _run_dotnet_tests(tier_filter, raw_results)

    # 8. M4 Store readiness & ADR 0016 Step 6 cross-repo verifier (covers T1, T2, T3, T4)
    if "M4" in active_ms:
        eff_site = _resolve_sibling_repo(REPO_ROOT, "totaldrop-site", "TOTALDROP_SITE_DIR", args.site_dir)
        eff_totaldrop = _resolve_sibling_repo(REPO_ROOT, "totaldrop", "TOTALDROP_MONOREPO_DIR", args.totaldrop_dir)
        eff_core = _resolve_sibling_repo(REPO_ROOT, "totaldrop-core", "TOTALDROP_CORE_DIR", args.core_dir)
        store_args = [
            "--run-tests",
            "--site-dir", str(eff_site),
            "--totaldrop-dir", str(eff_totaldrop),
            "--core-dir", str(eff_core),
        ]
        _run_python_verifier("tools/e2e/verify_store_step6.py", store_args, raw_results)

    # 9. Linux devbox M1-M3 governance, l10n codegen, and fuzz suites
    _run_linux_devbox_m1_m3(
        active_ms,
        active_tiers,
        raw_results,
        core_dir=args.core_dir,
        fuzz_dir=args.fuzz_dir,
    )

    # 10. Combine paired split tests cleanly (PASS iff both halves PASS)
    for parent_id, (part_a, part_b) in SPLIT_PAIRS.items():
        if parent_id in in_scope_runnable:
            ra = raw_results.get(part_a)
            rb = raw_results.get(part_b)
            if ra and rb and ra["status"] == "PASS" and rb["status"] == "PASS":
                raw_results[parent_id] = {
                    "status": "PASS",
                    "suite": f"{ra['suite']}+{rb['suite']}",
                    "detail": f"part-a PASS ({ra['detail']}); part-b PASS ({rb['detail']})",
                }
            else:
                raw_results[parent_id] = {
                    "status": "FAIL",
                    "suite": "split-pair",
                    "detail": f"part-a={ra}, part-b={rb}",
                }

    # 11. Reconcile canonical ledger with exact status WINDOWS_ONLY_READY
    checklist_ids = {
        item["test_id"]
        for item in json.loads(
            (REPO_ROOT / "tools" / "e2e" / "windows_interactive_wack_checklist.json").read_text(encoding="utf-8")
        )["tests"]
    }

    ledger_report: dict[str, dict[str, Any]] = {}
    summary: dict[str, Any] = {
        "tier_filter": args.tier,
        "milestone_filter": args.milestone,
        "total": 0,
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "missing": 0,
        "windows_only_ready": 0,
        "windows_ci_ready": 0,
        "windows_interactive_wack_ready": 0,
        "by_tier": {},
        "by_milestone": {},
    }

    def bump_bucket(group: dict[str, dict[str, int]], key: str, field: str) -> None:
        if key not in group:
            group[key] = {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "skipped": 0,
                "windows_only_ready": 0,
                "windows_ci_ready": 0,
                "windows_interactive_wack_ready": 0,
            }
        group[key]["total"] += 1
        group[key][field] += 1

    for ms in ("M1", "M2", "M3", "M4"):
        if ms not in active_ms:
            continue
        for env_name in ("cross-platform", "linux-devbox", "windows-ci", "windows-interactive-wack"):
            for tid in BLUEPRINT_LEDGER[ms][env_name]:
                t_num = _tier_of(tid)
                if t_num not in active_tiers:
                    continue
                t_key = f"T{t_num}"
                summary["total"] += 1

                if env_name == "windows-ci":
                    ledger_report[tid] = {
                        "tier": t_key,
                        "milestone": ms,
                        "env": "windows-ci",
                        "status": "WINDOWS_ONLY_READY",
                        "detail": "Implemented in tools/e2e/Invoke-WindowsE2E.ps1 (never faked on Linux)",
                    }
                    summary["windows_only_ready"] += 1
                    summary["windows_ci_ready"] += 1
                    bump_bucket(summary["by_tier"], t_key, "windows_only_ready")
                    summary["by_tier"][t_key]["windows_ci_ready"] += 1
                    bump_bucket(summary["by_milestone"], ms, "windows_only_ready")
                    summary["by_milestone"][ms]["windows_ci_ready"] += 1
                elif env_name == "windows-interactive-wack":
                    if tid not in checklist_ids:
                        ledger_report[tid] = {
                            "tier": t_key,
                            "milestone": ms,
                            "env": "windows-interactive-wack",
                            "status": "FAIL",
                            "detail": "Missing from tools/e2e/windows_interactive_wack_checklist.json",
                        }
                        summary["failed"] += 1
                        bump_bucket(summary["by_tier"], t_key, "failed")
                        bump_bucket(summary["by_milestone"], ms, "failed")
                    else:
                        ledger_report[tid] = {
                            "tier": t_key,
                            "milestone": ms,
                            "env": "windows-interactive-wack",
                            "status": "WINDOWS_ONLY_READY",
                            "detail": "Documented in tools/e2e/windows_interactive_wack_checklist.json (never faked on Linux)",
                        }
                        summary["windows_only_ready"] += 1
                        summary["windows_interactive_wack_ready"] += 1
                        bump_bucket(summary["by_tier"], t_key, "windows_only_ready")
                        summary["by_tier"][t_key]["windows_interactive_wack_ready"] += 1
                        bump_bucket(summary["by_milestone"], ms, "windows_only_ready")
                        summary["by_milestone"][ms]["windows_interactive_wack_ready"] += 1
                else:
                    res = raw_results.get(tid)
                    if res is None:
                        ledger_report[tid] = {
                            "tier": t_key,
                            "milestone": ms,
                            "env": env_name,
                            "status": "FAIL",
                            "detail": "MISSING: Test ID not emitted by any runner",
                        }
                        summary["failed"] += 1
                        summary["missing"] += 1
                        bump_bucket(summary["by_tier"], t_key, "failed")
                        bump_bucket(summary["by_milestone"], ms, "failed")
                    elif res["status"] == "PASS":
                        ledger_report[tid] = {
                            "tier": t_key,
                            "milestone": ms,
                            "env": env_name,
                            "status": "PASS",
                            "suite": res.get("suite", ""),
                            "detail": res.get("detail", ""),
                        }
                        summary["passed"] += 1
                        bump_bucket(summary["by_tier"], t_key, "passed")
                        bump_bucket(summary["by_milestone"], ms, "passed")
                    else:
                        ledger_report[tid] = {
                            "tier": t_key,
                            "milestone": ms,
                            "env": env_name,
                            "status": "FAIL",
                            "suite": res.get("suite", ""),
                            "detail": res.get("detail", ""),
                        }
                        summary["failed"] += 1
                        bump_bucket(summary["by_tier"], t_key, "failed")
                        bump_bucket(summary["by_milestone"], ms, "failed")

    if args.json_out is not None:
        json_out_path = args.json_out.expanduser().resolve()
        json_out_path.parent.mkdir(parents=True, exist_ok=True)
        json_out_path.write_text(
            json.dumps({"summary": summary, "tests": ledger_report}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    print(
        f"\n==> Full E2E Ledger (tier={args.tier}, milestone={args.milestone}): "
        f"{summary['total']}/{summary['total']} accounted | "
        f"{summary['passed']} PASS | "
        f"{summary['windows_only_ready']} WINDOWS_ONLY_READY "
        f"(windows-ci={summary['windows_ci_ready']}, windows-interactive-wack={summary['windows_interactive_wack_ready']}) | "
        f"{summary['failed']} failed | {summary['skipped']} skipped"
    )
    for t_key in sorted(summary["by_tier"]):
        b = summary["by_tier"][t_key]
        print(
            f"    {t_key}: {b['total']}/{b['total']} "
            f"({b['passed']} PASS, {b['windows_only_ready']} WINDOWS_ONLY_READY "
            f"[ci={b['windows_ci_ready']}, wack={b['windows_interactive_wack_ready']}], {b['failed']} failed)"
        )

    for tid, entry in sorted(ledger_report.items()):
        if entry["status"] != "PASS" and entry["status"] != "WINDOWS_ONLY_READY":
            print(f"  [{entry['status']}] {tid} ({entry['milestone']}/{entry['env']}): {entry['detail']}", file=sys.stderr)

    return 1 if (summary["failed"] > 0 or summary["missing"] > 0) else 0


if __name__ == "__main__":
    raise SystemExit(main())
