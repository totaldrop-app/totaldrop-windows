#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Opaque-box Kose MSIX visual asset & Win32 .ico geometric oracle (F03).

Validates byte-for-byte determinism, exact MRT scale/targetsize dimensions,
absence of conflicting bare PNGs (PRI175), unplated corner transparency,
WCAG 2.1 contrast against Windows 11 dark/light taskbars, Kose upper-right
square-corner asymmetry, and multi-resolution TotalDrop.ico binary framing.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any

from PIL import Image, ImageOps

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_ASSETS_DIR = REPO_ROOT / "ui-winui3-fluent2" / "Assets"
RENDER_SCRIPT = REPO_ROOT / "tools" / "render-windows-assets.py"

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"

EXPECTED_SCALE_DIMENSIONS: dict[str, tuple[int, int]] = {
    "StoreLogo.scale-100.png": (50, 50),
    "StoreLogo.scale-125.png": (63, 63),
    "StoreLogo.scale-150.png": (75, 75),
    "StoreLogo.scale-200.png": (100, 100),
    "StoreLogo.scale-400.png": (200, 200),
    "Square44x44Logo.scale-100.png": (44, 44),
    "Square44x44Logo.scale-125.png": (55, 55),
    "Square44x44Logo.scale-150.png": (66, 66),
    "Square44x44Logo.scale-200.png": (88, 88),
    "Square44x44Logo.scale-400.png": (176, 176),
    "Square44x44Logo.targetsize-16.png": (16, 16),
    "Square44x44Logo.targetsize-24.png": (24, 24),
    "Square44x44Logo.targetsize-32.png": (32, 32),
    "Square44x44Logo.targetsize-48.png": (48, 48),
    "Square44x44Logo.targetsize-256.png": (256, 256),
    "Square71x71Logo.scale-100.png": (71, 71),
    "Square71x71Logo.scale-125.png": (89, 89),
    "Square71x71Logo.scale-150.png": (107, 107),
    "Square71x71Logo.scale-200.png": (142, 142),
    "Square71x71Logo.scale-400.png": (284, 284),
    "Square150x150Logo.scale-100.png": (150, 150),
    "Square150x150Logo.scale-125.png": (188, 188),
    "Square150x150Logo.scale-150.png": (225, 225),
    "Square150x150Logo.scale-200.png": (300, 300),
    "Square150x150Logo.scale-400.png": (600, 600),
    "Wide310x150Logo.scale-100.png": (310, 150),
    "Wide310x150Logo.scale-125.png": (388, 188),
    "Wide310x150Logo.scale-150.png": (465, 225),
    "Wide310x150Logo.scale-200.png": (620, 300),
    "Wide310x150Logo.scale-400.png": (1240, 600),
    "Square310x310Logo.scale-100.png": (310, 310),
    "Square310x310Logo.scale-125.png": (388, 388),
    "Square310x310Logo.scale-150.png": (465, 465),
    "Square310x310Logo.scale-200.png": (620, 620),
    "Square310x310Logo.scale-400.png": (1240, 1240),
}

UNPLATED_SIZES: tuple[int, ...] = (16, 24, 32, 48, 256)

FORBIDDEN_BARE_PNGS: tuple[str, ...] = (
    "StoreLogo.png",
    "Square44x44Logo.png",
    "Square71x71Logo.png",
    "Square150x150Logo.png",
    "Wide310x150Logo.png",
    "Square310x310Logo.png",
)


def _srgb_channel(val: int) -> float:
    c = val / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def wcag_contrast(rgb1: tuple[int, int, int], rgb2: tuple[int, int, int]) -> float:
    l1 = 0.2126 * _srgb_channel(rgb1[0]) + 0.7152 * _srgb_channel(rgb1[1]) + 0.0722 * _srgb_channel(rgb1[2])
    l2 = 0.2126 * _srgb_channel(rgb2[0]) + 0.7152 * _srgb_channel(rgb2[1]) + 0.0722 * _srgb_channel(rgb2[2])
    hi, lo = (l1, l2) if l1 >= l2 else (l2, l1)
    return (hi + 0.05) / (lo + 0.05)


def iter_rgba_pixels(img: Image.Image) -> list[tuple[int, int, int, int]]:
    rgba = img.convert("RGBA")
    if hasattr(rgba, "get_flattened_data"):
        return list(rgba.get_flattened_data())
    raw = rgba.tobytes()
    return [
        (raw[i], raw[i + 1], raw[i + 2], raw[i + 3])
        for i in range(0, len(raw), 4)
    ]


def check_png_chunks_no_time(path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 8 or data[:8] != PNG_MAGIC:
        raise AssertionError(f"{path.name}: invalid PNG magic")
    pos = 8
    while pos + 8 <= len(data):
        chunk_len, chunk_type = struct.unpack_from(">I4s", data, pos)
        if chunk_type == b"tIME":
            raise AssertionError(f"{path.name}: forbidden PNG tIME chunk present")
        pos += 12 + chunk_len
        if chunk_type == b"IEND":
            break


def check_scale_and_bare_pngs(assets_dir: Path) -> None:
    for bare in FORBIDDEN_BARE_PNGS:
        if (assets_dir / bare).exists():
            raise AssertionError(f"forbidden unqualified bare PNG present (PRI175 conflict): {bare}")

    for name, expected_dim in EXPECTED_SCALE_DIMENSIONS.items():
        p = assets_dir / name
        if not p.is_file():
            raise AssertionError(f"missing required PNG asset: {name}")
        check_png_chunks_no_time(p)
        with Image.open(p) as img:
            if img.mode != "RGBA":
                raise AssertionError(f"{name}: expected mode RGBA, got {img.mode}")
            if img.size != expected_dim:
                raise AssertionError(f"{name}: expected size {expected_dim}, got {img.size}")


def check_unplated_icons(assets_dir: Path) -> None:
    dark_bg = (0x1C, 0x1C, 0x1C)
    light_bg = (0xF3, 0xF3, 0xF3)
    expected_dark_fg = (0xA6, 0x8B, 0xFF)
    expected_light_fg = (0x6D, 0x4A, 0xE0)

    for size in UNPLATED_SIZES:
        dark_path = assets_dir / f"Square44x44Logo.targetsize-{size}_altform-unplated.png"
        light_path = assets_dir / f"Square44x44Logo.targetsize-{size}_altform-lightunplated.png"
        for p, expected_fg, bg in (
            (dark_path, expected_dark_fg, dark_bg),
            (light_path, expected_light_fg, light_bg),
        ):
            if not p.is_file():
                raise AssertionError(f"missing unplated asset: {p.name}")
            check_png_chunks_no_time(p)
            with Image.open(p) as img:
                if img.mode != "RGBA":
                    raise AssertionError(f"{p.name}: expected RGBA, got {img.mode}")
                if img.size != (size, size):
                    raise AssertionError(f"{p.name}: expected {(size, size)}, got {img.size}")
                for cx, cy in ((0, 0), (size - 1, 0), (0, size - 1), (size - 1, size - 1)):
                    px = img.getpixel((cx, cy))
                    if px[3] != 0:
                        raise AssertionError(f"{p.name}: corner ({cx},{cy}) must have alpha==0, got {px}")
                pixels = iter_rgba_pixels(img)
                opaque_rgb = Counter((r, g, b) for (r, g, b, a) in pixels if a >= 250)
                if not opaque_rgb:
                    raise AssertionError(f"{p.name}: no opaque pixels found")
                dom_rgb, _ = opaque_rgb.most_common(1)[0]
                if dom_rgb != expected_fg:
                    raise AssertionError(f"{p.name}: dominant RGB {dom_rgb} != expected {expected_fg}")
                ratio = wcag_contrast(dom_rgb, bg)
                if ratio < 3.0:
                    raise AssertionError(f"{p.name}: WCAG contrast {ratio:.2f}:1 < 3.0:1")

        with Image.open(dark_path) as d_img, Image.open(light_path) as l_img:
            if d_img.tobytes() == l_img.tobytes():
                raise AssertionError(f"size {size}: altform-unplated and altform-lightunplated are identical")


def check_kose_asymmetry_and_palette(assets_dir: Path) -> None:
    scale = 256.0 / 112.0
    cx = 55.0 * scale
    cy = 57.0 * scale
    radius = 42.0 * scale
    ur = (round(cx + 0.78 * radius), round(cy - 0.78 * radius))
    ul = (round(cx - 0.78 * radius), round(cy - 0.78 * radius))

    for fname, expected_rgb in (
        ("Square44x44Logo.targetsize-256_altform-unplated.png", (0xA6, 0x8B, 0xFF)),
        ("Square44x44Logo.targetsize-256_altform-lightunplated.png", (0x6D, 0x4A, 0xE0)),
    ):
        p = assets_dir / fname
        if not p.is_file():
            raise AssertionError(f"missing {fname}")
        with Image.open(p) as img:
            rgba = img.convert("RGBA")
            ur_px = rgba.getpixel(ur)
            ul_px = rgba.getpixel(ul)
            if ur_px[3] <= 200 or ur_px[:3] != expected_rgb:
                raise AssertionError(
                    f"{fname}: Kose upper-right probe {ur} expected opaque {expected_rgb}, got {ur_px}"
                )
            if ul_px[3] != 0:
                raise AssertionError(
                    f"{fname}: Kose upper-left probe {ul} must have alpha==0 (mirrored?), got {ul_px}"
                )

    tile_path = assets_dir / "Square150x150Logo.scale-200.png"
    if not tile_path.is_file():
        raise AssertionError(f"missing {tile_path.name}")
    with Image.open(tile_path) as tile:
        pxs = set((r, g, b) for (r, g, b, a) in iter_rgba_pixels(tile) if a >= 250)
        if (0x6D, 0x4A, 0xE0) not in pxs:
            raise AssertionError(f"{tile_path.name}: missing canonical #6D4AE0 violet pixels")
        if (0xF4, 0xF2, 0xFB) not in pxs:
            raise AssertionError(f"{tile_path.name}: missing canonical #F4F2FB paper pixels")


def parse_ico_frames(ico_path: Path) -> dict[int, Image.Image]:
    data = ico_path.read_bytes()
    if len(data) < 6:
        raise AssertionError(f"{ico_path.name}: truncated ICO header")
    reserved, img_type, count = struct.unpack_from("<HHH", data, 0)
    if reserved != 0 or img_type != 1 or count < 5:
        raise AssertionError(f"{ico_path.name}: invalid ICO header {(reserved, img_type, count)}")
    frames: dict[int, Image.Image] = {}
    for idx in range(count):
        off = 6 + idx * 16
        if off + 16 > len(data):
            raise AssertionError(f"{ico_path.name}: truncated ICONDIRENTRY {idx}")
        w, h, _colors, _res, _planes, _bpp, size_bytes, img_offset = struct.unpack_from("<BBBBHHII", data, off)
        width = 256 if w == 0 else w
        height = 256 if h == 0 else h
        if width != height:
            raise AssertionError(f"{ico_path.name}: non-square frame {width}x{height}")
        if img_offset + size_bytes > len(data):
            raise AssertionError(f"{ico_path.name}: frame {width} out of bounds")
        chunk = data[img_offset : img_offset + size_bytes]
        if chunk.startswith(PNG_MAGIC):
            im = Image.open(io.BytesIO(chunk))
            im.load()
            if im.size != (width, height):
                raise AssertionError(f"{ico_path.name}: PNG frame size mismatch {im.size} != {(width, height)}")
            frames[width] = im.convert("RGBA")
        else:
            # Verify BMP DIB header decodes cleanly.
            if len(chunk) < 40:
                raise AssertionError(f"{ico_path.name}: truncated BMP DIB frame {width}")
            dib_size, dib_w, dib_h = struct.unpack_from("<Iii", chunk, 0)
            if dib_size < 40 or dib_w != width or abs(dib_h) != height * 2:
                raise AssertionError(f"{ico_path.name}: invalid BMP DIB frame {width}")
            with Image.open(ico_path) as im:
                frame = im.ico.getimage((width, height))
                frame.load()
                if frame.size != (width, height):
                    raise AssertionError(
                        f"{ico_path.name}: BMP DIB frame size mismatch {frame.size} != {(width, height)}"
                    )
                frames[width] = frame.convert("RGBA")
    expected_sizes = {16, 24, 32, 48, 256}
    if set(frames.keys()) != expected_sizes:
        raise AssertionError(f"{ico_path.name}: expected sizes {sorted(expected_sizes)}, got {sorted(frames.keys())}")
    return frames


def check_16x16_coverage(assets_dir: Path) -> None:
    for fname in (
        "Square44x44Logo.targetsize-16_altform-unplated.png",
        "Square44x44Logo.targetsize-16_altform-lightunplated.png",
    ):
        p = assets_dir / fname
        with Image.open(p) as img:
            rgba = img.convert("RGBA")
            for cx, cy in ((0, 0), (15, 0), (0, 15), (15, 15)):
                if rgba.getpixel((cx, cy))[3] != 0:
                    raise AssertionError(f"{fname}: 16x16 outer corner ({cx},{cy}) must be transparent")
            pixels = iter_rgba_pixels(rgba)
            opaque = sum(1 for (_, _, _, a) in pixels if a > 0)
            ratio = opaque / len(pixels)
            if not (0.20 <= ratio <= 0.90):
                raise AssertionError(f"{fname}: 16x16 opaque ratio {ratio:.4f} outside [0.20, 0.90]")

    frames = parse_ico_frames(assets_dir / "TotalDrop.ico")
    im16 = frames[16]
    for cx, cy in ((0, 0), (15, 0), (0, 15), (15, 15)):
        if im16.getpixel((cx, cy))[3] != 0:
            raise AssertionError(f"TotalDrop.ico 16x16: corner ({cx},{cy}) must be transparent")
    px16 = iter_rgba_pixels(im16)
    opaque_ratio = sum(1 for (_, _, _, a) in px16 if a > 0) / len(px16)
    if not (0.85 <= opaque_ratio <= 0.99):
        raise AssertionError(f"TotalDrop.ico 16x16: plated opaque ratio {opaque_ratio:.4f} outside [0.85, 0.99]")
    paper_count = sum(
        1
        for (r, g, b, a) in px16
        if a >= 200 and abs(r - 0xF4) <= 25 and abs(g - 0xF2) <= 25 and abs(b - 0xFB) <= 25
    )
    paper_ratio = paper_count / len(px16)
    if not (0.15 <= paper_ratio <= 0.40):
        raise AssertionError(
            f"TotalDrop.ico 16x16: paper #F4F2FB glyph ratio {paper_ratio:.4f} outside [0.15, 0.40]"
        )


def verify_directory(assets_dir: Path) -> None:
    check_scale_and_bare_pngs(assets_dir)
    check_unplated_icons(assets_dir)
    check_kose_asymmetry_and_palette(assets_dir)
    parse_ico_frames(assets_dir / "TotalDrop.ico")
    check_16x16_coverage(assets_dir)


def _run_render(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", str(RENDER_SCRIPT), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


def _sha256_tree(directory: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for p in sorted(directory.iterdir()):
        if p.is_file():
            out[p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def run_all_f03_tests(assets_dir: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}

    def record(test_id: str, fn: Any) -> None:
        try:
            detail = fn()
            results[test_id] = {"status": "PASS", "detail": detail or "ok"}
        except Exception as exc:  # noqa: BLE001
            results[test_id] = {"status": "FAIL", "detail": str(exc)}

    def t1_f03_01() -> str:
        proc = _run_render("--out-dir", str(assets_dir), "--check")
        if proc.returncode != 0:
            raise AssertionError(f"render-windows-assets.py --check failed: {proc.stdout}\n{proc.stderr}")
        return proc.stdout.strip()

    def t1_f03_02() -> str:
        check_scale_and_bare_pngs(assets_dir)
        return f"verified {len(EXPECTED_SCALE_DIMENSIONS)} scale/targetsize PNGs and 0 bare PNGs"

    def t1_f03_03() -> str:
        check_unplated_icons(assets_dir)
        return "verified 10 unplated/lightunplated icons, corner alpha==0, WCAG contrast >= 3.0:1"

    def t1_f03_04() -> str:
        check_kose_asymmetry_and_palette(assets_dir)
        return "verified Kose upper-right asymmetry and #6D4AE0/#F4F2FB palette"

    def t1_f03_05() -> str:
        frames = parse_ico_frames(assets_dir / "TotalDrop.ico")
        return f"verified TotalDrop.ico sizes {sorted(frames.keys())}"

    def t2_f03_01() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f03-bitflip-") as tmp:
            dst = Path(tmp) / "Assets"
            shutil.copytree(assets_dir, dst)
            target = dst / "Square44x44Logo.targetsize-256_altform-unplated.png"
            raw = bytearray(target.read_bytes())
            raw[-10] ^= 0x01
            target.write_bytes(bytes(raw))
            proc = _run_render("--out-dir", str(dst), "--check")
            combined = f"{proc.stdout}\n{proc.stderr}"
            if proc.returncode == 0:
                raise AssertionError("bit-flipped PNG unexpectedly passed --check")
            if target.name not in combined:
                raise AssertionError(f"bit-flip failure did not name {target.name}: {combined}")
        return "bit-flipped 256px unplated PNG rejected with filename"

    def t2_f03_02() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f03-miss-extra-") as tmp:
            tmp_root = Path(tmp)
            # (a) Missing lightunplated 16px
            dir_a = tmp_root / "a"
            shutil.copytree(assets_dir, dir_a)
            missing_name = "Square44x44Logo.targetsize-16_altform-lightunplated.png"
            (dir_a / missing_name).unlink()
            proc_a = _run_render("--out-dir", str(dir_a), "--check")
            out_a = f"{proc_a.stdout}\n{proc_a.stderr}"
            if proc_a.returncode == 0 or missing_name not in out_a:
                raise AssertionError(f"missing-asset mutation failed: rc={proc_a.returncode}, out={out_a}")

            # (b) Stray bare StoreLogo.png (PRI175 hazard)
            dir_b = tmp_root / "b"
            shutil.copytree(assets_dir, dir_b)
            shutil.copy2(dir_b / "StoreLogo.scale-100.png", dir_b / "StoreLogo.png")
            proc_b = _run_render("--out-dir", str(dir_b), "--check")
            out_b = f"{proc_b.stdout}\n{proc_b.stderr}"
            if proc_b.returncode == 0 or "StoreLogo.png" not in out_b:
                raise AssertionError(f"stray bare StoreLogo.png mutation failed: rc={proc_b.returncode}, out={out_b}")
        return "missing 16px lightunplated and stray StoreLogo.png both rejected"

    def t2_f03_03() -> str:
        with tempfile.TemporaryDirectory(prefix="td-f03-determ-") as tmp:
            tmp_a = Path(tmp) / "run_a"
            tmp_b = Path(tmp) / "run_b"
            p_a = _run_render("--out-dir", str(tmp_a), "--write")
            if p_a.returncode != 0:
                raise AssertionError(f"run A failed: {p_a.stdout}\n{p_a.stderr}")
            time.sleep(1.1)
            p_b = _run_render("--out-dir", str(tmp_b), "--write")
            if p_b.returncode != 0:
                raise AssertionError(f"run B failed: {p_b.stdout}\n{p_b.stderr}")
            hashes_a = _sha256_tree(tmp_a)
            hashes_b = _sha256_tree(tmp_b)
            if hashes_a != hashes_b or len(hashes_a) != 46:
                raise AssertionError(f"non-deterministic asset generation: {len(hashes_a)} vs {len(hashes_b)}")
        return "46/46 files identical SHA-256 across 1.1s wall-clock boundary"

    def t2_f03_04() -> str:
        check_16x16_coverage(assets_dir)
        return "16x16 unplated & ICO plated/glyph coverage within normative bounds"

    def t2_f03_05() -> str:
        # Clean check must pass first.
        check_kose_asymmetry_and_palette(assets_dir)
        with tempfile.TemporaryDirectory(prefix="td-f03-mirror-") as tmp:
            tmp_root = Path(tmp)
            for tag, fname in (
                ("unplated", "Square44x44Logo.targetsize-256_altform-unplated.png"),
                ("lightunplated", "Square44x44Logo.targetsize-256_altform-lightunplated.png"),
            ):
                dst = tmp_root / tag
                shutil.copytree(assets_dir, dst)
                target = dst / fname
                with Image.open(target) as img:
                    mirrored = ImageOps.mirror(img.convert("RGBA"))
                    mirrored.save(target, format="PNG")
                proc = subprocess.run(
                    [sys.executable, "-B", str(Path(__file__).resolve()), "--out-dir", str(dst)],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                out = f"{proc.stdout}\n{proc.stderr}"
                if proc.returncode == 0 or fname not in out:
                    raise AssertionError(f"mirrored {fname} was not rejected: rc={proc.returncode}, out={out}")
        return "clean lightunplated/unplated pass; mirrored copies of both rejected naming files"

    record("T1-F03-01", t1_f03_01)
    record("T1-F03-02", t1_f03_02)
    record("T1-F03-03", t1_f03_03)
    record("T1-F03-04", t1_f03_04)
    record("T1-F03-05", t1_f03_05)
    record("T2-F03-01", t2_f03_01)
    record("T2-F03-02", t2_f03_02)
    record("T2-F03-03", t2_f03_03)
    record("T2-F03-04", t2_f03_04)
    record("T2-F03-05", t2_f03_05)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify Kose MSIX visual assets and TotalDrop.ico.")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_ASSETS_DIR, help="Assets directory to verify.")
    parser.add_argument("--run-tests", action="store_true", help="Run all 10 F03 positive and negative mutation tests.")
    parser.add_argument("--json-out", type=Path, default=None, help="Optional JSON report path.")
    args = parser.parse_args(argv)

    if args.run_tests:
        results = run_all_f03_tests(args.out_dir)
        if args.json_out is not None:
            args.json_out.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        failed = [k for k, v in results.items() if v["status"] != "PASS"]
        for k, v in sorted(results.items()):
            print(f"[{v['status']}] {k}: {v['detail']}")
        return 1 if failed else 0

    try:
        verify_directory(args.out_dir)
    except Exception as exc:  # noqa: BLE001
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"verify_assets_kose OK: {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
