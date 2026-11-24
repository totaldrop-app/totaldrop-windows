#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Deterministic generator and verifier for TotalDrop Windows 11 Kose MSIX assets.

Renders the canonical Kose brand geometry (`M55 15H97V57A42 42 0 1 1 55 15Z`)
using exact analytical scanline rasterization with 4x BOX supersampling into:
  - 45 scale/targetsize/altform-qualified PNG files (zero unqualified duplicates
    so `MakePri.exe` never emits `PRI175` duplicate entry errors), and
  - 1 multi-resolution PNG-in-ICO Win32 application icon (`TotalDrop.ico`).

Usage:
  python3 tools/render-windows-assets.py --write
  python3 tools/render-windows-assets.py --check
"""

from __future__ import annotations

import argparse
import io
import math
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
ASSETS_DIR = REPO_ROOT / "ui-winui3-fluent2" / "Assets"

# Canonical Kose SVG mark geometry (112x112 viewBox) and brand palette.
MARK_PATH = "M55 15H97V57A42 42 0 1 1 55 15Z"
VIEWBOX = 112.0
CIRCLE_CX = 55.0
CIRCLE_CY = 57.0
CIRCLE_R = 42.0
CORNER_X_MIN = 55.0
CORNER_X_MAX = 97.0
CORNER_Y_MIN = 15.0
CORNER_Y_MAX = 57.0
PLATED_MARK_SCALE = 0.68
ICO_CORNER_RADIUS = 22.0
SUPERSAMPLE = 4

VIOLET_RGB = (0x6D, 0x4A, 0xE0)
PAPER_RGB = (0xF4, 0xF2, 0xFB)
GLOW_RGB = (0xA6, 0x8B, 0xFF)

VIOLET_RGBA = (*VIOLET_RGB, 255)
PAPER_RGBA = (*PAPER_RGB, 255)

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
ICO_SIZES: tuple[int, ...] = (16, 24, 32, 48, 256)


@dataclass(frozen=True)
class AssetSpec:
    filename: str
    width: int
    height: int
    style: str  # "plated" | "unplated_dark" | "unplated_light"


def build_asset_specs() -> tuple[AssetSpec, ...]:
    """Return the exact 45 qualified PNG assets referenced by Package.*.appxmanifest."""
    specs: list[AssetSpec] = []

    def add_scales(prefix: str, pairs: tuple[tuple[int, int, int], ...]) -> None:
        for scale, w, h in pairs:
            specs.append(AssetSpec(f"{prefix}.scale-{scale}.png", w, h, "plated"))

    add_scales(
        "StoreLogo",
        ((100, 50, 50), (125, 63, 63), (150, 75, 75), (200, 100, 100), (400, 200, 200)),
    )
    add_scales(
        "Square44x44Logo",
        ((100, 44, 44), (125, 55, 55), (150, 66, 66), (200, 88, 88), (400, 176, 176)),
    )
    for size in (16, 24, 32, 48, 256):
        specs.append(AssetSpec(f"Square44x44Logo.targetsize-{size}.png", size, size, "plated"))
    for size in (16, 24, 32, 48, 256):
        specs.append(
            AssetSpec(
                f"Square44x44Logo.targetsize-{size}_altform-unplated.png",
                size,
                size,
                "unplated_dark",
            )
        )
    for size in (16, 24, 32, 48, 256):
        specs.append(
            AssetSpec(
                f"Square44x44Logo.targetsize-{size}_altform-lightunplated.png",
                size,
                size,
                "unplated_light",
            )
        )
    add_scales(
        "Square71x71Logo",
        ((100, 71, 71), (125, 89, 89), (150, 107, 107), (200, 142, 142), (400, 284, 284)),
    )
    add_scales(
        "Square150x150Logo",
        ((100, 150, 150), (125, 188, 188), (150, 225, 225), (200, 300, 300), (400, 600, 600)),
    )
    add_scales(
        "Wide310x150Logo",
        ((100, 310, 150), (125, 388, 188), (150, 465, 225), (200, 620, 300), (400, 1240, 600)),
    )
    add_scales(
        "Square310x310Logo",
        ((100, 310, 310), (125, 388, 388), (150, 465, 465), (200, 620, 620), (400, 1240, 1240)),
    )
    return tuple(specs)


PNG_SPECS: tuple[AssetSpec, ...] = build_asset_specs()
ICO_FILENAME = "TotalDrop.ico"
EXPECTED_FILENAMES: frozenset[str] = frozenset(
    [spec.filename for spec in PNG_SPECS] + [ICO_FILENAME]
)


def rasterize_kose_mask(
    width: int, height: int, mark_scale: float, supersample: int = SUPERSAMPLE
) -> Image.Image:
    """Analytically rasterize the canonical Kose mark into an anti-aliased L-mode mask."""
    sw = width * supersample
    sh = height * supersample
    s = (min(width, height) * supersample / VIEWBOX) * mark_scale
    ox = (sw - VIEWBOX * s) / 2.0
    oy = (sh - VIEWBOX * s) / 2.0
    r_sq = CIRCLE_R * CIRCLE_R

    buf = bytearray(sw * sh)
    y_min = max(0, int(math.floor(oy + CORNER_Y_MIN * s)) - 1)
    y_max = min(sh - 1, int(math.ceil(oy + (CIRCLE_CY + CIRCLE_R) * s)) + 1)

    for y in range(y_min, y_max + 1):
        vy = (y + 0.5 - oy) / s
        if vy < CORNER_Y_MIN or vy > CIRCLE_CY + CIRCLE_R:
            continue
        dy = vy - CIRCLE_CY
        disc = r_sq - dy * dy
        if disc < 0.0:
            if not (CORNER_Y_MIN <= vy <= CORNER_Y_MAX):
                continue
            vx_min = CORNER_X_MIN
            vx_max = CORNER_X_MAX
        else:
            dx = math.sqrt(disc)
            vx_min = CIRCLE_CX - dx
            vx_max = CIRCLE_CX + dx
            if CORNER_Y_MIN <= vy <= CORNER_Y_MAX:
                if CORNER_X_MIN < vx_min:
                    vx_min = CORNER_X_MIN
                if CORNER_X_MAX > vx_max:
                    vx_max = CORNER_X_MAX

        x0 = max(0, int(math.ceil(ox + vx_min * s - 0.5)))
        x1 = min(sw - 1, int(math.floor(ox + vx_max * s - 0.5)))
        if x0 <= x1:
            row_start = y * sw
            buf[row_start + x0 : row_start + x1 + 1] = b"\xff" * (x1 - x0 + 1)

    hi_mask = Image.frombytes("L", (sw, sh), bytes(buf))
    return hi_mask.resize((width, height), resample=Image.Resampling.BOX)


def rasterize_rounded_square_mask(
    size: int, corner_radius_vb: float = ICO_CORNER_RADIUS, supersample: int = SUPERSAMPLE
) -> Image.Image:
    """Analytically rasterize the canonical 112x112 rounded-square app icon plate."""
    ss = size * supersample
    s = ss / VIEWBOX
    r = corner_radius_vb
    r_sq = r * r
    inner_hi = VIEWBOX - r

    buf = bytearray(ss * ss)
    for y in range(ss):
        vy = (y + 0.5) / s
        if vy < 0.0 or vy > VIEWBOX:
            continue
        if vy < r:
            dy = r - vy
            dx = math.sqrt(max(0.0, r_sq - dy * dy))
            vx_min = r - dx
            vx_max = inner_hi + dx
        elif vy > inner_hi:
            dy = vy - inner_hi
            dx = math.sqrt(max(0.0, r_sq - dy * dy))
            vx_min = r - dx
            vx_max = inner_hi + dx
        else:
            vx_min = 0.0
            vx_max = VIEWBOX

        x0 = max(0, int(math.ceil(vx_min * s - 0.5)))
        x1 = min(ss - 1, int(math.floor(vx_max * s - 0.5)))
        if x0 <= x1:
            row_start = y * ss
            buf[row_start + x0 : row_start + x1 + 1] = b"\xff" * (x1 - x0 + 1)

    hi_mask = Image.frombytes("L", (ss, ss), bytes(buf))
    return hi_mask.resize((size, size), resample=Image.Resampling.BOX)


def render_png_image(spec: AssetSpec) -> Image.Image:
    """Render an RGBA Pillow image for the requested MSIX asset spec."""
    size = (spec.width, spec.height)
    if spec.style == "plated":
        bg = Image.new("RGBA", size, VIOLET_RGBA)
        fg = Image.new("RGBA", size, PAPER_RGBA)
        mask = rasterize_kose_mask(spec.width, spec.height, PLATED_MARK_SCALE)
        return Image.composite(fg, bg, mask)

    if spec.style == "unplated_dark":
        rgb = GLOW_RGB
    elif spec.style == "unplated_light":
        rgb = VIOLET_RGB
    else:
        raise ValueError(f"unsupported asset style: {spec.style}")

    img = Image.new("RGBA", size, (*rgb, 0))
    mask = rasterize_kose_mask(spec.width, spec.height, 1.0)
    img.putalpha(mask)
    return img


def render_ico_frame_image(size: int) -> Image.Image:
    """Render one canonical rounded-square Kose app icon frame for TotalDrop.ico."""
    dims = (size, size)
    plate_rgb = Image.new("RGB", dims, VIOLET_RGB)
    mark_rgb = Image.new("RGB", dims, PAPER_RGB)
    mark_mask = rasterize_kose_mask(size, size, PLATED_MARK_SCALE)
    blended = Image.composite(mark_rgb, plate_rgb, mark_mask).convert("RGBA")
    plate_alpha = rasterize_rounded_square_mask(size)
    blended.putalpha(plate_alpha)
    return blended


def encode_deterministic_png(img: Image.Image) -> bytes:
    """Encode an RGBA image into a metadata-free deterministic PNG byte stream."""
    rgba = img if img.mode == "RGBA" else img.convert("RGBA")
    buf = io.BytesIO()
    rgba.save(buf, format="PNG", compress_level=9, optimize=False)
    data = buf.getvalue()
    validate_png_chunks(data, expected_size=rgba.size, label="<in-memory>")
    return data


def build_ico(frames: list[tuple[int, bytes]]) -> bytes:
    """Pack deterministic PNG frames into a standard Win32 PNG-in-ICO container."""
    header = struct.pack("<HHH", 0, 1, len(frames))
    directory = bytearray()
    offset = 6 + 16 * len(frames)
    payloads = bytearray()
    for size, png_bytes in frames:
        dim_byte = 0 if size == 256 else size
        directory += struct.pack(
            "<BBBBHHII",
            dim_byte,
            dim_byte,
            0,
            0,
            1,
            32,
            len(png_bytes),
            offset,
        )
        payloads += png_bytes
        offset += len(png_bytes)
    return header + bytes(directory) + bytes(payloads)


def validate_png_chunks(
    data: bytes, expected_size: tuple[int, int], label: str
) -> None:
    """Verify strict PNG signature, CRC32s, pure IHDR/IDAT/IEND chunks, and RGBA geometry."""
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError(f"{label}: invalid PNG signature")
    pos = len(PNG_SIGNATURE)
    chunk_types: list[str] = []
    ihdr_size: tuple[int, int] | None = None

    while pos < len(data):
        if pos + 12 > len(data):
            raise ValueError(f"{label}: truncated PNG chunk header at byte {pos}")
        length = struct.unpack(">I", data[pos : pos + 4])[0]
        ctype_bytes = data[pos + 4 : pos + 8]
        chunk_start = pos + 8
        chunk_end = chunk_start + length
        crc_end = chunk_end + 4
        if crc_end > len(data):
            raise ValueError(f"{label}: truncated PNG chunk payload at byte {pos}")
        payload = data[chunk_start:chunk_end]
        expected_crc = struct.unpack(">I", data[chunk_end:crc_end])[0]
        actual_crc = zlib.crc32(ctype_bytes + payload) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError(
                f"{label}: CRC mismatch in chunk {ctype_bytes!r} "
                f"(expected {expected_crc:#010x}, got {actual_crc:#010x})"
            )
        ctype = ctype_bytes.decode("ascii")
        chunk_types.append(ctype)
        if ctype == "IHDR":
            if length != 13:
                raise ValueError(f"{label}: invalid IHDR length {length}")
            w, h, bit_depth, color_type, comp, filt, interlace = struct.unpack(
                ">IIBBBBB", payload
            )
            ihdr_size = (w, h)
            if (bit_depth, color_type, comp, filt, interlace) != (8, 6, 0, 0, 0):
                raise ValueError(
                    f"{label}: expected 8-bit non-interlaced RGBA PNG, got "
                    f"depth={bit_depth} color={color_type} comp={comp} filt={filt} interlace={interlace}"
                )
        pos = crc_end

    if pos != len(data):
        raise ValueError(f"{label}: trailing bytes after PNG stream")
    if not chunk_types or chunk_types[0] != "IHDR" or chunk_types[-1] != "IEND":
        raise ValueError(f"{label}: invalid PNG chunk sequence {chunk_types}")
    if any(ct not in ("IHDR", "IDAT", "IEND") for ct in chunk_types):
        raise ValueError(f"{label}: forbidden metadata/ancillary PNG chunks present: {chunk_types}")
    if chunk_types.count("IDAT") < 1:
        raise ValueError(f"{label}: missing IDAT chunk")
    if ihdr_size != expected_size:
        raise ValueError(f"{label}: expected dimensions {expected_size}, got {ihdr_size}")


def parse_and_validate_ico(data: bytes, label: str) -> dict[int, bytes]:
    """Validate ICO directory structure and return `{size: embedded_png_bytes}`."""
    if len(data) < 6:
        raise ValueError(f"{label}: ICO too short ({len(data)} bytes)")
    reserved, icon_type, count = struct.unpack("<HHH", data[:6])
    if reserved != 0 or icon_type != 1:
        raise ValueError(f"{label}: invalid ICONDIR header ({reserved}, {icon_type})")
    if count != len(ICO_SIZES):
        raise ValueError(f"{label}: expected {len(ICO_SIZES)} ICO frames, got {count}")

    frames: dict[int, bytes] = {}
    expected_offset = 6 + len(ICO_SIZES) * 16
    for idx, expected_size in enumerate(ICO_SIZES):
        entry_off = 6 + idx * 16
        if entry_off + 16 > len(data):
            raise ValueError(f"{label}: truncated ICONDIRENTRY #{idx}")
        w, h, color_count, res, planes, bpp, byte_len, img_off = struct.unpack(
            "<BBBBHHII", data[entry_off : entry_off + 16]
        )
        actual_w = 256 if w == 0 else w
        actual_h = 256 if h == 0 else h
        if (actual_w, actual_h) != (expected_size, expected_size):
            raise ValueError(
                f"{label}: ICO frame #{idx} expected {expected_size}x{expected_size}, "
                f"got {actual_w}x{actual_h}"
            )
        if color_count != 0 or res != 0 or planes != 1 or bpp != 32:
            raise ValueError(
                f"{label}: ICO frame #{idx} unexpected metadata "
                f"(colors={color_count}, reserved={res}, planes={planes}, bpp={bpp})"
            )
        if img_off != expected_offset:
            raise ValueError(
                f"{label}: ICO frame #{idx} offset mismatch "
                f"(expected {expected_offset}, got {img_off})"
            )
        if img_off + byte_len > len(data):
            raise ValueError(f"{label}: ICO frame #{idx} payload out of bounds")
        png_bytes = data[img_off : img_off + byte_len]
        validate_png_chunks(
            png_bytes,
            expected_size=(expected_size, expected_size),
            label=f"{label}[{expected_size}x{expected_size}]",
        )
        expected_offset = img_off + byte_len
        frames[expected_size] = png_bytes

    if expected_offset != len(data):
        raise ValueError(
            f"{label}: trailing bytes after final ICO frame "
            f"(expected {expected_offset} bytes, got {len(data)})"
        )

    return frames


def write_all(out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    # Remove any stale files so inventory stays strictly at the 46 canonical assets.
    for existing in sorted(out_dir.iterdir()):
        if existing.is_file() and existing.name not in EXPECTED_FILENAMES:
            existing.unlink()

    total_bytes = 0
    for spec in PNG_SPECS:
        img = render_png_image(spec)
        raw = encode_deterministic_png(img)
        (out_dir / spec.filename).write_bytes(raw)
        total_bytes += len(raw)

    ico_frames = [
        (size, encode_deterministic_png(render_ico_frame_image(size)))
        for size in ICO_SIZES
    ]
    ico_bytes = build_ico(ico_frames)
    parse_and_validate_ico(ico_bytes, ICO_FILENAME)
    (out_dir / ICO_FILENAME).write_bytes(ico_bytes)
    total_bytes += len(ico_bytes)

    print(
        f"wrote {len(PNG_SPECS)} qualified PNGs + {ICO_FILENAME} "
        f"({len(EXPECTED_FILENAMES)} files, {total_bytes} bytes) -> {out_dir}"
    )
    return 0


def check_all(out_dir: Path) -> int:
    errors: list[str] = []
    if not out_dir.is_dir():
        print(f"error: assets directory missing: {out_dir}", file=sys.stderr)
        return 1

    actual_files = {p.name for p in out_dir.iterdir() if p.is_file()}
    missing = sorted(EXPECTED_FILENAMES - actual_files)
    extra = sorted(actual_files - EXPECTED_FILENAMES)
    if missing:
        errors.append(f"missing {len(missing)} asset file(s): {', '.join(missing[:8])}")
    if extra:
        errors.append(f"unexpected extra asset file(s): {', '.join(extra[:8])}")
    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return 1

    # Two-pass in-memory determinism self-test.
    sample_spec = PNG_SPECS[0]
    pass1 = encode_deterministic_png(render_png_image(sample_spec))
    pass2 = encode_deterministic_png(render_png_image(sample_spec))
    if pass1 != pass2:
        errors.append("determinism self-test failed: PNG output changed across passes")

    # Verify all 45 PNGs: chunk purity + bit-exact decoded RGBA equality.
    for spec in PNG_SPECS:
        path = out_dir / spec.filename
        raw = path.read_bytes()
        try:
            validate_png_chunks(raw, expected_size=(spec.width, spec.height), label=spec.filename)
            with Image.open(io.BytesIO(raw)) as decoded:
                actual_rgba = decoded.convert("RGBA").tobytes()
            expected_rgba = render_png_image(spec).tobytes()
            if actual_rgba != expected_rgba:
                errors.append(f"{spec.filename}: decoded RGBA pixels differ from canonical Kose render")
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))

    # Verify TotalDrop.ico directory + embedded PNG frames bit-exact RGBA equality.
    ico_path = out_dir / ICO_FILENAME
    try:
        ico_frames = parse_and_validate_ico(ico_path.read_bytes(), ICO_FILENAME)
        for size in ICO_SIZES:
            with Image.open(io.BytesIO(ico_frames[size])) as decoded:
                actual_rgba = decoded.convert("RGBA").tobytes()
            expected_rgba = render_ico_frame_image(size).tobytes()
            if actual_rgba != expected_rgba:
                errors.append(
                    f"{ICO_FILENAME}[{size}x{size}]: decoded RGBA pixels differ from canonical Kose render"
                )
    except Exception as exc:  # noqa: BLE001
        errors.append(str(exc))

    if errors:
        for err in errors:
            print(f"error: {err}", file=sys.stderr)
        return 1

    print(
        f"windows-assets check OK: {len(PNG_SPECS)} qualified PNGs + {ICO_FILENAME} "
        f"({len(EXPECTED_FILENAMES)} files) verified bit-exact (Kose {MARK_PATH})."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate or verify deterministic Kose Windows 11 MSIX assets."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        action="store_true",
        help="Render and write all 46 canonical assets into ui-winui3-fluent2/Assets/.",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="Verify inventory, PNG/ICO chunk purity, and bit-exact RGBA match (default).",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ASSETS_DIR,
        help="Target assets directory (defaults to ui-winui3-fluent2/Assets).",
    )
    args = parser.parse_args(argv)
    if args.write:
        return write_all(args.out_dir)
    return check_all(args.out_dir)


if __name__ == "__main__":
    raise SystemExit(main())
