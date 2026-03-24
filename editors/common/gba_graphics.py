"""
GBA graphics helpers: LZ77 decompress (pret ``lz.c``) and **pure-Python** palette/tile decode aligned with pret
``tools/gbagfx/gfx.c`` (``ReadGbaPalette``, 4bpp/8bpp tile layout, ``DecodeNonAffineTilemap``). PNG output uses Pillow.

Palette formats: ucp4, lzp4, **huff4p4** / **huff8p8** (GBA Huffman), ucp4:HEX…, ucp8:N / lzp8:N.
Sprite sheets: ucs/lzs (and **uct/lzt** — same layout as 4bpp/8bpp ``.4bpp`` / ``.8bpp`` in gbagfx); **huff4**/**huff8** mirror **lz** for Huff-compressed blobs (pret ``huff.c``).
Bare **uct4** / **lzt8** (no ``xWxH``): LZ77 or raw blob is only tiles; tile count = len÷32 or len÷64; drawn as one row (matches gbagfx tile strip + ``-width N`` style).
Tilemaps: ucm/lzm 4bpp or 8bpp non-affine maps (2 bytes/cell, same layout as [Tilemap Studio GBA_4BPP](https://github.com/Rangi42/tilemap-studio/blob/master/src/tilemap-format.cpp) / pret ``NonAffineTile``);
  tileset = another NamedAnchor; optional ``|palette`` — if omitted, Tools uses the tileset anchor’s ``|palette`` link.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Tuple

from .gba_huff import (
    compress_gba_huff,
    decompress_gba_huff,
    decompress_gba_huff_with_consumed,
    is_gba_huff_header,
)

# Repo root: editors/common -> repo
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_MODULE_DIR, "..", ".."))
GBAGFX_PATH = os.path.join(_REPO_ROOT, "deps", "gbagfx")

_log_tilemap = logging.getLogger("channeler.tilemap_import")

# ygodm8 ``ygodm_encode`` (pret gbagfx hook before Huff compress) — see
# https://github.com/shinny4/ygodm8/commit/0d99ae0544f892a345c3dda2a8bc7369da00e093
_YGODM_ARR = (1, 1, 1, 1, 1, 1, 1, 57)
_YGODM_ARR2 = (632, 632, 632, 632, 632, 632, 632, 56)


def ygodm_encode_inplace(buf: bytearray) -> None:
    """In-place transform matching C ``ygodm_encode`` (unsigned 8-bit wrap)."""
    buffer = 0
    for i in range(80):
        temp = 0
        for j in range(80):
            if buffer >= len(buf):
                buf.extend(b"\x00" * (buffer + 1 - len(buf)))
            buf[buffer] = (buf[buffer] - temp) & 0xFF
            temp = (temp + buf[buffer]) & 0xFF
            buffer += _YGODM_ARR[j % 8]
        buffer -= _YGODM_ARR2[i % 8]


def ygodm_decode_inplace(buf: bytearray) -> None:
    """Inverse of :func:`ygodm_encode_inplace` for ROM display (after Huff decompress).

    The C encoder resets ``temp`` each outer ``i``; the pointer walk visits byte indices ``0..6399``
    **exactly once** each, so each final byte is the ``v_new`` from its step and ``temp_before`` can
    be recovered from the encoded blob alone (same recurrence as encode: ``temp += v_new`` along the
    walk). Undo in reverse pointer order: ``plain = (enc + temp_before) & 0xFF``.
    """
    arr = _YGODM_ARR
    arr2 = _YGODM_ARR2
    enc = bytes(buf).ljust(6400, b"\x00")
    ops: List[Tuple[int, int]] = []
    buffer = 0
    for i in range(80):
        temp = 0
        for j in range(80):
            v = enc[buffer]
            ops.append((buffer, temp))
            temp = (temp + v) & 0xFF
            buffer += arr[j % 8]
        buffer -= arr2[i % 8]
    if len(buf) < 6400:
        buf.extend(b"\x00" * (6400 - len(buf)))
    for pos, temp_before in reversed(ops):
        buf[pos] = (buf[pos] + temp_before) & 0xFF


def _split_reshef_graphics_prefix(s: str) -> Tuple[str, bool]:
    """`` `reshef`ucs…`` / `` `reshef`huff8…`` prefix (standalone graphics Format)."""
    t = str(s or "").strip()
    m = re.match(r"^\s*`reshef`\s*", t, re.IGNORECASE)
    if m:
        return t[m.end() :].lstrip(), True
    return t, False


def _apply_ygodm_decode_after_decompress(spec: Any, data: bytes) -> bytes:
    """Undo ygodm8 ``ygodm_encode`` after LZ/Huff decompress (matches game pipeline)."""
    if not getattr(spec, "reshef_ygodm", False):
        return data
    if not (getattr(spec, "lz", False) or getattr(spec, "huff_bpp", None) is not None):
        return data
    b = bytearray(data)
    ygodm_decode_inplace(b)
    return bytes(b)


def _apply_ygodm_encode_before_compress(spec: Any, data: bytes) -> bytes:
    """Apply ``ygodm_encode`` before LZ/Huff compress (matches ygodm8 gbagfx ``-ygodm``)."""
    if not getattr(spec, "reshef_ygodm", False):
        return data
    if not (getattr(spec, "lz", False) or getattr(spec, "huff_bpp", None) is not None):
        return data
    b = bytearray(data)
    ygodm_encode_inplace(b)
    return bytes(b)


def repo_gbagfx_path() -> str:
    """Path to optional ``deps/gbagfx`` (not used for decode; kept for compatibility / manual use)."""
    return GBAGFX_PATH


def _hex_preview(data: bytes, max_bytes: int = 96) -> str:
    """Space-separated hex dump; truncates with note if longer than max_bytes."""
    if not data:
        return "(empty)"
    n = min(len(data), max_bytes)
    body = " ".join(f"{b:02X}" for b in data[:n])
    if len(data) > n:
        return f"{body} … (+{len(data) - n} more bytes; total len={len(data)})"
    return f"{body} (len={len(data)})"


def decompress_gba_lz77(data: bytes, max_out: int = 1 << 22) -> bytes:
    """
    Decompress type ``0x10`` LZ stream as in pret ``tools/gbagfx/lz.c`` (pokeemerald / gbagfx).

    Per that implementation: for each flags byte, walk bits **MSB first** (``flags & 0x80``,
    then ``flags <<= 1``). **1** = 2-byte back-reference; **0** = one literal byte.
    Oversized blocks clamp like Ruby/Sapphire tilesets in ``lz.c``.

    See: https://github.com/pret/pokeemerald/blob/master/tools/gbagfx/lz.c

    Raises ValueError on corrupt/short input (message includes hex context for debugging).
    """
    if len(data) < 4:
        raise ValueError(
            f"LZ77 input too short ({len(data)} bytes, need >= 4).\n"
            f"  Data: {_hex_preview(data, 64)}"
        )
    if data[0] != 0x10:
        raise ValueError(
            f"Expected LZ77 type 0x10, got 0x{data[0]:02X}.\n"
            f"  First 32 bytes: {_hex_preview(data[:32], 32)}"
        )
    dest_size = data[1] | (data[2] << 8) | (data[3] << 16)
    if dest_size <= 0 or dest_size > max_out:
        raise ValueError(
            f"Invalid LZ77 decompressed size {dest_size} (max allowed {max_out}).\n"
            f"  Header bytes: 10 {_hex_preview(data[1:4], 8)}\n"
            f"  First 48 bytes of stream: {_hex_preview(data[:48], 48)}"
        )
    out = bytearray()
    src_pos = 4
    while len(out) < dest_size and src_pos < len(data):
        flags = data[src_pos]
        src_pos += 1
        for _ in range(8):
            if len(out) >= dest_size:
                break
            # pret lz.c: MSB first; bit 1 = back-reference, bit 0 = literal
            if flags & 0x80:
                if src_pos + 1 >= len(data):
                    raise ValueError(
                        "LZ77 truncated while reading back-reference (need 2 bytes).\n"
                        f"  src_pos={src_pos}, input len={len(data)}, output len={len(out)}, dest_size={dest_size}\n"
                        f"  Input from start: {_hex_preview(data[:96], 96)}\n"
                        f"  Last 24 bytes of input: {_hex_preview(data[-24:], 24)}\n"
                        f"  Output tail: {_hex_preview(bytes(out[-48:]), 48)}"
                    )
                b0, b1 = data[src_pos], data[src_pos + 1]
                src_pos += 2
                block_size = (b0 >> 4) + 3
                block_distance = (((b0 & 0x0F) << 8) | b1) + 1
                block_pos = len(out) - block_distance
                if block_pos < 0:
                    raise ValueError(
                        "LZ77 invalid lookback (block_pos < 0; distance exceeds output so far).\n"
                        f"  block_distance={block_distance}, output_len={len(out)}, block_pos={block_pos}.\n"
                        f"  ref bytes at input[{src_pos - 2}:{src_pos}]: b0=0x{b0:02X} b1=0x{b1:02X}\n"
                        f"  -> block_size={block_size} (high nibble of b0 + 3)\n"
                        f"  (pret gbagfx lz.c: flags MSB-first, bit 1 = ref)\n"
                        f"  declared dest_size={dest_size}, src_pos after ref={src_pos}\n"
                        f"  input ({len(data)} bytes) from start:\n    {_hex_preview(data[:128], 128)}\n"
                        f"  input window around ref (~{src_pos}):\n    {_hex_preview(data[max(0, src_pos - 16) : min(len(data), src_pos + 24)], 80)}\n"
                        f"  output so far ({len(out)} bytes), tail:\n    {_hex_preview(bytes(out[-min(64, len(out)) :]), 64)}"
                    )
                if len(out) + block_size > dest_size:
                    block_size = dest_size - len(out)
                for j in range(block_size):
                    if len(out) >= dest_size:
                        break
                    out.append(out[block_pos + j])
            else:
                if src_pos >= len(data):
                    raise ValueError(
                        "LZ77 truncated while reading literal.\n"
                        f"  src_pos={src_pos}, input len={len(data)}, output len={len(out)}, dest_size={dest_size}\n"
                        f"  Input from start: {_hex_preview(data[:96], 96)}\n"
                        f"  Last 32 bytes of input: {_hex_preview(data[-32:], 32)}\n"
                        f"  Output tail: {_hex_preview(bytes(out[-48:]), 48)}"
                    )
                out.append(data[src_pos])
                src_pos += 1
            flags <<= 1
    if len(out) != dest_size:
        raise ValueError(
            f"LZ77 size mismatch: decompressed {len(out)} bytes, header declared {dest_size}.\n"
            f"  src_pos={src_pos}, input len={len(data)}\n"
            f"  Input from start: {_hex_preview(data[:128], 128)}\n"
            f"  Input end: {_hex_preview(data[-48:], 48)}\n"
            f"  Output tail: {_hex_preview(bytes(out[-64:]), 64)}"
        )
    return bytes(out)


def decompress_gba_lz77_with_consumed(data: bytes, max_out: int = 1 << 22) -> Tuple[bytes, int]:
    """Like :func:`decompress_gba_lz77` but also returns compressed input byte length (for footprint / replace)."""
    if len(data) < 4:
        raise ValueError("LZ77 input too short")
    if data[0] != 0x10:
        raise ValueError("Expected LZ77 type 0x10")
    dest_size = data[1] | (data[2] << 8) | (data[3] << 16)
    if dest_size <= 0 or dest_size > max_out:
        raise ValueError("Invalid LZ77 decompressed size")
    out = bytearray()
    src_pos = 4
    while len(out) < dest_size and src_pos < len(data):
        flags = data[src_pos]
        src_pos += 1
        for _ in range(8):
            if len(out) >= dest_size:
                break
            if flags & 0x80:
                if src_pos + 1 >= len(data):
                    raise ValueError("LZ77 truncated (ref)")
                b0, b1 = data[src_pos], data[src_pos + 1]
                src_pos += 2
                block_size = (b0 >> 4) + 3
                block_distance = (((b0 & 0x0F) << 8) | b1) + 1
                block_pos = len(out) - block_distance
                if block_pos < 0:
                    raise ValueError("LZ77 invalid lookback")
                if len(out) + block_size > dest_size:
                    block_size = dest_size - len(out)
                for j in range(block_size):
                    if len(out) >= dest_size:
                        break
                    out.append(out[block_pos + j])
            else:
                if src_pos >= len(data):
                    raise ValueError("LZ77 truncated (literal)")
                out.append(data[src_pos])
                src_pos += 1
            flags <<= 1
    if len(out) != dest_size:
        raise ValueError("LZ77 size mismatch")
    return bytes(out), src_pos


def _compression_from_format_prefix(prefix: str) -> Tuple[bool, Optional[int]]:
    """Map ``uc`` / ``lz`` / ``huff4`` / ``huff8`` to ``(use_lz77, huff_bpp)``. LZ and Huff are mutually exclusive."""
    p = prefix.lower()
    if p == "uc":
        return False, None
    if p == "lz":
        return True, None
    if p == "huff4":
        return False, 4
    if p == "huff8":
        return False, 8
    raise ValueError(f"unknown graphics compression prefix {prefix!r}")


def _huff_bpp_matches_tile_bpp(huff_bpp: Optional[int], pixel_bpp: int) -> bool:
    """Huff ``0x2n`` mode ``n`` must match how tile/palette bytes are packed (4bpp vs 6/8bpp)."""
    if huff_bpp is None:
        return True
    if huff_bpp == 4:
        return pixel_bpp == 4
    if huff_bpp == 8:
        return pixel_bpp in (6, 8)
    return False


def compress_gba_lz77(uncompressed: bytes, *, min_distance: int = 1) -> bytes:
    """
    LZ77 type ``0x10`` compression matching pret ``pokeemerald/tools/gbagfx/lz.c`` ``LZCompress``
    (same layout as :func:`decompress_gba_lz77`).
    """
    src = uncompressed
    src_size = len(src)
    if src_size <= 0:
        raise ValueError("LZ77: empty input")
    if src_size > 0xFFFFFF:
        raise ValueError("Data too large for GBA LZ77 (max 16 MiB)")
    worst_case = 4 + src_size + ((src_size + 7) // 8)
    worst_case = (worst_case + 3) & ~3
    dest = bytearray(worst_case)
    dest[0] = 0x10
    dest[1] = src_size & 0xFF
    dest[2] = (src_size >> 8) & 0xFF
    dest[3] = (src_size >> 16) & 0xFF
    src_pos = 0
    dest_pos = 4
    while True:
        flag_byte_pos = dest_pos
        dest_pos += 1
        dest[flag_byte_pos] = 0
        for i in range(8):
            best_block_distance = 0
            best_block_size = 0
            block_distance = min_distance
            while block_distance <= src_pos and block_distance <= 0x1000:
                block_start = src_pos - block_distance
                block_size = 0
                while (
                    block_size < 18
                    and src_pos + block_size < src_size
                    and src[block_start + block_size] == src[src_pos + block_size]
                ):
                    block_size += 1
                if block_size > best_block_size:
                    best_block_distance = block_distance
                    best_block_size = block_size
                    if block_size == 18:
                        break
                block_distance += 1
            if best_block_size >= 3:
                dest[flag_byte_pos] |= 0x80 >> i
                src_pos += best_block_size
                best_block_size -= 3
                best_block_distance -= 1
                dest[dest_pos] = (best_block_size << 4) | ((best_block_distance >> 8) & 0x0F)
                dest[dest_pos + 1] = best_block_distance & 0xFF
                dest_pos += 2
            else:
                dest[dest_pos] = src[src_pos]
                dest_pos += 1
                src_pos += 1
            if src_pos == src_size:
                remainder = dest_pos % 4
                if remainder != 0:
                    pad = 4 - remainder
                    dest[dest_pos : dest_pos + pad] = b"\x00" * pad
                    dest_pos += pad
                return bytes(dest[:dest_pos])


def rgb888_to_gba_rgb555(r: int, g: int, b: int) -> int:
    """Pack 8-bit RGB to GBA 15-bit color (little-endian word in ROM)."""
    r5 = min(31, (r * 31) // 255) if r > 0 else 0
    g5 = min(31, (g * 31) // 255) if g > 0 else 0
    b5 = min(31, (b * 31) // 255) if b > 0 else 0
    return r5 | (g5 << 5) | (b5 << 10)


def gba_palette_bytes_from_rgb888_list(colors: List[Tuple[int, int, int]], max_colors: int) -> bytes:
    """``max_colors`` entries (e.g. 16 for 4bpp, or 16–256 for 8bpp) → ``max_colors * 2`` bytes RGB555 LE."""
    out = bytearray()
    for i in range(max_colors):
        if i < len(colors):
            r, g, b = colors[i]
            w = rgb888_to_gba_rgb555(r, g, b)
        else:
            w = 0
        out.extend(w.to_bytes(2, "little"))
    return bytes(out)


def is_valid_8bpp_palette_color_count(n: int) -> bool:
    """True if ``n`` is 16–256 and a multiple of 16 (one or more GBA 16-color rows)."""
    return 16 <= n <= 256 and (n % 16) == 0


def parse_8bpp_palette_color_count(n: int) -> int:
    """Validate and return ``n`` for 8bpp palette import/export sizes."""
    if not is_valid_8bpp_palette_color_count(n):
        raise ValueError(
            "8bpp palette color count must be 16–256 and a multiple of 16 "
            "(each hardware row is 16 colors)."
        )
    return n


def encode_gba_tile_4bpp_from_indices(indices: List[int]) -> bytes:
    """64 indices 0–15 → 32 bytes (pret nybble order)."""
    if len(indices) != 64:
        raise ValueError("need 64 indices for 4bpp tile")
    out = bytearray(32)
    for row in range(8):
        for cb in range(4):
            lo = indices[row * 8 + cb * 2] & 0xF
            hi = indices[row * 8 + cb * 2 + 1] & 0xF
            out[row * 4 + cb] = lo | (hi << 4)
    return bytes(out)


def encode_gba_tile_8bpp_from_indices(indices: List[int]) -> bytes:
    if len(indices) != 64:
        raise ValueError("need 64 indices for 8bpp tile")
    return bytes(indices)


def encode_gba_tile_6bpp_from_indices(indices: List[int]) -> bytes:
    """Inverse of :func:`decode_gba_tile_6bpp_indices` — 64 indices 0–63 → 48 bytes."""
    if len(indices) != 64:
        raise ValueError("need 64 indices for 6bpp tile")
    for i in indices:
        if i < 0 or i > 0x3F:
            raise ValueError("6bpp palette index out of 0..63 range")
    out = bytearray(48)
    for ry in range(8):
        row_idxs = indices[ry * 8 : (ry + 1) * 8]
        for g in range(2):
            chunk = row_idxs[g * 4 : (g + 1) * 4]
            v = 0
            for k in range(4):
                v |= (chunk[k] & 0x3F) << (k * 6)
            out[ry * 6 + g * 3 + 0] = v & 0xFF
            out[ry * 6 + g * 3 + 1] = (v >> 8) & 0xFF
            out[ry * 6 + g * 3 + 2] = (v >> 16) & 0xFF
    return bytes(out)


# Manual import: index 0 reserved as “burner” transparency (neon green in RGB888).
MANUAL_BURNER_RGB: Tuple[int, int, int] = (0, 255, 0)


def validate_manual_palette_color_count(bpp: int, n: int) -> int:
    """
    Total palette slots including index 0 (burner). Must be a multiple of 16 where applicable.

    - **4bpp**: exactly 16 colors.
    - **6bpp**: exactly 64 colors (hardware 6-bit indices).
    - **8bpp**: 16–256, multiple of 16.
    """
    if bpp == 4:
        if n != 16:
            raise ValueError("4bpp mode requires exactly 16 palette colors (one hardware row).")
        return 16
    if bpp == 6:
        if n != 64:
            raise ValueError("6bpp mode requires exactly 64 palette colors.")
        return 64
    if bpp == 8:
        return parse_8bpp_palette_color_count(int(n))
    raise ValueError(f"Unsupported bpp: {bpp}")


def _pil_rgba_quantized_tiles(
    rgba_im: Any,
    *,
    bpp: int,
) -> Tuple[bytes, bytes, int, int, str]:
    """
    Quantize RGBA to GBA tiles. Tile grid size follows the image's pixel dimensions, each rounded **up**
    to a multiple of 8 (GBA tile size). The image is **not** scaled: it is pasted at the top-left on a
    white canvas; only padding is added if the pixel size is not already a multiple of 8.
    Returns ``(tile_bytes, pal_bytes, width_tiles, height_tiles, err)`` with ``err`` empty on success.
    """
    Image = _require_pillow()
    im = rgba_im
    if im.mode != "RGBA":
        im = im.convert("RGBA")
    iw, ih = im.size
    if iw < 1 or ih < 1:
        return b"", b"", 0, 0, "Image has zero width or height."
    tw = max(1, (iw + 7) // 8)
    th = max(1, (ih + 7) // 8)
    wpx, hpx = tw * 8, th * 8
    bg = Image.new("RGBA", (wpx, hpx), (255, 255, 255, 255))
    bg.paste(im, (0, 0), im.split()[3])
    rgb = bg.convert("RGB")
    ncols = 16 if bpp == 4 else 256
    try:
        q = rgb.quantize(colors=ncols, method=Image.Quantize.MEDIANCUT)  # type: ignore[attr-defined]
    except AttributeError:
        q = rgb.quantize(colors=ncols, method=2)
    pal_raw = q.getpalette()
    if not pal_raw:
        return b"", b"", 0, 0, "Could not build palette from image."
    # PIL palette: up to 256 * 3 bytes
    colors: List[Tuple[int, int, int]] = []
    for i in range(ncols):
        if i * 3 + 2 < len(pal_raw):
            colors.append((pal_raw[i * 3], pal_raw[i * 3 + 1], pal_raw[i * 3 + 2]))
        else:
            colors.append((0, 0, 0))
    pal_bytes = gba_palette_bytes_from_rgb888_list(colors, ncols)
    idxs = list(q.getdata())
    tile_data = bytearray()
    for ty in range(th):
        for tx in range(tw):
            tile_idx: List[int] = []
            for py in range(8):
                for px in range(8):
                    ix = tx * 8 + px
                    iy = ty * 8 + py
                    tile_idx.append(idxs[iy * wpx + ix])
            if bpp == 4:
                tile_data.extend(encode_gba_tile_4bpp_from_indices(tile_idx))
            else:
                tile_data.extend(encode_gba_tile_8bpp_from_indices(tile_idx))
    return bytes(tile_data), pal_bytes, tw, th, ""


def _idx_flat_and_palette_burner(
    rgba_im: Any,
    wpx: int,
    hpx: int,
    palette_color_count: int,
    *,
    bpp_for_pad: int,
    burner_rgb: Tuple[int, int, int] = MANUAL_BURNER_RGB,
) -> Tuple[List[int], bytes, str]:
    """
    Resize ``rgba_im`` to ``wpx×hpx``, quantize solid pixels to ``palette_color_count - 1`` colors,
    index 0 = ``burner_rgb`` for transparent pixels (alpha < 128). Returns flat indices and ROM palette.
    """
    Image = _require_pillow()
    try:
        validate_manual_palette_color_count(bpp_for_pad, palette_color_count)
    except ValueError as e:
        return [], b"", str(e)
    im = rgba_im
    if im.mode != "RGBA":
        im = im.convert("RGBA")
    if wpx < 1 or hpx < 1:
        return [], b"", "Invalid pixel dimensions."
    n_solid = palette_color_count - 1
    if n_solid < 1:
        return [], b"", "Palette must have room for at least one non-burner color."
    try:
        resample = Image.Resampling.LANCZOS  # type: ignore[attr-defined]
    except AttributeError:
        resample = Image.LANCZOS  # type: ignore[attr-defined]
    im = im.resize((wpx, hpx), resample)
    a = im.split()[3]
    sentinel = (255, 0, 255)
    if sentinel == burner_rgb:
        sentinel = (255, 0, 254)
    rgb_work = Image.new("RGB", (wpx, hpx), sentinel)
    rgb_work.paste(im.convert("RGB"), (0, 0), a)
    try:
        q = rgb_work.quantize(colors=n_solid, method=Image.Quantize.MEDIANCUT)  # type: ignore[attr-defined]
    except AttributeError:
        q = rgb_work.quantize(colors=n_solid, method=2)
    pal_raw = q.getpalette()
    if not pal_raw:
        return [], b"", "Could not build palette from image."
    a_arr = list(a.getdata())
    idx_q = list(q.getdata())
    idx_flat: List[int] = []
    for i in range(wpx * hpx):
        if a_arr[i] < 128:
            idx_flat.append(0)
        else:
            idx_flat.append(1 + int(idx_q[i]))
    colors_q: List[Tuple[int, int, int]] = []
    for i in range(n_solid):
        o = i * 3
        if o + 2 < len(pal_raw):
            colors_q.append((pal_raw[o], pal_raw[o + 1], pal_raw[o + 2]))
        else:
            colors_q.append((0, 0, 0))
    master: List[Tuple[int, int, int]] = [burner_rgb] + colors_q
    while len(master) < palette_color_count:
        master.append((0, 0, 0))
    master = master[:palette_color_count]
    if bpp_for_pad == 4:
        pal_bytes = gba_palette_bytes_from_rgb888_list(master, 16)
    elif bpp_for_pad == 6:
        pal_bytes = gba_palette_bytes_from_rgb888_list(master, 64)
    else:
        full = list(master) + [(0, 0, 0)] * (256 - len(master))
        pal_bytes = gba_palette_bytes_from_rgb888_list(full[:256], 256)
    return idx_flat, pal_bytes, ""


def _pil_rgba_tiles_burner_quantize(
    rgba_im: Any,
    *,
    bpp: int,
    width_tiles: int,
    height_tiles: int,
    palette_color_count: int,
    burner_rgb: Tuple[int, int, int] = MANUAL_BURNER_RGB,
) -> Tuple[bytes, bytes, int, int, str]:
    """
    Resize/composite to ``width_tiles*8`` × ``height_tiles*8`` px, reserve palette index **0** as
    ``burner_rgb`` (transparent via PNG alpha), quantize solid pixels to ``palette_color_count - 1``
    colors, emit tile bytes and GBA palette (4bpp: 32 bytes, 6bpp: 128, 8bpp: 512 master).
    """
    tw, th = int(width_tiles), int(height_tiles)
    if tw < 1 or th < 1:
        return b"", b"", 0, 0, "Width and height in tiles must be ≥ 1."
    wpx, hpx = tw * 8, th * 8
    idx_flat, pal_bytes, err = _idx_flat_and_palette_burner(
        rgba_im,
        wpx,
        hpx,
        palette_color_count,
        bpp_for_pad=bpp,
        burner_rgb=burner_rgb,
    )
    if err:
        return b"", b"", 0, 0, err
    tile_data = bytearray()
    for ty in range(th):
        for tx in range(tw):
            tile_idx: List[int] = []
            for py in range(8):
                for px in range(8):
                    ix = tx * 8 + px
                    iy = ty * 8 + py
                    tile_idx.append(idx_flat[iy * wpx + ix])
            if bpp == 4:
                tile_data.extend(encode_gba_tile_4bpp_from_indices(tile_idx))
            elif bpp == 6:
                tile_data.extend(encode_gba_tile_6bpp_from_indices(tile_idx))
            else:
                tile_data.extend(encode_gba_tile_8bpp_from_indices(tile_idx))
    return bytes(tile_data), pal_bytes, tw, th, ""


def build_sprite_payload_for_rom(tile_bytes: bytes, spec: GraphicsAnchorSpec) -> bytes:
    """Wrap tile bytes with optional LZ77 or Huff (must match ``spec`` / anchor storage)."""
    payload = _apply_ygodm_encode_before_compress(spec, tile_bytes)
    if spec.lz:
        return compress_gba_lz77(payload)
    if spec.huff_bpp is not None:
        return compress_gba_huff(payload, spec.huff_bpp)
    return payload


def palette_payload_for_rom(pal_bytes: bytes, spec: GraphicsAnchorSpec) -> bytes:
    payload = _apply_ygodm_encode_before_compress(spec, pal_bytes)
    if spec.lz:
        return compress_gba_lz77(payload)
    if spec.huff_bpp is not None:
        return compress_gba_huff(payload, spec.huff_bpp)
    return payload


def sprite_import_png(
    png_path: str,
    spec: GraphicsAnchorSpec,
) -> Tuple[bytes, bytes, str, int, int]:
    """
    Read PNG, return ``(tile_rom_bytes, palette_rom_bytes, error_message, width_tiles, height_tiles)``.

    Tile dimensions follow the **PNG pixel size** (each side rounded up to a multiple of 8px); the image
    is not scaled down or up to match the TOML sprite window.

    Only **4bpp** and **8bpp** sprites; **6bpp** not supported here.
    """
    if spec.kind != "sprite":
        return b"", b"", "Not a sprite graphics format.", 0, 0
    if spec.bpp not in (4, 8):
        return b"", b"", f"Import not implemented for {spec.bpp}bpp sprites (use 4bpp or 8bpp).", 0, 0
    Image = _require_pillow()
    try:
        im = Image.open(png_path)
    except OSError as e:
        return b"", b"", str(e), 0, 0
    rgba = im.convert("RGBA")
    tb, pb, tw, th, err = _pil_rgba_quantized_tiles(rgba, bpp=spec.bpp)
    if err:
        return b"", b"", err, 0, 0
    need = tile_data_bytes(spec.bpp, tw, th)
    if len(tb) < need:
        tb = tb.ljust(need, b"\x00")
    elif len(tb) > need:
        tb = tb[:need]
    # palette: 4bpp → 32 bytes, 8bpp → 512 for ROM
    if spec.bpp == 4:
        pb = pb[:32].ljust(32, b"\x00")
    else:
        pb = pb[:512].ljust(512, b"\x00")
    return tb, pb, "", tw, th


def sprite_import_png_manual(
    png_path: str,
    *,
    bpp: int,
    width_tiles: int,
    height_tiles: int,
    palette_color_count: int,
    burner_rgb: Tuple[int, int, int] = MANUAL_BURNER_RGB,
) -> Tuple[bytes, bytes, str, int, int]:
    """
    Manual static import: fixed tile grid, burner transparency at index 0, Pillow median-cut to
    ``palette_color_count - 1`` solid colors. Returns ``(tiles, palette, err, w_tiles, h_tiles)``.
    """
    if bpp not in (4, 6, 8):
        return b"", b"", f"Unsupported bpp {bpp} (use 4, 6, or 8).", 0, 0
    Image = _require_pillow()
    try:
        im = Image.open(png_path)
    except OSError as e:
        return b"", b"", str(e), 0, 0
    rgba = im.convert("RGBA")
    tb, pb, tw, th, err = _pil_rgba_tiles_burner_quantize(
        rgba,
        bpp=bpp,
        width_tiles=width_tiles,
        height_tiles=height_tiles,
        palette_color_count=palette_color_count,
        burner_rgb=burner_rgb,
    )
    if err:
        return b"", b"", err, 0, 0
    need = tile_data_bytes(bpp, tw, th)
    if len(tb) < need:
        tb = tb.ljust(need, b"\x00")
    elif len(tb) > need:
        tb = tb[:need]
    if bpp == 4:
        pb = pb[:32].ljust(32, b"\x00")
    elif bpp == 6:
        pb = pb[:128].ljust(128, b"\x00")
    else:
        pb = pb[:512].ljust(512, b"\x00")
    return tb, pb, "", tw, th


def palette_import_png(
    png_path: str,
    bpp: int,
    *,
    colors_8bpp: int = 256,
) -> Tuple[bytes, str]:
    """
    Build GBA palette bytes from a PNG (quantized: 16 colors for 4bpp, or ``colors_8bpp`` for 8bpp).

    ``colors_8bpp`` must be 16–256 and a multiple of 16 (defaults to 256). Output length is
    ``16 * 2`` or ``colors_8bpp * 2`` bytes.
    """
    if bpp not in (4, 8):
        return b"", "bpp must be 4 or 8."
    if bpp == 8:
        try:
            ncols = parse_8bpp_palette_color_count(int(colors_8bpp))
        except ValueError as e:
            return b"", str(e)
    else:
        ncols = 16
    Image = _require_pillow()
    try:
        im = Image.open(png_path)
    except OSError as e:
        return b"", str(e)
    rgba = im.convert("RGBA")
    iw, ih = rgba.size
    if iw < 1 or ih < 1:
        return b"", "Image has zero width or height."
    bg = Image.new("RGBA", (iw, ih), (255, 255, 255, 255))
    bg.paste(rgba, (0, 0), rgba.split()[3])
    rgb = bg.convert("RGB")
    try:
        q = rgb.quantize(colors=ncols, method=Image.Quantize.MEDIANCUT)  # type: ignore[attr-defined]
    except AttributeError:
        q = rgb.quantize(colors=ncols, method=2)
    pal_raw = q.getpalette()
    if not pal_raw:
        return b"", "Could not build palette from image."
    colors: List[Tuple[int, int, int]] = []
    for i in range(ncols):
        if i * 3 + 2 < len(pal_raw):
            colors.append((pal_raw[i * 3], pal_raw[i * 3 + 1], pal_raw[i * 3 + 2]))
        else:
            colors.append((0, 0, 0))
    out = gba_palette_bytes_from_rgb888_list(colors, ncols)
    return out, ""


def _clamp_rgb8(r: int, g: int, b: int) -> Tuple[int, int, int]:
    return (max(0, min(255, r)), max(0, min(255, g)), max(0, min(255, b)))


def parse_standard_palette_text(text: str) -> Tuple[Optional[List[Tuple[int, int, int]]], str]:
    """
    Parse common **text** palette formats (not raw GBA RGB555):

    - **JASC-PAL** (PaintShop / many tools, including Tilemap Studio export)
    - **GIMP GPL**
    - **Tilemap Studio “Assembly (RGB)”** — lines like ``RGB 31, 31, 31`` (5-bit components)

    Returns ``(colors or None, error_message)``.
    """
    raw = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not raw:
        return None, "Empty palette file."
    lines = raw.split("\n")

    # ── JASC-PAL ─────────────────────────────────────────────
    if lines[0].strip().upper().startswith("JASC-PAL"):
        if len(lines) < 4:
            return None, "JASC-PAL: file too short (need header, version, count, colors)."
        try:
            n = int(lines[2].strip())
        except ValueError:
            return None, "JASC-PAL: invalid color count on line 3."
        if n < 1 or n > 256:
            return None, f"JASC-PAL: unsupported color count {n} (expected 1–256)."
        colors: List[Tuple[int, int, int]] = []
        for i in range(n):
            li = 3 + i
            if li >= len(lines):
                return None, f"JASC-PAL: expected {n} color lines, got {i}."
            parts = lines[li].strip().split()
            if len(parts) < 3:
                return None, f"JASC-PAL: bad color line {li + 1}."
            try:
                r, g, b = int(parts[0]), int(parts[1]), int(parts[2])
            except ValueError:
                return None, f"JASC-PAL: non-integer RGB on line {li + 1}."
            colors.append(_clamp_rgb8(r, g, b))
        return colors, ""

    # ── GIMP Palette ────────────────────────────────────────
    if lines[0].strip().startswith("GIMP Palette"):
        colors = []
        for line in lines[1:]:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Name:") or line.startswith("Columns:"):
                continue
            # "R G B" or "R G B\t#hex" or "R G G B\tIndex"
            parts = line.split()
            if len(parts) < 3:
                continue
            try:
                r, g, b = int(parts[0]), int(parts[1]), int(parts[2])
            except ValueError:
                continue
            colors.append(_clamp_rgb8(r, g, b))
        if not colors:
            return None, "GIMP palette: no color lines found after header."
        return colors, ""

    # ── Tilemap Studio assembly RGB (5-bit per channel) ─────
    asm_re = re.compile(r"^\s*RGB\s+(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*$", re.IGNORECASE)
    asm_colors: List[Tuple[int, int, int]] = []
    for line in lines:
        m = asm_re.match(line)
        if not m:
            continue
        r5, g5, b5 = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if r5 > 31 or g5 > 31 or b5 > 31:
            return None, "Assembly RGB: components must be 0–31 (5-bit)."
        # Match pret/GBA conversion: (v * 255) // 31
        asm_colors.append(((r5 * 255) // 31, (g5 * 255) // 31, (b5 * 255) // 31))
    if asm_colors:
        return asm_colors, ""

    return (
        None,
        "Unrecognized text palette. Supported: JASC-PAL, GIMP (.gpl), or Tilemap Studio assembly RGB "
        "(lines like RGB 31, 31, 31). For raw GBA RGB555 bytes, use a .bin file.",
    )


def palette_import_palette_file(
    path: str,
    bpp: int,
    *,
    colors_8bpp: int = 256,
) -> Tuple[bytes, str]:
    """
    Load a **standard** palette file (text ``.pal`` / ``.gpl``), convert RGB888 → GBA RGB555 ROM layout.

    For 8bpp, ``colors_8bpp`` sets how many colors to keep (16–256, multiple of 16); extra colors in the
    file are truncated, missing slots are black.

    This is **not** raw binary GBA palette data; use :func:`palette_import_gba_binary` for pre-encoded blobs.
    """
    if bpp not in (4, 8):
        return b"", "bpp must be 4 or 8."
    if bpp == 8:
        try:
            need = parse_8bpp_palette_color_count(int(colors_8bpp))
        except ValueError as e:
            return b"", str(e)
    else:
        need = 16
    try:
        with open(path, "rb") as f:
            raw_b = f.read()
    except OSError as e:
        return b"", str(e)
    if not raw_b:
        return b"", "File is empty."
    try:
        text = raw_b.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw_b.decode("latin-1")
    colors, err = parse_standard_palette_text(text)
    if colors is None:
        return b"", err
    if len(colors) < need:
        colors = colors + [(0, 0, 0)] * (need - len(colors))
    else:
        colors = colors[:need]
    out = gba_palette_bytes_from_rgb888_list(colors, need)
    return out, ""


def palette_import_gba_binary(
    path: str,
    bpp: int,
    *,
    colors_8bpp: int = 256,
) -> Tuple[bytes, str]:
    """Read raw GBA palette bytes from disk (RGB555 LE: 32 bytes for 4bpp, or ``colors_8bpp * 2`` for 8bpp)."""
    if bpp not in (4, 8):
        return b"", "bpp must be 4 or 8."
    if bpp == 8:
        try:
            need = parse_8bpp_palette_color_count(int(colors_8bpp)) * 2
        except ValueError as e:
            return b"", str(e)
    else:
        need = 32
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return b"", str(e)
    if len(raw) < need:
        return b"", f"Need at least {need} bytes for this {bpp}bpp GBA palette, got {len(raw)}."
    return raw[:need], ""


def _tilemap_exact_indices_and_colors_from_rgb(
    rgb: Any,
    bpp: int,
) -> Tuple[List[int], List[Tuple[int, int, int]], str]:
    """
    Build per-pixel indices and an ordered palette from **exact** RGB888 colors (first-seen order),
    without quantizing to a new palette. ``bpp`` 4 → max 16 colors; 8 → max 256.
    ``rgb`` is a Pillow ``Image`` in **RGB** mode, size already final.
    """
    max_c = 16 if bpp == 4 else 256
    pixels = list(rgb.getdata())
    order: List[Tuple[int, int, int]] = []
    idx_map: Dict[Tuple[int, int, int], int] = {}
    for px in pixels:
        if px not in idx_map:
            if len(order) >= max_c:
                return (
                    [],
                    [],
                    f"This image has more than {max_c} unique RGB colors after compositing for {bpp}bpp. "
                    f"Enable “Quantize palette” in Tools, or use ≤{max_c} unique colors.",
                )
            idx_map[px] = len(order)
            order.append(px)
    idx_flat = [idx_map[px] for px in pixels]
    return idx_flat, order, ""


def tilemap_png_to_tileset_map_palette(
    png_path: str,
    *,
    map_w_tiles: int,
    map_h_tiles: int,
    bpp: int,
    palette_color_count: Optional[int] = None,
    use_burner_transparent: bool = False,
    burner_rgb: Tuple[int, int, int] = MANUAL_BURNER_RGB,
    preserve_exact_palette: bool = True,
    reduce_palette: bool = False,
) -> Tuple[bytes, bytes, bytes, int, str]:
    """
    Tilemap Studio–style **image → tiles**: quantize the full map image, dedupe 8×8 tiles (with H/V flips),
    and build raw non-affine map bytes + linear tileset + GBA palette bytes.

    The PNG is composited onto a ``map_w×map_h`` tile canvas (8 px/tile); smaller images align top-left
    (legacy) or are resized (``use_burner_transparent``).

    ``palette_color_count`` with ``use_burner_transparent``: index 0 is ``burner_rgb`` (transparent);
    Pillow quantizes to ``palette_color_count - 1`` solid colors. Supports 4bpp / 6bpp / 8bpp in that mode.

    Without burner: default ``preserve_exact_palette=True`` keeps **exact** RGB colors from the PNG
    (no MedianCut). Set ``reduce_palette=True`` to quantize; ``palette_color_count`` then caps 8bpp
    quantize (default 256).

    Returns ``(map_body, tileset_body, palette_flat, n_unique_tiles, err)`` where ``map_body`` is
    ``map_w * map_h * 2`` bytes (little-endian u16 per cell). ``palette_flat`` is 32 / 128 / 512 bytes.
    """
    if map_w_tiles < 1 or map_h_tiles < 1:
        return b"", b"", b"", 0, "Invalid tilemap dimensions."
    if use_burner_transparent:
        if palette_color_count is None:
            return b"", b"", b"", 0, "palette_color_count is required when using burner transparency."
        if bpp not in (4, 6, 8):
            return b"", b"", b"", 0, "With burner mode, bpp must be 4, 6, or 8."
    elif bpp not in (4, 8):
        return b"", b"", b"", 0, "Tilemap bpp must be 4 or 8 (or 4/6/8 with burner mode)."
    Image = _require_pillow()
    try:
        im = Image.open(png_path)
    except OSError as e:
        return b"", b"", b"", 0, str(e)
    rgba = im.convert("RGBA")
    wpx, hpx = map_w_tiles * 8, map_h_tiles * 8
    idx_flat: List[int]
    pal_bytes: bytes

    if use_burner_transparent:
        assert palette_color_count is not None
        idx_flat, pal_bytes, err = _idx_flat_and_palette_burner(
            rgba,
            wpx,
            hpx,
            int(palette_color_count),
            bpp_for_pad=bpp,
            burner_rgb=burner_rgb,
        )
        if err:
            return b"", b"", b"", 0, err
        _log_tilemap.debug(
            "tilemap_png_to_tileset_map_palette (burner): bpp=%s len(pal_bytes)=%s palette_color_count=%s",
            bpp,
            len(pal_bytes),
            palette_color_count,
        )
    else:
        bg = Image.new("RGBA", (wpx, hpx), (255, 255, 255, 255))
        bg.paste(rgba, (0, 0), rgba.split()[3])
        rgb = bg.convert("RGB")
        use_quantize = bool(reduce_palette) or not preserve_exact_palette
        if not use_quantize:
            idx_flat, order, eex = _tilemap_exact_indices_and_colors_from_rgb(rgb, bpp)
            if eex:
                return b"", b"", b"", 0, eex
            n_pal = len(order)
            pal_bytes = gba_palette_bytes_from_rgb888_list(order, n_pal if bpp == 4 else 256)
            if bpp == 4:
                pal_bytes = pal_bytes[:32].ljust(32, b"\x00")
            else:
                pal_bytes = pal_bytes[:512].ljust(512, b"\x00")
            _log_tilemap.debug(
                "tilemap_png_to_tileset_map_palette (non-burner exact): bpp=%s unique_colors=%s len(pal_bytes)=%s",
                bpp,
                n_pal,
                len(pal_bytes),
            )
        else:
            if bpp == 4:
                ncols = 16
            else:
                if palette_color_count is not None:
                    ncols = parse_8bpp_palette_color_count(int(palette_color_count))
                else:
                    ncols = 256
            try:
                q = rgb.quantize(colors=ncols, method=Image.Quantize.MEDIANCUT)  # type: ignore[attr-defined]
            except AttributeError:
                q = rgb.quantize(colors=ncols, method=2)
            pal_raw = q.getpalette()
            if not pal_raw:
                return b"", b"", b"", 0, "Could not build palette from image."
            colors = []
            for i in range(ncols):
                if i * 3 + 2 < len(pal_raw):
                    colors.append((pal_raw[i * 3], pal_raw[i * 3 + 1], pal_raw[i * 3 + 2]))
                else:
                    colors.append((0, 0, 0))
            pal_bytes = gba_palette_bytes_from_rgb888_list(colors, ncols)
            if bpp == 4:
                pal_bytes = pal_bytes[:32].ljust(32, b"\x00")
            else:
                pal_bytes = pal_bytes[:512].ljust(512, b"\x00")
            idx_flat = list(q.getdata())
            _log_tilemap.debug(
                "tilemap_png_to_tileset_map_palette (non-burner quantize): bpp=%s ncols=%s len(pal_bytes)=%s "
                "palette_color_count_kw=%s",
                bpp,
                ncols,
                len(pal_bytes),
                palette_color_count,
            )

    if len(idx_flat) != wpx * hpx:
        return b"", b"", b"", 0, "Internal error: quantized buffer size mismatch."

    unique: List[bytes] = []
    map_words: List[int] = []
    palno = 0

    for my in range(map_h_tiles):
        for mx in range(map_w_tiles):
            cell: List[int] = []
            for py in range(8):
                for px in range(8):
                    ix = mx * 8 + px
                    iy = my * 8 + py
                    cell.append(idx_flat[iy * wpx + ix])
            want = tuple(cell)
            m = _match_tile_index_and_flips(unique, want, bpp)
            if m is None:
                if len(unique) >= 1024:
                    return (
                        b"",
                        b"",
                        b"",
                        0,
                        "More than 1024 unique tiles after dedupe (GBA non-affine limit).",
                    )
                if bpp == 4:
                    tb = encode_gba_tile_4bpp_from_indices(list(want))
                elif bpp == 6:
                    tb = encode_gba_tile_6bpp_from_indices(list(want))
                else:
                    tb = encode_gba_tile_8bpp_from_indices(list(want))
                unique.append(tb)
                ti = len(unique) - 1
                hf = False
                vf = False
            else:
                ti, hf, vf = m
            w = encode_non_affine_tilemap_u16(ti, hf, vf, palno)
            map_words.append(w)

    raw_map = bytearray()
    for word in map_words:
        raw_map.extend(word.to_bytes(2, "little"))
    tileset_body = b"".join(unique)
    return bytes(raw_map), tileset_body, pal_bytes, len(unique), ""


def palette_byte_count_for_spec(spec: GraphicsAnchorSpec) -> int:
    """Bytes written for a palette anchor (uncompressed body)."""
    if spec.kind != "palette" or spec.bpp != 4:
        if spec.kind == "palette" and spec.bpp == 8:
            return palette_byte_count_8_variant(effective_ucp8_palette_hex_suffix(spec))
        return 32
    return 32 * palette_4_chunk_count(spec)


def palette_byte_count_8_variant(hex_digits: str) -> int:
    """ucp8:/lzp8: ROM byte length for one palette blob.

    - **One** hex digit ``N``: ``N * 32`` bytes (``N == 0`` is treated as ``1``), original rule.
    - **Several** digits (e.g. ``0123``): ``len(digits) * 32`` bytes — contiguous 32-byte chunks (64 colors
      when 4 chunks), used by card graphics tables.
    - **Empty** suffix: treat as full **256-color** master (512 bytes), same as bare ``ucp8`` in TOML
      (avoids accidentally resolving ``""`` to single-digit ``"1"`` → 32 bytes).
    """
    s = (hex_digits or "").strip().upper()
    if not s:
        return 512
    if len(s) == 1:
        n = int(s, 16)
        if n == 0:
            n = 1
        return n * 32
    return len(s) * 32


def tile_data_bytes(bpp: int, w_tiles: int, h_tiles: int) -> int:
    if bpp == 4:
        per_tile = 32
    elif bpp == 6:
        per_tile = 48  # 8×8 × 6 bits / 8
    else:
        per_tile = 64
    return w_tiles * h_tiles * per_tile


def compute_graphics_rom_span(spec: GraphicsAnchorSpec, rom_len: int, base: int) -> int:
    """Conservative byte span in ROM from anchor start (for selection / hit-testing)."""
    rest = max(0, rom_len - base)
    if spec.kind == "palette":
        if spec.lz or spec.huff_bpp is not None:
            return min(rest, 512 * 1024)
        if spec.bpp == 4:
            return min(rest, 32 * palette_4_chunk_count(spec))
        dig = effective_ucp8_palette_hex_suffix(spec)
        return min(rest, palette_byte_count_8_variant(dig))
    if spec.kind == "tilemap":
        if spec.lz or spec.huff_bpp is not None:
            return min(rest, 2 * 1024 * 1024)
        need = spec.map_w_tiles * spec.map_h_tiles * 2
        return min(rest, max(1, need))
    if spec.kind == "sprite" and spec.width_tiles == 0 and spec.height_tiles == 0:
        # Variable-length tile strip (``lzt4|pal``): unknown uncompressed span
        if spec.lz or spec.huff_bpp is not None:
            return min(rest, 2 * 1024 * 1024)
        return min(rest, 512 * 1024)
    if spec.lz or spec.huff_bpp is not None:
        return min(rest, 2 * 1024 * 1024)
    return min(rest, tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles))


@dataclass
class GraphicsAnchorSpec:
    kind: str  # "palette" | "sprite" | "tilemap"
    bpp: int  # palette: 4 or 8; sprite: 4, 6, or 8; tilemap: 4 or 8
    lz: bool
    # GBA Huffman (pret huff.c): 4 = 0x24… nybble symbols, 8 = 0x28… byte symbols. Exclusive with ``lz``.
    huff_bpp: Optional[int] = None
    # ygodm8: apply ``ygodm_encode`` before Huff compress / inverse after decompress (`` `reshef` `` in TOML).
    reshef_ygodm: bool = False
    # palette 4bpp: ``ucp4:`` hex digits = hardware indices; ``None`` = plain ucp4 → one chunk for index 0
    palette_4_indices: Optional[Tuple[int, ...]] = None
    # palette 8bpp: ucp8:N / lzp8:N — one or more hex digits; byte length via palette_byte_count_8_variant
    palette_hex_digit: Optional[str] = None
    # sprite / tile sheet: tile dimensions (uct/lzt/ucs/lzs). Both 0 = variable-length strip
    # (infer tile count from data ÷ 32 or ÷ 64; layout N×1), e.g. ``lzt4|palette``.
    width_tiles: int = 0
    height_tiles: int = 0
    # tilemap (ucm/lzm): map size in tiles; ROM holds ``map_w * map_h`` × u16 entries (non-affine)
    map_w_tiles: int = 0
    map_h_tiles: int = 0
    # tilemap: tileset NamedAnchor (``uct4…`` / ``lzt8…`` / ``ucs4…`` / …)
    tileset_anchor_name: Optional[str] = None
    # sprite or tilemap: optional palette NamedAnchor after ``|`` (tilemap: ``ucm…|tileset|palette``)
    palette_anchor_name: Optional[str] = None


def palette_4_chunk_count(spec: GraphicsAnchorSpec) -> int:
    """How many 32-byte palette chunks are stored in ROM for this 4bpp palette anchor."""
    if spec.kind != "palette" or spec.bpp != 4:
        return 0
    if spec.palette_4_indices is None:
        return 1
    return len(spec.palette_4_indices)


def prepare_palette_rom_body_from_import(spec: GraphicsAnchorSpec, flat: bytes) -> bytes:
    """
    Build uncompressed palette bytes for ROM (before optional LZ), padded with ``0xFF`` to the spec size.

    ``flat`` is the quantized palette from import: 32 bytes (4bpp) or 512 bytes (8bpp master).
    Multi-chunk 4bpp anchors repeat the first 32-byte subpalette across each chunk.
    """
    if spec.kind != "palette":
        raise ValueError("palette spec required")
    need = palette_byte_count_for_spec(spec)
    if spec.bpp == 4:
        chunk = flat[:32].ljust(32, b"\x00")
        nchunks = max(1, need // 32)
        body = (chunk * nchunks)[:need]
        return body.ljust(need, b"\xFF")
    # 8bpp — if the importer produced a larger valid GBA palette blob than TOML implies (e.g. legacy
    # ``ucp8:1`` / 32 B spec vs bare ``ucp8`` / 512 B data), expand ``need`` so we never truncate a
    # 256-color master to one 16-color row (``base[:32]``).
    nflat = len(flat)
    if nflat > need:
        try:
            nc = parse_8bpp_palette_color_count(nflat // 2)
            if nc * 2 == nflat and nflat <= 512:
                need = max(need, nflat)
        except ValueError:
            pass
    base = flat[:512].ljust(512, b"\x00")
    if need <= 512:
        return base[:need].ljust(need, b"\xFF")
    reps = (need + 511) // 512
    body = (base * reps)[:need]
    return body.ljust(need, b"\xFF")


def measure_sprite_rom_footprint(
    rom: bytes,
    blob_off: int,
    spec: GraphicsAnchorSpec,
    *,
    graphics_table_row_bytes: Optional[int] = None,
) -> int:
    """Byte length of the existing sprite blob on disk (LZ compressed length, or raw fixed size)."""
    if spec.kind != "sprite":
        raise ValueError("sprite spec required")
    if graphics_table_row_bytes is not None:
        return int(graphics_table_row_bytes)
    if blob_off < 0 or blob_off >= len(rom):
        return 0
    raw = bytes(rom[blob_off:])
    if spec.lz:
        if len(raw) < 4 or raw[0] != 0x10:
            raise ValueError("Sprite data is not valid GBA LZ77 (expected type byte 0x10).")
        _dec, consumed = decompress_gba_lz77_with_consumed(raw)
        # pret ``LZCompress`` pads the compressed stream to a multiple of 4 bytes (not read by decompress).
        return (consumed + 3) & ~3
    if spec.huff_bpp is not None:
        if not is_gba_huff_header(raw) or (raw[0] & 0x0F) != spec.huff_bpp:
            raise ValueError(
                f"Sprite data is not valid GBA Huffman (expected header 0x2{spec.huff_bpp:X})."
            )
        _dec, consumed = decompress_gba_huff_with_consumed(raw)
        return (consumed + 3) & ~3
    if spec.width_tiles > 0 and spec.height_tiles > 0:
        return tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles)
    raise ValueError(
        "Cannot size this raw sprite slot for import (variable-length strip without WxH). "
        "Use a fixed uct/ucs WxH format or LZ/Huff (lzt/lzs, huff4t/huff8t, …) in TOML."
    )


def measure_palette_rom_footprint(
    rom: bytes,
    blob_off: int,
    spec: GraphicsAnchorSpec,
    *,
    graphics_table_row_bytes: Optional[int] = None,
) -> int:
    """Byte length of the existing palette blob (LZ compressed length, or raw palette size)."""
    if spec.kind != "palette":
        raise ValueError("palette spec required")
    if graphics_table_row_bytes is not None:
        return int(graphics_table_row_bytes)
    if blob_off < 0 or blob_off >= len(rom):
        return 0
    raw = bytes(rom[blob_off:])
    if spec.lz:
        if len(raw) < 4 or raw[0] != 0x10:
            raise ValueError("Palette data is not valid GBA LZ77 (expected type byte 0x10).")
        _dec, consumed = decompress_gba_lz77_with_consumed(raw)
        return (consumed + 3) & ~3
    if spec.huff_bpp is not None:
        if not is_gba_huff_header(raw) or (raw[0] & 0x0F) != spec.huff_bpp:
            raise ValueError(
                f"Palette data is not valid GBA Huffman (expected header 0x2{spec.huff_bpp:X})."
            )
        _dec, consumed = decompress_gba_huff_with_consumed(raw)
        return (consumed + 3) & ~3
    return palette_byte_count_for_spec(spec)


def measure_tilemap_rom_footprint(
    rom: bytes,
    blob_off: int,
    spec: GraphicsAnchorSpec,
    *,
    graphics_table_row_bytes: Optional[int] = None,
) -> int:
    """Byte length of the existing tilemap blob (LZ compressed length, or raw fixed map size)."""
    if spec.kind != "tilemap":
        raise ValueError("tilemap spec required")
    if graphics_table_row_bytes is not None:
        return int(graphics_table_row_bytes)
    if blob_off < 0 or blob_off >= len(rom):
        return 0
    raw = bytes(rom[blob_off:])
    if spec.lz:
        if len(raw) < 4 or raw[0] != 0x10:
            raise ValueError("Tilemap data is not valid GBA LZ77 (expected type byte 0x10).")
        _dec, consumed = decompress_gba_lz77_with_consumed(raw)
        return (consumed + 3) & ~3
    if spec.huff_bpp is not None:
        if not is_gba_huff_header(raw) or (raw[0] & 0x0F) != spec.huff_bpp:
            raise ValueError(
                f"Tilemap data is not valid GBA Huffman (expected header 0x2{spec.huff_bpp:X})."
            )
        _dec, consumed = decompress_gba_huff_with_consumed(raw)
        return (consumed + 3) & ~3
    need = spec.map_w_tiles * spec.map_h_tiles * 2
    return max(1, need)


def build_tilemap_payload_for_rom(map_body: bytes, spec: GraphicsAnchorSpec) -> bytes:
    """Wrap raw tilemap u16 data (``map_w * map_h * 2`` bytes) with optional LZ."""
    if spec.kind != "tilemap":
        raise ValueError("tilemap spec required")
    need = spec.map_w_tiles * spec.map_h_tiles * 2
    if len(map_body) != need:
        raise ValueError(f"Tilemap body length {len(map_body)} != expected {need}")
    payload = _apply_ygodm_encode_before_compress(spec, map_body)
    if spec.lz:
        return compress_gba_lz77(payload)
    if spec.huff_bpp is not None:
        return compress_gba_huff(payload, spec.huff_bpp)
    return payload


def suggest_sprite_grid_for_tile_count(n_tiles: int) -> Tuple[int, int]:
    """
    Minimal ``W×H`` tile grid holding ``n_tiles`` tiles (row-major), for TOML ``uct/lzt/ucs/lzs`` previews.
    GBA hardware allows tile indices 0..1023.
    """
    if n_tiles < 1:
        return 1, 1
    if n_tiles > 1024:
        raise ValueError(f"Unique tile count {n_tiles} exceeds 1024 (GBA non-affine tile index limit).")
    w = min(32, n_tiles)
    h = (n_tiles + w - 1) // w
    return w, h


# 4bpp: 16 hardware indices × 16 colors × 2 bytes (master layout for multi-slot palettes / PNG decode)
GBA_4BPP_SUBPALETTE_BYTES = 32
GBA_4BPP_MASTER_INDEX_COUNT = 16
GBA_4BPP_MASTER_PALETTE_BYTES = GBA_4BPP_MASTER_INDEX_COUNT * GBA_4BPP_SUBPALETTE_BYTES  # 512


def gba_rgb555_word_to_rgb888(word: int) -> Tuple[int, int, int]:
    """pret ``gfx.c`` ``UPCONVERT_BIT_DEPTH``: (5-bit component * 255) // 31 → 8-bit RGB."""
    r5 = word & 0x1F
    g5 = (word >> 5) & 0x1F
    b5 = (word >> 10) & 0x1F
    return ((r5 * 255) // 31, (g5 * 255) // 31, (b5 * 255) // 31)


def decode_gba_palette32_to_rgb888(pal32: bytes) -> List[Tuple[int, int, int]]:
    """16 GBA colors (32 bytes) → list of RGB888 tuples."""
    if len(pal32) < 32:
        pal32 = pal32.ljust(32, b"\x00")
    out: List[Tuple[int, int, int]] = []
    for i in range(0, 32, 2):
        w = pal32[i] | (pal32[i + 1] << 8)
        out.append(gba_rgb555_word_to_rgb888(w))
    return out


def _require_pillow():
    try:
        from PIL import Image

        return Image
    except ImportError as e:
        raise ImportError(
            "Pillow is required for graphics PNG export. Install with: pip install Pillow"
        ) from e


def raw_gba_palette_to_rgb888_list(pal_data: bytes) -> List[Tuple[int, int, int]]:
    """pret ``ReadGbaPalette``: little-endian u16 per entry, same RGB expansion as gba_rgb555_word_to_rgb888."""
    if len(pal_data) % 2 != 0:
        pal_data = pal_data[: len(pal_data) // 2 * 2]
    colors: List[Tuple[int, int, int]] = []
    for i in range(0, len(pal_data), 2):
        w = pal_data[i] | (pal_data[i + 1] << 8)
        colors.append(gba_rgb555_word_to_rgb888(w))
    return colors


SPRITE_PALETTE_ROM_BYTE_COUNT = {4: 32, 6: 128, 8: 512}
"""Raw GBA RGB555 palette size at ROM: 16 / 64 / 256 colors × 2 bytes."""


def read_raw_sprite_palette_at_rom_offset(
    rom: bytes,
    file_off: int,
    palette_bpp: int,
) -> Tuple[Optional[bytes], str]:
    """
    Read a contiguous GBA palette at ``file_off``: 32 / 128 / 512 bytes for 4 / 6 / 8 bpp display modes.
    (6bpp sprites index 64 colors → 128 bytes.)
    """
    if palette_bpp not in SPRITE_PALETTE_ROM_BYTE_COUNT:
        return None, "Palette mode must be 4, 6, or 8 bpp."
    need = SPRITE_PALETTE_ROM_BYTE_COUNT[palette_bpp]
    if file_off < 0:
        return None, "Offset must be ≥ 0."
    if file_off >= len(rom):
        return None, "Offset past end of ROM."
    if file_off + need > len(rom):
        return None, f"Need {need} bytes at offset (palette {palette_bpp}bpp); ROM ends early."
    return bytes(rom[file_off : file_off + need]), ""


def read_sprite_preview_palette_at_rom_offset(
    rom: bytes,
    file_off: int,
    palette_bpp: int,
    *,
    lz77: bool = False,
    huff_bpp: Optional[int] = None,
    reshef_ygodm: bool = False,
) -> Tuple[Optional[bytes], str]:
    """
    Palette bytes for sprite preview at ``file_off``: **raw** RGB555, **LZ77** (type ``0x10``), or
    **Gba Huffman** (``0x24`` / ``0x28``), decompressed then truncated to 32 / 128 / 512 bytes.
    """
    if palette_bpp not in SPRITE_PALETTE_ROM_BYTE_COUNT:
        return None, "Palette mode must be 4, 6, or 8 bpp."
    need = SPRITE_PALETTE_ROM_BYTE_COUNT[palette_bpp]
    if huff_bpp is None and not lz77:
        return read_raw_sprite_palette_at_rom_offset(rom, file_off, palette_bpp)
    if file_off < 0:
        return None, "Offset must be ≥ 0."
    if file_off >= len(rom):
        return None, "Offset past end of ROM."
    blob = bytes(rom[file_off:])
    if huff_bpp is not None:
        if len(blob) < 5:
            return None, "Huff data too short (need at least 5 bytes for a header)."
        try:
            dec = decompress_gba_huff(blob)
        except ValueError as e:
            return None, f"Huff decompress failed: {e}"
    else:
        if len(blob) < 4:
            return None, "LZ77 data too short (need at least 4 bytes for a header)."
        try:
            dec = decompress_gba_lz77(blob)
        except ValueError as e:
            return None, f"LZ77 decompress failed: {e}"
    if reshef_ygodm:
        bb = bytearray(dec)
        ygodm_decode_inplace(bb)
        dec = bytes(bb)
    if len(dec) < need:
        tag = "Huff" if huff_bpp is not None else "LZ77"
        return None, (
            f"Decompressed data too short for {palette_bpp}bpp palette: need {need} bytes, "
            f"got {len(dec)} after {tag}."
        )
    return bytes(dec[:need]), ""


def ucp8_slot_hex_digits_for_chunk_count(n_chunks: int) -> str:
    """
    Build the ``ucp8:`` hex suffix for ``n_chunks`` contiguous 32-byte subpalettes (slots 0 … n−1).

    Each chunk holds **16** RGB555 colors. ``n_chunks`` is 1–16 (up to 256 colors total).
    """
    if n_chunks < 1 or n_chunks > 16:
        raise ValueError(f"ucp8 chunk count must be 1–16, got {n_chunks}")
    return "".join(f"{i:X}" for i in range(n_chunks))


# ``ucp8:`` hex suffix: ``len(digits) * 32`` bytes when more than one digit (see :func:`palette_byte_count_8_variant`).
# Digits name **16-color subpalette slots** in order (same convention as ``ucp4:0123``).
UCP8_PALETTE_4_CHUNK_HEX_DIGITS = ucp8_slot_hex_digits_for_chunk_count(4)  # 128 B (e.g. 6bpp / 64 colors)
UCP8_PALETTE_16_CHUNK_HEX_DIGITS = ucp8_slot_hex_digits_for_chunk_count(16)  # 512 B (256 colors)


def effective_ucp8_palette_hex_suffix(spec: GraphicsAnchorSpec) -> str:
    """
    Hex digits for ``ucp8:`` ROM size. If missing or empty, treat like **bare** ``ucp8`` / ``lzp8`` in TOML:
    full 256-color master (16×32-byte chunks = ``0123456789ABCDEF``), not a single ``1`` chunk (32 B).
    """
    if spec.kind != "palette" or spec.bpp != 8:
        raise ValueError("effective_ucp8_palette_hex_suffix: 8bpp palette spec only")
    d = spec.palette_hex_digit
    if d is None or not str(d).strip():
        return UCP8_PALETTE_16_CHUNK_HEX_DIGITS
    return str(d).strip()


def toml_format_ucp8_from_8bpp_rom_colors(num_colors: int) -> str:
    """``Format`` token for an 8bpp palette blob of ``num_colors`` (16–256, multiple of 16)."""
    n = parse_8bpp_palette_color_count(int(num_colors))
    dig = ucp8_slot_hex_digits_for_chunk_count(n // 16)
    return f"`ucp8:{dig}`"


def synthetic_palette_spec_for_sprite_import_write(
    sprite_bpp: int,
    *,
    rom_palette_colors_8bpp: Optional[int] = None,
) -> GraphicsAnchorSpec:
    """
    Minimal palette :class:`GraphicsAnchorSpec` for ``measure_palette_rom_footprint`` /
    ``prepare_palette_rom_body_from_import`` when writing to a raw file offset.

    **6bpp:** :data:`UCP8_PALETTE_4_CHUNK_HEX_DIGITS` (``ucp8:0123``) — 128 B.

    **8bpp:** ROM size follows ``rom_palette_colors_8bpp`` (default **256** colors → 512 B). Fewer colors
    (e.g. 64 → 128 B) use a shorter ``ucp8:`` suffix from :func:`ucp8_slot_hex_digits_for_chunk_count`.
    """
    if sprite_bpp == 4:
        return GraphicsAnchorSpec(kind="palette", bpp=4, lz=False, palette_4_indices=None)
    if sprite_bpp == 6:
        return GraphicsAnchorSpec(
            kind="palette",
            bpp=8,
            lz=False,
            palette_hex_digit=UCP8_PALETTE_4_CHUNK_HEX_DIGITS,
        )
    nc = rom_palette_colors_8bpp if rom_palette_colors_8bpp is not None else 256
    nc = parse_8bpp_palette_color_count(int(nc))
    n_chunks = nc // 16
    digits = ucp8_slot_hex_digits_for_chunk_count(n_chunks)
    return GraphicsAnchorSpec(kind="palette", bpp=8, lz=False, palette_hex_digit=digits)


def pret_pad_palette_over_16_colors(colors: List[Tuple[int, int, int]]) -> List[Tuple[int, int, int]]:
    """pret ``ReadGbaPalette``: if more than 16 colors, pad with black to 256 entries."""
    if len(colors) <= 16:
        return colors
    c = list(colors)
    while len(c) < 256:
        c.append((0, 0, 0))
    return c


def palette_rgb_for_4bpp_tile_decode(pal_bytes: bytes) -> List[Tuple[int, int, int]]:
    colors = raw_gba_palette_to_rgb888_list(pal_bytes)
    while len(colors) < 16:
        colors.append((0, 0, 0))
    return colors[:16]


def palette_rgb_for_8bpp_tile_decode(pal_bytes: bytes) -> List[Tuple[int, int, int]]:
    colors = raw_gba_palette_to_rgb888_list(pal_bytes)
    colors = pret_pad_palette_over_16_colors(colors)
    while len(colors) < 256:
        colors.append((0, 0, 0))
    return colors[:256]


def decode_gba_tile_4bpp_indices(tile: bytes) -> Tuple[int, ...]:
    """
    One 8×8 4bpp tile (32 bytes). Nybble order matches pret ``ConvertFromTiles4Bpp`` on read
    (low nybble first pixel, high nybble second).
    """
    tile = tile.ljust(32, b"\x00")[:32]
    out: List[int] = []
    for row in range(8):
        for cb in range(4):
            b = tile[row * 4 + cb]
            out.append(b & 0xF)
            out.append((b >> 4) & 0xF)
    return tuple(out)


def decode_gba_tile_8bpp_indices(tile: bytes) -> Tuple[int, ...]:
    """One 8×8 8bpp tile (64 bytes), row-major (pret ``ConvertFromTiles8Bpp``)."""
    return tuple(tile.ljust(64, b"\x00")[:64])


def decode_gba_tile_6bpp_indices(tile: bytes) -> Tuple[int, ...]:
    """
    One 8×8 6bpp tile (48 bytes). Each row is 6 bytes: two groups of 3 little-endian bytes form a 24-bit
    value; four 6-bit palette indices are ``(v >> (k*6)) & 0x3F`` for k = 0..3 per group.
    Matches ``decode_6bpp_tiled_to_8bpp`` in repo ``sprite.c`` (row-major pixels within the tile).
    """
    tile = tile.ljust(48, b"\x00")[:48]
    out: List[int] = []
    for ry in range(8):
        row = tile[ry * 6 : ry * 6 + 6]
        for g in range(2):
            v = row[g * 3] | (row[g * 3 + 1] << 8) | (row[g * 3 + 2] << 16)
            for k in range(4):
                out.append((v >> (k * 6)) & 0x3F)
    return tuple(out)


def gba_tiles_to_rgba(
    tile_data: bytes,
    bpp: int,
    tiles_wide: int,
    tiles_high: int,
    palette_rgb: List[Tuple[int, int, int]],
) -> bytes:
    """
    Row-major tile order with ``tiles_wide`` as gbagfx ``-mwidth`` (metatile 1×1), matching pret
    ``ReadTileImage`` + ``ConvertFromTiles*`` for 4bpp/8bpp/6bpp (6bpp: indices 0–63 per tile).
    """
    tw, th = tiles_wide, tiles_high
    pix_w, pix_h = tw * 8, th * 8
    if bpp == 4:
        tile_sz = 32
    elif bpp == 6:
        tile_sz = 48
    elif bpp == 8:
        tile_sz = 64
    else:
        raise ValueError(f"Unsupported tile bpp for decode: {bpp}")
    n_tiles = tw * th
    need = n_tiles * tile_sz
    if len(tile_data) < need:
        tile_data = tile_data.ljust(need, b"\x00")
    buf = bytearray(pix_w * pix_h * 4)

    for ti in range(n_tiles):
        off = ti * tile_sz
        chunk = tile_data[off : off + tile_sz]
        if bpp == 4:
            idxs = decode_gba_tile_4bpp_indices(chunk)
        elif bpp == 6:
            idxs = decode_gba_tile_6bpp_indices(chunk)
        else:
            idxs = decode_gba_tile_8bpp_indices(chunk)
        tcx = (ti % tw) * 8
        tcy = (ti // tw) * 8
        k = 0
        for y in range(8):
            for x in range(8):
                pi = idxs[k]
                k += 1
                if pi < len(palette_rgb):
                    r, g, b = palette_rgb[pi]
                else:
                    r, g, b = (0, 0, 0)
                q = ((tcy + y) * pix_w + (tcx + x)) * 4
                buf[q : q + 4] = bytes((r, g, b, 255))
    return bytes(buf)


def _decode_non_affine_tilemap_entry(word: int) -> Tuple[int, bool, bool, int]:
    """One map entry as in pret ``gfx.h`` ``NonAffineTile`` (packed u16, little-endian)."""
    tile_index = word & 0x3FF
    hflip = bool((word >> 10) & 1)
    vflip = bool((word >> 11) & 1)
    palno = (word >> 12) & 0xF
    return tile_index, hflip, vflip, palno


def encode_non_affine_tilemap_u16(
    tile_index: int,
    hflip: bool,
    vflip: bool,
    palno: int,
) -> int:
    """Pack one tilemap cell (same layout as :func:`_decode_non_affine_tilemap_entry`)."""
    w = tile_index & 0x3FF
    if hflip:
        w |= 1 << 10
    if vflip:
        w |= 1 << 11
    w |= (palno & 0xF) << 12
    return w


def _apply_non_affine_flips_to_indices(
    idxs: Tuple[int, ...],
    hflip: bool,
    vflip: bool,
) -> Tuple[int, ...]:
    """Match :func:`tilemap_non_affine_to_rgba` (horizontal flip, then vertical)."""
    cur = idxs
    if hflip:
        cur = _flip_tile_indices_horizontal(cur)
    if vflip:
        cur = _flip_tile_indices_vertical(cur)
    return cur


def _match_tile_index_and_flips(
    unique_tiles: List[bytes],
    want: Tuple[int, ...],
    bpp: int,
) -> Optional[Tuple[int, bool, bool]]:
    """
    Find an existing tile (optionally flipped) matching ``want`` indices.
    Used for Tilemap-Studio-style dedup when building a map from a PNG.
    """
    for ti, tb in enumerate(unique_tiles):
        if bpp == 4:
            base = decode_gba_tile_4bpp_indices(tb)
        elif bpp == 6:
            base = decode_gba_tile_6bpp_indices(tb)
        else:
            base = decode_gba_tile_8bpp_indices(tb)
        for hf in (False, True):
            for vf in (False, True):
                got = _apply_non_affine_flips_to_indices(base, hf, vf)
                if got == want:
                    return ti, hf, vf
    return None


def _flip_tile_indices_horizontal(idxs: Tuple[int, ...]) -> Tuple[int, ...]:
    """8×8 row-major indices, mirror left-right."""
    L = list(idxs)
    for y in range(8):
        base = y * 8
        L[base : base + 8] = list(reversed(L[base : base + 8]))
    return tuple(L)


def _flip_tile_indices_vertical(idxs: Tuple[int, ...]) -> Tuple[int, ...]:
    """8×8 row-major indices, mirror top-bottom."""
    L = list(idxs)
    out: List[int] = []
    for y in range(8):
        out.extend(L[(7 - y) * 8 : (8 - y) * 8])
    return tuple(out)


def tilemap_non_affine_to_rgba(
    tileset: bytes,
    map_bytes: bytes,
    *,
    bpp: int,
    map_w: int,
    map_h: int,
    pal_spec: Optional[GraphicsAnchorSpec],
    pal_bytes: bytes,
) -> bytes:
    """
    Expand a non-affine GBA tilemap (2 bytes/tile) using ``tileset`` 4bpp or 8bpp tiles,
    matching pret ``DecodeNonAffineTilemap`` + ``ConvertFromTiles*`` layout (metatile 1×1).
    """
    if bpp not in (4, 8):
        raise ValueError(f"tilemap bpp must be 4 or 8, got {bpp}")
    tile_sz = 32 if bpp == 4 else 64
    n_cells = map_w * map_h
    need_map = n_cells * 2
    if len(map_bytes) < need_map:
        raise ValueError(f"Tilemap data short: need {need_map} bytes, have {len(map_bytes)}")
    map_bytes = map_bytes[:need_map]

    if bpp == 8:
        pal_rgb = palette_rgb_for_8bpp_tile_decode(pal_bytes)
        multi_4 = False
    else:
        if (
            pal_spec is not None
            and pal_spec.kind == "palette"
            and pal_spec.bpp == 4
            and palette_4_chunk_count(pal_spec) > 1
        ):
            master = normalize_4bpp_palette_for_gbagfx(pal_bytes, pal_spec.palette_4_indices)
            pal_rgb = raw_gba_palette_to_rgb888_list(master)
            while len(pal_rgb) < 256:
                pal_rgb.append((0, 0, 0))
            pal_rgb = pal_rgb[:256]
            multi_4 = True
        else:
            pal_rgb = palette_rgb_for_4bpp_tile_decode(pal_bytes)
            multi_4 = False

    pix_w, pix_h = map_w * 8, map_h * 8
    buf = bytearray(pix_w * pix_h * 4)

    for mi in range(n_cells):
        w = map_bytes[mi * 2] | (map_bytes[mi * 2 + 1] << 8)
        tidx, hf, vf, palno = _decode_non_affine_tilemap_entry(w)
        off = tidx * tile_sz
        chunk = tileset[off : off + tile_sz].ljust(tile_sz, b"\x00")[:tile_sz]
        if bpp == 4:
            idxs: Tuple[int, ...] = decode_gba_tile_4bpp_indices(chunk)
        else:
            idxs = decode_gba_tile_8bpp_indices(chunk)
        if hf:
            idxs = _flip_tile_indices_horizontal(idxs)
        if vf:
            idxs = _flip_tile_indices_vertical(idxs)
        mx, my = mi % map_w, mi // map_w
        tcx, tcy = mx * 8, my * 8
        k = 0
        for y in range(8):
            for x in range(8):
                pidx = idxs[k]
                k += 1
                if bpp == 8:
                    if pidx < len(pal_rgb):
                        r, g, b = pal_rgb[pidx]
                    else:
                        r, g, b = (0, 0, 0)
                else:
                    if multi_4:
                        pi = (palno & 0xF) * 16 + (pidx & 0xF)
                        if pi < len(pal_rgb):
                            r, g, b = pal_rgb[pi]
                        else:
                            r, g, b = (0, 0, 0)
                    else:
                        if (pidx & 0xF) < len(pal_rgb):
                            r, g, b = pal_rgb[pidx & 0xF]
                        else:
                            r, g, b = (0, 0, 0)
                q = ((tcy + y) * pix_w + (tcx + x)) * 4
                buf[q : q + 4] = bytes((r, g, b, 255))
    return bytes(buf)


def write_rgba_png(path: str, width: int, height: int, rgba: bytes) -> None:
    Image = _require_pillow()
    expect = width * height * 4
    if len(rgba) != expect:
        raise ValueError(f"RGBA buffer length {len(rgba)} != {expect}")
    im = Image.frombytes("RGBA", (width, height), rgba, "raw", "RGBA", 0, 1)
    im.save(path, format="PNG")


def write_palette_strip_png(
    path: str,
    colors: List[Tuple[int, int, int]],
    *,
    swatch_w: int = 14,
    swatch_h: int = 28,
) -> None:
    Image = _require_pillow()
    if not colors:
        colors = [(0, 0, 0)]
    w, h = len(colors) * swatch_w, swatch_h
    im = Image.new("RGBA", (w, h), (0, 0, 0, 255))
    px = im.load()
    for i, (r, g, b) in enumerate(colors):
        x0 = i * swatch_w
        for yy in range(swatch_h):
            for xx in range(swatch_w):
                px[x0 + xx, yy] = (r, g, b, 255)
    im.save(path, format="PNG")


def write_palette_grid_png(
    path: str,
    colors: List[Tuple[int, int, int]],
    *,
    cols: int = 16,
    cell_w: int = 18,
    cell_h: int = 26,
    gap: int = 2,
    pad: int = 4,
) -> None:
    """
    Multi-row palette preview (same swatch size as 4bpp Tools canvas: 18×26, 16 columns).
    """
    Image = _require_pillow()
    if not colors:
        colors = [(0, 0, 0)]
    n = len(colors)
    nrow = (n + cols - 1) // cols
    w = pad * 2 + cols * cell_w + max(0, cols - 1) * gap
    h = pad * 2 + nrow * cell_h + max(0, nrow - 1) * gap
    im = Image.new("RGBA", (w, h), (30, 30, 30, 255))
    px = im.load()
    for i, (r, g, b) in enumerate(colors):
        row, col = divmod(i, cols)
        x0 = pad + col * (cell_w + gap)
        y0 = pad + row * (cell_h + gap)
        for yy in range(cell_h):
            for xx in range(cell_w):
                px[x0 + xx, y0 + yy] = (r, g, b, 255)
    im.save(path, format="PNG")


def get_palette_4_slot_bytes(spec: GraphicsAnchorSpec, pal_bytes: bytes, slot_index: int) -> bytes:
    """
    32 bytes for hardware palette index ``slot_index`` (0..15).
    Missing indices use ``00 00`` per color (returned as 32 zero bytes).
    """
    if spec.kind != "palette" or spec.bpp != 4:
        raise ValueError("not a 4bpp palette spec")
    if not 0 <= slot_index < GBA_4BPP_MASTER_INDEX_COUNT:
        raise ValueError(f"slot_index must be 0..{GBA_4BPP_MASTER_INDEX_COUNT - 1}")
    if spec.palette_4_indices is None:
        if slot_index == 0:
            return pal_bytes[:GBA_4BPP_SUBPALETTE_BYTES].ljust(GBA_4BPP_SUBPALETTE_BYTES, b"\x00")[
                : GBA_4BPP_SUBPALETTE_BYTES
            ]
        return bytes(GBA_4BPP_SUBPALETTE_BYTES)
    out = bytes(GBA_4BPP_SUBPALETTE_BYTES)
    for chunk_i, s in enumerate(spec.palette_4_indices):
        if s != slot_index:
            continue
        off = chunk_i * GBA_4BPP_SUBPALETTE_BYTES
        out = pal_bytes[off : off + GBA_4BPP_SUBPALETTE_BYTES].ljust(
            GBA_4BPP_SUBPALETTE_BYTES, b"\x00"
        )[: GBA_4BPP_SUBPALETTE_BYTES]
    return out


def _strip_outer_backticks(s: str) -> str:
    """TOML often uses Format = '''`ucs4x8x8|palette.anchor`''' — unwrap one or more backtick layers."""
    s = s.strip()
    while len(s) >= 2 and s[0] == "`" and s[-1] == "`":
        s = s[1:-1].strip()
    return s


def parse_graphics_anchor_format(fmt: str) -> Optional[GraphicsAnchorSpec]:
    """
    Whole NamedAnchor Format string (no struct brackets), e.g. ucp4, lzp8:A, ucs4x4x4,
    or `` `ucs4x8x8|graphics.items.fossils.palette1` `` (backticks optional).
    """
    s = fmt.strip()
    if s.startswith("^"):
        s = s[1:].strip()
    s = _strip_outer_backticks(s)
    s, reshef = _split_reshef_graphics_prefix(s)

    def _finish(sp: GraphicsAnchorSpec) -> GraphicsAnchorSpec:
        return replace(sp, reshef_ygodm=True) if reshef else sp

    # 8bpp palette: one or more hex digits after colon (e.g. ucp8:3 or ucp8:0123)
    m = re.fullmatch(r"(uc|lz|huff4|huff8)p8:([0-9a-fA-F]+)", s, re.IGNORECASE)
    if m:
        try:
            lz, huff_bp = _compression_from_format_prefix(m.group(1))
        except ValueError:
            return None
        if not _huff_bpp_matches_tile_bpp(huff_bp, 8):
            return None
        return _finish(
            GraphicsAnchorSpec(
                kind="palette",
                bpp=8,
                lz=lz,
                huff_bpp=huff_bp,
                palette_hex_digit=m.group(2).upper(),
            )
        )

    # Bare ``ucp8`` / ``lzp8`` — same footprint as full 256-color master (16×32-byte chunks).
    m = re.fullmatch(r"(uc|lz|huff4|huff8)p8", s, re.IGNORECASE)
    if m:
        try:
            lz, huff_bp = _compression_from_format_prefix(m.group(1))
        except ValueError:
            return None
        if not _huff_bpp_matches_tile_bpp(huff_bp, 8):
            return None
        return _finish(
            GraphicsAnchorSpec(
                kind="palette",
                bpp=8,
                lz=lz,
                huff_bpp=huff_bp,
                palette_hex_digit=ucp8_slot_hex_digits_for_chunk_count(16),
            )
        )

    # 4bpp palette: optional :HEX… — each hex digit names a palette index (0–F); one 32-byte chunk per digit in ROM order
    m = re.fullmatch(r"(uc|lz|huff4|huff8)p4(?::([0-9a-fA-F]+))?", s, re.IGNORECASE)
    if m:
        try:
            lz, huff_bp = _compression_from_format_prefix(m.group(1))
        except ValueError:
            return None
        if not _huff_bpp_matches_tile_bpp(huff_bp, 4):
            return None
        suffix = m.group(2)
        if not suffix:
            return _finish(
                GraphicsAnchorSpec(
                    kind="palette",
                    bpp=4,
                    lz=lz,
                    huff_bpp=huff_bp,
                    palette_4_indices=None,
                )
            )
        idxs = tuple(int(ch, 16) for ch in suffix)
        return _finish(
            GraphicsAnchorSpec(
                kind="palette",
                bpp=4,
                lz=lz,
                huff_bpp=huff_bp,
                palette_4_indices=idxs,
            )
        )

    # Tilemap (non-affine ``bin`` / ``bin.lz``): ucm4xWxH[|tileset.anchor[|palette.anchor]].
    # Dimensions-only (no ``|`` tail): tileset/palette come from struct fields or external decode args.
    m = re.fullmatch(r"(uc|lz|huff4|huff8)m([468])x(\d+)x(\d+)(?:\|(.+))?", s, re.IGNORECASE)
    if m:
        try:
            lz, huff_bp = _compression_from_format_prefix(m.group(1))
        except ValueError:
            return None
        bpp = int(m.group(2))
        if not _huff_bpp_matches_tile_bpp(huff_bp, bpp):
            return None
        mw, mh = int(m.group(3)), int(m.group(4))
        if mw <= 0 or mh <= 0:
            return None
        rest = (m.group(5) or "").strip()
        if not rest:
            return _finish(
                GraphicsAnchorSpec(
                    kind="tilemap",
                    bpp=bpp,
                    lz=lz,
                    huff_bpp=huff_bp,
                    map_w_tiles=mw,
                    map_h_tiles=mh,
                    tileset_anchor_name=None,
                    palette_anchor_name=None,
                )
            )
        parts = [p.strip() for p in rest.split("|") if p.strip()]
        if not parts:
            return None
        ts_name = parts[0]
        pal_name = parts[1] if len(parts) > 1 else None
        return _finish(
            GraphicsAnchorSpec(
                kind="tilemap",
                bpp=bpp,
                lz=lz,
                huff_bpp=huff_bp,
                map_w_tiles=mw,
                map_h_tiles=mh,
                tileset_anchor_name=ts_name,
                palette_anchor_name=pal_name,
            )
        )

    m = re.fullmatch(r"(uc|lz|huff4|huff8)s([468])x(\d+)(?:x(\d+))?", s, re.IGNORECASE)
    if m:
        try:
            lz, huff_bp = _compression_from_format_prefix(m.group(1))
        except ValueError:
            return None
        bpp = int(m.group(2))
        if not _huff_bpp_matches_tile_bpp(huff_bp, bpp):
            return None
        w = int(m.group(3))
        h = int(m.group(4)) if m.group(4) is not None else 1
        if w <= 0 or h <= 0:
            return None
        return _finish(
            GraphicsAnchorSpec(
                kind="sprite",
                bpp=bpp,
                lz=lz,
                huff_bpp=huff_bp,
                width_tiles=w,
                height_tiles=h,
            )
        )

    # e.g. ucs4x8x8|graphics.items.fossils.palette1
    spec, pal = parse_sprite_field_spec(s)
    if spec:
        if pal:
            return _finish(replace(spec, palette_anchor_name=pal))
        return _finish(spec)
    return None


def parse_tilemap_dimension_spec(inner: str) -> Optional[GraphicsAnchorSpec]:
    """
    Struct field inner for ``tilemap<`…`>``: ``ucm4xWxH`` / ``lzm4xWxH`` with optional ignored ``|tail``
    (e.g. ``|table``). Does not embed tileset/palette NamedAnchors; use ``tileset<`…`>`` / ``palette<`…`>`` fields.
    """
    s = _strip_outer_backticks(inner.strip())
    dim_part = s.split("|", 1)[0].strip()
    m = re.fullmatch(r"(uc|lz|huff4|huff8)m([468])x(\d+)x(\d+)", dim_part, re.IGNORECASE)
    if not m:
        return None
    try:
        lz, huff_bp = _compression_from_format_prefix(m.group(1))
    except ValueError:
        return None
    bpp = int(m.group(2))
    if not _huff_bpp_matches_tile_bpp(huff_bp, bpp):
        return None
    mw, mh = int(m.group(3)), int(m.group(4))
    if mw <= 0 or mh <= 0:
        return None
    return GraphicsAnchorSpec(
        kind="tilemap",
        bpp=bpp,
        lz=lz,
        huff_bpp=huff_bp,
        map_w_tiles=mw,
        map_h_tiles=mh,
        tileset_anchor_name=None,
        palette_anchor_name=None,
    )


_GRAPHICS_TABLE_COUNT_REF_RE = re.compile(r"^[A-Za-z_][\w.+-]*$")


def parse_graphics_table_format(
    fmt: str,
) -> Optional[Tuple[GraphicsAnchorSpec, str, bool]]:
    """
    Table of identical graphics blobs: ``[rowFormat]countRef``.

    ``rowFormat`` parses as a standalone graphics spec (palette, sprite/tile sheet, or tilemap, with optional ``|…`` tails).
    ``countRef`` is resolved in the hex editor (PCS table name, ``[[List]]`` name, numeric count, etc.).

    Returns ``(spec, countRef, row_is_pointer_column)``. The third flag is ``True`` when ``rowFormat`` uses struct
    shorthand like ``palette<`ucp8:0123`>`` (each row is a **pointer** to data decoded with that spec). Those tables
    are **not** contiguous stride rows; the hex editor registers them as **struct** NamedAnchors instead.

    Examples::

        [ucp8:0123]cardgraphicsindexes
        [ucs6x10x10|graphics.cards.palettes]cardgraphicsindexes
    """
    s = fmt.strip()
    if s.startswith("^"):
        s = s[1:].strip()
    s = _strip_outer_backticks(s)
    if not s.startswith("["):
        return None
    depth = 0
    close = -1
    for i, ch in enumerate(s):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                close = i
                break
    if close < 0:
        return None
    inner = s[1:close].strip()
    suffix = s[close + 1 :].strip()
    if not inner or not suffix:
        return None
    if not _GRAPHICS_TABLE_COUNT_REF_RE.match(suffix):
        return None
    row_is_pointer_column = False
    row_spec = parse_graphics_anchor_format(inner)
    if row_spec is None:
        # Row may mirror struct shorthand: ``pal<`ucp8:0123`>``, ``card<`huff8s8x10x10|graphics…`>``, etc.
        sm = re.match(r"^(\w+)<`([^`]*)`>\s*$", inner.strip())
        if sm:
            row_spec = parse_graphics_anchor_format(sm.group(2).strip())
            row_is_pointer_column = bool(row_spec is not None)
    if row_spec is None:
        return None
    return (row_spec, suffix, row_is_pointer_column)


def graphics_row_byte_size(spec: GraphicsAnchorSpec) -> int:
    """Uncompressed byte size of one row in a graphics table (palette blob or tile blob)."""
    if spec.kind == "palette":
        if spec.lz or spec.huff_bpp is not None:
            raise ValueError("LZ/Huff palette rows in graphics tables are not supported")
        if spec.bpp == 4:
            return 32 * palette_4_chunk_count(spec)
        return palette_byte_count_8_variant(effective_ucp8_palette_hex_suffix(spec))
    if spec.kind == "sprite":
        if spec.lz or spec.huff_bpp is not None:
            raise ValueError("LZ/Huff sprite rows in graphics tables are not supported")
        if spec.width_tiles == 0 or spec.height_tiles == 0:
            raise ValueError("Variable-length tile strips (uct4/lzt4 without WxH) cannot be graphics table rows")
        return tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles)
    if spec.kind == "tilemap":
        if spec.lz or spec.huff_bpp is not None:
            raise ValueError("LZ/Huff tilemap rows in graphics tables are not supported")
        return spec.map_w_tiles * spec.map_h_tiles * 2
    raise ValueError(f"unknown graphics kind {spec.kind!r}")


def graphics_table_row_logical_byte_size(spec: GraphicsAnchorSpec) -> int:
    """
    Uncompressed size of one logical row in a graphics table.

    For **LZ/Huff** row specs, ROM storage is still compressed per row (variable length), but this is
    the byte length after decompress — used for UI caps and for **uncompressed** table layouts.
    """
    if spec.kind == "palette":
        if spec.bpp == 4:
            return 32 * palette_4_chunk_count(spec)
        return palette_byte_count_8_variant(effective_ucp8_palette_hex_suffix(spec))
    if spec.kind == "sprite":
        if spec.width_tiles == 0 or spec.height_tiles == 0:
            raise ValueError("Variable-length tile strips cannot be graphics table rows")
        return tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles)
    if spec.kind == "tilemap":
        return spec.map_w_tiles * spec.map_h_tiles * 2
    raise ValueError(f"unknown graphics kind {spec.kind!r}")


def parse_sprite_field_spec(inner: str) -> Tuple[Optional[GraphicsAnchorSpec], Optional[str]]:
    """
    Inner part of sprite<`...`> e.g. lzs4x2x6|graphics.items.ball.palettes
    Returns (spec, palette_anchor_name or None).
    """
    inner = _strip_outer_backticks(inner.strip())
    inner, reshef = _split_reshef_graphics_prefix(inner)

    def _fin(sp: GraphicsAnchorSpec) -> GraphicsAnchorSpec:
        return replace(sp, reshef_ygodm=True) if reshef else sp

    pal_name: Optional[str] = None
    if "|" in inner:
        spec_part, pal_part = inner.split("|", 1)
        spec_part = spec_part.strip()
        pal_name = pal_part.strip() or None
    else:
        spec_part = inner

    # Bare uct4 / uct6 / lzt8 — whole blob is tiles; width = tile_count, height = 1 (gbagfx .4bpp.lz / .8bpp.lz strip)
    m = re.fullmatch(r"(uc|lz|huff4|huff8)t([468])$", spec_part, re.IGNORECASE)
    if m:
        try:
            lz, huff_bp = _compression_from_format_prefix(m.group(1))
        except ValueError:
            return None, pal_name
        bpp = int(m.group(2))
        if not _huff_bpp_matches_tile_bpp(huff_bp, bpp):
            return None, pal_name
        return (
            _fin(
                GraphicsAnchorSpec(
                    kind="sprite",
                    bpp=bpp,
                    lz=lz,
                    huff_bpp=huff_bp,
                    width_tiles=0,
                    height_tiles=0,
                )
            ),
            pal_name,
        )

    m = re.fullmatch(r"(uc|lz|huff4|huff8)t([468])x(\d+)(?:x(\d+))?", spec_part, re.IGNORECASE)
    if m:
        try:
            lz, huff_bp = _compression_from_format_prefix(m.group(1))
        except ValueError:
            return None, pal_name
        bpp = int(m.group(2))
        if not _huff_bpp_matches_tile_bpp(huff_bp, bpp):
            return None, pal_name
        w = int(m.group(3))
        h = int(m.group(4)) if m.group(4) is not None else 1
        if w <= 0 or h <= 0:
            return None, pal_name
        return (
            _fin(
                GraphicsAnchorSpec(
                    kind="sprite",
                    bpp=bpp,
                    lz=lz,
                    huff_bpp=huff_bp,
                    width_tiles=w,
                    height_tiles=h,
                )
            ),
            pal_name,
        )

    m = re.fullmatch(r"(uc|lz|huff4|huff8)s([468])x(\d+)(?:x(\d+))?", spec_part, re.IGNORECASE)
    if not m:
        return None, pal_name
    try:
        lz, huff_bp = _compression_from_format_prefix(m.group(1))
    except ValueError:
        return None, pal_name
    bpp = int(m.group(2))
    if not _huff_bpp_matches_tile_bpp(huff_bp, bpp):
        return None, pal_name
    w = int(m.group(3))
    h = int(m.group(4)) if m.group(4) is not None else 1
    if w <= 0 or h <= 0:
        return None, pal_name
    return (
        _fin(
            GraphicsAnchorSpec(
                kind="sprite",
                bpp=bpp,
                lz=lz,
                huff_bpp=huff_bp,
                width_tiles=w,
                height_tiles=h,
            )
        ),
        pal_name,
    )


def rewrite_standalone_sprite_format_dimensions(
    original_format: str,
    width_tiles: int,
    height_tiles: int,
) -> Optional[str]:
    """
    Rewrite WxH in a standalone graphics NamedAnchor ``Format`` (optional leading ``^``, outer backticks,
    optional ``|palette…`` tail, or ``[rowSpec]countRef`` graphics table).

    Recognizes ``ucs``/``lzs``/``uct``/``lzt`` sprite specs. Bare ``uct4`` / ``lzt8`` becomes ``uct4xWxH`` / …
    Returns ``None`` if the format is not a rewriteable sprite sheet token.
    """
    tw, th = int(width_tiles), int(height_tiles)
    if tw < 1 or th < 1:
        return None

    def rewrite_spec_token(spec_part: str) -> Optional[str]:
        sp = spec_part.strip()
        m = re.fullmatch(r"(?i)(uc|lz|huff4|huff8)s([468])x(\d+)(?:x(\d+))?", sp)
        if m:
            return f"{m.group(1).lower()}s{m.group(2)}x{tw}x{th}"
        m = re.fullmatch(r"(?i)(uc|lz|huff4|huff8)t([468])x(\d+)(?:x(\d+))?", sp)
        if m:
            return f"{m.group(1).lower()}t{m.group(2)}x{tw}x{th}"
        m = re.fullmatch(r"(?i)(uc|lz|huff4|huff8)t([468])", sp)
        if m:
            return f"{m.group(1).lower()}t{m.group(2)}x{tw}x{th}"
        return None

    def rewrite_inner_content(inner: str) -> Optional[str]:
        inner_st = _strip_outer_backticks(inner.strip())
        if "|" in inner_st:
            spec_part, rest = inner_st.split("|", 1)
            new_sp = rewrite_spec_token(spec_part)
            if new_sp is None:
                return None
            return f"{new_sp}|{rest}"
        new_sp = rewrite_spec_token(inner_st)
        if new_sp is None:
            return None
        return new_sp

    ori = original_format.strip()
    hat = ori.startswith("^")
    s = ori[1:].strip() if hat else ori

    layers = 0
    t = s
    while len(t) >= 2 and t[0] == "`" and t[-1] == "`":
        layers += 1
        t = t[1:-1].strip()
    core = t

    if core.startswith("["):
        depth = 0
        close = -1
        for i, ch in enumerate(core):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    close = i
                    break
        if close < 0:
            return None
        inner = core[1:close].strip()
        suffix = core[close + 1 :].strip()
        new_inner = rewrite_inner_content(inner)
        if new_inner is None:
            return None
        new_core = f"[{new_inner}]{suffix}"
    else:
        new_core = rewrite_inner_content(core)
        if new_core is None:
            return None

    out = new_core
    for _ in range(layers):
        out = f"`{out}`"
    return ("^" if hat else "") + out


def rewrite_standalone_tilemap_format_dimensions(
    original_format: str,
    map_w_tiles: int,
    map_h_tiles: int,
) -> Optional[str]:
    """
    Rewrite ``ucm``/``lzm`` map WxH in a standalone tilemap NamedAnchor ``Format`` (same wrapping rules as
    :func:`rewrite_standalone_sprite_format_dimensions`).
    """
    tw, th = int(map_w_tiles), int(map_h_tiles)
    if tw < 1 or th < 1:
        return None

    def rewrite_tm_inner(inner_st: str) -> Optional[str]:
        inner_st = inner_st.strip()
        if "|" in inner_st:
            spec_part, rest = inner_st.split("|", 1)
            spec_part = spec_part.strip()
            rest = rest.strip()
        else:
            spec_part = inner_st.strip()
            rest = ""
        m = re.fullmatch(r"(?i)(uc|lz|huff4|huff8)m([468])x(\d+)x(\d+)", spec_part)
        if not m:
            return None
        new_sp = f"{m.group(1).lower()}m{m.group(2)}x{tw}x{th}"
        if rest:
            return f"{new_sp}|{rest}"
        return new_sp

    def rewrite_inner_content(inner: str) -> Optional[str]:
        inner_st = _strip_outer_backticks(inner.strip())
        new_inner = rewrite_tm_inner(inner_st)
        if new_inner is None:
            return None
        return new_inner

    ori = original_format.strip()
    hat = ori.startswith("^")
    s = ori[1:].strip() if hat else ori

    layers = 0
    t = s
    while len(t) >= 2 and t[0] == "`" and t[-1] == "`":
        layers += 1
        t = t[1:-1].strip()
    core = t

    if core.startswith("["):
        depth = 0
        close = -1
        for i, ch in enumerate(core):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    close = i
                    break
        if close < 0:
            return None
        inner = core[1:close].strip()
        suffix = core[close + 1 :].strip()
        new_inner = rewrite_inner_content(inner)
        if new_inner is None:
            return None
        new_core = f"[{new_inner}]{suffix}"
    else:
        new_core = rewrite_inner_content(core)
        if new_core is None:
            return None

    out = new_core
    for _ in range(layers):
        out = f"`{out}`"
    return ("^" if hat else "") + out


def extract_palette_bytes(spec: GraphicsAnchorSpec, raw: bytes) -> bytes:
    if spec.kind != "palette":
        raise ValueError("not a palette spec")
    data = raw
    if spec.lz:
        data = decompress_gba_lz77(raw)
    elif spec.huff_bpp is not None:
        data = decompress_gba_huff(raw)
    data = _apply_ygodm_decode_after_decompress(spec, data)
    if spec.bpp == 4:
        need = 32 * palette_4_chunk_count(spec)
    else:
        need = palette_byte_count_8_variant(effective_ucp8_palette_hex_suffix(spec))
    if len(data) < need:
        raise ValueError(f"Palette data too short: need {need}, have {len(data)}")
    return data[:need]


def normalize_4bpp_palette_for_gbagfx(
    pal_bytes: bytes, indices: Optional[Tuple[int, ...]]
) -> bytes:
    """
    Plain ``ucp4`` (``indices is None``): return the single 32-byte chunk unchanged.

    Otherwise scatter each ROM chunk into its hardware palette slot named by the corresponding hex digit;
    unused slots stay ``00 00`` per color (512 bytes total). Chunks targeting the same index: first wins.
    """
    if indices is None:
        return pal_bytes
    out = bytearray(GBA_4BPP_MASTER_PALETTE_BYTES)
    for chunk_i, slot in enumerate(indices):
        if slot < 0 or slot >= GBA_4BPP_MASTER_INDEX_COUNT:
            continue
        off_rom = chunk_i * GBA_4BPP_SUBPALETTE_BYTES
        chunk = pal_bytes[off_rom : off_rom + GBA_4BPP_SUBPALETTE_BYTES]
        if len(chunk) < GBA_4BPP_SUBPALETTE_BYTES:
            chunk = chunk.ljust(GBA_4BPP_SUBPALETTE_BYTES, b"\x00")
        base = slot * GBA_4BPP_SUBPALETTE_BYTES
        out[base : base + GBA_4BPP_SUBPALETTE_BYTES] = chunk
    return bytes(out)


def palette_bytes_for_gbagfx(
    spec: GraphicsAnchorSpec,
    pal_bytes: bytes,
    *,
    sprite_bpp: Optional[int] = None,
) -> bytes:
    """
    Raw palette bytes before RGB decode (pret ``ReadGbaPalette`` input).

    - Multi-chunk ``ucp4:``: for **palette-only** preview, scatter into a 512-byte master; for **4bpp sprites**,
      use only the first ROM chunk (32 bytes).
    - ``sprite_bpp`` 4 + 8bpp-format palette anchor: trim to the first 32 bytes.
    """
    if spec.kind == "palette" and spec.bpp == 4 and palette_4_chunk_count(spec) > 1:
        if sprite_bpp == 4:
            pal_bytes = pal_bytes[:GBA_4BPP_SUBPALETTE_BYTES]
        else:
            pal_bytes = normalize_4bpp_palette_for_gbagfx(pal_bytes, spec.palette_4_indices)
    # 4bpp sprites with an 8bpp-format palette anchor: only the first subpalette applies.
    # 6bpp/8bpp sprites use the full extracted palette (e.g. 64 colors = 128 bytes for 6bpp card art).
    if sprite_bpp == 4 and spec.kind == "palette" and spec.bpp == 8:
        pal_bytes = pal_bytes[:GBA_4BPP_SUBPALETTE_BYTES]
    return pal_bytes


def sprite_bytes_per_tile(bpp: int) -> int:
    if bpp == 4:
        return 32
    if bpp == 6:
        return 48
    return 64


def max_sprite_height_tiles(num_tiles: int) -> int:
    """Largest ``H`` with ``H ≤ ceil(num_tiles / H)`` (row count does not exceed column count)."""
    if num_tiles < 1:
        return 1
    best = 1
    for h in range(1, num_tiles + 1):
        w = (num_tiles + h - 1) // h
        if h <= w:
            best = h
    return best


def compute_sprite_grid_layout(
    num_tiles: int,
    height_tiles: int,
    *,
    enforce_rows_le_cols: bool = True,
) -> Tuple[int, int]:
    """
    Lay out ``num_tiles`` tiles in a grid with ``height_tiles`` rows;
    ``width_tiles = ceil(num_tiles / height_tiles)``.

    If ``enforce_rows_le_cols`` is True (default), require ``height_tiles ≤ width_tiles``
    (good for variable tile strips so the grid is not “taller than wide”).

    For **fixed** ``ucs4xWxH`` / ``lzs4xWxH`` assets from TOML (e.g. 4×8 party icons), pass
    ``enforce_rows_le_cols=False`` so tall layouts (rows > columns) are allowed.
    """
    if height_tiles < 1:
        raise ValueError("Tile row count (height) must be at least 1")
    if num_tiles < 1:
        raise ValueError("No tiles in data")
    if height_tiles > num_tiles:
        raise ValueError(f"Tile rows ({height_tiles}) cannot exceed tile count ({num_tiles}).")
    w = (num_tiles + height_tiles - 1) // height_tiles
    if enforce_rows_le_cols and height_tiles > w:
        raise ValueError(
            f"Tile rows ({height_tiles}) exceed tile columns ({w}); require rows ≤ columns "
            f"(or use fixed-dimension decode with enforce_rows_le_cols=False)."
        )
    return w, height_tiles


def extract_sprite_bytes(spec: GraphicsAnchorSpec, raw: bytes) -> bytes:
    if spec.kind != "sprite":
        raise ValueError("not a sprite spec")
    if spec.width_tiles == 0 and spec.height_tiles == 0:
        if spec.bpp == 6:
            raise ValueError("Variable-length tile strip does not support 6bpp")
        per = 32 if spec.bpp == 4 else 64
        if spec.lz:
            data = decompress_gba_lz77(raw)
        elif spec.huff_bpp is not None:
            data = decompress_gba_huff(raw)
        else:
            data = raw
        data = _apply_ygodm_decode_after_decompress(spec, data)
        if len(data) < per:
            raise ValueError(f"Tile strip too short: need at least {per} bytes, have {len(data)}")
        n = len(data) // per
        need = n * per
        return data[:need]

    need = tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles)
    if spec.lz:
        data = decompress_gba_lz77(raw)
    elif spec.huff_bpp is not None:
        data = decompress_gba_huff(raw)
    else:
        data = raw
    data = _apply_ygodm_decode_after_decompress(spec, data)
    if len(data) < need:
        raise ValueError(f"Sprite tile data too short: need {need}, have {len(data)}")
    return data[:need]


def extract_tilemap_bytes(spec: GraphicsAnchorSpec, raw: bytes) -> bytes:
    if spec.kind != "tilemap":
        raise ValueError("not a tilemap spec")
    need = spec.map_w_tiles * spec.map_h_tiles * 2
    if spec.lz:
        data = decompress_gba_lz77(raw)
    elif spec.huff_bpp is not None:
        data = decompress_gba_huff(raw)
    else:
        data = raw
    data = _apply_ygodm_decode_after_decompress(spec, data)
    if len(data) < need:
        raise ValueError(f"Tilemap data too short: need {need} bytes (map {spec.map_w_tiles}×{spec.map_h_tiles}), have {len(data)}")
    return data[:need]


def decode_palette_to_png_pal(
    rom: bytes,
    base_off: int,
    spec: GraphicsAnchorSpec,
) -> Tuple[Optional[str], str]:
    """
    Read palette from ROM, write a strip preview PNG (pret ``ReadGbaPalette`` RGB conversion).
    Returns (path to PNG or None, log text).
    """
    if base_off < 0 or base_off >= len(rom):
        return None, "Invalid ROM offset for palette.\n"
    raw = bytes(rom[base_off : base_off + min(len(rom) - base_off, 1 << 20)])
    try:
        pal_bytes = extract_palette_bytes(spec, raw)
    except ValueError as e:
        return None, f"Palette decode error: {e}\n"
    pal_bytes = palette_bytes_for_gbagfx(spec, pal_bytes)

    td = tempfile.mkdtemp(prefix="ch_gfx_")
    try:
        colors_act = raw_gba_palette_to_rgb888_list(pal_bytes)
        png_path = os.path.join(td, "palette.png")
        # Grid layout (16×N) with 18×26 swatches — readable for 64-color rows; avoid padding to 256 for preview.
        write_palette_grid_png(png_path, colors_act)
        n = len(colors_act)
        log = f"Palette -> PNG ({n} GBA colors; grid preview, pret ReadGbaPalette RGB).\n"
        return png_path, log
    except ImportError as e:
        return None, f"{e}\n"
    except (OSError, ValueError) as e:
        return None, f"Palette PNG error: {e}\n"


def _sprite_tiles_to_png_path(
    tiles: bytes,
    spec: GraphicsAnchorSpec,
    pal_bytes: bytes,
    td: str,
    stem: str,
) -> Tuple[str, str]:
    if spec.bpp == 4:
        pal_rgb = palette_rgb_for_4bpp_tile_decode(pal_bytes)
    else:
        pal_rgb = palette_rgb_for_8bpp_tile_decode(pal_bytes)
    wpx = spec.width_tiles * 8
    hpx = spec.height_tiles * 8
    rgba = gba_tiles_to_rgba(
        tiles,
        spec.bpp,
        spec.width_tiles,
        spec.height_tiles,
        pal_rgb,
    )
    png_path = os.path.join(td, f"{stem}.png")
    write_rgba_png(png_path, wpx, hpx, rgba)
    if spec.bpp == 6:
        log = f"Sprite -> PNG {wpx}x{hpx} (6bpp packed → indices 0–63).\n"
    else:
        log = f"Sprite -> PNG {wpx}x{hpx} ({spec.bpp}bpp tiles, pret gfx.c tile order).\n"
    return png_path, log


def _palette_bytes_for_tilemap_decode(
    pal_spec: Optional[GraphicsAnchorSpec],
    pal_bytes: bytes,
    tilemap_bpp: int,
) -> bytes:
    """Keep multi-chunk ``ucp4:`` ROM layout for ``tilemap_non_affine_to_rgba``; otherwise gbagfx rules."""
    if pal_spec is None:
        return pal_bytes
    if (
        pal_spec.kind == "palette"
        and pal_spec.bpp == 4
        and palette_4_chunk_count(pal_spec) > 1
    ):
        return pal_bytes
    return palette_bytes_for_gbagfx(pal_spec, pal_bytes, sprite_bpp=tilemap_bpp)


def decode_graphics_anchor_to_png(
    rom: bytes,
    base_off: int,
    spec: GraphicsAnchorSpec,
    *,
    external_palette_spec: Optional[GraphicsAnchorSpec] = None,
    external_palette_base_off: Optional[int] = None,
    external_tileset_spec: Optional[GraphicsAnchorSpec] = None,
    external_tileset_base_off: Optional[int] = None,
    sprite_layout_height: Optional[int] = None,
    override_sprite_palette_bytes: Optional[bytes] = None,
) -> Tuple[Optional[str], str]:
    """
    Decode a standalone graphics NamedAnchor (palette-only returns None PNG; sprite/tilemap return PNG path).

    For sprite anchors with ``palette_anchor_name`` in TOML, pass the resolved palette as
    ``external_palette_spec`` + ``external_palette_base_off`` (or both None for default palette).

    For **tilemap** (``ucm`` / ``lzm``), pass ``external_tileset_spec`` + ``external_tileset_base_off`` for the
    tile sheet anchor (``uct`` / ``lzt`` / ``ucs`` / ``lzs``), and optional external palette like sprites.

    For **sprites**, ``sprite_layout_height`` sets the number of **tile rows** (``H``); width is
    ``ceil(tile_count / H)``. If omitted, variable strips use one row; fixed formats use TOML ``WxH``.

    If ``override_sprite_palette_bytes`` is set (raw GBA RGB555 data), it is used for sprite preview instead
    of ``external_palette_*`` (length must match sprite bpp: 32 / 128 / 512 bytes).
    """
    logs: List[str] = []
    if spec.kind == "palette":
        _pal, log = decode_palette_to_png_pal(rom, base_off, spec)
        logs.append(log)
        return None, "".join(logs)

    if base_off < 0 or base_off >= len(rom):
        return None, "Invalid ROM offset for graphics blob.\n"
    raw = bytes(rom[base_off : base_off + min(len(rom) - base_off, 4 << 20)])

    if spec.kind == "tilemap":
        if external_tileset_spec is None or external_tileset_base_off is None:
            return None, "Tilemap decode requires ``external_tileset_spec`` and ``external_tileset_base_off`` (tileset NamedAnchor).\n"
        if external_tileset_spec.kind != "sprite":
            return None, f"Tileset anchor must be a tile sheet (uct/lzt/ucs/lzs…), not {external_tileset_spec.kind!r}.\n"
        if external_tileset_base_off < 0 or external_tileset_base_off >= len(rom):
            return None, "Invalid ROM offset for tileset.\n"
        try:
            map_bytes = extract_tilemap_bytes(spec, raw)
        except ValueError as e:
            return None, f"Tilemap decode error: {e}\n"
        ts_raw = bytes(
            rom[
                external_tileset_base_off : external_tileset_base_off
                + min(len(rom) - external_tileset_base_off, 4 << 20)
            ]
        )
        try:
            tiles = extract_sprite_bytes(external_tileset_spec, ts_raw)
        except ValueError as e:
            return None, f"Tileset decode error: {e}\n"

        td = tempfile.mkdtemp(prefix="ch_gfx_tm_")
        try:
            if external_palette_spec is not None and external_palette_base_off is not None:
                praw = bytes(
                    rom[
                        external_palette_base_off : external_palette_base_off
                        + min(len(rom) - external_palette_base_off, 1 << 20)
                    ]
                )
                try:
                    pal_bytes = extract_palette_bytes(external_palette_spec, praw)
                except ValueError as e:
                    return None, f"External palette decode error: {e}\n"
                pal_bytes = _palette_bytes_for_tilemap_decode(
                    external_palette_spec, pal_bytes, spec.bpp
                )
            else:
                pal_bytes = bytes(32) if spec.bpp == 4 else bytes(512)

            wpx = spec.map_w_tiles * 8
            hpx = spec.map_h_tiles * 8
            rgba = tilemap_non_affine_to_rgba(
                tiles,
                map_bytes,
                bpp=spec.bpp,
                map_w=spec.map_w_tiles,
                map_h=spec.map_h_tiles,
                pal_spec=external_palette_spec,
                pal_bytes=pal_bytes,
            )
            png_path = os.path.join(td, "tilemap.png")
            write_rgba_png(png_path, wpx, hpx, rgba)
            logs.append(
                f"Tilemap -> PNG {wpx}x{hpx} ({spec.bpp}bpp, pret NonAffine tilemap + tileset).\n"
            )
            return png_path, "".join(logs)
        except ImportError as e:
            return None, f"{e}\n"
        except (OSError, ValueError) as e:
            return None, f"{''.join(logs)}\nTilemap PNG error: {e}\n"

    if spec.kind != "sprite":
        return None, f"Unsupported graphics kind {spec.kind!r}.\n"

    try:
        tiles = extract_sprite_bytes(spec, raw)
    except ValueError as e:
        return None, f"Sprite decode error: {e}\n"

    td = tempfile.mkdtemp(prefix="ch_gfx_")
    stem = "gfx"
    try:
        if override_sprite_palette_bytes is not None:
            need = SPRITE_PALETTE_ROM_BYTE_COUNT.get(spec.bpp)
            if need is None:
                return None, f"Unsupported sprite bpp for palette override: {spec.bpp}.\n"
            if len(override_sprite_palette_bytes) < need:
                return None, (
                    f"Preview palette override too short: need {need} bytes for {spec.bpp}bpp sprite, "
                    f"have {len(override_sprite_palette_bytes)}.\n"
                )
            pal_bytes = bytes(override_sprite_palette_bytes[:need])
        elif external_palette_spec is not None and external_palette_base_off is not None:
            praw = bytes(
                rom[
                    external_palette_base_off : external_palette_base_off
                    + min(len(rom) - external_palette_base_off, 1 << 20)
                ]
            )
            try:
                pal_bytes = extract_palette_bytes(external_palette_spec, praw)
            except ValueError as e:
                return None, f"External palette decode error: {e}\n"
            pal_bytes = palette_bytes_for_gbagfx(
                external_palette_spec, pal_bytes, sprite_bpp=spec.bpp
            )
        else:
            if spec.bpp == 8:
                pal_bytes = bytes(512)
            elif spec.bpp == 6:
                pal_bytes = bytes(128)
            else:
                pal_bytes = bytes(32)

        per = sprite_bytes_per_tile(spec.bpp)
        nt = len(tiles) // per
        eff_spec = spec
        fixed_wh = spec.width_tiles > 0 and spec.height_tiles > 0
        if sprite_layout_height is not None:
            try:
                w_t, h_t = compute_sprite_grid_layout(
                    nt,
                    int(sprite_layout_height),
                    enforce_rows_le_cols=not fixed_wh,
                )
            except ValueError as e:
                return None, f"Sprite layout: {e}\n"
            eff_spec = replace(spec, width_tiles=w_t, height_tiles=h_t)
        elif spec.width_tiles == 0 and spec.height_tiles == 0:
            eff_spec = replace(spec, width_tiles=nt, height_tiles=1)

        png_path, slog = _sprite_tiles_to_png_path(tiles, eff_spec, pal_bytes, td, stem)
        if spec.width_tiles == 0 and spec.height_tiles == 0 and sprite_layout_height is None:
            slog = slog.rstrip() + f" (variable strip: {eff_spec.width_tiles} tiles × 1 row).\n"
        elif sprite_layout_height is not None:
            slog = slog.rstrip() + f" (layout {eff_spec.width_tiles}×{eff_spec.height_tiles} tiles).\n"
        logs.append(slog)
        return png_path, "".join(logs)
    except ImportError as e:
        return None, f"{e}\n"
    except OSError as e:
        return None, f"{''.join(logs)}\nFilesystem error: {e}\n"


def decode_sprite_at_pointer(
    rom: bytes,
    sprite_file_off: int,
    spec: GraphicsAnchorSpec,
    palette_spec: Optional[GraphicsAnchorSpec],
    palette_base_off: Optional[int],
    *,
    sprite_layout_height: Optional[int] = None,
    override_sprite_palette_bytes: Optional[bytes] = None,
) -> Tuple[Optional[str], str]:
    """
    Decode sprite from ROM at sprite_file_off using optional external palette anchor.

    If ``override_sprite_palette_bytes`` is set (raw GBA RGB555 data), it is used instead of the
    resolved palette anchor (length must match sprite bpp: 32 / 128 / 512 bytes).
    """
    logs: List[str] = []
    if sprite_file_off < 0 or sprite_file_off >= len(rom):
        return None, "Invalid sprite pointer offset.\n"
    raw = bytes(rom[sprite_file_off : sprite_file_off + min(len(rom) - sprite_file_off, 4 << 20)])
    try:
        tiles = extract_sprite_bytes(spec, raw)
    except ValueError as e:
        return None, f"Sprite decode error: {e}\n"

    td = tempfile.mkdtemp(prefix="ch_gfx_sp_")
    try:
        if override_sprite_palette_bytes is not None:
            need = SPRITE_PALETTE_ROM_BYTE_COUNT.get(spec.bpp)
            if need is None:
                return None, f"Unsupported sprite bpp for palette override: {spec.bpp}.\n"
            if len(override_sprite_palette_bytes) < need:
                return None, (
                    f"Preview palette override too short: need {need} bytes for {spec.bpp}bpp sprite, "
                    f"have {len(override_sprite_palette_bytes)}.\n"
                )
            pal_bytes = bytes(override_sprite_palette_bytes[:need])
        elif palette_spec is not None and palette_base_off is not None:
            praw = bytes(rom[palette_base_off : palette_base_off + min(len(rom) - palette_base_off, 1 << 20)])
            try:
                pal_bytes = extract_palette_bytes(palette_spec, praw)
            except ValueError as e:
                return None, f"External palette decode error: {e}\n"
            pal_bytes = palette_bytes_for_gbagfx(palette_spec, pal_bytes, sprite_bpp=spec.bpp)
        else:
            if spec.bpp == 8:
                pal_bytes = bytes(512)
            elif spec.bpp == 6:
                pal_bytes = bytes(128)
            else:
                pal_bytes = bytes(32)

        per = sprite_bytes_per_tile(spec.bpp)
        nt = len(tiles) // per
        eff_spec = spec
        fixed_wh = spec.width_tiles > 0 and spec.height_tiles > 0
        if sprite_layout_height is not None:
            try:
                w_t, h_t = compute_sprite_grid_layout(
                    nt,
                    int(sprite_layout_height),
                    enforce_rows_le_cols=not fixed_wh,
                )
            except ValueError as e:
                return None, f"Sprite layout: {e}\n"
            eff_spec = replace(spec, width_tiles=w_t, height_tiles=h_t)
        elif spec.width_tiles == 0 and spec.height_tiles == 0:
            eff_spec = replace(spec, width_tiles=nt, height_tiles=1)

        png_path, slog = _sprite_tiles_to_png_path(tiles, eff_spec, pal_bytes, td, "sprite")
        if spec.width_tiles == 0 and spec.height_tiles == 0 and sprite_layout_height is None:
            slog = slog.rstrip() + f" (variable strip: {eff_spec.width_tiles} tiles × 1 row).\n"
        elif sprite_layout_height is not None:
            slog = slog.rstrip() + f" (layout {eff_spec.width_tiles}×{eff_spec.height_tiles} tiles).\n"
        logs.append(slog)
        return png_path, "".join(logs)
    except ImportError as e:
        return None, f"{e}\n"
    except OSError as e:
        return None, f"{''.join(logs)}\nFilesystem error: {e}\n"


def resolve_gba_pointer(rom: bytes, file_off: int) -> Optional[int]:
    """4-byte little-endian pointer; map 0x08xxxxxx to file offset."""
    if file_off < 0 or file_off + 4 > len(rom):
        return None
    ptr = int.from_bytes(rom[file_off : file_off + 4], "little")
    hi = ptr >> 24
    if hi in (0x08, 0x09):
        fo = ptr - 0x08000000
        if 0 <= fo < len(rom):
            return fo
    return None
