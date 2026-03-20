"""
GBA graphics helpers: LZ77 decompress (pret ``lz.c``) and **pure-Python** palette/tile decode aligned with pret
``tools/gbagfx/gfx.c`` (``ReadGbaPalette``, 4bpp/8bpp tile layout, ``DecodeNonAffineTilemap``). PNG output uses Pillow.

Palette formats: ucp4, lzp4, ucp4:HEX…, ucp8:N / lzp8:N.
Sprite sheets: ucs/lzs (and **uct/lzt** — same layout as 4bpp/8bpp ``.4bpp`` / ``.8bpp`` in gbagfx).
Bare **uct4** / **lzt8** (no ``xWxH``): LZ77 or raw blob is only tiles; tile count = len÷32 or len÷64; drawn as one row (matches gbagfx tile strip + ``-width N`` style).
Tilemaps: ucm/lzm 4bpp or 8bpp non-affine maps (2 bytes/cell, same layout as [Tilemap Studio GBA_4BPP](https://github.com/Rangi42/tilemap-studio/blob/master/src/tilemap-format.cpp) / pret ``NonAffineTile``);
  tileset = another NamedAnchor; optional ``|palette`` — if omitted, Tools uses the tileset anchor’s ``|palette`` link.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, replace
from typing import List, Optional, Tuple

# Repo root: editors/common -> repo
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_MODULE_DIR, "..", ".."))
GBAGFX_PATH = os.path.join(_REPO_ROOT, "deps", "gbagfx")


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


def palette_byte_count_8_variant(hex_digits: str) -> int:
    """ucp8:/lzp8: ROM byte length for one palette blob.

    - **One** hex digit ``N``: ``N * 32`` bytes (``N == 0`` is treated as ``1``), original rule.
    - **Several** digits (e.g. ``0123``): ``len(digits) * 32`` bytes — contiguous 32-byte chunks (64 colors
      when 4 chunks), used by card graphics tables.
    """
    s = (hex_digits or "1").strip().upper()
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
        if spec.lz:
            return min(rest, 512 * 1024)
        if spec.bpp == 4:
            return min(rest, 32 * palette_4_chunk_count(spec))
        dig = spec.palette_hex_digit or "1"
        return min(rest, palette_byte_count_8_variant(dig))
    if spec.kind == "tilemap":
        if spec.lz:
            return min(rest, 2 * 1024 * 1024)
        need = spec.map_w_tiles * spec.map_h_tiles * 2
        return min(rest, max(1, need))
    if spec.kind == "sprite" and spec.width_tiles == 0 and spec.height_tiles == 0:
        # Variable-length tile strip (``lzt4|pal``): unknown uncompressed span
        if spec.lz:
            return min(rest, 2 * 1024 * 1024)
        return min(rest, 512 * 1024)
    if spec.lz:
        return min(rest, 2 * 1024 * 1024)
    return min(rest, tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles))


@dataclass
class GraphicsAnchorSpec:
    kind: str  # "palette" | "sprite" | "tilemap"
    bpp: int  # palette: 4 or 8; sprite: 4, 6, or 8; tilemap: 4 or 8
    lz: bool
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

    # 8bpp palette: one or more hex digits after colon (e.g. ucp8:3 or ucp8:0123)
    m = re.fullmatch(r"(uc|lz)p8:([0-9a-fA-F]+)", s, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        return GraphicsAnchorSpec(
            kind="palette",
            bpp=8,
            lz=lz,
            palette_hex_digit=m.group(2).upper(),
        )

    # 4bpp palette: optional :HEX… — each hex digit names a palette index (0–F); one 32-byte chunk per digit in ROM order
    m = re.fullmatch(r"(uc|lz)p4(?::([0-9a-fA-F]+))?", s, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        suffix = m.group(2)
        if not suffix:
            return GraphicsAnchorSpec(kind="palette", bpp=4, lz=lz, palette_4_indices=None)
        idxs = tuple(int(ch, 16) for ch in suffix)
        return GraphicsAnchorSpec(
            kind="palette",
            bpp=4,
            lz=lz,
            palette_4_indices=idxs,
        )

    # Tilemap (non-affine ``bin`` / ``bin.lz``): ucm4xWxH[|tileset.anchor[|palette.anchor]].
    # Dimensions-only (no ``|`` tail): tileset/palette come from struct fields or external decode args.
    m = re.fullmatch(r"(uc|lz)m([48])x(\d+)x(\d+)(?:\|(.+))?", s, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        bpp = int(m.group(2))
        mw, mh = int(m.group(3)), int(m.group(4))
        if mw <= 0 or mh <= 0:
            return None
        rest = (m.group(5) or "").strip()
        if not rest:
            return GraphicsAnchorSpec(
                kind="tilemap",
                bpp=bpp,
                lz=lz,
                map_w_tiles=mw,
                map_h_tiles=mh,
                tileset_anchor_name=None,
                palette_anchor_name=None,
            )
        parts = [p.strip() for p in rest.split("|") if p.strip()]
        if not parts:
            return None
        ts_name = parts[0]
        pal_name = parts[1] if len(parts) > 1 else None
        return GraphicsAnchorSpec(
            kind="tilemap",
            bpp=bpp,
            lz=lz,
            map_w_tiles=mw,
            map_h_tiles=mh,
            tileset_anchor_name=ts_name,
            palette_anchor_name=pal_name,
        )

    m = re.fullmatch(r"(uc|lz)s([468])x(\d+)(?:x(\d+))?", s, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        bpp = int(m.group(2))
        w = int(m.group(3))
        h = int(m.group(4)) if m.group(4) is not None else 1
        if w <= 0 or h <= 0:
            return None
        return GraphicsAnchorSpec(
            kind="sprite",
            bpp=bpp,
            lz=lz,
            width_tiles=w,
            height_tiles=h,
        )

    # e.g. ucs4x8x8|graphics.items.fossils.palette1
    spec, pal = parse_sprite_field_spec(s)
    if spec:
        if pal:
            return replace(spec, palette_anchor_name=pal)
        return spec
    return None


def parse_tilemap_dimension_spec(inner: str) -> Optional[GraphicsAnchorSpec]:
    """
    Struct field inner for ``tilemap<`…`>``: ``ucm4xWxH`` / ``lzm4xWxH`` with optional ignored ``|tail``
    (e.g. ``|table``). Does not embed tileset/palette NamedAnchors; use ``tileset<`…`>`` / ``palette<`…`>`` fields.
    """
    s = _strip_outer_backticks(inner.strip())
    dim_part = s.split("|", 1)[0].strip()
    m = re.fullmatch(r"(uc|lz)m([48])x(\d+)x(\d+)", dim_part, re.IGNORECASE)
    if not m:
        return None
    lz = m.group(1).lower() == "lz"
    bpp = int(m.group(2))
    mw, mh = int(m.group(3)), int(m.group(4))
    if mw <= 0 or mh <= 0:
        return None
    return GraphicsAnchorSpec(
        kind="tilemap",
        bpp=bpp,
        lz=lz,
        map_w_tiles=mw,
        map_h_tiles=mh,
        tileset_anchor_name=None,
        palette_anchor_name=None,
    )


_GRAPHICS_TABLE_COUNT_REF_RE = re.compile(r"^[A-Za-z_][\w.+-]*$")


def parse_graphics_table_format(fmt: str) -> Optional[Tuple[GraphicsAnchorSpec, str]]:
    """
    Table of identical graphics blobs: ``[rowFormat]countRef``.

    ``rowFormat`` parses as a standalone graphics spec (palette, sprite/tile sheet, or tilemap, with optional ``|…`` tails).
    ``countRef`` is resolved in the hex editor (PCS table name, ``[[List]]`` name, numeric count, etc.).

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
    row_spec = parse_graphics_anchor_format(inner)
    if row_spec is None:
        return None
    return (row_spec, suffix)


def graphics_row_byte_size(spec: GraphicsAnchorSpec) -> int:
    """Uncompressed byte size of one row in a graphics table (palette blob or tile blob)."""
    if spec.kind == "palette":
        if spec.lz:
            raise ValueError("LZ palette rows in graphics tables are not supported")
        if spec.bpp == 4:
            return 32 * palette_4_chunk_count(spec)
        if spec.palette_hex_digit is None:
            raise ValueError("8bpp palette spec missing palette_hex_digit")
        return palette_byte_count_8_variant(spec.palette_hex_digit)
    if spec.kind == "sprite":
        if spec.lz:
            raise ValueError("LZ sprite rows in graphics tables are not supported")
        if spec.width_tiles == 0 or spec.height_tiles == 0:
            raise ValueError("Variable-length tile strips (uct4/lzt4 without WxH) cannot be graphics table rows")
        return tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles)
    if spec.kind == "tilemap":
        if spec.lz:
            raise ValueError("LZ tilemap rows in graphics tables are not supported")
        return spec.map_w_tiles * spec.map_h_tiles * 2
    raise ValueError(f"unknown graphics kind {spec.kind!r}")


def parse_sprite_field_spec(inner: str) -> Tuple[Optional[GraphicsAnchorSpec], Optional[str]]:
    """
    Inner part of sprite<`...`> e.g. lzs4x2x6|graphics.items.ball.palettes
    Returns (spec, palette_anchor_name or None).
    """
    inner = _strip_outer_backticks(inner.strip())
    pal_name: Optional[str] = None
    if "|" in inner:
        spec_part, pal_part = inner.split("|", 1)
        spec_part = spec_part.strip()
        pal_name = pal_part.strip() or None
    else:
        spec_part = inner

    # Bare uct4 / lzt8 — whole blob is tiles; width = tile_count, height = 1 (gbagfx .4bpp.lz / .8bpp.lz strip)
    m = re.fullmatch(r"(uc|lz)t([48])$", spec_part, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        bpp = int(m.group(2))
        return (
            GraphicsAnchorSpec(
                kind="sprite",
                bpp=bpp,
                lz=lz,
                width_tiles=0,
                height_tiles=0,
            ),
            pal_name,
        )

    m = re.fullmatch(r"(uc|lz)t([48])x(\d+)(?:x(\d+))?", spec_part, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        bpp = int(m.group(2))
        w = int(m.group(3))
        h = int(m.group(4)) if m.group(4) is not None else 1
        if w <= 0 or h <= 0:
            return None, pal_name
        return (
            GraphicsAnchorSpec(
                kind="sprite",
                bpp=bpp,
                lz=lz,
                width_tiles=w,
                height_tiles=h,
            ),
            pal_name,
        )

    m = re.fullmatch(r"(uc|lz)s([468])x(\d+)(?:x(\d+))?", spec_part, re.IGNORECASE)
    if not m:
        return None, pal_name
    lz = m.group(1).lower() == "lz"
    bpp = int(m.group(2))
    w = int(m.group(3))
    h = int(m.group(4)) if m.group(4) is not None else 1
    if w <= 0 or h <= 0:
        return None, pal_name
    return (
        GraphicsAnchorSpec(
            kind="sprite",
            bpp=bpp,
            lz=lz,
            width_tiles=w,
            height_tiles=h,
        ),
        pal_name,
    )


def extract_palette_bytes(spec: GraphicsAnchorSpec, raw: bytes) -> bytes:
    if spec.kind != "palette":
        raise ValueError("not a palette spec")
    data = raw
    if spec.lz:
        data = decompress_gba_lz77(raw)
    if spec.bpp == 4:
        need = 32 * palette_4_chunk_count(spec)
    else:
        assert spec.palette_hex_digit is not None
        need = palette_byte_count_8_variant(spec.palette_hex_digit)
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


def compute_sprite_grid_layout(num_tiles: int, height_tiles: int) -> Tuple[int, int]:
    """
    Lay out ``num_tiles`` tiles in a grid with ``height_tiles`` rows.
    ``width_tiles = ceil(num_tiles / height_tiles)``; require ``height_tiles ≤ width_tiles``.
    """
    if height_tiles < 1:
        raise ValueError("Tile row count (height) must be at least 1")
    if num_tiles < 1:
        raise ValueError("No tiles in data")
    w = (num_tiles + height_tiles - 1) // height_tiles
    if height_tiles > w:
        raise ValueError(
            f"Tile rows ({height_tiles}) exceed tile columns ({w}); require rows ≤ columns."
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
        else:
            data = raw
        if len(data) < per:
            raise ValueError(f"Tile strip too short: need at least {per} bytes, have {len(data)}")
        n = len(data) // per
        need = n * per
        return data[:need]

    need = tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles)
    if spec.lz:
        data = decompress_gba_lz77(raw)
    else:
        data = raw
    if len(data) < need:
        raise ValueError(f"Sprite tile data too short: need {need}, have {len(data)}")
    return data[:need]


def extract_tilemap_bytes(spec: GraphicsAnchorSpec, raw: bytes) -> bytes:
    if spec.kind != "tilemap":
        raise ValueError("not a tilemap spec")
    need = spec.map_w_tiles * spec.map_h_tiles * 2
    if spec.lz:
        data = decompress_gba_lz77(raw)
    else:
        data = raw
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
) -> Tuple[Optional[str], str]:
    """
    Decode a standalone graphics NamedAnchor (palette-only returns None PNG; sprite/tilemap return PNG path).

    For sprite anchors with ``palette_anchor_name`` in TOML, pass the resolved palette as
    ``external_palette_spec`` + ``external_palette_base_off`` (or both None for default palette).

    For **tilemap** (``ucm`` / ``lzm``), pass ``external_tileset_spec`` + ``external_tileset_base_off`` for the
    tile sheet anchor (``uct`` / ``lzt`` / ``ucs`` / ``lzs``), and optional external palette like sprites.

    For **sprites**, ``sprite_layout_height`` sets the number of **tile rows** (``H``); width is
    ``ceil(tile_count / H)``. If omitted, variable strips use one row; fixed formats use TOML ``WxH``.
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
            pal_bytes = palette_bytes_for_gbagfx(
                external_palette_spec, pal_bytes, sprite_bpp=spec.bpp
            )
        else:
            pal_bytes = bytes(128) if spec.bpp == 6 else bytes(32)

        per = sprite_bytes_per_tile(spec.bpp)
        nt = len(tiles) // per
        eff_spec = spec
        if sprite_layout_height is not None:
            try:
                w_t, h_t = compute_sprite_grid_layout(nt, int(sprite_layout_height))
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
) -> Tuple[Optional[str], str]:
    """
    Decode sprite from ROM at sprite_file_off using optional external palette anchor.
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
        if palette_spec is not None and palette_base_off is not None:
            praw = bytes(rom[palette_base_off : palette_base_off + min(len(rom) - palette_base_off, 1 << 20)])
            try:
                pal_bytes = extract_palette_bytes(palette_spec, praw)
            except ValueError as e:
                return None, f"External palette decode error: {e}\n"
            pal_bytes = palette_bytes_for_gbagfx(palette_spec, pal_bytes, sprite_bpp=spec.bpp)
        else:
            pal_bytes = bytes(128) if spec.bpp == 6 else bytes(32)

        per = sprite_bytes_per_tile(spec.bpp)
        nt = len(tiles) // per
        eff_spec = spec
        if sprite_layout_height is not None:
            try:
                w_t, h_t = compute_sprite_grid_layout(nt, int(sprite_layout_height))
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
