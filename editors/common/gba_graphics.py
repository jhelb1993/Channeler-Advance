"""
GBA graphics helpers: Nintendo-style LZ77 decompress and gbagfx (pret) invocation via WSL on Windows.
Palette formats: ucp4, lzp4, ucp4:HEX… (N digits → N×32 bytes), ucp8:N / lzp8:N (one hex digit, count×32).
Multi–4bpp (N>1): palette-only preview uses a 512-byte master (16×16 colors, 00 00 pad); 4bpp sprites use only
the first 32 bytes so gbagfx/libpng accept the PLTE. 8bpp-format palette anchors for 4bpp sprites are also trimmed to 32 bytes.
Sprite tile formats: ucs4xWxH / lzs4xWxH (and 8bpp variants), 8×8 tiles.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import tempfile
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Tuple

# Repo root: editors/common -> repo
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_MODULE_DIR, "..", ".."))
GBAGFX_PATH = os.path.join(_REPO_ROOT, "deps", "gbagfx")


def repo_gbagfx_path() -> str:
    return GBAGFX_PATH


def _windows_path_for_wsl_arg(win_path: str) -> str:
    """Normalize and use forward slashes.

    Passing ``C:\\Users\\...`` to ``wsl wslpath`` can drop backslashes (e.g. ``\\U`` in
    ``\\Users``), producing invalid paths like ``C:Users...``. WSL accepts ``C:/Users/...``.
    """
    p = os.path.normpath(os.path.abspath(win_path))
    if platform.system() == "Windows":
        return p.replace("\\", "/")
    return p


def _run_wslpath(win_path: str) -> Tuple[Optional[str], str]:
    """Convert a Windows path for WSL. Returns (linux_path_or_None, error_text_if_failed)."""
    path_arg = _windows_path_for_wsl_arg(win_path)
    cmd_list = ["wsl", "wslpath", "-a", path_arg]
    cmd_display = " ".join(cmd_list)
    try:
        r = subprocess.run(
            cmd_list,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except OSError as e:
        return None, f"{type(e).__name__}: {e}\ncommand: {cmd_display}"
    except subprocess.TimeoutExpired as e:
        return None, f"{type(e).__name__}: {e}\ncommand: {cmd_display}"

    out = (r.stdout or "").strip()
    err = (r.stderr or "").strip()
    if r.returncode != 0:
        parts = [f"wsl wslpath failed (exit {r.returncode})."]
        if out:
            parts.append(f"stdout:\n{out}")
        if err:
            parts.append(f"stderr:\n{err}")
        if not out and not err:
            parts.append("(no stdout or stderr from wslpath)")
        parts.append(f"command: {cmd_display}")
        return None, "\n".join(parts)
    if not out:
        return None, (
            "wslpath returned exit 0 but empty stdout.\n"
            f"stderr:\n{err or '(none)'}\n"
            f"command: {cmd_display}"
        )
    return out, ""


def run_gbagfx(
    argv: List[str],
    *,
    cwd: Optional[str] = None,
) -> Tuple[int, str, str]:
    """
    Run pret gbagfx. On Windows, invoke the Linux binary under WSL.
    ``argv`` is the argument list *after* the program name (e.g. ``["a.4bpp", "a.png", "-palette", "a.pal", "-mwidth", "4"]``).
    Paths may be Windows paths; they are converted for WSL as needed.
    Returns (returncode, stdout, stderr combined log string for UI).
    """
    exe = GBAGFX_PATH
    if not os.path.isfile(exe):
        return (
            127,
            "",
            f"gbagfx not found at {exe!r}. Place the Linux gbagfx binary at deps/gbagfx.\n",
        )

    cwd = cwd or os.getcwd()
    if platform.system() == "Windows":
        wsl_exe, wsl_err = _run_wslpath(exe)
        if not wsl_exe:
            return (1, "", wsl_err + "\n")
        wsl_args: List[str] = []
        for a in argv:
            if os.path.isabs(a) or (len(a) > 1 and a[1] == ":"):
                conv, conv_err = _run_wslpath(a)
                if not conv:
                    return (
                        1,
                        "",
                        f"wslpath failed for gbagfx argument {a!r}:\n{conv_err}\n",
                    )
                wsl_args.append(conv)
            else:
                wsl_args.append(a)
        cmd = ["wsl", wsl_exe] + wsl_args
    else:
        cmd = [exe] + argv

    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except OSError as e:
        return 1, "", f"Failed to run gbagfx: {e}\n"
    except subprocess.TimeoutExpired:
        return 1, "", "gbagfx timed out.\n"

    log_parts = []
    if proc.stdout:
        log_parts.append(f"stdout:\n{proc.stdout}")
    if proc.stderr:
        log_parts.append(f"stderr:\n{proc.stderr}")
    log = "\n".join(log_parts) if log_parts else "(no gbagfx output)\n"
    return proc.returncode, proc.stdout or "", log


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


def palette_byte_count_8_variant(hex_digit: str) -> int:
    """ucp8:/lzp8: — user spec: palette count is one hex digit 0–F, times 32 bytes."""
    n = int(hex_digit, 16)
    if n == 0:
        n = 1
    return n * 32


def tile_data_bytes(bpp: int, w_tiles: int, h_tiles: int) -> int:
    per_tile = 32 if bpp == 4 else 64
    return w_tiles * h_tiles * per_tile


def compute_graphics_rom_span(spec: GraphicsAnchorSpec, rom_len: int, base: int) -> int:
    """Conservative byte span in ROM from anchor start (for selection / hit-testing)."""
    rest = max(0, rom_len - base)
    if spec.kind == "palette":
        if spec.lz:
            return min(rest, 512 * 1024)
        if spec.bpp == 4:
            return min(rest, 32 * max(1, spec.palette_4_count))
        dig = spec.palette_hex_digit or "1"
        return min(rest, palette_byte_count_8_variant(dig))
    if spec.lz:
        return min(rest, 2 * 1024 * 1024)
    return min(rest, tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles))


@dataclass
class GraphicsAnchorSpec:
    kind: str  # "palette" | "sprite"
    bpp: int  # 4 or 8
    lz: bool
    # palette 4bpp: number of 32-byte GBA palettes (ucp4 = 1; ucp4:0F… = len(hex) palettes)
    palette_4_count: int = 1
    # palette 8bpp: ucp8:N / lzp8:N — one hex digit 0–F, byte length rule in palette_byte_count_8_variant
    palette_hex_digit: Optional[str] = None
    # sprite: tile dimensions
    width_tiles: int = 0
    height_tiles: int = 0
    # sprite (whole anchor or struct field): optional palette NamedAnchor name after |
    palette_anchor_name: Optional[str] = None


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

    # 8bpp palette: exactly one hex digit after colon (required)
    m = re.fullmatch(r"(uc|lz)p8:([0-9a-fA-F])", s, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        return GraphicsAnchorSpec(
            kind="palette",
            bpp=8,
            lz=lz,
            palette_hex_digit=m.group(2).upper(),
        )

    # 4bpp palette: optional :HEX… — each hex digit is one 32-byte sub-palette slot (e.g. 16 digits → 512 bytes)
    m = re.fullmatch(r"(uc|lz)p4(?::([0-9a-fA-F]+))?", s, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        suffix = m.group(2)
        count = len(suffix) if suffix else 1
        return GraphicsAnchorSpec(
            kind="palette",
            bpp=4,
            lz=lz,
            palette_4_count=count,
        )

    m = re.fullmatch(r"(uc|lz)s([48])x(\d+)x(\d+)", s, re.IGNORECASE)
    if m:
        lz = m.group(1).lower() == "lz"
        bpp = int(m.group(2))
        w, h = int(m.group(3)), int(m.group(4))
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

    m = re.fullmatch(r"(uc|lz)s([48])x(\d+)x(\d+)", spec_part, re.IGNORECASE)
    if not m:
        return None, pal_name
    lz = m.group(1).lower() == "lz"
    bpp = int(m.group(2))
    w, h = int(m.group(3)), int(m.group(4))
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
        need = 32 * max(1, spec.palette_4_count)
    else:
        assert spec.palette_hex_digit is not None
        need = palette_byte_count_8_variant(spec.palette_hex_digit)
    if len(data) < need:
        raise ValueError(f"Palette data too short: need {need}, have {len(data)}")
    return data[:need]


# Multi–4bpp-palette → single master palette for gbagfx: 16 hardware indices × 16 colors × 2 bytes.
GBA_4BPP_SUBPALETTE_BYTES = 32
GBA_4BPP_MASTER_INDEX_COUNT = 16
GBA_4BPP_MASTER_PALETTE_BYTES = GBA_4BPP_MASTER_INDEX_COUNT * GBA_4BPP_SUBPALETTE_BYTES  # 512


def normalize_4bpp_palette_for_gbagfx(pal_bytes: bytes, palette_4_count: int) -> bytes:
    """
    One 32-byte 4bpp palette is passed through unchanged.

    If the spec packs more than one sub-palette (N×32 bytes), build a fixed 16-index master palette:
    256 GBA colors (512 bytes). Copy each sub-palette into its slot; unused indices (when N < 16) or
    missing colors within a short slot are padded with 0x00, 0x00 per color. If N > 16, only the first
    16 sub-palettes are used.
    """
    if palette_4_count <= 1:
        return pal_bytes
    out = bytearray(GBA_4BPP_MASTER_PALETTE_BYTES)
    n_use = min(max(1, palette_4_count), GBA_4BPP_MASTER_INDEX_COUNT)
    for i in range(n_use):
        off = i * GBA_4BPP_SUBPALETTE_BYTES
        chunk = pal_bytes[off : off + GBA_4BPP_SUBPALETTE_BYTES]
        if len(chunk) >= GBA_4BPP_SUBPALETTE_BYTES:
            out[off : off + GBA_4BPP_SUBPALETTE_BYTES] = chunk
        else:
            out[off : off + len(chunk)] = chunk
            # remainder of this slot stays 0x00 per color pair
    return bytes(out)


def palette_bytes_for_gbagfx(
    spec: GraphicsAnchorSpec,
    pal_bytes: bytes,
    *,
    sprite_bpp: Optional[int] = None,
) -> bytes:
    """
    Bytes written to .gbapal before gbagfx.

    - Multi–4bpp palette anchors (N>1): for **palette-only** preview, expand to a 512-byte master. For **4bpp
      sprites**, use only the first 32 bytes (sub-palette 0); a 512-byte palette makes gbagfx/libpng fail with
      “Invalid palette length” on 4bpp PNG output.
    - When ``sprite_bpp`` is 4 and the palette anchor is 8bpp-format (``ucp8`` / ``lzp8``), trim to the first
      32 bytes.
    """
    if spec.kind == "palette" and spec.bpp == 4 and spec.palette_4_count > 1:
        if sprite_bpp == 4:
            pal_bytes = pal_bytes[:GBA_4BPP_SUBPALETTE_BYTES]
        else:
            pal_bytes = normalize_4bpp_palette_for_gbagfx(pal_bytes, spec.palette_4_count)
    if sprite_bpp == 4 and spec.kind == "palette" and spec.bpp == 8:
        pal_bytes = pal_bytes[:GBA_4BPP_SUBPALETTE_BYTES]
    return pal_bytes


def extract_sprite_bytes(spec: GraphicsAnchorSpec, raw: bytes) -> bytes:
    if spec.kind != "sprite":
        raise ValueError("not a sprite spec")
    need = tile_data_bytes(spec.bpp, spec.width_tiles, spec.height_tiles)
    if spec.lz:
        data = decompress_gba_lz77(raw)
    else:
        data = raw
    if len(data) < need:
        raise ValueError(f"Sprite tile data too short: need {need}, have {len(data)}")
    return data[:need]


def gbagfx_palette_pipeline(pal_bytes: bytes, work_dir: str, stem: str) -> Tuple[int, str, str]:
    """Write .gbapal, run gbagfx -> .pal (PNG palette for -palette flag)."""
    gbapal = os.path.join(work_dir, f"{stem}.gbapal")
    pal_out = os.path.join(work_dir, f"{stem}.pal")
    with open(gbapal, "wb") as f:
        f.write(pal_bytes)
    code, out, log = run_gbagfx([gbapal, pal_out], cwd=work_dir)
    return code, out, log


def gbagfx_sprite_pipeline(
    tile_bytes: bytes,
    bpp: int,
    mwidth: int,
    pal_path: str,
    work_dir: str,
    stem: str,
) -> Tuple[int, str, str, str]:
    """Write .4bpp or .8bpp, run gbagfx to PNG. Returns (code, stdout, log, png_path)."""
    ext = "4bpp" if bpp == 4 else "8bpp"
    bin_path = os.path.join(work_dir, f"{stem}.{ext}")
    png_path = os.path.join(work_dir, f"{stem}.png")
    with open(bin_path, "wb") as f:
        f.write(tile_bytes)
    argv = [
        bin_path,
        png_path,
        "-palette",
        pal_path,
        "-mwidth",
        str(mwidth),
    ]
    code, out, log = run_gbagfx(argv, cwd=work_dir)
    return code, out, log, png_path


def decode_palette_to_png_pal(
    rom: bytes,
    base_off: int,
    spec: GraphicsAnchorSpec,
) -> Tuple[Optional[str], str]:
    """
    Read palette from ROM at base_off, produce a .pal file via gbagfx in a temp directory.
    Returns (path to .pal or None, full log).
    """
    logs: List[str] = []
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
        code, _out, log = gbagfx_palette_pipeline(pal_bytes, td, "pal")
        logs.append(log)
        pal_path = os.path.join(td, "pal.pal")
        if code != 0 or not os.path.isfile(pal_path):
            return None, "".join(logs)
        # Keep temp dir alive: caller uses file; return path inside td (note: td leaked until exit)
        return pal_path, "".join(logs)
    except OSError as e:
        return None, f"{''.join(logs)}\nFilesystem error: {e}\n"


def decode_graphics_anchor_to_png(
    rom: bytes,
    base_off: int,
    spec: GraphicsAnchorSpec,
    *,
    external_palette_spec: Optional[GraphicsAnchorSpec] = None,
    external_palette_base_off: Optional[int] = None,
) -> Tuple[Optional[str], str]:
    """
    Decode a standalone graphics NamedAnchor (palette-only returns None PNG; sprite returns PNG path).
    For palette-only anchors, returns (None, log) — use decode_palette_to_png_pal for .pal preview.

    For sprite anchors with ``palette_anchor_name`` in TOML, pass the resolved palette as
    ``external_palette_spec`` + ``external_palette_base_off`` (or both None for default palette).
    """
    logs: List[str] = []
    if spec.kind == "palette":
        _pal, log = decode_palette_to_png_pal(rom, base_off, spec)
        logs.append(log)
        return None, "".join(logs)

    if base_off < 0 or base_off >= len(rom):
        return None, "Invalid ROM offset for sprite.\n"
    raw = bytes(rom[base_off : base_off + min(len(rom) - base_off, 4 << 20)])
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
            code, _o, log = gbagfx_palette_pipeline(pal_bytes, td, "ext")
            logs.append(log)
            pal_path = os.path.join(td, "ext.pal")
            if code != 0 or not os.path.isfile(pal_path):
                return None, "".join(logs)
        else:
            # Default 16-color palette if none (gbagfx still needs -palette)
            default_pal = bytes(32)
            code, _o, log = gbagfx_palette_pipeline(default_pal, td, "default")
            logs.append(log)
            pal_path = os.path.join(td, "default.pal")
            if code != 0 or not os.path.isfile(pal_path):
                return None, "".join(logs)

        code, _o, log2, png_path = gbagfx_sprite_pipeline(
            tiles,
            spec.bpp,
            spec.width_tiles,
            pal_path,
            td,
            stem,
        )
        logs.append(log2)
        if code != 0 or not os.path.isfile(png_path):
            return None, "".join(logs)
        return png_path, "".join(logs)
    except OSError as e:
        return None, f"{''.join(logs)}\nFilesystem error: {e}\n"


def decode_sprite_at_pointer(
    rom: bytes,
    sprite_file_off: int,
    spec: GraphicsAnchorSpec,
    palette_spec: Optional[GraphicsAnchorSpec],
    palette_base_off: Optional[int],
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
            code, _o, log = gbagfx_palette_pipeline(pal_bytes, td, "ext")
            logs.append(log)
            pal_path = os.path.join(td, "ext.pal")
            if code != 0 or not os.path.isfile(pal_path):
                return None, "".join(logs)
        else:
            default_pal = bytes(32)
            code, _o, log = gbagfx_palette_pipeline(default_pal, td, "default")
            logs.append(log)
            pal_path = os.path.join(td, "default.pal")
            if code != 0 or not os.path.isfile(pal_path):
                return None, "".join(logs)

        code, _o, log2, png_path = gbagfx_sprite_pipeline(
            tiles,
            spec.bpp,
            spec.width_tiles,
            pal_path,
            td,
            "sprite",
        )
        logs.append(log2)
        if code != 0 or not os.path.isfile(png_path):
            return None, "".join(logs)
        return png_path, "".join(logs)
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
