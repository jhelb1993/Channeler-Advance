"""
Shared hex editor for GBA ROM hacking.
Supports pointer detection (0x08/0x09), follow, incoming xref lists (.word vs BL), replace/insert mode, delete,
and context-menu **Repoint bytes** (move a selection to 0xFF free space and repoint .word / optional BL).
ASCII/PCS (Pokemon GBA) encoding for the character pane.
Optional Capstone disassembly (ARM7TDMI Thumb/ARM).
"""

import io
import logging
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from editors.common.channeler_script_api import format_run_header, run_user_script
from editors.common.gba_graphics import (
    GraphicsAnchorSpec,
    build_sprite_payload_for_rom,
    build_tilemap_payload_for_rom,
    compute_graphics_rom_span,
    decode_graphics_anchor_to_png,
    effective_ucp8_palette_hex_suffix,
    decode_palette_to_png_pal,
    decode_gba_palette32_to_rgb888,
    decode_sprite_at_pointer,
    extract_palette_bytes,
    extract_sprite_bytes,
    get_palette_4_slot_bytes,
    graphics_row_byte_size,
    max_sprite_height_tiles,
    measure_palette_rom_footprint,
    measure_sprite_rom_footprint,
    measure_tilemap_rom_footprint,
    palette_bytes_for_gbagfx,
    palette_import_gba_binary,
    palette_import_palette_file,
    palette_import_png,
    palette_payload_for_rom,
    parse_8bpp_palette_color_count,
    parse_graphics_anchor_format,
    parse_graphics_table_format,
    parse_sprite_field_spec,
    parse_tilemap_dimension_spec,
    palette_byte_count_for_spec,
    prepare_palette_rom_body_from_import,
    raw_gba_palette_to_rgb888_list,
    read_sprite_preview_palette_at_rom_offset,
    resolve_gba_pointer,
    rewrite_standalone_sprite_format_dimensions,
    rewrite_standalone_tilemap_format_dimensions,
    sprite_bytes_per_tile,
    sprite_import_png,
    sprite_import_png_manual,
    synthetic_palette_spec_for_sprite_import_write,
    tilemap_png_to_tileset_map_palette,
    toml_format_ucp8_from_8bpp_rom_colors,
    UCP8_PALETTE_4_CHUNK_HEX_DIGITS,
    validate_manual_palette_color_count,
)

_TOML_AVAILABLE = False
tomli = None  # type: ignore
try:
    import tomllib as _tomllib  # Python 3.11+
    tomli = _tomllib  # type: ignore
    _TOML_AVAILABLE = True
except ImportError:
    try:
        import tomli as _tomli
        tomli = _tomli  # type: ignore
        _TOML_AVAILABLE = True
    except ImportError:
        pass

_TOMLI_W_AVAILABLE = False
tomli_w = None  # type: ignore


def _try_import_tomli_w() -> bool:
    """Load ``tomli-w`` (retry after ``pip install`` without restarting the app)."""
    global _TOMLI_W_AVAILABLE, tomli_w
    try:
        import tomli_w as _tw

        tomli_w = _tw
        _TOMLI_W_AVAILABLE = True
        return True
    except ImportError:
        tomli_w = None  # type: ignore
        _TOMLI_W_AVAILABLE = False
        return False


_try_import_tomli_w()

_LOG_TILEMAP = logging.getLogger("channeler.tilemap_import")


def _tilemap_import_debug(logs: Optional[List[str]], label: str, **fields: Any) -> None:
    """Emit tilemap/palette import diagnostics to the logger and optionally the graphics decode log."""
    parts = " ".join(f"{k}={fields[k]!r}" for k in sorted(fields))
    msg = f"[debug] {label}: {parts}"
    _LOG_TILEMAP.debug(msg)
    if logs is not None:
        logs.append(msg + "\n")


def _tomli_w_missing_message() -> str:
    """User-facing hint when ``tomli-w`` is missing (often pip vs. runtime Python mismatch on Windows)."""
    exe = sys.executable
    return (
        "Writing TOML needs the ``tomli-w`` package in the same Python that runs this app.\n\n"
        f"This process is using:\n  {exe}\n\n"
        "Install into that interpreter (plain ``pip`` may target a different Python):\n"
        f'  "{exe}" -m pip install -U tomli-w\n\n'
        "Or install all deps from the repo root:\n"
        f'  "{exe}" -m pip install -r requirements.txt'
    )

_ANGR_AVAILABLE = False
try:
    import angr
    _ANGR_AVAILABLE = True
except ImportError:
    pass

_CAPSTONE_AVAILABLE = False
try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
    _CAPSTONE_AVAILABLE = True
except ImportError:
    ARM_OP_IMM = None  # type: ignore[misc, assignment]
    ARM_OP_MEM = None  # type: ignore[misc, assignment]
    ARM_REG_PC = None  # type: ignore[misc, assignment]

_PYGMENTS_AVAILABLE = False
try:
    from pygments import lex
    from pygments.lexers import get_lexer_by_name
    _PYGMENTS_AVAILABLE = True
except ImportError:
    pass

GBA_ROM_BASE = 0x08000000
GBA_ROM_MAX = 0x09FFFFFF  # addresses > this are not ROM code pointers; treat as code, not .word
# GBA cartridge header: 4-byte game code at 0xAC (e.g. ``BPRE`` = Pokémon FireRed US).
GBA_GAME_CODE_OFFSET = 0xAC


def rom_bytes_use_pokefirered_sym(data: Optional[bytes]) -> bool:
    """True when this ROM is Pokémon FireRed US (``BPRE``) — matches ``pokefirered.sym``."""
    if not data or len(data) < GBA_GAME_CODE_OFFSET + 4:
        return False
    return bytes(data[GBA_GAME_CODE_OFFSET : GBA_GAME_CODE_OFFSET + 4]) == b"BPRE"


def _channeler_repo_root() -> str:
    """Parent of ``editors/``; ``hex_editor.py`` is under ``editors/common/``."""
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _pokefirered_sym_default_path() -> str:
    return os.path.join(_channeler_repo_root(), "pokefirered.sym")


def _pokefirered_include_dir_default() -> str:
    return os.path.join(_channeler_repo_root(), "editors", "firered", "pokefirered", "include")


def _sym_type_priority(typ: str) -> int:
    """Higher wins when ``pokefirered.sym`` has duplicate addresses."""
    t = (typ or "").strip()
    if t in ("T", "t", "D", "d", "R", "r"):
        return 4
    if t in ("g", "G"):
        return 3
    if t in ("l", "L"):
        return 1
    return 2


def load_pokefirered_sym_norm_to_name(path: Optional[str] = None) -> Dict[int, str]:
    """Parse ``pokefirered.sym``: address field 0, symbol field 3 (0-based). Keys are ``addr & ~1``."""
    p = path or _pokefirered_sym_default_path()
    out: Dict[int, str] = {}
    pri: Dict[int, int] = {}
    if not os.path.isfile(p):
        return out
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "//" in line:
                line = line.split("//", 1)[0].strip()
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            stype = parts[1]
            name = parts[3]
            if not name or not re.match(r"^[A-Za-z_]\w*$", name):
                continue
            norm = addr & ~1
            pr = _sym_type_priority(stype)
            if norm not in out or pr >= pri.get(norm, 0):
                out[norm] = name
                pri[norm] = pr
    return out


def find_devkitarm_bin_dir() -> Optional[str]:
    """Directory containing ``arm-none-eabi-gcc``, or ``None`` / ``\"\"`` to use ``PATH``."""
    if sys.platform.startswith("win"):
        path_var = os.environ.get("Path") or os.environ.get("PATH") or ""
        for candidate in path_var.split(";"):
            if "devkitARM" in candidate and os.path.isdir(candidate):
                return candidate
        default = os.path.join("C:", os.sep, "devkitPro", "devkitARM", "bin")
        if os.path.isdir(default):
            return default
        return None
    return ""


def devkit_tool(name: str) -> str:
    """``arm-none-eabi-gcc`` etc.: full path on Windows when devkitARM is found."""
    d = find_devkitarm_bin_dir()
    if d:
        return os.path.join(d, name)
    return name


# Anchor browser: virtual folder for ``pokefirered.sym`` (segment must not contain ".")
ANCHOR_SYM_BROWSER_LABEL = "pokefirered.sym"
ANCHOR_SYM_BROWSER_SEGMENT = "sym"


def load_pokefirered_sym_name_to_addr(path: Optional[str] = None) -> Dict[str, int]:
    """Map symbol name -> address (field 0). On duplicate names, keep higher-priority ``g``/``l`` entry."""
    p = path or _pokefirered_sym_default_path()
    out: Dict[str, int] = {}
    pri: Dict[str, int] = {}
    if not os.path.isfile(p):
        return out
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "//" in line:
                line = line.split("//", 1)[0].strip()
            parts = line.split()
            if len(parts) < 4:
                continue
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            stype = parts[1]
            name = parts[3]
            if not name or not re.match(r"^[A-Za-z_]\w*$", name):
                continue
            if name.startswith(".") and name != ".":
                continue
            pr = _sym_type_priority(stype)
            if name not in out or pr >= pri.get(name, 0):
                out[name] = addr
                pri[name] = pr
    return out


def load_channeler_c_inject_rom_data_symbol_names() -> Set[str]:
    """Symbols in ROM that are data labels (even address); one name per line, ``#`` comments."""
    p = os.path.join(_channeler_repo_root(), "rom.txt")
    out: Set[str] = set()
    if not os.path.isfile(p):
        return out
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if not re.match(r"^[A-Za-z_]\w*$", line):
                continue
            out.add(line)
    return out


def link_defsym_value_for_rom_sym(addr: int, name: str, rom_data_names: Set[str]) -> int:
    """ROM Thumb code uses ``addr|1``; ROM data labels use even ``addr`` (see override file)."""
    if GBA_ROM_BASE <= addr <= GBA_ROM_MAX:
        if name in rom_data_names:
            return addr & ~1
        return addr | 1
    return addr


def collect_nm_undefined_symbols(nm_exe: str, obj_path: str) -> Tuple[List[str], str]:
    """Symbols marked ``U`` in ``nm -u`` output. On failure, second element is an error string."""
    try:
        r = subprocess.run(
            [nm_exe, "-u", obj_path],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as e:
        return [], str(e)
    if r.returncode != 0:
        return [], (r.stderr or r.stdout or "nm failed").strip()
    names: List[str] = []
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-2] == "U":
            names.append(parts[-1])
        elif len(parts) == 2 and parts[0] == "U":
            names.append(parts[1])
    return names, ""


# Offsets insert.py skips when scanning for repoint-all (vanilla CFRU compatibility).
_CFRU_REALPOINT_IGNORE_FILE_OFFS = {0x3986C0, 0x3986EC, 0xDABDF0}

C_INJECT_PATCHES_TEMPLATE = """### hooks
# Each line: function_name  hook_location  register
# function_name = injected symbol: channeler_inject / inject, any T/t symbol from last compile (nm on ELF), or pokefirered.sym name
# hook_location = GBA 0x08…… or file offset; register = 0–7 (ldr rN, [pc] / bx chain)
# Example (aligned hook site, 8 bytes):
# channeler_inject  0x08040000  0

### repointall
# Each line: target_symbol  sample_word_location
# Reads the 4-byte pointer at sample_word_location, then replaces every matching word in ROM with a pointer to target_symbol.
# sample_word_location: GBA or file offset of the word to read (not the value being matched).

### repoints
# Each line: target_symbol  word_location_to_overwrite
# Writes a 32-bit pointer (no +1) to the ROM word at word_location_to_overwrite.

### routinepointers
# Same as repoints, but the written pointer uses Thumb (+1) for a function address.
"""

CHANNELER_SCRIPT_TEMPLATE = """# In-tool script (Ctrl+Shift+Enter). API: ch / channeler
#  Why here: ch reads/writes the ROM open in this window (+ TOML); a .py on disk must reopen the .gba.
#  ch.log("msg")          — append to output pane
#  ch.toml                — copy of loaded TOML dict (FunctionAnchors / NamedAnchors / …)
#  ch.resolve("name")      — (file_offset|None, err) for Goto / NamedAnchor / ]count [[List]] name
#  ch.read_u32_le(off)     ch.write_bytes(off, bytes)
#  ch.label_for_gba(0x08001234)  — merged pokefirered.sym + TOML name, or None
#  ch.label_for_rom_pointer_word(w)  — word as symbol or hex
#  ch.classify_gba(addr)   — "rom" | "ewram" | "iwram" | "other"
#  ch.sym_name_to_addr()   full pokefirered.sym map
#  GBA_ROM_BASE, GBA_ROM_MAX, GBA_EWRAM_* … in namespace
#  hex_editor, gba_graphics — full modules; also common names at top level (parse_rom_file_offset, …)
#  Optional: from hex_editor import SomeSymbol  — works like normal Python

ch.log("Hello from Channeler script")
"""


def _gba_thumb_hook_write(data: bytearray, hook_file_off: int, dest_code_file_off: int, register: int) -> None:
    """Thumb ``ldr rN,[pc]; bx`` + pool word; matches CFRU ``Hook()`` (aligned hook uses 8 bytes)."""
    hook_at = hook_file_off
    if hook_at & 1:
        hook_at -= 1
    register &= 7
    if hook_at % 4:
        ins = bytes([0x01, 0x48 | register, 0x00 | (register << 3), 0x47, 0x0, 0x0])
    else:
        ins = bytes([0x00, 0x48 | register, 0x00 | (register << 3), 0x47])
    space = dest_code_file_off + 0x08000001
    ins += space.to_bytes(4, "little")
    for i, b in enumerate(ins):
        data[hook_at + i] = b


def _gba_repoint_word_write(
    data: bytearray, target_file_off: int, word_file_off: int, slide: int
) -> None:
    """``slide`` 0 = data pointer; 1 = Thumb function pointer (+1), CFRU ``Repoint(..., slide)``."""
    val = target_file_off + GBA_ROM_BASE + slide
    data[word_file_off : word_file_off + 4] = val.to_bytes(4, "little")


def _gba_real_repoint_all_scan(
    data: bytearray,
    sample_word_file_off: int,
    new_target_file_off: int,
    slide: int,
    skip_region: Optional[Tuple[int, int]],
    scan_limit: Optional[Tuple[int, int]] = None,
) -> int:
    """Replace every word equal to the sample pointer; optional skip_region is [start,end) insert blob.

    ``scan_limit`` if set is ``[lo, hi)`` file offsets: only scan aligned words in that half-open range
    (useful to repoint pointers only within a bank or region). Empty/unset = whole ROM.
    """
    old = int.from_bytes(data[sample_word_file_off : sample_word_file_off + 4], "little")
    new_val = new_target_file_off + GBA_ROM_BASE + slide
    n = 0
    end_insert = skip_region[1] if skip_region else -1
    start_insert = skip_region[0] if skip_region else -1
    if scan_limit:
        offset = scan_limit[0]
        while offset % 4:
            offset += 1
        lim = min(len(data) - 3, scan_limit[1])
    else:
        offset = 0
        lim = len(data) - 3
    while offset < lim:
        if offset in _CFRU_REALPOINT_IGNORE_FILE_OFFS:
            offset += 4
            continue
        if (
            skip_region
            and start_insert <= offset < end_insert
        ):
            offset = end_insert
            while offset % 4:
                offset += 1
            continue
        w = int.from_bytes(data[offset : offset + 4], "little")
        if w == old:
            data[offset : offset + 4] = new_val.to_bytes(4, "little")
            n += 1
        offset += 4
    return n


def parse_c_inject_patches_sections(text: str) -> Dict[str, List[str]]:
    """Split ``### hooks`` / ``### repointall`` / ``### repoints`` / ``### routinepointers`` blocks."""
    sections: Dict[str, List[str]] = {
        "hooks": [],
        "repointall": [],
        "repoints": [],
        "routinepointers": [],
    }
    current: Optional[str] = None
    for raw in text.splitlines():
        m = re.match(r"^\s*###\s*(\S+)\s*$", raw)
        if m:
            key = m.group(1).lower()
            current = key if key in sections else None
            continue
        if current is None:
            continue
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        sections[current].append(line)
    return sections


def parse_nm_elf_rom_text_symbols_to_file_offsets(nm_text: str) -> Dict[str, int]:
    """Parse ``arm-none-eabi-nm`` output on a linked ELF: map .text symbol names to ROM file offsets."""
    out: Dict[str, int] = {}
    for line in nm_text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym_type = parts[-2]
        if sym_type not in ("T", "t", "W", "w"):
            continue
        try:
            vma = int(parts[0], 16)
        except ValueError:
            continue
        name = parts[-1]
        if not (GBA_ROM_BASE <= vma <= GBA_ROM_MAX):
            continue
        out[name] = (vma - GBA_ROM_BASE) & ~1
    return out


GBA_EWRAM_START = 0x02000000
GBA_EWRAM_END = 0x0203FFFF
GBA_IWRAM_START = 0x03000000
GBA_IWRAM_END = 0x03007FFF
BYTES_PER_ROW = 16
# Hex pane text layout: "RRRRRRRR  " (10) + caret strip (16) + "  " (2) + hex pairs…
HEX_DISP_ADDR_END = 10
HEX_DISP_CARET_START = 10
HEX_DISP_CARET_END = 26  # exclusive
HEX_DISP_HEX_START = 28  # column index of first hex digit for byte 0
HEX_DIGITS = "0123456789ABCDEFabcdef"
# Goto box: letters/digits/dot/underscore (hex offsets + NamedAnchor names like data.header.title)
_GOTO_ALLOWED_CHARS = set(string.ascii_letters + string.digits + "._")


def _toml_sprite_format_token(lz: bool, bpp: int, w: int, h: int) -> str:
    p = "lz" if lz else "uc"
    return f"`{p}t{bpp}x{w}x{h}`"


def _toml_sprite_format_token_with_palette(
    lz: bool, bpp: int, w: int, h: int, palette_anchor: str
) -> str:
    """Sprite Format with optional ``|paletteNamedAnchor`` tail (same as Tools / vanilla TOML)."""
    p = "lz" if lz else "uc"
    inner = f"{p}t{bpp}x{w}x{h}"
    pa = normalize_named_anchor_lookup_key(palette_anchor) if (palette_anchor or "").strip() else ""
    if pa:
        return f"`{inner}|{pa}`"
    return f"`{inner}`"


def _toml_tilemap_format_token(lz: bool, bpp: int, mw: int, mh: int, tileset_name: str) -> str:
    p = "lz" if lz else "uc"
    ts = tileset_name.strip()
    if ts:
        return f"`{p}m{bpp}x{mw}x{mh}|{ts}`"
    return f"`{p}m{bpp}x{mw}x{mh}`"


def _toml_palette_format_for_tilemap_bpp(bpp: int, rom_colors_8bpp: Optional[int] = None) -> str:
    if bpp == 4:
        return "`ucp4`"
    if bpp == 6:
        return f"`ucp8:{UCP8_PALETTE_4_CHUNK_HEX_DIGITS}`"
    nc = rom_colors_8bpp if rom_colors_8bpp is not None else 256
    return toml_format_ucp8_from_8bpp_rom_colors(nc)


_GFX_COMBO_DISPLAY_SEP = "  —  "


def _graphics_anchor_combo_display(info: Dict[str, Any]) -> str:
    """Tools → Graphics combobox label; table anchors show row count + [[List]] index table."""
    name = str(info.get("name", ""))
    if not info.get("graphics_table"):
        return name
    ref = str(info.get("table_count_ref") or "").strip()
    n = int(info.get("table_num_entries") or 0)
    spec = info.get("spec")
    if spec is not None and getattr(spec, "kind", None) == "palette":
        if ref:
            return (
                f"{name}{_GFX_COMBO_DISPLAY_SEP}"
                f"{n} palette rows (each [ucp8…] blob), index from [[List]] {ref}"
            )
        return f"{name}{_GFX_COMBO_DISPLAY_SEP}palette table ({n} rows)"
    if ref:
        return f"{name}{_GFX_COMBO_DISPLAY_SEP}{n} rows via {ref}"
    return f"{name}{_GFX_COMBO_DISPLAY_SEP}graphics table ({n} rows)"


def _graphics_combo_entry_to_anchor_name(entry: str) -> str:
    """Strip combobox description suffix so lookups use the real NamedAnchor Name."""
    t = (entry or "").strip()
    if _GFX_COMBO_DISPLAY_SEP in t:
        return t.split(_GFX_COMBO_DISPLAY_SEP, 1)[0].strip()
    return t


def _sign_extend_uint(v: int, bits: int) -> int:
    """Sign-extend ``bits``-bit value ``v`` to a signed 32-bit integer."""
    v &= (1 << bits) - 1
    if v & (1 << (bits - 1)):
        v -= 1 << bits
    return v


def thumb2_bl_immediate_target_gba(hw1: int, hw2: int, bl_instruction_addr: int) -> Optional[int]:
    """
    If (hw1, hw2) is a Thumb-2 ``BL`` immediate encoding, return the absolute GBA branch target.

    ``bl_instruction_addr`` is the byte address of the **first** halfword of the 32-bit instruction
    (must be 2-byte aligned). Uses ARM-Thumb PC rule: ``PC = address_of_BL + 4``.

    This matches ROM scanning better than linear Capstone disassembly, which desynchronizes on data.
    """
    if ((hw1 >> 11) & 0x1F) != 0x1E:  # 11110
        return None
    if ((hw2 >> 11) & 0x1F) != 0x1F:  # 11111
        return None
    S = (hw1 >> 10) & 1
    imm10 = hw1 & 0x3FF
    J1 = (hw2 >> 13) & 1
    J2 = (hw2 >> 11) & 1
    imm11 = hw2 & 0x7FF
    I1 = (~(J1 ^ S)) & 1
    I2 = (~(J2 ^ S)) & 1
    imm25 = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    imm32 = _sign_extend_uint(imm25, 25)
    # Thumb BL: branch address = PC + imm32, PC = Addr(BL) + 4
    tgt = (bl_instruction_addr + 4 + imm32) & 0xFFFFFFFF
    return tgt


def thumb2_bl_encode(bl_addr: int, target_gba: int) -> Optional[Tuple[int, int]]:
    """
    Encode a Thumb-2 ``BL`` at ``bl_addr`` (byte address of first halfword) branching to ``target_gba``.

    Returns ``(hw1, hw2)`` halfwords or ``None`` if the branch is out of range (Thumb ``BL`` is ±4 MiB).
    """
    imm32 = (target_gba - bl_addr - 4) & 0xFFFFFFFF
    if imm32 & 0x80000000:
        imm32 -= 0x100000000
    # ±4 MiB (same practical limit as ``-mlong-calls`` / linker errors for BL).
    if imm32 < -0x400000 or imm32 >= 0x400000:
        return None
    imm25 = imm32 & 0x1FFFFFF
    S = (imm25 >> 24) & 1
    I1 = (imm25 >> 23) & 1
    I2 = (imm25 >> 22) & 1
    imm10 = (imm25 >> 12) & 0x3FF
    imm11 = (imm25 >> 1) & 0x7FF
    J1 = (~(I1 ^ S)) & 1
    J2 = (~(I2 ^ S)) & 1
    hw1 = 0xF000 | (S << 10) | imm10
    hw2 = 0xF800 | (J1 << 13) | (J2 << 11) | imm11
    if thumb2_bl_immediate_target_gba(hw1, hw2, bl_addr) != (target_gba & 0xFFFFFFFF):
        return None
    return hw1, hw2


def _repoint_rom_for_moved_byte_range(
    rom: bytearray,
    src_lo: int,
    src_hi: int,
    new_lo: int,
    *,
    include_bl: bool,
    fill_old: bool = True,
) -> Tuple[int, int, List[str]]:
    """
    Data in ``[src_lo, src_hi)`` has been logically moved to ``[new_lo, new_lo + (src_hi - src_lo))``.

    - Every word-aligned ROM pointer (0x08…… / 0x09……) whose target file offset lies in
      ``[src_lo, src_hi)`` is adjusted by ``(new_lo - src_lo)``.
    - If ``include_bl``, every Thumb-2 ``BL`` whose target lies in that range is re-encoded to the new target.

    Then the patched bytes from ``[src_lo, src_hi)`` are copied to ``new_lo``. If ``fill_old`` is true,
    ``[src_lo, src_hi)`` is filled with ``0xFF`` (reclaim as free space).

    Returns ``(n_word_patches, n_bl_patches, bl_error_messages)``.
    """
    bl_errors: List[str] = []
    if src_lo < 0 or src_hi <= src_lo or new_lo < 0:
        return 0, 0, ["Invalid range."]
    length = src_hi - src_lo
    if new_lo + length > len(rom):
        return 0, 0, ["Destination range extends past end of ROM."]
    excl_lo, excl_hi = src_lo, src_hi
    if not (new_lo + length <= excl_lo or new_lo >= excl_hi):
        return 0, 0, ["Destination overlaps the original range; pick a disjoint offset."]
    delta = new_lo - src_lo
    n_word = 0
    n_bl = 0

    for off in range(0, len(rom) - 3, 4):
        ptr = int.from_bytes(rom[off : off + 4], "little")
        if (ptr >> 24) not in (0x08, 0x09):
            continue
        tgt_fo = ptr - GBA_ROM_BASE
        if src_lo <= tgt_fo < src_hi:
            new_ptr = (ptr + delta) & 0xFFFFFFFF
            rom[off : off + 4] = new_ptr.to_bytes(4, "little")
            n_word += 1

    if include_bl:
        for off in range(0, len(rom) - 3, 2):
            hw1 = rom[off] | (rom[off + 1] << 8)
            hw2 = rom[off + 2] | (rom[off + 3] << 8)
            bl_gba = GBA_ROM_BASE + off
            tgt_gba = thumb2_bl_immediate_target_gba(hw1, hw2, bl_gba)
            if tgt_gba is None:
                continue
            if not (GBA_ROM_BASE <= tgt_gba <= GBA_ROM_MAX):
                continue
            tgt_fo = tgt_gba - GBA_ROM_BASE
            if not (src_lo <= tgt_fo < src_hi):
                continue
            new_tgt = (tgt_gba + delta) & 0xFFFFFFFF
            enc = thumb2_bl_encode(bl_gba, new_tgt)
            if enc is None:
                bl_errors.append(
                    f"file 0x{off:08X} (GBA 0x{bl_gba:08X}): BL cannot reach new target "
                    f"0x{new_tgt:08X} (Thumb BL range is ±4 MiB from the instruction)."
                )
                continue
            hw1n, hw2n = enc
            rom[off] = hw1n & 0xFF
            rom[off + 1] = (hw1n >> 8) & 0xFF
            rom[off + 2] = hw2n & 0xFF
            rom[off + 3] = (hw2n >> 8) & 0xFF
            n_bl += 1

    rom[new_lo : new_lo + length] = rom[src_lo:src_hi]
    if fill_old:
        for i in range(src_lo, src_hi):
            rom[i] = 0xFF

    return n_word, n_bl, bl_errors


def _toml_named_anchor_address_hex_string(file_offset: int) -> str:
    """Format a ROM **file** offset for ``[[NamedAnchors]].Address`` (``0x…`` hex, no ``0x08`` GBA prefix)."""
    fo = int(file_offset)
    if fo < 0:
        raise ValueError("ROM file offset must be non-negative")
    return f"0x{fo:X}"


def _toml_address_value_to_file_offset(addr: Any) -> Optional[int]:
    """Parse a TOML ``Address`` field (int or hex string) to ROM **file** offset (same rules as repoint / anchors)."""
    if addr is None:
        return None
    try:
        gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr).strip(), 0)
    except (ValueError, TypeError):
        return None
    if gba < GBA_ROM_BASE:
        gba += GBA_ROM_BASE
    return gba - GBA_ROM_BASE


def _normalize_toml_address_fields_to_hex_strings(toml_data: Dict[str, Any]) -> None:
    """Normalize ``Address`` on anchor-like tables to canonical ``0x…`` string form before writing TOML."""
    for key in ("NamedAnchors", "MatchedWords", "FunctionAnchors"):
        rows = toml_data.get(key)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            addr = row.get("Address")
            if addr is None:
                continue
            fo = _toml_address_value_to_file_offset(addr)
            if fo is None or fo < 0:
                continue
            row["Address"] = _toml_named_anchor_address_hex_string(fo)


def _toml_text_unquote_address_hex_literals(text: str) -> str:
    """Turn ``Address = \"0x…\"`` into ``Address = 0x…`` (valid TOML hex integers, no quotes)."""
    return re.sub(
        r'^(\s*)Address\s*=\s*"0x([0-9A-Fa-f]+)"\s*$',
        r"\1Address = 0x\2",
        text,
        flags=re.MULTILINE,
    )


def _toml_coerce_mapping_keys_to_str(obj: Any) -> Any:
    """Deep copy for writing: ``tomli_w`` requires ``str`` keys; ``tomli`` may load ``[[List]]`` indices as ``int``."""
    if isinstance(obj, dict):
        return {
            (k if isinstance(k, str) else str(k)): _toml_coerce_mapping_keys_to_str(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_toml_coerce_mapping_keys_to_str(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(_toml_coerce_mapping_keys_to_str(x) for x in obj)
    return obj


def _write_toml_file_unquoted_hex_addresses(toml_path: str, toml_data: Dict[str, Any]) -> None:
    """Write structure TOML: normalize addresses, ``tomli_w.dump``, then unquote hex ``Address`` lines."""
    _normalize_toml_address_fields_to_hex_strings(toml_data)
    safe_for_write = _toml_coerce_mapping_keys_to_str(toml_data)
    bio = io.BytesIO()
    tomli_w.dump(safe_for_write, bio)
    out = _toml_text_unquote_address_hex_literals(bio.getvalue().decode("utf-8"))
    with open(toml_path, "wb") as f:
        f.write(out.encode("utf-8"))


def _strip_outer_backticks(s: str) -> str:
    t = s.strip()
    while len(t) >= 2 and t[0] == "`" and t[-1] == "`":
        t = t[1:-1].strip()
    return t


def _struct_count_ref_base_name(count_ref: str) -> str:
    """Strip a single trailing ``±N`` from a ``]count`` token (same base step as :meth:`HexEditorFrame._resolve_struct_count`)."""
    s = str(count_ref).strip()
    m = re.match(r"^(.+?)([+-]\d+)$", s)
    if m:
        return m.group(1).strip()
    return s


def _struct_anchor_search_blob(a: Dict[str, Any], lists_map: Dict[str, Dict[int, str]]) -> str:
    """Lowercase text used to filter struct anchors by search query (name, ``]count`` ref, ``[[List]]`` rows, PCS name)."""
    parts: List[str] = [str(a.get("name", ""))]
    cr = a.get("count_ref")
    if cr:
        parts.append(str(cr))
    list_keys: List[str] = []
    elk = normalize_named_anchor_lookup_key(str(a.get("entry_label_list") or ""))
    if elk:
        list_keys.append(elk)
    if cr:
        cref = normalize_named_anchor_lookup_key(_struct_count_ref_base_name(str(cr)))
        if cref and cref not in list_keys:
            list_keys.append(cref)
    for lk in list_keys:
        parts.append(lk)
        lm = lists_map.get(lk) or {}
        for idx in sorted(lm.keys()):
            parts.append(str(lm[idx]))
    pcs = a.get("entry_label_pcs")
    if pcs:
        parts.append(str(pcs.get("name", "")))
    return "\n".join(parts).lower()


def normalize_named_anchor_lookup_key(s: str) -> str:
    """
    Normalize a NamedAnchor ``Name`` from TOML or from user input so comparisons succeed.

    Strips whitespace, straight/curly quotes, and balanced outer backticks (users often paste
    `` `graphics.foo` `` or typographic quotes from docs).
    """
    t = str(s or "").strip()
    t = t.replace("\u2018", "'").replace("\u2019", "'").replace("\u201c", '"').replace("\u201d", '"')
    t = t.strip("'\"").strip()
    t = _strip_outer_backticks(t)
    return t.strip()


def _named_anchor_row_name_field(anchor: Dict[str, Any]) -> str:
    """Return the anchor's logical name; supports ``Name`` or lowercase ``name``."""
    v = anchor.get("Name")
    if v is None:
        v = anchor.get("name")
    return normalize_named_anchor_lookup_key(str(v or ""))


def _normalize_loaded_toml_document(data: Dict[str, Any]) -> None:
    """Drop deprecated top-level sections so they are not written back by tomli-w."""
    data.pop("OffsetPointer", None)


# Pokemon GBA (PCS) character set - byte to display char. Based on HexManiacAdvance PCSString.
# https://github.com/haven1433/HexManiacAdvance/blob/master/src/HexManiac.Core/Models/PCSString.cs
_PCS_BYTE_TO_CHAR: Dict[int, str] = {}


def _fill_pcs(chars: str, start: int) -> None:
    for i, c in enumerate(chars):
        _PCS_BYTE_TO_CHAR[start + i] = c


def _init_pcs() -> None:
    if _PCS_BYTE_TO_CHAR:
        return
    _PCS_BYTE_TO_CHAR[0x00] = " "
    _fill_pcs("ÀÁÂÇÈÉÊËÌÎÏ", 0x01)
    _fill_pcs("ÒÓÔŒÙÚÛÑßàá", 0x0B)
    _fill_pcs("çèéêëìîïòóôœùúûñºª", 0x10)
    _PCS_BYTE_TO_CHAR[0x2C] = "·"  # \e
    _PCS_BYTE_TO_CHAR[0x2D] = "&"
    _PCS_BYTE_TO_CHAR[0x2E] = "+"   # \+
    _fill_pcs("Lv=;", 0x34)  # \Lv = ;
    for i in range(0x38, 0x48):
        if i not in _PCS_BYTE_TO_CHAR:
            _PCS_BYTE_TO_CHAR[i] = "·"
    _PCS_BYTE_TO_CHAR[0x48] = "·"  # \r
    for i in range(0x49, 0x51):
        if i not in _PCS_BYTE_TO_CHAR:
            _PCS_BYTE_TO_CHAR[i] = "·"
    _fill_pcs("¿¡PmPKBLoCÍ", 0x51)  # \pk \mn \Po \Ke \Bl \Lo \Ck Í (10 chars)
    _fill_pcs("%()", 0x5B)
    for i in range(0x5E, 0x68):
        if i not in _PCS_BYTE_TO_CHAR:
            _PCS_BYTE_TO_CHAR[i] = "·"
    _PCS_BYTE_TO_CHAR[0x68] = "â"
    for i in range(0x69, 0x6F):
        if i not in _PCS_BYTE_TO_CHAR:
            _PCS_BYTE_TO_CHAR[i] = "·"
    _PCS_BYTE_TO_CHAR[0x6F] = "í"
    _fill_pcs("↑↓←→", 0x79)  # \au \ad \al \ar
    for i in range(0x7D, 0x84):
        if i not in _PCS_BYTE_TO_CHAR:
            _PCS_BYTE_TO_CHAR[i] = "·"
    _PCS_BYTE_TO_CHAR[0x84] = "·"  # \d
    _fill_pcs("<>", 0x85)  # \< \>
    for i in range(0x87, 0xA1):
        if i not in _PCS_BYTE_TO_CHAR:
            _PCS_BYTE_TO_CHAR[i] = "·"
    _fill_pcs("0123456789", 0xA1)
    _fill_pcs("!?.-·'°$,*//", 0xAB)  # \. \qo \qc \sm \sf
    _fill_pcs("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 0xBB)
    _fill_pcs("abcdefghijklmnopqrstuvwxyz", 0xD5)
    for i in range(0xEF, 0xF0):
        if i not in _PCS_BYTE_TO_CHAR:
            _PCS_BYTE_TO_CHAR[i] = "·"
    _fill_pcs(":ÄÖÜäöü", 0xF0)
    _PCS_BYTE_TO_CHAR[0xF7] = "·"  # \?
    _PCS_BYTE_TO_CHAR[0xF8] = "·"  # \btn
    _PCS_BYTE_TO_CHAR[0xF9] = "·"  # \9
    _PCS_BYTE_TO_CHAR[0xFA] = "\u00B6"  # \l (¶ pilcrow)
    _PCS_BYTE_TO_CHAR[0xFB] = "\u00B6"  # \pn
    _PCS_BYTE_TO_CHAR[0xFC] = "·"  # \CC
    _PCS_BYTE_TO_CHAR[0xFD] = "\\"  # \\
    _PCS_BYTE_TO_CHAR[0xFE] = "\u00B6"  # \n (¶)
    _PCS_BYTE_TO_CHAR[0xFF] = '"'
    for i in range(0x100):
        if i not in _PCS_BYTE_TO_CHAR:
            _PCS_BYTE_TO_CHAR[i] = "·"


# Reverse map for typing: display char -> PCS byte (lowest byte wins for duplicates)
_PCS_CHAR_TO_BYTE: Dict[str, int] = {}


def _init_pcs_reverse() -> None:
    if _PCS_CHAR_TO_BYTE:
        return
    for b in range(0x100):
        c = _PCS_BYTE_TO_CHAR.get(b, "·")
        if c not in _PCS_CHAR_TO_BYTE:
            _PCS_CHAR_TO_BYTE[c] = b


_init_pcs()
_init_pcs_reverse()


def encode_pcs_string(text: str, width: int) -> bytearray:
    """Encode text to PCS bytes, terminated by 0xFF, padded to width with 0x00."""
    out = bytearray()
    for c in text:
        b = _PCS_CHAR_TO_BYTE.get(c)
        if b is not None:
            out.append(b)
    out.append(0xFF)
    while len(out) < width:
        out.append(0x00)
    return out[:width]


def encode_ascii_slot(text: str, width: int) -> bytearray:
    """Fixed-width Latin-1 / raw-byte slot: encode text, pad with 0x00 (NUL). Same width role as PCS ``name""N``."""
    raw = text.encode("latin-1", errors="replace")
    if len(raw) > width:
        raw = raw[:width]
    out = bytearray(raw)
    while len(out) < width:
        out.append(0x00)
    return out[:width]


def _normalize_offset_angle_open_bracket_before_ydk(t: str) -> str:
    """Insert ``[`` after ``offset<`` when a `` `ydk` `` deck inner omits it.

    Valid nested-array form is ``offset<[`ydk`Anchor[card:List]…``; TOML often has ``offset<`ydk`…`` with no
    ``[`` between ``<`` and the backticks, which breaks bracket matching for the outer struct."""
    return re.sub(r"offset<(?!\[)\s*(`ydk`)", r"offset<[\1", str(t or ""), flags=re.IGNORECASE)


def _normalize_offset_inner_card_before_count_slash(t: str) -> str:
    """Insert missing ``]`` before ``/countField>`` after ``[card:List]`` inside ``offset<[`…``.

    Writers often use ``…[card:List]/length>``; the bracket that closes the ``offset<[`` slice must appear
    **before** ``/length>``, i.e. ``…[card:List]]/length>``."""
    return re.sub(
        r"(\[card\s*:\s*[\w.]+\s*\])\s*/(\w+)>",
        r"\1]/\2>",
        str(t or ""),
        flags=re.IGNORECASE,
    )


def _normalize_nested_array_slash_count_bracket_order(t: str) -> str:
    """Fix mistaken ``…]/countField>]`` when the ``]`` that should close ``name<[`` was written *after* ``/countField>``.

    Correct form is ``…]/countField>``. A common typo is ``[inner[card:x]/length>]`` (one ``]`` short before
    ``/length>``); normalize to ``[inner[card:x]]/length>`` by rewriting the tail ``]/count>`` + extra ``]``.
    """
    return re.sub(r"(\])(/(\w+)>\s*\])", r"\1]/\3>", str(t or ""))


def _normalize_ydk_deck_struct_shorthand_format(t: str) -> str:
    """Expand minimal `` `ydk` `` deck lines so :func:`_parse_struct_fields` accepts them.

    * `` `ydk`anchor[card:List]N`` (no outer brackets) — common in TOML; struct loader requires ``[…]N``.
    * ``[`ydk`anchor[card:List]!HEX>]N`` — same idea with an explicit ``!`` terminator hex (ignored for layout).

    Both normalize to ``[card:List]N``: **N** rows of **u16** ``card`` slots with the given ``[[List]]`` enum — the
    password table name stays only in the **raw** Format (for YDK import / password lookup), not in this expansion.

    For a pointer-based deck blob (``offset<… main: …``), write the full ``offset<…>`` form in TOML instead of this shorthand.
    """
    s = str(t or "").strip()
    if not s:
        return s
    m_wrapped = re.match(
        r"^\[\s*`ydk`([\w.]+)\s*\[\s*card\s*:\s*([\w.]+)\s*\]\s*!([0-9a-fA-F]{2,})\s*>\s*\]\s*(\d+)\s*$",
        s,
        re.IGNORECASE,
    )
    if m_wrapped:
        lst, cnt = m_wrapped.group(2), m_wrapped.group(4)
        return f"[card:{lst}]{cnt}"
    m_bare = re.match(
        r"^\s*`ydk`([\w.]+)\s*\[\s*card\s*:\s*([\w.]+)\s*\]\s*(\d+)\s*$",
        s,
        re.IGNORECASE,
    )
    if m_bare:
        lst, cnt = m_bare.group(2), m_bare.group(3)
        return f"[card:{lst}]{cnt}"
    return s


def _normalize_shorthand_bracket_terminator_format(s: str) -> str:
    """
    Expand legacy ``[fields]!HEX`` where ``!HEX`` starts the ``!``-terminated nested blob (not ``]count``).

    Example: ``[rate:]!0000`` → ``[rows<[rate:]!0000>inline]1`` (one packed terminator table at ``Address``).
    """
    t = str(s or "").strip()
    prefix = ""
    if t.startswith("^"):
        prefix = "^"
        t = t[1:].strip()
    t = _normalize_offset_angle_open_bracket_before_ydk(t)
    t = _normalize_offset_inner_card_before_count_slash(t)
    t = _normalize_nested_array_slash_count_bracket_order(t)
    t = _normalize_ydk_deck_struct_shorthand_format(t)
    if "<[" in t and "!>" in t:
        return prefix + t
    m = re.match(r"^\[([^\[\]]*)\]!([0-9a-fA-F]{2,})(?:\](\d+))?\s*$", t)
    if not m:
        return prefix + t
    inner = (m.group(1) or "").strip()
    hx = m.group(2)
    count = m.group(3) if m.group(3) else "1"
    if not inner:
        return prefix + t
    inner_one = inner
    if not re.search(r"[.:]$", inner_one):
        inner_one = inner_one + "."
    nested = f"rows<[{inner_one}]!{hx}>inline"
    return f"{prefix}[{nested}]{count}"


def _strip_trailing_ydk_struct_format_tag(t: str) -> str:
    """Drop trailing `` `ydk`Anchor`` after ``]rowCount`` so the struct parses while :func:`_struct_format_has_ydk_import_marker` still sees it in *fmt_raw*."""
    s = str(t or "").strip()
    m = re.match(r"^(.+?\]\s*[^\s\[\]]+)\s+(`ydk`[\w.]*)\s*$", s, re.DOTALL)
    if m:
        return m.group(1).strip()
    return s


def normalize_named_anchor_format(raw: Any) -> str:
    """Whitespace-strip; expand ``[…]!HEX`` terminator shorthand and minimal `` `ydk` `` deck lines for struct NamedAnchors."""
    t = _normalize_shorthand_bracket_terminator_format(str(raw or "").strip())
    return _strip_trailing_ydk_struct_format_tag(t)


def decode_ascii_slot(raw: bytes) -> str:
    """Display bytes for an ASCII slot: C-string style up to first 0x00, else full width."""
    end = raw.find(b"\x00")
    if end < 0:
        end = len(raw)
    return raw[:end].decode("latin-1", errors="replace")


def pcs_encoded_payload_length(text: str) -> int:
    """Byte length of PCS encoding: mapped code units + 0xFF terminator (matches :func:`encode_pcs_string`)."""
    n = 0
    for c in text:
        if _PCS_CHAR_TO_BYTE.get(c) is not None:
            n += 1
    return n + 1


def measure_pcs_rom_slot_capacity(data: Any, off: int, max_scan: int = 8192) -> int:
    """Contiguous bytes at ``off`` usable for one PCS string: body through first 0xFF, then trailing 0xFF padding."""
    n = len(data)
    if off < 0 or off >= n:
        return 0
    end = min(n, off + max_scan)
    i = off
    while i < end:
        if data[i] == 0xFF:
            i += 1
            break
        i += 1
    else:
        return end - off
    while i < end and data[i] == 0xFF:
        i += 1
    return i - off


def find_disjoint_ff_gap_start(
    data: Any,
    need: int,
    excl_lo: int,
    excl_hi: int,
    *,
    window_lo: Optional[int] = None,
    window_hi: Optional[int] = None,
) -> Optional[int]:
    """First file offset ``s`` where ``data[s:s+need]`` are all ``0xFF`` and ``[s, s+need)`` is disjoint from ``[excl_lo, excl_hi)``.

    If ``window_lo`` / ``window_hi`` are set, only consider ``s`` such that ``[s, s+need)`` lies inside
    the half-open range ``[window_lo, window_hi)`` (clamped to ``[0, len(data))``).
    """
    if need <= 0:
        return None
    n = len(data)
    lo = 0 if window_lo is None else max(0, min(n, window_lo))
    hi_bound = n if window_hi is None else max(0, min(n, window_hi))
    if lo >= hi_bound or hi_bound - lo < need:
        return None
    i = lo
    while i < hi_bound:
        if data[i] != 0xFF:
            i += 1
            continue
        run_start = i
        while run_start > 0 and data[run_start - 1] == 0xFF:
            run_start -= 1
        j = i
        while j < n and data[j] == 0xFF:
            j += 1
        run_end = j
        seg_lo = max(run_start, lo)
        seg_hi = min(run_end, hi_bound)
        if seg_hi - seg_lo < need:
            i = j
            continue
        last_start = seg_hi - need
        for s in range(seg_lo, last_start + 1):
            seg_end = s + need
            if seg_end <= excl_lo or s >= excl_hi:
                return s
        i = j
    return None


def parse_ff_gap_search_window_strings(
    data: Any, fs: str, ts: str
) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """Parse FF-gap search range from two strings (same rules as StructEditor ``_parse_ff_gap_search_window``)."""
    if not data:
        return None, None, "No ROM loaded."
    n = len(data)
    fs, ts = fs.strip(), ts.strip()
    if not fs and not ts:
        return None, None, None
    if (fs and not ts) or (not fs and ts):
        return (
            None,
            None,
            'Enter both “from” and “to”, or leave both empty to search the entire ROM.',
        )
    try:
        lo = int(fs, 0)
        hi = int(ts, 0)
    except ValueError:
        return None, None, "Invalid offset (use decimal or 0x hex)."
    if GBA_ROM_BASE <= lo <= GBA_ROM_MAX:
        lo -= GBA_ROM_BASE
    if GBA_ROM_BASE <= hi <= GBA_ROM_MAX:
        hi -= GBA_ROM_BASE
    if lo < 0 or hi >= n:
        return None, None, f"Offsets must lie within the ROM file (0 … 0x{n - 1:X})."
    if hi < lo:
        return None, None, "End offset must be ≥ start offset."
    return lo, hi + 1, None


def _pad_graphic_slot(payload: bytes, cap: int) -> bytes:
    """Pad with ``0xFF`` so the written region exactly fills ``cap`` bytes (``cap`` ≥ ``len(payload)``)."""
    if len(payload) > cap:
        return payload
    return payload + bytes([0xFF]) * (cap - len(payload))


def _apply_word_aligned_pointer_patch(
    rom: bytearray,
    old_gba: int,
    new_gba: int,
    *,
    exclude_ranges: Optional[List[Tuple[int, int]]] = None,
) -> int:
    """
    Replace every **word-aligned** (4-byte) little-endian ``u32`` equal to ``old_gba`` with ``new_gba``.

    ``exclude_ranges`` are half-open ``[lo, hi)`` file offsets skipped (e.g. old/new graphics blobs) so embedded
    bytes are not mistaken for pointers.
    """
    if old_gba == new_gba:
        return 0
    old_b = int(old_gba).to_bytes(4, "little")
    new_b = int(new_gba).to_bytes(4, "little")
    excl = exclude_ranges or []

    def in_excl(pos: int) -> bool:
        for lo, hi in excl:
            if lo <= pos < hi:
                return True
        return False

    n = 0
    i = 0
    while i + 4 <= len(rom):
        if in_excl(i):
            i += 4
            continue
        if rom[i : i + 4] == old_b:
            rom[i : i + 4] = new_b
            n += 1
        i += 4
    return n


class _GfxRelocateDialog:
    """Pick a file offset for a blob that no longer fits its original slot; optional FF-gap search."""

    def __init__(
        self,
        parent: tk.Misc,
        title: str,
        need_bytes: int,
        excl_lo: int,
        excl_hi: int,
        hex_editor: "HexEditorFrame",
        old_gba_addr: int,
    ) -> None:
        self.result: Optional[int] = None
        self.fill_old_slot: bool = False
        self._need = need_bytes
        self._excl_lo = excl_lo
        self._excl_hi = excl_hi
        self._hex = hex_editor
        self._old_gba = int(old_gba_addr)
        self._dlg = tk.Toplevel(parent)
        self._dlg.title(title)
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            f,
            text=(
                f"Imported data is larger than the current slot (needs {need_bytes} byte(s)).\n"
                f"Previous start: GBA 0x{self._old_gba:08X} (file 0x{excl_lo:X}).\n\n"
                "Pick a new **file offset** below (or Search FF gap). After writing, the tool will:\n"
                f"  • Replace every word-aligned pointer equal to 0x{self._old_gba:08X} in the ROM\n"
                "    with the new GBA address, and\n"
                "  • Update the NamedAnchor Address in TOML when possible.\n"
            ),
            wraplength=440,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Label(f, text="Target file offset:", font=("Consolas", 9)).grid(row=1, column=0, sticky="w")
        self._off_var = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._off_var, width=22, font=("Consolas", 9)).grid(
            row=1, column=1, sticky="ew", pady=2
        )
        ttk.Label(f, text="FF gap search from / through:", font=("Consolas", 8), foreground="#666").grid(
            row=2, column=0, sticky="nw", pady=(8, 0)
        )
        gap_f = ttk.Frame(f)
        gap_f.grid(row=2, column=1, sticky="ew", pady=(8, 0))
        self._from_var = tk.StringVar(value="")
        self._to_var = tk.StringVar(value="")
        ttk.Entry(gap_f, textvariable=self._from_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(gap_f, textvariable=self._to_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT)
        ttk.Button(f, text="Search FF gap", command=self._on_search).grid(row=3, column=1, sticky="e", pady=(6, 0))
        self._fill_old_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            f,
            text="Fill original slot with 0xFF after moving (reclaim as free space)",
            variable=self._fill_old_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))
        btnf = ttk.Frame(f)
        btnf.grid(row=5, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        f.columnconfigure(1, weight=1)
        self._dlg.bind("<Return>", lambda e: self._on_ok())
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._dlg.wait_window()

    def _on_search(self) -> None:
        data = self._hex.get_data()
        if not data:
            messagebox.showerror("Relocate", "No ROM loaded.")
            return
        w_lo, w_hi_ex, w_err = parse_ff_gap_search_window_strings(
            data, self._from_var.get(), self._to_var.get()
        )
        if w_err:
            messagebox.showerror("Relocate", w_err)
            return
        gap = find_disjoint_ff_gap_start(
            data,
            self._need,
            self._excl_lo,
            self._excl_hi,
            window_lo=w_lo,
            window_hi=w_hi_ex,
        )
        if gap is None:
            messagebox.showerror(
                "Relocate",
                f"No qualifying block of {self._need} consecutive 0xFF byte(s) was found "
                f"(disjoint from the original slot). Adjust the search range or pick an offset manually.",
            )
            return
        self._off_var.set(f"0x{gap:X}")

    def _on_ok(self) -> None:
        data = self._hex.get_data()
        if not data:
            self._dlg.destroy()
            return
        s = self._off_var.get().strip()
        if not s:
            messagebox.showwarning("Relocate", "Enter a file offset (hex or decimal), or use Search FF gap.")
            return
        try:
            off = int(s, 0)
        except ValueError:
            messagebox.showwarning("Relocate", "Invalid offset (use decimal or 0x hex).")
            return
        if off < 0:
            messagebox.showwarning("Relocate", "Offset must be ≥ 0.")
            return
        if GBA_ROM_BASE <= off <= GBA_ROM_MAX:
            off -= GBA_ROM_BASE
        if off + self._need > len(data):
            messagebox.showerror(
                "Relocate",
                f"Region too small for this graphic: need {self._need} byte(s) from file offset 0x{off:X}, "
                f"but ROM size is {len(data)} bytes (would end at 0x{off + self._need:X}).",
            )
            return
        self.fill_old_slot = bool(self._fill_old_var.get())
        self.result = off
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _TableGrowRepointDialog:
    """When a table cannot grow in place (not enough 0xFF space after it), pick a new base file offset."""

    def __init__(
        self,
        parent: tk.Misc,
        hex_editor: "HexEditorFrame",
        need_bytes: int,
        excl_lo: int,
        excl_hi: int,
        old_base: int,
        table_desc: str,
    ) -> None:
        self.result: Optional[Tuple[int, bool]] = None  # (new_file_offset, fill_old_with_ff)
        self._need = int(need_bytes)
        self._excl_lo = int(excl_lo)
        self._excl_hi = int(excl_hi)
        self._old_base = int(old_base)
        self._hex = hex_editor
        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Repoint table — not enough free space")
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            f,
            text=(
                f"Not enough consecutive 0xFF space after this table to add rows in place.\n\n"
                f"{table_desc}\n"
                f"Current table starts at file offset 0x{self._old_base:X} (needs 0x{self._need:X} byte(s) total "
                f"for the expanded table).\n\n"
                "Choose a new **file offset** for the start of the full expanded table, or search for an FF gap.\n"
                "Word-aligned ROM pointers to the old start address will be updated to the new start.\n"
            ),
            wraplength=460,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Label(f, text="New table file offset:", font=("Consolas", 9)).grid(row=1, column=0, sticky="w")
        self._off_var = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._off_var, width=22, font=("Consolas", 9)).grid(
            row=1, column=1, sticky="ew", pady=2
        )
        ttk.Label(f, text="FF gap search from / through:", font=("Consolas", 8), foreground="#666").grid(
            row=2, column=0, sticky="nw", pady=(8, 0)
        )
        gap_f = ttk.Frame(f)
        gap_f.grid(row=2, column=1, sticky="ew", pady=(8, 0))
        self._from_var = tk.StringVar(value="")
        self._to_var = tk.StringVar(value="")
        ttk.Entry(gap_f, textvariable=self._from_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(gap_f, textvariable=self._to_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT)
        ttk.Label(
            f,
            text="(leave both empty to search the whole ROM; end is inclusive)",
            font=("Consolas", 7),
            foreground="#666",
        ).grid(row=3, column=1, sticky="w", pady=(2, 0))
        ttk.Button(f, text="Search FF gap", command=self._on_search).grid(row=4, column=1, sticky="e", pady=(6, 0))
        self._fill_old_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f,
            text="Fill old table range with 0xFF after moving (reclaim as free space)",
            variable=self._fill_old_var,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))
        btnf = ttk.Frame(f)
        btnf.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        f.columnconfigure(1, weight=1)
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._dlg.wait_window()

    def _on_search(self) -> None:
        data = self._hex.get_data()
        if not data:
            messagebox.showerror("Repoint table", "No ROM loaded.")
            return
        w_lo, w_hi_ex, w_err = parse_ff_gap_search_window_strings(
            data, self._from_var.get(), self._to_var.get()
        )
        if w_err:
            messagebox.showerror("Repoint table", w_err)
            return
        gap = find_disjoint_ff_gap_start(
            data,
            self._need,
            self._excl_lo,
            self._excl_hi,
            window_lo=w_lo,
            window_hi=w_hi_ex,
        )
        if gap is None:
            messagebox.showerror(
                "Repoint table",
                f"No qualifying block of {self._need} consecutive 0xFF byte(s) was found "
                f"(disjoint from the current table). Adjust the search range or enter an offset manually.",
            )
            return
        self._off_var.set(f"0x{gap:X}")

    def _on_ok(self) -> None:
        data = self._hex.get_data()
        if not data:
            self._dlg.destroy()
            return
        s = self._off_var.get().strip()
        if not s:
            messagebox.showwarning(
                "Repoint table",
                "Enter a file offset (hex or decimal), or use Search FF gap.",
            )
            return
        try:
            off = int(s, 0)
        except ValueError:
            messagebox.showwarning("Repoint table", "Invalid offset (use decimal or 0x hex).")
            return
        if off < 0:
            messagebox.showwarning("Repoint table", "Offset must be ≥ 0.")
            return
        if GBA_ROM_BASE <= off <= GBA_ROM_MAX:
            off -= GBA_ROM_BASE
        ok_slot, err = self._hex._dest_accepts_table_write(off, self._need)
        if not ok_slot:
            messagebox.showerror("Repoint table", err or "Destination is not free space.")
            return
        if off == self._old_base:
            messagebox.showwarning(
                "Repoint table",
                "Pick a different offset than the current table start (or cancel and free space in place).",
            )
            return
        self.result = (off, bool(self._fill_old_var.get()))
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _FillBytesPromptDialog:
    """Ask for hex fill bytes (tiled) before expanding ``!``-terminated nested slots."""

    def __init__(self, parent: tk.Misc) -> None:
        self.result: Optional[str] = None
        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Table slots — fill pattern")
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            f,
            text=(
                "New element bytes are filled by tiling this hex pattern (even length).\n"
                "Examples: 00 → 0x00 per byte; 0000 → two-byte pattern for 16-bit slots.\n"
                "Leave empty for 0x00."
            ),
            wraplength=420,
        ).grid(row=0, column=0, sticky="w", pady=(0, 8))
        self._var = tk.StringVar(value="00")
        ttk.Entry(f, textvariable=self._var, width=28, font=("Consolas", 9)).grid(row=1, column=0, sticky="ew")
        btnf = ttk.Frame(f)
        btnf.grid(row=2, column=0, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        f.columnconfigure(0, weight=1)
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._dlg.wait_window()

    def _on_ok(self) -> None:
        self.result = self._var.get()
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _PointedBlobRepointDialog:
    """When a pointer-backed nested ``!`` blob cannot grow in place, pick a new allocation start (FF gap search)."""

    def __init__(
        self,
        parent: tk.Misc,
        hex_editor: "HexEditorFrame",
        need_bytes: int,
        excl_lo: int,
        excl_hi: int,
        ptr_alloc_start: int,
        ptr_field_name: str,
        desc: str,
    ) -> None:
        self.result: Optional[Tuple[int, bool]] = None
        self._need = int(need_bytes)
        self._excl_lo = int(excl_lo)
        self._excl_hi = int(excl_hi)
        self._old_base = int(ptr_alloc_start)
        self._hex = hex_editor
        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Repoint pointer target — not enough free space")
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            f,
            text=(
                f"Not enough consecutive 0xFF space after the nested terminator to grow in place.\n\n"
                f"{desc}\n"
                f"Pointer field: {ptr_field_name!r} — allocation currently starts at file 0x{self._old_base:X}.\n"
                f"Expanded blob needs 0x{self._need:X} byte(s) starting at that allocation base.\n\n"
                "Choose a new **file offset** for the start of the pointed-to block (same address the pointer holds), "
                "or search for an FF gap. All word-aligned ROM pointers to the old start will be updated.\n"
            ),
            wraplength=480,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Label(f, text="New allocation file offset:", font=("Consolas", 9)).grid(row=1, column=0, sticky="w")
        self._off_var = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._off_var, width=22, font=("Consolas", 9)).grid(
            row=1, column=1, sticky="ew", pady=2
        )
        ttk.Label(f, text="FF gap search from / through:", font=("Consolas", 8), foreground="#666").grid(
            row=2, column=0, sticky="nw", pady=(8, 0)
        )
        gap_f = ttk.Frame(f)
        gap_f.grid(row=2, column=1, sticky="ew", pady=(8, 0))
        self._from_var = tk.StringVar(value="")
        self._to_var = tk.StringVar(value="")
        ttk.Entry(gap_f, textvariable=self._from_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(gap_f, textvariable=self._to_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT)
        ttk.Label(
            f,
            text="(leave both empty to search the whole ROM; end is inclusive)",
            font=("Consolas", 7),
            foreground="#666",
        ).grid(row=3, column=1, sticky="w", pady=(2, 0))
        ttk.Button(f, text="Search FF gap", command=self._on_search).grid(row=4, column=1, sticky="e", pady=(6, 0))
        self._fill_old_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f,
            text="Fill old allocation range with 0xFF after moving (reclaim as free space)",
            variable=self._fill_old_var,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(10, 0))
        btnf = ttk.Frame(f)
        btnf.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        f.columnconfigure(1, weight=1)
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._dlg.wait_window()

    def _on_search(self) -> None:
        data = self._hex.get_data()
        if not data:
            messagebox.showerror("Repoint pointer target", "No ROM loaded.")
            return
        w_lo, w_hi_ex, w_err = parse_ff_gap_search_window_strings(
            data, self._from_var.get(), self._to_var.get()
        )
        if w_err:
            messagebox.showerror("Repoint pointer target", w_err)
            return
        gap = find_disjoint_ff_gap_start(
            data,
            self._need,
            self._excl_lo,
            self._excl_hi,
            window_lo=w_lo,
            window_hi=w_hi_ex,
        )
        if gap is None:
            messagebox.showerror(
                "Repoint pointer target",
                f"No qualifying block of {self._need} consecutive 0xFF byte(s) was found. "
                "Adjust the search range or enter an offset manually.",
            )
            return
        self._off_var.set(f"0x{gap:X}")

    def _on_ok(self) -> None:
        data = self._hex.get_data()
        if not data:
            self._dlg.destroy()
            return
        s = self._off_var.get().strip()
        if not s:
            messagebox.showwarning(
                "Repoint pointer target",
                "Enter a file offset (hex or decimal), or use Search FF gap.",
            )
            return
        try:
            off = int(s, 0)
        except ValueError:
            messagebox.showwarning("Repoint pointer target", "Invalid offset (use decimal or 0x hex).")
            return
        if off < 0:
            messagebox.showwarning("Repoint pointer target", "Offset must be ≥ 0.")
            return
        if GBA_ROM_BASE <= off <= GBA_ROM_MAX:
            off -= GBA_ROM_BASE
        ok_slot, err = self._hex._dest_accepts_table_write(off, self._need)
        if not ok_slot:
            messagebox.showerror("Repoint pointer target", err or "Destination is not free space.")
            return
        if off == self._old_base:
            messagebox.showwarning(
                "Repoint pointer target",
                "Pick a different offset than the current allocation start, or cancel.",
            )
            return
        self.result = (off, bool(self._fill_old_var.get()))
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _RepointBytesDialog:
    """Move selected bytes to an FF gap (or manual offset); repoint .word pointers and optional BLs."""

    def __init__(
        self,
        parent: tk.Misc,
        hex_editor: "HexEditorFrame",
        src_lo: int,
        src_hi: int,
    ) -> None:
        self.result: Optional[Tuple[int, bool, bool]] = None
        self._hex = hex_editor
        self._src_lo = int(src_lo)
        self._src_hi = int(src_hi)
        self._need = self._src_hi - self._src_lo
        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Repoint bytes")
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            f,
            text=(
                f"Move {self._need} byte(s) from file 0x{self._src_lo:08X}–0x{self._src_hi - 1:08X} "
                f"(GBA 0x{self._src_lo + GBA_ROM_BASE:08X} …).\n\n"
                "All word-aligned ROM pointers (0x08…… / 0x09……) that target any address in this range "
                "will be adjusted. Optionally, Thumb-2 BL instructions that branch into this range are re-encoded.\n\n"
                "Pick a **destination file offset** (must be a run of 0xFF bytes of at least this length, "
                "disjoint from the source range), or use Search FF gap."
            ),
            wraplength=460,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Label(f, text="Destination file offset:", font=("Consolas", 9)).grid(row=1, column=0, sticky="w")
        self._off_var = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._off_var, width=22, font=("Consolas", 9)).grid(
            row=1, column=1, sticky="ew", pady=2
        )
        ttk.Label(f, text="FF gap search from / through:", font=("Consolas", 8), foreground="#666").grid(
            row=2, column=0, sticky="nw", pady=(8, 0)
        )
        gap_f = ttk.Frame(f)
        gap_f.grid(row=2, column=1, sticky="ew", pady=(8, 0))
        self._from_var = tk.StringVar(value="")
        self._to_var = tk.StringVar(value="")
        ttk.Entry(gap_f, textvariable=self._from_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(gap_f, textvariable=self._to_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT)
        ttk.Button(f, text="Search FF gap", command=self._on_search).grid(row=3, column=1, sticky="e", pady=(6, 0))
        self._fill_old_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f,
            text="Fill original range with 0xFF after moving (reclaim as free space)",
            variable=self._fill_old_var,
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self._include_bl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f,
            text="Also repoint Thumb-2 BL instructions that branch into this range",
            variable=self._include_bl_var,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(4, 0))
        btnf = ttk.Frame(f)
        btnf.grid(row=6, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        f.columnconfigure(1, weight=1)
        self._dlg.bind("<Return>", lambda e: self._on_ok())
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._dlg.wait_window()

    def _on_search(self) -> None:
        data = self._hex.get_data()
        if not data:
            messagebox.showerror("Repoint bytes", "No ROM loaded.")
            return
        w_lo, w_hi_ex, w_err = parse_ff_gap_search_window_strings(
            data, self._from_var.get(), self._to_var.get()
        )
        if w_err:
            messagebox.showerror("Repoint bytes", w_err)
            return
        gap = find_disjoint_ff_gap_start(
            data,
            self._need,
            self._src_lo,
            self._src_hi,
            window_lo=w_lo,
            window_hi=w_hi_ex,
        )
        if gap is None:
            messagebox.showerror(
                "Repoint bytes",
                f"No qualifying block of {self._need} consecutive 0xFF byte(s) found "
                f"(disjoint from the source range). Adjust the search range or enter an offset manually.",
            )
            return
        self._off_var.set(f"0x{gap:X}")

    def _on_ok(self) -> None:
        data = self._hex.get_data()
        if not data:
            self._dlg.destroy()
            return
        s = self._off_var.get().strip()
        if not s:
            messagebox.showwarning("Repoint bytes", "Enter a destination file offset, or use Search FF gap.")
            return
        try:
            off = int(s, 0)
        except ValueError:
            messagebox.showwarning("Repoint bytes", "Invalid offset (use decimal or 0x hex).")
            return
        if GBA_ROM_BASE <= off <= GBA_ROM_MAX:
            off -= GBA_ROM_BASE
        if off < 0:
            messagebox.showwarning("Repoint bytes", "Offset must be ≥ 0.")
            return
        if off + self._need > len(data):
            messagebox.showerror(
                "Repoint bytes",
                f"Need {self._need} byte(s) at file offset 0x{off:X}, but ROM ends before that region.",
            )
            return
        # Destination must be 0xFF run (and disjoint from source)
        for i in range(self._need):
            if off + i >= len(data) or data[off + i] != 0xFF:
                messagebox.showerror(
                    "Repoint bytes",
                    f"Destination 0x{off:08X}–0x{off + self._need - 1:08X} must be entirely 0xFF "
                    f"(free space). Use Search FF gap or pick another offset.",
                )
                return
        if not (off + self._need <= self._src_lo or off >= self._src_hi):
            messagebox.showerror("Repoint bytes", "Destination must not overlap the source range.")
            return
        fill_old = bool(self._fill_old_var.get())
        include_bl = bool(self._include_bl_var.get())
        self.result = (off, fill_old, include_bl)
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


def parse_rom_file_offset(s: str) -> Tuple[Optional[int], str]:
    """Parse a ROM **file** offset; accepts decimal/hex or GBA pointer ``0x08……``."""
    s = str(s).strip()
    if not s:
        return None, "Enter a file offset (or use Search FF gap)."
    try:
        v = int(s, 0)
    except ValueError:
        return None, "Invalid number (use decimal or 0x hex)."
    if GBA_ROM_BASE <= v <= GBA_ROM_MAX:
        v -= GBA_ROM_BASE
    if v < 0:
        return None, "Offset must be ≥ 0."
    return v, ""


class _StaticRomOffsetDialog:
    """Pick where to write ``need_bytes``; optional FF-gap search (does not patch pointers)."""

    def __init__(
        self,
        parent: tk.Misc,
        hex_editor: "HexEditorFrame",
        need_bytes: int,
        title: str,
        *,
        blurb: str = "",
    ) -> None:
        self.result: Optional[int] = None
        self._need = need_bytes
        self._hex = hex_editor
        self._dlg = tk.Toplevel(parent)
        self._dlg.title(title)
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        n = need_bytes
        head = (
            f"Data size: {n} byte(s) (0x{n:X}).\n"
            + (blurb + "\n" if blurb else "")
            + "Enter a **file offset** (hex/decimal or GBA 0x08……) or search for an FF gap.\n"
        )
        ttk.Label(f, text=head, wraplength=440).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))
        ttk.Label(f, text="File offset:", font=("Consolas", 9)).grid(row=1, column=0, sticky="w")
        self._off_var = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._off_var, width=22, font=("Consolas", 9)).grid(
            row=1, column=1, sticky="ew", pady=2
        )
        ttk.Label(f, text="FF gap search from / through:", font=("Consolas", 8), foreground="#666").grid(
            row=2, column=0, sticky="nw", pady=(8, 0)
        )
        gap_f = ttk.Frame(f)
        gap_f.grid(row=2, column=1, sticky="ew", pady=(8, 0))
        self._from_var = tk.StringVar(value="")
        self._to_var = tk.StringVar(value="")
        ttk.Entry(gap_f, textvariable=self._from_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Entry(gap_f, textvariable=self._to_var, width=14, font=("Consolas", 8)).pack(side=tk.LEFT)
        ttk.Button(f, text="Search FF gap", command=self._on_search).grid(row=3, column=1, sticky="e", pady=(6, 0))
        btnf = ttk.Frame(f)
        btnf.grid(row=4, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        f.columnconfigure(1, weight=1)
        self._dlg.bind("<Return>", lambda e: self._on_ok())
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._dlg.wait_window()

    def _on_search(self) -> None:
        data = self._hex.get_data()
        if not data:
            messagebox.showerror("Import", "No ROM loaded.")
            return
        w_lo, w_hi_ex, w_err = parse_ff_gap_search_window_strings(data, self._from_var.get(), self._to_var.get())
        if w_err:
            messagebox.showerror("Import", w_err)
            return
        gap = find_disjoint_ff_gap_start(
            data,
            self._need,
            0,
            0,
            window_lo=w_lo,
            window_hi=w_hi_ex,
        )
        if gap is None:
            messagebox.showerror(
                "Import",
                f"No qualifying block of {self._need} consecutive 0xFF byte(s) was found. "
                "Adjust the search range or enter an offset manually.",
            )
            return
        self._off_var.set(f"0x{gap:X}")

    def _on_ok(self) -> None:
        data = self._hex.get_data()
        if not data:
            self._dlg.destroy()
            return
        s = self._off_var.get().strip()
        if not s:
            messagebox.showwarning("Import", "Enter a file offset, or use Search FF gap.")
            return
        off, err = parse_rom_file_offset(s)
        if off is None:
            messagebox.showwarning("Import", err)
            return
        if off + self._need > len(data):
            messagebox.showerror(
                "Import",
                f"ROM too small: need {self._need} byte(s) from file offset 0x{off:X}, "
                f"but ROM ends at 0x{len(data):X}.",
            )
            return
        self.result = off
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _SpriteImportOptionsDialog:
    """Manual static sprite/tileset import: bpp, palette size, tile grid, LZ, TOML update."""

    def __init__(self, parent: tk.Misc, png_path: str, *, title: str = "Import sprite — options") -> None:
        # bpp, lz, w, h, pal_colors, toml_sprite, toml_palette, write_palette_rom, update_toml, rom_colors_8bpp_clip
        self.result: Optional[Tuple[int, bool, int, int, int, str, str, bool, bool, Optional[int]]] = None
        self._dlg = tk.Toplevel(parent)
        self._dlg.title(title)
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text=f"File:\n{png_path}", wraplength=420).grid(row=0, column=0, columnspan=2, sticky="w")
        self._bpp = tk.IntVar(value=4)
        bf = ttk.Frame(f)
        bf.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Label(bf, text="Tile BPP:").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Radiobutton(bf, text="4bpp", variable=self._bpp, value=4, command=self._sync_bpp).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Radiobutton(bf, text="6bpp", variable=self._bpp, value=6, command=self._sync_bpp).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Radiobutton(bf, text="8bpp", variable=self._bpp, value=8, command=self._sync_bpp).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Label(f, text="Palette color slots (multiple of 16; index 0 = transparent #00FF00):", wraplength=400).grid(
            row=2, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )
        self._pal_n = tk.StringVar(value="16")
        self._pal_entry = ttk.Entry(f, textvariable=self._pal_n, width=8)
        self._pal_entry.grid(row=3, column=0, sticky="w", pady=(2, 0))
        self._pal_hint = ttk.Label(f, text="", font=("Consolas", 8), foreground="#666")
        self._pal_hint.grid(row=3, column=1, sticky="w", padx=(8, 0), pady=(2, 0))
        self._rom_clip_row = ttk.Frame(f)
        self._rom_clip_row.grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Label(
            self._rom_clip_row,
            text="ROM palette size (8bpp colors; ≤ quantize; step 16):",
            wraplength=400,
        ).grid(row=0, column=0, sticky="nw")
        self._pal_rom_clip = tk.StringVar(value="")
        ttk.Entry(self._rom_clip_row, textvariable=self._pal_rom_clip, width=8).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        ttk.Label(
            self._rom_clip_row,
            text="(blank = match quantize)",
            font=("Consolas", 8),
            foreground="#666",
        ).grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Label(f, text="Sprite sheet size (tiles, 8×8 px each):").grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )
        whf = ttk.Frame(f)
        whf.grid(row=6, column=0, columnspan=2, sticky="w")
        ttk.Label(whf, text="Width:").pack(side=tk.LEFT)
        self._wt = tk.StringVar(value="1")
        ttk.Entry(whf, textvariable=self._wt, width=6).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Label(whf, text="Height:").pack(side=tk.LEFT)
        self._ht = tk.StringVar(value="1")
        ttk.Entry(whf, textvariable=self._ht, width=6).pack(side=tk.LEFT, padx=(4, 0))
        self._lz = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            f,
            text="Compress tiles (and palette) with LZ77 (0x10)",
            variable=self._lz,
        ).grid(row=7, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._write_pal = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f,
            text="Write quantized GBA palette to ROM (separate offset after tiles)",
            variable=self._write_pal,
        ).grid(row=8, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Label(
            f,
            text="Sprite NamedAnchor (TOML) — may be new; row is added if missing:",
            wraplength=420,
        ).grid(row=9, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._toml_name = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._toml_name, width=48).grid(row=10, column=0, columnspan=2, sticky="ew")
        ttk.Label(
            f,
            text="Palette NamedAnchor (optional — sprite Format gets |palette; row added if missing):",
            wraplength=420,
        ).grid(row=11, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._toml_pal_name = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._toml_pal_name, width=48).grid(row=12, column=0, columnspan=2, sticky="ew")
        self._upd_toml = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f,
            text="Update Address + Format in TOML (needs tomli-w)",
            variable=self._upd_toml,
        ).grid(row=13, column=0, columnspan=2, sticky="w", pady=(6, 0))
        btnf = ttk.Frame(f)
        btnf.grid(row=14, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._bpp.trace_add("write", lambda *_: self._sync_bpp())
        self._sync_bpp()
        self._dlg.wait_window()

    def _sync_bpp(self, *_a: Any) -> None:
        old_b = getattr(self, "_bpp_prev", None)
        b = int(self._bpp.get())
        if b == 4:
            self._pal_n.set("16")
            self._pal_hint.configure(text="(fixed 16 for 4bpp)")
            self._pal_entry.configure(state="disabled")
            self._rom_clip_row.grid_remove()
        elif b == 6:
            self._pal_n.set("64")
            self._pal_hint.configure(text="(fixed 64 for 6bpp)")
            self._pal_entry.configure(state="disabled")
            self._rom_clip_row.grid_remove()
        else:
            if old_b in (4, 6):
                self._pal_n.set("256")
            elif self._pal_entry.cget("state") == "disabled":
                self._pal_n.set("256")
            else:
                try:
                    pv = int(self._pal_n.get().strip(), 0)
                except ValueError:
                    pv = -1
                if pv in (16, 64):
                    self._pal_n.set("256")
            self._pal_entry.configure(state="normal")
            self._pal_hint.configure(text="16–256, step 16")
            self._rom_clip_row.grid(row=4, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self._bpp_prev = b

    def _on_ok(self) -> None:
        bpp = int(self._bpp.get())
        lz = bool(self._lz.get())
        try:
            wt = int(self._wt.get().strip(), 0)
            ht = int(self._ht.get().strip(), 0)
        except ValueError:
            messagebox.showwarning("Import", "Width and height (tiles) must be integers.")
            return
        if wt < 1 or ht < 1:
            messagebox.showwarning("Import", "Width and height must be ≥ 1 tile.")
            return
        try:
            pn = int(self._pal_n.get().strip(), 0)
            ncolors = validate_manual_palette_color_count(bpp, pn)
        except ValueError as e:
            messagebox.showwarning("Import", str(e))
            return
        rom_clip_8: Optional[int] = None
        if bpp == 8:
            clip_s = self._pal_rom_clip.get().strip()
            if not clip_s:
                rom_clip_8 = ncolors
            else:
                try:
                    rom_clip_8 = parse_8bpp_palette_color_count(int(clip_s.strip(), 0))
                except ValueError as e:
                    messagebox.showwarning("Import", str(e))
                    return
            if rom_clip_8 > ncolors:
                messagebox.showwarning(
                    "Import",
                    "ROM palette size cannot exceed the quantize color count "
                    f"({rom_clip_8} > {ncolors}). Lower quantize or increase clip.",
                )
                return
        name = self._toml_name.get().strip()
        pal_nm = self._toml_pal_name.get().strip()
        write_pal = bool(self._write_pal.get())
        if bool(self._upd_toml.get()) and not name:
            messagebox.showwarning("Import", "Enter a sprite NamedAnchor Name, or disable TOML update.")
            return
        self.result = (bpp, lz, wt, ht, ncolors, name, pal_nm, write_pal, bool(self._upd_toml.get()), rom_clip_8)
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _PaletteImportOptionsDialog:
    """4bpp / 8bpp, optional 8bpp color count (multiple of 16), optional LZ."""

    def __init__(self, parent: tk.Misc, *, is_png: bool) -> None:
        self.result: Optional[Tuple[int, bool, int]] = None  # bpp, lz, colors_8bpp (meaningful if bpp==8)
        self._is_png = is_png
        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Import palette — options")
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            f,
            text=(
                "PNG: quantized to a 4bpp (16-color) or 8bpp master palette.\n"
                if is_png
                else (
                    "Standard .pal / .gpl: JASC-PAL, GIMP, or Tilemap Studio assembly RGB "
                    "(then converted to GBA RGB555).\n"
                    "Raw GBA palette bytes: use a .bin file.\n"
                )
            ),
            wraplength=420,
        ).grid(row=0, column=0, columnspan=2, sticky="w")
        self._bpp = tk.IntVar(value=4)
        self._bpp_row = ttk.Frame(f)
        self._bpp_row.grid(row=1, column=0, columnspan=2, sticky="w", pady=(8, 0))
        ttk.Label(self._bpp_row, text="Mode:").pack(side=tk.LEFT, padx=(0, 8))

        def _sync_bpp(*_a: Any) -> None:
            if int(self._bpp.get()) == 8:
                self._c8_wrap.grid(row=2, column=0, columnspan=2, sticky="ew")
            else:
                self._c8_wrap.grid_remove()

        ttk.Radiobutton(
            self._bpp_row,
            text="4bpp (16 colors, 32 bytes)",
            variable=self._bpp,
            value=4,
            command=_sync_bpp,
        ).pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(
            self._bpp_row,
            text="8bpp",
            variable=self._bpp,
            value=8,
            command=_sync_bpp,
        ).pack(side=tk.LEFT, padx=4)

        self._c8_wrap = ttk.Frame(f)
        self._c8_frame = ttk.Frame(self._c8_wrap)
        self._c8_frame.pack(anchor="w")
        ttk.Label(
            self._c8_frame,
            text="8bpp color count (multiple of 16; unused slots filled with black):",
            font=("TkDefaultFont", 9),
        ).grid(row=0, column=0, sticky="w")
        self._colors_8 = tk.StringVar(value="256")
        self._c8_combo = ttk.Combobox(
            self._c8_frame,
            textvariable=self._colors_8,
            values=[str(x) for x in range(16, 257, 16)],
            width=5,
            state="readonly",
        )
        self._c8_combo.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self._c8_bytes_lbl = ttk.Label(self._c8_frame, text="", font=("Consolas", 8), foreground="#666")
        self._c8_bytes_lbl.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        def _upd_bytes(*_a: Any) -> None:
            try:
                n = int(self._colors_8.get())
            except (ValueError, tk.TclError):
                n = 256
            self._c8_bytes_lbl.configure(text=f"ROM size: {n * 2} bytes (0x{n * 2:X})")

        self._colors_8.trace_add("write", lambda *_: _upd_bytes())
        _upd_bytes()
        _sync_bpp()

        self._lz = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            f,
            text="Compress with LZ77 (0x10)",
            variable=self._lz,
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))
        btnf = ttk.Frame(f)
        btnf.grid(row=4, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._dlg.wait_window()

    def _on_ok(self) -> None:
        bpp = int(self._bpp.get())
        lz = bool(self._lz.get())
        try:
            n_raw = int(self._colors_8.get())
        except (ValueError, tk.TclError):
            n_raw = 256
        if bpp == 8:
            try:
                n8 = parse_8bpp_palette_color_count(n_raw)
            except ValueError as e:
                messagebox.showwarning("Import palette", str(e))
                return
        else:
            n8 = 16
        self.result = (bpp, lz, n8)
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _TilemapImportModeDialog:
    """How to import: raw blob, full PNG tilemap, or PNG tileset sheet."""

    def __init__(self, parent: tk.Misc) -> None:
        self.result: Optional[str] = None
        self._dlg = tk.Toplevel(parent)
        self._dlg.title("Import tilemap / tileset")
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            f,
            text=(
                "• Raw binary — any .bin (e.g. exported map or tile bytes).\n"
                "• PNG tilemap — full map image → map + tileset + palette (same as Tools graphics).\n"
                "• PNG tileset — one sprite sheet → tile data only."
            ),
            wraplength=420,
            justify=tk.LEFT,
        ).grid(row=0, column=0, sticky="w")
        self._mode = tk.StringVar(value="raw")
        ttk.Radiobutton(f, text="Raw binary file", variable=self._mode, value="raw").grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )
        ttk.Radiobutton(f, text="PNG tilemap (image → map + tiles + palette)", variable=self._mode, value="png_map").grid(
            row=2, column=0, sticky="w"
        )
        ttk.Radiobutton(f, text="PNG tileset (sprite sheet)", variable=self._mode, value="png_ts").grid(
            row=3, column=0, sticky="w"
        )
        btnf = ttk.Frame(f)
        btnf.grid(row=4, column=0, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._dlg.wait_window()

    def _on_ok(self) -> None:
        self.result = self._mode.get()
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _TilemapPngDimsDialog:
    """Map size in tiles, bpp, palette size, burner quantize, optional TOML updates (map / tileset / palette)."""

    def __init__(self, parent: tk.Misc) -> None:
        # mw, mh, bpp, pal_ncolors, skip_pal, map_name, ts_name, pal_name, update_toml, rom_colors_8bpp_clip
        self.result: Optional[Tuple[int, int, int, int, bool, str, str, str, bool, Optional[int]]] = None
        self.skip_palette = False
        self._dlg = tk.Toplevel(parent)
        self._dlg.title("PNG tilemap — options")
        self._dlg.transient(parent)
        self._dlg.grab_set()
        f = ttk.Frame(self._dlg, padding=10)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            f,
            text="Map image is resized to width×height tiles (8 px/tile). "
            "Index 0 = transparent #00FF00; Pillow quantizes to (palette slots − 1) solid colors.",
            wraplength=440,
        ).grid(row=0, column=0, columnspan=4, sticky="w")
        ttk.Label(f, text="Width (tiles):").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self._mw = tk.StringVar(value="32")
        ttk.Entry(f, textvariable=self._mw, width=8).grid(row=1, column=1, sticky="w", pady=(8, 0))
        ttk.Label(f, text="Height (tiles):").grid(row=1, column=2, sticky="w", padx=(12, 0), pady=(8, 0))
        self._mh = tk.StringVar(value="20")
        ttk.Entry(f, textvariable=self._mh, width=8).grid(row=1, column=3, sticky="w", pady=(8, 0))
        self._bpp = tk.IntVar(value=4)
        bf = ttk.Frame(f)
        bf.grid(row=2, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Label(bf, text="BPP:").pack(side=tk.LEFT, padx=(0, 8))
        ttk.Radiobutton(bf, text="4", variable=self._bpp, value=4, command=self._sync_bpp).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Radiobutton(bf, text="6", variable=self._bpp, value=6, command=self._sync_bpp).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Radiobutton(bf, text="8", variable=self._bpp, value=8, command=self._sync_bpp).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Label(f, text="Palette color slots (multiple of 16):", wraplength=400).grid(
            row=3, column=0, columnspan=4, sticky="w", pady=(8, 0)
        )
        self._pal_n = tk.StringVar(value="16")
        self._pal_entry = ttk.Entry(f, textvariable=self._pal_n, width=8)
        self._pal_entry.grid(row=4, column=0, sticky="w", pady=(2, 0))
        self._pal_hint = ttk.Label(f, text="", font=("Consolas", 8), foreground="#666")
        self._pal_hint.grid(row=4, column=1, columnspan=3, sticky="w", padx=(8, 0), pady=(2, 0))
        self._rom_clip_row_tm = ttk.Frame(f)
        self._rom_clip_row_tm.grid(row=5, column=0, columnspan=4, sticky="w", pady=(4, 0))
        ttk.Label(
            self._rom_clip_row_tm,
            text="ROM palette size (8bpp colors; ≤ quantize; step 16):",
            wraplength=400,
        ).grid(row=0, column=0, sticky="nw")
        self._pal_rom_clip_tm = tk.StringVar(value="")
        ttk.Entry(self._rom_clip_row_tm, textvariable=self._pal_rom_clip_tm, width=8).grid(
            row=0, column=1, sticky="w", padx=(8, 0)
        )
        ttk.Label(
            self._rom_clip_row_tm,
            text="(blank = match quantize)",
            font=("Consolas", 8),
            foreground="#666",
        ).grid(row=0, column=2, sticky="w", padx=(8, 0))
        self._skip_pal = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            f,
            text="Skip writing palette (tileset + map only)",
            variable=self._skip_pal,
        ).grid(row=6, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Label(
            f,
            text="TOML names (optional) — new names get a new [[NamedAnchors]] row:",
            wraplength=440,
        ).grid(row=7, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Label(f, text="Tilemap:").grid(row=8, column=0, sticky="w")
        self._nm_map = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._nm_map, width=52).grid(row=8, column=1, columnspan=3, sticky="ew")
        ttk.Label(f, text="Tileset:").grid(row=9, column=0, sticky="w", pady=(4, 0))
        self._nm_ts = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._nm_ts, width=52).grid(row=9, column=1, columnspan=3, sticky="ew", pady=(4, 0))
        ttk.Label(f, text="Palette:").grid(row=10, column=0, sticky="w", pady=(4, 0))
        self._nm_pal = tk.StringVar(value="")
        ttk.Entry(f, textvariable=self._nm_pal, width=52).grid(row=10, column=1, columnspan=3, sticky="ew", pady=(4, 0))
        self._upd_toml = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            f,
            text="Update Address + Format in TOML when a name is given (needs tomli-w)",
            variable=self._upd_toml,
        ).grid(row=11, column=0, columnspan=4, sticky="w", pady=(8, 0))
        btnf = ttk.Frame(f)
        btnf.grid(row=12, column=0, columnspan=4, sticky="e", pady=(12, 0))
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        self._dlg.bind("<Escape>", lambda e: self._on_cancel())
        self._bpp.trace_add("write", lambda *_: self._sync_bpp())
        self._sync_bpp()
        self._dlg.wait_window()

    def _sync_bpp(self, *_a: Any) -> None:
        old_b = getattr(self, "_bpp_prev", None)
        b = int(self._bpp.get())
        if b == 4:
            self._pal_n.set("16")
            self._pal_hint.configure(text="(fixed 16 for 4bpp)")
            self._pal_entry.configure(state="disabled")
            self._rom_clip_row_tm.grid_remove()
        elif b == 6:
            self._pal_n.set("64")
            self._pal_hint.configure(text="(fixed 64 for 6bpp)")
            self._pal_entry.configure(state="disabled")
            self._rom_clip_row_tm.grid_remove()
        else:
            if old_b in (4, 6):
                self._pal_n.set("256")
            elif self._pal_entry.cget("state") == "disabled":
                self._pal_n.set("256")
            else:
                try:
                    pv = int(self._pal_n.get().strip(), 0)
                except ValueError:
                    pv = -1
                if pv in (16, 64):
                    self._pal_n.set("256")
            self._pal_entry.configure(state="normal")
            self._pal_hint.configure(text="16–256, step 16")
            self._rom_clip_row_tm.grid(row=5, column=0, columnspan=4, sticky="w", pady=(4, 0))
        self._bpp_prev = b

    def _on_ok(self) -> None:
        try:
            mw = int(self._mw.get().strip(), 0)
            mh = int(self._mh.get().strip(), 0)
        except ValueError:
            messagebox.showwarning("Import", "Width and height must be integers.")
            return
        if mw < 1 or mh < 1:
            messagebox.showwarning("Import", "Width and height must be ≥ 1.")
            return
        bpp = int(self._bpp.get())
        try:
            pn = int(self._pal_n.get().strip(), 0)
            ncolors = validate_manual_palette_color_count(bpp, pn)
        except ValueError as e:
            messagebox.showwarning("Import", str(e))
            return
        rom_clip_8: Optional[int] = None
        if bpp == 8:
            clip_s = self._pal_rom_clip_tm.get().strip()
            if not clip_s:
                rom_clip_8 = ncolors
            else:
                try:
                    rom_clip_8 = parse_8bpp_palette_color_count(int(clip_s.strip(), 0))
                except ValueError as e:
                    messagebox.showwarning("Import", str(e))
                    return
            if rom_clip_8 > ncolors:
                messagebox.showwarning(
                    "Import",
                    "ROM palette size cannot exceed the quantize color count "
                    f"({rom_clip_8} > {ncolors}).",
                )
                return
        skip = bool(self._skip_pal.get())
        nm_map = self._nm_map.get().strip()
        nm_ts = self._nm_ts.get().strip()
        nm_pal = self._nm_pal.get().strip()
        upd = bool(self._upd_toml.get())
        if upd and not (nm_map or nm_ts or nm_pal):
            messagebox.showwarning(
                "Import",
                "Enter at least one NamedAnchor name for TOML update, or disable TOML update.",
            )
            return
        if upd and nm_map and not nm_ts:
            messagebox.showwarning(
                "Import",
                "Tilemap anchor Format is ucm…|tileset — enter the tileset NamedAnchor name.",
            )
            return
        self.result = (mw, mh, bpp, ncolors, skip, nm_map, nm_ts, nm_pal, upd, rom_clip_8)
        self.skip_palette = skip
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._dlg.destroy()


class _PcsEditDialog:
    """Modal dialog to edit a PCS string. Returns bytearray of length width (padded with 0xFF, 0x00) on OK."""

    def __init__(self, parent: tk.Misc, title: str, initial: str, width: int) -> None:
        self.result: Optional[bytearray] = None
        self._width = width
        self._dialog = tk.Toplevel(parent)
        self._dialog.title(title)
        self._dialog.transient(parent)
        self._dialog.grab_set()
        f = ttk.Frame(self._dialog, padding=8)
        f.pack(fill=tk.BOTH, expand=True)
        ttk.Label(f, text="Value:").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self._entry = ttk.Entry(f, width=min(40, width + 4), font=("Consolas", 10))
        self._entry.insert(0, initial)
        self._entry.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self._entry.select_range(0, tk.END)
        self._entry.focus_set()
        f.columnconfigure(0, weight=1)
        btnf = ttk.Frame(f)
        btnf.grid(row=2, column=0, sticky="e")
        ttk.Button(btnf, text="OK", command=self._on_ok).pack(side=tk.LEFT, padx=2)
        ttk.Button(btnf, text="Cancel", command=self._on_cancel).pack(side=tk.LEFT)
        self._entry.bind("<Return>", lambda e: self._on_ok())
        self._entry.bind("<Escape>", lambda e: self._on_cancel())
        self._dialog.wait_window()

    def _on_ok(self) -> None:
        text = self._entry.get()
        out = bytearray()
        for c in text:
            b = _PCS_CHAR_TO_BYTE.get(c)
            if b is not None:
                out.append(b)
        out.append(0xFF)
        while len(out) < self._width:
            out.append(0x00)
        self.result = out[: self._width]
        self._dialog.destroy()

    def _on_cancel(self) -> None:
        self._dialog.destroy()


class PcsStringTableFrame(ttk.Frame):
    """Compact PCS string table for Tools pane: combo + tree, inline editing, horizontal scroll."""

    def __init__(self, parent: tk.Misc, hex_editor: "HexEditorFrame", **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._hex = hex_editor
        self._anchors: List[Dict[str, Any]] = []
        self._edit_entry: Optional[tk.Entry] = None
        self._edit_iid: Optional[str] = None
        self._pcs_filter_job: Optional[str] = None
        self._build()

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        f = ttk.Frame(self)
        f.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        f.columnconfigure(1, weight=1)
        ttk.Label(f, text="Table:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._combo = ttk.Combobox(f, font=("Consolas", 8), state="readonly")
        self._combo.grid(row=0, column=1, sticky="ew")
        self._combo.bind("<<ComboboxSelected>>", self._on_combo_select)
        sf = ttk.Frame(self)
        sf.grid(row=1, column=0, sticky="ew", pady=(0, 2))
        sf.columnconfigure(1, weight=1)
        ttk.Label(sf, text="Search:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._combo_search_var = tk.StringVar()
        self._combo_search_entry = ttk.Entry(sf, textvariable=self._combo_search_var, font=("Consolas", 8))
        self._combo_search_entry.grid(row=0, column=1, sticky="ew")
        self._combo_search_var.trace_add("write", lambda *_: self._schedule_pcs_combo_filter())
        ttk.Label(sf, text="Matches:", font=("Consolas", 8)).grid(row=1, column=0, sticky="w", padx=(0, 4), pady=(2, 0))
        self._pcs_match_combo = ttk.Combobox(sf, font=("Consolas", 8), state="readonly")
        self._pcs_match_combo.grid(row=1, column=1, sticky="ew", pady=(2, 0))
        self._pcs_match_combo.bind("<<ComboboxSelected>>", self._on_pcs_match_combo_select)
        self._pcs_match_suppress = False
        tree_f = ttk.Frame(self)
        tree_f.grid(row=2, column=0, sticky="nsew")
        tree_f.columnconfigure(0, weight=1)
        tree_f.rowconfigure(0, weight=1)
        self._tree = ttk.Treeview(tree_f, columns=("idx", "val"), show="headings", height=5, selectmode="browse")
        self._tree.heading("idx", text="#")
        self._tree.heading("val", text="Name")
        self._tree.column("idx", width=28, minwidth=28)
        self._tree.column("val", width=120, minwidth=60)
        self._scroll_y = tk.Scrollbar(tree_f)
        self._scroll_x = tk.Scrollbar(tree_f, orient=tk.HORIZONTAL)
        self._tree.configure(yscrollcommand=self._scroll_y.set, xscrollcommand=self._scroll_x.set)
        self._scroll_y.configure(command=self._tree.yview)
        self._scroll_x.configure(command=self._tree.xview)
        self._tree.grid(row=0, column=0, sticky="nsew")
        self._scroll_y.grid(row=0, column=1, sticky="ns")
        self._scroll_x.grid(row=1, column=0, sticky="ew")
        self._tree.bind("<Return>", self._start_inline_edit)
        self._tree.bind("<F2>", self._start_inline_edit)
        self._tree.bind("<ButtonRelease-1>", self._on_tree_click)

        add_row = ttk.Frame(self)
        add_row.grid(row=3, column=0, sticky="w", pady=(4, 0))
        ttk.Label(add_row, text="Add", font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 4))
        self._pcs_add_n_var = tk.IntVar(value=1)
        ttk.Spinbox(add_row, from_=1, to=500, width=5, textvariable=self._pcs_add_n_var, font=("Consolas", 8)).pack(
            side=tk.LEFT
        )
        ttk.Label(add_row, text="new rows", font=("Consolas", 8)).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(add_row, text="Apply", command=self._on_pcs_add_rows).pack(side=tk.LEFT, padx=(8, 0))

    def _schedule_pcs_combo_filter(self, event: Optional[tk.Event] = None) -> None:
        if self._pcs_filter_job is not None:
            try:
                self.after_cancel(self._pcs_filter_job)
            except (ValueError, tk.TclError):
                pass
        self._pcs_filter_job = self.after(100, self._apply_pcs_combo_filter)

    def _on_pcs_match_combo_select(self, event: Optional[tk.Event] = None) -> None:
        if self._pcs_match_suppress:
            return
        v = self._pcs_match_combo.get().strip()
        if not v:
            return
        if self._combo.get().strip() == v:
            return
        self._combo.set(v)
        vals = list(self._combo["values"])
        if v in vals:
            self._combo.current(vals.index(v))
        self._load_table()

    def _apply_pcs_combo_filter(self) -> None:
        self._pcs_filter_job = None
        if not self._anchors:
            self._combo.configure(values=[])
            self._combo.set("")
            self._pcs_match_suppress = True
            self._pcs_match_combo.configure(values=[])
            self._pcs_match_combo.set("")
            self._pcs_match_suppress = False
            self._tree.delete(*self._tree.get_children())
            return
        names = [str(a["name"]) for a in self._anchors]
        q_raw = self._combo_search_var.get().strip()
        q = q_raw.lower()
        filt = [n for n in names if q in n.lower()] if q else list(names)
        cur = self._combo.get().strip()
        self._combo.configure(values=filt)
        self._pcs_match_suppress = True
        self._pcs_match_combo.configure(values=filt)
        self._pcs_match_suppress = False
        if q:
            for n in names:
                if n.lower() == q:
                    if cur != n:
                        self._combo.set(n)
                        if n in filt:
                            self._combo.current(filt.index(n))
                        self._pcs_match_suppress = True
                        self._pcs_match_combo.set(n)
                        self._pcs_match_suppress = False
                        self._load_table()
                    else:
                        self._pcs_match_suppress = True
                        self._pcs_match_combo.set(n)
                        self._pcs_match_suppress = False
                    return
        if filt:
            if cur in filt:
                self._combo.current(filt.index(cur))
                self._pcs_match_suppress = True
                self._pcs_match_combo.set(cur)
                self._pcs_match_suppress = False
                self._load_table()
            elif cur:
                self._combo.set(filt[0])
                self._combo.current(0)
                self._pcs_match_suppress = True
                self._pcs_match_combo.set(filt[0])
                self._pcs_match_suppress = False
                self._load_table()
            else:
                self._combo.set("")
                self._pcs_match_suppress = True
                self._pcs_match_combo.set("")
                self._pcs_match_suppress = False
                self._tree.delete(*self._tree.get_children())
        else:
            self._combo.set("")
            self._pcs_match_suppress = True
            self._pcs_match_combo.set("")
            self._pcs_match_suppress = False
            self._tree.delete(*self._tree.get_children())

    def _selected_pcs_anchor(self) -> Optional[Dict[str, Any]]:
        name = self._combo.get().strip()
        if not name:
            return None
        return next((a for a in self._anchors if str(a["name"]) == name), None)

    def _on_tree_click(self, event: tk.Event) -> None:
        reg = self._tree.identify_region(event.x, event.y)
        if reg == "cell":
            col = self._tree.identify_column(event.x)
            if col == "#2":
                self.after(50, self._start_inline_edit)

    def _start_inline_edit(self, event: Optional[tk.Event] = None) -> None:
        if self._edit_entry:
            return
        sel = self._tree.selection()
        if not sel:
            return
        iid = sel[0]
        if not iid.startswith("pcs_"):
            return
        if not self._anchors or not self._hex.get_data():
            return
        info = self._selected_pcs_anchor()
        if not info:
            return
        vals = self._tree.item(iid, "values")
        if len(vals) < 2:
            return
        try:
            bbox = self._tree.bbox(iid, "#2")
        except tk.TclError:
            return
        if not bbox:
            return
        x, y, w, h = bbox
        tw = self._tree
        self._edit_entry = tk.Entry(tw.master, font=("Consolas", 9))
        self._edit_entry.place(x=tw.winfo_x() + x, y=tw.winfo_y() + y, width=max(w, 80), height=h)
        self._edit_entry.insert(0, vals[1])
        self._edit_entry.select_range(0, tk.END)
        self._edit_entry.focus_set()
        self._edit_iid = iid
        self._edit_entry.bind("<Return>", self._commit_inline_edit)
        self._edit_entry.bind("<Escape>", self._cancel_inline_edit)
        self._edit_entry.bind("<FocusOut>", self._commit_inline_edit)
        self._edit_entry.bind("<Up>", self._edit_adjacent_row)
        self._edit_entry.bind("<Down>", self._edit_adjacent_row)

    def _commit_inline_edit(self, event: Optional[tk.Event] = None) -> None:
        if not self._edit_entry or not self._edit_iid:
            return
        text = self._edit_entry.get()
        row_idx = int(self._edit_iid.split("_")[1])
        info = self._selected_pcs_anchor()
        if info:
            try:
                gba = int(info["anchor"]["Address"]) if isinstance(info["anchor"]["Address"], (int, float)) else int(str(info["anchor"]["Address"]), 0)
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                off = gba - GBA_ROM_BASE + row_idx * info["width"]
                if info.get("encoding") == "ascii":
                    enc = encode_ascii_slot(text, info["width"])
                    disp = decode_ascii_slot(bytes(enc))
                else:
                    enc = encode_pcs_string(text, info["width"])
                    parts = enc[: enc.index(0xFF)] if 0xFF in enc else enc
                    disp = "".join(_PCS_BYTE_TO_CHAR.get(b, "·") for b in parts)
                self._hex.write_bytes_at(off, enc)
                self._tree.set(self._edit_iid, "val", disp)
            except (ValueError, TypeError, KeyError):
                pass
        self._cancel_inline_edit()

    def _edit_adjacent_row(self, event: tk.Event) -> Optional[str]:
        """Up/Down: commit current edit, move to previous/next row, start edit there."""
        if not self._edit_entry or not self._edit_iid:
            return None
        text = self._edit_entry.get()
        row_idx = int(self._edit_iid.split("_")[1])
        info = self._selected_pcs_anchor()
        if info:
            try:
                gba = int(info["anchor"]["Address"]) if isinstance(info["anchor"]["Address"], (int, float)) else int(str(info["anchor"]["Address"]), 0)
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                off = gba - GBA_ROM_BASE + row_idx * info["width"]
                if info.get("encoding") == "ascii":
                    enc = encode_ascii_slot(text, info["width"])
                    disp = decode_ascii_slot(bytes(enc))
                else:
                    enc = encode_pcs_string(text, info["width"])
                    parts = enc[: enc.index(0xFF)] if 0xFF in enc else enc
                    disp = "".join(_PCS_BYTE_TO_CHAR.get(b, "·") for b in parts)
                self._hex.write_bytes_at(off, enc)
                self._tree.set(self._edit_iid, "val", disp)
            except (ValueError, TypeError, KeyError):
                pass
        direction = -1 if event.keysym == "Up" else 1
        next_idx = row_idx + direction
        next_iid = f"pcs_{next_idx}"
        self._cancel_inline_edit()
        if self._tree.exists(next_iid):
            self._tree.selection_set(next_iid)
            self._tree.see(next_iid)
            self._tree.focus_set()
            self.after(10, self._start_inline_edit)
        return "break"

    def _cancel_inline_edit(self, event: Optional[tk.Event] = None) -> Optional[str]:
        ent = self._edit_entry
        self._edit_entry = None
        self._edit_iid = None
        if ent:
            ent.place_forget()
            ent.destroy()
        if self._tree:
            self._tree.focus_set()
        return "break"

    def _on_combo_select(self, event: Optional[tk.Event] = None) -> None:
        self._load_table()

    def _on_pcs_add_rows(self) -> None:
        try:
            n = int(self._pcs_add_n_var.get())
        except (tk.TclError, ValueError):
            n = 1
        n = max(1, min(n, 500))
        info = self._selected_pcs_anchor()
        if not info:
            messagebox.showinfo("PCS table", "Select a string table first.")
            return
        ok, err = self._hex.append_pcs_table_rows(info, n)
        if not ok:
            messagebox.showerror("PCS table", err)
            return
        self.refresh_anchors()
        self._load_table()

    def refresh_anchors(self) -> None:
        self._anchors = self._hex.get_pcs_table_anchors()
        self._combo.set("")
        self._combo_search_var.set("")
        self._apply_pcs_combo_filter()

    def show_table(self, anchor_name: str, row_index: Optional[int] = None) -> None:
        if not self._anchors:
            self.refresh_anchors()
        self._combo_search_var.set("")
        self._apply_pcs_combo_filter()
        want = anchor_name.strip()
        vals = list(self._combo["values"])
        if want in vals:
            self._combo.set(want)
            self._combo.current(vals.index(want))
            self._load_table()
            if row_index is not None and self._tree:
                try:
                    ri = int(row_index)
                except (ValueError, TypeError):
                    return
                iid = f"pcs_{ri}"
                if self._tree.exists(iid):
                    self._tree.selection_set(iid)
                    self._tree.see(iid)

    def _load_table(self) -> None:
        self._tree.delete(*self._tree.get_children())
        if not self._anchors or not self._hex.get_data():
            return
        info = self._selected_pcs_anchor()
        if not info:
            return
        anchor, width, count = info["anchor"], info["width"], info["count"]
        addr = anchor.get("Address")
        if addr is None:
            return
        try:
            gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
            if gba < GBA_ROM_BASE:
                gba += GBA_ROM_BASE
            base_off = gba - GBA_ROM_BASE
        except (ValueError, TypeError):
            return
        self._tree.heading("val", text=info["field"].capitalize())
        data = self._hex.get_data()
        if not data:
            return
        enc = info.get("encoding", "pcs")
        for i in range(count):
            off = base_off + i * width
            if off + width > len(data):
                break
            chunk = bytes(data[off : off + width])
            if enc == "ascii":
                disp = decode_ascii_slot(chunk)
            else:
                chars = []
                for b in chunk:
                    if b == 0xFF:
                        break
                    chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
                disp = "".join(chars)
            self._tree.insert("", tk.END, values=(str(i), disp), iid=f"pcs_{i}")


class GraphicsPreviewFrame(ttk.Frame):
    """Decode GBA palettes/sprites with built-in pret gfx.c–compatible logic (Pillow PNG); no gbagfx binary."""

    def __init__(self, parent: tk.Misc, hex_editor: "HexEditorFrame", **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._hex = hex_editor
        self._photo: Optional[Any] = None
        self._pal4_state: Optional[Tuple[Any, bytes]] = None  # (GraphicsAnchorSpec, extracted pal bytes)
        self._pal8_colors: Optional[List[Tuple[int, int, int]]] = None
        self._gfx_filter_job: Optional[str] = None
        self._gfx_sprite_anchor_name: Optional[str] = None
        self._gfx_decode_anchor_name: Optional[str] = None
        # (file_off, palette_bpp 4|6|8, lz77: read palette from LZ-compressed blob at offset)
        self._sprite_palette_override: Optional[Tuple[int, int, bool]] = None
        # If set, prepended once to the next graphics decode log (import traces must survive _decode_selected).
        self._gfx_decode_log_prefix: str = ""
        # Tilemap PNG import: default preserves exact RGBs from the image; enable to MedianCut-quantize.
        self._tilemap_quantize_palette_var = tk.BooleanVar(value=False)
        self._build()

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Graphics:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._combo = ttk.Combobox(top, font=("Consolas", 8), state="readonly")
        self._combo.grid(row=0, column=1, columnspan=3, sticky="ew", padx=(0, 4))
        self._combo.bind("<<ComboboxSelected>>", lambda e: self._decode_selected())
        gfx_btn_row = ttk.Frame(top)
        gfx_btn_row.grid(row=1, column=0, columnspan=4, sticky="w", pady=(2, 0))
        ttk.Button(gfx_btn_row, text="Decode", command=self._decode_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(gfx_btn_row, text="Import graphic…", command=self._on_import_graphic).pack(side=tk.LEFT)
        ttk.Checkbutton(
            gfx_btn_row,
            text="Quantize tilemap palette",
            variable=self._tilemap_quantize_palette_var,
        ).pack(side=tk.LEFT, padx=(12, 0))
        srow = ttk.Frame(top)
        srow.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(2, 0))
        srow.columnconfigure(1, weight=1)
        ttk.Label(srow, text="Search:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._combo_search_var = tk.StringVar()
        ttk.Entry(srow, textvariable=self._combo_search_var, font=("Consolas", 8)).grid(row=0, column=1, sticky="ew")
        self._combo_search_var.trace_add("write", lambda *_: self._schedule_gfx_combo_filter())
        ttk.Label(srow, text="Matches:", font=("Consolas", 8)).grid(row=1, column=0, sticky="w", padx=(0, 4), pady=(2, 0))
        self._gfx_match_combo = ttk.Combobox(srow, font=("Consolas", 8), state="readonly")
        self._gfx_match_combo.grid(row=1, column=1, sticky="ew", pady=(2, 0))
        self._gfx_match_combo.bind("<<ComboboxSelected>>", self._on_gfx_match_combo_select)
        self._gfx_match_suppress = False

        self._table_nav = ttk.Frame(top)
        self._table_nav.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(2, 0))
        self._table_nav.grid_remove()
        ttk.Label(self._table_nav, text="Table row:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w")
        self._table_idx_spin = ttk.Spinbox(
            self._table_nav,
            textvariable=self._hex.graphics_table_row_var,
            from_=0,
            to=0,
            width=8,
            font=("Consolas", 8),
            command=self._decode_selected,
        )
        self._table_idx_spin.grid(row=0, column=1, sticky="w", padx=(4, 8))
        self._table_idx_spin.bind("<Return>", lambda _e: self._decode_selected())
        self._table_row_label = ttk.Label(self._table_nav, text="", font=("Consolas", 8), foreground="#666")
        self._table_row_label.grid(row=0, column=2, sticky="w")

        self._gfx_table_list_frame = ttk.Frame(self._table_nav)
        self._gfx_table_list_frame.columnconfigure(1, weight=1)
        self._gfx_table_list_label = ttk.Label(self._gfx_table_list_frame, text="", font=("Consolas", 8))
        self._gfx_table_list_label.grid(row=0, column=0, sticky="nw", padx=(0, 4))
        self._gfx_table_list_search_var = tk.StringVar()
        self._gfx_table_list_search_entry = ttk.Entry(
            self._gfx_table_list_frame, textvariable=self._gfx_table_list_search_var, font=("Consolas", 8)
        )
        self._gfx_table_list_search_entry.grid(row=0, column=1, sticky="ew")
        self._gfx_table_list_search_var.trace_add("write", lambda *_: self._schedule_gfx_table_list_filter())
        self._gfx_table_list_search_entry.bind("<Return>", lambda _e: self._apply_gfx_table_list_filter())
        ttk.Label(self._gfx_table_list_frame, text="Matches:", font=("Consolas", 8)).grid(
            row=1, column=0, sticky="w", padx=(0, 4), pady=(2, 0)
        )
        self._gfx_table_list_combo = ttk.Combobox(
            self._gfx_table_list_frame, font=("Consolas", 8), state="readonly"
        )
        self._gfx_table_list_combo.grid(row=1, column=1, sticky="ew", pady=(2, 0))
        self._gfx_table_list_combo.bind("<<ComboboxSelected>>", self._on_gfx_table_list_combo_select)
        self._gfx_table_list_frame.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(2, 0))
        self._gfx_table_list_frame.grid_remove()
        self._gfx_table_list_job: Optional[str] = None
        self._gfx_table_list_all_rows: List[Tuple[int, str]] = []
        self._gfx_table_list_suppress = False
        self._gfx_table_list_anchor_name: Optional[str] = None

        self._sprite_layout_row = ttk.Frame(top)
        self._sprite_layout_row.grid(row=4, column=0, columnspan=4, sticky="w", pady=(4, 0))
        self._sprite_layout_row.grid_remove()
        ttk.Label(self._sprite_layout_row, text="Tile rows (H):", font=("Consolas", 8)).grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self._sprite_rows_var = tk.IntVar(value=1)
        self._sprite_rows_spin = ttk.Spinbox(
            self._sprite_layout_row,
            from_=1,
            to=9999,
            width=5,
            textvariable=self._sprite_rows_var,
            font=("Consolas", 8),
        )
        self._sprite_rows_spin.grid(row=0, column=1, sticky="w", padx=(0, 8))
        self._sprite_rows_spin.bind("<Return>", lambda _e: self._decode_selected())
        ttk.Button(self._sprite_layout_row, text="Apply layout", command=self._decode_selected).grid(
            row=0, column=2, sticky="w"
        )

        self._sprite_pal_override_row = ttk.Frame(top)
        self._sprite_pal_override_row.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        self._sprite_pal_override_row.grid_remove()
        self._sprite_pal_override_row.columnconfigure(1, weight=1)
        ttk.Label(
            self._sprite_pal_override_row,
            text="Preview palette (offset or TOML Name):",
            font=("Consolas", 8),
        ).grid(row=0, column=0, sticky="nw", padx=(0, 4), pady=(2, 0))
        self._sprite_pal_off_var = tk.StringVar(value="")
        ttk.Entry(
            self._sprite_pal_override_row,
            textvariable=self._sprite_pal_off_var,
            width=12,
            font=("Consolas", 8),
        ).grid(row=0, column=1, columnspan=3, sticky="ew", padx=(0, 6), pady=(2, 0))
        ttk.Label(self._sprite_pal_override_row, text="bpp:", font=("Consolas", 8)).grid(
            row=1, column=0, sticky="w", padx=(0, 4), pady=(2, 0)
        )
        self._sprite_pal_bpp_var = tk.StringVar(value="4")
        self._sprite_pal_bpp_combo = ttk.Combobox(
            self._sprite_pal_override_row,
            textvariable=self._sprite_pal_bpp_var,
            values=("4", "6", "8"),
            width=3,
            state="readonly",
            font=("Consolas", 8),
        )
        self._sprite_pal_bpp_combo.grid(row=1, column=1, sticky="w", padx=(0, 0), pady=(2, 0))
        ttk.Label(self._sprite_pal_override_row, text="Data:", font=("Consolas", 8)).grid(
            row=2, column=0, sticky="w", padx=(0, 4), pady=(2, 0)
        )
        self._sprite_pal_storage_var = tk.StringVar(value="raw")
        ttk.Combobox(
            self._sprite_pal_override_row,
            textvariable=self._sprite_pal_storage_var,
            values=("raw", "lz77"),
            width=6,
            state="readonly",
            font=("Consolas", 8),
        ).grid(row=2, column=1, sticky="w", padx=(0, 8), pady=(2, 0))
        pal_btns = ttk.Frame(self._sprite_pal_override_row)
        pal_btns.grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))
        ttk.Button(pal_btns, text="Load", command=self._on_sprite_preview_palette_load).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(pal_btns, text="Clear", command=self._on_sprite_preview_palette_clear).pack(side=tk.LEFT)
        self._sprite_pal_status = ttk.Label(
            self._sprite_pal_override_row,
            text="",
            font=("Consolas", 8),
            foreground="#060",
            wraplength=320,
        )
        self._sprite_pal_status.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(4, 0))

        self._pal4_row = ttk.Frame(self)
        self._pal4_row.grid(row=1, column=0, sticky="w", pady=(0, 2))
        self._pal4_row.grid_remove()
        ttk.Label(self._pal4_row, text="Palette index (0–15):", font=("Consolas", 8)).grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self._pal4_index_combo = ttk.Combobox(
            self._pal4_row,
            width=4,
            state="readonly",
            font=("Consolas", 8),
            values=tuple(str(i) for i in range(16)),
        )
        self._pal4_index_combo.grid(row=0, column=1, sticky="w")
        self._pal4_index_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_palette_4_swatches())
        self._pal4_toml_hint = ttk.Label(self._pal4_row, text="", font=("Consolas", 8), foreground="#666")
        self._pal4_toml_hint.grid(row=0, column=2, sticky="w", padx=(12, 0))

        self._pal4_canvas = tk.Canvas(
            self, height=44, bg="#1e1e1e", highlightthickness=1, highlightbackground="#555555"
        )
        self._pal4_canvas.grid(row=2, column=0, sticky="ew", pady=(0, 4))
        self._pal4_canvas.grid_remove()

        self._pal8_row = ttk.Frame(self)
        self._pal8_row.grid(row=1, column=0, sticky="w", pady=(0, 2))
        self._pal8_row.grid_remove()
        self._pal8_title = ttk.Label(self._pal8_row, text="8bpp palette:", font=("Consolas", 8))
        self._pal8_title.grid(row=0, column=0, sticky="w", padx=(0, 4))

        self._pal8_outer = ttk.Frame(self)
        self._pal8_outer.grid(row=2, column=0, sticky="ew", pady=(0, 4))
        self._pal8_outer.columnconfigure(0, weight=1)
        self._pal8_outer.rowconfigure(0, weight=1)
        self._pal8_canvas = tk.Canvas(
            self._pal8_outer,
            height=200,
            width=400,
            bg="#1e1e1e",
            highlightthickness=1,
            highlightbackground="#555555",
        )
        self._pal8_scroll = tk.Scrollbar(self._pal8_outer, orient=tk.VERTICAL, command=self._pal8_canvas.yview)
        self._pal8_canvas.configure(yscrollcommand=self._pal8_scroll.set)
        self._pal8_canvas.grid(row=0, column=0, sticky="nsew")
        self._pal8_scroll.grid(row=0, column=1, sticky="ns")

        def _pal8_wheel(ev: tk.Event) -> str:
            self._pal8_canvas.yview_scroll(int(-1 * (getattr(ev, "delta", 0) / 120)), "units")
            return "break"

        self._pal8_canvas.bind("<MouseWheel>", _pal8_wheel)
        self._pal8_canvas.bind("<Button-4>", lambda _e: self._pal8_canvas.yview_scroll(-2, "units"))
        self._pal8_canvas.bind("<Button-5>", lambda _e: self._pal8_canvas.yview_scroll(2, "units"))

        self._pal8_outer.grid_remove()

        ttk.Label(self, text="Decode log:", font=("Consolas", 8)).grid(row=3, column=0, sticky="w")
        self._log = tk.Text(self, height=5, font=("Consolas", 8), wrap=tk.WORD, state=tk.DISABLED)
        self._log.grid(row=4, column=0, sticky="ew", pady=(0, 4))
        self._img_label = ttk.Label(self, text="(no preview)")
        self._img_label.grid(row=5, column=0, sticky="nw")

    def _set_log(self, text: str) -> None:
        self._log.configure(state=tk.NORMAL)
        self._log.delete("1.0", tk.END)
        self._log.insert("1.0", text or "")
        self._log.configure(state=tk.DISABLED)

    def _emit_gfx_decode_log(self, text: str) -> None:
        """Replace decode log, optionally prefixing with a one-shot string (e.g. tilemap import [debug] lines)."""
        pfx = getattr(self, "_gfx_decode_log_prefix", "") or ""
        self._gfx_decode_log_prefix = ""
        self._set_log(pfx + text)

    def _clear_image(self, msg: str = "(no preview)") -> None:
        self._photo = None
        self._img_label.configure(image="", text=msg)

    def _hide_palette_4_ui(self) -> None:
        self._pal4_row.grid_remove()
        self._pal4_canvas.grid_remove()
        self._pal4_state = None
        self._pal4_toml_hint.configure(text="")

    def _hide_palette_8_ui(self) -> None:
        self._pal8_row.grid_remove()
        self._pal8_outer.grid_remove()
        self._pal8_colors = None

    def _refresh_palette_8_swatches(self) -> None:
        if not self._pal8_colors:
            return
        rgbs = self._pal8_colors
        c = self._pal8_canvas
        c.delete("all")
        cols = 16
        pad, cell_w, cell_h, gap = 4, 18, 26, 2
        n = len(rgbs)
        nrow = (n + cols - 1) // cols
        total_w = pad * 2 + cols * cell_w + max(0, cols - 1) * gap
        total_h = pad * 2 + nrow * cell_h + max(0, nrow - 1) * gap
        c.configure(width=min(total_w + 24, 420), scrollregion=(0, 0, total_w, total_h))
        for i, rgb in enumerate(rgbs):
            row, col = divmod(i, cols)
            x0 = pad + col * (cell_w + gap)
            y0 = pad + row * (cell_h + gap)
            fill = "#%02x%02x%02x" % rgb
            c.create_rectangle(x0, y0, x0 + cell_w, y0 + cell_h, fill=fill, outline="#666666")
        c.yview_moveto(0)

    def _refresh_palette_4_swatches(self) -> None:
        if not self._pal4_state:
            return
        spec, pal_bytes = self._pal4_state
        try:
            slot = int(self._pal4_index_combo.get())
        except (ValueError, tk.TclError):
            slot = 0
        try:
            sub = get_palette_4_slot_bytes(spec, pal_bytes, slot)
            rgbs = decode_gba_palette32_to_rgb888(sub)
        except (ValueError, IndexError):
            return
        c = self._pal4_canvas
        c.delete("all")
        pad, cell_w, cell_h = 4, 18, 26
        total_w = pad * 2 + 16 * (cell_w + 2)
        c.configure(width=total_w, height=pad * 2 + cell_h)
        for i, rgb in enumerate(rgbs):
            x0 = pad + i * (cell_w + 2)
            fill = "#%02x%02x%02x" % rgb
            c.create_rectangle(x0, pad, x0 + cell_w, pad + cell_h, fill=fill, outline="#666666")

    def _try_show_image(self, path: str) -> None:
        try:
            from PIL import Image, ImageTk  # type: ignore
        except ImportError:
            self._clear_image(f"Install Pillow to preview PNG.\n{path}")
            return
        try:
            im = Image.open(path)
            im = im.convert("RGBA")
            max_w, max_h = 280, 280
            try:
                resample = Image.Resampling.LANCZOS  # type: ignore[attr-defined]
            except AttributeError:
                resample = Image.LANCZOS
            im.thumbnail((max_w, max_h), resample)
            self._photo = ImageTk.PhotoImage(im)
            self._img_label.configure(image=self._photo, text="")
        except OSError as e:
            self._clear_image(f"Could not load image:\n{e}\n{path}")

    def refresh_anchors(self) -> None:
        self._combo_search_var.set("")
        self._apply_gfx_combo_filter()
        if not self._combo["values"]:
            self._combo.set("")
            self._hide_palette_4_ui()
            self._hide_palette_8_ui()
            self._table_nav.grid_remove()
            self._gfx_table_list_frame.grid_remove()
            self._gfx_table_list_anchor_name = None
            self._sprite_layout_row.grid_remove()
            self._sprite_pal_override_row.grid_remove()
            self._gfx_sprite_anchor_name = None
            self._gfx_decode_anchor_name = None
            self._sprite_palette_override = None
            self._sprite_pal_status.configure(text="")
            self._set_log("Graphics: built-in decode (pret gfx.c palette/tiles + Pillow).\n(no graphics NamedAnchors in TOML)")
            self._clear_image()

    def show_anchor(self, anchor_name: str) -> None:
        self.refresh_anchors()
        want = anchor_name.strip()
        vals = list(self._combo["values"])
        match = None
        for v in vals:
            if _graphics_combo_entry_to_anchor_name(str(v)) == want:
                match = v
                break
        if match is None:
            self._set_log(f"Graphics anchor not found: {anchor_name!r}")
            return
        self._combo.set(match)
        self._combo.current(vals.index(match))
        self._decode_selected()

    def _update_table_nav_for_info(self, info: Dict[str, Any]) -> None:
        """Show row spinbox when this anchor or its linked palette uses ``[format]count``."""
        need = bool(info.get("graphics_table"))
        spec = info["spec"]
        if not need and spec.kind == "sprite":
            pan = getattr(spec, "palette_anchor_name", None)
            if pan:
                ga = self._hex.find_graphics_anchor_by_name(pan)
                need = bool(ga and ga.get("graphics_table"))
        if not need and spec.kind == "tilemap":
            ts = getattr(spec, "tileset_anchor_name", None)
            ts_key = ts.strip() if ts else ""
            if ts_key:
                ga = self._hex.find_graphics_anchor_by_name(ts_key)
                need = bool(ga and ga.get("graphics_table"))
            if not need:
                pan = getattr(spec, "palette_anchor_name", None)
                if not pan and ts_key:
                    gat = self._hex.find_graphics_anchor_by_name(ts_key)
                    if gat and gat["spec"].kind == "sprite":
                        pan = getattr(gat["spec"], "palette_anchor_name", None)
                if pan:
                    ga = self._hex.find_graphics_anchor_by_name(pan.strip())
                    need = bool(ga and ga.get("graphics_table"))
        if need:
            _, eff, _ = self._effective_table_state(info)
            self._table_idx_spin.configure(from_=0, to=max(0, eff - 1))
            self._table_nav.grid()
            self._prepare_gfx_table_list_panel(info)
        else:
            self._table_nav.grid_remove()
            self._table_row_label.configure(text="")
            self._gfx_table_list_frame.grid_remove()

    def _effective_table_state(self, info: Dict[str, Any]) -> Tuple[int, int, str]:
        """Clamp shared row index; return (index, effective_row_count, warnings)."""
        counts: List[int] = []
        if info.get("graphics_table"):
            n = int(info.get("table_num_entries") or 0)
            if n <= 0:
                ref = info.get("table_count_ref") or ""
                c = self._hex._resolve_struct_count(ref)
                n = c if isinstance(c, int) and c > 0 else 1
            counts.append(max(1, n))
        spec = info["spec"]
        if spec.kind == "sprite" and getattr(spec, "palette_anchor_name", None):
            ga = self._hex.find_graphics_anchor_by_name(spec.palette_anchor_name)
            if ga and ga.get("graphics_table"):
                n = int(ga.get("table_num_entries") or 0)
                if n <= 0:
                    ref = ga.get("table_count_ref") or ""
                    c = self._hex._resolve_struct_count(ref)
                    n = c if isinstance(c, int) and c > 0 else 1
                counts.append(max(1, n))
        if spec.kind == "tilemap":
            ts = getattr(spec, "tileset_anchor_name", None)
            ts_key = ts.strip() if ts else ""
            if ts_key:
                ga = self._hex.find_graphics_anchor_by_name(ts_key)
                if ga and ga.get("graphics_table"):
                    n = int(ga.get("table_num_entries") or 0)
                    if n <= 0:
                        ref = ga.get("table_count_ref") or ""
                        c = self._hex._resolve_struct_count(ref)
                        n = c if isinstance(c, int) and c > 0 else 1
                    counts.append(max(1, n))
            pan = getattr(spec, "palette_anchor_name", None)
            if not pan and ts_key:
                gat = self._hex.find_graphics_anchor_by_name(ts_key)
                if gat and gat["spec"].kind == "sprite":
                    pan = getattr(gat["spec"], "palette_anchor_name", None)
            if pan:
                ga = self._hex.find_graphics_anchor_by_name(pan.strip())
                if ga and ga.get("graphics_table"):
                    n = int(ga.get("table_num_entries") or 0)
                    if n <= 0:
                        ref = ga.get("table_count_ref") or ""
                        c = self._hex._resolve_struct_count(ref)
                        n = c if isinstance(c, int) and c > 0 else 1
                    counts.append(max(1, n))
        eff = min(counts) if counts else 1
        warn = ""
        if len(counts) > 1 and min(counts) != max(counts):
            warn = f"Table size mismatch (graphics rows): using min length {eff}.\n"
        try:
            raw_i = int(self._hex.graphics_table_row_var.get())
        except (ValueError, tk.TclError):
            raw_i = 0
        idx = max(0, min(raw_i, eff - 1))
        self._hex.graphics_table_row_var.set(idx)
        return idx, eff, warn

    def _table_label_ref_name(self, info: Dict[str, Any]) -> str:
        if info.get("graphics_table"):
            return str(info.get("table_count_ref") or "")
        spec = info["spec"]
        if spec.kind == "tilemap":
            if info.get("graphics_table"):
                return str(info.get("table_count_ref") or "")
            ts = getattr(spec, "tileset_anchor_name", None)
            ts_key = ts.strip() if ts else ""
            if ts_key:
                ga = self._hex.find_graphics_anchor_by_name(ts_key)
                if ga and ga.get("graphics_table"):
                    return str(ga.get("table_count_ref") or "")
            pan = getattr(spec, "palette_anchor_name", None)
            if not pan and ts_key:
                gat = self._hex.find_graphics_anchor_by_name(ts_key)
                if gat and gat["spec"].kind == "sprite":
                    pan = getattr(gat["spec"], "palette_anchor_name", None)
            if pan:
                ga = self._hex.find_graphics_anchor_by_name(pan.strip())
                if ga and ga.get("graphics_table"):
                    return str(ga.get("table_count_ref") or "")
            return ""
        if spec.kind == "sprite" and getattr(spec, "palette_anchor_name", None):
            ga = self._hex.find_graphics_anchor_by_name(spec.palette_anchor_name)
            if ga and ga.get("graphics_table"):
                return str(ga.get("table_count_ref") or "")
        return ""

    def _schedule_gfx_combo_filter(self, event: Optional[tk.Event] = None) -> None:
        if self._gfx_filter_job is not None:
            try:
                self.after_cancel(self._gfx_filter_job)
            except (ValueError, tk.TclError):
                pass
        self._gfx_filter_job = self.after(100, self._apply_gfx_combo_filter)

    def _on_gfx_match_combo_select(self, event: Optional[tk.Event] = None) -> None:
        if self._gfx_match_suppress:
            return
        v = self._gfx_match_combo.get().strip()
        if not v:
            return
        if self._combo.get().strip() == v:
            return
        self._combo.set(v)
        vals = list(self._combo["values"])
        if v in vals:
            self._combo.current(vals.index(v))
        self._decode_selected()

    def _apply_gfx_combo_filter(self) -> None:
        self._gfx_filter_job = None
        anchors = self._hex.get_graphics_anchors()
        display_entries = [_graphics_anchor_combo_display(a) for a in anchors]
        q_raw = self._combo_search_var.get().strip()
        q = q_raw.lower()
        filt = [d for d in display_entries if q in d.lower()] if q else list(display_entries)
        cur = self._combo.get().strip()
        cur_key = _graphics_combo_entry_to_anchor_name(cur)
        self._combo.configure(values=filt)
        self._gfx_match_suppress = True
        self._gfx_match_combo.configure(values=filt)
        self._gfx_match_suppress = False
        if q:
            for d in display_entries:
                an = _graphics_combo_entry_to_anchor_name(d)
                if an.lower() == q or d.lower() == q_raw.lower():
                    pick = d
                    if cur_key != an or cur not in filt:
                        self._combo.set(pick)
                        if pick in filt:
                            self._combo.current(filt.index(pick))
                        self._gfx_match_suppress = True
                        self._gfx_match_combo.set(pick)
                        self._gfx_match_suppress = False
                        self._decode_selected()
                    else:
                        self._gfx_match_suppress = True
                        self._gfx_match_combo.set(pick if pick in filt else cur)
                        self._gfx_match_suppress = False
                    return
        if filt:
            cur_ok = cur in filt or (
                cur_key and any(_graphics_combo_entry_to_anchor_name(x) == cur_key for x in filt)
            )
            if cur_ok:
                pick = cur if cur in filt else next(
                    x for x in filt if _graphics_combo_entry_to_anchor_name(x) == cur_key
                )
                self._combo.set(pick)
                self._combo.current(filt.index(pick))
                self._gfx_match_suppress = True
                self._gfx_match_combo.set(pick)
                self._gfx_match_suppress = False
            elif cur_key:
                self._combo.set(filt[0])
                self._combo.current(0)
                self._gfx_match_suppress = True
                self._gfx_match_combo.set(filt[0])
                self._gfx_match_suppress = False
                self._decode_selected()
            else:
                self._combo.set("")
                self._gfx_match_suppress = True
                self._gfx_match_combo.set("")
                self._gfx_match_suppress = False
        else:
            self._combo.set("")
            self._gfx_match_suppress = True
            self._gfx_match_combo.set("")
            self._gfx_match_suppress = False
            self._clear_image()

    def _schedule_gfx_table_list_filter(self, event: Optional[tk.Event] = None) -> None:
        if self._gfx_table_list_job is not None:
            try:
                self.after_cancel(self._gfx_table_list_job)
            except (ValueError, tk.TclError):
                pass
        self._gfx_table_list_job = self.after(100, lambda: self._apply_gfx_table_list_filter(initial=False))

    def _apply_gfx_table_list_filter(self, initial: bool = False) -> None:
        self._gfx_table_list_job = None
        rows = self._gfx_table_list_all_rows
        if not rows:
            return
        sep = " \u2014 "
        q_raw = self._gfx_table_list_search_var.get().strip()
        q = q_raw.lower()
        filt_rows = [(i, lbl) for i, lbl in rows if not q or q in str(i) or q in lbl.lower()]
        disp = [f"{i}{sep}{lbl}" for i, lbl in filt_rows]
        self._gfx_table_list_suppress = True
        self._gfx_table_list_combo.configure(values=disp)
        if not initial and q:
            for i, lbl in rows:
                if lbl.strip().lower() == q:
                    try:
                        cur_r = int(self._hex.graphics_table_row_var.get())
                    except (ValueError, tk.TclError):
                        cur_r = -1
                    if cur_r != i:
                        self._hex.graphics_table_row_var.set(i)
                        self._gfx_table_list_suppress = False
                        self._decode_selected()
                    else:
                        pick = f"{i}{sep}{lbl}"
                        self._gfx_table_list_combo.set(pick if pick in disp else (disp[0] if disp else ""))
                        self._gfx_table_list_suppress = False
                    return
        try:
            tbl_idx = int(self._hex.graphics_table_row_var.get())
        except (ValueError, tk.TclError):
            tbl_idx = 0
        lbl_cur = ""
        for i, lb in rows:
            if i == tbl_idx:
                lbl_cur = lb
                break
        pick_cur = f"{tbl_idx}{sep}{lbl_cur}"
        if pick_cur in disp:
            self._gfx_table_list_combo.set(pick_cur)
        elif disp:
            self._gfx_table_list_combo.set(disp[0])
        else:
            self._gfx_table_list_combo.set("")
        self._gfx_table_list_suppress = False

    def _on_gfx_table_list_combo_select(self, event: Optional[tk.Event] = None) -> None:
        if self._gfx_table_list_suppress:
            return
        s = self._gfx_table_list_combo.get().strip()
        sep = " \u2014 "
        if sep not in s:
            return
        part = s.split(sep, 1)[0]
        try:
            idx = int(part.strip())
        except ValueError:
            return
        try:
            cur = int(self._hex.graphics_table_row_var.get())
        except (ValueError, tk.TclError):
            cur = -1
        if cur == idx:
            return
        self._hex.graphics_table_row_var.set(idx)
        self._decode_selected()

    def _prepare_gfx_table_list_panel(self, info: Dict[str, Any]) -> None:
        self._gfx_table_list_frame.grid_remove()
        list_ref = self._table_label_ref_name(info)
        aname = str(info.get("name", ""))
        if not list_ref:
            self._gfx_table_list_anchor_name = None
            return
        base, _delta = _split_enum_field_ref(list_ref)
        lk = normalize_named_anchor_lookup_key(base.strip())
        if lk not in self._hex.get_lists():
            self._gfx_table_list_anchor_name = None
            return
        _, eff, _ = self._effective_table_state(info)
        self._gfx_table_list_all_rows = []
        for i in range(eff):
            lbl = self._hex.get_list_entry_label(list_ref, i) or ""
            self._gfx_table_list_all_rows.append((i, lbl))
        self._gfx_table_list_label.configure(text=f"[[List]] {list_ref}:", font=("Consolas", 8))
        if self._gfx_table_list_anchor_name != aname:
            self._gfx_table_list_suppress = True
            self._gfx_table_list_search_var.set("")
            self._gfx_table_list_suppress = False
        self._gfx_table_list_anchor_name = aname
        self._apply_gfx_table_list_filter(initial=True)
        self._gfx_table_list_frame.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(2, 0))

    def _decode_selected(self, event: Optional[tk.Event] = None) -> None:
        name = _graphics_combo_entry_to_anchor_name(self._combo.get().strip())
        if not name:
            self._gfx_decode_log_prefix = ""
            return
        rom = self._hex.get_data()
        if not rom:
            self._gfx_decode_log_prefix = ""
            return
        if self._gfx_decode_anchor_name is not None and name != self._gfx_decode_anchor_name:
            self._sprite_palette_override = None
            self._sprite_pal_status.configure(text="")
        self._gfx_decode_anchor_name = name
        info = next((a for a in self._hex.get_graphics_anchors() if str(a["name"]) == name), None)
        if not info:
            self._emit_gfx_decode_log("Anchor missing.")
            return
        self._update_table_nav_for_info(info)
        spec = info["spec"]
        tbl_idx, _eff, tbl_warn = self._effective_table_state(info)
        list_ref = self._table_label_ref_name(info)
        lbl = self._hex.get_list_entry_label(list_ref, tbl_idx) if list_ref else None
        if lbl:
            disp = lbl if len(lbl) <= 56 else lbl[:53] + "..."
            self._table_row_label.configure(text=disp)
        else:
            self._table_row_label.configure(text="")

        blob_off = info["base_off"]
        if info.get("graphics_table"):
            blob_off = info["base_off"] + tbl_idx * int(info["row_byte_size"])

        if spec.kind == "sprite":
            self._sprite_layout_row.grid()
            self._sprite_pal_override_row.grid()
            if self._gfx_sprite_anchor_name != name:
                self._gfx_sprite_anchor_name = name
                if spec.width_tiles == 0 and spec.height_tiles == 0:
                    self._sprite_rows_var.set(1)
                else:
                    self._sprite_rows_var.set(max(1, spec.height_tiles))
            try:
                raw_sz = bytes(rom[blob_off : blob_off + min(len(rom) - blob_off, 4 << 20)])
                tb = extract_sprite_bytes(spec, raw_sz)
                per = sprite_bytes_per_tile(spec.bpp)
                t_n = len(tb) // per
                # Fixed ``ucs4xWxH`` etc.: allow tall grids (e.g. 4×8 icons); variable strips keep rows ≤ cols cap.
                if spec.width_tiles > 0 and spec.height_tiles > 0:
                    row_max = max(1, t_n)
                else:
                    row_max = max(1, max_sprite_height_tiles(t_n))
                self._sprite_rows_spin.configure(from_=1, to=row_max)
                hv = int(self._sprite_rows_var.get())
                if hv > row_max:
                    self._sprite_rows_var.set(row_max)
            except Exception:
                self._sprite_rows_spin.configure(from_=1, to=9999)
        else:
            self._sprite_layout_row.grid_remove()
            self._sprite_pal_override_row.grid_remove()
            self._gfx_sprite_anchor_name = None

        logs: List[str] = []
        if tbl_warn:
            logs.append(tbl_warn)
        if spec.kind == "palette":
            self._hide_palette_4_ui()
            self._hide_palette_8_ui()
            if spec.bpp == 4:
                raw = bytes(
                    rom[
                        blob_off : blob_off
                        + min(len(rom) - blob_off, 1 << 20)
                    ]
                )
                try:
                    pal_bytes = extract_palette_bytes(spec, raw)
                except ValueError as e:
                    self._emit_gfx_decode_log(f"Palette extract error: {e}")
                    self._clear_image()
                    return
                self._pal4_state = (spec, pal_bytes)
                d0 = spec.palette_4_indices[0] if spec.palette_4_indices else 0
                self._pal4_index_combo.set(str(d0))
                if spec.palette_4_indices:
                    hx = " ".join(format(i, "X") for i in spec.palette_4_indices)
                    self._pal4_toml_hint.configure(
                        text=f"Chunks map to palette indices (hex digits): {hx}"
                    )
                else:
                    self._pal4_toml_hint.configure(text="Plain ucp4 → ROM chunk is index 0 only")
                self._pal4_row.grid()
                self._pal4_canvas.grid()
                self._refresh_palette_4_swatches()
            elif spec.bpp == 8:
                raw = bytes(
                    rom[
                        blob_off : blob_off
                        + min(len(rom) - blob_off, 1 << 20)
                    ]
                )
                try:
                    pal_bytes = extract_palette_bytes(spec, raw)
                except ValueError as e:
                    self._emit_gfx_decode_log(f"Palette extract error: {e}")
                    self._clear_image()
                    return
                pal_bytes = palette_bytes_for_gbagfx(spec, pal_bytes)
                self._pal8_colors = raw_gba_palette_to_rgb888_list(pal_bytes)
                n8 = len(self._pal8_colors)
                self._pal8_title.configure(text=f"8bpp palette ({n8} colors):")
                self._pal8_row.grid()
                self._pal8_outer.grid()
                self._refresh_palette_8_swatches()
            pal_path, log = decode_palette_to_png_pal(bytes(rom), blob_off, spec)
            logs.append(log)
            self._emit_gfx_decode_log("\n".join(logs))
            if pal_path:
                self._try_show_image(pal_path)
            else:
                self._clear_image("(palette PNG not produced)")
            return
        self._hide_palette_4_ui()
        self._hide_palette_8_ui()
        ext_ps: Optional[Any] = None
        ext_pb: Optional[int] = None
        ext_ts_spec: Optional[Any] = None
        ext_ts_off: Optional[int] = None
        log_pre = ""

        if spec.kind == "tilemap":
            tsn = getattr(spec, "tileset_anchor_name", None) or ""
            ga_ts = self._hex.find_graphics_anchor_by_name(tsn.strip()) if tsn.strip() else None
            if ga_ts is None or ga_ts["spec"].kind != "sprite":
                self._emit_gfx_decode_log(
                    log_pre
                    + (
                        f"Tilemap needs a tile sheet NamedAnchor (uct/lzt/ucs/lzs…); "
                        f"missing or invalid: {tsn!r}\n"
                    )
                )
                self._clear_image("(tilemap needs valid tileset anchor)")
                return
            ext_ts_spec = ga_ts["spec"]
            ext_ts_off = int(ga_ts["base_off"])
            if ga_ts.get("graphics_table"):
                ext_ts_off = ga_ts["base_off"] + tbl_idx * int(ga_ts["row_byte_size"])
            pan = getattr(spec, "palette_anchor_name", None)
            if not pan:
                pan = getattr(ga_ts["spec"], "palette_anchor_name", None)
            if pan:
                ext_ps, ext_pb, pal_notes = self._hex.resolve_palette_for_graphics_row(pan.strip(), tbl_idx)
                if ext_ps is None or ext_pb is None:
                    dpal = "16-color" if spec.bpp == 4 else "256-color"
                    log_pre = (
                        (pal_notes or f"Warning: could not resolve palette {pan!r}.\n")
                        + f"Using default {dpal} palette.\n\n"
                    )
                else:
                    log_pre = pal_notes or ""
            png_path, log = decode_graphics_anchor_to_png(
                bytes(rom),
                blob_off,
                spec,
                external_palette_spec=ext_ps,
                external_palette_base_off=ext_pb,
                external_tileset_spec=ext_ts_spec,
                external_tileset_base_off=ext_ts_off,
            )
            logs.append(log_pre + log)
            self._emit_gfx_decode_log("\n".join(logs))
            if png_path:
                self._try_show_image(png_path)
            else:
                self._clear_image("(tilemap PNG not produced)")
            return

        override_pal_bytes: Optional[bytes] = None
        if spec.kind == "sprite" and self._sprite_palette_override is not None:
            ov_off, ov_bpp, ov_lz = self._sprite_palette_override
            if ov_bpp != spec.bpp:
                logs.append(
                    f"Preview palette override ignored: loaded {ov_bpp}bpp data but this sprite is {spec.bpp}bpp.\n"
                )
            else:
                raw_ov, oerr = read_sprite_preview_palette_at_rom_offset(
                    bytes(rom), ov_off, ov_bpp, lz77=ov_lz
                )
                if raw_ov is None:
                    logs.append(f"Preview palette override: {oerr}\n")
                else:
                    override_pal_bytes = raw_ov
                    src = "LZ77→" if ov_lz else "raw "
                    logs.append(
                        f"Preview palette: {src}file offset 0x{ov_off:X} ({ov_bpp}bpp, {len(raw_ov)} bytes); "
                        f"linked |palette ignored for preview.\n"
                    )

        if spec.kind == "sprite" and getattr(spec, "palette_anchor_name", None) and override_pal_bytes is None:
            pan = spec.palette_anchor_name
            ext_ps, ext_pb, pal_notes = self._hex.resolve_palette_for_graphics_row(pan, tbl_idx)
            if ext_ps is None or ext_pb is None:
                dpal = "64-color (empty)" if spec.bpp == 6 else "16-color"
                log_pre = (
                    (pal_notes or f"Warning: could not resolve palette {pan!r}.\n")
                    + f"Using default {dpal} palette.\n\n"
                )
            else:
                log_pre = pal_notes or ""
        layout_h = max(1, int(self._sprite_rows_var.get()))
        png_path, log = decode_graphics_anchor_to_png(
            bytes(rom),
            blob_off,
            spec,
            external_palette_spec=ext_ps,
            external_palette_base_off=ext_pb,
            sprite_layout_height=layout_h,
            override_sprite_palette_bytes=override_pal_bytes,
        )
        logs.append(log_pre + log)
        self._emit_gfx_decode_log("\n".join(logs))
        if png_path:
            self._try_show_image(png_path)
        else:
            self._clear_image("(sprite PNG not produced)")

    def _on_sprite_preview_palette_load(self) -> None:
        name = _graphics_combo_entry_to_anchor_name(self._combo.get().strip())
        if not name:
            messagebox.showinfo("Preview palette", "Select a graphics NamedAnchor first.")
            return
        rom = self._hex.get_data()
        if not rom:
            messagebox.showwarning("Preview palette", "No ROM loaded.")
            return
        info = next((a for a in self._hex.get_graphics_anchors() if str(a["name"]) == name), None)
        if not info or info["spec"].kind != "sprite":
            messagebox.showinfo("Preview palette", "Select a sprite anchor (uct/lzt/ucs/lzs…).")
            return
        sp = info["spec"]
        s = self._sprite_pal_off_var.get().strip()
        direct_off, _ = parse_rom_file_offset(s)
        off, err = self._hex.resolve_file_offset_or_named_anchor(s)
        if off is None:
            messagebox.showwarning("Preview palette", err or "Invalid offset or TOML Name.")
            return
        try:
            pb = int(str(self._sprite_pal_bpp_var.get()))
        except (ValueError, tk.TclError):
            pb = 4
        if pb not in (4, 6, 8):
            messagebox.showwarning("Preview palette", "Select palette mode 4, 6, or 8 bpp.")
            return
        if pb != sp.bpp:
            messagebox.showerror(
                "Preview palette",
                f"This sprite is {sp.bpp}bpp; set the palette mode to {sp.bpp}bpp "
                f"(4→16 colors, 6→64, 8→256).",
            )
            return
        use_lz = str(self._sprite_pal_storage_var.get()).strip().lower() == "lz77"
        raw, rerr = read_sprite_preview_palette_at_rom_offset(bytes(rom), off, pb, lz77=use_lz)
        if raw is None:
            messagebox.showerror("Preview palette", rerr or "Could not read palette bytes.")
            return
        self._sprite_palette_override = (off, pb, use_lz)
        src = "LZ77 at offset" if use_lz else "Raw bytes at"
        loc = (
            f"{src} 0x{off:X}"
            if direct_off is not None
            else f"{src} 0x{off:X} (NamedAnchor {normalize_named_anchor_lookup_key(s)!r})"
        )
        self._sprite_pal_status.configure(
            text=(
                f"{loc} — {pb}bpp preview ({len(raw)} bytes decoded). "
                "Import still writes uncompressed palette bytes unless the anchor uses LZ in TOML."
            ),
            foreground="#060",
        )
        self._gfx_decode_anchor_name = name
        self._decode_selected()

    def _on_sprite_preview_palette_clear(self) -> None:
        self._sprite_palette_override = None
        self._sprite_pal_status.configure(text="")
        self._decode_selected()

    def _gfx_import_write_blob(
        self,
        label: str,
        blob_off: int,
        payload: bytes,
        cap: int,
        *,
        is_table: bool,
        named_anchor_for_reloc: Optional[str],
    ) -> Tuple[bool, str]:
        rom = self._hex.get_data()
        if not rom:
            return False, ""
        if len(payload) <= cap:
            self._hex.write_bytes_at(blob_off, _pad_graphic_slot(payload, cap))
            return True, (
                f"{label}: wrote {len(payload)} byte(s) at file 0x{blob_off:X} "
                f"(padded to {cap} with 0xFF).\n"
            )
        if is_table:
            return (
                False,
                f"{label}: needs {len(payload)} byte(s) but this graphics table row only "
                f"allocates {cap} byte(s).\n",
            )
        old_gba = blob_off + GBA_ROM_BASE
        dlg = _GfxRelocateDialog(
            self.winfo_toplevel(),
            f"Relocate {label}",
            len(payload),
            blob_off,
            blob_off + max(cap, 1),
            self._hex,
            old_gba,
        )
        new_off = dlg.result
        if new_off is None:
            return False, f"{label}: relocate cancelled.\n"
        fill_old = bool(getattr(dlg, "fill_old_slot", False))
        self._hex.write_bytes_at(new_off, payload)
        if fill_old:
            self._hex.write_bytes_at(blob_off, bytes([0xFF]) * cap)
        new_gba = new_off + GBA_ROM_BASE
        excl_ranges: List[Tuple[int, int]] = [
            (blob_off, blob_off + max(cap, 1)),
            (new_off, new_off + len(payload)),
        ]
        ptr_n = self._hex.replace_word_aligned_rom_pointers(
            old_gba, new_gba, exclude_ranges=excl_ranges
        )
        log = (
            f"{label}: wrote {len(payload)} byte(s) at file 0x{new_off:X} "
            f"(GBA 0x{new_gba:08X}).\n"
        )
        if fill_old:
            log += (
                f"{label}: filled original slot ({cap} byte(s) at file 0x{blob_off:X}) with 0xFF.\n"
            )
        log += (
            f"{label}: updated {ptr_n} word-aligned pointer(s) "
            f"0x{old_gba:08X} → 0x{new_gba:08X} (ROM scan; old/new blob regions excluded).\n"
        )
        if named_anchor_for_reloc:
            ok, err = self._hex.update_named_anchor_gba_address(
                named_anchor_for_reloc, new_off + GBA_ROM_BASE
            )
            if ok:
                log += (
                    f"{label}: updated NamedAnchor {named_anchor_for_reloc!r} Address → "
                    f"0x{new_off + GBA_ROM_BASE:08X}.\n"
                )
            else:
                log += f"{label}: ROM updated but TOML Address not saved ({err}).\n"
                messagebox.showwarning(
                    "Import graphic",
                    f"{label} was written at file 0x{new_off:X}, but the TOML could not be updated:\n{err}",
                )
        else:
            log += (
                f"{label}: no NamedAnchor to auto-repoint; update ROM pointers or TOML manually if needed.\n"
            )
        return True, log

    def _on_import_graphic(self) -> None:
        name = _graphics_combo_entry_to_anchor_name(self._combo.get().strip())
        if not name:
            messagebox.showinfo("Import graphic", "Select a graphics NamedAnchor first.")
            return
        rom = self._hex.get_data()
        if not rom:
            messagebox.showwarning("Import graphic", "No ROM loaded.")
            return
        info = next((a for a in self._hex.get_graphics_anchors() if str(a["name"]) == name), None)
        if not info:
            messagebox.showerror("Import graphic", "Anchor missing.")
            return
        spec = info["spec"]
        if spec.kind == "tilemap":
            self._import_tilemap_from_png(name, info, spec)
            return
        if spec.kind != "sprite":
            messagebox.showinfo(
                "Import graphic",
                "Import is only implemented for sprite (uct/lzt/ucs/lzs…) or tilemap (ucm/lzm…) anchors, not palette-only.",
            )
            return
        if spec.bpp not in (4, 6, 8):
            messagebox.showinfo("Import graphic", f"{spec.bpp}bpp sprite import is not supported.")
            return
        tbl_idx, _eff, _ = self._effective_table_state(info)
        blob_off = int(info["base_off"])
        if info.get("graphics_table"):
            blob_off = int(info["base_off"]) + tbl_idx * int(info["row_byte_size"])
        is_table = bool(info.get("graphics_table"))
        table_row_b = int(info["row_byte_size"]) if is_table else None

        path = filedialog.askopenfilename(
            title="Import PNG",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if not path:
            return

        if spec.bpp == 6:
            wt0, ht0 = int(spec.width_tiles), int(spec.height_tiles)
            if wt0 <= 0 or ht0 <= 0:
                messagebox.showinfo(
                    "Import graphic",
                    "6bpp import needs a fixed WxH in TOML (e.g. uct6x8x8 or ucs6x4x4), not a variable-length strip.",
                )
                return
            tile_bytes, flat_pal, err, tw, th = sprite_import_png_manual(
                path,
                bpp=6,
                width_tiles=wt0,
                height_tiles=ht0,
                palette_color_count=64,
            )
            log_intro = (
                f"Import: 6bpp with index 0 = transparent #00FF00; quantized to 63 solid colors; "
                f"{tw}×{th} tiles ({tw * 8}×{th * 8} px).\n"
            )
        else:
            tile_bytes, flat_pal, err, tw, th = sprite_import_png(path, spec)
            log_intro = (
                f"Import: PNG pixel size → {tw}×{th} tiles ({tw * 8}×{th * 8} px canvas); "
                f"not resized to match the TOML / preview window.\n"
            )
        if err:
            messagebox.showerror("Import graphic", err)
            return

        try:
            sprite_cap = measure_sprite_rom_footprint(
                bytes(rom), blob_off, spec, graphics_table_row_bytes=table_row_b
            )
        except ValueError as e:
            messagebox.showerror("Import graphic", str(e))
            return

        sprite_payload = build_sprite_payload_for_rom(tile_bytes, spec, lz=spec.lz)
        logs: List[str] = [log_intro]

        ok_s, log_s = self._gfx_import_write_blob(
            "Sprite",
            blob_off,
            sprite_payload,
            sprite_cap,
            is_table=is_table,
            named_anchor_for_reloc=None if is_table else name,
        )
        logs.append(log_s)
        if not ok_s:
            self._set_log("".join(logs))
            messagebox.showerror("Import graphic", "Sprite import failed; see decode log.")
            return

        def _should_rewrite_sprite_format(sp: Any, w: int, h: int) -> bool:
            if getattr(sp, "kind", None) != "sprite":
                return False
            if sp.width_tiles == 0 and sp.height_tiles == 0:
                return True
            return (w, h) != (int(sp.width_tiles), int(sp.height_tiles))

        if _should_rewrite_sprite_format(spec, tw, th):
            cur_fmt = str(info["anchor"].get("Format", "") or "")
            new_fmt = rewrite_standalone_sprite_format_dimensions(cur_fmt, tw, th)
            if new_fmt:
                info["anchor"]["Format"] = new_fmt
                ok_toml, err_toml = self._hex.persist_toml_data()
                if ok_toml:
                    if self._hex.reload_toml_from_disk():
                        logs.append(
                            f"TOML: Format updated for {name!r} to {tw}×{th} tiles; structure file reloaded.\n"
                        )
                        info2 = next(
                            (a for a in self._hex.get_graphics_anchors() if str(a["name"]) == name),
                            None,
                        )
                        if info2:
                            info = info2
                            spec = info2["spec"]
                    else:
                        logs.append("TOML: Format saved but reload from disk failed.\n")
                else:
                    logs.append(f"TOML: could not save updated Format ({err_toml}).\n")
            else:
                logs.append(
                    "TOML: could not auto-rewrite Format for this anchor; set WxH in the TOML manually if needed.\n"
                )

        pan = getattr(spec, "palette_anchor_name", None)
        ov = self._sprite_palette_override
        use_pal_override = ov is not None and ov[1] == spec.bpp
        if use_pal_override:
            linked = pan.strip() if pan else ""
            lz_note = ""
            if ov[2]:
                lz_note = (
                    "\n\nPreview was loaded from LZ77 at that offset; import still writes an "
                    "**uncompressed** palette body there (same as raw preview imports)."
                )
            messagebox.showinfo(
                "Import graphic",
                "A preview palette ROM offset is active.\n\n"
                "The imported palette will be written to file offset "
                f"0x{ov[0]:08X} (GBA 0x{ov[0] + GBA_ROM_BASE:08X}), "
                "not to the linked |palette NamedAnchor"
                + (f" ({linked!r})." if linked else ".")
                + lz_note,
            )

        if spec.bpp == 8:
            if use_pal_override:
                ext_ps = synthetic_palette_spec_for_sprite_import_write(8)
                ext_pb = int(ov[0])
                try:
                    pal_cap = measure_palette_rom_footprint(
                        bytes(rom), ext_pb, ext_ps, graphics_table_row_bytes=None
                    )
                except ValueError as e:
                    self._set_log("".join(logs))
                    messagebox.showerror("Import graphic", str(e))
                    return
                pal_body = prepare_palette_rom_body_from_import(ext_ps, flat_pal)
                pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=ext_ps.lz)
                pal_cap = max(pal_cap, len(pal_payload))
                ok_p, log_p = self._gfx_import_write_blob(
                    "Palette",
                    ext_pb,
                    pal_payload,
                    pal_cap,
                    is_table=False,
                    named_anchor_for_reloc=None,
                )
                logs.append(log_p)
                if not ok_p:
                    self._set_log("".join(logs))
                    messagebox.showerror(
                        "Import graphic",
                        "Palette import failed; sprite data may already be written. See decode log.",
                    )
                    return
            elif not pan:
                messagebox.showerror(
                    "Import graphic",
                    "8bpp sprites need a linked palette NamedAnchor (|palette… in TOML), "
                    "or load a preview palette from a ROM offset (8 bpp / 256 colors).",
                )
                self._set_log("".join(logs))
                return
            else:
                ext_ps, ext_pb, _paln = self._hex.resolve_palette_for_graphics_row(pan.strip(), tbl_idx)
                if ext_ps is None or ext_pb is None:
                    messagebox.showerror("Import graphic", "Could not resolve 8bpp palette data in ROM.")
                    self._set_log("".join(logs))
                    return
                ga_p = self._hex.find_graphics_anchor_by_name(pan.strip())
                pal_table_b = int(ga_p["row_byte_size"]) if ga_p and ga_p.get("graphics_table") else None
                pal_is_table = bool(ga_p and ga_p.get("graphics_table"))
                try:
                    pal_cap = measure_palette_rom_footprint(
                        bytes(rom), ext_pb, ext_ps, graphics_table_row_bytes=pal_table_b
                    )
                except ValueError as e:
                    self._set_log("".join(logs))
                    messagebox.showerror("Import graphic", str(e))
                    return
                pal_body = prepare_palette_rom_body_from_import(ext_ps, flat_pal)
                pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=ext_ps.lz)
                pal_cap = max(pal_cap, len(pal_payload))
                pal_anchor_name = pan.strip() if ga_p and ga_p["spec"].kind == "palette" else None
                if pal_anchor_name and pal_is_table:
                    pal_anchor_name = None
                ok_p, log_p = self._gfx_import_write_blob(
                    "Palette",
                    ext_pb,
                    pal_payload,
                    pal_cap,
                    is_table=pal_is_table,
                    named_anchor_for_reloc=pal_anchor_name,
                )
                logs.append(log_p)
                if not ok_p:
                    self._set_log("".join(logs))
                    messagebox.showerror(
                        "Import graphic",
                        "Palette import failed; sprite data may already be written. See decode log.",
                    )
                    return
        elif spec.bpp == 6:
            if use_pal_override:
                ext_ps = synthetic_palette_spec_for_sprite_import_write(6)
                ext_pb = int(ov[0])
                try:
                    pal_cap = measure_palette_rom_footprint(
                        bytes(rom), ext_pb, ext_ps, graphics_table_row_bytes=None
                    )
                except ValueError as e:
                    self._set_log("".join(logs))
                    messagebox.showerror("Import graphic", str(e))
                    return
                pal_body = prepare_palette_rom_body_from_import(ext_ps, flat_pal)
                pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=ext_ps.lz)
                pal_cap = max(pal_cap, len(pal_payload))
                ok_p, log_p = self._gfx_import_write_blob(
                    "Palette",
                    ext_pb,
                    pal_payload,
                    pal_cap,
                    is_table=False,
                    named_anchor_for_reloc=None,
                )
                logs.append(log_p)
                if not ok_p:
                    self._set_log("".join(logs))
                    messagebox.showerror(
                        "Import graphic",
                        "Palette import failed; sprite data may already be written. See decode log.",
                    )
                    return
            elif not pan:
                messagebox.showerror(
                    "Import graphic",
                    "6bpp sprites need a linked palette NamedAnchor (|palette… in TOML), "
                    "or load a preview palette from a ROM offset (6 bpp / 64 colors).",
                )
                self._set_log("".join(logs))
                return
            else:
                ext_ps, ext_pb, _paln = self._hex.resolve_palette_for_graphics_row(pan.strip(), tbl_idx)
                if ext_ps is None or ext_pb is None:
                    messagebox.showerror("Import graphic", "Could not resolve 6bpp palette data in ROM.")
                    self._set_log("".join(logs))
                    return
                ga_p = self._hex.find_graphics_anchor_by_name(pan.strip())
                pal_table_b = int(ga_p["row_byte_size"]) if ga_p and ga_p.get("graphics_table") else None
                pal_is_table = bool(ga_p and ga_p.get("graphics_table"))
                try:
                    pal_cap = measure_palette_rom_footprint(
                        bytes(rom), ext_pb, ext_ps, graphics_table_row_bytes=pal_table_b
                    )
                except ValueError as e:
                    self._set_log("".join(logs))
                    messagebox.showerror("Import graphic", str(e))
                    return
                pal_body = prepare_palette_rom_body_from_import(ext_ps, flat_pal)
                pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=ext_ps.lz)
                pal_cap = max(pal_cap, len(pal_payload))
                pal_anchor_name = pan.strip() if ga_p and ga_p["spec"].kind == "palette" else None
                if pal_anchor_name and pal_is_table:
                    pal_anchor_name = None
                ok_p, log_p = self._gfx_import_write_blob(
                    "Palette",
                    ext_pb,
                    pal_payload,
                    pal_cap,
                    is_table=pal_is_table,
                    named_anchor_for_reloc=pal_anchor_name,
                )
                logs.append(log_p)
                if not ok_p:
                    self._set_log("".join(logs))
                    messagebox.showerror(
                        "Import graphic",
                        "Palette import failed; sprite data may already be written. See decode log.",
                    )
                    return
        elif spec.bpp == 4:
            if use_pal_override:
                ext_ps = synthetic_palette_spec_for_sprite_import_write(4)
                ext_pb = int(ov[0])
                try:
                    pal_cap = measure_palette_rom_footprint(
                        bytes(rom), ext_pb, ext_ps, graphics_table_row_bytes=None
                    )
                except ValueError as e:
                    self._set_log("".join(logs))
                    messagebox.showerror("Import graphic", str(e))
                    return
                pal_body = prepare_palette_rom_body_from_import(ext_ps, flat_pal)
                pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=ext_ps.lz)
                pal_cap = max(pal_cap, len(pal_payload))
                ok_p, log_p = self._gfx_import_write_blob(
                    "Palette",
                    ext_pb,
                    pal_payload,
                    pal_cap,
                    is_table=False,
                    named_anchor_for_reloc=None,
                )
                logs.append(log_p)
                if not ok_p:
                    self._set_log("".join(logs))
                    messagebox.showerror(
                        "Import graphic",
                        "Palette import failed; sprite data may already be written. See decode log.",
                    )
                    return
            elif pan:
                ext_ps, ext_pb, pal_notes = self._hex.resolve_palette_for_graphics_row(pan.strip(), tbl_idx)
                if ext_ps is None or ext_pb is None:
                    logs.append(pal_notes or "Palette not resolved; skipped palette write.\n")
                else:
                    ga_p = self._hex.find_graphics_anchor_by_name(pan.strip())
                    pal_table_b = int(ga_p["row_byte_size"]) if ga_p and ga_p.get("graphics_table") else None
                    pal_is_table = bool(ga_p and ga_p.get("graphics_table"))
                    try:
                        pal_cap = measure_palette_rom_footprint(
                            bytes(rom), ext_pb, ext_ps, graphics_table_row_bytes=pal_table_b
                        )
                    except ValueError as e:
                        self._set_log("".join(logs))
                        messagebox.showerror("Import graphic", str(e))
                        return
                    pal_body = prepare_palette_rom_body_from_import(ext_ps, flat_pal)
                    pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=ext_ps.lz)
                    pal_cap = max(pal_cap, len(pal_payload))
                    pal_anchor_name = pan.strip() if ga_p and ga_p["spec"].kind == "palette" else None
                    if pal_anchor_name and pal_is_table:
                        pal_anchor_name = None
                    ok_p, log_p = self._gfx_import_write_blob(
                        "Palette",
                        ext_pb,
                        pal_payload,
                        pal_cap,
                        is_table=pal_is_table,
                        named_anchor_for_reloc=pal_anchor_name,
                    )
                    logs.append(log_p)
                    if not ok_p:
                        self._set_log("".join(logs))
                        messagebox.showerror(
                            "Import graphic",
                            "Palette import failed; sprite data may already be written. See decode log.",
                        )
                        return
            else:
                logs.append(
                    "No |palette anchor on this sprite: tiles imported; preview uses default grayscale palette.\n"
                )

        self._gfx_decode_log_prefix = "".join(logs) + "\nRe-decoding preview…\n\n"
        self._decode_selected()

    def _import_tilemap_from_png(self, name: str, info: Dict[str, Any], spec: Any) -> None:
        """
        Tilemap Studio–style import: one PNG (full map at 8 px/tile) → deduped tileset + non-affine map + palette.

        Writes the tileset NamedAnchor blob, this tilemap blob, and the linked palette anchor when resolvable.
        """
        rom = self._hex.get_data()
        if not rom:
            messagebox.showwarning("Import tilemap", "No ROM loaded.")
            return
        if spec.bpp not in (4, 8):
            messagebox.showinfo("Import tilemap", "Only 4bpp or 8bpp tilemaps are supported.")
            return

        tsn = getattr(spec, "tileset_anchor_name", None) or ""
        ga_ts = self._hex.find_graphics_anchor_by_name(tsn.strip()) if tsn.strip() else None
        if ga_ts is None or ga_ts["spec"].kind != "sprite":
            messagebox.showerror(
                "Import tilemap",
                f"Tilemap needs a valid tile sheet NamedAnchor (uct/lzt/ucs/lzs…); missing or invalid: {tsn!r}",
            )
            return
        ts_spec = ga_ts["spec"]
        if ts_spec.bpp not in (4, 8):
            messagebox.showinfo("Import tilemap", "Tileset must be 4bpp or 8bpp for this import path.")
            return
        if ts_spec.bpp != spec.bpp:
            messagebox.showerror(
                "Import tilemap",
                f"Tilemap is {spec.bpp}bpp but tileset {tsn!r} is {ts_spec.bpp}bpp; they must match.",
            )
            return

        tbl_idx, _eff, tbl_warn = self._effective_table_state(info)
        blob_off_map = int(info["base_off"])
        if info.get("graphics_table"):
            blob_off_map = int(info["base_off"]) + tbl_idx * int(info["row_byte_size"])
        is_table_tm = bool(info.get("graphics_table"))
        table_row_b_tm = int(info["row_byte_size"]) if is_table_tm else None

        ts_off = int(ga_ts["base_off"])
        if ga_ts.get("graphics_table"):
            ts_off = int(ga_ts["base_off"]) + tbl_idx * int(ga_ts["row_byte_size"])
        is_table_ts = bool(ga_ts.get("graphics_table"))
        table_row_b_ts = int(ga_ts["row_byte_size"]) if is_table_ts else None

        pan_tm = getattr(spec, "palette_anchor_name", None)
        if not pan_tm:
            pan_tm = getattr(ts_spec, "palette_anchor_name", None)
        pan_key = pan_tm.strip() if pan_tm else ""

        if spec.bpp == 8 and not pan_key:
            messagebox.showerror(
                "Import tilemap",
                "8bpp tilemaps need a linked palette NamedAnchor (|palette… on tilemap or tileset).",
            )
            return

        try:
            map_cap = measure_tilemap_rom_footprint(
                bytes(rom), blob_off_map, spec, graphics_table_row_bytes=table_row_b_tm
            )
        except ValueError as e:
            messagebox.showerror("Import tilemap", str(e))
            return

        try:
            ts_cap = measure_sprite_rom_footprint(
                bytes(rom), ts_off, ts_spec, graphics_table_row_bytes=table_row_b_ts
            )
        except ValueError as e:
            messagebox.showerror(
                "Import tilemap",
                f"Could not size the tileset slot ({e}). Use a fixed uct/ucs WxH or LZ (lzt/lzs) in TOML.",
            )
            return

        path = filedialog.askopenfilename(
            title="Import tilemap PNG",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if not path:
            return

        mw, mh = int(spec.map_w_tiles), int(spec.map_h_tiles)
        tm_kw: Dict[str, Any] = {
            "map_w_tiles": mw,
            "map_h_tiles": mh,
            "bpp": spec.bpp,
        }
        if int(spec.bpp) == 8:
            tm_kw["palette_color_count"] = 256
        qpal = bool(self._tilemap_quantize_palette_var.get())
        tm_kw["preserve_exact_palette"] = not qpal
        tm_kw["reduce_palette"] = qpal
        raw_map, tile_body, pal_flat, n_unique, err = tilemap_png_to_tileset_map_palette(path, **tm_kw)
        if err:
            messagebox.showerror("Import tilemap", err)
            return

        logs: List[str] = [
            tbl_warn or "",
            "Import tilemap: PNG → deduped tileset + non-affine map (Tilemap Studio–style image→tiles; "
            "see https://github.com/Rangi42/tilemap-studio ).\n",
            f"  Unique tiles after dedupe (incl. flips): {n_unique} (hardware limit 1024).\n",
        ]
        _tilemap_import_debug(
            logs,
            "png_decode",
            bpp=int(spec.bpp),
            map_tiles=f"{mw}x{mh}",
            palette_color_count=tm_kw.get("palette_color_count"),
            len_pal_flat=len(pal_flat),
            len_tile_body=len(tile_body),
            len_raw_map=len(raw_map),
            n_unique=n_unique,
            pan_key=pan_key or "",
            tileset_anchor=tsn.strip(),
        )

        try:
            map_payload = build_tilemap_payload_for_rom(raw_map, spec)
        except ValueError as e:
            messagebox.showerror("Import tilemap", str(e))
            return

        try:
            ts_payload = build_sprite_payload_for_rom(tile_body, ts_spec, lz=ts_spec.lz)
        except ValueError as e:
            messagebox.showerror("Import tilemap", f"Tileset compress: {e}")
            return

        ts_name = str(ga_ts["name"])

        ok_ts, log_ts = self._gfx_import_write_blob(
            "Tileset",
            ts_off,
            ts_payload,
            ts_cap,
            is_table=is_table_ts,
            named_anchor_for_reloc=None if is_table_ts else ts_name,
        )
        logs.append(log_ts)
        if not ok_ts:
            self._set_log("".join(logs))
            messagebox.showerror("Import tilemap", "Tileset write failed; see decode log.")
            return

        ok_m, log_m = self._gfx_import_write_blob(
            "Tilemap",
            blob_off_map,
            map_payload,
            map_cap,
            is_table=is_table_tm,
            named_anchor_for_reloc=None if is_table_tm else name,
        )
        logs.append(log_m)
        if not ok_m:
            self._set_log("".join(logs))
            messagebox.showerror(
                "Import tilemap",
                "Tilemap write failed; tileset may already be written. See decode log.",
            )
            return

        if pan_key:
            ext_ps, ext_pb, pal_notes = self._hex.resolve_palette_for_graphics_row(pan_key, tbl_idx)
            if ext_ps is None or ext_pb is None:
                logs.append(pal_notes or "Palette not resolved; skipped palette write.\n")
            else:
                ga_p = self._hex.find_graphics_anchor_by_name(pan_key)
                pal_table_b = int(ga_p["row_byte_size"]) if ga_p and ga_p.get("graphics_table") else None
                pal_is_table = bool(ga_p and ga_p.get("graphics_table"))
                rom_now = self._hex.get_data()
                try:
                    pal_cap = measure_palette_rom_footprint(
                        bytes(rom_now or b""),
                        ext_pb,
                        ext_ps,
                        graphics_table_row_bytes=pal_table_b,
                    )
                except ValueError as e:
                    self._set_log("".join(logs))
                    messagebox.showerror("Import tilemap", str(e))
                    return
                need_before = palette_byte_count_for_spec(ext_ps)
                u8_sfx = ""
                if ext_ps.kind == "palette" and ext_ps.bpp == 8:
                    try:
                        u8_sfx = effective_ucp8_palette_hex_suffix(ext_ps)
                    except ValueError:
                        u8_sfx = "(error)"
                _tilemap_import_debug(
                    logs,
                    "palette_before_prepare",
                    anchor=pan_key,
                    bpp=int(ext_ps.bpp),
                    kind=str(ext_ps.kind),
                    lz=bool(ext_ps.lz),
                    palette_hex_digit=getattr(ext_ps, "palette_hex_digit", None),
                    effective_ucp8_suffix=u8_sfx,
                    need_bytes_spec=need_before,
                    len_pal_flat=len(pal_flat),
                    pal_cap_measure=pal_cap,
                )
                pal_body = prepare_palette_rom_body_from_import(ext_ps, pal_flat)
                pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=ext_ps.lz)
                pal_cap = max(pal_cap, len(pal_payload))
                _tilemap_import_debug(
                    logs,
                    "palette_after_pack",
                    len_pal_body=len(pal_body),
                    len_pal_payload=len(pal_payload),
                    pal_cap_final=pal_cap,
                )
                pal_anchor_name = pan_key if ga_p and ga_p["spec"].kind == "palette" else None
                if pal_anchor_name and pal_is_table:
                    pal_anchor_name = None
                ok_p, log_p = self._gfx_import_write_blob(
                    "Palette",
                    ext_pb,
                    pal_payload,
                    pal_cap,
                    is_table=pal_is_table,
                    named_anchor_for_reloc=pal_anchor_name,
                )
                logs.append(log_p)
                if not ok_p:
                    self._set_log("".join(logs))
                    messagebox.showerror(
                        "Import tilemap",
                        "Palette write failed; tileset/tilemap may already be written. See decode log.",
                    )
                    return
        else:
            logs.append("No |palette anchor: tileset + map written; palette bytes not written.\n")

        # Tileset TOML: single strip (W×1) so tools resolve dimensions from unique tile count.
        tw, th = max(1, int(n_unique)), 1

        def _should_rewrite_tileset_grid(sp: Any, w: int, h: int) -> bool:
            if getattr(sp, "kind", None) != "sprite":
                return False
            if sp.width_tiles == 0 and sp.height_tiles == 0:
                return True
            return (w, h) != (int(sp.width_tiles), int(sp.height_tiles))

        if _should_rewrite_tileset_grid(ts_spec, tw, th):
            cur_fmt = str(ga_ts["anchor"].get("Format", "") or "")
            new_fmt = rewrite_standalone_sprite_format_dimensions(cur_fmt, tw, th)
            if new_fmt:
                ga_ts["anchor"]["Format"] = new_fmt
                ok_toml, err_toml = self._hex.persist_toml_data()
                if ok_toml:
                    if self._hex.reload_toml_from_disk():
                        logs.append(
                            f"TOML: Tileset {ts_name!r} Format → {tw}×{th} tiles ({n_unique} unique); reloaded.\n"
                        )
                    else:
                        logs.append("TOML: tileset Format saved but reload from disk failed.\n")
                else:
                    logs.append(f"TOML: could not save tileset Format ({err_toml}).\n")
            else:
                logs.append(
                    "TOML: could not auto-rewrite tileset Format; adjust WxH manually if preview is wrong.\n"
                )

        self._gfx_decode_log_prefix = "".join(logs) + "\nRe-decoding preview…\n\n"
        self._decode_selected()


def _split_enum_field_ref(enum_ref: Optional[str]) -> Tuple[str, int]:
    """
    Parse ``listname`` or ``listname+3`` / ``foo.bar-2`` (trailing ``±`` integer only; base is ``[\\w.]+``).

    ROM stores ``idx``; labels / PCS rows use ``idx + delta`` (forward with ``+``, backward with ``-``).
    Leading ``.`` on the base is stripped so Format paths like ``.attributes`` match TOML ``Name = "attributes"``.
    """
    if not enum_ref:
        return "", 0
    s = str(enum_ref).strip()
    m = re.match(r"^([\w.]+)([+-]\d+)$", s)
    if m:
        base = m.group(1).strip().lstrip(".")
        return base, int(m.group(2))
    return s.lstrip("."), 0


def parse_struct_tree_iid(iid: str) -> Tuple[int, Any]:
    """Parse tree row id: ``sf_3`` → (3, None); ``sf_3_b0`` → (3, 0);
    ``sf_na_5_0_2`` → (5, (\"na\", 0, 2)); ``sf_nab_5_0_2_1`` → (5, (\"nab\", 0, 2, 1))."""
    if not iid.startswith("sf_"):
        return -1, None
    rest = iid[3:]
    if rest.startswith("nab_"):
        sub = rest[4:]
        parts = sub.split("_")
        if len(parts) >= 4:
            try:
                return int(parts[0]), ("nab", int(parts[1]), int(parts[2]), int(parts[3]))
            except ValueError:
                return -1, None
    if rest.startswith("na_"):
        sub = rest[3:]
        parts = sub.split("_")
        if len(parts) >= 3:
            try:
                return int(parts[0]), ("na", int(parts[1]), int(parts[2]))
            except ValueError:
                return -1, None
    if "_b" in rest:
        a, b = rest.split("_b", 1)
        try:
            return int(a), int(b)
        except ValueError:
            return -1, None
    try:
        return int(rest), None
    except ValueError:
        return -1, None


def _struct_tree_spec_is_nested(spec: Any) -> bool:
    """True if ``parse_struct_tree_iid`` returned a nested-array row id (``na`` / ``nab``)."""
    return isinstance(spec, tuple) and len(spec) > 0 and spec[0] in ("na", "nab")


def _normalize_bitfield_token_spacing(token: str) -> str:
    """Collapse stray spaces around ``|t|`` so ``evs: |t| hp:`` still tokenizes like ``evs:|t|hp:``."""
    t = token.strip()
    t = re.sub(r"\s+\|t\|", "|t|", t)
    t = re.sub(r"\|t\|\s+", "|t|", t)
    return t


def _parse_bitfield_segment_spec(seg: str) -> Optional[Tuple[str, int, Optional[str]]]:
    """Parse one bitfield subfield: ``name`` + ``[.:]+`` width run + optional enum identifier.

    **Every** ``.`` and ``:`` between the field name and the enum name is a width character
    (``.`` = 1 bit, ``:`` = 2 bits). The first ``\\w`` character after the width run starts the enum ref.

    Examples (name, bits, enum):
      ``stars::``                          → (stars, 4, None)
      ``defn::::.``                        → (defn, 9, None)
      ``type:types``                       → (type, 2, types)
      ``race::.races``                     → (race, 5, races)       — the ``.`` before ``races`` is 1 width bit
      ``attribute:.attributes``            → (attribute, 3, attributes)
      ``color:::.bodycolors``              → (color, 7, bodycolors)
      ``move::::.data.pokemon.moves.names`` → (move, 9, data.pokemon.moves.names)

    Third tuple element is the enum ref for :meth:`StructEditorFrame._resolve_enum`, or None."""
    seg = seg.strip()
    if not seg:
        return None
    m = re.match(r"^(\w+)([.:]+)(\w[\w.]*(?:[+-]\d+)?)?$", seg)
    if not m:
        return None
    sub_name = m.group(1)
    sch = m.group(2)
    nbits = sum(1 if c == "." else 2 for c in sch)
    if nbits <= 0:
        return None
    enum_ref = m.group(3) if m.group(3) else None
    return (sub_name, nbits, enum_ref)


def _parse_bitfield_token(token: str) -> Optional[Dict[str, Any]]:
    """Parse bitfield tokens. Storage width before ``|t|`` matches uints: ``.`` = 1 byte, ``:`` = 2 bytes per colon
    (e.g. ``field.|t|`` = 1 byte, ``field:|t|`` = 2 bytes, ``field::|t|`` = 4 bytes). After ``|t|``, subfields are
    ``|``-separated; every ``.`` = 1 bit and every ``:`` = 2 bits in the width run between name and enum identifier
    (e.g. ``race::.races`` = 5 bits + enum ``races``; ``color:::.bodycolors`` = 7 bits + enum ``bodycolors``).
    Subfields may sum to fewer bits than the storage size; the rest is implicit padding (kept on write).

    If the head uses a single ``.`` (1 byte) but subfields need 9–16 bits, storage is promoted to **2 bytes**
    (same as ``field:|t|``) so ``evs.|t|hp:|…`` still parses when the intent was ``evs:|t|…``."""
    if "|t|" not in token:
        return None
    token = _normalize_bitfield_token_spacing(token)
    head, tail = token.split("|t|", 1)
    head, tail = head.strip(), tail.strip()
    if not head or not tail:
        return None
    hm = re.match(r"^(\w+)([.:]+)$", head)
    if not hm:
        return None
    base_name = hm.group(1)
    size_chars = hm.group(2)
    byte_width = sum(1 if c == "." else 2 for c in size_chars)
    if byte_width <= 0:
        return None

    segments = [x.strip() for x in tail.split("|") if x.strip()]
    if not segments:
        return None
    part_specs: List[Tuple[str, int, Optional[str]]] = []
    for seg in segments:
        parsed_seg = _parse_bitfield_segment_spec(seg)
        if parsed_seg is None:
            return None
        part_specs.append(parsed_seg)
    sum_bits = sum(n for _, n, _e in part_specs)
    if sum_bits <= 0:
        return None

    total_bits = byte_width * 8
    # Promote 1-byte head to 2 bytes when subfields need 9–16 bits (common typo: evs.|t| vs evs:|t|).
    if sum_bits > total_bits and byte_width == 1 and sum_bits <= 16:
        byte_width = 2
        total_bits = byte_width * 8
    if sum_bits > total_bits:
        return None

    parts: List[Dict[str, Any]] = []
    shift = 0
    for sub_name, nbits, sub_enum in part_specs:
        pd: Dict[str, Any] = {"name": sub_name, "bits": nbits, "shift": shift}
        if sub_enum:
            pd["enum"] = sub_enum
        parts.append(pd)
        shift += nbits
    padding_bits = total_bits - shift
    return {
        "name": base_name,
        "size": byte_width,
        "type": "bitfield",
        "enum": None,
        "hex": False,
        "parts": parts,
        "padding_bits": padding_bits,
    }


def _parse_helper_field_token(token: str) -> Optional[Dict[str, Any]]:
    """Parse ``name|=a+b+…`` — computed sum of uint fields; no ROM bytes (size 0)."""
    m = re.match(r"^(\w+)\|=(.+)$", token.strip())
    if not m:
        return None
    name = m.group(1)
    expr = m.group(2).strip()
    if not expr:
        return None
    refs = [p.strip() for p in expr.split("+") if p.strip()]
    if not refs:
        return None
    return {"name": name, "size": 0, "type": "helper", "enum": None, "helper_refs": refs}


def _tokenize_struct_body(inner: str) -> List[str]:
    """Split struct inner on spaces respecting nested ``<>[]()`` depth."""
    tokens: List[str] = []
    buf = ""
    d_angle, d_bracket, d_paren = 0, 0, 0
    for ch in inner:
        if ch == "<":
            d_angle += 1
        elif ch == ">":
            d_angle -= 1
        elif ch == "[":
            d_bracket += 1
        elif ch == "]":
            d_bracket -= 1
        elif ch == "(":
            d_paren += 1
        elif ch == ")":
            d_paren -= 1
        if ch == " " and d_angle == 0 and d_bracket == 0 and d_paren == 0:
            if buf:
                tokens.append(buf)
                buf = ""
        else:
            buf += ch
    if buf:
        tokens.append(buf)
    return tokens


# ``offset<prefix [inner]!HEX>`` — table row is ``offset<>``; prefix + card run live at ``*offset`` (prefix via ``@offset+N``, cards via ``*offset+N``).
_OFFSET_ANGLE_INLINE_NESTED_RUN_RE = re.compile(
    r"offset<\s*(.*?)\s*\[\s*([^\]]+)\s*\]\s*!([0-9a-fA-F]+)\s*>",
    re.IGNORECASE | re.DOTALL,
)


def _struct_format_has_ydk_import_marker(fmt_raw: str) -> bool:
    """True when the Format names a ``!``-terminated card run with `` `ydk` `` before the inner ``[`` (optional password table name in between)."""
    return bool(re.search(r"`ydk`\s*[\w.]*\s*\[", str(fmt_raw or "")))


def _struct_format_ydk_password_anchor_name(fmt_raw: str) -> str:
    """NamedAnchor ``Name`` for 32-bit password lookup: text after `` `ydk` ``, up to the ``[`` that opens ``[card:…]``.

    Stops before that bracket so names like ``data.cards.passwords`` are not fused with the card list (and are not
    mistaken for a width token next to ``[``).
    """
    m = re.search(r"`ydk`\s*([\w.]*?)\s*\[", str(fmt_raw or ""))
    if not m:
        return "data.cards.passwords"
    name = (m.group(1) or "").strip()
    return name if name else "data.cards.passwords"


def _parse_bare_ydk_deck_shorthand_trailing_count(fmt_raw: str) -> Optional[int]:
    """If *fmt_raw* is the minimal `` `ydk`Anchor[card:List]N`` line (no outer ``[``), return *N*; else ``None``."""
    s = str(fmt_raw or "").strip()
    if s.startswith("^"):
        s = s[1:].strip()
    m = re.match(
        r"^\s*`ydk`\s*[\w.]+\s*\[\s*card\s*:\s*[\w.]+\s*\](\d+)\s*$",
        s,
        re.IGNORECASE | re.DOTALL,
    )
    if not m:
        return None
    return int(m.group(1))


def _struct_format_ydk_card_list_name(fmt_raw: str) -> Optional[str]:
    """``[card:ListName]`` inside the `` `ydk` `` … ``!`` card run (e.g. ``[card:cardnames]``).

    Deck u16 values use keys from this ``[[List]]``. When the password NamedAnchor uses a **different** ``]count``
    list (e.g. ``]cardstatsnames``), row *i* takes the label from that index list and reverse-looks it up here.
    If both lists are the same (or only this name is available), row *i* uses the *i*-th sorted key.
    """
    m = re.search(r"\[\s*card\s*:\s*([\w.]+)\s*\]", str(fmt_raw or ""), re.IGNORECASE)
    if not m:
        return None
    name = (m.group(1) or "").strip()
    return name if name else None


def _password_anchor_index_list_name(fmt_raw: str) -> Optional[str]:
    """``]ListName`` struct row-count suffix on the password table (e.g. ``[password::|h]cardstatsnames`` → ``cardstatsnames``)."""
    c = _parse_struct_count(str(fmt_raw or "").strip())
    if not isinstance(c, str):
        return None
    s = str(c).strip()
    if not s or s.isdigit():
        return None
    base = _struct_count_ref_base_name(s).strip()
    return base if base else None


def _list_reverse_label_to_smallest_key(enum_map: Dict[int, str]) -> Dict[str, int]:
    """Map trimmed label → smallest ``[[List]]`` key with that label (card id when names repeat)."""
    out: Dict[str, int] = {}
    for k in sorted(int(x) for x in enum_map.keys()):
        lab = str(enum_map[int(k)]).strip()
        if lab not in out:
            out[lab] = int(k)
    return out


def _struct_flat_ydk_card_table_field(fields: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Normalized ``[card:List]N`` from :func:`_normalize_ydk_deck_struct_shorthand_format`: one u16 ``card`` + enum."""
    if len(fields) != 1:
        return None
    fd = fields[0]
    if str(fd.get("name", "")).lower() != "card":
        return None
    if fd.get("type") != "uint":
        return None
    if int(fd.get("size") or 0) != 2:
        return None
    if not fd.get("enum"):
        return None
    return fd


def _struct_anchor_info_supports_ydk_import(info: Optional[Dict[str, Any]]) -> bool:
    """True if struct table row ``info`` from :meth:`HexEditorFrame.get_struct_anchors` is a YDK deck struct."""
    if not info:
        return False
    if info.get("ydk_import"):
        return True
    anch = info.get("anchor") or {}
    fmt_raw = str(anch.get("Format", "") or "")
    return _struct_format_has_ydk_import_marker(fmt_raw)


def _strip_ydk_marker_from_offset_prefix(prefix: str) -> str:
    """Remove `` `ydk` `` and optional ``Name`` token so ``padding:::: main:`` still parses as uint fields."""
    s = re.sub(r"`ydk`\s*[\w.]*", "", str(prefix or ""))
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _password_rom_u32_match_key(value: int) -> str:
    """Lowercase hex (no ``0x``) for a ROM u32; leading zero digits stripped — matches YDK line semantics."""
    return format(int(value) & 0xFFFFFFFF, "x").lstrip("0") or "0"


def _password_ydk_token_match_key(token: str) -> Optional[str]:
    """Normalize a YDK password token: strip ``0x``, keep hex digits only, lowercase, strip leading zeros.

    Returns ``None`` if there are no hex digits (invalid line). No decimal↔hex conversion: ``9596126`` in the
    file is compared to ``format(rom_u32,'x')`` stripped the same way (e.g. ROM ``0x09596126`` → ``9596126``).
    """
    t = str(token).strip().lower()
    if t.startswith("0x"):
        t = t[2:]
    t = re.sub(r"[^0-9a-f]", "", t)
    if not t:
        return None
    return t.lstrip("0") or "0"


def _parse_ydk_deck_text(text: str) -> Tuple[List[str], List[str], bool]:
    """Parse a YDK file: ``#main`` / ``#extra`` password lines; ``!side`` / ``#side`` ignored.

    Returns ``(main_tokens, extra_tokens, saw_extra_header)`` — first field per line as raw string (for
    password matching). If no ``#extra`` header appears, ``saw_extra_header`` is False.
    """
    main_toks: List[str] = []
    extra_toks: List[str] = []
    saw_extra = False
    section: Optional[str] = None
    for raw_line in str(text or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("#main"):
            section = "main"
            continue
        if low.startswith("#extra"):
            section = "extra"
            saw_extra = True
            continue
        if low.startswith("!side") or low.startswith("#side"):
            section = "side"
            continue
        if low.startswith("#"):
            continue
        if section == "side":
            continue
        if section not in ("main", "extra"):
            continue
        if "--" in line:
            line = line.split("--", 1)[0].strip()
        parts = line.split()
        if not parts:
            continue
        raw = parts[0].strip()
        if not raw:
            continue
        if section == "main":
            main_toks.append(raw)
        else:
            extra_toks.append(raw)
    return main_toks, extra_toks, saw_extra


def _ydk_build_deck_blob(
    main_idx: List[int],
    extra_idx: List[int],
    saw_extra_section: bool,
    term: bytes,
) -> bytes:
    """Little-endian ``u16`` card indices, optional ``u16`` extra count, then ``term`` (e.g. ``0000``)."""
    parts: List[bytes] = []
    for x in main_idx:
        parts.append(int(x).to_bytes(2, "little"))
    if saw_extra_section:
        parts.append(int(len(extra_idx)).to_bytes(2, "little"))
    for x in extra_idx:
        parts.append(int(x).to_bytes(2, "little"))
    parts.append(bytes(term))
    return b"".join(parts)


def _normalize_offset_padding_count_card_run(inner: str) -> str:
    """Expand sugar into ``offset<>`` + ``@offset+N`` payload fields + ``cards<…>inline*offset+N`` (payload at ``*offset``)."""

    def _repl(m: Any) -> str:
        prefix = _strip_ydk_marker_from_offset_prefix(m.group(1).strip())
        bracket_inner = m.group(2).strip()
        # ``card::`` is 4 bytes in the uint width DSL; deck lines almost always mean ``card:`` (u16).
        if re.match(r"^card::", bracket_inner, re.I):
            bracket_inner = re.sub(r"^card::", "card:", bracket_inner, count=1, flags=re.I)
        hexterm = m.group(3)
        expanded = _prefix_tokens_to_at_offset_payload_fields(prefix)
        if expanded is None:
            return m.group(0)
        parts_str, run_delta = expanded
        tail = f"cards<[{bracket_inner}]!{hexterm}>inline*offset+{run_delta}"
        if parts_str:
            return f"offset<> {parts_str} {tail}"
        return f"offset<> {tail}"

    return _OFFSET_ANGLE_INLINE_NESTED_RUN_RE.sub(_repl, inner)


def _merge_bitfield_tokens_list(tokens: List[str]) -> List[str]:
    """Merge tokens so an incomplete ``…|t|`` + continuation (split on spaces) becomes one bitfield token."""
    merged: List[str] = []
    ti = 0
    while ti < len(tokens):
        t = tokens[ti]
        if "|t|" in t:
            buf = t
            j = ti + 1
            parsed = _parse_bitfield_token(buf)
            while parsed is None and j < len(tokens):
                buf = f"{buf} {tokens[j]}"
                j += 1
                parsed = _parse_bitfield_token(buf)
            if parsed is not None:
                merged.append(buf)
                ti = j
                continue
            # Avoid leaving ``evs:|t|`` and ``hp:…`` as separate tokens (would mis-parse the rest of the struct).
            if j > ti + 1:
                merged.append(buf)
                ti = j
                continue
        merged.append(t)
        ti += 1
    return merged


def _parse_struct_inner_content_to_fields(inner: str) -> Optional[List[Dict[str, Any]]]:
    """Parse inner struct body like ``text<""> unused::`` (no outer ``[count]`` wrapper)."""
    inner = inner.strip()
    if not inner:
        return None
    tokens = _tokenize_struct_body(inner)
    tokens = _merge_bitfield_tokens_list(tokens)
    fields: List[Dict[str, Any]] = []
    lay_at = 0
    for tok in tokens:
        fd = _parse_helper_field_token(tok)
        if fd is None:
            fd = _parse_single_field(tok)
        if fd:
            if fd.get("type") == "nested_array":
                return None
            if fd.get("type") == "helper":
                return None
            fd["offset"] = lay_at
            lay_at += int(fd["size"])
            fields.append(fd)
    return fields if fields else None


def _parse_nested_array_inner_body_fields(inner_body: str) -> Optional[List[Dict[str, Any]]]:
    """Parse ``inner`` for ``name<[inner]/count>``.

    Flat tokens only. A bare `` `ydk`Anchor[card:List] `` fragment (same spelling as deck imports) names
    the password table and card list but is treated like ``card:List`` for layout: packed little-endian u16
    indices, stride 2, with the outer ``/count`` field giving the card count.
    """
    flat = _parse_struct_inner_content_to_fields(inner_body)
    if flat is not None:
        return flat
    m = re.match(
        r"^\s*`ydk`\s*([\w.]+)\s*\[\s*card\s*:\s*([\w.]+)\s*\]\s*$",
        inner_body.strip(),
        re.IGNORECASE,
    )
    if not m:
        return None
    lst = (m.group(2) or "").strip()
    if not lst:
        return None
    return _parse_struct_inner_content_to_fields(f"card:{lst}")


def _struct_field_omitted_from_editor_tree(fd: Optional[Dict[str, Any]]) -> bool:
    """True for layout-only names ``padding`` / ``unused``: bytes still define struct layout; tree omits the row."""
    if not fd:
        return False
    nm = str(fd.get("name", "")).lower()
    return nm in ("padding", "unused")


def _struct_field_payload_file_off(
    entry_base: int,
    fd: Dict[str, Any],
    fields: List[Dict[str, Any]],
    data: bytes,
) -> Optional[int]:
    """ROM file offset for a top-level field: row layout, or ``name@ptr+N`` payload under ``*ptr``."""
    if fd.get("at_ptr_field"):
        pfn = str(fd["at_ptr_field"])
        pfd = next((x for x in fields if str(x.get("name")) == pfn), None)
        if not pfd or pfd.get("type") not in ("ptr", "pcs_ptr"):
            return None
        poff = entry_base + int(pfd["offset"])
        if poff + 4 > len(data):
            return None
        ptr = int.from_bytes(data[poff : poff + 4], "little")
        if (ptr >> 24) not in (0x08, 0x09):
            return None
        fo = ptr - GBA_ROM_BASE + int(fd.get("at_ptr_delta") or 0)
        if fo < 0:
            return None
        return fo
    return entry_base + int(fd["offset"])


def _validate_at_ptr_payload_fields(fields: List[Dict[str, Any]]) -> bool:
    """Each ``at_ptr_field`` reference must name an earlier ``ptr`` / ``pcs_ptr`` field."""
    by_name = {str(f.get("name")): f for f in fields if f.get("name")}
    idx_by_name = {str(f.get("name")): i for i, f in enumerate(fields) if f.get("name")}
    for fd in fields:
        pfn = fd.get("at_ptr_field")
        if not pfn:
            continue
        pfd = by_name.get(str(pfn))
        if not pfd or pfd.get("type") not in ("ptr", "pcs_ptr"):
            return False
        i_fd = idx_by_name.get(str(fd.get("name", "")))
        i_p = idx_by_name.get(str(pfn))
        if i_fd is None or i_p is None or i_fd <= i_p:
            return False
    return True


def _prefix_tokens_to_at_offset_payload_fields(prefix: str) -> Optional[Tuple[str, int]]:
    """Expand ``padding:::: main:`` → ``padding@offset+0:::: main@offset+8:``; return (expanded, byte offset before card run)."""
    if not prefix.strip():
        return "", 0
    tokens = _tokenize_struct_body(prefix.strip())
    tokens = _merge_bitfield_tokens_list(tokens)
    delta = 0
    parts: List[str] = []
    for tok in tokens:
        pfd = _parse_helper_field_token(tok)
        if pfd is None:
            pfd = _parse_single_field(tok)
        if not pfd or pfd.get("type") != "uint":
            return None
        nm = str(pfd["name"])
        if not tok.startswith(nm):
            return None
        rest = tok[len(nm) :]
        parts.append(f"{nm}@offset+{delta}{rest}")
        delta += int(pfd["size"])
    return " ".join(parts), delta


def _parse_struct_fields(
    fmt: str,
    blist_resolver: Optional[Callable[[str], Optional[int]]] = None,
) -> Optional[List[Dict[str, Any]]]:
    """Parse the fields inside a Format like '[field1. field2: ...]count'.
    Returns list of field descriptors with byte offsets, or None if not a struct format.

    ``blist_resolver(ref)`` returns bit count for ``field|b[]ref`` (packed bits); used to set byte ``size``.
    """
    s = fmt.strip()
    if s.startswith("^"):
        s = s[1:]
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
    inner = _normalize_offset_padding_count_card_run(s[1:close])

    tokens = _tokenize_struct_body(inner)
    tokens = _merge_bitfield_tokens_list(tokens)

    fields: List[Dict[str, Any]] = []
    for tok in tokens:
        fd = _parse_helper_field_token(tok)
        if fd is None:
            fd = _parse_single_field(tok)
        if fd:
            if fd.get("type") == "nested_array":
                fd["size"] = 0
            fields.append(fd)
    if blist_resolver:
        for fd in fields:
            ref = fd.get("blist_ref")
            if not ref:
                continue
            bits = blist_resolver(ref)
            if bits is not None and bits > 0:
                fd["blist_bits"] = int(bits)
                fd["size"] = (int(bits) + 7) // 8
            else:
                fd["blist_bits"] = None
                fd["size"] = 1
                fd["blist_unresolved"] = True
    _finalize_nested_array_pointer_semantics(fields)
    if not _validate_nested_array_fields(fields):
        return None
    if not _validate_at_ptr_payload_fields(fields):
        return None
    _assign_struct_field_offsets(fields)
    return fields


def _finalize_nested_array_pointer_semantics(fields: List[Dict[str, Any]]) -> None:
    """Count-based ``name<[inner]/count>`` stores a 4-byte GBA pointer **at** ``name``; inner rows live at ``*ptr``.

    Exception: **implicit row pointer** — ``[options<…/count> count::]`` (nested field first, count last) — keeps the
    legacy layout: pointer at **row** offset 0, count after; no separate field name for the pointer.

    Another exception: ``…*base_ptr`` — pointer is in the named ``ptr``/``pcs_ptr`` field, not at ``name``.

    For ``!HEX>`` **without** the ``inline`` suffix: ``name`` is a **4-byte GBA pointer**; the terminator-delimited
    blob lives at ``*name`` (same idea as count-based ``name<[inner]/count>`` on ROM that store a pointer column).

    Use ``!HEX>inline`` only when the nested bytes are **packed inline** in the struct row (legacy behavior).
    """
    for fd in fields:
        if fd.get("type") != "nested_array":
            continue
        if fd.get("terminator") is not None:
            if fd.get("terminator_inline_packed"):
                fd["nested_ptr_is_self_field"] = False
            else:
                fd["nested_ptr_is_self_field"] = True
            continue
        if fd.get("base_ptr_field"):
            fd["nested_ptr_is_self_field"] = False
            continue
        if not fd.get("count_field"):
            continue
        if _nested_array_implicit_row_pointer(fields, fd):
            fd["nested_ptr_is_self_field"] = False
        else:
            fd["nested_ptr_is_self_field"] = True


def _assign_struct_field_offsets(fields: List[Dict[str, Any]]) -> None:
    """Lay out fields in declaration order: helpers (0 bytes), uints, nested_array (consumes max span), etc."""
    lay_at = 0
    for fd in fields:
        if fd.get("type") == "helper":
            fd["offset"] = lay_at
            continue
        if fd.get("type") == "nested_array":
            fd["offset"] = lay_at
            if fd.get("base_ptr_field"):
                pass
            elif fd.get("nested_ptr_is_self_field"):
                lay_at += 4
            elif _nested_array_implicit_row_pointer(fields, fd):
                lay_at += 4
            else:
                lay_at += _nested_array_max_span_bytes(fd, fields)
            continue
        fd["offset"] = lay_at
        if fd.get("at_ptr_field"):
            continue
        lay_at += int(fd["size"])


def _validate_nested_array_fields(fields: List[Dict[str, Any]]) -> bool:
    """Each ``nested_array`` either names a ``/countField`` uint elsewhere in the same struct, or uses
    ``!HEX>`` terminator bytes (even-length hex → raw bytes) and must be the **last** field.

    Valid layouts:
    - **Count first:** ``count`` appears before ``name<[inner]/count>``, and the nested field must be **last**
      (e.g. ``[cost:: … pack<[inner]/cardamount>]``) — ``pack`` holds a 4-byte pointer; inner rows at ``*pack``.
    - **Count last:** ``name<[inner]/count>`` appears before ``count``, and the **count** field must be **last**
      (e.g. ``[options<…/count> count::]``) — **implicit** pointer at row offset 0 unless ``*base_ptr`` is used.
    """
    names = [str(f.get("name", "")) for f in fields]
    for i, fd in enumerate(fields):
        if fd.get("type") != "nested_array":
            continue
        if fd.get("terminator"):
            # Delimited by a byte pattern; no count uint — must be the last field in the struct.
            if i != len(fields) - 1:
                return False
            continue
        cf_name = str(fd.get("count_field") or "")
        if not cf_name or cf_name not in names:
            return False
        ci = names.index(cf_name)
        ni = names.index(str(fd["name"]))
        if ci < ni:
            if i != len(fields) - 1:
                return False
        elif ni < ci:
            # Nested field before count: count uint is usually last (``[options<…/c> c::]``). Allow
            # trailing fixed slots (e.g. ``padding:.``) after the count when they are plain uint/PCS/ASCII.
            if ci != len(fields) - 1:
                for j in range(ci + 1, len(fields)):
                    fj = fields[j]
                    if fj.get("type") == "helper":
                        continue
                    if fj.get("type") not in ("uint", "pcs", "ascii"):
                        return False
        else:
            return False
        bpf = fd.get("base_ptr_field")
        if bpf:
            bf = next((x for x in fields if str(x.get("name")) == str(bpf)), None)
            if bf is None or bf.get("type") not in ("ptr", "pcs_ptr"):
                return False
            if names.index(str(bpf)) >= ni:
                return False
    return True


def _count_nested_elements_until_terminator(
    data: bytes, start: int, stride: int, terminator: bytes
) -> int:
    """
    Count ``stride``-byte elements starting at ``start`` until ``terminator`` appears at the current
    position (terminator is **not** counted as an element). If ROM ends first, returns elements scanned.
    """
    if stride < 1 or not terminator:
        return 0
    pos = start
    n = 0
    lim = len(data)
    tl = len(terminator)
    while pos < lim:
        if pos + tl <= lim and data[pos : pos + tl] == terminator:
            return n
        if pos + stride > lim:
            break
        n += 1
        pos += stride
    return n


def _terminator_nested_row_end_exclusive(
    data: bytes, start: int, stride: int, terminator: bytes
) -> Optional[int]:
    """Byte offset **after** the terminator that ends one ``!HEX`` nested row, or None if unterminated/out of range."""
    if stride < 1 or not terminator:
        return None
    pos = start
    lim = len(data)
    tl = len(terminator)
    while pos < lim:
        if pos + tl <= lim and data[pos : pos + tl] == terminator:
            return pos + tl
        if pos + stride > lim:
            return None
        pos += stride
    return None


def _terminator_nested_row_end_exclusive_pointer_blob(
    data: bytes, start: int, stride: int, terminator: bytes
) -> Optional[int]:
    """End offset for a **single** pointer-backed ``!HEX`` blob (e.g. deck at ``*offset``).

    When ``stride == len(terminator)`` (typical u16 cards + ``0000``), a card index of **0** is the same two
    bytes as the terminator. :func:`_terminator_nested_row_end_exclusive` would stop at the first card,
    yielding a ~2-byte span and breaking grow/repoint/YDK import loops.

    Here we take the **last** stride-aligned terminator in the blob whose suffix up to the next long ``0xFF``
    padding run (or ROM end) is only ``0xFF`` — i.e. the real end-of-deck marker before free space.

    For **packed** multi-row terminator tables (rows laid back-to-back without a padding gap), use
    :func:`_terminator_nested_row_end_exclusive` instead.
    """
    if stride < 1 or not terminator:
        return None
    lim = len(data)
    tl = len(terminator)
    if start < 0 or start >= lim:
        return None
    # Bound the allocation: first stretch of 8×0xFF is usual GBA padding after a relocated blob.
    blob_end = lim
    hi = lim - 7
    if start < hi:
        for i in range(start, hi):
            if data[i : i + 8] == b"\xff" * 8:
                blob_end = i
                break
    last_exc: Optional[int] = None
    pos = start
    while pos + tl <= blob_end:
        if data[pos : pos + tl] == terminator:
            tail = pos + tl
            if tail >= blob_end or all(data[j] == 0xFF for j in range(tail, blob_end)):
                last_exc = tail
        pos += stride
    if last_exc is not None:
        return last_exc
    return _terminator_nested_row_end_exclusive(data, start, stride, terminator)


def _struct_is_packed_terminator_only(fields: List[Dict[str, Any]]) -> bool:
    """True when the struct is only an **inline** ``!HEX>inline`` nested array — rows packed back-to-back in ROM."""
    non_h = [f for f in fields if f.get("type") != "helper"]
    return (
        len(non_h) == 1
        and non_h[0].get("type") == "nested_array"
        and non_h[0].get("terminator") is not None
        and bool(non_h[0].get("terminator_inline_packed"))
    )


def _packed_terminator_entry_file_offset(
    data: bytes, base_off: int, entry_idx: int, na_fd: Dict[str, Any]
) -> Optional[int]:
    """File offset of struct row ``entry_idx`` for a packed ``!HEX`` nested-array table."""
    if entry_idx < 0:
        return None
    stride = int(na_fd["inner_stride"])
    term = bytes(na_fd["terminator"])
    pos = base_off
    for _ in range(entry_idx):
        end = _terminator_nested_row_end_exclusive(data, pos, stride, term)
        if end is None:
            return None
        pos = end
    return pos


def _packed_terminator_table_span_bytes(data: bytes, base_off: int, count: int, na_fd: Dict[str, Any]) -> Optional[int]:
    """Total bytes occupied by ``count`` packed terminator rows starting at ``base_off``, or None if incomplete."""
    pos: Optional[int] = base_off
    for _ in range(count):
        if pos is None:
            return None
        pos = _terminator_nested_row_end_exclusive(data, pos, int(na_fd["inner_stride"]), bytes(na_fd["terminator"]))
    if pos is None:
        return None
    return int(pos) - base_off


def _packed_grow_inserts_before_trailing_terminator(term: bytes) -> bool:
    """If True, packed growth inserts new strides immediately before the last terminator (e.g. ``0000``), not after it."""
    return len(term) >= 2


def _room_overwrite_expand_at_terminator(
    data: bytes, term_start: int, term: bytes, new_blob: bytes
) -> bool:
    """True if ``term`` at ``term_start`` can be replaced with longer ``new_blob`` using only 0xFF after the old term."""
    tl = len(term)
    if tl < 1 or len(new_blob) < tl or term_start < 0:
        return False
    if term_start + tl > len(data):
        return False
    if data[term_start : term_start + tl] != term:
        return False
    extra = len(new_blob) - tl
    if extra <= 0:
        return True
    for i in range(term_start + tl, term_start + tl + extra):
        if i >= len(data):
            return True
        if data[i] != 0xFF:
            return False
    return True


def _count_packed_terminator_rows(data, base_off: int, na_fd: Dict[str, Any], *, max_rows: int = 100000) -> int:
    """Count packed ``!HEX`` terminator rows in ROM starting at ``base_off`` (0 if none complete).

    Capped at ``max_rows`` to avoid scanning the entire ROM when the terminator pattern
    (e.g. ``0000``, ``FF``) appears ubiquitously in arbitrary ROM data."""
    stride = int(na_fd["inner_stride"])
    term = bytes(na_fd["terminator"])
    if stride < 1 or not term:
        return 0
    pos = base_off
    lim = len(data)
    n = 0
    while pos < lim and n < max_rows:
        end = _terminator_nested_row_end_exclusive(data, pos, stride, term)
        if end is None:
            break
        n += 1
        pos = end
    return n


def _is_packed_terminator_shorthand_format(fmt_raw: str) -> bool:
    """True for ``[inner]!HEX`` packed terminator shorthand (optional erroneous ``]N`` suffix is ignored)."""
    s = fmt_raw.strip()
    if s.startswith("^"):
        s = s[1:].strip()
    return re.match(r"^\[([^\[\]]*)\]!([0-9a-fA-F]{2,})(?:\](\d+))?\s*$", s) is not None


def _struct_anchor_table_span_bytes(data: bytes, info: Dict[str, Any]) -> int:
    """Total ROM bytes covered by one struct NamedAnchor table (fixed stride or packed ``!HEX`` rows)."""
    if info.get("packed_terminator") and info.get("packed_terminator_fd"):
        na_fd = info["packed_terminator_fd"]
        span = _packed_terminator_table_span_bytes(
            data, int(info["base_off"]), int(info["count"]), na_fd
        )
        if span is not None:
            return int(span)
        return max(0, len(data) - int(info["base_off"]))
    return int(info["struct_size"]) * int(info["count"])


def _struct_row_index_for_file_offset(data: bytes, info: Dict[str, Any], file_off: int) -> int:
    """0-based struct row index whose ROM span contains ``file_off`` (for Goto / tools sync)."""
    base = int(info["base_off"])
    cnt = max(0, int(info.get("count") or 0))
    if cnt <= 0:
        return 0
    if file_off < base:
        return 0
    if info.get("packed_terminator") and info.get("packed_terminator_fd"):
        pfd = info["packed_terminator_fd"]
        stride = int(pfd["inner_stride"])
        term = bytes(pfd["terminator"])
        pos = base
        for i in range(cnt):
            row_start = pos
            end = _terminator_nested_row_end_exclusive(data, row_start, stride, term)
            if end is None:
                return i
            if row_start <= file_off < end:
                return i
            pos = end
        return max(0, cnt - 1)
    ss = int(info.get("struct_size") or 0)
    if ss <= 0:
        return 0
    idx = (file_off - base) // ss
    return max(0, min(idx, cnt - 1))


def _pcs_row_index_for_file_offset(info: Dict[str, Any], file_off: int) -> int:
    """0-based PCS table row containing ``file_off``."""
    addr = info["anchor"].get("Address")
    if addr is None:
        return 0
    try:
        gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
        if gba < GBA_ROM_BASE:
            gba += GBA_ROM_BASE
        start = gba - GBA_ROM_BASE
    except (ValueError, TypeError):
        return 0
    w = int(info.get("width") or 0)
    c = int(info.get("count") or 0)
    if w <= 0 or c <= 0:
        return 0
    if file_off < start:
        return 0
    idx = (file_off - start) // w
    return max(0, min(idx, c - 1))


def _nested_array_max_span_bytes(fd: Dict[str, Any], fields: List[Dict[str, Any]]) -> int:
    """Upper bound on bytes for ``nested_array`` from count field uint width."""
    if fd.get("terminator"):
        stride = int(fd["inner_stride"])
        tl = len(fd["terminator"])
        return min(1 << 20, stride * 65535 + max(tl, 0))
    cf = next((f for f in fields if f.get("name") == fd.get("count_field")), None)
    if not cf or cf.get("type") != "uint":
        return 0
    w = int(cf["size"])
    mx = min((1 << (8 * w)) - 1, 65535)
    return int(fd["inner_stride"]) * mx


def _nested_array_implicit_row_pointer(fields: List[Dict[str, Any]], na_fd: Dict[str, Any]) -> bool:
    """True for ``[options<…/count> count::]`` — row is implicit 4-byte GBA ptr @0 + ``count``; data at ``*ptr``."""
    if na_fd.get("base_ptr_field") or na_fd.get("type") != "nested_array":
        return False
    names = [str(f.get("name", "")) for f in fields]
    try:
        ni = names.index(str(na_fd["name"]))
        ci = names.index(str(na_fd.get("count_field") or ""))
    except ValueError:
        return False
    if not (ni < ci and ci == len(fields) - 1 and ni == 0):
        return False
    return True


def _nested_array_data_base_file(
    entry_base: int,
    na_fd: Dict[str, Any],
    fields: List[Dict[str, Any]],
    data: bytes,
) -> Optional[int]:
    """File offset where a nested array's elements live (same rules as ``_nested_array_data_base`` on the struct UI)."""
    bpf = na_fd.get("base_ptr_field")
    if _nested_array_implicit_row_pointer(fields, na_fd):
        poff = entry_base
        if poff + 4 > len(data):
            return None
        ptr = int.from_bytes(data[poff : poff + 4], "little")
        if (ptr >> 24) not in (0x08, 0x09):
            return None
        fo = ptr - GBA_ROM_BASE
        if fo < 0 or fo >= len(data):
            return None
        return fo
    if na_fd.get("nested_ptr_is_self_field"):
        poff = entry_base + int(na_fd["offset"])
        if poff + 4 > len(data):
            return None
        ptr = int.from_bytes(data[poff : poff + 4], "little")
        if (ptr >> 24) not in (0x08, 0x09):
            return None
        fo = ptr - GBA_ROM_BASE
        if fo < 0 or fo >= len(data):
            return None
        return fo
    if not bpf:
        return entry_base + int(na_fd["offset"])
    pfd = next((f for f in fields if str(f.get("name")) == str(bpf)), None)
    if not pfd or pfd.get("type") not in ("ptr", "pcs_ptr"):
        return None
    poff = entry_base + int(pfd["offset"])
    if poff + 4 > len(data):
        return None
    ptr = int.from_bytes(data[poff : poff + 4], "little")
    if (ptr >> 24) not in (0x08, 0x09):
        return None
    fo = ptr - GBA_ROM_BASE
    if fo < 0 or fo >= len(data):
        return None
    return fo + int(na_fd.get("base_ptr_delta") or 0)


def _ptr_word_off_and_alloc_start(
    entry_base: int,
    na_fd: Dict[str, Any],
    fields: List[Dict[str, Any]],
    data: bytes,
) -> Optional[Tuple[int, int, int]]:
    """
    For pointer-backed nested data: ``(ptr_word_file_off, ptr_alloc_file_start, na_base)``.
    ``ptr_alloc_file_start`` is where the ROM pointer targets (start of allocation); ``na_base`` is where
    the ``!``-terminated run begins (after ``*offset+N`` delta when applicable).
    Returns ``None`` if the nested blob is not relocated via a u32 pointer (e.g. inline-only layout).
    """
    bpf = na_fd.get("base_ptr_field")
    if _nested_array_implicit_row_pointer(fields, na_fd):
        poff = entry_base
        if poff + 4 > len(data):
            return None
        ptr = int.from_bytes(data[poff : poff + 4], "little")
        if (ptr >> 24) not in (0x08, 0x09):
            return None
        fo = ptr - GBA_ROM_BASE
        if fo < 0 or fo >= len(data):
            return None
        return poff, fo, fo
    if na_fd.get("nested_ptr_is_self_field"):
        poff = entry_base + int(na_fd["offset"])
        if poff + 4 > len(data):
            return None
        ptr = int.from_bytes(data[poff : poff + 4], "little")
        if (ptr >> 24) not in (0x08, 0x09):
            return None
        fo = ptr - GBA_ROM_BASE
        if fo < 0 or fo >= len(data):
            return None
        return poff, fo, fo
    if not bpf:
        return None
    pfd = next((f for f in fields if str(f.get("name")) == str(bpf)), None)
    if not pfd or pfd.get("type") not in ("ptr", "pcs_ptr"):
        return None
    poff = entry_base + int(pfd["offset"])
    if poff + 4 > len(data):
        return None
    ptr = int.from_bytes(data[poff : poff + 4], "little")
    if (ptr >> 24) not in (0x08, 0x09):
        return None
    fo = ptr - GBA_ROM_BASE
    if fo < 0 or fo >= len(data):
        return None
    na_base = fo + int(na_fd.get("base_ptr_delta") or 0)
    return poff, fo, na_base


def _struct_per_row_terminator_nested_field(fields: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """``!HEX`` nested data stored **per struct row** (under a pointer), not as the whole packed table at ``Address``."""
    if _struct_is_packed_terminator_only(fields):
        return None
    non_h = [f for f in fields if f.get("type") != "helper"]
    for fd in reversed(non_h):
        if fd.get("type") == "nested_array" and fd.get("terminator"):
            return fd
    return None


def _struct_ydk_pointer_count_nested_field(fields: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """``offset<[`ydk`…]/length>``-style: count-driven nested array at a pointer, u16 ``card`` slots, no ``!`` terminator."""
    for fd in fields:
        if fd.get("type") != "nested_array":
            continue
        if fd.get("terminator") is not None:
            continue
        if not fd.get("count_field"):
            continue
        inner = list(fd.get("inner_fields") or [])
        if len(inner) != 1:
            continue
        c0 = inner[0]
        if str(c0.get("name", "")).lower() != "card":
            continue
        if int(c0.get("size") or 0) != 2:
            continue
        if int(fd.get("inner_stride") or 0) != 2:
            continue
        return fd
    return None


def _struct_supports_terminator_table_slots(info: Dict[str, Any]) -> bool:
    """True if the struct has a ``!``-terminated nested run (packed at anchor base, or pointer-backed per row)."""
    if info.get("packed_terminator") and info.get("packed_terminator_fd"):
        return True
    return _struct_per_row_terminator_nested_field(list(info.get("fields") or [])) is not None


def _fill_bytes_from_spec(spec: str, total_len: int) -> Tuple[Optional[bytes], str]:
    """Tile a hex byte pattern to at least ``total_len`` bytes (default unit ``00`` → ``0x00``).

    If the pattern has more bytes than ``total_len`` (e.g. ``FFFF`` with one stride byte), the result is
    lengthened to hold at least one full pattern cycle so multi-byte fills are not truncated."""
    if total_len <= 0:
        return b"", ""
    s = (spec or "").strip()
    if not s:
        unit = b"\x00"
        min_len = 1
    else:
        hx = re.sub(r"\s+", "", s).lower().replace("0x", "")
        if len(hx) % 2 != 0:
            return None, "Fill pattern hex must have an even number of digits (e.g. 00 or FFFF)."
        try:
            unit = bytes.fromhex(hx)
        except ValueError:
            return None, "Invalid hex in fill pattern."
        if not unit:
            unit = b"\x00"
        min_len = len(unit)
    eff_len = max(total_len, min_len)
    out = bytearray()
    while len(out) < eff_len:
        out.extend(unit)
    return bytes(out[:eff_len]), ""


def _room_expand_terminator_run_inplace(
    data: bytes, term_start: int, term: bytes, insert_len: int
) -> bool:
    """True if ``insert_len`` bytes of free space (0xFF / EOF) follow the terminator at ``term_start``."""
    tl = len(term)
    if term_start < 0 or tl <= 0 or insert_len < 0:
        return False
    if term_start + tl > len(data):
        return False
    if data[term_start : term_start + tl] != term:
        return False
    for i in range(term_start + tl, term_start + tl + insert_len):
        if i >= len(data):
            return True
        if data[i] != 0xFF:
            return False
    return True


def _struct_row_byte_size(fields: List[Dict[str, Any]]) -> int:
    """Total bytes per struct row: fixed fields + upper bound for each inline ``nested_array``."""
    n = 0
    for f in fields:
        t = f.get("type")
        if t == "helper":
            continue
        if t == "nested_array":
            if f.get("base_ptr_field"):
                continue
            if f.get("nested_ptr_is_self_field"):
                n += 4
            elif _nested_array_implicit_row_pointer(fields, f):
                n += 4
            else:
                n += _nested_array_max_span_bytes(f, fields)
        else:
            if f.get("at_ptr_field"):
                continue
            n += int(f["size"])
    return n


def _try_parse_nested_array_token(token: str) -> Optional[Dict[str, Any]]:
    """Parse ``name<[inner]/countField>``, ``name<[inner]!HEX>`` (terminator bytes), or ``…*ptr`` / ``…*ptr+N``."""
    raw = token.strip()
    base_ptr_field: Optional[str] = None
    base_ptr_delta: int = 0
    if "*" in raw:
        head, tail = raw.rsplit("*", 1)
        h, t = head.strip(), tail.strip()
        m_tail = re.match(r"^(\w+)(\+(\d+))?$", t)
        # ``…!0000>inline`` ends with ``inline``, not ``>`` — same rule as below.
        if m_tail and (h.endswith(">") or re.search(r">\s*inline\s*$", h)):
            raw = h
            base_ptr_field = m_tail.group(1)
            base_ptr_delta = int(m_tail.group(3)) if m_tail.group(3) else 0
    if "<[" not in raw:
        return None
    rs = raw.rstrip()
    # Allow ``…!0000>inline`` (packed inline) as well as ``…!0000>`` (pointer column).
    if not (rs.endswith(">") or re.search(r">\s*inline\s*$", rs)):
        return None
    m = re.match(r"^(\w+)<(\[)", raw)
    if not m:
        return None
    name = m.group(1)
    start_bracket = m.start(2)
    depth = 0
    close_bracket = -1
    i = start_bracket
    while i < len(raw):
        if raw[i] == "[":
            depth += 1
        elif raw[i] == "]":
            depth -= 1
            if depth == 0:
                close_bracket = i
                break
        i += 1
    if close_bracket < 0:
        return None
    rest = raw[close_bracket + 1 :].strip()
    # ``/countField>`` — length from a uint field; ``!HEX>`` — run until this byte pattern (even hex = bytes).
    m_term = re.match(r"^!([0-9a-fA-F]+)>\s*(inline)?\s*$", rest)
    count_field: Optional[str] = None
    terminator: Optional[bytes] = None
    terminator_inline_packed = False
    if m_term:
        hs = m_term.group(1)
        if len(hs) % 2 != 0:
            return None
        try:
            terminator = bytes.fromhex(hs)
        except ValueError:
            return None
        if not terminator:
            return None
        terminator_inline_packed = bool(m_term.group(2))
    else:
        m2 = re.match(r"^/(\w+)>\s*$", rest)
        if not m2:
            return None
        count_field = m2.group(1)
    inner_bracketed = raw[start_bracket : close_bracket + 1]
    inner_s = inner_bracketed.strip()
    if not inner_s.startswith("[") or not inner_s.endswith("]"):
        return None
    inner_body = inner_s[1:-1].strip()
    inner_fields = _parse_nested_array_inner_body_fields(inner_body)
    if not inner_fields:
        return None
    inner_stride = sum(
        int(f["size"]) for f in inner_fields if f.get("type") not in ("helper",)
    )
    if inner_stride <= 0:
        return None
    out: Dict[str, Any] = {
        "name": name,
        "size": 0,
        "type": "nested_array",
        "enum": None,
        "hex": False,
        "inner_fields": inner_fields,
        "inner_stride": inner_stride,
        "count_field": count_field,
        "base_ptr_delta": 0,
    }
    if terminator is not None:
        out["terminator"] = terminator
        out["terminator_inline_packed"] = terminator_inline_packed
    if base_ptr_field:
        out["base_ptr_field"] = base_ptr_field
        out["base_ptr_delta"] = base_ptr_delta
    return out


def _strip_struct_field_modifiers(token: str) -> Tuple[str, bool, bool]:
    """Remove ``|h`` (hex display) and ``|z`` (signed integer) suffixes; return ``(token, hex_hint, signed_hint)``."""
    t = token.strip()
    hex_hint = "|h" in t
    signed_hint = "|z" in t
    for mod in ("|h", "|z"):
        t = t.replace(mod, "")
    return t, hex_hint, signed_hint


def _encode_struct_uint_field(fd: Dict[str, Any], val: int) -> bytes:
    """Little-endian ROM bytes for a struct ``uint`` (honors ``signed``)."""
    sz = int(fd["size"])
    if fd.get("signed"):
        return int(val).to_bytes(sz, "little", signed=True)
    return int(val).to_bytes(sz, "little")


def _parse_single_field(token: str) -> Optional[Dict[str, Any]]:
    """Parse a single field token like 'hp.', 'type1.enumname', 'unknown:cardgraphicsindexes+1', etc."""
    bf = _parse_bitfield_token(token)
    if bf is not None:
        return bf
    na = _try_parse_nested_array_token(token)
    if na is not None:
        return na
    if "|s=" in token:
        token = token.split("|s=")[0]
    token, hex_hint, signed_hint = _strip_struct_field_modifiers(token)
    m_at = re.match(r"^(\w+)@(\w+)\+(\d+)([.:]+)([\w.]*)([+-]\d+)?$", token.strip())
    if m_at:
        name = m_at.group(1)
        pfn = m_at.group(2)
        delta = int(m_at.group(3))
        size_chars = m_at.group(4)
        base = (m_at.group(5) or "").strip()
        tail = m_at.group(6) or ""
        enum_ref = (base + tail).strip() if base else None
        size = sum(1 if c == "." else 2 for c in size_chars)
        return {
            "name": name,
            "size": size,
            "type": "uint",
            "enum": enum_ref or None,
            "hex": hex_hint,
            "signed": signed_hint,
            "at_ptr_field": pfn,
            "at_ptr_delta": delta,
        }
    m_blist = re.match(r"^(\w+)\|b\[\]([\w.]+)$", token.strip())
    if m_blist:
        return {
            "name": m_blist.group(1),
            "size": 0,
            "type": "uint",
            "enum": None,
            "hex": hex_hint,
            "signed": False,
            "bit_array": True,
            "blist_ref": m_blist.group(2),
        }

    m = re.match(r'^(\w+)""(\d+)', token)
    if m:
        return {"name": m.group(1), "size": int(m.group(2)), "type": "pcs", "enum": None}

    m = re.match(r"^(\w+)''(\d+)", token)
    if m:
        return {"name": m.group(1), "size": int(m.group(2)), "type": "ascii", "enum": None}

    if token.endswith('<"">'):
        nm = re.match(r'^(\w+)', token)
        return {"name": nm.group(1) if nm else token, "size": 4, "type": "pcs_ptr", "enum": None}

    if token.endswith("<>"):
        nm = re.match(r'^(\w+)', token)
        return {"name": nm.group(1) if nm else token, "size": 4, "type": "ptr", "enum": None, "hex": True}

    sm = re.match(r"^(\w+)<`([^`]*)`>\s*$", token)
    if sm:
        fname = sm.group(1)
        inner = sm.group(2).strip()
        if fname == "tileset":
            gspec, _pal = parse_sprite_field_spec(inner)
            if gspec is not None and getattr(gspec, "kind", None) == "sprite":
                return {
                    "name": fname,
                    "size": 4,
                    "type": "gfx_tileset",
                    "enum": None,
                    "hex": True,
                    "gfx_spec": gspec,
                }
            return None
        if fname == "tilemap":
            tm_spec = parse_tilemap_dimension_spec(inner)
            if tm_spec is not None:
                return {
                    "name": fname,
                    "size": 4,
                    "type": "gfx_tilemap",
                    "enum": None,
                    "hex": True,
                    "gfx_spec": tm_spec,
                }
            # Legacy: full ``ucm…|anchor|pal`` in one backtick blob
            legacy = parse_graphics_anchor_format(inner)
            if legacy is not None and getattr(legacy, "kind", None) == "tilemap":
                return {
                    "name": fname,
                    "size": 4,
                    "type": "gfx_tilemap",
                    "enum": None,
                    "hex": True,
                    "gfx_spec": legacy,
                }
            return None
        if fname == "palette":
            pal_spec = parse_graphics_anchor_format(inner)
            if pal_spec is not None and getattr(pal_spec, "kind", None) == "palette":
                return {
                    "name": fname,
                    "size": 4,
                    "type": "gfx_palette",
                    "enum": None,
                    "hex": True,
                    "gfx_spec": pal_spec,
                }
            return None
        gspec, pal_name = parse_sprite_field_spec(inner)
        return {
            "name": fname,
            "size": 4,
            "type": "gfx_sprite",
            "enum": None,
            "hex": True,
            "gfx_spec": gspec,
            "gfx_palette_name": pal_name,
        }

    if "<[" in token or "<`" in token:
        nm = re.match(r'^(\w+)', token)
        return {"name": nm.group(1) if nm else token, "size": 4, "type": "ptr", "enum": None, "hex": True}

    # ``card::`` counts as ``::`` → u32 (4 bytes); deck lines almost always mean ``card:`` (u16).
    if re.match(r"^card::", token, re.I):
        token = re.sub(r"^card::", "card:", token, count=1, flags=re.I)

    # e.g. unknown:cardgraphicsindexes+1 — optional trailing +N / -N after the table name
    m = re.match(r"^(\w+)([.:]+)([\w.]*)([+-]\d+)?$", token)
    if m:
        name = m.group(1)
        size_chars = m.group(2)
        base = (m.group(3) or "").strip()
        tail = m.group(4) or ""
        enum_ref = (base + tail).strip() if base else None
        size = sum(1 if c == "." else 2 for c in size_chars)
        return {
            "name": name,
            "size": size,
            "type": "uint",
            "enum": enum_ref or None,
            "hex": hex_hint,
            "signed": signed_hint,
        }

    return None


def _parse_struct_count(fmt: str) -> Any:
    """Extract the row count after ``[fields]`` — ``]count`` suffix, or ``[inner]!HEX`` shorthand.

    For packed ``[inner]!HEX`` shorthand, returns ``1`` as a safe default.  The real row count
    should be derived from ROM scanning at the point of use (struct editor navigation)."""
    s = fmt.strip()
    if s.startswith("^"):
        s = s[1:]
    if not s.startswith("["):
        return None
    # ``[rate:]!0000`` or ``[rate:]!0000]3`` — terminator shorthand (default 1 if no ``]digits``).
    m_short = re.match(r"^\[([^\[\]]*)\]!([0-9a-fA-F]{2,})(?:\](\d+))?\s*$", s)
    if m_short:
        if m_short.group(3):
            return int(m_short.group(3))
        return 1
    depth = 0
    for i, ch in enumerate(s):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                count_str = s[i + 1:].strip()
                if not count_str:
                    return None
                if count_str.isdigit():
                    return int(count_str)
                return count_str
    return None


def _suffix_candidates_for_pcs_lookup(suffix: str) -> List[str]:
    """Strip trailing +N / -N segments to match NamedAnchor PCS table names (e.g. data.pokemon.names+28)."""
    out: List[str] = []
    s = suffix.strip()
    seen = set()
    while s and s not in seen:
        seen.add(s)
        out.append(s)
        m = re.match(r"^(.+?)([+-]\d+)$", s)
        if not m:
            break
        s = m.group(1).strip()
    return out


def _find_pcs_table_for_struct_suffix(
    pcs_tables: List[Dict[str, Any]], suffix: str
) -> Optional[Dict[str, Any]]:
    """If the constant after ] names a PCS string table, return its get_pcs_table_anchors() entry."""
    for cand in _suffix_candidates_for_pcs_lookup(suffix):
        for info in pcs_tables:
            if info["name"] == cand:
                return info
    return None


def _load_toml_lists(toml_data: Dict[str, Any]) -> Dict[str, Dict[int, str]]:
    """Load [[List]] entries into {name: {index: label}} (names normalized like NamedAnchors)."""
    lists: Dict[str, Dict[int, str]] = {}
    for lst in toml_data.get("List", []):
        if not isinstance(lst, dict):
            continue
        name = normalize_named_anchor_lookup_key(str(lst.get("Name", "")))
        if not name:
            continue
        enum_map: Dict[int, str] = {}
        for key, val in lst.items():
            if key in ("Name", "DefaultHash"):
                continue
            try:
                idx = int(key)
            except (ValueError, TypeError):
                continue
            if isinstance(val, list):
                for i, v in enumerate(val):
                    enum_map[idx + i] = str(v).strip().strip("'\"")
            else:
                enum_map[idx] = str(val).strip().strip("'\"")
        lists[name] = enum_map
    return lists


def _list_row_key_and_offset(list_dict: Dict[str, Any], flat_index: int) -> Optional[Tuple[Any, int]]:
    """For one ``[[List]]`` row dict, return ``(toml_key, offset_in_array)`` for a flat index, or None."""
    spans: List[Tuple[Any, int, int]] = []
    for key, val in list_dict.items():
        if str(key) in ("Name", "DefaultHash"):
            continue
        try:
            base = int(key)
        except (TypeError, ValueError):
            continue
        if isinstance(val, list):
            spans.append((key, base, len(val)))
        else:
            spans.append((key, base, 1))
    spans.sort(key=lambda t: t[1])
    for key, base, ln in spans:
        if base <= flat_index < base + ln:
            return (key, flat_index - base)
    return None


class StructEditorFrame(ttk.Frame):
    """Displays and edits structured data from a NamedAnchor, one entry at a time.
    Parses Format DSL fields (., :, <>, <"">, List enums, NamedAnchor cross-refs)."""

    def __init__(self, parent: tk.Misc, hex_editor: "HexEditorFrame", **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._hex = hex_editor
        self._anchors: List[Dict[str, Any]] = []
        self._lists: Dict[str, Dict[int, str]] = {}
        self._list_enum_active_pcs: Optional[Dict[str, Any]] = None
        self._fields: List[Dict[str, Any]] = []
        self._entry_count = 0
        self._struct_size = 0
        self._base_off = 0
        self._struct_packed_terminator = False
        self._packed_terminator_fd: Optional[Dict[str, Any]] = None
        self._edit_entry: Optional[tk.Entry] = None
        self._edit_iid: Optional[str] = None
        self._entry_index_context_pcs: Optional[Dict[str, Any]] = None
        self._entry_index_context_list: Optional[str] = None
        self._struct_filter_job: Optional[str] = None
        self._struct_match_entries: List[Tuple[str, str, Optional[int]]] = []
        self._build()

    def _entry_pcs_row_for_struct_index(self, struct_idx: int) -> Optional[int]:
        """PCS row for ``]pcsTable±N…`` struct count: ``pcs_row = struct_idx - (struct_count - pcs_count)``.

        When the Format suffix only changes the struct table length (e.g. ``data.pokemon.names+1``), the
        linked PCS table row count differs by the same amount; map struct indices so lookup matches that offset.
        """
        pcs = self._entry_index_context_pcs
        if not pcs:
            return None
        pcs_n = int(pcs.get("count") or 0)
        if pcs_n <= 0:
            return None
        delta = int(self._entry_count) - pcs_n
        row = int(struct_idx) - delta
        if 0 <= row < pcs_n:
            return row
        return None

    def _entry_list_row_for_struct_index(self, struct_idx: int, list_name: str) -> Optional[int]:
        """Map struct row index to flat ``[[List]]`` index (same delta rule as :meth:`_entry_pcs_row_for_struct_index`)."""
        lm = self._hex.get_lists().get(list_name)
        if not lm:
            return None
        list_n = self._hex._resolve_list_entry_span_end(list_name)
        if list_n is None or list_n <= 0:
            mk = [k for k in lm.keys() if isinstance(k, int)]
            list_n = max(mk) + 1 if mk else 0
        if list_n <= 0:
            return None
        delta = int(self._entry_count) - int(list_n)
        row = int(struct_idx) - delta
        if 0 <= row < list_n:
            return row
        return None

    def _entry_file_offset(self, entry_idx: int) -> int:
        """ROM file offset of struct row ``entry_idx`` (packed ``!HEX`` tables scan previous rows)."""
        if not self._struct_packed_terminator or not self._packed_terminator_fd:
            return self._base_off + entry_idx * self._struct_size
        data = self._hex.get_data()
        if not data:
            return self._base_off
        pos = _packed_terminator_entry_file_offset(
            bytes(data), self._base_off, entry_idx, self._packed_terminator_fd
        )
        return pos if pos is not None else self._base_off

    def _sync_hex_cursor_to_current_struct_entry(self, entry_idx: int) -> None:
        """Move hex view to the **struct row** in ROM (table base + index × row size).

        Pointer payloads (e.g. ``offset<>`` + data at ``*offset``) are **not** auto-followed here — that was
        stealing focus from NamedAnchor / Goto, which must land on the table ``Address``. Use **Follow pointer**
        on the ``offset`` field to jump to the deck blob.
        """
        he = self._hex
        if he is None or not hasattr(he, "_do_goto"):
            return
        data = self._hex.get_data()
        if not data:
            return
        entry_base = self._entry_file_offset(entry_idx)
        # Default ``!HEX>``: field (e.g. ``offset``) is a 4-byte ptr; jump to *ptr (card data), not the anchor.
        if (
            len(self._fields) == 1
            and self._fields[0].get("type") == "nested_array"
            and self._fields[0].get("terminator")
            and self._fields[0].get("nested_ptr_is_self_field")
        ):
            na_base = self._nested_array_data_base(entry_base, self._fields[0], bytes(data))
            if na_base is not None:
                he._do_goto(na_base)
                gv = getattr(he, "_goto_var", None)
                if gv is not None:
                    try:
                        gv.set(f"{na_base:08X}")
                    except (tk.TclError, AttributeError):
                        pass
            return
        he._do_goto(entry_base)
        gv = getattr(he, "_goto_var", None)
        if gv is not None:
            try:
                gv.set(f"{entry_base:08X}")
            except (tk.TclError, AttributeError):
                pass  # widget may be gone

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(6, weight=1)
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Struct:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._combo = ttk.Combobox(top, font=("Consolas", 8), state="readonly")
        self._combo.grid(row=0, column=1, sticky="ew")
        self._combo.bind("<<ComboboxSelected>>", self._on_combo_select)
        srow = ttk.Frame(top)
        srow.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(2, 0))
        srow.columnconfigure(1, weight=1)
        ttk.Label(srow, text="Search:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._struct_search_var = tk.StringVar()
        ttk.Entry(srow, textvariable=self._struct_search_var, font=("Consolas", 8)).grid(row=0, column=1, sticky="ew")
        ttk.Label(srow, text="Matches:", font=("Consolas", 8)).grid(row=1, column=0, sticky="w", padx=(0, 4), pady=(2, 0))
        self._struct_match_combo = ttk.Combobox(srow, font=("Consolas", 8), state="readonly", width=56)
        self._struct_match_combo.grid(row=1, column=1, sticky="ew", pady=(2, 0))
        self._struct_match_combo.bind("<<ComboboxSelected>>", self._on_struct_match_combo_select)
        self._struct_match_suppress = False

        nav = ttk.Frame(self)
        nav.grid(row=1, column=0, sticky="ew", pady=(0, 2))
        nav.columnconfigure(3, weight=1)
        ttk.Label(nav, text="Entry:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._idx_var = tk.StringVar(value="0")
        self._idx_spin = ttk.Spinbox(
            nav, textvariable=self._idx_var, from_=0, to=0,
            width=6, font=("Consolas", 8), command=self._on_spin_change,
        )
        self._idx_spin.grid(row=0, column=1, sticky="w")
        self._idx_spin.bind("<Return>", lambda e: self._on_spin_change())
        self._entry_label = ttk.Label(nav, text="/ 0", font=("Consolas", 8))
        self._entry_label.grid(row=0, column=2, sticky="w", padx=(4, 0))
        self._entry_index_name_label = ttk.Label(nav, text="", font=("Consolas", 8))
        self._entry_index_name_label.grid(row=0, column=3, sticky="w", padx=(8, 0))
        self._entry_index_name_label.grid_remove()
        self._struct_add_n_var = tk.IntVar(value=1)
        ttk.Label(nav, text="Add", font=("Consolas", 8)).grid(row=0, column=4, sticky="e", padx=(12, 2))
        ttk.Spinbox(
            nav, from_=1, to=500, width=4, textvariable=self._struct_add_n_var, font=("Consolas", 8)
        ).grid(row=0, column=5, sticky="w")
        self._struct_new_rows_btn = ttk.Button(nav, text="new rows", command=self._on_struct_add_rows)
        self._struct_new_rows_btn.grid(row=0, column=6, sticky="w", padx=(4, 0))

        self._entry_search_frame = ttk.Frame(nav)
        self._entry_search_frame.columnconfigure(1, weight=1)
        ttk.Label(self._entry_search_frame, text="Find:", font=("Consolas", 8)).grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self._entry_search_var = tk.StringVar()
        self._entry_search_entry = ttk.Entry(
            self._entry_search_frame, textvariable=self._entry_search_var, font=("Consolas", 8)
        )
        self._entry_search_entry.grid(row=0, column=1, sticky="ew")
        self._entry_search_var.trace_add("write", lambda *_: self._schedule_struct_combo_filter())
        self._entry_search_entry.bind("<Return>", lambda e: self._on_entry_search_next())
        self._entry_search_result_label = ttk.Label(
            self._entry_search_frame, text="", font=("Consolas", 8)
        )
        self._entry_search_result_label.grid(row=0, column=2, sticky="w", padx=(4, 0))
        self._entry_search_frame.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(2, 0))
        self._entry_search_frame.grid_remove()
        self._entry_search_matches: List[int] = []
        self._entry_search_match_pos: int = 0

        # Edit PCS string for the Format ]suffix table row (same index as struct entry)
        self._entry_label_pcs_frame = ttk.Frame(self)
        self._entry_label_pcs_frame.columnconfigure(1, weight=1)
        ttk.Label(self._entry_label_pcs_frame, text="Entry PCS (table row):", font=("Consolas", 8)).grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self._entry_label_pcs_var = tk.StringVar(value="")
        self._entry_label_pcs_entry = ttk.Entry(
            self._entry_label_pcs_frame, textvariable=self._entry_label_pcs_var, font=("Consolas", 9)
        )
        self._entry_label_pcs_entry.grid(row=0, column=1, sticky="ew", padx=(0, 4))
        self._entry_label_pcs_entry.bind("<Return>", lambda e: self._on_entry_label_pcs_apply())
        ttk.Button(
            self._entry_label_pcs_frame, text="Apply", command=self._on_entry_label_pcs_apply
        ).grid(row=0, column=2, sticky="e")
        self._entry_label_pcs_frame.grid(row=2, column=0, sticky="ew", pady=(0, 2))
        self._entry_label_pcs_frame.grid_remove()

        # pcs_ptr: edit GBA pointer and PCS text (relocates into 0xFF gaps if string grows)
        self._ptr_text_frame = ttk.Frame(self)
        self._ptr_text_frame.columnconfigure(1, weight=1)
        ttk.Label(self._ptr_text_frame, text="pcs_ptr field", font=("Consolas", 8, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w"
        )
        ttk.Label(self._ptr_text_frame, text="Pointer (GBA):", font=("Consolas", 8)).grid(
            row=1, column=0, sticky="w", padx=(0, 4), pady=(0, 2)
        )
        self._ptr_addr_var = tk.StringVar(value="")
        self._ptr_addr_entry = ttk.Entry(
            self._ptr_text_frame, textvariable=self._ptr_addr_var, font=("Consolas", 9), width=14
        )
        self._ptr_addr_entry.grid(row=1, column=1, sticky="ew", padx=(0, 4), pady=(0, 2))
        self._ptr_addr_entry.bind("<Return>", lambda e: self._on_ptr_pointer_apply())
        ttk.Button(
            self._ptr_text_frame, text="Set pointer", command=self._on_ptr_pointer_apply
        ).grid(row=1, column=2, sticky="e", pady=(0, 2))
        ttk.Label(self._ptr_text_frame, text="PCS text:", font=("Consolas", 8)).grid(
            row=2, column=0, sticky="nw", padx=(0, 4), pady=(0, 2)
        )
        self._ptr_text_entry = ttk.Entry(self._ptr_text_frame, font=("Consolas", 9))
        self._ptr_text_entry.grid(row=2, column=1, sticky="ew", padx=(0, 4), pady=(0, 2))
        self._ptr_text_entry.bind("<Return>", lambda e: self._on_ptr_text_update())
        self._ptr_text_update_btn = ttk.Button(
            self._ptr_text_frame, text="Apply text", command=self._on_ptr_text_update
        )
        self._ptr_text_update_btn.grid(row=2, column=2, sticky="e", pady=(0, 2))
        self._ptr_text_fi: Optional[int] = None

        gap_f = ttk.Frame(self._ptr_text_frame)
        gap_f.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        gap_f.columnconfigure(1, weight=1)
        gap_f.columnconfigure(3, weight=1)
        ttk.Label(gap_f, text="FF gap search from", font=("Consolas", 8)).grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self._ptr_ff_gap_from_var = tk.StringVar(value="")
        ttk.Entry(gap_f, textvariable=self._ptr_ff_gap_from_var, font=("Consolas", 8)).grid(
            row=0, column=1, sticky="ew", padx=(0, 4)
        )
        ttk.Label(gap_f, text="through", font=("Consolas", 8)).grid(row=0, column=2, padx=(0, 4))
        self._ptr_ff_gap_to_var = tk.StringVar(value="")
        ttk.Entry(gap_f, textvariable=self._ptr_ff_gap_to_var, font=("Consolas", 8)).grid(
            row=0, column=3, sticky="ew", padx=(0, 4)
        )
        ttk.Label(
            gap_f,
            text="(file offset or GBA 0x08…; both blank = whole ROM; “through” is inclusive)",
            font=("Consolas", 7),
        ).grid(row=1, column=0, columnspan=4, sticky="w", pady=(2, 0))

        # sprite<`ucs4xWxH|palette.anchor`>: decode via built-in gfx + optional palette NamedAnchor
        self._gfx_sprite_frame = ttk.Frame(self)
        self._gfx_sprite_frame.columnconfigure(0, weight=1)
        ttk.Label(self._gfx_sprite_frame, text="sprite (graphics)", font=("Consolas", 8, "bold")).grid(
            row=0, column=0, columnspan=3, sticky="w"
        )
        gfx_nav = ttk.Frame(self._gfx_sprite_frame)
        gfx_nav.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        gfx_nav.columnconfigure(0, weight=1)
        gfx_nav_top = ttk.Frame(gfx_nav)
        gfx_nav_top.grid(row=0, column=0, sticky="ew")
        ttk.Button(gfx_nav_top, text="Decode preview", command=self._on_decode_gfx_sprite).pack(
            side=tk.LEFT
        )
        ttk.Label(gfx_nav_top, text="Tile rows (H):", font=("Consolas", 8)).pack(side=tk.LEFT, padx=(12, 4))
        self._gfx_struct_sprite_rows_var = tk.IntVar(value=1)
        self._gfx_struct_sprite_rows_spin = ttk.Spinbox(
            gfx_nav_top,
            from_=1,
            to=9999,
            width=5,
            textvariable=self._gfx_struct_sprite_rows_var,
            font=("Consolas", 8),
        )
        self._gfx_struct_sprite_rows_spin.pack(side=tk.LEFT, padx=(0, 4))
        self._gfx_struct_sprite_rows_spin.bind("<Return>", lambda _e: self._on_decode_gfx_sprite())
        ttk.Button(gfx_nav_top, text="Apply layout", command=self._on_decode_gfx_sprite).pack(side=tk.LEFT)
        self._gfx_struct_sprite_pal_row = ttk.Frame(self._gfx_sprite_frame)
        self._gfx_struct_sprite_pal_row.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        self._gfx_struct_sprite_pal_row.columnconfigure(1, weight=1)
        ttk.Label(
            self._gfx_struct_sprite_pal_row,
            text="Preview palette (offset or TOML Name):",
            font=("Consolas", 8),
        ).grid(row=0, column=0, sticky="nw", padx=(0, 4), pady=(2, 0))
        self._gfx_struct_sprite_pal_off_var = tk.StringVar(value="")
        ttk.Entry(
            self._gfx_struct_sprite_pal_row,
            textvariable=self._gfx_struct_sprite_pal_off_var,
            width=12,
            font=("Consolas", 8),
        ).grid(row=0, column=1, columnspan=3, sticky="ew", padx=(0, 6), pady=(2, 0))
        ttk.Label(self._gfx_struct_sprite_pal_row, text="bpp:", font=("Consolas", 8)).grid(
            row=1, column=0, sticky="w", padx=(0, 4), pady=(2, 0)
        )
        self._gfx_struct_sprite_pal_bpp_var = tk.StringVar(value="4")
        ttk.Combobox(
            self._gfx_struct_sprite_pal_row,
            textvariable=self._gfx_struct_sprite_pal_bpp_var,
            values=("4", "6", "8"),
            width=3,
            state="readonly",
            font=("Consolas", 8),
        ).grid(row=1, column=1, sticky="w", padx=(0, 0), pady=(2, 0))
        ttk.Label(self._gfx_struct_sprite_pal_row, text="Data:", font=("Consolas", 8)).grid(
            row=2, column=0, sticky="w", padx=(0, 4), pady=(2, 0)
        )
        self._gfx_struct_sprite_pal_storage_var = tk.StringVar(value="raw")
        ttk.Combobox(
            self._gfx_struct_sprite_pal_row,
            textvariable=self._gfx_struct_sprite_pal_storage_var,
            values=("raw", "lz77"),
            width=6,
            state="readonly",
            font=("Consolas", 8),
        ).grid(row=2, column=1, sticky="w", padx=(0, 8), pady=(2, 0))
        struct_pal_btns = ttk.Frame(self._gfx_struct_sprite_pal_row)
        struct_pal_btns.grid(row=3, column=0, columnspan=4, sticky="w", pady=(4, 0))
        ttk.Button(
            struct_pal_btns,
            text="Load",
            command=self._on_struct_sprite_preview_palette_load,
        ).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(
            struct_pal_btns,
            text="Clear",
            command=self._on_struct_sprite_preview_palette_clear,
        ).pack(side=tk.LEFT)
        self._gfx_struct_sprite_pal_status = ttk.Label(
            self._gfx_struct_sprite_pal_row,
            text="",
            font=("Consolas", 7),
            foreground="#060",
            wraplength=280,
        )
        self._gfx_struct_sprite_pal_status.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(4, 0))
        self._gfx_log = tk.Text(
            self._gfx_sprite_frame, height=4, font=("Consolas", 7), wrap=tk.WORD, state=tk.DISABLED
        )
        self._gfx_log.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(0, 4))
        self._gfx_img_label = ttk.Label(self._gfx_sprite_frame, text="")
        self._gfx_img_label.grid(row=4, column=0, sticky="nw")
        self._gfx_sprite_frame.grid(row=5, column=0, sticky="ew", pady=(0, 2))
        self._gfx_sprite_frame.grid_remove()
        self._gfx_fi: Optional[int] = None
        self._gfx_sprite_last_fi: Optional[int] = None
        self._gfx_photo: Optional[Any] = None
        self._gfx_struct_sprite_palette_override: Optional[Tuple[int, int, bool]] = None

        # tileset<`lzt4`> tilemap<`lzm4xWxH|…`> palette<`ucp4`>: composite tilemap decode
        self._gfx_tilemap_frame = ttk.Frame(self)
        self._gfx_tilemap_frame.columnconfigure(0, weight=1)
        ttk.Label(self._gfx_tilemap_frame, text="tilemap (tileset + map + optional palette)", font=("Consolas", 8, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        tm_nav = ttk.Frame(self._gfx_tilemap_frame)
        tm_nav.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 4))
        ttk.Button(tm_nav, text="Decode preview", command=self._on_decode_gfx_tilemap).pack(side=tk.LEFT)
        self._gfx_tm_log = tk.Text(
            self._gfx_tilemap_frame, height=4, font=("Consolas", 7), wrap=tk.WORD, state=tk.DISABLED
        )
        self._gfx_tm_log.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        self._gfx_tm_img_label = ttk.Label(self._gfx_tilemap_frame, text="")
        self._gfx_tm_img_label.grid(row=3, column=0, sticky="nw")
        self._gfx_tilemap_frame.grid(row=5, column=0, sticky="ew", pady=(0, 2))
        self._gfx_tilemap_frame.grid_remove()
        self._gfx_tm_photo: Optional[Any] = None

        # [[List]] enum: ROM dropdown + TOML label. PCS NamedAnchor table enum: ROM dropdown + PCS string in ROM.
        self._list_enum_frame = ttk.Frame(self)
        self._list_enum_frame.columnconfigure(0, weight=1)
        ttk.Label(self._list_enum_frame, text="[ROM ▾]", font=("Consolas", 8, "bold")).grid(
            row=0, column=0, sticky="nw", padx=(0, 4), pady=(0, 2)
        )
        ttk.Label(self._list_enum_frame, text="Pick index (writes ROM only):", font=("Consolas", 8)).grid(
            row=0, column=1, sticky="w", pady=(0, 2)
        )
        self._list_enum_search_var = tk.StringVar(value="")
        search_row = ttk.Frame(self._list_enum_frame)
        search_row.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        search_row.columnconfigure(1, weight=1)
        ttk.Label(search_row, text="Search:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._list_enum_search_entry = ttk.Entry(
            search_row, textvariable=self._list_enum_search_var, font=("Consolas", 8)
        )
        self._list_enum_search_entry.grid(row=0, column=1, sticky="ew")
        self._list_enum_search_var.trace_add("write", lambda *_a: self._on_list_enum_search_changed())
        self._list_enum_rom_combo = ttk.Combobox(
            self._list_enum_frame, font=("Consolas", 8), width=36, state="readonly"
        )
        self._list_enum_rom_combo.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        self._list_enum_rom_combo.bind("<<ComboboxSelected>>", self._on_list_enum_rom_combo)
        self._list_enum_idx_by_combo: List[int] = []
        self._list_enum_all_display: List[str] = []
        self._list_enum_all_indices: List[int] = []
        ttk.Separator(self._list_enum_frame, orient=tk.HORIZONTAL).grid(
            row=3, column=0, columnspan=2, sticky="ew", pady=(0, 4)
        )
        self._list_enum_toml_block = ttk.Frame(self._list_enum_frame)
        self._list_enum_toml_block.columnconfigure(0, weight=1)
        ttk.Label(self._list_enum_toml_block, text="[TOML \u270e]", font=("Consolas", 8, "bold")).grid(
            row=0, column=0, sticky="nw", padx=(0, 4), pady=(0, 2)
        )
        ttk.Label(
            self._list_enum_toml_block,
            text="Label at current ROM index ([[List]]):",
            font=("Consolas", 8),
        ).grid(row=0, column=1, sticky="w", pady=(0, 2))
        self._list_enum_toml_var = tk.StringVar(value="")
        self._list_enum_toml_entry = ttk.Entry(
            self._list_enum_toml_block, textvariable=self._list_enum_toml_var, font=("Consolas", 9)
        )
        self._list_enum_toml_entry.grid(row=1, column=0, sticky="ew", padx=(0, 4))
        self._list_enum_toml_btn = ttk.Button(
            self._list_enum_toml_block, text="Apply to TOML", command=self._on_list_enum_toml_apply
        )
        self._list_enum_toml_btn.grid(row=1, column=1, sticky="e", padx=(4, 0))
        self._list_enum_toml_entry.bind("<Return>", lambda e: self._on_list_enum_toml_apply())
        self._list_enum_toml_block.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        self._list_enum_toml_block.grid_remove()

        self._list_enum_pcs_block = ttk.Frame(self._list_enum_frame)
        self._list_enum_pcs_block.columnconfigure(0, weight=1)
        ttk.Label(self._list_enum_pcs_block, text="[ROM PCS \u270e]", font=("Consolas", 8, "bold")).grid(
            row=0, column=0, sticky="nw", padx=(0, 4), pady=(0, 2)
        )
        ttk.Label(
            self._list_enum_pcs_block,
            text="String at current ROM index (NamedAnchor PCS table):",
            font=("Consolas", 8),
        ).grid(row=0, column=1, sticky="w", pady=(0, 2))
        self._list_enum_pcs_var = tk.StringVar(value="")
        self._list_enum_pcs_entry = ttk.Entry(
            self._list_enum_pcs_block, textvariable=self._list_enum_pcs_var, font=("Consolas", 9)
        )
        self._list_enum_pcs_entry.grid(row=1, column=0, sticky="ew", padx=(0, 4))
        self._list_enum_pcs_btn = ttk.Button(
            self._list_enum_pcs_block, text="Apply to ROM", command=self._on_list_enum_pcs_apply
        )
        self._list_enum_pcs_btn.grid(row=1, column=1, sticky="e", padx=(4, 0))
        self._list_enum_pcs_entry.bind("<Return>", lambda e: self._on_list_enum_pcs_apply())
        self._list_enum_pcs_block.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        self._list_enum_pcs_block.grid_remove()
        self._list_enum_fi: Optional[int] = None
        self._list_enum_ctx: Optional[Dict[str, Any]] = None
        self._list_enum_frame.grid(row=3, column=0, sticky="ew", pady=(0, 2))
        self._list_enum_frame.grid_remove()

        tree_f = ttk.Frame(self)
        tree_f.grid(row=6, column=0, sticky="nsew")
        tree_f.columnconfigure(0, weight=1)
        tree_f.rowconfigure(0, weight=1)
        self._tree = ttk.Treeview(
            tree_f, columns=("field", "val"), show="headings", height=8, selectmode="browse",
        )
        self._tree.heading("field", text="Field")
        self._tree.heading("val", text="Value")
        self._tree.column("field", width=80, minwidth=60)
        self._tree.column("val", width=100, minwidth=40)
        sy = tk.Scrollbar(tree_f, command=self._tree.yview)
        sx = tk.Scrollbar(tree_f, orient=tk.HORIZONTAL, command=self._tree.xview)
        self._tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        self._tree_expand_slots_frame = ttk.Frame(tree_f)
        ttk.Label(self._tree_expand_slots_frame, text="Add", font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 4))
        self._tree_expand_slots_n_var = tk.IntVar(value=1)
        ttk.Spinbox(
            self._tree_expand_slots_frame,
            from_=1,
            to=500,
            width=4,
            textvariable=self._tree_expand_slots_n_var,
            font=("Consolas", 8),
        ).pack(side=tk.LEFT)
        self._tree_expand_slots_btn = ttk.Button(
            self._tree_expand_slots_frame,
            text="table slots",
            command=self._on_struct_expand_table_slots,
        )
        self._tree_expand_slots_btn.pack(side=tk.LEFT, padx=(6, 0))
        self._tree_expand_slots_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self._tree_expand_slots_frame.grid_remove()
        self._tree.bind("<Return>", self._start_inline_edit)
        self._tree.bind("<F2>", self._start_inline_edit)
        self._tree.bind("<ButtonRelease-1>", self._on_tree_click)
        self._tree.bind("<<TreeviewSelect>>", lambda e: self._sync_field_aux_panels())

        def _tree_wheel(e: tk.Event) -> None:
            if e.delta:
                self._tree.yview_scroll(int(-1 * e.delta / 120), "units")
            elif getattr(e, "num", None) == 4:
                self._tree.yview_scroll(-3, "units")
            elif getattr(e, "num", None) == 5:
                self._tree.yview_scroll(3, "units")

        self._tree.bind("<MouseWheel>", _tree_wheel)
        self._tree.bind("<Button-4>", _tree_wheel)
        self._tree.bind("<Button-5>", _tree_wheel)

    def _on_tree_click(self, event: tk.Event) -> None:
        reg = self._tree.identify_region(event.x, event.y)
        if reg == "cell":
            col = self._tree.identify_column(event.x)
            if col == "#2":
                self.after_idle(self._start_inline_edit_after_click)
        self._sync_field_aux_panels()

    def _sync_field_aux_panels(self) -> None:
        self._update_ptr_text_panel()
        self._update_list_enum_panel()
        self._update_gfx_sprite_panel()
        self._update_gfx_tilemap_panel()

    def _set_gfx_log(self, text: str) -> None:
        self._gfx_log.configure(state=tk.NORMAL)
        self._gfx_log.delete("1.0", tk.END)
        self._gfx_log.insert("1.0", text)
        self._gfx_log.configure(state=tk.DISABLED)

    def _set_gfx_tm_log(self, text: str) -> None:
        self._gfx_tm_log.configure(state=tk.NORMAL)
        self._gfx_tm_log.delete("1.0", tk.END)
        self._gfx_tm_log.insert("1.0", text)
        self._gfx_tm_log.configure(state=tk.DISABLED)

    def _explicit_tilemap_field_indices(self) -> Optional[Tuple[int, int, Optional[int]]]:
        """If struct has ``tileset<`…`>`` + ``tilemap<`…`>`` (+ optional ``palette<`…`>``), return (ts_i, tm_i, pl_i)."""
        by_name: Dict[str, Tuple[int, Dict[str, Any]]] = {}
        for i, f in enumerate(self._fields):
            n = f.get("name")
            if not n:
                continue
            t = f.get("type")
            if t in ("gfx_tileset", "gfx_tilemap", "gfx_palette"):
                by_name[str(n)] = (i, f)
        if "tilemap" in by_name and by_name["tilemap"][1].get("type") == "gfx_tilemap":
            tm_i, _ = by_name["tilemap"]
            ts_i: Optional[int] = None
            pl_i: Optional[int] = None
            if "tileset" in by_name and by_name["tileset"][1].get("type") == "gfx_tileset":
                ts_i = by_name["tileset"][0]
            if "palette" in by_name and by_name["palette"][1].get("type") == "gfx_palette":
                pl_i = by_name["palette"][0]
            if ts_i is not None:
                return (ts_i, tm_i, pl_i)
        ts_list = [i for i, f in enumerate(self._fields) if f.get("type") == "gfx_tileset"]
        tm_list = [i for i, f in enumerate(self._fields) if f.get("type") == "gfx_tilemap"]
        pl_list = [i for i, f in enumerate(self._fields) if f.get("type") == "gfx_palette"]
        if len(tm_list) == 1 and len(ts_list) == 1:
            pl_opt = pl_list[0] if len(pl_list) == 1 else None
            return (ts_list[0], tm_list[0], pl_opt)
        return None

    def _update_gfx_tilemap_panel(self) -> None:
        self._gfx_tilemap_frame.grid_remove()
        tri = self._explicit_tilemap_field_indices()
        if not tri:
            return
        ts_i, tm_i, pl_i = tri
        sel = self._tree.selection()
        if not sel or not sel[0].startswith("sf_"):
            return
        fi, sp = parse_struct_tree_iid(sel[0])
        if _struct_tree_spec_is_nested(sp):
            return
        allowed = {ts_i, tm_i}
        if pl_i is not None:
            allowed.add(pl_i)
        if fi not in allowed:
            return
        self._gfx_sprite_frame.grid_remove()
        self._gfx_tilemap_frame.grid(row=5, column=0, sticky="ew", pady=(0, 2))

    def _on_decode_gfx_tilemap(self) -> None:
        tri = self._explicit_tilemap_field_indices()
        if not tri:
            self._set_gfx_tm_log(
                "Struct has no tileset + tilemap fields (name them tileset/tilemap or use one of each type)."
            )
            return
        ts_i, tm_i, pl_i = tri
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        ts_fd = self._fields[ts_i]
        tm_fd = self._fields[tm_i]
        ts_spec = ts_fd.get("gfx_spec")
        tm_spec = tm_fd.get("gfx_spec")
        if (
            ts_spec is None
            or getattr(ts_spec, "kind", None) != "sprite"
            or tm_spec is None
            or getattr(tm_spec, "kind", None) != "tilemap"
        ):
            self._set_gfx_tm_log("Invalid gfx specs on tileset/tilemap fields.")
            return
        off_base = self._entry_file_offset(entry_idx)
        ts_off_f = off_base + ts_fd["offset"]
        tm_off_f = off_base + tm_fd["offset"]
        if ts_off_f + 4 > len(data) or tm_off_f + 4 > len(data):
            return
        ts_tgt = resolve_gba_pointer(data, ts_off_f)
        tm_tgt = resolve_gba_pointer(data, tm_off_f)
        if ts_tgt is None or tm_tgt is None:
            self._set_gfx_tm_log("Tileset or tilemap pointer does not reference ROM (need 0x08…/0x09…).")
            self._gfx_tm_img_label.configure(image="", text="(bad pointer)")
            return
        pal_spec = None
        pal_base = None
        log_pre = ""
        if pl_i is not None:
            pl_fd = self._fields[pl_i]
            psp = pl_fd.get("gfx_spec")
            if psp is None or getattr(psp, "kind", None) != "palette":
                log_pre = "Warning: palette field spec invalid; using default colors.\n\n"
            else:
                pal_spec = psp
                pl_off = off_base + pl_fd["offset"]
                if pl_off + 4 > len(data):
                    self._set_gfx_tm_log("Palette field out of range.")
                    return
                ptgt = resolve_gba_pointer(data, pl_off)
                if ptgt is None:
                    log_pre = "Warning: palette pointer invalid; using default colors.\n\n"
                else:
                    pal_base = ptgt
        png_path, log = decode_graphics_anchor_to_png(
            bytes(data),
            tm_tgt,
            tm_spec,
            external_palette_spec=pal_spec,
            external_palette_base_off=pal_base,
            external_tileset_spec=ts_spec,
            external_tileset_base_off=ts_tgt,
        )
        self._set_gfx_tm_log(log_pre + log)
        self._gfx_tm_photo = None
        if png_path:
            try:
                from PIL import Image, ImageTk  # type: ignore
                im = Image.open(png_path)
                im = im.convert("RGBA")
                try:
                    resample = Image.Resampling.LANCZOS  # type: ignore[attr-defined]
                except AttributeError:
                    resample = Image.LANCZOS
                im.thumbnail((280, 280), resample)
                self._gfx_tm_photo = ImageTk.PhotoImage(im)
                self._gfx_tm_img_label.configure(image=self._gfx_tm_photo, text="")
            except ImportError:
                self._gfx_tm_img_label.configure(
                    image="",
                    text=f"Install Pillow to preview PNG.\n{png_path}",
                )
            except OSError as e:
                self._gfx_tm_img_label.configure(image="", text=f"Image error: {e}")
        else:
            self._gfx_tm_img_label.configure(image="", text="(decode failed)")

    def _clear_gfx_struct_sprite_palette_override(self) -> None:
        self._gfx_struct_sprite_palette_override = None
        self._gfx_struct_sprite_pal_status.configure(text="")

    def _update_gfx_sprite_panel(self) -> None:
        self._gfx_tilemap_frame.grid_remove()
        prev_fi = self._gfx_fi
        sel = self._tree.selection()
        if not sel or not sel[0].startswith("sf_"):
            self._gfx_sprite_frame.grid_remove()
            self._gfx_fi = None
            self._gfx_sprite_last_fi = None
            self._clear_gfx_struct_sprite_palette_override()
            return
        fi, sp = parse_struct_tree_iid(sel[0])
        if _struct_tree_spec_is_nested(sp):
            self._gfx_sprite_frame.grid_remove()
            self._gfx_fi = None
            self._gfx_sprite_last_fi = None
            self._clear_gfx_struct_sprite_palette_override()
            return
        if fi >= len(self._fields):
            self._gfx_sprite_frame.grid_remove()
            self._gfx_fi = None
            self._gfx_sprite_last_fi = None
            self._clear_gfx_struct_sprite_palette_override()
            return
        fd = self._fields[fi]
        if fd.get("type") != "gfx_sprite":
            self._gfx_sprite_frame.grid_remove()
            self._gfx_fi = None
            self._gfx_sprite_last_fi = None
            self._clear_gfx_struct_sprite_palette_override()
            return
        if prev_fi is not None and prev_fi != fi:
            self._clear_gfx_struct_sprite_palette_override()
        self._gfx_fi = fi
        self._gfx_sprite_frame.grid(row=5, column=0, sticky="ew", pady=(0, 2))
        spec = fd.get("gfx_spec")
        if self._gfx_sprite_last_fi != fi and spec is not None and getattr(spec, "kind", None) == "sprite":
            self._gfx_sprite_last_fi = fi
            if spec.width_tiles == 0 and spec.height_tiles == 0:
                self._gfx_struct_sprite_rows_var.set(1)
            else:
                self._gfx_struct_sprite_rows_var.set(max(1, spec.height_tiles))

    def _on_decode_gfx_sprite(self) -> None:
        fi = self._gfx_fi
        if fi is None or fi >= len(self._fields):
            return
        fd = self._fields[fi]
        if fd.get("type") != "gfx_sprite":
            return
        spec = fd.get("gfx_spec")
        if spec is None:
            messagebox.showwarning("Struct", "Invalid sprite graphics spec in field Format.")
            return
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = self._entry_file_offset(entry_idx) + fd["offset"]
        if foff + 4 > len(data):
            return
        tgt = resolve_gba_pointer(data, foff)
        if tgt is None:
            self._set_gfx_log("Pointer does not reference ROM (need 0x08…/0x09… GBA address).")
            self._gfx_img_label.configure(image="", text="(bad pointer)")
            return
        log_extra = ""
        override_pal_bytes: Optional[bytes] = None
        ov = self._gfx_struct_sprite_palette_override
        if ov is not None:
            ov_off, ov_bpp, ov_lz = ov
            if ov_bpp != spec.bpp:
                log_extra += (
                    f"\nPreview palette override ignored: {ov_bpp}bpp ROM data vs {spec.bpp}bpp sprite field.\n"
                )
            else:
                raw_ov, oerr = read_sprite_preview_palette_at_rom_offset(
                    bytes(data), ov_off, ov_bpp, lz77=ov_lz
                )
                if raw_ov is None:
                    log_extra += f"\nPreview palette override: {oerr}\n"
                else:
                    override_pal_bytes = raw_ov
                    src = "LZ77→" if ov_lz else "raw "
                    log_extra += (
                        f"\nPreview palette: {src}file offset 0x{ov_off:X} ({ov_bpp}bpp, {len(raw_ov)} bytes); "
                        f"linked palette ignored for preview.\n"
                    )

        pal_name = fd.get("gfx_palette_name")
        pal_spec = None
        pal_base = None
        if override_pal_bytes is None and pal_name:
            pal_spec, pal_base, pal_notes = self._hex.resolve_palette_for_graphics_row(pal_name, entry_idx)
            if pal_spec is None or pal_base is None:
                dpal = "64-color (empty)" if spec.bpp == 6 else "16-color"
                log_extra += (
                    (pal_notes or f"\nWarning: could not resolve palette {pal_name!r}.\n")
                    + f"Using default {dpal} palette.\n"
                )
            else:
                log_extra += ("\n" + pal_notes) if pal_notes else ""
        raw_pre = bytes(data[tgt : tgt + min(len(data) - tgt, 4 << 20)])
        try:
            tb = extract_sprite_bytes(spec, raw_pre)
            per = sprite_bytes_per_tile(spec.bpp)
            t_n = len(tb) // per
            if spec.width_tiles > 0 and spec.height_tiles > 0:
                row_max = max(1, t_n)
            else:
                row_max = max(1, max_sprite_height_tiles(t_n))
            self._gfx_struct_sprite_rows_spin.configure(from_=1, to=row_max)
            hv = int(self._gfx_struct_sprite_rows_var.get())
            if hv > row_max:
                self._gfx_struct_sprite_rows_var.set(row_max)
        except Exception:
            self._gfx_struct_sprite_rows_spin.configure(from_=1, to=9999)
        layout_h = max(1, int(self._gfx_struct_sprite_rows_var.get()))
        png_path, log = decode_sprite_at_pointer(
            bytes(data),
            tgt,
            spec,
            pal_spec,
            pal_base,
            sprite_layout_height=layout_h,
            override_sprite_palette_bytes=override_pal_bytes,
        )
        self._set_gfx_log(log_extra + log)
        self._gfx_photo = None
        if png_path:
            try:
                from PIL import Image, ImageTk  # type: ignore
                im = Image.open(png_path)
                im = im.convert("RGBA")
                try:
                    resample = Image.Resampling.LANCZOS  # type: ignore[attr-defined]
                except AttributeError:
                    resample = Image.LANCZOS
                im.thumbnail((220, 220), resample)
                self._gfx_photo = ImageTk.PhotoImage(im)
                self._gfx_img_label.configure(image=self._gfx_photo, text="")
            except ImportError:
                self._gfx_img_label.configure(
                    image="",
                    text=f"Install Pillow to preview PNG.\n{png_path}",
                )
            except OSError as e:
                self._gfx_img_label.configure(image="", text=f"Image error: {e}")
        else:
            self._gfx_img_label.configure(image="", text="(decode failed)")

    def _on_struct_sprite_preview_palette_load(self) -> None:
        fi = self._gfx_fi
        if fi is None or fi >= len(self._fields):
            messagebox.showinfo("Preview palette", "Select a sprite field in the struct tree first.")
            return
        fd = self._fields[fi]
        if fd.get("type") != "gfx_sprite":
            return
        spec = fd.get("gfx_spec")
        if spec is None or getattr(spec, "kind", None) != "sprite":
            messagebox.showwarning("Preview palette", "Invalid sprite graphics spec on this field.")
            return
        data = self._hex.get_data()
        if not data:
            messagebox.showwarning("Preview palette", "No ROM loaded.")
            return
        s = self._gfx_struct_sprite_pal_off_var.get().strip()
        direct_off, _ = parse_rom_file_offset(s)
        off, err = self._hex.resolve_file_offset_or_named_anchor(s)
        if off is None:
            messagebox.showwarning("Preview palette", err or "Invalid offset or TOML Name.")
            return
        try:
            pb = int(str(self._gfx_struct_sprite_pal_bpp_var.get()))
        except (ValueError, tk.TclError):
            pb = 4
        if pb not in (4, 6, 8):
            messagebox.showwarning("Preview palette", "Select palette mode 4, 6, or 8 bpp.")
            return
        if pb != spec.bpp:
            messagebox.showerror(
                "Preview palette",
                f"This sprite field is {spec.bpp}bpp; set the palette mode to {spec.bpp}bpp "
                f"(4→16 colors, 6→64, 8→256).",
            )
            return
        use_lz = str(self._gfx_struct_sprite_pal_storage_var.get()).strip().lower() == "lz77"
        raw, rerr = read_sprite_preview_palette_at_rom_offset(bytes(data), off, pb, lz77=use_lz)
        if raw is None:
            messagebox.showerror("Preview palette", rerr or "Could not read palette bytes.")
            return
        self._gfx_struct_sprite_palette_override = (off, pb, use_lz)
        src = "LZ77 at" if use_lz else "Raw at"
        loc = (
            f"{src} 0x{off:X}"
            if direct_off is not None
            else f"{src} 0x{off:X} (NamedAnchor {normalize_named_anchor_lookup_key(s)!r})"
        )
        self._gfx_struct_sprite_pal_status.configure(
            text=(
                f"{loc} — {pb}bpp ({len(raw)} bytes decoded). "
                "Decode uses this instead of the linked palette."
            ),
            foreground="#060",
        )
        self._on_decode_gfx_sprite()

    def _on_struct_sprite_preview_palette_clear(self) -> None:
        self._clear_gfx_struct_sprite_palette_override()
        self._on_decode_gfx_sprite()

    def _start_inline_edit_after_click(self) -> None:
        if self._tree.selection():
            self._start_inline_edit()

    def _update_ptr_text_panel(self) -> None:
        """Show/hide the text-at-pointer panel depending on selected field type."""
        sel = self._tree.selection()
        if not sel or not sel[0].startswith("sf_"):
            self._ptr_text_frame.grid_remove()
            self._ptr_text_fi = None
            return
        fi, sp = parse_struct_tree_iid(sel[0])
        if _struct_tree_spec_is_nested(sp):
            self._ptr_text_frame.grid_remove()
            self._ptr_text_fi = None
            return
        if fi >= len(self._fields):
            self._ptr_text_frame.grid_remove()
            self._ptr_text_fi = None
            return
        fd = self._fields[fi]
        if fd["type"] != "pcs_ptr":
            self._ptr_text_frame.grid_remove()
            self._ptr_text_fi = None
            return
        self._ptr_text_fi = fi
        self._ptr_text_frame.grid(row=4, column=0, sticky="ew", pady=(0, 2))
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = self._entry_file_offset(entry_idx) + fd["offset"]
        if foff + 4 > len(data):
            return
        ptr = int.from_bytes(data[foff:foff + 4], "little")
        self._ptr_addr_var.set(f"0x{ptr:08X}")
        if (ptr >> 24) in (0x08, 0x09):
            text = self._read_pcs_at_pointer(ptr - GBA_ROM_BASE)
        else:
            text = ""
        self._ptr_text_entry.delete(0, tk.END)
        self._ptr_text_entry.insert(0, text)

    def _pcs_ptr_field_file_off(self, fi: int) -> Optional[int]:
        if fi < 0 or fi >= len(self._fields):
            return None
        fd = self._fields[fi]
        if fd["type"] != "pcs_ptr":
            return None
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return None
        foff = self._entry_file_offset(entry_idx) + fd["offset"]
        data = self._hex.get_data()
        if not data or foff + 4 > len(data):
            return None
        return foff

    def _refresh_pcs_ptr_tree_row(self, fi: int) -> None:
        foff = self._pcs_ptr_field_file_off(fi)
        if foff is None:
            return
        fd = self._fields[fi]
        iid = f"sf_{fi}"
        data2 = self._hex.get_data()
        if data2 and self._tree.exists(iid):
            raw = bytes(data2[foff:foff + fd["size"]])
            try:
                ei = int(self._idx_var.get())
                eb = self._entry_file_offset(ei)
            except (ValueError, TypeError):
                eb = self._base_off
            self._tree.set(iid, "val", self._format_value(raw, fd, entry_base=eb))
            self._refresh_helper_field_rows(eb)

    def _parse_ff_gap_search_window(self) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        """Parse FF-gap search range. Returns ``(window_lo, window_hi_exclusive, error)``.
        ``(None, None, None)`` means search the full ROM."""
        data = self._hex.get_data()
        if not data:
            return None, None, "No ROM loaded."
        n = len(data)
        fs = self._ptr_ff_gap_from_var.get().strip()
        ts = self._ptr_ff_gap_to_var.get().strip()
        if not fs and not ts:
            return None, None, None
        if (fs and not ts) or (not fs and ts):
            return (
                None,
                None,
                'Enter both “from” and “to”, or leave both empty to search the entire ROM.',
            )
        try:
            lo = int(fs, 0)
            hi = int(ts, 0)
        except ValueError:
            return None, None, "Invalid offset (use decimal or 0x hex)."
        if GBA_ROM_BASE <= lo <= GBA_ROM_MAX:
            lo -= GBA_ROM_BASE
        if GBA_ROM_BASE <= hi <= GBA_ROM_MAX:
            hi -= GBA_ROM_BASE
        if lo < 0 or hi >= n:
            return None, None, f"Offsets must lie within the ROM file (0 … 0x{n - 1:X})."
        if hi < lo:
            return None, None, "End offset must be ≥ start offset."
        # Inclusive end → half-open [lo, hi + 1)
        return lo, hi + 1, None

    def _apply_pcs_ptr_string_write(
        self, fi: int, new_text: str, *, file_off: Optional[int] = None
    ) -> bool:
        """Write PCS text at the current pointer; grow into trailing 0xFF padding or relocate into an FF gap."""
        foff = file_off if file_off is not None else self._pcs_ptr_field_file_off(fi)
        if foff is None:
            return False
        data = self._hex.get_data()
        if not data:
            return False
        ptr = int.from_bytes(data[foff:foff + 4], "little")
        if (ptr >> 24) not in (0x08, 0x09):
            messagebox.showwarning(
                "Struct",
                "Pointer must target ROM (0x08xxxxxx or 0x09xxxxxx). Set it under “Pointer (GBA)” first.",
            )
            return False
        target_off = ptr - GBA_ROM_BASE
        if target_off < 0 or target_off >= len(data):
            messagebox.showwarning("Struct", "Pointer is outside the ROM file range.")
            return False
        need = pcs_encoded_payload_length(new_text)
        cap = measure_pcs_rom_slot_capacity(data, target_off)
        if need <= cap:
            enc = encode_pcs_string(new_text, cap)
            self._hex.write_bytes_at(target_off, enc)
            return True
        excl_lo, excl_hi = target_off, target_off + max(cap, 1)
        w_lo, w_hi_ex, w_err = self._parse_ff_gap_search_window()
        if w_err:
            messagebox.showerror("Struct", w_err)
            return False
        if w_lo is not None and w_hi_ex is not None and (w_hi_ex - w_lo) < need:
            messagebox.showerror(
                "Struct",
                f"The chosen search range is only {w_hi_ex - w_lo} byte(s) wide; "
                f"the string needs {need} consecutive 0xFF byte(s) for relocation.",
            )
            return False
        gap = find_disjoint_ff_gap_start(
            data, need, excl_lo, excl_hi, window_lo=w_lo, window_hi=w_hi_ex
        )
        if gap is None:
            hint = (
                "\n\nAdjust “FF gap search from / through” to a known padding region, "
                "or clear those fields to search the whole ROM."
                if w_lo is not None
                else "\n\nTry limiting the search to a region you know is padding (false positives often come "
                "from unrelated 0xFF runs elsewhere in the ROM)."
            )
            messagebox.showerror(
                "Struct",
                f"This string needs {need} byte(s) (text + 0xFF end), but only {cap} byte(s) fit "
                f"at the current address (including any 0xFF padding after the string).\n\n"
                f"No qualifying block of {need} consecutive 0xFF bytes was found in the search range."
                f"{hint}",
            )
            return False
        gba_gap = gap + GBA_ROM_BASE
        if w_lo is not None and w_hi_ex is not None:
            range_note = (
                f"\n\nSearch was limited to file 0x{w_lo:X} … 0x{w_hi_ex - 1:X} (inclusive)."
            )
        else:
            range_note = "\n\nSearch used the entire ROM (set “FF gap search” fields to restrict)."
        if not messagebox.askyesno(
            "Relocate PCS string",
            f"The string needs {need} byte(s) (including 0xFF terminator), but only {cap} byte(s) "
            f"are available at the current address.\n\n"
            f"Found a 0xFF padding region large enough at:\n"
            f"  file offset 0x{gap:X}\n"
            f"  GBA address 0x{gba_gap:08X}\n\n"
            f"Write the string there and update this field’s pointer?"
            f"{range_note}",
        ):
            return False
        enc = encode_pcs_string(new_text, need)
        self._hex.write_bytes_at(gap, enc)
        self._hex.write_bytes_at(foff, gba_gap.to_bytes(4, "little"))
        self._ptr_addr_var.set(f"0x{gba_gap:08X}")
        if messagebox.askyesno(
            "Clear old string",
            f"Fill the previous slot ({cap} byte(s) at GBA 0x{target_off + GBA_ROM_BASE:08X}) "
            f"with 0xFF (recommended)?",
        ):
            self._hex.write_bytes_at(target_off, bytes([0xFF]) * cap)
        return True

    def _on_ptr_pointer_apply(self) -> None:
        """Write the GBA pointer from the panel into the struct field."""
        fi = self._ptr_text_fi
        if fi is None or fi >= len(self._fields):
            return
        fd = self._fields[fi]
        if fd["type"] != "pcs_ptr":
            return
        foff = self._pcs_ptr_field_file_off(fi)
        if foff is None:
            return
        s = self._ptr_addr_var.get().strip()
        try:
            val = int(s, 0)
        except ValueError:
            messagebox.showwarning("Struct", "Invalid pointer. Use hex, e.g. 0x08123456.")
            return
        self._hex.write_bytes_at(foff, val.to_bytes(4, "little"))
        self._refresh_pcs_ptr_tree_row(fi)
        self._update_ptr_text_panel()

    def _on_ptr_text_update(self) -> None:
        """Apply PCS text using padding / 0xFF gap relocation rules."""
        fi = self._ptr_text_fi
        if fi is None or fi >= len(self._fields):
            return
        fd = self._fields[fi]
        if fd["type"] != "pcs_ptr":
            return
        new_text = self._ptr_text_entry.get()
        if self._apply_pcs_ptr_string_write(fi, new_text):
            self._refresh_pcs_ptr_tree_row(fi)
            self._update_ptr_text_panel()

    def _find_pcs_anchor_info_for_enum(self, enum_name: str) -> Optional[Dict[str, Any]]:
        base, _ = _split_enum_field_ref(enum_name)
        ref = base.strip()
        if not ref:
            return None
        nk = normalize_named_anchor_lookup_key(ref)
        for info in self._hex.get_pcs_table_anchors():
            if normalize_named_anchor_lookup_key(str(info["name"])) == nk:
                return info
        return None

    def _is_toml_list_enum_field(self, fd: Dict[str, Any]) -> bool:
        if fd.get("type") != "uint" or not fd.get("enum"):
            return False
        base, _ = _split_enum_field_ref(fd["enum"])
        return bool(base) and normalize_named_anchor_lookup_key(base) in self._lists

    def _is_pcs_table_enum_field(self, fd: Dict[str, Any]) -> bool:
        if fd.get("type") != "uint" or not fd.get("enum"):
            return False
        base, _ = _split_enum_field_ref(fd["enum"])
        if not base or normalize_named_anchor_lookup_key(base) in self._lists:
            return False
        return self._find_pcs_anchor_info_for_enum(fd["enum"]) is not None

    def _is_enum_panel_field(self, fd: Dict[str, Any]) -> bool:
        return self._is_toml_list_enum_field(fd) or self._is_pcs_table_enum_field(fd)

    def _update_list_enum_panel(self) -> None:
        """Show ROM index combobox + [[List]] TOML editor or PCS table string editor (uint or bitfield subfield)."""
        sel = self._tree.selection()
        if not sel or not sel[0].startswith("sf_"):
            self._list_enum_frame.grid_remove()
            self._list_enum_fi = None
            self._list_enum_ctx = None
            self._list_enum_active_pcs = None
            return
        ctx = self._struct_resolve_enum_field_context(sel[0])
        self._list_enum_ctx = ctx
        if ctx is None:
            self._list_enum_frame.grid_remove()
            self._list_enum_fi = None
            self._list_enum_active_pcs = None
            return
        fd = ctx["fd"]
        self._list_enum_fi = int(ctx["fi"])
        self._list_enum_frame.grid(row=3, column=0, sticky="ew", pady=(0, 2))
        data = self._hex.get_data()
        if not data:
            return
        foff = int(ctx["foff"])
        kind = ctx["kind"]
        er = ctx["enum_ref"]
        if kind in ("uint", "nested_uint"):
            if foff + int(fd["size"]) > len(data):
                return
            cur = int.from_bytes(data[foff : foff + int(fd["size"])], "little")
        else:
            if foff + int(fd["size"]) > len(data):
                return
            val = int.from_bytes(data[foff : foff + int(fd["size"])], "little")
            part = ctx["part"]
            cur = (val >> part["shift"]) & ((1 << part["bits"]) - 1)

        self._list_enum_idx_by_combo = []
        self._list_enum_all_display = []
        self._list_enum_all_indices = []
        display_vals: List[str] = []
        list_base, delta = _split_enum_field_ref(er)
        list_key = normalize_named_anchor_lookup_key(list_base)
        list_row = cur + delta
        self._list_enum_search_var.set("")

        if list_key in self._lists:
            self._list_enum_active_pcs = None
            self._list_enum_toml_block.grid()
            self._list_enum_pcs_block.grid_remove()
            lm = self._lists.get(list_key, {})
            mx_bf: Optional[int] = None
            if kind not in ("uint", "nested_uint"):
                mx_bf = (1 << int(ctx["part"]["bits"])) - 1
            for idx in sorted(lm.keys()):
                if mx_bf is not None:
                    rom_try = idx - delta
                    if rom_try < 0 or rom_try > mx_bf:
                        continue
                lab = lm[idx]
                self._list_enum_all_indices.append(idx)
                short = lab.replace("\n", " ")
                if len(short) > 52:
                    short = short[:49] + "\u2026"
                self._list_enum_all_display.append(f"{idx}: {short}")
            self._list_enum_idx_by_combo = list(self._list_enum_all_indices)
            display_vals = list(self._list_enum_all_display)
            self._list_enum_rom_combo["values"] = tuple(display_vals)
            try:
                pos = self._list_enum_idx_by_combo.index(list_row)
            except ValueError:
                if mx_bf is not None and list_row in lm:
                    self._list_enum_rom_combo.set(
                        f"(list row {list_row} needs ROM {list_row - delta}; "
                        f"subfield allows 0\u2013{mx_bf} \u2014 widen Format or trim [[List]])"
                    )
                else:
                    self._list_enum_rom_combo.set(
                        f"(ROM {cur} \u2192 list row {list_row} \u2014 not in [[List]] {list_base!r})"
                    )
            else:
                self._list_enum_rom_combo.current(pos)
            self._list_enum_toml_var.set(lm.get(list_row, ""))
            return

        pcs_info = self._find_pcs_anchor_info_for_enum(er)
        self._list_enum_active_pcs = pcs_info
        self._list_enum_toml_block.grid_remove()
        self._list_enum_pcs_block.grid()
        count = int(pcs_info.get("count") or 0) if pcs_info else 0
        mx_bf_pcs: Optional[int] = None
        if kind not in ("uint", "nested_uint"):
            mx_bf_pcs = (1 << int(ctx["part"]["bits"])) - 1
        for idx in range(count):
            if mx_bf_pcs is not None:
                rom_try = idx - delta
                if rom_try < 0 or rom_try > mx_bf_pcs:
                    continue
            lab = self._pcs_decode_table_row(pcs_info, idx) if pcs_info else ""
            self._list_enum_all_indices.append(idx)
            short = lab.replace("\n", " ")
            if len(short) > 52:
                short = short[:49] + "\u2026"
            self._list_enum_all_display.append(f"{idx}: {short}")
        self._list_enum_idx_by_combo = list(self._list_enum_all_indices)
        display_vals = list(self._list_enum_all_display)
        self._list_enum_rom_combo["values"] = tuple(display_vals)
        try:
            pos = self._list_enum_idx_by_combo.index(list_row)
        except ValueError:
            if mx_bf_pcs is not None and 0 <= list_row < count:
                self._list_enum_rom_combo.set(
                    f"(PCS row {list_row} needs ROM {list_row - delta}; "
                    f"subfield allows 0\u2013{mx_bf_pcs} \u2014 widen Format or trim PCS table)"
                )
            else:
                self._list_enum_rom_combo.set(
                    f"(ROM {cur} \u2192 PCS row {list_row} \u2014 past table or negative)"
                )
        else:
            self._list_enum_rom_combo.current(pos)
        if pcs_info and 0 <= list_row < count:
            self._list_enum_pcs_var.set(self._pcs_decode_table_row(pcs_info, list_row))
        else:
            self._list_enum_pcs_var.set("")

    def _on_list_enum_search_changed(self) -> None:
        """Filter the ROM index combobox by the search text (case-insensitive substring match on the label)."""
        query = self._list_enum_search_var.get().strip().lower()
        if not query:
            self._list_enum_idx_by_combo = list(self._list_enum_all_indices)
            self._list_enum_rom_combo["values"] = tuple(self._list_enum_all_display)
            return
        filtered_display: List[str] = []
        filtered_indices: List[int] = []
        for disp, idx in zip(self._list_enum_all_display, self._list_enum_all_indices):
            if query in disp.lower():
                filtered_display.append(disp)
                filtered_indices.append(idx)
        self._list_enum_idx_by_combo = filtered_indices
        self._list_enum_rom_combo["values"] = tuple(filtered_display)
        if len(filtered_display) == 1:
            self._list_enum_rom_combo.current(0)

    def _on_list_enum_rom_combo(self, event: Optional[tk.Event] = None) -> None:
        ctx = self._list_enum_ctx
        if ctx is None:
            return
        fd = ctx["fd"]
        pos = self._list_enum_rom_combo.current()
        if pos < 0 or pos >= len(self._list_enum_idx_by_combo):
            return
        new_idx = self._list_enum_idx_by_combo[pos]
        _, delta = _split_enum_field_ref(ctx["enum_ref"])
        rom_val = new_idx - delta
        if rom_val < 0:
            messagebox.showwarning("Struct", f"Selection would need ROM index {rom_val} (negative).")
            return
        kind = ctx["kind"]
        if kind in ("uint", "nested_uint"):
            max_u = (1 << (8 * int(fd["size"]))) - 1 if int(fd["size"]) <= 8 else (1 << 32) - 1
            if rom_val > max_u:
                messagebox.showwarning("Struct", f"ROM index {rom_val} does not fit field size.")
                return
        else:
            part = ctx["part"]
            mx = (1 << part["bits"]) - 1
            if rom_val > mx or rom_val < 0:
                messagebox.showwarning(
                    "Struct",
                    f"ROM value {rom_val} does not fit this subfield ({part.get('bits', '?')} bits, "
                    f"allowed 0–{mx}). Widen the segment in the Format string or remove list rows "
                    f"that need a larger stored value.",
                )
                return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        entry_base = self._entry_file_offset(entry_idx)
        foff = int(ctx["foff"])
        data = self._hex.get_data()
        if not data or foff + int(fd["size"]) > len(data):
            return
        if kind in ("uint", "nested_uint"):
            self._hex.write_bytes_at(foff, rom_val.to_bytes(int(fd["size"]), "little"))
            data2 = self._hex.get_data()
            if data2:
                raw = bytes(data2[foff : foff + int(fd["size"])])
                tiid = ctx.get("tree_iid") or f"sf_{ctx['fi']}"
                if self._tree.exists(tiid):
                    self._tree.set(tiid, "val", self._format_value(raw, fd, entry_base=entry_base))
            self._refresh_helper_field_rows(entry_base)
        else:
            if not self._write_bitfield_subvalue_merge(foff, fd, int(ctx["part_idx"]), rom_val):
                return
            self._refresh_bitfield_tree_rows_from_ctx(ctx)
            self._refresh_helper_field_rows(entry_base)

        lk = normalize_named_anchor_lookup_key(_split_enum_field_ref(ctx["enum_ref"])[0])
        if lk in self._lists:
            self._list_enum_toml_var.set(self._lists.get(lk, {}).get(new_idx, ""))
        elif self._list_enum_active_pcs:
            self._list_enum_pcs_var.set(self._pcs_decode_table_row(self._list_enum_active_pcs, new_idx))

    def _on_list_enum_toml_apply(self) -> None:
        ctx = self._list_enum_ctx
        if ctx is None:
            return
        fd = ctx["fd"]
        lk = normalize_named_anchor_lookup_key(_split_enum_field_ref(ctx["enum_ref"])[0])
        if lk not in self._lists:
            return
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = int(ctx["foff"])
        if foff + int(fd["size"]) > len(data):
            return
        kind = ctx["kind"]
        if kind in ("uint", "nested_uint"):
            cur = int.from_bytes(data[foff : foff + int(fd["size"])], "little")
        else:
            val = int.from_bytes(data[foff : foff + int(fd["size"])], "little")
            part = ctx["part"]
            cur = (val >> part["shift"]) & ((1 << part["bits"]) - 1)
        _, delta = _split_enum_field_ref(ctx["enum_ref"])
        list_row = cur + delta
        new_s = self._list_enum_toml_var.get()
        if not self._hex.update_toml_list_string_at_index(lk, list_row, new_s):
            return
        self._reload_lists()
        self._update_list_enum_panel()
        entry_base = self._entry_file_offset(entry_idx)
        data2 = self._hex.get_data()
        if not data2:
            return
        if kind in ("uint", "nested_uint"):
            raw = bytes(data2[foff : foff + int(fd["size"])])
            tiid = ctx.get("tree_iid") or f"sf_{ctx['fi']}"
            if self._tree.exists(tiid):
                self._tree.set(tiid, "val", self._format_value(raw, fd, entry_base=entry_base))
        else:
            self._refresh_bitfield_tree_rows_from_ctx(ctx)
        self._refresh_helper_field_rows(entry_base)

    def _on_list_enum_pcs_apply(self) -> None:
        ctx = self._list_enum_ctx
        if ctx is None or not self._list_enum_active_pcs:
            return
        fd = ctx["fd"]
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = int(ctx["foff"])
        if foff + int(fd["size"]) > len(data):
            return
        kind = ctx["kind"]
        if kind in ("uint", "nested_uint"):
            cur = int.from_bytes(data[foff : foff + int(fd["size"])], "little")
        else:
            val = int.from_bytes(data[foff : foff + int(fd["size"])], "little")
            part = ctx["part"]
            cur = (val >> part["shift"]) & ((1 << part["bits"]) - 1)
        pcs_info = self._list_enum_active_pcs
        count = int(pcs_info.get("count") or 0)
        _, delta = _split_enum_field_ref(ctx["enum_ref"])
        list_row = cur + delta
        if list_row < 0 or list_row >= count:
            messagebox.showwarning(
                "Struct",
                f"Resolved PCS row {list_row} (ROM {cur} + offset {delta:+d}) is outside the table.",
            )
            return
        new_text = self._list_enum_pcs_var.get()
        if not self._write_pcs_table_row(pcs_info, list_row, new_text):
            messagebox.showerror("Struct", "Could not write PCS string (bad address or ROM bounds).")
            return
        self._update_list_enum_panel()
        entry_base = self._entry_file_offset(entry_idx)
        data2 = self._hex.get_data()
        if not data2:
            return
        if kind in ("uint", "nested_uint"):
            tiid = ctx.get("tree_iid") or f"sf_{ctx['fi']}"
            if self._tree.exists(tiid):
                raw = bytes(data2[foff : foff + int(fd["size"])])
                self._tree.set(tiid, "val", self._format_value(raw, fd, entry_base=entry_base))
        else:
            self._refresh_bitfield_tree_rows_from_ctx(ctx)
        self._refresh_helper_field_rows(entry_base)

    def _pcs_table_row_file_offset(self, pcs_info: Dict[str, Any], row_idx: int) -> Optional[int]:
        """File offset of one row in a PCS table anchor, or None."""
        if row_idx < 0 or row_idx >= pcs_info.get("count", 0):
            return None
        anchor = pcs_info["anchor"]
        width = pcs_info["width"]
        addr = anchor.get("Address")
        if addr is None:
            return None
        try:
            gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
            if gba < GBA_ROM_BASE:
                gba += GBA_ROM_BASE
            base = gba - GBA_ROM_BASE
        except (ValueError, TypeError):
            return None
        data = self._hex.get_data()
        if not data:
            return None
        off = base + row_idx * width
        if off + width > len(data):
            return None
        return off

    def _write_pcs_table_row(self, pcs_info: Dict[str, Any], row_idx: int, text: str) -> bool:
        off = self._pcs_table_row_file_offset(pcs_info, row_idx)
        if off is None:
            return False
        width = pcs_info["width"]
        if pcs_info.get("encoding") == "ascii":
            enc = encode_ascii_slot(text, width)
        else:
            enc = encode_pcs_string(text, width)
        self._hex.write_bytes_at(off, bytes(enc))
        return True

    def _on_entry_label_pcs_apply(self) -> None:
        """Write the Entry PCS field to the ]suffix PCS table at the current struct index."""
        if not self._entry_index_context_pcs:
            return
        try:
            idx = int(self._idx_var.get())
        except ValueError:
            return
        idx = max(0, min(idx, self._entry_count - 1))
        pcs_row = self._entry_pcs_row_for_struct_index(idx)
        if pcs_row is None:
            pcs_count = int(self._entry_index_context_pcs.get("count") or 0)
            delta = int(self._entry_count) - pcs_count
            raw = idx - delta
            if raw < 0:
                messagebox.showwarning(
                    "Struct",
                    "This struct index maps before the first PCS row (check Format ]count ±N vs table size).",
                )
            else:
                messagebox.showwarning("Struct", "Current index maps past the PCS table length.")
            return
        text = self._entry_label_pcs_var.get()
        if not self._write_pcs_table_row(self._entry_index_context_pcs, pcs_row, text):
            messagebox.showerror("Struct", "Could not write PCS string (bad address or ROM bounds).")
            return
        self._update_entry_index_name_label()
        self._load_entry(idx)

    def _schedule_struct_combo_filter(self, event: Optional[tk.Event] = None) -> None:
        if self._struct_filter_job is not None:
            try:
                self.after_cancel(self._struct_filter_job)
            except (ValueError, tk.TclError):
                pass
        self._struct_filter_job = self.after(100, self._apply_struct_combo_filter)

    def _on_struct_match_combo_select(self, event: Optional[tk.Event] = None) -> None:
        if self._struct_match_suppress:
            return
        v = self._struct_match_combo.get().strip()
        if not v:
            return
        ent = next((e for e in self._struct_match_entries if e[0] == v), None)
        if not ent:
            return
        _disp, nm, list_idx = ent
        cur_nm = self._combo.get().strip()
        if nm != cur_nm:
            self._combo.set(nm)
            vals = list(self._combo["values"])
            if nm in vals:
                self._combo.current(vals.index(nm))
            self._on_combo_select()
        if list_idx is not None:
            try:
                cur_i = int(self._idx_var.get())
            except ValueError:
                cur_i = -1
            if cur_i != list_idx:
                self._idx_var.set(str(list_idx))
                self._on_spin_change()

    def _apply_struct_combo_filter(self) -> None:
        self._struct_filter_job = None
        # Rebuild from live TOML each time so Search/Matches never uses stale cache.
        self._anchors = self._hex.get_struct_anchors()
        cur = self._combo.get().strip()
        if not self._anchors:
            self._combo.configure(values=[])
            self._combo.set("")
            self._struct_match_entries = []
            self._struct_match_suppress = True
            self._struct_match_combo.configure(values=[])
            self._struct_match_combo.set("")
            self._struct_match_suppress = False
            self._tree.delete(*self._tree.get_children())
            return
        lists_map = self._hex.get_lists()
        q_raw = self._entry_search_var.get().strip()
        q = q_raw.lower()

        # Build result rows from list labels driven by ]count and/or entry_label_list.
        label_entries: List[Tuple[str, str, Optional[int]]] = []
        fallback_entries: List[Tuple[str, str, Optional[int]]] = []
        label_anchor_names_hit: Set[str] = set()
        fallback_anchor_names_hit: Set[str] = set()
        for a in self._anchors:
            nm = str(a["name"])
            nm_l = nm.lower()
            count_ref_raw = str(a.get("count_ref") or "")
            cr = count_ref_raw.lower()
            elk = normalize_named_anchor_lookup_key(str(a.get("entry_label_list") or ""))
            elk_l = elk.lower()
            cr_list_key = normalize_named_anchor_lookup_key(_struct_count_ref_base_name(count_ref_raw)) if count_ref_raw else ""
            pcs = a.get("entry_label_pcs")
            pcs_name_l = str((pcs or {}).get("name", "")).lower()

            if q and q not in _struct_anchor_search_blob(a, lists_map):
                continue

            list_keys: List[str] = []
            if elk:
                list_keys.append(elk)
            if cr_list_key and cr_list_key not in list_keys:
                list_keys.append(cr_list_key)

            found_label = False
            if q:
                for lk in list_keys:
                    lm = lists_map.get(lk) or {}
                    for idx in sorted(lm.keys()):
                        lbl = str(lm[idx])
                        if q in lbl.lower():
                            label_entries.append((lbl, nm, idx))
                            label_anchor_names_hit.add(nm)
                            found_label = True

            if found_label:
                continue

            # Keep anchor fallback results only for non-label matches, or when query is empty.
            if (not q) or (q in nm_l) or (q in cr) or (q in elk_l) or (q in pcs_name_l):
                fallback_entries.append((nm, nm, None))
                fallback_anchor_names_hit.add(nm)

        if q and label_entries:
            match_entries = label_entries
            anchor_names_hit = label_anchor_names_hit
        else:
            match_entries = label_entries + fallback_entries
            anchor_names_hit = label_anchor_names_hit | fallback_anchor_names_hit

        # One row per display string: duplicate labels from shared ]count lists or
        # multiple anchors were cluttering Matches / Find. Prefer the current struct when both match.
        dedup: Dict[str, Tuple[str, str, Optional[int]]] = {}
        for disp, nm, idx in match_entries:
            k = disp.lower()
            prev = dedup.get(k)
            if prev is None:
                dedup[k] = (disp, nm, idx)
            elif cur and nm == cur and prev[1] != cur:
                dedup[k] = (disp, nm, idx)
        match_entries = list(dedup.values())
        self._struct_match_entries = match_entries

        filt = [str(a["name"]) for a in self._anchors if str(a["name"]) in anchor_names_hit]
        self._combo.configure(values=filt)
        self._struct_match_suppress = True
        match_values = [d for d, _, _ in match_entries]
        self._struct_match_combo.configure(values=match_values)
        if match_values:
            if q:
                picked_idx = 0
                for i, (disp, _nm, _idx) in enumerate(match_entries):
                    if disp.lower() == q:
                        picked_idx = i
                        break
                self._struct_match_combo.current(picked_idx)
            else:
                self._struct_match_combo.set("")
        else:
            self._struct_match_combo.set("")
        self._struct_match_suppress = False

        # Select an anchor when Struct dropdown is empty or current is not in filtered set.
        if filt:
            if cur in filt:
                self._combo.current(filt.index(cur))
            elif cur:
                self._combo.set(filt[0])
                self._combo.current(0)
                self._on_combo_select()
            else:
                self._combo.set("")
                self._tree_expand_slots_frame.grid_remove()
                self._struct_new_rows_btn.grid_remove()
        else:
            self._combo.set("")
            self._tree.delete(*self._tree.get_children())
            self._tree_expand_slots_frame.grid_remove()
            self._struct_new_rows_btn.grid_remove()

    def _selected_struct_anchor(self) -> Optional[Dict[str, Any]]:
        name = self._combo.get().strip()
        if not name:
            return None
        want = normalize_named_anchor_lookup_key(name)
        for a in self._anchors:
            if normalize_named_anchor_lookup_key(str(a["name"])) == want:
                return a
        return None

    def selected_struct_supports_ydk_import(self) -> bool:
        """True when the struct Format has `` `ydk` `` (and optional password table name) before the card ``[…]``."""
        return _struct_anchor_info_supports_ydk_import(self._selected_struct_anchor())

    def _on_combo_select(self, event: Optional[tk.Event] = None) -> None:
        info = self._selected_struct_anchor()
        if not info:
            self._tree_expand_slots_frame.grid_remove()
            self._struct_new_rows_btn.grid_remove()
            return
        self._fields = info["fields"]
        self._entry_count = info["count"]
        self._struct_size = info["struct_size"]
        self._base_off = info["base_off"]
        self._struct_packed_terminator = bool(info.get("packed_terminator"))
        self._packed_terminator_fd = info.get("packed_terminator_fd")
        self._entry_index_context_pcs = info.get("entry_label_pcs")
        self._entry_index_context_list = info.get("entry_label_list")
        if not self._entry_index_context_list:
            count_ref_raw = str(info.get("count_ref") or "")
            if count_ref_raw:
                lk = normalize_named_anchor_lookup_key(_struct_count_ref_base_name(count_ref_raw))
                if lk and lk in self._hex.get_lists():
                    self._entry_index_context_list = lk
        self._idx_spin.configure(to=max(0, self._entry_count - 1))
        self._idx_var.set("0")
        self._entry_label.config(text=f"/ {self._entry_count}")
        # Keep Find text while switching structs; it now drives Struct Search/Matches filtering.
        if self._entry_index_context_pcs or self._entry_index_context_list:
            self._entry_search_frame.grid()
        else:
            self._entry_search_frame.grid_remove()
        self._load_entry(0)
        self._sync_hex_cursor_to_current_struct_entry(0)
        self._sync_struct_table_slots_row_buttons()

    def _sync_struct_table_slots_row_buttons(self) -> None:
        """Under the field tree: **table slots** for any ``!``-terminated nested run; nav **new rows** hidden for packed-only ``!`` tables."""
        info = self._selected_struct_anchor()
        if not info:
            self._tree_expand_slots_frame.grid_remove()
            self._struct_new_rows_btn.grid_remove()
            return
        if _struct_supports_terminator_table_slots(info):
            self._tree_expand_slots_frame.grid()
        else:
            self._tree_expand_slots_frame.grid_remove()
        if info.get("packed_terminator") and info.get("packed_terminator_fd"):
            self._struct_new_rows_btn.grid_remove()
        else:
            self._struct_new_rows_btn.grid()

    def _on_struct_add_rows(self) -> None:
        try:
            n = int(self._struct_add_n_var.get())
        except (tk.TclError, ValueError):
            n = 1
        n = max(1, min(n, 500))
        info = self._selected_struct_anchor()
        if not info:
            messagebox.showinfo("Struct", "Select a struct table first.")
            return
        old_count = int(info["count"])
        anchor_name = str(info.get("name", "")).strip()
        ok, err = self._hex.append_struct_table_rows(info, n)
        if not ok:
            messagebox.showerror("Struct", err)
            return
        self._anchors = self._hex.get_struct_anchors()
        self._struct_search_var.set("")
        self._apply_struct_combo_filter()
        vals = list(self._combo["values"])
        if anchor_name in vals:
            self._combo.set(anchor_name)
            self._combo.current(vals.index(anchor_name))
        self._on_combo_select()
        self._idx_var.set(str(old_count))
        self._on_spin_change()

    def _on_struct_expand_table_slots(self) -> None:
        try:
            n = int(self._tree_expand_slots_n_var.get())
        except (tk.TclError, ValueError):
            n = 1
        n = max(1, min(n, 500))
        info = self._selected_struct_anchor()
        if not info:
            messagebox.showinfo("Struct", "Select a struct table first.")
            return
        anchor_name = str(info.get("name", "")).strip()
        fill_dlg = _FillBytesPromptDialog(self.winfo_toplevel())
        if fill_dlg.result is None:
            return
        fill_spec = fill_dlg.result
        try:
            entry_i = int(self._idx_var.get())
        except (ValueError, tk.TclError):
            entry_i = 0
        ok, err = self._hex.expand_struct_table_slots(
            info,
            n,
            entry_i,
            fill_spec=fill_spec,
            repoint_parent=self.winfo_toplevel(),
        )
        if not ok:
            messagebox.showerror("Struct", err)
            return
        self._anchors = self._hex.get_struct_anchors()
        self._struct_search_var.set("")
        self._apply_struct_combo_filter()
        vals = list(self._combo["values"])
        if anchor_name in vals:
            self._combo.set(anchor_name)
            self._combo.current(vals.index(anchor_name))
        self._on_combo_select()
        self._idx_var.set(str(entry_i))
        self._on_spin_change()

    def _on_spin_change(self) -> None:
        try:
            i = int(self._idx_var.get())
        except ValueError:
            return
        i = max(0, min(i, self._entry_count - 1))
        self._idx_var.set(str(i))
        self._load_entry(i)
        self._sync_hex_cursor_to_current_struct_entry(i)

    def _on_entry_search_next(self) -> None:
        """Find entries whose PCS/List label contains the search text and cycle through matches."""
        query = self._entry_search_var.get().strip().lower()
        if not query:
            self._entry_search_result_label.config(text="")
            self._entry_search_matches.clear()
            self._entry_search_match_pos = 0
            return

        matches: List[int] = []
        seen_label: Set[str] = set()
        for idx in range(self._entry_count):
            label = self._entry_label_for_index(idx)
            if not label or query not in label.lower():
                continue
            lk = label.casefold()
            if lk in seen_label:
                continue
            seen_label.add(lk)
            matches.append(idx)

        if not matches:
            self._entry_search_result_label.config(text="0 matches")
            self._entry_search_matches.clear()
            self._entry_search_match_pos = 0
            return

        if matches == self._entry_search_matches:
            self._entry_search_match_pos = (self._entry_search_match_pos + 1) % len(matches)
        else:
            self._entry_search_matches = matches
            self._entry_search_match_pos = 0

        target = matches[self._entry_search_match_pos]
        self._idx_var.set(str(target))
        self._on_spin_change()
        pos_display = self._entry_search_match_pos + 1
        self._entry_search_result_label.config(text=f"{pos_display}/{len(matches)}")

    def _entry_label_for_index(self, idx: int) -> Optional[str]:
        """Return the PCS or ``[[List]]`` label for struct entry *idx*, or ``None``."""
        if self._entry_index_context_pcs:
            row = self._entry_pcs_row_for_struct_index(idx)
            if row is not None:
                return self._pcs_decode_table_row(self._entry_index_context_pcs, row) or None
        if self._entry_index_context_list:
            ln = self._entry_index_context_list
            row = self._entry_list_row_for_struct_index(idx, ln)
            if row is not None:
                lm = self._hex.get_lists().get(ln) or {}
                txt = lm.get(row, "")
                return txt if txt else None
        return None

    def _pcs_decode_table_row(self, pcs_info: Dict[str, Any], row_idx: int) -> str:
        """Decode PCS string at row_idx in a PCS table anchor."""
        if row_idx < 0 or row_idx >= pcs_info.get("count", 0):
            return ""
        anchor = pcs_info["anchor"]
        width = pcs_info["width"]
        addr = anchor.get("Address")
        if addr is None:
            return ""
        try:
            gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
            if gba < GBA_ROM_BASE:
                gba += GBA_ROM_BASE
            base = gba - GBA_ROM_BASE
        except (ValueError, TypeError):
            return ""
        data = self._hex.get_data()
        if not data:
            return ""
        off = base + row_idx * width
        if off + width > len(data):
            return ""
        chunk = bytes(data[off : off + width])
        if pcs_info.get("encoding") == "ascii":
            return decode_ascii_slot(chunk)
        chars = []
        for i in range(width):
            b = data[off + i]
            if b == 0xFF:
                break
            chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
        return "".join(chars)

    def _update_entry_index_name_label(self) -> None:
        """Show PCS or ``[[List]]`` label for the current entry when ``]count`` matches a PCS table or List name."""
        try:
            idx = int(self._idx_var.get())
        except ValueError:
            self._entry_index_name_label.grid_remove()
            self._entry_label_pcs_frame.grid_remove()
            return
        idx = max(0, min(idx, self._entry_count - 1))

        if self._entry_index_context_pcs:
            pcs_row = self._entry_pcs_row_for_struct_index(idx)
            if pcs_row is None:
                pcs_count = int(self._entry_index_context_pcs.get("count") or 0)
                delta = int(self._entry_count) - pcs_count
                raw = idx - delta
                if raw < 0:
                    self._entry_index_name_label.config(text="→ (before PCS table)")
                else:
                    self._entry_index_name_label.config(text="→ (past PCS table)")
                self._entry_index_name_label.grid()
                self._entry_label_pcs_frame.grid_remove()
                return
            txt = self._pcs_decode_table_row(self._entry_index_context_pcs, pcs_row)
            if txt:
                self._entry_index_name_label.config(text=f"→ {txt}")
            else:
                self._entry_index_name_label.config(text="→ (empty)")
            self._entry_index_name_label.grid()
            self._entry_label_pcs_var.set(txt)
            self._entry_label_pcs_frame.grid()
            return

        if self._entry_index_context_list:
            ln = self._entry_index_context_list
            row = self._entry_list_row_for_struct_index(idx, ln)
            lm = self._hex.get_lists().get(ln) or {}
            if row is None:
                self._entry_index_name_label.config(text="→ (outside [[List]] range)")
                self._entry_index_name_label.grid()
                self._entry_label_pcs_frame.grid_remove()
                return
            txt = lm.get(row, "")
            if txt:
                self._entry_index_name_label.config(text=f"→ {txt}")
            else:
                self._entry_index_name_label.config(text="→ (empty)")
            self._entry_index_name_label.grid()
            self._entry_label_pcs_frame.grid_remove()
            return

        self._entry_index_name_label.grid_remove()
        self._entry_label_pcs_frame.grid_remove()

    def _reload_lists(self) -> None:
        self._lists = self._hex.get_lists()

    def refresh_anchors(self) -> None:
        """Reload struct/PCS lists from TOML. Preserves the selected struct name + row when still valid."""
        saved_name = self._combo.get().strip()
        try:
            saved_entry = int(self._idx_var.get())
        except (ValueError, tk.TclError):
            saved_entry = 0
        self._anchors = self._hex.get_struct_anchors()
        self._reload_lists()
        self._entry_index_context_pcs = None
        self._entry_index_context_list = None
        self._list_enum_ctx = None
        self._entry_index_name_label.grid_remove()
        self._entry_label_pcs_frame.grid_remove()
        self._entry_search_frame.grid_remove()
        self._tree_expand_slots_frame.grid_remove()
        self._struct_new_rows_btn.grid_remove()
        self._entry_search_var.set("")
        self._entry_search_matches.clear()
        self._entry_search_match_pos = 0
        self._list_enum_frame.grid_remove()
        self._list_enum_fi = None
        self._gfx_sprite_frame.grid_remove()
        self._gfx_tilemap_frame.grid_remove()
        self._gfx_fi = None
        self._combo.set("")
        self._struct_search_var.set("")
        self._apply_struct_combo_filter()
        self._tree.delete(*self._tree.get_children())
        vals = list(self._combo["values"])
        if saved_name and saved_name in vals:
            self._combo.set(saved_name)
            self._combo.current(vals.index(saved_name))
            self._on_combo_select()
            ei = max(0, min(saved_entry, max(0, self._entry_count - 1)))
            self._idx_var.set(str(ei))
            self._on_spin_change()

    def show_struct(self, anchor_name: str, entry_idx: Optional[int] = None) -> None:
        if not self._anchors:
            self.refresh_anchors()
        want = anchor_name.strip()
        self._struct_search_var.set("")
        self._apply_struct_combo_filter()
        vals = list(self._combo["values"])
        if want not in vals:
            return
        self._combo.set(want)
        self._combo.current(vals.index(want))
        self._on_combo_select()
        if entry_idx is not None:
            try:
                ei = int(entry_idx)
            except (ValueError, TypeError):
                return
            ei = max(0, min(ei, max(0, self._entry_count - 1)))
            self._idx_var.set(str(ei))
            self._on_spin_change()

    def _read_nested_array_element_count(
        self, entry_base: int, na_fd: Dict[str, Any], na_base: int
    ) -> int:
        term = na_fd.get("terminator")
        if term:
            data = self._hex.get_data()
            if not data:
                return 0
            raw = bytes(data)
            st = int(na_fd["inner_stride"])
            tb = bytes(term)
            # Pointer-backed ``!`` blob: u16 index 0 is indistinguishable from ``0000`` terminator — use
            # padding-aware end, then derive element count from span (not first-match terminator steps).
            if na_fd.get("base_ptr_field") or na_fd.get("nested_ptr_is_self_field"):
                end_exc = _terminator_nested_row_end_exclusive_pointer_blob(raw, na_base, st, tb)
                if end_exc is not None:
                    inner = end_exc - na_base - len(tb)
                    if inner >= 0 and st > 0:
                        return inner // st
            return _count_nested_elements_until_terminator(raw, na_base, st, tb)
        return self._read_nested_array_count(entry_base, na_fd)

    def _struct_field_file_off(self, entry_base: int, fd: Dict[str, Any]) -> Optional[int]:
        """Row layout or ``@ptr+N`` payload under ``*ptr`` (``offset`` column)."""
        data = self._hex.get_data()
        if not data:
            return None
        return _struct_field_payload_file_off(entry_base, fd, self._fields, bytes(data))

    def _read_nested_array_count(self, entry_base: int, na_fd: Dict[str, Any]) -> int:
        cf_name = str(na_fd.get("count_field") or "")
        cf = next((f for f in self._fields if f.get("name") == cf_name), None)
        if not cf or cf.get("type") != "uint":
            return 0
        data = self._hex.get_data()
        if not data:
            return 0
        roff = self._struct_field_file_off(entry_base, cf)
        if roff is None:
            return 0
        rsz = int(cf["size"])
        if roff + rsz > len(data):
            return 0
        raw = int.from_bytes(data[roff : roff + rsz], "little")
        mx = min((1 << (8 * rsz)) - 1, 65535)
        return max(0, min(raw, mx))

    def _nested_array_data_base(self, entry_base: int, na_fd: Dict[str, Any], data: bytes) -> Optional[int]:
        """File offset where nested rows live: ptr @ ``name``, implicit ptr@0 + count, ``*base_ptr``, or inline."""
        bpf = na_fd.get("base_ptr_field")
        if _nested_array_implicit_row_pointer(self._fields, na_fd):
            poff = entry_base
            if poff + 4 > len(data):
                return None
            ptr = int.from_bytes(data[poff : poff + 4], "little")
            if (ptr >> 24) not in (0x08, 0x09):
                return None
            fo = ptr - GBA_ROM_BASE
            if fo < 0 or fo >= len(data):
                return None
            return fo
        if na_fd.get("nested_ptr_is_self_field"):
            poff = entry_base + int(na_fd["offset"])
            if poff + 4 > len(data):
                return None
            ptr = int.from_bytes(data[poff : poff + 4], "little")
            if (ptr >> 24) not in (0x08, 0x09):
                return None
            fo = ptr - GBA_ROM_BASE
            if fo < 0 or fo >= len(data):
                return None
            return fo
        if not bpf:
            return entry_base + int(na_fd["offset"])
        pfd = next((f for f in self._fields if str(f.get("name")) == str(bpf)), None)
        if not pfd or pfd.get("type") not in ("ptr", "pcs_ptr"):
            return None
        poff = entry_base + int(pfd["offset"])
        if poff + 4 > len(data):
            return None
        ptr = int.from_bytes(data[poff : poff + 4], "little")
        if (ptr >> 24) not in (0x08, 0x09):
            return None
        fo = ptr - GBA_ROM_BASE
        if fo < 0 or fo >= len(data):
            return None
        return fo + int(na_fd.get("base_ptr_delta") or 0)

    def _nested_element_file_off(
        self, entry_base: int, na_fd: Dict[str, Any], ai: int, ij: int
    ) -> Optional[int]:
        inner = na_fd.get("inner_fields") or []
        if ij < 0 or ij >= len(inner):
            return None
        ifd = inner[ij]
        stride = int(na_fd["inner_stride"])
        data = self._hex.get_data()
        if not data:
            return None
        na_base = self._nested_array_data_base(entry_base, na_fd, bytes(data))
        if na_base is None:
            return None
        return na_base + ai * stride + int(ifd["offset"])

    def _count_field_drives_nested(self, count_field_name: str) -> bool:
        for f in self._fields:
            if (
                f.get("type") == "nested_array"
                and not f.get("terminator")
                and str(f.get("count_field")) == count_field_name
            ):
                return True
        return False

    def _load_entry(self, entry_idx: int) -> None:
        self._cancel_inline_edit()
        self._ptr_text_frame.grid_remove()
        self._ptr_text_fi = None
        self._list_enum_frame.grid_remove()
        self._list_enum_fi = None
        self._list_enum_ctx = None
        self._gfx_sprite_frame.grid_remove()
        self._gfx_tilemap_frame.grid_remove()
        self._gfx_fi = None
        self._tree.delete(*self._tree.get_children())
        try:
            data = self._hex.get_data()
            if not data or not self._fields:
                return
            off = self._entry_file_offset(entry_idx)
            if self._struct_packed_terminator and self._packed_terminator_fd is not None:
                pfd = self._packed_terminator_fd
                pend = _terminator_nested_row_end_exclusive(
                    bytes(data),
                    off,
                    int(pfd["inner_stride"]),
                    bytes(pfd["terminator"]),
                )
                if pend is None or pend > len(data) or off >= len(data):
                    return
            elif off + self._struct_size > len(data):
                return
            for fi, fd in enumerate(self._fields):
                if fd.get("type") == "helper":
                    val_str = self._format_value(b"", fd, entry_base=off)
                    self._tree.insert("", tk.END, values=(fd["name"], val_str), iid=f"sf_{fi}")
                    continue
                if fd.get("type") == "nested_array":
                    inner = fd.get("inner_fields") or []
                    stride = int(fd["inner_stride"])
                    na_base = self._nested_array_data_base(off, fd, bytes(data))
                    if na_base is None:
                        continue
                    n_sub = self._read_nested_array_element_count(off, fd, na_base)
                    for ai in range(n_sub):
                        for ij, ifd in enumerate(inner):
                            if _struct_field_omitted_from_editor_tree(ifd):
                                continue
                            if ifd.get("type") == "bitfield":
                                foff = na_base + ai * stride + int(ifd["offset"])
                                sz = int(ifd["size"])
                                if foff + sz > len(data):
                                    break
                                raw = bytes(data[foff : foff + sz])
                                val = int.from_bytes(raw, "little")
                                for j, p in enumerate(ifd["parts"]):
                                    if _struct_field_omitted_from_editor_tree(p):
                                        continue
                                    subv = (val >> p["shift"]) & ((1 << p["bits"]) - 1)
                                    label = f"{fd['name']}[{ai}].{p['name']}"
                                    disp = self._format_bitfield_part_display(subv, p)
                                    self._tree.insert(
                                        "",
                                        tk.END,
                                        values=(label, disp),
                                        iid=f"sf_nab_{fi}_{ai}_{ij}_{j}",
                                    )
                            else:
                                foff = na_base + ai * stride + int(ifd["offset"])
                                sz = int(ifd["size"])
                                if foff + sz > len(data):
                                    break
                                raw = bytes(data[foff:foff + sz])
                                val_str = self._format_value(raw, ifd, entry_base=off)
                                label = f"{fd['name']}[{ai}].{ifd['name']}"
                                self._tree.insert("", tk.END, values=(label, val_str), iid=f"sf_na_{fi}_{ai}_{ij}")
                    continue
                if fd.get("type") == "bitfield":
                    foff = off + fd["offset"]
                    sz = int(fd["size"])
                    if foff + sz > len(data):
                        break
                    raw = bytes(data[foff : foff + sz])
                    val = int.from_bytes(raw, "little")
                    for j, p in enumerate(fd["parts"]):
                        if _struct_field_omitted_from_editor_tree(p):
                            continue
                        subv = (val >> p["shift"]) & ((1 << p["bits"]) - 1)
                        disp = self._format_bitfield_part_display(subv, p)
                        self._tree.insert(
                            "",
                            tk.END,
                            values=(p["name"], disp),
                            iid=f"sf_{fi}_b{j}",
                        )
                    continue
                if _struct_field_omitted_from_editor_tree(fd):
                    continue
                foff = self._struct_field_file_off(off, fd)
                if foff is None:
                    break
                sz = fd["size"]
                if foff + sz > len(data):
                    break
                raw = bytes(data[foff:foff + sz])
                val_str = self._format_value(raw, fd, entry_base=off)
                self._tree.insert("", tk.END, values=(fd["name"], val_str), iid=f"sf_{fi}")
        finally:
            self._update_entry_index_name_label()
            self._sync_field_aux_panels()

    def _format_bitfield_part_display(self, subv: int, part: Dict[str, Any]) -> str:
        """Pretty-print one bitfield subfield; use [[List]] / PCS like uint :enum when ``part['enum']`` is set."""
        er = part.get("enum")
        if er:
            label = self._resolve_enum(subv, str(er))
            if label is not None:
                return label
        return str(subv)

    def _struct_resolve_enum_field_context(self, iid: str) -> Optional[Dict[str, Any]]:
        """Map tree row id to enum panel context: top-level uint, top-level bitfield part, nested uint, nested bitfield part."""
        if not iid.startswith("sf_"):
            return None
        fi, sp = parse_struct_tree_iid(iid)
        if fi < 0 or fi >= len(self._fields):
            return None
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return None
        entry_base = self._entry_file_offset(entry_idx)

        if isinstance(sp, tuple) and sp[0] == "na":
            _, ai, ij = sp
            na_fd = self._fields[fi]
            if na_fd.get("type") != "nested_array":
                return None
            inner = na_fd.get("inner_fields") or []
            if ij >= len(inner):
                return None
            ifd = inner[ij]
            if ifd.get("type") == "bitfield":
                return None
            if not ifd.get("enum"):
                return None
            foff = self._nested_element_file_off(entry_base, na_fd, ai, ij)
            if foff is None:
                return None
            return {
                "kind": "nested_uint",
                "enum_ref": str(ifd["enum"]),
                "foff": foff,
                "fd": ifd,
                "fi": fi,
                "na_fd": na_fd,
                "ai": ai,
                "ij": ij,
                "tree_iid": iid,
            }

        if isinstance(sp, tuple) and sp[0] == "nab":
            _, ai, ij, bk = sp
            na_fd = self._fields[fi]
            if na_fd.get("type") != "nested_array":
                return None
            inner = na_fd.get("inner_fields") or []
            if ij >= len(inner):
                return None
            ifd = inner[ij]
            if ifd.get("type") != "bitfield":
                return None
            parts = ifd.get("parts") or []
            if bk < 0 or bk >= len(parts):
                return None
            part = parts[bk]
            er = part.get("enum")
            if not er:
                return None
            foff = self._nested_element_file_off(entry_base, na_fd, ai, ij)
            if foff is None:
                return None
            return {
                "kind": "nested_bitfield",
                "enum_ref": str(er),
                "foff": foff,
                "fd": ifd,
                "part_idx": bk,
                "part": part,
                "fi": fi,
                "na_fd": na_fd,
                "ai": ai,
                "ij": ij,
                "tree_iid": iid,
            }

        fd = self._fields[fi]
        if isinstance(sp, int):
            if fd.get("type") != "bitfield":
                return None
            parts = fd.get("parts") or []
            if sp < 0 or sp >= len(parts):
                return None
            part = parts[sp]
            er = part.get("enum")
            if not er:
                return None
            return {
                "kind": "bitfield",
                "enum_ref": str(er),
                "foff": entry_base + int(fd["offset"]),
                "fd": fd,
                "part_idx": sp,
                "part": part,
                "fi": fi,
                "tree_iid": iid,
            }

        if sp is not None:
            return None
        if fd.get("type") != "uint" or not fd.get("enum"):
            return None
        foff_u = self._struct_field_file_off(entry_base, fd)
        if foff_u is None:
            return None
        return {
            "kind": "uint",
            "enum_ref": str(fd["enum"]),
            "foff": foff_u,
            "fd": fd,
            "fi": fi,
            "tree_iid": iid,
        }

    def _bitfield_row_iid_from_ctx(self, ctx: Dict[str, Any], j: int) -> str:
        k = ctx["kind"]
        if k == "bitfield":
            return f"sf_{ctx['fi']}_b{j}"
        if k == "nested_bitfield":
            return f"sf_nab_{ctx['fi']}_{ctx['ai']}_{ctx['ij']}_{j}"
        raise ValueError(k)

    def _refresh_bitfield_tree_rows_from_ctx(self, ctx: Dict[str, Any]) -> None:
        data = self._hex.get_data()
        if not data or not self._tree:
            return
        fd = ctx["fd"]
        foff = int(ctx["foff"])
        sz = int(fd["size"])
        if foff + sz > len(data):
            return
        val = int.from_bytes(data[foff : foff + sz], "little")
        for j, pp in enumerate(fd.get("parts") or []):
            subv = (val >> pp["shift"]) & ((1 << pp["bits"]) - 1)
            disp = self._format_bitfield_part_display(subv, pp)
            rid = self._bitfield_row_iid_from_ctx(ctx, j)
            if self._tree.exists(rid):
                self._tree.set(rid, "val", disp)

    def _write_bitfield_subvalue_merge(self, foff: int, fd: Dict[str, Any], part_idx: int, new_subv: int) -> bool:
        data = self._hex.get_data()
        if not data:
            return False
        parts = fd.get("parts") or []
        if part_idx < 0 or part_idx >= len(parts):
            return False
        part = parts[part_idx]
        mx = (1 << part["bits"]) - 1
        if new_subv < 0 or new_subv > mx:
            return False
        if foff + int(fd["size"]) > len(data):
            return False
        cur = int.from_bytes(data[foff : foff + int(fd["size"])], "little")
        m = ((1 << part["bits"]) - 1) << part["shift"]
        cur = (cur & ~m) | ((new_subv & mx) << part["shift"])
        self._hex.write_bytes_at(foff, cur.to_bytes(int(fd["size"]), "little"))
        return True

    def _format_helper_value(self, fd: Dict[str, Any], data: Any, entry_base: int) -> str:
        """Sum ROM uint values for fields named in ``helper_refs`` (same struct row)."""
        refs: List[str] = list(fd.get("helper_refs") or [])
        by_name = {str(f["name"]): f for f in self._fields if f.get("type") != "helper"}
        total = 0
        missing: List[str] = []
        for ref in refs:
            rf = by_name.get(ref)
            if rf is None or rf.get("type") != "uint":
                missing.append(ref)
                continue
            roff = self._struct_field_file_off(entry_base, rf)
            if roff is None:
                missing.append(ref)
                continue
            rsz = int(rf["size"])
            if roff + rsz > len(data):
                missing.append(ref)
                continue
            total += int.from_bytes(data[roff : roff + rsz], "little")
        if missing:
            return f"{total}  (missing: {', '.join(missing)})"
        return str(total)

    def _refresh_helper_field_rows(self, entry_base: int) -> None:
        data = self._hex.get_data()
        if not data or not self._tree:
            return
        for fi, fd in enumerate(self._fields):
            if fd.get("type") != "helper":
                continue
            iid = f"sf_{fi}"
            if self._tree.exists(iid):
                self._tree.set(iid, "val", self._format_helper_value(fd, data, entry_base))

    def _format_value(self, raw: bytes, fd: Dict[str, Any], entry_base: Optional[int] = None) -> str:
        ftype = fd["type"]
        if ftype == "bitfield":
            return ""
        if ftype == "helper":
            if entry_base is None:
                try:
                    ei = int(self._idx_var.get())
                    entry_base = self._entry_file_offset(ei)
                except (ValueError, TypeError):
                    return "(—)"
            data = self._hex.get_data()
            if not data:
                return "(—)"
            return self._format_helper_value(fd, data, entry_base)
        if ftype == "pcs":
            chars = []
            for b in raw:
                if b == 0xFF:
                    break
                chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
            return "".join(chars)
        if ftype == "ascii":
            return decode_ascii_slot(raw)
        if ftype == "pcs_ptr":
            if len(raw) >= 4:
                ptr = int.from_bytes(raw[:4], "little")
                if (ptr >> 24) in (0x08, 0x09):
                    preview = self._read_pcs_at_pointer(ptr - GBA_ROM_BASE)
                    if len(preview) > 48:
                        preview = preview[:45] + "…"
                    return f"0x{ptr:08X} → {preview}"
                return f"0x{ptr:08X}"
            return ""
        if ftype == "ptr":
            if len(raw) >= 4:
                ptr = int.from_bytes(raw[:4], "little")
                return f"0x{ptr:08X}"
            return ""
        if ftype == "gfx_sprite":
            if len(raw) >= 4:
                ptr = int.from_bytes(raw[:4], "little")
                return f"0x{ptr:08X}  (sprite)"
            return ""
        val_u = int.from_bytes(raw, "little")
        if fd.get("blist_ref"):
            hx = raw.hex().upper()
            spaced = " ".join(hx[i : i + 2] for i in range(0, len(hx), 2))
            bb = fd.get("blist_bits")
            if bb is not None:
                return f"bit array ({int(bb)} bits, {len(raw)} B)  [{spaced}]"
            return f"bit array (unresolved |b[], {len(raw)} B)  [{spaced}]"
        enum_ref = fd.get("enum")
        if enum_ref:
            label = self._resolve_enum(val_u, enum_ref)
            if label is not None:
                if self._is_enum_panel_field(fd):
                    return f"{label}  ▾"
                return label
        if fd.get("signed"):
            val_s = int.from_bytes(raw, "little", signed=True)
            w = len(raw) * 2
            mask = (1 << (8 * len(raw))) - 1
            if fd.get("hex"):
                return f"0x{(val_s & mask):0{w}X}  ({val_s})"
            return str(val_s)
        if fd.get("hex"):
            return f"0x{val_u:0{len(raw) * 2}X}"
        return str(val_u)

    def _read_pcs_at_pointer(self, file_off: int) -> str:
        data = self._hex.get_data()
        if not data or file_off < 0 or file_off >= len(data):
            return ""
        chars = []
        for i in range(256):
            if file_off + i >= len(data):
                break
            b = data[file_off + i]
            if b == 0xFF:
                break
            chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
        return "".join(chars)

    def _resolve_enum(self, value: int, enum_ref: str) -> Optional[str]:
        base, delta = _split_enum_field_ref(enum_ref)
        idx = value + delta
        base_key = normalize_named_anchor_lookup_key(base)
        lm = self._lists.get(base_key)
        if lm is not None:
            label = lm.get(idx)
            if label is not None:
                return f"{value} ({label})"
        for info in self._hex.get_pcs_table_anchors():
            if normalize_named_anchor_lookup_key(str(info["name"])) == base_key:
                anchor = info["anchor"]
                addr = anchor.get("Address")
                if addr is None:
                    continue
                try:
                    gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                    if gba < GBA_ROM_BASE:
                        gba += GBA_ROM_BASE
                    rom_base = gba - GBA_ROM_BASE
                except (ValueError, TypeError):
                    continue
                data = self._hex.get_data()
                if not data:
                    continue
                entry_off = rom_base + idx * info["width"]
                if entry_off + info["width"] > len(data):
                    continue
                chunk = bytes(data[entry_off : entry_off + info["width"]])
                if info.get("encoding") == "ascii":
                    preview = decode_ascii_slot(chunk)
                else:
                    chars = []
                    for i in range(info["width"]):
                        b = data[entry_off + i]
                        if b == 0xFF:
                            break
                        chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
                    preview = "".join(chars)
                return f"{value} ({preview})"
        return None

    def _start_inline_edit(self, event: Optional[tk.Event] = None) -> None:
        if self._edit_entry:
            return
        sel = self._tree.selection()
        if not sel:
            return
        iid = sel[0]
        if not iid.startswith("sf_"):
            return
        fi, spec = parse_struct_tree_iid(iid)
        if fi < 0 or fi >= len(self._fields):
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        entry_base = self._entry_file_offset(entry_idx)

        if self._struct_resolve_enum_field_context(iid) is not None:
            self._sync_field_aux_panels()
            self._list_enum_rom_combo.focus_set()
            return

        fd: Dict[str, Any]
        foff: Optional[int] = None

        if isinstance(spec, tuple) and spec[0] == "nab":
            _, ai, ij, bk = spec
            na_fd = self._fields[fi]
            if na_fd.get("type") != "nested_array":
                return
            inner = na_fd.get("inner_fields") or []
            if ij >= len(inner):
                return
            ifd = inner[ij]
            if ifd.get("type") != "bitfield" or bk >= len(ifd["parts"]):
                return
            fd = ifd
            foff = self._nested_element_file_off(entry_base, na_fd, ai, ij)
        elif isinstance(spec, tuple) and spec[0] == "na":
            _, ai, ij = spec
            na_fd = self._fields[fi]
            if na_fd.get("type") != "nested_array":
                return
            inner = na_fd.get("inner_fields") or []
            if ij >= len(inner):
                return
            ifd = inner[ij]
            if ifd.get("type") == "bitfield":
                return
            fd = ifd
            foff = self._nested_element_file_off(entry_base, na_fd, ai, ij)
        else:
            fd = self._fields[fi]
            if fd.get("type") == "helper":
                return
            foff = self._struct_field_file_off(entry_base, fd)

        if foff is None:
            return

        vals = self._tree.item(iid, "values")
        if len(vals) < 2:
            return
        try:
            bbox = self._tree.bbox(iid, "#2")
        except tk.TclError:
            return
        if not bbox:
            return
        x, y, w, h = bbox
        tw = self._tree
        self._edit_entry = tk.Entry(tw.master, font=("Consolas", 9))
        self._edit_entry.place(x=tw.winfo_x() + x, y=tw.winfo_y() + y, width=max(w, 80), height=h)
        raw_val = vals[1]
        if fd.get("enum"):
            raw_val = raw_val.split(" (", 1)[0] if " (" in raw_val else raw_val
        elif fd.get("type") == "bitfield":
            pidx: Optional[int] = None
            if isinstance(spec, int):
                pidx = spec
            elif isinstance(spec, tuple) and spec[0] == "nab" and len(spec) >= 4:
                pidx = spec[3]
            if (
                pidx is not None
                and 0 <= pidx < len(fd.get("parts") or [])
                and fd["parts"][pidx].get("enum")
            ):
                raw_val = raw_val.split(" (", 1)[0] if " (" in raw_val else raw_val
        elif fd["type"] == "pcs_ptr":
            rom = self._hex.get_data()
            if rom and foff + 4 <= len(rom):
                ptr = int.from_bytes(rom[foff:foff + 4], "little")
                if (ptr >> 24) in (0x08, 0x09):
                    raw_val = self._read_pcs_at_pointer(ptr - GBA_ROM_BASE)
                else:
                    raw_val = vals[1].split(" → ", 1)[0].strip() if " → " in vals[1] else vals[1]
        elif fd["type"] == "gfx_sprite":
            raw_val = vals[1].split()[0].strip() if vals[1] else vals[1]
        elif " → " in raw_val:
            raw_val = raw_val.split(" → ", 1)[0].strip()
        self._edit_entry.insert(0, raw_val)
        self._edit_entry.select_range(0, tk.END)
        self._edit_entry.focus_set()
        self._edit_iid = iid
        self._edit_entry.bind("<Return>", self._commit_inline_edit)
        self._edit_entry.bind("<Escape>", self._cancel_inline_edit)
        self._edit_entry.bind("<FocusOut>", self._commit_inline_edit)
        self._edit_entry.bind("<Up>", self._edit_adjacent_field)
        self._edit_entry.bind("<Down>", self._edit_adjacent_field)

    def _commit_inline_edit(self, event: Optional[tk.Event] = None) -> None:
        if not self._edit_entry or not self._edit_iid:
            return
        raw_edit = self._edit_entry.get()
        text = raw_edit.strip()
        fi, bi = parse_struct_tree_iid(self._edit_iid)
        if fi < 0 or fi >= len(self._fields):
            self._cancel_inline_edit()
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            self._cancel_inline_edit()
            return
        entry_base = self._entry_file_offset(entry_idx)
        data = self._hex.get_data()
        if not data:
            self._cancel_inline_edit()
            return

        na_fd = self._fields[fi]

        if isinstance(bi, tuple) and bi[0] == "nab":
            if na_fd.get("type") != "nested_array":
                self._cancel_inline_edit()
                return
            _, ai, ij, bk = bi
            inner = na_fd.get("inner_fields") or []
            if ij >= len(inner):
                self._cancel_inline_edit()
                return
            fd = inner[ij]
            if fd.get("type") != "bitfield" or bk >= len(fd["parts"]):
                self._cancel_inline_edit()
                return
            foff = self._nested_element_file_off(entry_base, na_fd, ai, ij)
            if foff is None or foff + int(fd["size"]) > len(data):
                self._cancel_inline_edit()
                return
            try:
                new_val = int(text, 0)
            except ValueError:
                self._cancel_inline_edit()
                return
            part = fd["parts"][bk]
            mx = (1 << part["bits"]) - 1
            if new_val < 0 or new_val > mx:
                messagebox.showwarning("Struct", f"Value must be in 0 … {mx} for this bitfield.")
                self._cancel_inline_edit()
                return
            cur = int.from_bytes(data[foff : foff + fd["size"]], "little")
            m = ((1 << part["bits"]) - 1) << part["shift"]
            cur = (cur & ~m) | ((new_val & ((1 << part["bits"]) - 1)) << part["shift"])
            self._hex.write_bytes_at(foff, cur.to_bytes(fd["size"], "little"))
            for j, pp in enumerate(fd["parts"]):
                subv = (cur >> pp["shift"]) & ((1 << pp["bits"]) - 1)
                disp = self._format_bitfield_part_display(subv, pp)
                self._tree.set(f"sf_nab_{fi}_{ai}_{ij}_{j}", "val", disp)
            self._refresh_helper_field_rows(entry_base)
            self._cancel_inline_edit()
            self._sync_field_aux_panels()
            return

        if isinstance(bi, tuple) and bi[0] == "na":
            if na_fd.get("type") != "nested_array":
                self._cancel_inline_edit()
                return
            _, ai, ij = bi
            inner = na_fd.get("inner_fields") or []
            if ij >= len(inner):
                self._cancel_inline_edit()
                return
            fd = inner[ij]
            if fd.get("type") == "bitfield":
                self._cancel_inline_edit()
                return
            foff = self._nested_element_file_off(entry_base, na_fd, ai, ij)
            if foff is None or foff + int(fd["size"]) > len(data):
                self._cancel_inline_edit()
                return
            if fd["type"] == "pcs":
                enc = encode_pcs_string(text, fd["size"])
                self._hex.write_bytes_at(foff, enc)
            elif fd["type"] == "ascii":
                enc = encode_ascii_slot(text, fd["size"])
                self._hex.write_bytes_at(foff, enc)
            elif fd["type"] == "pcs_ptr":
                ptr = int.from_bytes(data[foff:foff + 4], "little")
                if re.fullmatch(r"0[xX][0-9A-Fa-f]{1,8}", text):
                    try:
                        val = int(text, 0)
                    except ValueError:
                        self._cancel_inline_edit()
                        return
                    self._hex.write_bytes_at(foff, val.to_bytes(4, "little"))
                elif (ptr >> 24) in (0x08, 0x09):
                    if not self._apply_pcs_ptr_string_write(fi, raw_edit, file_off=foff):
                        self._cancel_inline_edit()
                        return
                else:
                    messagebox.showwarning(
                        "Struct",
                        "This pointer does not target ROM. Set Pointer (GBA) in the panel below, "
                        "or type a ROM address (e.g. 0x08XXXXXX) here.",
                    )
                    self._cancel_inline_edit()
                    return
            elif fd["type"] in ("uint", "ptr", "gfx_sprite", "gfx_tileset", "gfx_tilemap", "gfx_palette"):
                try:
                    val = int(text, 0)
                except ValueError:
                    self._cancel_inline_edit()
                    return
                enc = (
                    _encode_struct_uint_field(fd, val)
                    if fd["type"] == "uint"
                    else val.to_bytes(fd["size"], "little")
                )
                self._hex.write_bytes_at(foff, enc)
                if fd.get("type") == "uint" and self._count_field_drives_nested(str(fd["name"])):
                    self._load_entry(entry_idx)
                    self._cancel_inline_edit()
                    self._sync_field_aux_panels()
                    return
            else:
                self._cancel_inline_edit()
                return

            raw = bytes(self._hex.get_data()[foff:foff + fd["size"]])
            self._tree.set(self._edit_iid, "val", self._format_value(raw, fd, entry_base=entry_base))
            self._refresh_helper_field_rows(entry_base)
            self._cancel_inline_edit()
            self._sync_field_aux_panels()
            return

        fd = self._fields[fi]
        if fd.get("type") == "helper":
            self._cancel_inline_edit()
            return
        foff = self._struct_field_file_off(entry_base, fd)
        if foff is None or foff + int(fd["size"]) > len(data):
            self._cancel_inline_edit()
            return

        skip_tree_refresh = False
        if fd.get("type") == "bitfield":
            if bi is None:
                self._cancel_inline_edit()
                return
            try:
                new_val = int(text, 0)
            except ValueError:
                self._cancel_inline_edit()
                return
            part = fd["parts"][bi]
            mx = (1 << part["bits"]) - 1
            if new_val < 0 or new_val > mx:
                messagebox.showwarning("Struct", f"Value must be in 0 … {mx} for this bitfield.")
                self._cancel_inline_edit()
                return
            cur = int.from_bytes(data[foff : foff + fd["size"]], "little")
            m = ((1 << part["bits"]) - 1) << part["shift"]
            cur = (cur & ~m) | ((new_val & ((1 << part["bits"]) - 1)) << part["shift"])
            self._hex.write_bytes_at(foff, cur.to_bytes(fd["size"], "little"))
            for j, pp in enumerate(fd["parts"]):
                subv = (cur >> pp["shift"]) & ((1 << pp["bits"]) - 1)
                disp = self._format_bitfield_part_display(subv, pp)
                self._tree.set(f"sf_{fi}_b{j}", "val", disp)
            self._refresh_helper_field_rows(entry_base)
            self._cancel_inline_edit()
            self._sync_field_aux_panels()
            return
        if fd["type"] == "pcs":
            enc = encode_pcs_string(text, fd["size"])
            self._hex.write_bytes_at(foff, enc)
        elif fd["type"] == "ascii":
            enc = encode_ascii_slot(text, fd["size"])
            self._hex.write_bytes_at(foff, enc)
        elif fd["type"] == "pcs_ptr":
            ptr = int.from_bytes(data[foff:foff + 4], "little")
            if re.fullmatch(r"0[xX][0-9A-Fa-f]{1,8}", text):
                try:
                    val = int(text, 0)
                except ValueError:
                    self._cancel_inline_edit()
                    return
                self._hex.write_bytes_at(foff, val.to_bytes(4, "little"))
            elif (ptr >> 24) in (0x08, 0x09):
                if not self._apply_pcs_ptr_string_write(fi, raw_edit):
                    self._cancel_inline_edit()
                    return
                skip_tree_refresh = True
            else:
                messagebox.showwarning(
                    "Struct",
                    "This pointer does not target ROM. Set Pointer (GBA) in the panel below, "
                    "or type a ROM address (e.g. 0x08XXXXXX) here.",
                )
                self._cancel_inline_edit()
                return
        elif fd["type"] in ("uint", "ptr", "gfx_sprite", "gfx_tileset", "gfx_tilemap", "gfx_palette"):
            try:
                val = int(text, 0)
            except ValueError:
                self._cancel_inline_edit()
                return
            enc = (
                _encode_struct_uint_field(fd, val)
                if fd["type"] == "uint"
                else val.to_bytes(fd["size"], "little")
            )
            self._hex.write_bytes_at(foff, enc)
            if fd.get("type") == "uint" and self._count_field_drives_nested(str(fd["name"])):
                self._load_entry(entry_idx)
                self._cancel_inline_edit()
                self._sync_field_aux_panels()
                return
        else:
            self._cancel_inline_edit()
            return

        if not skip_tree_refresh:
            raw = bytes(self._hex.get_data()[foff:foff + fd["size"]])
            self._tree.set(self._edit_iid, "val", self._format_value(raw, fd, entry_base=entry_base))
            self._refresh_helper_field_rows(entry_base)
        else:
            self._refresh_pcs_ptr_tree_row(fi)
        self._cancel_inline_edit()
        self._sync_field_aux_panels()

    def _edit_adjacent_field(self, event: tk.Event) -> Optional[str]:
        if not self._edit_entry or not self._edit_iid:
            return None
        cur_iid = self._edit_iid
        self._edit_entry.unbind("<FocusOut>")
        self._commit_inline_edit()
        direction = -1 if event.keysym == "Up" else 1
        kids = self._tree.get_children("")
        try:
            pos = kids.index(cur_iid)
        except ValueError:
            return "break"
        next_pos = pos + direction
        if 0 <= next_pos < len(kids):
            next_iid = kids[next_pos]
            self._tree.selection_set(next_iid)
            self._tree.see(next_iid)
            self._tree.focus_set()
            self.after(10, self._start_inline_edit)
        return "break"

    def _cancel_inline_edit(self, event: Optional[tk.Event] = None) -> Optional[str]:
        ent = self._edit_entry
        self._edit_entry = None
        self._edit_iid = None
        if ent:
            ent.place_forget()
            ent.destroy()
        if self._tree:
            self._tree.focus_set()
        return "break"


class HexEditorFrame(ttk.Frame):
    """Embeddable hex editor with 16 bytes/row, pointer highlighting, follow, save, delete, insert mode."""

    def __init__(self, parent: tk.Misc, default_encoding: str = "ascii", **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._data = bytearray()
        self._file_path: Optional[str] = None
        self._insert_mode = False
        self._nibble_pos = 0  # 0 = high nibble, 1 = low nibble
        self._cursor_byte_offset = 0
        self._selection_start: Optional[int] = None
        self._selection_end: Optional[int] = None
        self._modified = False
        self._visible_row_start = 0
        self._visible_row_count = 1  # Updated dynamically from widget height
        self._total_rows = 0
        self._syncing_scroll = False
        self._encoding = default_encoding if default_encoding in ("ascii", "pcs") else "ascii"
        self._asm_mode = "thumb"  # thumb | arm for GBA ARM7TDMI
        self._asm_pane_visible = False
        self._hackmew_mode = False
        self._hackmew_asm_start: Optional[int] = None
        self._hackmew_asm_end: Optional[int] = None
        self._pseudo_c_pane_visible = False
        self._c_inject_mode = False
        self._c_inject_region: Optional[Tuple[int, int]] = None  # [start, end) file offsets for repoint-all skip
        self._c_inject_elf_symbols: Dict[str, int] = {}  # last successful link: nm .text symbol -> ROM file offset
        self._pokefirered_sym_norm_to_name: Optional[Dict[int, str]] = None
        self._rom_use_pokefirered_sym: bool = False
        self._anchor_browser_pane_visible = False
        self._anchor_tools_pane_layout: bool = False  # True when Anchors + Tools share a horizontal PanedWindow
        self._anchor_browser_path: List[str] = []
        self._anchor_sym_filter_var = tk.StringVar(value="")
        self._sym_browser_rom_list: Optional[List[Tuple[str, int]]] = None  # (name, file_off) ROM only, sorted
        self._ldr_pc_targets: Optional[Set[int]] = None
        self._ldr_pc_targets_valid = False
        # Reverse refs: file offset T -> list of source file offsets (word pointers / BL sites)
        self._xref_rom_word: Dict[int, List[int]] = {}
        self._xref_bl: Dict[int, List[int]] = {}
        self._xref_index_valid: bool = False
        self._xref_rebuild_after_id: Optional[str] = None
        self._toml_path: Optional[str] = None
        self._toml_data: Dict[str, Any] = {}
        # When set, this file is loaded instead of auto-resolving {ROM}.toml (until cleared).
        self._toml_manual_override: Optional[str] = None
        # Row index for ``[format]count`` graphics / palette tables (spinbox in Tools → Graphics).
        self.graphics_table_row_var = tk.IntVar(value=0)
        self._script_pane_visible = False
        self._script_ui_saved: Optional[Dict[str, Any]] = None
        # Optional: PCS/Struct/Graphics tools refresh after structure TOML is written on disk.
        self._anchor_refresh_callback: Optional[Callable[[], None]] = None
        # Hex pane: byte value before the current high-nibble edit (for MatchedWords delta propagation).
        self._hex_pair_snapshot_byte: Optional[int] = None
        self._suppress_matched_word_propagate: bool = False
        # Cache for get_struct_anchors (ROM-derived packed row counts are expensive).
        self._struct_anchors_cache: Optional[List[Dict[str, Any]]] = None
        # Set by the host editor after :class:`RomToolsShell` builds :class:`StructEditorFrame`.
        self._struct_editor_ref: Any = None
        self._build_ui()

    # ── UI construction ──────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        outer = ttk.Frame(self)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        # Top row: mode | cursor offset | ASM mode | Goto | Chars
        top_row = ttk.Frame(outer)
        top_row.grid(row=0, column=0, sticky="w", pady=(0, 1))
        self._mode_label = ttk.Label(top_row, text="REPLACE", font=("Consolas", 9, "bold"))
        self._mode_label.grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Label(top_row, text="Offset:", font=("Consolas", 9)).grid(row=0, column=1, sticky="w", padx=(8, 2))
        self._cursor_offset_var = tk.StringVar(value="")
        self._cursor_offset_entry = ttk.Entry(
            top_row, textvariable=self._cursor_offset_var,
            font=("Consolas", 9), width=10, state="readonly"
        )
        self._cursor_offset_entry.grid(row=0, column=2, sticky="w", padx=(0, 8))
        ttk.Label(top_row, text="ASM mode:", font=("Consolas", 9)).grid(row=0, column=3, sticky="w", padx=(8, 2))
        self._asm_mode_var = tk.StringVar(value="Thumb")
        self._asm_mode_combo = ttk.Combobox(
            top_row, textvariable=self._asm_mode_var, values=["Thumb", "ARM"], width=6, state="readonly", font=("Consolas", 9)
        )
        self._asm_mode_combo.grid(row=0, column=4, sticky="w", padx=(0, 2))
        self._asm_mode_combo.current(0)
        self._asm_mode_combo.bind("<<ComboboxSelected>>", self._on_asm_mode_change)
        ttk.Label(top_row, text="Goto:", font=("Consolas", 9)).grid(row=0, column=5, sticky="w", padx=(8, 2))
        self._goto_var = tk.StringVar(value="")
        self._goto_entry = ttk.Entry(top_row, textvariable=self._goto_var, width=10, font=("Consolas", 9))
        self._goto_entry.grid(row=0, column=6, sticky="w", padx=(0, 8))
        self._goto_entry.bind("<KeyRelease>", self._on_goto_entry_change)
        self._goto_entry.bind("<FocusIn>", self._on_goto_focus_in)
        self._goto_entry.bind("<KeyPress>", self._on_goto_keypress, add=True)
        self._goto_entry.bind("<<Paste>>", self._on_goto_paste, add=True)
        self._goto_entry.bind("<Escape>", self._on_goto_escape_to_hex)
        ttk.Label(top_row, text="Chars:", font=("Consolas", 9)).grid(row=0, column=7, sticky="w", padx=(8, 2))
        self._encoding_var = tk.StringVar(value=self._encoding.upper())
        self._encoding_combo = ttk.Combobox(
            top_row, textvariable=self._encoding_var, values=["ASCII", "PCS"], width=8, state="readonly"
        )
        self._encoding_combo.grid(row=0, column=8, sticky="w")
        self._encoding_combo.bind("<<ComboboxSelected>>", self._on_encoding_change)
        self._selection_label = ttk.Label(top_row, text="", font=("Consolas", 9))
        self._selection_label.grid(row=0, column=9, sticky="w", padx=(8, 0))

        # Main content: hex | ascii | asm (toggleable) | scrollbar | tools area
        body = ttk.Frame(outer)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=0)
        body.columnconfigure(2, weight=0)
        body.columnconfigure(3, weight=0)
        body.columnconfigure(4, weight=0)
        body.columnconfigure(5, weight=1)
        body.columnconfigure(6, weight=1)
        body.rowconfigure(0, weight=0)
        body.rowconfigure(1, weight=1)

        hex_width = HEX_DISP_HEX_START + 3 * BYTES_PER_ROW - 1
        hex_header_text = " " * HEX_DISP_HEX_START + "  ".join(f"{i:X}" for i in range(BYTES_PER_ROW))
        self._hex_header = ttk.Label(body, text=hex_header_text, font=("Consolas", 10))
        self._hex_header.grid(row=0, column=0, sticky="w", padx=(0, 0), pady=(0, 0))

        self._scroll_y = tk.Scrollbar(body)
        self._text = tk.Text(
            body, font=("Consolas", 10), wrap=tk.NONE, borderwidth=0,
            highlightthickness=0, padx=0, pady=0, width=hex_width,
            insertbackground="black",
            selectbackground="#add8e6", selectforeground="black",
            exportselection=False,
        )
        self._text_ascii = tk.Text(
            body, font=("Consolas", 10), wrap=tk.NONE, borderwidth=0,
            highlightthickness=0, padx=0, pady=0, width=18,
            insertbackground="black",
            selectbackground="#add8e6", selectforeground="black",
            exportselection=False,
        )
        self._text.configure(yscrollcommand=self._on_text_yscroll)
        self._scroll_y.configure(command=self._on_scrollbar_command)

        self._text.grid(row=1, column=0, sticky="nsew", padx=(0, 0))
        self._text_ascii.grid(row=1, column=1, sticky="ns", padx=(0, 0))
        self._scroll_y.grid(row=1, column=2, sticky="ns")

        # ASM panel: to the right of hex scrollbar, toggleable, has vertical and horizontal scrollbars
        self._asm_frame = ttk.LabelFrame(body, text=" Disassembly ", padding=2)
        self._asm_frame.grid(row=1, column=3, sticky="nsew", padx=(4, 0))
        self._asm_frame.columnconfigure(0, weight=1)
        self._asm_frame.rowconfigure(0, weight=1)
        self._scroll_asm = tk.Scrollbar(self._asm_frame)
        self._scroll_asm_h = tk.Scrollbar(self._asm_frame, orient=tk.HORIZONTAL)
        self._text_asm = tk.Text(
            self._asm_frame, font=("Consolas", 10), wrap=tk.NONE, width=44,
            borderwidth=1, relief=tk.SOLID, padx=4, pady=2,
            state=tk.DISABLED,
            background="#f8f8f8",
            insertbackground="black",
        )
        self._text_asm.configure(yscrollcommand=self._scroll_asm.set, xscrollcommand=self._scroll_asm_h.set)
        self._scroll_asm.configure(command=self._text_asm.yview)
        self._scroll_asm_h.configure(command=self._text_asm.xview)
        self._text_asm.grid(row=0, column=0, sticky="nsew")
        self._scroll_asm.grid(row=0, column=1, sticky="ns")
        self._scroll_asm_h.grid(row=1, column=0, sticky="ew")

        def _asm_scroll(delta: int) -> None:
            self._text_asm.yview_scroll(-delta, "units")

        for w in (self._text_asm, self._asm_frame):
            w.bind("<MouseWheel>", lambda e: _asm_scroll(int((e.delta or 0) / 120)))
            w.bind("<Button-4>", lambda e: _asm_scroll(3))
            w.bind("<Button-5>", lambda e: _asm_scroll(-3))

        # Pseudo-C pane: to the right of ASM, hidden by default, toggleable with Ctrl+D
        self._pseudo_c_frame = ttk.LabelFrame(body, text=" Pseudo-C ", padding=2)
        self._pseudo_c_frame.grid(row=1, column=4, sticky="nsew", padx=(4, 0))
        self._pseudo_c_frame.columnconfigure(0, weight=3)
        self._pseudo_c_frame.columnconfigure(1, weight=5)
        self._pseudo_c_frame.rowconfigure(2, weight=1)
        self._c_inject_offset_var = tk.StringVar(value="")
        self._c_inject_size_var = tk.StringVar(value="—")
        self._c_inject_rom_window_from_var = tk.StringVar(value="")
        self._c_inject_rom_window_to_var = tk.StringVar(value="")
        pc_toolbar = ttk.Frame(self._pseudo_c_frame)
        pc_toolbar.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        ttk.Label(pc_toolbar, text="Inject @", font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 2))
        self._c_inject_offset_entry = ttk.Entry(
            pc_toolbar, textvariable=self._c_inject_offset_var, width=20, font=("Consolas", 8)
        )
        self._c_inject_offset_entry.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(pc_toolbar, text="Compiled:", font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Label(pc_toolbar, textvariable=self._c_inject_size_var, font=("Consolas", 8)).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(pc_toolbar, text="Ctrl+Shift+4 edit · 5 compile · 6 apply patches", font=("Consolas", 8), foreground="#555").pack(
            side=tk.LEFT
        )

        c_inj_opts = ttk.Frame(self._pseudo_c_frame)
        c_inj_opts.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        for col in (0, 1, 2):
            c_inj_opts.columnconfigure(col, weight=1)
        ttk.Label(
            c_inj_opts,
            text="Optional ROM window (file offsets): limits ### repointall; same range for FF gap → Inject @.",
            font=("Consolas", 8),
            foreground="#555",
            wraplength=520,
            justify=tk.LEFT,
        ).grid(row=0, column=0, columnspan=3, sticky="ew")
        ttk.Label(c_inj_opts, text="from", font=("Consolas", 8), foreground="#555").grid(row=1, column=0, sticky="w")
        self._c_inject_rom_window_from = ttk.Entry(
            c_inj_opts, textvariable=self._c_inject_rom_window_from_var, width=18, font=("Consolas", 8)
        )
        self._c_inject_rom_window_from.grid(row=2, column=0, sticky="ew", padx=(0, 6))
        ttk.Label(c_inj_opts, text="through", font=("Consolas", 8), foreground="#555").grid(row=1, column=1, sticky="w")
        self._c_inject_rom_window_to = ttk.Entry(
            c_inj_opts, textvariable=self._c_inject_rom_window_to_var, width=18, font=("Consolas", 8)
        )
        self._c_inject_rom_window_to.grid(row=2, column=1, sticky="ew", padx=(0, 6))
        ttk.Button(
            c_inj_opts,
            text="FF gap → Inject @",
            command=self._c_inject_search_ff_gap_to_inject_offset,
        ).grid(row=2, column=2, sticky="ew")

        self._pseudo_c_left = ttk.Frame(self._pseudo_c_frame)
        self._pseudo_c_left.grid(row=2, column=0, sticky="nsew", padx=(0, 4))
        self._pseudo_c_left.columnconfigure(0, weight=1)
        self._pseudo_c_left.rowconfigure(0, weight=1)

        self._scroll_pseudo_c = tk.Scrollbar(self._pseudo_c_left)
        self._scroll_pseudo_c_h = tk.Scrollbar(self._pseudo_c_left, orient=tk.HORIZONTAL)
        self._text_pseudo_c = tk.Text(
            self._pseudo_c_left, font=("Consolas", 10), wrap=tk.NONE, width=42,
            borderwidth=1, relief=tk.SOLID, padx=4, pady=2,
            state=tk.DISABLED,
            background="#fafaf8",
            insertbackground="black",
        )
        self._text_pseudo_c.configure(yscrollcommand=self._scroll_pseudo_c.set, xscrollcommand=self._scroll_pseudo_c_h.set)
        self._scroll_pseudo_c.configure(command=self._text_pseudo_c.yview)
        self._scroll_pseudo_c_h.configure(command=self._text_pseudo_c.xview)
        self._text_pseudo_c.grid(row=0, column=0, sticky="nsew")
        self._scroll_pseudo_c.grid(row=0, column=1, sticky="ns")
        self._scroll_pseudo_c_h.grid(row=1, column=0, columnspan=2, sticky="ew")

        self._pseudo_c_right = ttk.Frame(self._pseudo_c_frame)
        self._pseudo_c_right.columnconfigure(0, weight=1)
        self._pseudo_c_right.rowconfigure(1, weight=1)

        self._c_inject_patches_label = ttk.Label(
            self._pseudo_c_right,
            text=" ROM hooks & repoints — ### hooks / repointall / repoints / routinepointers ",
            font=("Consolas", 8),
        )
        self._scroll_c_inject_patches = tk.Scrollbar(self._pseudo_c_right)
        self._scroll_c_inject_patches_h = tk.Scrollbar(self._pseudo_c_right, orient=tk.HORIZONTAL)
        self._text_c_inject_patches = tk.Text(
            self._pseudo_c_right,
            font=("Consolas", 9),
            wrap=tk.NONE,
            width=52,
            height=16,
            borderwidth=1,
            relief=tk.SOLID,
            padx=4,
            pady=2,
            state=tk.NORMAL,
            background="#f5f8ff",
            insertbackground="black",
        )
        self._text_c_inject_patches.configure(
            yscrollcommand=self._scroll_c_inject_patches.set,
            xscrollcommand=self._scroll_c_inject_patches_h.set,
        )
        self._scroll_c_inject_patches.configure(command=self._text_c_inject_patches.yview)
        self._scroll_c_inject_patches_h.configure(command=self._text_c_inject_patches.xview)
        self._c_inject_patches_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 2))
        self._text_c_inject_patches.grid(row=1, column=0, sticky="nsew")
        self._scroll_c_inject_patches.grid(row=1, column=1, sticky="ns")
        self._scroll_c_inject_patches_h.grid(row=2, column=0, columnspan=2, sticky="ew")
        self._pseudo_c_right.grid_remove()

        def _pseudo_c_scroll(delta: int) -> None:
            self._text_pseudo_c.yview_scroll(-delta, "units")

        def _c_inject_patches_scroll(delta: int) -> None:
            self._text_c_inject_patches.yview_scroll(-delta, "units")

        for w in (self._text_pseudo_c, self._pseudo_c_left, self._pseudo_c_frame):
            w.bind("<MouseWheel>", lambda e: _pseudo_c_scroll(int((e.delta or 0) / 120)))
            w.bind("<Button-4>", lambda e: _pseudo_c_scroll(3))
            w.bind("<Button-5>", lambda e: _pseudo_c_scroll(-3))
        for w in (self._text_c_inject_patches, self._c_inject_patches_label, self._pseudo_c_right):
            w.bind("<MouseWheel>", lambda e: _c_inject_patches_scroll(int((e.delta or 0) / 120)))
            w.bind("<Button-4>", lambda e: _c_inject_patches_scroll(3))
            w.bind("<Button-5>", lambda e: _c_inject_patches_scroll(-3))

        # Horizontal sash between Anchors and Tools (user-adjustable width); Ctrl+M toggles Anchors pane.
        self._anchor_tools_pane = ttk.PanedWindow(body, orient=tk.HORIZONTAL)

        # Function/NamedAnchor browser: hierarchical nav (1st -> 2nd -> 3rd order), Ctrl+M
        self._anchor_frame = ttk.LabelFrame(body, text=" Anchors ", padding=2)
        self._anchor_frame.columnconfigure(0, weight=1)
        self._anchor_frame.rowconfigure(1, weight=1)
        self._anchor_sym_filter_frame = ttk.Frame(self._anchor_frame)
        ttk.Label(self._anchor_sym_filter_frame, text="sym filter:", font=("Consolas", 8)).pack(
            side=tk.LEFT, padx=(0, 4)
        )
        self._anchor_sym_filter_entry = ttk.Entry(
            self._anchor_sym_filter_frame,
            textvariable=self._anchor_sym_filter_var,
            width=32,
            font=("Consolas", 8),
        )
        self._anchor_sym_filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._anchor_sym_filter_entry.bind("<KeyRelease>", self._on_anchor_sym_filter_keyrelease)
        self._scroll_anchor = tk.Scrollbar(self._anchor_frame)
        self._scroll_anchor_h = tk.Scrollbar(self._anchor_frame, orient=tk.HORIZONTAL)
        self._listbox_anchor = tk.Listbox(
            self._anchor_frame, font=("Consolas", 9), width=36, height=20,
            activestyle="dotbox", selectmode=tk.SINGLE,
            yscrollcommand=self._scroll_anchor.set,
            xscrollcommand=self._scroll_anchor_h.set,
        )
        self._scroll_anchor.configure(command=self._listbox_anchor.yview)
        self._scroll_anchor_h.configure(command=self._listbox_anchor.xview)
        self._listbox_anchor.grid(row=1, column=0, sticky="nsew")
        self._scroll_anchor.grid(row=1, column=1, sticky="ns")
        self._scroll_anchor_h.grid(row=2, column=0, sticky="ew")
        ttk.Frame(self._anchor_frame, width=12).grid(row=2, column=1, sticky="se")
        self._listbox_anchor.bind("<Double-Button-1>", self._on_anchor_browser_double_click)
        self._anchor_sym_filter_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        self._anchor_sym_filter_frame.grid_remove()

        def _anchor_scroll(delta: int) -> None:
            self._listbox_anchor.yview_scroll(-delta, "units")
        for w in (self._listbox_anchor, self._anchor_frame, self._anchor_sym_filter_frame, self._anchor_sym_filter_entry):
            w.bind("<MouseWheel>", lambda e: _anchor_scroll(int((e.delta or 0) / 120)))
            w.bind("<Button-4>", lambda e: _anchor_scroll(3))
            w.bind("<Button-5>", lambda e: _anchor_scroll(-3))

        self._tools_frame = ttk.Frame(body, width=1)
        self._tools_frame.grid(row=1, column=6, sticky="nsew", padx=(4, 0))

        # Python script pane (Ctrl+Shift+7): full right side; hides disasm / pseudo-C / tools
        self._script_frame = ttk.LabelFrame(body, text=" Python script ", padding=2)
        self._script_frame.columnconfigure(0, weight=1)
        self._script_frame.rowconfigure(1, weight=1)
        _stb = ttk.Frame(self._script_frame)
        _stb.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        ttk.Label(
            _stb,
            text="Ctrl+Shift+Enter — run   ·   Ctrl+Shift+7 — close",
            font=("Consolas", 8),
            foreground="#555",
        ).pack(side=tk.LEFT)
        self._script_paned = ttk.PanedWindow(self._script_frame, orient=tk.VERTICAL)
        self._script_paned.grid(row=1, column=0, sticky="nsew")
        _code_fr = ttk.Frame(self._script_paned)
        _out_fr = ttk.Frame(self._script_paned)
        _sc_code = tk.Scrollbar(_code_fr)
        _sc_out = tk.Scrollbar(_out_fr)
        self._text_script = tk.Text(
            _code_fr,
            font=("Consolas", 10),
            wrap=tk.WORD,
            height=18,
            undo=True,
            borderwidth=1,
            relief=tk.SOLID,
            padx=4,
            pady=4,
            background="#fffef8",
        )
        self._text_script_output = tk.Text(
            _out_fr,
            font=("Consolas", 9),
            wrap=tk.WORD,
            height=12,
            state=tk.DISABLED,
            borderwidth=1,
            relief=tk.SOLID,
            padx=4,
            pady=4,
            background="#f4f4f4",
            foreground="#111",
        )
        self._text_script.grid(row=0, column=0, sticky="nsew")
        _sc_code.grid(row=0, column=1, sticky="ns")
        self._text_script_output.grid(row=0, column=0, sticky="nsew")
        _sc_out.grid(row=0, column=1, sticky="ns")
        _code_fr.columnconfigure(0, weight=1)
        _code_fr.rowconfigure(0, weight=1)
        _out_fr.columnconfigure(0, weight=1)
        _out_fr.rowconfigure(0, weight=1)
        self._text_script.configure(yscrollcommand=_sc_code.set)
        _sc_code.configure(command=self._text_script.yview)
        self._text_script_output.configure(yscrollcommand=_sc_out.set)
        _sc_out.configure(command=self._text_script_output.yview)
        self._script_paned.add(_code_fr, weight=3)
        self._script_paned.add(_out_fr, weight=2)
        self._script_frame.grid_remove()

        self._on_pointer_to_named_anchor_cb: Optional[Any] = None

        if not self._asm_pane_visible:
            self._asm_frame.grid_remove()
        if not self._pseudo_c_pane_visible:
            self._pseudo_c_frame.grid_remove()
        if not self._anchor_browser_pane_visible:
            self._anchor_frame.grid_remove()

        self._text.tag_configure("pointer", foreground="red")
        self._text.tag_configure("xref_caret", foreground="#1565C0")
        self._text.tag_configure("sel_hex", background="#add8e6", foreground="black")
        self._text.tag_configure("cursor_byte", background="#e0e0e0")
        self._text_ascii.tag_configure("pointer", foreground="red")
        self._text_ascii.tag_configure("sel_ascii", background="#add8e6", foreground="black")
        self._text_ascii.tag_configure("cursor_byte", background="#e0e0e0")

        self._init_syntax_highlight_tags()

        # Key / mouse bindings on hex widget
        self._text.bind("<KeyPress>", self._on_key)
        self._text.bind("<Button-1>", self._on_click)
        self._text.bind("<B1-Motion>", self._on_drag)
        self._text.bind("<Double-Button-1>", self._on_double_click)
        self._text.bind("<Button-3>", self._on_right_click)
        def _bind_asm_toggle(w: tk.Misc) -> None:
            w.bind("<Control-p>", self._toggle_asm_pane)
            w.bind("<Control-P>", self._toggle_asm_pane)

        def _bind_pseudo_c_toggle(w: tk.Misc) -> None:
            w.bind("<Control-d>", self._toggle_pseudo_c_pane)
            w.bind("<Control-D>", self._toggle_pseudo_c_pane)
        def _bind_goto(w: tk.Misc) -> None:
            w.bind("<Control-g>", self._focus_goto_entry)
            w.bind("<Control-G>", self._focus_goto_entry)

        _bind_asm_toggle(self._text)
        _bind_asm_toggle(self._text_ascii)
        _bind_asm_toggle(self._goto_entry)
        _bind_asm_toggle(self._encoding_combo)
        _bind_asm_toggle(self._asm_mode_combo)
        _bind_asm_toggle(outer)
        self.winfo_toplevel().bind("<Control-p>", self._toggle_asm_pane, add=True)
        self.winfo_toplevel().bind("<Control-P>", self._toggle_asm_pane, add=True)
        _bind_pseudo_c_toggle(self._text)
        _bind_pseudo_c_toggle(self._text_ascii)
        _bind_pseudo_c_toggle(self._goto_entry)
        _bind_pseudo_c_toggle(self._encoding_combo)
        _bind_pseudo_c_toggle(self._asm_mode_combo)
        _bind_pseudo_c_toggle(self._asm_frame)
        _bind_pseudo_c_toggle(self._text_asm)
        _bind_pseudo_c_toggle(self._pseudo_c_frame)
        _bind_pseudo_c_toggle(self._text_pseudo_c)
        _bind_pseudo_c_toggle(outer)
        self.winfo_toplevel().bind("<Control-d>", self._toggle_pseudo_c_pane, add=True)
        self.winfo_toplevel().bind("<Control-D>", self._toggle_pseudo_c_pane, add=True)
        def _bind_anchor_toggle(w: tk.Misc) -> None:
            w.bind("<Control-m>", self._toggle_anchor_browser_pane)
            w.bind("<Control-M>", self._toggle_anchor_browser_pane)
        _bind_anchor_toggle(self._text)
        _bind_anchor_toggle(self._text_ascii)
        _bind_anchor_toggle(self._goto_entry)
        _bind_anchor_toggle(self._encoding_combo)
        _bind_anchor_toggle(self._asm_mode_combo)
        _bind_anchor_toggle(self._asm_frame)
        _bind_anchor_toggle(self._text_asm)
        _bind_anchor_toggle(self._pseudo_c_frame)
        _bind_anchor_toggle(self._text_pseudo_c)
        _bind_anchor_toggle(self._anchor_frame)
        _bind_anchor_toggle(self._listbox_anchor)
        _bind_anchor_toggle(self._anchor_sym_filter_entry)
        _bind_anchor_toggle(outer)
        self.winfo_toplevel().bind("<Control-m>", self._toggle_anchor_browser_pane, add=True)
        self.winfo_toplevel().bind("<Control-M>", self._toggle_anchor_browser_pane, add=True)
        _bind_goto(self._text)
        _bind_goto(self._text_ascii)
        _bind_goto(self._goto_entry)
        _bind_goto(self._encoding_combo)
        _bind_goto(self._asm_mode_combo)
        _bind_goto(self._asm_frame)
        _bind_goto(self._text_asm)
        _bind_goto(self._pseudo_c_frame)
        _bind_goto(self._text_pseudo_c)
        _bind_goto(self._anchor_sym_filter_entry)
        _bind_goto(outer)
        self.winfo_toplevel().bind("<Control-g>", self._focus_goto_entry, add=True)
        self.winfo_toplevel().bind("<Control-G>", self._focus_goto_entry, add=True)
        for w in (
            self._text, self._text_ascii, self._goto_entry, self._encoding_combo,
            self._asm_mode_combo, self._asm_frame, self._text_asm,
            self._pseudo_c_frame, self._text_pseudo_c, outer,
        ):
            w.bind("<Control-h>", self._toggle_hackmew_mode)
            w.bind("<Control-H>", self._toggle_hackmew_mode)
            w.bind("<Control-i>", self._compile_hackmew_asm)
            w.bind("<Control-I>", self._compile_hackmew_asm)
        self.winfo_toplevel().bind("<Control-h>", self._toggle_hackmew_mode, add=True)
        self.winfo_toplevel().bind("<Control-H>", self._toggle_hackmew_mode, add=True)
        self.winfo_toplevel().bind("<Control-i>", self._compile_hackmew_asm, add=True)
        self.winfo_toplevel().bind("<Control-I>", self._compile_hackmew_asm, add=True)
        for w in (
            self._text, self._text_ascii, self._goto_entry, self._encoding_combo,
            self._asm_mode_combo, self._asm_frame, self._text_asm,
            self._pseudo_c_frame, self._text_pseudo_c, self._text_c_inject_patches,
            self._c_inject_patches_label, pc_toolbar, self._c_inject_offset_entry, outer,
        ):
            w.bind("<Control-Shift-Key-4>", self._toggle_c_inject_edit_mode)
            w.bind("<Control-Shift-dollar>", self._toggle_c_inject_edit_mode)
            w.bind("<Control-Shift-Key-5>", self._compile_c_inject)
            w.bind("<Control-Shift-percent>", self._compile_c_inject)
            w.bind("<Control-Shift-Key-6>", self._apply_c_inject_rom_patches_cmd)
            w.bind("<Control-Shift-asciicircum>", self._apply_c_inject_rom_patches_cmd)
        self.winfo_toplevel().bind("<Control-Shift-Key-4>", self._toggle_c_inject_edit_mode, add=True)
        self.winfo_toplevel().bind("<Control-Shift-dollar>", self._toggle_c_inject_edit_mode, add=True)
        self.winfo_toplevel().bind("<Control-Shift-Key-5>", self._compile_c_inject, add=True)
        self.winfo_toplevel().bind("<Control-Shift-percent>", self._compile_c_inject, add=True)
        self.winfo_toplevel().bind("<Control-Shift-Key-6>", self._apply_c_inject_rom_patches_cmd, add=True)
        self.winfo_toplevel().bind("<Control-Shift-asciicircum>", self._apply_c_inject_rom_patches_cmd, add=True)
        for w in (
            self._text,
            self._text_ascii,
            self._goto_entry,
            self._encoding_combo,
            self._asm_mode_combo,
            self._asm_frame,
            self._text_asm,
            self._pseudo_c_frame,
            self._text_pseudo_c,
            self._text_script,
            self._text_script_output,
            outer,
        ):
            w.bind("<Control-Shift-Key-7>", self._toggle_script_pane)
            w.bind("<Control-Shift-ampersand>", self._toggle_script_pane)
        self.winfo_toplevel().bind("<Control-Shift-Key-7>", self._toggle_script_pane, add=True)
        self.winfo_toplevel().bind("<Control-Shift-ampersand>", self._toggle_script_pane, add=True)
        self._text_script.bind("<Control-Shift-Return>", self._run_channeler_script)
        self._text_script.bind("<Control-Shift-Key-Return>", self._run_channeler_script)
        self._text_script_output.bind("<Control-Shift-Return>", self._run_channeler_script)
        self._text_script_output.bind("<Control-Shift-Key-Return>", self._run_channeler_script)
        self.winfo_toplevel().bind("<Control-Shift-Return>", self._run_channeler_script, add=True)
        self.winfo_toplevel().bind("<Control-Shift-Key-Return>", self._run_channeler_script, add=True)

        def _script_scroll(delta: int) -> None:
            w = self.winfo_toplevel().focus_get()
            if w == self._text_script_output:
                self._text_script_output.yview_scroll(-delta, "units")
            else:
                self._text_script.yview_scroll(-delta, "units")

        for w in (self._text_script, self._text_script_output, self._script_frame):
            w.bind("<MouseWheel>", lambda e: _script_scroll(int((e.delta or 0) / 120)))
            w.bind("<Button-4>", lambda e: _script_scroll(3))
            w.bind("<Button-5>", lambda e: _script_scroll(-3))
        for w in (
            self._text, self._text_ascii, self._goto_entry, self._encoding_combo,
            self._asm_mode_combo, self._asm_frame, self._text_asm,
            self._pseudo_c_frame, self._text_pseudo_c, self._anchor_frame,
            self._listbox_anchor, outer,
        ):
            w.bind("<Control-f>", self._show_find_dialog)
            w.bind("<Control-F>", self._show_find_dialog)
            w.bind("<Control-r>", self._show_replace_dialog)
            w.bind("<Control-R>", self._show_replace_dialog)
        self.winfo_toplevel().bind("<Control-f>", self._show_find_dialog, add=True)
        self.winfo_toplevel().bind("<Control-F>", self._show_find_dialog, add=True)
        self.winfo_toplevel().bind("<Control-r>", self._show_replace_dialog, add=True)
        self.winfo_toplevel().bind("<Control-R>", self._show_replace_dialog, add=True)

        for w in (self._text_asm, self._text_pseudo_c, self._text_c_inject_patches):
            w.bind("<Control-a>", self._select_all)
            w.bind("<Control-A>", self._select_all)
        self._text.bind("<Control-c>", self._copy_hex_ascii)
        self._text.bind("<Control-C>", self._copy_hex_ascii)
        self._text_ascii.bind("<Control-c>", self._copy_hex_ascii)
        self._text_ascii.bind("<Control-C>", self._copy_hex_ascii)
        self._text.bind("<<Copy>>", lambda e: self._copy_hex_ascii(e) or "break")
        self._text_ascii.bind("<<Copy>>", lambda e: self._copy_hex_ascii(e) or "break")
        self._text.bind("<Control-v>", self._paste_insert)
        self._text.bind("<Control-V>", self._paste_insert)
        self._text.bind("<Control-b>", self._paste_write)
        self._text.bind("<Control-B>", self._paste_write)
        self._text.bind("<<Paste>>", lambda e: self._paste_insert(e) or "break")
        self._text_ascii.bind("<Control-v>", self._paste_insert)
        self._text_ascii.bind("<Control-V>", self._paste_insert)
        self._text_ascii.bind("<Control-b>", self._paste_write)
        self._text_ascii.bind("<Control-B>", self._paste_write)
        self._text_ascii.bind("<<Paste>>", lambda e: self._paste_insert(e) or "break")
        self._text.bind("<Delete>", self._on_delete)
        self._text.bind("<Insert>", self._on_insert_key)
        self._text.bind("<BackSpace>", self._on_backspace)
        self._text.bind("<Left>", lambda e: self._move_cursor(-1) or "break")
        self._text.bind("<Right>", lambda e: self._move_cursor(1) or "break")
        self._text.bind("<Up>", lambda e: self._move_cursor(-BYTES_PER_ROW) or "break")
        self._text.bind("<Down>", lambda e: self._move_cursor(BYTES_PER_ROW) or "break")
        self._text.bind("<Home>", self._on_home)
        self._text.bind("<End>", self._on_end)
        self._text.bind("<Control-Home>", self._on_ctrl_home)
        self._text.bind("<Control-End>", self._on_ctrl_end)
        self._text.bind("<Configure>", self._on_text_configure)
        def _scroll_and_sync(amount: int, units: str = "units") -> Optional[str]:
            if self._data:
                self._on_scrollbar_command("scroll", amount, units)
            return "break"

        self._text.bind("<Prior>", lambda e: _scroll_and_sync(-self._visible_row_count))
        self._text.bind("<Next>", lambda e: _scroll_and_sync(self._visible_row_count))
        self._text.bind("<MouseWheel>", self._on_mousewheel)
        self._text.bind("<Button-4>", lambda e: _scroll_and_sync(-3))
        self._text.bind("<Button-5>", lambda e: _scroll_and_sync(3))
        self._text_ascii.bind("<MouseWheel>", self._on_mousewheel)
        self._text_ascii.bind("<Button-4>", lambda e: _scroll_and_sync(-3))
        self._text_ascii.bind("<Button-5>", lambda e: _scroll_and_sync(3))
        self._text_ascii.bind("<Button-1>", self._on_ascii_click)
        self._text_ascii.bind("<B1-Motion>", self._on_ascii_drag)
        self._text_ascii.bind("<KeyPress>", self._on_ascii_key)

        self._text.bind("<KeyPress>", self._prevent_unwanted, add=True)

    def _focus_goto_entry(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Focus the Goto (offset) entry box. Bound to Ctrl+G."""
        self._goto_entry.focus_set()
        self._goto_entry.select_range(0, tk.END)
        return "break"

    def _on_goto_escape_to_hex(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Leave the Goto field and return keyboard focus to the hex pane."""
        self._text.focus_set()
        return "break"

    def _init_syntax_highlight_tags(self) -> None:
        """Configure Pygments token tags for ASM and Pseudo-C panes. GBA address regions use custom greens."""
        for w in (self._text_asm, self._text_pseudo_c):
            w.tag_configure("Token.Keyword", foreground="#0000FF")
            w.tag_configure("Token.Keyword.Declaration", foreground="#0000FF")
            w.tag_configure("Token.Keyword.Type", foreground="#2E8B57")
            w.tag_configure("Token.Comment", foreground="#B22222")
            w.tag_configure("Token.Comment.Single", foreground="#B22222")
            w.tag_configure("Token.Comment.Multi", foreground="#B22222")
            w.tag_configure("Token.String", foreground="#BC8F8F")
            w.tag_configure("Token.Number", foreground="#68228B")
            w.tag_configure("Token.Number.Hex", foreground="#68228B")
            w.tag_configure("Token.Operator", foreground="#333333")
            w.tag_configure("Token.Name.Label", foreground="#228B22")
            w.tag_configure("Token.Name.Function", foreground="#00008B")
            w.tag_configure("addr_rom", foreground="#39FF14")   # neon green
            w.tag_configure("addr_ewram", foreground="#32CD32")  # leaf green
            w.tag_configure("addr_iwram", foreground="#006400")  # dark green
            w.tag_configure("loc_label", foreground="#DC143C")  # crimson red for loc_

    def _apply_syntax_highlighting(self, widget: tk.Text, lang: str) -> None:
        """Apply Pygments syntax highlighting and GBA address coloring to widget content."""
        text = widget.get("1.0", tk.END)
        if not text.strip():
            return
        try:
            if _PYGMENTS_AVAILABLE:
                lexer = get_lexer_by_name("gas" if lang == "asm" else "c", stripall=False)
                widget.mark_set("_hl_start", "1.0")
                for token_type, value in lex(text, lexer):
                    if not value:
                        continue
                    widget.mark_set("_hl_end", "_hl_start + %dc" % len(value))
                    tag_name = str(token_type)
                    try:
                        raw = value.strip().lstrip("#<>")
                        if raw.lower().startswith("0x"):
                            val = int(raw, 16)
                            if GBA_ROM_BASE <= val <= GBA_ROM_MAX:
                                tag_name = "addr_rom"
                            elif GBA_EWRAM_START <= val <= GBA_EWRAM_END:
                                tag_name = "addr_ewram"
                            elif GBA_IWRAM_START <= val <= GBA_IWRAM_END:
                                tag_name = "addr_iwram"
                    except (ValueError, TypeError):
                        pass
                    widget.tag_add(tag_name, "_hl_start", "_hl_end")
                    widget.mark_set("_hl_start", "_hl_end")
            self._apply_gba_address_tags(widget, text)
        except Exception:
            pass

    def _classify_gba_address(self, val: int) -> Optional[str]:
        """Return the highlight tag for a GBA address value, or None."""
        if GBA_ROM_BASE <= val <= GBA_ROM_MAX:
            return "addr_rom"
        if GBA_EWRAM_START <= val <= GBA_EWRAM_END:
            return "addr_ewram"
        if GBA_IWRAM_START <= val <= GBA_IWRAM_END:
            return "addr_iwram"
        return None

    def _apply_gba_address_tags(self, widget: tk.Text, text: str) -> None:
        """Tag GBA addresses, sub_/loc_/g_ labels in a text widget."""
        # Hex address literals: 0x08XXXXXX, 0x8XXXXXX, 0x02XXXXXX, 0x2XXXXXX, etc.
        for match in re.finditer(r"(?<![.\w])#?(0x[0-9A-Fa-f]{7,8})\b", text):
            try:
                val = int(match.group(1), 16)
                tag = self._classify_gba_address(val)
                if tag:
                    widget.tag_add(tag, f"1.0+{match.start(1)}c", f"1.0+{match.end(1)}c")
            except (ValueError, TypeError):
                pass
        # sub_XXXXXXXX / sub_XXXXXXX — ROM function names (neon green)
        for match in re.finditer(r"\bsub_([0-9A-Fa-f]{7,8})\b", text):
            try:
                val = int(match.group(1), 16)
                if self._classify_gba_address(val) == "addr_rom":
                    widget.tag_add("addr_rom", f"1.0+{match.start(0)}c", f"1.0+{match.end(0)}c")
            except (ValueError, TypeError):
                pass
        # loc_XXXXXXXX — branch labels (red)
        for match in re.finditer(r"\bloc_[0-9A-Fa-f]{7,8}\b", text):
            widget.tag_add("loc_label", f"1.0+{match.start(0)}c", f"1.0+{match.end(0)}c")
        # g_XXXXXXX — EWRAM / IWRAM global variable names
        for match in re.finditer(r"\bg_([0-9A-Fa-f]{7,8})\b", text):
            try:
                val = int(match.group(1), 16)
                tag = self._classify_gba_address(val)
                if tag in ("addr_ewram", "addr_iwram"):
                    widget.tag_add(tag, f"1.0+{match.start(0)}c", f"1.0+{match.end(0)}c")
            except (ValueError, TypeError):
                pass
        for tag in ("addr_rom", "addr_ewram", "addr_iwram", "loc_label"):
            widget.tag_raise(tag)

    def _toggle_asm_pane(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Toggle ASM disassembly pane visibility. Bound to Ctrl+P.
        When opening, uses highlighted bytes if any."""
        self._goto_entry.selection_clear()
        self._text.focus_set()
        self._asm_pane_visible = not self._asm_pane_visible
        if self._asm_pane_visible:
            self._asm_frame.grid(row=1, column=3, sticky="nsew", padx=(4, 0))
            if self._hackmew_mode:
                self._refresh_asm_hackmew()
            else:
                self._refresh_asm_selection()
        else:
            if self._hackmew_mode:
                self._hackmew_mode = False
                self._asm_frame.configure(text=" Disassembly ")
            self._asm_frame.grid_remove()
        self.after_idle(self._refresh_visible)
        return "break"

    def _toggle_hackmew_mode(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Toggle between standard ASM display and editable HackMew ASM. Bound to Ctrl+H."""
        if not self._asm_pane_visible:
            return "break"
        self._hackmew_mode = not self._hackmew_mode
        if self._hackmew_mode:
            self._asm_frame.configure(text=" HackMew ASM (editable) ")
            self._refresh_asm_hackmew()
        else:
            self._asm_frame.configure(text=" Disassembly ")
            self._refresh_asm_selection()
        return "break"

    def _preprocess_hackmew_asm_for_compile(self, asm_text: str) -> str:
        """Convert ldr rX, [pc, <label>] to ldr rX, [pc, #0xYY] by resolving label positions within the ASM.
        Normalize S-suffix mnemonics (eors, ands, orrs, bics) to base forms for Hackmew assembler compatibility."""
        lines = asm_text.splitlines()
        # Hackmew's assembler expects eor not eors, etc.
        for i, raw in enumerate(lines):
            line = raw.split("@")[0].strip()
            if line and not line.endswith(":") and not line.startswith("."):
                normalized = re.sub(r"\beors\b", "eor", line, flags=re.IGNORECASE)
                normalized = re.sub(r"\bands\b", "and", normalized, flags=re.IGNORECASE)
                normalized = re.sub(r"\borrs\b", "orr", normalized, flags=re.IGNORECASE)
                normalized = re.sub(r"\bbics\b", "bic", normalized, flags=re.IGNORECASE)
                if normalized != line:
                    lines[i] = raw[: raw.find(line)] + normalized + raw[raw.find(line) + len(line) :]
        base = self._hackmew_asm_start
        align = 4

        def _insn_size(raw_line: str) -> int:
            s = raw_line.split("@")[0].strip()
            if not s or s.endswith(":"):
                return 0
            if s.startswith(".word"):
                return 4
            if s.startswith(".byte"):
                return 2
            if re.match(r"(?:bl|blx)\b", s):
                return 4
            return align

        label_to_file_off: Dict[str, int] = {}
        addr = base
        for raw in lines:
            line = raw.split("@")[0].strip()
            if not line:
                continue
            if line.endswith(":"):
                label_to_file_off[line[:-1].strip()] = addr
                continue
            addr += _insn_size(raw)

        addr = base
        for i, raw in enumerate(lines):
            line = raw.split("@")[0].strip()
            if not line:
                continue
            if line.endswith(":"):
                continue
            if line.startswith(".word") or line.startswith(".byte"):
                addr += _insn_size(raw)
                continue

            match = re.search(
                r"(ldr[bh]?\s+\w+\s*,\s*\[\s*pc\s*,\s*)"
                r"((?:<\s*)?loc_[0-9A-Fa-f]{8}(?:\s*>)?)\s*(\])",
                raw,
                re.IGNORECASE,
            )
            if match:
                prefix, label_ref, closer = match.groups()
                label_name = label_ref.strip().strip("<>").strip()
                target_file_off = label_to_file_off.get(label_name)
                if target_file_off is not None:
                    target_rom = GBA_ROM_BASE + target_file_off
                    if self._asm_mode == "thumb":
                        pc_val = GBA_ROM_BASE + ((addr + 4) & ~3)
                    else:
                        pc_val = GBA_ROM_BASE + addr + 8
                    offset = target_rom - pc_val
                    new_operand = f"{prefix}#0x{offset & 0xFFFFFFFF:x}{closer}"
                    lines[i] = raw[: match.start()] + new_operand + raw[match.end() :]
            addr += _insn_size(raw)

        return "\n".join(lines)

    def _compile_hackmew_asm(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Compile edited HackMew ASM via deps/thumb.bat and insert .bin into ROM. Bound to Ctrl+I."""
        if not self._hackmew_mode or not self._asm_pane_visible:
            return "break"
        if self._hackmew_asm_start is None or self._hackmew_asm_end is None:
            messagebox.showerror("Compile Error", "No ASM region defined.")
            return "break"
        asm_text = self._text_asm.get("1.0", tk.END).strip()
        if not asm_text:
            messagebox.showerror("Compile Error", "ASM pane is empty.")
            return "break"
        asm_text = self._preprocess_hackmew_asm_for_compile(asm_text)

        original_size = self._hackmew_asm_end - self._hackmew_asm_start

        deps_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "deps")
        thumb_bat = os.path.join(deps_dir, "thumb.bat")
        if not os.path.isfile(thumb_bat):
            messagebox.showerror("Compile Error", f"thumb.bat not found at:\n{thumb_bat}")
            return "break"

        import tempfile
        import subprocess
        with tempfile.TemporaryDirectory() as tmpdir:
            asm_path = os.path.join(tmpdir, "edit.asm")
            bin_path = os.path.join(tmpdir, "edit.bin")
            origin = GBA_ROM_BASE + self._hackmew_asm_start
            preamble = f".thumb\n.align 4\n.org 0x{origin:X}\n\n"
            with open(asm_path, "w", encoding="utf-8") as f:
                f.write(preamble + asm_text + "\n")

            result = subprocess.run(
                [thumb_bat, asm_path, bin_path],
                cwd=deps_dir,
                capture_output=True,
                text=True,
                shell=True,
            )
            if result.returncode != 0 or not os.path.isfile(bin_path):
                err = (result.stdout + "\n" + result.stderr).strip()
                messagebox.showerror("Compile Error", f"Assembly failed:\n{err}")
                return "break"

            with open(bin_path, "rb") as f:
                compiled = f.read()

            # Skip bytes before .org origin (padding inserted by assembler)
            if len(compiled) > origin:
                compiled = compiled[origin:]
            elif len(compiled) < origin:
                messagebox.showerror(
                    "Compile Error",
                    f"Assembler output ({len(compiled)} bytes) smaller than "
                    f"origin (0x{origin:X}); cannot clip.",
                )
                return "break"

        if len(compiled) > original_size:
            messagebox.showerror(
                "Compile Error",
                f"Compiled binary ({len(compiled)} bytes) exceeds "
                f"original routine space ({original_size} bytes).",
            )
            return "break"

        start = self._hackmew_asm_start
        for i, b in enumerate(compiled):
            self._data[start + i] = b
        for i in range(len(compiled), original_size):
            self._data[start + i] = 0xFF
        self._modified = True
        self._ldr_pc_targets_valid = False
        self._schedule_xref_rebuild()
        self._hackmew_mode = False
        self._asm_frame.configure(text=" Disassembly ")
        self._refresh_asm_selection()
        self._refresh_visible()
        messagebox.showinfo(
            "Compile Success",
            f"Inserted {len(compiled)} bytes at 0x{start:08X} "
            f"({original_size - len(compiled)} bytes remaining).",
        )
        return "break"

    def _toggle_pseudo_c_pane(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Toggle Pseudo-C pane visibility. Bound to Ctrl+D."""
        self._goto_entry.selection_clear()
        self._text.focus_set()
        self._pseudo_c_pane_visible = not self._pseudo_c_pane_visible
        if self._pseudo_c_pane_visible:
            self._pseudo_c_frame.grid(row=1, column=4, sticky="nsew", padx=(4, 0))
            self._refresh_pseudo_c_selection()
        else:
            self._pseudo_c_frame.grid_remove()
        self.after_idle(self._refresh_visible)
        return "break"

    def _hide_asm_and_anchor_for_c_inject(self) -> None:
        """Close disassembly and anchor browser (C inject steals horizontal space / focus)."""
        if self._asm_pane_visible:
            self._asm_pane_visible = False
            if self._hackmew_mode:
                self._hackmew_mode = False
                self._asm_frame.configure(text=" Disassembly ")
            self._asm_frame.grid_remove()
        if self._anchor_browser_pane_visible:
            self._anchor_browser_pane_visible = False
            if self._anchor_tools_pane_layout:
                self._anchor_tools_pane.grid_remove()
                try:
                    self._anchor_tools_pane.remove(self._anchor_frame)
                except tk.TclError:
                    pass
                try:
                    self._anchor_tools_pane.remove(self._tools_frame)
                except tk.TclError:
                    pass
                self._tools_frame.grid(row=1, column=6, sticky="nsew", padx=(4, 0))
                self._anchor_tools_pane_layout = False
            else:
                self._anchor_frame.grid_remove()

    def _show_c_inject_patches_pane(self) -> None:
        """Show ``### hooks`` / repoint column to the right of decompilation."""
        self._pseudo_c_right.grid(row=2, column=1, sticky="nsew")
        if not self._text_c_inject_patches.get("1.0", tk.END).strip():
            self._text_c_inject_patches.insert("1.0", C_INJECT_PATCHES_TEMPLATE)

    def _hide_c_inject_patches_pane(self) -> None:
        self._pseudo_c_right.grid_remove()

    def _append_script_log(self, s: str) -> None:
        """Append text to the script output pane (thread: main / Tk only)."""
        self._text_script_output.configure(state=tk.NORMAL)
        self._text_script_output.insert(tk.END, s)
        self._text_script_output.configure(state=tk.DISABLED)
        self._text_script_output.see(tk.END)

    def _hide_right_side_for_script(self) -> None:
        """Remove disassembly, pseudo-C, anchors, and tools from the grid (script pane will cover columns 3–6)."""
        self._script_ui_saved = {
            "asm_visible": self._asm_pane_visible,
            "pseudo_c_visible": self._pseudo_c_pane_visible,
            "c_inject": self._c_inject_mode,
            "anchor_browser": self._anchor_browser_pane_visible,
            "anchor_layout": self._anchor_tools_pane_layout,
            "hackmew": self._hackmew_mode,
        }
        if self._asm_pane_visible:
            self._asm_frame.grid_remove()
        if self._pseudo_c_pane_visible:
            self._pseudo_c_frame.grid_remove()
        if self._anchor_browser_pane_visible:
            if self._anchor_tools_pane_layout:
                self._anchor_tools_pane.grid_remove()
                try:
                    self._anchor_tools_pane.remove(self._anchor_frame)
                except tk.TclError:
                    pass
                try:
                    self._anchor_tools_pane.remove(self._tools_frame)
                except tk.TclError:
                    pass
                self._tools_frame.grid(row=1, column=6, sticky="nsew", padx=(4, 0))
                self._anchor_tools_pane_layout = False
            else:
                self._anchor_frame.grid_remove()
        self._tools_frame.grid_remove()

    def _restore_right_side_after_script(self) -> None:
        """Restore panes saved by :meth:`_hide_right_side_for_script`."""
        st = self._script_ui_saved or {}
        self._script_ui_saved = None
        if st.get("asm_visible"):
            self._asm_frame.grid(row=1, column=3, sticky="nsew", padx=(4, 0))
            if st.get("hackmew"):
                self._refresh_asm_hackmew()
            else:
                self._refresh_asm_selection()
        if st.get("pseudo_c_visible"):
            self._pseudo_c_frame.grid(row=1, column=4, sticky="nsew", padx=(4, 0))
            if st.get("c_inject"):
                self._c_inject_mode = True
                self._pseudo_c_frame.configure(text=" Pseudo-C (C edit) ")
                self._text_pseudo_c.configure(state=tk.NORMAL)
                self._show_c_inject_patches_pane()
            else:
                self._c_inject_mode = False
                self._pseudo_c_frame.configure(text=" Pseudo-C ")
                self._hide_c_inject_patches_pane()
                self._refresh_pseudo_c_selection()
        if st.get("anchor_browser"):
            try:
                self._tools_frame.grid_remove()
            except tk.TclError:
                pass
            self._anchor_tools_pane.add(self._anchor_frame, weight=1)
            self._anchor_tools_pane.add(self._tools_frame, weight=1)
            self._anchor_tools_pane.grid(row=1, column=5, columnspan=2, sticky="nsew", padx=(4, 0))
            self._anchor_tools_pane_layout = True
            self._anchor_browser_pane_visible = True

            def _sash() -> None:
                try:
                    self._anchor_tools_pane.sashpos(0, 320)
                except tk.TclError:
                    pass

            self.after_idle(_sash)
        else:
            self._tools_frame.grid(row=1, column=6, sticky="nsew", padx=(4, 0))

    def _toggle_script_pane(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Toggle full-width Python script pane. Bound to Ctrl+Shift+7."""
        self._goto_entry.selection_clear()
        self._script_pane_visible = not self._script_pane_visible
        if self._script_pane_visible:
            self._hide_right_side_for_script()
            if not self._text_script.get("1.0", tk.END).strip():
                self._text_script.insert("1.0", CHANNELER_SCRIPT_TEMPLATE)
            self._append_script_log(format_run_header())
            self._append_script_log(
                "Script pane opened. Edit above, Ctrl+Shift+Enter to run. Output below.\n\n"
            )
            self._script_frame.grid(row=1, column=3, columnspan=4, sticky="nsew", padx=(4, 0))
            self._text_script.focus_set()
        else:
            self._script_frame.grid_remove()
            self._restore_right_side_after_script()
            self._text.focus_set()
        self.after_idle(self._refresh_visible)
        return "break"

    def _run_channeler_script(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Execute script text; log full traceback on error. Ctrl+Shift+Enter."""
        if not self._script_pane_visible:
            return None
        if not self._data:
            self._append_script_log("ERROR: No ROM loaded.\n")
            return "break"
        source = self._text_script.get("1.0", tk.END)
        self._append_script_log("\n" + format_run_header())

        def log_fn(msg: str) -> None:
            self._append_script_log(msg)
            self.update_idletasks()

        run_user_script(source, self, log_fn)
        self.after_idle(self._refresh_visible)
        return "break"

    def _toggle_c_inject_edit_mode(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Toggle editable Pseudo-C for devkitARM C injection. Bound to Ctrl+Shift+4."""
        if not self._pseudo_c_pane_visible:
            self._pseudo_c_pane_visible = True
            self._pseudo_c_frame.grid(row=1, column=4, sticky="nsew", padx=(4, 0))
            self.after_idle(self._refresh_visible)
        self._c_inject_mode = not self._c_inject_mode
        if self._c_inject_mode:
            self._hide_asm_and_anchor_for_c_inject()
            self._pseudo_c_frame.configure(text=" Pseudo-C (C edit) ")
            self._text_pseudo_c.configure(state=tk.NORMAL)
            self._show_c_inject_patches_pane()
            self._text_pseudo_c.focus_set()
        else:
            self._pseudo_c_frame.configure(text=" Pseudo-C ")
            self._hide_c_inject_patches_pane()
            self._refresh_pseudo_c_selection()
        self.after_idle(self._refresh_visible)
        return "break"

    def _parse_c_inject_repointall_scan_limit(self) -> Tuple[Optional[Tuple[int, int]], Optional[str]]:
        """Half-open ``[lo, hi)`` file offsets for ``### repointall`` only; ``None`` = scan entire ROM."""
        fs = (self._c_inject_rom_window_from_var.get() or "").strip()
        ts = (self._c_inject_rom_window_to_var.get() or "").strip()
        if not fs and not ts:
            return None, None
        lo, hi_ex, err = parse_ff_gap_search_window_strings(self._data, fs, ts)
        if err:
            return None, err
        if lo is None or hi_ex is None:
            return None, "Repoint-all scan: enter both from and through, or leave both empty."
        return (lo, hi_ex), None

    def _c_inject_search_ff_gap_to_inject_offset(self) -> None:
        """Find ``0xFF`` padding in an optional window and set **Inject @** (same rules as Struct FF gap)."""
        if not self._data:
            messagebox.showerror("FF gap", "No ROM loaded.")
            return
        m = re.match(r"(\d+)\s*bytes?\b", self._c_inject_size_var.get() or "", re.I)
        need = int(m.group(1)) if m else 256
        fs = (self._c_inject_rom_window_from_var.get() or "").strip()
        ts = (self._c_inject_rom_window_to_var.get() or "").strip()
        w_lo, w_hi_ex, err = parse_ff_gap_search_window_strings(self._data, fs, ts)
        if err:
            messagebox.showerror("FF gap", err)
            return
        excl = self._c_inject_region
        if excl is None:
            excl_lo, excl_hi = 0, 0
        else:
            excl_lo, excl_hi = excl
        gap = find_disjoint_ff_gap_start(
            self._data,
            need,
            excl_lo,
            excl_hi,
            window_lo=w_lo,
            window_hi=w_hi_ex,
        )
        if gap is None:
            messagebox.showwarning(
                "FF gap",
                f"No contiguous 0xFF region of {need} bytes found in the search window.",
            )
            return
        self._c_inject_offset_var.set(f"0x{gap:X}")
        messagebox.showinfo(
            "FF gap",
            f"Inject @ set to file offset 0x{gap:X} (GBA 0x{GBA_ROM_BASE + gap:08X}).",
        )

    def _effective_inject_skip_region(self) -> Optional[Tuple[int, int]]:
        """Skip region for repoint-all scan (insert blob). Uses last compile span or Inject @ + compiled size."""
        if self._c_inject_region is not None:
            return self._c_inject_region
        off_s = (self._c_inject_offset_var.get() or "").strip()
        if not off_s:
            return None
        fo, _e = self.resolve_file_offset_or_named_anchor(off_s)
        if fo is None:
            return None
        m = re.match(r"(\d+)\s*bytes?\b", self._c_inject_size_var.get() or "", re.I)
        if m:
            return (fo, fo + int(m.group(1)))
        return (fo, fo + 0x1000)

    def _resolve_c_inject_target_file_off(self, sym: str, inject_fo: int) -> Tuple[Optional[int], str]:
        """Map ``channeler_inject``, last-link ELF symbols (nm), or ``pokefirered.sym`` name to ROM file offset (even)."""
        s = sym.strip()
        if not s:
            return None, "empty symbol"
        if s.lower() in ("channeler_inject", "inject"):
            return inject_fo & ~1, ""
        fo_elf = self._c_inject_elf_symbols.get(s)
        if fo_elf is not None:
            return fo_elf & ~1, ""
        addr = self.get_pokefirered_sym_name_to_addr().get(s)
        if addr is None:
            return None, f"{sym!r} not in pokefirered.sym"
        if not (GBA_ROM_BASE <= addr <= GBA_ROM_MAX):
            return None, f"{sym} is not a ROM symbol"
        return (addr - GBA_ROM_BASE) & ~1, ""

    def _apply_c_inject_rom_patches_cmd(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Apply hooks/repoints from the ``###`` document. Bound to Ctrl+Shift+6."""
        if not self._pseudo_c_pane_visible or not self._c_inject_mode:
            messagebox.showinfo("ROM patches", "Enable C inject edit mode (Ctrl+Shift+4) first.")
            return "break"
        if not self._data:
            messagebox.showerror("ROM patches", "No ROM loaded.")
            return "break"
        ok, msg = self._apply_c_inject_rom_patches()
        if ok:
            messagebox.showinfo("ROM patches", msg)
        else:
            messagebox.showerror("ROM patches", msg)
        return "break"

    def _apply_c_inject_rom_patches(self) -> Tuple[bool, str]:
        """Parse ``###`` sections and patch ``self._data``. Returns (ok, message)."""
        if not self._data:
            return False, "No ROM."
        off_s = (self._c_inject_offset_var.get() or "").strip()
        if not off_s:
            return False, "Set Inject @ for hook destination / symbol resolution."
        inject_fo, err = self.resolve_file_offset_or_named_anchor(off_s)
        if inject_fo is None:
            return False, f"Inject @: {err or 'invalid'}"
        sections = parse_c_inject_patches_sections(self._text_c_inject_patches.get("1.0", tk.END))
        nlines = sum(len(sections[k]) for k in sections)
        if nlines == 0:
            return True, "(no ### lines to apply)"
        skip = self._effective_inject_skip_region()
        log: List[str] = []

        for raw in sections["hooks"]:
            parts = raw.split()
            if len(parts) < 3:
                log.append(
                    f"hooks: skip (need 3 fields: function_name hook_location register): {raw!r}"
                )
                continue
            sym_tok, addr_tok, reg_tok = parts[0], parts[1], parts[2]
            dest_fo, er = self._resolve_c_inject_target_file_off(sym_tok, inject_fo)
            if dest_fo is None:
                return False, f"hooks: {sym_tok}: {er}"
            hfo, e = parse_rom_file_offset(addr_tok)
            if hfo is None:
                return False, f"hooks: bad address {addr_tok!r}: {e}"
            try:
                reg = int(reg_tok, 0)
            except ValueError:
                return False, f"hooks: bad register {reg_tok!r}"
            if not (0 <= reg <= 7):
                return False, f"hooks: register must be 0–7, got {reg}"
            hook_at = hfo
            if hook_at & 1:
                hook_at -= 1
            ins_len = 10 if (hook_at % 4) else 8
            if hook_at + ins_len > len(self._data):
                return False, f"hooks: hook at 0x{hook_at:X} needs {ins_len} bytes past ROM end."
            _gba_thumb_hook_write(self._data, hfo, dest_fo, reg)
            log.append(
                f"hooks: 0x{GBA_ROM_BASE + hfo:08X} → {sym_tok} (r{reg}), {ins_len} bytes"
            )

        for raw in sections["repoints"]:
            parts = raw.split()
            if len(parts) < 2:
                log.append(f"repoints: skip: {raw!r}")
                continue
            sym, addr_tok = parts[0], parts[1]
            tfo, er = self._resolve_c_inject_target_file_off(sym, inject_fo)
            if tfo is None:
                return False, f"repoints: {er}"
            wfo, e2 = parse_rom_file_offset(addr_tok)
            if wfo is None:
                return False, f"repoints: bad word address {addr_tok!r}: {e2}"
            if wfo + 4 > len(self._data):
                return False, f"repoints: write past ROM at 0x{wfo:X}"
            _gba_repoint_word_write(self._data, tfo, wfo, 0)
            log.append(f"repoints: *0x{GBA_ROM_BASE + wfo:08X} = ptr to {sym} (no +1)")

        for raw in sections["routinepointers"]:
            parts = raw.split()
            if len(parts) < 2:
                log.append(f"routinepointers: skip: {raw!r}")
                continue
            sym, addr_tok = parts[0], parts[1]
            tfo, er = self._resolve_c_inject_target_file_off(sym, inject_fo)
            if tfo is None:
                return False, f"routinepointers: {er}"
            wfo, e2 = parse_rom_file_offset(addr_tok)
            if wfo is None:
                return False, f"routinepointers: bad word address {addr_tok!r}: {e2}"
            if wfo + 4 > len(self._data):
                return False, f"routinepointers: write past ROM at 0x{wfo:X}"
            _gba_repoint_word_write(self._data, tfo, wfo, 1)
            log.append(f"routinepointers: *0x{GBA_ROM_BASE + wfo:08X} = Thumb ptr to {sym} (+1)")

        scan_limit: Optional[Tuple[int, int]] = None
        if sections["repointall"]:
            scan_limit, scan_err = self._parse_c_inject_repointall_scan_limit()
            if scan_err:
                return False, scan_err

        for raw in sections["repointall"]:
            parts = raw.split()
            if len(parts) < 2:
                log.append(f"repointall: skip: {raw!r}")
                continue
            sym, sample_tok = parts[0], parts[1]
            tfo, er = self._resolve_c_inject_target_file_off(sym, inject_fo)
            if tfo is None:
                return False, f"repointall: {er}"
            sfo, e2 = parse_rom_file_offset(sample_tok)
            if sfo is None:
                return False, f"repointall: bad sample {sample_tok!r}: {e2}"
            if sfo + 4 > len(self._data):
                return False, f"repointall: sample past ROM"
            n = _gba_real_repoint_all_scan(self._data, sfo, tfo, 0, skip, scan_limit)
            win_note = ""
            if scan_limit:
                win_note = f", scan 0x{scan_limit[0]:X}..0x{scan_limit[1]:X}"
            log.append(
                f"repointall: {n} word(s) → ptr to {sym} (no +1), sample 0x{GBA_ROM_BASE + sfo:08X}{win_note}"
            )

        self._modified = True
        self._ldr_pc_targets_valid = False
        self._schedule_xref_rebuild()
        self.after_idle(self._refresh_visible)
        return True, "\n".join(log) if log else "OK"

    def _prepare_c_inject_source(self, user_text: str) -> str:
        """Build one translation unit with ``channeler_inject`` unless the user supplied a full file."""
        t = user_text.strip()
        if not t:
            return ""
        first_stmt = ""
        for line in t.splitlines():
            s = line.strip()
            if s:
                first_stmt = s
                break
        if first_stmt.startswith("#"):
            return t
        if re.search(r"\bchanneler_inject\s*\(", t):
            return t
        return (
            '#include "global.h"\n\n'
            "void channeler_inject(void) {\n"
            + "\n".join("    " + line if line.strip() else line for line in t.splitlines())
            + "\n}\n"
        )

    def _compile_c_inject(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Compile C with devkitARM and write raw ``.text`` bytes at Inject @. Bound to Ctrl+Shift+5."""
        if not self._pseudo_c_pane_visible:
            return "break"
        if not self._c_inject_mode:
            messagebox.showinfo(
                "C inject",
                "Enable C edit mode first (Ctrl+Shift+4), then edit C and set Inject @.",
            )
            return "break"
        if not self._data:
            messagebox.showerror("C inject", "No ROM loaded.")
            return "break"
        src_raw = self._text_pseudo_c.get("1.0", tk.END)
        c_src = self._prepare_c_inject_source(src_raw)
        if not c_src.strip():
            messagebox.showerror("C inject", "Pseudo-C source is empty.")
            return "break"
        off_str = (self._c_inject_offset_var.get() or "").strip()
        if not off_str:
            messagebox.showerror(
                "C inject",
                "Set Inject @ (file offset, 0x08… GBA address, or NamedAnchor name).",
            )
            return "break"
        file_off, err = self.resolve_file_offset_or_named_anchor(off_str)
        if file_off is None:
            messagebox.showerror("C inject", f"Bad inject offset: {err or off_str!r}")
            return "break"
        if file_off < 0 or file_off >= len(self._data):
            messagebox.showerror("C inject", "Inject offset is outside the ROM.")
            return "break"
        inc = _pokefirered_include_dir_default()
        if not os.path.isdir(inc):
            messagebox.showerror(
                "C inject",
                "Include directory not found:\n"
                f"{inc}\n\n"
                "Place pret pokefirered headers under:\n"
                "  editors/firered/pokefirered/include\n"
                "(at least global.h).",
            )
            return "break"
        gcc = devkit_tool("arm-none-eabi-gcc")
        objcopy = devkit_tool("arm-none-eabi-objcopy")
        nm = devkit_tool("arm-none-eabi-nm")
        nm_tool = nm if os.path.isfile(nm) else shutil.which("arm-none-eabi-nm")
        if not nm_tool:
            messagebox.showerror(
                "C inject",
                "arm-none-eabi-nm was not found (needed to resolve ROM symbols).\n"
                "Install devkitARM and ensure arm-none-eabi-nm is on PATH.",
            )
            return "break"
        link_addr = GBA_ROM_BASE + (file_off & ~1)
        sym_by_name = self.get_pokefirered_sym_name_to_addr()
        rom_data_names = load_channeler_c_inject_rom_data_symbol_names()
        with tempfile.TemporaryDirectory(prefix="ch_c_inj_") as tmp:
            c_path = os.path.join(tmp, "inject.c")
            o_path = os.path.join(tmp, "inject.o")
            elf_path = os.path.join(tmp, "inject.elf")
            bin_path = os.path.join(tmp, "inject.bin")
            with open(c_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(c_src)
            # Headers only declare ROM APIs; the linker needs absolute symbols (pokefirered.sym).
            # Thumb BL reaches only ±4 MiB: inject sites in expanded ROM (e.g. 0x0871…) cannot reach
            # vanilla code at 0x0800… with a direct BL. -mlong-calls emits load+bx (or veneer) so calls
            # resolve to real PutWindowTilemap-style addresses instead of nearby glue (sub_871a25x).
            compile_flags = [
                "-mcpu=arm7tdmi",
                "-mtune=arm7tdmi",
                "-mthumb",
                "-mthumb-interwork",
                "-mlong-calls",
                "-O2",
                "-ffreestanding",
                "-fno-builtin",
                "-nostdlib",
                "-fno-asynchronous-unwind-tables",
                "-I",
                inc,
                "-c",
                "-o",
                o_path,
                c_path,
            ]
            try:
                r0 = subprocess.run([gcc] + compile_flags, capture_output=True, text=True)
            except FileNotFoundError:
                messagebox.showerror(
                    "C inject",
                    "arm-none-eabi-gcc was not found.\n"
                    "Install devkitARM (devkitPro) and ensure its bin directory is on PATH,\n"
                    "or use the default C:\\devkitPro\\devkitARM\\bin on Windows.",
                )
                return "break"
            if r0.returncode != 0 or not os.path.isfile(o_path):
                err = (r0.stdout + "\n" + r0.stderr).strip()
                messagebox.showerror("C inject", f"Compile failed:\n{err[:4000]}")
                return "break"
            undef, nm_err = collect_nm_undefined_symbols(nm_tool, o_path)
            if nm_err:
                messagebox.showerror("C inject", f"arm-none-eabi-nm failed:\n{nm_err[:1200]}")
                return "break"
            missing: List[str] = []
            link_cmd: List[str] = [
                gcc,
                "-o",
                elf_path,
                o_path,
                "-nostdlib",
                "-nostartfiles",
                f"-Wl,-Ttext=0x{link_addr:08X}",
                "-Wl,-e,channeler_inject",
            ]
            for name in undef:
                addr = sym_by_name.get(name)
                if addr is None:
                    missing.append(name)
                    continue
                val = link_defsym_value_for_rom_sym(addr, name, rom_data_names)
                link_cmd.append(f"-Wl,--defsym,{name}=0x{val:X}")
            if missing:
                sample = ", ".join(missing[:12])
                more = f" (+{len(missing) - 12} more)" if len(missing) > 12 else ""
                messagebox.showerror(
                    "C inject",
                    "Undefined symbols not found in pokefirered.sym (or nm failed):\n"
                    f"{sample}{more}\n\n"
                    "Runtime/compiler helpers (e.g. __aeabi_*) need libgcc or different flags.\n"
                    "ROM data labels in ROM (0x08…) need an even address: add the symbol name to\n"
                    "rom.txt in the repo root (one per line).",
                )
                return "break"
            try:
                r = subprocess.run(link_cmd, capture_output=True, text=True)
            except FileNotFoundError:
                messagebox.showerror("C inject", "arm-none-eabi-gcc was not found for linking.")
                return "break"
            if r.returncode != 0 or not os.path.isfile(elf_path):
                err = (r.stdout + "\n" + r.stderr).strip()
                messagebox.showerror("C inject", f"Link failed:\n{err[:4000]}")
                return "break"
            try:
                r_nm_elf = subprocess.run([nm_tool, elf_path], capture_output=True, text=True)
            except FileNotFoundError:
                r_nm_elf = None
            if r_nm_elf and r_nm_elf.returncode == 0:
                self._c_inject_elf_symbols = parse_nm_elf_rom_text_symbols_to_file_offsets(
                    r_nm_elf.stdout
                )
            else:
                self._c_inject_elf_symbols = {}
            try:
                r2 = subprocess.run(
                    [objcopy, "-O", "binary", "-j", ".text", elf_path, bin_path],
                    capture_output=True,
                    text=True,
                )
            except FileNotFoundError:
                messagebox.showerror(
                    "C inject",
                    "arm-none-eabi-objcopy was not found (devkitARM bin directory).",
                )
                return "break"
            if r2.returncode != 0 or not os.path.isfile(bin_path):
                err = (r2.stdout + "\n" + r2.stderr).strip()
                messagebox.showerror("C inject", f"objcopy failed:\n{err[:2000]}")
                return "break"
            with open(bin_path, "rb") as f:
                blob = f.read()
        if not blob:
            messagebox.showerror("C inject", "Compiled binary is empty.")
            return "break"
        if file_off + len(blob) > len(self._data):
            messagebox.showerror(
                "C inject",
                f"Binary ({len(blob)} bytes) does not fit in ROM from 0x{file_off:X}.",
            )
            return "break"
        self._c_inject_size_var.set(f"{len(blob)} bytes")
        for i, b in enumerate(blob):
            self._data[file_off + i] = b
        self._c_inject_region = (file_off, file_off + len(blob))
        self._modified = True
        self._ldr_pc_targets_valid = False
        self._schedule_xref_rebuild()
        self._refresh_visible()
        if self._asm_pane_visible:
            self._refresh_asm_selection()
        patch_ok, patch_msg = self._apply_c_inject_rom_patches()
        base_msg = (
            f"Wrote {len(blob)} bytes at file offset 0x{file_off:08X} "
            f"(GBA 0x{GBA_ROM_BASE + file_off:08X})."
        )
        if patch_ok and patch_msg and not patch_msg.startswith("("):
            base_msg += "\n\nROM patches:\n" + patch_msg
        elif not patch_ok:
            messagebox.showwarning("C inject", base_msg + "\n\nROM patches failed:\n" + patch_msg)
            return "break"
        messagebox.showinfo("C inject", base_msg)
        return "break"

    def _toggle_anchor_browser_pane(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Toggle FunctionAnchor browser pane visibility. Bound to Ctrl+M."""
        self._goto_entry.selection_clear()
        self._text.focus_set()
        self._anchor_browser_pane_visible = not self._anchor_browser_pane_visible
        if self._anchor_browser_pane_visible:
            if not self._anchor_tools_pane_layout:
                self._tools_frame.grid_remove()
                self._anchor_tools_pane.add(self._anchor_frame, weight=1)
                self._anchor_tools_pane.add(self._tools_frame, weight=1)
                self._anchor_tools_pane.grid(row=1, column=5, columnspan=2, sticky="nsew", padx=(4, 0))
                self._anchor_tools_pane_layout = True

                def _apply_anchor_sash() -> None:
                    try:
                        self._anchor_tools_pane.sashpos(0, 320)
                    except tk.TclError:
                        pass

                self.after_idle(_apply_anchor_sash)
            else:
                self._anchor_tools_pane.grid(row=1, column=5, columnspan=2, sticky="nsew", padx=(4, 0))
            self._anchor_browser_path = []
            self._refresh_anchor_browser()
        else:
            if self._anchor_tools_pane_layout:
                self._anchor_tools_pane.grid_remove()
                try:
                    self._anchor_tools_pane.remove(self._anchor_frame)
                except tk.TclError:
                    pass
                try:
                    self._anchor_tools_pane.remove(self._tools_frame)
                except tk.TclError:
                    pass
                self._tools_frame.grid(row=1, column=6, sticky="nsew", padx=(4, 0))
                self._anchor_tools_pane_layout = False
            else:
                self._anchor_frame.grid_remove()
        self.after_idle(self._refresh_visible)
        return "break"

    def _on_anchor_sym_filter_keyrelease(self, event: Optional[tk.Event] = None) -> None:
        """Refresh symbol list while typing the filter (``pokefirered.sym`` browser only)."""
        if self._anchor_browser_path == [ANCHOR_SYM_BROWSER_SEGMENT]:
            self._refresh_anchor_browser()

    def _ensure_sym_browser_rom_list(self) -> None:
        """Build sorted (name, file_off) list for ROM symbols from ``pokefirered.sym`` (cached)."""
        if self._sym_browser_rom_list is not None:
            return
        if not getattr(self, "_rom_use_pokefirered_sym", False):
            self._sym_browser_rom_list = []
            return
        sym = self.get_pokefirered_sym_name_to_addr()
        lst: List[Tuple[str, int]] = []
        for name, addr in sym.items():
            if GBA_ROM_BASE <= addr <= GBA_ROM_MAX:
                lst.append((name, addr - GBA_ROM_BASE))
        lst.sort(key=lambda t: t[0].lower())
        self._sym_browser_rom_list = lst

    def _get_pokefirered_sym_browser_items(self) -> List[Tuple[str, Optional[int]]]:
        """List ROM symbols from ``pokefirered.sym`` with optional substring filter."""
        if not getattr(self, "_rom_use_pokefirered_sym", False):
            return [("(pokefirered.sym only when ROM game code is BPRE — FireRed US)", -2)]
        self._ensure_sym_browser_rom_list()
        filt = (self._anchor_sym_filter_var.get() or "").strip().lower()
        if not os.path.isfile(_pokefirered_sym_default_path()):
            return [("(pokefirered.sym not found)", -2)]
        if not self._sym_browser_rom_list:
            return [("(no ROM symbols in pokefirered.sym)", -2)]
        out: List[Tuple[str, Optional[int]]] = []
        for name, fo in self._sym_browser_rom_list:
            if filt and filt not in name.lower():
                continue
            out.append((name, fo))
        if not out:
            return [("(no ROM symbols match filter)", -2)]
        return out

    def _is_function_anchor_name(self, name: str) -> bool:
        """True if ``name`` matches a ``[[FunctionAnchors]]`` entry (exact ``Name``)."""
        want = name.strip()
        for a in self._toml_data.get("FunctionAnchors", []) or []:
            if str(a.get("Name", "")).strip() == want:
                return True
        return False

    def _get_anchor_browser_items(self) -> List[Tuple[str, Optional[int]]]:
        """Return [(display_text, address_or_none), ...]. address is set for leaves (full anchor names).
        Includes both FunctionAnchors and NamedAnchors."""
        path = self._anchor_browser_path
        if path == [ANCHOR_SYM_BROWSER_SEGMENT]:
            return self._get_pokefirered_sym_browser_items()
        funcs = self._toml_data.get("FunctionAnchors", [])
        named = self._toml_data.get("NamedAnchors", [])
        anchors = list(funcs) + [a for a in named if a.get("Address") is not None]
        prefix = ".".join(path) + "." if path else ""
        branches: Set[str] = set()
        leaves: List[Tuple[str, int]] = []
        for a in anchors:
            name = (a.get("Name") or "").strip()
            if not name:
                continue
            parts = name.split(".")
            if path:
                if not all(i < len(parts) and parts[i] == p for i, p in enumerate(path)):
                    continue
                if len(parts) == len(path) + 1:
                    addr = a.get("Address")
                    if addr is not None:
                        try:
                            val = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                            if val < GBA_ROM_BASE:
                                val += GBA_ROM_BASE
                            leaves.append((name, val - GBA_ROM_BASE))
                        except (ValueError, TypeError):
                            leaves.append((name, 0))
                else:
                    branch = ".".join(parts[: len(path) + 1])
                    branches.add(branch)
            else:
                if len(parts) == 1:
                    addr = a.get("Address")
                    if addr is not None:
                        try:
                            val = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                            if val < GBA_ROM_BASE:
                                val += GBA_ROM_BASE
                            leaves.append((name, val - GBA_ROM_BASE))
                        except (ValueError, TypeError):
                            leaves.append((name, 0))
                else:
                    branches.add(parts[0])
        if not path and getattr(self, "_rom_use_pokefirered_sym", False):
            branches.add(ANCHOR_SYM_BROWSER_LABEL)
        result: List[Tuple[str, Optional[int]]] = []
        for b in sorted(branches):
            result.append((b, None))
        for name, off in sorted(leaves, key=lambda x: x[0]):
            result.append((name, off))
        return result

    def _refresh_anchor_browser(self) -> None:
        """Populate the anchor browser Listbox from current path."""
        if self._anchor_browser_path == [ANCHOR_SYM_BROWSER_SEGMENT]:
            self._anchor_sym_filter_frame.grid()
            self.after_idle(lambda: self._anchor_sym_filter_entry.focus_set())
        else:
            self._anchor_sym_filter_frame.grid_remove()
        self._listbox_anchor.delete(0, tk.END)
        items: List[Tuple[str, Optional[int]]] = []
        if self._anchor_browser_path:
            items.append(("\u2190 Back", -1))
        for display, addr in self._get_anchor_browser_items():
            items.append((display, addr))
        for display, _ in items:
            self._listbox_anchor.insert(tk.END, display)
        self._listbox_anchor._anchor_items = items

    def _on_anchor_browser_double_click(self, event: tk.Event) -> None:
        """Handle anchors browser activation on double-click only."""
        sel = self._listbox_anchor.curselection()
        if not sel:
            return
        idx = int(sel[0])
        items = getattr(self._listbox_anchor, "_anchor_items", None)
        if not items or idx >= len(items):
            return
        display, address = items[idx]
        if address == -1:
            self._anchor_browser_path = self._anchor_browser_path[:-1]
            if not self._anchor_browser_path:
                self._anchor_sym_filter_var.set("")
            self._refresh_anchor_browser()
            return
        if address == -2:
            return
        if address is None:
            if display == ANCHOR_SYM_BROWSER_LABEL:
                self._anchor_browser_path = self._anchor_browser_path + [ANCHOR_SYM_BROWSER_SEGMENT]
            else:
                self._anchor_browser_path = display.split(".")
            self._refresh_anchor_browser()
            return
        self._do_goto(address)
        if self._is_function_anchor_name(display):
            ext = self._find_function_extent(address)
            if ext is not None:
                fs, fe = ext
                self._selection_start = fs
                self._selection_end = fe
                self._cursor_byte_offset = fs
            elif self._data and 0 <= int(address) < len(self._data):
                fe = min(int(address) + 0x100, len(self._data)) - 1
                self._selection_start = int(address)
                self._selection_end = fe
                self._cursor_byte_offset = int(address)
            if not self._asm_pane_visible:
                self._asm_frame.grid(row=1, column=3, sticky="nsew", padx=(4, 0))
                self._asm_pane_visible = True
            self._refresh_asm_selection()
            if self._ensure_cursor_visible():
                self._update_scrollbar()
            self._update_cursor_display()
            self.after_idle(self._refresh_visible)
        cb = self._on_pointer_to_named_anchor_cb
        if not cb:
            return
        anchor_info = self._named_anchor_info_for_tools(display)
        if anchor_info is None and address is not None and int(address) >= 0:
            anchor_info = self._find_named_anchor_at_offset(int(address), exact=False)
        if anchor_info:
            self.after(10, lambda ai=anchor_info: cb(ai))

    def _parse_pcs_format(self, fmt: str) -> Optional[Tuple[str, int, Any, str]]:
        """Parse PCS/ASCII string table formats. Returns ``(field, width, count_or_ref, encoding)``."""
        if not fmt:
            return None
        s = str(fmt).strip()
        m = re.search(r'\^?\[(\w+)""(\d+)\](.+)', s)
        if m:
            field, width_str, length_part = m.group(1), m.group(2), m.group(3).strip()
            width = int(width_str)
            if length_part.isdigit():
                return (field, width, int(length_part), "pcs")
            return (field, width, length_part, "pcs")
        m = re.search(r"\^?\[(\w*)''(\d+)\](.+)", s)
        if m:
            field = (m.group(1) or "").strip() or "text"
            width_str, length_part = m.group(2), m.group(3).strip()
            width = int(width_str)
            if length_part.isdigit():
                return (field, width, int(length_part), "ascii")
            return (field, width, length_part, "ascii")
        m = re.match(r"^\^?''(\d+)\s*$", s)
        if m:
            width = int(m.group(1))
            return ("text", width, 1, "ascii")
        # TOML multiline literals use '' for one '; ``''2`` in a file often parses as ``'2`` (one quote lost).
        m = re.match(r"^'(\d+)$", s)
        if m:
            return ("text", int(m.group(1)), 1, "ascii")
        # Collapsed bracket form: ``['2]1`` instead of ``[''2]1``
        m = re.match(r"^\[\'(\d+)\](.+)$", s)
        if m:
            width = int(m.group(1))
            length_part = m.group(2).strip()
            if length_part.isdigit():
                return ("text", width, int(length_part), "ascii")
            return ("text", width, length_part, "ascii")
        return None

    def _resolve_table_length(self, length_ref: Any) -> Optional[int]:
        if isinstance(length_ref, int):
            return length_ref if length_ref >= 0 else None
        if not isinstance(length_ref, str) or not self._data:
            return None
        for mw in self._toml_data.get("MatchedWords", []):
            if str(mw.get("Name", "")).strip() == length_ref.strip():
                addr, ln = mw.get("Address"), mw.get("Length", 1)
                if addr is None:
                    continue
                try:
                    gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                    if gba < GBA_ROM_BASE:
                        gba += GBA_ROM_BASE
                    off = gba - GBA_ROM_BASE
                    if 0 <= off < len(self._data) - ln:
                        val = sum(self._data[off + i] << (i * 8) for i in range(ln))
                        return val
                except (ValueError, TypeError):
                    pass
        return None

    def _get_pcs_table_anchors(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for anchor in self._toml_data.get("NamedAnchors", []):
            fmt = normalize_named_anchor_format(anchor.get("Format", ""))
            parsed = self._parse_pcs_format(fmt)
            if parsed:
                field, width, length, enc = parsed
                count = length if isinstance(length, int) else self._resolve_table_length(length)
                if count is not None and count > 0:
                    result.append({
                        "anchor": anchor, "name": str(anchor.get("Name", "")).strip(),
                        "field": field, "width": width, "count": count,
                        "encoding": enc,
                    })
        result.sort(key=lambda x: str(x["name"]).lower())
        return result

    def set_on_pointer_to_named_anchor(self, cb: Optional[Any]) -> None:
        """Set callback(anchor_info) for NamedAnchor navigation (pointer follow or direct offset match)."""
        self._on_pointer_to_named_anchor_cb = cb

    def _struct_anchor_for_list_count_name(self, list_name: str) -> Optional[Dict[str, Any]]:
        """Return the first struct table whose ``]count`` is driven by this ``[[List]]`` ``Name`` (``entry_label_list``)."""
        want = normalize_named_anchor_lookup_key(list_name)
        if not want:
            return None
        lm = _load_toml_lists(self._toml_data) if getattr(self, "_toml_data", None) else {}
        if want not in lm:
            return None
        for info in self.get_struct_anchors():
            elk = info.get("entry_label_list")
            if not elk:
                continue
            if normalize_named_anchor_lookup_key(str(elk)) == want:
                return dict(info)
        return None

    def _named_anchor_info_for_tools(self, anchor_name: str) -> Optional[Dict[str, Any]]:
        """If ``anchor_name`` is a PCS table or struct NamedAnchor, return info with ``type`` ``pcs`` or ``struct``.

        Also resolves a ``[[List]]`` **Name** when that list is the ``]count`` for a struct table (row index source),
        so Goto can jump to the struct ROM block by typing the list name (e.g. ``cardnumbers``).

        Shape matches :meth:`_find_named_anchor_at_offset` results for use with
        ``set_on_pointer_to_named_anchor`` (e.g. FireRed tools pane).
        """
        want = anchor_name.strip().lower()
        for info in self._get_pcs_table_anchors():
            if str(info["name"]).strip().lower() == want:
                return {**info, "type": "pcs"}
        for info in self.get_struct_anchors():
            if str(info["name"]).strip().lower() == want:
                return {**info, "type": "struct"}
        for info in self.get_graphics_anchors():
            if str(info["name"]).strip().lower() == want:
                return {**info, "type": "graphics"}
        si = self._struct_anchor_for_list_count_name(anchor_name)
        if si is not None:
            return {**si, "type": "struct"}
        return None

    def _find_named_anchor_at_offset(self, file_off: int, exact: bool = False) -> Optional[Dict[str, Any]]:
        """Return anchor info if file_off matches a NamedAnchor (PCS table or struct).
        exact=True: only match if file_off is the exact start.
        exact=False: match if file_off falls within the table's byte range.
        Result includes 'type' key: 'pcs' or 'struct'."""
        for info in self._get_pcs_table_anchors():
            addr = info["anchor"].get("Address")
            if addr is None:
                continue
            try:
                gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                start = gba - GBA_ROM_BASE
                if exact:
                    if start == file_off:
                        info["type"] = "pcs"
                        return info
                else:
                    end = start + info["width"] * info["count"]
                    if start <= file_off < end:
                        info["type"] = "pcs"
                        return info
            except (ValueError, TypeError):
                pass
        for info in self.get_struct_anchors():
            base = info["base_off"]
            total = _struct_anchor_table_span_bytes(bytes(self._data), info)
            if exact:
                if base == file_off:
                    info["type"] = "struct"
                    return info
            else:
                if base <= file_off < base + total:
                    info["type"] = "struct"
                    return info
        for info in self.get_graphics_anchors():
            base = info["base_off"]
            span = int(info.get("rom_span", 1))
            total = max(1, span)
            if exact:
                if base == file_off:
                    gi = dict(info)
                    gi["type"] = "graphics"
                    return gi
            else:
                if base <= file_off < base + total:
                    gi = dict(info)
                    gi["type"] = "graphics"
                    return gi
        return None

    def _select_named_anchor_extent(self, info: Dict[str, Any]) -> None:
        """Select all bytes of a NamedAnchor table/struct and place cursor at the start."""
        t = info.get("type")
        if t == "graphics" or info.get("graphics_entry"):
            start = info["base_off"]
            total_bytes = max(1, int(info.get("rom_span", 1)))
        elif t == "struct" or "struct_size" in info:
            start = info["base_off"]
            total_bytes = _struct_anchor_table_span_bytes(bytes(self._data), info)
        else:
            addr = info["anchor"].get("Address")
            if addr is None:
                return
            try:
                gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                start = gba - GBA_ROM_BASE
            except (ValueError, TypeError):
                return
            total_bytes = info.get("width", 0) * info.get("count", 0)
        end = start + total_bytes - 1
        if end >= len(self._data):
            end = len(self._data) - 1
        self._cursor_byte_offset = start
        self._selection_start = start
        self._selection_end = end
        self._visible_row_start = start // BYTES_PER_ROW
        self._refresh_visible()
        self._update_scrollbar()
        self._update_cursor_display()

    def _on_asm_mode_change(self, event: Optional[tk.Event] = None) -> None:
        sel = self._asm_mode_var.get()
        self._asm_mode = "thumb" if sel == "Thumb" else "arm"
        if self._data:
            self._refresh_asm_selection()

    def _on_encoding_change(self, event: Optional[tk.Event] = None) -> None:
        sel = self._encoding_var.get().upper()
        if sel in ("ASCII", "PCS"):
            self._encoding = "pcs" if sel == "PCS" else "ascii"
            if self._data:
                self._refresh_visible()

    def _on_goto_focus_in(self, event: Optional[tk.Event] = None) -> None:
        if self._data:
            self._goto_var.set(f"{self._cursor_byte_offset:08X}")
            self._goto_entry.select_range(0, tk.END)

    def _on_goto_keypress(self, event: tk.Event) -> Optional[str]:
        """Block characters that cannot appear in hex offsets or NamedAnchor names (e.g. spaces, symbols)."""
        if event.keysym in (
            "BackSpace",
            "Delete",
            "Tab",
            "Return",
            "Escape",
            "Left",
            "Right",
            "Up",
            "Down",
            "Home",
            "End",
            "Prior",
            "Next",
        ):
            return None
        if event.state & 0x4:
            return None  # Ctrl+A/C/V etc. (native entry behavior)
        ch = event.char
        if not ch:
            return None
        if ch not in _GOTO_ALLOWED_CHARS:
            return "break"
        return None

    def _on_goto_paste(self, event: tk.Event) -> Optional[str]:
        """Strip disallowed characters from pasted text (same rules as :meth:`_on_goto_keypress`)."""
        try:
            clip = self.winfo_toplevel().clipboard_get()
        except tk.TclError:
            return None
        if not isinstance(clip, str):
            return None
        filt = "".join(c for c in clip if c in _GOTO_ALLOWED_CHARS)
        if filt == clip:
            return None
        try:
            self._goto_entry.delete(0, tk.END)
            self._goto_entry.insert(0, filt)
        except tk.TclError:
            return None
        self._on_goto_entry_change()
        return "break"

    def _goto_named_anchor_at_offset_with_tools(self, file_off: int, ai: Dict[str, Any]) -> None:
        """Jump hex to ``file_off`` (inside a table) and notify tools with row index for Struct / PCS."""
        self._do_goto(file_off)
        cb = self._on_pointer_to_named_anchor_cb
        if not cb:
            return
        snap = dict(ai)
        t = ai.get("type")
        if t == "struct":
            snap["struct_entry_index"] = _struct_row_index_for_file_offset(bytes(self._data), ai, file_off)
        elif t == "pcs":
            snap["pcs_row_index"] = _pcs_row_index_for_file_offset(ai, file_off)
        self.after(10, lambda s=snap: cb(s))

    def _goto_resolve_and_maybe_open_tool(self, s: str) -> bool:
        """If ``s`` is a NamedAnchor name or a file/GBA offset inside one, select that anchor and notify tools."""
        s = s.strip()
        if not s or not self._data:
            return False
        cb = self._on_pointer_to_named_anchor_cb
        ai = self._named_anchor_info_for_tools(s)
        if ai:
            self._select_named_anchor_extent(ai)
            if cb:
                snap = dict(ai)
                self.after(10, lambda s=snap: cb(s))
            return True
        sym_offset = self._get_function_anchor_offset_by_name(s)
        if sym_offset is not None and 0 <= sym_offset < len(self._data):
            ai2 = self._find_named_anchor_at_offset(sym_offset, exact=False)
            if ai2:
                self._goto_named_anchor_at_offset_with_tools(sym_offset, ai2)
                return True
        ts = s
        if ts.startswith("0x") or ts.startswith("0X"):
            ts = ts[2:]
        if not ts:
            return False
        try:
            val = int(ts, 16)
        except ValueError:
            return False
        if val >= GBA_ROM_BASE and val < GBA_ROM_BASE + len(self._data):
            val = val - GBA_ROM_BASE
        if 0 <= val < len(self._data):
            ai3 = self._find_named_anchor_at_offset(val, exact=False)
            if ai3:
                self._goto_named_anchor_at_offset_with_tools(val, ai3)
                return True
        return False

    def _on_goto_entry_change(self, event: Optional[tk.Event] = None) -> None:
        if not self._data:
            return
        if event and event.keysym in (
            "Control_L", "Control_R", "Shift_L", "Shift_R",
            "Alt_L", "Alt_R", "Caps_Lock", "Num_Lock",
        ):
            return
        s = self._goto_var.get().strip()
        if not s:
            return
        if self._goto_resolve_and_maybe_open_tool(s):
            return
        sym_offset = self._get_function_anchor_offset_by_name(s)
        if sym_offset is not None and 0 <= sym_offset < len(self._data):
            self._do_goto(sym_offset)
            return
        if s.startswith("0x") or s.startswith("0X"):
            s = s[2:]
        if not s:
            return
        try:
            val = int(s, 16)
            if val >= GBA_ROM_BASE and val < GBA_ROM_BASE + len(self._data):
                val = val - GBA_ROM_BASE
            if 0 <= val < len(self._data):
                self._do_goto(val)
        except ValueError:
            pass

    def _do_goto(self, offset: int) -> None:
        """Jump to offset in hex editor. Puts target row at the very top of the view.
        Sets selection anchor so Shift+click extends from this offset."""
        if not self._data or offset < 0 or offset >= len(self._data):
            return
        self._cursor_byte_offset = offset
        self._selection_start = offset
        self._selection_end = offset
        cr = offset // BYTES_PER_ROW
        max_start = max(0, self._total_rows - self._visible_row_count)
        self._visible_row_start = min(cr, max_start)
        self._refresh_visible()
        self._update_scrollbar()
        self._refresh_asm_selection()

    def _byte_to_char(self, b: int) -> str:
        if self._encoding == "pcs":
            return _PCS_BYTE_TO_CHAR.get(b, "·")
        return chr(b) if 32 <= b < 127 else "."

    def _on_ascii_key(self, event: tk.Event) -> Optional[str]:
        """Handle typing in character panel: update byte at cursor, refresh, advance."""
        if event.state & 0x4 and event.keysym.lower() == "a":
            self._select_all(event)
            return "break"
        if not self._data:
            return None
        # Mirror hex pane: arrow/home/etc. move the shared cursor so both panels stay in sync.
        if event.keysym in ("Left", "Right", "Up", "Down"):
            return self._move_cursor(
                {"Left": -1, "Right": 1, "Up": -BYTES_PER_ROW, "Down": BYTES_PER_ROW}[event.keysym]
            )
        if (event.state & 0x4) and event.keysym == "Home":
            return self._on_ctrl_home(event)
        if (event.state & 0x4) and event.keysym == "End":
            return self._on_ctrl_end(event)
        if event.keysym == "Home":
            return self._on_home(event)
        if event.keysym == "End":
            return self._on_end(event)
        if event.keysym == "Prior":
            if self._data:
                self._on_scrollbar_command("scroll", -self._visible_row_count, "units")
            return "break"
        if event.keysym == "Next":
            if self._data:
                self._on_scrollbar_command("scroll", self._visible_row_count, "units")
            return "break"
        idx = self._text_ascii.index("insert")
        off = self._ascii_index_to_offset(idx)
        if off is None:
            return None
        if event.keysym in ("BackSpace", "Delete"):
            self._cursor_byte_offset = off
            if event.keysym == "Delete":
                self._on_delete(event)
            else:
                self._on_backspace(event)
            return "break"
        if event.char and len(event.char) == 1:
            if self._encoding == "pcs":
                byte_val = _PCS_CHAR_TO_BYTE.get(event.char)
                if byte_val is None:
                    byte_val = ord(event.char) % 256
            else:
                byte_val = ord(event.char) % 256
            old_b = self._data[off]
            self._data[off] = byte_val
            if not self._suppress_matched_word_propagate:
                self._propagate_matched_word_byte_change(off, old_b, byte_val)
            self._modified = True
            self._ldr_pc_targets_valid = False
            self._schedule_xref_rebuild()
            self._refresh_visible()
            self._update_scrollbar()
            self._refresh_asm_selection()
            next_off = min(off + 1, len(self._data) - 1)
            next_idx = self._offset_to_ascii_index(next_off) if next_off != off else idx
            if next_idx:
                self._text_ascii.mark_set("insert", next_idx)
                self._text_ascii.see(next_idx)
            return "break"
        return None

    def _offset_to_ascii_index(self, offset: int) -> Optional[str]:
        """Map byte offset to ASCII widget index (for |c0|c1|... format)."""
        if offset < 0 or offset >= len(self._data):
            return None
        fr = offset // BYTES_PER_ROW
        if fr < self._visible_row_start or fr >= self._visible_row_start + self._visible_row_count:
            return None
        dr = fr - self._visible_row_start + 1
        bc = offset % BYTES_PER_ROW
        return f"{dr}.{1 + bc}"

    def _copy_hex_ascii(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Copy selected hex/ASCII bytes to clipboard. Bound to Ctrl+C. Hex pane: hex string; ASCII pane: text."""
        if not self._data:
            return "break"
        if self._selection_start is not None and self._selection_end is not None:
            s = min(self._selection_start, self._selection_end)
            e = max(self._selection_start, self._selection_end) + 1
            data = bytes(self._data[s:e])
        else:
            data = bytes(self._data[self._cursor_byte_offset : self._cursor_byte_offset + 1])
        if not data:
            return "break"
        try:
            focus = self.winfo_toplevel().focus_get()
            if focus == self._text:
                text = " ".join(f"{b:02X}" for b in data)
            else:
                text = "".join(self._byte_to_char(b) for b in data)
            self.clipboard_clear()
            self.clipboard_append(text)
        except tk.TclError:
            pass
        return "break"

    def _parse_paste_hex(self, text: str) -> bytearray:
        """Parse clipboard as hex; only hex digits used, invalid chars skipped."""
        digits = "".join(c for c in text if c in HEX_DIGITS)
        out = bytearray()
        for i in range(0, len(digits) - 1, 2):
            out.append(int(digits[i : i + 2], 16))
        return out

    def _parse_paste_ascii(self, text: str) -> bytearray:
        """Parse clipboard as ASCII; only printable chars (32–126) used, invalid skipped."""
        out = bytearray()
        for c in text:
            if self._encoding == "pcs":
                b = _PCS_CHAR_TO_BYTE.get(c)
                if b is not None:
                    out.append(b)
                elif 32 <= ord(c) <= 126:
                    out.append(ord(c))
            else:
                if 32 <= ord(c) <= 126:
                    out.append(ord(c))
        return out

    def _paste_write(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Paste clipboard over bytes at cursor. Ctrl+V. Hex pane: hex string; ASCII pane: text."""
        if not self._data:
            return "break"
        try:
            raw = self.clipboard_get()
        except tk.TclError:
            return "break"
        focus = self.winfo_toplevel().focus_get()
        data = self._parse_paste_hex(raw) if focus == self._text else self._parse_paste_ascii(raw)
        if not data:
            return "break"
        pos = self._cursor_byte_offset
        end = min(pos + len(data), len(self._data))
        count = end - pos
        self._data[pos:end] = data[:count]
        self._modified = True
        self._ldr_pc_targets_valid = False
        self._schedule_xref_rebuild()
        self._hex_pair_snapshot_byte = None
        self._nibble_pos = 0
        self._cursor_byte_offset = min(pos + count, len(self._data) - 1) if self._data else 0
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
        self._ensure_cursor_visible()
        self._refresh_visible()
        self._update_scrollbar()
        self._refresh_asm_selection()
        return "break"

    def _paste_insert(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Insert clipboard bytes at cursor, shifting existing bytes. Ctrl+B."""
        if not self._data:
            return "break"
        try:
            raw = self.clipboard_get()
        except tk.TclError:
            return "break"
        focus = self.winfo_toplevel().focus_get()
        data = self._parse_paste_hex(raw) if focus == self._text else self._parse_paste_ascii(raw)
        if not data:
            return "break"
        pos = self._cursor_byte_offset
        self._data[pos:pos] = data
        self._modified = True
        self._ldr_pc_targets_valid = False
        self._schedule_xref_rebuild()
        self._hex_pair_snapshot_byte = None
        self._nibble_pos = 0
        self._cursor_byte_offset = min(pos + len(data), len(self._data) - 1)
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
        self._ensure_cursor_visible()
        self._refresh_visible()
        self._update_scrollbar()
        self._refresh_asm_selection()
        return "break"

    def _prevent_unwanted(self, event: tk.Event) -> Optional[str]:
        if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End", "Prior", "Next"):
            return None
        if event.state & 0x4 and event.keysym.lower() in (
            "b",
            "c",
            "f",
            "g",
            "h",
            "i",
            "m",
            "p",
            "r",
            "v",
            "x",
            "s",
        ):
            return None
        if event.char and event.char in HEX_DIGITS:
            return "break"
        if event.keysym in ("Delete", "Insert", "BackSpace"):
            return "break"
        if event.char or event.keysym in ("Return", "Tab", "space"):
            if event.state & 0x4:
                return None
            return "break"
        return None

    # ── Find / Replace ───────────────────────────────────────────────

    def _parse_find_hex_literal(self, text: str) -> Optional[bytearray]:
        """Parse hex to bytes only (no ``xx`` wildcards). Used for replace fill pattern."""
        digits = "".join(c for c in text if c in HEX_DIGITS)
        if len(digits) < 2:
            return None
        out = bytearray()
        for i in range(0, len(digits) - 1, 2):
            out.append(int(digits[i : i + 2], 16))
        return out if out else None

    def _parse_find_hex(self, text: str) -> Optional[List[Optional[int]]]:
        """Parse find string as hex.

        **Wildcard:** whitespace-separated token ``xx`` or ``XX`` matches any byte.

        **Multi-token:** each token is ``xx``/``XX`` or an even-length hex run (e.g. ``00 11`` or ``00 DEAD``).

        **Single token, no wildcard:** legacy parse — all hex digits are paired (``DEADBEEF``), spaces ignored.

        Result is ``List[Optional[int]]`` where ``None`` = wildcard byte.
        """
        t = (text or "").strip()
        if not t:
            return None
        tokens = t.split()
        has_wild = any(len(tok) == 2 and tok.lower() == "xx" for tok in tokens)

        def push_hex_token(tok: str, buf: List[Optional[int]]) -> bool:
            if len(tok) < 2 or len(tok) % 2 != 0:
                return False
            if not all(c in HEX_DIGITS for c in tok):
                return False
            for i in range(0, len(tok), 2):
                buf.append(int(tok[i : i + 2], 16))
            return True

        if has_wild or len(tokens) > 1:
            out: List[Optional[int]] = []
            for tok in tokens:
                if len(tok) == 2 and tok.lower() == "xx":
                    out.append(None)
                elif push_hex_token(tok, out):
                    pass
                else:
                    return None
            return out if out else None

        digits = "".join(c for c in t if c in HEX_DIGITS)
        if len(digits) < 2:
            return None
        out2: List[Optional[int]] = []
        for i in range(0, len(digits) - 1, 2):
            out2.append(int(digits[i : i + 2], 16))
        return out2 if out2 else None

    def _parse_find_ascii(self, text: str) -> Optional[bytearray]:
        """Parse find string as ASCII/PCS text."""
        if not text:
            return None
        out = bytearray()
        for c in text:
            if self._encoding == "pcs":
                b = _PCS_CHAR_TO_BYTE.get(c)
                if b is not None:
                    out.append(b)
                elif 32 <= ord(c) <= 126:
                    out.append(ord(c))
            else:
                if 32 <= ord(c) <= 126:
                    out.append(ord(c))
        return out if out else None

    def _pattern_match_at(self, offset: int, pattern: List[Optional[int]]) -> bool:
        """True if ``pattern`` matches ``_data`` at ``offset`` (``None`` = any byte)."""
        if not self._data or offset < 0:
            return False
        n = len(pattern)
        if offset + n > len(self._data):
            return False
        for i, p in enumerate(pattern):
            if p is not None and self._data[offset + i] != p:
                return False
        return True

    def _hex_find_pattern_to_bytes(self, pattern: List[Optional[int]]) -> Optional[bytes]:
        """If ``pattern`` has no wildcards, return fixed bytes; else ``None``."""
        if any(p is None for p in pattern):
            return None
        return bytes(pattern)

    def _find_next_hex_pattern(self, pattern: List[Optional[int]], forward: bool) -> Optional[int]:
        """Find with ``xx``/``XX`` wildcards; same wrap rules as :meth:`_find_next`."""
        if not self._data or not pattern:
            return None
        data = self._data
        n = len(pattern)
        start = self._cursor_byte_offset
        last_start = len(data) - n
        if last_start < 0:
            return None
        if forward:
            for i in range(start + 1, last_start + 1):
                if self._pattern_match_at(i, pattern):
                    return i
            for i in range(0, min(start, last_start + 1)):
                if self._pattern_match_at(i, pattern):
                    return i
            return None
        for i in range(min(start - 1, last_start), -1, -1):
            if self._pattern_match_at(i, pattern):
                return i
        for i in range(last_start, start, -1):
            if self._pattern_match_at(i, pattern):
                return i
        return None

    def _find_bytes_or_pattern_from(self, pos: int, needle: Union[bytes, bytearray, List[Optional[int]]]) -> int:
        """First match at index ``>= pos``, or -1. Fixed patterns use fast ``find``."""
        if not self._data or not needle:
            return -1
        if not isinstance(needle, list):
            i = self._data.find(needle, pos)
            return i if i >= 0 else -1
        b = self._hex_find_pattern_to_bytes(needle)
        if b is not None:
            i = self._data.find(b, pos)
            return i if i >= 0 else -1
        n = len(needle)
        for i in range(pos, len(self._data) - n + 1):
            if self._pattern_match_at(i, needle):
                return i
        return -1

    def _find_next(self, needle: Union[bytes, bytearray, List[Optional[int]]], forward: bool) -> Optional[int]:
        """Find needle in _data. Forward: from cursor+1; backward: from cursor-1. Returns offset or None.

        ``needle`` may be a hex pattern list with ``None`` entries (wildcard bytes from ``xx``/``XX`` tokens).
        """
        if not self._data or not needle:
            return None
        if isinstance(needle, list):
            b = self._hex_find_pattern_to_bytes(needle)
            if b is not None:
                needle = b
            else:
                return self._find_next_hex_pattern(needle, forward)
        data = self._data
        needle = bytes(needle) if isinstance(needle, bytearray) else needle
        start = self._cursor_byte_offset
        if forward:
            idx = data.find(needle, start + 1)
            if idx < 0:
                idx = data.find(needle, 0, start)  # wrap from start
            return idx if idx >= 0 else None
        else:
            idx = data.rfind(needle, 0, start)
            if idx < 0:
                idx = data.rfind(needle, start + 1, len(data))  # wrap from end
            return idx if idx >= 0 else None

    def _select_at_offset(self, offset: int, length: int) -> None:
        """Select bytes at offset, scroll into view, refresh."""
        self._cursor_byte_offset = offset
        self._selection_start = offset
        self._selection_end = offset + length - 1
        self._hex_pair_snapshot_byte = None
        self._nibble_pos = 0
        self._ensure_cursor_visible()
        self._refresh_visible()
        self._update_scrollbar()
        self._refresh_asm_selection()

    def _show_find_dialog(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Open Find dialog. Bound to Ctrl+F."""
        if not self._data:
            return "break"
        d = tk.Toplevel(self.winfo_toplevel())
        d.title("Find")
        d.transient(self.winfo_toplevel())
        d.grab_set()
        d.geometry("420x168")
        d.resizable(True, False)
        focus = self.winfo_toplevel().focus_get()
        default_hex = focus == self._text
        frm = ttk.Frame(d, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text="Find:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=2)
        find_var = tk.StringVar()
        find_entry = ttk.Entry(frm, textvariable=find_var, width=36)
        find_entry.grid(row=0, column=1, sticky="ew", pady=2)
        frm.columnconfigure(1, weight=1)
        ttk.Label(
            frm,
            text="Hex: token xx or XX = any byte (e.g. 00 xx 08 XX 09 xx 10)",
            font=("Consolas", 8),
            foreground="#666",
        ).grid(row=1, column=1, sticky="w", pady=(0, 2))
        mode_var = tk.StringVar(value="hex" if default_hex else "ascii")
        ttk.Radiobutton(frm, text="Hex", variable=mode_var, value="hex").grid(
            row=2, column=1, sticky="w", pady=2
        )
        ttk.Radiobutton(frm, text="ASCII", variable=mode_var, value="ascii").grid(
            row=3, column=1, sticky="w", pady=2
        )

        def do_find(forward: bool) -> None:
            raw = find_var.get()
            needle = self._parse_find_hex(raw) if mode_var.get() == "hex" else self._parse_find_ascii(raw)
            if not needle:
                messagebox.showwarning("Find", "Invalid or empty search string.", parent=d)
                return
            idx = self._find_next(needle, forward)
            if idx is not None:
                self._select_at_offset(idx, len(needle))
            else:
                messagebox.showinfo("Find", "No further matches found.", parent=d)

        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=4, column=1, sticky="w", pady=8)
        ttk.Button(btn_frm, text="Find Next", command=lambda: do_find(True)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frm, text="Find Previous", command=lambda: do_find(False)).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frm, text="Close", command=d.destroy).pack(side=tk.LEFT, padx=(0, 4))
        find_entry.focus_set()
        d.bind("<Return>", lambda e: do_find(True))
        d.bind("<Shift-Return>", lambda e: do_find(False))
        d.bind("<Escape>", lambda e: d.destroy())
        return "break"

    def _show_replace_dialog(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Open Find & Replace dialog. Bound to Ctrl+R."""
        if not self._data:
            return "break"
        d = tk.Toplevel(self.winfo_toplevel())
        d.title("Find & Replace")
        d.transient(self.winfo_toplevel())
        d.grab_set()
        d.geometry("440x300")
        d.resizable(True, False)
        focus = self.winfo_toplevel().focus_get()
        default_hex = focus == self._text
        frm = ttk.Frame(d, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text="Find:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=2)
        find_var = tk.StringVar()
        find_entry = ttk.Entry(frm, textvariable=find_var, width=36)
        find_entry.grid(row=0, column=1, sticky="ew", pady=2)
        ttk.Label(
            frm,
            text="Hex: token xx or XX = any byte (e.g. 00 xx 08 XX 09 xx 10)",
            font=("Consolas", 8),
            foreground="#666",
        ).grid(row=1, column=1, sticky="w", pady=(0, 2))
        ttk.Label(frm, text="Replace:").grid(row=2, column=0, sticky="w", padx=(0, 8), pady=2)
        repl_var = tk.StringVar()
        repl_entry = ttk.Entry(frm, textvariable=repl_var, width=36)
        repl_entry.grid(row=2, column=1, sticky="ew", pady=2)
        frm.columnconfigure(1, weight=1)
        mode_var = tk.StringVar(value="hex" if default_hex else "ascii")
        ttk.Radiobutton(frm, text="Hex", variable=mode_var, value="hex").grid(
            row=3, column=1, sticky="w", pady=2
        )
        ttk.Radiobutton(frm, text="ASCII", variable=mode_var, value="ascii").grid(
            row=4, column=1, sticky="w", pady=2
        )
        fill_pad_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frm,
            text="Pad shorter replacement to match length (tile fill pattern)",
            variable=fill_pad_var,
        ).grid(row=5, column=1, sticky="w", pady=(4, 0))
        ttk.Label(frm, text="Fill pattern:").grid(row=6, column=0, sticky="w", padx=(0, 8), pady=2)
        fill_pattern_var = tk.StringVar(value="FF")
        fill_entry = ttk.Entry(frm, textvariable=fill_pattern_var, width=36)
        fill_entry.grid(row=6, column=1, sticky="ew", pady=2)
        ttk.Label(
            frm,
            text="(Hex e.g. FF or 00; ASCII text; repeats as needed; default 0xFF if empty)",
            font=("Consolas", 7),
        ).grid(row=7, column=1, sticky="w")
        status_var = tk.StringVar(value="")

        def get_needle() -> Optional[bytearray]:
            raw = find_var.get()
            return self._parse_find_hex(raw) if mode_var.get() == "hex" else self._parse_find_ascii(raw)

        def get_replacement() -> Optional[bytearray]:
            raw = repl_var.get()
            return self._parse_find_hex(raw) if mode_var.get() == "hex" else self._parse_find_ascii(raw)

        def effective_replacement(repl: Optional[bytearray], needle_len: int) -> bytearray:
            """Expand replacement to ``needle_len`` when padding is enabled; else return as-is (may be shorter)."""
            if repl is None:
                repl = bytearray()
            if len(repl) >= needle_len:
                return repl[:needle_len]
            if not fill_pad_var.get():
                return repl
            raw = fill_pattern_var.get().strip()
            pad = self._parse_find_hex_literal(raw) if mode_var.get() == "hex" else self._parse_find_ascii(raw)
            if pad is None or len(pad) == 0:
                pad = bytearray([0xFF])
            out = bytearray(repl)
            i = 0
            while len(out) < needle_len:
                out.append(pad[i % len(pad)])
                i += 1
            return out

        def selection_matches(needle: Union[bytes, bytearray, List[Optional[int]]]) -> bool:
            s = min(self._selection_start or 0, self._selection_end or 0)
            e = max(self._selection_start or 0, self._selection_end or 0) + 1
            if s < 0 or e > len(self._data):
                return False
            if isinstance(needle, list):
                return e - s == len(needle) and self._pattern_match_at(s, needle)
            return e - s == len(needle) and bytes(self._data[s:e]) == needle

        def do_replace_one() -> None:
            needle = get_needle()
            repl = get_replacement()
            if not needle:
                messagebox.showwarning("Replace", "Invalid or empty search string.", parent=d)
                return
            if repl is None:
                repl = bytearray()
            if not selection_matches(needle):
                idx = self._find_next(needle, True)
                if idx is None:
                    messagebox.showinfo("Replace", "No matches found.", parent=d)
                    return
                self._select_at_offset(idx, len(needle))
            s = min(self._selection_start or 0, self._selection_end or 0)
            e = max(self._selection_start or 0, self._selection_end or 0) + 1
            eff_repl = effective_replacement(repl, len(needle))
            if len(eff_repl) == len(needle):
                self._data[s:e] = eff_repl
            elif len(eff_repl) < len(needle):
                del self._data[s + len(eff_repl):e]
                self._data[s : s + len(eff_repl)] = eff_repl
            else:
                self._data[s:e] = eff_repl[: len(needle)]
                self._data[s + len(needle) : s + len(needle)] = eff_repl[len(needle) :]
            self._modified = True
            self._ldr_pc_targets_valid = False
            self._schedule_xref_rebuild()
            self._cursor_byte_offset = min(s + len(eff_repl), len(self._data) - 1) if self._data else 0
            self._selection_start = self._cursor_byte_offset
            self._selection_end = self._cursor_byte_offset
            self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
            self._ensure_cursor_visible()
            self._refresh_visible()
            self._update_scrollbar()
            self._refresh_asm_selection()
            status_var.set("Replaced 1 occurrence.")
            idx = self._find_next(needle, True)
            if idx is not None:
                self._select_at_offset(idx, len(needle))

        def do_replace_all() -> None:
            needle = get_needle()
            repl = get_replacement()
            if not needle:
                messagebox.showwarning("Replace", "Invalid or empty search string.", parent=d)
                return
            if repl is None:
                repl = bytearray()
            count = 0
            pos = 0
            while True:
                idx = self._find_bytes_or_pattern_from(pos, needle)
                if idx < 0:
                    break
                eff = effective_replacement(repl, len(needle))
                if len(eff) == len(needle):
                    self._data[idx : idx + len(needle)] = eff
                    pos = idx + len(needle)
                elif len(eff) < len(needle):
                    del self._data[idx + len(eff) : idx + len(needle)]
                    self._data[idx : idx + len(eff)] = eff
                    pos = idx + len(eff)
                else:
                    self._data[idx : idx + len(needle)] = eff[: len(needle)]
                    self._data[idx + len(needle) : idx + len(needle)] = eff[len(needle) :]
                    pos = idx + len(eff)
                count += 1
            if count > 0:
                self._modified = True
                self._ldr_pc_targets_valid = False
                self._schedule_xref_rebuild()
                self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
                self._refresh_visible()
                self._refresh_asm_selection()
            status_var.set(f"Replaced {count} occurrence(s)." if count else "No matches found.")
            messagebox.showinfo("Replace All", status_var.get(), parent=d)

        def do_find_next() -> None:
            needle = get_needle()
            if not needle:
                messagebox.showwarning("Replace", "Invalid or empty search string.", parent=d)
                return
            idx = self._find_next(needle, True)
            if idx is not None:
                self._select_at_offset(idx, len(needle))
            else:
                messagebox.showinfo("Replace", "No matches found.", parent=d)

        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=8, column=1, sticky="w", pady=8)
        ttk.Button(btn_frm, text="Find Next", command=do_find_next).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frm, text="Replace", command=do_replace_one).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frm, text="Replace All", command=do_replace_all).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frm, text="Close", command=d.destroy).pack(side=tk.LEFT, padx=(0, 4))
        lbl = ttk.Label(frm, textvariable=status_var)
        lbl.grid(row=9, column=1, sticky="w", pady=2)
        find_entry.focus_set()
        d.bind("<Return>", lambda e: do_replace_one())
        d.bind("<Escape>", lambda e: d.destroy())
        return "break"

    # ── Dynamic row count ────────────────────────────────────────────

    def _on_text_configure(self, event: tk.Event) -> None:
        """Recompute _visible_row_count when the text widget resizes."""
        try:
            font = tkfont.Font(font=self._text.cget("font"))
            line_h = font.metrics("linespace")
        except tk.TclError:
            return
        if line_h <= 0:
            return
        new_count = max(1, event.height // line_h)
        if new_count != self._visible_row_count:
            old = self._visible_row_count
            self._visible_row_count = new_count
            if self._data:
                max_start = max(0, self._total_rows - self._visible_row_count)
                if self._visible_row_start > max_start:
                    self._visible_row_start = max_start
                if old != new_count:
                    self._refresh_visible()
                    self._update_scrollbar()
                    self._refresh_asm_selection()

    # ── File I/O ─────────────────────────────────────────────────────

    def load_file(self, path: str) -> bool:
        try:
            with open(path, "rb") as f:
                chunks = []
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                self._data = bytearray(b"".join(chunks))
        except OSError as e:
            messagebox.showerror("Open Failed", str(e))
            return False
        self._file_path = path
        self._pokefirered_sym_norm_to_name = None
        self._sym_browser_rom_list = None
        self._rom_use_pokefirered_sym = rom_bytes_use_pokefirered_sym(bytes(self._data))
        self._modified = False
        self._ldr_pc_targets_valid = False
        self._cursor_byte_offset = 0
        self._selection_start = self._selection_end = None
        self._nibble_pos = 0
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW if self._data else 0
        self._visible_row_start = 0
        self._load_toml_for_rom()
        self._invalidate_xref_index()
        if self._xref_rebuild_after_id is not None:
            try:
                self.after_cancel(self._xref_rebuild_after_id)
            except (tk.TclError, ValueError):
                pass
            self._xref_rebuild_after_id = None
        self._refresh_visible()
        self._update_scrollbar()
        self._refresh_asm_selection()
        self._text.focus_set()
        self.after(200, self._xref_build_after_load)
        return True

    def save_file(self) -> bool:
        if not self._file_path:
            return self.save_file_as()
        try:
            with open(self._file_path, "wb") as f:
                f.write(self._data)
        except OSError as e:
            messagebox.showerror("Save Failed", str(e))
            return False
        self._modified = False
        return True

    def save_file_as(self) -> bool:
        path = filedialog.asksaveasfilename(
            title="Save As",
            filetypes=[("GBA ROM", "*.gba"), ("Binary files", "*.bin"), ("All files", "*.*")],
            defaultextension=".gba",
        )
        if not path:
            return False
        if self._toml_path and self._file_path and os.path.normpath(path) != os.path.normpath(self._file_path):
            self._copy_toml_for_save_as(path)
        self._file_path = path
        return self.save_file()

    def get_file_path(self) -> Optional[str]:
        return self._file_path

    def _get_toml_path(self, rom_path: str) -> str:
        """Return path to TOML file (same name as ROM, .toml extension)."""
        base = os.path.splitext(os.path.basename(rom_path))[0]
        return os.path.join(os.path.dirname(rom_path), base + ".toml")

    def _resolve_toml_path_for_rom(self, rom_path: str) -> Tuple[str, bool]:
        """Pick which TOML to load next to the ROM.

        Prefer ``{ROM stem}.toml``, then ``{ROM stem}_test.toml`` (common in this repo).

        If those are missing, try well-known project files (``wct06_test.toml`` before ``wct06.toml`` so the
        edited test TOML wins when both exist). ``EDS.toml`` is included for EDS projects whose ROM name does
        not match ``EDS.toml`` — use **File → Load structure TOML** to force that file if another fallback
        matches first.

        If the folder has exactly one ``*.toml``, use it. Otherwise return ``{stem}.toml`` (may not exist) so
        the caller can create a default.

        Returns (path, exists_on_disk).
        """
        rom_dir = os.path.dirname(os.path.abspath(rom_path))
        stem = os.path.splitext(os.path.basename(rom_path))[0]
        primary = os.path.join(rom_dir, stem + ".toml")
        if os.path.isfile(primary):
            return primary, True
        stem_test = os.path.join(rom_dir, stem + "_test.toml")
        if os.path.isfile(stem_test):
            return stem_test, True
        for name in (
            "wct06_test.toml",
            "wct06.toml",
            "BPRE0_test.toml",
            "BPRE0.toml",
            "EDS.toml",
            "bpred.toml",
        ):
            alt = os.path.join(rom_dir, name)
            if os.path.isfile(alt):
                return alt, True
        try:
            toml_names = sorted(
                f for f in os.listdir(rom_dir) if f.lower().endswith(".toml")
            )
        except OSError:
            toml_names = []
        if len(toml_names) == 1:
            return os.path.join(rom_dir, toml_names[0]), True
        return primary, False

    def _load_toml_bytes_from_path(self, toml_path: str) -> bool:
        """Read and parse TOML at ``toml_path`` into ``self._toml_data``. Returns False on failure."""
        self._invalidate_struct_anchors_cache()
        loaded = False
        if _TOML_AVAILABLE:
            try:
                with open(toml_path, "rb") as f:
                    self._toml_data = tomli.load(f)
                _normalize_loaded_toml_document(self._toml_data)
                loaded = True
            except Exception as e:
                messagebox.showerror("TOML load failed", f"{toml_path}\n{e}")
                return False
        if not loaded:
            self._toml_data = self._load_toml_regex_fallback(toml_path)
            _normalize_loaded_toml_document(self._toml_data)
        return True

    def load_toml_manual(self, toml_path: str) -> bool:
        """Use this TOML for structures/lists for the rest of the session (overrides ROM basename pairing)."""
        path = os.path.abspath(toml_path)
        if not os.path.isfile(path):
            messagebox.showerror("TOML", f"File not found:\n{path}")
            return False
        prev_ov = self._toml_manual_override
        prev_path = self._toml_path
        prev_data = self._toml_data
        self._toml_manual_override = path
        self._toml_path = path
        if not self._load_toml_bytes_from_path(path):
            self._toml_manual_override = prev_ov
            self._toml_path = prev_path
            self._toml_data = prev_data
            return False
        self._ldr_pc_targets_valid = False
        return True

    def clear_toml_manual_override(self) -> None:
        """Resume auto-selecting TOML next to the ROM (and reload)."""
        self._toml_manual_override = None
        self._load_toml_for_rom()

    def has_toml_manual_override(self) -> bool:
        return self._toml_manual_override is not None

    def get_toml_path(self) -> Optional[str]:
        """Path of the structure TOML in use (ROM-paired or manually loaded)."""
        return self._toml_path

    def _load_toml_for_rom(self) -> None:
        """Load TOML for current ROM. Create default if missing.
        Tries tomli first; on failure uses regex fallback. Treats '''...''' same as \"...\" for Name/Format."""
        if not self._file_path:
            self._toml_path = None
            self._toml_data = {}
            return
        if self._toml_manual_override:
            mp = self._toml_manual_override
            if os.path.isfile(mp):
                self._toml_path = mp
                if self._load_toml_bytes_from_path(mp):
                    return
            self._toml_manual_override = None
        toml_path, exists = self._resolve_toml_path_for_rom(self._file_path)
        if not exists:
            self._create_default_toml(toml_path)
            return
        self._toml_path = toml_path
        self._load_toml_bytes_from_path(toml_path)

    def _resolve_list_entry_span_end(self, list_name: str) -> Optional[int]:
        """Upper bound for indices in ``[[List]]`` with this Name (for struct counts).

        For ``0 = [ a, b, c ]`` returns ``3``. For ``4007 = [ x, y ]`` returns ``4009``.
        Matches how :func:`_load_toml_lists` assigns indices.
        """
        want = normalize_named_anchor_lookup_key(list_name.strip())
        for lst in self._toml_data.get("List", []):
            if not isinstance(lst, dict):
                continue
            name = normalize_named_anchor_lookup_key(str(lst.get("Name", "")))
            if name != want:
                continue
            hi = 0
            found = False
            for key, val in lst.items():
                if key in ("Name", "DefaultHash"):
                    continue
                try:
                    idx = int(key)
                except (ValueError, TypeError):
                    continue
                found = True
                if isinstance(val, list):
                    hi = max(hi, idx + len(val))
                else:
                    hi = max(hi, idx + 1)
            return hi if found else None
        return None

    def _load_toml_regex_fallback(self, toml_path: str) -> Dict[str, Any]:
        """Regex-based TOML loader when tomli fails. Treats '''...''' same as \"...\"."""
        text = ""
        try:
            text = open(toml_path, encoding="utf-8", errors="replace").read()
        except OSError:
            return {}
        result: Dict[str, Any] = {}
        # Match Key = '''value''' or Key = "value" - value can span lines for '''
        def _parse_str(m: "re.Match") -> str:
            s = m.group(1)
            if s.startswith("'''") and s.endswith("'''"):
                return s[3:-3].replace("\\'", "'")
            if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
                return s[1:-1].replace('\\"', '"').replace("\\'", "'")
            return s
        for section in (
            "FunctionAnchors",
            "NamedAnchors",
            "MatchedWords",
            "Constants",
            "Structs",
            "List",
        ):
            pattern = rf"\[\[{section}\]\](.*?)(?=\[\[|\Z)"
            blocks = re.findall(pattern, text, re.DOTALL)
            items: List[Dict[str, Any]] = []
            for block in blocks:
                item: Dict[str, Any] = {}
                idx = 0
                while idx < len(block):
                    m = re.match(r"\s*(\w+)\s*=\s*", block[idx:])
                    if not m:
                        idx += 1
                        continue
                    key, val_start = m.group(1), idx + m.end()
                    rest = block[val_start:]
                    if rest.startswith("'''"):
                        end = rest.find("'''", 3)
                        if end >= 0:
                            item[key] = rest[3:end].replace("\\'", "'")
                            idx = val_start + end + 3
                        else:
                            idx = val_start + 3
                    elif rest.startswith('"'):
                        i, n = 1, len(rest)
                        while i < n:
                            if rest[i] == "\\" and i + 1 < n:
                                i += 2
                                continue
                            if rest[i] == '"':
                                item[key] = rest[1:i].replace('\\"', '"')
                                idx = val_start + i + 1
                                break
                            i += 1
                        else:
                            idx = val_start + n
                    elif rest.startswith("'"):
                        i, n = 1, len(rest)
                        while i < n:
                            if rest[i] == "\\" and i + 1 < n:
                                i += 2
                                continue
                            if rest[i] == "'":
                                item[key] = rest[1:i].replace("\\'", "'")
                                idx = val_start + i + 1
                                break
                            i += 1
                        else:
                            idx = val_start + n
                    else:
                        hm = re.match(r"(0x[0-9A-Fa-f]+|\d+)\s*", rest)
                        if hm:
                            s = hm.group(1)
                            item[key] = int(s, 16) if s.startswith("0x") else int(s)
                            idx = val_start + hm.end()
                        elif rest.startswith("true"):
                            item[key] = True
                            idx = val_start + 4
                        elif rest.startswith("false"):
                            item[key] = False
                            idx = val_start + 5
                        else:
                            idx = val_start + 1
                if item:
                    items.append(item)
            result[section] = items
        return result

    def _create_default_toml(self, toml_path: str) -> None:
        """Create default TOML file with template structure."""
        default = """# Structure definitions for this ROM
# Add [[FunctionAnchors]], [[Structs]], [[Constants]] as needed.
# ``Address`` values are ROM **file** offsets in hex (no 0x08xxxxxx GBA prefix).

[[Constants]]
Name = "EXAMPLE_CONST"
Value = 0

[[Structs]]
Name = "structs.Example"
Format = "`s`{field|u8}"

[[FunctionAnchors]]
Name = "funcs.example.FuncName"
Address = 0x0
Format = "`f|u8`[u8 arg0]"
"""
        try:
            with open(toml_path, "w", encoding="utf-8") as f:
                f.write(default)
            self._toml_path = toml_path
            self._toml_data = {}
            if _TOML_AVAILABLE:
                with open(toml_path, "rb") as f:
                    self._toml_data = tomli.load(f)
                _normalize_loaded_toml_document(self._toml_data)
        except OSError:
            self._toml_path = None
            self._toml_data = {}

    def _copy_toml_for_save_as(self, new_rom_path: str) -> None:
        """Copy current TOML to new ROM's TOML path."""
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return
        new_toml = self._get_toml_path(new_rom_path)
        try:
            shutil.copy2(self._toml_path, new_toml)
            self._toml_path = new_toml
            if _TOML_AVAILABLE:
                with open(new_toml, "rb") as f:
                    self._toml_data = tomli.load(f)
                _normalize_loaded_toml_document(self._toml_data)
        except OSError:
            pass

    def _get_function_anchor_offset_by_name(self, name: str) -> Optional[int]:
        """Return file offset for FunctionAnchor or NamedAnchor with given Name, or None if not found."""
        if not self._toml_data or not name:
            return None
        name_lo = name.strip().lower()
        for anchor in list(self._toml_data.get("FunctionAnchors", [])) + list(self._toml_data.get("NamedAnchors", [])):
            anchor_name = anchor.get("Name")
            if anchor_name and str(anchor_name).lower() == name_lo:
                addr = anchor.get("Address")
                if addr is None:
                    return None
                try:
                    val = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                except (ValueError, TypeError):
                    return None
                if val < GBA_ROM_BASE:
                    val += GBA_ROM_BASE
                return val - GBA_ROM_BASE
        return None

    def resolve_file_offset_or_named_anchor(self, s: str) -> Tuple[Optional[int], str]:
        """Parse a ROM **file** offset (or GBA ``0x08…``), resolve a ``[[NamedAnchors]]`` **Name**, or a ``[[List]]``
        **Name** when that list is the ``]count`` source for a struct table (same as Goto)."""
        off, err = parse_rom_file_offset(s)
        if off is not None:
            return off, ""
        if not getattr(self, "_toml_data", None):
            return None, err or "Enter a numeric offset, or load TOML to use a NamedAnchor Name."
        key = normalize_named_anchor_lookup_key(s)
        if not key:
            return None, err or "Invalid offset or Name."
        key_lo = key.lower()
        for anchor in self._toml_data.get("NamedAnchors", []):
            an = _named_anchor_row_name_field(anchor)
            if not an or an.lower() != key_lo:
                continue
            addr = anchor.get("Address")
            if addr is None:
                return None, f"NamedAnchor {key!r} has no Address in TOML."
            try:
                val = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
            except (ValueError, TypeError):
                return None, f"NamedAnchor {key!r} has an invalid Address."
            if val < GBA_ROM_BASE:
                val += GBA_ROM_BASE
            return val - GBA_ROM_BASE, ""
        si = self._struct_anchor_for_list_count_name(key)
        if si is not None and si.get("base_off") is not None:
            return int(si["base_off"]), ""
        return None, f"No [[NamedAnchors]] row named {key!r}, and no struct table uses {key!r} as its ]count list."

    def _anchor_address_matches_gba(self, anchor: Dict[str, Any], gba_addr: int) -> bool:
        """True if anchor ``Address`` matches ``gba_addr`` (Thumb-aware)."""
        addr = anchor.get("Address")
        if addr is None:
            return False
        if isinstance(addr, int):
            anchor_addr = addr
        else:
            try:
                anchor_addr = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
            except (ValueError, TypeError):
                return False
        if anchor_addr < GBA_ROM_BASE:
            anchor_addr += GBA_ROM_BASE
        if (anchor_addr & 0x01) != (gba_addr & 0x01):
            anchor_addr &= ~1
            gba_check = gba_addr & ~1
        else:
            gba_check = gba_addr
        return anchor_addr == gba_check or anchor_addr == gba_addr

    def _toml_format_has_function_decomp_spec(self, fmt: Any) -> bool:
        """True if Format carries a pret-style function template (`` `f` `` / `` `f|` ``), not just data/free-space."""
        s = str(fmt or "").strip()
        if not s:
            return False
        return "`f`" in s or "`f|" in s

    def _get_function_anchor_for_addr(self, gba_addr: int) -> Optional[Dict[str, Any]]:
        """Return FunctionAnchor or NamedAnchor dict if gba_addr matches any anchor Address."""
        if not self._toml_data:
            return None
        for anchor in list(self._toml_data.get("FunctionAnchors", [])) + list(self._toml_data.get("NamedAnchors", [])):
            if self._anchor_address_matches_gba(anchor, gba_addr):
                return anchor
        return None

    def _get_function_anchor_for_decompilation(self, gba_addr: int) -> Optional[Dict[str, Any]]:
        """Anchor used to shape angr pseudo-C: ``[[FunctionAnchors]]`` only, plus ``[[NamedAnchors]]`` that have a real ``Format`` function spec.

        Generic NamedAnchors (e.g. free-space labels like ``gFreeSpace1`` with non-function Format) must not
        override signatures or rewrite parameters — that produced wrong names (e.g. ``gFreeSpace1``) for injected code.
        """
        if not self._toml_data:
            return None
        for anchor in self._toml_data.get("FunctionAnchors", []):
            if isinstance(anchor, dict) and self._anchor_address_matches_gba(anchor, gba_addr):
                return anchor
        for anchor in self._toml_data.get("NamedAnchors", []):
            if not isinstance(anchor, dict):
                continue
            if not self._toml_format_has_function_decomp_spec(anchor.get("Format", "")):
                continue
            if self._anchor_address_matches_gba(anchor, gba_addr):
                return anchor
        return None

    def _build_toml_sub_name_map(self) -> Dict[int, str]:
        """Map normalized GBA code address (Thumb bit cleared) -> full anchor Name for TOML-labeled functions.

        Used to rewrite angr's ``sub_DEADBEEF`` identifiers to e.g. ``funcs.trainer_card.DrawTrainerCardWindow``.
        FunctionAnchors are processed before NamedAnchors; first entry wins on duplicate addresses.
        """
        out: Dict[int, str] = {}
        if not self._toml_data:
            return out
        for key in ("FunctionAnchors", "NamedAnchors"):
            for anchor in self._toml_data.get(key, []):
                addr = anchor.get("Address")
                if addr is None:
                    continue
                raw_name = anchor.get("Name")
                if raw_name is None or not str(raw_name).strip():
                    continue
                name = str(raw_name).strip().strip("'\"")
                try:
                    gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                except (ValueError, TypeError):
                    continue
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                norm = gba & ~1
                if norm not in out:
                    out[norm] = name
        return out

    def _rewrite_angr_sub_names(self, text: str, name_by_norm_addr: Dict[int, str]) -> str:
        """Replace ``sub_<hex>`` with TOML names where ``int(hex,16) & ~1`` is a known anchor address."""
        if not text or not name_by_norm_addr:
            return text

        def repl(m: re.Match[str]) -> str:
            try:
                h = int(m.group(1), 16)
            except ValueError:
                return m.group(0)
            norm = h & ~1
            mapped = name_by_norm_addr.get(norm)
            return mapped if mapped is not None else m.group(0)

        return re.sub(r"\bsub_([0-9a-fA-F]+)\b", repl, text)

    def get_pokefirered_sym_name_to_addr(self) -> Dict[str, int]:
        """``pokefirered.sym`` name → address when the loaded ROM is FireRed (``BPRE``); else empty."""
        if not getattr(self, "_rom_use_pokefirered_sym", False):
            return {}
        return load_pokefirered_sym_name_to_addr()

    def _get_pokefirered_sym_norm_map(self) -> Dict[int, str]:
        """Lazy-loaded ``pokefirered.sym`` (repo root): normalized GBA address -> symbol name."""
        if not getattr(self, "_rom_use_pokefirered_sym", False):
            return {}
        if self._pokefirered_sym_norm_to_name is None:
            self._pokefirered_sym_norm_to_name = load_pokefirered_sym_norm_to_name()
        return self._pokefirered_sym_norm_to_name

    def _merged_sub_name_map(self) -> Dict[int, str]:
        """``pokefirered.sym`` plus TOML FunctionAnchors/NamedAnchors; TOML overrides on duplicate addresses."""
        merged = dict(self._get_pokefirered_sym_norm_map())
        merged.update(self._build_toml_sub_name_map())
        return merged

    def _rewrite_decompiler_hex_literals(self, text: str, merged: Dict[int, str]) -> str:
        """Replace ``0x08…`` / RAM literals with symbol names when present in ``merged`` (keys are norm addresses)."""
        if not text or not merged:
            return text

        def repl(m: re.Match[str]) -> str:
            raw = m.group(0)
            try:
                val = int(m.group(1), 16)
            except ValueError:
                return raw
            if val > 0xFFFFFFFF:
                return raw
            name = merged.get(val) or merged.get(val & ~1)
            return name if name is not None else raw

        return re.sub(r"\b0x([0-9A-Fa-f]+)\b", repl, text)

    def _apply_symbol_names_to_decompiler_text(self, text: str) -> str:
        """Apply ``pokefirered.sym`` + TOML names: ``sub_*`` identifiers and hex address literals."""
        merged = self._merged_sub_name_map()
        if not merged:
            return text
        text = self._rewrite_angr_sub_names(text, merged)
        text = self._rewrite_decompiler_hex_literals(text, merged)
        return text

    def _extract_extern_lines(self, text: str) -> List[str]:
        """Extract lines that are extern declarations from decompiler output."""
        lines: List[str] = []
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("extern "):
                lines.append(s)
        return lines

    def _extract_angr_function_body(self, text: str) -> str:
        """Extract the function body (from opening brace to end) from angr decompilation."""
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if re.search(r"\bsub_[a-fA-F0-9]+\s*\(", line):
                rest = "\n".join(lines[i:])
                match = re.search(r"\{", rest)
                if match:
                    return rest[match.start():]
                break
        return ""

    def _indent_function_body(self, text: str, spaces: int = 4) -> str:
        """Indent function body lines. Opening { and closing } stay at column 0."""
        indent = " " * spaces
        lines = text.splitlines()
        result: List[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped in ("{", "}"):
                result.append(stripped)
            else:
                result.append(indent + stripped)
        return "\n".join(result)

    def _format_struct_from_toml(self, struct_def: Dict[str, Any], constants: Dict[str, int]) -> Optional[str]:
        """Convert Struct Format to C struct definition. Format: `s`{field|type}..."""
        fmt = struct_def.get("Format", "")
        if not fmt or "`s`" not in fmt:
            return None
        name = struct_def.get("Name", "struct")
        type_map = {"b8": "bool8", "u8": "u8", "s8": "s8", "u16": "u16", "s16": "s16", "u32": "u32", "s32": "s32"}
        lines: List[str] = [f"struct {name}", "{"]
        for m in re.finditer(r"\{([^|]+)\|([^}]+)\}", fmt):
            field, typ = m.group(1).strip(), m.group(2).strip()
            for k, v in constants.items():
                field = re.sub(r"\b" + re.escape(str(k)) + r"\b", str(v), field)
            ptr = typ.startswith("*")
            core = typ.lstrip("*")
            ctype = type_map.get(core, core)
            if ptr:
                ctype = ctype + "*"
            lines.append(f"    {ctype} {field};")
        lines.append("}")
        return "\n".join(lines)

    def _get_struct_names_from_anchor(self, anchor: Dict[str, Any]) -> List[str]:
        """Return ordered list of struct names referenced in Format args (struct_0, struct_1, ...)."""
        names: List[str] = []
        if not self._toml_data:
            return names
        fmt = anchor.get("Format", "")
        for bracket in re.findall(r"\[([^\]]+)\]", fmt):
            m = re.search(r"struct\s+(\w+)", bracket)
            if m:
                name = m.group(1)
                if name not in names:
                    names.append(name)
        return names

    def _get_param_names_from_anchor(self, anchor: Dict[str, Any]) -> List[str]:
        """Return ordered list of parameter names from Format args (a0, a1, ... mapping)."""
        names: List[str] = []
        fmt = anchor.get("Format", "")
        for bracket in re.findall(r"\[([^\]]+)\]", fmt):
            s = bracket.strip()
            m = re.search(r"(\w+)\s*$", s)
            if m and m.group(1) != "void":
                names.append(m.group(1))
        return names

    def _rewrite_angr_param_refs(self, text: str, param_names: List[str]) -> str:
        """Replace angr's a0, a1, a2, ... with TOML parameter names in body."""
        if not param_names:
            return text
        result = text
        for i, name in enumerate(param_names):
            angr_param = f"a{i}"
            result = re.sub(r"\b" + re.escape(angr_param) + r"\b", name, result)
        return result

    def _rewrite_param_aliases(self, text: str, param_names: List[str]) -> str:
        """Replace 'var = param;' aliases: substitute var with param, remove the assignment and declaration.
        Only when var is assigned exactly once from a param (no reassignments)."""
        if not param_names:
            return text
        param_set = set(param_names)
        lines = text.splitlines()
        alias_map: Dict[str, str] = {}  # var -> param
        for i, line in enumerate(lines):
            m = re.match(r"^\s*(\w+)\s*=\s*(\w+)\s*;\s*(?://.*)?$", line.strip())
            if not m:
                continue
            var, rhs = m.group(1), m.group(2)
            if rhs not in param_set:
                continue
            assigns_to_var = [
                j for j, ln in enumerate(lines)
                if re.search(r"\b" + re.escape(var) + r"\s*=", ln)
            ]
            if len(assigns_to_var) == 1:
                alias_map[var] = rhs
        if not alias_map:
            return text
        result = text
        for var, param in alias_map.items():
            result = re.sub(
                r"^\s*" + re.escape(var) + r"\s*=\s*" + re.escape(param) + r"\s*;\s*(?://.*)?\s*\n?",
                "",
                result,
                flags=re.MULTILINE,
            )
            result = re.sub(
                r"^\s*[^=\n]*\b" + re.escape(var) + r"\s*;\s*(?://.*)?\s*\n?",
                "",
                result,
                flags=re.MULTILINE,
            )
        for var, param in alias_map.items():
            result = re.sub(r"\b" + re.escape(var) + r"\b", param, result)
        return result

    def _get_struct_defs_from_anchor(self, anchor: Dict[str, Any], constants: Dict[str, int]) -> List[str]:
        """Return C struct definitions for structs referenced in Format args (deduped by struct name)."""
        seen: Set[str] = set()
        result: List[str] = []
        if not self._toml_data:
            return result
        fmt = anchor.get("Format", "")
        struct_by_name = {s.get("Name"): s for s in self._toml_data.get("Structs", []) if s.get("Name")}
        for bracket in re.findall(r"\[([^\]]+)\]", fmt):
            m = re.search(r"struct\s+(\w+)", bracket)
            if m:
                name = m.group(1)
                if name in seen:
                    continue
                st = struct_by_name.get(name)
                if st and st.get("Format"):
                    seen.add(name)
                    formatted = self._format_struct_from_toml(st, constants)
                    if formatted:
                        result.append(formatted)
        return result

    def _rewrite_angr_struct_refs(self, text: str, struct_names: List[str]) -> str:
        """Replace angr's struct_0, struct_1, ... with TOML struct names in body."""
        if not struct_names:
            return text
        result = text
        for i, name in enumerate(struct_names):
            angr_name = f"struct_{i}"
            full_type = f"struct {name}"
            result = re.sub(r"struct\s+" + re.escape(angr_name) + r"\b", full_type, result)
            result = re.sub(r"\b" + re.escape(angr_name) + r"\b", full_type, result)
        return result

    def _get_struct_offset_to_field(
        self, struct_def: Dict[str, Any], constants: Dict[str, int]
    ) -> Dict[int, str]:
        """Build offset->field_access map for a struct. E.g. 8->'data[0]', 10->'data[1]'."""
        type_info = {
            "*u8": (4, 4), "*u16": (4, 4), "*s16": (4, 4), "*u32": (4, 4), "*s32": (4, 4),
            "u8": (1, 1), "s8": (1, 1), "b8": (1, 1),
            "u16": (2, 2), "s16": (2, 2),
            "u32": (4, 4), "s32": (4, 4),
        }
        fmt = struct_def.get("Format", "")
        if not fmt or "`s`" not in fmt:
            return {}
        offset = 0
        result: Dict[int, str] = {}
        for m in re.finditer(r"\{([^|]+)\|([^}]+)\}", fmt):
            field_raw, typ = m.group(1).strip(), m.group(2).strip()
            ptr = typ.startswith("*")
            core = typ.lstrip("*")
            key = f"*{core}" if ptr else core
            size, align = type_info.get(key, type_info.get(core, (4, 4)))
            offset = (offset + align - 1) & ~(align - 1)
            field = field_raw
            for k, v in constants.items():
                field = re.sub(r"\b" + re.escape(str(k)) + r"\b", str(v), field)
            arr_match = re.match(r"(\w+)\[(\d+)\]", field)
            if arr_match:
                base_name, count = arr_match.group(1), int(arr_match.group(2))
                for i in range(count):
                    result[offset + i * size] = f"{base_name}[{i}]"
                offset += size * count
            else:
                result[offset] = field
                offset += size
        return result

    def _rewrite_struct_offsets_to_fields(
        self, text: str, param_names: List[str], anchor: Dict[str, Any], constants: Dict[str, int]
    ) -> str:
        """Replace (param + offset) with (&param->field) and param->field_N with param->field based on struct layout."""
        if not self._toml_data or not param_names:
            return text
        fmt = anchor.get("Format", "")
        struct_by_name = {s.get("Name"): s for s in self._toml_data.get("Structs", []) if s.get("Name")}
        result = text
        for bracket in re.findall(r"\[([^\]]+)\]", fmt):
            m = re.search(r"struct\s+(\w+)\s*\*\s*(\w+)", bracket)
            if not m:
                continue
            struct_name, param_name = m.group(1), m.group(2)
            if param_name not in param_names:
                continue
            st = struct_by_name.get(struct_name)
            if not st or not st.get("Format"):
                continue
            offset_map = self._get_struct_offset_to_field(st, constants)
            for off in sorted(offset_map.keys(), reverse=True):
                field = offset_map[off]
                esc_param = re.escape(param_name)
                result = re.sub(
                    r"\(" + esc_param + r"\s*\+\s*" + str(off) + r"\s*\)",
                    f"(&{param_name}->{field})",
                    result,
                )
            for off in sorted(offset_map.keys(), reverse=True):
                field = offset_map[off]
                esc_param = re.escape(param_name)
                result = re.sub(
                    r"\b" + esc_param + r"\s*->\s*field_" + str(off) + r"\b",
                    f"{param_name}->{field}",
                    result,
                )
            for off in sorted(offset_map.keys(), reverse=True):
                field = offset_map[off]
                esc_param = re.escape(param_name)
                result = re.sub(
                    r"\b" + esc_param + r"\s*->\s*field_0x" + hex(off)[2:].lower() + r"\b",
                    f"{param_name}->{field}",
                    result,
                )
        result = re.sub(
            r"\*\(\s*\(\s*[^)]+\s*\)\s*\(\s*&\s*(\w+)\s*->\s*(\w+(?:\[\d+\])?)\s*\)\s*\)",
            r"\1->\2",
            result,
        )
        return result

    def _remove_unused_assignments(self, text: str) -> str:
        """Remove lines 'var = expr;' where var is never used after."""
        lines = text.splitlines()
        keep: List[int] = []
        for i, line in enumerate(lines):
            m = re.match(r"^\s*(\w+)\s*=\s*(.+);\s*(?://.*)?$", line.strip())
            if m:
                var = m.group(1)
                rest = "\n".join(lines[i + 1:])
                if not re.search(r"\b" + re.escape(var) + r"\b", rest):
                    continue
            keep.append(i)
        return "\n".join(lines[i] for i in keep)

    def _rewrite_decimal_addresses_to_hex(self, text: str) -> str:
        """Convert all decimal numbers to hex. Skips numbers already in 0x... form."""
        def repl(m: re.Match) -> str:
            n = int(m.group(1))
            return "0" if n == 0 else f"0x{n:X}"
        return re.sub(r"(?<!0x)\b(\d+)\b", repl, text)

    def _format_sig_from_anchor(self, anchor: Dict[str, Any], constants: Dict[str, int]) -> str:
        """Convert TOML Format to C-like signature string."""
        name = anchor.get("Name", "sub")
        if "." in str(name):
            name = str(name).rsplit(".", 1)[-1]
        fmt = anchor.get("Format", "")
        if not fmt:
            return f"/* {anchor.get('Name', name)} */"
        ret_type = "void"
        args: List[str] = []
        m = re.search(r"`f\|?([^`]*)`", fmt)
        if m:
            ret_part = m.group(1).strip()
            if ret_part:
                ptr = ret_part.startswith("*")
                core = ret_part.lstrip("*")
                type_map = {"b8": "bool8", "u8": "u8", "s8": "s8", "u16": "u16", "s16": "s16", "u32": "u32", "s32": "s32"}
                ret_type = type_map.get(core, core)
                if ptr:
                    ret_type = ret_type + "*"
        for bracket in re.findall(r"\[([^\]]+)\]", fmt):
            args.append(bracket.strip())
        for k, v in constants.items():
            for i, a in enumerate(args):
                args[i] = re.sub(r"\b" + re.escape(str(k)) + r"\b", str(v), a)
        args_str = ", ".join(args) if args else "void"
        return f"{ret_type} {name}({args_str})"

    def is_modified(self) -> bool:
        return self._modified

    def has_data(self) -> bool:
        return len(self._data) > 0

    def get_data(self) -> Optional[bytearray]:
        return self._data if self._data else None

    def get_pcs_table_anchors(self) -> List[Dict[str, Any]]:
        return self._get_pcs_table_anchors()

    def get_graphics_anchors(self) -> List[Dict[str, Any]]:
        """NamedAnchors whose Format is a graphics palette/sprite/tile/tilemap spec (ucp4, uct4xWxH, ucm4xWxH|…, …)
        or a table ``[rowSpec]countRef`` of identical rows."""
        result: List[Dict[str, Any]] = []
        pcs_names = {a["name"] for a in self._get_pcs_table_anchors()}
        rom_len = len(self._data) if self._data else 0
        for anchor in self._toml_data.get("NamedAnchors", []):
            if not isinstance(anchor, dict):
                continue
            name = _named_anchor_row_name_field(anchor)
            if not name or name in pcs_names:
                continue
            fmt = normalize_named_anchor_format(anchor.get("Format", ""))
            spec = parse_graphics_anchor_format(fmt)
            table_count_ref: Optional[str] = None
            if spec is None:
                tbl = parse_graphics_table_format(fmt)
                if tbl is None:
                    continue
                spec, table_count_ref = tbl
                try:
                    if spec.lz:
                        raise ValueError("LZ rows in graphics tables are not supported")
                    row_byte_size = graphics_row_byte_size(spec)
                except ValueError:
                    continue
                n_entries = self._resolve_struct_count(table_count_ref)
                if n_entries is None or n_entries <= 0:
                    continue
                total_span = row_byte_size * n_entries
            else:
                row_byte_size = 0
                n_entries = 0
                total_span = 0
            addr = anchor.get("Address")
            if addr is None:
                continue
            try:
                gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                base_off = gba - GBA_ROM_BASE
            except (ValueError, TypeError):
                continue
            if base_off < 0 or base_off >= rom_len:
                continue
            rest = max(0, rom_len - base_off)
            if table_count_ref is not None:
                rom_span = min(rest, total_span)
            else:
                rom_span = compute_graphics_rom_span(spec, rom_len, base_off)
            entry: Dict[str, Any] = {
                "name": name,
                "anchor": anchor,
                "spec": spec,
                "base_off": base_off,
                "rom_span": rom_span,
                "graphics_entry": True,
                "graphics_table": table_count_ref is not None,
                "table_count_ref": table_count_ref,
                "row_byte_size": row_byte_size,
                "table_num_entries": n_entries,
            }
            result.append(entry)
        result.sort(key=lambda x: str(x["name"]).lower())
        return result

    def find_graphics_anchor_by_name(self, anchor_name: str) -> Optional[Dict[str, Any]]:
        want = normalize_named_anchor_lookup_key(anchor_name)
        wl = want.lower()
        exact: Optional[Dict[str, Any]] = None
        folded: Optional[Dict[str, Any]] = None
        for a in self.get_graphics_anchors():
            n = str(a.get("name", ""))
            if n == want:
                exact = a
                break
            if n.lower() == wl:
                if folded is None:
                    folded = a
        return exact if exact is not None else folded

    def find_struct_anchor_by_name(self, anchor_name: str) -> Optional[Dict[str, Any]]:
        want = anchor_name.strip()
        for a in self.get_struct_anchors():
            if str(a["name"]) == want:
                return a
        return None

    def resolve_palette_table_row(self, table_name: str, row_idx: int) -> Tuple[Optional[Any], Optional[int], str]:
        """Return ``(palette_spec, rom_file_offset, notes)`` for one row of a palette table."""
        notes = ""
        ga = self.find_graphics_anchor_by_name(table_name)
        if ga is not None and ga["spec"].kind == "palette":
            if ga.get("graphics_table"):
                rsz = int(ga["row_byte_size"])
                nent = int(ga.get("table_num_entries") or 0)
                if nent and (row_idx < 0 or row_idx >= nent):
                    notes += f"Warning: palette row {row_idx} may be out of range (0..{nent - 1}) for {table_name!r}.\n"
                ext_pb = int(ga["base_off"]) + row_idx * rsz
                return ga["spec"], ext_pb, notes
            return ga["spec"], int(ga["base_off"]), notes

        si = self.find_struct_anchor_by_name(table_name)
        if si is None:
            return None, None, f"Palette table {table_name!r} not found.\n"
        data = self.get_data()
        if not data:
            return None, None, notes
        cnt = int(si["count"])
        if row_idx < 0 or row_idx >= cnt:
            return None, None, notes + f"Palette row {row_idx} out of range (0..{cnt - 1}) for {table_name!r}.\n"
        row_off = int(si["base_off"]) + row_idx * int(si["struct_size"])
        rsz = int(si["struct_size"])
        if row_off + rsz > len(data):
            return None, None, notes + f"Palette table row out of ROM ({table_name!r}).\n"
        for f in si["fields"]:
            if f.get("type") != "gfx_palette":
                continue
            gsp = f.get("gfx_spec")
            if gsp is None or getattr(gsp, "kind", None) != "palette":
                continue
            fo = int(f["offset"])
            tgt = resolve_gba_pointer(bytes(data), row_off + fo)
            if tgt is not None:
                return (
                    gsp,
                    tgt,
                    notes + f"Palette via struct table {table_name!r} row {row_idx} (field {f.get('name')!r}).\n",
                )
        return None, None, notes + f"Struct {table_name!r} has no gfx_palette field.\n"

    def resolve_palette_for_graphics_row(self, palette_ref: str, table_row_idx: int) -> Tuple[Optional[Any], Optional[int], str]:
        """
        Resolve palette spec + ROM offset for graphics ``|paletteRef`` when the main anchor is a graphics **table**
        (same row index for sprite and palette).

        If ``paletteRef`` is a palette NamedAnchor → use it (or its table row).

        If it is a **lookup** struct (e.g. ``[index.foo.palettes]count``) → read row ``table_row_idx``, then either
        follow a ``gfx_palette`` pointer or a uint ``index`` into another NamedAnchor's palette table.
        """
        notes = ""
        ref = palette_ref.strip()
        if not ref:
            return None, None, ""

        ga = self.find_graphics_anchor_by_name(ref)
        if ga is not None:
            if ga["spec"].kind == "palette":
                if ga.get("graphics_table"):
                    ext_pb = int(ga["base_off"]) + table_row_idx * int(ga["row_byte_size"])
                    return ga["spec"], ext_pb, notes
                return ga["spec"], int(ga["base_off"]), notes
            return (
                None,
                None,
                f"Graphics anchor {ref!r} is {ga['spec'].kind!r}, not a palette; expected a palette or lookup struct.\n",
            )

        si = self.find_struct_anchor_by_name(ref)
        if si is None:
            return None, None, notes + f"NamedAnchor {ref!r} not found (palette or lookup struct).\n"

        data = self.get_data()
        if not data:
            return None, None, notes
        cnt = int(si["count"])
        if table_row_idx < 0 or table_row_idx >= cnt:
            return None, None, notes + f"Lookup row {table_row_idx} out of range (0..{cnt - 1}) for {ref!r}.\n"
        row_off = int(si["base_off"]) + table_row_idx * int(si["struct_size"])
        rsz = int(si["struct_size"])
        if row_off + rsz > len(data):
            return None, None, notes + f"Lookup row out of ROM for {ref!r}.\n"
        row = bytes(data[row_off : row_off + rsz])

        for f in si["fields"]:
            if f.get("type") != "gfx_palette":
                continue
            gsp = f.get("gfx_spec")
            if gsp is None or getattr(gsp, "kind", None) != "palette":
                continue
            fo = int(f["offset"])
            tgt = resolve_gba_pointer(bytes(data), row_off + fo)
            if tgt is not None:
                return (
                    gsp,
                    tgt,
                    notes + f"Palette pointer from lookup struct {ref!r} (field {f.get('name')!r}).\n",
                )

        for f in si["fields"]:
            if f.get("type") != "uint":
                continue
            enum_ref = f.get("enum")
            if not enum_ref or not isinstance(enum_ref, str):
                continue
            target_tbl = enum_ref.strip()
            if not target_tbl:
                continue
            fo = int(f["offset"])
            fsz = int(f["size"])
            if fo + fsz > len(row):
                continue
            pal_idx = int.from_bytes(row[fo : fo + fsz], "little")
            ps, pb, n2 = self.resolve_palette_table_row(target_tbl, pal_idx)
            return ps, pb, notes + n2 + f"Index {pal_idx} ({ref!r}.{f.get('name')}) → {target_tbl!r}.\n"

        return None, None, notes + f"Lookup struct {ref!r} has no uint index or gfx_palette field.\n"

    def _bit_count_for_blist_ref(self, ref: str) -> Optional[int]:
        """Bit width for ``field|b[]ref``: ``[[List]]`` length or PCS/struct table row count for ``ref``."""
        ref = ref.strip()
        if not ref:
            return None
        lm = self.get_lists().get(ref)
        if lm is not None:
            if not lm:
                return None
            # One bit per [[List]] row (contiguous indices); ``len`` matches ``max+1`` for dense tables.
            return len(lm)
        for anchor in self._toml_data.get("NamedAnchors", []) or []:
            name = str(anchor.get("Name", "")).strip().strip("'\"")
            if name != ref:
                continue
            a_fmt_raw = str(anchor.get("Format", "")).strip()
            cr = _parse_struct_count(a_fmt_raw)
            if isinstance(cr, int) and cr > 0:
                return cr
            if isinstance(cr, str):
                c2 = self._resolve_struct_count(cr)
                if c2 is not None and c2 > 0:
                    return c2
        return None

    def _invalidate_struct_anchors_cache(self) -> None:
        self._struct_anchors_cache = None

    def get_struct_anchors(self) -> List[Dict[str, Any]]:
        """Return NamedAnchors whose Format is a parseable struct (not pure PCS tables)."""
        if self._struct_anchors_cache is not None:
            return self._struct_anchors_cache
        result: List[Dict[str, Any]] = []
        pcs_names = {a["name"] for a in self._get_pcs_table_anchors()}
        for anchor in self._toml_data.get("NamedAnchors", []):
            name = str(anchor.get("Name", "")).strip().strip("'\"")
            if name in pcs_names:
                continue
            fmt_raw = str(anchor.get("Format", "")).strip()
            fmt = normalize_named_anchor_format(anchor.get("Format", ""))
            fields = _parse_struct_fields(fmt, blist_resolver=self._bit_count_for_blist_ref)
            if not fields:
                continue
            addr = anchor.get("Address")
            if addr is None:
                continue
            try:
                gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                base_off = gba - GBA_ROM_BASE
            except (ValueError, TypeError):
                continue
            packed = _struct_is_packed_terminator_only(fields)
            packed_fd: Optional[Dict[str, Any]] = None
            if packed:
                packed_fd = next(
                    (
                        f
                        for f in fields
                        if f.get("type") == "nested_array" and f.get("terminator") is not None
                    ),
                    None,
                )
                if packed_fd is None:
                    continue
                struct_size = 1
            else:
                struct_size = _struct_row_byte_size(fields)
                if struct_size <= 0:
                    continue
            # Use normalized Format for ]count — bare `` `ydk`…[card:…]N`` TOML has no leading ``[``, so
            # :func:`_parse_struct_count` would return None on *fmt_raw* even when *fields* parsed from *fmt*.
            count_raw = _parse_struct_count(fmt)
            if count_raw is None:
                continue
            count = count_raw if isinstance(count_raw, int) else self._resolve_struct_count(count_raw)
            if count is None or count <= 0:
                continue
            entry_label_pcs: Optional[Dict[str, Any]] = None
            entry_label_list: Optional[str] = None
            if isinstance(count_raw, str):
                entry_label_pcs = _find_pcs_table_for_struct_suffix(
                    self._get_pcs_table_anchors(), count_raw
                )
                # Keep [[List]] label lookup independent from PCS detection so
                # Struct "Find/Matches" can search list contents even when a
                # same-named PCS table exists.
                cref = _struct_count_ref_base_name(str(count_raw))
                lk = normalize_named_anchor_lookup_key(cref)
                if lk and lk in _load_toml_lists(self._toml_data):
                    entry_label_list = lk
            count_ref_str: Optional[str] = str(count_raw).strip() if isinstance(count_raw, str) else None
            result.append({
                "name": name, "anchor": anchor, "fields": fields,
                "count": count, "struct_size": struct_size, "base_off": base_off,
                "count_ref": count_ref_str,
                "entry_label_pcs": entry_label_pcs,
                "entry_label_list": entry_label_list,
                "packed_terminator": packed,
                "packed_terminator_fd": packed_fd,
                "ydk_import": _struct_format_has_ydk_import_marker(fmt_raw),
                "ydk_password_anchor": (
                    _struct_format_ydk_password_anchor_name(fmt_raw)
                    if _struct_format_has_ydk_import_marker(fmt_raw)
                    else None
                ),
            })
        result.sort(key=lambda x: str(x["name"]).lower())
        self._struct_anchors_cache = result
        return result

    def _resolve_struct_count(self, ref: str) -> Optional[int]:
        """Resolve count reference: number, MatchedWord, or NamedAnchor name (with optional +/-N)."""
        ref = ref.strip()
        offset = 0
        m = re.match(r'^(.+?)([+-]\d+)$', ref)
        if m:
            ref = m.group(1)
            offset = int(m.group(2))
        mw = self._resolve_table_length(ref)
        if mw is not None:
            return mw + offset
        list_hi = self._resolve_list_entry_span_end(ref)
        if list_hi is not None:
            return list_hi + offset
        for pcs in self._get_pcs_table_anchors():
            if pcs["name"] == ref:
                return pcs["count"] + offset
        for anchor in self._toml_data.get("NamedAnchors", []):
            a_name = str(anchor.get("Name", "")).strip().strip("'\"")
            if a_name == ref:
                a_fmt_raw = str(anchor.get("Format", "")).strip()
                a_count = _parse_struct_count(a_fmt_raw)
                if isinstance(a_count, int):
                    return a_count + offset
                if isinstance(a_count, str):
                    c3 = self._resolve_struct_count(a_count)
                    if c3 is not None:
                        return c3 + offset
        return None

    def get_lists(self) -> Dict[str, Dict[int, str]]:
        """Return all [[List]] entries as {name: {index: label}}."""
        return _load_toml_lists(self._toml_data)

    def insert_rom_bytes(self, offset: int, blob: bytes) -> bool:
        """Insert ``blob`` at ``offset`` (``offset`` may be ``len(ROM)`` to append). Returns False on bad bounds."""
        if self._data is None or offset < 0 or offset > len(self._data):
            return False
        self._data[offset:offset] = blob
        self._modified = True
        self._ldr_pc_targets_valid = False
        self._schedule_xref_rebuild()
        self._invalidate_xref_index()
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
        self._refresh_visible()
        self._update_scrollbar()
        return True

    def _dest_accepts_table_write(self, off: int, need: int) -> Tuple[bool, str]:
        """True if ``need`` bytes can be written starting at ``off`` without clobbering non-0xFF (EOF append OK)."""
        if need <= 0:
            return True, ""
        if not self._data or off < 0:
            return False, "Invalid ROM or offset."
        d = self._data
        n = len(d)
        if off > n:
            return False, "Offset is past end of ROM."
        if off == n:
            return True, ""
        end = off + need
        for i in range(off, min(end, n)):
            if d[i] != 0xFF:
                return (
                    False,
                    f"Not enough free space: byte at file 0x{i:X} is 0x{d[i]:02X} (need 0xFF padding here).",
                )
        return True, ""

    def _room_for_table_grow(self, table_end: int, need: int) -> bool:
        """True if new row bytes can be placed at ``table_end`` using only 0xFF padding / EOF growth."""
        ok, _ = self._dest_accepts_table_write(table_end, need)
        return ok

    def write_bytes_at_extend(self, offset: int, data: bytes) -> None:
        """Write ``data`` at ``offset``, extending the ROM if the write ends past ``len(ROM)``."""
        if not self._data or offset < 0:
            return
        n = len(self._data)
        if offset > n:
            return
        for i, b in enumerate(data):
            p = offset + i
            if p < n:
                self._data[p] = b
            else:
                self._data.append(b)
        self._modified = True
        self._ldr_pc_targets_valid = False
        self._invalidate_struct_anchors_cache()
        self._schedule_xref_rebuild()
        self._invalidate_xref_index()
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
        self._refresh_visible()
        self._update_scrollbar()

    def _repoint_anchor_table_for_grow(
        self,
        anchor: Dict[str, Any],
        old_base: int,
        old_total: int,
        new_tail: bytes,
        new_base: int,
        fill_old_with_ff: bool,
        *,
        full_payload: Optional[bytes] = None,
    ) -> Tuple[bool, str]:
        """Move expanded table: copy ``old_total`` bytes from ``old_base``, append ``new_tail``, write at ``new_base``.

        If ``full_payload`` is set (e.g. multi-byte terminator: insert new strides *before* trailing ``0000``),
        it is written as the whole new blob instead of ``old_chunk + new_tail``."""
        if not self._data:
            return False, "No ROM loaded."
        old_chunk = bytes(self._data[old_base : old_base + old_total]) if old_total > 0 else b""
        if full_payload is not None:
            payload = bytes(full_payload)
        else:
            payload = old_chunk + bytes(new_tail)
        total_new = len(payload)
        old_gba = GBA_ROM_BASE + int(old_base)
        new_gba = GBA_ROM_BASE + int(new_base)
        self.write_bytes_at_extend(int(new_base), payload)
        excl = [
            (int(old_base), int(old_base) + max(int(old_total), 4)),
            (int(new_base), int(new_base) + int(total_new)),
        ]
        self.replace_word_aligned_rom_pointers(old_gba, new_gba, exclude_ranges=excl)
        if fill_old_with_ff:
            ob = int(old_base)
            for i in range(ob, ob + int(old_total)):
                if i < len(self._data):
                    self._data[i] = 0xFF
        anchor["Address"] = _toml_named_anchor_address_hex_string(int(new_base))
        return True, ""

    def _repoint_pointed_allocation(
        self,
        old_alloc_lo: int,
        old_alloc_hi: int,
        new_blob: bytes,
        new_alloc_lo: int,
        fill_old_with_ff: bool,
    ) -> Tuple[bool, str]:
        """Write ``new_blob`` at ``new_alloc_lo``; repoint all u32 == old start; optionally FF-fill ``[old_alloc_lo, old_alloc_hi)``."""
        if not self._data:
            return False, "No ROM loaded."
        old_lo = int(old_alloc_lo)
        old_hi = int(old_alloc_hi)
        new_lo = int(new_alloc_lo)
        nb = bytes(new_blob)
        need = len(nb)
        if need <= 0:
            return False, "Internal: empty payload."
        old_gba = GBA_ROM_BASE + old_lo
        new_gba = GBA_ROM_BASE + new_lo
        self.write_bytes_at_extend(new_lo, nb)
        excl = [
            (old_lo, old_lo + max(old_hi - old_lo, 4)),
            (new_lo, new_lo + need),
        ]
        self.replace_word_aligned_rom_pointers(old_gba, new_gba, exclude_ranges=excl)
        if fill_old_with_ff:
            for i in range(old_lo, old_hi):
                if i < len(self._data):
                    self._data[i] = 0xFF
        self._modified = True
        self._schedule_xref_rebuild()
        self._invalidate_xref_index()
        self._refresh_visible()
        return True, ""

    def _struct_list_name_for_append_labels(self, struct_info: Dict[str, Any]) -> Optional[str]:
        """If this struct's row count is driven by a ``[[List]]``, return that list's TOML ``Name`` for new labels."""
        elk = struct_info.get("entry_label_list")
        if elk:
            lk = normalize_named_anchor_lookup_key(str(elk).strip())
            if lk in _load_toml_lists(self._toml_data):
                return str(elk).strip()
        cr = struct_info.get("count_ref")
        if cr and isinstance(cr, str):
            base = _struct_count_ref_base_name(str(cr).strip())
            lk = normalize_named_anchor_lookup_key(base)
            if lk in _load_toml_lists(self._toml_data):
                return base
        return None

    def _append_list_placeholders_mut(self, list_name: str, n: int) -> Tuple[bool, str]:
        """Append ``n`` lines ``New entry {index}`` to ``[[List]]`` (mutates ``self._toml_data`` only)."""
        if n <= 0:
            return False, "Count must be positive."
        rows = self._toml_data.get("List")
        if not isinstance(rows, list):
            return False, "TOML has no [[List]] section."
        want = normalize_named_anchor_lookup_key(list_name.strip())
        target: Optional[Dict[str, Any]] = None
        for row in rows:
            if not isinstance(row, dict):
                continue
            if normalize_named_anchor_lookup_key(str(row.get("Name", ""))) == want:
                target = row
                break
        if target is None:
            return False, f"[[List]] not found: {list_name!r}"
        hi = self._resolve_list_entry_span_end(list_name.strip())
        if hi is None:
            hi = 0
        z = target.get(0)
        if isinstance(z, list):
            for i in range(n):
                z.append(f"New entry {hi + i}")
        else:
            for i in range(n):
                target[hi + i] = f"New entry {hi + i}"
        return True, ""

    def _replace_pcs_format_literal_count(self, anchor: Dict[str, Any], new_count: int) -> bool:
        fmt = normalize_named_anchor_format(anchor.get("Format", ""))
        parsed = self._parse_pcs_format(fmt)
        if not parsed:
            return False
        _field, _w, ln, _enc = parsed
        if not isinstance(ln, int):
            return False
        m = re.search(r"\](\d+)\s*$", fmt)
        if not m:
            return False
        anchor["Format"] = fmt[: m.start(1)] + str(int(new_count)) + fmt[m.end(1) :]
        return True

    def _replace_struct_format_literal_count(self, anchor: Dict[str, Any], new_count: int) -> bool:
        raw_in = str(anchor.get("Format", "")).strip()
        has_caret = raw_in.startswith("^")
        body = raw_in[1:].strip() if has_caret else raw_in
        # Packed ``[inner]!HEX`` shorthand: strip any legacy ``]N``; do not add ``Count`` (row count stays in Format / ROM).
        m_short = re.match(r"^\[([^\[\]]*)\]!([0-9a-fA-F]{2,})(?:\](\d+))?\s*$", body)
        if m_short:
            inner, hx = m_short.group(1), m_short.group(2)
            if int(new_count) <= 0:
                return False
            anchor["Format"] = ("^" if has_caret else "") + f"[{inner}]!{hx}"
            anchor.pop("Count", None)
            return True
        # Bare YDK deck line: `` `ydk`Anchor[card:List]N`` (no outer ``[``) — common in TOML before normalization.
        m_bare_ydk = re.match(
            r"^(\s*`ydk`\s*[\w.]+\s*\[\s*card\s*:\s*[\w.]+\s*\])(\d+)\s*$",
            body,
            re.IGNORECASE | re.DOTALL,
        )
        if m_bare_ydk:
            if int(new_count) <= 0:
                return False
            anchor["Format"] = ("^" if has_caret else "") + m_bare_ydk.group(1) + str(int(new_count))
            return True
        cr = _parse_struct_count(raw_in)
        if not isinstance(cr, int):
            return False
        # Standard ``[…]count`` (depth-balanced): replace trailing literal integer after outer ``]``.
        s = body
        depth = 0
        for i, ch in enumerate(s):
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    anchor["Format"] = ("^" if has_caret else "") + s[: i + 1] + str(int(new_count))
                    return True
        return False

    def _ydk_maybe_bump_anchor_literal_after_import(
        self, anchor: Dict[str, Any], fmt_raw: str, min_table_rows: int
    ) -> Optional[str]:
        """Bare `` `ydk`…[card:…]N``: if the table needs more than *N* rows, raise the trailing count in TOML."""
        cur = _parse_bare_ydk_deck_shorthand_trailing_count(fmt_raw)
        if cur is None or min_table_rows <= cur:
            return None
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return None
        if not self._replace_struct_format_literal_count(anchor, min_table_rows):
            return None
        ok, err = self.persist_toml_data()
        if not ok:
            return f"Could not save TOML ({err})."
        return f"Structure Format ]count: {cur} → {min_table_rows}."

    def _write_matched_word_numeric_value(self, mw_name: str, value: int) -> bool:
        """Write little-endian integer to the MatchedWord row named ``mw_name`` in ROM."""
        want = str(mw_name).strip()
        for mw in self._toml_data.get("MatchedWords", []) or []:
            if not isinstance(mw, dict):
                continue
            if str(mw.get("Name", "")).strip() != want:
                continue
            fo = _toml_address_value_to_file_offset(mw.get("Address"))
            if fo is None or fo < 0 or not self._data:
                return False
            try:
                ln = int(mw.get("Length", 1))
            except (ValueError, TypeError):
                ln = 1
            if ln <= 0:
                ln = 1
            v = int(value)
            for i in range(ln):
                if fo + i >= len(self._data):
                    return False
                self._data[fo + i] = (v >> (8 * i)) & 0xFF
            return True
        return False

    def append_pcs_table_rows(self, pcs_info: Dict[str, Any], n: int) -> Tuple[bool, str]:
        """Add ``n`` empty PCS/ASCII slots at the end of a string table; update Format or MatchedWord count."""
        if n <= 0:
            return False, "Count must be positive."
        if not self._data:
            return False, "No ROM loaded."
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return False, "Save or load a structure TOML next to the ROM before adding rows."
        anchor = pcs_info["anchor"]
        width = int(pcs_info["width"])
        old_count = int(pcs_info["count"])
        enc = pcs_info.get("encoding", "pcs")
        addr = anchor.get("Address")
        if addr is None:
            return False, "Anchor has no Address."
        try:
            gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
            if gba < GBA_ROM_BASE:
                gba += GBA_ROM_BASE
            base_off = gba - GBA_ROM_BASE
        except (ValueError, TypeError):
            return False, "Bad anchor Address."
        fmt = normalize_named_anchor_format(anchor.get("Format", ""))
        parsed = self._parse_pcs_format(fmt)
        if not parsed:
            return False, "Could not parse PCS Format."
        _f, _w, length_part, _enc = parsed
        insert_off = base_off + old_count * width
        parts = bytearray()
        for _ in range(n):
            if enc == "ascii":
                parts.extend(encode_ascii_slot("", width))
            else:
                parts.extend(encode_pcs_string("", width))
        blob = bytes(parts)
        need = len(blob)
        old_total = old_count * width
        total_expanded = old_total + need

        def _apply_pcs_metadata() -> Tuple[bool, str, bool]:
            toml_changed = False
            if isinstance(length_part, int):
                if not self._replace_pcs_format_literal_count(anchor, old_count + n):
                    return False, "Could not update PCS Format row count.", False
                toml_changed = True
            else:
                ref = str(length_part).strip()
                if not self._write_matched_word_numeric_value(ref, old_count + n):
                    return (
                        False,
                        f"Could not write MatchedWord {ref!r} (not found, or ROM range invalid).",
                        False,
                    )
            return True, "", toml_changed

        parent = self.winfo_toplevel()
        if self._room_for_table_grow(insert_off, need):
            ok_m, err_m, toml_changed = _apply_pcs_metadata()
            if not ok_m:
                return False, err_m
            self.write_bytes_at_extend(insert_off, blob)
            if toml_changed:
                ok, err = self.persist_toml_data()
                if not ok:
                    return False, err
            self._invoke_anchor_refresh_callback()
            self._do_goto(int(insert_off))
            return True, ""

        dlg = _TableGrowRepointDialog(
            parent,
            self,
            total_expanded,
            base_off,
            base_off + old_total,
            base_off,
            f"PCS table {pcs_info.get('name', '')!r}",
        )
        if dlg.result is None:
            return False, "Cancelled."
        new_base, fill_old = dlg.result
        ok_m, err_m, toml_changed = _apply_pcs_metadata()
        if not ok_m:
            return False, err_m
        ok_r, err_r = self._repoint_anchor_table_for_grow(
            anchor, base_off, old_total, blob, new_base, fill_old
        )
        if not ok_r:
            return False, err_r
        if toml_changed:
            ok, err = self.persist_toml_data()
            if not ok:
                return False, err
        self._invoke_anchor_refresh_callback()
        self._do_goto(int(new_base))
        return True, ""

    def _append_packed_terminator_struct_rows(
        self, struct_info: Dict[str, Any], n: int, fill_spec: str = "00"
    ) -> Tuple[bool, str]:
        """Grow a packed ``!HEX>inline`` table: append ``n`` rows after the last ``!`` (each row = fill × stride + terminator)."""
        name = str(struct_info.get("name", "")).strip()
        info = self.find_struct_anchor_by_name(name)
        if not info:
            return False, f"Struct {name!r} not found."
        if not info.get("packed_terminator") or not info.get("packed_terminator_fd"):
            return False, "Internal: expected a packed !HEX terminator table."
        na_fd = info["packed_terminator_fd"]
        term = bytes(na_fd["terminator"])
        stride = int(na_fd["inner_stride"])
        if not term or stride < 1:
            return False, "Invalid terminator or inner stride in struct Format."
        fill_row, ferr = _fill_bytes_from_spec(fill_spec, stride)
        if fill_row is None:
            return False, ferr or "Invalid fill pattern."
        anchor = info["anchor"]
        old_count = int(info["count"])
        base_off = int(info["base_off"])
        cr = info.get("count_ref")
        fmt_raw = str(anchor.get("Format", "")).strip()
        fmt_n = normalize_named_anchor_format(anchor.get("Format", ""))
        count_raw = _parse_struct_count(fmt_n)

        data = bytes(self._data)
        span = _packed_terminator_table_span_bytes(data, base_off, old_count, na_fd)
        if span is None:
            return (
                False,
                "Could not measure packed table (missing terminators, truncated ROM, or incomplete last row).",
            )
        old_total = int(span)
        tl = len(term)
        term_start = base_off + old_total - tl
        old_chunk = data[base_off : base_off + old_total]
        can_before_trailing = (
            _packed_grow_inserts_before_trailing_terminator(term)
            and old_total >= tl
            and term_start >= base_off
            and term_start + tl <= len(data)
            and data[term_start : term_start + tl] == term
        )
        blob_before = fill_row * n + term
        full_payload_before: Optional[bytes] = (
            old_chunk[:-tl] + blob_before if can_before_trailing and len(old_chunk) >= tl else None
        )

        def _apply_struct_metadata() -> Tuple[bool, str, bool]:
            toml_changed = False
            list_nm = self._struct_list_name_for_append_labels(info)
            if list_nm:
                ok, err = self._append_list_placeholders_mut(list_nm, n)
                if not ok:
                    return False, err, False
                toml_changed = True
            elif isinstance(cr, str):
                base = _struct_count_ref_base_name(str(cr).strip())
                if self._resolve_table_length(base) is not None:
                    if not self._write_matched_word_numeric_value(base, old_count + n):
                        return False, f"Could not update MatchedWord {base!r} in ROM.", False
                elif any(str(p["name"]) == base for p in self._get_pcs_table_anchors()):
                    return (
                        False,
                        "This struct's ]count references another PCS table. Add rows to that PCS table first, then reload.",
                        False,
                    )
                elif isinstance(count_raw, str):
                    return (
                        False,
                        f"Unsupported ]count reference {count_raw!r} for adding rows (use a List, literal count, or MatchedWord).",
                        False,
                    )
            elif isinstance(count_raw, int):
                if not self._replace_struct_format_literal_count(anchor, old_count + n):
                    return False, "Could not update struct Format row count.", False
                toml_changed = True
            else:
                return False, "Could not determine how this table's size is stored (List / literal / MatchedWord).", False
            return True, "", toml_changed

        parent = self.winfo_toplevel()
        # Multi-byte terminators (e.g. 0000): insert new strides *before* the trailing terminator.
        if (
            full_payload_before is not None
            and _room_overwrite_expand_at_terminator(data, term_start, term, blob_before)
        ):
            ok_m, err_m, toml_changed = _apply_struct_metadata()
            if not ok_m:
                return False, err_m
            self.write_bytes_at_extend(term_start, blob_before)
            if toml_changed:
                ok, err = self.persist_toml_data()
                if not ok:
                    return False, err
            self._invoke_anchor_refresh_callback()
            self._do_goto(int(term_start))
            return True, ""

        blob_append = (fill_row + term) * n
        insert_off_append = base_off + old_total
        if full_payload_before is not None:
            total_expanded = len(full_payload_before)
        else:
            total_expanded = old_total + len(blob_append)

        if full_payload_before is None and self._room_for_table_grow(insert_off_append, len(blob_append)):
            ok_m, err_m, toml_changed = _apply_struct_metadata()
            if not ok_m:
                return False, err_m
            self.write_bytes_at_extend(insert_off_append, blob_append)
            if toml_changed:
                ok, err = self.persist_toml_data()
                if not ok:
                    return False, err
            self._invoke_anchor_refresh_callback()
            self._do_goto(int(insert_off_append))
            return True, ""

        dlg = _TableGrowRepointDialog(
            parent,
            self,
            total_expanded,
            base_off,
            base_off + old_total,
            base_off,
            f"Struct table {name!r} (packed !HEX)",
        )
        if dlg.result is None:
            return False, "Cancelled."
        new_base, fill_old = dlg.result
        ok_m, err_m, toml_changed = _apply_struct_metadata()
        if not ok_m:
            return False, err_m
        if full_payload_before is not None:
            ok_r, err_r = self._repoint_anchor_table_for_grow(
                anchor, base_off, old_total, b"", new_base, fill_old, full_payload=full_payload_before
            )
        else:
            ok_r, err_r = self._repoint_anchor_table_for_grow(
                anchor, base_off, old_total, blob_append, new_base, fill_old
            )
        if not ok_r:
            return False, err_r
        if toml_changed:
            ok, err = self.persist_toml_data()
            if not ok:
                return False, err
        self._invoke_anchor_refresh_callback()
        self._do_goto(int(new_base))
        return True, ""

    def _append_per_row_terminator_slots(
        self,
        struct_info: Dict[str, Any],
        n: int,
        entry_idx: int,
        fill_spec: str,
        repoint_parent: Optional[tk.Misc],
    ) -> Tuple[bool, str]:
        """Per-row ``!`` nested blob: insert ``n`` element strides of fill bytes before the terminator."""
        name = str(struct_info.get("name", "")).strip()
        info = self.find_struct_anchor_by_name(name)
        if not info:
            return False, f"Struct {name!r} not found."
        fields = list(info.get("fields") or [])
        na_fd = _struct_per_row_terminator_nested_field(fields)
        if not na_fd:
            return False, "Internal: expected a per-row ! terminator nested field."
        old_count = int(info["count"])
        if old_count <= 0:
            return False, "Struct has no rows."
        ei = max(0, min(int(entry_idx), old_count - 1))
        struct_size = int(info["struct_size"])
        base_off = int(info["base_off"])
        entry_base = base_off + ei * struct_size
        term = bytes(na_fd["terminator"])
        stride = int(na_fd["inner_stride"])
        if not term or stride < 1:
            return False, "Invalid terminator or inner stride in struct Format."
        fill_chunk, ferr = _fill_bytes_from_spec(fill_spec, n * stride)
        if fill_chunk is None:
            return False, ferr or "Invalid fill pattern."
        data = bytes(self._data)
        na_base = _nested_array_data_base_file(entry_base, na_fd, fields, data)
        if na_base is None:
            return False, "Could not resolve nested list pointer (invalid GBA pointer?)."
        end = _terminator_nested_row_end_exclusive_pointer_blob(data, na_base, stride, term)
        if end is None:
            return False, "Could not find nested ! terminator for this row (truncated ROM?)."
        term_start = end - len(term)
        blob = fill_chunk + term
        if _room_expand_terminator_run_inplace(data, term_start, term, len(fill_chunk)):
            self.write_bytes_at_extend(term_start, blob)
            self._invoke_anchor_refresh_callback()
            self._do_goto(int(term_start))
            return True, ""

        reloc = _ptr_word_off_and_alloc_start(entry_base, na_fd, fields, data)
        if reloc is None:
            return (
                False,
                "Not enough 0xFF padding after the nested terminator to grow in place, and this layout has no "
                "relocatable pointer (inline nested data). Free space or change the format.",
            )
        _poff, ptr_lo, na_chk = reloc
        if na_chk != na_base:
            return False, "Internal: nested base mismatch."
        prefix = data[ptr_lo:na_base]
        expanded = data[na_base:term_start] + fill_chunk + term
        new_blob = prefix + expanded
        need = len(new_blob)
        if na_fd.get("base_ptr_field"):
            ptr_label = str(na_fd["base_ptr_field"])
        elif na_fd.get("nested_ptr_is_self_field"):
            ptr_label = str(na_fd.get("name") or "pointer")
        else:
            ptr_label = "pointer"
        desc = f"Struct {name!r}, row index {ei}."
        par = repoint_parent if repoint_parent is not None else self.winfo_toplevel()
        dlg = _PointedBlobRepointDialog(
            par,
            self,
            need,
            ptr_lo,
            end,
            ptr_lo,
            ptr_label,
            desc,
        )
        if dlg.result is None:
            return False, "Cancelled."
        new_off, fill_old = dlg.result
        ok_r, err_r = self._repoint_pointed_allocation(ptr_lo, end, new_blob, new_off, fill_old)
        if not ok_r:
            return False, err_r
        self._invoke_anchor_refresh_callback()
        self._do_goto(int(new_off))
        return True, ""

    def expand_struct_table_slots(
        self,
        struct_info: Dict[str, Any],
        n: int,
        entry_idx: int = 0,
        *,
        fill_spec: str = "00",
        repoint_parent: Optional[tk.Misc] = None,
    ) -> Tuple[bool, str]:
        """Grow a ``!``-terminated nested table: packed rows at the anchor base, or slots inside the selected row's blob."""
        if n <= 0:
            return False, "Count must be positive."
        if not self._data:
            return False, "No ROM loaded."
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return False, "Save or load a structure TOML next to the ROM before editing."
        if struct_info.get("packed_terminator") and struct_info.get("packed_terminator_fd"):
            return self._append_packed_terminator_struct_rows(struct_info, n, fill_spec=fill_spec)
        fields = list(struct_info.get("fields") or [])
        if not _struct_per_row_terminator_nested_field(fields):
            return False, "This struct has no !-terminated nested table to expand."
        return self._append_per_row_terminator_slots(
            struct_info, n, entry_idx, fill_spec, repoint_parent
        )

    def append_struct_table_rows(self, struct_info: Dict[str, Any], n: int) -> Tuple[bool, str]:
        """Add ``n`` top-level struct rows (fixed stride or packed ``!`` at the table base)."""
        if n <= 0:
            return False, "Count must be positive."
        if not self._data:
            return False, "No ROM loaded."
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return False, "Save or load a structure TOML next to the ROM before adding rows."
        if struct_info.get("packed_terminator") and struct_info.get("packed_terminator_fd"):
            return self._append_packed_terminator_struct_rows(struct_info, n)
        name = str(struct_info.get("name", "")).strip()
        info = self.find_struct_anchor_by_name(name)
        if not info:
            return False, f"Struct {name!r} not found."
        anchor = info["anchor"]
        old_count = int(info["count"])
        struct_size = int(info["struct_size"])
        base_off = int(info["base_off"])
        cr = info.get("count_ref")
        fmt_raw = str(anchor.get("Format", "")).strip()
        fmt_n = normalize_named_anchor_format(anchor.get("Format", ""))
        count_raw = _parse_struct_count(fmt_n)
        insert_off = base_off + old_count * struct_size
        blob = b"\x00" * (n * struct_size)
        need = len(blob)
        old_total = old_count * struct_size
        total_expanded = old_total + need

        def _apply_struct_metadata() -> Tuple[bool, str, bool]:
            toml_changed = False
            list_nm = self._struct_list_name_for_append_labels(info)
            if list_nm:
                ok, err = self._append_list_placeholders_mut(list_nm, n)
                if not ok:
                    return False, err, False
                toml_changed = True
            elif isinstance(cr, str):
                base = _struct_count_ref_base_name(str(cr).strip())
                if self._resolve_table_length(base) is not None:
                    if not self._write_matched_word_numeric_value(base, old_count + n):
                        return False, f"Could not update MatchedWord {base!r} in ROM.", False
                elif any(str(p["name"]) == base for p in self._get_pcs_table_anchors()):
                    return (
                        False,
                        "This struct's ]count references another PCS table. Add rows to that PCS table first, then reload.",
                        False,
                    )
                elif isinstance(count_raw, str):
                    return (
                        False,
                        f"Unsupported ]count reference {count_raw!r} for adding rows (use a List, literal count, or MatchedWord).",
                        False,
                    )
            elif isinstance(count_raw, int):
                if not self._replace_struct_format_literal_count(anchor, old_count + n):
                    return False, "Could not update struct Format row count.", False
                toml_changed = True
            else:
                return False, "Could not determine how this table's size is stored (List / literal / MatchedWord).", False
            return True, "", toml_changed

        parent = self.winfo_toplevel()
        if self._room_for_table_grow(insert_off, need):
            ok_m, err_m, toml_changed = _apply_struct_metadata()
            if not ok_m:
                return False, err_m
            self.write_bytes_at_extend(insert_off, blob)
            if toml_changed:
                ok, err = self.persist_toml_data()
                if not ok:
                    return False, err
            self._invoke_anchor_refresh_callback()
            self._do_goto(int(insert_off))
            return True, ""

        dlg = _TableGrowRepointDialog(
            parent,
            self,
            total_expanded,
            base_off,
            base_off + old_total,
            base_off,
            f"Struct table {name!r}",
        )
        if dlg.result is None:
            return False, "Cancelled."
        new_base, fill_old = dlg.result
        ok_m, err_m, toml_changed = _apply_struct_metadata()
        if not ok_m:
            return False, err_m
        ok_r, err_r = self._repoint_anchor_table_for_grow(
            anchor, base_off, old_total, blob, new_base, fill_old
        )
        if not ok_r:
            return False, err_r
        if toml_changed:
            ok, err = self.persist_toml_data()
            if not ok:
                return False, err
        self._invoke_anchor_refresh_callback()
        self._do_goto(int(new_base))
        return True, ""

    def update_toml_list_string_at_index(self, list_name: str, flat_index: int, new_label: str) -> bool:
        """Update one string in ``[[List]]`` and rewrite the TOML file on disk."""
        _try_import_tomli_w()
        if not _TOMLI_W_AVAILABLE or tomli_w is None:
            messagebox.showerror("Struct", _tomli_w_missing_message())
            return False
        if not self._toml_path or not os.path.isfile(self._toml_path):
            messagebox.showerror(
                "Struct",
                "No TOML file to write (open a ROM with a .toml, or use Load structure TOML).",
            )
            return False
        rows = self._toml_data.get("List")
        if not isinstance(rows, list):
            messagebox.showerror("Struct", "TOML has no [[List]] section.")
            return False
        target: Optional[Dict[str, Any]] = None
        want = normalize_named_anchor_lookup_key(list_name.strip())
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = normalize_named_anchor_lookup_key(str(row.get("Name", "")))
            if name == want:
                target = row
                break
        if target is None:
            messagebox.showerror("Struct", f"[[List]] entry not found: {list_name!r}")
            return False
        coords = _list_row_key_and_offset(target, flat_index)
        if coords is None:
            messagebox.showerror(
                "Struct",
                f"Index {flat_index} is not defined in [[List]] {list_name!r}.",
            )
            return False
        key, off = coords
        val = target[key]
        if isinstance(val, list):
            if off < 0 or off >= len(val):
                return False
            val[off] = new_label
        else:
            if off != 0:
                return False
            target[key] = new_label
        try:
            _write_toml_file_unquoted_hex_addresses(self._toml_path, self._toml_data)
        except OSError as e:
            messagebox.showerror("Struct", f"Could not write TOML:\n{e}")
            return False
        except Exception as e:
            messagebox.showerror("Struct", f"TOML write failed:\n{e}")
            return False
        return True

    def get_list_entry_label(self, list_name: str, flat_index: int) -> Optional[str]:
        """Return the string at ``flat_index`` in ``[[List]]`` with this Name, or None.

        ``list_name`` may include a trailing ``+N`` / ``-N`` (same convention as ``]pcsName±N`` struct/graphics
        counts). The base name selects the [[List]] row; the index passed here is a **table row** (0..N-1), so the
        list key used is ``flat_index - N`` when the suffix is ``+N`` (same mapping as Entry PCS vs PCS row count).
        """
        base, delta = _split_enum_field_ref(list_name)
        want = normalize_named_anchor_lookup_key(base.strip())
        if not want:
            return None
        list_idx = flat_index - delta
        for row in self._toml_data.get("List", []) or []:
            if not isinstance(row, dict):
                continue
            name = normalize_named_anchor_lookup_key(str(row.get("Name", "")))
            if name != want:
                continue
            coords = _list_row_key_and_offset(row, list_idx)
            if coords is None:
                return None
            key, off = coords
            val = row[key]
            if isinstance(val, list):
                if 0 <= off < len(val):
                    return str(val[off]).strip().strip("'\"")
                return None
            if off == 0:
                return str(val).strip().strip("'\"")
            return None
        return None

    def update_named_anchor_gba_address(self, anchor_name: str, gba_addr: int) -> Tuple[bool, str]:
        """Persist ``Address`` for a ``[[NamedAnchors]]`` row: ROM **file offset** as hex (``0x…``), no ``0x08`` prefix.

        ``gba_addr`` may be a full GBA ROM pointer (``0x08xxxxxx``) or a file offset; file offset is what gets stored.
        """
        ok, err, _ = self.update_named_anchor_address_and_format(
            anchor_name, gba_addr=gba_addr, new_format=None, create_if_missing=False
        )
        return ok, err

    def update_named_anchor_address_and_format(
        self,
        anchor_name: str,
        *,
        gba_addr: Optional[int] = None,
        new_format: Optional[str] = None,
        create_if_missing: bool = False,
    ) -> Tuple[bool, str, Optional[str]]:
        """
        Update ``Address`` and/or ``Format`` on a ``[[NamedAnchors]]`` row (needs tomli-w).

        If ``create_if_missing`` is True and no row matches ``Name``, appends a **new**
        ``[[NamedAnchors]]`` entry (requires both ``gba_addr`` and ``new_format``). Used when
        importing graphics under a new logical name that is not in the TOML yet.

        Returns ``(ok, message, action)`` where ``action`` is ``\"updated\"``, ``\"created\"``, or ``None`` on failure.
        """
        _try_import_tomli_w()
        if not _TOMLI_W_AVAILABLE or tomli_w is None:
            return False, _tomli_w_missing_message(), None
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return False, "No TOML file path set (open a ROM with a .toml beside it).", None
        if gba_addr is None and new_format is None:
            return False, "Nothing to update (need gba_addr and/or new_format).", None
        file_off: Optional[int] = None
        if gba_addr is not None:
            g = int(gba_addr)
            if GBA_ROM_BASE <= g <= GBA_ROM_MAX:
                file_off = g - GBA_ROM_BASE
            elif 0 <= g < GBA_ROM_BASE:
                file_off = g
            else:
                return False, f"Invalid ROM address for TOML: 0x{g:X}", None
        want = normalize_named_anchor_lookup_key(anchor_name)
        if not want:
            return False, "NamedAnchor name is empty (check quotes/backticks).", None
        want_lower = want.lower()
        if "NamedAnchors" not in self._toml_data or self._toml_data.get("NamedAnchors") is None:
            self._toml_data["NamedAnchors"] = []
        rows_raw = self._toml_data.get("NamedAnchors")
        if not isinstance(rows_raw, list):
            return (
                False,
                "TOML has no [[NamedAnchors]] array (structure file missing or not loaded next to this ROM).",
                None,
            )
        rows: List[Dict[str, Any]] = [a for a in rows_raw if isinstance(a, dict)]
        match: Optional[Dict[str, Any]] = None
        for anchor in rows:
            n = _named_anchor_row_name_field(anchor)
            if not n:
                continue
            if n == want:
                match = anchor
                break
        if match is None:
            for anchor in rows:
                n = _named_anchor_row_name_field(anchor)
                if not n:
                    continue
                if n.lower() == want_lower:
                    match = anchor
                    break
        action: str = "updated"
        if match is None:
            if create_if_missing and file_off is not None and new_format is not None:
                match = {
                    "Name": want,
                    "Address": _toml_named_anchor_address_hex_string(file_off),
                    "Format": new_format,
                    # Placeholder; Channeler may recompute when you next save from the main tool.
                    "DefaultHash": "00000000",
                }
                rows_raw.append(match)
                action = "created"
            else:
                samples: List[str] = []
                for anchor in rows[:200]:
                    n = _named_anchor_row_name_field(anchor)
                    if n and n not in samples:
                        samples.append(n)
                    if len(samples) >= 6:
                        break
                extra = ""
                if samples:
                    show = ", ".join(repr(s) for s in samples[:5])
                    if len(samples) > 5:
                        show += ", …"
                    extra = f" First name(s) in this TOML: {show}."
                hint = ""
                if create_if_missing and (file_off is None or new_format is None):
                    hint = " To add a new row, both a destination address and Format must be set."
                tp = self._toml_path or "(unknown)"
                return (
                    False,
                    f"NamedAnchor not found: {anchor_name!r} (normalized {want!r}). "
                    f"Must match [[NamedAnchors]] Name in: {tp}.{extra}{hint}",
                    None,
                )
        if file_off is not None:
            match["Address"] = _toml_named_anchor_address_hex_string(file_off)
        if new_format is not None:
            match["Format"] = new_format
        try:
            _write_toml_file_unquoted_hex_addresses(self._toml_path, self._toml_data)
        except OSError as e:
            return False, str(e), None
        return True, "", action

    def persist_toml_data(self) -> Tuple[bool, str]:
        """Write ``self._toml_data`` to ``self._toml_path`` (requires tomli-w)."""
        _try_import_tomli_w()
        if not _TOMLI_W_AVAILABLE or tomli_w is None:
            return False, _tomli_w_missing_message()
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return False, "No TOML file path set."
        try:
            _write_toml_file_unquoted_hex_addresses(self._toml_path, self._toml_data)
        except OSError as e:
            return False, str(e)
        return True, ""

    def _propagate_matched_word_byte_change(self, off: int, old_b: int, new_b: int) -> None:
        """When a byte inside a ``[[MatchedWords]]`` range changes, apply the same delta to the **same slot**
        in **other** instances (other ``Address`` rows with that ``Name``).

        Bytes at other indices within the edited row are left alone (e.g. length-2 words: editing byte 0 does
        not change byte 1 in the same ROM span).
        """
        if self._suppress_matched_word_propagate:
            return
        if old_b == new_b:
            return
        if not self._data or off < 0 or off >= len(self._data):
            return
        rows = self._toml_data.get("MatchedWords")
        if not isinstance(rows, list):
            return
        names: Set[str] = set()
        idx_within: Optional[int] = None
        for row in rows:
            if not isinstance(row, dict):
                continue
            nm = str(row.get("Name", "")).strip()
            if not nm:
                continue
            fo = _toml_address_value_to_file_offset(row.get("Address"))
            if fo is None or fo < 0:
                continue
            try:
                ln = int(row.get("Length", 1))
            except (ValueError, TypeError):
                ln = 1
            if ln <= 0:
                ln = 1
            if fo <= off < fo + ln:
                names.add(nm)
                if idx_within is None:
                    idx_within = off - fo
        if not names or idx_within is None:
            return
        delta = new_b - old_b
        self._suppress_matched_word_propagate = True
        try:
            for row in rows:
                if not isinstance(row, dict):
                    continue
                nm = str(row.get("Name", "")).strip()
                if nm not in names:
                    continue
                fo = _toml_address_value_to_file_offset(row.get("Address"))
                if fo is None or fo < 0:
                    continue
                try:
                    ln = int(row.get("Length", 1))
                except (ValueError, TypeError):
                    ln = 1
                if ln <= 0:
                    ln = 1
                # Do not touch other bytes in the instance the user edited.
                if fo <= off < fo + ln:
                    continue
                if idx_within >= ln:
                    continue
                o = fo + idx_within
                if o < 0 or o >= len(self._data):
                    continue
                self._data[o] = (self._data[o] + delta) & 0xFF
        finally:
            self._suppress_matched_word_propagate = False

    def open_matched_words_editor(self) -> None:
        """Dialog to edit ``[[MatchedWords]]`` Address / Length / Offset; saves the structure TOML with hex addresses."""
        rows_raw = self._toml_data.get("MatchedWords")
        if not isinstance(rows_raw, list) or not rows_raw:
            messagebox.showinfo("Matched words", "No [[MatchedWords]] section in the structure TOML.")
            return
        if not self._toml_path or not os.path.isfile(self._toml_path):
            messagebox.showwarning(
                "Matched words",
                "No structure TOML file on disk — use Load structure TOML or open a ROM with a paired .toml first.",
            )
            return
        parent = self.winfo_toplevel()
        d = tk.Toplevel(parent)
        d.title("Matched Words")
        d.transient(parent)
        d.minsize(520, 420)

        outer = ttk.Frame(d, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)

        tv = ttk.Treeview(
            outer,
            columns=("name", "address", "length", "offset"),
            show="headings",
            height=14,
            selectmode="browse",
        )
        tv.heading("name", text="Name")
        tv.heading("address", text="Address")
        tv.heading("length", text="Length")
        tv.heading("offset", text="Offset")
        tv.column("name", width=220, stretch=True)
        tv.column("address", width=100, stretch=False)
        tv.column("length", width=56, stretch=False)
        tv.column("offset", width=56, stretch=False)
        sb = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.grid(row=0, column=0, sticky="nsew")
        sb.grid(row=0, column=1, sticky="ns")
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)

        def row_display_vals(r: Dict[str, Any]) -> Tuple[str, str, str, str]:
            nm = str(r.get("Name", ""))
            addr = r.get("Address", "")
            ln = r.get("Length", 1)
            off = r.get("Offset", "")
            off_s = "" if off == "" or off is None else str(off)
            return (nm, str(addr), str(ln), off_s)

        for i, row in enumerate(rows_raw):
            if not isinstance(row, dict):
                continue
            tv.insert("", tk.END, iid=str(i), values=row_display_vals(row))

        edit_fr = ttk.LabelFrame(outer, text="Edit selected row", padding=6)
        edit_fr.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        ttk.Label(edit_fr, text="Address (hex or file offset):").grid(row=0, column=0, sticky="w")
        addr_var = tk.StringVar(value="")
        len_var = tk.StringVar(value="1")
        off_var = tk.StringVar(value="")

        addr_e = ttk.Entry(edit_fr, textvariable=addr_var, width=22)
        addr_e.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        ttk.Label(edit_fr, text="Length:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        ttk.Entry(edit_fr, textvariable=len_var, width=8).grid(row=1, column=1, sticky="w", padx=(4, 0), pady=(4, 0))
        ttk.Label(edit_fr, text="Offset (optional):").grid(row=2, column=0, sticky="w", pady=(4, 0))
        ttk.Entry(edit_fr, textvariable=off_var, width=8).grid(row=2, column=1, sticky="w", padx=(4, 0), pady=(4, 0))
        edit_fr.columnconfigure(1, weight=1)

        name_lbl = ttk.Label(edit_fr, text="", wraplength=480)
        name_lbl.grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))

        def load_selection(*_a: Any) -> None:
            sel = tv.selection()
            if not sel:
                return
            i = int(sel[0])
            row = rows_raw[i]
            if not isinstance(row, dict):
                return
            addr_var.set(str(row.get("Address", "")))
            len_var.set(str(row.get("Length", 1)))
            o = row.get("Offset", "")
            off_var.set("" if o == "" or o is None else str(o))
            name_lbl.config(text=f"Name: {row.get('Name', '')}")

        tv.bind("<<TreeviewSelect>>", load_selection)
        kids = tv.get_children()
        if kids:
            tv.selection_set(kids[0])
            tv.focus(kids[0])
            load_selection()

        def apply_row() -> None:
            sel = tv.selection()
            if not sel:
                messagebox.showwarning("Matched words", "Select a row.", parent=d)
                return
            i = int(sel[0])
            row = rows_raw[i]
            if not isinstance(row, dict):
                return
            try:
                s = addr_var.get().strip()
                gba = int(s, 0)
            except ValueError:
                messagebox.showerror("Matched words", "Address must be a hex or decimal integer (e.g. 0x15B7CC8).", parent=d)
                return
            if gba < GBA_ROM_BASE:
                gba += GBA_ROM_BASE
            fo = gba - GBA_ROM_BASE
            if fo < 0:
                messagebox.showerror("Matched words", "Address resolves to a negative file offset.", parent=d)
                return
            try:
                ln = int(len_var.get().strip(), 0)
            except ValueError:
                messagebox.showerror("Matched words", "Length must be an integer.", parent=d)
                return
            if ln < 1:
                messagebox.showerror("Matched words", "Length must be at least 1.", parent=d)
                return
            off_txt = off_var.get().strip()
            if off_txt == "":
                row.pop("Offset", None)
            else:
                try:
                    row["Offset"] = int(off_txt, 0)
                except ValueError:
                    messagebox.showerror("Matched words", "Offset must be an integer or empty.", parent=d)
                    return
            row["Address"] = _toml_named_anchor_address_hex_string(fo)
            row["Length"] = ln
            ok, err = self.persist_toml_data()
            if not ok:
                messagebox.showerror("Matched words", err, parent=d)
                return
            self._invoke_anchor_refresh_callback()
            tv.item(str(i), values=row_display_vals(row))

        btn_fr = ttk.Frame(outer)
        btn_fr.grid(row=2, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btn_fr, text="Apply", command=apply_row).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btn_fr, text="Close", command=d.destroy).pack(side=tk.LEFT)

        d.bind("<Escape>", lambda e: d.destroy())
        d.grab_set()

    def set_anchor_refresh_callback(self, cb: Optional[Callable[[], None]]) -> None:
        """Register a callback (e.g. ``RomToolsShell.refresh_anchors``) after structure TOML changes on disk."""
        self._anchor_refresh_callback = cb

    def _invoke_anchor_refresh_callback(self) -> None:
        self._invalidate_struct_anchors_cache()
        if self._anchor_refresh_callback is None:
            return
        try:
            self._anchor_refresh_callback()
        except Exception:
            pass

    def shift_toml_named_anchors_for_repoint(self, src_lo: int, src_hi: int, delta: int) -> Tuple[int, str]:
        """
        After **Repoint bytes**, shift ``[[NamedAnchors]]`` and ``[[MatchedWords]]`` **Address** by ``delta``
        when the row’s start file offset lies in ``[src_lo, src_hi)``.

        Persists the TOML when at least one row is updated. Returns ``(rows_updated, error_message)``.
        """
        if delta == 0:
            return 0, ""
        _try_import_tomli_w()
        if not _TOMLI_W_AVAILABLE or tomli_w is None:
            return 0, _tomli_w_missing_message()
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return 0, ""
        n = 0
        rom_len = len(self._data) if self._data else 0
        for table_key in ("NamedAnchors", "MatchedWords"):
            rows_raw = self._toml_data.get(table_key)
            if not isinstance(rows_raw, list):
                continue
            for anchor in rows_raw:
                if not isinstance(anchor, dict):
                    continue
                addr = anchor.get("Address")
                if addr is None:
                    continue
                fo = _toml_address_value_to_file_offset(addr)
                if fo is None:
                    continue
                if not (src_lo <= fo < src_hi):
                    continue
                new_fo = fo + delta
                if new_fo < 0 or (rom_len and new_fo >= rom_len):
                    continue
                anchor["Address"] = _toml_named_anchor_address_hex_string(new_fo)
                n += 1
        if n == 0:
            return 0, ""
        ok, err = self.persist_toml_data()
        if not ok:
            return n, err
        self._ldr_pc_targets_valid = False
        self._invoke_anchor_refresh_callback()
        return n, ""

    def reload_toml_from_disk(self) -> bool:
        """Re-read the structure TOML from disk into ``self._toml_data`` (normalizes deprecated keys)."""
        if not self._toml_path or not os.path.isfile(self._toml_path):
            return False
        ok = self._load_toml_bytes_from_path(self._toml_path)
        if ok:
            self._ldr_pc_targets_valid = False
        return ok

    def replace_word_aligned_rom_pointers(
        self,
        old_gba: int,
        new_gba: int,
        *,
        exclude_ranges: Optional[List[Tuple[int, int]]] = None,
    ) -> int:
        """
        Scan the ROM at 4-byte alignment; replace little-endian ``u32 == old_gba`` with ``new_gba``.
        Used after relocating graphics so tables / struct fields that pointed at the old start are updated.
        """
        if not self._data:
            return 0
        n = _apply_word_aligned_pointer_patch(
            self._data, old_gba, new_gba, exclude_ranges=exclude_ranges
        )
        if n:
            self._modified = True
            self._schedule_xref_rebuild()
            self._refresh_visible()
        return n

    def write_bytes_at(self, offset: int, data: bytes) -> None:
        if not self._data or offset < 0:
            return
        for i, b in enumerate(data):
            if offset + i < len(self._data):
                self._data[offset + i] = b
        self._modified = True
        self._schedule_xref_rebuild()
        self._refresh_visible()

    def set_struct_editor_ref(self, ref: Any) -> None:
        """Host editor wires the Struct tools pane so File → Import YDK can use the selected struct."""
        self._struct_editor_ref = ref

    def _build_card_password_index_map(
        self, password_anchor_name: str, *, card_list_name: Optional[str] = None
    ) -> Tuple[Optional[Dict[str, int]], str]:
        """Map normalized password key (:func:`_password_rom_u32_match_key`) → **u16 card id** for the deck blob.

        * *card_list_name* (deck ``[card:ListName]``): target ``[[List]]`` whose **keys** are written as u16.

        * Password Format ``]indexList`` (e.g. ``]cardstatsnames``): row *i* reads the label from that list at
          the *i*-th sorted key, then finds the **same** label in *card_list_name* and uses that list's key. This
          matches tables like ``data.cards.passwords`` indexed by ``cardstatsnames`` but storing ``cardnames`` ids.

        * If both list names are the same (or only *card_list_name* applies), row *i* uses the *i*-th sorted key
          in that list.

        * Otherwise fall back to row index *i*. First password row wins on duplicate ROM passwords.
        """
        want = normalize_named_anchor_lookup_key(password_anchor_name.strip())
        anchor: Optional[Dict[str, Any]] = None
        for a in self._toml_data.get("NamedAnchors", []):
            if normalize_named_anchor_lookup_key(str(a.get("Name", ""))) == want:
                anchor = a
                break
        if not anchor:
            return None, f"NamedAnchor {password_anchor_name!r} was not found in the structure TOML."
        if not self._data:
            return None, "No ROM loaded."
        fmt_raw = str(anchor.get("Format", "")).strip()
        fmt = normalize_named_anchor_format(anchor.get("Format", ""))
        fields = _parse_struct_fields(fmt, blist_resolver=self._bit_count_for_blist_ref)
        if not fields:
            return None, f"Could not parse Format for {password_anchor_name!r}."
        addr = anchor.get("Address")
        if addr is None:
            return None, f"{password_anchor_name!r} has no Address."
        try:
            gba = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
            if gba < GBA_ROM_BASE:
                gba += GBA_ROM_BASE
            base_off = gba - GBA_ROM_BASE
        except (ValueError, TypeError):
            return None, f"Bad Address for {password_anchor_name!r}."
        struct_size = _struct_row_byte_size(fields)
        if struct_size <= 0:
            return None, f"Could not compute row size for {password_anchor_name!r}."
        count_raw = _parse_struct_count(fmt)
        if count_raw is None:
            return None, f"Could not read row count for {password_anchor_name!r}."
        n = count_raw if isinstance(count_raw, int) else self._resolve_struct_count(str(count_raw))
        if n is None or n <= 0:
            return None, f"Invalid row count for {password_anchor_name!r}."
        pw_f = next((f for f in fields if str(f.get("name")) == "password"), fields[0])
        delta = int(pw_f.get("offset") or 0)

        lists_all = _load_toml_lists(self._toml_data)
        idx_list_raw = _password_anchor_index_list_name(fmt_raw)
        n_card = normalize_named_anchor_lookup_key(str(card_list_name).strip()) if card_list_name else ""
        n_idx = normalize_named_anchor_lookup_key(str(idx_list_raw).strip()) if idx_list_raw else ""
        card_lm: Optional[Dict[int, str]] = lists_all.get(n_card) if n_card else None
        stats_lm: Optional[Dict[int, str]] = lists_all.get(n_idx) if n_idx else None
        sk_card: List[int] = sorted(int(k) for k in card_lm.keys()) if card_lm else []
        sk_stats: List[int] = sorted(int(k) for k in stats_lm.keys()) if stats_lm else []

        use_label_bridge = bool(
            card_lm
            and stats_lm
            and n_idx
            and n_card
            and n_idx != n_card
        )
        rev_card: Optional[Dict[str, int]] = _list_reverse_label_to_smallest_key(card_lm) if use_label_bridge else None

        def row_to_card_u16(i: int) -> int:
            if use_label_bridge and rev_card is not None and i < len(sk_stats):
                label = str(stats_lm[int(sk_stats[i])]).strip()  # type: ignore[index]
                cid = rev_card.get(label)
                if cid is not None:
                    return int(cid)
            if sk_card and i < len(sk_card):
                return int(sk_card[i])
            return int(i)

        out: Dict[str, int] = {}
        for i in range(int(n)):
            ro = base_off + i * struct_size + delta
            if ro + 4 > len(self._data):
                break
            word = self._data[ro : ro + 4]
            v_le = int.from_bytes(word, "little")
            v_be = int.from_bytes(word, "big")
            card_u16 = max(0, min(0xFFFF, row_to_card_u16(i)))
            for v in (v_le, v_be):
                mk = _password_rom_u32_match_key(v)
                if mk not in out:
                    out[mk] = card_u16
        return out, ""

    def _file_import_ydk_pointer_count_deck_blob(
        self,
        *,
        parent: tk.Misc,
        info: Dict[str, Any],
        fields: List[Dict[str, Any]],
        na_fd: Dict[str, Any],
        new_blob: bytes,
        new_len: int,
        path: str,
        se: Any,
        entry_idx: int,
    ) -> None:
        """Write a main-deck-only u16 blob at ``*ptr`` for ``offset<[`ydk`…]/length>`` layouts; update ``length``."""
        struct_name = str(info.get("name", "")).strip()
        base_off = int(info["base_off"])
        entry_base = base_off + entry_idx * int(info["struct_size"])
        stride = int(na_fd["inner_stride"])
        cf_name = str(na_fd.get("count_field") or "")
        cf = next((f for f in fields if str(f.get("name")) == cf_name), None)
        if not cf or cf.get("type") != "uint":
            messagebox.showerror("Import YDK", f"Count field {cf_name!r} not found for this layout.")
            return
        rsz = int(cf["size"])
        data = bytes(self._data)
        na_base = _nested_array_data_base_file(entry_base, na_fd, fields, data)
        if na_base is None:
            messagebox.showerror("Import YDK", "Could not resolve the deck pointer for this row.")
            return
        cur_len = int(se._read_nested_array_count(entry_base, na_fd))
        old_span = max(0, cur_len * stride)
        reloc = _ptr_word_off_and_alloc_start(entry_base, na_fd, fields, data)
        if reloc is None:
            messagebox.showerror(
                "Import YDK",
                "This pointer-backed deck layout is not relocatable (expected a GBA pointer field).",
            )
            return
        _poff, alloc_lo, na_chk = reloc
        if na_chk != na_base:
            messagebox.showerror("Import YDK", "Internal: nested base mismatch.")
            return
        old_hi = alloc_lo + old_span
        need_bytes = len(new_blob)
        mx = min((1 << (8 * rsz)) - 1, 65535)
        length_val = max(0, min(int(new_len), mx))

        def _write_length_field() -> bool:
            roff = se._struct_field_file_off(entry_base, cf)
            if roff is None or roff + rsz > len(self._data):
                messagebox.showerror("Import YDK", "Could not write the length field.")
                return False
            self.write_bytes_at_extend(roff, int(length_val).to_bytes(rsz, "little"))
            return True

        def _done_ok() -> None:
            self._invoke_anchor_refresh_callback()
            try:
                se._load_entry(entry_idx)
            except (tk.TclError, AttributeError):
                pass
            messagebox.showinfo(
                "Import YDK",
                f"Imported {path}\nStruct {struct_name!r}, row {entry_idx}: "
                f"{new_len} main card index(es) (pointer+length layout; extra deck not stored).",
            )

        if need_bytes <= 0:
            messagebox.showerror("Import YDK", "Nothing to import.")
            return
        lim = len(self._data)
        tail_room = max(0, lim - alloc_lo)
        if old_span > 0 and need_bytes <= old_span:
            pad = b"\xFF" * (old_span - need_bytes)
            self.write_bytes_at_extend(alloc_lo, new_blob + pad)
            if not _write_length_field():
                return
            _done_ok()
            return
        if need_bytes <= tail_room:
            self.write_bytes_at_extend(alloc_lo, new_blob)
            if not _write_length_field():
                return
            _done_ok()
            return
        ptr_label = str(na_fd.get("name") or "pointer")
        desc = f"Struct {struct_name!r}, row index {entry_idx} (pointer+length deck)."
        excl_hi = old_hi if old_hi > alloc_lo else alloc_lo + 1
        dlg = _PointedBlobRepointDialog(
            parent,
            self,
            need_bytes,
            alloc_lo,
            excl_hi,
            alloc_lo,
            ptr_label,
            desc,
        )
        if dlg.result is None:
            return
        new_off, fill_old = dlg.result
        ok_r, err_r = self._repoint_pointed_allocation(alloc_lo, old_hi if old_hi > alloc_lo else alloc_lo, new_blob, new_off, fill_old)
        if not ok_r:
            messagebox.showerror("Import YDK", err_r or "Repoint failed.")
            return
        if not _write_length_field():
            return
        _done_ok()

    def _file_import_ydk_flat_card_table(
        self,
        *,
        info: Dict[str, Any],
        fields: List[Dict[str, Any]],
        card_fd: Dict[str, Any],
        main_idx: List[int],
        extra_idx: List[int],
        saw_extra: bool,
        se: Any,
        path: str,
        fmt_src: str,
        entry_idx: int,
    ) -> None:
        """Import passwords into a ``[card:List]N`` table (normalized `` `ydk`…[card:List]N`` shorthand)."""
        struct_name = str(info.get("name", "")).strip()
        struct_size = int(info["struct_size"])
        base_off = int(info["base_off"])
        tbl_count = int(info["count"])
        anchor = info["anchor"]
        nm = len(main_idx)
        ne = len(extra_idx)
        need_rows = int(entry_idx) + nm

        if saw_extra and ne > 0:
            if not messagebox.askyesno(
                "Import YDK — extra deck",
                "This table only stores main-deck card slots (u16 per row). "
                f"The YDK has {ne} extra-deck card(s), which will not be written.\n\n"
                "Import main deck only?",
            ):
                return

        if need_rows > tbl_count:
            n_add = need_rows - tbl_count
            fresh = self.find_struct_anchor_by_name(struct_name)
            if not fresh:
                messagebox.showerror("Import YDK", "Lost struct anchor (reload TOML?).")
                return
            ok_a, err_a = self.append_struct_table_rows(fresh, n_add)
            if not ok_a:
                messagebox.showerror(
                    "Import YDK",
                    err_a or f"Need {need_rows} card row(s) but the struct only has {tbl_count}.",
                )
                return
            self._invalidate_struct_anchors_cache()
            info2 = self.find_struct_anchor_by_name(struct_name)
            if not info2:
                messagebox.showerror("Import YDK", "Struct anchor missing after expanding rows.")
                return
            info = info2
            fields = list(info.get("fields") or [])
            fd2 = _struct_flat_ydk_card_table_field(fields)
            if not fd2:
                messagebox.showerror("Import YDK", "Internal: flat card field missing after expand.")
                return
            card_fd = fd2
            tbl_count = int(info["count"])
            base_off = int(info["base_off"])
            struct_size = int(info["struct_size"])

        anchor = info["anchor"]
        bump = self._ydk_maybe_bump_anchor_literal_after_import(anchor, fmt_src, need_rows)
        for i, vid in enumerate(main_idx):
            row = int(entry_idx) + i
            entry_base = base_off + row * struct_size
            foff = se._struct_field_file_off(entry_base, card_fd)
            if foff is None:
                messagebox.showerror("Import YDK", f"Could not resolve file offset for card row {row}.")
                return
            self.write_bytes_at_extend(foff, int(vid).to_bytes(2, "little"))

        self._invoke_anchor_refresh_callback()
        try:
            se._load_entry(entry_idx)
        except (tk.TclError, AttributeError):
            pass
        msg_lines = [
            f"Imported {path}",
            f"Struct {struct_name!r}: wrote {nm} main card index(es) starting at row {entry_idx}.",
        ]
        if bump:
            msg_lines.append(bump)
        messagebox.showinfo("Import YDK", "\n".join(msg_lines))

    def file_import_ydk_deck(self) -> None:
        """Import a YDK deck into the selected `` `ydk` `` deck struct (``!``-terminated blob or pointer+``length``)."""
        parent = self.winfo_toplevel()
        if not self._data:
            messagebox.showwarning("Import YDK", "No ROM loaded.")
            return
        se = self._struct_editor_ref
        if se is None:
            messagebox.showinfo(
                "Import YDK",
                "Open the tools pane (Struct tab) once after loading so the deck import can see the selected struct.",
            )
            return
        info = se._selected_struct_anchor()
        if not _struct_anchor_info_supports_ydk_import(info):
            messagebox.showinfo(
                "Import YDK",
                "Select a struct whose Format includes `ydk` (and optional password table Name) before the card field list "
                "(e.g. offset<… main: `ydk`data.cards.passwords[card:cardnames]!0000> — see Structure TOML).",
            )
            return
        if not self._toml_path or not os.path.isfile(self._toml_path):
            messagebox.showwarning("Import YDK", "Save or load a structure TOML next to the ROM before importing.")
            return
        if info.get("packed_terminator"):
            messagebox.showerror(
                "Import YDK",
                "YDK import applies to per-row `!`-terminated deck blobs, not packed-only terminator tables.",
            )
            return
        fields = list(info.get("fields") or [])
        fmt_src_early = str((info.get("anchor") or {}).get("Format", "") or "")
        flat_card_fd = _struct_flat_ydk_card_table_field(fields)
        flat_ydk = bool(flat_card_fd and _struct_format_has_ydk_import_marker(fmt_src_early))
        na_fd_term: Optional[Dict[str, Any]] = None
        na_fd_pc: Optional[Dict[str, Any]] = None
        stride = 2
        term = b""
        na_fd: Optional[Dict[str, Any]] = None
        if not flat_ydk:
            na_fd_term = _struct_per_row_terminator_nested_field(fields)
            na_fd_pc = _struct_ydk_pointer_count_nested_field(fields)
            if not na_fd_term and not (na_fd_pc and _struct_format_has_ydk_import_marker(fmt_src_early)):
                messagebox.showerror(
                    "Import YDK",
                    "This struct must have either a per-row !-terminated nested card run, a "
                    "`ydk` [card:…] card table, or a `ydk` pointer+length deck (offset<[…]/length> with u16 cards).",
                )
                return
            na_fd = na_fd_term if na_fd_term else na_fd_pc
            assert na_fd is not None
            stride = int(na_fd["inner_stride"])
            term = bytes(na_fd["terminator"]) if na_fd.get("terminator") is not None else b""
            if stride < 1:
                messagebox.showerror("Import YDK", "Invalid nested card stride.")
                return
            if na_fd_term:
                if not term:
                    messagebox.showerror("Import YDK", "Invalid nested terminator.")
                    return
            if stride != 2:
                messagebox.showerror(
                    "Import YDK",
                    f"YDK import expects 2-byte card slots (u16); this struct uses inner stride {stride}.",
                )
                return

        path = filedialog.askopenfilename(
            title="Import YDK deck",
            filetypes=[("YDK deck", "*.ydk"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                ydk_text = f.read()
        except OSError as e:
            messagebox.showerror("Import YDK", str(e))
            return

        fmt_src = str((info.get("anchor") or {}).get("Format", "") or "")
        pwd_anchor = str(
            info.get("ydk_password_anchor") or _struct_format_ydk_password_anchor_name(fmt_src)
        ).strip()
        main_pw, extra_pw, saw_extra = _parse_ydk_deck_text(ydk_text)
        pw_map, err = self._build_card_password_index_map(
            pwd_anchor, card_list_name=_struct_format_ydk_card_list_name(fmt_src)
        )
        if pw_map is None:
            messagebox.showerror("Import YDK", err or "Password table error.")
            return

        def _lookup_card_index(raw_tok: str) -> Tuple[Optional[int], Optional[str]]:
            mk = _password_ydk_token_match_key(raw_tok)
            if mk is None:
                return None, None
            ix = pw_map.get(mk)
            if ix is not None and 0 <= ix <= 0xFFFF:
                return int(ix), mk
            # Same hex digits as u32: try the other endian label (forward / big-endian password wording).
            try:
                w = int(mk, 16) & 0xFFFFFFFF
                alt = _password_rom_u32_match_key(int.from_bytes(w.to_bytes(4, "little"), "big"))
                if alt != mk:
                    ix = pw_map.get(alt)
                    if ix is not None and 0 <= ix <= 0xFFFF:
                        return int(ix), alt
                alt2 = _password_rom_u32_match_key(int.from_bytes(w.to_bytes(4, "big"), "little"))
                if alt2 not in (mk, alt):
                    ix = pw_map.get(alt2)
                    if ix is not None and 0 <= ix <= 0xFFFF:
                        return int(ix), alt2
            except (ValueError, OverflowError):
                pass
            return None, mk

        invalid_pw: List[str] = []
        main_idx: List[int] = []
        for p in main_pw:
            ix, _mk = _lookup_card_index(p)
            if ix is None:
                invalid_pw.append(p)
            else:
                main_idx.append(ix)
        extra_idx: List[int] = []
        for p in extra_pw:
            ix, _mk = _lookup_card_index(p)
            if ix is None:
                invalid_pw.append(p)
            else:
                extra_idx.append(ix)
        if invalid_pw:
            uniq_bad = sorted(set(invalid_pw))
            preview = ", ".join(str(x) for x in uniq_bad[:12])
            if len(uniq_bad) > 12:
                preview += ", …"
            if not messagebox.askyesno(
                "Import YDK — unknown passwords",
                f"{len(invalid_pw)} line(s) reference passwords not in this ROM (e.g. {preview}).\n\n"
                "Skip those cards and import the rest?\n\n"
                "No = cancel the whole import.",
            ):
                return
            main_idx = []
            for p in main_pw:
                ix, _mk = _lookup_card_index(p)
                if ix is not None:
                    main_idx.append(ix)
            extra_idx = []
            for p in extra_pw:
                ix, _mk = _lookup_card_index(p)
                if ix is not None:
                    extra_idx.append(ix)

        nm = len(main_idx)
        ne = len(extra_idx)
        warn_lines: List[str] = []
        if na_fd_term or flat_ydk:
            if nm < 40 or nm > 60:
                warn_lines.append(f"Main deck has {nm} valid card(s) (expected 40–60).")
            if ne > 15:
                warn_lines.append(f"Extra deck has {ne} card(s) (maximum 15).")
            if warn_lines:
                msg = "\n\n".join(warn_lines) + "\n\nContinue import anyway?"
                if not messagebox.askyesno("Import YDK — deck size", msg):
                    return

        try:
            entry_idx = int(se._idx_var.get())
        except (ValueError, tk.TclError):
            entry_idx = 0

        if flat_ydk and flat_card_fd:
            self._file_import_ydk_flat_card_table(
                info=info,
                fields=fields,
                card_fd=flat_card_fd,
                main_idx=main_idx,
                extra_idx=extra_idx,
                saw_extra=saw_extra,
                se=se,
                path=path,
                fmt_src=fmt_src_early,
                entry_idx=entry_idx,
            )
            return

        if na_fd_pc:
            new_blob = b"".join(int(x).to_bytes(2, "little") for x in main_idx)
            self._file_import_ydk_pointer_count_deck_blob(
                parent=parent,
                info=info,
                fields=fields,
                na_fd=na_fd_pc,
                new_blob=new_blob,
                new_len=len(main_idx),
                path=path,
                se=se,
                entry_idx=entry_idx,
            )
            return

        new_blob = _ydk_build_deck_blob(main_idx, extra_idx, saw_extra, term)
        struct_name = str(info.get("name", "")).strip()
        struct_size = int(info["struct_size"])
        base_off = int(info["base_off"])
        entry_base = base_off + entry_idx * struct_size
        na_fd = na_fd_term
        assert na_fd is not None

        for _ in range(64):
            data = bytes(self._data)
            na_base = _nested_array_data_base_file(entry_base, na_fd, fields, data)
            if na_base is None:
                messagebox.showerror("Import YDK", "Could not resolve the deck blob pointer for this row.")
                return
            end = _terminator_nested_row_end_exclusive_pointer_blob(data, na_base, stride, term)
            if end is None:
                messagebox.showerror(
                    "Import YDK",
                    "Could not find the nested terminator for this deck (truncated ROM or invalid pointer?).",
                )
                return
            current_span = end - na_base
            if len(new_blob) <= current_span:
                pad = b"\xFF" * (current_span - len(new_blob))
                self.write_bytes_at_extend(na_base, new_blob + pad)
                self._invoke_anchor_refresh_callback()
                try:
                    se._load_entry(entry_idx)
                except (tk.TclError, AttributeError):
                    pass
                messagebox.showinfo(
                    "Import YDK",
                    f"Imported {path}\n"
                    f"Struct {struct_name!r}, row {entry_idx}: "
                    f"{len(main_idx)} main + {len(extra_idx)} extra card index(es).",
                )
                return
            need_grow = len(new_blob) - current_span
            n_slots = (need_grow + stride - 1) // stride
            fresh = self.find_struct_anchor_by_name(struct_name)
            if not fresh:
                messagebox.showerror("Import YDK", "Lost struct anchor while expanding (reload TOML?).")
                return
            ok, err_exp = self.expand_struct_table_slots(
                fresh, n_slots, entry_idx, fill_spec="00", repoint_parent=parent
            )
            if not ok:
                messagebox.showerror("Import YDK", err_exp or "Could not expand the deck blob.")
                return
            self._invalidate_struct_anchors_cache()
            info2 = self.find_struct_anchor_by_name(struct_name)
            if not info2:
                messagebox.showerror("Import YDK", "Struct anchor missing after expand.")
                return
            fields = list(info2.get("fields") or [])
            na_fd2 = _struct_per_row_terminator_nested_field(fields)
            if not na_fd2:
                messagebox.showerror("Import YDK", "Nested deck field missing after expand.")
                return
            na_fd = na_fd2

        messagebox.showerror("Import YDK", "Could not fit the deck after repeated expands (give up).")

    # ── File menu: static ROM imports (user-chosen offsets / FF gaps) ─

    def file_import_sprite_static(self) -> None:
        """File → Import Sprite: PNG → tiles and optional palette at file offsets (optional LZ)."""
        parent = self.winfo_toplevel()
        if not self._data:
            messagebox.showwarning("Import sprite", "No ROM loaded.")
            return
        path = filedialog.askopenfilename(
            title="Import sprite — PNG",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if not path:
            return
        opt = _SpriteImportOptionsDialog(parent, path, title="Import sprite — options")
        if opt.result is None:
            return
        bpp, lz, wt, ht, ncolors, tom_name, tom_pal_name, write_pal, upd, rom_clip_8 = opt.result
        tb, flat_pal, err, tw, th = sprite_import_png_manual(
            path,
            bpp=bpp,
            width_tiles=int(wt),
            height_tiles=int(ht),
            palette_color_count=int(ncolors),
        )
        if err:
            messagebox.showerror("Import sprite", err)
            return
        spec = GraphicsAnchorSpec(kind="sprite", bpp=bpp, lz=lz, width_tiles=tw, height_tiles=th)
        try:
            payload = build_sprite_payload_for_rom(tb, spec, lz=lz)
        except ValueError as e:
            messagebox.showerror("Import sprite", str(e))
            return
        ext_ps = synthetic_palette_spec_for_sprite_import_write(
            bpp,
            rom_palette_colors_8bpp=rom_clip_8 if bpp == 8 else None,
        )
        try:
            pal_body = prepare_palette_rom_body_from_import(ext_ps, flat_pal)
            pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=lz)
        except ValueError as e:
            messagebox.showerror("Import sprite", f"Palette pack: {e}")
            return

        dest = _StaticRomOffsetDialog(
            parent,
            self,
            len(payload),
            "Import sprite — tile data destination",
            blurb=f"Sprite sheet {tw}×{th} tiles ({tw * 8}×{th * 8} px).",
        )
        if dest.result is None:
            return
        off = dest.result

        pal_off: Optional[int] = None
        if write_pal:
            dest_pal = _StaticRomOffsetDialog(
                parent,
                self,
                len(pal_payload),
                "Import sprite — palette destination",
                blurb=f"Quantized GBA palette: {len(pal_payload)} bytes ({bpp}bpp).",
            )
            if dest_pal.result is None:
                return
            pal_off = dest_pal.result

        self.write_bytes_at(off, payload)
        gba = off + GBA_ROM_BASE
        msg = f"Tiles: {len(payload)} byte(s) at file 0x{off:X} (GBA 0x{gba:08X})."
        gba_p: Optional[int] = None
        if write_pal and pal_off is not None:
            self.write_bytes_at(pal_off, pal_payload)
            gba_p = pal_off + GBA_ROM_BASE
            msg += f"\nPalette: {len(pal_payload)} byte(s) at file 0x{pal_off:X} (GBA 0x{gba_p:08X})."

        link_pal = bool(write_pal and pal_off is not None and normalize_named_anchor_lookup_key(tom_pal_name))
        fmt_sprite = _toml_sprite_format_token_with_palette(
            lz, bpp, tw, th, tom_pal_name if link_pal else ""
        )
        did_reload = False
        if upd and tom_name:
            ok_t, err_t, how = self.update_named_anchor_address_and_format(
                tom_name, gba_addr=gba, new_format=fmt_sprite, create_if_missing=True
            )
            if ok_t:
                tag = "Added new" if how == "created" else "Updated"
                msg += f"\n\nTOML sprite: {tag} {tom_name!r} — {fmt_sprite}"
                did_reload = True
            else:
                msg += f"\n\nTOML sprite failed: {err_t}"
        if upd and link_pal and tom_pal_name and gba_p is not None:
            fmt_pal = _toml_palette_format_for_tilemap_bpp(bpp, rom_clip_8 if bpp == 8 else None)
            ok_p, err_p, how_p = self.update_named_anchor_address_and_format(
                tom_pal_name, gba_addr=gba_p, new_format=fmt_pal, create_if_missing=True
            )
            if ok_p:
                tagp = "Added new" if how_p == "created" else "Updated"
                msg += f"\nTOML palette: {tagp} {tom_pal_name!r} — {fmt_pal}"
                did_reload = True
            else:
                msg += f"\nTOML palette failed: {err_p}"
        if did_reload:
            self.reload_toml_from_disk()
        messagebox.showinfo("Import sprite", msg)

    def file_import_palette_static(self) -> None:
        """File → Import Palette: PNG, standard text .pal/.gpl, or raw GBA .bin (optional LZ)."""
        parent = self.winfo_toplevel()
        if not self._data:
            messagebox.showwarning("Import palette", "No ROM loaded.")
            return
        path = filedialog.askopenfilename(
            title="Import palette",
            filetypes=[
                ("All supported", "*.png;*.pal;*.gpl;*.bin"),
                ("PNG", "*.png"),
                ("Standard palette (JASC / GIMP / asm RGB)", "*.pal;*.gpl"),
                ("Raw GBA RGB555 binary", "*.bin"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        low = path.lower()
        is_png = low.endswith(".png")
        opt = _PaletteImportOptionsDialog(parent, is_png=is_png)
        if opt.result is None:
            return
        bpp, lz, n_colors_8 = opt.result
        kw: Dict[str, Any] = {}
        if bpp == 8:
            kw["colors_8bpp"] = n_colors_8
        if is_png:
            pal_body, err = palette_import_png(path, bpp, **kw)
            if err:
                messagebox.showerror("Import palette", err)
                return
        elif low.endswith(".bin"):
            pal_body, err = palette_import_gba_binary(path, bpp, **kw)
            if err:
                messagebox.showerror("Import palette", err)
                return
        else:
            pal_body, err = palette_import_palette_file(path, bpp, **kw)
            if err:
                messagebox.showerror("Import palette", err)
                return
        if bpp == 4:
            pal_spec = GraphicsAnchorSpec(kind="palette", bpp=4, lz=lz, palette_4_indices=None)
        else:
            syn = synthetic_palette_spec_for_sprite_import_write(
                8,
                rom_palette_colors_8bpp=n_colors_8,
            )
            pal_spec = GraphicsAnchorSpec(
                kind="palette",
                bpp=8,
                lz=lz,
                palette_hex_digit=syn.palette_hex_digit,
            )
        try:
            payload = palette_payload_for_rom(pal_body, pal_spec, lz=lz)
        except ValueError as e:
            messagebox.showerror("Import palette", str(e))
            return
        dest = _StaticRomOffsetDialog(
            parent,
            self,
            len(payload),
            "Import palette — destination",
        )
        if dest.result is None:
            return
        off = dest.result
        self.write_bytes_at(off, payload)
        gba = off + GBA_ROM_BASE
        messagebox.showinfo(
            "Import palette",
            f"Wrote {len(payload)} byte(s) at file offset 0x{off:X} (GBA 0x{gba:08X}).",
        )

    def file_import_tilemap_tileset_static(self) -> None:
        """File → Import Tilemap/Tileset: raw blob, PNG tilemap pipeline, or PNG tileset sheet."""
        parent = self.winfo_toplevel()
        if not self._data:
            messagebox.showwarning("Import tilemap/tileset", "No ROM loaded.")
            return
        mode_dlg = _TilemapImportModeDialog(parent)
        if mode_dlg.result is None:
            return
        mode = mode_dlg.result

        if mode == "raw":
            path = filedialog.askopenfilename(
                title="Import raw tilemap or tileset bytes",
                filetypes=[("Binary", "*.bin"), ("All files", "*.*")],
            )
            if not path:
                return
            try:
                with open(path, "rb") as f:
                    blob = f.read()
            except OSError as e:
                messagebox.showerror("Import", str(e))
                return
            if not blob:
                messagebox.showerror("Import", "File is empty.")
                return
            dest = _StaticRomOffsetDialog(
                parent,
                self,
                len(blob),
                "Import raw data — destination",
                blurb="Writes the file bytes unchanged.",
            )
            if dest.result is None:
                return
            off = dest.result
            self.write_bytes_at(off, blob)
            messagebox.showinfo(
                "Import",
                f"Wrote {len(blob)} byte(s) at file offset 0x{off:X} (GBA 0x{off + GBA_ROM_BASE:08X}).",
            )
            return

        if mode == "png_ts":
            path = filedialog.askopenfilename(
                title="Import tileset — PNG",
                filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
            )
            if not path:
                return
            opt = _SpriteImportOptionsDialog(parent, path, title="Import tileset — options")
            if opt.result is None:
                return
            bpp, lz, wt, ht, ncolors, tom_name, tom_pal_name, write_pal, upd, rom_clip_8 = opt.result
            tb, flat_pal, err, tw, th = sprite_import_png_manual(
                path,
                bpp=bpp,
                width_tiles=int(wt),
                height_tiles=int(ht),
                palette_color_count=int(ncolors),
            )
            if err:
                messagebox.showerror("Import tileset", err)
                return
            spec = GraphicsAnchorSpec(kind="sprite", bpp=bpp, lz=lz, width_tiles=tw, height_tiles=th)
            try:
                payload = build_sprite_payload_for_rom(tb, spec, lz=lz)
            except ValueError as e:
                messagebox.showerror("Import tileset", str(e))
                return
            ext_ps = synthetic_palette_spec_for_sprite_import_write(
                bpp,
                rom_palette_colors_8bpp=rom_clip_8 if bpp == 8 else None,
            )
            try:
                pal_body = prepare_palette_rom_body_from_import(ext_ps, flat_pal)
                pal_payload = palette_payload_for_rom(pal_body, ext_ps, lz=lz)
            except ValueError as e:
                messagebox.showerror("Import tileset", f"Palette pack: {e}")
                return
            dest = _StaticRomOffsetDialog(
                parent,
                self,
                len(payload),
                "Import tileset — tile data destination",
                blurb=f"Tile sheet {tw}×{th} tiles.",
            )
            if dest.result is None:
                return
            off = dest.result
            pal_off: Optional[int] = None
            if write_pal:
                dest_pal = _StaticRomOffsetDialog(
                    parent,
                    self,
                    len(pal_payload),
                    "Import tileset — palette destination",
                    blurb=f"Quantized GBA palette: {len(pal_payload)} bytes ({bpp}bpp).",
                )
                if dest_pal.result is None:
                    return
                pal_off = dest_pal.result
            self.write_bytes_at(off, payload)
            gba = off + GBA_ROM_BASE
            msg = f"Tiles: {len(payload)} byte(s) at file 0x{off:X} (GBA 0x{gba:08X})."
            gba_p: Optional[int] = None
            if write_pal and pal_off is not None:
                self.write_bytes_at(pal_off, pal_payload)
                gba_p = pal_off + GBA_ROM_BASE
                msg += f"\nPalette: {len(pal_payload)} byte(s) at file 0x{pal_off:X} (GBA 0x{gba_p:08X})."
            link_pal = bool(write_pal and pal_off is not None and normalize_named_anchor_lookup_key(tom_pal_name))
            fmt_sprite = _toml_sprite_format_token_with_palette(
                lz, bpp, tw * th, 1, tom_pal_name if link_pal else ""
            )
            did_reload = False
            if upd and tom_name:
                ok_t, err_t, how = self.update_named_anchor_address_and_format(
                    tom_name, gba_addr=gba, new_format=fmt_sprite, create_if_missing=True
                )
                if ok_t:
                    tag = "Added new" if how == "created" else "Updated"
                    msg += f"\n\nTOML tileset: {tag} {tom_name!r} — {fmt_sprite}"
                    did_reload = True
                else:
                    msg += f"\n\nTOML tileset failed: {err_t}"
            if upd and link_pal and tom_pal_name and gba_p is not None:
                fmt_pal = _toml_palette_format_for_tilemap_bpp(bpp, rom_clip_8 if bpp == 8 else None)
                ok_p, err_p, how_p = self.update_named_anchor_address_and_format(
                    tom_pal_name, gba_addr=gba_p, new_format=fmt_pal, create_if_missing=True
                )
                if ok_p:
                    tagp = "Added new" if how_p == "created" else "Updated"
                    msg += f"\nTOML palette: {tagp} {tom_pal_name!r} — {fmt_pal}"
                    did_reload = True
                else:
                    msg += f"\nTOML palette failed: {err_p}"
            if did_reload:
                self.reload_toml_from_disk()
            messagebox.showinfo("Import tileset", msg)
            return

        # png_map
        dim = _TilemapPngDimsDialog(parent)
        if dim.result is None:
            return
        mw, mh, bpp, pal_n, skip_pal, nm_map, nm_ts, nm_pal, upd, rom_clip_8 = dim.result
        path = filedialog.askopenfilename(
            title="Import tilemap — PNG",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if not path:
            return
        raw_map, tile_body, pal_flat, n_u, err = tilemap_png_to_tileset_map_palette(
            path,
            map_w_tiles=mw,
            map_h_tiles=mh,
            bpp=bpp,
            palette_color_count=pal_n,
            use_burner_transparent=True,
        )
        if err:
            messagebox.showerror("Import tilemap", err)
            return
        _tilemap_import_debug(
            None,
            "file_static_png_map_after_decode",
            bpp=bpp,
            burner=True,
            len_pal_flat=len(pal_flat),
            len_raw_map=len(raw_map),
            len_tile_body=len(tile_body),
            map_tiles=f"{mw}x{mh}",
            n_unique=n_u,
            palette_color_count=pal_n,
        )
        dest_map = _StaticRomOffsetDialog(
            parent,
            self,
            len(raw_map),
            "Import tilemap — map destination",
            blurb=f"Non-affine map: {mw}×{mh} cells, {len(raw_map)} bytes.",
        )
        if dest_map.result is None:
            return
        dest_ts = _StaticRomOffsetDialog(
            parent,
            self,
            len(tile_body),
            "Import tilemap — tileset destination",
            blurb=f"Unique tiles: {n_u} ({len(tile_body)} bytes).",
        )
        if dest_ts.result is None:
            return

        pal_payload = b""
        pal_off: Optional[int] = None
        if not skip_pal:
            if bpp == 4:
                pal_spec = GraphicsAnchorSpec(kind="palette", bpp=4, lz=False, palette_4_indices=None)
            elif bpp == 6:
                pal_spec = GraphicsAnchorSpec(
                    kind="palette",
                    bpp=8,
                    lz=False,
                    palette_hex_digit=UCP8_PALETTE_4_CHUNK_HEX_DIGITS,
                )
            else:
                pal_spec = synthetic_palette_spec_for_sprite_import_write(
                    8,
                    rom_palette_colors_8bpp=rom_clip_8,
                )
            pal_use = pal_flat
            if bpp == 8 and rom_clip_8 is not None:
                pal_use = pal_flat[: rom_clip_8 * 2]
            try:
                pal_payload = palette_payload_for_rom(pal_use, pal_spec, lz=False)
            except ValueError as e:
                messagebox.showerror("Import tilemap", str(e))
                return
            dpal = _StaticRomOffsetDialog(
                parent,
                self,
                len(pal_payload),
                "Import tilemap — palette destination",
                blurb="Quantized master palette for this map.",
            )
            if dpal.result is None:
                return
            pal_off = dpal.result

        self.write_bytes_at(dest_map.result, raw_map)
        self.write_bytes_at(dest_ts.result, tile_body)
        if not skip_pal and pal_off is not None:
            self.write_bytes_at(pal_off, pal_payload)
        msg = (
            f"Map: {len(raw_map)} byte(s) at 0x{dest_map.result:X}.\n"
            f"Tileset: {len(tile_body)} byte(s) at 0x{dest_ts.result:X}."
        )
        if not skip_pal and pal_off is not None:
            msg += f"\nPalette: {len(pal_payload)} byte(s) at 0x{pal_off:X}."
        if upd:
            tw_g, th_g = max(1, int(n_u)), 1
            fmt_ts = _toml_sprite_format_token(False, bpp, tw_g, th_g)
            fmt_pal = _toml_palette_format_for_tilemap_bpp(bpp, rom_clip_8 if bpp == 8 else None)
            gba_m = dest_map.result + GBA_ROM_BASE
            gba_ts = dest_ts.result + GBA_ROM_BASE
            if nm_map:
                cur_fmt = None
                nm_key = normalize_named_anchor_lookup_key(nm_map)
                nm_low = nm_key.lower()
                for row in self._toml_data.get("NamedAnchors", []) or []:
                    if not isinstance(row, dict):
                        continue
                    n = _named_anchor_row_name_field(row)
                    if n == nm_key or n.lower() == nm_low:
                        cur_fmt = str(row.get("Format", "") or "")
                        break
                fmt_map = (
                    rewrite_standalone_tilemap_format_dimensions(cur_fmt, mw, mh)
                    if cur_fmt
                    else None
                )
                if fmt_map is None:
                    fmt_map = _toml_tilemap_format_token(False, bpp, mw, mh, nm_ts)
                ok_m, err_m, how_m = self.update_named_anchor_address_and_format(
                    nm_map, gba_addr=gba_m, new_format=fmt_map, create_if_missing=True
                )
                if ok_m:
                    tag = "Added" if how_m == "created" else "Updated"
                    msg += f"\n\nTOML map ({tag}): {nm_map!r} — Address + Format ({fmt_map})"
                else:
                    msg += f"\n\nTOML map: {err_m}"
            if nm_ts:
                ok_t, err_t, how_t = self.update_named_anchor_address_and_format(
                    nm_ts, gba_addr=gba_ts, new_format=fmt_ts, create_if_missing=True
                )
                if ok_t:
                    tag = "Added" if how_t == "created" else "Updated"
                    msg += f"\n\nTOML tileset ({tag}): {nm_ts!r} — Address + Format ({fmt_ts})"
                else:
                    msg += f"\n\nTOML tileset: {err_t}"
            if not skip_pal and pal_off is not None and nm_pal:
                gba_p = pal_off + GBA_ROM_BASE
                ok_p, err_p, how_p = self.update_named_anchor_address_and_format(
                    nm_pal, gba_addr=gba_p, new_format=fmt_pal, create_if_missing=True
                )
                if ok_p:
                    tag = "Added" if how_p == "created" else "Updated"
                    msg += f"\n\nTOML palette ({tag}): {nm_pal!r} — Address + Format ({fmt_pal})"
                else:
                    msg += f"\n\nTOML palette: {err_p}"
            if nm_map or nm_ts or nm_pal:
                self.reload_toml_from_disk()
        messagebox.showinfo("Import tilemap", msg)

    # ── Scrolling ────────────────────────────────────────────────────

    def _on_mousewheel(self, event: tk.Event) -> Optional[str]:
        if not self._data:
            return None
        delta = -1 if (getattr(event, "delta", 0) or 0) > 0 else 1
        self._on_scrollbar_command("scroll", delta * 5, "units")
        return "break"

    def _on_text_yscroll(self, first: str, last: str) -> None:
        if not self._syncing_scroll:
            self._update_scrollbar()

    def _on_scrollbar_command(self, *args) -> None:
        if not self._data:
            return
        if self._syncing_scroll:
            return
        self._on_scrollbar_command_hex(*args)

    def _on_scrollbar_command_hex(self, *args) -> None:
        if self._total_rows == 0:
            return
        max_start = max(0, self._total_rows - self._visible_row_count)
        if max_start == 0:
            return
        action = str(args[0]) if args else ""
        if action == "moveto":
            fraction = float(args[1]) if len(args) > 1 else 0
            thumb_size = min(1.0, self._visible_row_count / self._total_rows)
            scrollable = 1.0 - thumb_size
            if scrollable > 0:
                self._visible_row_start = int((fraction / scrollable) * max_start)
                self._visible_row_start = max(0, min(max_start, self._visible_row_start))
        elif action == "scroll":
            amount = int(args[1]) if len(args) > 1 else 0
            units = str(args[2]) if len(args) > 2 else "units"
            if units == "pages":
                amount *= self._visible_row_count
            else:
                amount *= 1
            self._visible_row_start = max(0, min(max_start, self._visible_row_start + amount))
        self._syncing_scroll = True
        try:
            self._refresh_visible()
            self._update_scrollbar()
            self._refresh_asm_selection()
        finally:
            self._syncing_scroll = False

    def _update_scrollbar(self) -> None:
        if not self._data or self._total_rows == 0:
            self._scroll_y.set(0.0, 1.0)
            return
        max_start = max(0, self._total_rows - self._visible_row_count)
        if max_start == 0:
            self._scroll_y.set(0.0, 1.0)
            return
        thumb_size = min(1.0, self._visible_row_count / self._total_rows)
        first = (self._visible_row_start / max_start) * (1.0 - thumb_size) if max_start > 0 else 0
        last = first + thumb_size
        self._scroll_y.set(first, min(last, 1.0))

    def _refresh_asm_selection(self) -> None:
        """Disassemble selected/highlighted bytes (or cursor instruction) into ASM panel."""
        if not self._asm_pane_visible:
            if self._pseudo_c_pane_visible:
                self._refresh_pseudo_c_selection()
            return
        if self._hackmew_mode:
            self._refresh_asm_hackmew()
            if self._pseudo_c_pane_visible:
                self._refresh_pseudo_c_selection()
            return
        self._text_asm.configure(state=tk.NORMAL)
        self._text_asm.delete("1.0", tk.END)
        if not self._data or not _CAPSTONE_AVAILABLE:
            self._text_asm.insert(tk.END, "(No data or Capstone not available)")
            self._text_asm.configure(state=tk.DISABLED)
            return
        mode = CS_MODE_THUMB if self._asm_mode == "thumb" else CS_MODE_ARM
        align = 4
        if self._selection_start is not None and self._selection_end is not None:
            start = min(self._selection_start, self._selection_end)
            end = max(self._selection_start, self._selection_end) + 1
            start = (start // align) * align
        else:
            vis_start = self._visible_row_start * BYTES_PER_ROW
            vis_end = min(vis_start + self._visible_row_count * BYTES_PER_ROW, len(self._data))
            start = (vis_start // align) * align
            end = vis_end
        if start >= len(self._data):
            self._text_asm.insert(tk.END, "(No bytes selected)")
            self._text_asm.configure(state=tk.DISABLED)
            return
        end = min(end, len(self._data))
        ldr_targets = self._get_ldr_pc_targets(mode)
        chunk = bytes(self._data[start:end])
        base = GBA_ROM_BASE + start
        cs = Cs(CS_ARCH_ARM, mode)
        cs.detail = True
        insn_map: Dict[int, object] = {}
        try:
            for i in cs.disasm(chunk, base):
                file_off = i.address - GBA_ROM_BASE
                insn_map[file_off] = i
        except Exception:
            pass
        branch_targets = self._collect_branch_targets(
            start, end, mode, insn_map, ldr_targets
        )
        target_to_label: Dict[int, str] = {
            fo: f"loc_{GBA_ROM_BASE + fo:08X}" for fo in branch_targets
        }

        def _replace_addrs(text: str) -> str:
            def _repl(m: re.Match) -> str:
                addr = int(m.group(1), 16)
                fo = addr - GBA_ROM_BASE
                return target_to_label.get(fo, m.group(0))
            return re.sub(r"#0x([0-9A-Fa-f]+)\b", _repl, text)

        offset = start
        lines: List[str] = []
        while offset < end:
            file_off = offset
            if file_off in target_to_label and lines:
                lines.append("\n")
            if file_off in target_to_label:
                lines.append(f"{target_to_label[file_off]}:\n")
            if file_off in ldr_targets and self._is_ldr_word_pool(file_off, ldr_targets):
                b0 = self._data[file_off]
                b1 = self._data[file_off + 1] if file_off + 1 < len(self._data) else 0
                b2 = self._data[file_off + 2] if file_off + 2 < len(self._data) else 0
                b3 = self._data[file_off + 3] if file_off + 3 < len(self._data) else 0
                val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
                hex_bytes = f"{b0:02x} {b1:02x} {b2:02x} {b3:02x}"
                word_line = f".word #0x{val:08X}"
                word_line = _replace_addrs(word_line)
                lines.append(f"{GBA_ROM_BASE + file_off:08X}:  {hex_bytes:12s}  {word_line}\n")
                offset += 4
            elif file_off in insn_map:
                insn = insn_map[file_off]
                raw = insn.bytes
                insn_end = file_off + len(raw)
                overlaps_target = any(
                    self._is_ldr_word_pool(t, ldr_targets)
                    for t in range(file_off + 1, insn_end)
                )
                if overlaps_target:
                    offset += align
                    continue
                mnemonic, op_str = insn.mnemonic, insn.op_str
                hex_bytes = " ".join(f"{b:02x}" for b in raw)
                operands = f" {op_str}" if op_str else ""
                comment = self._get_ldr_pc_comment(insn, mode)
                if comment:
                    operands += f"  @ {comment}"
                insn_text = _replace_addrs(f"{mnemonic}{operands}")
                lines.append(f"{GBA_ROM_BASE + file_off:08X}:  {hex_bytes:12s}  {insn_text}\n")
                offset += len(raw)
            else:
                if align == 2:
                    b0 = self._data[offset]
                    b1 = self._data[offset + 1] if offset + 1 < len(self._data) else 0
                    hex_bytes = f"{b0:02x} {b1:02x}"
                    lines.append(f"{GBA_ROM_BASE + offset:08X}:  {hex_bytes:12s}  .byte 0x{b0:02x}, 0x{b1:02x}\n")
                else:
                    b0 = self._data[offset]
                    b1 = self._data[offset + 1] if offset + 1 < len(self._data) else 0
                    b2 = self._data[offset + 2] if offset + 2 < len(self._data) else 0
                    b3 = self._data[offset + 3] if offset + 3 < len(self._data) else 0
                    hex_bytes = f"{b0:02x} {b1:02x} {b2:02x} {b3:02x}"
                    lines.append(f"{GBA_ROM_BASE + offset:08X}:  {hex_bytes:12s}  .word 0x{b3:02x}{b2:02x}{b1:02x}{b0:02x}\n")
                offset += align
        content = "".join(lines) if lines else "(No instructions)"
        self._text_asm.insert("1.0", content)
        if lines:
            self._apply_syntax_highlighting(self._text_asm, "asm")
        self._text_asm.configure(state=tk.DISABLED)
        if self._pseudo_c_pane_visible:
            self._refresh_pseudo_c_selection()

    def _refresh_asm_hackmew(self) -> None:
        """Show editable HackMew-style ASM in the ASM pane. Records region for Ctrl+I compile."""
        self._text_asm.configure(state=tk.NORMAL)
        self._text_asm.delete("1.0", tk.END)
        if not self._data or not _CAPSTONE_AVAILABLE:
            self._text_asm.insert(tk.END, "(No data or Capstone not available)")
            return
        lines = self._build_asm_export_lines_with_labels(hackmew=True)
        if not lines:
            self._text_asm.insert(tk.END, "(No instructions)")
            return
        mode = CS_MODE_THUMB if self._asm_mode == "thumb" else CS_MODE_ARM
        align = 4
        if self._selection_start is not None and self._selection_end is not None:
            start = min(self._selection_start, self._selection_end)
            end = max(self._selection_start, self._selection_end) + 1
            start = (start // align) * align
        else:
            vis_start = self._visible_row_start * BYTES_PER_ROW
            vis_end = min(vis_start + self._visible_row_count * BYTES_PER_ROW, len(self._data))
            start = (vis_start // align) * align
            end = vis_end
        end = min(end, len(self._data))
        self._hackmew_asm_start = start
        self._hackmew_asm_end = end
        self._text_asm.insert("1.0", "\n".join(lines))
        self._apply_syntax_highlighting(self._text_asm, "asm")
        if self._pseudo_c_pane_visible:
            self._refresh_pseudo_c_selection()

    def _refresh_pseudo_c_selection(self) -> None:
        """Decompile selected/visible bytes into pseudo-C. Uses angr when available."""
        if not self._pseudo_c_pane_visible:
            return
        if self._c_inject_mode:
            return
        self._text_pseudo_c.configure(state=tk.NORMAL)
        self._text_pseudo_c.delete("1.0", tk.END)
        if not self._data:
            self._text_pseudo_c.insert(tk.END, "(No data)")
            self._text_pseudo_c.configure(state=tk.DISABLED)
            return
        align = 4
        if self._selection_start is not None and self._selection_end is not None:
            start = min(self._selection_start, self._selection_end)
            end = max(self._selection_start, self._selection_end) + 1
            start = (start // align) * align
        else:
            vis_start = self._visible_row_start * BYTES_PER_ROW
            vis_end = min(vis_start + self._visible_row_count * BYTES_PER_ROW, len(self._data))
            start = (vis_start // align) * align
            end = vis_end
        if start >= len(self._data):
            self._text_pseudo_c.insert(tk.END, "(No bytes selected)")
            self._text_pseudo_c.configure(state=tk.DISABLED)
            return
        end = min(end, len(self._data))
        data_copy = bytes(self._data)
        if _ANGR_AVAILABLE:
            self._text_pseudo_c.insert(tk.END, "Decompiling with angr (CFG + Decompiler)...")
            self._text_pseudo_c.configure(state=tk.DISABLED)
            thread = threading.Thread(
                target=self._angr_decompile_worker,
                args=(start, end, data_copy),
                daemon=True,
            )
            thread.start()
        else:
            self._refresh_pseudo_c_capstone_fallback(start, end, align)

    def _angr_decompile_worker(self, start: int, end: int, data_copy: bytes) -> None:
        """Background worker: run angr CFG + Decompiler, then schedule UI update."""
        result: Optional[str] = None
        try:
            result = self._angr_decompile_impl(start, end, data_copy)
        except Exception as e:
            result = f"(angr failed: {e})"
        if result and not result.startswith("(angr "):
            self.after(0, lambda: self._angr_decompile_done(result))
        else:
            align = 4
            self.after(0, lambda: self._angr_fallback_to_capstone(start, end, align, result))

    def _angr_decompile_done(self, text: str) -> None:
        """Called on main thread after angr decompilation completes."""
        if not self._pseudo_c_pane_visible:
            return
        if self._c_inject_mode:
            return
        self._text_pseudo_c.configure(state=tk.NORMAL)
        self._text_pseudo_c.delete("1.0", tk.END)
        self._text_pseudo_c.insert(tk.END, text)
        self._apply_syntax_highlighting(self._text_pseudo_c, "c")
        self._text_pseudo_c.configure(state=tk.DISABLED)

    def _angr_fallback_to_capstone(self, start: int, end: int, align: int, angr_error: Optional[str]) -> None:
        """When angr fails, show error + Capstone pseudo-C fallback."""
        if not self._pseudo_c_pane_visible:
            return
        if self._c_inject_mode:
            return
        self._text_pseudo_c.configure(state=tk.NORMAL)
        self._text_pseudo_c.delete("1.0", tk.END)
        if angr_error:
            self._text_pseudo_c.insert(tk.END, angr_error + "\n\n--- Capstone pseudo-C fallback ---\n\n")
        self._refresh_pseudo_c_capstone_fallback(start, end, align)

    def _angr_decompile_impl(self, start: int, end: int, data_copy: bytes) -> Optional[str]:
        """Full angr decompilation: load binary, CFG, Decompiler per function."""
        use_thumb = self._asm_mode == "thumb"
        entry_addr = GBA_ROM_BASE + start
        if use_thumb:
            entry_addr |= 1
        proj = angr.load_shellcode(
            data_copy,
            "armel",
            start_offset=start,
            load_address=GBA_ROM_BASE,
            thumb=use_thumb,
            auto_load_libs=False,
        )
        region_start = GBA_ROM_BASE + start
        region_end = GBA_ROM_BASE + end
        cfg = proj.analyses.CFGFast(
            regions=[(region_start, region_end)],
            function_starts=[entry_addr],
            start_at_entry=True,
            normalize=True,  # required for Decompiler
            switch_mode_on_nodecode=True,  # helps with ARM/Thumb mixed code
        )
        out_lines: List[str] = []
        errors: List[str] = []
        funcs_in_region = [
            (addr, func)
            for addr, func in cfg.kb.functions.items()
            if func.addr < region_end and (func.addr + (func.size or 0)) > region_start
        ]
        if not funcs_in_region:
            funcs_in_region = list(cfg.kb.functions.items())
        constants = {c["Name"]: c.get("Value", 0) for c in self._toml_data.get("Constants", [])}
        for addr, func in sorted(funcs_in_region, key=lambda x: x[0]):
            try:
                dec = proj.analyses.Decompiler(func, cfg=cfg)
                if dec and dec.codegen and dec.codegen.text:
                    raw_codegen = dec.codegen.text
                    anchor = self._get_function_anchor_for_decompilation(addr)
                    if anchor:
                        # Replace angr output with TOML-derived struct(s) + externs + signature
                        repl: List[str] = []
                        for struct_def in self._get_struct_defs_from_anchor(anchor, constants):
                            repl.append(struct_def)
                        if repl:
                            repl.append("")
                        externs = self._extract_extern_lines(raw_codegen)
                        if externs:
                            repl.extend(externs)
                            repl.append("")
                        sig = self._format_sig_from_anchor(anchor, constants)
                        repl.append(sig)
                        body = self._extract_angr_function_body(raw_codegen)
                        if body:
                            struct_names = self._get_struct_names_from_anchor(anchor)
                            body = self._rewrite_angr_struct_refs(body, struct_names)
                            param_names = self._get_param_names_from_anchor(anchor)
                            body = self._rewrite_angr_param_refs(body, param_names)
                            body = self._rewrite_param_aliases(body, param_names)
                            body = self._rewrite_struct_offsets_to_fields(body, param_names, anchor, constants)
                            body = self._remove_unused_assignments(body)
                            body = self._rewrite_decimal_addresses_to_hex(body)
                            body = self._indent_function_body(body)
                            repl.append(body)
                        out_lines.extend(repl)
                    else:
                        out_lines.append(f"/* sub_{addr:08X} */")
                        out_lines.append(raw_codegen.strip())
                    out_lines.append("")
            except Exception as e:
                err_msg = str(e).replace("\n", " ")[:120]
                errors.append(f"sub_{addr:08X}: {err_msg}")
        if errors and not out_lines:
            return "(angr decompilation failed)\n\n" + "\n".join(errors[:8]) + (
                "\n\n(... more)" if len(errors) > 8 else ""
            )
        if out_lines:
            if errors:
                out_lines.insert(0, "/* Some functions failed: " + "; ".join(errors[:2]) + " */\n")
            return self._apply_symbol_names_to_decompiler_text("\n".join(out_lines))
        return None

    def _refresh_pseudo_c_capstone_fallback(self, start: int, end: int, align: int) -> None:
        """Fallback: pattern-based pseudo-C when angr unavailable."""
        if not _CAPSTONE_AVAILABLE:
            self._text_pseudo_c.insert(tk.END, "(Capstone not available)")
            self._text_pseudo_c.configure(state=tk.DISABLED)
            return
        mode = CS_MODE_THUMB if self._asm_mode == "thumb" else CS_MODE_ARM
        ldr_targets = self._get_ldr_pc_targets(mode)
        chunk = bytes(self._data[start:end])
        base = GBA_ROM_BASE + start
        cs = Cs(CS_ARCH_ARM, mode)
        cs.detail = True
        lines: List[str] = []
        try:
            for i in cs.disasm(chunk, base):
                file_off = i.address - GBA_ROM_BASE
                if self._is_ldr_word_pool(file_off, ldr_targets):
                    continue
                if file_off >= end:
                    break
                line = self._insn_to_pseudo_c(i, mode)
                if line:
                    lines.append(line + "\n")
        except Exception:
            pass
        content = "".join(lines) if lines else "(No instructions)"
        if lines and content != "(No instructions)":
            content = self._apply_symbol_names_to_decompiler_text(content)
        self._text_pseudo_c.insert(tk.END, content)
        if lines:
            self._apply_syntax_highlighting(self._text_pseudo_c, "c")
        self._text_pseudo_c.configure(state=tk.DISABLED)

    def _insn_to_pseudo_c(self, insn: object, mode: int) -> str:
        """Convert a Capstone instruction to pseudo-C line."""
        m = insn.mnemonic
        ops = insn.op_str
        if not ops:
            return f"// {m}"
        parts = [p.strip() for p in ops.split(",")]
        dst = parts[0] if parts else ""
        if m in ("mov", "movs", "movw", "mvn", "mvns"):
            return f"{dst} = {self._op_to_c(parts[1] if len(parts) > 1 else '')};"
        if m in ("add", "adds", "adc", "adcs"):
            if len(parts) >= 3:
                return f"{dst} = {self._op_to_c(parts[1])} + {self._op_to_c(parts[2])};"
            return f"{dst} += {self._op_to_c(parts[1])};"
        if m in ("sub", "subs", "sbc", "sbcs"):
            if len(parts) >= 3:
                return f"{dst} = {self._op_to_c(parts[1])} - {self._op_to_c(parts[2])};"
            return f"{dst} -= {self._op_to_c(parts[1])};"
        if m in ("and", "ands", "orr", "orrs", "eor", "eors", "bic", "bics"):
            op_map = {"and": "&", "ands": "&", "orr": "|", "orrs": "|", "eor": "^", "eors": "^", "bic": "& ~", "bics": "& ~"}
            sym = op_map.get(m, "&")
            if len(parts) >= 3:
                return f"{dst} = {self._op_to_c(parts[1])} {sym} {self._op_to_c(parts[2])};"
            return f"{dst} {sym}= {self._op_to_c(parts[1])};"
        if m in ("lsl", "lsls", "lsr", "lsrs", "asr", "asrs", "ror", "rors"):
            shift_map = {"lsl": "<<", "lsls": "<<", "lsr": ">>", "lsrs": ">>", "asr": ">>", "asrs": ">>", "ror": ">>>", "rors": ">>>"}
            sym = shift_map.get(m, "<<")
            if len(parts) >= 3:
                return f"{dst} = {self._op_to_c(parts[1])} {sym} {self._op_to_c(parts[2])};"
            return f"{dst} {sym}= {self._op_to_c(parts[1])};"
        if m in ("mul", "muls"):
            if len(parts) >= 3:
                return f"{dst} = {self._op_to_c(parts[1])} * {self._op_to_c(parts[2])};"
        if m in ("mla", "mlas") and len(parts) >= 4:
            return f"{dst} = {self._op_to_c(parts[1])} * {self._op_to_c(parts[2])} + {self._op_to_c(parts[3])};"
        if m == "mls" and len(parts) >= 4:
            return f"{dst} = {self._op_to_c(parts[3])} - {self._op_to_c(parts[1])} * {self._op_to_c(parts[2])};"
        if m in ("ldr", "ldrb", "ldrh"):
            if "[" in ops and len(parts) > 1:
                return f"{dst} = *({self._mem_to_c(parts[1])});"
            if len(parts) > 1:
                return f"{dst} = {self._op_to_c(parts[1])};"
        if m in ("str", "strb", "strh"):
            if "[" in ops and len(parts) > 1:
                return f"*({self._mem_to_c(parts[1])}) = {dst};"
            if len(parts) > 1:
                return f"*({self._op_to_c(parts[1])}) = {dst};"
        if m in ("cmp", "cmn", "tst", "teq"):
            return f"// {m} {ops} (flags)"
        if m in ("b", "bl", "bx", "blx"):
            if m == "bl":
                return f"call {self._op_to_c(parts[0])};"
            if m == "bx":
                return f"return {self._op_to_c(parts[0])};"
            return f"goto {self._op_to_c(parts[0])};"
        if m in ("push", "pop"):
            return f"// {m} {{{ops}}}"
        if m in ("bhi", "bls", "bhs", "blo", "bmi", "bpl", "bvs", "bvc", "bgt", "ble", "bge", "blt", "bne", "beq"):
            return f"if (cond) goto {self._op_to_c(parts[0])};  // {m}"
        return f"// {m} {ops}"

    def _op_to_c(self, s: str) -> str:
        """Convert operand string to C-like form."""
        s = s.strip()
        s = re.sub(r"#0x([0-9a-fA-F]+)", r"0x\1", s)
        s = re.sub(r"#(\d+)", r"\1", s)
        return s

    def _mem_to_c(self, ops: str) -> str:
        """Convert memory operand [base, #offs] or [base] to C pointer form."""
        m = re.search(r"\[([^\]]+)\]", ops)
        if not m:
            return ops
        inner = m.group(1).strip()
        inner = re.sub(r"#0x([0-9a-fA-F]+)", r"0x\1", inner)
        inner = re.sub(r"#(-?\d+)", r"\1", inner)
        if ", " in inner:
            base, off = inner.split(", ", 1)
            return f"({base} + {off})"
        return inner

    def _get_ldr_pc_targets(self, mode: int) -> Set[int]:
        """Set of file offsets that are load targets of LDR [pc, #imm].
        Uses fast brute-force byte scan (no Capstone needed). Cached."""
        if self._ldr_pc_targets_valid and self._ldr_pc_targets is not None:
            return self._ldr_pc_targets
        targets: Set[int] = set()
        if not self._data:
            self._ldr_pc_targets = targets
            self._ldr_pc_targets_valid = True
            return targets
        data = self._data
        data_len = len(data)

        # Thumb-16 LDR Rd, [PC, #imm8*4]: encoding 0100_1xxx in high byte
        for off in range(0, data_len - 1, 2):
            hi = data[off + 1]
            if 0x48 <= hi <= 0x4F:
                imm8 = data[off]
                insn_addr = GBA_ROM_BASE + off
                target = ((insn_addr + 4) & ~3) + imm8 * 4
                file_off = target - GBA_ROM_BASE
                if 0 <= file_off and file_off + 3 < data_len:
                    targets.add(file_off)

        # ARM LDR/LDRB Rd, [PC, #±imm12]: cond 0101 UB01 1111 Rd imm12
        for off in range(0, data_len - 3, 4):
            word = data[off] | (data[off + 1] << 8) | (data[off + 2] << 16) | (data[off + 3] << 24)
            if (word & 0x0F3F0000) == 0x051F0000:
                imm12 = word & 0xFFF
                u = (word >> 23) & 1
                disp = imm12 if u else -imm12
                insn_addr = GBA_ROM_BASE + off
                target = insn_addr + 8 + disp
                file_off = target - GBA_ROM_BASE
                if 0 <= file_off and file_off + 3 < data_len:
                    targets.add(file_off)

        self._ldr_pc_targets = targets
        self._ldr_pc_targets_valid = True
        return targets

    def _get_ldr_pc_target_addr(self, insn: object, mode: int) -> Optional[int]:
        """If insn is LDR/LDRB/LDRH with [pc, #imm], return the resolved load target address (GBA ROM addr)."""
        if not _CAPSTONE_AVAILABLE or insn.mnemonic not in ("ldr", "ldrb", "ldrh"):
            return None
        disp = None
        for op in insn.operands:
            if op.type == ARM_OP_MEM and op.value.mem.base == ARM_REG_PC:
                disp = op.value.mem.disp
                break
        if disp is None:
            return None
        addr = insn.address
        if mode == CS_MODE_ARM:
            pc = (addr + 8) & ~3
            return pc + disp
        pc = (addr + 4) & ~3
        return pc + disp

    _BRANCH_MNEMONICS = frozenset((
        "b", "bl", "beq", "bne", "bgt", "bge", "blt", "ble",
        "bhi", "bls", "bhs", "blo", "bmi", "bpl", "bvs", "bvc",
    ))

    def _get_branch_target_from_insn(self, insn: object, mode: int) -> Optional[int]:
        """If instruction is a branch with immediate target or LDR [pc], return file offset of target."""
        if not _CAPSTONE_AVAILABLE:
            return None
        m = insn.mnemonic
        if m in self._BRANCH_MNEMONICS:
            match = re.search(r"#0x([0-9A-Fa-f]+)\b", insn.op_str)
            if match:
                addr = int(match.group(1), 16)
                if (addr >> 24) in (0x08, 0x09):
                    return addr - GBA_ROM_BASE
        if m in ("ldr", "ldrb", "ldrh"):
            addr = self._get_ldr_pc_target_addr(insn, mode)
            if addr is not None:
                return addr - GBA_ROM_BASE
        return None

    def _get_ldr_pc_comment(self, insn: object, mode: int, hackmew: bool = False) -> Optional[str]:
        """If insn is LDR/LDRB/LDRH with [pc, #imm], return comment. Standard: @ <loc_X> = #val. HackMew: @ #offset = #val."""
        target_addr = self._get_ldr_pc_target_addr(insn, mode)
        if target_addr is None:
            return None
        file_off = target_addr - GBA_ROM_BASE
        if file_off < 0:
            return None
        n = 4 if insn.mnemonic == "ldr" else (2 if insn.mnemonic == "ldrh" else 1)
        if file_off + n > len(self._data):
            return None
        val = sum(self._data[file_off + i] << (i * 8) for i in range(n))
        if hackmew:
            if mode == CS_MODE_THUMB:
                pc_val = (insn.address + 4) & ~3
            else:
                pc_val = insn.address + 8
            offset = target_addr - pc_val
            return f"#0x{offset & 0xFFFFFFFF:x} = #0x{val:0{n * 2}X}"
        return f"<loc_{target_addr:08X}> = #0x{val:0{n * 2}X}"

    def _is_ldr_word_pool(self, file_off: int, ldr_targets: Set[int]) -> bool:
        """True if file_off is an LDR [pc] target and the 4-byte value is a ROM pointer (<=0x09FFFFFF)."""
        if file_off not in ldr_targets or file_off + 4 > len(self._data):
            return False
        val = (
            self._data[file_off]
            | (self._data[file_off + 1] << 8)
            | (self._data[file_off + 2] << 16)
            | (self._data[file_off + 3] << 24)
        )
        return val <= GBA_ROM_MAX

    def _collect_branch_targets(
        self,
        start: int,
        end: int,
        mode: int,
        insn_map: Dict[int, object],
        ldr_targets: Set[int],
    ) -> Set[int]:
        """Collect file offsets that are actually jumped to by branch instructions.
        Does NOT add .word pointees (those are data, not branch targets).
        Skips instructions that overlap .word pools (misdisassembled data)."""
        targets: Set[int] = set()
        data_len = len(self._data)
        for file_off, insn in insn_map.items():
            if file_off < start or file_off >= end:
                continue
            # Skip "instructions" that overlap .word data - Capstone misdisassembles data as code
            if self._is_ldr_word_pool(file_off, ldr_targets):
                continue
            insn_end = file_off + len(insn.bytes)
            if any(
                self._is_ldr_word_pool(t, ldr_targets)
                for t in range(file_off, insn_end)
            ):
                continue
            t = self._get_branch_target_from_insn(insn, mode)
            if t is not None and 0 <= t < data_len:
                targets.add(t)
        return targets

    def _build_asm_export_lines_with_labels(self, hackmew: bool = False) -> List[str]:
        """Build ASM export lines with labels at branch targets and label refs instead of raw offsets."""
        if not self._data or not _CAPSTONE_AVAILABLE:
            return []
        mode = CS_MODE_THUMB if self._asm_mode == "thumb" else CS_MODE_ARM
        align = 4
        if self._selection_start is not None and self._selection_end is not None:
            start = min(self._selection_start, self._selection_end)
            end = max(self._selection_start, self._selection_end) + 1
            start = (start // align) * align
        else:
            vis_start = self._visible_row_start * BYTES_PER_ROW
            vis_end = min(
                vis_start + self._visible_row_count * BYTES_PER_ROW, len(self._data)
            )
            start = (vis_start // align) * align
            end = vis_end
        if start >= len(self._data):
            return []
        end = min(end, len(self._data))

        ldr_targets = self._get_ldr_pc_targets(mode)
        chunk = bytes(self._data[start:end])
        base = GBA_ROM_BASE + start
        cs = Cs(CS_ARCH_ARM, mode)
        cs.detail = True
        insn_map: Dict[int, object] = {}
        try:
            for i in cs.disasm(chunk, base):
                file_off = i.address - GBA_ROM_BASE
                insn_map[file_off] = i
        except Exception:
            pass

        branch_targets = self._collect_branch_targets(
            start, end, mode, insn_map, ldr_targets
        )
        label_offsets = branch_targets | {
            fo for fo in ldr_targets
            if start <= fo < end and self._is_ldr_word_pool(fo, ldr_targets)
        }
        target_to_label: Dict[int, str] = {
            fo: f"loc_{GBA_ROM_BASE + fo:08X}" for fo in label_offsets
        }

        def replace_addrs_with_labels(text: str, local_only: bool = False) -> str:
            def repl(m: re.Match) -> str:
                addr = int(m.group(1), 16)
                fo = addr - GBA_ROM_BASE
                if local_only and (fo < start or fo >= end):
                    return m.group(0)
                return target_to_label.get(fo, m.group(0))
            return re.sub(r"#0x([0-9A-Fa-f]+)\b", repl, text)

        output: List[str] = []
        offset = start
        while offset < end:
            file_off = offset
            if file_off in target_to_label:
                if output:
                    output.append("")
                output.append(f"{target_to_label[file_off]}:")
            if file_off in ldr_targets and self._is_ldr_word_pool(file_off, ldr_targets):
                b0 = self._data[file_off]
                b1 = self._data[file_off + 1] if file_off + 1 < len(self._data) else 0
                b2 = self._data[file_off + 2] if file_off + 2 < len(self._data) else 0
                b3 = self._data[file_off + 3] if file_off + 3 < len(self._data) else 0
                val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
                if hackmew:
                    line = f".word 0x{val:X}"
                else:
                    line = f".word #0x{val:08X}"
                line = replace_addrs_with_labels(line, local_only=hackmew)
                output.append(line)
                offset += 4
            elif file_off in insn_map:
                insn = insn_map[file_off]
                raw = insn.bytes
                insn_end = file_off + len(raw)
                overlaps_target = any(
                    self._is_ldr_word_pool(t, ldr_targets)
                    for t in range(file_off + 1, insn_end)
                )
                if overlaps_target:
                    offset += align
                    continue
                mnemonic, op_str = insn.mnemonic, insn.op_str
                operands = f" {op_str}" if op_str else ""
                comment = self._get_ldr_pc_comment(insn, mode, hackmew=hackmew)
                if comment:
                    operands += f"  @ {comment}"
                line = f"{mnemonic}{operands}"
                line = replace_addrs_with_labels(line, local_only=hackmew)
                if hackmew:
                    ldr_target = self._get_ldr_pc_target_addr(insn, mode)
                    if ldr_target is not None:
                        fo = ldr_target - GBA_ROM_BASE
                        label = target_to_label.get(fo)
                        if label and "[" in op_str and "pc" in op_str.lower():
                            line = re.sub(
                                r"\[\s*pc\s*,\s*#?0x[0-9A-Fa-f]+\s*\]",
                                f"[pc, <{label}>]",
                                line,
                                count=1,
                            )
                    line = re.sub(r"\badds\b", "add", line)
                    line = re.sub(r"\bsubs\b", "sub", line)
                    line = re.sub(r"\blsls\b", "lsl", line)
                    line = re.sub(r"\blsrs\b", "lsr", line)
                    line = re.sub(r"\bmuls\b", "mul", line)
                    line = re.sub(r"\basrs\b", "asr", line)
                    line = re.sub(r"\beors\b", "eor", line)
                    line = re.sub(r"\bands\b", "and", line)
                    line = re.sub(r"\borrs\b", "orr", line)
                    line = re.sub(r"\bbics\b", "bic", line)
                    if re.match(
                        r"(?:b|bl|bx|blx|beq|bne|bgt|bge|blt|ble|bhi|bls|bhs|blo|bmi|bpl|bvs|bvc)\b",
                        line,
                    ):
                        line = line.replace("#", "")
                output.append(line.strip())
                offset += len(raw)
            else:
                if align == 2:
                    b0 = self._data[offset]
                    b1 = self._data[offset + 1] if offset + 1 < len(self._data) else 0
                    line = f".byte 0x{b0:02x}, 0x{b1:02x}"
                else:
                    b0 = self._data[offset]
                    b1 = self._data[offset + 1] if offset + 1 < len(self._data) else 0
                    b2 = self._data[offset + 2] if offset + 2 < len(self._data) else 0
                    b3 = self._data[offset + 3] if offset + 3 < len(self._data) else 0
                    val = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
                    if hackmew:
                        line = f".word 0x{val:X}"
                    else:
                        line = f".word #0x{val:08X}"
                output.append(line)
                offset += align
        return output

    # ── Rendering ────────────────────────────────────────────────────

    def _refresh_visible(self) -> None:
        """Render exactly _visible_row_count rows into hex and ASCII widgets."""
        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text_ascii.configure(state=tk.NORMAL)
        self._text_ascii.delete("1.0", tk.END)

        if not self._data:
            self._text.insert(tk.END, "(No data)")
            self._update_cursor_display()
            return

        row_end = min(self._visible_row_start + self._visible_row_count, self._total_rows)
        hex_lines = []
        ascii_lines = []
        for row in range(self._visible_row_start, row_end):
            rs = row * BYTES_PER_ROW
            rb = self._data[rs: rs + BYTES_PER_ROW]
            hx = " ".join(f"{b:02X}" for b in rb)
            asc = "".join(self._byte_to_char(b) for b in rb)
            carets: List[str] = []
            for bi in range(BYTES_PER_ROW):
                bo = rs + bi
                has = False
                if self._xref_index_valid:
                    has = bo in self._xref_rom_word or bo in self._xref_bl
                carets.append("›" if has else "·")
            caret_str = "".join(carets)
            hex_lines.append(f"{rs:08X}  {caret_str}  {hx.ljust(3 * BYTES_PER_ROW - 1)}\n")
            ascii_lines.append(f"|{asc}|\n")
        self._text.insert("1.0", "".join(hex_lines))
        self._text_ascii.insert("1.0", "".join(ascii_lines))

        # Pointer tags (both widgets)
        self._text.tag_remove("pointer", "1.0", tk.END)
        self._text.tag_remove("xref_caret", "1.0", tk.END)
        self._text_ascii.tag_remove("pointer", "1.0", tk.END)
        vis_start = self._visible_row_start * BYTES_PER_ROW
        vis_end = row_end * BYTES_PER_ROW
        off = (max(0, vis_start - 3) // 4) * 4
        while off + 4 <= len(self._data) and off < vis_end:
            if self._data[off + 3] in (0x08, 0x09):
                for i in range(4):
                    bo = off + i
                    br = bo // BYTES_PER_ROW
                    bc = bo % BYTES_PER_ROW
                    if self._visible_row_start <= br < row_end:
                        dr = br - self._visible_row_start + 1
                        self._text.tag_add(
                            "pointer",
                            f"{dr}.{HEX_DISP_HEX_START + bc * 3}",
                            f"{dr}.{HEX_DISP_HEX_START + 2 + bc * 3}",
                        )
                        self._text_ascii.tag_add("pointer", f"{dr}.{1 + bc}", f"{dr}.{2 + bc}")
            off += 4
        # Blue carets (incoming refs)
        for row in range(self._visible_row_start, row_end):
            rs = row * BYTES_PER_ROW
            dr = row - self._visible_row_start + 1
            for bi in range(BYTES_PER_ROW):
                bo = rs + bi
                if self._xref_index_valid and (bo in self._xref_rom_word or bo in self._xref_bl):
                    cc = HEX_DISP_CARET_START + bi
                    self._text.tag_add("xref_caret", f"{dr}.{cc}", f"{dr}.{cc + 1}")

        self._text.tag_raise("xref_caret")
        self._text.tag_raise("pointer")

        self._update_cursor_display()

    # ── Coordinate helpers ───────────────────────────────────────────

    def _offset_to_index(self, offset: int) -> Optional[str]:
        if offset < 0 or offset >= len(self._data):
            return None
        fr = offset // BYTES_PER_ROW
        if fr < self._visible_row_start or fr >= self._visible_row_start + self._visible_row_count:
            return None
        dr = fr - self._visible_row_start + 1
        return f"{dr}.{HEX_DISP_HEX_START + (offset % BYTES_PER_ROW) * 3}"

    def _index_to_offset(self, index: str) -> Optional[int]:
        """Map hex widget index to byte offset. Address (col 0-9) maps to first byte of row."""
        try:
            line, col = index.split(".")
            ln = int(line)
            cn = int(col)
        except (ValueError, TypeError):
            return None
        if ln < 1 or not self._data:
            return None
        fr = self._visible_row_start + (ln - 1)
        if cn < HEX_DISP_ADDR_END:
            off = fr * BYTES_PER_ROW
        elif cn < HEX_DISP_CARET_END:
            bc = cn - HEX_DISP_CARET_START
            off = fr * BYTES_PER_ROW + min(bc, BYTES_PER_ROW - 1)
        elif cn < HEX_DISP_HEX_START:
            off = fr * BYTES_PER_ROW
        else:
            bc = (cn - HEX_DISP_HEX_START) // 3
            if bc >= BYTES_PER_ROW:
                off = fr * BYTES_PER_ROW + BYTES_PER_ROW - 1
            else:
                off = fr * BYTES_PER_ROW + bc
        return max(0, min(off, len(self._data) - 1))

    def _ascii_index_to_offset(self, index: str) -> Optional[int]:
        """Map ASCII widget index to byte offset. Format: |..16 chars..| per line."""
        try:
            line, col = index.split(".")
            ln = int(line)
            cn = int(col)
        except (ValueError, TypeError):
            return None
        if ln < 1 or not self._data:
            return None
        fr = self._visible_row_start + (ln - 1)
        if cn < 1:
            off = fr * BYTES_PER_ROW
        elif cn > BYTES_PER_ROW:
            off = fr * BYTES_PER_ROW + BYTES_PER_ROW - 1
        else:
            off = fr * BYTES_PER_ROW + (cn - 1)
        return max(0, min(off, len(self._data) - 1))

    def _ensure_cursor_visible(self) -> bool:
        if not self._data:
            return False
        self._cursor_byte_offset = max(0, min(self._cursor_byte_offset, len(self._data) - 1))
        cr = self._cursor_byte_offset // BYTES_PER_ROW
        if cr < self._visible_row_start:
            self._visible_row_start = max(0, cr)
            return True
        elif cr >= self._visible_row_start + self._visible_row_count:
            self._visible_row_start = cr - self._visible_row_count + 1
            return True
        return False

    # ── Cursor / selection display ───────────────────────────────────

    def _update_cursor_display(self) -> None:
        self._text.tag_remove("cursor_byte", "1.0", tk.END)
        self._text.tag_remove("sel_hex", "1.0", tk.END)
        self._text_ascii.tag_remove("cursor_byte", "1.0", tk.END)
        self._text_ascii.tag_remove("sel_ascii", "1.0", tk.END)
        if not self._data:
            return
        self._cursor_byte_offset = max(0, min(self._cursor_byte_offset, len(self._data) - 1))
        fo = self._cursor_byte_offset
        self._cursor_offset_var.set(
            f"{GBA_ROM_BASE + fo:08X}" if self._data else ""
        )

        idx = self._offset_to_index(self._cursor_byte_offset)
        idx_asc = self._offset_to_ascii_index(self._cursor_byte_offset)
        if idx:
            self._text.tag_add("cursor_byte", idx, f"{idx}+2c")
            self._text.mark_set("insert", idx)
        if idx_asc:
            self._text_ascii.tag_add("cursor_byte", idx_asc, f"{idx_asc}+1c")
            self._text_ascii.mark_set("insert", idx_asc)

        if self._selection_start is not None and self._selection_end is not None:
            s = min(self._selection_start, self._selection_end)
            e = max(self._selection_start, self._selection_end)
            count = e - s + 1
            self._selection_label.config(text=f"{count} bytes (0x{count:X})")
            vis_start = self._visible_row_start * BYTES_PER_ROW
            vis_end = min(
                (self._visible_row_start + self._visible_row_count) * BYTES_PER_ROW,
                len(self._data),
            )
            first_vis = max(s, vis_start)
            last_vis = min(e, vis_end - 1) if vis_end > 0 else e
            if first_vis <= last_vis:
                first_row = first_vis // BYTES_PER_ROW
                last_row = last_vis // BYTES_PER_ROW
                for row in range(first_row, last_row + 1):
                    row_start_off = max(s, row * BYTES_PER_ROW)
                    row_end_off = min(e, row * BYTES_PER_ROW + BYTES_PER_ROW - 1)
                    ix_s = self._offset_to_index(row_start_off)
                    ix_e = self._offset_to_index(row_end_off)
                    if ix_s and ix_e:
                        self._text.tag_add("sel_hex", ix_s, f"{ix_e}+2c")
                    aix_s = self._offset_to_ascii_index(row_start_off)
                    aix_e = self._offset_to_ascii_index(row_end_off)
                    if aix_s and aix_e:
                        self._text_ascii.tag_add("sel_ascii", aix_s, f"{aix_e}+1c")
            self._text.tag_raise("sel_hex")
            self._text_ascii.tag_raise("sel_ascii")
        else:
            self._selection_label.config(text="")
        self._text.tag_raise("cursor_byte")
        self._text_ascii.tag_raise("cursor_byte")

        self._refresh_asm_selection()

    # ── Mouse interaction ────────────────────────────────────────────

    def _on_click(self, event: tk.Event) -> Optional[str]:
        # Must take focus (same as ASCII pane); otherwise after Ctrl+G the Goto entry keeps focus and
        # typed hex digits go there instead of into the hex buffer editor.
        self._text.focus_set()
        idx = self._text.index(f"@{event.x},{event.y}")
        off = self._index_to_offset(idx)
        if off is not None:
            self._cursor_byte_offset = off
            if event.state & 0x1:  # Shift held - extend selection
                if self._selection_start is not None and self._selection_end is not None:
                    s, e = self._selection_start, self._selection_end
                    self._selection_start = min(s, e, off)
                    self._selection_end = max(s, e, off)
                else:
                    self._selection_start = off
                    self._selection_end = off
            else:
                self._selection_start = None
                self._selection_end = None
            self._nibble_pos = 0
            self._update_cursor_display()
        return "break"

    def _on_drag(self, event: tk.Event) -> Optional[str]:
        if not self._data:
            return "break"
        h = self._text.winfo_height()
        margin = 24
        if event.y < margin and self._visible_row_start > 0:
            step = max(1, (margin - event.y) // 8)
            self._visible_row_start = max(0, self._visible_row_start - step)
            self._refresh_visible()
            self._update_scrollbar()
            return "break"
        if event.y > h - margin:
            max_start = max(0, self._total_rows - self._visible_row_count)
            if self._visible_row_start < max_start:
                step = max(1, (event.y - (h - margin)) // 8)
                self._visible_row_start = min(max_start, self._visible_row_start + step)
                self._refresh_visible()
                self._update_scrollbar()
                return "break"
        idx = self._text.index(f"@{event.x},{event.y}")
        off = self._index_to_offset(idx)
        if off is not None:
            if self._selection_start is None:
                self._selection_start = self._cursor_byte_offset
            self._selection_end = off
            self._update_cursor_display()
        return "break"

    def _on_ascii_click(self, event: tk.Event) -> Optional[str]:
        self._text_ascii.focus_set()
        idx = self._text_ascii.index(f"@{event.x},{event.y}")
        off = self._ascii_index_to_offset(idx)
        if off is not None:
            self._cursor_byte_offset = off
            if event.state & 0x1:  # Shift held - extend selection
                if self._selection_start is not None and self._selection_end is not None:
                    s, e = self._selection_start, self._selection_end
                    self._selection_start = min(s, e, off)
                    self._selection_end = max(s, e, off)
                else:
                    self._selection_start = off
                    self._selection_end = off
            else:
                self._selection_start = None
                self._selection_end = None
            self._nibble_pos = 0
            self._update_cursor_display()
        return "break"

    def _on_ascii_drag(self, event: tk.Event) -> Optional[str]:
        if not self._data:
            return "break"
        h = self._text_ascii.winfo_height()
        margin = 24
        if event.y < margin and self._visible_row_start > 0:
            step = max(1, (margin - event.y) // 8)
            self._visible_row_start = max(0, self._visible_row_start - step)
            self._refresh_visible()
            self._update_scrollbar()
            return "break"
        if event.y > h - margin:
            max_start = max(0, self._total_rows - self._visible_row_count)
            if self._visible_row_start < max_start:
                step = max(1, (event.y - (h - margin)) // 8)
                self._visible_row_start = min(max_start, self._visible_row_start + step)
                self._refresh_visible()
                self._update_scrollbar()
                return "break"
        idx = self._text_ascii.index(f"@{event.x},{event.y}")
        off = self._ascii_index_to_offset(idx)
        if off is not None:
            if self._selection_start is None:
                self._selection_start = self._cursor_byte_offset
            self._selection_end = off
            self._update_cursor_display()
        return "break"

    def _find_function_extent(self, offset: int) -> Optional[Tuple[int, int]]:
        """From a byte offset (assumed function start), find extent: (start, end_inclusive).
        End is the byte after the bx instruction plus any tailing LDR pool words used in the function.
        Returns None if Capstone unavailable or no bx found."""
        if not self._data or not _CAPSTONE_AVAILABLE:
            return None
        align = 4
        start = (offset // align) * align
        if start >= len(self._data):
            return None
        mode = CS_MODE_THUMB if self._asm_mode == "thumb" else CS_MODE_ARM
        ldr_targets = self._get_ldr_pc_targets(mode)
        cs = Cs(CS_ARCH_ARM, mode)
        cs.detail = True
        bx_end: Optional[int] = None
        ldr_file_offsets: List[int] = []
        try:
            chunk = bytes(self._data[start : min(start + 0x2000, len(self._data))])
            for i in cs.disasm(chunk, GBA_ROM_BASE + start):
                file_off = i.address - GBA_ROM_BASE
                if self._is_ldr_word_pool(file_off, ldr_targets):
                    continue
                if i.mnemonic == "bx":
                    bx_end = file_off + len(i.bytes)
                    break
                target = self._get_ldr_pc_target_addr(i, mode)
                if target is not None:
                    fo = target - GBA_ROM_BASE
                    if 0 <= fo < len(self._data):
                        ldr_file_offsets.append(fo)
        except Exception:
            return None
        if bx_end is None:
            return None
        end = bx_end - 1
        for fo in ldr_file_offsets:
            if fo >= bx_end:
                end = max(end, fo + 3)
        return (start, end)

    def _on_double_click(self, event: tk.Event) -> str:
        idx = self._text.index(f"@{event.x},{event.y}")
        off = self._index_to_offset(idx)
        if off is None:
            self._on_click(event)
            return "break"

        try:
            _, cn = idx.split(".")
            cn_i = int(cn)
        except (ValueError, TypeError):
            cn_i = HEX_DISP_HEX_START
        # Caret strip (blue ›): show incoming xref picker
        if HEX_DISP_CARET_START <= cn_i < HEX_DISP_CARET_END:
            try:
                line, _ = idx.split(".")
                ln = int(line)
                fr = self._visible_row_start + (ln - 1)
                bc = cn_i - HEX_DISP_CARET_START
                tgt = fr * BYTES_PER_ROW + bc
            except (ValueError, TypeError):
                tgt = off
            self._show_xref_dialog(tgt)
            return "break"

        on_addr_col = cn_i < HEX_DISP_ADDR_END

        if not on_addr_col and cn_i >= HEX_DISP_HEX_START:
            # Hex data: double-click a GBA pointer word → jump to target (overrides table/struct highlight)
            ptr_start = (off // 4) * 4
            if self._get_pointer_at_offset(ptr_start) is not None:
                if self._follow_pointer_at(ptr_start):
                    return "break"

        # Check if current offset falls within a NamedAnchor PCS table
        anchor_info = self._find_named_anchor_at_offset(off)
        if anchor_info:
            self._select_named_anchor_extent(anchor_info)
            if self._on_pointer_to_named_anchor_cb:
                self.after(10, lambda ai=anchor_info: self._on_pointer_to_named_anchor_cb(ai))
            return "break"

        extent = self._find_function_extent(off)
        if extent is not None:
            func_start, func_end = extent
            self._selection_start = func_start
            self._selection_end = func_end
            self._cursor_byte_offset = func_start
            if self._ensure_cursor_visible():
                self._update_scrollbar()
            self._refresh_visible()
            self._update_cursor_display()
            return "break"
        self._on_click(event)
        return "break"

    def _on_right_click(self, event: tk.Event) -> None:
        idx = self._text.index(f"@{event.x},{event.y}")
        off = self._index_to_offset(idx)
        menu = tk.Menu(self._text, tearoff=0)
        ptr_start = None
        if off is not None:
            s = (off // 4) * 4
            if self._get_pointer_at_offset(s) is not None:
                ptr_start = s
        if ptr_start is not None:
            menu.add_command(label="Follow pointer", command=lambda: self._follow_pointer_at(ptr_start))
        if off is not None:
            menu.add_command(
                label="Incoming references to this byte…",
                command=lambda o=off: self._show_xref_dialog(o),
            )
        if self._selection_start is not None and self._selection_end is not None and self._data:
            menu.add_command(label="Repoint bytes…", command=self._on_repoint_bytes)
        menu.add_command(label="Select all", command=lambda: self._select_all())
        menu.add_command(label="Go to offset...", command=self._on_goto_offset)
        menu.add_separator()
        export_menu = tk.Menu(menu, tearoff=0)
        export_menu.add_command(label="ASM to clipboard", command=self._export_asm_clipboard)
        export_menu.add_command(label="ASM to file...", command=self._export_asm_file)
        export_menu.add_command(label="HackMew ASM to clipboard", command=self._export_hackmew_clipboard)
        export_menu.add_command(label="Pseudo-C to clipboard", command=self._export_pseudo_c_clipboard)
        export_menu.add_command(label="Pseudo-C to file...", command=self._export_pseudo_c_file)
        menu.add_cascade(label="Export", menu=export_menu)
        menu.tk_popup(event.x_root, event.y_root)

    # ── Export helpers ────────────────────────────────────────────────

    def _get_asm_text_clean(self) -> str:
        """Get ASM export with labels at branch targets and label refs instead of raw offsets."""
        lines = self._build_asm_export_lines_with_labels(hackmew=False)
        return "\n".join(lines) if lines else ""

    def _get_pseudo_c_text(self) -> str:
        """Get pseudo-C pane content."""
        raw = self._text_pseudo_c.get("1.0", tk.END).strip()
        if not raw or raw.startswith("("):
            return ""
        return raw

    def _get_asm_text_hackmew(self) -> str:
        """Get ASM in HackMew style with labels: adds->add, subs->sub, strip # from branches and .word."""
        lines = self._build_asm_export_lines_with_labels(hackmew=True)
        return "\n".join(lines) if lines else ""

    def _export_asm_clipboard(self) -> None:
        text = self._get_asm_text_clean()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def _export_asm_file(self) -> None:
        text = self._get_asm_text_clean()
        if not text:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".asm",
            filetypes=[("ASM files", "*.asm"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Export ASM",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)

    def _export_hackmew_clipboard(self) -> None:
        text = self._get_asm_text_hackmew()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def _export_pseudo_c_clipboard(self) -> None:
        text = self._get_pseudo_c_text()
        if not text:
            return
        self.clipboard_clear()
        self.clipboard_append(text)

    def _export_pseudo_c_file(self) -> None:
        text = self._get_pseudo_c_text()
        if not text:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".c",
            filetypes=[("C files", "*.c"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Export Pseudo-C",
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)

    # ── Pointer helpers ──────────────────────────────────────────────

    def _get_pointer_at_offset(self, off: int) -> Optional[int]:
        if off < 0 or off > len(self._data) - 4 or off % 4 != 0:
            return None
        ptr = (
            self._data[off]
            | (self._data[off + 1] << 8)
            | (self._data[off + 2] << 16)
            | (self._data[off + 3] << 24)
        )
        if (ptr >> 24) in (0x08, 0x09):
            fo = ptr - GBA_ROM_BASE
            if 0 <= fo < len(self._data):
                return fo
        return None

    def _follow_pointer_at(self, off: int) -> bool:
        target = self._get_pointer_at_offset(off)
        if target is not None:
            self._cursor_byte_offset = target
            self._selection_start = self._selection_end = None
            self._visible_row_start = target // BYTES_PER_ROW
            self._refresh_visible()
            self._update_scrollbar()
            self._update_cursor_display()
            return True
        return False

    def _on_repoint_bytes(self) -> None:
        """Context menu: move selected bytes to free space and repoint references."""
        if not self._data or self._selection_start is None or self._selection_end is None:
            return
        src_lo = min(self._selection_start, self._selection_end)
        src_hi = max(self._selection_start, self._selection_end) + 1
        if src_hi <= src_lo:
            return
        dlg = _RepointBytesDialog(self.winfo_toplevel(), self, src_lo, src_hi)
        if dlg.result is None:
            return
        new_lo, fill_old, include_bl = dlg.result
        n_w, n_bl, bl_errs = _repoint_rom_for_moved_byte_range(
            self._data,
            src_lo,
            src_hi,
            new_lo,
            include_bl=include_bl,
            fill_old=fill_old,
        )
        delta = new_lo - src_lo
        n_toml, err_toml = self.shift_toml_named_anchors_for_repoint(src_lo, src_hi, delta)
        self._modified = True
        self._schedule_xref_rebuild()
        self._cursor_byte_offset = new_lo
        self._selection_start = new_lo
        self._selection_end = new_lo + (src_hi - src_lo) - 1
        self._visible_row_start = new_lo // BYTES_PER_ROW
        self._refresh_visible()
        self._update_scrollbar()
        self._update_cursor_display()
        msg = (
            f"Moved {src_hi - src_lo} byte(s) to file 0x{new_lo:08X} (GBA 0x{new_lo + GBA_ROM_BASE:08X}).\n"
            f"Updated {n_w} word-aligned pointer(s)"
        )
        if include_bl:
            msg += f"; repointed {n_bl} Thumb BL instruction(s)."
        else:
            msg += "."
        if n_toml:
            msg += f"\n\nUpdated {n_toml} [[NamedAnchors]] Address row(s) in the structure TOML."
        if err_toml:
            msg += f"\n\nTOML: {err_toml}"
        if bl_errs:
            msg += "\n\nBL out of range (not patched):\n" + "\n".join(bl_errs[:20])
            if len(bl_errs) > 20:
                msg += f"\n… and {len(bl_errs) - 20} more."
        parent = self.winfo_toplevel()
        if bl_errs or err_toml:
            messagebox.showwarning("Repoint bytes", msg, parent=parent)
        else:
            messagebox.showinfo("Repoint bytes", msg, parent=parent)

    def _invalidate_xref_index(self) -> None:
        self._xref_index_valid = False
        self._xref_rom_word.clear()
        self._xref_bl.clear()

    def _xref_build_after_load(self) -> None:
        """Build xref maps after opening a ROM (deferred so the window appears first)."""
        if not self._data:
            return
        self._build_xref_index()
        self._refresh_visible()
        self._update_cursor_display()

    def _schedule_xref_rebuild(self) -> None:
        """Debounce full xref scan (ROM words + BL) after ROM edits."""
        self._invalidate_xref_index()
        if self._xref_rebuild_after_id is not None:
            try:
                self.after_cancel(self._xref_rebuild_after_id)
            except (tk.TclError, ValueError):
                pass
            self._xref_rebuild_after_id = None
        if not self._data:
            return

        def _run() -> None:
            self._xref_rebuild_after_id = None
            if not self._data:
                return
            self._build_xref_index()
            self._refresh_visible()
            self._update_cursor_display()

        self._xref_rebuild_after_id = self.after(450, _run)

    def _build_xref_index(self) -> None:
        """Map each target file offset → sources: word-aligned ROM pointers, and Thumb BL/BLX sites (separate)."""
        self._xref_rom_word.clear()
        self._xref_bl.clear()
        n = len(self._data)
        if n <= 0:
            self._xref_index_valid = True
            return
        data = bytes(self._data)
        for off in range(0, n - 3, 4):
            ptr = int.from_bytes(data[off : off + 4], "little")
            if (ptr >> 24) in (0x08, 0x09):
                tgt = ptr - GBA_ROM_BASE
                if 0 <= tgt < n:
                    self._xref_rom_word.setdefault(tgt, []).append(off)
        # Thumb-2 BL: scan every 2 bytes and decode immediates manually. Linear Capstone disassembly
        # misses many BLs in mixed data/code ROMs because it loses instruction alignment.
        for off in range(0, n - 3, 2):
            hw1 = data[off] | (data[off + 1] << 8)
            hw2 = data[off + 2] | (data[off + 3] << 8)
            bl_addr = GBA_ROM_BASE + off
            tgt_gba = thumb2_bl_immediate_target_gba(hw1, hw2, bl_addr)
            if tgt_gba is None:
                continue
            if GBA_ROM_BASE <= tgt_gba <= GBA_ROM_MAX:
                tgt_fo = tgt_gba - GBA_ROM_BASE
                if 0 <= tgt_fo < n:
                    self._xref_bl.setdefault(tgt_fo, []).append(off)
        self._xref_index_valid = True

    def _ensure_xref_index(self) -> None:
        if not self._data:
            return
        if not self._xref_index_valid:
            self._build_xref_index()

    def _show_xref_dialog(self, target_off: int) -> None:
        """List incoming .word pointers and BL instructions; double-click to jump to source."""
        if not self._data:
            return
        self._ensure_xref_index()
        target_off = max(0, min(target_off, len(self._data) - 1))
        words = sorted(set(self._xref_rom_word.get(target_off, [])))
        bls = sorted(set(self._xref_bl.get(target_off, [])))
        if not words and not bls:
            messagebox.showinfo(
                "Cross-references",
                f"No references to file offset 0x{target_off:08X}\n"
                f"(GBA 0x{target_off + GBA_ROM_BASE:08X}).",
                parent=self.winfo_toplevel(),
            )
            return
        top = tk.Toplevel(self.winfo_toplevel())
        top.title(f"Refs to 0x{target_off:08X} (GBA 0x{target_off + GBA_ROM_BASE:08X})")
        top.transient(self.winfo_toplevel())
        ttk.Label(
            top,
            text="ROM .word pointers (0x08…… / 0x09……) that point here:",
            font=("Consolas", 9),
        ).grid(row=0, column=0, sticky="w", padx=6, pady=(6, 2))
        lb_w = tk.Listbox(top, font=("Consolas", 9), height=8, width=72, selectmode=tk.SINGLE)
        lb_w.grid(row=1, column=0, sticky="nsew", padx=6, pady=2)
        sw = ttk.Scrollbar(top, command=lb_w.yview)
        sw.grid(row=1, column=1, sticky="ns", pady=2)
        lb_w.configure(yscrollcommand=sw.set)
        for s in words:
            lb_w.insert(tk.END, f"file 0x{s:08X}  (word at start of pointer)  →  GBA 0x{s + GBA_ROM_BASE:08X}")
        if not words:
            lb_w.insert(tk.END, "(none)")

        ttk.Label(
            top,
            text="Thumb BL / BLX instructions that branch here (separate from .word pointers):",
            font=("Consolas", 9),
        ).grid(row=2, column=0, sticky="w", padx=6, pady=(8, 2))
        lb_b = tk.Listbox(top, font=("Consolas", 9), height=8, width=72, selectmode=tk.SINGLE)
        lb_b.grid(row=3, column=0, sticky="nsew", padx=6, pady=2)
        sb = ttk.Scrollbar(top, command=lb_b.yview)
        sb.grid(row=3, column=1, sticky="ns", pady=2)
        lb_b.configure(yscrollcommand=sb.set)
        for s in bls:
            lb_b.insert(tk.END, f"file 0x{s:08X}  (start of BL/BLX)  →  GBA 0x{s + GBA_ROM_BASE:08X}")
        if not bls:
            lb_b.insert(tk.END, "(none)")

        top.columnconfigure(0, weight=1)
        top.rowconfigure(1, weight=1)
        top.rowconfigure(3, weight=1)

        def _jump_from(off: int) -> None:
            if off < 0 or off >= len(self._data):
                return
            self._do_goto(off)
            top.destroy()

        def _on_w_double(_e: tk.Event) -> None:
            if not words:
                return
            i = lb_w.curselection()
            if not i:
                return
            _jump_from(words[i[0]])

        def _on_b_double(_e: tk.Event) -> None:
            if not bls:
                return
            i = lb_b.curselection()
            if not i:
                return
            _jump_from(bls[i[0]])

        lb_w.bind("<Double-Button-1>", _on_w_double)
        lb_b.bind("<Double-Button-1>", _on_b_double)

        def _go_word_btn() -> None:
            if not words:
                return
            i = lb_w.curselection()
            if not i:
                return
            _jump_from(words[i[0]])

        def _go_bl_btn() -> None:
            if not bls:
                return
            i = lb_b.curselection()
            if not i:
                return
            _jump_from(bls[i[0]])

        bf = ttk.Frame(top)
        bf.grid(row=4, column=0, columnspan=2, pady=6)
        ttk.Button(bf, text="Go to selected (.word)", command=_go_word_btn).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="Go to selected (BL)", command=_go_bl_btn).pack(side=tk.LEFT, padx=4)
        ttk.Button(bf, text="Close", command=top.destroy).pack(side=tk.LEFT, padx=12)

    # ── Dialogs ──────────────────────────────────────────────────────

    def _on_goto_offset(self) -> None:
        if not self._data:
            return
        dialog = tk.Toplevel(self)
        dialog.title("Go to offset")
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()
        ttk.Label(
            dialog,
            text="Anchor name, offset (hex), or GBA 0x08…:",
            font=("Consolas", 9),
        ).grid(row=0, column=0, padx=5, pady=5)
        entry = ttk.Entry(dialog, width=12)
        entry.grid(row=0, column=1, padx=5, pady=5)
        entry.insert(0, f"{self._cursor_byte_offset:08X}")
        entry.select_range(0, tk.END)
        entry.focus_set()

        def do_goto() -> None:
            raw = entry.get().strip()
            if not raw:
                return
            if self._goto_resolve_and_maybe_open_tool(raw):
                dialog.destroy()
                return
            ts = raw
            if ts.startswith("0x") or ts.startswith("0X"):
                ts = ts[2:]
            try:
                val = int(ts, 16)
                if val >= GBA_ROM_BASE and val < GBA_ROM_BASE + len(self._data):
                    val = val - GBA_ROM_BASE
                if 0 <= val < len(self._data):
                    self._do_goto(val)
                    dialog.destroy()
            except ValueError:
                pass

        ttk.Button(dialog, text="Go", command=do_goto).grid(row=1, column=0, columnspan=2, pady=5)
        entry.bind("<Return>", lambda e: do_goto())
        dialog.bind("<Escape>", lambda e: dialog.destroy())

    # ── Key handling ─────────────────────────────────────────────────

    def _select_all(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Select all in the focused editor: hex/ASCII (whole ROM) or Text panes (disasm / pseudo-C / hooks)."""
        w = self.winfo_toplevel().focus_get() if event is None else event.widget
        if w in (self._text, self._text_ascii):
            if self._data:
                self._selection_start = 0
                self._selection_end = len(self._data) - 1
                self._update_cursor_display()
            return "break"
        if w in (self._text_asm, self._text_pseudo_c, self._text_c_inject_patches, self._text_script, self._text_script_output):
            try:
                w.tag_remove("sel", "1.0", "end")
                w.tag_add("sel", "1.0", "end-1c")
                w.mark_set("insert", "1.0")
                w.see("insert")
            except tk.TclError:
                pass
            return "break"
        if isinstance(w, (tk.Entry, ttk.Entry)):
            try:
                w.select_range(0, tk.END)
            except tk.TclError:
                pass
            return "break"
        if w is None and self._data:
            self._selection_start = 0
            self._selection_end = len(self._data) - 1
            self._update_cursor_display()
        return "break"

    def _on_key(self, event: tk.Event) -> Optional[str]:
        if event.state & 0x4 and event.keysym.lower() == "a":
            self._select_all(event)
            return "break"
        if not self._data:
            return None
        if event.keysym == "Delete":
            return None
        if event.char and event.char in HEX_DIGITS:
            digit = int(event.char, 16)
            if self._insert_mode and self._nibble_pos == 0:
                self._data.insert(self._cursor_byte_offset, 0)
                self._modified = True
                self._ldr_pc_targets_valid = False
                self._schedule_xref_rebuild()
            b = self._data[self._cursor_byte_offset]
            if self._nibble_pos == 0:
                self._hex_pair_snapshot_byte = b
                self._data[self._cursor_byte_offset] = (b & 0x0F) | (digit << 4)
                self._nibble_pos = 1
            else:
                old_b = self._hex_pair_snapshot_byte if self._hex_pair_snapshot_byte is not None else b
                cur_off = self._cursor_byte_offset
                self._data[self._cursor_byte_offset] = (b & 0xF0) | digit
                new_b = self._data[self._cursor_byte_offset]
                self._hex_pair_snapshot_byte = None
                if not self._suppress_matched_word_propagate:
                    self._propagate_matched_word_byte_change(cur_off, old_b, new_b)
                self._nibble_pos = 0
                self._cursor_byte_offset = min(self._cursor_byte_offset + 1, len(self._data) - 1)
            self._modified = True
            self._ldr_pc_targets_valid = False
            self._schedule_xref_rebuild()
            self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
            self._ensure_cursor_visible()
            self._refresh_visible()
            self._update_scrollbar()
            self._refresh_asm_selection()
            return "break"
        return None

    def _on_delete(self, event: tk.Event) -> Optional[str]:
        if not self._data:
            return "break"
        if self._selection_start is not None and self._selection_end is not None:
            s = min(self._selection_start, self._selection_end)
            e = max(self._selection_start, self._selection_end)
            del self._data[s: e + 1]
            self._cursor_byte_offset = min(s, len(self._data) - 1) if self._data else 0
            self._selection_start = self._selection_end = None
        else:
            if self._cursor_byte_offset < len(self._data):
                del self._data[self._cursor_byte_offset]
                self._cursor_byte_offset = min(self._cursor_byte_offset, len(self._data) - 1)
        self._modified = True
        self._ldr_pc_targets_valid = False
        self._schedule_xref_rebuild()
        self._hex_pair_snapshot_byte = None
        self._nibble_pos = 0
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
        self._ensure_cursor_visible()
        self._refresh_visible()
        self._update_scrollbar()
        self._refresh_asm_selection()
        return "break"

    def _on_backspace(self, event: tk.Event) -> Optional[str]:
        if not self._data:
            return "break"
        if self._selection_start is not None and self._selection_end is not None:
            return self._on_delete(event)
        if self._cursor_byte_offset > 0:
            del self._data[self._cursor_byte_offset - 1]
            self._cursor_byte_offset -= 1
            self._modified = True
            self._ldr_pc_targets_valid = False
            self._schedule_xref_rebuild()
            self._hex_pair_snapshot_byte = None
            self._nibble_pos = 0
            self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
            self._ensure_cursor_visible()
            self._refresh_visible()
            self._update_scrollbar()
            self._refresh_asm_selection()
        return "break"

    # ── Cursor movement ──────────────────────────────────────────────

    def _move_cursor(self, delta: int) -> Optional[str]:
        if not self._data:
            return None
        self._selection_start = self._selection_end = None
        self._cursor_byte_offset = max(0, min(len(self._data) - 1, self._cursor_byte_offset + delta))
        self._hex_pair_snapshot_byte = None
        self._nibble_pos = 0
        if self._ensure_cursor_visible():
            self._refresh_visible()
            self._update_scrollbar()
        else:
            self._update_cursor_display()
        return "break"

    def _on_home(self, event: tk.Event) -> Optional[str]:
        return self._move_cursor(-(self._cursor_byte_offset % BYTES_PER_ROW))

    def _on_end(self, event: tk.Event) -> Optional[str]:
        if not self._data:
            return "break"
        in_row = self._cursor_byte_offset % BYTES_PER_ROW
        row_end = min(self._cursor_byte_offset + (BYTES_PER_ROW - 1 - in_row), len(self._data) - 1)
        return self._move_cursor(row_end - self._cursor_byte_offset)

    def _on_ctrl_home(self, event: tk.Event) -> Optional[str]:
        return self._move_cursor(-self._cursor_byte_offset)

    def _on_ctrl_end(self, event: tk.Event) -> Optional[str]:
        if not self._data:
            return "break"
        return self._move_cursor(len(self._data) - 1 - self._cursor_byte_offset)

    def _on_insert_key(self, event: tk.Event) -> Optional[str]:
        self._insert_mode = not self._insert_mode
        self._mode_label.config(text="INSERT" if self._insert_mode else "REPLACE")
        self._hex_pair_snapshot_byte = None
        self._nibble_pos = 0
        return "break"

    # ── Public helpers ───────────────────────────────────────────────

    def tools_container(self) -> ttk.Frame:
        """Return the frame for embedding additional tools (right of hex/ASCII)."""
        return self._tools_frame


class RomToolsShell:
    """PCS string table, struct editor, and graphics preview in a bottom pane.

    FireRed-parity behavior: **Ctrl+T** toggles the tools strip; **Ctrl+Shift+1/2/3**
    toggles Table / Struct / Graphics slots. Double-clicking pointers in the hex view
    can open the matching tool when :meth:`HexEditorFrame.set_on_pointer_to_named_anchor`
    is wired (done in :meth:`RomToolsShell.__init__`).
    """

    def __init__(
        self,
        root: tk.Misc,
        main_paned: ttk.PanedWindow,
        hex_editor: "HexEditorFrame",
        *,
        bind_hotkeys: bool = True,
    ) -> None:
        self._root = root
        self._main_paned = main_paned
        self._hex = hex_editor
        self._tools_visible = False
        self._slot_active: List[bool] = [False, False, False]

        self._tools_frame = ttk.LabelFrame(self._main_paned, text=" Tools ", padding=2)
        self._tools_frame.rowconfigure(0, weight=1)

        self._pcs_canvas, self._pcs_inner = self._make_scroll_slot()
        self.pcs_table = PcsStringTableFrame(self._pcs_inner, self._hex)
        self.pcs_table.pack(fill=tk.BOTH, expand=True)

        self._struct_canvas, self._struct_inner = self._make_scroll_slot()
        self.struct_editor = StructEditorFrame(self._struct_inner, self._hex)
        self.struct_editor.pack(fill=tk.BOTH, expand=True)

        self._tool3_canvas, self._tool3_inner = self._make_scroll_slot()
        self.graphics_preview = GraphicsPreviewFrame(self._tool3_inner, self._hex)
        self.graphics_preview.pack(fill=tk.BOTH, expand=True)

        self._hex.set_on_pointer_to_named_anchor(self._on_pointer_to_named_anchor)

        if bind_hotkeys:
            self._root.bind_all("<Control-KeyPress-t>", self._on_ctrl_t)
            self._root.bind_all("<Control-KeyPress-T>", self._on_ctrl_t)
            self._root.bind_all("<Control-Shift-Key-exclam>", lambda e: self._hotkey_slot(0))
            self._root.bind_all("<Control-Shift-Key-at>", lambda e: self._hotkey_slot(1))
            self._root.bind_all("<Control-Shift-Key-numbersign>", lambda e: self._hotkey_slot(2))
            self._root.bind_all("<Control-Shift-Key-1>", lambda e: self._hotkey_slot(0))
            self._root.bind_all("<Control-Shift-Key-2>", lambda e: self._hotkey_slot(1))
            self._root.bind_all("<Control-Shift-Key-3>", lambda e: self._hotkey_slot(2))

    def refresh_anchors(self) -> None:
        """Reload NamedAnchor lists in all three tools (call after ROM / TOML changes)."""
        self.pcs_table.refresh_anchors()
        self.struct_editor.refresh_anchors()
        self.graphics_preview.refresh_anchors()

    def _focus_in_text_entry(self) -> bool:
        w = self._root.focus_get()
        if w is None:
            return False
        try:
            cls = w.winfo_class()
        except tk.TclError:
            return False
        return cls in ("TEntry", "Entry", "TSpinbox", "Spinbox", "TCombobox")

    def _make_scroll_slot(self) -> Tuple[ttk.Frame, ttk.Frame]:
        """Canvas + vertical and horizontal scrollbars; inner frame scrolls (~1/3 screen wide / tall)."""
        third = max(200, self._root.winfo_screenwidth() // 3)
        outer = ttk.Frame(self._tools_frame, width=third)
        outer.grid_propagate(False)
        outer.rowconfigure(0, weight=1)
        outer.columnconfigure(0, weight=1)

        canvas = tk.Canvas(outer, highlightthickness=0, borderwidth=0)
        try:
            bg = ttk.Style().lookup("TFrame", "background") or "#f0f0f0"
        except tk.TclError:
            bg = "#f0f0f0"
        canvas.configure(background=bg)

        vsb = ttk.Scrollbar(outer, orient=tk.VERTICAL, command=canvas.yview)
        hsb = ttk.Scrollbar(outer, orient=tk.HORIZONTAL, command=canvas.xview)
        canvas.configure(xscrollcommand=hsb.set, yscrollcommand=vsb.set)

        inner = ttk.Frame(canvas)
        wid = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _sync_inner(_e: tk.Event) -> None:
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _sync_canvas(e: tk.Event) -> None:
            try:
                req_w = inner.winfo_reqwidth()
                req_h = inner.winfo_reqheight()
            except tk.TclError:
                req_w, req_h = 0, 0
            w = max(e.width, req_w)
            h = max(e.height, req_h)
            canvas.itemconfigure(wid, width=w, height=h)
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _slot_wheel(ev: tk.Event) -> None:
            if ev.delta:
                canvas.yview_scroll(int(-1 * ev.delta / 120), "units")
            elif getattr(ev, "num", None) == 4:
                canvas.yview_scroll(-3, "units")
            elif getattr(ev, "num", None) == 5:
                canvas.yview_scroll(3, "units")

        inner.bind("<Configure>", _sync_inner)
        canvas.bind("<Configure>", _sync_canvas)
        canvas.bind("<MouseWheel>", _slot_wheel)
        canvas.bind("<Button-4>", _slot_wheel)
        canvas.bind("<Button-5>", _slot_wheel)
        inner.bind("<MouseWheel>", _slot_wheel)
        inner.bind("<Button-4>", _slot_wheel)
        inner.bind("<Button-5>", _slot_wheel)

        canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, columnspan=2, sticky="ew")

        outer._canvas = canvas  # type: ignore[attr-defined]
        return outer, inner

    def _slot_frames(self) -> List[ttk.Frame]:
        return [self._pcs_canvas, self._struct_canvas, self._tool3_canvas]

    def _layout_tool_slots(self) -> None:
        frames = self._slot_frames()
        for fr in frames:
            fr.grid_remove()

        active = [(i, frames[i]) for i in range(3) if self._slot_active[i]]
        third = max(200, self._root.winfo_screenwidth() // 3)

        for col in range(4):
            self._tools_frame.columnconfigure(col, weight=0, minsize=0)
        self._tools_frame.columnconfigure(3, weight=1)

        for col, (_, fr) in enumerate(active):
            padx = (0, 2) if col < len(active) - 1 else (0, 0)
            fr.grid(row=0, column=col, sticky="nsew", padx=padx)
            c = getattr(fr, "_canvas", None)
            if c is not None:
                try:
                    c.configure(width=third)
                except tk.TclError:
                    pass

    def _on_ctrl_t(self, event: Optional[tk.Event] = None) -> Optional[str]:
        if self._tools_visible:
            self._tools_visible = False
            self._main_paned.forget(self._tools_frame)
            return "break"
        if self._focus_in_text_entry():
            return None
        self._tools_visible = not self._tools_visible
        if self._tools_visible:
            self._slot_active[0] = True
            self._slot_active[1] = True
            self._slot_active[2] = True
            self._main_paned.add(self._tools_frame)
            self.refresh_anchors()
            self._layout_tool_slots()
        return "break"

    def _hotkey_slot(self, index: int) -> Optional[str]:
        others_on = any(self._slot_active[j] for j in range(3) if j != index)
        hiding_last_slot = self._tools_visible and self._slot_active[index] and not others_on
        if self._focus_in_text_entry() and not hiding_last_slot:
            return None
        self._slot_active[index] = not self._slot_active[index]

        if not any(self._slot_active):
            if self._tools_visible:
                self._tools_visible = False
                self._main_paned.forget(self._tools_frame)
            return "break"

        if not self._tools_visible:
            self._tools_visible = True
            self._main_paned.add(self._tools_frame)
            self.refresh_anchors()

        self._layout_tool_slots()
        return "break"

    def _on_pointer_to_named_anchor(self, anchor_info: dict) -> None:
        t = anchor_info.get("type")
        if t == "graphics":
            self._slot_active[2] = True
        elif t == "struct":
            self._slot_active[1] = True
        else:
            self._slot_active[0] = True

        if not self._tools_visible:
            self._tools_visible = True
            self._main_paned.add(self._tools_frame)

        self._layout_tool_slots()
        name = anchor_info.get("name", "")
        if t == "graphics":
            self.graphics_preview.refresh_anchors()
            self.graphics_preview.show_anchor(name)
            self._root.after(50, lambda: self.graphics_preview._combo.focus_set())
        elif t == "struct":
            self.struct_editor.refresh_anchors()
            ei = anchor_info.get("struct_entry_index")
            if ei is not None:
                self.struct_editor.show_struct(name, entry_idx=ei)
            else:
                self.struct_editor.show_struct(name)
            self._root.after(50, lambda: self.struct_editor._tree.focus_set())
        else:
            self.pcs_table.refresh_anchors()
            pri = anchor_info.get("pcs_row_index")
            if pri is not None:
                self.pcs_table.show_table(name, row_index=pri)
            else:
                self.pcs_table.show_table(name)
            self._root.after(50, lambda: self.pcs_table._tree.focus_set())
