"""
PCS string *view* decoding for Tools / struct / enum labels (not the hex editor character pane).

Decodes ``FD`` / ``F8`` / ``F9`` / ``FC`` using ``editors/firered/pokefirered/charmap.txt`` (pret
pokefirered) when present: ``STRING = FD``, ``COLOR = FC 01``, ``FONT_SMALL = FC 06 00``, ``@ colors``, etc.

HexManiac-style notes: https://github.com/haven1433/HexManiacAdvance/blob/master/src/HexManiac.Core/Models/Code/pcsReference.txt

The hex editor keeps a simple byte→glyph map; use :func:`decode_pcs_string_view` elsewhere.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Tuple

# --- Single-byte display (same mapping as hex_editor._init_pcs; ROM-facing glyphs) ---
_PCS_BYTE: Dict[int, str] = {}


def _fill(chars: str, start: int) -> None:
    for i, c in enumerate(chars):
        _PCS_BYTE[start + i] = c


def _build_pcs_byte_table() -> None:
    if _PCS_BYTE:
        return
    _PCS_BYTE[0x00] = " "
    _fill("ÀÁÂÇÈÉÊËÌÎÏ", 0x01)
    _fill("ÒÓÔŒÙÚÛÑßàá", 0x0B)
    _fill("çèéêëìîïòóôœùúûñºª", 0x10)
    _PCS_BYTE[0x2C] = "."
    _PCS_BYTE[0x2D] = "&"
    _PCS_BYTE[0x2E] = "+"
    _fill("Lv=;", 0x34)
    for i in range(0x38, 0x48):
        if i not in _PCS_BYTE:
            _PCS_BYTE[i] = "."
    _PCS_BYTE[0x48] = "."
    for i in range(0x49, 0x51):
        if i not in _PCS_BYTE:
            _PCS_BYTE[i] = "."
    _fill("¿¡PmPKBLoCÍ", 0x51)
    _fill("%()", 0x5B)
    for i in range(0x5E, 0x68):
        if i not in _PCS_BYTE:
            _PCS_BYTE[i] = "."
    _PCS_BYTE[0x68] = "â"
    for i in range(0x69, 0x6F):
        if i not in _PCS_BYTE:
            _PCS_BYTE[i] = "."
    _PCS_BYTE[0x6F] = "í"
    _fill("^v<>", 0x79)
    for i in range(0x7D, 0x84):
        if i not in _PCS_BYTE:
            _PCS_BYTE[i] = "."
    _PCS_BYTE[0x84] = "."
    _fill("<>", 0x85)
    for i in range(0x87, 0xA1):
        if i not in _PCS_BYTE:
            _PCS_BYTE[i] = "."
    _fill("0123456789", 0xA1)
    _fill("!?.-‧'°$,*//", 0xAB)
    _fill("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 0xBB)
    _fill("abcdefghijklmnopqrstuvwxyz", 0xD5)
    for i in range(0xEF, 0xF0):
        if i not in _PCS_BYTE:
            _PCS_BYTE[i] = "."
    _fill(":ÄÖÜäöü", 0xF0)
    _PCS_BYTE[0xF7] = "."
    _PCS_BYTE[0xF8] = "."
    _PCS_BYTE[0xF9] = "."
    _PCS_BYTE[0xFA] = "¶"
    _PCS_BYTE[0xFB] = "¶"
    _PCS_BYTE[0xFC] = "."
    _PCS_BYTE[0xFD] = "\\"
    _PCS_BYTE[0xFE] = "¶"
    _PCS_BYTE[0xFF] = '"'
    for i in range(0x100):
        if i not in _PCS_BYTE:
            _PCS_BYTE[i] = "."


# --- Fallback FD labels (overridden by charmap ``NAME = FD XX``) ---
_FD_MACRO: Dict[int, str] = {
    0x01: "[PLAYER]",
    0x02: "[STR_VAR_1]",
    0x03: "[STR_VAR_2]",
    0x04: "[STR_VAR_3]",
    0x06: "[RIVAL]",
}

_CHARMAP_FD: Dict[int, str] = {}
_CHARMAP_FC_LABEL: Dict[int, str] = {}
_CHARMAP_FC_PAIR: Dict[Tuple[int, int], str] = {}
_CHARMAP_COLOR: Dict[int, str] = {}
_CHARMAP_TRIED = False


def _charmap_path() -> str:
    return os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "firered", "pokefirered", "charmap.txt")
    )


def _load_charmap_txt() -> None:
    """Parse ``charmap.txt`` for ``NAME = FD xx``, ``NAME = FC xx``, ``NAME = FC xx yy``, and ``@ colors``."""
    global _CHARMAP_TRIED
    if _CHARMAP_TRIED:
        return
    _CHARMAP_TRIED = True
    path = _charmap_path()
    if not os.path.isfile(path):
        return
    in_colors = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                ls = line.strip()
                if not ls:
                    continue
                if ls.startswith("@ colors"):
                    in_colors = True
                    continue
                if ls.startswith("@") and "sound" in ls.lower():
                    in_colors = False
                    continue
                if in_colors and "=" in ls and not ls.startswith("'"):
                    m = re.match(r"^([A-Z_][A-Z0-9_]*)\s*=\s*([0-9A-Fa-f]{1,2})\s*$", ls)
                    if m:
                        _CHARMAP_COLOR[int(m.group(2), 16)] = m.group(1).lower()
                    continue
                m = re.match(
                    r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*FD\s+([0-9A-Fa-f]{1,2})\b",
                    ls,
                )
                if m:
                    _CHARMAP_FD[int(m.group(2), 16)] = f"[{m.group(1)}]"
                    continue
                m = re.match(
                    r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*FC\s+([0-9A-Fa-f]{1,2})\s+([0-9A-Fa-f]{1,2})\b",
                    ls,
                )
                if m:
                    a, b = int(m.group(2), 16), int(m.group(3), 16)
                    _CHARMAP_FC_PAIR[(a, b)] = f"[{m.group(1)}]"
                    continue
                m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*FC\s+([0-9A-Fa-f]{1,2})\s*$", ls)
                if m:
                    _CHARMAP_FC_LABEL[int(m.group(2), 16)] = m.group(1)
                    continue
    except OSError:
        pass


def _fd_label(second: int) -> str:
    _load_charmap_txt()
    if second in _CHARMAP_FD:
        return _CHARMAP_FD[second]
    return _FD_MACRO.get(second, "")


# F9 xx — extended symbol set (HexManiac / GBATEK style names)
_F9_MACRO: Dict[int, str] = {
    0x00: "[up]",
    0x01: "[down]",
    0x02: "[left]",
    0x03: "[right]",
    0x04: "[plus]",
    0x05: "[LV]",
    0x06: "[PP]",
    0x07: "[ID]",
    0x08: "[No]",
    0x09: "[_]",
    0x0A: "[1]",
    0x0B: "[2]",
    0x0C: "[3]",
    0x0D: "[4]",
    0x0E: "[5]",
    0x0F: "[6]",
    0x10: "[7]",
    0x11: "[8]",
    0x12: "[9]",
    0x13: "[left_parenthesis]",
    0x14: "[right_parenthesis]",
    0x15: "[super_effective]",
    0x16: "[not_very_effective]",
    0x17: "[not_effective]",
    0xD0: "[down_bar]",
    0xD1: "[vertical_bar]",
    0xD2: "[up_bar]",
    0xD3: "[tilde]",
    0xD4: "[left_parenthesis_bold]",
    0xD5: "[right_parenthesis_bold]",
    0xD6: "[subset_of]",
    0xD7: "[greater_than_short]",
    0xD8: "[left_eye]",
    0xD9: "[right_eye]",
    0xDA: "[commercial_at]",
    0xDB: "[semicolon]",
    0xDC: "[bold_plus_1]",
    0xDD: "[bold_minus]",
    0xDE: "[bold_equals]",
    0xDF: "[dazed]",
    0xE0: "[tongue]",
    0xE1: "[delta]",
    0xE2: "[acute]",
    0xE3: "[grave]",
    0xE4: "[circle]",
    0xE5: "[triangle]",
    0xE6: "[square]",
    0xE7: "[heart]",
    0xE8: "[moon]",
    0xE9: "[eighth_note]",
    0xEA: "[half_circle]",
    0xEB: "[thunderbolt]",
    0xEC: "[leaf]",
    0xED: "[fire]",
    0xEE: "[teardrop]",
    0xEF: "[left_wing]",
    0xF0: "[right_wing]",
    0xF1: "[rose]",
    0xF2: "[unknown_F2]",
    0xF3: "[unknown_F3]",
    0xF4: "[frustration_mark]",
    0xF5: "[sad]",
    0xF6: "[happy]",
    0xF7: "[angry]",
    0xF8: "[excited]",
    0xF9: "[joyful]",
    0xFA: "[maliciously_happy]",
    0xFB: "[upset]",
    0xFC: "[straight_face]",
    0xFD: "[surprised]",
    0xFE: "[outraged]",
}

# If charmap has no @ colors section, use FireRed-style names (charmap.txt 454–471)
_COLOR_FALLBACK: Dict[int, str] = {
    0x00: "transparent",
    0x01: "white",
    0x02: "dark_gray",
    0x03: "light_gray",
    0x04: "red",
    0x05: "light_red",
    0x06: "green",
    0x07: "light_green",
    0x08: "blue",
    0x09: "light_blue",
    0x0A: "dynamic_color1",
    0x0B: "dynamic_color2",
    0x0C: "dynamic_color3",
    0x0D: "dynamic_color4",
    0x0E: "dynamic_color5",
    0x0F: "dynamic_color6",
}

_BTN_NAMES = ("A", "B", "L", "R", "START", "SELECT", "UP", "DOWN", "LEFT", "RIGHT", "UP_DOWN", "LEFT_RIGHT", "DPAD")


def _color_token(idx: int) -> str:
    _load_charmap_txt()
    if idx in _CHARMAP_COLOR:
        return _CHARMAP_COLOR[idx]
    return _COLOR_FALLBACK.get(idx, f"0x{idx:02X}")


def _fc_arg_count(sub: int) -> int:
    """Extra argument bytes after ``FC <sub>`` (pokefirered ``charmap.txt`` *more text functions*)."""
    if sub == 0x00:
        return 0
    if sub in (0x01, 0x02, 0x03, 0x05, 0x06, 0x08, 0x14):
        return 1
    if sub == 0x04:
        return 3
    if sub in (0x0B, 0x10, 0x13):
        return 2
    if sub in (0x07, 0x09, 0x0A, 0x0C, 0x0D, 0x0E, 0x0F, 0x11, 0x12, 0x15, 0x16, 0x17, 0x18):
        return 0
    if sub > 0x18:
        return 0
    return 1


def _fc_zero_arg_label(sub: int) -> str:
    _load_charmap_txt()
    name = _CHARMAP_FC_LABEL.get(sub)
    if name:
        return f"[{name.lower()}]"
    # minimal fallbacks if charmap missing
    fb = {
        0x00: "[name_end]",
        0x07: "[reset_font]",
        0x09: "[pause_until_press]",
        0x0A: "[wait_se]",
        0x0C: "[escape]",
        0x0D: "[shift_right]",
        0x0E: "[shift_down]",
        0x0F: "[fill_window]",
        0x11: "[clear]",
        0x12: "[skip]",
        0x15: "[jpn]",
        0x16: "[eng]",
        0x17: "[pause_music]",
        0x18: "[resume_music]",
    }
    return fb.get(sub, f"[fc_{sub:02x}]")


def decode_pcs_string_view(data: bytes) -> str:
    """
    Decode PCS bytes to a readable view string (macros, ``FC``/``FD``/``F8``/``F9``, newlines).

    Stops at first ``0xFF`` terminator. Does not affect hex editor one-byte-per-column display.
    """
    _build_pcs_byte_table()
    _load_charmap_txt()
    out: List[str] = []
    i = 0
    n = len(data)

    def can_take(k: int) -> bool:
        return i + k <= n

    while i < n:
        b = data[i]
        if b == 0xFF:
            break

        if b == 0xF7:
            out.append("[dynamic]")
            i += 1
            continue

        if b == 0xFD:
            if not can_take(2):
                out.append("[FD?]")
                break
            second = data[i + 1]
            lab = _fd_label(second)
            if lab:
                out.append(lab)
            else:
                out.append(
                    _PCS_BYTE.get(second)
                    or (chr(second) if 32 <= second < 127 else f"\\x{second:02X}")
                )
            i += 2
            continue

        if b == 0xF8:
            if not can_take(2):
                out.append("[btn?]")
                break
            bid = data[i + 1]
            if bid < len(_BTN_NAMES):
                out.append(f"[btn:{_BTN_NAMES[bid]}]")
            else:
                out.append(f"[btn:{bid}]")
            i += 2
            continue

        if b == 0xF9:
            if not can_take(2):
                out.append("[F9?]")
                break
            second = data[i + 1]
            macro = _F9_MACRO.get(second)
            if macro:
                out.append(macro)
            else:
                out.append(f"[F9:{second:02X}]")
            i += 2
            continue

        if b == 0xFC:
            if not can_take(2):
                out.append("[FC?]")
                break
            sub = data[i + 1]
            ac = _fc_arg_count(sub)
            if not can_take(2 + ac):
                out.append(f"[FC:{sub:02X}?]")
                break
            args = data[i + 2 : i + 2 + ac]

            if sub == 0x06 and ac == 1:
                pair = _CHARMAP_FC_PAIR.get((0x06, args[0]))
                if pair:
                    out.append(pair)
                else:
                    out.append(f"[font:{args[0]:02X}]")
            elif sub == 0x01 and ac == 1:
                out.append(f"[color:{_color_token(args[0])}]")
            elif sub == 0x02 and ac == 1:
                out.append(f"[highlight:{_color_token(args[0])}]")
            elif sub == 0x03 and ac == 1:
                out.append(f"[shadow:{_color_token(args[0])}]")
            elif sub == 0x04 and ac == 3:
                out.append(
                    f"[color_highlight_shadow {args[0]:02X} {args[1]:02X} {args[2]:02X}]"
                )
            elif sub == 0x05 and ac == 1:
                out.append(f"[palette:{args[0]:02X}]")
            elif sub == 0x08 and ac == 1:
                out.append(f"[pause:{args[0]:02X}]")
            elif sub == 0x0B and ac == 2:
                out.append(f"[play_bgm {args[0]:02X} {args[1]:02X}]")
            elif sub == 0x10 and ac == 2:
                out.append(f"[play_se {args[0]:02X} {args[1]:02X}]")
            elif sub == 0x13 and ac == 2:
                out.append(f"[clear_to {args[0]:02X} {args[1]:02X}]")
            elif sub == 0x14 and ac == 1:
                out.append(f"[min_letter_spacing:{args[0]:02X}]")
            elif ac == 0:
                out.append(_fc_zero_arg_label(sub))
            else:
                parts = " ".join(f"{x:02X}" for x in [sub, *args])
                out.append(f"[FC {parts}]")
            i += 2 + ac
            continue

        if b == 0xFE:
            out.append("[newline]")
            i += 1
            continue
        if b == 0xFA:
            out.append("[linefeed]")
            i += 1
            continue
        if b == 0xFB:
            out.append("[paragraph]")
            i += 1
            continue

        out.append(_PCS_BYTE.get(b, "."))
        i += 1

    return "".join(out)
