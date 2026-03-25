"""
PCS string *view* decoding for Tools / struct / enum labels (not the hex editor character pane).

Decodes ``FD`` / ``F8`` / ``F9`` / ``FC`` using ``editors/firered/pokefirered/charmap.txt`` (pret
pokefirered) when present: ``STRING = FD``, ``COLOR = FC 01``, ``FONT_SMALL = FC 06 00``, ``@ colors``, etc.

Encoding for the PCS edit field uses :func:`encode_pcs_string_body`: pret-style ``{CLEAR_TO 0x49}``,
``{FONT_SMALL}``, and legacy ``[...]`` forms (``[fc 06 00]``, ``[color:red]``, etc.) emit the corresponding bytes.

``CLEAR_TO`` (``FC 13``) consumes **one** argument byte in pokefirered (see ``strings.c`` ``_("...{CLEAR_TO 0x49}...")``).

HexManiac-style notes: https://github.com/haven1433/HexManiacAdvance/blob/master/src/HexManiac.Core/Models/Code/pcsReference.txt

The hex editor keeps a simple byte→glyph map; use :func:`decode_pcs_string_view` elsewhere.
"""

from __future__ import annotations

import os
import re
from typing import Dict, List, Optional, Tuple

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
    0x01: "{PLAYER}",
    0x02: "{STR_VAR_1}",
    0x03: "{STR_VAR_2}",
    0x04: "{STR_VAR_3}",
    0x06: "{RIVAL}",
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
                    _CHARMAP_FD[int(m.group(2), 16)] = f"{{{m.group(1)}}}"
                    continue
                m = re.match(
                    r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*FC\s+([0-9A-Fa-f]{1,2})\s+([0-9A-Fa-f]{1,2})\b",
                    ls,
                )
                if m:
                    a, b = int(m.group(2), 16), int(m.group(3), 16)
                    _CHARMAP_FC_PAIR[(a, b)] = f"{{{m.group(1)}}}"
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
    0x00: "{up}",
    0x01: "{down}",
    0x02: "{left}",
    0x03: "{right}",
    0x04: "{plus}",
    0x05: "{LV}",
    0x06: "{PP}",
    0x07: "{ID}",
    0x08: "{No}",
    0x09: "{_}",
    0x0A: "{1}",
    0x0B: "{2}",
    0x0C: "{3}",
    0x0D: "{4}",
    0x0E: "{5}",
    0x0F: "{6}",
    0x10: "{7}",
    0x11: "{8}",
    0x12: "{9}",
    0x13: "{left_parenthesis}",
    0x14: "{right_parenthesis}",
    0x15: "{super_effective}",
    0x16: "{not_very_effective}",
    0x17: "{not_effective}",
    0xD0: "{down_bar}",
    0xD1: "{vertical_bar}",
    0xD2: "{up_bar}",
    0xD3: "{tilde}",
    0xD4: "{left_parenthesis_bold}",
    0xD5: "{right_parenthesis_bold}",
    0xD6: "{subset_of}",
    0xD7: "{greater_than_short}",
    0xD8: "{left_eye}",
    0xD9: "{right_eye}",
    0xDA: "{commercial_at}",
    0xDB: "{semicolon}",
    0xDC: "{bold_plus_1}",
    0xDD: "{bold_minus}",
    0xDE: "{bold_equals}",
    0xDF: "{dazed}",
    0xE0: "{tongue}",
    0xE1: "{delta}",
    0xE2: "{acute}",
    0xE3: "{grave}",
    0xE4: "{circle}",
    0xE5: "{triangle}",
    0xE6: "{square}",
    0xE7: "{heart}",
    0xE8: "{moon}",
    0xE9: "{eighth_note}",
    0xEA: "{half_circle}",
    0xEB: "{thunderbolt}",
    0xEC: "{leaf}",
    0xED: "{fire}",
    0xEE: "{teardrop}",
    0xEF: "{left_wing}",
    0xF0: "{right_wing}",
    0xF1: "{rose}",
    0xF2: "{unknown_F2}",
    0xF3: "{unknown_F3}",
    0xF4: "{frustration_mark}",
    0xF5: "{sad}",
    0xF6: "{happy}",
    0xF7: "{angry}",
    0xF8: "{excited}",
    0xF9: "{joyful}",
    0xFA: "{maliciously_happy}",
    0xFB: "{upset}",
    0xFC: "{straight_face}",
    0xFD: "{surprised}",
    0xFE: "{outraged}",
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
    if sub in (0x01, 0x02, 0x03, 0x05, 0x06, 0x08, 0x13, 0x14):
        return 1
    if sub == 0x04:
        return 3
    if sub in (0x0B, 0x10):
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
        return f"{{{name}}}"
    # minimal fallbacks if charmap missing
    fb = {
        0x00: "{NAME_END}",
        0x07: "{RESET_FONT}",
        0x09: "{PAUSE_UNTIL_PRESS}",
        0x0A: "{WAIT_SE}",
        0x0C: "{ESCAPE}",
        0x0D: "{SHIFT_RIGHT}",
        0x0E: "{SHIFT_DOWN}",
        0x0F: "{FILL_WINDOW}",
        0x11: "{CLEAR}",
        0x12: "{SKIP}",
        0x15: "{JPN}",
        0x16: "{ENG}",
        0x17: "{PAUSE_MUSIC}",
        0x18: "{RESUME_MUSIC}",
    }
    return fb.get(sub, f"{{fc_{sub:02x}}}")


# --- Bracket command encoding (Tools / PCS edit field; charmap-aware) ---
_ENCODE_MAPS_BUILT = False
_ENCODE_FC_FULL: Dict[str, bytes] = {}
_ENCODE_FC_ZERO: Dict[str, bytes] = {}
_ENCODE_FD: Dict[str, bytes] = {}
_ENCODE_COLOR_NAME: Dict[str, int] = {}
_ENCODE_BTN_NAME: Dict[str, int] = {}


def _parse_hex_byte(tok: str) -> Optional[int]:
    t = tok.strip()
    if not t:
        return None
    if t.lower().startswith("0x"):
        t = t[2:]
    if len(t) > 2:
        return None
    try:
        v = int(t, 16)
    except ValueError:
        return None
    if not (0 <= v <= 0xFF):
        return None
    return v


def _parse_color_token(tok: str) -> Optional[int]:
    _ensure_encode_maps()
    t = tok.strip()
    if not t:
        return None
    hx = _parse_hex_byte(t)
    if hx is not None:
        return hx
    return _ENCODE_COLOR_NAME.get(t.lower().replace("-", "_"))


def _ensure_encode_maps() -> None:
    global _ENCODE_MAPS_BUILT
    if _ENCODE_MAPS_BUILT:
        return
    _load_charmap_txt()
    _ENCODE_FC_FULL.clear()
    _ENCODE_FC_ZERO.clear()
    _ENCODE_FD.clear()
    _ENCODE_COLOR_NAME.clear()
    _ENCODE_BTN_NAME.clear()

    for (a, b), lab in _CHARMAP_FC_PAIR.items():
        name = lab.strip("{}").strip("[]")
        bts = bytes([0xFC, a, b])
        _ENCODE_FC_FULL[name.lower()] = bts
        _ENCODE_FC_FULL[name] = bts

    for sub, raw in _CHARMAP_FC_LABEL.items():
        if _fc_arg_count(sub) == 0:
            bz = bytes([0xFC, sub])
            _ENCODE_FC_ZERO[raw.lower()] = bz
            _ENCODE_FC_ZERO[raw] = bz

    for second, lab in _CHARMAP_FD.items():
        name = lab.strip("{}").strip("[]")
        _ENCODE_FD[name.lower()] = bytes([0xFD, second])
        _ENCODE_FD[name] = bytes([0xFD, second])

    for idx, cname in _CHARMAP_COLOR.items():
        _ENCODE_COLOR_NAME[cname.lower()] = idx
    for idx, cname in _COLOR_FALLBACK.items():
        _ENCODE_COLOR_NAME.setdefault(cname.lower(), idx)

    for i, nm in enumerate(_BTN_NAMES):
        _ENCODE_BTN_NAME[nm.lower()] = i

    _ENCODE_MAPS_BUILT = True


def _encode_control_inner(inner: str) -> Optional[bytes]:
    """Parse ``...`` inside ``[...]`` or pret ``{...}`` as a PCS control sequence; ``None`` = not recognized."""
    _ensure_encode_maps()
    s = inner.strip()
    if not s:
        return None

    m_pret_ct = re.match(
        r"^\s*CLEAR_TO\s+(0x[0-9a-fA-F]{1,2}|[0-9A-Fa-f]{1,2})\s*$",
        s,
        re.I,
    )
    if m_pret_ct:
        v = _parse_hex_byte(m_pret_ct.group(1))
        if v is not None:
            return bytes([0xFC, 0x13, v])

    mc = re.match(r"^(color|highlight|shadow)\s*:\s*(\S+)\s*$", s, re.I)
    if mc:
        which = mc.group(1).lower()
        sub = {"color": 0x01, "highlight": 0x02, "shadow": 0x03}[which]
        v = _parse_color_token(mc.group(2))
        if v is not None:
            return bytes([0xFC, sub, v])
        return None

    for pat, sub_b in (
        (r"^pause\s*:\s*([0-9A-Fa-f]{1,2})\s*$", 0x08),
        (r"^palette\s*:\s*([0-9A-Fa-f]{1,2})\s*$", 0x05),
        (r"^min_letter_spacing\s*:\s*([0-9A-Fa-f]{1,2})\s*$", 0x14),
        (r"^font\s*:\s*([0-9A-Fa-f]{1,2})\s*$", 0x06),
    ):
        mm = re.match(pat, s, re.I)
        if mm:
            v = _parse_hex_byte(mm.group(1))
            if v is not None:
                return bytes([0xFC, sub_b, v])
            return None

    mb = re.match(r"^btn\s*:\s*(\S+)\s*$", s, re.I)
    if mb:
        t = mb.group(1).strip()
        bid = _parse_hex_byte(t)
        if bid is None:
            bid = _ENCODE_BTN_NAME.get(t.lower())
        if bid is not None and 0 <= bid <= 0xFF:
            return bytes([0xF8, bid])
        return None

    parts = [p for p in re.split(r"\s+", s) if p]
    if not parts:
        return None
    cmd = parts[0].lower()

    if len(parts) == 1:
        if cmd in _ENCODE_FC_FULL:
            return _ENCODE_FC_FULL[cmd]
        if cmd in _ENCODE_FC_ZERO:
            return _ENCODE_FC_ZERO[cmd]
        if cmd in _ENCODE_FD:
            return _ENCODE_FD[cmd]
        if cmd == "dynamic":
            return b"\xF7"
        if cmd == "newline":
            return b"\xFE"
        if cmd == "linefeed":
            return b"\xFA"
        if cmd == "paragraph":
            return b"\xFB"
        return None

    if cmd == "clear_to" and len(parts) == 2:
        b1 = _parse_hex_byte(parts[1])
        if b1 is not None:
            return bytes([0xFC, 0x13, b1])
        return None

    if cmd == "color" and len(parts) == 2:
        v = _parse_color_token(parts[1])
        if v is not None:
            return bytes([0xFC, 0x01, v])
        return None
    if cmd == "highlight" and len(parts) == 2:
        v = _parse_color_token(parts[1])
        if v is not None:
            return bytes([0xFC, 0x02, v])
        return None
    if cmd == "shadow" and len(parts) == 2:
        v = _parse_color_token(parts[1])
        if v is not None:
            return bytes([0xFC, 0x03, v])
        return None

    if cmd == "color_highlight_shadow" and len(parts) == 4:
        a, b, c = _parse_hex_byte(parts[1]), _parse_hex_byte(parts[2]), _parse_hex_byte(parts[3])
        if a is not None and b is not None and c is not None:
            return bytes([0xFC, 0x04, a, b, c])
        return None

    if cmd == "palette" and len(parts) == 2:
        v = _parse_hex_byte(parts[1])
        if v is not None:
            return bytes([0xFC, 0x05, v])
        return None

    if cmd == "font" and len(parts) == 2:
        v = _parse_hex_byte(parts[1])
        if v is not None:
            return bytes([0xFC, 0x06, v])
        return None

    if cmd == "pause" and len(parts) == 2:
        v = _parse_hex_byte(parts[1])
        if v is not None:
            return bytes([0xFC, 0x08, v])
        return None

    if cmd == "play_bgm" and len(parts) == 3:
        a, b = _parse_hex_byte(parts[1]), _parse_hex_byte(parts[2])
        if a is not None and b is not None:
            return bytes([0xFC, 0x0B, a, b])
        return None

    if cmd == "play_se" and len(parts) == 3:
        a, b = _parse_hex_byte(parts[1]), _parse_hex_byte(parts[2])
        if a is not None and b is not None:
            return bytes([0xFC, 0x10, a, b])
        return None

    if cmd == "min_letter_spacing" and len(parts) == 2:
        v = _parse_hex_byte(parts[1])
        if v is not None:
            return bytes([0xFC, 0x14, v])
        return None

    if cmd == "fd" and len(parts) == 2:
        v = _parse_hex_byte(parts[1])
        if v is not None:
            return bytes([0xFD, v])
        return None

    if cmd == "fc" and len(parts) >= 2:
        sub = _parse_hex_byte(parts[1])
        if sub is None:
            return None
        ac = _fc_arg_count(sub)
        if len(parts) != 2 + ac:
            return None
        args: List[int] = []
        for j in range(ac):
            x = _parse_hex_byte(parts[2 + j])
            if x is None:
                return None
            args.append(x)
        return bytes([0xFC, sub, *args])

    if cmd == "f9" and len(parts) == 2:
        v = _parse_hex_byte(parts[1])
        if v is not None:
            return bytes([0xF9, v])
        return None

    if cmd == "f8" and len(parts) == 2:
        v = _parse_hex_byte(parts[1])
        if v is not None:
            return bytes([0xF8, v])
        return None

    return None


def encode_pcs_string_body(text: str, char_to_byte: Dict[str, int]) -> bytearray:
    """
    Encode user text to PCS bytes (no ``0xFF`` terminator).

    Literal characters use ``char_to_byte`` (same reverse map as the hex editor). Control codes may be
    written as pret ``{CLEAR_TO 0x49}`` / ``{FONT_SMALL}`` or legacy ``[...]`` (``[fc 06 00]``, ``[color:red]``).
    """
    out = bytearray()
    i = 0
    n = len(text)
    while i < n:
        c0 = text[i]
        if c0 not in "[{":
            b = char_to_byte.get(c0)
            if b is not None:
                out.append(b)
            i += 1
            continue
        if c0 == "[":
            closer = "]"
        else:
            closer = "}"
        j = text.find(closer, i + 1)
        if j < 0:
            b = char_to_byte.get(c0)
            if b is not None:
                out.append(b)
            i += 1
            continue
        inner = text[i + 1 : j]
        eb = _encode_control_inner(inner)
        if eb is not None:
            out.extend(eb)
        else:
            for k in range(i + 1, j):
                c = text[k]
                bb = char_to_byte.get(c)
                if bb is not None:
                    out.append(bb)
        i = j + 1
    return out


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
            out.append("{dynamic}")
            i += 1
            continue

        if b == 0xFD:
            if not can_take(2):
                out.append("{FD?}")
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
                out.append("{btn?}")
                break
            bid = data[i + 1]
            if bid < len(_BTN_NAMES):
                out.append(f"{{btn:{_BTN_NAMES[bid]}}}")
            else:
                out.append(f"{{btn:{bid}}}")
            i += 2
            continue

        if b == 0xF9:
            if not can_take(2):
                out.append("{F9?}")
                break
            second = data[i + 1]
            macro = _F9_MACRO.get(second)
            if macro:
                out.append(macro)
            else:
                out.append(f"{{F9:{second:02X}}}")
            i += 2
            continue

        if b == 0xFC:
            if not can_take(2):
                out.append("{FC?}")
                break
            sub = data[i + 1]
            ac = _fc_arg_count(sub)
            if not can_take(2 + ac):
                out.append(f"{{FC:{sub:02X}?}}")
                break
            args = data[i + 2 : i + 2 + ac]

            if sub == 0x06 and ac == 1:
                pair = _CHARMAP_FC_PAIR.get((0x06, args[0]))
                if pair:
                    out.append(pair)
                else:
                    out.append(f"{{font:{args[0]:02X}}}")
            elif sub == 0x01 and ac == 1:
                out.append(f"{{color:{_color_token(args[0])}}}")
            elif sub == 0x02 and ac == 1:
                out.append(f"{{highlight:{_color_token(args[0])}}}")
            elif sub == 0x03 and ac == 1:
                out.append(f"{{shadow:{_color_token(args[0])}}}")
            elif sub == 0x04 and ac == 3:
                out.append(
                    f"{{color_highlight_shadow {args[0]:02X} {args[1]:02X} {args[2]:02X}}}"
                )
            elif sub == 0x05 and ac == 1:
                out.append(f"{{palette:{args[0]:02X}}}")
            elif sub == 0x08 and ac == 1:
                out.append(f"{{pause:{args[0]:02X}}}")
            elif sub == 0x0B and ac == 2:
                out.append(f"{{play_bgm {args[0]:02X} {args[1]:02X}}}")
            elif sub == 0x10 and ac == 2:
                out.append(f"{{play_se {args[0]:02X} {args[1]:02X}}}")
            elif sub == 0x13 and ac == 1:
                out.append(f"{{CLEAR_TO 0x{args[0]:02X}}}")
            elif sub == 0x14 and ac == 1:
                out.append(f"{{min_letter_spacing:{args[0]:02X}}}")
            elif ac == 0:
                out.append(_fc_zero_arg_label(sub))
            else:
                parts = " ".join(f"{x:02X}" for x in [sub, *args])
                out.append(f"{{FC {parts}}}")
            i += 2 + ac
            continue

        if b == 0xFE:
            out.append("{newline}")
            i += 1
            continue
        if b == 0xFA:
            out.append("{linefeed}")
            i += 1
            continue
        if b == 0xFB:
            out.append("{paragraph}")
            i += 1
            continue

        out.append(_PCS_BYTE.get(b, "."))
        i += 1

    return "".join(out)
