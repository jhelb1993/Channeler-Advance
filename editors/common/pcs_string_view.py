"""
PCS string *view* decoding for Tools / struct / enum labels (not the hex editor character pane).

Implements control codes, ``FD`` / ``F8`` / ``F9`` / ``FC`` sequences, and named macros aligned with
HexManiacAdvance ``pcsReference.txt``:
https://github.com/haven1433/HexManiacAdvance/blob/master/src/HexManiac.Core/Models/Code/pcsReference.txt

The hex editor keeps a simple byte→glyph map so column width stays stable; use
:func:`decode_pcs_string_view` everywhere a human-readable PCS string is shown elsewhere.
"""

from __future__ import annotations

from typing import Dict, List

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


# FD xx named escapes (second byte)
_FD_MACRO: Dict[int, str] = {
    0x01: "[player]",
    0x02: "[buffer1]",
    0x03: "[buffer2]",
    0x04: "[buffer3]",
    0x06: "[rival]",
}

# F9 xx — Pokémon FireRed / Emerald style symbol names (subset + extras from reference)
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

# FC xx with no extra bytes (named)
_FC_ZERO: Dict[int, str] = {
    0x07: "[resetfont]",
    0x09: "[pause]",
    0x0A: "[wait_sound]",
    0x0C: "[escape]",
    0x0D: "[shift_right]",
    0x0E: "[shift_down]",
    0x0F: "[fill_window]",
    0x12: "[skip]",
    0x15: "[japanese]",
    0x16: "[latin]",
    0x17: "[pause_music]",
    0x18: "[resume_music]",
}

# BPRE/BPGE color names (FC 01 xx) — pcsReference @!game(BPRE_BPGE)
_BPRE_COLOR: Dict[int, str] = {
    0x00: "[white]",
    0x01: "[white2]",
    0x02: "[black]",
    0x03: "[grey]",
    0x04: "[red]",
    0x05: "[orange]",
    0x06: "[green]",
    0x07: "[lightgreen]",
    0x08: "[blue]",
    0x09: "[lightblue]",
    0x0A: "[white3]",
    0x0B: "[lightblue2]",
    0x0C: "[cyan]",
    0x0D: "[lightblue3]",
    0x0E: "[navyblue]",
    0x0F: "[darknavyblue]",
}

_BTN_NAMES = ("A", "B", "L", "R", "START", "SELECT", "UP", "DOWN", "LEFT", "RIGHT", "UP_DOWN", "LEFT_RIGHT", "DPAD")


def _fc_arg_count(sub: int) -> int:
    """Bytes after the FC sub-byte (reference: CC_xx and defaults)."""
    if sub == 0x01:
        return 1
    if sub == 0x04:
        return 3
    if sub in (0x09, 0x0A):
        return 0
    if sub in (0x0B, 0x10):
        return 2
    if sub in _FC_ZERO:
        return 0
    if sub > 0x14:
        return 0
    return 1


def decode_pcs_string_view(data: bytes) -> str:
    """
    Decode PCS bytes to a readable view string (macros, ``FC``/``FD``/``F8``/``F9``, newlines).

    Stops at first ``0xFF`` terminator. Does not affect hex editor one-byte-per-column display.
    """
    _build_pcs_byte_table()
    out: List[str] = []
    i = 0
    n = len(data)

    def can_take(k: int) -> bool:
        return i + k <= n

    while i < n:
        b = data[i]
        if b == 0xFF:
            break

        if b == 0xFD:
            if not can_take(2):
                out.append("[FD?]")
                break
            second = data[i + 1]
            macro = _FD_MACRO.get(second)
            if macro:
                out.append(macro)
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

            if sub == 0x01 and ac == 1:
                out.append(_BPRE_COLOR.get(args[0], f"[color:{args[0]:02X}]"))
            elif sub == 0x04 and ac == 3:
                out.append(f"[shadow {args[0]:02X} {args[1]:02X} {args[2]:02X}]")
            elif sub == 0x0B and ac == 2:
                out.append(f"[bgm {args[0]:02X} {args[1]:02X}]")
            elif sub == 0x10 and ac == 2:
                out.append(f"[sfx {args[0]:02X} {args[1]:02X}]")
            elif sub in _FC_ZERO and ac == 0:
                out.append(_FC_ZERO[sub])
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
