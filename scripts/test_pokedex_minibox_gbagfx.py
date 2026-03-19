#!/usr/bin/env python3
"""
Regression check: decode graphics.pokedex.minibox (lzs4x8x4 + catchmap palette) via gbagfx.

Requires:
  - BPRE0_test.gba (or pass path as argv[1])
  - deps/gbagfx Linux binary + WSL on Windows

Usage:
  python scripts/test_pokedex_minibox_gbagfx.py [path/to/BPRE0_test.gba]
"""

from __future__ import annotations

import os
import sys

# Repo root
_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

GBA_ROM_BASE = 0x08000000


def main() -> int:
    rom_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(_ROOT, "BPRE0_test.gba")
    if not os.path.isfile(rom_path):
        print(f"ROM not found: {rom_path!r}", file=sys.stderr)
        return 2

    from editors.common.gba_graphics import (  # noqa: E402
        decode_graphics_anchor_to_png,
        parse_graphics_anchor_format,
    )

    with open(rom_path, "rb") as f:
        rom = f.read()

    # Offsets from BPRE0.toml (FireRed)
    minibox_gba = 0x440124
    pal_gba = 0x4406E0
    minibox_off = minibox_gba - GBA_ROM_BASE
    pal_off = pal_gba - GBA_ROM_BASE

    sprite_fmt = "`lzs4x8x4|graphics.townmap.catchmap.palette`"
    pal_fmt = "`ucp4:0123456789ABCDEF`"

    spec = parse_graphics_anchor_format(sprite_fmt)
    pal_spec = parse_graphics_anchor_format(pal_fmt)
    assert spec and spec.kind == "sprite", spec
    assert pal_spec and pal_spec.kind == "palette", pal_spec

    png_path, log = decode_graphics_anchor_to_png(
        rom,
        minibox_off,
        spec,
        external_palette_spec=pal_spec,
        external_palette_base_off=pal_off,
    )
    if not png_path:
        print(log, file=sys.stderr)
        return 1
    print("OK:", png_path)
    print(log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
