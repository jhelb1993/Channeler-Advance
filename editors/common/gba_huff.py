"""
GBA Huffman compression matching pret ``tools/gbagfx/huff.c``.

Reference: https://github.com/pret/pokefirered/blob/master/tools/gbagfx/huff.c
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Tuple


def is_gba_huff_header(data: bytes) -> bool:
    if len(data) < 5:
        return False
    b0 = data[0]
    return (b0 & 0xF0) == 0x20 and (b0 & 0x0F) in (4, 8)


def _read_u32_le(src: bytes, pos: int) -> Tuple[int, int]:
    v = src[pos] | (src[pos + 1] << 8) | (src[pos + 2] << 16) | (src[pos + 3] << 24)
    return v, pos + 4


def _write_u32_le_buf(dest: bytearray, pos: int, v: int) -> int:
    dest[pos] = v & 0xFF
    dest[pos + 1] = (v >> 8) & 0xFF
    dest[pos + 2] = (v >> 16) & 0xFF
    dest[pos + 3] = (v >> 24) & 0xFF
    return pos + 4


def decompress_gba_huff(src: bytes, max_out: int = 1 << 22) -> bytes:
    dec, _ = decompress_gba_huff_with_consumed(src, max_out=max_out)
    return dec


def decompress_gba_huff_with_consumed(src: bytes, max_out: int = 1 << 22) -> Tuple[bytes, int]:
    if len(src) < 4:
        raise ValueError("Huff input too short (need header)")
    bit_depth = src[0] & 15
    if bit_depth not in (4, 8):
        raise ValueError(f"Huff bit depth must be 4 or 8, got {bit_depth}")
    dest_size = src[1] | (src[2] << 8) | (src[3] << 16)
    if dest_size <= 0 or dest_size > max_out:
        raise ValueError(f"Invalid Huff uncompressed size {dest_size}")

    tree_pos = 5
    tree_size = (src[4] + 1) * 2
    src_pos = 4 + tree_size
    dest = bytearray(dest_size)
    dest_pos = 0
    cur_val_pos = 0
    dest_tmp = 0

    while True:
        if src_pos + 4 > len(src):
            raise ValueError("Huff truncated (need next 32-bit chunk)")
        window, src_pos = _read_u32_le(src, src_pos)
        window &= 0xFFFFFFFF
        for _ in range(32):
            cur_bit = (window >> 31) & 1
            tree_view = src[tree_pos]
            is_leaf = ((tree_view << cur_bit) & 0x80) != 0
            tree_pos &= ~1
            tree_pos += ((tree_view & 0x3F) + 1) * 2 + cur_bit
            if is_leaf:
                dest_tmp = (dest_tmp >> bit_depth) & 0xFFFFFFFF
                dest_tmp |= (src[tree_pos] & 0xFF) << (32 - bit_depth)
                dest_tmp &= 0xFFFFFFFF
                cur_val_pos += 1
                if cur_val_pos == 32 // bit_depth:
                    dest_pos = _write_u32_le_buf(dest, dest_pos, dest_tmp)
                    dest_tmp = 0
                    cur_val_pos = 0
                    if dest_pos == dest_size:
                        return bytes(dest), src_pos
                tree_pos = 5
            window = ((window << 1) & 0xFFFFFFFF)


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _win_path_to_wsl(path: str) -> str:
    path = os.path.normpath(path)
    if len(path) >= 2 and path[1] == ":":
        return "/mnt/" + path[0].lower() + path[2:].replace("\\", "/")
    return path


def compress_gba_huff(src: bytes, bit_depth: int) -> bytes:
    """
    Huffman-compress using pret ``tools/gbagfx/huff.c`` (via ``tools/huff_golden/stdio_huff``).

    A native build of ``stdio_huff`` is required (same algorithm as upstream gbagfx). On Windows,
    ``wsl`` must be available to run the Linux binary under ``tools/huff_golden/stdio_huff``.
    Build::

        gcc -O2 -o tools/huff_golden/stdio_huff tools/huff_golden/stdio_huff.c tools/huff_golden/huff.c
    """
    if bit_depth not in (4, 8):
        raise ValueError("Huff compress bit_depth must be 4 or 8")
    src_size = len(src)
    if src_size <= 0:
        raise ValueError("Huff: empty input")
    if src_size > 0xFFFFFF:
        raise ValueError("Huff: data too large (max 16 MiB)")

    exe = _repo_root() / "tools" / "huff_golden" / "stdio_huff"
    if not exe.is_file():
        raise RuntimeError(
            "Huff compress: build tools/huff_golden/stdio_huff from pret huff.c "
            "(see docstring in compress_gba_huff)."
        )

    header = bytes([bit_depth]) + src_size.to_bytes(3, "little")
    stdin = header + src

    if os.name == "nt":
        wsl = shutil.which("wsl")
        if not wsl:
            raise RuntimeError("Huff compress on Windows requires WSL to run tools/huff_golden/stdio_huff.")
        cmd = [wsl, _win_path_to_wsl(str(exe))]
    else:
        cmd = [str(exe)]

    try:
        proc = subprocess.run(cmd, input=stdin, capture_output=True, check=False)
    except OSError as e:
        raise RuntimeError(f"Huff compress could not run pret stdio_huff: {e}") from e

    if proc.returncode != 0:
        err = (proc.stderr or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"Huff compress (stdio_huff) failed (exit {proc.returncode}): {err}")
    return proc.stdout
