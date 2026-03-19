"""
Shared hex editor for GBA ROM hacking.
Supports pointer detection (0x08/0x09), follow, replace/insert mode, delete.
ASCII/PCS (Pokemon GBA) encoding for the character pane.
Optional Capstone disassembly (ARM7TDMI Thumb/ARM).
"""

import os
import re
import shutil
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox
from typing import Optional, Dict, List, Tuple, Set, Any

from editors.common.gba_graphics import (
    decode_graphics_anchor_to_png,
    decode_palette_to_png_pal,
    decode_sprite_at_pointer,
    decode_gba_palette32_to_rgb888,
    extract_palette_bytes,
    get_palette_4_slot_bytes,
    palette_bytes_for_gbagfx,
    parse_graphics_anchor_format,
    parse_graphics_table_format,
    parse_sprite_field_spec,
    graphics_row_byte_size,
    compute_graphics_rom_span,
    raw_gba_palette_to_rgb888_list,
    resolve_gba_pointer,
)

_TOML_AVAILABLE = False
try:
    import tomli
    _TOML_AVAILABLE = True
except ImportError:
    pass

_TOMLI_W_AVAILABLE = False
try:
    import tomli_w
    _TOMLI_W_AVAILABLE = True
except ImportError:
    tomli_w = None  # type: ignore

_ANGR_AVAILABLE = False
try:
    import angr
    _ANGR_AVAILABLE = True
except ImportError:
    pass

_CAPSTONE_AVAILABLE = False
try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    from capstone.arm import ARM_OP_MEM, ARM_REG_PC
    _CAPSTONE_AVAILABLE = True
except ImportError:
    pass

_PYGMENTS_AVAILABLE = False
try:
    from pygments import lex
    from pygments.lexers import get_lexer_by_name
    _PYGMENTS_AVAILABLE = True
except ImportError:
    pass

GBA_ROM_BASE = 0x08000000
GBA_ROM_MAX = 0x09FFFFFF  # addresses > this are not ROM code pointers; treat as code, not .word
GBA_EWRAM_START = 0x02000000
GBA_EWRAM_END = 0x0203FFFF
GBA_IWRAM_START = 0x03000000
GBA_IWRAM_END = 0x03007FFF
BYTES_PER_ROW = 16
HEX_DIGITS = "0123456789ABCDEFabcdef"

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
        self._build()

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        f = ttk.Frame(self)
        f.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        f.columnconfigure(1, weight=1)
        ttk.Label(f, text="Table:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._combo = ttk.Combobox(f, font=("Consolas", 8), state="readonly")
        self._combo.grid(row=0, column=1, sticky="ew")
        self._combo.bind("<<ComboboxSelected>>", self._on_combo_select)
        tree_f = ttk.Frame(self)
        tree_f.grid(row=1, column=0, sticky="nsew")
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
        idx = self._combo.current()
        if idx < 0 or idx >= len(self._anchors):
            return
        info = self._anchors[idx]
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
        idx = self._combo.current()
        if idx >= 0 and idx < len(self._anchors):
            info = self._anchors[idx]
            try:
                gba = int(info["anchor"]["Address"]) if isinstance(info["anchor"]["Address"], (int, float)) else int(str(info["anchor"]["Address"]), 0)
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                off = gba - GBA_ROM_BASE + row_idx * info["width"]
                enc = encode_pcs_string(text, info["width"])
                self._hex.write_bytes_at(off, enc)
                parts = enc[:enc.index(0xFF)] if 0xFF in enc else enc
                disp = "".join(_PCS_BYTE_TO_CHAR.get(b, "·") for b in parts)
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
        idx = self._combo.current()
        if idx >= 0 and idx < len(self._anchors):
            info = self._anchors[idx]
            try:
                gba = int(info["anchor"]["Address"]) if isinstance(info["anchor"]["Address"], (int, float)) else int(str(info["anchor"]["Address"]), 0)
                if gba < GBA_ROM_BASE:
                    gba += GBA_ROM_BASE
                off = gba - GBA_ROM_BASE + row_idx * info["width"]
                enc = encode_pcs_string(text, info["width"])
                self._hex.write_bytes_at(off, enc)
                parts = enc[:enc.index(0xFF)] if 0xFF in enc else enc
                self._tree.set(self._edit_iid, "val", "".join(_PCS_BYTE_TO_CHAR.get(b, "·") for b in parts))
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

    def refresh_anchors(self) -> None:
        self._anchors = self._hex.get_pcs_table_anchors()
        self._combo.set("")
        self._combo.configure(values=[a["name"] for a in self._anchors] if self._anchors else [])
        self._tree.delete(*self._tree.get_children())

    def show_table(self, anchor_name: str) -> None:
        if not self._anchors:
            self.refresh_anchors()
        for i, a in enumerate(self._anchors):
            if a["name"] == anchor_name:
                self._combo.current(i)
                self._load_table()
                return

    def _load_table(self) -> None:
        self._tree.delete(*self._tree.get_children())
        if not self._anchors or not self._hex.get_data():
            return
        idx = self._combo.current()
        if idx < 0 or idx >= len(self._anchors):
            return
        info = self._anchors[idx]
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
        for i in range(count):
            off = base_off + i * width
            if off + width > len(data):
                break
            chunk = bytes(data[off : off + width])
            chars = []
            for b in chunk:
                if b == 0xFF:
                    break
                chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
            self._tree.insert("", tk.END, values=(str(i), "".join(chars)), iid=f"pcs_{i}")


class GraphicsPreviewFrame(ttk.Frame):
    """Decode GBA palettes/sprites with built-in pret gfx.c–compatible logic (Pillow PNG); no gbagfx binary."""

    def __init__(self, parent: tk.Misc, hex_editor: "HexEditorFrame", **kwargs) -> None:
        super().__init__(parent, **kwargs)
        self._hex = hex_editor
        self._photo: Optional[Any] = None
        self._pal4_state: Optional[Tuple[Any, bytes]] = None  # (GraphicsAnchorSpec, extracted pal bytes)
        self._pal8_colors: Optional[List[Tuple[int, int, int]]] = None
        self._build()

    def _build(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(5, weight=1)
        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text="Graphics:", font=("Consolas", 8)).grid(row=0, column=0, sticky="w", padx=(0, 4))
        self._combo = ttk.Combobox(top, font=("Consolas", 8), state="readonly")
        self._combo.grid(row=0, column=1, sticky="ew", padx=(0, 4))
        self._combo.bind("<<ComboboxSelected>>", lambda e: self._decode_selected())
        ttk.Button(top, text="Decode", command=self._decode_selected).grid(row=0, column=2, sticky="e")

        self._table_nav = ttk.Frame(top)
        self._table_nav.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(2, 0))
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

        self._pal8_canvas = tk.Canvas(
            self, height=44, bg="#1e1e1e", highlightthickness=1, highlightbackground="#555555"
        )
        self._pal8_canvas.grid(row=2, column=0, sticky="ew", pady=(0, 4))
        self._pal8_canvas.grid_remove()

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
        self._pal8_canvas.grid_remove()
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
        c.configure(width=total_w, height=total_h)
        for i, rgb in enumerate(rgbs):
            row, col = divmod(i, cols)
            x0 = pad + col * (cell_w + gap)
            y0 = pad + row * (cell_h + gap)
            fill = "#%02x%02x%02x" % rgb
            c.create_rectangle(x0, y0, x0 + cell_w, y0 + cell_h, fill=fill, outline="#666666")

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
        names = [a["name"] for a in self._hex.get_graphics_anchors()]
        self._combo.configure(values=names)
        if not names:
            self._combo.set("")
            self._hide_palette_4_ui()
            self._hide_palette_8_ui()
            self._table_nav.grid_remove()
            self._set_log("Graphics: built-in decode (pret gfx.c palette/tiles + Pillow).\n(no graphics NamedAnchors in TOML)")
            self._clear_image()

    def show_anchor(self, anchor_name: str) -> None:
        self.refresh_anchors()
        vals = list(self._combo["values"])
        try:
            i = vals.index(anchor_name)
        except ValueError:
            self._set_log(f"Graphics anchor not found: {anchor_name!r}")
            return
        self._combo.current(i)
        self._decode_selected()

    def _update_table_nav_for_info(self, info: Dict[str, Any]) -> None:
        """Show row spinbox when this anchor or its linked palette uses ``[format]count``."""
        need = bool(info.get("graphics_table"))
        if not need and info["spec"].kind == "sprite":
            pan = getattr(info["spec"], "palette_anchor_name", None)
            if pan:
                ga = self._hex.find_graphics_anchor_by_name(pan)
                need = bool(ga and ga.get("graphics_table"))
        if need:
            _, eff, _ = self._effective_table_state(info)
            self._table_idx_spin.configure(from_=0, to=max(0, eff - 1))
            self._table_nav.grid()
        else:
            self._table_nav.grid_remove()
            self._table_row_label.configure(text="")

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
        eff = min(counts) if counts else 1
        warn = ""
        if len(counts) > 1 and min(counts) != max(counts):
            warn = f"Table size mismatch (sprite vs palette): using min length {eff}.\n"
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
        if spec.kind == "sprite" and getattr(spec, "palette_anchor_name", None):
            ga = self._hex.find_graphics_anchor_by_name(spec.palette_anchor_name)
            if ga and ga.get("graphics_table"):
                return str(ga.get("table_count_ref") or "")
        return ""

    def _decode_selected(self, event: Optional[tk.Event] = None) -> None:
        idx = self._combo.current()
        vals = list(self._combo["values"])
        if idx < 0 or idx >= len(vals):
            return
        name = vals[idx]
        rom = self._hex.get_data()
        if not rom:
            return
        info = next((a for a in self._hex.get_graphics_anchors() if a["name"] == name), None)
        if not info:
            self._set_log("Anchor missing.")
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

        pal_data_off = info["base_off"]
        if info.get("graphics_table"):
            pal_data_off = info["base_off"] + tbl_idx * int(info["row_byte_size"])

        logs: List[str] = []
        if tbl_warn:
            logs.append(tbl_warn)
        if spec.kind == "palette":
            self._hide_palette_4_ui()
            self._hide_palette_8_ui()
            if spec.bpp == 4:
                raw = bytes(
                    rom[
                        pal_data_off : pal_data_off
                        + min(len(rom) - pal_data_off, 1 << 20)
                    ]
                )
                try:
                    pal_bytes = extract_palette_bytes(spec, raw)
                except ValueError as e:
                    self._set_log(f"Palette extract error: {e}")
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
                        pal_data_off : pal_data_off
                        + min(len(rom) - pal_data_off, 1 << 20)
                    ]
                )
                try:
                    pal_bytes = extract_palette_bytes(spec, raw)
                except ValueError as e:
                    self._set_log(f"Palette extract error: {e}")
                    self._clear_image()
                    return
                pal_bytes = palette_bytes_for_gbagfx(spec, pal_bytes)
                self._pal8_colors = raw_gba_palette_to_rgb888_list(pal_bytes)
                n8 = len(self._pal8_colors)
                self._pal8_title.configure(text=f"8bpp palette ({n8} colors):")
                self._pal8_row.grid()
                self._pal8_canvas.grid()
                self._refresh_palette_8_swatches()
            pal_path, log = decode_palette_to_png_pal(bytes(rom), pal_data_off, spec)
            logs.append(log)
            self._set_log("\n".join(logs))
            if pal_path:
                self._try_show_image(pal_path)
            else:
                self._clear_image("(palette PNG not produced)")
            return
        self._hide_palette_4_ui()
        self._hide_palette_8_ui()
        ext_ps: Optional[Any] = None
        ext_pb: Optional[int] = None
        log_pre = ""
        sprite_off = info["base_off"]
        if info.get("graphics_table"):
            sprite_off = info["base_off"] + tbl_idx * int(info["row_byte_size"])
        if spec.kind == "sprite" and getattr(spec, "palette_anchor_name", None):
            pan = spec.palette_anchor_name
            ga = self._hex.find_graphics_anchor_by_name(pan)
            if ga is None or ga["spec"].kind != "palette":
                dpal = "64-color (empty)" if spec.bpp == 6 else "16-color"
                log_pre = (
                    f"Warning: palette NamedAnchor not found or not a palette format: {pan!r}\n"
                    f"Using default {dpal} palette.\n\n"
                )
            else:
                ext_ps = ga["spec"]
                ext_pb = ga["base_off"]
                if ga.get("graphics_table"):
                    ext_pb = ga["base_off"] + tbl_idx * int(ga["row_byte_size"])
        png_path, log = decode_graphics_anchor_to_png(
            bytes(rom),
            sprite_off,
            spec,
            external_palette_spec=ext_ps,
            external_palette_base_off=ext_pb,
        )
        logs.append(log_pre + log)
        self._set_log("\n".join(logs))
        if png_path:
            self._try_show_image(png_path)
        else:
            self._clear_image("(sprite PNG not produced)")


def _split_enum_field_ref(enum_ref: Optional[str]) -> Tuple[str, int]:
    """
    Parse ``listname`` or ``listname+3`` / ``foo.bar-2`` (trailing ``±`` integer only; base is ``[\\w.]+``).

    ROM stores ``idx``; labels / PCS rows use ``idx + delta`` (forward with ``+``, backward with ``-``).
    """
    if not enum_ref:
        return "", 0
    s = str(enum_ref).strip()
    m = re.match(r"^([\w.]+)([+-]\d+)$", s)
    if m:
        return m.group(1).strip(), int(m.group(2))
    return s, 0


def _parse_struct_fields(fmt: str) -> Optional[List[Dict[str, Any]]]:
    """Parse the fields inside a Format like '[field1. field2: ...]count'.
    Returns list of field descriptors with byte offsets, or None if not a struct format."""
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
    inner = s[1:close]

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

    fields: List[Dict[str, Any]] = []
    offset = 0
    for tok in tokens:
        fd = _parse_single_field(tok)
        if fd:
            fd["offset"] = offset
            offset += fd["size"]
            fields.append(fd)
    return fields if fields else None


def _parse_single_field(token: str) -> Optional[Dict[str, Any]]:
    """Parse a single field token like 'hp.', 'type1.enumname', 'unknown:cardgraphicsindexes+1', etc."""
    if "|=" in token:
        return None
    if "|t|" in token:
        token = token.split("|t|")[0]
    if "|s=" in token:
        token = token.split("|s=")[0]
    hex_hint = False
    if "|h" in token:
        hex_hint = True
        token = token.replace("|h", "")
    if "|b[" in token:
        token = token.split("|b[")[0]

    m = re.match(r'^(\w+)""(\d+)', token)
    if m:
        return {"name": m.group(1), "size": int(m.group(2)), "type": "pcs", "enum": None}

    if token.endswith('<"">'):
        nm = re.match(r'^(\w+)', token)
        return {"name": nm.group(1) if nm else token, "size": 4, "type": "pcs_ptr", "enum": None}

    if token.endswith("<>"):
        nm = re.match(r'^(\w+)', token)
        return {"name": nm.group(1) if nm else token, "size": 4, "type": "ptr", "enum": None, "hex": True}

    sm = re.match(r"^(\w+)<`([^`]*)`>\s*$", token)
    if sm:
        inner = sm.group(2).strip()
        gspec, pal_name = parse_sprite_field_spec(inner)
        return {
            "name": sm.group(1),
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

    # e.g. unknown:cardgraphicsindexes+1 — optional trailing +N / -N after the table name
    m = re.match(r"^(\w+)([.:]+)([\w.]*)([+-]\d+)?$", token)
    if m:
        name = m.group(1)
        size_chars = m.group(2)
        base = (m.group(3) or "").strip()
        tail = m.group(4) or ""
        enum_ref = (base + tail).strip() if base else None
        size = sum(1 if c == "." else 2 for c in size_chars)
        return {"name": name, "size": size, "type": "uint", "enum": enum_ref or None, "hex": hex_hint}

    return None


def _parse_struct_count(fmt: str) -> Any:
    """Extract the count part after the closing ] in '[fields]count'."""
    s = fmt.strip()
    if s.startswith("^"):
        s = s[1:]
    if not s.startswith("["):
        return None
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
    """Load [[List]] entries into {name: {index: label}}."""
    lists: Dict[str, Dict[int, str]] = {}
    for lst in toml_data.get("List", []):
        if not isinstance(lst, dict):
            continue
        name = str(lst.get("Name", "")).strip().strip("'\"")
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
        self._edit_entry: Optional[tk.Entry] = None
        self._edit_iid: Optional[str] = None
        self._entry_index_context_pcs: Optional[Dict[str, Any]] = None
        self._build()

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
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Button(
            self._gfx_sprite_frame, text="Decode preview", command=self._on_decode_gfx_sprite
        ).grid(row=1, column=0, sticky="w", pady=(0, 4))
        self._gfx_log = tk.Text(
            self._gfx_sprite_frame, height=4, font=("Consolas", 7), wrap=tk.WORD, state=tk.DISABLED
        )
        self._gfx_log.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        self._gfx_img_label = ttk.Label(self._gfx_sprite_frame, text="")
        self._gfx_img_label.grid(row=3, column=0, sticky="nw")
        self._gfx_sprite_frame.grid(row=5, column=0, sticky="ew", pady=(0, 2))
        self._gfx_sprite_frame.grid_remove()
        self._gfx_fi: Optional[int] = None
        self._gfx_photo: Optional[Any] = None

        # [[List]] enum: ROM dropdown + TOML label. PCS NamedAnchor table enum: ROM dropdown + PCS string in ROM.
        self._list_enum_frame = ttk.Frame(self)
        self._list_enum_frame.columnconfigure(0, weight=1)
        ttk.Label(self._list_enum_frame, text="[ROM ▾]", font=("Consolas", 8, "bold")).grid(
            row=0, column=0, sticky="nw", padx=(0, 4), pady=(0, 2)
        )
        ttk.Label(self._list_enum_frame, text="Pick index (writes ROM only):", font=("Consolas", 8)).grid(
            row=0, column=1, sticky="w", pady=(0, 2)
        )
        self._list_enum_rom_combo = ttk.Combobox(
            self._list_enum_frame, font=("Consolas", 8), width=36, state="readonly"
        )
        self._list_enum_rom_combo.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        self._list_enum_rom_combo.bind("<<ComboboxSelected>>", self._on_list_enum_rom_combo)
        self._list_enum_idx_by_combo: List[int] = []
        ttk.Separator(self._list_enum_frame, orient=tk.HORIZONTAL).grid(
            row=2, column=0, columnspan=2, sticky="ew", pady=(0, 4)
        )
        self._list_enum_toml_block = ttk.Frame(self._list_enum_frame)
        self._list_enum_toml_block.columnconfigure(0, weight=1)
        ttk.Label(self._list_enum_toml_block, text="[TOML ✎]", font=("Consolas", 8, "bold")).grid(
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
        self._list_enum_toml_block.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        self._list_enum_toml_block.grid_remove()

        self._list_enum_pcs_block = ttk.Frame(self._list_enum_frame)
        self._list_enum_pcs_block.columnconfigure(0, weight=1)
        ttk.Label(self._list_enum_pcs_block, text="[ROM PCS ✎]", font=("Consolas", 8, "bold")).grid(
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
        self._list_enum_pcs_block.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        self._list_enum_pcs_block.grid_remove()
        self._list_enum_fi: Optional[int] = None
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
        self._tree.bind("<Return>", self._start_inline_edit)
        self._tree.bind("<F2>", self._start_inline_edit)
        self._tree.bind("<ButtonRelease-1>", self._on_tree_click)
        self._tree.bind("<<TreeviewSelect>>", lambda e: self._sync_field_aux_panels())

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

    def _set_gfx_log(self, text: str) -> None:
        self._gfx_log.configure(state=tk.NORMAL)
        self._gfx_log.delete("1.0", tk.END)
        self._gfx_log.insert("1.0", text)
        self._gfx_log.configure(state=tk.DISABLED)

    def _update_gfx_sprite_panel(self) -> None:
        sel = self._tree.selection()
        if not sel or not sel[0].startswith("sf_"):
            self._gfx_sprite_frame.grid_remove()
            self._gfx_fi = None
            return
        fi = int(sel[0].split("_")[1])
        if fi >= len(self._fields):
            self._gfx_sprite_frame.grid_remove()
            self._gfx_fi = None
            return
        fd = self._fields[fi]
        if fd.get("type") != "gfx_sprite":
            self._gfx_sprite_frame.grid_remove()
            self._gfx_fi = None
            return
        self._gfx_fi = fi
        self._gfx_sprite_frame.grid(row=5, column=0, sticky="ew", pady=(0, 2))

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
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
        if foff + 4 > len(data):
            return
        tgt = resolve_gba_pointer(data, foff)
        if tgt is None:
            self._set_gfx_log("Pointer does not reference ROM (need 0x08…/0x09… GBA address).")
            self._gfx_img_label.configure(image="", text="(bad pointer)")
            return
        pal_name = fd.get("gfx_palette_name")
        pal_spec = None
        pal_base = None
        log_extra = ""
        if pal_name:
            ga = self._hex.find_graphics_anchor_by_name(pal_name)
            if ga is None or ga["spec"].kind != "palette":
                dpal = "64-color (empty)" if spec.bpp == 6 else "16-color"
                log_extra = (
                    f"\nWarning: palette anchor missing or not palette format: {pal_name!r}\n"
                    f"Using default {dpal} palette.\n"
                )
            else:
                pal_spec = ga["spec"]
                if ga.get("graphics_table"):
                    nrow = int(ga.get("table_num_entries") or 0)
                    if nrow <= 0:
                        cref = ga.get("table_count_ref") or ""
                        c = self._hex._resolve_struct_count(cref)
                        nrow = c if isinstance(c, int) and c > 0 else 1
                    row_i = max(0, min(entry_idx, nrow - 1))
                    pal_base = ga["base_off"] + row_i * int(ga["row_byte_size"])
                else:
                    pal_base = ga["base_off"]
        png_path, log = decode_sprite_at_pointer(bytes(data), tgt, spec, pal_spec, pal_base)
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
        fi = int(sel[0].split("_")[1])
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
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
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
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
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
            self._tree.set(iid, "val", self._format_value(raw, fd))

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

    def _apply_pcs_ptr_string_write(self, fi: int, new_text: str) -> bool:
        """Write PCS text at the current pointer; grow into trailing 0xFF padding or relocate into an FF gap."""
        foff = self._pcs_ptr_field_file_off(fi)
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
        for info in self._hex.get_pcs_table_anchors():
            if info["name"] == ref:
                return info
        return None

    def _is_toml_list_enum_field(self, fd: Dict[str, Any]) -> bool:
        if fd.get("type") != "uint" or not fd.get("enum"):
            return False
        base, _ = _split_enum_field_ref(fd["enum"])
        return bool(base) and base in self._lists

    def _is_pcs_table_enum_field(self, fd: Dict[str, Any]) -> bool:
        if fd.get("type") != "uint" or not fd.get("enum"):
            return False
        base, _ = _split_enum_field_ref(fd["enum"])
        if not base or base in self._lists:
            return False
        return self._find_pcs_anchor_info_for_enum(fd["enum"]) is not None

    def _is_enum_panel_field(self, fd: Dict[str, Any]) -> bool:
        return self._is_toml_list_enum_field(fd) or self._is_pcs_table_enum_field(fd)

    def _update_list_enum_panel(self) -> None:
        """Show ROM index combobox + [[List]] TOML editor or PCS table string editor."""
        sel = self._tree.selection()
        if not sel or not sel[0].startswith("sf_"):
            self._list_enum_frame.grid_remove()
            self._list_enum_fi = None
            self._list_enum_active_pcs = None
            return
        fi = int(sel[0].split("_")[1])
        if fi >= len(self._fields):
            self._list_enum_frame.grid_remove()
            self._list_enum_fi = None
            self._list_enum_active_pcs = None
            return
        fd = self._fields[fi]
        if not self._is_enum_panel_field(fd):
            self._list_enum_frame.grid_remove()
            self._list_enum_fi = None
            self._list_enum_active_pcs = None
            return
        self._list_enum_fi = fi
        self._list_enum_frame.grid(row=3, column=0, sticky="ew", pady=(0, 2))
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
        if foff + fd["size"] > len(data):
            return
        cur = int.from_bytes(data[foff:foff + fd["size"]], "little")
        self._list_enum_idx_by_combo = []
        display_vals: List[str] = []

        if self._is_toml_list_enum_field(fd):
            self._list_enum_active_pcs = None
            self._list_enum_toml_block.grid()
            self._list_enum_pcs_block.grid_remove()
            list_base, delta = _split_enum_field_ref(fd["enum"])
            lm = self._lists.get(list_base, {})
            list_row = cur + delta
            for idx in sorted(lm.keys()):
                lab = lm[idx]
                self._list_enum_idx_by_combo.append(idx)
                short = lab.replace("\n", " ")
                if len(short) > 52:
                    short = short[:49] + "…"
                display_vals.append(f"{idx}: {short}")
            self._list_enum_rom_combo["values"] = tuple(display_vals)
            try:
                pos = self._list_enum_idx_by_combo.index(list_row)
            except ValueError:
                self._list_enum_rom_combo.set(
                    f"(ROM {cur} → list row {list_row} — not in [[List]] {list_base!r})"
                )
            else:
                self._list_enum_rom_combo.current(pos)
            self._list_enum_toml_var.set(lm.get(list_row, ""))
            return

        pcs_info = self._find_pcs_anchor_info_for_enum(fd["enum"])
        self._list_enum_active_pcs = pcs_info
        self._list_enum_toml_block.grid_remove()
        self._list_enum_pcs_block.grid()
        count = int(pcs_info.get("count") or 0) if pcs_info else 0
        for idx in range(count):
            lab = self._pcs_decode_table_row(pcs_info, idx) if pcs_info else ""
            self._list_enum_idx_by_combo.append(idx)
            short = lab.replace("\n", " ")
            if len(short) > 52:
                short = short[:49] + "…"
            display_vals.append(f"{idx}: {short}")
        self._list_enum_rom_combo["values"] = tuple(display_vals)
        _, delta = _split_enum_field_ref(fd["enum"])
        list_row = cur + delta
        if 0 <= list_row < count:
            self._list_enum_rom_combo.current(list_row)
        else:
            self._list_enum_rom_combo.set(
                f"(ROM {cur} → PCS row {list_row} — past table or negative)"
            )
        if pcs_info and 0 <= list_row < count:
            self._list_enum_pcs_var.set(self._pcs_decode_table_row(pcs_info, list_row))
        else:
            self._list_enum_pcs_var.set("")

    def _on_list_enum_rom_combo(self, event: Optional[tk.Event] = None) -> None:
        fi = self._list_enum_fi
        if fi is None or fi >= len(self._fields):
            return
        fd = self._fields[fi]
        if not self._is_enum_panel_field(fd):
            return
        pos = self._list_enum_rom_combo.current()
        if pos < 0 or pos >= len(self._list_enum_idx_by_combo):
            return
        new_idx = self._list_enum_idx_by_combo[pos]
        _, delta = _split_enum_field_ref(fd.get("enum"))
        rom_val = new_idx - delta
        if rom_val < 0:
            messagebox.showwarning("Struct", f"Selection would need ROM index {rom_val} (negative).")
            return
        max_u = (1 << (8 * fd["size"])) - 1 if fd["size"] <= 8 else (1 << 32) - 1
        if rom_val > max_u:
            messagebox.showwarning("Struct", f"ROM index {rom_val} does not fit field size.")
            return
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
        if foff + fd["size"] > len(data):
            return
        self._hex.write_bytes_at(foff, rom_val.to_bytes(fd["size"], "little"))
        iid = f"sf_{fi}"
        data2 = self._hex.get_data()
        if data2 and self._tree.exists(iid):
            raw = bytes(data2[foff:foff + fd["size"]])
            self._tree.set(iid, "val", self._format_value(raw, fd))
        if self._is_toml_list_enum_field(fd):
            list_base, _ = _split_enum_field_ref(fd["enum"])
            self._list_enum_toml_var.set(self._lists.get(list_base, {}).get(new_idx, ""))
        elif self._list_enum_active_pcs:
            self._list_enum_pcs_var.set(self._pcs_decode_table_row(self._list_enum_active_pcs, new_idx))

    def _on_list_enum_toml_apply(self) -> None:
        fi = self._list_enum_fi
        if fi is None or fi >= len(self._fields):
            return
        fd = self._fields[fi]
        if not self._is_toml_list_enum_field(fd):
            return
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
        if foff + fd["size"] > len(data):
            return
        cur = int.from_bytes(data[foff:foff + fd["size"]], "little")
        list_name, delta = _split_enum_field_ref(fd["enum"])
        list_row = cur + delta
        new_s = self._list_enum_toml_var.get()
        if not self._hex.update_toml_list_string_at_index(list_name, list_row, new_s):
            return
        self._reload_lists()
        self._update_list_enum_panel()
        iid = f"sf_{fi}"
        data2 = self._hex.get_data()
        if data2 and self._tree.exists(iid):
            raw = bytes(data2[foff:foff + fd["size"]])
            self._tree.set(iid, "val", self._format_value(raw, fd))

    def _on_list_enum_pcs_apply(self) -> None:
        fi = self._list_enum_fi
        if fi is None or fi >= len(self._fields):
            return
        fd = self._fields[fi]
        if not self._is_pcs_table_enum_field(fd) or not self._list_enum_active_pcs:
            return
        data = self._hex.get_data()
        if not data:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
        if foff + fd["size"] > len(data):
            return
        cur = int.from_bytes(data[foff:foff + fd["size"]], "little")
        pcs_info = self._list_enum_active_pcs
        count = int(pcs_info.get("count") or 0)
        _, delta = _split_enum_field_ref(fd.get("enum"))
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
        iid = f"sf_{fi}"
        data2 = self._hex.get_data()
        if data2 and self._tree.exists(iid):
            raw = bytes(data2[foff:foff + fd["size"]])
            self._tree.set(iid, "val", self._format_value(raw, fd))

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
        pcs_count = int(self._entry_index_context_pcs.get("count") or 0)
        if idx >= pcs_count:
            messagebox.showwarning("Struct", "Current index is past the PCS table length.")
            return
        text = self._entry_label_pcs_var.get()
        if not self._write_pcs_table_row(self._entry_index_context_pcs, idx, text):
            messagebox.showerror("Struct", "Could not write PCS string (bad address or ROM bounds).")
            return
        self._update_entry_index_name_label()
        self._load_entry(idx)

    def _on_combo_select(self, event: Optional[tk.Event] = None) -> None:
        idx = self._combo.current()
        if idx < 0 or idx >= len(self._anchors):
            return
        info = self._anchors[idx]
        self._fields = info["fields"]
        self._entry_count = info["count"]
        self._struct_size = info["struct_size"]
        self._base_off = info["base_off"]
        self._entry_index_context_pcs = info.get("entry_label_pcs")
        self._idx_spin.configure(to=max(0, self._entry_count - 1))
        self._idx_var.set("0")
        self._entry_label.config(text=f"/ {self._entry_count}")
        self._load_entry(0)

    def _on_spin_change(self) -> None:
        try:
            i = int(self._idx_var.get())
        except ValueError:
            return
        i = max(0, min(i, self._entry_count - 1))
        self._idx_var.set(str(i))
        self._load_entry(i)

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
        chars = []
        for i in range(width):
            b = data[off + i]
            if b == 0xFF:
                break
            chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
        return "".join(chars)

    def _update_entry_index_name_label(self) -> None:
        """Show PCS text from the Format ]suffix table at the current entry index, if applicable."""
        if not self._entry_index_context_pcs:
            self._entry_index_name_label.grid_remove()
            self._entry_label_pcs_frame.grid_remove()
            return
        try:
            idx = int(self._idx_var.get())
        except ValueError:
            self._entry_index_name_label.grid_remove()
            self._entry_label_pcs_frame.grid_remove()
            return
        idx = max(0, min(idx, self._entry_count - 1))
        pcs_count = int(self._entry_index_context_pcs.get("count") or 0)
        if idx >= pcs_count:
            self._entry_index_name_label.config(text="→ (past PCS table)")
            self._entry_index_name_label.grid()
            self._entry_label_pcs_frame.grid_remove()
            return
        txt = self._pcs_decode_table_row(self._entry_index_context_pcs, idx)
        if txt:
            self._entry_index_name_label.config(text=f"→ {txt}")
        else:
            self._entry_index_name_label.config(text="→ (empty)")
        self._entry_index_name_label.grid()
        self._entry_label_pcs_var.set(txt)
        self._entry_label_pcs_frame.grid()

    def _reload_lists(self) -> None:
        self._lists = self._hex.get_lists()

    def refresh_anchors(self) -> None:
        self._anchors = self._hex.get_struct_anchors()
        self._reload_lists()
        self._entry_index_context_pcs = None
        self._entry_index_name_label.grid_remove()
        self._entry_label_pcs_frame.grid_remove()
        self._list_enum_frame.grid_remove()
        self._list_enum_fi = None
        self._gfx_sprite_frame.grid_remove()
        self._gfx_fi = None
        self._combo.set("")
        self._combo.configure(values=[a["name"] for a in self._anchors] if self._anchors else [])
        self._tree.delete(*self._tree.get_children())

    def show_struct(self, anchor_name: str) -> None:
        if not self._anchors:
            self.refresh_anchors()
        for i, a in enumerate(self._anchors):
            if a["name"] == anchor_name:
                self._combo.current(i)
                self._on_combo_select()
                return

    def _load_entry(self, entry_idx: int) -> None:
        self._cancel_inline_edit()
        self._ptr_text_frame.grid_remove()
        self._ptr_text_fi = None
        self._list_enum_frame.grid_remove()
        self._list_enum_fi = None
        self._gfx_sprite_frame.grid_remove()
        self._gfx_fi = None
        self._tree.delete(*self._tree.get_children())
        try:
            data = self._hex.get_data()
            if not data or not self._fields:
                return
            off = self._base_off + entry_idx * self._struct_size
            if off + self._struct_size > len(data):
                return
            for fi, fd in enumerate(self._fields):
                foff = off + fd["offset"]
                sz = fd["size"]
                if foff + sz > len(data):
                    break
                raw = bytes(data[foff:foff + sz])
                val_str = self._format_value(raw, fd)
                self._tree.insert("", tk.END, values=(fd["name"], val_str), iid=f"sf_{fi}")
        finally:
            self._update_entry_index_name_label()
            self._sync_field_aux_panels()

    def _format_value(self, raw: bytes, fd: Dict[str, Any]) -> str:
        ftype = fd["type"]
        if ftype == "pcs":
            chars = []
            for b in raw:
                if b == 0xFF:
                    break
                chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
            return "".join(chars)
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
        val = int.from_bytes(raw, "little")
        enum_ref = fd.get("enum")
        if enum_ref:
            label = self._resolve_enum(val, enum_ref)
            if label is not None:
                if self._is_enum_panel_field(fd):
                    return f"{label}  ▾"
                return label
        if fd.get("hex"):
            return f"0x{val:0{len(raw) * 2}X}"
        return str(val)

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
        lm = self._lists.get(base)
        if lm is not None:
            label = lm.get(idx)
            if label is not None:
                return f"{value} ({label})"
        for info in self._hex.get_pcs_table_anchors():
            if info["name"] == base:
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
                chars = []
                for i in range(info["width"]):
                    b = data[entry_off + i]
                    if b == 0xFF:
                        break
                    chars.append(_PCS_BYTE_TO_CHAR.get(b, "·"))
                return f"{value} ({''.join(chars)})"
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
        fi = int(iid.split("_")[1])
        if fi >= len(self._fields):
            return
        fd = self._fields[fi]
        if self._is_enum_panel_field(fd):
            self._sync_field_aux_panels()
            self._list_enum_rom_combo.focus_set()
            return
        vals = self._tree.item(iid, "values")
        if len(vals) < 2:
            return
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            return
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
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
            raw_val = raw_val.split(" (")[0] if " (" in raw_val else raw_val
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
        fi = int(self._edit_iid.split("_")[1])
        if fi >= len(self._fields):
            self._cancel_inline_edit()
            return
        fd = self._fields[fi]
        try:
            entry_idx = int(self._idx_var.get())
        except ValueError:
            self._cancel_inline_edit()
            return
        foff = self._base_off + entry_idx * self._struct_size + fd["offset"]
        data = self._hex.get_data()
        if not data or foff + fd["size"] > len(data):
            self._cancel_inline_edit()
            return

        skip_tree_refresh = False
        if fd["type"] == "pcs":
            enc = encode_pcs_string(text, fd["size"])
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
        elif fd["type"] in ("uint", "ptr", "gfx_sprite"):
            try:
                val = int(text, 0)
            except ValueError:
                self._cancel_inline_edit()
                return
            enc = val.to_bytes(fd["size"], "little")
            self._hex.write_bytes_at(foff, enc)
        else:
            self._cancel_inline_edit()
            return

        if not skip_tree_refresh:
            raw = bytes(self._hex.get_data()[foff:foff + fd["size"]])
            self._tree.set(self._edit_iid, "val", self._format_value(raw, fd))
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
        fi = int(cur_iid.split("_")[1])
        direction = -1 if event.keysym == "Up" else 1
        next_fi = fi + direction
        next_iid = f"sf_{next_fi}"
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
        self._anchor_browser_pane_visible = False
        self._anchor_browser_path: List[str] = []
        self._ldr_pc_targets: Optional[Set[int]] = None
        self._ldr_pc_targets_valid = False
        self._toml_path: Optional[str] = None
        self._toml_data: Dict[str, Any] = {}
        # When set, this file is loaded instead of auto-resolving {ROM}.toml (until cleared).
        self._toml_manual_override: Optional[str] = None
        # Row index for ``[format]count`` graphics / palette tables (spinbox in Tools → Graphics).
        self.graphics_table_row_var = tk.IntVar(value=0)
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
        body.columnconfigure(5, weight=0)
        body.columnconfigure(6, weight=1)
        body.rowconfigure(0, weight=0)
        body.rowconfigure(1, weight=1)

        hex_width = 10 + 3 * BYTES_PER_ROW - 1
        hex_header_text = " " * 10 + "  ".join(f"{i:X}" for i in range(BYTES_PER_ROW))
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
            self._asm_frame, font=("Consolas", 10), wrap=tk.NONE, width=58,
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
        self._pseudo_c_frame.columnconfigure(0, weight=1)
        self._pseudo_c_frame.rowconfigure(0, weight=1)
        self._scroll_pseudo_c = tk.Scrollbar(self._pseudo_c_frame)
        self._scroll_pseudo_c_h = tk.Scrollbar(self._pseudo_c_frame, orient=tk.HORIZONTAL)
        self._text_pseudo_c = tk.Text(
            self._pseudo_c_frame, font=("Consolas", 10), wrap=tk.NONE, width=48,
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
        self._scroll_pseudo_c_h.grid(row=1, column=0, sticky="ew")

        def _pseudo_c_scroll(delta: int) -> None:
            self._text_pseudo_c.yview_scroll(-delta, "units")

        for w in (self._text_pseudo_c, self._pseudo_c_frame):
            w.bind("<MouseWheel>", lambda e: _pseudo_c_scroll(int((e.delta or 0) / 120)))
            w.bind("<Button-4>", lambda e: _pseudo_c_scroll(3))
            w.bind("<Button-5>", lambda e: _pseudo_c_scroll(-3))

        # Function/NamedAnchor browser: hierarchical nav (1st -> 2nd -> 3rd order), Ctrl+M
        self._anchor_frame = ttk.LabelFrame(body, text=" Anchors ", padding=2)
        self._anchor_frame.grid(row=1, column=5, sticky="nsew", padx=(4, 0))
        self._anchor_frame.columnconfigure(0, weight=1)
        self._anchor_frame.rowconfigure(0, weight=1)
        self._scroll_anchor = tk.Scrollbar(self._anchor_frame)
        self._listbox_anchor = tk.Listbox(
            self._anchor_frame, font=("Consolas", 9), width=36, height=20,
            activestyle="dotbox", selectmode=tk.SINGLE,
            yscrollcommand=self._scroll_anchor.set,
        )
        self._listbox_anchor.grid(row=0, column=0, sticky="nsew")
        self._scroll_anchor.grid(row=0, column=1, sticky="ns")
        self._scroll_anchor.configure(command=self._listbox_anchor.yview)
        self._listbox_anchor.bind("<Double-Button-1>", self._on_anchor_browser_double_click)

        def _anchor_scroll(delta: int) -> None:
            self._listbox_anchor.yview_scroll(-delta, "units")
        for w in (self._listbox_anchor, self._anchor_frame):
            w.bind("<MouseWheel>", lambda e: _anchor_scroll(int((e.delta or 0) / 120)))
            w.bind("<Button-4>", lambda e: _anchor_scroll(3))
            w.bind("<Button-5>", lambda e: _anchor_scroll(-3))

        self._tools_frame = ttk.Frame(body, width=1)
        self._tools_frame.grid(row=1, column=6, sticky="nsew", padx=(4, 0))

        self._on_pointer_to_named_anchor_cb: Optional[Any] = None

        if not self._asm_pane_visible:
            self._asm_frame.grid_remove()
        if not self._pseudo_c_pane_visible:
            self._pseudo_c_frame.grid_remove()
        if not self._anchor_browser_pane_visible:
            self._anchor_frame.grid_remove()

        self._text.tag_configure("pointer", foreground="red")
        self._text.tag_configure("sel_hex", background="#add8e6", foreground="black")
        self._text.tag_configure("cursor_byte", background="#e0e0e0")
        self._text_ascii.tag_configure("pointer", foreground="red")
        self._text_ascii.tag_configure("sel_ascii", background="#add8e6", foreground="black")

        self._init_syntax_highlight_tags()

        # Key / mouse bindings on hex widget
        self._text.bind("<KeyPress>", self._on_key)
        self._text.bind("<Button-1>", self._on_click)
        self._text.bind("<B1-Motion>", self._on_drag)
        self._text.bind("<Double-Button-1>", self._on_double_click)
        self._text.bind("<Button-3>", self._on_right_click)
        def _bind_asm_toggle(w: tk.Misc) -> None:
            w.bind("<Control-a>", self._toggle_asm_pane)
            w.bind("<Control-A>", self._toggle_asm_pane)

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
        self.winfo_toplevel().bind("<Control-a>", self._toggle_asm_pane, add=True)
        self.winfo_toplevel().bind("<Control-A>", self._toggle_asm_pane, add=True)
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

        self._text.bind("<Control-Shift-A>", lambda e: self._select_all())
        self._text_ascii.bind("<Control-Shift-A>", lambda e: self._select_all())
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
        """Toggle ASM disassembly pane visibility. Bound to Ctrl+A.
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

    def _toggle_anchor_browser_pane(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Toggle FunctionAnchor browser pane visibility. Bound to Ctrl+M."""
        self._goto_entry.selection_clear()
        self._text.focus_set()
        self._anchor_browser_pane_visible = not self._anchor_browser_pane_visible
        if self._anchor_browser_pane_visible:
            self._anchor_frame.grid(row=1, column=5, sticky="nsew", padx=(4, 0))
            self._anchor_browser_path = []
            self._refresh_anchor_browser()
        else:
            self._anchor_frame.grid_remove()
        self.after_idle(self._refresh_visible)
        return "break"

    def _get_anchor_browser_items(self) -> List[Tuple[str, Optional[int]]]:
        """Return [(display_text, address_or_none), ...]. address is set for leaves (full anchor names).
        Includes both FunctionAnchors and NamedAnchors."""
        funcs = self._toml_data.get("FunctionAnchors", [])
        named = self._toml_data.get("NamedAnchors", [])
        anchors = list(funcs) + [a for a in named if a.get("Address") is not None]
        path = self._anchor_browser_path
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
        result: List[Tuple[str, Optional[int]]] = []
        for b in sorted(branches):
            result.append((b, None))
        for name, off in sorted(leaves, key=lambda x: x[0]):
            result.append((name, off))
        return result

    def _refresh_anchor_browser(self) -> None:
        """Populate the anchor browser Listbox from current path."""
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
            self._refresh_anchor_browser()
            return
        if address is None:
            self._anchor_browser_path = display.split(".")
            self._refresh_anchor_browser()
            return
        self._do_goto(address)
        cb = self._on_pointer_to_named_anchor_cb
        if not cb:
            return
        anchor_info = self._named_anchor_info_for_tools(display)
        if anchor_info:
            self.after(10, lambda ai=anchor_info: cb(ai))

    def _parse_pcs_format(self, fmt: str) -> Optional[Tuple[str, int, Any]]:
        if not fmt:
            return None
        m = re.search(r'\^?\[(\w+)""(\d+)\](.+)', fmt)
        if not m:
            return None
        field, width_str, length_part = m.group(1), m.group(2), m.group(3).strip()
        width = int(width_str)
        if length_part.isdigit():
            return (field, width, int(length_part))
        return (field, width, length_part)

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
            fmt = str(anchor.get("Format", "")).strip().strip("'\"")
            parsed = self._parse_pcs_format(fmt)
            if parsed:
                field, width, length = parsed
                count = length if isinstance(length, int) else self._resolve_table_length(length)
                if count is not None and count > 0:
                    result.append({
                        "anchor": anchor, "name": str(anchor.get("Name", "")).strip(),
                        "field": field, "width": width, "count": count,
                    })
        return result

    def set_on_pointer_to_named_anchor(self, cb: Optional[Any]) -> None:
        """Set callback(anchor_info) for NamedAnchor navigation (pointer follow or direct offset match)."""
        self._on_pointer_to_named_anchor_cb = cb

    def _named_anchor_info_for_tools(self, anchor_name: str) -> Optional[Dict[str, Any]]:
        """If ``anchor_name`` is a PCS table or struct NamedAnchor, return info with ``type`` ``pcs`` or ``struct``.

        Shape matches :meth:`_find_named_anchor_at_offset` results for use with
        ``set_on_pointer_to_named_anchor`` (e.g. FireRed tools pane).
        """
        want = anchor_name.strip()
        for info in self._get_pcs_table_anchors():
            if info["name"] == want:
                return {**info, "type": "pcs"}
        for info in self.get_struct_anchors():
            if info["name"] == want:
                return {**info, "type": "struct"}
        for info in self.get_graphics_anchors():
            if info["name"] == want:
                return {**info, "type": "graphics"}
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
            total = info["struct_size"] * info["count"]
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
            total_bytes = info["struct_size"] * info["count"]
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
            self._toggle_asm_pane(event)
            return "break"
        if not self._data:
            return None
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
            self._data[off] = byte_val
            self._modified = True
            self._ldr_pc_targets_valid = False
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
        if event.state & 0x4 and event.keysym.lower() in ("a", "b", "c", "f", "g", "h", "i", "m", "r", "v", "x", "s"):
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

    def _parse_find_hex(self, text: str) -> Optional[bytearray]:
        """Parse find string as hex (DE AD BE EF or DEADBEEF)."""
        digits = "".join(c for c in text if c in HEX_DIGITS)
        if len(digits) < 2:
            return None
        out = bytearray()
        for i in range(0, len(digits) - 1, 2):
            out.append(int(digits[i : i + 2], 16))
        return out if out else None

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

    def _find_next(self, needle: bytes, forward: bool) -> Optional[int]:
        """Find needle in _data. Forward: from cursor+1; backward: from cursor-1. Returns offset or None."""
        if not self._data or not needle:
            return None
        data = self._data
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
        d.geometry("420x140")
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
        mode_var = tk.StringVar(value="hex" if default_hex else "ascii")
        ttk.Radiobutton(frm, text="Hex", variable=mode_var, value="hex").grid(
            row=1, column=1, sticky="w", pady=2
        )
        ttk.Radiobutton(frm, text="ASCII", variable=mode_var, value="ascii").grid(
            row=2, column=1, sticky="w", pady=2
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
        btn_frm.grid(row=3, column=1, sticky="w", pady=8)
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
        d.geometry("420x180")
        d.resizable(True, False)
        focus = self.winfo_toplevel().focus_get()
        default_hex = focus == self._text
        frm = ttk.Frame(d, padding=8)
        frm.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frm, text="Find:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=2)
        find_var = tk.StringVar()
        find_entry = ttk.Entry(frm, textvariable=find_var, width=36)
        find_entry.grid(row=0, column=1, sticky="ew", pady=2)
        ttk.Label(frm, text="Replace:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=2)
        repl_var = tk.StringVar()
        repl_entry = ttk.Entry(frm, textvariable=repl_var, width=36)
        repl_entry.grid(row=1, column=1, sticky="ew", pady=2)
        frm.columnconfigure(1, weight=1)
        mode_var = tk.StringVar(value="hex" if default_hex else "ascii")
        ttk.Radiobutton(frm, text="Hex", variable=mode_var, value="hex").grid(
            row=2, column=1, sticky="w", pady=2
        )
        ttk.Radiobutton(frm, text="ASCII", variable=mode_var, value="ascii").grid(
            row=3, column=1, sticky="w", pady=2
        )
        status_var = tk.StringVar(value="")

        def get_needle() -> Optional[bytearray]:
            raw = find_var.get()
            return self._parse_find_hex(raw) if mode_var.get() == "hex" else self._parse_find_ascii(raw)

        def get_replacement() -> Optional[bytearray]:
            raw = repl_var.get()
            return self._parse_find_hex(raw) if mode_var.get() == "hex" else self._parse_find_ascii(raw)

        def selection_matches(needle: bytes) -> bool:
            s = min(self._selection_start or 0, self._selection_end or 0)
            e = max(self._selection_start or 0, self._selection_end or 0) + 1
            return (e - s == len(needle) and
                    s >= 0 and e <= len(self._data) and
                    bytes(self._data[s:e]) == needle)

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
            if len(repl) == len(needle):
                self._data[s:e] = repl
            elif len(repl) < len(needle):
                del self._data[s + len(repl):e]
                self._data[s:s + len(repl)] = repl
            else:
                self._data[s:e] = repl[:len(needle)]
                self._data[s + len(needle):s + len(needle)] = repl[len(needle):]
            self._modified = True
            self._ldr_pc_targets_valid = False
            self._cursor_byte_offset = min(s + len(repl), len(self._data) - 1) if self._data else 0
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
                idx = self._data.find(needle, pos)
                if idx < 0:
                    break
                if len(repl) == len(needle):
                    self._data[idx:idx + len(needle)] = repl
                elif len(repl) < len(needle):
                    del self._data[idx + len(repl):idx + len(needle)]
                    self._data[idx:idx + len(repl)] = repl
                else:
                    self._data[idx:idx + len(needle)] = repl[:len(needle)]
                    self._data[idx + len(needle):idx + len(needle)] = repl[len(needle):]
                count += 1
                pos = idx + len(repl)
            if count > 0:
                self._modified = True
                self._ldr_pc_targets_valid = False
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
        btn_frm.grid(row=4, column=1, sticky="w", pady=8)
        ttk.Button(btn_frm, text="Find Next", command=do_find_next).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frm, text="Replace", command=do_replace_one).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frm, text="Replace All", command=do_replace_all).pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(btn_frm, text="Close", command=d.destroy).pack(side=tk.LEFT, padx=(0, 4))
        lbl = ttk.Label(frm, textvariable=status_var)
        lbl.grid(row=5, column=1, sticky="w", pady=2)
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
        self._modified = False
        self._ldr_pc_targets_valid = False
        self._cursor_byte_offset = 0
        self._selection_start = self._selection_end = None
        self._nibble_pos = 0
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW if self._data else 0
        self._visible_row_start = 0
        self._load_toml_for_rom()
        self._refresh_visible()
        self._update_scrollbar()
        self._refresh_asm_selection()
        self._text.focus_set()
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

        Prefer ``{ROM stem}.toml``. If missing, accept well-known project names
        (``wct06.toml``, ``BPRE0.toml``) or a single ``*.toml`` in the same
        folder — so a ROM with a different basename still picks up the repo
        structure file.

        Returns (path, exists_on_disk).
        """
        rom_dir = os.path.dirname(os.path.abspath(rom_path))
        stem = os.path.splitext(os.path.basename(rom_path))[0]
        primary = os.path.join(rom_dir, stem + ".toml")
        if os.path.isfile(primary):
            return primary, True
        for name in ("wct06.toml", "BPRE0.toml", "bpred.toml"):
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
        loaded = False
        if _TOML_AVAILABLE:
            try:
                with open(toml_path, "rb") as f:
                    self._toml_data = tomli.load(f)
                loaded = True
            except Exception as e:
                messagebox.showerror("TOML load failed", f"{toml_path}\n{e}")
                return False
        if not loaded:
            self._toml_data = self._load_toml_regex_fallback(toml_path)
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
        want = list_name.strip()
        for lst in self._toml_data.get("List", []):
            if not isinstance(lst, dict):
                continue
            name = str(lst.get("Name", "")).strip().strip("'\"")
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

[[Constants]]
Name = "EXAMPLE_CONST"
Value = 0

[[Structs]]
Name = "structs.Example"
Format = "`s`{field|u8}"

[[FunctionAnchors]]
Name = "funcs.example.FuncName"
Address = 0x8000000
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

    def _get_function_anchor_for_addr(self, gba_addr: int) -> Optional[Dict[str, Any]]:
        """Return FunctionAnchor or NamedAnchor dict if gba_addr matches any anchor Address."""
        if not self._toml_data:
            return None
        for anchor in list(self._toml_data.get("FunctionAnchors", [])) + list(self._toml_data.get("NamedAnchors", [])):
            addr = anchor.get("Address")
            if addr is None:
                continue
            if isinstance(addr, int):
                anchor_addr = addr
            else:
                try:
                    anchor_addr = int(addr) if isinstance(addr, (int, float)) else int(str(addr), 0)
                except (ValueError, TypeError):
                    continue
            if anchor_addr < GBA_ROM_BASE:
                anchor_addr += GBA_ROM_BASE
            if (anchor_addr & 0x01) != (gba_addr & 0x01):
                anchor_addr &= ~1
                gba_check = gba_addr & ~1
            else:
                gba_check = gba_addr
            if anchor_addr == gba_check or anchor_addr == gba_addr:
                return anchor
        return None

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
        """NamedAnchors whose Format is a graphics palette/sprite spec (ucp4, lzs4xWxH, …)
        or a table ``[rowSpec]countRef`` of identical rows."""
        result: List[Dict[str, Any]] = []
        pcs_names = {a["name"] for a in self._get_pcs_table_anchors()}
        rom_len = len(self._data) if self._data else 0
        for anchor in self._toml_data.get("NamedAnchors", []):
            name = str(anchor.get("Name", "")).strip().strip("'\"")
            if not name or name in pcs_names:
                continue
            fmt = str(anchor.get("Format", "")).strip().strip("'\"")
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
        return result

    def find_graphics_anchor_by_name(self, anchor_name: str) -> Optional[Dict[str, Any]]:
        want = anchor_name.strip()
        for a in self.get_graphics_anchors():
            if a["name"] == want:
                return a
        return None

    def get_struct_anchors(self) -> List[Dict[str, Any]]:
        """Return NamedAnchors whose Format is a parseable struct (not pure PCS tables)."""
        result: List[Dict[str, Any]] = []
        pcs_names = {a["name"] for a in self._get_pcs_table_anchors()}
        for anchor in self._toml_data.get("NamedAnchors", []):
            name = str(anchor.get("Name", "")).strip().strip("'\"")
            if name in pcs_names:
                continue
            fmt = str(anchor.get("Format", "")).strip().strip("'\"")
            fields = _parse_struct_fields(fmt)
            if not fields:
                continue
            count_raw = _parse_struct_count(fmt)
            if count_raw is None:
                continue
            count = count_raw if isinstance(count_raw, int) else self._resolve_struct_count(count_raw)
            if count is None or count <= 0:
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
            struct_size = sum(f["size"] for f in fields)
            if struct_size <= 0:
                continue
            entry_label_pcs: Optional[Dict[str, Any]] = None
            if isinstance(count_raw, str):
                entry_label_pcs = _find_pcs_table_for_struct_suffix(
                    self._get_pcs_table_anchors(), count_raw
                )
            result.append({
                "name": name, "anchor": anchor, "fields": fields,
                "count": count, "struct_size": struct_size, "base_off": base_off,
                "entry_label_pcs": entry_label_pcs,
            })
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
                a_fmt = str(anchor.get("Format", "")).strip().strip("'\"")
                a_count = _parse_struct_count(a_fmt)
                if isinstance(a_count, int):
                    return a_count + offset
        return None

    def get_lists(self) -> Dict[str, Dict[int, str]]:
        """Return all [[List]] entries as {name: {index: label}}."""
        return _load_toml_lists(self._toml_data)

    def update_toml_list_string_at_index(self, list_name: str, flat_index: int, new_label: str) -> bool:
        """Update one string in ``[[List]]`` and rewrite the TOML file on disk."""
        if not _TOMLI_W_AVAILABLE:
            messagebox.showerror(
                "Struct",
                "Editing TOML requires the tomli-w package.\n"
                "Install with: pip install tomli-w",
            )
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
        want = list_name.strip()
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get("Name", "")).strip().strip("'\"")
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
            with open(self._toml_path, "wb") as f:
                tomli_w.dump(self._toml_data, f)
        except OSError as e:
            messagebox.showerror("Struct", f"Could not write TOML:\n{e}")
            return False
        except Exception as e:
            messagebox.showerror("Struct", f"TOML write failed:\n{e}")
            return False
        return True

    def get_list_entry_label(self, list_name: str, flat_index: int) -> Optional[str]:
        """Return the string at ``flat_index`` in ``[[List]]`` with this Name, or None.
        ``list_name`` may include a trailing ``+N`` / ``-N`` (struct-style); only the base name is used for [[List]].
        """
        base, _ = _split_enum_field_ref(list_name)
        want = base.strip()
        if not want:
            return None
        for row in self._toml_data.get("List", []) or []:
            if not isinstance(row, dict):
                continue
            name = str(row.get("Name", "")).strip().strip("'\"")
            if name != want:
                continue
            coords = _list_row_key_and_offset(row, flat_index)
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

    def write_bytes_at(self, offset: int, data: bytes) -> None:
        if not self._data or offset < 0:
            return
        for i, b in enumerate(data):
            if offset + i < len(self._data):
                self._data[offset + i] = b
        self._modified = True
        self._refresh_visible()

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
        self._text_pseudo_c.configure(state=tk.NORMAL)
        self._text_pseudo_c.delete("1.0", tk.END)
        self._text_pseudo_c.insert(tk.END, text)
        self._apply_syntax_highlighting(self._text_pseudo_c, "c")
        self._text_pseudo_c.configure(state=tk.DISABLED)

    def _angr_fallback_to_capstone(self, start: int, end: int, align: int, angr_error: Optional[str]) -> None:
        """When angr fails, show error + Capstone pseudo-C fallback."""
        if not self._pseudo_c_pane_visible:
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
                    anchor = self._get_function_anchor_for_addr(addr)
                    if anchor:
                        # Replace angr output with TOML-derived struct(s) + externs + signature
                        repl: List[str] = []
                        for struct_def in self._get_struct_defs_from_anchor(anchor, constants):
                            repl.append(struct_def)
                        if repl:
                            repl.append("")
                        externs = self._extract_extern_lines(dec.codegen.text)
                        if externs:
                            repl.extend(externs)
                            repl.append("")
                        sig = self._format_sig_from_anchor(anchor, constants)
                        repl.append(sig)
                        body = self._extract_angr_function_body(dec.codegen.text)
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
                        out_lines.append(dec.codegen.text.strip())
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
            return "\n".join(out_lines)
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
            hex_lines.append(f"{rs:08X}  {hx.ljust(3 * BYTES_PER_ROW - 1)}\n")
            ascii_lines.append(f"|{asc}|\n")
        self._text.insert("1.0", "".join(hex_lines))
        self._text_ascii.insert("1.0", "".join(ascii_lines))

        # Pointer tags (both widgets)
        self._text.tag_remove("pointer", "1.0", tk.END)
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
                        self._text.tag_add("pointer", f"{dr}.{10 + bc * 3}", f"{dr}.{12 + bc * 3}")
                        self._text_ascii.tag_add("pointer", f"{dr}.{1 + bc}", f"{dr}.{2 + bc}")
            off += 4

        self._update_cursor_display()

    # ── Coordinate helpers ───────────────────────────────────────────

    def _offset_to_index(self, offset: int) -> Optional[str]:
        if offset < 0 or offset >= len(self._data):
            return None
        fr = offset // BYTES_PER_ROW
        if fr < self._visible_row_start or fr >= self._visible_row_start + self._visible_row_count:
            return None
        dr = fr - self._visible_row_start + 1
        return f"{dr}.{10 + (offset % BYTES_PER_ROW) * 3}"

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
        if cn < 10:
            off = fr * BYTES_PER_ROW
        else:
            bc = (cn - 10) // 3
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

        self._refresh_asm_selection()

    # ── Mouse interaction ────────────────────────────────────────────

    def _on_click(self, event: tk.Event) -> Optional[str]:
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

        # Determine if click is on address column (col < 10) vs hex data
        try:
            _, cn = idx.split(".")
            on_addr_col = int(cn) < 10
        except (ValueError, TypeError):
            on_addr_col = False
        if not on_addr_col:
            # Hex data click: check 4-byte word for pointer to a PCS table start
            ptr_start = (off // 4) * 4
            target_fo = self._get_pointer_at_offset(ptr_start)
            if target_fo is not None:
                anchor_info = self._find_named_anchor_at_offset(target_fo, exact=True)
                if anchor_info:
                    self._select_named_anchor_extent(anchor_info)
                    if self._on_pointer_to_named_anchor_cb:
                        self.after(10, lambda ai=anchor_info: self._on_pointer_to_named_anchor_cb(ai))
                    return "break"

        # Check if current offset falls within a NamedAnchor PCS table
        anchor_info = self._find_named_anchor_at_offset(off)
        if anchor_info:
            self._select_named_anchor_extent(anchor_info)
            if self._on_pointer_to_named_anchor_cb:
                self.after(10, lambda ai=anchor_info: self._on_pointer_to_named_anchor_cb(ai))
            return "break"

        if not on_addr_col:
            ptr_start = (off // 4) * 4
            if self._follow_pointer_at(ptr_start):
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

    # ── Dialogs ──────────────────────────────────────────────────────

    def _on_goto_offset(self) -> None:
        if not self._data:
            return
        dialog = tk.Toplevel(self)
        dialog.title("Go to offset")
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()
        ttk.Label(dialog, text="Offset (hex):").grid(row=0, column=0, padx=5, pady=5)
        entry = ttk.Entry(dialog, width=12)
        entry.grid(row=0, column=1, padx=5, pady=5)
        entry.insert(0, f"{self._cursor_byte_offset:08X}")
        entry.select_range(0, tk.END)
        entry.focus_set()

        def do_goto() -> None:
            try:
                val = int(entry.get(), 16)
                if 0 <= val < len(self._data):
                    self._do_goto(val)
                dialog.destroy()
            except ValueError:
                pass

        ttk.Button(dialog, text="Go", command=do_goto).grid(row=1, column=0, columnspan=2, pady=5)
        entry.bind("<Return>", lambda e: do_goto())
        dialog.bind("<Escape>", lambda e: dialog.destroy())

    # ── Key handling ─────────────────────────────────────────────────

    def _select_all(self) -> Optional[str]:
        if self._data:
            self._selection_start = 0
            self._selection_end = len(self._data) - 1
            self._update_cursor_display()
        return "break"

    def _on_key(self, event: tk.Event) -> Optional[str]:
        if event.state & 0x4 and event.keysym.lower() == "a":
            self._toggle_asm_pane(event)
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
            b = self._data[self._cursor_byte_offset]
            if self._nibble_pos == 0:
                self._data[self._cursor_byte_offset] = (b & 0x0F) | (digit << 4)
                self._nibble_pos = 1
            else:
                self._data[self._cursor_byte_offset] = (b & 0xF0) | digit
                self._nibble_pos = 0
                self._cursor_byte_offset = min(self._cursor_byte_offset + 1, len(self._data) - 1)
            self._modified = True
            self._ldr_pc_targets_valid = False
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
        self._nibble_pos = 0
        return "break"

    # ── Public helpers ───────────────────────────────────────────────

    def tools_container(self) -> ttk.Frame:
        """Return the frame for embedding additional tools (right of hex/ASCII)."""
        return self._tools_frame
