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

_TOML_AVAILABLE = False
try:
    import tomli
    _TOML_AVAILABLE = True
except ImportError:
    pass

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

GBA_ROM_BASE = 0x08000000
GBA_ROM_MAX = 0x09FFFFFF  # addresses > this are not ROM code pointers; treat as code, not .word
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
        self._ldr_pc_targets: Optional[Set[int]] = None
        self._ldr_pc_targets_valid = False
        self._toml_path: Optional[str] = None
        self._toml_data: Dict[str, Any] = {}
        self._build_ui()

    # ── UI construction ──────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        outer = ttk.Frame(self)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        # Top row: mode | ASM mode | Goto | Chars
        top_row = ttk.Frame(outer)
        top_row.grid(row=0, column=0, sticky="w", pady=(0, 1))
        self._mode_label = ttk.Label(top_row, text="REPLACE", font=("Consolas", 9, "bold"))
        self._mode_label.grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Label(top_row, text="ASM mode:", font=("Consolas", 9)).grid(row=0, column=1, sticky="w", padx=(8, 2))
        self._asm_mode_var = tk.StringVar(value="Thumb")
        self._asm_mode_combo = ttk.Combobox(
            top_row, textvariable=self._asm_mode_var, values=["Thumb", "ARM"], width=6, state="readonly", font=("Consolas", 9)
        )
        self._asm_mode_combo.grid(row=0, column=2, sticky="w", padx=(0, 2))
        self._asm_mode_combo.current(0)
        self._asm_mode_combo.bind("<<ComboboxSelected>>", self._on_asm_mode_change)
        ttk.Label(top_row, text="Goto:", font=("Consolas", 9)).grid(row=0, column=3, sticky="w", padx=(8, 2))
        self._goto_var = tk.StringVar(value="")
        self._goto_entry = ttk.Entry(top_row, textvariable=self._goto_var, width=10, font=("Consolas", 9))
        self._goto_entry.grid(row=0, column=4, sticky="w", padx=(0, 8))
        self._goto_entry.bind("<KeyRelease>", self._on_goto_entry_change)
        self._goto_entry.bind("<FocusIn>", self._on_goto_focus_in)
        ttk.Label(top_row, text="Chars:", font=("Consolas", 9)).grid(row=0, column=5, sticky="w", padx=(8, 2))
        self._encoding_var = tk.StringVar(value=self._encoding.upper())
        self._encoding_combo = ttk.Combobox(
            top_row, textvariable=self._encoding_var, values=["ASCII", "PCS"], width=8, state="readonly"
        )
        self._encoding_combo.grid(row=0, column=6, sticky="w")
        self._encoding_combo.bind("<<ComboboxSelected>>", self._on_encoding_change)
        self._selection_label = ttk.Label(top_row, text="", font=("Consolas", 9))
        self._selection_label.grid(row=0, column=7, sticky="w", padx=(8, 0))

        # Main content: hex | ascii | asm (toggleable) | scrollbar | tools area
        body = ttk.Frame(outer)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=0)
        body.columnconfigure(2, weight=0)
        body.columnconfigure(3, weight=0)
        body.columnconfigure(4, weight=0)
        body.columnconfigure(5, weight=1)
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

        # Pseudo-C pane: to the right of ASM, hidden by default, toggleable with Ctrl+G
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

        self._tools_frame = ttk.Frame(body, width=1)
        self._tools_frame.grid(row=1, column=5, sticky="nsew", padx=(4, 0))

        if not self._asm_pane_visible:
            self._asm_frame.grid_remove()
        if not self._pseudo_c_pane_visible:
            self._pseudo_c_frame.grid_remove()

        self._text.tag_configure("pointer", foreground="red")
        self._text.tag_configure("sel_hex", background="#add8e6", foreground="black")
        self._text.tag_configure("cursor_byte", background="#e0e0e0")
        self._text_ascii.tag_configure("pointer", foreground="red")
        self._text_ascii.tag_configure("sel_ascii", background="#add8e6", foreground="black")

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
            w.bind("<Control-g>", self._toggle_pseudo_c_pane)
            w.bind("<Control-G>", self._toggle_pseudo_c_pane)

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
        self.winfo_toplevel().bind("<Control-g>", self._toggle_pseudo_c_pane, add=True)
        self.winfo_toplevel().bind("<Control-G>", self._toggle_pseudo_c_pane, add=True)
        for w in (
            self._text, self._text_ascii, self._goto_entry, self._encoding_combo,
            self._asm_mode_combo, self._asm_frame, self._text_asm,
            self._pseudo_c_frame, self._text_pseudo_c, outer,
        ):
            w.bind("<Control-d>", self._toggle_hackmew_mode)
            w.bind("<Control-D>", self._toggle_hackmew_mode)
            w.bind("<Control-e>", self._compile_hackmew_asm)
            w.bind("<Control-E>", self._compile_hackmew_asm)
        self.winfo_toplevel().bind("<Control-d>", self._toggle_hackmew_mode, add=True)
        self.winfo_toplevel().bind("<Control-D>", self._toggle_hackmew_mode, add=True)
        self.winfo_toplevel().bind("<Control-e>", self._compile_hackmew_asm, add=True)
        self.winfo_toplevel().bind("<Control-E>", self._compile_hackmew_asm, add=True)

        self._text.bind("<Control-Shift-A>", lambda e: self._select_all())
        self._text_ascii.bind("<Control-Shift-A>", lambda e: self._select_all())
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
        """Focus the Goto (offset) entry box."""
        self._goto_entry.focus_set()
        self._goto_entry.select_range(0, tk.END)
        return "break"

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
        """Toggle between standard ASM display and editable HackMew ASM. Bound to Ctrl+D."""
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
        """Convert ldr rX, [pc, <label>] to ldr rX, [pc, #0xYY] by resolving label positions within the ASM."""
        lines = asm_text.splitlines()
        base = self._hackmew_asm_start
        align = 2 if self._asm_mode == "thumb" else 4

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
        """Compile edited HackMew ASM via deps/thumb.bat and insert .bin into ROM. Bound to Ctrl+E."""
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
            with open(asm_path, "w", encoding="utf-8") as f:
                f.write(asm_text + "\n")

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
        """Toggle Pseudo-C pane visibility. Bound to Ctrl+G."""
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
        if event.state & 0x4 and event.keysym.lower() in ("a", "b", "c", "v", "x", "s"):
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

    def _load_toml_for_rom(self) -> None:
        """Load TOML for current ROM. Create default if missing."""
        if not self._file_path or not _TOML_AVAILABLE:
            self._toml_path = None
            self._toml_data = {}
            return
        toml_path = self._get_toml_path(self._file_path)
        if os.path.isfile(toml_path):
            try:
                with open(toml_path, "rb") as f:
                    self._toml_data = tomli.load(f)
                self._toml_path = toml_path
            except Exception:
                self._toml_data = {}
                self._toml_path = toml_path
        else:
            self._create_default_toml(toml_path)

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
        """Return file offset for FunctionAnchor with given Name, or None if not found."""
        if not self._toml_data or not name:
            return None
        name_lo = name.strip().lower()
        for anchor in self._toml_data.get("FunctionAnchors", []):
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
        """Return FunctionAnchor dict if gba_addr matches any anchor Address."""
        if not self._toml_data:
            return None
        for anchor in self._toml_data.get("FunctionAnchors", []):
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
        align = 2 if self._asm_mode == "thumb" else 4
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
        self._text_asm.insert("1.0", "".join(lines) if lines else "(No instructions)")
        self._text_asm.configure(state=tk.DISABLED)
        if self._pseudo_c_pane_visible:
            self._refresh_pseudo_c_selection()

    def _refresh_asm_hackmew(self) -> None:
        """Show editable HackMew-style ASM in the ASM pane. Records region for Ctrl+E compile."""
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
        align = 2 if self._asm_mode == "thumb" else 4
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
        align = 2 if self._asm_mode == "thumb" else 4
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
            align = 2 if self._asm_mode == "thumb" else 4
            self.after(0, lambda: self._angr_fallback_to_capstone(start, end, align, result))

    def _angr_decompile_done(self, text: str) -> None:
        """Called on main thread after angr decompilation completes."""
        if not self._pseudo_c_pane_visible:
            return
        self._text_pseudo_c.configure(state=tk.NORMAL)
        self._text_pseudo_c.delete("1.0", tk.END)
        self._text_pseudo_c.insert(tk.END, text)
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
        self._text_pseudo_c.insert(tk.END, "".join(lines) if lines else "(No instructions)")
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
        """First scan: collect all file offsets that are jumped to (branch targets)."""
        targets: Set[int] = set()
        data_len = len(self._data)
        for file_off, insn in insn_map.items():
            if file_off < start or file_off >= end:
                continue
            t = self._get_branch_target_from_insn(insn, mode)
            if t is not None and 0 <= t < data_len:
                targets.add(t)
        for file_off in ldr_targets:
            if file_off < start or file_off >= end or file_off + 4 > data_len:
                continue
            val = (
                self._data[file_off]
                | (self._data[file_off + 1] << 8)
                | (self._data[file_off + 2] << 16)
                | (self._data[file_off + 3] << 24)
            )
            if (val >> 24) in (0x08, 0x09):
                fo = val - GBA_ROM_BASE
                if 0 <= fo < data_len:
                    targets.add(fo)
        return targets

    def _build_asm_export_lines_with_labels(self, hackmew: bool = False) -> List[str]:
        """Build ASM export lines with labels at branch targets and label refs instead of raw offsets."""
        if not self._data or not _CAPSTONE_AVAILABLE:
            return []
        mode = CS_MODE_THUMB if self._asm_mode == "thumb" else CS_MODE_ARM
        align = 2 if self._asm_mode == "thumb" else 4
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

        def replace_addrs_with_labels(text: str) -> str:
            def repl(m: re.Match) -> str:
                addr = int(m.group(1), 16)
                fo = addr - GBA_ROM_BASE
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
                line = replace_addrs_with_labels(line)
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
                line = replace_addrs_with_labels(line)
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
        align = 2 if self._asm_mode == "thumb" else 4
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

    def _on_double_click(self, event: tk.Event) -> None:
        idx = self._text.index(f"@{event.x},{event.y}")
        off = self._index_to_offset(idx)
        if off is not None:
            ptr_start = (off // 4) * 4
            if self._follow_pointer_at(ptr_start):
                return
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
                return
        self._on_click(event)

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
            self._ensure_cursor_visible()
            self._refresh_visible()
            self._update_scrollbar()
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
