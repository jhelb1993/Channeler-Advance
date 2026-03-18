"""
Shared hex editor for GBA ROM hacking.
Supports pointer detection (0x08/0x09), follow, replace/insert mode, delete.
ASCII/PCS (Pokemon GBA) encoding for the character pane.
"""

import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk, filedialog, messagebox
from typing import Optional, Dict

GBA_ROM_BASE = 0x08000000
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
        self._build_ui()

    # ── UI construction ──────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        outer = ttk.Frame(self)
        outer.grid(row=0, column=0, sticky="nsew")
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(1, weight=1)

        # Top row: mode | encoding switcher
        top_row = ttk.Frame(outer)
        top_row.grid(row=0, column=0, sticky="w", pady=(0, 1))
        self._mode_label = ttk.Label(top_row, text="REPLACE", font=("Consolas", 9, "bold"))
        self._mode_label.grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Label(top_row, text="Chars:", font=("Consolas", 9)).grid(row=0, column=1, sticky="w", padx=(0, 2))
        self._encoding_var = tk.StringVar(value=self._encoding.upper())
        self._encoding_combo = ttk.Combobox(
            top_row, textvariable=self._encoding_var, values=["ASCII", "PCS"], width=8, state="readonly"
        )
        self._encoding_combo.grid(row=0, column=2, sticky="w")
        self._encoding_combo.bind("<<ComboboxSelected>>", self._on_encoding_change)

        # Main content: hex (no trailing space) | ascii | scrollbar | tools area
        body = ttk.Frame(outer)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=0)
        body.columnconfigure(1, weight=0)
        body.columnconfigure(2, weight=0)
        body.columnconfigure(3, weight=1)
        body.rowconfigure(0, weight=1)

        hex_width = 10 + 3 * BYTES_PER_ROW - 1
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

        self._text.grid(row=0, column=0, sticky="nsew", padx=(0, 0))
        self._text_ascii.grid(row=0, column=1, sticky="ns", padx=(0, 0))
        self._scroll_y.grid(row=0, column=2, sticky="ns")
        self._tools_frame = ttk.Frame(body, width=1)
        self._tools_frame.grid(row=0, column=3, sticky="nsew", padx=(4, 0))

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
        self._text.bind("<Control-a>", lambda e: self._select_all())
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

    def _on_encoding_change(self, event: Optional[tk.Event] = None) -> None:
        sel = self._encoding_var.get().upper()
        if sel in ("ASCII", "PCS"):
            self._encoding = "pcs" if sel == "PCS" else "ascii"
            if self._data:
                self._refresh_visible()

    def _byte_to_char(self, b: int) -> str:
        if self._encoding == "pcs":
            return _PCS_BYTE_TO_CHAR.get(b, "·")
        return chr(b) if 32 <= b < 127 else "."

    def _on_ascii_key(self, event: tk.Event) -> Optional[str]:
        """Handle typing in character panel: update byte at cursor, refresh, advance."""
        if not self._data:
            return None
        idx = self._text_ascii.index("insert")
        off = self._ascii_index_to_offset(idx)
        if off is None:
            return None
        if event.keysym in ("BackSpace", "Delete"):
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

    def _prevent_unwanted(self, event: tk.Event) -> Optional[str]:
        if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End", "Prior", "Next"):
            return None
        if event.state & 0x4 and event.keysym.lower() in ("a", "c", "v", "x", "s"):
            return None
        if event.char and event.char in HEX_DIGITS:
            return "break"
        if event.keysym in ("Delete", "Insert", "BackSpace"):
            return "break"
        if event.char or event.keysym in ("Return", "Tab", "space"):
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
        self._cursor_byte_offset = 0
        self._selection_start = self._selection_end = None
        self._nibble_pos = 0
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW if self._data else 0
        self._visible_row_start = 0
        self._refresh_visible()
        self._update_scrollbar()
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
        self._file_path = path
        return self.save_file()

    def get_file_path(self) -> Optional[str]:
        return self._file_path

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
        if not self._data or self._total_rows == 0:
            return
        if self._syncing_scroll:
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
                amount *= max(3, self._visible_row_count // 10)
            self._visible_row_start = max(0, min(max_start, self._visible_row_start + amount))
        self._syncing_scroll = True
        try:
            self._refresh_visible()
            self._update_scrollbar()
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
        if ln < 1:
            return None
        fr = self._visible_row_start + (ln - 1)
        if cn < 10:
            return fr * BYTES_PER_ROW
        bc = (cn - 10) // 3
        if bc >= BYTES_PER_ROW:
            return fr * BYTES_PER_ROW + BYTES_PER_ROW - 1
        return fr * BYTES_PER_ROW + bc

    def _ascii_index_to_offset(self, index: str) -> Optional[int]:
        """Map ASCII widget index to byte offset. Format: |..16 chars..| per line."""
        try:
            line, col = index.split(".")
            ln = int(line)
            cn = int(col)
        except (ValueError, TypeError):
            return None
        if ln < 1:
            return None
        fr = self._visible_row_start + (ln - 1)
        if cn < 1:
            return fr * BYTES_PER_ROW
        if cn > BYTES_PER_ROW:
            return fr * BYTES_PER_ROW + BYTES_PER_ROW - 1
        return fr * BYTES_PER_ROW + (cn - 1)

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
            for off in range(s, e + 1):
                ix = self._offset_to_index(off)
                if ix:
                    self._text.tag_add("sel_hex", ix, f"{ix}+2c")
                aix = self._offset_to_ascii_index(off)
                if aix:
                    self._text_ascii.tag_add("sel_ascii", aix, f"{aix}+1c")

    # ── Mouse interaction ────────────────────────────────────────────

    def _on_click(self, event: tk.Event) -> Optional[str]:
        idx = self._text.index(f"@{event.x},{event.y}")
        off = self._index_to_offset(idx)
        if off is not None:
            self._cursor_byte_offset = off
            self._selection_start = None
            self._selection_end = None
            self._nibble_pos = 0
            self._update_cursor_display()
        return "break"

    def _on_drag(self, event: tk.Event) -> Optional[str]:
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
            self._selection_start = None
            self._selection_end = None
            self._nibble_pos = 0
            self._update_cursor_display()
        return "break"

    def _on_ascii_drag(self, event: tk.Event) -> Optional[str]:
        idx = self._text_ascii.index(f"@{event.x},{event.y}")
        off = self._ascii_index_to_offset(idx)
        if off is not None:
            if self._selection_start is None:
                self._selection_start = self._cursor_byte_offset
            self._selection_end = off
            self._update_cursor_display()
        return "break"

    def _on_double_click(self, event: tk.Event) -> None:
        idx = self._text.index(f"@{event.x},{event.y}")
        off = self._index_to_offset(idx)
        if off is not None:
            ptr_start = (off // 4) * 4
            if self._follow_pointer_at(ptr_start):
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
        menu.add_command(label="Go to offset...", command=self._on_goto_offset)
        menu.tk_popup(event.x_root, event.y_root)

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
                    self._cursor_byte_offset = val
                    self._selection_start = self._selection_end = None
                    self._ensure_cursor_visible()
                    self._refresh_visible()
                    self._update_scrollbar()
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
        if not self._data:
            return None
        if event.keysym == "Delete":
            return None
        if event.char and event.char in HEX_DIGITS:
            digit = int(event.char, 16)
            if self._insert_mode and self._nibble_pos == 0:
                self._data.insert(self._cursor_byte_offset, 0)
                self._modified = True
            b = self._data[self._cursor_byte_offset]
            if self._nibble_pos == 0:
                self._data[self._cursor_byte_offset] = (b & 0x0F) | (digit << 4)
                self._nibble_pos = 1
            else:
                self._data[self._cursor_byte_offset] = (b & 0xF0) | digit
                self._nibble_pos = 0
                self._cursor_byte_offset = min(self._cursor_byte_offset + 1, len(self._data) - 1)
            self._modified = True
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
        self._nibble_pos = 0
        self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
        self._ensure_cursor_visible()
        self._refresh_visible()
        self._update_scrollbar()
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
            self._nibble_pos = 0
            self._total_rows = (len(self._data) + BYTES_PER_ROW - 1) // BYTES_PER_ROW
            self._ensure_cursor_visible()
            self._refresh_visible()
            self._update_scrollbar()
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
