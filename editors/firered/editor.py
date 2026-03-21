"""
Pokémon FireRed ROM Editor
Uses the pokefirered decompilation (in ./pokefirered) for parsing C code.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import List, Optional

from editors.common.hex_editor import (
    HexEditorFrame,
    PcsStringTableFrame,
    StructEditorFrame,
    GraphicsPreviewFrame,
)

POKEFIRERED_PATH = os.path.join(os.path.dirname(__file__), "pokefirered")


class FireRedEditor:

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Channeler Advance - Pokémon FireRed Editor")
        self.root.geometry("900x650")
        self.root.minsize(720, 520)

        self._hex_editor: Optional[HexEditorFrame] = None
        self._main_paned: Optional[ttk.PanedWindow] = None
        self._tools_frame: Optional[ttk.Frame] = None
        self._tools_visible = False
        self._slot_active: List[bool] = [False, False, False]
        self._build_ui()

    def _focus_in_text_entry(self) -> bool:
        w = self.root.focus_get()
        if w is None:
            return False
        try:
            cls = w.winfo_class()
        except tk.TclError:
            return False
        return cls in ("TEntry", "Entry", "TSpinbox", "Spinbox", "TCombobox")

    def _build_ui(self) -> None:
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open ROM...", command=self._on_open_rom)
        file_menu.add_command(label="Load structure TOML...", command=self._on_load_structure_toml, state=tk.DISABLED)
        file_menu.add_command(
            label="Use ROM-paired TOML (clear override)",
            command=self._on_clear_toml_override,
            state=tk.DISABLED,
        )
        file_menu.add_command(label="Save", command=self._on_save, state=tk.DISABLED)
        file_menu.add_command(label="Save As...", command=self._on_save_as, state=tk.DISABLED)
        file_menu.add_separator()
        file_menu.add_command(label="Import Sprite...", command=self._on_file_import_sprite, state=tk.DISABLED)
        file_menu.add_command(
            label="Import Tilemap/Tileset...",
            command=self._on_file_import_tilemap,
            state=tk.DISABLED,
        )
        file_menu.add_command(label="Import Palette...", command=self._on_file_import_palette, state=tk.DISABLED)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_exit)
        self._file_menu = file_menu

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._on_about)

        self._main_paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self._main_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        self._hex_editor = HexEditorFrame(self._main_paned, default_encoding="pcs")
        self._main_paned.add(self._hex_editor)

        # Tools pane — each slot is a scrollable frame capped at ~1/3 screen width
        self._tools_frame = ttk.LabelFrame(self._main_paned, text=" Tools ", padding=2)
        self._tools_frame.rowconfigure(0, weight=1)

        # Slot 0: PCS string table
        self._pcs_canvas, self._pcs_inner = self._make_scroll_slot()
        self._pcs_table = PcsStringTableFrame(self._pcs_inner, self._hex_editor)
        self._pcs_table.pack(fill=tk.BOTH, expand=True)

        # Slot 1: Struct editor
        self._struct_canvas, self._struct_inner = self._make_scroll_slot()
        self._struct_editor = StructEditorFrame(self._struct_inner, self._hex_editor)
        self._struct_editor.pack(fill=tk.BOTH, expand=True)

        # Slot 2: graphics (built-in pret-compatible decode + Pillow)
        self._tool3_canvas, self._tool3_inner = self._make_scroll_slot()
        self._graphics_preview = GraphicsPreviewFrame(self._tool3_inner, self._hex_editor)
        self._graphics_preview.pack(fill=tk.BOTH, expand=True)

        self._tools_visible = False

        # Ctrl+T: show/hide pane (both PCS + Struct dropdowns, empty until chosen)
        self.root.bind_all("<Control-KeyPress-t>", self._on_ctrl_t)
        self.root.bind_all("<Control-KeyPress-T>", self._on_ctrl_t)

        # Ctrl+Shift+1/2/3: toggle individual slots
        self.root.bind_all("<Control-Shift-Key-exclam>", lambda e: self._hotkey_slot(0))
        self.root.bind_all("<Control-Shift-Key-at>", lambda e: self._hotkey_slot(1))
        self.root.bind_all("<Control-Shift-Key-numbersign>", lambda e: self._hotkey_slot(2))
        self.root.bind_all("<Control-Shift-Key-1>", lambda e: self._hotkey_slot(0))
        self.root.bind_all("<Control-Shift-Key-2>", lambda e: self._hotkey_slot(1))
        self.root.bind_all("<Control-Shift-Key-3>", lambda e: self._hotkey_slot(2))

        self._hex_editor.set_on_pointer_to_named_anchor(self._on_pointer_to_named_anchor)
        self._update_file_menu_state()
        self.root.bind("<Control-s>", lambda e: self._on_save())

    # ── Scrollable slot container ─────────────────────────────────────

    def _make_scroll_slot(self):
        """Create a Canvas+Scrollbar pair that caps at ~1/3 screen width and scrolls horizontally."""
        third = max(200, self.root.winfo_screenwidth() // 3)
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

        hsb = ttk.Scrollbar(outer, orient=tk.HORIZONTAL, command=canvas.xview)
        canvas.configure(xscrollcommand=hsb.set)

        inner = ttk.Frame(canvas)
        wid = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _sync_inner(_e):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _sync_canvas(e):
            # Size inner to at least canvas width but allow wider content so widgets don't paint into the next tool slot.
            try:
                req_w = inner.winfo_reqwidth()
                req_h = inner.winfo_reqheight()
            except tk.TclError:
                req_w, req_h = 0, 0
            w = max(e.width, req_w)
            h = max(e.height, req_h)
            canvas.itemconfigure(wid, width=w, height=h)
            canvas.configure(scrollregion=canvas.bbox("all"))

        inner.bind("<Configure>", _sync_inner)
        canvas.bind("<Configure>", _sync_canvas)

        canvas.grid(row=0, column=0, sticky="nsew")
        hsb.grid(row=1, column=0, sticky="ew")

        outer._canvas = canvas  # stash reference for resizing
        return outer, inner

    # ── Slot layout ───────────────────────────────────────────────────

    def _slot_frames(self) -> List[ttk.Frame]:
        return [self._pcs_canvas, self._struct_canvas, self._tool3_canvas]

    def _layout_tool_slots(self) -> None:
        """Grid only active slots, packed left, each ≈1/3 screen width."""
        frames = self._slot_frames()
        for fr in frames:
            fr.grid_remove()

        active = [(i, frames[i]) for i in range(3) if self._slot_active[i]]
        third = max(200, self.root.winfo_screenwidth() // 3)

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

    # ── Keyboard handling ─────────────────────────────────────────────

    def _on_ctrl_t(self, event=None) -> Optional[str]:
        # Always allow hiding the tools pane (focus is often in a combobox / search / spinbox).
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
            self._pcs_table.refresh_anchors()
            self._struct_editor.refresh_anchors()
            self._graphics_preview.refresh_anchors()
            self._layout_tool_slots()
        return "break"

    def _hotkey_slot(self, index: int) -> Optional[str]:
        # Still run when turning off the last active tool slot (closes pane) while focus is in search/combo.
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
            self._pcs_table.refresh_anchors()
            self._struct_editor.refresh_anchors()
            self._graphics_preview.refresh_anchors()

        self._layout_tool_slots()
        return "break"

    # ── Pointer/anchor callbacks ──────────────────────────────────────

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
            self._graphics_preview.refresh_anchors()
            self._graphics_preview.show_anchor(name)
            self.root.after(50, lambda: self._graphics_preview._combo.focus_set())
        elif t == "struct":
            self._struct_editor.refresh_anchors()
            self._struct_editor.show_struct(name)
            self.root.after(50, lambda: self._struct_editor._tree.focus_set())
        else:
            self._pcs_table.refresh_anchors()
            self._pcs_table.show_table(name)
            self.root.after(50, lambda: self._pcs_table._tree.focus_set())

    # ── File menu ─────────────────────────────────────────────────────

    def _update_file_menu_state(self) -> None:
        has_file = self._hex_editor and self._hex_editor.has_data()
        state = tk.NORMAL if has_file else tk.DISABLED
        self._file_menu.entryconfig("Save", state=state)
        self._file_menu.entryconfig("Save As...", state=state)
        self._file_menu.entryconfig("Load structure TOML...", state=state)
        ov = (
            has_file
            and self._hex_editor.has_toml_manual_override()
        )
        self._file_menu.entryconfig(
            "Use ROM-paired TOML (clear override)",
            state=tk.NORMAL if ov else tk.DISABLED,
        )
        for _imp in ("Import Sprite...", "Import Tilemap/Tileset...", "Import Palette..."):
            self._file_menu.entryconfig(_imp, state=state)
        if has_file:
            self._pcs_table.refresh_anchors()
            self._struct_editor.refresh_anchors()
            self._graphics_preview.refresh_anchors()

    def _on_load_structure_toml(self) -> None:
        if not self._hex_editor or not self._hex_editor.has_data():
            return
        path = filedialog.askopenfilename(
            title="Load structure TOML",
            filetypes=[("TOML", "*.toml"), ("All files", "*.*")],
        )
        if path and self._hex_editor.load_toml_manual(path):
            self._pcs_table.refresh_anchors()
            self._struct_editor.refresh_anchors()
            self._graphics_preview.refresh_anchors()
            self._update_file_menu_state()
            messagebox.showinfo("TOML", f"Using structure file:\n{path}")

    def _on_clear_toml_override(self) -> None:
        if not self._hex_editor or not self._hex_editor.has_toml_manual_override():
            return
        self._hex_editor.clear_toml_manual_override()
        self._pcs_table.refresh_anchors()
        self._struct_editor.refresh_anchors()
        self._graphics_preview.refresh_anchors()
        self._update_file_menu_state()
        paired = self._hex_editor.get_toml_path() or "(none)"
        messagebox.showinfo("TOML", f"Reloaded ROM-paired structure file:\n{paired}")

    def _on_file_import_sprite(self) -> None:
        if self._hex_editor:
            self._hex_editor.file_import_sprite_static()

    def _on_file_import_tilemap(self) -> None:
        if self._hex_editor:
            self._hex_editor.file_import_tilemap_tileset_static()

    def _on_file_import_palette(self) -> None:
        if self._hex_editor:
            self._hex_editor.file_import_palette_static()

    def _on_open_rom(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Pokémon FireRed ROM",
            filetypes=[("GBA ROM", "*.gba"), ("All files", "*.*")],
        )
        if path and self._hex_editor.load_file(path):
            self.root.title(f"Channeler Advance - Pokémon FireRed — {path}")
            self._update_file_menu_state()
            self._pcs_table.refresh_anchors()
            self._struct_editor.refresh_anchors()
            self._graphics_preview.refresh_anchors()

    def _on_save(self) -> None:
        if self._hex_editor and self._hex_editor.save_file():
            self._update_file_menu_state()

    def _on_save_as(self) -> None:
        if self._hex_editor and self._hex_editor.save_file_as():
            self.root.title(f"Channeler Advance - Pokémon FireRed — {self._hex_editor.get_file_path()}")

    def _on_exit(self) -> None:
        if self._hex_editor and self._hex_editor.is_modified():
            if messagebox.askyesno("Unsaved Changes", "Save changes before closing?"):
                self._hex_editor.save_file()
        self.root.quit()

    def _on_about(self) -> None:
        messagebox.showinfo(
            "About",
            "Channeler Advance - Pokémon FireRed Editor\n\n"
            "Uses pret/pokefirered for C code reference.\n\n"
            "Ctrl+T — show/hide tools pane\n"
            "Ctrl+Shift+1/2/3 — toggle Table / Struct / Graphics slot\n"
            "Pseudo-C: Ctrl+D — pane; Ctrl+Shift+4 — C edit mode; Ctrl+Shift+5 — compile C inject\n"
            "Graphics: built-in decode (pret gfx.c–compatible); Pillow required for PNG preview\n"
            "Ctrl+M — Anchors browser: double-click a table/struct leaf to open it in Tools\n"
            "Goto box: NamedAnchor name, file offset, or 0x08… address opens the matching tool when valid",
        )
