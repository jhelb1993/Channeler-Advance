"""
Pokémon FireRed ROM Editor
Uses the pokefirered decompilation (in ./pokefirered) for parsing C code.
"""

import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from typing import Optional

from editors.common.hex_editor import HexEditorFrame, RomToolsShell

POKEFIRERED_PATH = os.path.join(os.path.dirname(__file__), "pokefirered")


class FireRedEditor:

    def __init__(self, root: tk.Tk, path: str) -> None:
        self.path = path
        self.root = root
        self.root.title("Channeler Advance - Pokémon FireRed Editor")
        self.root.geometry("900x650")
        self.root.minsize(720, 520)

        self._hex_editor: Optional[HexEditorFrame] = None
        self._main_paned: Optional[ttk.PanedWindow] = None
        self._tools_shell: Optional[RomToolsShell] = None
        self._build_ui()

    def _build_ui(self) -> None:
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Load structure TOML...", command=self._on_load_structure_toml, state=tk.DISABLED)
        file_menu.add_command(
            label="Use ROM-paired TOML (clear override)",
            command=self._on_clear_toml_override,
            state=tk.DISABLED,
        )
        file_menu.add_command(label="Save", command=self._on_save, state=tk.DISABLED)
        file_menu.add_command(label="Save As...", command=self._on_save_as, state=tk.DISABLED)
        file_menu.add_command(label="Edit Matched Words...", command=self._on_edit_matched_words, state=tk.DISABLED)
        file_menu.add_separator()
        file_menu.add_command(label="Import Sprite...", command=self._on_file_import_sprite, state=tk.DISABLED)
        file_menu.add_command(
            label="Import Tilemap/Tileset...",
            command=self._on_file_import_tilemap,
            state=tk.DISABLED,
        )
        file_menu.add_command(label="Import Palette...", command=self._on_file_import_palette, state=tk.DISABLED)
        file_menu.add_command(
            label="Import YDK deck...",
            command=self._on_file_import_ydk,
            state=tk.DISABLED,
        )
        file_menu.add_command(
            label="Import banlist (.conf / .lflist)...",
            command=self._on_file_import_banlist,
            state=tk.DISABLED,
        )
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

        self._tools_shell = RomToolsShell(self.root, self._main_paned, self._hex_editor)
        self._hex_editor.set_struct_editor_ref(self._tools_shell.struct_editor)
        self._hex_editor.set_file_menu_refresh_callback(self._refresh_banlist_import_menu_state)
        
        self._hex_editor.load_file(self.path)

        def _on_structure_toml_refreshed() -> None:
            if self._tools_shell:
                self._tools_shell.refresh_anchors()
            self._update_file_menu_state()

        self._hex_editor.set_anchor_refresh_callback(_on_structure_toml_refreshed)

        self._update_file_menu_state()
        self.root.bind("<Control-s>", lambda e: self._on_save())

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
        for _imp in (
            "Import Sprite...",
            "Import Tilemap/Tileset...",
            "Import Palette...",
            "Import YDK deck...",
        ):
            self._file_menu.entryconfig(_imp, state=state)
        self._file_menu.entryconfig("Edit Matched Words...", state=state)
        self._refresh_banlist_import_menu_state()
        if has_file and self._tools_shell:
            self._tools_shell.refresh_anchors()

    def _refresh_banlist_import_menu_state(self) -> None:
        st = tk.DISABLED
        if self._hex_editor and self._hex_editor.has_data() and self._hex_editor.selected_struct_supports_ban_import():
            st = tk.NORMAL
        self._file_menu.entryconfig("Import banlist (.conf / .lflist)...", state=st)

    def _on_load_structure_toml(self) -> None:
        if not self._hex_editor or not self._hex_editor.has_data():
            return
        path = filedialog.askopenfilename(
            title="Load structure TOML",
            filetypes=[("TOML", "*.toml"), ("All files", "*.*")],
        )
        if path and self._hex_editor.load_toml_manual(path):
            if self._tools_shell:
                self._tools_shell.refresh_anchors()
            self._update_file_menu_state()
            messagebox.showinfo("TOML", f"Using structure file:\n{path}")

    def _on_clear_toml_override(self) -> None:
        if not self._hex_editor or not self._hex_editor.has_toml_manual_override():
            return
        self._hex_editor.clear_toml_manual_override()
        if self._tools_shell:
            self._tools_shell.refresh_anchors()
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

    def _on_file_import_ydk(self) -> None:
        if self._hex_editor:
            self._hex_editor.file_import_ydk_deck()

    def _on_file_import_banlist(self) -> None:
        if self._hex_editor:
            self._hex_editor.file_import_banlist_conf()

    def _on_open_rom(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Pokémon FireRed ROM",
            filetypes=[("GBA ROM", "*.gba"), ("All files", "*.*")],
        )
        if path and self._hex_editor.load_file(path):
            self.root.title(f"Channeler Advance - Pokémon FireRed — {path}")
            self._update_file_menu_state()

    def _on_save(self) -> None:
        if self._hex_editor and self._hex_editor.save_file():
            self._update_file_menu_state()

    def _on_save_as(self) -> None:
        if self._hex_editor and self._hex_editor.save_file_as():
            self.root.title(f"Channeler Advance - Pokémon FireRed — {self._hex_editor.get_file_path()}")

    def _on_edit_matched_words(self) -> None:
        if self._hex_editor:
            self._hex_editor.open_matched_words_editor()

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
            "Pseudo-C: Ctrl+D — pane; Ctrl+Shift+4 — C edit + hooks/repoints; Ctrl+Shift+5 — compile; Ctrl+Shift+6 — apply ROM patches\n"
            "Graphics: built-in decode (pret gfx.c–compatible); Pillow required for PNG preview\n"
            "Ctrl+M — Anchors browser: double-click a table/struct leaf to open it in Tools\n"
            "Goto box: NamedAnchor name, file offset, or 0x08... address opens the matching tool when valid",
        )
