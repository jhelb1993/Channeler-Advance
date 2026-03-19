"""
Pokémon FireRed ROM Editor
Uses the pokefirered decompilation (in ./pokefirered) for parsing C code.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional

from editors.common.hex_editor import HexEditorFrame, PcsStringTableFrame

# Path to pokefirered submodule for C parsing
POKEFIRERED_PATH = os.path.join(os.path.dirname(__file__), "pokefirered")


class FireRedEditor:
    """Main editor window for Pokémon FireRed hacking."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Channeler Advance - Pokémon FireRed Editor")
        self.root.geometry("900x650")
        self.root.minsize(720, 520)

        self._hex_editor: Optional[HexEditorFrame] = None
        self._main_paned: Optional[ttk.PanedWindow] = None
        self._tools_frame: Optional[ttk.Frame] = None
        self._tools_visible = False
        self._build_ui()

    def _build_ui(self) -> None:
        """Build the editor interface."""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open ROM...", command=self._on_open_rom)
        file_menu.add_command(label="Save", command=self._on_save, state=tk.DISABLED)
        file_menu.add_command(label="Save As...", command=self._on_save_as, state=tk.DISABLED)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._on_exit)
        self._file_menu = file_menu

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._on_about)

        # Main content: paned window with hex editor and Tools pane
        self._main_paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self._main_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Top: hex editor (takes most space), default to PCS for Pokemon GBA text
        self._hex_editor = HexEditorFrame(self._main_paned, default_encoding="pcs")
        self._main_paned.add(self._hex_editor)

        # Bottom: Tools pane (toggleable, room for 3 tools side-by-side)
        self._tools_frame = ttk.LabelFrame(self._main_paned, text=" Tools ", padding=2)
        self._tools_frame.columnconfigure(0, weight=1)
        self._tools_frame.columnconfigure(1, weight=1)
        self._tools_frame.columnconfigure(2, weight=1)
        self._tools_frame.rowconfigure(0, weight=1)
        # Tool 1: PCS String Table (compact, left-aligned)
        self._pcs_tool = ttk.Frame(self._tools_frame)
        self._pcs_tool.grid(row=0, column=0, sticky="nsew", padx=(0, 2))
        self._pcs_tool.columnconfigure(0, weight=1)
        self._pcs_tool.rowconfigure(0, weight=1)
        self._pcs_table = PcsStringTableFrame(self._pcs_tool, self._hex_editor)
        self._pcs_table.grid(row=0, column=0, sticky="nsew")
        # Tool 2 & 3: placeholders for future tools
        self._tool2 = ttk.Frame(self._tools_frame)
        self._tool2.grid(row=0, column=1, sticky="nsew", padx=2)
        self._tool3 = ttk.Frame(self._tools_frame)
        self._tool3.grid(row=0, column=2, sticky="nsew", padx=(2, 0))
        self._tools_visible = False  # Start hidden, no tool selected by default

        # Ctrl+T toggle Tools pane
        self.root.bind("<Control-t>", self._toggle_tools)
        self.root.bind("<Control-T>", self._toggle_tools)

        # Pointer->NamedAnchor: when double-clicking pointer to PCS table, show it
        self._hex_editor.set_on_pointer_to_named_anchor(self._on_pointer_to_pcs_anchor)

        self._update_file_menu_state()
        self.root.bind("<Control-s>", lambda e: self._on_save())

    def _toggle_tools(self, event: Optional[tk.Event] = None) -> Optional[str]:
        """Toggle Tools pane visibility. Bound to Ctrl+T."""
        self._tools_visible = not self._tools_visible
        if self._tools_visible:
            self._main_paned.add(self._tools_frame)
        else:
            self._main_paned.forget(self._tools_frame)
        return "break"

    def _on_pointer_to_pcs_anchor(self, anchor_info: dict) -> None:
        """Called when user double-clicks a pointer/offset for a NamedAnchor PCS table."""
        if not self._tools_visible:
            self._tools_visible = True
            self._main_paned.add(self._tools_frame)
        self._pcs_table.refresh_anchors()
        name = anchor_info.get("name", "")
        self._pcs_table.show_table(name)
        self.root.after(50, lambda: self._pcs_table._tree.focus_set())

    def _update_file_menu_state(self) -> None:
        has_file = self._hex_editor and self._hex_editor.has_data()
        state = tk.NORMAL if has_file else tk.DISABLED
        self._file_menu.entryconfig("Save", state=state)
        self._file_menu.entryconfig("Save As...", state=state)
        if has_file:
            self._pcs_table.refresh_anchors()

    def _on_open_rom(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Pokémon FireRed ROM",
            filetypes=[
                ("GBA ROM", "*.gba"),
                ("All files", "*.*"),
            ],
        )
        if path and self._hex_editor.load_file(path):
            self.root.title(f"Channeler Advance - Pokémon FireRed — {path}")
            self._update_file_menu_state()
            self._pcs_table.refresh_anchors()

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
            "Uses pret/pokefirered for C code reference.",
        )
