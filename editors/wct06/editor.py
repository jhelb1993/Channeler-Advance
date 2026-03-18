"""
Yu-Gi-Oh! Ultimate Masters: World Championship Tournament 2006 ROM Editor
Uses the ygowct06 disassembly (in ./ygowct06) for ARM7TDMI ASM reference.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Optional

from editors.common.hex_editor import HexEditorFrame

# Path to ygowct06 submodule for ASM reference
YGOWCT06_PATH = os.path.join(os.path.dirname(__file__), "ygowct06")


class WCT06Editor:
    """Main editor window for Yu-Gi-Oh! WCT 2006 hacking."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Channeler Advance - Yu-Gi-Oh! WCT 2006 Editor")
        self.root.geometry("900x650")
        self.root.minsize(720, 520)

        self._hex_editor: Optional[HexEditorFrame] = None
        self._main_paned: Optional[ttk.PanedWindow] = None
        self._placeholder_frame: Optional[ttk.Frame] = None
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

        # Main content: paned window with hex editor and room for tools
        self._main_paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        self._main_paned.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Top: hex editor (takes most space)
        self._hex_editor = HexEditorFrame(self._main_paned)
        self._main_paned.add(self._hex_editor)

        # Bottom: placeholder for future tools (resizable)
        self._placeholder_frame = ttk.LabelFrame(
            self._main_paned,
            text="Tools",
        )
        self._main_paned.add(self._placeholder_frame)

        self._update_file_menu_state()
        self.root.bind("<Control-s>", lambda e: self._on_save())

    def _update_file_menu_state(self) -> None:
        has_file = self._hex_editor and self._hex_editor.has_data()
        state = tk.NORMAL if has_file else tk.DISABLED
        self._file_menu.entryconfig("Save", state=state)
        self._file_menu.entryconfig("Save As...", state=state)

    def _on_open_rom(self) -> None:
        path = filedialog.askopenfilename(
            title="Open Yu-Gi-Oh! WCT 2006 ROM",
            filetypes=[
                ("GBA ROM", "*.gba"),
                ("All files", "*.*"),
            ],
        )
        if path and self._hex_editor.load_file(path):
            self.root.title(f"Channeler Advance - Yu-Gi-Oh! WCT 2006 — {path}")
            self._update_file_menu_state()

    def _on_save(self) -> None:
        if self._hex_editor and self._hex_editor.save_file():
            self._update_file_menu_state()

    def _on_save_as(self) -> None:
        if self._hex_editor and self._hex_editor.save_file_as():
            self.root.title(f"Channeler Advance - Yu-Gi-Oh! WCT 2006 — {self._hex_editor.get_file_path()}")

    def _on_exit(self) -> None:
        if self._hex_editor and self._hex_editor.is_modified():
            if messagebox.askyesno("Unsaved Changes", "Save changes before closing?"):
                self._hex_editor.save_file()
        self.root.quit()

    def _on_about(self) -> None:
        messagebox.showinfo(
            "About",
            "Channeler Advance - Yu-Gi-Oh! WCT 2006 Editor\n\n"
            "Uses Soul-8691/ygowct06 for ARM7TDMI ASM reference.",
        )
