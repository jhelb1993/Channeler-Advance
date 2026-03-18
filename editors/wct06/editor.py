"""
Yu-Gi-Oh! Ultimate Masters: World Championship Tournament 2006 ROM Editor
Uses the ygowct06 disassembly (in ./ygowct06) for ARM7TDMI ASM reference.
"""

import os
import tkinter as tk
from tkinter import ttk

# Path to ygowct06 submodule for ASM reference
YGOWCT06_PATH = os.path.join(os.path.dirname(__file__), "ygowct06")


class WCT06Editor:
    """Main editor window for Yu-Gi-Oh! WCT 2006 hacking."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Channeler Advance - Yu-Gi-Oh! WCT 2006 Editor")
        self.root.geometry("800x600")
        self.root.minsize(640, 480)

        self._build_ui()

    def _build_ui(self) -> None:
        """Build the editor interface."""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open ROM...", command=self._on_open_rom)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._on_about)

        # Main content
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="Yu-Gi-Oh! WCT 2006 Editor", font=("", 16, "bold")).pack(anchor=tk.W)
        ttk.Label(
            main,
            text=f"ASM reference: {YGOWCT06_PATH}",
            font=("", 9),
            foreground="gray",
        ).pack(anchor=tk.W, pady=(0, 15))

        ttk.Separator(main, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)

        ttk.Label(
            main,
            text="No ROM loaded. Use File → Open ROM to get started.",
            font=("", 10),
        ).pack(anchor=tk.W, pady=20)

    def _on_open_rom(self) -> None:
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            title="Open Yu-Gi-Oh! WCT 2006 ROM",
            filetypes=[
                ("GBA ROM", "*.gba"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._load_rom(path)

    def _load_rom(self, path: str) -> None:
        """Load a ROM file. Placeholder for future implementation."""
        self.root.title(f"Channeler Advance - Yu-Gi-Oh! WCT 2006 Editor — {path}")
        # TODO: Implement ROM loading and parsing

    def _on_about(self) -> None:
        from tkinter import messagebox
        messagebox.showinfo(
            "About",
            "Channeler Advance - Yu-Gi-Oh! WCT 2006 Editor\n\n"
            "Uses Soul-8691/ygowct06 for ARM7TDMI ASM reference.",
        )
