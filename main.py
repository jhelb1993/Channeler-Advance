#!/usr/bin/env python3
"""
Channeler Advance - ROM Hacking Tool
Supports Pokemon FireRed and Yu-Gi-Oh! Ultimate Masters: World Championship Tournament 2006
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

def open_rom() -> None:
    path = filedialog.askopenfilename(
        title="Open ROM",
        filetypes=[("FIRERED/YUGIOH GBA ROM", "*.gba"), ("All files", "*.*")],
    )
    return path

def launch_editor(path: str) -> None:
    """Load the appropriate editor based on game selection."""
    data = None
    try:
        data = open(path,'rb').read(512)
    except IOError as err:
        messagebox.showerror("Error", f"{err.strerror}!")
        return
    if b"POKEMON FIRE" in data:
        from editors.firered.editor import FireRedEditor
        root = tk.Tk()
        app = FireRedEditor(root, path)
        root.mainloop()
    elif b"WCT06" in data:
        from editors.wct06.editor import WCT06Editor
        root = tk.Tk()
        app = WCT06Editor(root)
        root.mainloop()
    else:
        messagebox.showerror("Error", f"Unknown game: {game}")


def main() -> None:
    path = open_rom()
    launch_editor(path)



if __name__ == "__main__":
    main()
