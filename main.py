#!/usr/bin/env python3
"""
Channeler Advance - ROM Hacking Tool
Supports Pokemon FireRed and Yu-Gi-Oh! Ultimate Masters: World Championship Tournament 2006
"""

import tkinter as tk
from tkinter import ttk, messagebox


def launch_editor(game: str) -> None:
    """Load the appropriate editor based on game selection."""
    if game == "firered":
        from editors.firered.editor import FireRedEditor
        root = tk.Tk()
        app = FireRedEditor(root)
        root.mainloop()
    elif game == "wct06":
        from editors.wct06.editor import WCT06Editor
        root = tk.Tk()
        app = WCT06Editor(root)
        root.mainloop()
    else:
        messagebox.showerror("Error", f"Unknown game: {game}")


def main() -> None:
    root = tk.Tk()
    root.title("Channeler Advance")
    root.resizable(False, False)

    # Center window
    root.update_idletasks()
    width, height = 400, 180
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")

    # Main frame
    frame = ttk.Frame(root, padding=20)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="Select a game to hack:", font=("", 11)).pack(pady=(0, 10))

    games = [
        ("Pokémon FireRed", "firered"),
        ("Yu-Gi-Oh! Ultimate Masters: WCT 2006", "wct06"),
    ]
    selected = tk.StringVar(value=games[0][1])

    dropdown = ttk.Combobox(
        frame,
        textvariable=selected,
        values=[g[0] for g in games],
        state="readonly",
        width=42,
        font=("", 10),
    )
    dropdown.current(0)
    dropdown.pack(pady=5, padx=20)

    # Map display names back to internal keys
    name_to_key = {g[0]: g[1] for g in games}

    def on_launch() -> None:
        root.destroy()
        key = name_to_key.get(selected.get(), selected.get())
        launch_editor(key)

    ttk.Button(frame, text="Launch Editor", command=on_launch).pack(pady=20)

    root.mainloop()


if __name__ == "__main__":
    main()
