# Channeler Advance

A ROM hacking tool for Game Boy Advance games, built with Python and Tkinter.

## Supported Games

- **Pokémon FireRed** – Uses [pret/pokefirered](https://github.com/pret/pokefirered) for C code reference
- **Yu-Gi-Oh! Ultimate Masters: World Championship Tournament 2006** – Uses [Soul-8691/ygowct06](https://github.com/Soul-8691/ygowct06) for ARM7TDMI ASM reference

## Setup

1. Clone the repository (with submodules):

   ```bash
   git clone --recurse-submodules https://github.com/YOUR_USER/Channeler-Advance.git
   ```

   If already cloned:

   ```bash
   git submodule update --init --recursive
   ```

2. Run the launcher:

   ```bash
   python main.py
   ```

3. Select the game you want to hack from the dropdown and click **Launch Editor**.

## Project Structure

```
Channeler-Advance/
├── main.py              # Launcher with game selector
├── editors/
│   ├── firered/         # Pokémon FireRed editor
│   │   ├── editor.py
│   │   └── pokefirered/  # Submodule: pret/pokefirered
│   └── wct06/           # Yu-Gi-Oh! WCT 2006 editor
│       ├── editor.py
│       └── ygowct06/    # Submodule: Soul-8691/ygowct06
└── requirements.txt
```

## Requirements

- Python 3.8+
- Tkinter (included with most Python installations)

Install Python dependencies (use the same interpreter you use to run `main.py`):

```bash
python -m pip install -r requirements.txt
```

**If the app says `tomli-w` is missing but you installed it:** `pip` and `python` often point at different installations on Windows. Install with the interpreter that runs Channeler:

```bash
python -m pip install -U tomli-w
```

Or copy the path shown in the error dialog and run `"<that path>" -m pip install -U tomli-w`.

## Graphics import (Tools → graphics preview)

- **Sprites** (`uct`/`lzt`/`ucs`/`lzs`): Import PNG; if the data is moved to a new ROM address, the relocate dialog can **fill the original slot with `0xFF`** to reclaim it as free space.
- **Tilemaps** (`ucm`/`lzm`): Import a PNG sized to the map in **tiles × 8 pixels** per side. The tool builds a deduped tileset (with flip matching, similar in spirit to [Tilemap Studio](https://github.com/Rangi42/tilemap-studio)’s image→tiles workflow), writes the **tileset**, **tilemap**, and linked **palette** blobs, and updates the tileset NamedAnchor **Format** grid when the unique tile count changes.
