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
