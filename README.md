# Channeler Advance

A ROM hacking tool for Game Boy Advance games, built with Python and Tkinter — hex/table/struct editing, ARM7TDMI disassembly and HackMew-style ASM insertion, pseudo-C decompilation, and graphics preview tied to TOML “NamedAnchors” (similar in spirit to [Hex Maniac Advance](https://github.com/huderlem/hex-maniac-advance)).

**Releases & changelog:** [GitHub Releases — Channeler-Advance](https://github.com/Soul-8691/Channeler-Advance/releases) (e.g. demo **v0.1.0** notes).

## ROM and structure TOML

- Use the bundled **`FireRed.toml`** when hacking FireRed, or **`WCT06.toml`** for *Yu-Gi-Oh! Ultimate Masters: World Championship Tournament 2006*.
- By default, the editor looks for **`{YourRomBasename}.toml`** next to the ROM. You can load another file with **File → Load structure TOML**.
- **Authoritative DSL notes** for anchors and `Format` strings also live in **`editors/common/TOML.toml`** (commented reference). The summary below matches that file.

### Anchor addresses

- **`[[NamedAnchors]]` / `[[FunctionAnchors]]` — `Address`:** ROM **file** offset in hex (e.g. `0x147148`), **not** a GBA bus address with the `0x08` prefix.
- Deprecated **`[[OffsetPointer]]`** sections are ignored and are not written back.

### Struct `Format`: integers, lists, and text

Inside **`[ … ]count`** struct layouts:

- **Uint width:** `.` = 1 byte, `:` = 2 bytes per colon (e.g. `field:` = 2 bytes, `field::` = 4 bytes).
- **List / PCS enums:** `name:listname` or `name:listname+3` / `name:pcs.table-1` — optional trailing signed integer shifts the label index (`ROM index + offset`).
- **PCS string:** `name""N` — PCS-encoded, `N` bytes wide (`0xFF` terminator; same rules as PCS string tables).
- **Raw Latin-1 / byte string:** `name''N` — `N` bytes, NUL-padded; display stops at first `0x00`.
- **Helper (no ROM bytes):** `name|=a+b+…` — sums named **uint** fields; not editable in the struct grid.
- **Modifiers (append to a uint token):**
  - **`|h`** — show this **uint** in **hex** in the Structure tool (combine with **`|z`** for signed hex + decimal).
  - **`|z`** — treat the value as **signed** (two’s complement) for display and inline edit.
  - **`|b[]listOrTableName`** — **bit array:** one bit per row of the named **`[[List]]`**, or **`count`** rows if `listOrTableName` is a NamedAnchor table; storage is `ceil(bits/8)` bytes, LSB-first within each byte. The tool labels this as a bit array and shows raw bytes.
- **Bitfield (`|t|`):** storage before **`|t|`** uses the same `.` / `:` width rules as uints. After **`|t|`**, pipe-separated subfields use `.` = 1 bit and `:` = 2 bits (LSB-first). Subfields need not fill the word; high bits are padding. If you use one `.` before **`|t|`** but subfields need 9–16 bits, the parser promotes to 2 bytes.

### Struct `Format`: count-based nested arrays

In a NamedAnchor **struct** `Format`, **`name<[inner]/countField>`** means the **`inner`** layout is repeated **`countField`** times. The **`<>…`** block describes the layout **at the address** where the data lives:

- **Default (count before `name`, `name` last):** **`name`** is a **4-byte GBA pointer**; inner rows are read from `*name` (e.g. `pack<[card:… rarity:…]/cardamount>` after earlier `cardamount:` fields).
- **Implicit pointer (`name` first, `countField` last):** the first **4 bytes of the struct row** are the pointer; **`countField`** follows (e.g. `[options<…/count> count::]`).
- **`*otherPtr` suffix:** use a named **`ptr` / `pcs_ptr`** field instead of the two cases above.

### Struct `Format`: terminator-delimited nested arrays

In a NamedAnchor **struct** `Format`, a nested field can end with **`!HEX`** instead of **`/countField`**:

- **`name<[inner]/count>`** — `count` is the name of a **uint** field in the same struct that gives the number of inner rows (see **count-based nested arrays** above for pointer layout).
- **`name<[inner]!0000>`** — **even-length hex** is the **terminator** byte pattern (e.g. `!0000` → **`00 00`**). **By default**, **`name`** is a **4-byte GBA pointer**; the terminator-delimited blob is read starting at **`*name`** (same idea as a pointer column — the field name is unrelated to the layout byte offset variable in the parser).
- **`name<[inner]!0000>inline`** — **legacy / packed inline**: the nested bytes are stored **inline** in the struct row (no pointer). If the struct has **only** this field, consecutive table entries are **packed** back-to-back in ROM until each terminator; the editor scans row-by-row.

The terminator form must be the **last** field in the struct body. Suffix after `]` is still the table length (e.g. `]deckinfo`).

### Standalone string tables (not `[struct…]`)

- **`[field""N]count`** — PCS table (`count` = row count or table name).
- **`[field''N]count`** — same idea, ASCII / Latin-1 slots.
- **`''N`** — single ASCII blob of `N` bytes at `Address` (Tools → PCS list shows one row).

### Quoting `Format` in TOML

The tools do **not** strip stray `'` / `"` from `Format` (that broke `''N`). Prefer `Format = "''12"` or `Format = '[field''8]100'`. In multi-line `'''…'''` literals, each `''` is one `'`, so you may need extra quotes to get `''` in the value — or use lenient forms like `'12` / `['12]1` (collapsed).

### Graphics NamedAnchors (summary)

Whole-anchor **Format** (no `[`…`]` struct wrapper) describes sprites, tile sheets, palettes, tilemaps, and tables — decode uses Python + Pillow and aims for **pret/gbagfx**-compatible layouts. You may wrap the value in backticks in TOML, e.g. `` `ucs4x8x8|graphics.items.fossils.palette1` ``.

Common tokens include **`ucp4`**, **`ucp4:`** index runs, **`lzp4` / `lzp8`**, **`ucs4xWxH`** sprites, **`uct4xWxH` / `uct8xWxH`** tile sheets, **`lzt4` / `lzt8`** variable strips, **`ucs6xWxH`**, **`ucm4xMWxMH`** tilemaps, **`lzm4` / `lzm8`**, and **`[rowSpec]count`** graphics tables. In struct layouts, fields can use **pointer + backtick-wrapped graphics specs** inside angle brackets, and composite **tileset** / **tilemap** / **palette** fields; see **`editors/common/TOML.toml`** for full syntax.

**Full graphics DSL** (every prefix, LZ rules, palette linking, struct field patterns): **`editors/common/TOML.toml`** (Graphics section).

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

Python packages used by the app include **tomli** / **tomli-w**, **Pillow**, **Capstone** (disassembly), **angr** (pseudo-C / analysis, optional in some paths), **Pygments** (syntax highlighting), and the repo may integrate external tools such as **HackMew’s THUMB assembler** for ASM insertion workflows.

Install Python dependencies (use the same interpreter you use to run `main.py`):

```bash
python -m pip install -r requirements.txt
```

**If the app says `tomli-w` is missing but you installed it:** `pip` and `python` often point at different installations on Windows. Install with the interpreter that runs Channeler:

```bash
python -m pip install -U tomli-w
```

Or copy the path shown in the error dialog and run `"<that path>" -m pip install -U tomli-w`.

## Keyboard shortcuts

Bindings use **Ctrl** as the primary modifier (Windows/Linux). macOS may use **Cmd** for some system shortcuts; Tkinter typically still uses **Control** for these bindings.

### Pokémon FireRed editor — window / tools

| Shortcut | Action |
| -------- | ------ |
| **Ctrl+S** | Save ROM |
| **Ctrl+T** | Show or hide the **Tools** pane (PCS string table, Struct editor, Graphics preview) |
| **Ctrl+Shift+1** / **Ctrl+Shift+!** | Toggle Tools **slot 1** (PCS string table) |
| **Ctrl+Shift+2** / **Ctrl+Shift+@** | Toggle Tools **slot 2** (Struct editor) |
| **Ctrl+Shift+3** / **Ctrl+Shift+#** | Toggle Tools **slot 3** (Graphics preview) |

### Hex editor (all game editors)

These apply when the main hex view (or the overall window, for global toggles) has focus unless noted.

| Shortcut | Action |
| -------- | ------ |
| **Ctrl+G** | Focus the **Goto** (file offset) field |
| **Ctrl+F** | Open **Find** (hex mode: space-separated token **`xx`** or **`XX`** matches any byte, e.g. `00 xx 08 XX 09 xx 10`) |
| **Ctrl+R** | Open **Replace** (same hex wildcards in **Find**; replacement uses fixed hex only) |
| **Ctrl+A** | **Select all** in the focused pane (hex/ASCII = whole ROM; disassembly / pseudo-C / hooks text = all text) |
| **Ctrl+C** / **Copy** | Copy selection (hex + ASCII) |
| **Ctrl+V** / **Paste** | Paste — **insert** bytes at cursor (insert mode) |
| **Ctrl+B** | Paste — **overwrite** (write) |
| **Ctrl+Home** | Jump to **start** of ROM |
| **Ctrl+End** | Jump to **end** of ROM |
| **Ctrl+P** | Toggle **ARM/Thumb disassembly** pane |
| **Ctrl+D** | Toggle **pseudo-C** pane |
| **Ctrl+M** | Toggle **Named Anchor browser** pane (with the pane open, **drag the vertical sash** between Anchors and the Tools column to resize width; **horizontal scrollbar** under the list scrolls long names) |
| **Ctrl+H** | Toggle **HackMew** mode (when available) |
| **Ctrl+I** | **Compile** HackMew ASM (when HackMew mode and the disassembly pane are active) |

### Hex view — movement and editing

| Shortcut | Action |
| -------- | ------ |
| **←** / **→** | Move by byte (nybble within byte) |
| **↑** / **↓** | Move by **row** |
| **Home** / **End** | Start / end of **current row** |
| **PgUp** / **PgDn** | Scroll by **one visible page** |
| **Mouse wheel** | Scroll hex (and ASCII column) |
| **0–9**, **A–F** | Enter hex digits |
| **Insert** | Toggle **INSERT** vs **REPLACE** mode |
| **Delete** | Delete byte(s) (selection or at cursor) |
| **Backspace** | Delete previous byte |

### Tools panes (PCS / Struct / Graphics)

| Shortcut | Action |
| -------- | ------ |
| **F2** or **Enter** | Start **inline edit** on selected PCS / Struct tree row |
| **Enter** | Commit inline edit (also **FocusOut**) |
| **Escape** | Cancel inline edit |
| **↑** / **↓** | While editing PCS inline field — move to **previous/next row** |
| **Enter** in various fields | Apply (Goto, struct index, graphics table row, list enum, etc.) |

### Dialogs

Many modal dialogs use **Enter** to confirm and **Escape** to cancel.

### Yu-Gi-Oh! WCT 2006 editor

| Shortcut | Action |
| -------- | ------ |
| **Ctrl+S** | Save ROM |

All **Hex editor** shortcuts above apply. The FireRed-only **Ctrl+T** / **Ctrl+Shift+1–3** tools layout is not present in the WCT 2006 UI.

## Graphics import (Tools → graphics preview)

- **Sprites** (`uct`/`lzt`/`ucs`/`lzs`): Import PNG; if the data is moved to a new ROM address, the relocate dialog can **fill the original slot with `0xFF`** to reclaim it as free space.
- **Tilemaps** (`ucm`/`lzm`): Import a PNG sized to the map in **tiles × 8 pixels** per side. The tool builds a deduped tileset (with flip matching, similar in spirit to [Tilemap Studio](https://github.com/Rangi42/tilemap-studio)’s image→tiles workflow), writes the **tileset**, **tilemap**, and linked **palette** blobs, and updates the tileset NamedAnchor **Format** grid when the unique tile count changes.
  - **Palette:** By default the ROM palette matches the image’s **exact** RGB colors after compositing onto white (first-seen order, no MedianCut). Check **Quantize tilemap palette** next to **Import graphic…** to use Pillow quantization instead (e.g. if the PNG has more than 256 unique colors for 8bpp).
- **8bpp palette preview** (`ucp8` / `lzp8`): The swatch grid is **scrollable** (wheel / scrollbar) so full **256-color** masters show as multiple rows, not just the first 16 colors.

## File → static imports (any offset)

Without using NamedAnchors, **File → Import Sprite / Import Tilemap/Tileset / Import Palette** writes encoded data to a **file offset** you enter (or to the start of an **FF gap** found via Search). These commands **do not** update pointers or TOML—you repoint data in your disassembly or structs yourself.

**Import palette:** Choose **4bpp** (16 colors) or **8bpp**. For 8bpp, set the **color count** to any **multiple of 16** from 16–256 (full “master” palette is 256 colors / 512 bytes; smaller counts match multi-row ``ucp8:``-style blobs). ``.pal`` / ``.gpl`` files are **standard text palettes** (JASC-PAL, GIMP GPL, or Tilemap Studio assembly ``RGB`` lines), then converted to GBA RGB555. Use a **``.bin``** for **raw** GBA RGB555 bytes (length must match the selected 4bpp/8bpp size).

## Features overview (from project release notes)

High-level capabilities include:

- General editing: write, insert (**Insert** key toggles insert mode), delete, copy, paste-overwrite (**Ctrl+B**) / paste-insert (**Ctrl+V**), find/replace, goto.
- Hex / ASCII / PCS text; table and struct editing from TOML; repointing text and pointers (including optional **FF**-fill of old space when relocating).
- In-tool editing of TOML anchor formats; **double-click** pointers to follow (red highlight); **double-click** the start of an ASM routine in the hex view to highlight through the end (when applicable).
- **Ctrl+T** / **Ctrl+Shift+1–3** to show or focus Tools slots (FireRed layout).
- Disassembly (**Ctrl+P**), HackMew ASM (**Ctrl+H**), pseudo-C (**Ctrl+D**), **Ctrl+M** anchor browser.
- Graphics: sprites, tilemaps, tilesets, palettes; anchor visual browser.

**Rough roadmap / not implemented yet** (non-exhaustive): auto-generated TOML on ROM open, Python scripting interface, complete pret→TOML function/struct/constant conversion, undo, some FireRed-specific editors (trainer teams, overworld sprites, egg moves).

**Not currently planned:** songs, mapping, event scripting, battle/animation/trainer-AI scripting.

## Credits

- **[pret/pokefirered](https://github.com/pret/pokefirered)** — decomp and **gbagfx**-aligned behavior used throughout graphics code.
- **HackMew** and the THUMB assembler tooling referenced for ASM workflows.
- Tooling built with **Cursor** (often **Composer**).
