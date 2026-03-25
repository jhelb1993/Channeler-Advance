# Channeler Advance

A ROM hacking tool for Game Boy Advance games, built with Python and Tkinter — hex/table/struct editing, ARM7TDMI disassembly and HackMew-style ASM insertion, pseudo-C decompilation, and graphics preview tied to TOML “NamedAnchors” (similar in spirit to [Hex Maniac Advance](https://github.com/huderlem/hex-maniac-advance)).

**Cross-platform:** runs on **Windows**, **macOS**, and **Linux** (standard CPython + Tkinter). Use the same Python interpreter for `pip` and for launching `main.py` so optional native wheels (Capstone, angr) load correctly.

**Releases & changelog:** [GitHub Releases — Channeler-Advance](https://github.com/Soul-8691/Channeler-Advance/releases) (e.g. demo **v0.1.0** notes). Compare any tag to `main` on GitHub (or `git diff <tag>...main` locally) for file-level history.

The hex editor skips redundant analysis when the viewport and ROM slice are unchanged (**faster refresh** on large ROMs). **macOS / Linux** path and helper behavior are exercised in-tree (e.g. **`deps/thumb.sh`**). The PCS table tool includes basic **Find** / filter for rows. Labels and PCS-related UI use improved **Unicode / symbol** handling where it matters for display (including **Linux-safe** label text so ellipsis and similar characters do not render as broken glyphs).

## ROM and structure TOML

- Use the bundled **`FireRed.toml`** when hacking FireRed or **`wct06.toml`** for *Yu-Gi-Oh! Ultimate Masters: World Championship Tournament 2006* (see **Yu-Gi-Oh! structure files** below for other titles).
- By default, the editor looks for **`{YourRomBasename}.toml`** next to the ROM. You can load another file with **File → Load structure TOML**.
- **Authoritative DSL notes** for anchors and `Format` strings also live in **`editors/common/TOML.toml`** (commented reference). The summary below matches that file.
- **Yu-Gi-Oh! structure files:** **`EDS.toml`** (*The Eternal Duelist Soul*) is the most **in-depth** bundled map (broad per-card naming and other tables). **`WCT04.toml`** (*Yu-Gi-Oh! World Championship 2004*), **`WCT05.toml`** (*Yu-Gi-Oh! 7 Trials to Glory: World Championship Tournament 2005*), **`WWE.toml`** (*Yu-Gi-Oh! Worldwide Edition: Stairway to the Destined Duel*), and **`Reshef.toml`** (*Yu-Gi-Oh! Reshef of Destruction*) are **partial** TOMLs—useful anchors and structs, not full game coverage. (On case-insensitive filesystems, names like **`WCT06.toml`** may match **`wct06.toml`**.)

- Bundled **`Reshef.toml`** (*Reshef of Destruction*, **partial**—see above) still documents Reshef-specific workflows: **`.ydk`** deck import, **`.conf` / `.lflist`**-style list paths where configured, **duelist**-related table updates, and **card-sprite** Huff/LZ handling tied to the `reshef` graphics path. The struct/hex pipeline supports **`seq`** parallel columns, pointer-backed string fields, nested-array validation tied to a shared **`count`**, and related edge cases documented in **`TOML.toml`**.

### Anchor addresses

- **`[[NamedAnchors]]` / `[[FunctionAnchors]]` — `Address`:** ROM **file** offset in hex (e.g. `0x147148`), **not** a GBA bus address with the `0x08` prefix.
- Deprecated **`[[OffsetPointer]]`** sections are ignored and are not written back.

### Struct `Format`: integers, lists, and text

Inside **`[ … ]count`** struct layouts:

- **Uint width:** `.` = 1 byte, `:` = 2 bytes per colon (e.g. `field:` = 2 bytes, `field::` = 4 bytes).
- **List / PCS enums:** `name:listname` or `name:listname+3` / `name:pcs.table-1` — optional trailing signed integer shifts the label index (`ROM index + offset`).
- **PCS string:** `name""N` — PCS-encoded, `N` bytes wide (`0xFF` terminator; same rules as PCS string tables).
- **PCS control codes / pret-style `{…}` macros:** expanded using the same **`charmap.txt`** mapping the project ships with (so editor display and length checks stay aligned with the game’s encoding). Expansion and growth rules respect **bracket** boundaries so nested `{…}` text stays well-formed.
- **Raw Latin-1 / byte string:** `name''N` — `N` bytes, NUL-padded; display stops at first `0x00`.
- **Pointer-backed text (`pcs_ptr` / `ascii_ptr`):** the Structure tool shows **Pointer (GBA)** plus decoded PCS or ASCII text for **both** top-level fields and **nested-array** inner fields. **Inline** edits and the pointer box accept several pointer forms (`0x…`, eight hex digits without `0x`, larger ROM **file** offsets in decimal) while still treating short edits as **string text** when the current pointer targets ROM (`0x08……` / `0x09……`).
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

The terminator form must be the **last** field in the struct body. Suffix after `]` is still the table length (e.g. `]deckinfo`).

### Standalone string tables (not `[struct…]`)

- **`[field""N]count`** — PCS table (`count` = row count or table name).
- **`[field''N]count`** — same idea, ASCII / Latin-1 slots.
- **`''N`** — single ASCII blob of `N` bytes at `Address` (Tools → PCS list shows one row).

### Quoting `Format` in TOML

The tools do **not** strip stray `'` / `"` from `Format` (that broke `''N`). Prefer `Format = "''12"` or `Format = '[field''8]100'`. In multi-line `'''…'''` literals, each `''` is one `'`, so you may need extra quotes to get `''` in the value — or use lenient forms like `'12` / `['12]1` (collapsed).

### Graphics NamedAnchors (summary)

Whole-anchor **Format** (no `[`…`]` struct wrapper) describes sprites, tile sheets, palettes, tilemaps, and tables — decode uses Python + Pillow and aims for **pret/gbagfx**-compatible layouts. You may wrap the value in backticks in TOML, e.g. `` `ucs4x8x8|graphics.items.fossils.palette1` ``.

Common tokens include **`ucp4`**, **`ucp4:`** index runs, **`lzp4` / `lzp8`**, **`ucs4xWxH`** sprites, **`uct4xWxH` / `uct8xWxH`** tile sheets, **`lzt4` / `lzt8`** variable strips, **`ucs6xWxH`**, **`ucm4xMWxMH`** tilemaps, **`lzm4` / `lzm8`**, and **`[rowSpec]count`** graphics tables. In struct layouts, fields can use **pointer + backtick-wrapped graphics specs** inside angle brackets, and composite **tileset** / **tilemap** / **palette** fields; see **`editors/common/TOML.toml`** for full syntax. When a struct defines a **`name`** (or similar) column alongside graphics, the Tools **graphics preview** can **resolve palettes automatically** from a sibling **`pal` / `palette`** field or a `` `pal` `` token in the graphics spec.

**`reshef` (Yu-Gi-Oh! Reshef card graphics):** prefix a standalone graphics `Format` or inner struct field spec with `` `reshef` `` so Channeler applies the same **pre-LZ77/Huff byte transform** as [ygodm8](https://github.com/shinny4/ygodm8)’s `ygodm_encode` hook (inverse after decompress for display/import). Use it for Huff- or LZ-compressed card art and palettes that were built with that pipeline—see **[shinny4/ygodm8](https://github.com/shinny4/ygodm8)** (credit below).

**ROM span sizing:** when the ROM is loaded, LZ77 and GBA Huff blobs use **measured** compressed lengths (stream length + 4-byte padding) for selection and anchor bounds where possible; graphics tables with consecutive compressed rows sum row sizes when that layout matches the ROM.

**Full graphics DSL** (every prefix, LZ rules, palette linking, struct field patterns): **`editors/common/TOML.toml`** (Graphics section).

## Supported Games

- **Pokémon FireRed** – Uses [pret/pokefirered](https://github.com/pret/pokefirered) for C code reference
- **Yu-Gi-Oh! Ultimate Masters: World Championship Tournament 2006** – Uses [Soul-8691/ygowct06](https://github.com/Soul-8691/ygowct06) for ARM7TDMI ASM reference; bundled **`wct06.toml`**
- **Yu-Gi-Oh! The Eternal Duelist Soul** – Bundled **`EDS.toml`** (**more in-depth** than the partial TOMLs below)
- **Yu-Gi-Oh!** (partial TOMLs) – **`WCT04.toml`** (*World Championship 2004*), **`WCT05.toml`** (*7 Trials to Glory: World Championship Tournament 2005*), **`WWE.toml`** (*Worldwide Edition: Stairway to the Destined Duel*), **`Reshef.toml`** (*Reshef of Destruction*). For Reshef, card sprite **Huff/LZ** may require the `` `reshef` `` graphics prefix (see [shinny4/ygodm8](https://github.com/shinny4/ygodm8) in **Credits**). Load with **File → Load structure TOML** or place next to your ROM as **`{basename}.toml`**.

## Setup

1. Clone the repository (with submodules):

   ```bash
   git clone --recurse-submodules https://github.com/YOUR_USER/Channeler-Advance.git
   ```

   If already cloned:

   ```bash
   git submodule update --init --recursive
   ```

2. **Install Python dependencies** (Capstone, angr, Pygments, Pillow, TOML libraries — see `requirements.txt`). Always use the interpreter you will use to run the app:

   ```bash
   python3 -m pip install -r requirements.txt
   ```

   On **macOS** and **Linux**, prefer a **venv** so system Python and wheels stay aligned:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Linux / macOS: adjust for your shell
   python -m pip install -U pip
   python -m pip install -r requirements.txt
   ```

   - **Tkinter:** Most official Python builds include it. On **Debian/Ubuntu**, if `import tkinter` fails, install `python3-tk` (package name may differ on other distros).
   - **Capstone** (`capstone>=5`): ARM disassembly for the hex pane and the **pseudo-C** Capstone fallback. Wheels are usually available from PyPI on macOS and common Linux architectures.
   - **angr** (`angr>=9.2`): CFG + decompiler for **pseudo-C** when you press **Ctrl+D**. It pulls larger native dependencies (e.g. Z3, unicorn); the first install can take several minutes. If `import angr` fails (missing module, `OSError` loading a library), the editor still starts; **pseudo-C** falls back to Capstone-only until angr installs cleanly into that same environment.
   - **Troubleshooting:** If `pip` and `python` point at different installations, run `python -m pip install -r requirements.txt` using the same `python` you use for `python main.py`.

3. Run the launcher:

   ```bash
   python main.py
   ```

4. Select the game you want to hack from the dropdown and click **Launch Editor**.

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

- **Python 3.8+** (64-bit recommended on Windows; use a current CPython from [python.org](https://www.python.org/) or your package manager on macOS/Linux).
- **Tkinter** — bundled with many installers; on Linux you may need a separate `python3-tk` (or equivalent) package.

Python packages from `requirements.txt`: **tomli** / **tomli-w**, **Pillow**, **Pygments**, **Capstone** (ARM disassembly), **angr** (pseudo-C decompilation via CFG + decompiler). The repo may also use external tools such as **HackMew’s THUMB assembler** for ASM insertion workflows.

**Pseudo-C behavior:** With **angr** installed, **Ctrl+D** shows structured decompilation when possible. Without a working **angr** import, the same pane uses a **Capstone**-based line-by-line pseudo-C fallback (still useful, but not the full decompiler). Install everything with:

```bash
python -m pip install -r requirements.txt
```

(or `python3 -m pip` on macOS/Linux — see **Setup** above).

**If the app says `tomli-w` is missing but you installed it:** `pip` and `python` often point at different installations (common on Windows). Install with the interpreter that runs Channeler:

```bash
python -m pip install -U tomli-w
```

Or copy the path shown in the error dialog and run `"<that path>" -m pip install -U tomli-w`.

## Keyboard shortcuts

Bindings use **Ctrl** as the primary modifier (Windows/Linux). macOS may use **Cmd** for some system shortcuts; Tkinter typically still uses **Control** for these bindings.

### Hex editor (all game editors)

These apply when the main hex view (or the overall window, for global toggles) has focus unless noted.

| Shortcut | Action |
| -------- | ------ |
| **Ctrl+A** | **Select all** in the focused pane (hex/ASCII = whole ROM; disassembly / pseudo-C / hooks text = all text) |
| **Ctrl+B** | Paste — **overwrite** (write) |
| **Ctrl+C** / **Copy** | Copy selection (hex + ASCII) |
| **Ctrl+D** | Toggle **pseudo-C** pane |
| **Ctrl+End** | Jump to **end** of ROM |
| **Ctrl+F** | Open **Find** (hex mode: space-separated token **`xx`** or **`XX`** matches any byte, e.g. `00 xx 08 XX 09 xx 10`) |
| **Ctrl+G** | Focus the **Goto** field (type an offset or anchor name, then **Enter** to jump — navigation runs on **Enter**, not on every keystroke) |
| **Ctrl+H** | Toggle **HackMew** mode (when available) |
| **Ctrl+Home** | Jump to **start** of ROM |
| **Ctrl+I** | **Compile** HackMew ASM (when HackMew mode and the disassembly pane are active) |
| **Ctrl+M** | Toggle **Named Anchor browser** pane (with the pane open, **drag the vertical sash** between Anchors and the Tools column to resize width; **horizontal scrollbar** under the list scrolls long names) |
| **Ctrl+P** | Toggle **ARM/Thumb disassembly** pane |
| **Ctrl+R** | Open **Replace** (same hex wildcards in **Find**; replacement uses fixed hex only) |
| **Ctrl+S** | Save ROM |
| **1.** **Ctrl+Shift+1** / **Ctrl+Shift+!** | Toggle Tools **slot 1** (PCS string table) |
| **2.** **Ctrl+Shift+2** / **Ctrl+Shift+@** | Toggle Tools **slot 2** (Struct editor) |
| **3.** **Ctrl+Shift+3** / **Ctrl+Shift+#** | Toggle Tools **slot 3** (Graphics preview) |
| **4.** **Ctrl+Shift+4** / **Ctrl+Shift+$** | Toggle **pseudo-C full edit** mode (C edit + hooks/repoints panel) |
| **5.** **Ctrl+Shift+5** / **Ctrl+Shift+%** | **Compile** pseudo-C inject sources |
| **6.** **Ctrl+Shift+6** / **Ctrl+Shift+^** | **Apply ROM patches** from pseudo-C inject output |
| **7.** **Ctrl+Shift+7** / **Ctrl+Shift+&** | Toggle **Python script pane** (full right side); close with the same shortcut |
| **Ctrl+T** | Show or hide the **Tools** pane (PCS string table, Struct editor, Graphics preview) |
| **Ctrl+V** / **Paste** | Paste — **insert** bytes at cursor (insert mode) |

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

### Hex view — double-click (hex / ASCII data columns)

- **Graphics NamedAnchor (table):** selects the **row**’s bytes in ROM (for pointer-column palette tables, the **palette blob** at the resolved address). **LZ77- or Huffman-compressed** rows use the **measured stream length** so the selection covers the full compressed blob, not just the header. The **graphics table row** control syncs when applicable.
- **Struct — graphics field:** if the click lies in a **`gfx` / backtick graphics** field, the selection is **just that field** (LZ77/Huff length is **measured** from the stream when the header is valid).
- **PCS or struct table:** Tools jumps to the **row** that contains the byte; the table range stays highlighted.
- **Pointer follow:** a **valid GBA ROM `.word`** (0x08…… / 0x09……) is followed **after** graphics-table and pointer-field rules, so struct pointer fields still jump to `*ptr` targets.
- **Goto / Tools focus:** syncing Tools does not pull focus away from **Goto** while you are typing there.

### Tools panes (PCS / Struct / Graphics)

| Shortcut | Action |
| -------- | ------ |
| **F2** or **Enter** | Start **inline edit** on selected PCS / Struct tree row |
| **Enter** | Commit inline edit (also **FocusOut**) |
| **Escape** | Cancel inline edit |
| **↑** / **↓** | While editing PCS inline field — move to **previous/next row** |
| **Enter** in various fields | Apply (**Goto** after typing, struct index, graphics table row, list enum, etc.) |

### Dialogs

Many modal dialogs use **Enter** to confirm and **Escape** to cancel.

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
- Hex / ASCII / PCS text; table and struct editing from TOML; repointing text and pointers (including optional **FF**-fill of old space when relocating, without spurious prompts for FF-gap search bounds when the relocation path does not need them).
- In-tool editing of TOML anchor formats; **double-click** valid **`.word`** ROM pointers to follow—including from **raw bytes** in the hex view when the ROM data is a valid pointer; **double-click** the start of an ASM routine in the hex view to highlight through the end (when applicable). **Thumb** disassembly in the hex pane follows **16-bit** instruction alignment. **Double-click** handling for PCS/struct tables, graphics tables, struct **graphics** fields, and pointers is summarized under **Hex view — double-click** above.
- **Ctrl+T** / **Ctrl+Shift+1–3** to show or focus Tools slots; struct tables with a **`name`** (or similar) field can drive **automatic row labels** in the Structure tool when configured.
- **Ctrl+Shift+4–7** for pseudo-C inject workflow and Python script pane.
- Disassembly (**Ctrl+P**), HackMew ASM (**Ctrl+H**; **Linux** insertion path fixed), pseudo-C (**Ctrl+D**), **Ctrl+M** anchor browser.
- Graphics: sprites, tilemaps, tilesets, palettes; anchor visual browser.

**Rough roadmap / not implemented yet** (non-exhaustive): auto-generated TOML on ROM open, Python scripting interface, complete pret→TOML function/struct/constant conversion, undo, some FireRed-specific editors (trainer teams, overworld sprites, egg moves).

**Not currently planned:** songs, mapping, event scripting, battle/animation/trainer-AI scripting.

## Credits

- **[Hex Maniac Advance](https://github.com/huderlem/hex-maniac-advance)** — primary inspiration for this kind of GBA ROM editor (thanks to **[haven1433](https://github.com/haven1433)** and contributors).
- **[gbagfx](https://github.com/pret/pokefirered/tree/master/tools/gbagfx)** — pret’s reference graphics tool (the same `tools/gbagfx` tree is shared across pret disassemblies, e.g. FireRed and Emerald) for encoding alignment in Channeler’s Python graphics path.
- **[Tilemap Studio](https://github.com/Rangi42/tilemap-studio)** (**Rangi42**) — image→tiles workflow and palette conventions that informed tilemap import behavior.
- **Kertra** — for discovering and documenting the **6bpp** Yu-Gi-Oh! card sprite layout used in WCT-era titles.
- **[pret/pokefirered](https://github.com/pret/pokefirered)** — decomp reference and **gbagfx**-aligned behavior used throughout graphics code.
- **[shinny4/ygodm8](https://github.com/shinny4/ygodm8)** — reference for **Yu-Gi-Oh!** DM8 disassembly tooling; Channeler’s **`reshef`** / **ygodm**-style pre-Huff (and inverse on decode) sprite and palette handling for *Reshef of Destruction* aligns with the **`ygodm_encode`** approach in that project’s **gbagfx** fork.
- **HackMew** and the THUMB assembler tooling referenced for ASM workflows.
- Tooling built with **Cursor** (often **Composer**).
