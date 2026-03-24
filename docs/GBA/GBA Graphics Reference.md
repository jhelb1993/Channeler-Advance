# GBA Tiled Graphics Reference

A comprehensive guide to GBA tiled graphics covering hardware architecture, the pokeemerald sprite engine, the gbagfx conversion tool, and the Tilemap Studio editor.

---

## Table of Contents

1. [GBA Graphics Architecture](#1-gba-graphics-architecture)
2. [Tiles and Bit Depth](#2-tiles-and-bit-depth)
3. [Palettes](#3-palettes)
4. [Sprites (Objects)](#4-sprites-objects)
5. [Tiled Backgrounds](#5-tiled-backgrounds)
6. [Windowing](#6-windowing)
7. [pokeemerald Sprite Engine](#7-pokeemerald-sprite-engine)
8. [gbagfx Conversion Tool](#8-gbagfx-conversion-tool)
9. [Tilemap Studio](#9-tilemap-studio)
10. [LZ Compression](#10-lz-compression)
11. [Affine Transforms](#11-affine-transforms)
12. [Glossary of Key Terms](#12-glossary-of-key-terms)
13. [Function Glossary: pokeemerald sprite.c](#13-function-glossary-pokeemerald-spritec)
14. [Function Glossary: gbagfx](#14-function-glossary-gbagfx)
15. [Function Glossary: Tilemap Studio](#15-function-glossary-tilemap-studio)

---

## 1. GBA Graphics Architecture

The GBA has 96 KiB of Video RAM (VRAM) starting at `0600:0000h`, plus 1 KiB of palette RAM at `0500:0000h` and 1 KiB of OAM at `0700:0000h`.

VRAM is divided into **charblocks** (16 KiB each) and **screenblocks** (2 KiB each). These share the same address space:

| Memory Range    | Charblock | Screenblocks |
|-----------------|-----------|--------------|
| `0600:0000`     | 0         | 0-7          |
| `0600:4000`     | 1         | 8-15         |
| `0600:8000`     | 2         | 16-23        |
| `0600:C000`     | 3         | 24-31        |
| `0601:0000`     | 4 (sprite low)  | —      |
| `0601:4000`     | 5 (sprite high)  | —     |

- Charblocks 0-3 store **background tile graphics**.
- Charblocks 4-5 store **sprite tile graphics** (object VRAM).
- Screenblocks store **tilemaps** (the grid of which-tile-goes-where).

The display control register `REG_DISPCNT` at `0400:0000h` selects the video mode and enables individual backgrounds and sprites.

### Video Modes (Tiled)

| Mode | BG0  | BG1  | BG2  | BG3  |
|------|------|------|------|------|
| 0    | reg  | reg  | reg  | reg  |
| 1    | reg  | reg  | aff  | —    |
| 2    | —    | —    | aff  | aff  |

Modes 3-5 are bitmap modes where the framebuffer overlaps into sprite charblock 4, restricting sprites to tiles 512-1023.

---

## 2. Tiles and Bit Depth

All GBA tiled graphics are built from 8×8 pixel tiles. Each pixel is a palette index.

### 4bpp Tiles (s-tiles)

- 32 bytes per tile.
- Each byte holds two pixels: low nybble = left pixel, high nybble = right pixel.
- 16 colors per palette bank, up to 16 palette banks.

```
Byte layout of one 4bpp tile row (4 bytes = 8 pixels):
  [px0|px1] [px2|px3] [px4|px5] [px6|px7]
  Each nybble is a 4-bit palette index.
```

### 8bpp Tiles (d-tiles)

- 64 bytes per tile.
- Each byte is one pixel (a full 8-bit palette index).
- 256 colors, single palette.

### 1bpp Tiles

- 8 bytes per tile.
- Each bit is one pixel (monochrome).
- Used by some fonts and simple graphics.

### Tile Indexing: BG vs Sprites

Background tile indices follow the bit depth: index N points to byte offset `N * 32` for 4bpp or `N * 64` for 8bpp. Sprite tile indices **always** use 32-byte offsets regardless of bit depth.

```
Pseudocode: tile address calculation

BG tile address:
  addr = charblock_base + tile_index * (bitDepth * 8)
  // 4bpp: tile_index * 32
  // 8bpp: tile_index * 64

Sprite tile address:
  addr = 0x0601_0000 + tile_index * 32  // always 32-byte steps
```

---

## 3. Palettes

The GBA uses 15-bit BGR555 color: 5 bits per channel, packed into a 16-bit halfword.

```
Bit layout: [0bbbbbgg gggrrrrr]
  bits  0-4:  red   (0-31)
  bits  5-9:  green (0-31)
  bits 10-14: blue  (0-31)
  bit  15:    unused
```

Palette RAM holds two 256-color palettes:

| Address       | Purpose           |
|---------------|-------------------|
| `0500:0000h`  | Background palette (512 bytes) |
| `0500:0200h`  | Sprite palette (512 bytes)     |

Each palette can be viewed as 16 **palette banks** of 16 colors each (for 4bpp mode).

### Transparency

Pixel value 0 is always transparent. For sprites, this is the standard way to make parts of a sprite invisible. In PNG files, this corresponds to a `tRNS` chunk marking palette index 0 as fully transparent.

### Color Conversion

```
Pseudocode: GBA ↔ 8-bit color conversion

// 5-bit (GBA) to 8-bit (PNG/standard):
  color8 = (color5 * 255) / 31

// 8-bit to 5-bit:
  color5 = color8 / 8
```

---

## 4. Sprites (Objects)

The GBA supports 128 sprites, controlled through Object Attribute Memory (OAM) at `0700:0000h`. Each sprite has three 16-bit attributes plus a filler halfword (8 bytes total, 1 KiB for all 128).

### OAM Attribute Layout

**Attribute 0** (Y, shape, mode, color mode):

| Bits  | Field | Description |
|-------|-------|-------------|
| 0-7   | Y     | Y coordinate (top edge) |
| 8-9   | Mode  | 00=regular, 01=affine, 10=hidden, 11=affine double |
| A-B   | GFX   | 00=normal, 01=alpha blend, 10=obj window |
| C     | Mos   | Mosaic enable |
| D     | CM    | 0=4bpp, 1=8bpp |
| E-F   | Shape | 00=square, 01=wide, 10=tall |

**Attribute 1** (X, size, flip/affine index):

| Bits  | Field      | Description |
|-------|------------|-------------|
| 0-8   | X          | X coordinate (left edge, 9-bit signed) |
| 9-D   | AffineIdx  | Affine matrix index (if affine) |
| C     | HFlip      | Horizontal flip (if regular) |
| D     | VFlip      | Vertical flip (if regular) |
| E-F   | Size       | Size selector (combined with Shape) |

**Attribute 2** (tile, priority, palette bank):

| Bits  | Field | Description |
|-------|-------|-------------|
| 0-9   | TID   | Base tile index (10-bit, always 32-byte steps) |
| A-B   | Prio  | Priority (0=highest, 3=lowest) |
| C-F   | PB    | Palette bank (4bpp only) |

### Sprite Sizes

Shape and Size combine to determine pixel dimensions:

| Shape\Size | 0     | 1     | 2     | 3     |
|------------|-------|-------|-------|-------|
| Square     | 8×8   | 16×16 | 32×32 | 64×64 |
| Wide       | 16×8  | 32×8  | 32×16 | 64×32 |
| Tall       | 8×16  | 8×32  | 16×32 | 32×64 |

### Sprite Mapping Modes

Set by `REG_DISPCNT` bit 6:

- **1D mapping** (bit 6 set): tiles for a sprite are stored consecutively in VRAM. Standard for programming.
- **2D mapping** (bit 6 clear): VRAM is treated as a 256×256 pixel bitmap; each tile-row of a sprite is offset by 32 tiles.

### OAM Double Buffering

OAM is locked during VDraw. The standard practice is to maintain a shadow buffer in RAM, modify it freely, then DMA-copy it to real OAM during VBlank.

```
Pseudocode: OAM double buffer

// In RAM:
OBJ_ATTR obj_buffer[128];

// During game logic:
obj_buffer[n].attr0 = ...;  // modify freely

// During VBlank:
DMA_copy(obj_buffer -> OAM, sizeof(obj_buffer));
```

---

## 5. Tiled Backgrounds

Up to 4 tiled backgrounds, controlled by `REG_BGxCNT` registers at `0400:0008h + 2*x`.

### Background Control Register

| Bits  | Field | Description |
|-------|-------|-------------|
| 0-1   | Prio  | Drawing priority |
| 2-3   | CBB   | Character Base Block (0-3) |
| 6     | Mos   | Mosaic enable |
| 7     | CM    | 0=4bpp, 1=8bpp |
| 8-12  | SBB   | Screen Base Block (0-31) |
| 13    | Wrap  | Affine wrap (no effect on regular) |
| 14-15 | Size  | Map size |

### Regular BG Sizes

| Flag | Tiles  | Pixels   |
|------|--------|----------|
| 00   | 32×32  | 256×256  |
| 01   | 64×32  | 512×256  |
| 10   | 32×64  | 256×512  |
| 11   | 64×64  | 512×512  |

### Screen Entry Format (Regular BG)

Each entry is 16 bits:

| Bits  | Field | Description |
|-------|-------|-------------|
| 0-9   | TID   | Tile index |
| 10    | HFlip | Horizontal flip |
| 11    | VFlip | Vertical flip |
| 12-15 | PB    | Palette bank (4bpp only) |

This is the same bit layout used by the GBA_4BPP format in Tilemap Studio and the `NonAffineTile` struct in gbagfx.

### Multi-Screenblock Layout

Maps larger than 32×32 tiles use multiple screenblocks. They are not linear; they tile in blocks:

```
64×32t: | SBB+0 | SBB+1 |

32×64t: | SBB+0 |
        | SBB+1 |

64×64t: | SBB+0 | SBB+1 |
        | SBB+2 | SBB+3 |
```

To find a screen entry in a multi-screenblock map:

```
Pseudocode: screen entry index

function se_index(tx, ty, pitch):
  sbb = (ty / 32) * (pitch / 32) + (tx / 32)
  return sbb * 1024 + (ty % 32) * 32 + (tx % 32)
```

### Scrolling

`REG_BGxHOFS` and `REG_BGxVOFS` set the **screen's position on the map** (not the map's position on the screen). Increasing HOFS scrolls the map left. These registers are **write-only**.

---

## 6. Windowing

Hardware **windowing** clips or selects where backgrounds and sprites are drawn by dividing the screen into rectangular regions. This is separate from sprite/BG priority ordering. Summary based on [gbadev.net/gbadoc/windowing](https://gbadev.net/gbadoc/windowing.html).

### Window Types

| Window | How it is defined |
|--------|-------------------|
| **WIN0** | Horizontal/vertical bounds in dedicated registers (see below). Enabled via `REG_DISPCNT`. |
| **WIN1** | Same as WIN0, independent second rectangle. |
| **OBJ window** | Pixels covered by sprites whose **gfx mode** is “object window” (`attr0` bits A–B = `10`). Those sprites are not drawn normally; they define a mask region. |
| **Outside (WINOUT)** | Everything **not** covered by the active rectangle windows, per the rules below—not a fourth hardware rectangle, but a logical region controlled by `REG_WINOUT`. |

### Position Registers (I/O offsets from `0400:0000h`)

| Offset | Register | Contents |
|--------|----------|----------|
| `0x40` | `REG_WIN0H` | WIN0 left and right X (inclusive left, exclusive right—see below) |
| `0x42` | `REG_WIN1H` | WIN1 horizontal bounds |
| `0x44` | `REG_WIN0V` | WIN0 top and bottom Y |
| `0x46` | `REG_WIN1V` | WIN1 vertical bounds |
| `0x48` | `REG_WININ` | Which layers are visible **inside** WIN0 and WIN1 (per halfword fields) |
| `0x4A` | `REG_WINOUT` | Which layers are visible **outside** the windows (see below) |

### Boundary Semantics

- For WIN0 and WIN1, the window is the rectangle from the **left/top** boundary **up to but not including** the **right/bottom** boundary (standard half-open interval).
- **Priority overlap:** Everything in WIN0 is considered “above” WIN1. Everything in WIN0 or WIN1 is above regions controlled only by WINOUT and the OBJ window.
- **DISPCNT still wins:** If a background or OBJ layer is disabled in `REG_DISPCNT`, it does not appear in **any** window, regardless of `WININ` / `WINOUT`.
- **WINOUT scope:**
  - If **one** rectangle window is enabled, `REG_WINOUT` applies to everything **outside** that window.
  - If **both** WIN0 and WIN1 are enabled, `REG_WINOUT` applies to pixels that are in **neither** WIN0 nor WIN1 (logical `(!WIN0) && (!WIN1)`).
- **Empty window:** If a window is enabled but the effective “display this layer” bits for that zone are all clear, the **backdrop** color is shown.
- **Inverted bounds (hardware quirk):** If the left coordinate is **greater than** the right, the window is drawn in the **two** side regions (left of “right” and right of “left”), not the strip between them. If top **>** bottom, similarly the window splits to the **top and bottom** bands. A fully inverted configuration can produce an “outside a + shape” region.

### Per-Scanline Effects

The window registers define **axis-aligned rectangles**, but games often change `WIN0H` / `WIN0V` (or others) **each scanline** via HDMA or H-blank interrupts to fake circles, cones, or “lantern” lighting—effects noted in the [gbadoc windowing page](https://gbadev.net/gbadoc/windowing.html).

```
Pseudocode: logical “where does WINOUT apply?” (both rectangle windows on)

for each pixel (x, y):
  in0 = win0_contains(x, y)   // half-open rect per WIN0H/WIN0V
  in1 = win1_contains(x, y)
  if in0:
    apply WININ fields for WIN0
  else if in1:
    apply WININ fields for WIN1
  else:
    apply REG_WINOUT   // “outside” both
  // OBJ window is combined per hardware rules with these regions
```

---

## 7. pokeemerald Sprite Engine

Source: [`src/sprite.c`](https://github.com/pret/pokeemerald/blob/master/src/sprite.c)

The pokeemerald sprite engine is a high-level system that sits between game logic and OAM hardware. It manages up to 128 sprite slots (`gSprites[]`), 32 affine matrices, tile/palette allocation, frame animation, affine animation, priority sorting, and double-buffered OAM output.

### Sprite Lifecycle

```
Pseudocode: sprite lifecycle

1. Load resources:
   LoadSpriteSheet(sheet)     // tiles → VRAM
   LoadSpritePalette(palette) // colors → sprite palette RAM

2. Create:
   id = CreateSprite(template, x, y, subpriority)
   // Allocates slot, sets OAM from template, resolves tile/palette tags

3. Per frame:
   AnimateSprites()   // calls each sprite's callback, then advances animation
   BuildOamBuffer()   // sorts sprites, writes shadow OAM buffer
   // During VBlank:
   LoadOam()                   // DMA shadow buffer → hardware OAM
   ProcessSpriteCopyRequests() // DMA queued tile data → VRAM

4. Destroy:
   DestroySprite(sprite)                // frees slot + tiles (if non-sheet)
   DestroySpriteAndFreeResources(sprite) // also frees tile tag, palette tag, matrix
```

### Tile Management

Sprite tiles are tracked with a 1024-bit bitmap (`sSpriteTileAllocBitmap`). Each bit represents one 32-byte tile slot. Named tile ranges are associated with **tags** (16-bit identifiers) so multiple sprites can share one loaded tileset.

- **Sheet mode** (`tileTag != TAG_NONE`): Tiles are pre-loaded via `LoadSpriteSheet`. The sprite's `sheetTileStart` points into the shared sheet; animation offsets from there.
- **Image mode** (`tileTag == TAG_NONE`): Each sprite allocates its own tile block. On each animation frame change, `RequestSpriteFrameImageCopy` queues a DMA to copy that frame's pixel data into the sprite's VRAM tiles during VBlank.

### Frame Animation

Animation commands are stored as `AnimCmd` arrays:

| Command | Behavior |
|---------|----------|
| `frame` | Display image N for D frames, with optional h/v flip |
| `end`   | Stop animating (stay on last frame) |
| `jump`  | Jump to command index N (for looping) |
| `loop`  | Repeat previous commands N times |

```
Pseudocode: animation tick

function ContinueAnim(sprite):
  if sprite.animDelayCounter > 0:
    sprite.animDelayCounter--
    return
  sprite.animCmdIndex++
  cmd = sprite.anims[sprite.animNum][sprite.animCmdIndex]
  switch cmd.type:
    case FRAME: set tile offset, flip bits, delay counter
    case END:   mark animEnded
    case JUMP:  set animCmdIndex = target, apply that frame
    case LOOP:  repeat block N times
```

### Per-Frame Pipeline

`BuildOamBuffer` runs every frame after game logic:

1. **UpdateOamCoords** — Computes `oam.x` and `oam.y` from `sprite.x + x2 + centerToCornerVecX` (plus global camera offset if `coordOffsetEnabled`).
2. **BuildSpritePriorities** — Packs `oam.priority` (high byte) and `subpriority` (low byte) into a 16-bit sort key.
3. **SortSprites** — Insertion sort by priority, then by Y position (lower Y drawn later = on top). Handles Y-wrapping.
4. **AddSpritesToOamBuffer** — Writes each visible sprite's OAM data into the shadow buffer. Supports **subsprites** (composite sprites built from multiple OAM entries). Unused slots filled with hidden dummy entries.
5. **CopyMatricesToOamBuffer** — Weaves 32 affine matrices into the shadow buffer's filler halfwords (the hardware interleave between `OBJ_ATTR` and `OBJ_AFFINE`).

### Palette Management

16 sprite palette banks tracked by tag. `LoadSpritePalette` finds a free slot, registers the tag, and DMA-copies 16 colors to `0500:0200h + slot * 32`. `IndexOfSpritePaletteTag` looks up a tag to get the bank index for `oam.paletteNum`.

### Subsprites

For composite sprites (e.g., large Pokémon that exceed 64×64, or sprites needing per-component priority), a `SubspriteTable` splits one logical sprite into multiple OAM entries, each with its own shape, size, tile offset, and position offset.

---

## 8. gbagfx Conversion Tool

Source: `tools/gbagfx/` in the pokeemerald/pokefirered repository.

`gbagfx` is a command-line tool that converts between GBA-native binary formats and PNG. It determines the operation from the input/output file extensions.

### Supported Conversions

| Input      | Output    | Operation |
|------------|-----------|-----------|
| `.4bpp`    | `.png`    | GBA 4bpp tiles → PNG |
| `.8bpp`    | `.png`    | GBA 8bpp tiles → PNG |
| `.1bpp`    | `.png`    | GBA 1bpp tiles → PNG |
| `.png`     | `.4bpp`   | PNG → GBA 4bpp tiles |
| `.png`     | `.8bpp`   | PNG → GBA 8bpp tiles |
| `.png`     | `.gbapal` | Extract palette from PNG |
| `.png`     | `.pal`    | Extract palette as JASC-PAL |
| `.gbapal`  | `.pal`    | GBA palette → JASC-PAL |
| `.pal`     | `.gbapal` | JASC-PAL → GBA palette |
| `*`        | `.lz`     | LZ77 compress |
| `.lz`      | `*`       | LZ77 decompress |

### Tile Conversion (4bpp)

GBA tiles store pixels in a tiled layout (8×8 blocks), not as a linear bitmap. gbagfx converts between these:

```
Pseudocode: ConvertFromTiles4Bpp (GBA → linear pixels)

for each tile:
  for each row j in 0..7:
    for each byte k in 0..3:       // 4 bytes per row
      srcByte = *src++
      leftPixel  = srcByte & 0x0F  // low nybble
      rightPixel = srcByte >> 4    // high nybble
      write leftPixel, rightPixel to destination at
        destY = (metatileY * metatileH + subTileY) * 8 + j
        destX = (metatileX * metatileW + subTileX) * 4 + k
  advance metatile position
```

The reverse (`ConvertToTiles4Bpp`) reads from the linear buffer and packs back into GBA nybble order (right pixel in high nybble, left in low).

### Metatile Traversal

Tiles are arranged in metatile order. `AdvanceMetatilePosition` walks: sub-tile X → sub-tile Y → metatile X → metatile Y. This handles both simple tile grids and larger metatile arrangements (e.g., 2×2 metatiles for 16×16 sprites).

### Palette I/O

- **`.gbapal`** — Raw binary, 2 bytes per color (little-endian BGR555). `ReadGbaPalette` upconverts 5-bit→8-bit. `WriteGbaPalette` downconverts 8-bit→5-bit.
- **`.pal` (JASC-PAL)** — Text format: `JASC-PAL` header, version `0100`, color count, then `R G B` lines (0-255 per channel, CRLF line endings).

### Plain vs Tiled Images

- **Tiled** (default): Uses `ReadTileImage`/`WriteTileImage`. Data is in 8×8 tile order.
- **Plain** (`-plain` flag): Uses `ReadPlainImage`/`WritePlainImage` with `CopyPlainPixels`. Data is a raw linear bitmap with byte-order reversal per `dataWidth` chunk.

### Tilemap Decoding

When a `-tilemap` file is provided, `ReadTileImage` calls `DecodeTilemap`:

- **Non-affine**: Each 16-bit tilemap entry has a 10-bit tile index, h/v flip flags, and a 4-bit palette number. `DecodeNonAffineTilemap` copies tiles by index, applies `HflipTile`/`VflipTile`, and can promote 4bpp to 8bpp with embedded palette numbers.
- **Affine**: Each byte is a simple tile index. `DecodeAffineTilemap` copies tiles by index with no flipping.

### CLI Options (GBA→PNG)

| Flag | Description |
|------|-------------|
| `-palette PATH` | External palette file (.gbapal or .pal) |
| `-object` | Mark palette index 0 as transparent |
| `-width N` | Width in tiles |
| `-mwidth N` | Metatile width |
| `-mheight N` | Metatile height |
| `-tilemap PATH` | Tilemap binary file |
| `-affine` | Tilemap is affine format |
| `-plain` | Non-tiled, linear image |
| `-data_width N` | Byte-swap chunk size for plain images |

### CLI Options (PNG→GBA)

| Flag | Description |
|------|-------------|
| `-num_tiles N` | Limit output tile count |
| `-Wnum_tiles` | Warn if extra tiles are non-empty |
| `-Werror=num_tiles` | Error if extra tiles are non-empty |
| `-mwidth N` / `-mheight N` | Metatile dimensions |
| `-plain` / `-data_width N` | Non-tiled mode |

---

## 9. Tilemap Studio

Source: [github.com/Rangi42/tilemap-studio](https://github.com/Rangi42/tilemap-studio)

Tilemap Studio is a GUI tilemap editor (C++/FLTK) supporting Game Boy, GBC, GBA, NDS, SNES, Genesis, and TG16 formats. It reads/writes binary tilemap files and displays them using loaded tileset graphics.

### GBA Formats

Two GBA tilemap formats, both using `.bin` files with 2 bytes per entry:

**GBA_4BPP:**
- 10-bit tile index (0-1023)
- H-flip, V-flip flags
- 4-bit palette bank (0-15)
- 16 palette banks of 16 colors each

**GBA_8BPP:**
- 10-bit tile index (0-1023)
- H-flip, V-flip flags
- No palette bank (single 256-color palette)

```
Pseudocode: GBA tilemap entry layout (both formats)

Byte 0 (low):  tile_index[7:0]
Byte 1 (high): [palette:4][vflip:1][hflip:1][tile_index[9:8]]
```

### Reading Tilemap Binaries

`make_tiles` in `tilemap.cpp` parses the raw bytes:

```
Pseudocode: reading GBA_4BPP entries

for i = 0 to file_size step 2:
  lo = bytes[i]
  hi = bytes[i+1]
  tile_index = lo | ((hi & 0x03) << 8)
  x_flip = (hi & 0x04) != 0
  y_flip = (hi & 0x08) != 0
  palette = hi >> 4
  create Tile_Tessera(tile_index, x_flip, y_flip, palette)
```

### Writing Tilemap Binaries

`make_tilemap_bytes` in `tilemap-format.cpp` packs back:

```
Pseudocode: writing GBA_4BPP entries

for each tile_tessera:
  lo = tile_id & 0xFF
  hi = (tile_id >> 8) & 0x03
  if x_flip: hi |= 0x04
  if y_flip: hi |= 0x08
  hi |= (palette << 4) & 0xF0
  output lo, hi
```

### Tileset Loading

Tilesets provide the visual data. Tilemap Studio loads:

- **`.4bpp`** — 32 bytes/tile, nybble-pair pixels → 16-shade grayscale display.
- **`.8bpp`** — 64 bytes/tile, byte pixels → inverted grayscale display.
- **`.png` / `.bmp` / `.gif`** — Standard image formats (dimensions must be multiples of 8).
- **`.1bpp.lz` / `.2bpp.lz`** — Game Boy LZ-compressed tilesets (pokécrystal format, not GBA BIOS LZ77).

### Tile Matching

`are_identical_tiles` in `tile.cpp` compares two 8×8 tiles pixel-by-pixel, optionally checking all four flip combinations (identity, h-flip, v-flip, both). Color channels are rounded to 5-bit precision before comparison to match GBA's BGR555 space.

### Width Guessing

When opening a tilemap without explicit dimensions, `guess_width` heuristically tries:
1. 30 tiles (GBA screen: 240px / 8)
2. 32 tiles (GBA VRAM width: 256px / 8)
3. 20 tiles (Game Boy width)
4. 64 tiles
5. Square root of tile count
6. Fallback: 16

### Export Formats

`export_tiles` can write tilemap data as:

- **`.bin`** — Raw binary (same as `write_tiles`)
- **`.csv`** — Comma-separated byte values, one row per tilemap row
- **`.c` / `.h`** — C array: `unsigned char name_tilemap[] = { 0xNN, ... };`
- **`.s` / `.asm`** — Assembly: `name_Tilemap:: db $NN, ...` with `name_LEN EQU N`

---

## 10. LZ Compression

gbagfx implements GBA BIOS LZ77 compression (type `0x10`).

### Format

**Header** (4 bytes):
- Byte 0: `0x10` (type tag)
- Bytes 1-3: uncompressed size (24-bit little-endian)

**Data**: groups of 8 blocks, each group preceded by a flags byte. Each flag bit (MSB first):
- `0` = literal: copy 1 byte directly
- `1` = back-reference: 2 bytes encoding length and distance

```
Back-reference encoding:
  Byte 0: [length-3 : 4 bits][distance_high : 4 bits]
  Byte 1: [distance_low : 8 bits]

  length:   3 to 18 bytes
  distance: 1 to 4096 bytes back
```

### Decompression (`LZDecompress`)

```
Pseudocode:

dest_size = header bytes 1-3
src_pos = 4
dest_pos = 0

loop:
  flags = src[src_pos++]
  for i in 0..7:
    if flags & 0x80:
      // back-reference
      length   = (src[src_pos] >> 4) + 3
      distance = ((src[src_pos] & 0x0F) << 8 | src[src_pos+1]) + 1
      src_pos += 2
      copy length bytes from dest[dest_pos - distance]
    else:
      // literal
      dest[dest_pos++] = src[src_pos++]
    if dest_pos == dest_size: return
    flags <<= 1
```

### Compression (`LZCompress`)

Greedy encoder. For each position, scans backward from `minDistance` up to 4096 bytes looking for the longest match (up to 18 bytes). If a match ≥3 is found, emits a back-reference; otherwise emits a literal. Output is padded to a 4-byte boundary.

`minDistance` defaults to 2 for compatibility with `LZ77UnCompVram` (the GBA BIOS function reads 2 bytes at a time and can't handle distance-1 references). The `-search` CLI flag overrides this.

### Overflow Quirk

The `-overflow N` option pads the input with N zero bytes before compressing, then patches the header back to the original size. This reproduces a quirk in some Ruby/Sapphire tilesets where decompression intentionally overflows.

---

## 11. Affine Transforms

Affine sprites and backgrounds use a 2×2 matrix for rotation, scaling, and shearing. The matrix maps **screen space to texture space** (not the other way around).

### Hardware Affine Matrices

The GBA has 32 affine matrices shared among all affine sprites. Each matrix has four 8.8 fixed-point parameters (pa, pb, pc, pd) stored in the OAM filler bytes:

```
| pa pb |   maps screen pixel (sx, sy) to texture pixel (tx, ty):
| pc pd |   tx = pa * sx + pb * sy
            ty = pc * sx + pd * sy
```

The identity matrix is `pa=0x100, pb=0, pc=0, pd=0x100` (scale = 1.0).

### pokeemerald Affine Animation

Each affine sprite can run an affine animation that modifies xScale, yScale, and rotation over time. State is tracked per-matrix in `sAffineAnimStates[]`.

Commands:
- **frame**: If duration=0, set absolute scale/rotation. If duration>0, accumulate relative deltas each tick.
- **end**: Stop animating.
- **jump**: Jump to a command index.
- **loop**: Repeat a block N times.

Each tick, `ApplyAffineAnimFrameRelativeAndUpdateMatrix` accumulates the deltas, converts scale to the BIOS reciprocal format (`0x10000 / scale`), calls `ObjAffineSet` to build the 2×2 matrix from scale + rotation, and writes it to `gOamMatrices[]`.

### Affine Backgrounds

Affine backgrounds use a different tilemap format (1 byte per entry = 8-bit tile index, no flip flags) and support rotation, scaling, and wrapping. Regular backgrounds cannot use affine transforms.

### Affine Tilemaps in gbagfx

When gbagfx receives `-affine`, it treats the tilemap as a byte array of tile indices. `DecodeAffineTilemap` simply copies tiles by index:

```
Pseudocode: DecodeAffineTilemap

for i in 0..numTiles:
  memcpy(output[i], input[tilemap[i]], tileSize)
```

No flip flags exist in affine tilemaps. Affine maps are always 8bpp.

---

## 12. Glossary of Key Terms

| Term | Definition |
|------|------------|
| **4bpp** | 4 bits per pixel. 16 colors per palette bank. 32 bytes per tile. Also called s-tile. |
| **8bpp** | 8 bits per pixel. 256 colors, one palette. 64 bytes per tile. Also called d-tile. |
| **BGR555** | GBA color format: 5 bits each for blue, green, red, packed into 16 bits. |
| **Charblock (CBB)** | A 16 KiB block of VRAM holding tile graphics. 512 s-tiles or 256 d-tiles each. |
| **Color keying** | Pixel value 0 is transparent (not rendered). |
| **d-tile** | Double-size tile (8bpp, 64 bytes). |
| **Metatile** | A group of tiles treated as one unit (e.g., 2×2 tiles = 16×16 pixel metatile). |
| **OAM** | Object Attribute Memory (`0700:0000h`). 128 sprite entries × 8 bytes. |
| **OBJ_ATTR** | One sprite's three 16-bit attributes in OAM. |
| **OBJ_AFFINE** | One 2×2 affine matrix (pa, pb, pc, pd) interleaved in OAM's filler bytes. |
| **Palette bank** | One of 16 sub-palettes (16 colors each) within a 256-color palette. Used in 4bpp mode. |
| **Screen entry (SE)** | One entry in a tilemap screenblock (16 bits for regular BG: tile index + flip + palette). |
| **Screenblock (SBB)** | A 2 KiB block of VRAM holding 32×32 screen entries (one tilemap page). |
| **s-tile** | Single-size tile (4bpp, 32 bytes). |
| **Sprite sheet** | A pre-loaded set of tiles in VRAM shared by multiple sprites via tag lookup. |
| **Subsprite** | One OAM entry within a composite sprite built from a SubspriteTable. |
| **Tag** | A 16-bit identifier used by pokeemerald to name tile ranges and palette banks for lookup. |
| **Tile** | An 8×8 pixel bitmap. The fundamental unit of GBA tiled graphics. |
| **Tilemap** | A grid of screen entries describing which tile goes at each position. |
| **Tileset** | The collection of unique tiles available for a tilemap or sprite. |
| **VRAM** | Video RAM. 96 KiB at `0600:0000h`. Holds tile graphics and tilemaps. |
| **VBlank** | The vertical blanking interval between frames. Safe time to update OAM and VRAM. |
| **VDraw** | The active drawing period. OAM is locked; don't write to it. |
| **1D mapping** | Sprite tiles stored consecutively in VRAM. Set by `REG_DISPCNT` bit 6. |
| **2D mapping** | Sprite tiles arranged as a 256×256 pixel bitmap in VRAM. Default mode. |
| **LZ77** | Lempel-Ziv sliding window compression. GBA BIOS type `0x10`. |
| **JASC-PAL** | Paint Shop Pro text palette format. Header `JASC-PAL`, then `R G B` lines. |
| **`.gbapal`** | Raw GBA palette file. Sequence of 16-bit little-endian BGR555 values. |
| **Backdrop** | The solid background color shown when no BG/sprite pixel wins; also used when a window is on but no layers are enabled for that region. |
| **OBJ window** | A window region defined by sprites in **object window** gfx mode (`attr0` A–B = `10`); those sprites act as a mask, not normal pixels. |
| **Outside window (WINOUT)** | The screen area not covered by WIN0/WIN1 (per `REG_WINOUT` rules); controlled by `REG_WINOUT`. |
| **WIN0 / WIN1** | Two programmable rectangular windows; bounds in `REG_WIN0H/V`, `REG_WIN1H/V`. WIN0 draws “above” WIN1. |
| **WININ** | `REG_WININ` (`0400:0048h`): per-layer visibility **inside** WIN0 and WIN1. |
| **WINOUT** | `REG_WINOUT` (`0400:004Ah`): per-layer visibility **outside** the enabled rectangle window(s). |
| **Windowing** | Hardware clipping/masking of BG and OBJ layers using WIN0, WIN1, OBJ window, and WINOUT. |

---

## 13. Function Glossary: pokeemerald sprite.c

### Lifecycle

| Function | Description |
|----------|-------------|
| `ResetSpriteData` | Full engine reset: clear OAM, sprites, affine data, tile ranges. |
| `CreateSprite` | Find free slot, create sprite from template. Returns slot index. |
| `CreateSpriteAtEnd` | Same, searching from last slot backward. |
| `CreateSpriteAt` | Construct sprite at specific index: set OAM, alloc tiles, resolve tags. |
| `CreateSpriteAndAnimate` | Create + immediately run one callback + animation tick. |
| `CreateInvisibleSprite` | Create hidden sprite with custom callback (logic-only). |
| `DestroySprite` | Free tiles (if non-sheet), reset slot. |
| `DestroySpriteAndFreeResources` | Free tiles, palette, matrix, then destroy. |
| `ResetSprite` | Reset a single slot to the dummy sprite. |
| `ResetAllSprites` | Reset all 128 slots and reinitialize sort order. |

### Per-Frame Pipeline

| Function | Description |
|----------|-------------|
| `AnimateSprites` | Call each sprite's callback, then `AnimateSprite`. |
| `BuildOamBuffer` | Coord update → priority build → sort → write shadow OAM. |
| `UpdateOamCoords` | Compute `oam.x/y` from sprite position + offsets. |
| `BuildSpritePriorities` | Pack priority + subpriority into sort key. |
| `SortSprites` | Insertion sort by priority, then Y. |
| `AddSpritesToOamBuffer` | Write sorted sprites into shadow buffer; fill unused with dummy. |
| `CopyMatricesToOamBuffer` | Weave affine matrices into shadow buffer. |
| `LoadOam` | DMA shadow buffer → hardware OAM. |
| `ProcessSpriteCopyRequests` | DMA queued tile data → VRAM (for non-sheet animation). |

### Animation

| Function | Description |
|----------|-------------|
| `AnimateSprite` | Dispatch to frame anim + affine anim functions. |
| `BeginAnim` | Reset counters, apply first frame. |
| `ContinueAnim` | Decrement delay; on expiry, advance to next command. |
| `AnimCmd_frame` | Set tile offset, flip, delay for current frame. |
| `AnimCmd_end` | Mark animation ended. |
| `AnimCmd_jump` | Jump to a command index. |
| `AnimCmd_loop` | Repeat block N times. |
| `StartSpriteAnim` | Set animation number, flag restart. |
| `StartSpriteAnimIfDifferent` | Only restart if animNum changed. |
| `SeekSpriteAnim` | Jump to specific command index mid-animation. |
| `SetSpriteSheetFrameTileNum` | Update `oam.tileNum` for sheet sprites. |

### Tile Management

| Function | Description |
|----------|-------------|
| `AllocSpriteTiles` | First-fit allocate N contiguous tiles. Returns start index. |
| `LoadSpriteSheet` | Alloc tiles + DMA sheet data → VRAM. Register tag. |
| `LoadSpriteSheets` | Load null-terminated array of sheets. |
| `FreeSpriteTilesByTag` | Free tiles and clear tag entry. |
| `FreeSpriteTileRanges` | Clear all tag-to-range mappings. |
| `GetSpriteTileStartByTag` | Look up tile start index by tag. |
| `AllocSpriteTileRange` | Register (tag, start, count) in range table. |

### Palette Management

| Function | Description |
|----------|-------------|
| `LoadSpritePalette` | Find free bank, register tag, load 16 colors. |
| `LoadSpritePalettes` | Load null-terminated array. |
| `AllocSpritePalette` | Reserve bank by tag without loading data. |
| `FreeSpritePaletteByTag` | Clear tag, freeing the bank. |
| `FreeAllSpritePalettes` | Reset all 16 palette tag slots. |
| `IndexOfSpritePaletteTag` | Find bank index (0-15) for a tag. |

### Matrix Management

| Function | Description |
|----------|-------------|
| `AllocOamMatrix` | Claim first free matrix (0-31). |
| `FreeOamMatrix` | Release matrix, reset to identity. |
| `SetOamMatrix` | Set pa, pb, pc, pd directly. |
| `ResetOamMatrices` | Set all 32 matrices to identity. |
| `CopyOamMatrix` | Copy OamMatrix struct into global array. |

### Affine Animation

| Function | Description |
|----------|-------------|
| `InitSpriteAffineAnim` | Alloc matrix, set center-to-corner, flag start. |
| `BeginAffineAnim` | Reset state, apply first affine frame. |
| `ContinueAffineAnim` | Decrement delay; on expiry, advance command. |
| `AffineAnimCmd_frame` | Apply scale/rotation frame (absolute or relative). |
| `AffineAnimCmd_end` | Mark affine animation ended. |
| `AffineAnimCmd_jump` | Jump to affine command index. |
| `AffineAnimCmd_loop` | Repeat affine block N times. |
| `StartSpriteAffineAnim` | Set affine anim number, flag restart. |
| `SetOamMatrixRotationScaling` | Set matrix from xScale, yScale, rotation directly. |
| `SetSpriteMatrixAnchor` | Set pivot point for anchored scaling. |

### Subsprites & Misc

| Function | Description |
|----------|-------------|
| `SetSubspriteTables` | Assign subsprite table to a sprite. |
| `AddSpriteToOamBuffer` | Write one sprite (or its subsprites) to shadow OAM. |
| `AddSubspritesToOamBuffer` | Expand subsprite table into multiple OAM entries. |
| `CalcCenterToCornerVec` | Look up half-size offset for shape+size. |
| `SetSpriteOamFlipBits` | Encode h/v flip into matrixNum bits 3-4. |
| `CopyFromSprites` / `CopyToSprites` | Serialize/deserialize sprite array. |
| `ResetOamRange` | Fill OAM range with hidden dummy entries. |
| `SpriteCallbackDummy` | Empty callback (no-op). |

---

## 14. Function Glossary: gbagfx

### PNG I/O (`convert_png.c`)

| Function | Description |
|----------|-------------|
| `ReadPng` | Read PNG into Image struct (grayscale or paletted). Convert bit depth if needed. |
| `WritePng` | Write Image to PNG. Set color type, palette, optional tRNS transparency chunk. |
| `ReadPngPalette` | Read only the PLTE chunk from a PNG into a Palette struct. |
| `SetPngPalette` | Write Palette to a PNG write struct via `png_set_PLTE`. |
| `ConvertBitDepth` | Repack pixel data between bit depths (1/2/4/8). |

### Tile Conversion (`gfx.c`)

| Function | Description |
|----------|-------------|
| `ConvertFromTiles4Bpp` | GBA 4bpp tile data → linear pixel buffer. |
| `ConvertToTiles4Bpp` | Linear pixel buffer → GBA 4bpp tile data. |
| `ConvertFromTiles8Bpp` | GBA 8bpp tile data → linear pixel buffer. |
| `ConvertToTiles8Bpp` | Linear pixel buffer → GBA 8bpp tile data. |
| `ConvertFromTiles1Bpp` | GBA 1bpp tile data → linear pixel buffer. |
| `ConvertToTiles1Bpp` | Linear pixel buffer → GBA 1bpp tile data. |
| `CopyPlainPixels` | Copy non-tiled pixel data with byte-order reversal and optional inversion. |
| `AdvanceMetatilePosition` | Walk sub-tile X → sub-tile Y → metatile X → metatile Y. |

### Image I/O (`gfx.c`)

| Function | Description |
|----------|-------------|
| `ReadTileImage` | Read raw tile file, optionally decode tilemap, convert to linear pixels. |
| `WriteTileImage` | Convert linear pixels to tiles, validate tile count, write to file. |
| `ReadPlainImage` | Read raw non-tiled image via `CopyPlainPixels`. |
| `WritePlainImage` | Write non-tiled image via `CopyPlainPixels`. |
| `FreeImage` | Free pixel buffer and tilemap data. |

### Palette I/O (`gfx.c`, `jasc_pal.c`)

| Function | Description |
|----------|-------------|
| `ReadGbaPalette` | Read `.gbapal` binary (BGR555 le) → Palette struct (8-bit RGB). |
| `WriteGbaPalette` | Write Palette struct → `.gbapal` binary (BGR555 le). |
| `ReadJascPalette` | Parse JASC-PAL text file → Palette struct. |
| `WriteJascPalette` | Write Palette struct → JASC-PAL text file. |

### Tilemap Decoding (`gfx.c`)

| Function | Description |
|----------|-------------|
| `DecodeTilemap` | Dispatch to affine or non-affine decoder. |
| `DecodeAffineTilemap` | Copy tiles by 8-bit index (no flip). |
| `DecodeNonAffineTilemap` | Copy tiles by 10-bit index, apply h/v flip, embed palette in 8bpp promotion. |
| `HflipTile` | Flip tile data horizontally in-place (1/4/8bpp). |
| `VflipTile` | Flip tile data vertically in-place (1/4/8bpp). |

### LZ Compression (`lz.c`)

| Function | Description |
|----------|-------------|
| `LZDecompress` | Decompress GBA BIOS LZ77 (type 0x10). |
| `LZCompress` | Greedy LZ77 compress with configurable min search distance. |

### CLI Handlers (`main.c`)

| Function | Description |
|----------|-------------|
| `HandleGbaToPngCommand` | Parse options, call `ConvertGbaToPng`. |
| `HandlePngToGbaCommand` | Parse options, call `ConvertPngToGba`. |
| `HandleLZCompressCommand` | Read file, compress, optionally apply overflow quirk. |
| `HandleLZDecompressCommand` | Read file, decompress, write output. |
| `ConvertGbaToPng` | High-level: load palette → read tiles → decode tilemap → write PNG. |
| `ConvertPngToGba` | High-level: read PNG → convert bit depth → write tiles. |

---

## 15. Function Glossary: Tilemap Studio

### Tilemap I/O (`tilemap.cpp`)

| Function | Description |
|----------|-------------|
| `make_tiles` | Parse raw bytes into `Tile_Tessera` objects based on current format (GBA_4BPP, GBA_8BPP, etc.). |
| `read_tiles` | Read binary tilemap file, call `make_tiles`. |
| `write_tiles` | Serialize tiles via `make_tilemap_bytes`, write to binary file. |
| `export_tiles` | Write tilemap as `.csv`, `.c`, or `.asm` file. |
| `guess_width` | Heuristically determine map width from tile count. |

### Format Properties (`tilemap-format.cpp`)

| Function | Description |
|----------|-------------|
| `format_tileset_size` | Max tile IDs for a format (1024 for GBA). |
| `format_palettes_size` | Number of palette banks (16 for GBA_4BPP, 1 for GBA_8BPP). |
| `format_palette_size` | Colors per palette (16 for GBA_4BPP, 256 for GBA_8BPP). |
| `format_color_depth` | Bit depth (4 or 8 for GBA). |
| `format_bytes_per_tile` | Bytes per tilemap entry (2 for GBA). |
| `format_can_flip` | Whether format supports h/v flip (yes for GBA). |
| `guess_format` | Auto-detect format from file size and name. |
| `make_tilemap_bytes` | Serialize `Tile_Tessera` vector to raw bytes for a given format. |

### Tileset Loading (`tileset.cpp`)

| Function | Description |
|----------|-------------|
| `read_tiles` (Tileset) | Dispatch to format-specific reader by extension. |
| `read_4bpp_graphics` | Read raw `.4bpp` file, call `parse_4bpp_data`. |
| `read_8bpp_graphics` | Read raw `.8bpp` file, call `parse_8bpp_data`. |
| `read_png_graphics` | Load PNG via FLTK. |
| `parse_4bpp_data` | Decode 4bpp tiles to grayscale image for display. |
| `parse_8bpp_data` | Decode 8bpp tiles to inverted grayscale image. |
| `postprocess_graphics` | Create 1x, 2x, zoomed copies; validate tile grid alignment. |

### Tile Operations (`tile.cpp`)

| Function | Description |
|----------|-------------|
| `are_identical_tiles` | Compare two 8×8 tiles, optionally checking all flip combinations. |
| `get_image_tiles` | Slice an image into 8×8 tile array with 5-bit color rounding. |

### Tilemap Operations (`tilemap.cpp`)

| Function | Description |
|----------|-------------|
| `resize` | Resize tilemap, preserving existing tiles at offset. |
| `shift` | Wrap-shift all tiles by (dx, dy). |
| `transpose` | Swap rows and columns. |
| `can_format_as` | Check if all tiles fit within a format's constraints. |
| `limit_to_format` | Clamp tile IDs, palette, flip to format limits. |
| `remember` / `undo` / `redo` | Tilemap state history for undo/redo. |

### Export Helpers (`tilemap.cpp`)

| Function | Description |
|----------|-------------|
| `export_c_tiles` | Write tilemap as C array with header comment. |
| `export_asm_tiles` | Write tilemap as assembly `db` directives with label. |
| `export_csv_tiles` | Write tilemap as comma-separated decimal values. |
