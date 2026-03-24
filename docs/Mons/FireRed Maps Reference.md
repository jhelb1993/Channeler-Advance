# Pokemon FireRed Map System Reference

A comprehensive reference for how maps work in Pokemon FireRed/LeafGreen, covering the conceptual model, binary data layout, the pokefirered decomp's C implementation, and how HexManiac Advance (HMA) interprets and edits the same data.

---

## Table of Contents

1. [Conceptual Overview](#1-conceptual-overview)
2. [Data Hierarchy](#2-data-hierarchy)
3. [Metatiles and Tilesets](#3-metatiles-and-tilesets)
4. [The Blockmap](#4-the-blockmap)
5. [Border Blocks](#5-border-blocks)
6. [Map Events](#6-map-events)
7. [Map Connections](#7-map-connections)
8. [The Map Header](#8-the-map-header)
9. [The Layout Table and Layout ID](#9-the-layout-table-and-layout-id)
10. [Map Banks (Groups)](#10-map-banks-groups)
11. [Runtime: How the Game Uses Map Data (pokefirered Detail)](#11-runtime-how-the-game-uses-map-data-pokefirered-detail)
12. [Build Pipeline: JSON to Binary (pokefirered Detail)](#12-build-pipeline-json-to-binary-pokefirered-detail)
13. [HMA: How the Editor Reads and Writes Map Data (Detailed)](#13-hma-how-the-editor-reads-and-writes-map-data-detailed)
14. [Advanced Topics](#14-advanced-topics)
15. [Glossary of Terms](#15-glossary-of-terms)
16. [Function and Constant Reference: pokefirered](#16-function-and-constant-reference-pokefirered)
17. [Class, Field, and Constant Reference: HMA](#17-class-field-and-constant-reference-hma)

---

## 1. Conceptual Overview

A "map" in FireRed is a discrete playable area — a town, a route, a floor of a cave, or the interior of a building. At its core, every map is:

- A **grid of metatiles** (the blockmap) that defines what the player sees and walks on.
- A set of **events** placed on that grid (NPCs, warps, script triggers, signposts).
- A **header** containing metadata (music, weather, map type, region name, flags).
- Optional **connections** to adjacent maps (north/south/east/west, plus dive/emerge).

Maps are organized into **banks** (also called **groups**). A map is uniquely identified by its **(group, map)** pair — e.g., bank 3, map 0.

---

## 2. Data Hierarchy

The full map data tree, from the root table to the leaf data:

```
data.maps.banks                         (array of banks)
 └─ bank[group]                         (array of map slots)
     └─ map[index]                      (pointer to a map record)
         ├─ layout       ──►  MapLayout (width, height, blockmap, border, tilesets)
         ├─ events       ──►  MapEvents (objects, warps, scripts, signposts)
         ├─ mapscripts   ──►  MapScripts (on-load/on-frame scripts)
         ├─ connections   ──►  MapConnections (count + connection list)
         └─ [header fields: music, layoutID, regionSectionID, weather, ...]

data.maps.layouts                       (flat array of layout pointers)
 └─ layout[layoutID - 1]  ──►  same MapLayout struct as above
```

A single `MapLayout` can be **shared** by multiple maps (e.g., identical Pokemon Center interiors). The `layoutID` field on the map header is a **1-based index** into the global layouts table, while the `layout` pointer is the actual address of the layout struct.

---

## 3. Metatiles and Tilesets

### 8×8 Tiles

The GBA's graphics hardware works with **8×8 pixel tiles** stored as 4 bits per pixel (4bpp). These are the atomic graphical units, stored in tileset images.

### Metatiles (Blocks)

A **metatile** (also called a "block" or "metatile block") is a **16×16 pixel** composite made of **8 individual 8×8 tile references** (a 2×2 grid across two layers). Each tile reference specifies:

- Which 8×8 tile index to use
- Which palette to apply
- Horizontal and/or vertical flip

Metatiles are what the player actually sees as the terrain — a patch of grass, a wall segment, a door, a water tile.

### Primary and Secondary Tilesets

Every map layout references **two tilesets**:

| Property | Primary | Secondary |
|----------|---------|-----------|
| Tile indices | 0–639 | 640–1023 |
| Metatile indices | 0–639 | 640–1023 |
| Palette slots | 0–6 (7 palettes) | 7–12 (6 palettes) |

The primary tileset typically contains **shared** tiles used by many maps in a region (general outdoor terrain, generic indoor tiles). The secondary tileset holds **area-specific** tiles (a particular town's unique buildings, a cave's specific rock formations).

### Metatile Attributes

Each metatile has a **32-bit attribute word** that encodes multiple properties:

| Attribute | Bits | Purpose |
|-----------|------|---------|
| Behavior | 0–8 | What happens when the player stands/interacts (grass, water, ledge, door, etc.) |
| Terrain | 9–13 | Normal, grass, water, waterfall |
| Encounter type | 24–26 | None, land, water |
| Layer type | 29–30 | Normal, covered, split (controls which BG layers the metatile occupies) |

### Tileset Struct (C)

```c
struct Tileset {
    bool8 isCompressed;
    bool8 isSecondary;
    const u32 *tiles;           // 8×8 tile graphics (4bpp)
    const u16 (*palettes)[16];  // color palettes
    const u16 *metatiles;       // metatile definitions (tile refs)
    TilesetCB callback;         // animation callback
    const u32 *metatileAttributes;
};
```

---

## 4. The Blockmap

The **blockmap** (also called the **map grid**) is the core of every map's visual and collision data. It is a flat array of **16-bit values**, one per cell, arranged in row-major order (width × height).

### Cell Format

Each 16-bit cell packs three fields:

```
Bits 15 14 13 12 | 11 10 | 9 8 7 6 5 4 3 2 1 0
     [elevation ] | [col] | [  metatile index   ]
```

| Field | Bits | Mask | Shift | Range |
|-------|------|------|-------|-------|
| Metatile ID | 0–9 | `0x03FF` | 0 | 0–1023 |
| Collision | 10–11 | `0x0C00` | 10 | 0–3 |
| Elevation | 12–15 | `0xF000` | 12 | 0–15 |

- **Metatile ID**: indexes into the combined primary+secondary metatile set (0–639 = primary, 640–1023 = secondary).
- **Collision**: 0 = passable, non-zero = impassable. The game typically uses bit 10 as a simple passable/impassable flag.
- **Elevation**: used for elevation-based collision (bridges, multilevel areas).

### Size Limit

The game enforces `(width + 15) × (height + 14) ≤ 0x2800` (10240). This comes from the runtime buffer size (`MAX_MAP_DATA_SIZE`). Typical maximum dimensions: 113×66, 497×6, etc.

### Binary Format

In the ROM and in `data/layouts/*/map.bin`, the blockmap is simply `width × height × 2` bytes of packed 16-bit values, little-endian.

---

## 5. Border Blocks

Every map has a **border** — a small tile pattern that fills the area outside the map's edges (visible when the camera scrolls near an edge that has no connection).

- The border is a small grid of metatile halfwords, typically **2×2** in FireRed (configurable via `borderWidth` / `borderHeight`).
- It tiles/repeats to fill the visible border region.
- On edges that **do** have a connection, the connected map's data replaces the border in the runtime buffer.

---

## 6. Map Events

Events are things placed on the map grid at specific (x, y) coordinates. There are four categories:

### Object Events (NPCs)

People, items on the ground, trainers — anything with a sprite.

```c
struct ObjectEventTemplate {
    u8 localId;
    u8 graphicsId;          // OW sprite index
    u8 kind;                // OBJ_KIND_NORMAL or OBJ_KIND_CLONE
    s16 x, y;
    // For normal objects:
    u8 elevation, movementType;
    u16 movementRangeX:4, movementRangeY:4;
    u16 trainerType, trainerRange_berryTreeId;
    const u8 *script;
    u16 flagId;
    // For clone objects (FRLG only):
    // targetLocalId, targetMapNum, targetMapGroup
};
```

**Clone objects** are a FireRed/LeafGreen feature: an NPC on one map can mirror an NPC from an adjacent map, so the player sees them across map boundaries.

### Warp Events

Teleport the player to another map (doors, stairs, cave entrances).

```c
struct WarpEvent {
    s16 x, y;
    u8 elevation;
    u8 warpId;    // index into target map's warp list
    u8 mapNum;
    u8 mapGroup;
};
```

### Coord Events (Script Triggers)

Invisible triggers that fire a script when stepped on (or set weather).

```c
struct CoordEvent {
    u16 x, y;
    u8 elevation;
    u16 trigger;    // variable to check
    u16 index;      // value to compare
    const u8 *script;
};
```

### Background Events (Signposts / Hidden Items)

Signs the player can read (facing checks), or hidden items found with the Itemfinder.

```c
struct BgEvent {
    u16 x, y;
    u8 elevation;
    u8 kind;
    union {
        const u8 *script;     // for sign types
        u32 hiddenItem;       // packed item/flag/quantity/underfoot
    } bgUnion;
};
```

### Events Container

```c
struct MapEvents {
    u8 objectEventCount;
    u8 warpCount;
    u8 coordEventCount;
    u8 bgEventCount;
    const struct ObjectEventTemplate *objectEvents;
    const struct WarpEvent *warps;
    const struct CoordEvent *coordEvents;
    const struct BgEvent *bgEvents;
};
```

---

## 7. Map Connections

Connections define how maps join at their edges for seamless scrolling.

```c
struct MapConnection {
    u8 direction;   // CONNECTION_SOUTH/NORTH/WEST/EAST/DIVE/EMERGE
    u32 offset;     // tile offset along the shared edge
    u8 mapGroup;
    u8 mapNum;
};

struct MapConnections {
    s32 count;
    const struct MapConnection *connections;
};
```

**Direction values:**

| Value | Name | Meaning |
|-------|------|---------|
| 1 | `CONNECTION_SOUTH` / Down | Map is below |
| 2 | `CONNECTION_NORTH` / Up | Map is above |
| 3 | `CONNECTION_WEST` / Left | Map is to the left |
| 4 | `CONNECTION_EAST` / Right | Map is to the right |
| 5 | `CONNECTION_DIVE` | Underwater map (Dive) |
| 6 | `CONNECTION_EMERGE` | Surface map (Emerge from Dive) |

The **offset** field controls alignment: a positive offset shifts the connected map in the positive axis direction along the shared edge.

---

## 8. The Map Header

The map header ties everything together:

```c
struct MapHeader {
    const struct MapLayout *mapLayout;
    const struct MapEvents *events;
    const u8 *mapScripts;
    const struct MapConnections *connections;
    u16 music;
    u16 mapLayoutId;          // 1-based index into gMapLayouts
    u8 regionMapSectionId;    // +88 offset in FRLG
    u8 cave;
    u8 weather;
    u8 mapType;
    bool8 bikingAllowed;
    bool8 allowEscaping:1;
    bool8 allowRunning:1;
    bool8 showMapName:6;
    s8 floorNum;
    u8 battleType;
};
```

Key points:

- **`mapLayoutId`** is **1-based** (the layouts table is 0-indexed, so the runtime does `gMapLayouts[mapLayoutId - 1]`).
- **`regionMapSectionId`** has a **+88 offset** in FRLG (the first 88 slots are Kanto region names; HMA's format string says `regionSectionID.data.maps.names+88`).
- The **`mapLayout` pointer** and **`mapLayoutId`** can point to different things if the layout was swapped at runtime (e.g., by map scripts), but at compile time they are consistent.

---

## 9. The Layout Table and Layout ID

The **global layouts table** (`gMapLayouts` in C, `data.maps.layouts` in HMA) is a flat array of pointers to `MapLayout` structs.

- **383 entries** in a typical FireRed ROM.
- Indexed by `mapLayoutId - 1` (1-based ID).
- Multiple map headers can reference the same layout (shared interiors).
- The `SetCurrentMapLayout` function can swap the active layout at runtime.

### MapLayout Struct

```c
struct MapLayout {
    s32 width;
    s32 height;
    const u16 *border;            // border metatile grid
    const u16 *map;               // the blockmap
    const struct Tileset *primaryTileset;
    const struct Tileset *secondaryTileset;
    u8 borderWidth;               // FRLG only
    u8 borderHeight;              // FRLG only
};
```

---

## 10. Map Banks (Groups)

Maps are organized into **banks** (called "groups" in the code). A bank is simply an array of map header pointers.

```c
extern const struct MapHeader *const *gMapGroups[];
// Usage: gMapGroups[mapGroup][mapNum]
```

The root table `data.maps.banks` (in HMA) or `gMapGroups` (in C) has a fixed number of banks (43 for FireRed). Each bank has a variable number of maps.

A map is uniquely identified by **(group, map)** — sometimes encoded as a single integer: `group * 1000 + map` (HMA) or `mapNum | (group << 8)` (C constants).

---

## 11. Runtime: How the Game Uses Map Data (pokefirered Detail)

### Map Loading Sequence

When the player enters a new map (warp, connection transition, or new game):

1. **`LoadCurrentMapData()`** / **`LoadSaveblockMapHeader()`**: copy the `MapHeader` from `gMapGroups[group][num]` into the global `gMapHeader`. Save the `mapLayoutId`, then resolve `gMapHeader.mapLayout` via `GetMapLayout()`.

2. **`LoadObjEventTemplatesFromHeader()`**: copy object event templates into the save block. For **clone** objects (`kind == OBJ_KIND_CLONE`), resolve the target map's header via `Overworld_GetMapHeaderByGroupAndId(targetMapGroup, targetMapNum)` and copy the referenced NPC's graphics and position data (adjusted for connection offset).

3. **`SetPlayerCoordsFromWarp()`**: set player position from the target warp's (x, y), or from the explicit (x, y) in the warp data, or fall back to `(width/2, height/2)` as a last resort.

4. **`InitMap()`** → **`InitMapLayoutData()`**:
   - `CpuFastFill16(MAPGRID_UNDEFINED, gBackupMapData, sizeof(gBackupMapData))` — fill the entire 0x2800-halfword buffer with the `0x03FF` sentinel.
   - `VMap.map = gBackupMapData`
   - `VMap.Xsize = mapLayout->width + MAP_OFFSET_W` (width + 15)
   - `VMap.Ysize = mapLayout->height + MAP_OFFSET_H` (height + 14)
   - Assert: `VMap.Xsize * VMap.Ysize <= VIRTUAL_MAP_SIZE`
   - **`InitBackupMapLayoutData()`**: Copy the ROM blockmap into VMap's center. The destination starts at `VMap.map + VMap.Xsize * 7 + MAP_OFFSET` (row 7, column 7). Each row copies `width` halfwords, then advances `width + MAP_OFFSET_W` in the destination (to account for the margin columns).
   - **`InitBackupMapLayoutConnections()`**: for each connection, copy a strip of the neighboring map's blockmap into the appropriate edge of `VMap`.

5. **`InitMapView()`**: `move_tilemap_camera_to_upper_left_corner()`, `CopyMapTilesetsToVram(gMapHeader.mapLayout)`, `LoadMapTilesetPalettes(gMapHeader.mapLayout)`, `DrawWholeMapView()`, `InitTilesetAnimations()`.

### The VMap Buffer

At runtime, the game doesn't read the ROM blockmap directly. Instead, it works with **`VMap`** (`struct BackupMapLayout`) — a RAM buffer that contains:

```
struct BackupMapLayout {
    s32 Xsize;    // width + 15
    s32 Ysize;    // height + 14
    u16 *map;     // -> gBackupMapData[0x2800]
};
```

The buffer layout looks like this (numbers are metatile-space coordinates):

```
         0                          7     7+width         Xsize
    0    ┌──────────────────────────┬──────────────┬────────┐
         │      UNDEFINED           │  UNDEFINED   │ UNDEF  │
    7    ├──────────────────────────┼──────────────┼────────┤
         │ conn strip (west) or     │              │ conn   │
         │ UNDEFINED                │   MAP DATA   │ strip  │
         │                          │   (from ROM) │ (east) │
  7+h    ├──────────────────────────┼──────────────┼────────┤
         │      UNDEFINED or south connection strip          │
  Ysize  └───────────────────────────────────────────────────┘
```

- **Center**: the map's actual blockmap data from ROM.
- **North/South/East/West margins**: filled with connection data by `FillNorthConnection` etc., or left as `MAPGRID_UNDEFINED`.
- **`MAPGRID_UNDEFINED` cells**: when read via `GetMapGridBlockAt`, the `GetBorderBlockAt` macro kicks in — it indexes into `mapLayout->border` using `borderWidth`/`borderHeight` with wrapping, and ORs `MAPGRID_COLLISION_MASK` (making border tiles impassable).

All gameplay queries (`MapGridGetMetatileIdAt`, `MapGridGetCollisionAt`, etc.) go through `GetMapGridBlockAt`, which reads from `VMap.map`.

### Connection Fill Logic

Each `Fill*Connection` function calculates exactly which rectangular region of the neighbor's blockmap to copy and where in VMap it belongs:

**`FillSouthConnection(mapHeader, connectedMapHeader, offset)`**:
- Source: connected map's blockmap, starting at row 0 (its top edge)
- Destination: `VMap` row `(mapLayout->height + MAP_OFFSET)` — just below the main map data
- X positioning: `x = offset + MAP_OFFSET`, clamped to VMap bounds
- Height: `MAP_OFFSET` rows (7 rows of the neighbor visible)

**`FillNorthConnection`**:
- Source: connected map's blockmap, starting at row `(connectedHeight - MAP_OFFSET)` — its bottom edge
- Destination: `VMap` row 0

**`FillWestConnection`**:
- Source: connected map's blockmap, starting at column `(connectedWidth - MAP_OFFSET)` — its right edge
- Destination: `VMap` column 0, width = `MAP_OFFSET` (7 columns)

**`FillEastConnection`**:
- Source: connected map's blockmap, starting at column 0
- Destination: `VMap` column `(mapLayout->width + MAP_OFFSET)`, width = `MAP_OFFSET + 1`

All four clip to VMap bounds and handle negative offsets (where the connected map starts before VMap's origin).

### Reading Cells at Runtime

**`GetMapGridBlockAt(x, y)`** (macro):
1. If `(x >= 0 && x < VMap.Xsize && y >= 0 && y < VMap.Ysize)`: return `VMap.map[x + VMap.Xsize * y]`.
2. Otherwise: return `GetBorderBlockAt(x, y)`.

**`GetBorderBlockAt(x, y)`** (macro):
```c
xprime = (x - MAP_OFFSET + 8 * borderWidth) % borderWidth;
yprime = (y - MAP_OFFSET + 8 * borderHeight) % borderHeight;
block = border[xprime + yprime * borderWidth] | MAPGRID_COLLISION_MASK;
```
The border pattern wraps both horizontally and vertically. Collision bits are forced on (border is always impassable).

**Decoding a cell**: Given a `u16 block` from the grid:
```c
metatileId = block & MAPGRID_METATILE_ID_MASK;    // bits 0-9
collision  = (block & MAPGRID_COLLISION_MASK) >> MAPGRID_COLLISION_SHIFT;  // bits 10-11
elevation  = block >> MAPGRID_ELEVATION_SHIFT;     // bits 12-15
```

### Metatile Attribute Lookup

**`GetAttributeByMetatileIdAndMapLayout(mapLayout, metatileId, attributeType)`**:
```c
if (metatileId < NUM_METATILES_IN_PRIMARY) {       // < 640
    attributes = mapLayout->primaryTileset->metatileAttributes;
    return ExtractMetatileAttribute(attributes[metatileId], attributeType);
} else if (metatileId < NUM_METATILES_TOTAL) {     // < 1024
    attributes = mapLayout->secondaryTileset->metatileAttributes;
    return ExtractMetatileAttribute(attributes[metatileId - NUM_METATILES_IN_PRIMARY], attributeType);
} else {
    return 0xFF;
}
```

The attribute masks are fixed 32-bit patterns applied to each metatile's `u32` attribute word:

```c
sMetatileAttrMasks[METATILE_ATTRIBUTE_BEHAVIOR]       = 0x000001ff;  // bits 0-8
sMetatileAttrMasks[METATILE_ATTRIBUTE_TERRAIN]        = 0x00003e00;  // bits 9-13
sMetatileAttrMasks[METATILE_ATTRIBUTE_ENCOUNTER_TYPE] = 0x07000000;  // bits 24-26
sMetatileAttrMasks[METATILE_ATTRIBUTE_LAYER_TYPE]     = 0x60000000;  // bits 29-30
```

### Camera Transitions

When the camera would move into a connection zone (`CameraMove` → `GetPostCameraMoveMapBorderId`), the game:

1. **`SaveMapView()`** — persist the current 15×14 block window around the player into `gSaveBlock2Ptr->mapView`.
2. **`GetIncomingConnection(direction, x, y)`** — iterate connections, find one matching the direction where the player's position falls within the connected map's range.
3. **`SetPositionFromConnection(connection, direction, x, y)`** — adjust `gSaveBlock1Ptr->pos` based on connection offset and the connected map's dimensions.
4. **`LoadMapFromCameraTransition(mapGroup, mapNum)`** — full map reload: `SetWarpDestination`, `ApplyCurrentWarp`, `LoadCurrentMapData`, `LoadObjEventTemplatesFromHeader`, weather/scripts/etc., then `InitMap()` + `CopySecondaryTilesetToVramUsingHeap` + palette reload.
5. **`MoveMapViewToBackup(direction)`** — copy the saved map view into the new VMap at the correct position, then clear the save.

---

## 12. Build Pipeline: JSON to Binary (pokefirered Detail)

The decomp uses a **JSON → asm → binary** pipeline. Understanding this pipeline is key to seeing how the human-readable JSON maps end up as the binary structures that both the game engine and HMA parse.

### Source Files

| File | Contents |
|------|----------|
| `data/maps/MapName/map.json` | Map header fields (music, weather, type, flags), event lists, connections |
| `data/layouts/layouts.json` | All layout definitions (dimensions, tileset refs, border/blockdata paths) |
| `data/layouts/LayoutName/border.bin` | Raw border metatile data (borderWidth × borderHeight × 2 bytes) |
| `data/layouts/LayoutName/map.bin` | Raw blockmap data (width × height × 2 bytes, packed u16s) |
| `data/maps/map_groups.json` | Bank organization (which maps are in which group, and ordering) |

### The `mapjson` Tool

`mapjson` (C++ tool in `tools/mapjson/mapjson.cpp`) reads JSON and generates `.inc` assembly files. It supports multiple game variants (FireRed, Ruby, Emerald) via `--ruby`, `--emerald`, `--firered` flags, which control output differences like the `map_header_flags` macro (FRLG only), clone events, border width/height, and `map.json` field names.

**`mapjson map <path> <out_dir> <layouts_json>`**:
Generates per-map assembly from `map.json`:

- **`header.inc`**: The map header structure.
  ```asm
  .4byte gMapLayout_PalletTown       @ layout pointer
  .4byte PalletTown_MapEvents        @ events pointer
  .4byte PalletTown_MapScripts       @ scripts pointer
  .4byte PalletTown_MapConnections   @ connections pointer (or 0 if none)
  .2byte MUS_PALLET                  @ music
  .2byte LAYOUT_PALLET_TOWN          @ mapLayoutId (1-based constant)
  .byte  MAPSEC_PALLET_TOWN          @ regionMapSectionId
  .byte  0                           @ cave
  .byte  WEATHER_NONE                @ weather
  .byte  MAP_TYPE_TOWN               @ mapType
  .byte  TRUE                        @ allowBiking
  map_header_flags TRUE, TRUE, TRUE  @ allowEscaping, allowRunning, showMapName (FRLG macro)
  .byte  0                           @ floorNum
  .byte  0                           @ battleType
  ```

- **`events.inc`**: Object events, warps, coord events, bg events, then the `map_events` struct.
  ```asm
  PalletTown_ObjectEvents:
      object_event 1, SPRITE_GIRL, 0, 8, 5, 3, MOVEMENT_TYPE_WANDER_AROUND, 1, 1, ...
      clone_event 2, 5, 3, MAP_ROUTE1  @ FRLG only

  PalletTown_Warps:
      warp_def 5, 4, 3, 0, MAP_PALLET_TOWN_PLAYER_HOUSE_1F

  PalletTown_CoordEvents:
      coord_event 8, 10, 3, VAR_TEMP_1, 0, PalletTown_OnStep_Route1

  PalletTown_BgEvents:
      bg_sign_event 13, 13, 0, BG_EVENT_PLAYER_FACING_NORTH, PalletTown_Sign

  PalletTown_MapEvents:
      map_events PalletTown_ObjectEvents, PalletTown_Warps, PalletTown_CoordEvents, PalletTown_BgEvents
  ```

- **`connections.inc`**: Connection list.
  ```asm
  PalletTown_MapConnectionsList:
      connection north, 0, MAP_ROUTE1

  PalletTown_MapConnections:
      .4byte 1                              @ count
      .4byte PalletTown_MapConnectionsList  @ pointer
  ```

**`mapjson layouts <layouts_json> <out_dir>`**:
Generates from `layouts.json`:

- **`layouts.inc`**: For each layout, `.incbin` the binary data then emit the `MapLayout` struct.
- **`layouts_table.inc`**: The `gMapLayouts[]` pointer table (what `GetMapLayout()` indexes into).
- **`layouts.h`**: `#define LAYOUT_PALLET_TOWN 1` (1-based constants matching `mapLayoutId`).

**`mapjson groups <map_groups_json> <out_dir> <layouts_json>`**:
Generates from `map_groups.json`:

- **`groups.inc`**: Per-bank map pointer arrays + the `gMapGroups[]` table.
- **Bulk includes**: `#include "data/maps/PalletTown/header.inc"` etc. for all maps.
- **`map_groups.h`**: `#define MAP_PALLET_TOWN (0 | (3 << 8))` — packed (mapNum | group << 8) constants.

**`mapjson event_constants <out_dir> <map_dirs...>`**:
- Scans map.json files to emit `#define` constants for object/warp/coord/bg event IDs.

### Assembly Macros (`asm/macros/map.inc`)

The generated `.inc` files use macros that emit bytes matching the C struct layouts. Each macro precisely mirrors the byte layout in `global.fieldmap.h`:

| Macro | Bytes | Matches Struct | Notes |
|-------|-------|----------------|-------|
| `map MAP_ID` | 2 | — | Splits constant into `(MAP_ID >> 8)` group + `(MAP_ID & 0xFF)` num |
| `object_event` | 24 | `ObjectEventTemplate` (normal) | `kind` = `OBJ_KIND_NORMAL`, includes x/y/elevation/movement/trainer/script/flag |
| `clone_event` | 24 | `ObjectEventTemplate` (clone) | `kind` = `OBJ_KIND_CLONE`, references target localId + map |
| `warp_def` | 8 | `WarpEvent` | x, y, elevation, warpId, mapNum, mapGroup |
| `coord_event` | 16 | `CoordEvent` | x, y, elevation, trigger var, index, script pointer |
| `coord_weather_event` | 16 | `CoordEvent` | Similar but trigger = weather constant |
| `bg_event` | 12 | `BgEvent` | Generic background event |
| `bg_sign_event` | 12 | `BgEvent` | Sign (with facing direction check) |
| `bg_hidden_item_event` | 12 | `BgEvent` | Hidden item (packed item/flag/quantity/underfoot) |
| `bg_secret_base_event` | 12 | `BgEvent` | Secret base spot (RSE only) |
| `map_events` | 20 | `MapEvents` | 4 counts (1 byte each) + 4 pointers (4 bytes each) |
| `connection` | 12 | `MapConnection` | direction (4 bytes), offset (4 bytes), map group + num + padding (4 bytes) |
| `map_header_flags` | 2 | Flag bitfield | FRLG only: packs allowEscaping, allowRunning, showMapName into 2 bytes |

### Layout Assembly

Each layout in `layouts.inc` becomes:

```asm
    .align 2
LayoutName_Border::
    .incbin "data/layouts/LayoutName/border.bin"

    .align 2
LayoutName_Blockdata::
    .incbin "data/layouts/LayoutName/map.bin"

    .align 2
LayoutName::
    .4byte width                      @ MapLayout.width
    .4byte height                     @ MapLayout.height
    .4byte LayoutName_Border          @ MapLayout.border
    .4byte LayoutName_Blockdata       @ MapLayout.map (the blockmap)
    .4byte gTileset_General           @ MapLayout.primaryTileset
    .4byte gTileset_PalletTown        @ MapLayout.secondaryTileset
    .byte  borderWidth                @ MapLayout.borderWidth (FRLG only)
    .byte  borderHeight               @ MapLayout.borderHeight (FRLG only)
    .2byte 0                          @ padding
```

For RSE, the `borderWidth`/`borderHeight`/padding bytes are omitted — the `MapLayout` struct is shorter.

### How Constants Connect

The mapjson-generated `map_groups.h` constants like `MAP_PALLET_TOWN` encode both the group and map number:

```c
#define MAP_PALLET_TOWN (0 | (3 << 8))
// mapNum = MAP_PALLET_TOWN & 0xFF = 0
// mapGroup = MAP_PALLET_TOWN >> 8 = 3
```

The `map` assembly macro decomposes this for structs that store group and num as separate bytes. The `layouts.h` constants like `LAYOUT_PALLET_TOWN` are simple 1-based integers matching `MapHeader.mapLayoutId`.

---

## 13. HMA: How the Editor Reads and Writes Map Data (Detailed)

### TOML Format String: The Schema Definition

HMA discovers map data through **Named Anchors** in its TOML configuration (`default.toml`). The TOML doesn't just record addresses — it **is** the schema that drives all data parsing. The format string language is HMA's own DSL for describing recursive pointer-based data structures in a GBA ROM.

For FireRed, the full format strings are:

```toml
[[NamedAnchors]]
Name = '''data.maps.banks'''
Address = 0x3526A8
Format = '''[maps<[map<[layout<[width:: height:: borderblock<> blockmap<`blm`>
  blockdata1<[isCompressed. isSecondary. padding: tileset<> pal<`ucp4:0123456789ABCDEF`>
  blockset<> animation<> attributes<>]1>
  blockdata2<[isCompressed. isSecondary. padding: tileset<> pal<`ucp4:0123456789ABCDEF`>
  blockset<> animation<> attributes<>]1>
  borderwidth. borderheight. unused:]1>
  events<[objectCount.100 warpCount.100 scriptCount.100 signpostCount.100
  objects<[id. graphics.graphics.overworld.sprites kind: x:|z y:|z elevation.11
    moveType. range:|t|x::|y:: trainerType: trainerRangeOrBerryID: script<`xse`>
    flag:|h padding:]/objectCount>
  warps<[x:|z y:|z elevation.11 warpID. map. bank.]/warpCount>
  scripts<[x:|z y:|z elevation:11 trigger:|h index:: script<`xse`>]/scriptCount>
  signposts<[x:|z y:|z elevation.11 kind. unused:1
    arg::|s=kind(0=<>|1=<>|2=<>|3=<>|4=<>)]/signpostCount>]1>
  mapscripts<[type. pointer<>]!00>
  connections<[count:: connections<[direction::mapdirections offset::
    mapGroup. mapNum. unused:]/count>]1>
  music:songnames layoutID:data.maps.layouts+1
  regionSectionID.data.maps.names+88 cave. weather. mapType.
  allowBiking. flags.|t|allowEscaping.|allowRunning.|showMapName:::
  floorNum. battleType.]1>]?>]43'''

[[NamedAnchors]]
Name = '''data.maps.layouts'''
Address = 0x34EB8C
Format = '''[layout<[width:: height:: borderblock<> blockmap<`blm`>
  blockdata1<[isCompressed. isSecondary. padding: tileset<>
  pal<`ucp4:0123456789ABCDEF`> blockset<> animation<> attributes<>]1>
  blockdata2<[isCompressed. isSecondary. padding: tileset<>
  pal<`ucp4:0123456789ABCDEF`> blockset<> animation<> attributes<>]1>
  borderwidth. borderheight. unused:]1>]383'''
```

### Format String Syntax Reference

| Syntax | Meaning |
|--------|---------|
| `.` | 1-byte field |
| `:` | 2-byte field |
| `::` | 4-byte field |
| `<>` | Pointer to data |
| `<[...]N>` | Pointer to an inline table of N elements |
| `<\`blm\`>` | Pointer using the `BlockmapRun` handler (custom codec) |
| `<\`xse\`>` | Pointer to a script (XSE scripting engine) |
| `<\`ucp4:...\`>` | Pointer to uncompressed 4bpp palette data with named palette slots |
| `[...]N` | Fixed-length table with N elements |
| `[...]!00` | Variable-length table terminated by a `00` byte (null terminator) |
| `]/fieldName>` | Table whose length comes from a prior field |
| `]?>` | Variable-length pointer table (null-terminated pointer array) |
| `\|z` | Signed display hint (show as signed integer) |
| `\|h` | Hex display hint |
| `\|t\|x::\|y::` | Tuple display: show as `(x, y)` pair |
| `.100` | Byte field, max value 100 |
| `.11` | Byte field, max value 11 |
| `fieldname:enumname` | 2-byte field using enum `enumname` for display |
| `fieldname.tablename+N` | Byte field indexing into `tablename` with offset N |
| `\|s=kind(0=<>\|1=<>...)` | Switch/union on a prior field's value |

### How the Code Walks the Format Tree

When `BlockMapViewModel` needs to access a specific map, it navigates the format tree like a filesystem path:

```
data.maps.banks               → root table (43 banks)
  → banks[group]              → one bank entry
    → GetSubTable("maps")     → the pointer array of maps in this bank
      → maps[mapIndex]        → one map slot
        → GetSubTable("map")  → the map record (array of 1)
          → [0]               → the actual map data

From the map record:
  → GetSubTable("layout")    → layout<[width:: height:: ...]1>  → [0]
  → GetSubTable("events")    → events<[objectCount... ...]1>    → [0]
  → GetSubTable("connections")→ connections<[count:: ...]1>      → [0]
```

The `GetSubTable(fieldName)` call follows the pointer for that field and interprets the data at the destination address using the inner format string. This is how `model.GetTable(HardcodeTablesModel.MapBankTable)` eventually resolves to every piece of map data.

### The `Format` Class (MapModel.cs)

The `Format` class **dynamically constructs** format strings equivalent to the TOML, but adapted to the detected game version. It provides:

1. **Static property names** — `Format.Layout`, `Format.BlockMap`, `Format.Events`, etc. These are the field names used in `GetSubTable()` calls.
2. **Composed format strings** — `LayoutFormat`, `ObjectsFormat`, `WarpsFormat`, `ConnectionsFormat`, `HeaderFormat`, etc. assembled from sub-parts.
3. **Version-aware construction** — The constructor takes an `IDataModel` and detects RSE vs FRLG differences:
   - RSE: 6 primary palettes, 10 secondary, 512 primary blocks, no clone events, no borderwidth/borderheight
   - FRLG: 7 primary palettes, 6 secondary, 640 primary blocks, clone events supported, borderwidth/borderheight present

The TOML and the `Format` class must agree on field names and structure. When they diverge (e.g., a custom ROM hack adds fields), the TOML takes precedence since it's the declared schema.

### Key Field Name Mappings (TOML ↔ C ↔ Format class)

| HMA TOML field | `Format` static property | C struct field | Size | Purpose |
|----------------|-------------------------|----------------|------|---------|
| `layout` | `Format.Layout` | `MapHeader.mapLayout` | 4 (ptr) | Layout pointer |
| `width` | — | `MapLayout.width` | 4 | Map width in metatiles |
| `height` | — | `MapLayout.height` | 4 | Map height in metatiles |
| `blockmap` | `Format.BlockMap` | `MapLayout.map` | 4 (ptr) | The metatile grid data (`BlockmapRun`) |
| `borderblock` | `Format.BorderBlock` | `MapLayout.border` | 4 (ptr) | Border metatile data |
| `blockdata1` | `Format.PrimaryBlockset` | `MapLayout.primaryTileset` | 4 (ptr) | Primary tileset struct |
| `blockdata2` | `Format.SecondaryBlockset` | `MapLayout.secondaryTileset` | 4 (ptr) | Secondary tileset struct |
| `tileset` | `Format.Tileset` | `Tileset.tiles` | 4 (ptr) | Raw 8×8 tile graphics (inside blockdata) |
| `pal` | `Format.Palette` | `Tileset.palettes` | 4 (ptr) | Color palettes (inside blockdata) |
| `blockset` | `Format.Blocks` | `Tileset.metatiles` | 4 (ptr) | Metatile definitions (inside blockdata) |
| `attributes` | `Format.BlockAttributes` | `Tileset.metatileAttributes` | 4 (ptr) | Per-metatile behavior (inside blockdata) |
| `animation` | — | `Tileset.callback` | 4 (ptr) | Tileset animation callback |
| `isCompressed` | — | `Tileset.isCompressed` | 1 | Compression flag |
| `isSecondary` | — | `Tileset.isSecondary` | 1 | Primary/secondary flag |
| `borderwidth` | `Format.BorderWidth` | `MapLayout.borderWidth` | 1 | Border width (FRLG only) |
| `borderheight` | `Format.BorderHeight` | `MapLayout.borderHeight` | 1 | Border height (FRLG only) |
| `events` | `Format.Events` | `MapHeader.events` | 4 (ptr) | Events struct pointer |
| `objectCount` | — | `MapEvents.objectEventCount` | 1 | Number of object events |
| `warpCount` | — | `MapEvents.warpCount` | 1 | Number of warps |
| `scriptCount` | — | `MapEvents.coordEventCount` | 1 | Number of coord events |
| `signpostCount` | — | `MapEvents.bgEventCount` | 1 | Number of bg events |
| `connections` | `Format.Connections` | `MapHeader.connections` | 4 (ptr) | Connections struct pointer |
| `direction` | — | `MapConnection.direction` | 4 | Connection direction (enum) |
| `offset` | — | `MapConnection.offset` | 4 | Connection alignment offset |
| `mapGroup` | — | `MapConnection.mapGroup` | 1 | Target map group |
| `mapNum` | — | `MapConnection.mapNum` | 1 | Target map number |
| `music` | — | `MapHeader.music` | 2 | Music track (enum: `songnames`) |
| `layoutID` | — | `MapHeader.mapLayoutId` | 2 | 1-based layout index |
| `regionSectionID` | `Format.RegionSection` | `MapHeader.regionMapSectionId` | 1 | Region name (+88 offset in FRLG) |
| `cave` | — | `MapHeader.cave` | 1 | Cave type |
| `weather` | — | `MapHeader.weather` | 1 | Weather type |
| `mapType` | — | `MapHeader.mapType` | 1 | Map type |
| `allowBiking` | — | `MapHeader.bikingAllowed` | 1 | Biking permission |
| `flags` | — | (bitfield) | 1 | Packed: allowEscaping, allowRunning, showMapName |
| `floorNum` | — | `MapHeader.floorNum` | 1 | Floor number (for multi-story buildings) |
| `battleType` | — | `MapHeader.battleType` | 1 | Battle scene type |

### The `layoutID` Dual Reference

Each map has **both** a `layout` pointer (direct address of the `MapLayout` struct in ROM) **and** a `layoutID` (1-based index into `data.maps.layouts`). The TOML expresses this as:

```
layoutID:data.maps.layouts+1
```

This means: `layoutID` is a 2-byte value whose display is linked to `data.maps.layouts` with a +1 offset (since the table is 0-indexed but the ID is 1-based).

In code:
- **Rendering and editing** follow the actual `layout` pointer (`GetLayout()` → `GetSubTable("layout")[0]`).
- **Layout management** (detecting sharing, updating references, `FixLayoutTable`) uses the `layoutID` field and the `data.maps.layouts` table via `HardcodeTablesModel.MapLayoutTable`.
- The layout embedded inline in the map record and the one in the layouts table typically point to the **same ROM address**, but they can diverge if the layout is swapped at runtime (see `SetCurrentMapLayout` in `overworld.c`).

### Rendering Pipeline (Detailed)

HMA renders maps through a multi-stage lazy cache system. Each stage only recomputes when its dependencies change.

**Stage 1: Palette Cache** (`RefreshPaletteCache()`)
- Read palette data from both tilesets: primary (slots 0–6 in FRLG / 0–5 in RSE) + secondary (remaining slots up to 12/15).
- Each palette is 16 colors, each color a 15-bit RGB value (5 bits per channel).
- Result: `IReadOnlyList<short>[]` — one `short[]` per palette slot.

**Stage 2: Tile Cache** (`RefreshTileCache()`)
- Decompress (LZ77 if `isCompressed`) the 4bpp tile graphics from both tilesets.
- Each 8×8 tile becomes an `int[8,8]` array of palette indices (0–15).
- Primary tiles: indices 0–639. Secondary tiles: indices 640–1023.
- Result: `int[][,]` — indexed by tile number.

**Stage 3: Block Cache** (`RefreshBlockCache()`)
- Read the metatile definition data from both tilesets' `blockset` pointers.
- Each metatile is defined by 8 tile references (2×2 grid × 2 layers). Each reference is a 16-bit value packing: tile index (10 bits), flip flags (2 bits), palette index (4 bits).
- Primary blocks: indices 0–639. Secondary blocks: indices 640–1023.
- Result: `int[][]` — raw metatile definition data per block.

**Stage 4: Block Attribute Cache** (`RefreshBlockAttributeCache()`)
- Read the `attributes` pointer from both tilesets.
- Each attribute is a 32-bit word (behavior, terrain, encounter type, layer type).
- Result: `IReadOnlyList<byte[]>`.

**Stage 5: Block Render Cache** (`RefreshBlockRenderCache()`)
- Calls `BlockmapRun.CalculateBlockRenders()`.
- For each of the up to 1024 metatiles:
  1. Create a 16×16 pixel buffer.
  2. For each of the 8 tile references in the metatile:
     - Look up the 8×8 tile from the tile cache.
     - Apply horizontal/vertical flip.
     - Apply the referenced palette.
     - Composite onto the 16×16 buffer at the correct quadrant and layer.
  3. Bottom layer tiles are drawn first, top layer on top.
- Result: `IPixelViewModel[]` — one 16×16 pre-rendered image per block.

**Stage 6: Map Pixel Data** (`FillMapPixelData()`)
1. Read the map's layout: width, height, blockmap address.
2. Calculate **border thickness** per edge. Each edge gets `BorderThickness` (typically 2) metatiles of border **unless** a connection exists on that edge, in which case that edge has 0 border tiles (the connection map's data fills the visual gap instead).
3. Create a `CanvasPixelViewModel` of size `(width + borderW + borderE) × 16` by `(height + borderN + borderS) × 16`.
4. **Draw border cells**: For each cell in the border region, index into the border block pattern using modular wrap (`x % borderWidth`, `y % borderHeight`), look up the pre-rendered block image from the block render cache, and blit it.
5. **Draw map cells**: For each cell in the map area, read the 16-bit halfword from the blockmap. Extract the metatile ID (low 10 bits). Look up `blockRenders[metatileId]` and blit the 16×16 image.
6. **Collision highlighting**: If `CollisionHighlight >= 0`, darken all cells whose collision value matches. If a block index is selected, draw a yellow border on all cells matching that block.
7. **Event sprites**: For each event, call its `Render()` method to get a sprite image (overworld character, warp arrow icon, script icon, signpost icon). Position at `(event.X + borderW) × 16`, `(event.Y + borderN) × 16`. Draw a gray outline around the selected event.
8. **Selected map highlight**: If this is the primary (active) map, draw a subtle darkened border around the entire map content area to visually distinguish it from neighbors.
9. Store result in `pixelData` (`short[]`).

**Incremental Updates**: When drawing a single block via `DrawBlock()`, HMA avoids a full re-render. It patches the `pixelData` array directly by blitting just the new block render at the correct pixel position, then raises `PropertyChanged` on `PixelData`. Full re-render (`ClearPixelCache()`) is only triggered by larger changes (resize, tileset edit, connection change).

### The `short[]` Pixel Format

All HMA pixel data uses `short[]` arrays where each element is a 15-bit packed GBA-native RGB color:

```
Bit 14       10 9        5 4        0
[  blue (5)  ] [ green (5)] [  red (5) ]
```

The special value `-1` (`0xFFFF` as unsigned) is used as the transparent color. `CanvasPixelViewModel` provides helper methods: `Draw(source, destX, destY)`, `DarkenRect(x, y, w, h)`, `DrawBox(x, y, w, h, color)`.

### ViewModel Architecture (Detailed)

**`MapEditorViewModel`** — the tab-level controller:
- Manages a single `PrimaryMap` (`BlockMapViewModel`) and a list of `VisibleMaps` (neighbors).
- **Neighbor discovery**: `GetMapNeighbors()` recursively walks connections. Depth varies by zoom: 1 at normal zoom, up to 5 at 1/16x zoom. `SpartanMode` (for performance) only loads the one neighbor in the panning direction.
- **Mouse interaction** dispatches through `PrimaryInteractionType`:
  - `Draw`: left-click places blocks. Modes include single block, multi-block stamp, rectangle fill (Ctrl+click), 9-grid smart draw, and flood fill (double-click).
  - `Event`: left-click selects/drags events; right-click shows context menu.
  - `Pan`: middle-click drags the entire view.
- **Block picker**: `Blocks` image (8 blocks wide). Supports single selection, drag-select for multi-block stamps, and a "block bag" (randomized painting set).
- **Undo/Redo**: integrated with HMA's `ChangeHistory<ModelDelta>`. Each drawing operation creates a reversible token.
- **History stack**: `Back()`/`Forward()` navigate between previously visited maps.
- **Wave Function Collapse**: scans every map in the ROM sharing the same tileset pair, builds neighbor frequency matrices, uses constrained random selection to fill regions.

**`BlockMapViewModel`** — one per visible map:
- **Identity**: `MapID = group × 1000 + map`. Properties: `Group`, `Map`, `FullName`.
- **Position/Scale**: `LeftEdge`, `TopEdge` (pixel coordinates in editor viewport), `SpriteScale` (0.0625 to 10).
- **Neighbor positioning formula**:
  ```
  // For a connection in direction Up:
  neighbor.TopEdge  = primary.TopEdge - neighbor.PixelHeight * scale
  neighbor.LeftEdge = primary.LeftEdge + (offset + primary.BorderWest - neighbor.BorderWest) * 16 * scale

  // For a connection in direction Left:
  neighbor.LeftEdge = primary.LeftEdge - neighbor.PixelWidth * scale
  neighbor.TopEdge  = primary.TopEdge + (offset + primary.BorderNorth - neighbor.BorderNorth) * 16 * scale
  ```
  The `offset` comes from the `MapConnection.offset` field. Border adjustments ensure that the visual content (not the border margin) aligns correctly.
- **Caches**: palettes, tiles, blocks, blockAttributes, blockRenders, blockPixels (the block picker image). All lazily loaded and invalidated via `ClearCaches()`.
- **BlockmapRun**: The `blockmap` field in the TOML is tagged `` `blm` ``, telling HMA to use the `BlockmapRun` handler. This handler knows the blockmap is `width × height × 2` bytes of packed u16 values, and provides methods for reading/writing individual cells.
- **Event loading**: `GetEvents()` creates `ObjectEventViewModel`, `WarpEventViewModel`, `ScriptEventViewModel`, `SignpostEventViewModel` instances from the events table. Each has position, sprite rendering, and editing properties.
- **Event hover tooltips**: `SummarizeScript()` on the `MapEditorViewModel` disassembles an event's XSE script and extracts: text strings (for signs/NPCs), trainer sprites + Pokemon team icons (for trainers), item images (for item balls), mart listings, and trade previews.
- **Map creation**: `CreateMapForWarp()` allocates a new 9×9 map. It analyzes existing maps with the same blockset to find common wall/floor/door metatile prototypes, shows a visual picker if multiple templates exist, and auto-places a return warp on the new map.
- **Connection management**: `ConnectNewMap()`, `ConnectExistingMap()`, `RemoveConnections()`, `CanConnect()`. When creating a connection, the inverse connection is also added on the target map.

**`MapRepointer`** — handles the "shared data" problem:
- Multiple maps can share the same layout, blockmap, tileset, palette, or block definition data.
- When the user tries to edit shared data, `MapRepointer` detects this by scanning all maps for references to the same ROM address.
- It offers to **repoint**: allocate a new block of ROM space, copy the shared data there, and update only the current map's pointer.
- Tracks reference counts for: layout structs, blockmap data, tileset structs, palette data, block definitions, block attributes.
- `FindLayoutUses()`: counts how many maps point to the same layout address.
- `BlockMapIsShared`/`BlockMapUses`: properties exposing sharing status for the current map's blockmap.

**`BlockEditor`** — sub-VM for metatile composition:
- Edits which 8×8 tiles compose a specific 16×16 metatile.
- Shows a zoomed view of the selected block's 2×2×2 tile grid (bottom and top layers).
- Allows changing tile indices, palette assignments, and flip flags for each position.

**`BorderEditor`** — sub-VM for the border block pattern:
- Edits the small repeating grid (typically 2×2 in FRLG) shown outside map edges.
- Changes here affect all unconnected edges of the map.

### Map Size Validation

Before any resize operation, HMA checks `IsMapWithinSizeLimit`:

```csharp
bool IsMapWithinSizeLimit(int width, int height)
    => (width + MAP_OFFSET_W) * (height + MAP_OFFSET_H) <= MapSizeLimit;
// MAP_OFFSET_W = 15, MAP_OFFSET_H = 14, MapSizeLimit = 0x2800 (10240)
```

This mirrors the game's `VMap` buffer constraint. If the check fails, the resize is rejected.

### Block Picker and Auto-Collision

The **block picker** displays all 1024 metatiles in an 8-column grid. When a block is selected:

1. **Auto-collision**: HMA scans **every map in the ROM** (using the same tileset pair) to build a histogram of which collision value (0–3) most commonly accompanies each metatile ID. The most frequent collision for the selected block auto-fills the collision tool.
2. **Block bag**: The user can Ctrl+click multiple blocks to build a "bag." When painting, HMA randomly picks from the bag for each cell — useful for natural-looking terrain variation.
3. **Multi-block stamp**: Right-click-drag in the block picker or on the map selects a rectangular region, which is then used as a stamp for painting.

---

## 14. Advanced Topics

### Layout Sharing and Repointing

Multiple maps can share a single layout (common for Pokemon Centers, Marts, etc.). In a vanilla FireRed ROM, many interior maps share identical layouts — every standard Pokemon Center uses the same layout, as does every Poke Mart.

**Detecting sharing**: `BlockMapViewModel.FindLayoutUses()` scans the layout table and all map bank entries for pointers that match the current map's layout address. If more than one map references the same layout, editing is destructive to all of them.

**Repointing**: When HMA detects shared data and the user attempts an edit, it offers to:
1. Allocate a new block of free space in the ROM (using HMA's free space finder).
2. Copy the shared data (layout struct, blockmap bytes, or tileset struct) to the new location.
3. Update only the current map's pointer to reference the new copy.
4. Leave all other maps still pointing at the original data.

`MapRepointer` handles this for **six levels** of shared data:
- **Layout struct** itself (the width/height/pointers record)
- **Blockmap data** (the raw `width × height × 2` byte grid)
- **Primary tileset struct** / **Secondary tileset struct**
- **Palette data** within a tileset
- **Block definitions** (metatile data) within a tileset
- **Block attributes** within a tileset

The `BlockMapIsShared` property and `BlockMapUses` count are exposed on `BlockMapViewModel` so the UI can warn users before edits.

### Clone Objects (FRLG)

Clone objects are a FireRed/LeafGreen-specific feature that lets NPCs appear to walk across map boundaries. Without clones, an NPC standing near the edge of Map A would simply disappear when the camera scrolls to show Map B's territory.

**How clones work in the ROM**:
A clone event on Map A has `kind = OBJ_KIND_CLONE` (value 1, vs 0 for normal). Instead of the usual NPC fields (movement, trainer data, script), it stores:
- `targetLocalId`: the object event ID on the source map
- `targetMapNum`, `targetMapGroup`: which map the source NPC lives on

**At runtime** (`LoadObjEventTemplatesFromHeader` in `overworld.c`):
The game reads the clone's target map header via `Overworld_GetMapHeaderByGroupAndId()`, finds the referenced object event by `localId`, copies its graphics ID, and adjusts its position by the connection offset between the two maps.

**In the assembly macros** (`map.inc`):
```asm
clone_event localId, graphicsId, x, y, MAP_TARGET
@ Emits 24 bytes matching ObjectEventTemplate with kind=OBJ_KIND_CLONE
@ and the target map's group+num packed from MAP_TARGET
```

**In HMA**:
Clone management is **automatic**. When you drag an object event near a map edge that has a connection, HMA:
1. Checks if the NPC's visual sprite would be visible from the connected map.
2. If so, creates or updates a clone entry on the connected map.
3. If the NPC moves away from the edge, removes the clone.
4. Clone entries are created/removed as part of the edit transaction (undoable).

### Wave Function Collapse (WFC)

HMA's WFC implementation is a map-specific adaptation of the general WFC algorithm, specialized for metatile grids:

**Training phase** (runs once per tileset pair):
1. Scan **every map in the ROM** that uses the same primary+secondary tileset combination.
2. For each map, examine every cell and its 4 neighbors (up/down/left/right).
3. Build a frequency table: `P(neighborBlock | centerBlock, direction)` — "given block X at the center, how often does block Y appear to the north/south/east/west?"
4. This captures the ROM's existing map design patterns as statistical constraints.

**Generation phase** (when the user invokes WFC on a selected region):
1. Start with every cell in the target region in a "superposition" of all possible blocks.
2. Find the cell with the **lowest entropy** (fewest remaining possibilities that satisfy all neighbor constraints).
3. **Collapse** that cell: pick a specific block weighted by its frequency in the training data.
4. **Propagate**: remove blocks from neighboring cells' possibility sets that would violate the learned neighbor frequency (blocks that never appeared next to the chosen block in any existing map).
5. Repeat steps 2–4 until all cells are collapsed.
6. If a contradiction occurs (a cell has zero possibilities), backtrack or restart.

The result is a region that "looks like" existing maps in the ROM — it reuses the same tile adjacency patterns that the original designers used.

### 9-Grid Smart Drawing

When you select a 3×3 block pattern from the block picker, HMA interprets it as a **9-grid template**:

```
┌────────┬────────┬────────┐
│ top-   │  top   │ top-   │
│ left   │ edge   │ right  │
├────────┼────────┼────────┤
│ left   │ center │ right  │
│ edge   │        │ edge   │
├────────┼────────┼────────┤
│ bottom-│ bottom │ bottom-│
│ left   │ edge   │ right  │
└────────┴────────┴────────┘
```

When painting, HMA examines each cell's 8 neighbors and selects the correct piece:
- **Center**: surrounded by filled cells on all sides
- **Edge**: one side faces empty space
- **Corner**: two adjacent sides face empty space
- **Inner corner**: HMA also discovers inner-corner blocks by scanning existing maps for blocks that appear at concave corners of the same 9-grid pattern. This handles L-shaped regions correctly.

The neighborhood is evaluated as an 8-bit mask (N/NE/E/SE/S/SW/W/NW), and each mask pattern maps to one of the 9 grid positions or an inner corner variant.

### Preferred Collisions

The auto-collision system works by statistical analysis:

1. On first use (then cached), scan every blockmap cell in every map sharing the current tileset pair.
2. For each metatile ID, tally how many times it appears with collision=0, collision=1, collision=2, collision=3.
3. The most frequent collision value for each metatile becomes its "preferred collision."
4. When the user selects a block in the block picker, the collision tool auto-sets to this preferred value.

This saves time because most blocks have a "natural" collision — grass is passable, walls are impassable, water is impassable (for walking) — and the histogram captures these patterns from the existing ROM.

### Map Size Constraints

The runtime VMap buffer is `MAX_MAP_DATA_SIZE = 0x2800` halfwords (10240 cells). The expanded size must fit:

```
(width + MAP_OFFSET_W) × (height + MAP_OFFSET_H) ≤ MAX_MAP_DATA_SIZE
(width + 15)           × (height + 14)            ≤ 10240
```

This means there's a **tradeoff** between width and height. Example maximum dimensions:
- 113 × 66 (wide landscape)
- 66 × 113 (tall corridor)
- 497 × 6 (extreme narrow)
- ~86 × ~86 (roughly square)

HMA enforces this in `IsMapWithinSizeLimit` and rejects resize operations that would exceed it. The game itself would crash or corrupt memory if a map exceeded this limit.

### Tileset Animation

Both tilesets can have **animation callbacks** (`Tileset.callback`). These are C functions that periodically swap tile graphics in VRAM — used for flowing water, flashing lights, etc.

In the ROM data, the `animation` field in the tileset struct is a function pointer. In `fieldmap.c`, `InitTilesetAnimations()` is called after loading tilesets, and the callbacks run each frame via `TilesetAnims_Main()`.

HMA reads the `animation` field but doesn't execute the callbacks. Static tile graphics are used for rendering. However, the field is preserved during editing and repointing.

### Map Scripts

Map scripts (`mapscripts` in the TOML) are a variable-length array terminated by `type = 0`. Each entry has a type byte and a pointer:

| Type | Name | When it runs |
|------|------|-------------|
| 1 | `ON_LOAD` | When map data is loaded |
| 2 | `ON_FRAME_TABLE` | Checked each frame (table of condition/script pairs) |
| 3 | `ON_TRANSITION` | During map transition |
| 4 | `ON_WARP_INTO_MAP_TABLE` | When warping into this map (table of condition/script pairs) |
| 5 | `ON_RESUME` | When returning to this map from a submenu |

In the TOML: `mapscripts<[type. pointer<>]!00>` — the `!00` means the array continues until a `type` byte of `0x00` is encountered.

### HMA's Layout Table Fixer

`FixLayoutTable()` in `MapEditorViewModel` handles a common ROM hack scenario: external tools add new layout data to the ROM but don't register it in the `data.maps.layouts` table. HMA detects "orphan" layouts (pointed to by map headers but absent from the layout table) and offers to expand the layout table to include them, assigning new `layoutID` values.

---

## 15. Glossary of Terms

| Term | Definition |
|------|------------|
| **4bpp** | 4 bits per pixel. The GBA's native tile format where each pixel is a 4-bit index into a 16-color palette. |
| **9-Grid** | An HMA smart drawing mode where a 3×3 block template is used to auto-select corners, edges, center, and inner corners based on each cell's neighborhood. |
| **Bank / Group** | A collection of maps. Maps are organized into banks (43 in FireRed). A map is identified by (bank, map index). |
| **Block Bag** | An HMA feature: a set of metatiles that are randomly chosen from during painting, for natural terrain variation. |
| **Block Picker** | The HMA panel showing all 1024 available metatiles in an 8-column grid for selection. |
| **Blockmap** | The 2D grid of 16-bit cells that defines a map's terrain, collision, and elevation. Each cell references a metatile. Stored as `width × height × 2` bytes, little-endian. |
| **BlockmapRun** | HMA's custom data handler for blockmap data, triggered by the `` `blm` `` tag in format strings. Knows the data is packed u16 cells. |
| **Border** | A small repeating tile pattern (typically 2×2 in FRLG) shown outside map edges that lack connections. The border is always rendered with collision bits forced on (impassable). |
| **CanvasPixelViewModel** | HMA helper class for compositing pixel data. Provides `Draw`, `DarkenRect`, `DrawBox` methods on a `short[]` buffer. |
| **Clone Object** | A FireRed/LeafGreen feature: an NPC on one map (`OBJ_KIND_CLONE`) that mirrors an NPC from an adjacent map across a connection boundary. At runtime, the game resolves the target map's header to copy the source NPC's graphics. |
| **Collision** | A 2-bit field (bits 10–11) in each blockmap cell. 0 = passable, non-zero = impassable. The game primarily checks bit 10. |
| **Connection** | A link between two maps at their edges, enabling seamless scrolling. Defined by direction (1–6), offset (signed tile count), and target map (group + num). |
| **Coord Event** | An invisible script trigger at a specific (x, y) position on the map. Also called a "script trigger." |
| **Elevation** | A 4-bit value (bits 12–15) per blockmap cell controlling vertical collision layers (e.g., bridges where NPCs at different elevations don't collide). |
| **Format String** | HMA's DSL for describing binary data layouts. Uses `.` (byte), `:` (halfword), `::` (word), `<>` (pointer), `<[...]N>` (pointer to table), etc. |
| **Free Space** | Unused ROM area (typically filled with `0xFF` bytes) where HMA can allocate new data during repointing. |
| **gBackupMapData** | The `u16[0x2800]` RAM array backing `VMap.map`. Holds the expanded blockmap at runtime. |
| **gMapGroups** | The C global: `const MapHeader *const *gMapGroups[]`. A 2D lookup table: `gMapGroups[group][mapNum]` → `MapHeader*`. |
| **gMapHeader** | The C global holding the currently active map's header data, copied from `gMapGroups` during map loading. |
| **gMapLayouts** | The C global: `const MapLayout *gMapLayouts[]`. Indexed by `mapLayoutId - 1`. This is the compiled form of `data.maps.layouts`. |
| **Layout** | The combination of dimensions, blockmap, border, and tileset references for a map's terrain. Can be shared across multiple maps. |
| **Layout ID** | A 1-based index into the global layout table (`gMapLayouts` / `data.maps.layouts`). Stored in the map header alongside the direct layout pointer. |
| **Map Header** | The root record for a map: pointers to layout, events, scripts, connections, plus metadata (music, weather, type, flags). |
| **Map Scripts** | Scripts that run on map load, frame ticks, transition, warp, or resume. Terminated by a type=0 sentinel. |
| **MAP_OFFSET** | The 7-metatile margin added to each edge of VMap for connections and border rendering. Total expansion: +15 width, +14 height. |
| **MAPGRID_UNDEFINED** | Sentinel value `0x03FF` filling uninitialized VMap cells. When read, treated as border block. |
| **mapjson** | The C++ build tool that converts JSON map definitions into `.inc` assembly files using `map.inc` macros. |
| **Metatile** | A 16×16 pixel "block" composed of 8 individual 8×8 tile references (2×2 grid × 2 layers). The basic unit of map terrain. Up to 1024 total (640 primary + 384 secondary). |
| **Metatile Attributes** | A 32-bit word per metatile encoding behavior (bits 0–8), terrain (bits 9–13), encounter type (bits 24–26), and layer type (bits 29–30). |
| **Named Anchor** | An HMA TOML entry that pins a format string schema to a specific ROM address, enabling structured parsing of binary data. |
| **Object Event** | An NPC, item ball, trainer, or other sprite-based entity placed on the map. Defined by `ObjectEventTemplate` (24 bytes). |
| **Preferred Collision** | HMA's auto-collision feature: scans all maps to find the most common collision value for each metatile, then auto-fills when that metatile is selected. |
| **Primary Tileset** | The first of two tilesets for a layout. Contains shared/common tiles and metatiles (indices 0–639). Provides 7 palette slots in FRLG. |
| **Region Section ID** | Index into the map names table (`data.maps.names`), identifying which region name to display. Offset by +88 in FRLG (first 88 slots are Kanto region names). |
| **Repoint** | Copying shared data to a new ROM location so edits to the copy don't affect other maps that reference the original. Managed by `MapRepointer`. |
| **Secondary Tileset** | The second tileset for a layout. Contains area-specific tiles and metatiles (indices 640–1023). Provides 6 palette slots in FRLG. |
| **Signpost / BgEvent** | A background event: a sign (read by facing it), hidden item (found with Itemfinder), or secret base spot. |
| **SpartanMode** | An HMA performance option that limits neighbor loading to only the one map in the panning direction. |
| **Tile Reference** | A 16-bit value in a metatile definition: tile index (10 bits), horizontal flip (1 bit), vertical flip (1 bit), palette index (4 bits). |
| **VMap** | The runtime RAM buffer (`BackupMapLayout` struct) holding the expanded blockmap: current map data centered with 7-tile margins, connection strips, and `MAPGRID_UNDEFINED` elsewhere. |
| **Warp** | An event that teleports the player to a specific (warpId, mapNum, mapGroup) — resolved to the target warp's (x, y) position. |
| **Wave Function Collapse** | A procedural generation technique HMA uses to fill map regions with contextually appropriate blocks, trained on neighbor-frequency statistics from all maps in the ROM. |

---

## 16. Function and Constant Reference: pokefirered

### Constants (`include/fieldmap.h`, `include/global.fieldmap.h`)

| Constant | Value | Purpose |
|----------|-------|---------|
| `NUM_TILES_IN_PRIMARY` | 640 | 8×8 tiles in the primary tileset |
| `NUM_TILES_TOTAL` | 1024 | Total 8×8 tiles (primary + secondary) |
| `NUM_METATILES_IN_PRIMARY` | 640 | Metatiles in the primary tileset |
| `NUM_METATILES_TOTAL` | 1024 | Total metatiles |
| `NUM_PALS_IN_PRIMARY` | 7 | Palette slots for the primary tileset |
| `NUM_PALS_TOTAL` | 13 | Total palette slots |
| `MAX_MAP_DATA_SIZE` | 0x2800 | Maximum VMap buffer size in halfwords |
| `MAP_OFFSET` | 7 | Border/connection margin in metatiles |
| `MAP_OFFSET_W` | 15 | `MAP_OFFSET * 2 + 1` |
| `MAP_OFFSET_H` | 14 | `MAP_OFFSET * 2` |
| `MAPGRID_METATILE_ID_MASK` | `0x03FF` | Bits 0–9 of a map grid cell |
| `MAPGRID_COLLISION_MASK` | `0x0C00` | Bits 10–11 of a map grid cell |
| `MAPGRID_ELEVATION_MASK` | `0xF000` | Bits 12–15 of a map grid cell |
| `MAPGRID_COLLISION_SHIFT` | 10 | Bit shift for collision field |
| `MAPGRID_ELEVATION_SHIFT` | 12 | Bit shift for elevation field |
| `MAPGRID_UNDEFINED` | `0x03FF` | Sentinel value for uninitialized cells |
| `CONNECTION_SOUTH` | 1 | Direction constant |
| `CONNECTION_NORTH` | 2 | Direction constant |
| `CONNECTION_WEST` | 3 | Direction constant |
| `CONNECTION_EAST` | 4 | Direction constant |
| `CONNECTION_DIVE` | 5 | Direction constant |
| `CONNECTION_EMERGE` | 6 | Direction constant |

### Metatile Attribute Constants

| Constant | Mask | Bits |
|----------|------|------|
| `METATILE_ATTRIBUTE_BEHAVIOR` | `0x000001FF` | 0–8 |
| `METATILE_ATTRIBUTE_TERRAIN` | `0x00003E00` | 9–13 |
| `METATILE_ATTRIBUTE_ENCOUNTER_TYPE` | `0x07000000` | 24–26 |
| `METATILE_ATTRIBUTE_LAYER_TYPE` | `0x60000000` | 29–30 |

### Functions — fieldmap.c

| Function | Signature | Purpose |
|----------|-----------|---------|
| `InitMap()` | `void InitMap(void)` | Initialize map layout data and run on-load map scripts |
| `InitMapFromSavedGame()` | `void InitMapFromSavedGame(void)` | Initialize map layout data and restore saved map view |
| `InitMapLayoutData()` | `void InitMapLayoutData(struct MapHeader *header)` | Clear VMap to `MAPGRID_UNDEFINED`, set VMap dimensions, copy blockmap + connections |
| `InitBackupMapLayoutData()` | `void InitBackupMapLayoutData(struct MapHeader *header)` | Copy ROM blockmap into center of VMap buffer (row by row with stride adjustment) |
| `InitBackupMapLayoutConnections()` | `void InitBackupMapLayoutConnections(struct MapHeader *header)` | Iterate connections, call `Fill*Connection` for each to populate VMap edges |
| `FillSouthConnection()` | `void FillSouthConnection(struct MapHeader *, struct MapHeader *, s32 offset)` | Copy connected map's top rows into VMap south margin |
| `FillNorthConnection()` | `void FillNorthConnection(struct MapHeader *, struct MapHeader *, s32 offset)` | Copy connected map's bottom rows into VMap north margin |
| `FillWestConnection()` | `void FillWestConnection(struct MapHeader *, struct MapHeader *, s32 offset)` | Copy connected map's right columns into VMap west margin |
| `FillEastConnection()` | `void FillEastConnection(struct MapHeader *, struct MapHeader *, s32 offset)` | Copy connected map's left columns into VMap east margin |
| `GetMapGridBlockAt()` | `u16 GetMapGridBlockAt(int x, int y)` | Read full u16 cell from VMap (or border if out of bounds) |
| `GetBorderBlockAt()` | macro | Index into `mapLayout->border` with wrapping, OR collision mask |
| `MapGridGetMetatileIdAt()` | `u16 MapGridGetMetatileIdAt(int x, int y)` | Read metatile ID (bits 0–9) from VMap |
| `MapGridGetCollisionAt()` | `u32 MapGridGetCollisionAt(int x, int y)` | Read collision flag (bits 10–11, shifted) from VMap |
| `MapGridGetElevationAt()` | `u32 MapGridGetElevationAt(int x, int y)` | Read elevation (bits 12–15, shifted) from VMap |
| `MapGridGetMetatileBehaviorAt()` | `u32 MapGridGetMetatileBehaviorAt(int x, int y)` | Get behavior attribute for the metatile at (x, y) |
| `MapGridGetMetatileAttributeAt()` | `u32 MapGridGetMetatileAttributeAt(int x, int y, u8 type)` | Get any attribute type for the metatile at (x, y) |
| `MapGridSetMetatileIdAt()` | `void MapGridSetMetatileIdAt(int x, int y, u16 metatile)` | Write metatile ID preserving elevation+collision bits |
| `MapGridSetMetatileEntryAt()` | `void MapGridSetMetatileEntryAt(int x, int y, u16 entry)` | Write full 16-bit cell value |
| `MapGridSetMetatileImpassabilityAt()` | `void MapGridSetMetatileImpassabilityAt(int x, int y, bool v)` | Set/clear collision bits (bit 10) |
| `ExtractMetatileAttribute()` | `u32 ExtractMetatileAttribute(u32 attrs, u8 type)` | Apply mask from `sMetatileAttrMasks[type]` and shift to decode one field |
| `GetAttributeByMetatileIdAndMapLayout()` | `u32 GetAttributeByMetatileIdAndMapLayout(...)` | Route to primary or secondary tileset's `metatileAttributes` based on ID < 640 |
| `GetMapBorderIdAt()` | `int GetMapBorderIdAt(int x, int y)` | Return which map edge (or CONNECTION_* direction) a VMap position falls in |
| `GetPostCameraMoveMapBorderId()` | `int GetPostCameraMoveMapBorderId(int dx, int dy)` | Check if a camera move would cross a map border |
| `CanCameraMoveInDirection()` | `bool CanCameraMoveInDirection(int direction)` | Check `gMapConnectionFlags` for whether a connection exists in that direction |
| `CameraMove()` | `int CameraMove(int deltaX, int deltaY)` | Handle camera movement, triggering connection transitions if crossing a border |
| `GetMapConnectionAtPos()` | `struct MapConnection *GetMapConnectionAtPos(int x, int y, int dx, int dy)` | Find which connection covers a given position + movement direction |
| `GetMapHeaderFromConnection()` | `struct MapHeader *GetMapHeaderFromConnection(struct MapConnection *conn)` | Resolve a connection to its target MapHeader via `Overworld_GetMapHeaderByGroupAndId` |
| `SaveMapView()` | `void SaveMapView(void)` | Persist the visible 15×14 metatile window into `gSaveBlock2Ptr->mapView` |
| `LoadSavedMapView()` | `void LoadSavedMapView(void)` | Restore saved map view into current VMap position |
| `CopyMapTilesetsToVram()` | `void CopyMapTilesetsToVram(struct MapLayout *)` | Load both tilesets' tile graphics into VRAM |
| `LoadMapTilesetPalettes()` | `void LoadMapTilesetPalettes(struct MapLayout *)` | Load both tilesets' palettes into BG palette RAM |
| `CopyPrimaryTilesetToVram()` | `void CopyPrimaryTilesetToVram(struct MapLayout *)` | Load primary tileset tiles at VRAM indices 0–639 |
| `CopySecondaryTilesetToVram()` | `void CopySecondaryTilesetToVram(struct MapLayout *)` | Load secondary tileset tiles at VRAM indices 640–1023 |
| `InitTilesetAnimations()` | `void InitTilesetAnimations(void)` | Initialize tileset animation callbacks for both tilesets |

### Functions — overworld.c

| Function | Purpose |
|----------|---------|
| `Overworld_GetMapHeaderByGroupAndId(group, num)` | Look up a MapHeader from `gMapGroups` |
| `GetMapLayout()` | Resolve `mapLayoutId` → `gMapLayouts[id - 1]` |
| `LoadCurrentMapData()` | Copy MapHeader into gMapHeader, resolve layout |
| `LoadSaveblockMapHeader()` | Same but without saving mapLayoutId |
| `SetPlayerCoordsFromWarp()` | Position player from warp data or map center |
| `WarpIntoMap()` | Apply warp, load map data, set position |
| `LoadMapFromCameraTransition(group, num)` | Full map reload during seamless scrolling |
| `LoadMapFromWarp()` | Full map reload after a warp |
| `SetCurrentMapLayout(layoutId)` | Swap the active layout at runtime |
| `LoadObjEventTemplatesFromHeader()` | Copy events to save, resolving clones |
| `SetWarpDestination()` | Set warp target (group, num, warpId, x, y) |
| `GetMapConnection(direction)` | Find a connection in the given direction |
| `SetDiveWarpEmerge()` / `SetDiveWarpDive()` | Handle dive/emerge transitions |

### Structs

| Struct | File | Purpose |
|--------|------|---------|
| `MapHeader` | `global.fieldmap.h` | Root map record |
| `MapLayout` | `global.fieldmap.h` | Dimensions, blockmap, tilesets |
| `Tileset` | `global.fieldmap.h` | Tile graphics, palettes, metatiles, attributes |
| `MapEvents` | `global.fieldmap.h` | Event counts + pointers |
| `ObjectEventTemplate` | `global.fieldmap.h` | NPC/item/trainer placement |
| `WarpEvent` | `global.fieldmap.h` | Warp definition |
| `CoordEvent` | `global.fieldmap.h` | Script trigger |
| `BgEvent` | `global.fieldmap.h` | Sign/hidden item |
| `MapConnection` | `global.fieldmap.h` | Single connection entry |
| `MapConnections` | `global.fieldmap.h` | Count + connection array |
| `BackupMapLayout` (`VMap`) | `global.fieldmap.h` | Runtime expanded map buffer |

### Assembly Macros (`asm/macros/map.inc`)

| Macro | Emits |
|-------|-------|
| `map MAP_ID` | 2 bytes: group, num |
| `object_event ...` | 24-byte ObjectEventTemplate (normal) |
| `clone_event ...` | 24-byte ObjectEventTemplate (clone) |
| `warp_def ...` | 8-byte WarpEvent |
| `coord_event ...` | 16-byte CoordEvent |
| `bg_sign_event ...` | 12-byte BgEvent (sign) |
| `bg_hidden_item_event ...` | 12-byte BgEvent (hidden item) |
| `map_events ...` | MapEvents struct |
| `connection ...` | 12-byte MapConnection |
| `map_header_flags ...` | 2-byte flag bitfield |

### mapjson Modes

| Mode | Input | Output |
|------|-------|--------|
| `mapjson map` | `map.json` + `layouts.json` | `header.inc`, `events.inc`, `connections.inc` |
| `mapjson layouts` | `layouts.json` | `layouts.inc`, `layouts_table.inc`, `layouts.h` |
| `mapjson groups` | `map_groups.json` | `groups.inc`, `connections.inc`, `headers.inc`, `events.inc`, `map_groups.h` |
| `mapjson event_constants` | `map.json` files | `map_event_ids.h` |

---

## 17. Class, Field, and Constant Reference: HMA

### Core ViewModels

| Class | File | Role |
|-------|------|------|
| `MapEditorViewModel` | `MapEditorViewModel.cs` | Tab-level map editor: primary map, neighbors, interaction, undo/redo |
| `BlockMapViewModel` | `BlockMapViewModel.cs` | Single map: pixels, layout, events, connections, block editing |
| `BlockEditor` | `BlockEditor.cs` | Edit individual metatile tile composition |
| `BorderEditor` | `BorderEditor.cs` | Edit border block pattern |
| `MapRepointer` | `MapRepointer.cs` | Repoint shared data (layout, blockmap, tilesets, blocks, palettes) |
| `MapHeaderViewModel` | (map header panel) | Edit map header fields (music, weather, type, flags) |

### Model Classes (`Models/Map/MapModel.cs`)

| Class | Role |
|-------|------|
| `AllMapsModel` | Wraps `data.maps.banks`; iterable bank list |
| `MapBankModel` | One bank; iterable map list |
| `MapModel` | One map's header element; provides `Layout`, `Events`, `Blocks`, `Connections` |
| `LayoutModel` | One layout; provides `Width`, `Height`, `PrimaryBlockset`, `SecondaryBlockset`, `BlockMap` |
| `BlockCells` | Read-only view of a blockmap (per-cell `BlockCell` with `.Tile` and `.Collision`) |
| `BlockCell` | One blockmap cell: `Tile` (metatile ID), `Collision`, combined `Block` |
| `ConnectionModel` | One connection entry: `Direction`, `Offset`, `MapGroup`, `MapNum` |
| `Format` | Builds format strings; defines field name constants |

### Format Field Names (`Format` class)

| Static Property | String Value | Maps To |
|-----------------|-------------|---------|
| `Format.Layout` | `"layout"` | Layout pointer |
| `Format.BlockMap` | `"blockmap"` | Blockmap data pointer |
| `Format.BorderBlock` | `"borderblock"` | Border data pointer |
| `Format.PrimaryBlockset` | `"blockdata1"` | Primary tileset pointer |
| `Format.SecondaryBlockset` | `"blockdata2"` | Secondary tileset pointer |
| `Format.Tileset` | `"tileset"` | Tile graphics within a tileset |
| `Format.Palette` | `"pal"` | Palettes within a tileset |
| `Format.Blocks` | `"blockset"` | Metatile definitions within a tileset |
| `Format.BlockAttributes` | `"attributes"` | Metatile attributes within a tileset |
| `Format.Events` | `"events"` | Events pointer |
| `Format.Connections` | `"connections"` | Connections pointer |
| `Format.RegionSection` | `"regionSectionID"` | Region name index |
| `Format.BorderWidth` | `"borderwidth"` | Border width |
| `Format.BorderHeight` | `"borderheight"` | Border height |

### Hardcoded Table Names (`HardcodeTablesModel`)

| Constant | Value |
|----------|-------|
| `MapBankTable` | `"data.maps.banks"` |
| `MapLayoutTable` | `"data.maps.layouts"` |
| `MapNameTable` | `"data.maps.names"` |
| `OverworldSprites` | `"graphics.overworld.sprites"` |
| `FlyConnections` | `"data.maps.fly.connections"` |
| `FlySpawns` | `"data.maps.fly.spawns"` |

### Key BlockMapViewModel Constants and Properties

| Member | Value / Type | Purpose |
|--------|-------------|---------|
| `BlocksPerRow` | `8` | Blocks per row in the block picker grid |
| `TotalBlocks` | `1024` | Max metatile count (primary + secondary) |
| `PrimaryBlocks` | `640` (FRLG) / `512` (RSE) | Metatiles in primary tileset |
| `PrimaryPalettes` | `7` (FRLG) / `6` (RSE) | Palette slots for primary tileset |
| `MapSizeLimit` | `0x2800` | `(w+15)*(h+14)` must not exceed this (mirrors game's `MAX_MAP_DATA_SIZE`) |
| `MapID` | `group * 1000 + map` | Unique map identifier encoding |
| `Group` | `int` | Map bank/group index |
| `Map` | `int` | Map index within the bank |
| `FullName` | `string` | Resolved from the map name table (e.g., "Pallet Town") |
| `PixelData` | `short[]` | Lazily rendered map image (15-bit packed RGB) |
| `PixelWidth` / `PixelHeight` | `int` | Dimensions of the rendered pixel data in pixels |
| `SpriteScale` | `double` | Zoom level (0.0625 to 10) |
| `LeftEdge` / `TopEdge` | `int` | Pixel position of top-left corner in editor viewport |
| `RightEdge` / `BottomEdge` | `int` | Computed: `LeftEdge + PixelWidth * SpriteScale` / etc. |
| `CollisionHighlight` | `int` | Which collision value to highlight (-1 = none) |
| `BlockMapIsShared` | `bool` | Whether the blockmap data is referenced by multiple maps |
| `BlockMapUses` | `int` | Number of maps sharing this blockmap |
| `Header` | `MapHeaderViewModel` | Sub-VM for editing map header fields |
| `BlockEditor` | `BlockEditor` | Sub-VM for editing individual metatile composition |
| `BorderEditor` | `BorderEditor` | Sub-VM for editing border block pattern |
| `WildPokemon` | sub-VM | Wild encounter data editor for this map |
| `SurfConnection` | sub-VM | Dive/Emerge connection editor |

### Key MapEditorViewModel Properties

| Property | Type | Purpose |
|----------|------|---------|
| `PrimaryMap` | `BlockMapViewModel` | The currently active/focused map |
| `VisibleMaps` | `List<BlockMapViewModel>` | All maps currently visible (primary + neighbors) |
| `Blocks` | `IPixelViewModel` | The block picker panel image (8 columns wide) |
| `SelectedEvent` | `IEventViewModel` | Currently selected event (object, warp, script, signpost) |
| `ShowEvents` | `bool` | Whether events are visible on the map |
| `ShowCollisionIndex` | `int` | Which collision value to highlight across all maps |
| `SpartanMode` | `bool` | Performance mode: only load one neighbor at a time |
| `Name` | `string` | Tab name: map name + dirty indicator |

### Key MapEditorViewModel Methods

| Method | Purpose |
|--------|---------|
| `UpdatePrimaryMap(map)` | Set active map, validate it, discover neighbors at current zoom depth, refresh blockset cache, update block picker, refresh connection slider buttons |
| `NavigateTo(bank, map)` | Navigate to a different map, pushing current map onto the history stack |
| `Back()` / `Forward()` | Navigate the map history stack |
| `Hover(x, y)` | Update cursor highlight, show event tooltips via `SummarizeScript()` |
| `PrimaryDown(x, y)` / `PrimaryMove(x, y)` / `PrimaryUp(x, y)` | Left-click: draw blocks or select/drag events, depending on `PrimaryInteractionType` |
| `SelectDown(x, y)` / `SelectMove(x, y)` / `SelectUp(x, y)` | Right-click: pick block+collision from map, or drag-select a multi-block stamp |
| `MiddleDown(x, y)` / `MiddleMove(x, y)` / `MiddleUp(x, y)` | Middle-click: pan the entire editor view |
| `DrawDown(x, y)` / `DrawMove(x, y)` | Block painting (single, multi-stamp, 9-grid, Ctrl+rectangle fill) |
| `DoubleClick(x, y)` | Flood-fill paint, or navigate to warp destination, or open script editor |
| `Zoom(x, y, enlarge)` | Scroll-wheel zoom centered on cursor position |
| `Pan(dx, dy)` | Shift all visible maps and slider buttons by (dx, dy) pixels |
| `Delete()` | Remove the currently selected event |
| `Refresh()` | Invalidate all caches and re-render all visible maps |
| `SummarizeScript(event)` | Disassemble an event's XSE script to extract text, trainer info, item images, etc. for hover tooltip |
| `GetPreferredCollision(blockIndex)` | Look up the most common collision for a metatile across all maps with the same tileset pair |
| `FixLayoutTable()` | Detect and absorb orphan layouts not in `data.maps.layouts` |

### Key BlockMapViewModel Methods

| Method | Purpose |
|--------|---------|
| `GetLayout()` | Resolve the layout pointer: `GetSubTable("layout")[0]` from the map record |
| `GetBlock(x, y)` | Read metatile ID + collision at a screen position (adjusting for border offset) |
| `DrawBlock(token, blockIdx, collision, x, y)` | Write one block to the blockmap and incrementally patch the pixel data |
| `DrawBlocks(token, tiles, source, dest)` | Stamp a multi-block pattern onto the blockmap |
| `Draw9Grid(token, grid, x, y)` | Smart edge/corner drawing using a 3×3 template + neighborhood analysis |
| `PaintBlock(token, blockIdx, collision, x, y)` | Recursive flood-fill with a single block (replaces all contiguous matching cells) |
| `PaintBlockBag(token, bag, collision, x, y)` | Flood-fill with random selection from a bag of blocks |
| `PaintWaveFunction(token, x, y, wave)` | Fill a contiguous region via wave function collapse algorithm |
| `RepeatBlock(token, blockIdx, collision, x, y, w, h)` | Fill a rectangle with a single block |
| `RepeatBlocks(token, tiles, x, y, w, h)` | Fill a rectangle with a repeating multi-block pattern |
| `GetNeighbors(direction)` | Create positioned `BlockMapViewModel` instances for all maps connected in the given direction |
| `GetBorderThickness()` | Calculate border margins per edge: 0 if a connection exists on that edge, else `BorderThickness` (typically 2) |
| `GetEvents()` | Load all events from the events table, creating typed ViewModel instances |
| `CreateMapForWarp(warp)` | Create a new 9×9 map as a warp destination, with auto-detected wall/floor/door templates |
| `CreateNewMap(token, layout, width, height, ...)` | Low-level map/layout/blockmap allocation in the ROM |
| `ConnectNewMap(direction)` | Create a new map and establish a bidirectional connection |
| `ConnectExistingMap(direction, targetGroup, targetMap)` | Create a connection to an already-existing map (with inverse) |
| `RemoveConnections(direction)` | Remove connection(s) in a given direction (and the inverse on the target map) |
| `CanConnect(direction)` | Check if a connection can be added in the given direction |
| `ResizeMapData(token, deltaLeft, deltaTop, deltaRight, deltaBottom)` | Add/remove rows/columns, updating connection offsets and event positions |
| `EditTileset(isPrimary)` | Open the primary or secondary tileset's sprite+palette in an image editor tab |
| `ClearCaches()` | Invalidate all render caches (`palettes`, `tiles`, `blocks`, `blockAttributes`, `blockRenders`, `blockPixels`, `pixelData`), forcing lazy re-render on next access |
| `ClearPixelCache()` | Invalidate only the map pixel data (not the blockset caches) |
| `FillMapPixelData()` | Full map render: border + blocks + collision highlights + event sprites |
| `FillBlockPixelData()` | Render the block picker panel (all 1024 metatiles in 8-column grid) |
| `RefreshPaletteCache()` | Reload palette data from both tilesets |
| `RefreshTileCache()` | Decompress and reload 8×8 tile graphics from both tilesets |
| `RefreshBlockCache()` | Reload metatile definitions (tile references) from both tilesets |
| `RefreshBlockAttributeCache()` | Reload per-metatile attribute data from both tilesets |
| `RefreshBlockRenderCache()` | Composite all metatile 16×16 pixel images from tiles + palettes |
| `FindLayoutUses()` | Count how many maps reference the same layout address |
| `UpdateEdgesFromScale()` | Recalculate `LeftEdge`/`TopEdge` to keep the visual center stable after zoom |
| `UpdateLayoutID(token)` | Synchronize the `layoutID` field in the map header with the actual layout pointer |

### Key Model Class Properties

| Class.Property | Type | Purpose |
|----------------|------|---------|
| `AllMapsModel.Count` | `int` | Number of banks (43 in FRLG) |
| `MapBankModel.Count` | `int` | Number of maps in this bank |
| `MapModel.Layout` | `LayoutModel` | The map's layout (via pointer) |
| `MapModel.Events` | table element | The map's events struct |
| `MapModel.Connections` | table element | The map's connections struct |
| `LayoutModel.Width` | `int` | Map width in metatiles |
| `LayoutModel.Height` | `int` | Map height in metatiles |
| `LayoutModel.PrimaryBlockset` | table element | Primary tileset struct |
| `LayoutModel.SecondaryBlockset` | table element | Secondary tileset struct |
| `LayoutModel.BlockMap` | table element | Blockmap data (via `BlockmapRun`) |
| `BlockCells[x, y]` | `BlockCell` | Read-only accessor for blockmap cells |
| `BlockCell.Tile` | `int` | Metatile ID (bits 0–9) |
| `BlockCell.Collision` | `int` | Collision value (bits 10–11) |
| `BlockCell.Block` | `int` | Full 16-bit cell value |
| `ConnectionModel.Direction` | `int` | Connection direction (1–6) |
| `ConnectionModel.Offset` | `int` | Signed alignment offset along shared edge |
| `ConnectionModel.MapGroup` | `int` | Target map group |
| `ConnectionModel.MapNum` | `int` | Target map number |

---

*Generated from analysis of HexManiac Advance source and the pokefirered decomp.*
