# gbagfx (optional)

The **hex / graphics preview** decodes GBA palettes and 4bpp/8bpp tiles in **Python**, matching pret
[`tools/gbagfx/gfx.c`](https://github.com/pret/pokeemerald/blob/master/tools/gbagfx/gfx.c)
(`ReadGbaPalette`, tile nybble layout, `UPCONVERT_BIT_DEPTH`), and writes PNG with **Pillow**. You do **not**
need `deps/gbagfx` for the editor.

You may still place the Linux ELF build of pret’s `gbagfx` at `deps/gbagfx` for **manual** command-line use, e.g.:

- `gbagfx file.gbapal file.pal`
- `gbagfx file.4bpp file.png -palette file.pal -mwidth <tiles_wide>`

LZ77 in-app matches pret [`tools/gbagfx/lz.c`](https://github.com/pret/pokeemerald/blob/master/tools/gbagfx/lz.c)
(type `0x10`, MSB-first flags: **1** = ref, **0** = literal).
