# gbagfx (Linux binary)

Place the **Linux ELF** build of pret’s `gbagfx` at:

`deps/gbagfx`

On **Windows**, the editor runs it through **WSL** (`wsl wslpath` + `wsl <path-to-gbagfx> …`).

Ensure WSL is installed and can execute binaries from `/mnt/c/...`.

Palette step: `gbagfx file.gbapal file.pal`  
Sprite step: `gbagfx file.4bpp file.png -palette file.pal -mwidth <tiles_wide>`

LZ77 decompression in-app matches **pret** [`tools/gbagfx/lz.c`](https://github.com/pret/pokeemerald/blob/master/tools/gbagfx/lz.c) (type `0x10`, 24-bit LE size, MSB-first flags: **1** = ref, **0** = literal). For the abstract LZ77 idea, see e.g. [this overview](https://cs.stanford.edu/people/eroberts/courses/soco/projects/data-compression/lossless/lz77/algorithm.htm).
