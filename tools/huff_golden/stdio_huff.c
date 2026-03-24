/* stdin: [1 byte bit_depth 4|8][3 byte LE size][raw bytes...]  -> stdout: compressed blob (padded) */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "global.h"
#include "huff.h"

int main(void) {
    int bd = fgetc(stdin);
    if (bd == EOF)
        return 1;
    unsigned char hdr[3];
    if (fread(hdr, 1, 3, stdin) != 3)
        return 1;
    int srcSize = hdr[0] | (hdr[1] << 8) | (hdr[2] << 16);
    if (srcSize < 0 || srcSize > (1 << 22))
        return 1;
    unsigned char *src = malloc((size_t)srcSize + 1);
    if (!src)
        return 1;
    if ((int)fread(src, 1, (size_t)srcSize, stdin) != srcSize) {
        free(src);
        return 1;
    }
    int cs = 0;
    unsigned char *out = HuffCompress(src, srcSize, &cs, bd);
    free(src);
    if (!out)
        return 2;
    if (fwrite(out, 1, (size_t)cs, stdout) != (size_t)cs) {
        free(out);
        return 3;
    }
    free(out);
    return 0;
}
