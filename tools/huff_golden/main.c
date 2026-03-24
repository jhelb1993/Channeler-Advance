#include "global.h"
#include "huff.h"

static void dump_hex(const unsigned char *p, int n) {
    for (int i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

int main(void) {
    unsigned char buf[256];
    int n = 32;
    for (int i = 0; i < n; i++)
        buf[i] = (unsigned char)i;

    int bit = 4;
    int cs = 0;
    unsigned char *c = HuffCompress(buf, n, &cs, bit);
    printf("compressed_len=%d\n", cs);
    dump_hex(c, cs);

    int us = 0;
    unsigned char *d = HuffDecompress(c, cs, &us);
    printf("us=%d\n", us);
    for (int i = 0; i < n && i < us; i++) {
        if (d[i] != buf[i]) {
            printf("first diff at %d: got %02x want %02x\n", i, d[i], buf[i]);
            break;
        }
    }
    if (us != n)
        printf("size mismatch us=%d n=%d\n", us, n);
    free(d);
    free(c);
    return 0;
}
