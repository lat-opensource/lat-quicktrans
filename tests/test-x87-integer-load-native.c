/* Native sequence check, not a timing test or a guest translator test.
 * cc -O2 test-x87-integer-load-native.c -o /tmp/x87-load && /tmp/x87-load */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#define CHECK(WIDTH, LOAD, FLOAD, CONVERT) do { \
    uint64_t before, after; unsigned sf_before, sf_after; \
    __asm__ volatile("movgr2fcsr $fcsr0,%4\n\t" \
        LOAD " $t0,%3,0\n\tmovgr2fr.d $f0,$t0\n\t" \
        CONVERT " $f0,$f0\n\tmovfr2gr.d %0,$f0\n\t" \
        "movfcsr2gr %1,$fcsr0" \
        : "=&r"(before), "=&r"(sf_before) \
        : "m"(value), "r"(&value), "r"(control) : "$t0", "$f0", "memory"); \
    __asm__ volatile("movgr2fcsr $fcsr0,%4\n\t" \
        FLOAD " $f0,%3,0\n\t" CONVERT " $f0,$f0\n\t" \
        "movfr2gr.d %0,$f0\n\tmovfcsr2gr %1,$fcsr0" \
        : "=&r"(after), "=&r"(sf_after) \
        : "m"(value), "r"(&value), "r"(control) : "$f0", "memory"); \
    if (before != after || sf_before != sf_after) { \
        fprintf(stderr, "width=%d input=%016llx mode=%u mismatch\n", \
                WIDTH, (unsigned long long)value, mode); return 1; \
    } \
    count++; \
} while (0)

int main(void)
{
    unsigned saved, count = 0;
    uint64_t random = 1;
    const uint64_t edge[] = {0,1,UINT64_MAX,0x80000000,0x7fffffff,
        0x8000000000000000ULL,0x7fffffffffffffffULL,
        0x10000000000001ULL,0x1fffffffffffffULL};
    __asm__ volatile("movfcsr2gr %0,$fcsr0" : "=r"(saved));
    for (unsigned mode = 0; mode < 4; mode++) {
        unsigned control = mode << 8;
        for (unsigned i = 0; i < 65536; i++) {
            random = random * 6364136223846793005ULL + 1;
            uint64_t value = i < sizeof(edge)/sizeof(edge[0]) ? edge[i] : random;
            CHECK(32, "ld.w", "fld.s", "ffint.d.w");
            CHECK(64, "ld.d", "fld.d", "ffint.d.l");
        }
    }
    __asm__ volatile("movgr2fcsr $fcsr0,%0" :: "r"(saved));
    printf("x87 integer load sequences: %u cases PASS\n", count);
    return 0;
}
