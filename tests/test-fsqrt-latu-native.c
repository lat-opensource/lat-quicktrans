/* Native LA reproduction; not a guest entry or performance test.
 * cc -O2 test-fsqrt-latu-native.c -o /tmp/fsqrt-check && /tmp/fsqrt-check */
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
int main(void)
{
    const uint64_t inputs[] = {0,0x8000000000000000ULL,
        0x3ff0000000000000ULL,0x4010000000000000ULL,
        0xbff0000000000000ULL,0x7ff0000000000000ULL,
        0xfff0000000000000ULL,0x7ff8000000000123ULL,
        0xfff8000000000123ULL,1,0x8000000000000001ULL};
    unsigned saved, count=0, differences=0;
    __asm__ volatile("movfcsr2gr %0,$fcsr0":"=r"(saved));
    for(unsigned mode=0;mode<4;mode++) for(unsigned i=0;i<sizeof(inputs)/sizeof(inputs[0]);i++) {
        uint64_t input=inputs[i], direct, previous;
        unsigned control=mode<<8, direct_status, previous_status;
        __asm__ volatile("movgr2fcsr $fcsr0,%3\n\tmovgr2fr.d $f0,%2\n\t"
            "fsqrt.d $f0,$f0\n\tmovfr2gr.d %0,$f0\n\tmovfcsr2gr %1,$fcsr0"
            :"=&r"(direct),"=&r"(direct_status):"r"(input),"r"(control):"$f0");
        uint64_t nan=0xfff8000000000000ULL;
        __asm__ volatile("movgr2fcsr $fcsr0,%3\n\tmovgr2fr.d $f0,%2\n\t"
            "movfr2gr.d $t0,$f0\n\tsrai.d $t1,$t0,63\n\t"
            "fsqrt.d $f0,$f0\n\tmovfr2gr.d $t2,$f0\n\t"
            "and $t3,%4,$t1\n\tandn $t2,$t2,$t1\n\tor $t2,$t2,$t3\n\t"
            "movgr2fr.d $f0,$t2\n\tmovfr2gr.d %0,$f0\n\tmovfcsr2gr %1,$fcsr0"
            :"=&r"(previous),"=&r"(previous_status):"r"(input),"r"(control),"r"(nan)
            :"$f0","$t0","$t1","$t2","$t3");
        assert(direct_status==previous_status);
        if(input==0x8000000000000000ULL) {
            assert(direct==input && previous==nan);
            printf("mode %u: -zero old-LATU=%016llx previous-QT=%016llx\n",mode,
                (unsigned long long)direct,(unsigned long long)previous);
        }
        differences += direct!=previous;
        count++;
    }
    __asm__ volatile("movgr2fcsr $fcsr0,%0"::"r"(saved));
    printf("%u cases; %u output differences; FCSR identical; PASS\n",count,differences);
}
