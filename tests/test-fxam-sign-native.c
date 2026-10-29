/* Compare the FXAM C1 replacement on real LoongArch; no timing. */
#include <stdint.h>
#include <stdio.h>
int main(void) {
    unsigned count=0;
    for (uint64_t sw=0; sw<65536; ++sw) {
        for (unsigned sign=0; sign<2; ++sign) {
            uint64_t bits=((uint64_t)sign<<63) | (sw*0x123456789abULL);
            uint64_t actual=sw&0xb8ff, tmp;
            __asm__ volatile("bstrpick.d %1,%2,63,63\n\t"
                             "bstrins.d %0,%1,9,9"
                             : "+r"(actual), "=&r"(tmp) : "r"(bits));
            uint64_t expected=(sw&0xb8ff) | ((bits>>63)<<9);
            if(actual!=expected) return 1;
            ++count;
        }
    }
    printf("FXAM C1 native equivalence: %u cases passed\n",count);
    return 0;
}
