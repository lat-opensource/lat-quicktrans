/* Run on LoongArch with: cc -O2 -mlsx test-vmskltz-native.c -o /tmp/test-vmskltz && /tmp/test-vmskltz
 * Checks native sign-mask result including all high GPR bits; no timing. */
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#define CHECK(OP) __asm__ volatile("vld $vr0, %1, 0\n\t" OP " $vr1, $vr0\n\tmovfr2gr.d %0, $f1" : "=r"(got) : "r"(input) : "$f0", "$f1", "memory")
int main(void) {
    unsigned cases=0;
    for (int width=8;width<=64;width*=2) {
        if(width==16) continue;
        for(unsigned pattern=0;pattern<65536;pattern++) {
            uint64_t input[2]={0,0}, want=0, got;
            uint64_t mask=UINT64_MAX>>(64-width);
            for(int i=0;i<128/width;i++) {
                uint64_t value=((uint64_t)pattern*0x9e3779b97f4a7c15ULL+i*131)&(mask>>1);
                if(pattern&(1U<<i)) {value|=1ULL<<(width-1);want|=1ULL<<i;}
                input[i*width/64]|=value<<(i*width%64);
            }
            if(width==8) { CHECK("vmskltz.b"); }
            else if(width==32) { CHECK("vmskltz.w"); }
            else { CHECK("vmskltz.d"); }
            assert(got==want);cases++;
        }
    }
    printf("native VMSKLTZ B/W/D: %u cases PASS\n",cases);
}
