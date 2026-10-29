/* Native non-timing comparison of raw MOVSS store sequences.
 * cc -O2 -mlsx test-movss-store-native.c -o /tmp/movss && /tmp/movss */
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
int main(void){unsigned cases=0;uint32_t bits=0x12345678;
for(unsigned i=0;i<65536;i++)for(unsigned offset=0;offset<8;offset++){
uint32_t input[4]={bits,0xffffffff,0x7fc00000,0x80000000};unsigned char a[24],b[24],want[24];
memset(a,0xa5,24);memset(b,0xa5,24);memset(want,0xa5,24);memcpy(want+offset,&bits,4);
__asm__ volatile("vld $vr0,%0,0\n\tvpickve2gr.wu $t0,$vr0,0\n\tst.w $t0,%1,0"::"r"(input),"r"(a+offset):"$f0","$t0","memory");
__asm__ volatile("vld $vr0,%0,0\n\tfst.s $f0,%1,0"::"r"(input),"r"(b+offset):"$f0","memory");
assert(!memcmp(a,b,24)&&!memcmp(b,want,24));bits=bits*1664525U+1013904223U;cases++;}printf("native MOVSS store sequences: %u cases PASS\n",cases);}
