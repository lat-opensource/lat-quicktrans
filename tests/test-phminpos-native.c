/* Native LSX check: cc -O2 -mlsx test-phminpos-native.c -o /tmp/phmin && /tmp/phmin */
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#define REST \
 "vmin.hu $vr1,$vr1,$vr0\n\t" \
 "vsrli.d $vr1,$vr1,16\n\t" \
 "vmin.hu $vr1,$vr1,$vr0\n\t" \
 "vsrli.d $vr1,$vr1,16\n\t" \
 "vmin.hu $vr1,$vr1,$vr0\n\t" \
 "vandi.b $vr3,$vr3,0\n\t" \
 "vextrins.d $vr3,$vr1,1\n\t" \
 "vmin.hu $vr1,$vr1,$vr3\n\t" \
 "vreplvei.h $vr1,$vr1,0\n\t" \
 "vseq.h $vr2,$vr0,$vr1\n\t" \
 "vfrstpi.h $vr3,$vr2,0\n\t" \
 "vpackev.h $vr0,$vr3,$vr1\n\t" \
 "vinsgr2vr.d $vr0,$zero,1\n\t" \
 "vinsgr2vr.w $vr0,$zero,1\n\t" \
 "vst $vr0,%0,0\n\t"
#define RUN(PREFIX,OUT) __asm__ volatile("vld $vr0,%1,0\n\t" PREFIX REST : : "r"(OUT),"r"(in) : "$f0","$f1","$f2","$f3","memory")
int main(void){unsigned cases=0;uint64_t seed=123456789;
for(unsigned c=0;c<100000;c++){uint16_t in[8],old[8],now[8],want[8]={0};for(int i=0;i<8;i++){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;in[i]=c<65536?c:seed;}if(c>=65536&&c%3==0)in[c%8]=in[(c+1)%8]=0;
want[0]=in[0];for(int i=1;i<8;i++)if(in[i]<want[0]){want[0]=in[i];want[1]=i;}
RUN("vori.b $vr1,$vr0,0\n\tvsrli.d $vr1,$vr1,16\n\t",old);
RUN("vsrli.d $vr1,$vr0,16\n\t",now);
assert(!memcmp(old,now,16));assert(!memcmp(want,now,16));cases++;}printf("native PHMINPOSUW old/new/scalar: %u cases PASS\n",cases);}
