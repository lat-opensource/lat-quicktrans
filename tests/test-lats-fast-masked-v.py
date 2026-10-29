#!/usr/bin/env python3
"""Execute the real FCSR emitter operations for all 16-bit MXCSR inputs."""
import os, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
def function(file,name):
 s=file.read_text();n=s.index(name+'(');a=s.rfind('static ',0,n);b=s.index('{',n);level=1;i=b+1
 while level:
  level+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[a:i]
base=root/'src/emitter/fast_translator'
src=function(base/'fast-translator.c','ft_fast_masked_v_enabled')+'\n'+function(base/'emit-helper.inc.c','ft_emit_lats_soft_fcsr_from_mxcsr')+'\n'+function(base/'emit-helper.inc.c','ft_emit_mxcsr_flags_from_fcsr')
header=r'''#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
static uint32_t r[8],fcsr,count;
static int option_fast_masked_v;
static int option_soft_fpu=1;
#define CONFIG_SOFTMMU 1
enum {la_t0,la_t1,la_t2,la_t3,la_t4};
#define FCSR_OFF_RM 8
#define FCSR_OFF_EN_V 4
#define FCSR_OFF_FLAGS_V 20
#define FCSR_OFF_FLAGS_Z 19
#define FCSR_OFF_FLAGS_O 18
#define FCSR_OFF_FLAGS_U 17
#define FCSR_OFF_FLAGS_I 16
#define EMIT(o,x) do {(void)(o);x;count++;}while(0)
static uint32_t reverse_bytes(uint32_t x){uint32_t y=0;for(int i=0;i<32;i++)y|=((x>>i)&1)<<((i&~7)+7-(i&7));return y;}
static uint32_t mask(int hi,int lo){return (uint32_t)(((1ull<<(hi-lo+1))-1)<<lo);}
#define FT_LA_BSTRPICK_W_EMIT(o,d,s,h,l) EMIT(o,r[d]=(r[s]&mask(h,l))>>(l))
#define FT_LA_BSTRINS_W_EMIT(o,d,s,h,l) EMIT(o,r[d]=(r[d]&~mask(h,l))|((r[s]<<(l))&mask(h,l)))
#define FT_LA_ANDI_EMIT(o,d,s,i) EMIT(o,r[d]=r[s]&(i))
#define FT_LA_ORI_EMIT(o,d,s,i) EMIT(o,r[d]=r[s]|(i))
#define FT_LA_SLLI_W_EMIT(o,d,s,i) EMIT(o,r[d]=r[s]<<(i))
#define FT_LA_SLLI_D_EMIT FT_LA_SLLI_W_EMIT
#define FT_LA_SRLI_W_EMIT(o,d,s,i) EMIT(o,r[d]=r[s]>>(i))
#define FT_LA_OR_EMIT(o,d,s,t) EMIT(o,r[d]=r[s]|r[t])
#define FT_LA_MOVFCSR2GR_EMIT(o,d,s) EMIT(o,r[d]=fcsr)
#define FT_LA_XOR_EMIT(o,d,s,t) EMIT(o,r[d]=r[s]^r[t])
#define FT_LA_BITREV_4B_EMIT(o,d,s) EMIT(o,r[d]=reverse_bytes(r[s]))
#define FT_LA_MOVGR2FCSR_EMIT(o,d,s) EMIT(o,fcsr=r[s])
'''
main=r'''
int main(void){
 uint32_t *out=0;
 const int rm[]={0,3,2,1};
 for(int enabled=0;enabled<2;enabled++)for(unsigned m=0;m<65536;m++){
  option_fast_masked_v=enabled;r[la_t1]=m;count=0;
  ft_emit_lats_soft_fcsr_from_mxcsr(&out,la_t1);
  unsigned flags=((m&1)<<4)|((m>>2&1)<<3)|((m>>3&1)<<2)|((m>>4&1)<<1)|(m>>5&1);
  unsigned expected=(rm[m>>13&3]<<8)|(flags<<16)|(flags<<24)|(enabled?16:0);
  assert(fcsr==expected);assert(r[la_t1]==m);assert(count==13u+enabled);
 }
 for(unsigned m=0;m<65536;m++)for(unsigned hw=0;hw<32;hw++){
  fcsr=hw<<16;r[la_t1]=m;
  ft_emit_mxcsr_flags_from_fcsr(&out,la_t1);
  unsigned flags=(hw>>4&1)|((hw>>3&1)<<2)|((hw>>2&1)<<3)|((hw>>1&1)<<4)|((hw&1)<<5);
  assert(r[la_t1]==((m&~0x3du)|flags));
 }
 puts("LATS fast_masked_v: 131072 FCSR mappings PASS");
}
'''
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'test.c';c.write_text(header+src+main);exe=Path(d)/'test'
 subprocess.run([os.environ.get('CC','cc'),'-O2','-Wall','-Werror',str(c),'-o',str(exe)],check=True)
 subprocess.run([str(exe)],check=True)
