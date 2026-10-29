#!/usr/bin/env python3
"""Run actual MOVBE emitter bodies with register/memory semantics."""
import os, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/emitter/fast_translator/emit-gpr.inc.c').read_text()
a=s.index('static int ft_movbe_width(');b=s.index('static int ft_crc32_source_width(',a)
body=s[a:b]
header=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
enum {FT_MOVBE_R64_M64,FT_MOVBE_R32_M32,FT_MOVBE_R16_M16,FT_MOVBE_M64_R64,FT_MOVBE_M32_R32,FT_MOVBE_M16_R16,GPR_NUM=16,la_t2=18,la_zero=31,dt_X86_PREFIX_OPSIZE=0x66};
typedef struct {int kind,reg,modrm_mod,prefix2;bool rex;} FastTemplateFields;
typedef int FastTemplateKind;typedef int TranslationBlock;typedef uint64_t target_ulong;
static uint64_t r[32],mem;
#define ft_modrm_reg_index(f) ((f)->reg)
#define ft_rex_w(f) ((f)->rex)
#define ft_gpr(i) (i)
#define T(o) (++*(o))
#define FT_LA_REVB_D_EMIT(o,d,s) do{r[d]=__builtin_bswap64(r[s]);T(o);}while(0)
#define FT_LA_REVB_2W_EMIT(o,d,s) do{r[d]=((uint64_t)__builtin_bswap32(r[s]>>32)<<32)|__builtin_bswap32(r[s]);T(o);}while(0)
#define FT_LA_REVB_2H_EMIT(o,d,s) do{r[d]=((r[s]&0xff00ff00ff00ff00ULL)>>8)|((r[s]&0x00ff00ff00ff00ffULL)<<8);T(o);}while(0)
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) do{r[d]=(r[s]&((1ULL<<((h)+1))-1))>>(l);T(o);}while(0)
#define FT_LA_BSTRINS_D_EMIT(o,d,s,h,l) do{r[d]=(r[d]&~65535ULL)|(r[s]&65535);T(o);}while(0)
#define FT_LA_OR_EMIT(o,d,s,t) do{r[d]=r[s]|r[t];T(o);}while(0)
static bool load(uint32_t **o,int *s,int w){r[16]=w==64?mem:w==32?(uint64_t)(int64_t)(int32_t)mem:(uint16_t)mem;*s=16;T(o);return true;}
static bool store(uint32_t **o,int s,int w){mem=w==64?r[s]:w==32?(uint32_t)r[s]:(uint16_t)r[s];T(o);return true;}
#define ft_emit_load_rm64(o,f,p,s) load(o,s,64)
#define ft_emit_load_rm32(o,f,p,s) load(o,s,32)
#define ft_emit_load_rm16(o,f,p,s) load(o,s,16)
#define ft_emit_store_rm64(o,f,p,s) store(o,s,64)
#define ft_emit_store_rm32(o,f,p,s,z) store(o,s,32)
#define ft_emit_store_rm16(o,f,p,s) store(o,s,16)
'''
main=r'''
int main(void){uint64_t state=0x70123456789abcdeULL;unsigned cases=0;
 for(int kind=0;kind<6;kind++)for(int reg=0;reg<16;reg++)for(int j=0;j<72;j++){
  state^=state<<13;state^=state>>7;state^=state<<17;uint64_t value=j==0?0:j<65?1ULL<<(j-1):state;
  FastTemplateFields f={.kind=kind,.reg=reg,.modrm_mod=0,.rex=kind%3==0,.prefix2=kind%3==2?0x66:0};
  int w=kind%3==0?64:kind%3==1?32:16;bool isstore=kind>=3;
  for(int i=0;i<32;i++)r[i]=state;r[reg]=value;r[31]=0;mem=value;uint64_t initial=r[reg];uint32_t code[32];
  int n=ft_emit_movbe_template(&f,0,0,code);uint64_t result=0;
  for(int i=0;i<w/8;i++)result|=((value>>(i*8))&255)<<(w-8-i*8);
  assert(n==(isstore?(w==64?2:3):(w==64?(EXPECT_LATS?2:3):w==32?(EXPECT_LATS?3:4):4)));
  if(isstore)assert(mem==result&&r[reg]==initial);
  else {assert(mem==value);assert(r[reg]==(w==16?(initial&~65535ULL)|result:result));}
  cases++;
 }
 printf("actual MOVBE emission %u cases PASS LATS=%d\n",cases,EXPECT_LATS);
}
'''
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'movbe.c';c.write_text(header+body+main)
 for label,defs in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LATS=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),('user',['-DEXPECT_LATS=0'])]:
  exe=Path(d)/label
  subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined',*defs,str(c),'-o',str(exe)],check=True)
  subprocess.run([str(exe)],check=True)
