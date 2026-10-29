#!/usr/bin/env python3
"""Interpret actual BSF/BSR emission, including its zero-source branch."""
import os, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/emitter/fast_translator/emit-template.inc.c').read_text()
block=s[s.index('    case FT_BSF_R64_RM64:'):s.index('    case FT_MUL_RM64:')]
header=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
enum {FT_BSF_R64_RM64,FT_BSF_R32_RM32,FT_BSF_R16_RM16,FT_BSR_R64_RM64,FT_BSR_R32_RM32,FT_BSR_R16_RM16,GPR_NUM=16,la_t0=16,la_t2=18,la_t3=19,la_t4=20,la_zero=31,ZF_USEDEF_BIT=64,FT_LA_OPCODE_CLZ_D=1,FT_LA_OPCODE_CTZ_D=2};
typedef struct {int kind,dst,src,modrm_mod;bool skip_flags,rex;} FastTemplateFields;
typedef int TranslationBlock;typedef uint64_t target_ulong;
typedef struct {int op,d,s,t,h,l;} Ins;
static Ins ins[64];static int n;static uint64_t r[32],flags,mem;
static uint32_t add(int op,int d,int s,int t,int h,int l){ins[n]=(Ins){op,d,s,t,h,l};return n++;}
#define E(out,op,d,s,t,h,l) do{*(*(out))++=add(op,d,s,t,h,l);}while(0)
#define FT_LA_OR_EMIT(o,d,s,t) E(o,3,d,s,t,0,0)
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) E(o,4,d,s,0,h,l)
#define FT_LA_BSTRINS_D_EMIT(o,d,s,h,l) E(o,5,d,s,0,h,l)
#define FT_LA_BEQ_EMIT(o,s,t,k) E(o,6,0,s,t,k,0)
#define FT_LA_ADDI_D_EMIT(o,d,s,i) E(o,7,d,s,0,i,0)
#define FT_LA_SUB_D_EMIT(o,d,s,t) E(o,8,d,s,t,0,0)
#define FT_LA_X86MTFLAG_EMIT(o,s,m) E(o,9,0,s,0,m,0)
#define ft_gpr(d) (d)
#define ft_rex_w(f) ((f)->rex)
#define ft_modrm_reg_index(f) ((f)->dst)
#define ft_scratch_avoid3(s,d,t) (la_t3)
static uint32_t ft_gpr2_rd_rj(int op,int d,int s){return add(op,d,s,0,0,0);}
static void ft_emit_raw(uint32_t **o,uint32_t i){*(*o)++=i;}
static bool load(uint32_t **o,const FastTemplateFields*f,int*s,int w){
 if(f->src>=16)return false;
 if(f->modrm_mod==3)*s=f->src;
 else {E(o,10,la_t0,0,0,w,0);*s=la_t0;}
 return true;
}
#define ft_emit_load_rm64(o,f,p,s) load(o,f,s,64)
#define ft_emit_load_rm32(o,f,p,s) load(o,f,s,32)
#define ft_emit_load_rm16(o,f,p,s) load(o,f,s,16)
static void ft_count_bits_set_zf_from_zero(uint32_t **o,int s){E(o,11,0,s,0,0,0);}
static int emit(const FastTemplateFields *fields, TranslationBlock *tb,target_ulong pc,uint32_t *code){uint32_t *out=code;switch(fields->kind){
'''
tail=r'''
default:return 0;}return out-code;}
static void run(uint32_t*code,int count){
 for(int ip=0;ip<count;ip++){
  Ins x=ins[code[ip]];uint64_t mask=x.h==63?UINT64_MAX:x.h>=0&&x.h<63?((1ULL<<(x.h+1))-1):0;
  switch(x.op){
  case 1:r[x.d]=__builtin_clzll(r[x.s]);break;
  case 2:r[x.d]=__builtin_ctzll(r[x.s]);break;
  case 3:r[x.d]=r[x.s]|r[x.t];break;
  case 4:r[x.d]=(r[x.s]&mask)>>x.l;break;
  case 5:mask&=UINT64_MAX<<x.l;r[x.d]=(r[x.d]&~mask)|((r[x.s]<<x.l)&mask);break;
  case 6:if(r[x.s]==r[x.t])ip+=x.h-1;break;
  case 7:r[x.d]=r[x.s]+x.h;break;
  case 8:r[x.d]=r[x.s]-r[x.t];break;
  case 9:flags=(flags&~(uint64_t)x.h)|(r[x.s]&x.h);break;
  case 10:r[x.d]=x.h==64?mem:x.h==32?(uint64_t)(int64_t)(int32_t)mem:(uint16_t)mem;break;
  case 11:if(!r[x.s])flags|=64;break;
  default:assert(0);
  }
 }
}
int main(void){
 uint64_t seed=0x70123456789abcdeULL;unsigned cases=0;
 for(int kind=0;kind<6;kind++)for(int memory=0;memory<2;memory++)for(int overlap=0;overlap<2;overlap++)for(int dead=0;dead<2;dead++)for(int j=0;j<72;j++){
  seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;
  uint64_t v=j==0?0:j<65?1ULL<<(j-1):seed;
  int w=kind%3==0?64:kind%3==1?32:16;
  uint64_t value=w==64?v:w==32?(uint32_t)v:(uint16_t)v;
  for(int k=0;k<32;k++)r[k]=seed;r[31]=0;r[8]=v;mem=v;
  FastTemplateFields f={.kind=kind,.dst=overlap?8:0,.src=8,.modrm_mod=memory?0:3,.skip_flags=dead,.rex=w==64};
  uint64_t initial=r[f.dst],expected=initial;flags=0x8d5;uint32_t code[64];n=0;
  int count=emit(&f,0,0,code);assert(count>0);run(code,count);
  if(value){uint64_t result=kind>=3?63-__builtin_clzll(value):__builtin_ctzll(value);expected=w==16?(initial&~65535ULL)|result:result;}
  assert(r[f.dst]==expected);assert((flags&~64ULL)==(0x8d5&~64ULL));
  if(!dead)assert((flags&64)==(value?0:64));else assert(flags==0x8d5);
  cases++;
 }
 printf("actual BSF/BSR emission %u cases PASS LATS=%d\n",cases,EXPECT_LATS);
}
'''
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'bscan.c';c.write_text(header+block+tail)
 for label,defs in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LATS=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),('latu-native',['-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),('user',['-DEXPECT_LATS=0'])]:
  exe=Path(d)/label
  subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined',*defs,str(c),'-o',str(exe)],check=True)
  subprocess.run([str(exe)],check=True)
