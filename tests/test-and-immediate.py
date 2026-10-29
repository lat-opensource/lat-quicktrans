#!/usr/bin/env python3
"""Execute actual AND-immediate emission with a small LA semantic model."""
import os
import subprocess
import tempfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
src = (root/'src/emitter/fast_translator/emit-alu.inc.c').read_text()
a = src.index('static bool ft_emit_and_imm_reg(')
b = src.index('/* Keep the existing flag computation', a)
helper = src[a:b]
assert src[b:].count('if (op == FT_ALU_AND && ft_emit_and_imm_reg(out, fields))') == 2
header = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
enum {FT_ALU_AND,FT_ALU_ADD,FT_ALU_FORM_ACC_IMM,FT_ALU_FORM_RM_IMM,FT_ALU_FORM_RM_R,dt_X86_PREFIX_LOCK=0xf0,GPR_NUM=16,rax_index=0,la_t2=24,la_zero=31};
typedef struct {int alu_op,alu_width,alu_form,modrm_mod,rm,prefix0;bool skip_flags;int64_t imm;} FastTemplateFields;
static uint64_t r[32];static int n;
#define ft_modrm_rm_index(f) ((f)->rm)
#define ft_gpr(x) (x)
static uint64_t bits(int hi,int lo) {assert(hi>=lo&&hi<64&&lo>=0);return (UINT64_MAX>>(63-hi)) & (UINT64_MAX<<lo);}
#define FT_LA_ANDI_EMIT(out,d,s,i) do {assert((uint64_t)(i)<=4095);r[d]=r[s]&(i);n++;(*out)++;} while(0)
#define FT_LA_BSTRPICK_D_EMIT(out,d,s,h,l) do {r[d]=(r[s]&bits(h,l))>>(l);n++;(*out)++;} while(0)
#define FT_LA_BSTRINS_D_EMIT(out,d,s,h,l) do {uint64_t m=bits(h,l);r[d]=(r[d]&~m)|((r[s]<<(l))&m);n++;(*out)++;} while(0)
'''
main=r'''
int main(void) {
 uint32_t code[8];uint64_t state=0x7437391919ULL;unsigned cases=0,hits=0;
 int64_t masks[400]={0,3,4095,4096,65535,0x7fffffff,(int64_t)(int32_t)0x80000000,-1,-8,0xff00};int nm=10;
 for(int k=1;k<32;k++){masks[nm++]=(1LL<<k)-1;masks[nm++]=-(1LL<<k);}
 for(int k=0;k<64;k++){state^=state<<13;state^=state>>7;state^=state<<17;masks[nm++]=(int32_t)state;}
 for(int w=32;w<=64;w+=32)for(int form=0;form<3;form++)for(int flags=0;flags<2;flags++)for(int lock=0;lock<2;lock++)for(int mem=0;mem<2;mem++)for(int reg=0;reg<3;reg++)for(int mi=0;mi<nm;mi++)for(int v=0;v<5;v++) {
  state^=state<<13;state^=state>>7;state^=state<<17;
  uint64_t value=v==0?UINT64_MAX:v==1?0:v==2?0x80000000ffffffffULL:state;
  FastTemplateFields f={.alu_op=FT_ALU_AND,.alu_width=w,.alu_form=form==0?FT_ALU_FORM_ACC_IMM:form==1?FT_ALU_FORM_RM_IMM:FT_ALU_FORM_RM_R,.modrm_mod=mem?0:3,.rm=reg==0?0:reg==1?8:16,.prefix0=lock?dt_X86_PREFIX_LOCK:0,.skip_flags=flags,.imm=masks[mi]};
  int dst=form==0?0:f.rm;for(int j=0;j<32;j++)r[j]=value;r[31]=0;n=0;uint32_t *out=code;
  bool ok=ft_emit_and_imm_reg(&out,&f);
  bool eligible=EXPECT_LOCAL && flags && !lock && (form==0 || (form==1&&!mem&&dst<16));
  if(ok) {
   assert(eligible);uint64_t expected=value & (uint64_t)f.imm;if(w==32)expected=(uint32_t)expected;
   assert(r[dst]==expected);assert(n>=1&&n<=2);hits++;
  } else {assert(n==0&&out==code);if(dst<16)assert(r[dst]==value);}
  if(eligible && (mi==0||mi==1||mi==2||mi==4||mi==5||mi==8))assert(ok);
  if(!eligible)assert(!ok);
  cases++;
 }
 FastTemplateFields rejected={.alu_op=FT_ALU_ADD,.alu_width=32,.alu_form=FT_ALU_FORM_ACC_IMM,.skip_flags=true,.imm=3};
 uint32_t *out=code;assert(!ft_emit_and_imm_reg(&out,&rejected));
 rejected.alu_op=FT_ALU_AND;rejected.alu_width=16;
#if defined(QUICKTRANS_LATU) && !defined(CONFIG_SOFTMMU)
 for(int mi=0;mi<nm;mi++) {
  uint64_t value=UINT64_C(0xdeadbeef89abcdef);
  rejected.imm=masks[mi];r[0]=value;r[31]=0;out=code;n=0;
  bool ok=ft_emit_and_imm_reg(&out,&rejected);
  uint16_t mask=(uint16_t)rejected.imm;
  bool eligible=mask!=65535 && (((mask & (mask+1))==0)||mask<=4095);
  assert(ok==eligible);
  assert(r[0]==(ok?((value & ~UINT64_C(65535)) | ((uint16_t)value & mask)):value));
  assert(ok?(n>=1&&n<=2):(n==0));
 }
#else
 assert(!ft_emit_and_imm_reg(&out,&rejected));
#endif
 rejected.alu_width=8;assert(!ft_emit_and_imm_reg(&out,&rejected));
 printf("AND immediate semantic cases=%u hits=%u local-sequence=%d PASS\n",cases,hits,EXPECT_LOCAL);
}
'''
with tempfile.TemporaryDirectory() as d:
    c=Path(d)/'test.c';c.write_text(header+helper+main)
    for label,flags in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LOCAL=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('latu-native',['-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('user',['-DEXPECT_LOCAL=0'])]:
        exe=Path(d)/label
        # Keep UB checks without requiring the shared libubsan runtime.
        subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined','-fsanitize-undefined-trap-on-error',*flags,str(c),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
