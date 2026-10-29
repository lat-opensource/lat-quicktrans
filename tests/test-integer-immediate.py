#!/usr/bin/env python3
"""Execute actual immediate emission over widths, forms, flags and boundary values."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
src=(root/'src/emitter/fast_translator/emit-alu.inc.c').read_text()
a=src.index('static bool ft_emit_logic_imm_reg(')
b=src.index('static bool ft_emit_alu_template(',a)
helper=src[a:b]
header = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
enum {FT_ALU_AND,FT_ALU_ADD,FT_ALU_SUB,FT_ALU_OR,FT_ALU_XOR,FT_ALU_FORM_ACC_IMM,FT_ALU_FORM_RM_IMM,FT_ALU_FORM_RM_R,dt_X86_PREFIX_LOCK=0xf0,GPR_NUM=16,rax_index=0,la_zero=31};
typedef struct {int alu_op,alu_width,alu_form,modrm_mod,rm,prefix0;bool skip_flags;int64_t imm;} FastTemplateFields;
static uint64_t r[32];static int n;
#define ft_modrm_rm_index(f) ((f)->rm)
#define ft_gpr(x) (x)
static uint64_t bits(int hi,int lo) {assert(hi>=lo&&hi<64&&lo>=0);return (UINT64_MAX>>(63-hi)) & (UINT64_MAX<<lo);}
#define FT_LA_ANDI_EMIT(out,d,s,i) do {assert((uint64_t)(i)<=4095);r[d]=r[s]&(i);n++;(*out)++;} while(0)
#define FT_LA_BSTRPICK_D_EMIT(out,d,s,h,l) do {r[d]=(r[s]&bits(h,l))>>(l);n++;(*out)++;} while(0)
#define FT_LA_BSTRINS_D_EMIT(out,d,s,h,l) do {uint64_t m=bits(h,l);r[d]=(r[d]&~m)|((r[s]<<(l))&m);n++;(*out)++;} while(0)

#define ft_fits_simm12(v) ((v)>=-2048 && (v)<=2047)
#define FT_LA_ADDI_D_EMIT(out,d,s,i) do {r[d]=r[s]+(uint64_t)(i);n++;(*out)++;} while(0)
#define FT_LA_ADDI_W_EMIT(out,d,s,i) do {r[d]=(int64_t)(int32_t)((uint32_t)r[s]+(uint32_t)(i));n++;(*out)++;} while(0)
#define FT_LA_ORI_EMIT(out,d,s,i) do {assert((uint64_t)(i)<=4095);r[d]=r[s]|(i);n++;(*out)++;} while(0)
#define FT_LA_XORI_EMIT(out,d,s,i) do {assert((uint64_t)(i)<=4095);r[d]=r[s]^(i);n++;(*out)++;} while(0)
'''
main = r'''
int main(void) {
 uint32_t code[8];uint64_t state=0x7437391919ULL;unsigned cases=0,hits=0;
 int64_t imms[]={-2147483648LL,-4096,-2049,-2048,-2047,-1,0,1,3,2047,2048,4095,4096,2147483647};
 for(int op=FT_ALU_ADD;op<=FT_ALU_XOR;op++)for(int w=8;w<=64;w*=2)for(int form=0;form<3;form++)for(int flags=0;flags<2;flags++)for(int mem=0;mem<2;mem++)for(int reg=0;reg<3;reg++)for(unsigned mi=0;mi<sizeof(imms)/sizeof(imms[0]);mi++)for(int v=0;v<20;v++) {
  state^=state<<13;state^=state>>7;state^=state<<17;
  uint64_t value=v==0?UINT64_MAX:v==1?0:v==2?0x80000000ffffffffULL:state;
  FastTemplateFields f={.alu_op=op,.alu_width=w,.alu_form=form==0?FT_ALU_FORM_ACC_IMM:form==1?FT_ALU_FORM_RM_IMM:FT_ALU_FORM_RM_R,.modrm_mod=mem?0:3,.rm=reg==0?0:reg==1?8:16,.skip_flags=flags,.imm=imms[mi]};
  int dst=form==0?0:f.rm;for(int j=0;j<32;j++)r[j]=value;r[31]=0;n=0;uint32_t *out=code;
  bool logic=op==FT_ALU_OR||op==FT_ALU_XOR;
  bool ok=logic?ft_emit_logic_imm_reg(&out,&f):ft_emit_addsub_imm_reg(&out,&f);
  int64_t addend=op==FT_ALU_ADD?f.imm:-f.imm;
  uint64_t imm=w==32?(uint32_t)f.imm:(uint64_t)f.imm;
  bool eligible=EXPECT_LOCAL && flags && w>=32 && (form==0 || (form==1&&!mem&&dst<16)) && (logic?imm<=4095:ft_fits_simm12(addend));
  assert(ok==eligible);
  if(ok) {
   uint64_t expected=op==FT_ALU_ADD?value+(uint64_t)f.imm:op==FT_ALU_SUB?value-(uint64_t)f.imm:op==FT_ALU_OR?value|imm:value^imm;
   if(w==32)expected=(uint32_t)expected;
   assert(r[dst]==expected);assert(n==(w==32?2:1));hits++;
  } else {assert(n==0&&out==code);if(dst<16)assert(r[dst]==value);}
  cases++;
 }
 printf("integer immediate semantic cases=%u hits=%u local-sequence=%d PASS\n",cases,hits,EXPECT_LOCAL);
}
'''
with tempfile.TemporaryDirectory() as d:
    c=Path(d)/'test.c';c.write_text(header+helper+main)
    for label,flags in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LOCAL=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('latu-native',['-DQUICKTRANS_LATU=1','-DEXPECT_LOCAL=1']),('user',['-DEXPECT_LOCAL=0'])]:
        exe=Path(d)/label
        subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined',*flags,str(c),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
