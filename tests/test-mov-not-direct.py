#!/usr/bin/env python3
"""Execute extracted MOV and non-LOCK NOT emission bodies in three macro modes.

Memory helpers are modeled; guest probes separately exercise real decode/memory.
This is not a full LATU build. --optimized additionally checks local instruction counts.
"""
import os,subprocess,tempfile,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
g=(root/'src/emitter/fast_translator/emit-gpr.inc.c').read_text()
t=(root/'src/emitter/fast_translator/emit-template.inc.c').read_text()
f=(root/'src/emitter/fast_translator/fields.inc.c').read_text()
li=f[f.index('static int ft_simm20_field('):f.index('static void ft_emit_li64(')]
mov=g[g.index('static void ft_emit_mov_imm32(') if 'static void ft_emit_mov_imm32(' in g else g.index('static int ft_emit_mov_reg_imm_template('):g.index('static int ft_emit_mov_moffs_template(')]
rr=t[t.index('    case FT_MOV_RM32_R32:'):t.index('    case FT_MOV_RM64_IMM32:')]
# The register C7 and 89 branches are included verbatim; memory stubs are
# deliberately outside the affected optimization and receive guard checks.
notbody=g[g.index('    switch (fields->kind) {',g.index('static int ft_emit_not_template(')):g.index('static int ft_emit_neg_template(')]
header=r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
enum {FT_MOV_R8_IMM8,FT_MOV_R16_IMM16,FT_MOV_R32_IMM32,FT_MOV_R64_IMM64,FT_MOV_RM32_R32,FT_MOV_RM32_IMM32,FT_NOT_RM8,FT_NOT_RM16,FT_NOT_RM32,FT_NOT_RM64,GPR_NUM=16,la_t0=16,la_t1=17,la_t2=18,la_zero=31,dt_X86_PREFIX_OPSIZE=0x66,FT_LA_OPCODE_LU12I_W=1,FT_LA_OPCODE_ST_H=2,FT_LA_OPCODE_ST_W=3};
typedef struct {int kind,reg,rex,imm,prefix2,modrm_mod,modrm_reg,modrm_rm,segment,addr32,size,disp;} FastTemplateFields;
typedef int TranslationBlock;typedef uint64_t target_ulong;
static uint64_t r[32],mem;static unsigned loads,stores;
#define ft_gpr(i) (i)
#define ft_rex_w(f) ((f)->rex>0)
#define ft_modrm_reg_index(f) ((f)->modrm_reg)
#define ft_modrm_rm_index(f) ((f)->modrm_rm)
#define T(o) (++*(o))
#define FT_LA_ORI_EMIT(o,d,s,i) do{r[d]=r[s]|(uint32_t)(i);T(o);}while(0)
#define FT_LA_OR_EMIT(o,d,s,t) do{r[d]=r[s]|r[t];T(o);}while(0)
#define FT_LA_NOR_EMIT(o,d,s,t) do{r[d]=~(r[s]|r[t]);T(o);}while(0)
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) do{r[d]=(r[s]&((1ULL<<((h)+1))-1))>>(l);T(o);}while(0)
#define FT_LA_BSTRINS_D_EMIT(o,d,s,h,l) do{uint64_t mask=((1ULL<<((h)+1))-1)&(UINT64_MAX<<(l));r[d]=(r[d]&~mask)|((r[s]<<(l))&mask);T(o);}while(0)
#define FT_LA_LU12I_W_EMIT(o,d,i) do{r[d]=(uint64_t)(int64_t)(int32_t)((uint32_t)(i)<<12);T(o);}while(0)
static uint32_t ft_gpr2_imm20(int op,int d,int i){r[d]=(uint64_t)(int64_t)(int32_t)((uint32_t)i<<12);return 0;}
static bool ft_emit_store_addr_bytes(uint32_t**o,target_ulong pc,int d,int off,int s,int w){return true;}
static uint32_t ft_gpr3_imm12(int op,int d,int s,int i){return 0;}
static void ft_emit_raw(uint32_t **o,uint32_t v){T(o);}
static void ft_emit_li64(uint32_t **o,int d,uint64_t v){r[d]=v;T(o);}
#define imm64 imm
static bool ft_emit_guest_addr(uint32_t **o,int d,uint64_t v){r[d]=v;T(o);return true;}
static bool ft_emit_mem_addr(uint32_t **o,const FastTemplateFields*f,int*d){*d=la_t1;return true;}
static int ft_mem_access_offset(const FastTemplateFields*f,int d){return 0;}
static bool ft_emit_data_store(uint32_t**o,target_ulong pc,int d,int off,int s,int w){return false;}
#define FT_LA_ST_W_EMIT(o,s,d,i) do{mem=(mem&~0xffffffffULL)|(uint32_t)r[s];stores++;T(o);}while(0)
#define FT_LA_ST_H_EMIT(o,s,d,i) do{mem=(mem&~65535ULL)|(uint16_t)r[s];stores++;T(o);}while(0)
#define FT_LA_ST_B_EMIT(o,s,d,i) do{mem=(mem&~255ULL)|(uint8_t)r[s];stores++;T(o);}while(0)
#define FT_LA_SRLI_D_EMIT(o,d,s,i) do{r[d]=r[s]>>(i);T(o);}while(0)
static bool load(uint32_t**o,const FastTemplateFields*f,int*s,int w){
 if(f->modrm_mod==3){if(f->modrm_rm>=16)return false;*s=f->modrm_rm;}
 else {r[16]=w==64?mem:w==32?(uint64_t)(int64_t)(int32_t)mem:w==16?(uint16_t)mem:(uint8_t)mem;*s=16;loads++;T(o);}return true;
}
static bool store(uint32_t**o,const FastTemplateFields*f,int s,int w){
 if(f->modrm_mod==3){if(f->modrm_rm>=16)return false;int d=f->modrm_rm;FT_LA_OR_EMIT(o,d,s,la_zero);if(w==32){FT_LA_BSTRPICK_D_EMIT(o,d,d,31,0);}else if(w<32){uint64_t mask=(1ULL<<w)-1;r[d]=(r[d]&~mask)|(r[s]&mask);}}
 else {uint64_t mask=w==64?UINT64_MAX:(1ULL<<w)-1;mem=(mem&~mask)|(r[s]&mask);stores++;T(o);}return true;
}
#define ft_emit_load_rm8(o,f,p,s) load(o,f,s,8)
#define ft_emit_load_rm16(o,f,p,s) load(o,f,s,16)
#define ft_emit_load_rm32(o,f,p,s) load(o,f,s,32)
#define ft_emit_load_rm64(o,f,p,s) load(o,f,s,64)
#define ft_emit_store_rm8(o,f,p,s) store(o,f,s,8)
#define ft_emit_store_rm16(o,f,p,s) store(o,f,s,16)
#define ft_emit_store_rm32(o,f,p,s,z) store(o,f,s,32)
#define ft_emit_store_rm64(o,f,p,s) store(o,f,s,64)
'''
# Model small-width stores without clobbering their original high bits.
header=header.replace('int d=f->modrm_rm;FT_LA_OR_EMIT(o,d,s,la_zero);','int d=f->modrm_rm;uint64_t old=r[d];FT_LA_OR_EMIT(o,d,s,la_zero);').replace('r[d]=(r[d]&~mask)|(r[s]&mask);','r[d]=(old&~mask)|(r[s]&mask);')
main=r'''
int main(void){unsigned count=0;uint64_t seed=0xa55a5aa5c33c3cc3ULL;
 uint32_t edges[]={0,1,0xffe,0xfff,0x1000,0x1001,0x7fffffff,0x80000000,0x80000001,0xfffff000,0xffffffff};
 for(int form=0;form<2;form++)for(int dst=0;dst<16;dst++)for(int j=0;j<75;j++){
  seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;uint32_t v=j<11?edges[j]:(uint32_t)seed;
  for(int i=0;i<32;i++)r[i]=seed;r[31]=0;uint32_t code[64];FastTemplateFields x={.kind=form?FT_MOV_RM32_IMM32:FT_MOV_R32_IMM32,.reg=dst,.modrm_mod=3,.modrm_rm=dst,.imm=(int32_t)v,.rex=0};
  int n=form?emit_mov(&x,0,0,code):ft_emit_mov_reg_imm_template(&x,0,0,code);assert(n>0&&r[dst]==v);
  if(OPTIMIZED&&EXPECT_LATS){int expected=v<=0xfff?1:1+!!(v&0xfff)+!!(v&0x80000000u);assert(n==expected);}else if(OPTIMIZED)assert(n==3);
  for(int k=0;k<16;k++)if(k!=dst)assert(r[k]==seed);count++;
 }
 for(int src=0;src<16;src++)for(int dst=0;dst<16;dst++)for(int j=0;j<75;j++){
  seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;uint64_t v=j<11?0xdeadbeef00000000ULL|edges[j]:seed;
  for(int i=0;i<32;i++)r[i]=seed;r[31]=0;r[src]=v;uint32_t code[64];FastTemplateFields x={.kind=FT_MOV_RM32_R32,.modrm_mod=3,.modrm_reg=src,.modrm_rm=dst};
  int n=emit_mov(&x,0,0,code);assert(r[dst]==(uint32_t)v);if(OPTIMIZED)assert(n==(EXPECT_LATS?1:2));
  for(int k=0;k<16;k++)if(k!=dst)assert(r[k]==(k==src?v:seed));count++;
 }
 for(int w=32;w<=64;w+=32)for(int dst=0;dst<16;dst++)for(int j=0;j<75;j++)for(int memory=0;memory<2;memory++){
  seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;uint64_t v=j==0?0:j==1?UINT64_MAX:j<66?1ULL<<(j-2):seed;
  for(int i=0;i<32;i++)r[i]=seed;r[31]=0;r[dst]=v;mem=v;loads=stores=0;uint32_t code[64];FastTemplateFields x={.kind=w==32?FT_NOT_RM32:FT_NOT_RM64,.modrm_mod=memory?0:3,.modrm_rm=dst};
  int n=emit_not(&x,0,0,code);uint64_t expected=w==32?(uint32_t)~v:~v;
  if(memory){assert(mem==(w==32?(v&~0xffffffffULL)|expected:expected));assert(r[dst]==v&&loads==1&&stores==1);}
  else {assert(r[dst]==expected&&loads==0&&stores==0);if(OPTIMIZED)assert(n==(w==32?2:1)+(EXPECT_LATS?0:1));}
  for(int k=0;k<16;k++)if(k!=dst)assert(r[k]==seed);count++;
 }
 printf("actual MOV/NOT body %u cases PASS LATS=%d optimized=%d\n",count,EXPECT_LATS,OPTIMIZED);
}
'''
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'movnot.c';c.write_text(header+li+mov+'\nstatic int emit_mov(const FastTemplateFields*fields,TranslationBlock*tb,target_ulong pc,uint32_t*code){uint32_t*out=code;switch(fields->kind){\n'+rr+'default:return 0;}return out-code;}\nstatic int emit_not(const FastTemplateFields*fields,TranslationBlock*tb,target_ulong pc,uint32_t*code){uint32_t*out=code;int dst;\n'+notbody+main)
 for label,defs in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LATS=1']),('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),('user',['-DEXPECT_LATS=0'])]:
  exe=Path(d)/label
  subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror',*(['-fsanitize=undefined'] if not os.environ.get('NO_SANITIZE') else []),f'-DOPTIMIZED={int("--optimized" in sys.argv)}',*defs,str(c),'-o',str(exe)],check=True)
  subprocess.run([str(exe)],check=True)
