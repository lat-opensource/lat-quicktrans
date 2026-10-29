#!/usr/bin/env python3
"""Check actual JCXZ emitter operand selection; exit layout is modeled."""
from pathlib import Path
import subprocess,tempfile,os
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-template.inc.c').read_text()
b=s[s.index('    case FT_JRCXZ_REL8:'):s.index('    case FT_LOOP_REL8:')]
head=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
enum {FT_JRCXZ_REL8,rcx_index=1,la_t0=16,la_t1=17,la_zero=31};
typedef uint64_t target_ulong;
typedef struct {int kind,alu_width,size;uint64_t imm64;} FastTemplateFields;
typedef struct {uint64_t pc,lazypc[2];int canlink[2];} TranslationBlock;
static uint64_t r[32];static int route,selected;static bool taken;
#define ft_gpr(x) (x)
#define ft_exit_target_pc(x) (x)
#define T(o) (*(*(o))++=0)
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) do{r[d]=(r[s]>>(l))&(UINT64_MAX>>(63-(h)+(l)));T(o);}while(0)
#define FT_LA_SLTU_EMIT(o,d,s,t) do{r[d]=r[s]<r[t];T(o);}while(0)
#define FT_LA_XORI_EMIT(o,d,s,k) do{r[d]=r[s]^(k);T(o);}while(0)
static int branch(uint32_t*c,uint32_t**o,int lhs,int rhs,bool eq,int which){if(route!=which)return 0;selected=which;taken=(r[lhs]==r[rhs])==eq;T(o);return *o-c;}
#define ft_emit_tu_jcc_compare(t,c,o,p,f,l,r,e) branch(c,o,l,r,e,0)
#define ft_emit_tu_jcc_partial_compare(t,c,o,p,f,l,r,e) branch(c,o,l,r,e,1)
#define ft_emit_jcc_exit_or_self_loop(t,c,o,p,f,l,r,e) branch(c,o,l,r,e,2)
'''
body='static int emit(TranslationBlock*tb,const FastTemplateFields*fields,uint32_t*code){uint32_t*out=code;uint64_t pc=0;switch(fields->kind){'+b+'}return 0;}\n'
tail=r'''
int main(void){uint32_t code[16];TranslationBlock tb={0};uint64_t seed=7;unsigned cases=0;
for(int w=16;w<=64;w*=2)for(route=0;route<3;route++)for(int j=0;j<4096;j++){
seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;uint64_t v=j==0?0:j==1?1:j==2?0x10000ULL:j==3?0x100000000ULL:seed;
r[1]=v;r[31]=0;FastTemplateFields f={.kind=FT_JRCXZ_REL8,.alu_width=w};int n=emit(&tb,&f,code);
uint64_t mask=w==64?UINT64_MAX:(1ULL<<w)-1;assert(taken==((v&mask)==0)&&r[1]==v&&selected==route);
#ifdef QUICKTRANS_LATU
assert(n==1+(w<64));
#else
assert(n==3+(w<64));
#endif
cases++;}printf("JCXZ actual emitter: %u cases PASS (modeled exits)\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'test.c';p.write_text(head+body+tail)
 for label,flags in [('latu',['-DQUICKTRANS_LATU']),('other',[])]:
  exe=Path(d)/label;subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',*flags,str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
