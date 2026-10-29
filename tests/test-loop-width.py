#!/usr/bin/env python3
"""Check LOOP counter widths and flags; exit layout is modeled."""
from pathlib import Path
import subprocess,tempfile,os
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-template.inc.c').read_text()
b=s[s.index('    case FT_LOOP_REL8:'):s.index('    case FT_JCC_REL:')]
head=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
enum {FT_LOOP_REL8,FT_LOOPE_REL8,FT_LOOPNE_REL8,COND_E=4,COND_NE=5,FT_LA_OPCODE_SETX86J=0x100000,rcx_index=1,la_t0=16,la_t1=17,la_t2=18,la_zero=31};
typedef uint64_t target_ulong;
typedef struct {int kind,alu_width,size;uint64_t imm64;} FastTemplateFields;
typedef struct {uint64_t pc,lazypc[2];int canlink[2];} TranslationBlock;
static int zf;static uint64_t r[32];static int route,selected;static bool taken;
#define ft_gpr(x) (x)
#define ft_exit_target_pc(x) (x)
#define T(o) (*(*(o))++=0)
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) do{r[d]=(r[s]>>(l))&(UINT64_MAX>>(63-(h)+(l)));T(o);}while(0)
#define FT_LA_SLTU_EMIT(o,d,s,t) do{r[d]=r[s]<r[t];T(o);}while(0)
#define FT_LA_XORI_EMIT(o,d,s,k) do{r[d]=r[s]^(k);T(o);}while(0)
#define FT_LA_ADDI_D_EMIT(o,d,s,k) do{r[d]=r[s]+(k);T(o);}while(0)
#define FT_LA_AND_EMIT(o,d,s,t) do{r[d]=r[s]&r[t];T(o);}while(0)
#define FT_LA_BSTRINS_D_EMIT(o,d,s,h,l) do{uint64_t m=(UINT64_MAX>>(63-(h)+(l)))<<(l);r[d]=(r[d]&~m)|((r[s]<<(l))&m);T(o);}while(0)
static void ft_emit_raw(uint32_t**o,uint32_t v){r[v&31]=((v>>10)&15)==COND_E?zf:!zf;T(o);}
static int branch(uint32_t*c,uint32_t**o,int lhs,int rhs,bool eq,int which){if(route!=which)return 0;selected=which;taken=(r[lhs]==r[rhs])==eq;T(o);return *o-c;}
#define ft_emit_tu_jcc_compare(t,c,o,p,f,l,r,e) branch(c,o,l,r,e,0)
#define ft_emit_tu_jcc_partial_compare(t,c,o,p,f,l,r,e) branch(c,o,l,r,e,1)
#define ft_emit_jcc_exit_or_self_loop(t,c,o,p,f,l,r,e) branch(c,o,l,r,e,2)
'''
body='static int emit(TranslationBlock*tb,const FastTemplateFields*fields,uint32_t*code){uint32_t*out=code;uint64_t pc=0;switch(fields->kind){'+b+'}return 0;}\n'
tail=r'''
int main(void){uint32_t code[32];TranslationBlock tb={0};uint64_t seed=7;unsigned cases=0;
for(int w=16;w<=64;w*=2)for(int kind=0;kind<3;kind++)for(zf=0;zf<2;zf++)for(route=0;route<3;route++)for(int j=0;j<4096;j++){
seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;uint64_t v=j==0?0:j==1?1:j==2?0x10001ULL:j==3?0x100000001ULL:seed;
r[1]=v;r[31]=0;FastTemplateFields f={.kind=kind,.alu_width=w};int n=emit(&tb,&f,code);
uint64_t mask=w==64?UINT64_MAX:(1ULL<<w)-1,low=(v-1)&mask;
uint64_t want=w==16?(v&~mask)|low:low;
bool jump=low!=0&&(kind==FT_LOOP_REL8||(kind==FT_LOOPE_REL8?zf:!zf));
if(!(n>0&&taken==jump&&r[1]==want&&selected==route)){fprintf(stderr,"FAIL width=%d kind=%d input=%llx result=%llx expected=%llx taken=%d expected=%d\n",w,kind,(unsigned long long)v,(unsigned long long)r[1],(unsigned long long)want,taken,jump);return 1;}cases++;}
printf("LOOP actual emitter: %u cases PASS (modeled flags/exits)\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'test.c';p.write_text(head+body+tail)
 for label,flags in [('latu',['-DQUICKTRANS_LATU']),('other',[])]:
  exe=Path(d)/label;subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',*flags,str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
