#!/usr/bin/env python3
"""Actual XLAT emitter, with modeled address-dependent byte memory."""
from pathlib import Path
import subprocess,tempfile,os
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-gpr.inc.c').read_text();b=s[s.index('static int ft_emit_xlat_template'):s.index('static int ft_emit_xchg_template')]
h=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
typedef struct{int prefix0,prefix2,segment;bool addr32;}FastTemplateFields;
typedef int TranslationBlock;typedef uint64_t target_ulong;
enum{dt_X86_PREFIX_OPSIZE=102,rax_index=0,rbx_index=3,la_t0=16,la_t1=17};
static uint64_t r[32],address;
#define ft_gpr(x) (x)
#define T(o) (*(*(o))++=0)
static uint64_t load(uint64_t a){address=a;return (a^(a>>8)^(a>>32))&255;}
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) do{r[d]=(r[s]>>(l))&(UINT64_MAX>>(63-(h)+(l)));T(o);}while(0)
#define FT_LA_BSTRINS_D_EMIT(o,d,s,h,l) do{uint64_t m=(UINT64_MAX>>(63-(h)+(l)))<<(l);r[d]=(r[d]&~m)|((r[s]<<(l))&m);T(o);}while(0)
#define FT_LA_ADD_D_EMIT(o,d,s,t) do{r[d]=r[s]+r[t];T(o);}while(0)
#define FT_LA_LD_BU_EMIT(o,d,s,k) do{r[d]=load(r[s]+(k));T(o);}while(0)
#define FT_LA_LDX_BU_EMIT(o,d,s,t) do{r[d]=load(r[s]+r[t]);T(o);}while(0)
'''
t=r'''
int main(void){uint32_t code[32];unsigned cases=0;uint64_t bases[]={0,1,0xffffff80ULL,0xffffffffULL,0x100000000ULL,0x1234567812345678ULL,UINT64_MAX};
for(int a=0;a<2;a++)for(int i=0;i<7;i++)for(int v=0;v<256;v++)for(int p=0;p<2;p++){
r[0]=0x9876543212345600ULL|v;r[3]=bases[i];uint64_t old=r[0],wantaddr=(r[3]+v)&(a?UINT32_MAX:UINT64_MAX),value=load(wantaddr);FastTemplateFields f={.addr32=a,.segment=-1,.prefix2=p?102:0};int n=ft_emit_xlat_template(&f,0,0,code);assert(n==(a?5:3)&&address==wantaddr&&r[0]==((old&~255ULL)|value)&&r[3]==bases[i]);cases++;}
printf("XLAT actual emitter: %u cases PASS (modeled memory)\n",cases);}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'t.c';p.write_text(h+b+t);exe=Path(d)/'t'
 subprocess.run([os.environ.get('CC','cc'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(p),'-o',str(exe)],check=True);subprocess.run([str(exe)],check=True)
