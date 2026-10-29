#!/usr/bin/env python3
"""Compile the real NOP emitter under LATU/LATS/user configurations."""
from pathlib import Path
import subprocess
import tempfile
s=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-misc.inc.c').read_text()
s=s[s.index('static inline bool ft_emit_zero_code_allowed'):s.index('static int ft_emit_prefetchw_template')]
a=s.index('#ifdef QUICKTRANS_LATU\nstatic int ft_emit_latu_bound')
b=s.index('static int ft_emit_nop_template',a)
s=s[:a]+s[b:]
h='''#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
typedef struct { int kind,id; } FastTemplateFields;
typedef int TranslationBlock;
typedef uint64_t target_ulong;
enum { FT_ENDBR32,FT_ENDBR64,FT_PAUSE,FT_NOP_MULTI,dt_X86_INS_FSETPM,dt_X86_INS_NOP,dt_X86_INS_FNOP,dt_X86_INS_BOUND,la_zero };
static int option_pause=1;
static int ft_emit_latu_bound(const FastTemplateFields*f,target_ulong p,uint32_t*c){return 0;}
#define FT_LA_ORI_EMIT(o,d,s,i) (*(*(o))++=123)
'''
t='''int main(void){uint32_t code[4]={42}; FastTemplateFields f={FT_NOP_MULTI,dt_X86_INS_FSETPM};
int n=ft_emit_nop_template(&f,0,0,code);
#ifdef QUICKTRANS_LATU
assert(n==0 && code[0]==42 && !ft_emit_zero_code_allowed(&f));
#elif defined(CONFIG_SOFTMMU)
assert(n==0 && code[0]==42 && ft_emit_zero_code_allowed(&f));
#else
assert(n==1 && code[0]==123);
#endif
f.id=dt_X86_INS_FNOP;assert(ft_emit_nop_template(&f,0,0,code)==1);
return 0;}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.c').write_text(h+s+t)
 for defs in (['-DQUICKTRANS_LATU'],['-DQUICKTRANS_LATU','-DCONFIG_SOFTMMU'],['-DCONFIG_SOFTMMU'],[]):
  subprocess.run(['cc','-std=c11','-fsanitize=undefined',*defs,str(p/'test.c'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
print('FSETPM rejection / LATS zero-code success / FNOP preserved: 4 configurations passed')
