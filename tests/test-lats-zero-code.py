#!/usr/bin/env python3
"""Compile the real no-code policy/emitter under LATS, TU and LATU guards."""
import os,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/emitter/fast_translator/emit-misc.inc.c').read_text()
a=s.index('static inline bool ft_emit_zero_code_allowed');b=s.index('static int ft_emit_prefetchw_template');real=s[a:b]
header=r'''
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
typedef int TranslationBlock;
typedef uint64_t target_ulong;
enum { FT_ENDBR32, FT_ENDBR64, FT_PAUSE, FT_NOP_MULTI, FT_WAIT, FT_HLT, FT_OTHER };
enum { dt_X86_INS_NOP, dt_X86_INS_FSETPM, dt_X86_INS_FNOP };
typedef struct {int kind; int id;} FastTemplateFields;
static int option_pause;
enum {la_zero=0};
#define FT_LA_ORI_EMIT(out,d,s,i) (*(*(out))++ = 0x03400000)
'''
main=r'''
static void check(int kind,int id,bool zero) {
 FastTemplateFields f={kind,id}; uint32_t code[2]={0xdeadbeef,0xcafebabe};
 assert(ft_emit_zero_code_allowed(&f)==zero);
 int words=ft_emit_nop_template(&f,0,0,code);
 assert(words==(zero?0:1));
 assert(code[0]==(zero?0xdeadbeef:0x03400000));
 assert(code[1]==0xcafebabe);
}
int main(void) {
 for(option_pause=0;option_pause<=1;option_pause++) {
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
 bool lats=true;
#else
 bool lats=false;
#endif
 bool nop=lats;
#ifdef CONFIG_LATX_TU
 nop=lats && option_pause;
#endif
 check(FT_ENDBR32,dt_X86_INS_NOP,lats);
 check(FT_ENDBR64,dt_X86_INS_NOP,lats);
 check(FT_NOP_MULTI,dt_X86_INS_FSETPM,lats);
 check(FT_NOP_MULTI,dt_X86_INS_NOP,nop);
 check(FT_PAUSE,dt_X86_INS_NOP,lats && option_pause);
 check(FT_NOP_MULTI,dt_X86_INS_FNOP,false);
 check(FT_WAIT,dt_X86_INS_NOP,false);
 check(FT_HLT,dt_X86_INS_NOP,false);
 check(FT_OTHER,dt_X86_INS_NOP,false);
 }
 return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.c').write_text(header+real+main)
 for flags in [[],['CONFIG_SOFTMMU'],['CONFIG_SOFTMMU','CONFIG_LATX_TU'],['QUICKTRANS_LATU'],['CONFIG_SOFTMMU','CONFIG_LATX_TU','QUICKTRANS_LATU']]:
  subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Wall','-Werror',*['-D'+f for f in flags],str(p/'test.c'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
source=(root/'src/emitter/fast_translator/fast-translator.c').read_text()
assert source.count('if (!insn_emitted && !ft_emit_zero_code_allowed(fields)) {')==3
assert 'if (!insn_emitted) {' not in source
print('PASS: zero-code emitter, error whitelist and five build configurations')
