#!/usr/bin/env python3
"""Compile the real no-code policy/emitter under LATS, TU and LATU guards."""
import os,re,subprocess,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/emitter/fast_translator/emit-misc.inc.c').read_text()
def function(name):
 pos=s.index(name+'(');start=s.rfind('static ',0,pos)
 end=s.index('{',pos)+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
real=function('ft_emit_zero_code_allowed')+'\n'+function('ft_emit_nop_template')
header=r'''
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
typedef int TranslationBlock;
typedef uint64_t target_ulong;
typedef struct {int kind,id,opcode0,opcode1,modrm_mod,modrm_reg,modrm_rm,prefix0,prefix2,segment,imm;bool omit_zext32;} FastTemplateFields;
#define ft_rex_w(f) false
#define ft_rex_r(f) false
#define ft_rex_b(f) false
#define ft_modrm_rm_index(f) ((f)->modrm_rm)
#define ft_modrm_reg_index(f) ((f)->modrm_reg)
#define ft_omit_gpr_zext32(f) ((f)->omit_zext32)
enum {GPR_NUM=16,XMM_NUM=16};
static int option_soft_fpu, fwait_calls;
typedef struct {uint32_t *pc;} FastBranchLabel;
typedef struct {int unused;} FastBranchFixup;
enum {la_t0=12,la_a0=4,FT_BRANCH_BEQ,FT_LA_OPCODE_LD_HU,FT_LA_OPCODE_ST_D};
#define lsenv_offset_of_status_word(e) 0
#define lsenv_offset_of_eip(e) 8
static inline void helper_fwait(void) {}
#define ft_emit_load_env(o,...) ((*(o))++)
#define FT_LA_ANDI_EMIT(o,...) ((*(o))++)
#define ft_emit_branch_placeholder(o,...) ((*(o))++)
#define ft_emit_helper_prologue(o) ((*(o))++)
#define ft_emit_li64(o,...) ((*(o))++)
#define ft_emit_store_env(o,...) ((*(o))++)
#define ft_emit_cpu_env_ptr(o,...) ((*(o))++)
#define ft_emit_host_call(o,f,m) (assert((f)==(void *)helper_fwait),fwait_calls++,(*(o))++)
#define ft_emit_helper_epilogue(o) ((*(o))++)
#define ft_bind_branch_label(l,p) ((l)->pc=(p))
#define ft_resolve_branch_fixup(f) ((void)(f))
static inline int ft_emit_latu_wait(uint32_t *code) {code[0]=0x12345678;return 1;}
static inline int ft_emit_latu_bound(const FastTemplateFields *f,target_ulong pc,uint32_t *code) {code[0]=0x87654321;return 1;}
static int option_pause;
enum {la_zero=0};
#define FT_LA_ORI_EMIT(out,d,s,i) (*(*(out))++ = 0x03400000)
'''
ids=sorted(set(re.findall(r'\b(?:FT_[A-Z0-9_]+|dt_X86_INS_[A-Z0-9_]+|dt_X86_PREFIX_[A-Z0-9_]+)\b', function('ft_emit_zero_code_allowed'))) | {'FT_OTHER','FT_WAIT','FT_HLT','dt_X86_INS_BOUND'})
header += 'enum {'+','.join(ids)+'};\n'
main=r'''
static void check(int kind,int id,bool zero) {
 FastTemplateFields f={.kind=kind,.id=id}; uint32_t code[32]={0xdeadbeef,0xcafebabe};
 assert(ft_emit_zero_code_allowed(&f)==zero);
 fwait_calls=0;
 int words=ft_emit_nop_template(&f,0,0,code);
#ifdef QUICKTRANS_LATU
 if(id==dt_X86_INS_FSETPM) {assert(words==0 && !zero && code[0]==0xdeadbeef);return;}
 if(kind==FT_WAIT || (id==dt_X86_INS_FNOP && option_soft_fpu)) {
  assert(!zero);assert(words==(option_soft_fpu?9:1));
  assert(fwait_calls==(option_soft_fpu?1:0));
  if(!option_soft_fpu)assert(code[0]==0x12345678);
  return;
 }
#endif
 assert(words==(zero?0:1));
 assert(code[0]==(zero?0xdeadbeef:0x03400000));
 assert(code[1]==0xcafebabe);
}
int main(void) {
 for(option_soft_fpu=0;option_soft_fpu<=1;option_soft_fpu++)
 for(option_pause=0;option_pause<=1;option_pause++) {
#if defined(CONFIG_SOFTMMU) && !defined(QUICKTRANS_LATU)
 bool lats=true;
#else
 bool lats=false;
#endif
#ifdef QUICKTRANS_LATU
 bool latu=true;
#else
 bool latu=false;
#endif
 bool nop=lats || latu;
#ifdef CONFIG_LATX_TU
 nop=latu || (lats && option_pause);
#endif
 check(FT_ENDBR32,dt_X86_INS_NOP,lats || latu);
 check(FT_ENDBR64,dt_X86_INS_NOP,lats || latu);
 check(FT_NOP_MULTI,dt_X86_INS_FSETPM,lats);
 check(FT_NOP_MULTI,dt_X86_INS_NOP,nop);
 check(FT_PAUSE,dt_X86_INS_NOP,latu || (lats && option_pause));
 check(FT_NOP_MULTI,dt_X86_INS_FNOP,latu && !option_soft_fpu);
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
assert source.count('if (!insn_emitted && !ft_emit_zero_code_allowed(fields)) {')==2
primary=(root/'src/emitter/fast_translator/primary-translate-body.inc.c').read_text()
assert 'if (!insn_emitted && !rsp_elided && !ft_emit_zero_code_allowed(fields)) {' in primary
assert 'if (!insn_emitted) {' not in source
print('PASS: zero-code emitter, error whitelist and five build configurations')
