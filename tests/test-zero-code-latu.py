#!/usr/bin/env python3
"""Check the actual zero-output allowlist; guest tests cover emission/recovery."""
from pathlib import Path
import re, subprocess, tempfile
src=(Path(__file__).resolve().parents[1]/'src/emitter/fast_translator/emit-misc.inc.c').read_text()
s=src[src.index('static inline bool ft_emit_zero_code_allowed'):src.index('\n#ifdef QUICKTRANS_LATU\nstatic int ft_emit_latu_bound')]
names=sorted(set(re.findall(r'\b(?:FT_[A-Z0-9_]+|dt_X86_[A-Z0-9_]+)\b',s)))
h='''#include <assert.h>
#include <stdbool.h>
typedef struct { int kind,id,modrm_mod,modrm_reg,modrm_rm,prefix0,prefix2,imm,reg,rm,opcode0,opcode1,segment,rex; bool omit_zext32; } FastTemplateFields;
#define XMM_NUM 16
#define GPR_NUM 16
static bool ft_rex_w(const FastTemplateFields *f){return f->rex & 8;}
static bool ft_rex_r(const FastTemplateFields *f){return f->rex & 4;}
static bool ft_rex_b(const FastTemplateFields *f){return f->rex & 1;}
static bool ft_omit_gpr_zext32(const FastTemplateFields *f){return f->omit_zext32;}
static int option_soft_fpu, option_pause=1;
static int ft_modrm_reg_index(const FastTemplateFields *f){return f->reg;}
static int ft_modrm_rm_index(const FastTemplateFields *f){return f->rm;}
'''+ 'enum {'+','.join(names)+'};\n'
t='''int main(void) {
 FastTemplateFields f={0};
#ifdef QUICKTRANS_LATU
 int noop[]={FT_ENDBR32,FT_ENDBR64,FT_PAUSE};
 for(int i=0;i<3;i++){ f.kind=noop[i]; assert(ft_emit_zero_code_allowed(&f)); }
 f.kind=FT_NOP_MULTI;f.id=dt_X86_INS_NOP;assert(ft_emit_zero_code_allowed(&f));
 f.id=dt_X86_INS_FSETPM;assert(!ft_emit_zero_code_allowed(&f));
 f.id=dt_X86_INS_FNOP;
 for(int mode=0;mode<3;mode++){option_soft_fpu=mode;assert(ft_emit_zero_code_allowed(&f)==(mode==0));}
 f=(FastTemplateFields){.kind=FT_BNDMOV,.id=dt_X86_INS_BNDMOV,.opcode0=0x0f,.opcode1=0x1a,.prefix2=dt_X86_PREFIX_OPSIZE};
 for(int op=0x1a;op<=0x1b;op++)for(int mod=0;mod<4;mod++)for(int reg=0;reg<8;reg++)for(int rm=0;rm<8;rm++)for(int rex=0;rex<16;rex++){
 f.opcode1=op;f.modrm_mod=mod;f.modrm_reg=reg;f.modrm_rm=rm;f.rex=rex;
 assert(ft_emit_zero_code_allowed(&f)==(!(rex&4)&&reg<=3&&(mod!=3||(!(rex&1)&&rm<=3))));
 }
 f=(FastTemplateFields){0};
 int moves[]={FT_MOV128_XMM_XMMM,FT_MOV128_XMMM_XMM,FT_MOVSD_XMM_M64,FT_MOVSD_M64_XMM};
 for(int k=0;k<4;k++)for(int mod=0;mod<4;mod++)for(int a=0;a<17;a++)for(int b=0;b<17;b++){
 f.kind=moves[k];f.modrm_mod=mod;f.reg=a;f.rm=b;
 assert(ft_emit_zero_code_allowed(&f)==(mod==3&&a==b&&a<16));
 }
 int ids[]={dt_X86_INS_BLENDPS,dt_X86_INS_BLENDPD,dt_X86_INS_PBLENDW};
 int masks[]={15,3,255};
 for(int k=0;k<3;k++)for(int mod=0;mod<4;mod++)for(int imm=0;imm<256;imm++){
 f.kind=FT_BLEND_XMM_XMMM_IMM8;f.id=ids[k];f.modrm_mod=mod;f.imm=imm;f.reg=0;f.rm=15;f.prefix2=dt_X86_PREFIX_OPSIZE;
 assert(ft_emit_zero_code_allowed(&f)==(mod==3&&!(imm&masks[k])));
 }
#else
 f.kind=FT_ENDBR64;
#ifdef CONFIG_SOFTMMU
 assert(ft_emit_zero_code_allowed(&f));
#else
 assert(!ft_emit_zero_code_allowed(&f));
#endif
#endif
 return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'test.c').write_text(h+s+t)
 for flags in (['-DQUICKTRANS_LATU'],['-DQUICKTRANS_LATU','-DCONFIG_SOFTMMU'],['-DCONFIG_SOFTMMU'],[]):
  subprocess.run(['cc','-std=c11','-fsanitize=undefined',*flags,str(p/'test.c'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
print('zero-output allowlist: four configurations passed')
