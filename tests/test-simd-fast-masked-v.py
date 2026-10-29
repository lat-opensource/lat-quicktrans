#!/usr/bin/env python3
"""Exercise actual scalar/packed conversion emitters under four build modes.

This checks emitted operations and option isolation, not hardware FP semantics.
Guest tests must compare normal and invalid conversions against legacy LATS.
"""
import os
import re
import subprocess
import tempfile
from pathlib import Path
root = Path(__file__).resolve().parents[1]
base = root / 'src/emitter/fast_translator'
def extract(file, name):
    text = file.read_text()
    pos = text.index(name + '(')
    start = text.rfind('static ', 0, pos)
    end = text.index('{', pos) + 1
    depth = 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]
parts = [extract(base/'fast-translator.c', 'ft_fast_masked_v_enabled')]
for name in ('ft_emit_cvtsx2si_convert', 'ft_emit_cvtsx2si_template',
             'ft_emit_cvt_fp2i_fix_invalid', 'ft_emit_cvt_fp2i_lanes',
             'ft_emit_cvt_fp2i_core', 'ft_emit_cvt_fp2i_mmx_template'):
    parts.append(extract(base/'emit-simd.inc.c', name))
source = '\n'.join(parts)
macros = sorted(set(re.findall(r'\bFT_LA_\w+_EMIT', source)))
ids = sorted(set(re.findall(r'\b(?:dt_X86_INS_\w+|FT_CVT\w+)\b', source)) | {'FT_CVTSS2SI_GPR_XMMM', 'dt_X86_INS_CVTPS2DQ', 'dt_X86_INS_CVTPS2PI'})
header = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
typedef unsigned long target_ulong;
typedef struct { int unused; } TranslationBlock;
typedef struct { int kind, id, prefix0, prefix2, modrm_mod, width, reg, rm; } FastTemplateFields;
static int option_fast_masked_v;
static int option_soft_fpu=1;
static int lsenv;
#define lsenv_offset_of_top(x) 0
#define FT_LA_OPCODE_ST_W 0
#define la_zero 0
#define ft_mmx(r) (8+(r))
enum { la_t0, la_t1, ft_vscratch=24, GPR_NUM=16, XMM_NUM=16 };
static int n, fpe_checks, seen[128];
static void record(uint32_t **out,int op) { (*out)++; n++; seen[op]++; }
#define ft_modrm_reg_index(f) ((f)->reg)
#define ft_modrm_rm_index(f) ((f)->rm)
#define ft_rex_w(f) ((f)->width==64)
#define ft_gpr(r) (r)
#define ft_xmm(r) (r)
#define ft_mem_access_offset(f,a) 0
static bool ft_emit_rip_or_mem_addr(uint32_t **out,const FastTemplateFields *f,target_ulong pc,int *addr) { *addr=0;return true; }
static void ft_emit_lats_simd_fpe_check(uint32_t **out,TranslationBlock *tb,target_ulong pc) { fpe_checks++; }
static void ft_emit_li64(uint32_t **out,int dst,uint64_t value) { (*out)++; n++; }
static void ft_emit_store_env(uint32_t **out,int src,int off,int op) { (*out)++; n++; }
static bool ft_emit_xmmm_src_bytes(uint32_t **out,const FastTemplateFields *f,target_ulong pc,int bytes,int *src) { *src=1;return true; }
static void reset(void) { n=fpe_checks=0;for(int i=0;i<128;i++)seen[i]=0; }
'''
header += 'enum {' + ','.join(ids) + '};\n'
header += 'enum {' + ','.join('OP_'+m for m in macros) + '};\n'
for m in macros:
    header += '#define '+m+'(out,...) record(out,OP_'+m+')\n'
main = r'''
int main(void) {
 uint32_t code[256];TranslationBlock tb={0};int cases=0;
 int kinds[]={FT_CVTSS2SI_GPR_XMMM,FT_CVTSD2SI_GPR_XMMM,
              FT_CVTTSS2SI_GPR_XMMM,FT_CVTTSD2SI_GPR_XMMM};
 int packed[]={dt_X86_INS_CVTPS2DQ,dt_X86_INS_CVTTPS2DQ,
               dt_X86_INS_CVTPD2DQ,dt_X86_INS_CVTTPD2DQ,
               dt_X86_INS_CVTPS2PI,dt_X86_INS_CVTTPS2PI,
               dt_X86_INS_CVTPD2PI,dt_X86_INS_CVTTPD2PI};
 for(int enabled=0;enabled<2;enabled++) {
  option_fast_masked_v=enabled;
  bool fast=enabled && EXPECT_LATS;
  assert(ft_fast_masked_v_enabled()==fast);
  for(int k=0;k<4;k++)for(int wide=0;wide<2;wide++)for(int mem=0;mem<2;mem++) {
   FastTemplateFields f={.kind=kinds[k],.width=wide?64:32,.prefix0=(k%2)?0xf2:0xf3,.modrm_mod=mem?0:3,.reg=0,.rm=1};
   reset();int count=ft_emit_cvtsx2si_template(&f,&tb,0,code);
   assert(count==(fast?2:7)+!wide+mem);
   assert(seen[OP_FT_LA_MOVFCSR2GR_EMIT]==!fast);
   assert(seen[OP_FT_LA_MASKNEZ_EMIT]==!fast);
   assert(seen[OP_FT_LA_MOVFR2GR_D_EMIT]==1);
   assert(fpe_checks==1);cases++;
  }
  for(int k=0;k<8;k++) {
   FastTemplateFields f={.id=packed[k]};uint32_t *out=code;
   reset();assert(ft_emit_cvt_fp2i_core(&out,&f,&tb,0,1,2));
   assert(seen[OP_FT_LA_VBITSEL_V_EMIT]==!fast);
   assert(seen[OP_FT_LA_VLDI_EMIT]==(fast?0:(k==0||k==1||k==4||k==5?2:1)));
   int lanes=(k==1)?4:2;
   assert(fpe_checks==((fast&&k!=0)?lanes:1));
   if(fast)assert(n==(k==0?2:3*lanes-1));cases++;
   if(k>=4) {
    for(int soft=0;soft<2;soft++) {
     option_soft_fpu=soft;
     reset();assert(ft_emit_cvt_fp2i_mmx_template(&f,&tb,0,code)>0);
     bool skip=fast && EXPECT_NOFP && soft;
     assert(seen[OP_FT_LA_X86MTTOP_EMIT]==!skip);
     assert(seen[OP_FT_LA_X86SETTM_EMIT]==!skip);
     cases++;
    }
    option_soft_fpu=1;
   }
  }
 }
 printf("SIMD fast_masked_v: %d emitter cases PASS (LATS=%d)\n",cases,EXPECT_LATS);
}
'''
with tempfile.TemporaryDirectory() as d:
    c = Path(d)/'test.c'; c.write_text(header+source+main)
    for label, flags in [('lats',['-DCONFIG_SOFTMMU=1','-DCONFIG_LATX_OPT_NOFP=1','-DEXPECT_NOFP=1','-DEXPECT_LATS=1']),
                         ('lats_without_nofp',['-DCONFIG_SOFTMMU=1','-DEXPECT_NOFP=0','-DEXPECT_LATS=1']),
                         ('latu',['-DEXPECT_NOFP=0','-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),
                         ('user',['-DEXPECT_NOFP=0','-DEXPECT_LATS=0'])]:
        exe=Path(d)/label
        subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror',*flags,str(c),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
