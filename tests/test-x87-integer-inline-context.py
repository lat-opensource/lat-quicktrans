#!/usr/bin/env python3
"""Exercise the real context emitter for all preserved GPR/XMM values and gates."""
from pathlib import Path
import os, subprocess, tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'src/emitter/fast_translator/emit-x87.inc.c').read_text()
a=s.index('static bool ft_emit_x87_integer_inline_context(');b=s.index('\n#if defined(CONFIG_SOFTMMU)',a+100)
f=s[a:b]
c=r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>
#define CONFIG_SOFTMMU 1
#define GPR_NUM 16
#define XMM_NUM 16
#define la_s0 20
static int option_soft_fpu=1,option_soft_fpu_fast=1,large,count;
static uint64_t regs[32],vec[16][2],saved_flags,flags;
static unsigned char mem[1024];
#define ft_gpr(i) (i)
#define ft_xmm(i) (i)
#define lsenv_offset_of_gpr(e,i) ((i)*8+large)
#define lsenv_offset_of_xmm(e,i) (256+(i)*16+large)
#define ft_offset_fits_imm12(v) ((v)>=-2048&&(v)<=2047)
#define FT_LA_ST_D_EMIT(o,s,b,v) do{assert((b)==la_s0);memcpy(mem+(v),&regs[s],8);++count;}while(0)
#define FT_LA_LD_D_EMIT(o,d,b,v) do{assert((b)==la_s0);memcpy(&regs[d],mem+(v),8);++count;}while(0)
#define FT_LA_VST_EMIT(o,s,b,v) do{assert((b)==la_s0);memcpy(mem+(v),vec[s],16);++count;}while(0)
#define FT_LA_VLD_EMIT(o,d,b,v) do{assert((b)==la_s0);memcpy(vec[d],mem+(v),16);++count;}while(0)
static void ft_emit_save_condition_flags(uint32_t **out){assert(count==32);saved_flags=flags;++count;}
static void ft_emit_restore_condition_flags(uint32_t **out){assert(count==0);flags=saved_flags;++count;}
'''+f+r'''
int main(void){
 for(unsigned sample=0;sample<256;++sample){
  uint64_t expected[16],ev[16][2];
  for(int i=0;i<16;i++){expected[i]=regs[i]=((uint64_t)sample<<40)^((uint64_t)i*0x123456789ULL);for(int j=0;j<2;j++)ev[i][j]=vec[i][j]=expected[i]+j+1;}
  flags=sample;count=0;assert(ft_emit_x87_integer_inline_context(0,false));assert(count==33);
  memset(regs,0,sizeof(regs));memset(vec,0,sizeof(vec));flags=0;count=0;
  assert(ft_emit_x87_integer_inline_context(0,true));assert(count==33);
  assert(!memcmp(expected,regs,sizeof(expected)));assert(!memcmp(ev,vec,sizeof(ev)));assert(flags==sample);
 }
 large=4096;count=0;assert(!ft_emit_x87_integer_inline_context(0,false));assert(!ft_emit_x87_integer_inline_context(0,true));assert(!count);
 large=0;option_soft_fpu_fast=0;assert(!ft_emit_x87_integer_inline_context(0,false));assert(!count);
 option_soft_fpu_fast=1;option_soft_fpu=0;assert(!ft_emit_x87_integer_inline_context(0,true));assert(!count);
}
'''
with tempfile.TemporaryDirectory() as t:
 p=Path(t);(p/'test.c').write_text(c)
 subprocess.run([os.environ.get('CC','cc'),'-O2',str(p/'test.c'),'-o',str(p/'test')],check=True)
 subprocess.run([str(p/'test')],check=True)
print('passed: 256 complete GPR/XMM/flags contexts; large-offset and soft-fast gates')
