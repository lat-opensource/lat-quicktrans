#!/usr/bin/env python3
"""Run the actual MOVSQ emitter branch across its mode/segment guards."""
import os
import subprocess
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[1]
src = (root / 'src/emitter/fast_translator/emit-string.inc.c').read_text()
addr = src[src.index('static bool ft_emit_string_addr('):src.index('static void ft_emit_string_load_bytes(')]
a = src.index('static bool ft_emit_string_body(')
b = src.index('    int src_addr =', a)
body = src[a:b] + '    return false;\n}\n'
header = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
enum {es_index,cs_index,ss_index,ds_index,fs_index,gs_index};
enum {rsi_index=6,rdi_index=7,la_t0=12,la_t3=15,la_t4=16,la_zero=31};
enum {dt_X86_INS_MOVSQ=1, HF_CS64_MASK=128, FT_LA_OPCODE_LD_D=1};
typedef struct {struct {uint64_t base;} segs[6];} CPUX86State;
typedef struct {int id,segment;bool addr32;} FastTemplateFields;
typedef struct {unsigned flags;} TranslationBlock;
static CPUX86State env;
static uint64_t r[32];
static unsigned char mem[4096];
#define ft_gpr(i) (i)
#define ft_fits_simm12(x) ((x)>=-2048 && (x)<=2047)
static void ft_emit_load_env(uint32_t **out,int dst,int offset,int op) {
 (void)op; memcpy(&r[dst],(char *)&env+offset,8);(*out)++;
}
#define FT_LA_BSTRPICK_D_EMIT(o,d,s,h,l) do {r[d]=(r[s]>>(l))&((UINT64_C(1)<<((h)-(l)+1))-1);(*o)++;} while(0)
#define FT_LA_OR_EMIT(o,d,s,z) do {r[d]=r[s]|r[z];(*o)++;} while(0)
#define FT_LA_ADD_D_EMIT(o,d,s,t) do {r[d]=r[s]+r[t];(*o)++;} while(0)
#define FT_LA_LD_D_EMIT(o,d,s,i) do {assert(r[s]+i+8<=sizeof(mem));memcpy(&r[d],mem+r[s]+i,8);(*o)++;} while(0)
#define FT_LA_ST_D_EMIT(o,d,s,i) do {assert(r[s]+i+8<=sizeof(mem));memcpy(mem+r[s]+i,&r[d],8);(*o)++;} while(0)
"""
main = r"""
int main(void) {
 unsigned n=0;
 for(int mode=0;mode<2;mode++)for(int a32=0;a32<2;a32++)for(int seg=-1;seg<6;seg++)for(int nulltb=0;nulltb<2;nulltb++)for(int high=0;high<2;high++) {
  uint32_t code[32],*out=code;unsigned char expected[sizeof(mem)];
  for(unsigned i=0;i<sizeof(mem);i++)mem[i]=(unsigned char)(i*13+(i>>8));
  memcpy(expected,mem,sizeof(mem));memset(r,0,sizeof(r));
  for(int i=0;i<6;i++)env.segs[i].base=32*(i+1);
  uint64_t hi=(mode&&a32&&!nulltb&&high)?UINT64_C(0xdead000000000000):0;
  r[rsi_index]=hi|128;r[rdi_index]=hi|2048;
  FastTemplateFields f={.id=dt_X86_INS_MOVSQ,.segment=seg,.addr32=a32};
  TranslationBlock tb={.flags=mode?HF_CS64_MASK:0};
  bool longmode=mode&&!nulltb;
  bool flat=longmode&&!a32;
  unsigned source=128+((seg<0||(longmode&&seg!=fs_index&&seg!=gs_index))?0:env.segs[seg].base);
  unsigned dest=2048+(longmode?0:env.segs[es_index].base);
  uint64_t value;memcpy(&value,expected+source,8);memcpy(expected+dest,&value,8);
  bool ok=ft_emit_string_body(&out,&f,8,nulltb?NULL:&tb);
#if EXPECT_LATS
  assert(ok);assert(memcmp(mem,expected,sizeof(mem))==0);
  if(flat&&seg!=fs_index&&seg!=gs_index)assert(out-code==2);
#else
  assert(!ok && out==code);
#endif
  assert(r[rsi_index]==(hi|128)&&r[rdi_index]==(hi|2048));n++;
 }
 printf("MOVSQ mode/segment cases=%u LATS=%d PASS\n",n,EXPECT_LATS);
}
"""
with tempfile.TemporaryDirectory() as d:
    c = Path(d) / 'test.c'
    c.write_text(header + addr + body + main)
    for label, flags in [('lats',['-DCONFIG_SOFTMMU=1','-DEXPECT_LATS=1']),
                         ('latu',['-DCONFIG_SOFTMMU=1','-DQUICKTRANS_LATU=1','-DEXPECT_LATS=0']),
                         ('user',['-DEXPECT_LATS=0'])]:
        binary = Path(d) / label
        subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror',
                        '-fsanitize=undefined',*flags,str(c),'-o',str(binary)],check=True)
        subprocess.run([str(binary)],check=True)
