#!/usr/bin/env python3
"""Exercise real string load/store emission for unaligned and overlapping data."""
import os, subprocess, tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[1]
s=(root/'src/emitter/fast_translator/emit-string.inc.c').read_text()
a=s.index('static bool ft_string_lats_wide_access(')
b=s.index('\n#endif',a)
helper=s[a:b]
ids=['MOVSW','MOVSD','LODSQ','STOSQ','CMPSQ','SCASQ','MOVSB','MOVSQ','CMPSD']
header='''#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
static uint64_t r[32];
static unsigned char mem[4096];
static void load(uint32_t **o,int d,int a,int i,int n) {
 r[d]=0;memcpy(&r[d],mem+r[a]+i,n);(*o)++;
}
static void store(uint32_t **o,int d,int a,int i,int n) {
 memcpy(mem+r[a]+i,&r[d],n);(*o)++;
}
#define FT_LA_LD_HU_EMIT(o,d,a,i) load(o,d,a,i,2)
#define FT_LA_LD_WU_EMIT(o,d,a,i) load(o,d,a,i,4)
#define FT_LA_LD_D_EMIT(o,d,a,i) load(o,d,a,i,8)
#define FT_LA_ST_H_EMIT(o,d,a,i) store(o,d,a,i,2)
#define FT_LA_ST_W_EMIT(o,d,a,i) store(o,d,a,i,4)
#define FT_LA_ST_D_EMIT(o,d,a,i) store(o,d,a,i,8)
'''
header+='enum {'+','.join('dt_X86_INS_'+x for x in ids)+'};\n'
main='''
int main(void) {
 unsigned n=0;
 for(int width=2;width<=8;width*=2)
 for(int align=0;align<16;align++)
 for(int overlap=-9;overlap<=9;overlap++)
 for(int seed=0;seed<16;seed++) {
  unsigned char expected[sizeof(mem)];uint64_t value=0;
  uint32_t code[4],*out=code;
  for(unsigned i=0;i<sizeof(mem);i++)mem[i]=(unsigned char)(i*13+(i>>8)+seed*17);
  memcpy(expected,mem,sizeof(mem));memcpy(&value,expected+256+align,width);
  memcpy(expected+256+align+overlap,&value,width);
  memset(r,0xff,sizeof(r));r[1]=256+align;r[2]=256+align+overlap;
  ft_emit_string_load_wide(&out,0,1,width);
  assert(r[0]==value && out-code==1);
  ft_emit_string_store_wide(&out,0,2,width);
  assert(out-code==2 && !memcmp(mem,expected,sizeof(mem)));n++;
 }
 assert(!ft_string_lats_wide_access(dt_X86_INS_MOVSB));
 assert(!ft_string_lats_wide_access(dt_X86_INS_MOVSQ));
 assert(!ft_string_lats_wide_access(dt_X86_INS_CMPSD));
 printf("wide string unaligned/overlap/zero extension cases=%u PASS\\n",n);
}
'''
with tempfile.TemporaryDirectory() as d:
 c=Path(d)/'test.c';c.write_text(header+helper+main)
 binary=Path(d)/'test'
 subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Werror','-fsanitize=undefined',str(c),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True)
