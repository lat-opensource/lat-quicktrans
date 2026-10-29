#!/usr/bin/env python3
"""Compile the actual LATU/LATS bit adapter and exhaustively check masks."""
from pathlib import Path
import os,re,subprocess,tempfile
root=Path(__file__).resolve().parents[1]
s=(root/'src/emitter/fast_translator/fast-translator.c').read_text()
a=s.index('static bool ft_instptn_enabled(');b=s.index('\nstatic void ',a)
body=s[a:b];defs='\n'.join(re.findall(r'^#define FT_INSTPTN_\w+\s+\(1ULL << \d+\)',s,re.M))
main='''
int main(void) {
 for (int mode=-2; mode<34; ++mode) {
  option_instptn = mode==-2 ? 0 : mode==-1 ? 0x3ffffff : 1ULL<<mode;
  for (int i=0;i<34;++i) {
#ifdef QUICKTRANS_LATU
   int legacy=i<=20?i:i==22?21:i==30?24:i==23?25:-1;
   bool expect=legacy>=0 ? ((uint32_t)option_instptn & (1u<<legacy))!=0 : (uint32_t)option_instptn==0x3ffffff;
#else
   bool expect=(option_instptn & (1ULL<<i))!=0;
#endif
   assert(ft_instptn_enabled(1ULL<<i)==expect);
  }
 }
 return 0;
}
'''
with tempfile.TemporaryDirectory() as d:
 p=Path(d);(p/'t.c').write_text('#include <stdint.h>\n#include <stdbool.h>\n#include <assert.h>\nstatic uint64_t option_instptn;\n'+defs+'\n'+body+main)
 for flags in [[],['-DQUICKTRANS_LATU']]:
  subprocess.run([os.environ.get('CC','cc'),'-std=c99','-O2','-Wall','-Werror',*flags,str(p/'t.c'),'-o',str(p/'t')],check=True);subprocess.run([str(p/'t')],check=True)
print('PASS: 34 patterns x 36 masks x LATU/LATS')
